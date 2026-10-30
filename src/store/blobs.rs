use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::error::ApiError;

/// Blob file layout: `/data/blobs/ab/<64-hex>` — one file per blob,
/// 2-hex bucket dirs, bytes verified once at store time (decision #11).
pub fn blob_path(data_dir: &Path, hash_hex: &str) -> PathBuf {
    data_dir.join("blobs").join(&hash_hex[..2]).join(hash_hex)
}

pub fn tmp_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("tmp")
}

/// Ensure the on-disk layout exists (called once at boot).
pub fn init_dirs(data_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(tmp_dir(data_dir))?;
    std::fs::create_dir_all(data_dir.join("blobs"))?;
    for i in 0..256u32 {
        std::fs::create_dir_all(data_dir.join("blobs").join(format!("{i:02x}")))?;
    }
    Ok(())
}

#[derive(Debug)]
pub enum Abort {
    TooLarge,
    Watermark,
    /// Upload slots or the temp-file budget are exhausted; retry shortly.
    Busy,
    /// Free disk space is below the configured safety floor.
    DiskFull,
    Io(String),
}

impl From<Abort> for ApiError {
    fn from(a: Abort) -> Self {
        match a {
            Abort::TooLarge => ApiError::too_large("single blob exceeds 10% of STORAGE_MAX"),
            Abort::Watermark => ApiError::at_watermark(),
            Abort::Busy => ApiError::busy(),
            Abort::DiskFull => ApiError::disk_full(),
            Abort::Io(m) => ApiError::internal(m),
        }
    }
}

/// How long an upload waits for a slot before the relay says "busy".
const UPLOAD_SLOT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long an upload may stall between body chunks before it is aborted.
pub const UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Concurrent blob uploads allowed per process.
const MAX_CONCURRENT_UPLOADS: usize = 8;
/// Stale temp files older than this are removed by the reaper.
pub const TMP_FILE_TTL: Duration = Duration::from_secs(24 * 3600);

/// Process-wide upload admission. Slots bound concurrent streams; the byte
/// reservation bounds temp files so parallel uploads cannot each pass the
/// per-request watermark check and fill the disk together.
#[derive(Debug)]
pub struct UploadGovernor {
    slots: Arc<tokio::sync::Semaphore>,
    inflight: AtomicI64,
    tmp_budget: i64,
    free_floor: u64,
}

impl UploadGovernor {
    pub fn from_config(cfg: &crate::config::Config) -> Arc<Self> {
        // Temp files may use at most half of the admission watermark, so a
        // burst of uploads cannot consume the space reserved for committed
        // data. The floor keeps at least a small amount of disk free for the
        // DB/WAL and the operator.
        let tmp_budget = (cfg.watermark_bytes / 2)
            .max(16 * 1024 * 1024)
            .min(cfg.watermark_bytes.max(1));
        let free_floor = (cfg.storage_max / 20)
            .max(16 * 1024 * 1024)
            .min((cfg.storage_max / 2).max(1));
        Arc::new(UploadGovernor {
            slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UPLOADS)),
            inflight: AtomicI64::new(0),
            tmp_budget: tmp_budget.min(i64::MAX as u64) as i64,
            free_floor,
        })
    }

    pub fn inflight_bytes(&self) -> i64 {
        self.inflight.load(Ordering::Relaxed)
    }

    async fn acquire(self: &Arc<Self>) -> Result<UploadPermit, Abort> {
        let slot = tokio::time::timeout(
            UPLOAD_SLOT_TIMEOUT,
            Arc::clone(&self.slots).acquire_owned(),
        )
        .await
        .map_err(|_| Abort::Busy)?
        .map_err(|_| Abort::Busy)?;
        Ok(UploadPermit {
            governor: Arc::clone(self),
            reserved: 0,
            _slot: slot,
        })
    }
}

/// RAII reservation for one upload stream. Dropping it releases the slot and
/// all bytes reserved by the stream, including a staged file not yet installed.
#[derive(Debug)]
pub struct UploadPermit {
    governor: Arc<UploadGovernor>,
    reserved: i64,
    _slot: tokio::sync::OwnedSemaphorePermit,
}

impl UploadPermit {
    /// Reserve `n` bytes against both the global temp budget and the
    /// admission watermark. Released automatically when the permit drops.
    fn try_reserve(&mut self, n: u64, live_start: i64, watermark: u64) -> Result<(), Abort> {
        let n = i64::try_from(n).map_err(|_| Abort::TooLarge)?;
        let watermark = i64::try_from(watermark).unwrap_or(i64::MAX);
        loop {
            let current = self.governor.inflight.load(Ordering::Acquire);
            let next = current.saturating_add(n);
            if next > self.governor.tmp_budget {
                return Err(Abort::Busy);
            }
            if live_start.max(0).saturating_add(next) > watermark {
                return Err(Abort::Watermark);
            }
            if self
                .governor
                .inflight
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.reserved = self.reserved.saturating_add(n);
                return Ok(());
            }
        }
    }
}

impl Drop for UploadPermit {
    fn drop(&mut self) {
        if self.reserved != 0 {
            self.governor.inflight.fetch_sub(self.reserved, Ordering::AcqRel);
        }
    }
}

/// Where a blob body came from. Peer bodies must never evict local events to
/// make room: the sync plane is pull-only and best-effort, while event loss is
/// permanent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobOrigin {
    Local,
    Peer,
}

/// File removals deferred until the surrounding DB transaction commits.
/// Eviction can run inside an admission transaction; unlinking immediately
/// would leave rows without bytes if that transaction rolls back.
#[derive(Debug, Default)]
pub struct UnlinkQueue {
    paths: Vec<PathBuf>,
}

impl UnlinkQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, path: PathBuf) {
        self.paths.push(path);
    }

    pub fn flush(&mut self) {
        for path in self.paths.drain(..) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The destination every blob write streams through (both doors): temp file +
/// incremental sha256 in one pass, caps enforced *during* the stream.
#[derive(Debug)]
pub struct BlobSink {
    file: Option<std::fs::File>,
    hasher: Sha256,
    written: u64,
    live_bytes_start: i64,
    watermark: u64,
    max_single: u64,
    path: PathBuf,
    permit: Option<UploadPermit>,
    /// Set by `finish`/`discard` so Drop does not remove a file that was
    /// deliberately handed off or already removed.
    done: bool,
}

#[derive(Debug)]
pub struct Staged {
    pub hash_hex: String,
    pub hash: [u8; 32],
    pub size: u64,
    pub path: PathBuf, // still temp; caller materializes after commit
    /// Keeps the upload's byte reservation alive until install/refusal, so
    /// concurrent uploads see the staged file in the in-flight total.
    #[allow(dead_code)] // held for its Drop side effect
    permit: Option<UploadPermit>,
}

impl Staged {
    /// Drop the staged temp file when the row was refused or the commit failed.
    pub fn discard(self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        // After materialize the temp path no longer exists; after a DB error it
        // still does. Either way this is the last-resort cleanup for paths that
        // do not explicitly call discard().
        let _ = std::fs::remove_file(&self.path);
    }
}

impl BlobSink {
    /// Start one upload stream. Admission is process-wide: a slot bounds
    /// concurrency, and the byte reservation bounds temp files against both
    /// the global temp budget and the storage watermark.
    pub async fn start(
        gov: &Arc<UploadGovernor>,
        data_dir: &Path,
        live_bytes_start: i64,
        watermark: u64,
        max_single: u64,
    ) -> Result<BlobSink, Abort> {
        if matches!(
            crate::config::free_bytes_opt(data_dir),
            Some(free) if free < gov.free_floor
        ) {
            return Err(Abort::DiskFull);
        }
        let permit = gov.acquire().await?;
        let path = tmp_dir(data_dir).join(format!(
            "p{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        let file = std::fs::File::create(&path)
            .map_err(|e| Abort::Io(format!("cannot create temp file: {e}")))?;
        Ok(BlobSink {
            file: Some(file),
            hasher: Sha256::new(),
            written: 0,
            live_bytes_start,
            watermark,
            max_single,
            path,
            permit: Some(permit),
            done: false,
        })
    }

    /// Feed one chunk. When a cap is hit, returns an error; the sink keeps
    /// buffering nothing more — the caller drains + discards.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), Abort> {
        self.written += chunk.len() as u64;
        if self.written > self.max_single {
            return Err(Abort::TooLarge);
        }
        self.permit
            .as_mut()
            .expect("sink permit already released")
            .try_reserve(chunk.len() as u64, self.live_bytes_start, self.watermark)?;
        let Some(f) = self.file.as_mut() else {
            return Err(Abort::Io("sink already closed".into()));
        };
        self.hasher.update(chunk);
        if let Err(e) = f.write_all(chunk) {
            return Err(Abort::Io(e.to_string()));
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<Staged, Abort> {
        if let Err(e) = self.take_file().sync_all() {
            self.done = true;
            let _ = std::fs::remove_file(&self.path);
            return Err(Abort::Io(e.to_string()));
        }
        let hash: [u8; 32] = self.hasher.clone().finalize().into();
        let path = self.path.clone();
        self.done = true;
        Ok(Staged {
            hash_hex: hex::encode(hash),
            hash,
            size: self.written,
            path,
            permit: self.permit.take(),
        })
    }

    pub fn discard(mut self) {
        self.done = true;
        drop(self.file.take());
        let _ = std::fs::remove_file(&self.path);
    }

    fn take_file(&mut self) -> std::fs::File {
        self.file.take().expect("sink file already closed")
    }

    pub fn written(&self) -> u64 {
        self.written
    }
}

impl Drop for BlobSink {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        drop(self.file.take());
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Move a staged temp file into its content-addressed slot.
/// Returns Ok(false) when the bytes already exist (dedupe: existing wins).
/// Called inside the install transaction, before commit; a crash between the
/// move and the commit leaves an orphan file the boot sweep removes.
pub fn materialize(data_dir: &Path, staged: &Staged) -> std::io::Result<bool> {
    let dest = blob_path(data_dir, &staged.hash_hex);
    if dest.is_file() {
        std::fs::remove_file(&staged.path)?;
        return Ok(false);
    }
    std::fs::rename(&staged.path, &dest).map(|_| true)
}

/// Blob-row insert; idempotent by hash (dedupe by content). Must run inside
/// the caller's transaction so the row and its counter move together. The
/// final watermark re-check uses the authoritative counter table.
pub fn insert_blob_row(
    c: &rusqlite::Connection,
    hash: &[u8; 32],
    size: u64,
    stored_at: i64,
    watermark_bytes: u64,
) -> rusqlite::Result<BlobInsertResult> {
    let exists: i64 = c
        .query_row("SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)", [hash], |r| r.get(0))?;
    if exists == 1 {
        return Ok(BlobInsertResult::Deduped);
    }
    let (events_now, blobs_now) = crate::db::live_bytes(c);
    if (events_now + blobs_now + size as i64) as u64 > watermark_bytes {
        return Ok(BlobInsertResult::WatermarkFull);
    }
    c.execute(
        "INSERT INTO blobs(hash, size, stored_at, ever_attached, state) VALUES (?1, ?2, ?3, 0, 'live')",
        rusqlite::params![hash, size as i64, stored_at],
    )?;
    crate::db::bump_counters(c, 0, size as i64)?;
    Ok(BlobInsertResult::Inserted)
}

#[derive(Debug, PartialEq)]
pub enum BlobInsertResult {
    Inserted,
    Deduped,
    WatermarkFull,
}

/// Destination of an install attempt.
#[derive(Debug, PartialEq)]
pub enum Install {
    Fresh,
    Deduped,
    Refused,
}

/// Install a staged temp file: transactional accept-or-refuse + file move.
/// Used by the raw PUT door, the sync push door, and lazy fetch-on-read.
///
/// Admission and any eviction it triggers run in the same transaction as the
/// blob row, so a failed insert rolls the eviction back. Peer-origin bodies
/// never evict local events; they are refused at the watermark instead.
///
/// The file is moved into its content-addressed slot *inside* the writer lock
/// but before the row commit. A crash before the commit leaves an orphan file
/// (removed by boot hygiene); a crash after it leaves a complete row+file pair.
/// A materialization failure rolls the row back, so we never publish a row
/// whose bytes are missing.
pub async fn install_staged(
    db: &crate::db::Db,
    cfg: &crate::config::Config,
    staged: Staged,
    origin: BlobOrigin,
) -> rusqlite::Result<Install> {
    let dir = cfg.data_dir.clone();
    let water = cfg.watermark_bytes;
    let cfg2 = cfg.clone();
    let hash = staged.hash;
    let size = staged.size;
    let now = crate::store::reaper::now();
    let allow_event_eviction = origin == BlobOrigin::Local;

    db.write(move |c: &rusqlite::Connection| -> rusqlite::Result<Install> {
        let tx = c.unchecked_transaction()?;
        let mut unlinks = UnlinkQueue::new();

        // A duplicate install adds no bytes: never evict for a retry.
        let exists: i64 = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
            [&hash],
            |r| r.get(0),
        )?;
        if exists == 0 {
            // Demand-aware admission: make room for this blob (or refuse)
            // before the row insert, so eviction is charged to a write
            // that can actually be accepted. Peer bodies may reclaim
            // collectible blobs but never delete events.
            if crate::store::reaper::pressure_check_with(
                &tx,
                &cfg2,
                size,
                allow_event_eviction,
                &mut unlinks,
            )
            .is_err()
            {
                drop(tx); // rollback any eviction
                staged.discard();
                return Ok(Install::Refused);
            }
        }
        let r = insert_blob_row(&tx, &hash, size, now, water)?;
        if r == BlobInsertResult::WatermarkFull {
            drop(tx); // rollback any eviction
            staged.discard();
            return Ok(Install::Refused);
        }
        tx.execute(
            "UPDATE blobs SET ever_attached=1 WHERE hash=?1 AND EXISTS(SELECT 1 FROM refs WHERE blob_hash=?1)",
            rusqlite::params![&hash],
        )?;
        let moved = match materialize(&dir, &staged) {
            Ok(moved) => moved,
            Err(e) => {
                tracing::error!("materialize {}: {e}", staged.hash_hex);
                drop(tx); // rollback the row: never publish a row without bytes
                staged.discard();
                return Ok(Install::Refused);
            }
        };
        if let Err(e) = tx.commit() {
            if moved && r == BlobInsertResult::Inserted {
                let _ = std::fs::remove_file(blob_path(&dir, &hex::encode(hash)));
            }
            return Err(e);
        }
        // The row is durable; now it is safe to unlink evicted files.
        unlinks.flush();
        Ok(if r == BlobInsertResult::Inserted { Install::Fresh } else { Install::Deduped })
    })
    .await
}

/// Attach a blob to an event (same transaction as the event insert);
/// `ever_attached = 1` means: rides parenthood from now on, not the 1h clock.
pub fn attach_ref(c: &rusqlite::Connection, event: &[u8; 32], blob: &[u8; 32]) -> rusqlite::Result<()> {
    c.execute(
        "INSERT OR IGNORE INTO refs(event_id, blob_hash) VALUES (?1, ?2)",
        rusqlite::params![event, blob],
    )?;
    c.execute("UPDATE blobs SET ever_attached = 1 WHERE hash = ?1", [blob])?;
    Ok(())
}

/// Remove one blob row + its file + refs rows. Returns freed bytes.
/// File removal is immediate; transactional callers use `delete_blob_with`
/// and flush the queue only after commit.
pub fn delete_blob(c: &rusqlite::Connection, hash: &[u8; 32], data_dir: &Path) -> rusqlite::Result<i64> {
    let mut unlinks = UnlinkQueue::new();
    let freed = delete_blob_with(c, hash, data_dir, &mut unlinks)?;
    unlinks.flush();
    Ok(freed)
}

/// Transaction-safe variant: records the file path instead of unlinking it.
pub fn delete_blob_with(
    c: &rusqlite::Connection,
    hash: &[u8; 32],
    data_dir: &Path,
    unlinks: &mut UnlinkQueue,
) -> rusqlite::Result<i64> {
    let size: i64 = c.query_row("SELECT size FROM blobs WHERE hash = ?1", [hash], |r| r.get(0))?;
    let n = c.execute("DELETE FROM blobs WHERE hash = ?1", [hash])?;
    if n == 0 {
        return Ok(0);
    }
    c.execute("DELETE FROM refs WHERE blob_hash = ?1", [hash])?;
    crate::db::bump_counters(c, 0, -size)?;
    unlinks.push(blob_path(data_dir, &hex::encode(hash)));
    Ok(size)
}

/// Delete events rows (+ refs, labels, counters) for the given raw ids.
/// The caller runs this in-transaction, usually with the blob pass following.
pub fn delete_events(c: &rusqlite::Connection, ids: &[[u8; 32]], data_dir: &Path) -> rusqlite::Result<i64> {
    let mut freed = 0i64;
    for id in ids {
        let size: i64 = c.query_row("SELECT size FROM events WHERE id = ?1", [id], |r| r.get(0))?;
        let n = c.execute("DELETE FROM events WHERE id = ?1", [id])?;
        if n == 0 {
            continue;
        }
        c.execute("DELETE FROM refs WHERE event_id = ?1", [id])?;
        c.execute("DELETE FROM labels WHERE event_id = ?1", [id])?;
        crate::db::bump_counters(c, -size, 0)?;
        freed += size;
    }
    let _ = data_dir; // events carry no files
    Ok(freed)
}

/// Blob expiry pass — ONE rule covers all of plan.md §Eviction Layer 1:
///   refs==0 AND ever_attached=1  → die-with-parent (last parent left)
///   refs==0 AND stored_at+1h past → born-orphan clock
///   refs>0                        → alive, parent governs
/// Called after the event sweep and after every eviction pass.
pub fn blob_pass(c: &rusqlite::Connection, now: i64, data_dir: &Path) -> rusqlite::Result<BlobPassReport> {
    let mut unlinks = UnlinkQueue::new();
    let report = blob_pass_with(c, now, data_dir, &mut unlinks)?;
    unlinks.flush();
    Ok(report)
}

/// Transaction-safe variant: file removals are queued for after commit.
pub fn blob_pass_with(
    c: &rusqlite::Connection,
    now: i64,
    data_dir: &Path,
    unlinks: &mut UnlinkQueue,
) -> rusqlite::Result<BlobPassReport> {
    use crate::db::ORPHAN_TTL_SECONDS as ORPHAN;
    let mut report = BlobPassReport::default();

    {
        let sql = format!(
            "SELECT hash, size FROM blobs
             WHERE state='live'
               AND NOT EXISTS (SELECT 1 FROM refs r WHERE r.blob_hash = blobs.hash)
               AND (ever_attached = 1 OR ?1 >= stored_at + {ORPHAN})"
        );
        let mut stmt = c.prepare(&sql)?;
        let mut rows = stmt.query([now])?;
        while let Some(r) = rows.next()? {
            let hash: Vec<u8> = r.get(0)?;
            let size: i64 = r.get(1)?;
            let mut h = [0u8; 32];
            h.copy_from_slice(&hash);
            report.victims.push((h, size));
        }
    }

    for (h, _size) in report.victims.iter() {
        let freed = delete_blob_with(c, h, data_dir, unlinks)?;
        report.blob_bytes += freed;
        report.blobs_removed += 1;
    }
    Ok(report)
}

#[derive(Debug, Default)]
pub struct BlobPassReport {
    pub blobs_removed: usize,
    pub blob_bytes: i64,
    victims: Vec<([u8; 32], i64)>,
}

/// Remove stale temp files left behind by cancelled uploads or crashes.
/// Boot hygiene clears the directory unconditionally; this periodic pass
/// only touches files older than `max_age` so active slow uploads survive.
pub fn cleanup_tmp(data_dir: &Path, max_age: Duration) -> usize {
    let now = std::time::SystemTime::now();
    let Ok(entries) = std::fs::read_dir(tmp_dir(data_dir)) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let Ok(modified) = meta.modified() else { continue };
        if now.duration_since(modified).unwrap_or_default() > max_age
            && std::fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// Full data-dir open + boot hygiene: remove leftover temp files, remove
/// files with no row (crash leftovers, collected at boot only — no dir
/// scans in steady state, the DB stays the source of truth).
pub async fn boot_hygiene(db: &Db, data_dir: PathBuf) -> rusqlite::Result<()> {
    db.write(move |c| {
        // stale temp files
        if let Ok(entries) = std::fs::read_dir(tmp_dir(&data_dir)) {
            for e in entries.flatten() {
                let _ = std::fs::remove_file(e.path()); // between boots, nothing temp is live
            }
        }
        // files on disk with no row
        if let Ok(buckets) = std::fs::read_dir(data_dir.join("blobs")) {
            for bucket in buckets.flatten() {
                let Ok(files) = std::fs::read_dir(bucket.path()) else { continue };
                for f in files.flatten() {
                    let hash_hex = f.file_name().to_string_lossy().to_string();
                    if hash_hex.len() != 64 || !hash_hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
                        continue;
                    }
                    let mut id = [0u8; 32];
                    if let Ok(b) = hex::decode(&hash_hex) {
                        id.copy_from_slice(&b);
                    }
                    let exists: i64 = c
                        .query_row("SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)", [&id], |r| r.get(0))
                        .unwrap_or(1); // on query error, keep (fail open)
                    if exists == 0 {
                        let _ = std::fs::remove_file(f.path());
                    }
                }
            }
        }
        // rows whose file went missing (crash between rename & delete): drop
        // them here so reads never 500 afterwards
        let mut orphans: Vec<Vec<u8>> = Vec::new();
        {
            let mut stmt = c.prepare("SELECT hash FROM blobs")?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let h: Vec<u8> = r.get(0)?;
                let hex = hex::encode(&h);
                if !blob_path(&data_dir, &hex).exists() {
                    orphans.push(h);
                }
            }
        }
        for h in orphans {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            delete_blob(c, &arr, &data_dir)?;
        }
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let dir = std::env::temp_dir().join(format!("rabta-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_cfg(dir: &std::path::Path) -> Config {
        Config {
            port: 0,
            data_dir: dir.to_path_buf(),
            storage_max: 100,
            storage_clamped: false,
            storage_max_configured: 100,
            max_single_blob: 10,
            watermark_bytes: 90,
            eviction_target_bytes: 85,
            sse_subscriber_cap: 1,
            sync_nodes: Vec::new(),
            sync_interval: Duration::from_secs(60),
        }
    }

    fn staged_file(dir: &std::path::Path, hash: [u8; 32], body: &[u8], tag: &str) -> Staged {
        let path = tmp_dir(dir).join(tag);
        std::fs::write(&path, body).unwrap();
        Staged {
            hash_hex: hex::encode(hash),
            hash,
            size: body.len() as u64,
            path,
            permit: None,
        }
    }

    async fn seed_event(db: &Db, id: [u8; 32], size: i64) {
        db.write(move |c: &rusqlite::Connection| -> rusqlite::Result<()> {
            let seq = crate::db::next_event_seq(c)?;
            c.execute(
                "INSERT INTO events(id,seq,owner,collection,created_at,expires_at,data,labels,size,state)
                 VALUES (?1,?2,?3,'c',1,9999999999,x'7b7d','[]',?4,'live')",
                rusqlite::params![&id[..], seq, &[0u8; 32], size],
            )?;
            crate::db::bump_counters(c, size, 0)?;
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn peer_blob_admission_refuses_instead_of_evicting_events() {
        let dir = temp_dir("blob-peer-no-evict");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);
        seed_event(&db, [9u8; 32], 90).await;

        let peer = staged_file(&dir, [3u8; 32], b"0123456789", "peer");
        let outcome = install_staged(&db, &cfg, peer, BlobOrigin::Peer)
            .await
            .unwrap();
        assert_eq!(outcome, Install::Refused);
        let events: i64 = db
            .read(|c| {
                c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
                    .unwrap()
            })
            .await;
        assert_eq!(events, 1, "peer blob evicted a local event");

        let local = staged_file(&dir, [4u8; 32], b"0123456789", "local");
        let outcome = install_staged(&db, &cfg, local, BlobOrigin::Local)
            .await
            .unwrap();
        assert_eq!(outcome, Install::Fresh);
        let events: i64 = db
            .read(|c| {
                c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
                    .unwrap()
            })
            .await;
        assert_eq!(events, 0, "local admission should still make room");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn watermark_refusal_discards_staged_file() {
        let dir = temp_dir("blob-refusal");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = Config {
            port: 0,
            data_dir: dir.clone(),
            storage_max: 100,
            storage_clamped: false,
            storage_max_configured: 100,
            max_single_blob: 10,
            watermark_bytes: 5,
            eviction_target_bytes: 4,
            sse_subscriber_cap: 1,
            sync_nodes: Vec::new(),
            sync_interval: Duration::from_secs(60),
        };

        let path = tmp_dir(&dir).join("staged");
        std::fs::write(&path, b"0123456789").unwrap();
        let staged = Staged {
            hash_hex: hex::encode([7u8; 32]),
            hash: [7u8; 32],
            size: 10,
            path: path.clone(),
            permit: None,
        };

        let outcome = install_staged(&db, &cfg, staged, BlobOrigin::Local).await.unwrap();
        assert_eq!(outcome, Install::Refused);
        assert!(!path.exists(), "refused upload left its temp file behind");

        let rows: i64 = db
            .read(|c| c.query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0)).unwrap())
            .await;
        assert_eq!(rows, 0);

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn failed_materialize_rolls_back_the_blob_row() {
        let dir = temp_dir("blob-materialize-fail");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);

        let hash = [7u8; 32];
        // A directory at the destination makes the final rename fail.
        std::fs::create_dir_all(blob_path(&dir, &hex::encode(hash))).unwrap();
        let staged = staged_file(&dir, hash, b"0123456789", "fail");
        let path = staged.path.clone();

        let outcome = install_staged(&db, &cfg, staged, BlobOrigin::Local).await.unwrap();
        assert_eq!(outcome, Install::Refused);
        assert!(!path.exists(), "failed materialization left its temp file behind");
        let rows: i64 = db
            .read(|c| c.query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0)).unwrap())
            .await;
        assert_eq!(rows, 0, "row was published without its bytes");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn deduped_install_heals_a_missing_file() {
        let dir = temp_dir("blob-heal");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);
        let hash = [8u8; 32];
        let dest = blob_path(&dir, &hex::encode(hash));

        let first = install_staged(
            &db,
            &cfg,
            staged_file(&dir, hash, b"abcd", "first"),
            BlobOrigin::Local,
        )
        .await
        .unwrap();
        assert_eq!(first, Install::Fresh);
        assert_eq!(std::fs::read(&dest).unwrap(), b"abcd");

        std::fs::remove_file(&dest).unwrap();
        let second = install_staged(
            &db,
            &cfg,
            staged_file(&dir, hash, b"abcd", "second"),
            BlobOrigin::Local,
        )
        .await
        .unwrap();
        assert_eq!(second, Install::Deduped);
        assert_eq!(std::fs::read(&dest).unwrap(), b"abcd", "dedupe did not heal the file");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn test_governor(tmp_budget: i64, free_floor: u64) -> Arc<UploadGovernor> {
        Arc::new(UploadGovernor {
            slots: Arc::new(tokio::sync::Semaphore::new(8)),
            inflight: AtomicI64::new(0),
            tmp_budget,
            free_floor,
        })
    }

    fn tmp_files(dir: &std::path::Path) -> usize {
        std::fs::read_dir(tmp_dir(dir))
            .map(|entries| entries.flatten().filter(|e| e.path().is_file()).count())
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn concurrent_uploads_share_one_watermark() {
        let dir = temp_dir("blob-shared-watermark");
        init_dirs(&dir).unwrap();
        let gov = test_governor(1_000, 0);

        let mut first = BlobSink::start(&gov, &dir, 0, 90, 100).await.unwrap();
        first.push(&[1u8; 50]).unwrap();

        // A second stream with the same live-byte snapshot must not assume the
        // whole watermark is available to it.
        let mut second = BlobSink::start(&gov, &dir, 0, 90, 100).await.unwrap();
        assert!(matches!(second.push(&[2u8; 50]), Err(Abort::Watermark)));

        drop(first);
        drop(second);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn temp_budget_bounds_parallel_upload_bytes() {
        let dir = temp_dir("blob-temp-budget");
        init_dirs(&dir).unwrap();
        let gov = test_governor(45, 0);

        let mut first = BlobSink::start(&gov, &dir, 0, 1_000, 100).await.unwrap();
        first.push(&[1u8; 40]).unwrap();

        let mut second = BlobSink::start(&gov, &dir, 0, 1_000, 100).await.unwrap();
        assert!(matches!(second.push(&[2u8; 10]), Err(Abort::Busy)));
        assert_eq!(gov.inflight_bytes(), 40);

        drop(first);
        drop(second);
        assert_eq!(gov.inflight_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn dropped_sink_removes_temp_file_and_releases_bytes() {
        let dir = temp_dir("blob-sink-drop");
        init_dirs(&dir).unwrap();
        let gov = test_governor(1_000, 0);

        let mut sink = BlobSink::start(&gov, &dir, 0, 1_000, 100).await.unwrap();
        sink.push(&[1u8; 10]).unwrap();
        assert_eq!(gov.inflight_bytes(), 10);
        assert_eq!(tmp_files(&dir), 1);

        drop(sink);
        assert_eq!(gov.inflight_bytes(), 0);
        assert_eq!(tmp_files(&dir), 0, "cancelled upload leaked its temp file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn staged_keeps_reservation_until_install_or_drop() {
        let dir = temp_dir("blob-staged-reservation");
        init_dirs(&dir).unwrap();
        let gov = test_governor(1_000, 0);

        let mut sink = BlobSink::start(&gov, &dir, 0, 1_000, 100).await.unwrap();
        sink.push(&[1u8; 10]).unwrap();
        let staged = sink.finish().unwrap();
        assert_eq!(gov.inflight_bytes(), 10, "staged file lost its reservation");

        drop(staged);
        assert_eq!(gov.inflight_bytes(), 0);
        assert_eq!(tmp_files(&dir), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn free_space_floor_refuses_uploads() {
        let dir = temp_dir("blob-free-floor");
        init_dirs(&dir).unwrap();
        let gov = test_governor(1_000, u64::MAX);

        let err = BlobSink::start(&gov, &dir, 0, 1_000, 100).await.unwrap_err();
        assert!(matches!(err, Abort::DiskFull));
        assert_eq!(tmp_files(&dir), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_tmp_removes_only_stale_files() {
        let dir = temp_dir("blob-tmp-cleanup");
        init_dirs(&dir).unwrap();
        let old = tmp_dir(&dir).join("old");
        std::fs::write(&old, b"x").unwrap();
        let old_time = std::time::SystemTime::now() - Duration::from_secs(2 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old_time))
            .unwrap();

        let fresh = tmp_dir(&dir).join("fresh");
        std::fs::write(&fresh, b"x").unwrap();

        assert_eq!(cleanup_tmp(&dir, Duration::from_secs(3600)), 1);
        assert!(!old.exists());
        assert!(fresh.exists());
        assert_eq!(cleanup_tmp(&dir, Duration::from_secs(3600)), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
