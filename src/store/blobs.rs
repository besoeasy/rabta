use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::error::{ApiError, ApiResult};

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
    Io(String),
}

/// The destination every blob write streams through (both doors): temp file +
/// incremental sha256 in one pass, caps enforced *during* the stream.
pub struct BlobSink {
    file: Option<std::fs::File>,
    hasher: Sha256,
    written: u64,
    live_bytes_start: i64,
    watermark: u64,
    max_single: u64,
    path: PathBuf,
}

#[derive(Debug)]
pub struct Staged {
    pub hash_hex: String,
    pub hash: [u8; 32],
    pub size: u64,
    pub path: PathBuf, // still temp; caller materializes after commit
}

impl Staged {
    /// Drop the staged temp file when the row was refused or the commit failed.
    pub fn discard(self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl BlobSink {
    pub fn start(data_dir: &Path, live_bytes_start: i64, watermark: u64, max_single: u64) -> ApiResult<BlobSink> {
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
            .map_err(|e| ApiError::internal(format!("cannot create temp file: {e}")))?;
        Ok(BlobSink {
            file: Some(file),
            hasher: Sha256::new(),
            written: 0,
            live_bytes_start,
            watermark,
            max_single,
            path,
        })
    }

    /// Feed one chunk. When a cap is hit, returns an error; the sink keeps
    /// buffering nothing more — the caller drains + discards.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), Abort> {
        self.written += chunk.len() as u64;
        if self.written > self.max_single {
            return Err(Abort::TooLarge);
        }
        if self.live_bytes_start + self.written as i64 > self.watermark as i64 {
            return Err(Abort::Watermark);
        }
        let Some(f) = self.file.as_mut() else { return Err(Abort::Io("sink already closed".into())) };
        self.hasher.update(chunk);
        if let Err(e) = f.write_all(chunk) {
            return Err(Abort::Io(e.to_string()));
        }
        Ok(())
    }

    pub fn finish(self) -> Result<Staged, Abort> {
        let mut me = self;
        if let Err(e) = me.take_file().sync_all() {
            let _ = std::fs::remove_file(&me.path);
            return Err(Abort::Io(e.to_string()));
        }
        let hash: [u8; 32] = me.hasher.finalize().into();
        Ok(Staged { hash_hex: hex::encode(hash), hash, size: me.written, path: me.path })
    }

    pub fn discard(mut self) {
        self.take_file();
        let _ = std::fs::remove_file(&self.path);
    }

    fn take_file(&mut self) -> std::fs::File {
        self.file.take().expect("sink file already closed")
    }

    pub fn written(&self) -> u64 {
        self.written
    }

}

/// Move a staged temp file into its content-addressed slot.
/// Returns Ok(false) when the bytes already exist (dedupe: existing wins).
/// Called AFTER the row commit; a crash between the two leaves an orphan
/// file the boot sweep removes.
pub fn materialize(data_dir: &Path, staged: &Staged) -> std::io::Result<bool> {
    let dest = blob_path(data_dir, &staged.hash_hex);
    if dest.exists() {
        std::fs::remove_file(&staged.path)?;
        return Ok(false);
    }
    std::fs::rename(&staged.path, &dest).map(|_| true)
}

/// One-transaction blob-row insert; idempotent by hash (dedupe by content).
/// The final watermark re-check uses the authoritative counter table.
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
    crate::db::bump_counters(c, 0, size as i64);
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
pub async fn install_staged(
    db: &crate::db::Db,
    cfg: &crate::config::Config,
    staged: Staged,
) -> rusqlite::Result<Install> {
    let dir = cfg.data_dir.clone();
    let water = cfg.watermark_bytes;
    let cfg2 = cfg.clone();
    let hash = staged.hash;
    let size = staged.size;
    let now = crate::store::reaper::now();

    let outcome = match db
        .write(move |c: &rusqlite::Connection| -> rusqlite::Result<Install> {
            let (ev, bl) = crate::db::live_bytes(c);
            if (ev + bl + size as i64) as u64 > water {
                crate::store::reaper::evict_pass(c, &cfg2);
                let (ev2, bl2) = crate::db::live_bytes(c);
                if (ev2 + bl2 + size as i64) as u64 > water {
                    // cannot free enough — the insert below will refuse
                }
            }
            let r = insert_blob_row(c, &hash, size, now, water)?;
            if r == BlobInsertResult::WatermarkFull {
                return Ok(Install::Refused);
            }
            let _ = c.execute(
                "UPDATE blobs SET ever_attached=1 WHERE hash=?1 AND EXISTS(SELECT 1 FROM refs WHERE blob_hash=?1)",
                rusqlite::params![&hash],
            )?;
            Ok(if r == BlobInsertResult::Inserted { Install::Fresh } else { Install::Deduped })
        })
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            // The row was not committed: never leave the temp file behind.
            staged.discard();
            return Err(e);
        }
    };

    match outcome {
        Install::Fresh => {
            if let Err(e) = materialize(&dir, &staged) {
                tracing::error!("materialize {}: {e}", staged.hash_hex);
            }
        }
        Install::Deduped => {
            // Existing wins, but if its file vanished the staged bytes heal it.
            if let Err(e) = materialize(&dir, &staged) {
                tracing::error!("materialize {}: {e}", staged.hash_hex);
            }
        }
        Install::Refused => {
            staged.discard();
        }
    }
    Ok(outcome)
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
pub fn delete_blob(c: &rusqlite::Connection, hash: &[u8; 32], data_dir: &Path) -> rusqlite::Result<i64> {
    let size: i64 = c.query_row("SELECT size FROM blobs WHERE hash = ?1", [hash], |r| r.get(0))?;
    let n = c.execute("DELETE FROM blobs WHERE hash = ?1", [hash])?;
    if n == 0 {
        return Ok(0);
    }
    c.execute("DELETE FROM refs WHERE blob_hash = ?1", [hash])?;
    crate::db::bump_counters(c, 0, -size);
    let _ = std::fs::remove_file(blob_path(data_dir, &hex::encode(hash)));
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
        crate::db::bump_counters(c, -size, 0);
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
        let freed = delete_blob(c, h, data_dir)?;
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
        };

        let outcome = install_staged(&db, &cfg, staged).await.unwrap();
        assert_eq!(outcome, Install::Refused);
        assert!(!path.exists(), "refused upload left its temp file behind");

        let rows: i64 = db
            .read(|c| c.query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0)).unwrap())
            .await;
        assert_eq!(rows, 0);

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
