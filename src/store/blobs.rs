use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::error::ApiError;

/// Blob file layout: `/data/blobs/ab/<64-hex>` — one file per blob,
/// 2-hex bucket dirs, bytes verified once at store time.
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

/// A process-wide counter makes temp names unique even when two uploads start
/// in the same clock tick. `create_new` also refuses to truncate a stale file
/// left behind by a crashed process.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn create_temp_file(data_dir: &Path) -> std::io::Result<(PathBuf, std::fs::File)> {
    loop {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = tmp_dir(data_dir).join(format!("p{}-{seq}", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

#[derive(Debug)]
pub enum Abort {
    TooLarge,
    /// Upload slots or the temp-file budget are exhausted; retry shortly.
    Busy,
    /// Free disk space is below the configured safety floor.
    DiskFull,
    /// Body is not a RABTA1 encrypted container: the relay stores
    /// client-encrypted blobs only, and never learns any key.
    NotEncrypted,
    Io(String),
}

impl From<Abort> for ApiError {
    fn from(a: Abort) -> Self {
        match a {
            Abort::TooLarge => ApiError::too_large("single blob exceeds 0.1% of STORAGE"),
            Abort::Busy => ApiError::busy(),
            Abort::DiskFull => ApiError::disk_full(),
            Abort::NotEncrypted => ApiError::blob_not_encrypted(),
            Abort::Io(m) => ApiError::internal(m),
        }
    }
}

// ---------------------------------------------------------------------------
// Blob wire format: the only shape the relay accepts. Clients encrypt
// end-to-end (AEAD under a key the relay never sees) and upload the wrapped
// container; the relay validates shape, never content.
//
//   "RABTA1" | ver | salt(16) | ciphertext(min 25) | tag(16)
//
// The hash address stays SHA-256 over the wrapped bytes, so dedup, Range,
// ETag and the reaper are unchanged.
// ---------------------------------------------------------------------------
pub const BLOB_MAGIC: [u8; 6] = *b"RABTA1";
pub const BLOB_WIRE_VERSION: u8 = 1;
pub const BLOB_WIRE_SALT_LEN: usize = 16;
pub const BLOB_WIRE_TAG_LEN: usize = 16;
pub const BLOB_WIRE_MIN_PAYLOAD: usize = 25;
pub const BLOB_WIRE_HEADER_LEN: usize = BLOB_MAGIC.len() + 1 + BLOB_WIRE_SALT_LEN;
pub const BLOB_WIRE_MIN_LEN: usize =
    BLOB_WIRE_HEADER_LEN + BLOB_WIRE_MIN_PAYLOAD + BLOB_WIRE_TAG_LEN;
/// Entropy screen on the body: uncompressed plaintexts (text, BMP, RAW)
/// fail it; real ciphertext and compressed media pass. Best-effort.
const WIRE_ENTROPY_SAMPLE: usize = 4096;
const WIRE_ENTROPY_FLOOR_BITS: f64 = 5.5;
const WIRE_ENTROPY_MIN_SAMPLE: usize = 256;

/// Streaming validator: checks the magic + version as soon as the first
/// bytes arrive (so a plaintext body is cut off before it is received),
/// then screens the entropy of the first payload bytes. Inspection only —
/// every byte still goes to the file and the hash.
pub struct WireCheck {
    header: [u8; BLOB_WIRE_HEADER_LEN],
    header_filled: usize,
    entropy_sample: [u8; WIRE_ENTROPY_SAMPLE],
    entropy_len: usize,
    entropy_done: bool,
}

impl std::fmt::Debug for WireCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireCheck")
            .field("header_filled", &self.header_filled)
            .field("entropy_len", &self.entropy_len)
            .finish()
    }
}

impl WireCheck {
    pub fn new() -> Self {
        Self {
            header: [0u8; BLOB_WIRE_HEADER_LEN],
            header_filled: 0,
            entropy_sample: [0u8; WIRE_ENTROPY_SAMPLE],
            entropy_len: 0,
            entropy_done: false,
        }
    }

    /// Inspect one chunk. Returns `NotEncrypted` the moment the header is
    /// bad; every byte still belongs to the file and the hash.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), Abort> {
        if self.header_filled < BLOB_WIRE_HEADER_LEN {
            let take = (BLOB_WIRE_HEADER_LEN - self.header_filled).min(chunk.len());
            self.header[self.header_filled..self.header_filled + take]
                .copy_from_slice(&chunk[..take]);
            self.header_filled += take;
            if self.header_filled > BLOB_MAGIC.len() {
                if self.header[..6] != BLOB_MAGIC {
                    return Err(Abort::NotEncrypted);
                }
                if self.header[6] != BLOB_WIRE_VERSION {
                    return Err(Abort::NotEncrypted);
                }
            }
        }
        if !self.entropy_done {
            let take = (WIRE_ENTROPY_SAMPLE - self.entropy_len).min(chunk.len());
            self.entropy_sample[self.entropy_len..self.entropy_len + take]
                .copy_from_slice(&chunk[..take]);
            self.entropy_len += take;
            if self.entropy_len == WIRE_ENTROPY_SAMPLE {
                self.entropy_done = true;
            }
        }
        Ok(())
    }

    /// Final shape gate: minimum length + payload entropy.
    pub fn finish(&self, total_len: u64) -> Result<(), Abort> {
        if self.header_filled < BLOB_WIRE_HEADER_LEN || total_len < BLOB_WIRE_MIN_LEN as u64 {
            return Err(Abort::NotEncrypted);
        }
        let sample = &self.entropy_sample[..self.entropy_len];
        if sample.len() >= WIRE_ENTROPY_MIN_SAMPLE {
            let n = sample.len() as f64;
            if shannon_bits(sample, n) < WIRE_ENTROPY_FLOOR_BITS {
                return Err(Abort::NotEncrypted);
            }
        }
        Ok(())
    }
}

fn shannon_bits(sample: &[u8], n: f64) -> f64 {
    let mut freq = [0u32; 256];
    for &b in sample {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|f| **f > 0)
        .map(|f| {
            let p = *f as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Wrap into a valid RABTA1 container (tests and harnesses). The payload is
/// deterministic pseudo-random: real containers are ciphertext-like, so the
/// entropy screen passes regardless of the body bytes.
#[cfg(test)]
pub(crate) fn wire_wrap(body: &[u8]) -> Vec<u8> {
    let payload_len = body.len().max(BLOB_WIRE_MIN_PAYLOAD);
    let mut out = Vec::with_capacity(BLOB_WIRE_HEADER_LEN + payload_len + BLOB_WIRE_TAG_LEN);
    out.extend_from_slice(&BLOB_MAGIC);
    out.push(BLOB_WIRE_VERSION);
    let mut state = 0x9E3779B97F4A7C15u64 ^ (body.len() as u64);
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..BLOB_WIRE_SALT_LEN + payload_len + BLOB_WIRE_TAG_LEN {
        out.push(next() as u8);
    }
    out
}

/// Authoritative full-shape check for a fully-staged file (covers blobs a
/// peer's worker downloaded as well as local uploads).
pub fn validate_wire_file(path: &Path) -> Result<(), Abort> {
    use std::io::Read;
    let meta = std::fs::metadata(path).map_err(|e| Abort::Io(e.to_string()))?;
    if meta.len() < BLOB_WIRE_MIN_LEN as u64 {
        return Err(Abort::NotEncrypted);
    }
    let mut f = std::fs::File::open(path).map_err(|e| Abort::Io(e.to_string()))?;
    let mut head = [0u8; BLOB_WIRE_HEADER_LEN];
    f.read_exact(&mut head)
        .map_err(|e| Abort::Io(e.to_string()))?;
    if head[..6] != BLOB_MAGIC || head[6] != BLOB_WIRE_VERSION {
        return Err(Abort::NotEncrypted);
    }
    let sample_len = WIRE_ENTROPY_SAMPLE.min((meta.len() as usize) - BLOB_WIRE_HEADER_LEN);
    if sample_len >= WIRE_ENTROPY_MIN_SAMPLE {
        let mut sample = vec![0u8; sample_len];
        f.read_exact(&mut sample)
            .map_err(|e| Abort::Io(e.to_string()))?;
        if shannon_bits(&sample, sample_len as f64) < WIRE_ENTROPY_FLOOR_BITS {
            return Err(Abort::NotEncrypted);
        }
    }
    Ok(())
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
        // Temp files may use at most half of the blob admission watermark, so
        // a burst of uploads cannot consume the space reserved for committed
        // data. The floor keeps at least a small amount of disk free for the
        // DB/WAL and the operator.
        let water = cfg.watermark_bytes().max(1);
        let tmp_budget = (water / 2).max(16 * 1024 * 1024).min(water);
        Arc::new(UploadGovernor {
            slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UPLOADS)),
            inflight: AtomicI64::new(0),
            tmp_budget: tmp_budget.min(i64::MAX as u64) as i64,
            free_floor: cfg.free_floor_bytes(),
        })
    }

    pub fn inflight_bytes(&self) -> i64 {
        self.inflight.load(Ordering::Relaxed)
    }

    async fn acquire(self: &Arc<Self>) -> Result<UploadPermit, Abort> {
        let slot =
            tokio::time::timeout(UPLOAD_SLOT_TIMEOUT, Arc::clone(&self.slots).acquire_owned())
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
    /// Reserve `n` bytes against the process-wide temp budget. Released
    /// automatically when the permit drops. Committed admission is decided
    /// later, in the install transaction, against the combined budget when the
    /// blob is already claimed.
    fn try_reserve(&mut self, n: u64) -> Result<(), Abort> {
        let n = i64::try_from(n).map_err(|_| Abort::TooLarge)?;
        loop {
            let current = self.governor.inflight.load(Ordering::Acquire);
            let next = current.saturating_add(n);
            if next > self.governor.tmp_budget {
                return Err(Abort::Busy);
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
            self.governor
                .inflight
                .fetch_sub(self.reserved, Ordering::AcqRel);
        }
    }
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

/// The destination every blob write streams through: temp file + incremental
/// sha256 in one pass, caps enforced
/// *during* the stream.
#[derive(Debug)]
pub struct BlobSink {
    file: Option<std::fs::File>,
    hasher: Sha256,
    written: u64,
    max_single: u64,
    path: PathBuf,
    permit: Option<UploadPermit>,
    wire: WireCheck,
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
    pub fn new(hash: [u8; 32], size: u64, path: PathBuf) -> Self {
        Self {
            hash_hex: hex::encode(hash),
            hash,
            size,
            path,
            permit: None,
        }
    }

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
    /// Start one upload stream. A slot bounds concurrency and the process-wide
    /// temp budget bounds staged bytes; whether a claimed blob fits `STORAGE` is
    /// decided by `install_staged` inside the writer transaction, so a full
    /// store can still accept a stream that evicts a cold blob.
    pub async fn start(
        gov: &Arc<UploadGovernor>,
        data_dir: &Path,
        max_single: u64,
    ) -> Result<BlobSink, Abort> {
        if matches!(
            crate::config::free_bytes_opt(data_dir),
            Some(free) if free < gov.free_floor
        ) {
            return Err(Abort::DiskFull);
        }
        let permit = gov.acquire().await?;
        let (path, file) = create_temp_file(data_dir)
            .map_err(|e| Abort::Io(format!("cannot create temp file: {e}")))?;
        Ok(BlobSink {
            file: Some(file),
            hasher: Sha256::new(),
            written: 0,
            max_single,
            path,
            permit: Some(permit),
            wire: WireCheck::new(),
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
        // Container shape is checked before the chunk is written anywhere:
        // a plaintext body is cut off at the first bytes it arrives.
        self.wire.push(chunk)?;
        if let Some(permit) = self.permit.as_mut() {
            permit.try_reserve(chunk.len() as u64)?;
        } else {
            return Err(Abort::Io("sink permit already released".into()));
        }
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
        if let Err(a) = self.wire.finish(self.written) {
            self.done = true;
            let _ = std::fs::remove_file(&self.path);
            return Err(a);
        }
        let file = self
            .file
            .take()
            .ok_or_else(|| Abort::Io("sink file already closed".into()))?;
        if let Err(e) = file.sync_all() {
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

/// Whether a live event currently claims this blob.
pub fn blob_is_claimed(c: &rusqlite::Connection, hash: &[u8; 32]) -> rusqlite::Result<bool> {
    c.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM blob_refs r
             JOIN events e ON e.id = r.event_id
            WHERE r.hash = ?1)",
        [hash],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n != 0)
}

/// Live blobs with no live event reference, as `(count, bytes)`. Expired rows
/// are included until the reaper removes them.
pub fn unclaimed_stats(c: &rusqlite::Connection) -> rusqlite::Result<(i64, i64)> {
    c.query_row(
        "SELECT COUNT(*), COALESCE(SUM(b.size), 0)
           FROM blobs b
          WHERE NOT EXISTS (
                SELECT 1 FROM blob_refs r
                  JOIN events e ON e.id = r.event_id
                 WHERE r.hash = b.hash
            )",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
}

/// Blob-row insert; idempotent by hash (dedupe by content). Must run inside
/// the caller's transaction so the row and its counter move together. The
/// final watermark re-check uses the authoritative counter table.
///
/// A duplicate only refreshes access metadata and re-derives expiry from the
/// current event references; it can never extend an unclaimed blob past its
/// 6-hour window.
pub fn insert_blob_row(
    c: &rusqlite::Connection,
    hash: &[u8; 32],
    size: u64,
    stored_at: i64,
    expires_at: i64,
    store_watermark: u64,
) -> rusqlite::Result<BlobInsertResult> {
    let exists: i64 = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
        [hash],
        |r| r.get(0),
    )?;
    if exists == 1 {
        c.execute(
            "UPDATE blobs SET last_access_at = MAX(last_access_at, ?2) WHERE hash = ?1",
            rusqlite::params![hash, stored_at],
        )?;
        refresh_blob_expiry(c, hash)?;
        return Ok(BlobInsertResult::Deduped);
    }

    // Unclaimed uploads are outside the budget: they live in the 6-hour
    // window and only the disk free floor applies. A blob already claimed by
    // an event is charged and must fit the combined budget.
    let claimed = blob_is_claimed(c, hash)?;
    if claimed && crate::db::used_bytes(c).max(0) as u64 + size > store_watermark {
        return Ok(BlobInsertResult::WatermarkFull);
    }

    c.execute(
        "INSERT INTO blobs(hash, size, stored_at, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![hash, size as i64, stored_at, expires_at],
    )?;
    // An event may already reference this hash (uploaded out of order), in
    // which case the blob inherits that event's expiry immediately.
    refresh_blob_expiry(c, hash)?;
    crate::db::bump_counters(c, 0, size as i64, if claimed { size as i64 } else { 0 })?;
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
    /// Battery below the ingress floor; regen restores admission.
    Quota {
        retry_after: u64,
    },
    /// Staged bytes are not a RABTA1 encrypted container.
    NotEncrypted,
}

/// Install a staged temp file: transactional accept-or-refuse + file move.
///
/// Admission and any eviction it triggers run in the same transaction as the
/// blob row, so a failed insert rolls the eviction back.
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
    battery_cost: f64,
) -> rusqlite::Result<Install> {
    let (outcome, leftover) = install_staged_keep(db, cfg, staged, battery_cost).await?;
    if let Some(staged) = leftover {
        staged.discard();
    }
    Ok(outcome)
}

/// Like `install_staged`, but returns the staged file when admission is
/// refused so the caller can stream it through without caching it.
pub async fn install_staged_keep(
    db: &crate::db::Db,
    cfg: &crate::config::Config,
    staged: Staged,
    battery_cost: f64,
) -> rusqlite::Result<(Install, Option<Staged>)> {
    let dir = cfg.data_dir.clone();
    let water = cfg.watermark_bytes();
    let cfg2 = cfg.clone();
    let hash = staged.hash;
    let size = staged.size;
    let now = crate::store::reaper::now();
    let expires_at = now.saturating_add(crate::db::BLOB_UNCLAIMED_TTL_SECONDS);

    db.write(
        move |c: &rusqlite::Connection| -> rusqlite::Result<(Install, Option<Staged>)> {
            let tx = c.unchecked_transaction()?;
            let mut unlinks = UnlinkQueue::new();

            // A duplicate install adds no bytes: never evict for a retry.
            let exists: i64 = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                [&hash],
                |r| r.get(0),
            )?;
            let mut unclaimed_eviction = UnclaimedEviction::default();
            if exists == 0 {
                // The relay stores client-encrypted containers only. The
                // upload door checks the stream as bytes arrive; this is the
                // authoritative check on the staged file (covers blobs a
                // malicious peer's worker downloaded).
                if validate_wire_file(&staged.path).is_err() {
                    drop(tx);
                    return Ok((Install::NotEncrypted, Some(staged)));
                }
                // A duplicate adds no bytes and pays no battery; new
                // bytes pay before any eviction work happens. Charging
                // inside the transaction means a later rollback (no
                // room, watermark full, materialize failure) refunds it.
                if battery_cost > 0.0 {
                    match crate::sync::battery::reserve_battery(
                        &tx,
                        battery_cost,
                        now,
                        crate::sync::battery::SYNC_BATTERY_MAX,
                        cfg2.battery_regen_per_sec,
                    ) {
                        Ok(_) => {}
                        Err(retry) => {
                            drop(tx);
                            return Ok((Install::Quota { retry_after: retry }, Some(staged)));
                        }
                    }
                }
                let claimed = blob_is_claimed(&tx, &hash)?;
                if claimed {
                    // Claimed uploads are charged to the combined budget.
                    if crate::store::reaper::blob_pressure_check(
                        &tx,
                        &cfg2,
                        size,
                        claimed,
                        &mut unlinks,
                    )
                    .is_err()
                    {
                        drop(tx); // rollback any eviction
                        return Ok((Install::Refused, Some(staged)));
                    }
                } else {
                    // Unclaimed uploads are outside the combined budget but
                    // share a separate byte ceiling. Make room by
                    // evicting the oldest unclaimed rows.
                    match trim_unclaimed(&tx, &cfg2, size, &mut unlinks)? {
                        Some(ev) => unclaimed_eviction = ev,
                        None => {
                            drop(tx); // rollback any eviction
                            return Ok((Install::Refused, Some(staged)));
                        }
                    }
                }
            }
            let r = insert_blob_row(&tx, &hash, size, now, expires_at, water)?;
            if r == BlobInsertResult::WatermarkFull {
                drop(tx); // rollback any eviction
                return Ok((Install::Refused, Some(staged)));
            }
            let moved = match materialize(&dir, &staged) {
                Ok(moved) => moved,
                Err(e) => {
                    tracing::error!("materialize {}: {e}", staged.hash_hex);
                    drop(tx); // rollback the row: never publish a row without bytes
                    return Ok((Install::Refused, Some(staged)));
                }
            };
            let _ = tx.execute("DELETE FROM sync_blob_queue WHERE hash = ?1", [&hash[..]]);
            if let Err(e) = tx.commit() {
                if moved && r == BlobInsertResult::Inserted {
                    let _ = std::fs::remove_file(blob_path(&dir, &hex::encode(hash)));
                }
                return Err(e);
            }
            // The row is durable; now it is safe to unlink evicted files.
            unlinks.flush();
            if unclaimed_eviction.blobs > 0 {
                crate::store::reaper::record_unclaimed_eviction(
                    unclaimed_eviction.blobs,
                    unclaimed_eviction.bytes,
                );
            }
            let outcome = if r == BlobInsertResult::Inserted {
                Install::Fresh
            } else {
                Install::Deduped
            };
            Ok((outcome, None))
        },
    )
    .await
}

/// Remove one blob row + its file. Returns freed bytes.
/// File removal is immediate; transactional callers use `delete_blob_with`
/// and flush the queue only after commit.
pub fn delete_blob(
    c: &rusqlite::Connection,
    hash: &[u8; 32],
    data_dir: &Path,
) -> rusqlite::Result<i64> {
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
    let size: i64 = c.query_row("SELECT size FROM blobs WHERE hash = ?1", [hash], |r| {
        r.get(0)
    })?;
    let claimed = blob_is_claimed(c, hash)?;
    let n = c.execute("DELETE FROM blobs WHERE hash = ?1", [hash])?;
    if n == 0 {
        return Ok(0);
    }
    crate::db::bump_counters(c, 0, -size, if claimed { -size } else { 0 })?;
    unlinks.push(blob_path(data_dir, &hex::encode(hash)));
    Ok(size)
}

/// Unclaimed rows removed to satisfy the unclaimed caps.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnclaimedEviction {
    pub blobs: u64,
    pub bytes: u64,
}

/// Evict the coldest unclaimed blobs until one more `incoming`-byte blob fits
/// both the byte cap and the blob-count cap (the reaper sweep passes
/// `incoming = 0` and enforces the caps as-is). Coldness is the effective
/// last touch, `MAX(stored_at, last_access_at)`: a never-read blob ranks by
/// upload time, a recently read one is protected even if uploaded earlier;
/// equal ages prefer the lower `access_count` (least-read evicted first).
/// `None` means the incoming blob cannot fit the byte cap even after
/// clearing every unclaimed row. File removals are queued.
pub fn trim_unclaimed(
    c: &rusqlite::Connection,
    cfg: &crate::config::Config,
    incoming: u64,
    unlinks: &mut UnlinkQueue,
) -> rusqlite::Result<Option<UnclaimedEviction>> {
    let (count, bytes) = unclaimed_stats(c)?;
    let mut bytes = bytes.max(0) as u64;
    let mut count = count.max(0) as u64;
    let mut out = UnclaimedEviction::default();

    if incoming > cfg.unclaimed_limit_bytes {
        return Ok(None);
    }
    // One upload occupies one row; the sweep passes incoming = 0. Sound
    // because every real upload is at least 1 byte: the PUT door refuses
    // empty bodies (blobs_api::stage_body) and sync refuses empty peer
    // transfers (blob::download_blob).
    let incoming_rows = u64::from(incoming > 0);
    let fits = |bytes: u64, count: u64| {
        bytes.saturating_add(incoming) <= cfg.unclaimed_limit_bytes
            && count + incoming_rows <= cfg.max_unclaimed_blobs
    };
    if fits(bytes, count) {
        return Ok(Some(out));
    }

    let mut hashes: Vec<[u8; 32]> = Vec::new();
    {
        let mut stmt = c.prepare(
            "SELECT b.hash FROM blobs b
              WHERE NOT EXISTS (
                    SELECT 1 FROM blob_refs r
                      JOIN events e ON e.id = r.event_id
                     WHERE r.hash = b.hash
                )
              ORDER BY MAX(b.stored_at, b.last_access_at) ASC,
                       b.access_count ASC,
                       b.stored_at ASC,
                       b.hash ASC",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let raw: Vec<u8> = row.get(0)?;
            if let Ok(hash) = raw.try_into() {
                hashes.push(hash);
            }
        }
    }

    for hash in hashes {
        if fits(bytes, count) {
            break;
        }
        let freed = delete_blob_with(c, &hash, &cfg.data_dir, unlinks)?;
        if freed <= 0 {
            continue;
        }
        bytes = bytes.saturating_sub(freed as u64);
        count = count.saturating_sub(1);
        out.blobs += 1;
        out.bytes = out.bytes.saturating_add(freed as u64);
    }

    if fits(bytes, count) {
        Ok(Some(out))
    } else {
        Ok(None)
    }
}

/// Blob expiry pass — deletes every live blob whose derived deadline has
/// passed. The deadline already accounts for event claims; this pass only
/// reads `expires_at`.
/// Called after the event sweep and after every eviction pass.
pub fn blob_pass(
    c: &rusqlite::Connection,
    now: i64,
    data_dir: &Path,
) -> rusqlite::Result<BlobPassReport> {
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
    let mut report = BlobPassReport::default();

    {
        let sql = "SELECT hash, size FROM blobs WHERE expires_at <= ?1";
        let mut stmt = c.prepare(sql)?;
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

/// Pressure-only reclaim for the combined budget. Only blobs claimed by a
/// live event are charged, so only they are candidates here. Unclaimed blobs
/// expire through the 6-hour sweep instead.
///
/// A blob claimed by any live event matching a `POLICY` rule is never a
/// victim, even if an unprotected event also references it.
///
/// Candidates are tiered so cold data leaves first, and inside a tier the
/// **largest blob goes first** (fewest deletions per byte freed). Tiers:
///
///   0. deadline already passed            (housekeeping, should be gone)
///   1. never read and past the grace     (uploaded, never fetched)
///   2. idle at least a day               (cold)
///   3. idle at least an hour             (cooling)
///   4. everything else                   (active; last resort)
///
/// Ties inside a tier fall back to least-recently-touched, then hash, so the
/// victim list is deterministic. Deletion stops as soon as charged usage is at
/// or below `target_bytes`.
pub fn blob_pressure_pass_with(
    c: &rusqlite::Connection,
    now: i64,
    target_bytes: i64,
    data_dir: &Path,
    unlinks: &mut UnlinkQueue,
    policy: &crate::store::policy::PolicyRules,
) -> rusqlite::Result<BlobPassReport> {
    let mut report = BlobPassReport::default();
    let mut live = crate::db::used_bytes(c);
    if live <= target_bytes {
        return Ok(report);
    }

    let mut rule_params: Vec<rusqlite::types::Value> = Vec::new();
    // Numbered holes from `?5` on: a bare `?` would collide with `?1`, which
    // first appears later in the ORDER BY.
    let pinned = match policy.rule_clause("pe", true, 5) {
        None => String::new(),
        Some((frag, params)) => {
            rule_params = params;
            format!(
                " AND NOT EXISTS (
                     SELECT 1 FROM blob_refs pr
                       JOIN events pe ON pe.id = pr.event_id
                      WHERE pr.hash = blobs.hash
                        AND ({frag})
                   )"
            )
        }
    };

    let mut victims: Vec<([u8; 32], i64)> = Vec::new();
    {
        let sql = format!(
            "SELECT hash, size FROM blobs
             WHERE EXISTS (
                 SELECT 1 FROM blob_refs r
                   JOIN events e ON e.id = r.event_id
                  WHERE r.hash = blobs.hash
               ){pinned}
             ORDER BY
               CASE
                 WHEN expires_at <= ?1 THEN 0
                 WHEN last_access_at = 0
                      AND ?1 - stored_at >= ?2 THEN 1
                 WHEN ?1 - MAX(stored_at, last_access_at) >= ?3 THEN 2
                 WHEN ?1 - MAX(stored_at, last_access_at) >= ?4 THEN 3
                 ELSE 4
               END ASC,
               size DESC,
               MAX(stored_at, last_access_at) ASC,
               hash ASC"
        );
        let grace = crate::db::BLOB_GRACE_SECONDS;
        let cold = crate::db::BLOB_COLD_AFTER_SECONDS;
        let active = crate::db::BLOB_ACTIVE_WINDOW_SECONDS;
        let mut binds: Vec<&dyn rusqlite::ToSql> = vec![&now, &grace, &cold, &active];
        for value in &rule_params {
            binds.push(value);
        }
        let mut stmt = c.prepare(&sql)?;
        let mut rows = stmt.query(binds.as_slice())?;
        while let Some(r) = rows.next()? {
            let hash: Vec<u8> = r.get(0)?;
            let size: i64 = r.get(1)?;
            let mut h = [0u8; 32];
            h.copy_from_slice(&hash);
            victims.push((h, size));
        }
    }

    for (h, _size) in victims {
        if live <= target_bytes {
            break;
        }
        let freed = delete_blob_with(c, &h, data_dir, unlinks)?;
        report.blob_bytes += freed;
        report.blobs_removed += 1;
        live = crate::db::used_bytes(c);
    }
    Ok(report)
}

/// Re-derive one blob's deadline from its live event references.
/// Claimed blobs expire with the latest referencing event; unclaimed blobs
/// fall back to 6 hours after their first upload. Call after any change to
/// `blob_refs`.
pub fn refresh_blob_expiry(c: &rusqlite::Connection, hash: &[u8; 32]) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE blobs
         SET expires_at = COALESCE(
             (SELECT MAX(e.expires_at)
                FROM blob_refs r
                JOIN events e ON e.id = r.event_id
               WHERE r.hash = ?1),
             stored_at + ?2)
         WHERE hash = ?1",
        rusqlite::params![hash, crate::db::BLOB_UNCLAIMED_TTL_SECONDS],
    )?;
    Ok(())
}

/// Boot-time repair: re-derive every blob deadline from the refs table.
pub fn reconcile_blob_expiry(c: &rusqlite::Connection) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE blobs
         SET expires_at = COALESCE(
             (SELECT MAX(e.expires_at)
                FROM blob_refs r
                JOIN events e ON e.id = r.event_id
               WHERE r.hash = blobs.hash),
             blobs.stored_at + ?1)",
        [crate::db::BLOB_UNCLAIMED_TTL_SECONDS],
    )?;
    Ok(())
}

/// Record a successful read (`GET` 200/206, `HEAD` 200, `GET` 304) for
/// eviction ordering. Reads never extend a blob's deadline. Throttled by
/// `BLOB_REFRESH_SECONDS` so a hot blob costs at most one writer transaction
/// per hour. A miss or expired row is a no-op.
pub fn touch_blob(c: &rusqlite::Connection, hash: &[u8; 32], now: i64) -> rusqlite::Result<bool> {
    let n = c.execute(
        "UPDATE blobs
         SET last_access_at = ?2,
             access_count = access_count + 1
         WHERE hash = ?1
           AND expires_at > ?2
           AND last_access_at <= ?2 - ?3",
        rusqlite::params![hash, now, crate::db::BLOB_REFRESH_SECONDS],
    )?;
    Ok(n > 0)
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
        let Ok(modified) = meta.modified() else {
            continue;
        };
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
                let Ok(files) = std::fs::read_dir(bucket.path()) else {
                    continue;
                };
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
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                            [&id],
                            |r| r.get(0),
                        )
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
    use crate::sync::battery::SYNC_BATTERY_MAX;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rabta-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_cfg(dir: &std::path::Path) -> crate::config::Config {
        crate::config::Config::test_cfg(dir.to_path_buf(), 100)
    }

    fn staged_file(dir: &std::path::Path, hash: [u8; 32], body: &[u8], tag: &str) -> Staged {
        let wrapped = wire_wrap(body);
        let path = tmp_dir(dir).join(tag);
        std::fs::write(&path, &wrapped).unwrap();
        Staged {
            hash_hex: hex::encode(hash),
            hash,
            size: wrapped.len() as u64,
            path,
            permit: None,
        }
    }

    async fn seed_event(db: &Db, id: [u8; 32], size: i64) {
        db.write(move |c: &rusqlite::Connection| -> rusqlite::Result<()> {
            c.execute(
                "INSERT INTO events(id,owner,collection,created_at,expires_at,data,size)
                 VALUES (?1,?2,'c',1,9999999999,x'7b7d',?3)",
                rusqlite::params![&id[..], &[0u8; 32], size],
            )?;
            crate::db::bump_counters(c, size, 0, 0)?;
            Ok(())
        })
        .await
        .unwrap();
    }

    /// Insert a live blob plus the event that claims it, as an upload followed
    /// by a publish would.
    async fn seed_claimed_blob(
        db: &Db,
        hash: [u8; 32],
        event_id: [u8; 32],
        size: i64,
        stored_at: i64,
    ) {
        db.write(move |c: &rusqlite::Connection| -> rusqlite::Result<()> {
            c.execute(
                "INSERT INTO events(id,owner,collection,created_at,expires_at,data,size)
                 VALUES (?1,?2,'c',1,9999999999,x'7b7d',0)",
                rusqlite::params![&event_id[..], &[0u8; 32][..]],
            )?;
            c.execute(
                "INSERT INTO blobs(hash,size,stored_at,expires_at)
                 VALUES (?1,?2,?3,9999999999)",
                rusqlite::params![&hash[..], size, stored_at],
            )?;
            c.execute(
                "INSERT INTO blob_refs(hash,event_id) VALUES (?1,?2)",
                rusqlite::params![&hash[..], &event_id[..]],
            )?;
            crate::db::bump_counters(c, 0, size, size)
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn blob_install_charges_battery_duplicates_are_free_quota_refuses() {
        let dir = temp_dir("blob-battery-charge");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);

        async fn battery(db: &Db) -> f64 {
            db.read(|c| {
                c.query_row("SELECT battery FROM sync_meta WHERE id = 1", [], |r| {
                    r.get(0)
                })
                .unwrap()
            })
            .await
        }

        // Fresh install pays the ingress price.
        let a = staged_file(&dir, [7u8; 32], b"battery-a", "a");
        assert_eq!(
            install_staged(&db, &cfg, a, 100.0).await.unwrap(),
            Install::Fresh
        );
        let after_first: f64 = battery(&db).await;
        assert!((after_first - (SYNC_BATTERY_MAX - 100.0)).abs() < 1.0);

        // The same bytes again: free.
        let dup = staged_file(&dir, [7u8; 32], b"battery-a", "a2");
        assert_eq!(
            install_staged(&db, &cfg, dup, 100.0).await.unwrap(),
            Install::Deduped
        );
        let after_dup: f64 = battery(&db).await;
        assert!((after_dup - after_first).abs() < 1.0);

        // Drained tank: refused with a regen wait, nothing installed.
        db.write(|c| {
            c.execute("UPDATE sync_meta SET battery = 50.0", [])
                .unwrap();
            Ok::<(), rusqlite::Error>(())
        })
        .await
        .unwrap();
        let b = staged_file(&dir, [8u8; 32], b"battery-b", "b");
        match install_staged(&db, &cfg, b, 100.0).await.unwrap() {
            Install::Quota { retry_after } => assert!(retry_after >= 1),
            other => panic!("expected quota refusal, got {other:?}"),
        }
        let exists: i64 = db
            .read(|c| {
                c.query_row(
                    "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                    [[8u8; 32]],
                    |r| r.get(0),
                )
                .unwrap()
            })
            .await;
        assert_eq!(exists, 0);
    }

    #[tokio::test]
    async fn wire_container_is_accepted_and_hashed_over_wrapped_bytes() {
        use sha2::{Digest, Sha256};
        let dir = temp_dir("blob-wire-accept");
        init_dirs(&dir).unwrap();
        let gov = test_governor(10_000, 0);

        let mut sink = BlobSink::start(&gov, &dir, 10_000).await.unwrap();
        // Split the container across pushes to exercise chunk boundaries.
        let wrapped = wire_wrap(&[0xABu8; 512]);
        sink.push(&wrapped[..10]).unwrap();
        sink.push(&wrapped[10..300]).unwrap();
        sink.push(&wrapped[300..]).unwrap();
        let staged = sink.finish().unwrap();

        let expect: [u8; 32] = Sha256::digest(&wrapped).into();
        assert_eq!(staged.hash, expect);
        assert_eq!(staged.size as usize, wrapped.len());
        assert_eq!(staged.hash_hex, hex::encode(expect));

        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);
        let r = install_staged(&db, &cfg, staged, 0.0).await.unwrap();
        assert_eq!(r, Install::Fresh);
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn plaintext_magic_is_cut_off_at_the_first_bytes() {
        let dir = temp_dir("blob-wire-jpeg");
        init_dirs(&dir).unwrap();
        let gov = test_governor(10_000, 0);

        let mut sink = BlobSink::start(&gov, &dir, 10_000).await.unwrap();
        let jpeg: Vec<u8> = [[0xFF, 0xD8, 0xFF].as_slice(), &[0u8; 100][..]].concat();
        assert!(matches!(sink.push(&jpeg), Err(Abort::NotEncrypted)));
        sink.discard();
        assert_eq!(tmp_files(&dir), 0, "rejected upload leaked its temp file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn short_and_low_entropy_bodies_are_rejected() {
        let dir = temp_dir("blob-wire-shapes");
        init_dirs(&dir).unwrap();
        let gov = test_governor(10_000, 0);

        let container = |payload: &[u8]| {
            let mut out = Vec::new();
            out.extend_from_slice(&BLOB_MAGIC);
            out.push(BLOB_WIRE_VERSION);
            out.extend_from_slice(&[0x42u8; BLOB_WIRE_SALT_LEN]);
            out.extend_from_slice(payload);
            out.extend_from_slice(&[0x42u8; BLOB_WIRE_TAG_LEN]);
            out
        };

        // Too short: header + tag do not fit (44 bytes < 64).
        let mut sink = BlobSink::start(&gov, &dir, 10_000).await.unwrap();
        sink.push(&container(&[1u8; 5])).unwrap();
        assert!(matches!(sink.finish(), Err(Abort::NotEncrypted)));

        // Long enough but low entropy: 600 bytes of 'A' behind a real header.
        let mut sink = BlobSink::start(&gov, &dir, 10_000).await.unwrap();
        sink.push(&container(&[b'A'; 600])).unwrap();
        assert!(matches!(sink.finish(), Err(Abort::NotEncrypted)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn install_rejects_a_peer_served_plaintext_file() {
        let dir = temp_dir("blob-wire-install");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);

        let path = tmp_dir(&dir).join("peer-raw");
        std::fs::write(&path, b"plain bytes, no container").unwrap();
        let staged = Staged::new([0xEEu8; 32], 24, path.clone());

        let r = install_staged(&db, &cfg, staged, 0.0).await.unwrap();
        assert_eq!(r, Install::NotEncrypted);
        assert!(!path.exists(), "refused staged file was discarded");
        let rows: i64 = db
            .read(|c| {
                c.query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))
                    .unwrap()
            })
            .await;
        assert_eq!(rows, 0);
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unclaimed_blob_admission_never_evicts_events() {
        let dir = temp_dir("blob-local-keep-events");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);
        seed_event(&db, [9u8; 32], 90).await;

        let local = staged_file(&dir, [4u8; 32], b"0123456789", "local");
        let outcome = install_staged(&db, &cfg, local, 0.0).await.unwrap();
        assert_eq!(outcome, Install::Fresh);
        let events: i64 = db
            .read(|c| {
                c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
                    .unwrap()
            })
            .await;
        assert_eq!(
            events, 1,
            "an unclaimed upload reclaimed events from the combined budget"
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn watermark_refusal_discards_staged_file() {
        let dir = temp_dir("blob-refusal");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = crate::config::Config::test_cfg(dir.clone(), 10);

        let path = tmp_dir(&dir).join("staged");
        let bytes = wire_wrap(b"0123456789");
        std::fs::write(&path, &bytes).unwrap();
        let staged = Staged {
            hash_hex: hex::encode([7u8; 32]),
            hash: [7u8; 32],
            size: bytes.len() as u64,
            path: path.clone(),
            permit: None,
        };

        seed_event(&db, [9u8; 32], 9).await;
        // Claim the (not yet uploaded) hash so the install is charged to the
        // combined budget instead of the free 6-hour window.
        db.write(|c: &rusqlite::Connection| {
            c.execute(
                "INSERT INTO blob_refs(hash, event_id) VALUES (?1, ?2)",
                rusqlite::params![&[7u8; 32][..], &[9u8; 32][..]],
            )
        })
        .await
        .unwrap();

        let outcome = install_staged(&db, &cfg, staged, 0.0).await.unwrap();
        assert_eq!(outcome, Install::Refused);
        assert!(!path.exists(), "refused upload left its temp file behind");

        let rows: i64 = db
            .read(|c| {
                c.query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))
                    .unwrap()
            })
            .await;
        assert_eq!(rows, 0);

        let events: i64 = db
            .read(|c| {
                c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
                    .unwrap()
            })
            .await;
        assert_eq!(events, 1, "a refused blob upload reclaimed events");

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

        let outcome = install_staged(&db, &cfg, staged, 0.0).await.unwrap();
        assert_eq!(outcome, Install::Refused);
        assert!(
            !path.exists(),
            "failed materialization left its temp file behind"
        );
        let rows: i64 = db
            .read(|c| {
                c.query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))
                    .unwrap()
            })
            .await;
        assert_eq!(rows, 0, "row was published without its bytes");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn refusal_keeps_the_staged_file_for_stream_through() {
        let dir = temp_dir("blob-refusal-keep");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = crate::config::Config::test_cfg(dir.clone(), 10);

        let path = tmp_dir(&dir).join("staged");
        let bytes = wire_wrap(b"0123456789");
        std::fs::write(&path, &bytes).unwrap();
        let staged = Staged {
            hash_hex: hex::encode([7u8; 32]),
            hash: [7u8; 32],
            size: bytes.len() as u64,
            path: path.clone(),
            permit: None,
        };

        seed_event(&db, [9u8; 32], 9).await;
        db.write(|c: &rusqlite::Connection| {
            c.execute(
                "INSERT INTO blob_refs(hash, event_id) VALUES (?1, ?2)",
                rusqlite::params![&[7u8; 32][..], &[9u8; 32][..]],
            )
        })
        .await
        .unwrap();

        let (outcome, leftover) = install_staged_keep(&db, &cfg, staged, 0.0).await.unwrap();
        assert_eq!(outcome, Install::Refused);
        assert!(path.exists(), "stream-through staging was discarded");
        leftover.unwrap().discard();
        assert!(!path.exists());

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

        let first = install_staged(&db, &cfg, staged_file(&dir, hash, b"abcd", "first"), 0.0)
            .await
            .unwrap();
        assert_eq!(first, Install::Fresh);
        assert_eq!(std::fs::read(&dest).unwrap(), wire_wrap(b"abcd"));

        std::fs::remove_file(&dest).unwrap();
        let second = install_staged(&db, &cfg, staged_file(&dir, hash, b"abcd", "second"), 0.0)
            .await
            .unwrap();
        assert_eq!(second, Install::Deduped);
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            wire_wrap(b"abcd"),
            "dedupe did not heal the file"
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unclaimed_blob_expires_after_six_hours() {
        let dir = temp_dir("blob-lease");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);
        let hash = [5u8; 32];
        let dest = blob_path(&dir, &hex::encode(hash));

        let outcome = install_staged(&db, &cfg, staged_file(&dir, hash, b"abcd", "lease"), 0.0)
            .await
            .unwrap();
        assert_eq!(outcome, Install::Fresh);

        let (stored_at, expires_at): (i64, i64) = db
            .read(move |c| {
                c.query_row(
                    "SELECT stored_at, expires_at FROM blobs WHERE hash = ?1",
                    [&hash[..]],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
            })
            .await;
        assert_eq!(
            expires_at,
            stored_at + crate::db::BLOB_UNCLAIMED_TTL_SECONDS,
            "an unclaimed blob did not get the 6-hour window"
        );

        let dir2 = dir.clone();
        db.write(move |c| {
            let report = blob_pass(c, expires_at + 1, &dir2).unwrap();
            assert_eq!(report.blobs_removed, 1);
        })
        .await;
        assert!(!dest.exists(), "expired blob file survived the sweep");
        let rows: i64 = db
            .read(|c| {
                c.query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))
                    .unwrap()
            })
            .await;
        assert_eq!(rows, 0, "expired blob row survived the sweep");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn upload_after_event_claim_inherits_event_expiry() {
        let dir = temp_dir("blob-claim-late");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);
        let hash = [0x33u8; 32];
        let event_id = [0x44u8; 32];
        let now = crate::store::reaper::now();
        let event_expiry = now + 5_000;

        db.write(move |c| {
            c.execute(
                "INSERT INTO events(id, owner, collection, created_at, expires_at, data, size)
                 VALUES (?1, ?2, 'test', ?3, ?4, '{}', 2)",
                rusqlite::params![&event_id[..], &[7u8; 32][..], now, event_expiry],
            )
            .unwrap();
            c.execute(
                "INSERT INTO blob_refs(hash, event_id) VALUES (?1, ?2)",
                rusqlite::params![&hash[..], &event_id[..]],
            )
            .unwrap();
        })
        .await;

        let outcome = install_staged(&db, &cfg, staged_file(&dir, hash, b"abcd", "late"), 0.0)
            .await
            .unwrap();
        assert_eq!(outcome, Install::Fresh);

        let expires_at: i64 = db
            .read(move |c| {
                c.query_row(
                    "SELECT expires_at FROM blobs WHERE hash = ?1",
                    [&hash[..]],
                    |r| r.get(0),
                )
                .unwrap()
            })
            .await;
        assert_eq!(
            expires_at, event_expiry,
            "upload ignored an event that already claimed the hash"
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn dedupe_never_extends_an_unclaimed_blob() {
        let dir = temp_dir("blob-dedupe");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);
        let hash = [6u8; 32];

        let first = install_staged(&db, &cfg, staged_file(&dir, hash, b"abcd", "first"), 0.0)
            .await
            .unwrap();
        assert_eq!(first, Install::Fresh);

        let stored_at: i64 = db
            .read(move |c| {
                c.query_row(
                    "SELECT stored_at FROM blobs WHERE hash = ?1",
                    [&hash[..]],
                    |r| r.get(0),
                )
                .unwrap()
            })
            .await;

        let far = stored_at + crate::db::BLOB_UNCLAIMED_TTL_SECONDS + 10_000;
        db.write(move |c| {
            c.execute(
                "UPDATE blobs SET expires_at = ?1 WHERE hash = ?2",
                rusqlite::params![far, &hash[..]],
            )
            .unwrap();
        })
        .await;

        let second = install_staged(&db, &cfg, staged_file(&dir, hash, b"abcd", "second"), 0.0)
            .await
            .unwrap();
        assert_eq!(second, Install::Deduped);
        let stored: i64 = db
            .read(move |c| {
                c.query_row(
                    "SELECT expires_at FROM blobs WHERE hash = ?1",
                    [&hash[..]],
                    |r| r.get(0),
                )
                .unwrap()
            })
            .await;
        assert_eq!(
            stored,
            stored_at + crate::db::BLOB_UNCLAIMED_TTL_SECONDS,
            "re-upload extended an unclaimed blob past 6 hours"
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Never-accessed blobs outrank larger ones that are still being read.
    #[tokio::test]
    async fn unaccessed_blob_goes_before_a_larger_accessed_one() {
        let dir = temp_dir("blob-tier-unaccessed");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);
        let never_read = [0x11u8; 32];
        let read = [0x22u8; 32];

        let a = install_staged(
            &db,
            &cfg,
            staged_file(&dir, never_read, &[1u8; 15], "never"),
            0.0,
        )
        .await
        .unwrap();
        assert_eq!(a, Install::Fresh);
        let b = install_staged(&db, &cfg, staged_file(&dir, read, &[2u8; 30], "read"), 0.0)
            .await
            .unwrap();
        assert_eq!(b, Install::Fresh);

        // Only claimed blobs are charged, so both need a live reference.
        seed_event(&db, [0x31u8; 32], 0).await;
        seed_event(&db, [0x32u8; 32], 0).await;
        db.write(move |c| {
            c.execute(
                "INSERT INTO blob_refs(hash, event_id) VALUES (?1, ?2)",
                rusqlite::params![&never_read[..], &[0x31u8; 32][..]],
            )
            .unwrap();
            c.execute(
                "INSERT INTO blob_refs(hash, event_id) VALUES (?1, ?2)",
                rusqlite::params![&read[..], &[0x32u8; 32][..]],
            )
            .unwrap();
            crate::db::bump_counters(c, 0, 0, 45).unwrap();
        })
        .await;

        let now = crate::store::reaper::now();
        let dir2 = dir.clone();
        db.write(move |c| {
            // Both are old uploads; only `read` was fetched afterwards.
            c.execute(
                "UPDATE blobs SET stored_at = ?1 WHERE hash = ?2",
                rusqlite::params![now - 7200, &never_read[..]],
            )
            .unwrap();
            c.execute(
                "UPDATE blobs SET stored_at = ?1, last_access_at = ?1, access_count = 1
                 WHERE hash = ?2",
                rusqlite::params![now - 7200, &read[..]],
            )
            .unwrap();
            let mut unlinks = UnlinkQueue::new();
            // 45 charged bytes, target 35: exactly one blob must go.
            blob_pressure_pass_with(c, now, 35, &dir2, &mut unlinks, &Default::default()).unwrap();
            unlinks.flush();
        })
        .await;

        let (never_present, read_present) = db
            .read(move |c| {
                let exists = |h: &[u8; 32]| -> i64 {
                    c.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                        [&h[..]],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                (exists(&never_read), exists(&read))
            })
            .await;
        assert_eq!(never_present, 0, "unaccessed blob survived the pass");
        assert_eq!(read_present, 1, "the accessed blob was evicted first");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unclaimed_blobs_are_never_evicted_by_pressure() {
        let dir = temp_dir("blob-tier-claimed");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);
        let claimed = [0x51u8; 32];
        let unclaimed = [0x52u8; 32];

        for (hash, body, tag) in [
            (claimed, &[1u8; 30][..], "claimed"),
            (unclaimed, &[2u8; 15][..], "unclaimed"),
        ] {
            let out = install_staged(&db, &cfg, staged_file(&dir, hash, body, tag), 0.0)
                .await
                .unwrap();
            assert_eq!(out, Install::Fresh);
        }

        let now = crate::store::reaper::now();
        let event_id = [0x53u8; 32];
        let dir2 = dir.clone();
        db.write(move |c| {
            c.execute(
                "INSERT INTO events(id, owner, collection, created_at, expires_at, data, size)
                 VALUES (?1, ?2, 'test', ?3, ?4, '{}', 2)",
                rusqlite::params![&event_id[..], &[7u8; 32][..], now, now + 86_400],
            )
            .unwrap();
            c.execute(
                "INSERT INTO blob_refs(hash, event_id) VALUES (?1, ?2)",
                rusqlite::params![&claimed[..], &event_id[..]],
            )
            .unwrap();
            crate::db::bump_counters(c, 2, 30, 30).unwrap();
            crate::store::blobs::refresh_blob_expiry(c, &claimed).unwrap();

            let mut unlinks = UnlinkQueue::new();
            // Charged usage is 32 (event 2 + claimed blob 30). Target 0 forces
            // a victim; only the claimed blob is a candidate.
            blob_pressure_pass_with(c, now, 0, &dir2, &mut unlinks, &Default::default()).unwrap();
            unlinks.flush();
        })
        .await;

        let (claimed_present, unclaimed_present) = db
            .read(move |c| {
                let exists = |h: &[u8; 32]| -> i64 {
                    c.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                        [&h[..]],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                (exists(&claimed), exists(&unclaimed))
            })
            .await;
        assert_eq!(unclaimed_present, 1, "an unclaimed blob was evicted");
        assert_eq!(claimed_present, 0, "the claimed blob survived the pass");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Inside one tier the largest blob is reclaimed first.
    #[tokio::test]
    async fn biggest_blob_goes_first_inside_a_tier() {
        let dir = temp_dir("blob-tier-biggest");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);
        let small = [0x31u8; 32];
        let big = [0x32u8; 32];
        let medium = [0x33u8; 32];

        // Bodies stay >= 25 bytes so the wire-format padding (min payload)
        // keeps the wrapped sizes proportional: 74 / 84 / 79.
        for (hash, size) in [(small, 35usize), (big, 45), (medium, 40)] {
            let body = vec![7u8; size];
            let staged = staged_file(&dir, hash, &body, &hex::encode(hash));
            assert_eq!(
                install_staged(&db, &cfg, staged, 0.0).await.unwrap(),
                Install::Fresh
            );
        }

        // Claim all three so they are charged and eligible for pressure.
        for (i, hash) in [small, big, medium].into_iter().enumerate() {
            let id = [0x40u8 + i as u8; 32];
            seed_event(&db, id, 0).await;
            db.write(move |c: &rusqlite::Connection| {
                c.execute(
                    "INSERT INTO blob_refs(hash, event_id) VALUES (?1, ?2)",
                    rusqlite::params![&hash[..], &id[..]],
                )
            })
            .await
            .unwrap();
        }
        let charged: i64 = [35usize, 45, 40]
            .iter()
            .map(|size| wire_wrap(&vec![7u8; *size]).len() as i64)
            .sum();
        db.write(move |c: &rusqlite::Connection| crate::db::bump_counters(c, 0, 0, charged))
            .await
            .unwrap();

        let now = crate::store::reaper::now();
        let dir2 = dir.clone();
        // Target reaches by deleting exactly the biggest wrapped blob; all
        // three are equally cold, so size decides.
        let target = charged - wire_wrap(&[7u8; 45]).len() as i64;
        db.write(move |c| {
            c.execute(
                "UPDATE blobs SET stored_at = ?1",
                rusqlite::params![now - 7200],
            )
            .unwrap();
            let mut unlinks = UnlinkQueue::new();
            blob_pressure_pass_with(c, now, target, &dir2, &mut unlinks, &Default::default())
                .unwrap();
            unlinks.flush();
        })
        .await;

        let (s, b, m) = db
            .read(move |c| {
                let exists = |h: &[u8; 32]| -> i64 {
                    c.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                        [&h[..]],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                (exists(&small), exists(&big), exists(&medium))
            })
            .await;
        assert_eq!(b, 0, "the largest blob was not reclaimed first");
        assert_eq!(s, 1);
        assert_eq!(m, 1);

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn read_records_access_without_extending_expiry() {
        let dir = temp_dir("blob-touch");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);
        let hash = [0x41u8; 32];
        install_staged(&db, &cfg, staged_file(&dir, hash, b"abcd", "touch"), 0.0)
            .await
            .unwrap();

        let now = crate::store::reaper::now();
        let fixed_expiry = now + 10_000;
        db.write(move |c| {
            c.execute(
                "UPDATE blobs SET stored_at = ?1, expires_at = ?2, last_access_at = 0
                 WHERE hash = ?3",
                rusqlite::params![now, fixed_expiry, &hash[..]],
            )
            .unwrap();
        })
        .await;

        let first = db.write(move |c| touch_blob(c, &hash, now)).await.unwrap();
        assert!(first, "a successful read was not recorded");

        let (expires, touched, hits) = db
            .read(move |c| {
                c.query_row(
                    "SELECT expires_at, last_access_at, access_count FROM blobs WHERE hash = ?1",
                    [&hash[..]],
                    |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, i64>(2)?,
                        ))
                    },
                )
                .unwrap()
            })
            .await;
        assert_eq!(expires, fixed_expiry, "a read extended the blob deadline");
        assert_eq!(touched, now);
        assert_eq!(hits, 1);

        let throttled = db
            .write(move |c| touch_blob(c, &hash, now + 10))
            .await
            .unwrap();
        assert!(!throttled, "access tracking was not throttled");

        let later = now + crate::db::BLOB_REFRESH_SECONDS + 1;
        let renewed = db
            .write(move |c| touch_blob(c, &hash, later))
            .await
            .unwrap();
        assert!(renewed, "access tracking stayed throttled past the window");

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
    async fn staging_is_bounded_by_the_temp_budget_not_live_bytes() {
        let dir = temp_dir("blob-stage-past-watermark");
        init_dirs(&dir).unwrap();
        let gov = test_governor(1_000, 0);

        // The store may already be at its admission watermark; staging the
        // upload that will evict a cold blob must still be possible. Only the
        // install transaction decides whether it fits.
        let mut first = BlobSink::start(&gov, &dir, 100).await.unwrap();
        let body = wire_wrap(&[1u8; 61]);
        first.push(&body).unwrap();
        assert_eq!(first.written(), body.len() as u64);

        drop(first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn temp_budget_bounds_parallel_upload_bytes() {
        let dir = temp_dir("blob-temp-budget");
        init_dirs(&dir).unwrap();
        let gov = test_governor(100, 0);

        let mut first = BlobSink::start(&gov, &dir, 100).await.unwrap();
        let body = wire_wrap(&[1u8; 4]);
        first.push(&body).unwrap();

        let mut second = BlobSink::start(&gov, &dir, 100).await.unwrap();
        let other = wire_wrap(&[2u8; 10]);
        assert!(matches!(second.push(&other), Err(Abort::Busy)));
        assert_eq!(gov.inflight_bytes(), body.len() as i64);

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

        let mut sink = BlobSink::start(&gov, &dir, 100).await.unwrap();
        let body = wire_wrap(&[1u8; 10]);
        sink.push(&body).unwrap();
        assert_eq!(gov.inflight_bytes(), body.len() as i64);
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

        let mut sink = BlobSink::start(&gov, &dir, 100).await.unwrap();
        let body = wire_wrap(&[1u8; 10]);
        sink.push(&body).unwrap();
        let staged = sink.finish().unwrap();
        assert_eq!(
            gov.inflight_bytes(),
            body.len() as i64,
            "staged file lost its reservation"
        );

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

        let err = BlobSink::start(&gov, &dir, 100).await.unwrap_err();
        assert!(matches!(err, Abort::DiskFull));
        assert_eq!(tmp_files(&dir), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two uploads starting in the same clock tick must never share a temp
    /// path; `File::create` would truncate the first stream.
    #[tokio::test]
    async fn parallel_uploads_get_distinct_temp_files() {
        let dir = temp_dir("blob-tmp-unique");
        init_dirs(&dir).unwrap();
        let gov = test_governor(1_000_000, 0);

        let a = BlobSink::start(&gov, &dir, 1024).await.unwrap();
        let b = BlobSink::start(&gov, &dir, 1024).await.unwrap();

        assert_ne!(a.path, b.path, "uploads shared a temp path");
        assert!(a.path.is_file() && b.path.is_file());
        assert_eq!(tmp_files(&dir), 2);

        drop(a);
        drop(b);
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

    /// A blob claimed by a protected event is not a pressure victim, even
    /// when it sorts first. The unprotected blob goes instead.
    #[tokio::test]
    async fn blob_claimed_by_a_protected_event_survives_pressure() {
        let dir = temp_dir("blob-pinned-claim");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);

        let pinned_blob = [0xa1u8; 32];
        let loose_blob = [0xa2u8; 32];
        let pinned_owner = [0x55u8; 32];

        db.write(move |c| -> rusqlite::Result<()> {
            for (hash, id, owner) in [
                (pinned_blob, [0x61u8; 32], pinned_owner),
                (loose_blob, [0x62u8; 32], [0u8; 32]),
            ] {
                c.execute(
                    "INSERT INTO events(id, owner, collection, created_at, expires_at, data, size)
                     VALUES (?1, ?2, 'c', 1, 9999999999, x'7b7d', 10)",
                    rusqlite::params![&id[..], &owner[..]],
                )?;
                c.execute(
                    "INSERT INTO blob_refs(hash, event_id) VALUES (?1, ?2)",
                    rusqlite::params![&hash[..], &id[..]],
                )?;
                c.execute(
                    "INSERT INTO blobs(hash, size, stored_at, expires_at)
                     VALUES (?1, 20, 1, 9999999999)",
                    rusqlite::params![&hash[..]],
                )?;
            }
            // 40 charged bytes; events are uncharged here because the tier
            // sweep only looks at claimed blobs.
            crate::db::bump_counters(c, 20, 0, 40)
        })
        .await
        .unwrap();

        let policy = crate::store::policy::PolicyRules::test_owner(pinned_owner);

        let now = crate::store::reaper::now();
        let dir2 = dir.clone();
        db.write(move |c| -> rusqlite::Result<()> {
            let mut unlinks = UnlinkQueue::new();
            // 60 charged bytes; target 50: deleting the loose 20-byte blob
            // reaches it, and the protected one must not be touched.
            blob_pressure_pass_with(c, now, 50, &dir2, &mut unlinks, &policy)?;
            unlinks.flush();
            Ok(())
        })
        .await
        .unwrap();

        let (pinned_present, loose_present) = db
            .read(move |c| {
                let exists = |h: &[u8; 32]| -> i64 {
                    c.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                        [&h[..]],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                (exists(&pinned_blob), exists(&loose_blob))
            })
            .await;
        assert_eq!(pinned_present, 1, "the protected claim was evicted");
        assert_eq!(loose_present, 0, "the unprotected blob survived");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The unclaimed blob-count cap evicts the oldest orphan regardless of
    /// bytes: many small blobs cannot crowd out the staging plane.
    #[tokio::test]
    async fn unclaimed_count_cap_evicts_oldest() {
        let dir = temp_dir("blob-unclaimed-count-cap");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let mut cfg = test_cfg(&dir);
        // Byte cap out of the way; the count cap binds instead.
        cfg.unclaimed_limit_bytes = u64::MAX;
        cfg.max_unclaimed_blobs = 3;

        let a = [0x41u8; 32];
        let b = [0x42u8; 32];
        let c = [0x43u8; 32];
        let d = [0x44u8; 32];
        for (hash, body, tag) in [(a, b"aaaa", "a"), (b, b"bbbb", "b"), (c, b"cccc", "c")] {
            let out = install_staged(&db, &cfg, staged_file(&dir, hash, body, tag), 0.0)
                .await
                .unwrap();
            assert_eq!(out, Install::Fresh);
        }
        db.write(move |conn| -> rusqlite::Result<()> {
            conn.execute("UPDATE blobs SET stored_at = 10 WHERE hash = ?1", [&a[..]])?;
            conn.execute("UPDATE blobs SET stored_at = 20 WHERE hash = ?1", [&b[..]])?;
            conn.execute("UPDATE blobs SET stored_at = 30 WHERE hash = ?1", [&c[..]])?;
            Ok(())
        })
        .await
        .unwrap();

        // Three unclaimed blobs at the count cap: the fourth evicts `a`.
        let out = install_staged(&db, &cfg, staged_file(&dir, d, b"dddd", "d"), 0.0)
            .await
            .unwrap();
        assert_eq!(out, Install::Fresh);

        let (a_row, b_row, c_row, d_row) = db
            .read(move |conn| {
                let exists = |h: &[u8; 32]| -> i64 {
                    conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                        [&h[..]],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                (exists(&a), exists(&b), exists(&c), exists(&d))
            })
            .await;
        assert_eq!(a_row, 0, "the oldest unclaimed blob was not evicted");
        assert_eq!(b_row, 1, "a newer unclaimed blob was evicted");
        assert_eq!(c_row, 1);
        assert_eq!(d_row, 1, "the incoming blob was not installed");
        assert!(!blob_path(&dir, &hex::encode(a)).exists());

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Among equally cold unclaimed blobs, eviction prefers the least-read
    /// one: `access_count` breaks ties, so a repeatedly pulled blob survives
    /// a single-touch neighbour uploaded later.
    #[tokio::test]
    async fn unclaimed_trim_spares_frequently_read_blobs() {
        let dir = temp_dir("blob-unclaimed-frequency");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let mut cfg = test_cfg(&dir);
        // Wrapped blobs are 64 bytes each; the cap holds exactly two.
        cfg.unclaimed_limit_bytes = 128;

        let hot = [0x61u8; 32];
        let stale = [0x62u8; 32];
        for (hash, body, tag) in [(hot, b"hhhh", "hot"), (stale, b"ssss", "stale")] {
            let out = install_staged(&db, &cfg, staged_file(&dir, hash, body, tag), 0.0)
                .await
                .unwrap();
            assert_eq!(out, Install::Fresh);
        }
        db.write(move |conn| -> rusqlite::Result<()> {
            // Equal touch (100) for both; `hot` was read seven times,
            // `stale` never.
            conn.execute(
                "UPDATE blobs SET stored_at = 10, last_access_at = 100, access_count = 7
                 WHERE hash = ?1",
                [&hot[..]],
            )?;
            conn.execute(
                "UPDATE blobs SET stored_at = 20, last_access_at = 100 WHERE hash = ?1",
                [&stale[..]],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        // 2x64 unclaimed bytes at the 128 cap + 64 incoming exceeds it.
        // Both victims tie on touch; `access_count` decides: `stale` (0)
        // goes, not `hot` (7) - which the upload-time ranking would have
        // evicted, being the older upload.
        let fresh = [0x44u8; 32];
        let out = install_staged(&db, &cfg, staged_file(&dir, fresh, b"ffff", "f"), 0.0)
            .await
            .unwrap();
        assert_eq!(out, Install::Fresh);

        let (hot_row, stale_row, fresh_row) = db
            .read(move |conn| {
                let exists = |h: &[u8; 32]| -> i64 {
                    conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                        [&h[..]],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                (exists(&hot), exists(&stale), exists(&fresh))
            })
            .await;
        assert_eq!(stale_row, 0, "the least-read blob was not evicted first");
        assert_eq!(hot_row, 1, "cap eviction killed a frequently read blob");
        assert_eq!(fresh_row, 1, "the incoming blob was not installed");
        assert!(!blob_path(&dir, &hex::encode(stale)).exists());
        assert!(blob_path(&dir, &hex::encode(hot)).exists());

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cap eviction ranks unclaimed blobs by effective last touch: a blob
    /// that was read recently survives an older, never-read upload, so sync
    /// bursts and active reads are not thrashed by stale orphans.
    #[tokio::test]
    async fn unclaimed_trim_spares_recently_read_blobs() {
        let dir = temp_dir("blob-unclaimed-lru");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let mut cfg = test_cfg(&dir);
        // Wrapped blobs are 64 bytes each; the cap holds exactly two.
        cfg.unclaimed_limit_bytes = 128;

        let hot = [0x51u8; 32];
        let stale = [0x52u8; 32];
        for (hash, body, tag) in [(hot, b"hhhh", "hot"), (stale, b"ssss", "stale")] {
            let out = install_staged(&db, &cfg, staged_file(&dir, hash, body, tag), 0.0)
                .await
                .unwrap();
            assert_eq!(out, Install::Fresh);
        }
        db.write(move |conn| -> rusqlite::Result<()> {
            // `hot` is the older upload but was read recently; `stale` is
            // newer on disk and has never been read.
            conn.execute(
                "UPDATE blobs SET stored_at = 10, last_access_at = 100 WHERE hash = ?1",
                [&hot[..]],
            )?;
            conn.execute(
                "UPDATE blobs SET stored_at = 20 WHERE hash = ?1",
                [&stale[..]],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        // 2x64 unclaimed bytes at the 128 cap + 64 incoming exceeds it.
        // The coldest orphan is `stale` (touched at 20), not `hot` (100):
        // the oldest-by-upload victim would have been `hot`.
        let fresh = [0x44u8; 32];
        let out = install_staged(&db, &cfg, staged_file(&dir, fresh, b"ffff", "f"), 0.0)
            .await
            .unwrap();
        assert_eq!(out, Install::Fresh);

        let (hot_row, stale_row, fresh_row) = db
            .read(move |conn| {
                let exists = |h: &[u8; 32]| -> i64 {
                    conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                        [&h[..]],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                (exists(&hot), exists(&stale), exists(&fresh))
            })
            .await;
        assert_eq!(stale_row, 0, "the coldest unclaimed blob was not evicted");
        assert_eq!(hot_row, 1, "cap eviction killed a recently read blob");
        assert_eq!(fresh_row, 1, "the incoming blob was not installed");
        assert!(!blob_path(&dir, &hex::encode(stale)).exists());
        assert!(blob_path(&dir, &hex::encode(hot)).exists());

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The unclaimed byte cap evicts the oldest orphan first and never touches
    /// claimed blobs, which are charged to the combined budget instead.
    #[tokio::test]
    async fn unclaimed_byte_cap_evicts_oldest_and_spares_claimed() {
        let dir = temp_dir("blob-unclaimed-byte-cap");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let mut cfg = test_cfg(&dir);
        // Wrapped blobs are 64 bytes each; the cap fits exactly two, so the
        // third incoming one must evict the oldest orphan.
        cfg.unclaimed_limit_bytes = 128;

        let claimed = [0x01u8; 32];
        seed_claimed_blob(&db, claimed, [0x10u8; 32], 4, 1).await;
        std::fs::write(blob_path(&dir, &hex::encode(claimed)), b"dddd").unwrap();

        let a = [0x41u8; 32];
        let b = [0x42u8; 32];
        let c = [0x43u8; 32];
        for (hash, body, tag) in [(a, b"aaaa", "a"), (b, b"bbbb", "b")] {
            let out = install_staged(&db, &cfg, staged_file(&dir, hash, body, tag), 0.0)
                .await
                .unwrap();
            assert_eq!(out, Install::Fresh);
        }
        db.write(move |c| -> rusqlite::Result<()> {
            c.execute("UPDATE blobs SET stored_at = 10 WHERE hash = ?1", [&a[..]])?;
            c.execute("UPDATE blobs SET stored_at = 20 WHERE hash = ?1", [&b[..]])?;
            Ok(())
        })
        .await
        .unwrap();

        // 2×64 unclaimed bytes at the 128 cap + 64 incoming exceeds it: evict `a`.
        let out = install_staged(&db, &cfg, staged_file(&dir, c, b"cccc", "c"), 0.0)
            .await
            .unwrap();
        assert_eq!(out, Install::Fresh);

        let (a_row, b_row, c_row, claimed_row) = db
            .read(move |conn| {
                let exists = |h: &[u8; 32]| -> i64 {
                    conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                        [&h[..]],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                (exists(&a), exists(&b), exists(&c), exists(&claimed))
            })
            .await;
        assert_eq!(a_row, 0, "the oldest unclaimed blob was not evicted");
        assert_eq!(b_row, 1, "a newer unclaimed blob was evicted");
        assert_eq!(c_row, 1);
        assert_eq!(claimed_row, 1, "cap eviction touched a claimed blob");
        assert!(!blob_path(&dir, &hex::encode(a)).exists());
        assert!(blob_path(&dir, &hex::encode(b)).exists());
        assert!(blob_path(&dir, &hex::encode(c)).exists());
        assert!(blob_path(&dir, &hex::encode(claimed)).exists());

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A blob larger than the whole unclaimed byte cap is refused instead of
    /// evicting every orphan for bytes that still would not fit.
    #[tokio::test]
    async fn oversized_unclaimed_upload_is_refused_without_evicting() {
        let dir = temp_dir("blob-unclaimed-oversized");
        init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let mut cfg = test_cfg(&dir);
        cfg.unclaimed_limit_bytes = 100;

        let kept = [0x61u8; 32];
        let out = install_staged(&db, &cfg, staged_file(&dir, kept, b"aaaa", "kept"), 0.0)
            .await
            .unwrap();
        assert_eq!(out, Install::Fresh);

        cfg.unclaimed_limit_bytes = 3;
        let big = [0x62u8; 32];
        let staged = staged_file(&dir, big, b"bbbb", "big");
        let staged_path = staged.path.clone();
        let out = install_staged(&db, &cfg, staged, 0.0).await.unwrap();
        assert_eq!(out, Install::Refused);
        assert!(!staged_path.exists(), "refused upload left its temp file");

        let (kept_row, big_row) = db
            .read(move |c| {
                let exists = |h: &[u8; 32]| -> i64 {
                    c.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                        [&h[..]],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                (exists(&kept), exists(&big))
            })
            .await;
        assert_eq!(kept_row, 1, "a refused upload evicted existing blobs");
        assert_eq!(big_row, 0);
        assert!(blob_path(&dir, &hex::encode(kept)).exists());

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
