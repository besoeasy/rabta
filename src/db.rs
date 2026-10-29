use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

/// SQLite access layer.
///
/// Concurrency contract (plan.md): reads never block and writes are serialized
/// through exactly one connection-writer. WAL mode gives readers a snapshot;
/// the shared `Mutex<Connection>` guarantees one writer at a time without a
/// second config mechanism. All DB calls run through `spawn_blocking`.
#[derive(Clone)]
pub struct Db {
    inner: Arc<Mutex<Connection>>,
}

pub const MAX_ENVELOPE: usize = 100_000;
pub const MAX_TTL_SECONDS: i64 = 365 * 86400; // max_age: 1 year
pub const MIN_TTL_SECONDS: i64 = 60; // expires_at must be > created_at + 60s
pub const ORPHAN_TTL_SECONDS: i64 = 3600; // orphan blob flat lifetime: 1 hour

impl Db {
    pub fn open(data_dir: &Path) -> Db {
        let path = data_dir.join("index.db");
        let c = Connection::open(&path).expect("cannot open /data/index.db");
        c.pragma_update(None, "journal_mode", "WAL").ok();
        c.pragma_update(None, "synchronous", "NORMAL").ok();
        c.pragma_update(None, "temp_store", "MEMORY").ok();
        c.busy_timeout(std::time::Duration::from_secs(10)).ok();
        c.execute_batch(SCHEMA).expect("schema init failed");
        let db = Db { inner: Arc::new(Mutex::new(c)) };
        reconcile_counters(&db);
        db
    }

    /// Run a closure against the connection inside a blocking task.
    /// Writes and builds that mutate state run here; one writer at a time.
    pub async fn write<T, F>(&self, f: F) -> T
    where
        F: FnOnce(&Connection) -> T + Send + 'static,
        T: Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let c = inner.lock().expect("db mutex poisoned");
            f(&c)
        })
        .await
        .expect("db write task panicked")
    }

    /// Read-only closure; short queries only.
    pub async fn read<T, F>(&self, f: F) -> T
    where
        F: FnOnce(&Connection) -> T + Send + 'static,
        T: Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let c = inner.lock().expect("db mutex poisoned");
            f(&c)
        })
        .await
        .expect("db read task panicked")
    }
}

/// Recompute the live_bytes counters from the tables themselves — a periodic
/// hygiene pass, and the boot-time repair. `live_bytes` is normally maintained
/// per transaction, never recomputed.
fn reconcile_counters(db: &Db) {
    let c = db.inner.lock().expect("poisoned");
    let mut stmt = c.prepare("SELECT COALESCE(SUM(size),0) FROM events WHERE state='live'").unwrap();
    let ev: i64 = stmt.query_row([], |r| r.get(0)).unwrap_or(0);
    let mut stmt = c.prepare("SELECT COALESCE(SUM(size),0) FROM blobs WHERE state='live'").unwrap();
    let bl: i64 = stmt.query_row([], |r| r.get(0)).unwrap_or(0);
    c.execute_batch(&format!(
        "INSERT INTO counters(k,v) VALUES('live_bytes_events',{ev}), ('live_bytes_blobs',{bl})
         ON CONFLICT(k) DO UPDATE SET v=excluded.v;"
    ))
    .ok();
    tracing::info!("counters reconciled: events {} + blobs {} bytes", ev, bl);
}

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
  id          BLOB(32) PRIMARY KEY,   -- raw sha256 digest
  owner       BLOB(32) NOT NULL,
  collection  TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,       -- time of death; reaper deletes <= now
  data        BLOB    NOT NULL,       -- stored envelope JSON (canonical + id + sig)
  labels      TEXT    NOT NULL,       -- JSON array (denormalized view copy)
  size        INTEGER NOT NULL,       -- envelope bytes (as served)
  mime        TEXT    NOT NULL DEFAULT 'application/json',
  state       TEXT    NOT NULL DEFAULT 'live'
);
CREATE INDEX IF NOT EXISTS ev_collection ON events(collection);
CREATE INDEX IF NOT EXISTS ev_owner      ON events(owner);
CREATE INDEX IF NOT EXISTS ev_created    ON events(created_at);
CREATE INDEX IF NOT EXISTS ev_expires    ON events(expires_at);

CREATE TABLE IF NOT EXISTS labels (
  event_id BLOB(32) NOT NULL,
  label    TEXT     NOT NULL,
  PRIMARY KEY (event_id, label)
);
CREATE INDEX IF NOT EXISTS lab_label ON labels(label);

CREATE TABLE IF NOT EXISTS blobs (
  hash      BLOB(32) PRIMARY KEY,     -- raw sha256 of the bytes
  size      INTEGER NOT NULL,
  stored_at INTEGER NOT NULL,         -- unix seconds; never resets
  ever_attached INTEGER NOT NULL DEFAULT 0, -- was referenced by ≥1 event once
  state     TEXT    NOT NULL DEFAULT 'live'
);

CREATE TABLE IF NOT EXISTS refs (
  event_id  BLOB(32) NOT NULL,
  blob_hash BLOB(32) NOT NULL,
  PRIMARY KEY (event_id, blob_hash)
);
CREATE INDEX IF NOT EXISTS ref_blob ON refs(blob_hash);

CREATE TABLE IF NOT EXISTS counters (
  k TEXT PRIMARY KEY,
  v INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS stale_files (
  path TEXT PRIMARY KEY,
  size INTEGER NOT NULL,
  seen_at INTEGER NOT NULL
);
"#;

/// O(1) budget totals from the counters table (never SUM(size) on hot paths).
pub fn live_bytes(c: &Connection) -> (i64, i64) {
    let get = |k: &str| -> i64 {
        c.query_row("SELECT v FROM counters WHERE k = ?", [k], |r| r.get(0)).unwrap_or(0)
    };
    (get("live_bytes_events"), get("live_bytes_blobs"))
}

pub fn bump_counters(c: &Connection, events_delta: i64, blobs_delta: i64) {
    if events_delta != 0 {
        c.execute(
            "INSERT INTO counters(k,v) VALUES('live_bytes_events', ?1)
             ON CONFLICT(k) DO UPDATE SET v = v + ?1",
            [events_delta],
        )
        .ok();
    }
    if blobs_delta != 0 {
        c.execute(
            "INSERT INTO counters(k,v) VALUES('live_bytes_blobs', ?1)
             ON CONFLICT(k) DO UPDATE SET v = v + ?1",
            [blobs_delta],
        )
        .ok();
    }
}
