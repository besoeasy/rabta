use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};

use rusqlite::Connection;

/// SQLite access layer.
///
/// Concurrency contract (plan.md): reads never block writes and writes are
/// serialized through exactly one connection-writer. WAL mode gives readers
/// their own snapshots, so a pool of reader connections is used instead of
/// sharing the writer's mutex. All DB calls run through `spawn_blocking`.
#[derive(Clone)]
pub struct Db {
    writer: Arc<Mutex<Connection>>,
    readers: Arc<ReaderPool>,
    /// Wakes the shared SSE feed after a committed event insert.
    events_changed: Arc<tokio::sync::Notify>,
}

/// A pool of read-only SQLite connections. It starts small and opens extra
/// readers on demand up to a cap, so concurrent reads never queue behind each
/// other just because the machine has fewer CPUs. The idle-list lock is held
/// only while taking/returning a connection, never while a query runs.
struct ReaderPool {
    path: PathBuf,
    state: Mutex<ReaderPoolState>,
    available: Condvar,
    max: usize,
}

struct ReaderPoolState {
    idle: Vec<Connection>,
    open: usize,
}

struct ReaderGuard {
    pool: Arc<ReaderPool>,
    conn: Option<Connection>,
}

const READER_POOL_MAX: usize = 64;

impl ReaderPool {
    fn new(path: PathBuf, connections: Vec<Connection>) -> ReaderPool {
        let open = connections.len();
        ReaderPool {
            path,
            state: Mutex::new(ReaderPoolState { idle: connections, open }),
            available: Condvar::new(),
            max: READER_POOL_MAX,
        }
    }

    fn acquire(self: &Arc<Self>) -> ReaderGuard {
        loop {
            let mut state = self.state.lock().expect("db reader mutex poisoned");
            if let Some(conn) = state.idle.pop() {
                return ReaderGuard { pool: Arc::clone(self), conn: Some(conn) };
            }
            if state.open < self.max {
                state.open += 1;
                drop(state);
                match open_reader(&self.path) {
                    Ok(conn) => return ReaderGuard { pool: Arc::clone(self), conn: Some(conn) },
                    Err(_) => {
                        let mut state = self.state.lock().expect("db reader mutex poisoned");
                        state.open -= 1;
                        self.available.notify_one();
                        let _unused = self
                            .available
                            .wait(state)
                            .expect("db reader condvar poisoned");
                        continue;
                    }
                }
            }
            let _unused = self.available.wait(state).expect("db reader condvar poisoned");
        }
    }

    fn release(&self, conn: Connection) {
        let mut state = self.state.lock().expect("db reader mutex poisoned");
        state.idle.push(conn);
        self.available.notify_one();
    }
}

impl Deref for ReaderGuard {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("reader guard already released")
    }
}

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.release(conn);
        }
    }
}

pub const MAX_ENVELOPE: usize = 100_000;
pub const MAX_TTL_SECONDS: i64 = 365 * 86400; // max_age: 1 year
pub const MIN_TTL_SECONDS: i64 = 60; // expires_at must be > created_at + 60s
pub const ORPHAN_TTL_SECONDS: i64 = 3600; // orphan blob flat lifetime: 1 hour

impl Db {
    pub fn open(data_dir: &Path) -> Db {
        let path = data_dir.join("index.db");
        let c = Connection::open(&path).expect("cannot open /data/index.db");
        configure_connection(&c);
        c.pragma_update(None, "journal_mode", "WAL").ok();
        c.execute_batch(SCHEMA).expect("schema init failed");

        // One writer + a reader pool. WAL lets readers run against a stable
        // snapshot while the writer commits; they never share its lock.
        let reader_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(2, 8);
        let mut readers = Vec::with_capacity(reader_count);
        for _ in 0..reader_count {
            readers.push(open_reader(&path).expect("cannot open read connection"));
        }

        let db = Db {
            writer: Arc::new(Mutex::new(c)),
            readers: Arc::new(ReaderPool::new(path, readers)),
            events_changed: Arc::new(tokio::sync::Notify::new()),
        };
        reconcile_counters(&db);
        db
    }

    /// Path of the underlying `index.db`. Used to key per-database runtime
    /// state (e.g. the shared SSE feed) when several `Db`s exist in-process.
    pub fn path(&self) -> &Path {
        &self.readers.path
    }

    /// Wake the shared SSE feed after committing new event rows. Callers may
    /// signal after a batch; notifications coalesce.
    pub fn notify_event_row(&self) {
        self.events_changed.notify_one();
    }

    /// Resolve on the next event-row signal (or immediately if one is queued).
    pub async fn wait_for_event_row(&self) {
        self.events_changed.notified().await;
    }

    /// Run a closure against the single writer connection inside a blocking
    /// task; writes are serialized, readers are not.
    pub async fn write<T, F>(&self, f: F) -> T
    where
        F: FnOnce(&Connection) -> T + Send + 'static,
        T: Send + 'static,
    {
        let writer = self.writer.clone();
        tokio::task::spawn_blocking(move || {
            let c = writer.lock().expect("db mutex poisoned");
            f(&c)
        })
        .await
        .expect("db write task panicked")
    }

    /// Read-only closure on a pooled connection; short queries only. The
    /// connection is checked out for the duration of `f`, so concurrent reads
    /// proceed independently and never queue behind a writer.
    pub async fn read<T, F>(&self, f: F) -> T
    where
        F: FnOnce(&Connection) -> T + Send + 'static,
        T: Send + 'static,
    {
        let pool = self.readers.clone();
        tokio::task::spawn_blocking(move || {
            let c = pool.acquire();
            f(&c)
        })
        .await
        .expect("db read task panicked")
    }
}

fn open_reader(path: &Path) -> rusqlite::Result<Connection> {
    let c = Connection::open(path)?;
    configure_connection(&c);
    c.pragma_update(None, "query_only", true).ok();
    Ok(c)
}

fn configure_connection(c: &Connection) {
    c.pragma_update(None, "synchronous", "NORMAL").ok();
    c.pragma_update(None, "temp_store", "MEMORY").ok();
    c.busy_timeout(std::time::Duration::from_secs(10)).ok();
}

/// Recompute the live_bytes counters from the tables themselves — a periodic
/// hygiene pass, and the boot-time repair. `live_bytes` is normally maintained
/// per transaction, never recomputed.
fn reconcile_counters(db: &Db) {
    let c = db.writer.lock().expect("poisoned");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let dir = std::env::temp_dir().join(format!("rabta-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn reads_do_not_share_the_writer_lock() {
        let dir = temp_dir("db-readers");
        let db = Db::open(&dir);

        // Simulate an in-flight write holding the writer connection.
        let writer = db.writer.lock().unwrap();
        let read = tokio::time::timeout(
            Duration::from_secs(1),
            db.read(|c| c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)).unwrap()),
        )
        .await;
        drop(writer);

        assert_eq!(read.expect("read blocked behind the writer"), 1);
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
