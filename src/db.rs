use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use rusqlite::Connection;

/// SQLite access layer.
///
/// Concurrency contract: reads never block writes and writes are
/// serialized through exactly one connection-writer. WAL mode gives readers
/// their own snapshots, so a pool of reader connections is used instead of
/// sharing the writer's mutex. All DB calls run through `spawn_blocking`.
#[derive(Clone)]
pub struct Db {
    writer: Arc<Mutex<Connection>>,
    readers: Arc<ReaderPool>,
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
/// A read that cannot obtain a pooled connection within this window falls back
/// to the writer instead of waiting on the condvar forever.
const READER_WAIT: Duration = Duration::from_secs(5);

impl ReaderPool {
    fn new(path: PathBuf, connections: Vec<Connection>) -> ReaderPool {
        let open = connections.len();
        ReaderPool {
            path,
            state: Mutex::new(ReaderPoolState {
                idle: connections,
                open,
            }),
            available: Condvar::new(),
            max: READER_POOL_MAX,
        }
    }

    fn acquire(self: &Arc<Self>) -> rusqlite::Result<ReaderGuard> {
        loop {
            let mut state = self.state.lock().expect("db reader mutex poisoned");
            if let Some(conn) = state.idle.pop() {
                return Ok(ReaderGuard {
                    pool: Arc::clone(self),
                    conn: Some(conn),
                });
            }
            if state.open < self.max {
                state.open += 1;
                drop(state);
                match open_reader(&self.path) {
                    Ok(conn) => {
                        return Ok(ReaderGuard {
                            pool: Arc::clone(self),
                            conn: Some(conn),
                        });
                    }
                    Err(e) => {
                        let mut state = self.state.lock().expect("db reader mutex poisoned");
                        state.open -= 1;
                        self.available.notify_one();
                        return Err(e);
                    }
                }
            }
            let (state, timed_out) = self
                .available
                .wait_timeout(state, READER_WAIT)
                .expect("db reader condvar poisoned");
            if timed_out.timed_out() {
                drop(state);
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                    Some("timed out waiting for a reader connection".to_string()),
                ));
            }
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
/// Blob references an event may carry (0-8; empty is valid). A live event
/// that lists a blob keeps it until the event's own expiry; validation still
/// never requires the blob to exist.
pub const MAX_BLOB_REFS: usize = 8;
pub const MAX_TTL_SECONDS: i64 = 400 * 86400; // max_age: 400 days
pub const MIN_TTL_SECONDS: i64 = 60; // expires_at must be > created_at + 60s
/// An unclaimed blob lives 6 hours from its first upload. Reads do not
/// extend it; claiming it from an event replaces this with the event's
/// `expires_at`.
pub const BLOB_UNCLAIMED_TTL_SECONDS: i64 = 6 * 3600;
/// Access tracking is write-throttled: a read only touches the row when the
/// previous touch is at least this old, bounding writer load.
pub const BLOB_REFRESH_SECONDS: i64 = 3600;
/// A freshly uploaded blob is never a pressure candidate before this.
pub const BLOB_GRACE_SECONDS: i64 = 3600;
/// Idle longer than this makes a blob "cold" (pressure tier 2).
pub const BLOB_COLD_AFTER_SECONDS: i64 = 86400;
/// Idle shorter than this makes a blob "active" (pressure tier 4, last resort).
pub const BLOB_ACTIVE_WINDOW_SECONDS: i64 = 3600;

impl Db {
    pub fn open(data_dir: &Path) -> Db {
        let path = data_dir.join("index.db");
        let c = Connection::open(&path).expect("cannot open /data/index.db");
        configure_connection(&c);
        c.pragma_update(None, "journal_mode", "WAL").ok();
        c.execute_batch(SCHEMA).expect("schema init failed");
        crate::store::blobs::reconcile_blob_expiry(&c).ok();
        reconcile_counters(&c);

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

        Db {
            writer: Arc::new(Mutex::new(c)),
            readers: Arc::new(ReaderPool::new(path, readers)),
        }
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
            // Recover rather than wedge the single writer forever: SQLite rolls
            // back any uncommitted transaction while the panic unwinds.
            let c = writer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
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
        let writer = self.writer.clone();
        tokio::task::spawn_blocking(move || match pool.acquire() {
            Ok(c) => f(&c),
            Err(e) => {
                // The reader pool is an optimization, not a requirement: a
                // read that cannot open or borrow a reader still completes on
                // the writer (serialized, but never parked forever).
                tracing::warn!(error = %e, "reader pool unavailable; using the writer for this read");
                let c = writer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                f(&c)
            }
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
    // POLICY globs compile to `LIKE ... ESCAPE '\'` and must match
    // case-sensitively; the node runs no other LIKE, so this is safe
    // connection-wide.
    c.pragma_update(None, "case_sensitive_like", true).ok();
    c.busy_timeout(std::time::Duration::from_secs(10)).ok();
}

/// Recompute the live_bytes counters from the tables themselves — a periodic
/// hygiene pass, and the boot-time repair. `live_bytes` is normally maintained
/// per transaction, never recomputed.
pub fn reconcile_counters(c: &Connection) {
    let get = |sql: &str| -> i64 { c.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };
    let ev = get("SELECT COALESCE(SUM(size),0) FROM events");
    let bl = get("SELECT COALESCE(SUM(size),0) FROM blobs");
    let cl = get("SELECT COALESCE(SUM(b.size),0)
           FROM blobs b
          WHERE EXISTS (
              SELECT 1 FROM blob_refs r
                JOIN events e ON e.id = r.event_id
               WHERE r.hash = b.hash
            )");
    c.execute_batch(&format!(
        "INSERT INTO counters(k,v) VALUES
           ('live_bytes_events',{ev}),
           ('live_bytes_blobs',{bl}),
           ('live_bytes_claimed_blobs',{cl})
         ON CONFLICT(k) DO UPDATE SET v=excluded.v;"
    ))
    .ok();
    tracing::info!(
        "counters reconciled: events {} + claimed blobs {} (all blobs {}) bytes",
        ev,
        cl,
        bl
    );
}

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
  id          BLOB(32) PRIMARY KEY,   -- raw sha256 digest
  owner       BLOB(32) NOT NULL,
  collection  TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,       -- time of death; reaper deletes <= now
  data        BLOB    NOT NULL,       -- stored envelope JSON (canonical + id + sig)
  size        INTEGER NOT NULL        -- envelope bytes (as served)
);
CREATE INDEX IF NOT EXISTS ev_collection ON events(collection);
CREATE INDEX IF NOT EXISTS ev_owner      ON events(owner);
CREATE INDEX IF NOT EXISTS ev_created_id ON events(created_at, id);
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
  expires_at INTEGER NOT NULL,        -- claimed: max event expiry; else stored_at + 6h
  last_access_at INTEGER NOT NULL DEFAULT 0, -- 0 = never read since upload
  access_count   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS blob_expires ON blobs(expires_at);
CREATE INDEX IF NOT EXISTS blob_access  ON blobs(last_access_at);

CREATE TABLE IF NOT EXISTS blob_refs (
  hash     BLOB(32) NOT NULL,         -- referenced blob
  event_id BLOB(32) NOT NULL,         -- live event carrying it in `blobs`
  PRIMARY KEY (hash, event_id)
);
CREATE INDEX IF NOT EXISTS bref_event ON blob_refs(event_id);

CREATE TABLE IF NOT EXISTS counters (
  k TEXT PRIMARY KEY,
  v INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_meta (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  epoch       BLOB(16) NOT NULL,
  battery     REAL      NOT NULL,
  battery_at  INTEGER   NOT NULL,
  created_at  INTEGER   NOT NULL,
  tier        INTEGER   NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sync_peers (
  url              TEXT PRIMARY KEY,
  penalty          REAL    NOT NULL DEFAULT 1.0,
  penalty_at       INTEGER NOT NULL DEFAULT 0,
  strikes          INTEGER NOT NULL DEFAULT 0,
  next_poll_at     INTEGER NOT NULL DEFAULT 0,
  last_success_at  INTEGER,
  last_error       TEXT,
  last_error_at    INTEGER
);

CREATE TABLE IF NOT EXISTS peer_battery (
  url        TEXT PRIMARY KEY,
  remaining  REAL NOT NULL,
  max        REAL NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_nonces (
  peer_key   BLOB(32) NOT NULL,
  nonce      BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (peer_key, nonce)
);

CREATE TABLE IF NOT EXISTS sync_blob_queue (
  hash            BLOB(32) PRIMARY KEY,
  state           TEXT NOT NULL DEFAULT 'pending',
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  first_seen_at   INTEGER NOT NULL
);
"#;

/// O(1) budget totals from the counters table (never SUM(size) on hot paths).
/// Returns `(events, claimed blobs)`: the bytes charged to the single budget.
/// Unclaimed blobs are intentionally excluded.
pub fn live_bytes(c: &Connection) -> (i64, i64) {
    let get = |k: &str| -> i64 {
        c.query_row("SELECT v FROM counters WHERE k = ?", [k], |r| r.get(0))
            .unwrap_or(0)
    };
    (get("live_bytes_events"), get("live_bytes_claimed_blobs"))
}

/// All live blob bytes, claimed or not, for diagnostics.
pub fn blob_bytes(c: &Connection) -> i64 {
    c.query_row(
        "SELECT v FROM counters WHERE k = 'live_bytes_blobs'",
        [],
        |r| r.get(0),
    )
    .unwrap_or(0)
}

/// Combined budget usage: events plus claimed blobs.
pub fn used_bytes(c: &Connection) -> i64 {
    let (ev, cl) = live_bytes(c);
    ev.max(0).saturating_add(cl.max(0))
}

pub fn bump_counters(
    c: &Connection,
    events_delta: i64,
    blobs_delta: i64,
    claimed_delta: i64,
) -> rusqlite::Result<()> {
    for (key, delta) in [
        ("live_bytes_events", events_delta),
        ("live_bytes_blobs", blobs_delta),
        ("live_bytes_claimed_blobs", claimed_delta),
    ] {
        if delta != 0 {
            c.execute(
                "INSERT INTO counters(k,v) VALUES(?1, ?2)
                 ON CONFLICT(k) DO UPDATE SET v = v + ?2",
                rusqlite::params![key, delta],
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rabta-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    // Intentional: the test holds the writer lock across the read to prove the
    // reader pool completes without it.
    #[allow(clippy::await_holding_lock)]
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

    /// A reader that cannot be opened must surface an error immediately, not
    /// park the request on a condvar that nothing can signal.
    #[test]
    fn reader_pool_open_failure_returns_an_error() {
        let missing = std::env::temp_dir()
            .join(format!(
                "rabta-missing-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ))
            .join("index.db");
        let pool = Arc::new(ReaderPool::new(missing, Vec::new()));

        let start = std::time::Instant::now();
        let err = match pool.acquire() {
            Ok(_) => panic!("an unopenable reader must report an error"),
            Err(e) => e,
        };
        assert!(start.elapsed() < Duration::from_secs(2), "acquire stalled");
        assert!(
            err.to_string().contains("unable to open"),
            "unexpected error: {err}"
        );
    }
}
