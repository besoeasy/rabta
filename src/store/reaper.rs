use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use rusqlite::Connection;

use crate::config::Config;
use crate::db::Db;

/// Periodic maintenance cadence. The startup pass runs immediately; after
/// that, idle nodes still reclaim expired/orphan data without waiting an hour.
pub const REAPER_INTERVAL: Duration = Duration::from_secs(300);

pub fn now() -> i64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

/// Eviction & reclaim counters for /stats (plan.md §Guards).
#[derive(Debug, Default, Clone, Copy)]
pub struct EvictionStats {
    pub events_evicted: u64,
    pub blobs_evicted: u64,
    pub bytes_reclaimed: u64,
}

pub struct Counters {
    pub events_evicted: AtomicU64,
    pub blobs_evicted: AtomicU64,
    pub bytes_reclaimed: AtomicU64,
    pub live_blobs_cache: AtomicI64,
    pub live_events_cache: AtomicI64,
}

pub static COUNTERS: Counters = Counters {
    events_evicted: AtomicU64::new(0),
    blobs_evicted: AtomicU64::new(0),
    bytes_reclaimed: AtomicU64::new(0),
    live_blobs_cache: AtomicI64::new(0),
    live_events_cache: AtomicI64::new(0),
};

/// Unix seconds of the last completed reaper tick (0 before the first).
static LAST_SWEEP_AT: AtomicI64 = AtomicI64::new(0);

pub fn last_sweep_at() -> i64 {
    LAST_SWEEP_AT.load(Ordering::Relaxed)
}

fn add(a: &AtomicU64, n: u64) {
    a.fetch_add(n, Ordering::Relaxed);
}

fn id32(v: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(v);
    a
}

/// Max bytes freed per eviction pass: 20% of STORAGE_MAX (then yields).
pub fn pass_cap(cfg: &Config) -> i64 {
    (cfg.storage_max / 100 * 20) as i64
}

/// Layer 3: demand-aware, largest-unit-first eviction.
///
/// Evicts only when `live_bytes + incoming` exceeds the watermark, and frees
/// until the live set fits both the eviction target and the room the incoming
/// write needs (`target = min(85%, watermark - incoming)`). This keeps local
/// writes moving under pressure instead of refusing at 90% while the reaper
/// thinks there is nothing to do. `unit_size(E) = E.size + Σ blob.size /
/// n_live_referrers(blob)` (pro-rata); tie-break: age ASC, then id ASC.
/// Capped at ~20% of budget per pass; stop decisions use the real counters.
pub fn evict_pass(c: &Connection, cfg: &Config, incoming: u64) -> EvictionStats {
    let mut out = EvictionStats::default();

    let (ev0, bl0) = crate::db::live_bytes(c);
    sync_cache(ev0, bl0);
    let start_live = (ev0 + bl0).max(0);
    if start_live as u64 + incoming <= cfg.watermark_bytes {
        return out;
    }

    let dir = cfg.data_dir.clone();

    // Fully collectible blobs are pure overhead: free them before touching
    // any event. This is housekeeping, not chargeable to the pass cap.
    let report = crate::store::blobs::blob_pass(c, now(), &dir).unwrap_or_default();
    out.blobs_evicted = report.blobs_removed as u64;

    let (ev, bl) = crate::db::live_bytes(c);
    let mut live = (ev + bl).max(0);
    let target = cfg
        .eviction_target_bytes
        .min(cfg.watermark_bytes.saturating_sub(incoming)) as i64;

    if live as u64 + incoming > cfg.watermark_bytes {
        struct Unit {
            id: [u8; 32],
            size: i64,
            created_at: i64,
            attach: i64, // pro-rata attachment share
        }

        let mut units: Vec<Unit> = Vec::new();
        {
            let mut stmt =
                c.prepare("SELECT id, size, created_at FROM events WHERE state='live'").unwrap();
            let mut rows = stmt.query([]).unwrap();
            while let Some(r) = rows.next().unwrap() {
                let id: Vec<u8> = r.get(0).unwrap();
                units.push(Unit {
                    id: id32(&id),
                    size: r.get(1).unwrap(),
                    created_at: r.get(2).unwrap(),
                    attach: 0,
                });
            }
        }

        // Blobs referenced by exactly one event die with it, so their bytes
        // can be reclaimed immediately instead of waiting for the blob pass.
        let mut exclusive: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
        {
            // pro-rata: event's share of each attached blob = blob.size / total referrers
            let mut attach: HashMap<[u8; 32], i64> = HashMap::new();
            let mut stmt = c
                .prepare(
                    "SELECT r.event_id, r.blob_hash, b.size,
                            (SELECT COUNT(*) FROM refs x WHERE x.blob_hash = r.blob_hash)
                     FROM refs r JOIN blobs b ON b.hash = r.blob_hash",
                )
                .unwrap();
            let mut rows = stmt.query([]).unwrap();
            while let Some(r) = rows.next().unwrap() {
                let eid_v: Vec<u8> = r.get(0).unwrap();
                let hash_v: Vec<u8> = r.get(1).unwrap();
                let bsize: i64 = r.get(2).unwrap();
                let refs: i64 = r.get(3).unwrap();
                let eid = id32(&eid_v);
                let share = bsize / refs.max(1);
                *attach.entry(eid).or_insert(0) += share;
                if refs <= 1 {
                    exclusive.entry(eid).or_default().push(id32(&hash_v));
                }
            }
            for u in units.iter_mut() {
                u.attach = attach.get(&u.id).copied().unwrap_or(0);
            }
        }

        units.sort_by(|a, b| {
            (b.size + b.attach)
                .cmp(&(a.size + a.attach))
                .then(a.created_at.cmp(&b.created_at))
                .then(a.id.cmp(&b.id))
        });

        let cap = pass_cap(cfg).max(0);
        let mut freed_this_pass = 0i64;
        for u in &units {
            if freed_this_pass >= cap || live <= target {
                break;
            }
            let before = live;
            let freed = match crate::store::blobs::delete_events(c, std::slice::from_ref(&u.id), &dir)
            {
                Ok(n) if n > 0 => n,
                _ => continue,
            };
            if let Some(hashes) = exclusive.get(&u.id) {
                for h in hashes {
                    crate::store::blobs::delete_blob(c, h, &dir).unwrap_or(0);
                }
            }
            let (ev2, bl2) = crate::db::live_bytes(c);
            live = (ev2 + bl2).max(0);
            // Actual counter movement is authoritative; the event's own size
            // is a floor so a drifted counter cannot stall the pass.
            freed_this_pass += (before - live).max(freed);
            out.events_evicted += 1;
        }
    }

    // Die-with-parent follows every event deletion (blobs with no live refs).
    let report = crate::store::blobs::blob_pass(c, now(), &dir).unwrap_or_default();
    out.blobs_evicted += report.blobs_removed as u64;

    let (ev2, bl2) = crate::db::live_bytes(c);
    let end_live = (ev2 + bl2).max(0);
    sync_cache(ev2, bl2);
    out.bytes_reclaimed = (start_live - end_live).max(0) as u64;
    add(&COUNTERS.events_evicted, out.events_evicted);
    add(&COUNTERS.blobs_evicted, out.blobs_evicted);
    add(&COUNTERS.bytes_reclaimed, out.bytes_reclaimed);
    out
}

fn sync_cache(ev: i64, bl: i64) {
    COUNTERS.live_events_cache.store(ev, Ordering::Relaxed);
    COUNTERS.live_blobs_cache.store(bl, Ordering::Relaxed);
}

/// Layer 2 entry for write paths: evict until `live_bytes + incoming` fits
/// below the 90% watermark; Err(at_watermark) when nothing more can free.
pub fn pressure_check(c: &Connection, cfg: &Config, incoming: u64) -> Result<(), crate::error::ApiError> {
    let (ev, bl) = crate::db::live_bytes(c);
    sync_cache(ev, bl);
    // An item that cannot fit even in an empty store must be refused before
    // we destroy existing data trying to make room for it.
    if incoming > cfg.watermark_bytes {
        return Err(crate::error::ApiError::at_watermark());
    }
    for _ in 0..40 {
        let (ev, bl) = crate::db::live_bytes(c);
        let total = (ev + bl).max(0) as u64;
        sync_cache(ev, bl);
        if total + incoming <= cfg.watermark_bytes {
            return Ok(());
        }
        let out = evict_pass(c, cfg, incoming);
        if out.events_evicted == 0 && out.blobs_evicted == 0 {
            return Err(crate::error::ApiError::at_watermark());
        }
    }
    Err(crate::error::ApiError::at_watermark())
}

/// Layer 1: hourly expiry sweep — events by `expires_at` (≤ now), then blobs
/// by parenthood ∨ 1-hour flat with die-with-parent.
pub fn sweep_once(c: &Connection, cfg: &Config) -> EvictionStats {
    let mut out = EvictionStats::default();
    let now_n = now();

    let mut ids: Vec<[u8; 32]> = Vec::new();
    {
        let mut stmt = c.prepare("SELECT id FROM events WHERE state='live' AND expires_at <= ?1").unwrap();
        let mut rows = stmt.query([now_n]).unwrap();
        while let Some(r) = rows.next().unwrap() {
            let id: Vec<u8> = r.get(0).unwrap();
            ids.push(id32(&id));
        }
    }
    let freed = crate::store::blobs::delete_events(c, &ids, &cfg.data_dir).unwrap_or(0);
    out.events_evicted = ids.len() as u64;
    out.bytes_reclaimed = freed.max(0) as u64;
    add(&COUNTERS.events_evicted, out.events_evicted);
    add(&COUNTERS.bytes_reclaimed, out.bytes_reclaimed);

    let report = crate::store::blobs::blob_pass(c, now_n, &cfg.data_dir).unwrap_or_default();
    out.blobs_evicted = report.blobs_removed as u64;
    out.bytes_reclaimed += report.blob_bytes.max(0) as u64;
    add(&COUNTERS.blobs_evicted, out.blobs_evicted);

    let (ev2, bl2) = crate::db::live_bytes(c);
    sync_cache(ev2, bl2);
    out
}

/// The reaper task body
pub async fn reaper_tick(db: &Db, cfg: Config) {
    let _ = db
        .write(move |conn: &Connection| {
            // Cheap table scan once per cadence: repair any counter drift before
            // this pass makes eviction decisions from those totals.
            crate::db::reconcile_counters(conn);
            sweep_once(conn, &cfg);
            evict_pass(conn, &cfg, 0);
            0
        })
        .await;
    LAST_SWEEP_AT.store(now(), Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;
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

    fn seed_events(c: &Connection, count: u8, size: i64) {
        for i in 1..=count {
            c.execute(
                "INSERT INTO events(id, owner, collection, created_at, expires_at, data, labels, size, mime, state)
                 VALUES (?1, ?2, 'c', 1, 9999999999, x'', '[]', ?3, 'application/json', 'live')",
                rusqlite::params![[i; 32], [0u8; 32], size],
            )
            .unwrap();
        }
        crate::db::bump_counters(c, size * count as i64, 0).unwrap();
    }

    /// Regression: at exactly the watermark a passive pass must do nothing,
    /// but a pass with an incoming write must free room for it.
    #[tokio::test]
    async fn evicts_to_admit_an_incoming_write_at_the_watermark() {
        let dir = temp_dir("reaper-demand");
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);

        let cfg_idle = cfg.clone();
        let idle = db
            .write(move |c| {
                seed_events(c, 3, 30); // 90 bytes = exactly the watermark
                evict_pass(c, &cfg_idle, 0)
            })
            .await;
        assert_eq!(idle.events_evicted, 0, "passive pass evicted at the watermark");

        let cfg_pressure = cfg.clone();
        let (stats, live) = db
            .write(move |c| {
                let stats = evict_pass(c, &cfg_pressure, 5);
                let live = crate::db::live_bytes(c);
                (stats, live)
            })
            .await;
        assert!(stats.events_evicted >= 1, "incoming write did not trigger eviction");
        assert!(live.0 + live.1 <= 85, "live bytes {} still above target", live.0 + live.1);

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tick_reconciles_drifted_counters_and_records_sweep_time() {
        let dir = temp_dir("reaper-reconcile");
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);
        let cfg_tick = cfg.clone();

        db.write(|c| {
            c.execute(
                "INSERT INTO events(id, owner, collection, created_at, expires_at, data, labels, size, mime, state)
                 VALUES (?1, ?2, 'c', 1, 9999999999, x'', '[]', 30, 'application/json', 'live')",
                rusqlite::params![[9u8; 32], [0u8; 32]],
            )
            .unwrap();
            // Deliberately leave live_bytes_events stale at zero.
        })
        .await;

        let before = now();
        reaper_tick(&db, cfg_tick).await;

        let (ev, _) = db.read(|c| crate::db::live_bytes(c)).await;
        assert_eq!(ev, 30, "reaper did not reconcile the event byte counter");
        assert!(last_sweep_at() >= before, "reaper did not record the sweep time");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
