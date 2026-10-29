use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::SystemTime;

use rusqlite::Connection;

use crate::config::Config;
use crate::db::Db;

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

/// Layer 3: largest-unit-first eviction at the watermark until
/// `live_bytes <= target (85%)`, capped at ~20% of budget per pass.
/// `unit_size(E) = E.size + Σ blob.size / n_live_referrers(blob)` (pro-rata);
/// tie-break: age ASC (created_at), then id ASC — deterministic.
pub fn evict_pass(c: &Connection, cfg: &Config) -> EvictionStats {
    let mut out = EvictionStats::default();

    let (ev, bl) = crate::db::live_bytes(c);
    let total = ev + bl;
    if total as u64 <= cfg.watermark_bytes {
        sync_cache(ev, bl);
        return out;
    }

    struct Unit {
        id: [u8; 32],
        size: i64,
        created_at: i64,
        attach: i64, // pro-rata attachment share
    }

    let mut units: Vec<Unit> = Vec::new();
    {
        let mut stmt = c.prepare("SELECT id, size, created_at FROM events WHERE state='live'").unwrap();
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
    {
        // pro-rata: event's share of each attached blob = blob.size / total referrers
        let mut attach: HashMap<[u8; 32], i64> = HashMap::new();
        let mut stmt = c
            .prepare(
                "SELECT r.event_id, b.size,
                        (SELECT COUNT(*) FROM refs x WHERE x.blob_hash = r.blob_hash)
                 FROM refs r JOIN blobs b ON b.hash = r.blob_hash",
            )
            .unwrap();
        let mut rows = stmt.query([]).unwrap();
        while let Some(r) = rows.next().unwrap() {
            let eid: Vec<u8> = r.get(0).unwrap();
            let bsize: i64 = r.get(1).unwrap();
            let refs: i64 = r.get(2).unwrap();
            let share = bsize / refs.max(1);
            *attach.entry(id32(&eid)).or_insert(0) += share;
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

    let target = cfg.eviction_target_bytes as i64;
    let cap = pass_cap(cfg);
    let dir = cfg.data_dir.clone();

    let mut evicted_bytes = 0i64;
    for u in &units {
        if total - evicted_bytes <= target || evicted_bytes >= cap {
            break;
        }
        let id = u.id;
        let freed = crate::store::blobs::delete_events(c, std::slice::from_ref(&id), &dir).unwrap_or(0);
        evicted_bytes += freed;
        out.events_evicted += 1;
    }

    // die-with-parent follows every event deletion (blobs with no live refs)
    let report = crate::store::blobs::blob_pass(c, now(), &dir).unwrap_or_default();

    out.blobs_evicted = report.blobs_removed as u64;
    out.bytes_reclaimed = (evicted_bytes + report.blob_bytes).max(0) as u64;
    add(&COUNTERS.events_evicted, out.events_evicted);
    add(&COUNTERS.blobs_evicted, out.blobs_evicted);
    add(&COUNTERS.bytes_reclaimed, out.bytes_reclaimed);
    let (ev2, bl2) = crate::db::live_bytes(c);
    sync_cache(ev2, bl2);
    out
}

fn sync_cache(ev: i64, bl: i64) {
    COUNTERS.live_events_cache.store(ev, Ordering::Relaxed);
    COUNTERS.live_blobs_cache.store(bl, Ordering::Relaxed);
}

/// Layer 2 entry for write paths: evict until `live_bytes + incoming` fits
/// below the 90% watermark; Err(at_watermark) when nothing more can free.
pub fn pressure_check(c: &Connection, cfg: &Config, incoming: u64) -> Result<(), crate::error::ApiError> {
    for _ in 0..40 {
        let (ev, bl) = crate::db::live_bytes(c);
        let total = (ev + bl) as u64;
        sync_cache(ev, bl);
        if total + incoming <= cfg.watermark_bytes {
            return Ok(());
        }
        let out = evict_pass(c, cfg);
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
            sweep_once(conn, &cfg);
            evict_pass(conn, &cfg);
            0
        })
        .await;
}
