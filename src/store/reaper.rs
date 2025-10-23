use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use rusqlite::Connection;

use crate::config::Config;
use crate::db::Db;

/// Periodic maintenance cadence. The startup pass runs immediately; after
/// that, idle nodes still reclaim expired data without waiting an hour.
pub const REAPER_INTERVAL: Duration = Duration::from_secs(300);

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Eviction & reclaim counters for /api/v1/node.
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
    pub unclaimed_blobs_evicted: AtomicU64,
    pub unclaimed_bytes_reclaimed: AtomicU64,
    pub live_blobs_cache: AtomicI64,
    pub live_events_cache: AtomicI64,
}

pub static COUNTERS: Counters = Counters {
    events_evicted: AtomicU64::new(0),
    blobs_evicted: AtomicU64::new(0),
    bytes_reclaimed: AtomicU64::new(0),
    unclaimed_blobs_evicted: AtomicU64::new(0),
    unclaimed_bytes_reclaimed: AtomicU64::new(0),
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

fn record(out: &EvictionStats) {
    add(&COUNTERS.events_evicted, out.events_evicted);
    add(&COUNTERS.blobs_evicted, out.blobs_evicted);
    add(&COUNTERS.bytes_reclaimed, out.bytes_reclaimed);
}

/// Record unclaimed-cap evictions separately from TTL/pressure eviction.
pub fn record_unclaimed_eviction(blobs: u64, bytes: u64) {
    add(&COUNTERS.unclaimed_blobs_evicted, blobs);
    add(&COUNTERS.unclaimed_bytes_reclaimed, bytes);
}

/// Decode a stored 32-byte id without panicking on a malformed row.
fn id32(v: &[u8]) -> Option<[u8; 32]> {
    v.try_into().ok()
}

/// A failed eviction query must refuse the write, never panic the request.
fn eviction_error(e: rusqlite::Error) -> crate::error::ApiError {
    tracing::error!(error = %e, "eviction query failed");
    crate::error::ApiError::internal("storage failure")
}

// ---------------------------------------------------------------------------
// Combined-budget eviction
//
// Events and claimed blobs share one ceiling (`STORAGE`). Unclaimed blobs
// are outside it. Eviction first removes whole events (which may also unclaim
// their blobs), then claimed blobs as a last resort. Records protected by
// `POLICY` rules are excluded from every victim sweep; TTL still expires
// them.
// ---------------------------------------------------------------------------

/// One pressure-eviction candidate: a live event plus the blobs only it keeps
/// alive. `footprint` is what deleting this event actually frees from the
/// combined budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventVictim {
    pub id: [u8; 32],
    /// Envelope bytes charged to the budget.
    pub envelope_size: i64,
    /// Live blob bytes that become uncharged when this event is deleted.
    pub blob_bytes: i64,
    pub created_at: i64,
}

impl EventVictim {
    /// Total charged bytes reclaimed by deleting this event.
    pub fn footprint(&self) -> i64 {
        self.envelope_size.saturating_add(self.blob_bytes)
    }
}

/// Correlated expression: live blob bytes that only the outer `e` event keeps
/// alive. A blob shared with another live event is worth zero here because
/// deleting one claimant frees no charged bytes.
const SOLE_CLAIMED_BLOB_BYTES: &str = "COALESCE((
    SELECT SUM(b.size)
      FROM blob_refs r
      JOIN blobs b ON b.hash = r.hash
     WHERE r.event_id = e.id
       AND NOT EXISTS (
           SELECT 1
             FROM blob_refs r2
             JOIN events e2 ON e2.id = r2.event_id
            WHERE r2.hash = r.hash
              AND e2.id <> e.id
       )
), 0)";

/// Live events ranked as pressure victims, biggest total footprint first.
///
/// The footprint is the event envelope plus every live blob that **only** this
/// event claims. A blob shared with another live event frees no charged bytes
/// when one claimant goes, so it is not counted. Events matching a
/// `POLICY` rule are excluded entirely; TTL still expires them.
///
/// Ties fall back to the older event, then the lower id, so eviction is
/// deterministic.
pub fn event_victims(c: &Connection, cfg: &Config) -> rusqlite::Result<Vec<EventVictim>> {
    let sql = format!(
        "SELECT e.id, e.size, e.created_at, {}
           FROM events e{}",
        SOLE_CLAIMED_BLOB_BYTES,
        cfg.policy
            .exclusion_where("e")
            .map(|(w, _)| format!(" {w}"))
            .unwrap_or_default()
    );
    let params: Vec<rusqlite::types::Value> = cfg
        .policy
        .rule_clause("e", false, 1)
        .map(|(_, p)| p)
        .unwrap_or_default();

    let mut stmt = c.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params.iter()))?;
    let mut victims = Vec::new();
    while let Some(r) = rows.next()? {
        let id_raw: Vec<u8> = r.get(0)?;
        let Some(id) = id32(&id_raw) else {
            tracing::warn!(
                len = id_raw.len(),
                "skipping event row with a malformed id during eviction"
            );
            continue;
        };
        victims.push(EventVictim {
            id,
            envelope_size: r.get(1)?,
            created_at: r.get(2)?,
            blob_bytes: r.get(3)?,
        });
    }

    victims.sort_by(|a, b| {
        b.footprint()
            .cmp(&a.footprint())
            .then(a.created_at.cmp(&b.created_at))
            .then(a.id.cmp(&b.id))
    });
    Ok(victims)
}

/// Snapshot of what pressure eviction could reclaim right now, without
/// building the full victim list. Used by `/api/v1/node` and operator diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EvictionSummary {
    /// Live events that may be evicted (policy-exempt records excluded).
    pub candidates: i64,
    /// Charged envelope bytes across those candidates.
    pub envelope_bytes: i64,
    /// Blob bytes that would become uncharged if every candidate went.
    pub blob_bytes: i64,
    /// Footprint of the single largest candidate, in charged bytes.
    pub largest_footprint: i64,
}

impl EvictionSummary {
    /// Total charged bytes reclaimable from all candidates.
    pub fn reclaimable_bytes(&self) -> i64 {
        self.envelope_bytes.saturating_add(self.blob_bytes)
    }
}

/// Summarize the current eviction candidates in one scan.
pub fn eviction_summary(c: &Connection, cfg: &Config) -> rusqlite::Result<EvictionSummary> {
    let sql = format!(
        "WITH victims AS (
             SELECT e.size AS envelope_size,
                    e.size + {} AS footprint
               FROM events e{}
         )
         SELECT COUNT(*),
                COALESCE(SUM(envelope_size), 0),
                COALESCE(SUM(footprint), 0),
                COALESCE(MAX(footprint), 0)
           FROM victims",
        SOLE_CLAIMED_BLOB_BYTES,
        cfg.policy
            .exclusion_where("e")
            .map(|(w, _)| format!(" {w}"))
            .unwrap_or_default()
    );

    let params: Vec<rusqlite::types::Value> = cfg
        .policy
        .rule_clause("e", false, 1)
        .map(|(_, p)| p)
        .unwrap_or_default();
    let (candidates, envelope_bytes, footprint_bytes, largest_footprint) =
        c.query_row(&sql, rusqlite::params_from_iter(params.iter()), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
    Ok(EvictionSummary {
        candidates,
        envelope_bytes,
        blob_bytes: footprint_bytes.saturating_sub(envelope_bytes),
        largest_footprint,
    })
}

/// Delete live events one at a time, largest total footprint first, until
/// charged usage is at or below `target`. Each iteration re-reads the
/// authoritative combined counter, so eviction stops as soon as the needed
/// space is free.
fn event_evict_to(c: &Connection, cfg: &Config, target: i64) -> rusqlite::Result<EvictionStats> {
    let mut out = EvictionStats::default();

    let used0 = crate::db::used_bytes(c);
    let mut used = used0;
    if used <= target {
        return Ok(out);
    }

    let victims = event_victims(c, cfg)?;
    if !victims.is_empty() {
        let top = victims
            .iter()
            .take(5)
            .map(|v| {
                format!(
                    "{} env={}B blob={}B total={}B",
                    hex::encode(v.id),
                    v.envelope_size,
                    v.blob_bytes,
                    v.footprint()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        tracing::info!(
            candidates = victims.len(),
            used,
            target,
            top = %top,
            "event eviction candidates"
        );
    }

    for victim in victims {
        if used <= target {
            break;
        }
        match crate::store::events::delete_events(c, std::slice::from_ref(&victim.id)) {
            Ok(n) if n > 0 => {}
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!(error = %e, "event eviction failed; continuing with the next row");
                continue;
            }
        }
        used = crate::db::used_bytes(c);
        out.events_evicted += 1;
    }
    if used > target && out.events_evicted == 0 && !cfg.policy.is_empty() {
        tracing::warn!(
            used,
            target,
            rules = cfg.policy.rule_count(),
            "over budget but only policy-exempt events remain; writes will be refused"
        );
    }
    out.bytes_reclaimed = (used0 - used).max(0) as u64;
    if out.events_evicted > 0 {
        tracing::info!(
            evicted = out.events_evicted,
            freed_bytes = out.bytes_reclaimed,
            used_after = used,
            target,
            "event eviction complete"
        );
    }
    Ok(out)
}

/// Delete the tiered blob victims until charged usage is at or below
/// `target`. The tier list lives in `blobs::blob_pressure_pass_with`.
fn blob_evict_to(
    c: &Connection,
    cfg: &Config,
    now: i64,
    target: i64,
    unlinks: &mut crate::store::blobs::UnlinkQueue,
) -> EvictionStats {
    let mut out = EvictionStats::default();
    let report = crate::store::blobs::blob_pressure_pass_with(
        c,
        now,
        target,
        &cfg.data_dir,
        unlinks,
        &cfg.policy,
    )
    .unwrap_or_default();
    out.blobs_evicted = report.blobs_removed as u64;
    out.bytes_reclaimed = report.blob_bytes.max(0) as u64;
    out
}

/// Passive maintenance: reclaim expired rows, then trim the combined budget
/// only if it is over its watermark.
pub fn evict_pass(c: &Connection, cfg: &Config) -> rusqlite::Result<EvictionStats> {
    let mut unlinks = crate::store::blobs::UnlinkQueue::new();
    let out = evict_pass_with(c, cfg, &mut unlinks);
    unlinks.flush();
    out
}

fn evict_pass_with(
    c: &Connection,
    cfg: &Config,
    unlinks: &mut crate::store::blobs::UnlinkQueue,
) -> rusqlite::Result<EvictionStats> {
    let mut out = EvictionStats::default();
    let now = now();

    let used0 = crate::db::used_bytes(c);
    sync_cache(c);

    if used0.max(0) as u64 > cfg.watermark_bytes() {
        let r = event_evict_to(c, cfg, cfg.target_bytes() as i64)?;
        out.events_evicted += r.events_evicted;
        out.bytes_reclaimed += r.bytes_reclaimed;
    }

    // Expired blobs are pure overhead: free them before any pressure
    // decision. This is housekeeping, not chargeable to the target.
    let report =
        crate::store::blobs::blob_pass_with(c, now, &cfg.data_dir, unlinks).unwrap_or_default();
    out.blobs_evicted += report.blobs_removed as u64;
    out.bytes_reclaimed += report.blob_bytes.max(0) as u64;

    if crate::db::used_bytes(c).max(0) as u64 > cfg.watermark_bytes() {
        let r = blob_evict_to(c, cfg, now, cfg.target_bytes() as i64, unlinks);
        out.blobs_evicted += r.blobs_evicted;
        out.bytes_reclaimed += r.bytes_reclaimed;
    }

    sync_cache(c);
    record(&out);
    Ok(out)
}

/// Bytes held by policy-matching records: live envelopes plus the blobs their live
/// events claim, each blob counted once. Used by /api/v1/node so an operator
/// can see why a write was refused when only policy data remains.
pub fn policy_bytes(c: &Connection, cfg: &Config) -> (i64, i64) {
    if cfg.policy.is_empty() {
        return (0, 0);
    }
    // `rule_clause` is Some: the empty case returned above.
    let (events_frag, events_params) = cfg.policy.rule_clause("e", false, 1).unwrap();
    let events = c
        .query_row(
            &format!("SELECT COALESCE(SUM(size),0) FROM events e WHERE ({events_frag})"),
            rusqlite::params_from_iter(events_params.iter()),
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0);

    let (blobs_frag, blobs_params) = cfg.policy.rule_clause("e2", false, 1).unwrap();
    let blobs = c
        .query_row(
            &format!(
                "SELECT COALESCE(SUM(size),0) FROM blobs b
                  WHERE EXISTS (
                      SELECT 1 FROM blob_refs r
                        JOIN events e2 ON e2.id = r.event_id
                       WHERE r.hash = b.hash AND ({blobs_frag})
                    )"
            ),
            rusqlite::params_from_iter(blobs_params.iter()),
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0);

    (events, blobs)
}

fn sync_cache(c: &Connection) {
    let (ev, cl) = crate::db::live_bytes(c);
    COUNTERS.live_events_cache.store(ev, Ordering::Relaxed);
    COUNTERS.live_blobs_cache.store(cl, Ordering::Relaxed);
}

/// Combined-budget admission for a write of `incoming` charged bytes
/// (envelope plus any blobs it newly claims). Reclaims events first, then
/// claimed blobs. Err(`at_watermark`) when the write cannot fit.
pub fn event_pressure_check(
    c: &Connection,
    cfg: &Config,
    incoming: u64,
) -> Result<(), crate::error::ApiError> {
    sync_cache(c);

    // An item that cannot fit even in an empty store must be refused before
    // we destroy existing data trying to make room for it.
    if incoming > cfg.watermark_bytes() {
        return Err(crate::error::ApiError::at_watermark());
    }

    for _ in 0..40 {
        let used = crate::db::used_bytes(c).max(0) as u64;
        if used + incoming <= cfg.watermark_bytes() {
            return Ok(());
        }
        let target = cfg
            .target_bytes()
            .min(cfg.watermark_bytes().saturating_sub(incoming)) as i64;
        let out = event_evict_to(c, cfg, target).map_err(eviction_error)?;
        record(&out);
        if out.events_evicted == 0 {
            // Deleting an event also unclaims any blobs only it referenced,
            // so event eviction alone always frees the charged blob bytes.
            return Err(crate::error::ApiError::at_watermark());
        }
    }
    Err(crate::error::ApiError::at_watermark())
}

/// Admission for a blob write. Unclaimed uploads are free (6-hour window);
/// claimed uploads are charged and may trigger combined eviction.
pub fn blob_pressure_check(
    c: &Connection,
    cfg: &Config,
    incoming: u64,
    claimed: bool,
    unlinks: &mut crate::store::blobs::UnlinkQueue,
) -> Result<(), crate::error::ApiError> {
    if !claimed {
        return Ok(());
    }
    let now = now();
    sync_cache(c);

    if incoming > cfg.watermark_bytes() {
        return Err(crate::error::ApiError::at_watermark());
    }

    // Expired blobs are free capacity and never count against the target.
    let report =
        crate::store::blobs::blob_pass_with(c, now, &cfg.data_dir, unlinks).unwrap_or_default();
    if report.blobs_removed > 0 {
        let out = EvictionStats {
            blobs_evicted: report.blobs_removed as u64,
            bytes_reclaimed: report.blob_bytes.max(0) as u64,
            ..Default::default()
        };
        record(&out);
    }

    for _ in 0..40 {
        let used = crate::db::used_bytes(c).max(0) as u64;
        if used + incoming <= cfg.watermark_bytes() {
            sync_cache(c);
            return Ok(());
        }
        let target = cfg
            .target_bytes()
            .min(cfg.watermark_bytes().saturating_sub(incoming)) as i64;
        let ev = event_evict_to(c, cfg, target).map_err(eviction_error)?;
        record(&ev);
        if crate::db::used_bytes(c).max(0) as u64 + incoming <= cfg.watermark_bytes() {
            sync_cache(c);
            return Ok(());
        }
        let out = blob_evict_to(c, cfg, now, target, unlinks);
        record(&out);
        if ev.events_evicted == 0 && out.blobs_evicted == 0 {
            return Err(crate::error::ApiError::at_watermark());
        }
    }
    Err(crate::error::ApiError::at_watermark())
}

/// Layer 1: expiry sweep — events by `expires_at` (≤ now), then blobs by
/// their derived deadline (event claim or the 6-hour unclaimed window).
pub fn sweep_once(c: &Connection, cfg: &Config) -> rusqlite::Result<EvictionStats> {
    let mut out = EvictionStats::default();
    let now_n = now();

    let mut ids: Vec<[u8; 32]> = Vec::new();
    {
        let mut stmt = c.prepare("SELECT id FROM events WHERE expires_at <= ?1")?;
        let mut rows = stmt.query([now_n])?;
        while let Some(r) = rows.next()? {
            let id_raw: Vec<u8> = r.get(0)?;
            let Some(id) = id32(&id_raw) else {
                tracing::warn!(
                    len = id_raw.len(),
                    "skipping expired event with a malformed id"
                );
                continue;
            };
            ids.push(id);
        }
    }
    let freed = match crate::store::events::delete_events(c, &ids) {
        Ok(freed) => freed,
        Err(e) => {
            tracing::warn!(error = %e, "expired event deletion failed; continuing");
            0
        }
    };
    out.events_evicted = ids.len() as u64;
    out.bytes_reclaimed = freed.max(0) as u64;
    add(&COUNTERS.events_evicted, out.events_evicted);
    add(&COUNTERS.bytes_reclaimed, out.bytes_reclaimed);

    let report = crate::store::blobs::blob_pass(c, now_n, &cfg.data_dir).unwrap_or_default();
    out.blobs_evicted = report.blobs_removed as u64;
    out.bytes_reclaimed += report.blob_bytes.max(0) as u64;
    add(&COUNTERS.blobs_evicted, out.blobs_evicted);

    // Enforce the unclaimed byte and blob-count caps even without a new
    // upload, so a lowered cap takes effect on the next sweep.
    let mut unlinks = crate::store::blobs::UnlinkQueue::new();
    if let Some(trim) = crate::store::blobs::trim_unclaimed(c, cfg, 0, &mut unlinks)? {
        add(&COUNTERS.unclaimed_blobs_evicted, trim.blobs);
        add(&COUNTERS.unclaimed_bytes_reclaimed, trim.bytes);
    }
    unlinks.flush();

    sync_cache(c);
    Ok(out)
}

/// The reaper task body. A failed or panicking pass must never kill the
/// periodic loop or leave `last_sweep_at` looking fresh.
pub async fn reaper_tick(db: &Db, cfg: Config) {
    let tick = db
        .write(move |conn: &Connection| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // Cheap table scan once per cadence: repair any counter drift before
                // this pass makes eviction decisions from those totals.
                crate::db::reconcile_counters(conn);
                sweep_once(conn, &cfg)?;
                evict_pass(conn, &cfg)?;
                let _ = conn.execute("DELETE FROM sync_nonces WHERE expires_at < ?1", [now()]);
                let _ = conn.execute(
                    "DELETE FROM sync_blob_queue
                     WHERE attempts >= 10
                        OR (?1 - first_seen_at) > 86400
                        OR hash NOT IN (SELECT hash FROM blob_refs)",
                    [now()],
                );
                let removed = crate::store::blobs::cleanup_tmp(
                    &cfg.data_dir,
                    crate::store::blobs::TMP_FILE_TTL,
                );
                if removed > 0 {
                    tracing::info!(removed, "removed stale upload temp files");
                }
                Ok::<(), rusqlite::Error>(())
            }))
        })
        .await;

    match tick {
        Ok(Ok(())) => {
            LAST_SWEEP_AT.store(now(), Ordering::Relaxed);
            tracing::debug!("reaper tick completed");
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "reaper tick failed; retaining the previous sweep time");
        }
        Err(_) => {
            tracing::error!("reaper tick panicked; keeping the periodic loop alive");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rabta-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_cfg(dir: &std::path::Path) -> Config {
        Config::test_cfg(dir.to_path_buf(), 100)
    }

    fn seed_events(c: &Connection, count: u8, size: i64) {
        for i in 1..=count {
            c.execute(
                "INSERT INTO events(id, owner, collection, created_at, expires_at, data, size)
                 VALUES (?1, ?2, 'c', 1, 9999999999, x'', ?3)",
                rusqlite::params![[i; 32], [0u8; 32], size],
            )
            .unwrap();
        }
        crate::db::bump_counters(c, size * count as i64, 0, 0).unwrap();
    }

    /// Passive maintenance must do nothing at exactly the event watermark,
    /// while a demand write must free room for itself.
    #[tokio::test]
    async fn evicts_to_admit_an_incoming_event_at_the_watermark() {
        let dir = temp_dir("reaper-demand");
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);

        let cfg_idle = cfg.clone();
        let idle = db
            .write(move |c| {
                // Exactly the event watermark (100 bytes).
                seed_events(c, 2, 50);
                evict_pass(c, &cfg_idle).unwrap()
            })
            .await;
        assert_eq!(
            idle.events_evicted, 0,
            "passive pass evicted at the watermark"
        );

        let cfg_pressure = cfg.clone();
        let (live, _) = db
            .write(move |c| {
                event_pressure_check(c, &cfg_pressure, 10).unwrap();
                crate::db::live_bytes(c)
            })
            .await;
        assert!(
            live <= cfg.target_bytes() as i64,
            "store {} still above target {}",
            live,
            cfg.target_bytes()
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unclaimed_blob_upload_never_evicts_events() {
        let dir = temp_dir("reaper-blob-isolation");
        let db = Db::open(&dir);
        let cfg = Config::test_cfg(dir.clone(), 100);
        let cfg2 = cfg.clone();
        let events = db
            .write(move |c| {
                seed_events(c, 1, 90);
                c.execute(
                    "INSERT INTO blobs(hash,size,stored_at,expires_at)
                     VALUES (?1, 90, 1, 9999999999)",
                    rusqlite::params![&[7u8; 32][..]],
                )
                .unwrap();
                crate::db::bump_counters(c, 0, 90, 0).unwrap();
                let mut unlinks = crate::store::blobs::UnlinkQueue::new();
                blob_pressure_check(c, &cfg2, 20, false, &mut unlinks).unwrap();
                unlinks.flush();
                crate::db::live_bytes(c).0
            })
            .await;
        assert_eq!(events, 90, "unclaimed blob pressure reclaimed events");

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
                "INSERT INTO events(id, owner, collection, created_at, expires_at, data, size)
                 VALUES (?1, ?2, 'c', 1, 9999999999, x'', 30)",
                rusqlite::params![[9u8; 32], [0u8; 32]],
            )
            .unwrap();
            // Deliberately leave live_bytes_events stale at zero.
        })
        .await;

        let before = now();
        reaper_tick(&db, cfg_tick).await;

        let (ev, _) = db.read(crate::db::live_bytes).await;
        assert_eq!(ev, 30, "reaper did not reconcile the event byte counter");
        assert!(
            last_sweep_at() >= before,
            "reaper did not record the sweep time"
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupt row must be skipped, not unwrapped into a panic that would
    /// take the whole reaper task down with it.
    #[test]
    fn malformed_event_id_is_skipped_during_eviction() {
        let dir = temp_dir("reaper-malformed-id");
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        c.execute(
            "INSERT INTO events(id, owner, collection, created_at, expires_at, data, size)
             VALUES (?1, ?2, 'c', 1, 9999999999, x'', 90)",
            rusqlite::params![[2u8; 32], [0u8; 32]],
        )
        .unwrap();
        // SQLite does not enforce BLOB(32); simulate a corrupt/short id.
        c.execute(
            "INSERT INTO events(id, owner, collection, created_at, expires_at, data, size)
             VALUES (x'010203', ?1, 'c', 1, 9999999999, x'', 90)",
            rusqlite::params![[0u8; 32]],
        )
        .unwrap();
        crate::db::bump_counters(&c, 180, 0, 0).unwrap();

        let out = evict_pass(&c, &test_cfg(&dir)).expect("a malformed row aborted eviction");
        assert_eq!(out.events_evicted, 1);
        let remaining: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 1, "the malformed row was unexpectedly deleted");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A broken schema is reported as an error, never as a panic.
    #[test]
    fn sweep_reports_a_missing_schema_instead_of_panicking() {
        let dir = temp_dir("reaper-noschema");
        let c = Connection::open_in_memory().unwrap();
        let err = sweep_once(&c, &test_cfg(&dir)).expect_err("missing schema must be an error");
        assert!(
            err.to_string().contains("no such table"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The periodic loop survives a failed tick and stays alive for the next.
    #[tokio::test]
    async fn reaper_tick_survives_a_broken_schema() {
        let dir = temp_dir("reaper-broken");
        let db = Db::open(&dir);
        db.write(|c| c.execute("DROP TABLE events", []).unwrap())
            .await;

        reaper_tick(&db, test_cfg(&dir)).await;
        // Reaching this point is the assertion: the tick did not panic.

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn insert_event(c: &Connection, id: u8, owner: [u8; 32], size: i64, expires_at: i64) {
        c.execute(
            "INSERT INTO events(id, owner, collection, created_at, expires_at, data, size)
             VALUES (?1, ?2, 'c', 1, ?3, x'', ?4)",
            rusqlite::params![[id; 32], &owner[..], expires_at, size],
        )
        .unwrap();
    }

    /// Insert one live blob and claim it from `event_id`. The counters move the
    /// same way a real upload + event reference would (blob bytes and
    /// sole-claimed bytes).
    fn insert_blob_ref(c: &Connection, hash: u8, event_id: u8, size: i64) {
        c.execute(
            "INSERT INTO blobs(hash, size, stored_at, expires_at)
             VALUES (?1, ?2, 1, 9999999999)",
            rusqlite::params![[hash; 32], size],
        )
        .unwrap();
        c.execute(
            "INSERT INTO blob_refs(hash, event_id) VALUES (?1, ?2)",
            rusqlite::params![[hash; 32], [event_id; 32]],
        )
        .unwrap();
        crate::db::bump_counters(c, 0, size, size).unwrap();
    }

    /// Ranking uses the event envelope **plus** blobs only that event keeps
    /// alive; a shared blob counts for nobody.
    #[tokio::test]
    async fn event_victims_rank_by_envelope_plus_sole_claimed_blobs() {
        let dir = temp_dir("reaper-footprint");
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);

        db.write(|c| -> rusqlite::Result<()> {
            // Event 1: 10-byte envelope + a 100-byte blob only it claims = 110.
            insert_event(c, 1, [0u8; 32], 10, 9_999_999_999);
            insert_blob_ref(c, 1, 1, 100);
            // Event 2: 150-byte envelope, no blobs = 150.
            insert_event(c, 2, [0u8; 32], 150, 9_999_999_999);
            // Event 3: 20-byte envelope, no blobs = 20.
            insert_event(c, 3, [0u8; 32], 20, 9_999_999_999);
            crate::db::bump_counters(c, 180, 0, 0)
        })
        .await
        .unwrap();

        let cfg_victims = cfg.clone();
        let victims = db
            .read(move |c| event_victims(c, &cfg_victims))
            .await
            .unwrap();
        assert_eq!(
            victims.iter().map(|v| v.id).collect::<Vec<_>>(),
            vec![[2u8; 32], [1u8; 32], [3u8; 32]],
            "victims were not ranked by envelope + sole-claimed blob bytes"
        );
        assert_eq!(victims[1].blob_bytes, 100);
        assert_eq!(victims[1].footprint(), 110);
        assert_eq!(victims[0].footprint(), 150);

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn shared_blobs_are_not_counted_in_any_event_footprint() {
        let dir = temp_dir("reaper-shared-blob");
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);

        db.write(|c| -> rusqlite::Result<()> {
            insert_event(c, 1, [0u8; 32], 40, 9_999_999_999);
            insert_event(c, 2, [0u8; 32], 20, 9_999_999_999);
            insert_event(c, 3, [0u8; 32], 10, 9_999_999_999);
            crate::db::bump_counters(c, 70, 0, 0)?;
            // One 100-byte blob kept alive by both event 1 and event 2.
            insert_blob_ref(c, 9, 1, 100);
            c.execute(
                "INSERT INTO blob_refs(hash, event_id) VALUES (?1, ?2)",
                rusqlite::params![&[9u8; 32][..], &[2u8; 32][..]],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let cfg_victims = cfg.clone();
        let victims = db
            .read(move |c| event_victims(c, &cfg_victims))
            .await
            .unwrap();
        assert_eq!(
            victims.iter().map(|v| v.blob_bytes).collect::<Vec<_>>(),
            vec![0, 0, 0],
            "a shared blob was charged to a victim"
        );
        assert_eq!(
            victims.iter().map(|v| v.id).collect::<Vec<_>>(),
            vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            "shared-blob events were not ranked by envelope size"
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `/api/v1/node` sees what eviction could reclaim: candidates, bytes, largest.
    #[tokio::test]
    async fn eviction_summary_reports_candidates_and_reclaimable_bytes() {
        let dir = temp_dir("reaper-summary");
        let db = Db::open(&dir);
        let mut cfg = test_cfg(&dir);
        let pinned = [0x55u8; 32];
        cfg.policy = Rules::test_owner(pinned);

        db.write(move |c| -> rusqlite::Result<()> {
            // Evictable: 10-byte envelope + a 100-byte sole blob = 110.
            insert_event(c, 1, [0u8; 32], 10, 9_999_999_999);
            insert_blob_ref(c, 1, 1, 100);
            // Evictable: 20-byte envelope, no blobs.
            insert_event(c, 2, [0u8; 32], 20, 9_999_999_999);
            // Pinned: excluded from the summary.
            insert_event(c, 3, pinned, 30, 9_999_999_999);
            insert_blob_ref(c, 2, 3, 200);
            crate::db::bump_counters(c, 60, 0, 0)
        })
        .await
        .unwrap();

        let cfg_summary = cfg.clone();
        let summary = db
            .read(move |c| eviction_summary(c, &cfg_summary))
            .await
            .unwrap();
        assert_eq!(summary.candidates, 2);
        assert_eq!(summary.envelope_bytes, 30);
        assert_eq!(summary.blob_bytes, 100);
        assert_eq!(summary.reclaimable_bytes(), 130);
        assert_eq!(summary.largest_footprint, 110);

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Evict the biggest total footprint first and stop as soon as the target
    /// is reached, without deleting extra events.
    #[tokio::test]
    async fn eviction_removes_biggest_footprint_first_and_stops_at_target() {
        let dir = temp_dir("reaper-footprint-evict");
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir); // store 100 -> watermark 90, target 85

        db.write(move |c| -> rusqlite::Result<()> {
            for i in 1..=3u8 {
                insert_event(c, i, [0u8; 32], 30, 9_999_999_999);
            }
            crate::db::bump_counters(c, 90, 0, 0)?;
            // Event 2 is 30-byte envelope + a sole-claimed 40-byte blob = 70,
            // making it the biggest victim.
            insert_blob_ref(c, 2, 2, 40);
            Ok(())
        })
        .await
        .unwrap();

        let cfg_evict = cfg.clone();
        let out = db
            .write(move |c| event_evict_to(c, &cfg_evict, cfg_evict.target_bytes() as i64))
            .await
            .unwrap();

        // 130 charged bytes; deleting event 2 frees 70, leaving 60 <= 85.
        assert_eq!(out.events_evicted, 1);
        let (present, used) = db
            .read(|c| {
                let exists = |id: u8| -> i64 {
                    c.query_row(
                        "SELECT EXISTS(SELECT 1 FROM events WHERE id = ?1)",
                        [&[id; 32][..]],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                (exists(2), crate::db::used_bytes(c))
            })
            .await;
        assert_eq!(present, 0, "the biggest-footprint event was not evicted");
        assert!(
            used <= cfg.target_bytes() as i64,
            "used {used} above target"
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pressure eviction deletes events to stay under budget.
    #[tokio::test]
    async fn pressure_eviction_removes_events() {
        let dir = temp_dir("reaper-evict-events");
        let db = Db::open(&dir);
        let cfg = test_cfg(&dir);

        db.write(move |c| -> rusqlite::Result<()> {
            for i in 1..=3u8 {
                insert_event(c, i, [0u8; 32], 30, 9_999_999_999);
            }
            crate::db::bump_counters(c, 90, 0, 0)?;
            Ok(())
        })
        .await
        .unwrap();

        let cfg_evict = cfg.clone();
        let out = db
            .write(move |c| event_evict_to(c, &cfg_evict, cfg_evict.target_bytes() as i64))
            .await
            .unwrap();
        assert!(out.events_evicted > 0, "something was evicted");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn protected_events_survive_pressure_eviction() {
        let dir = temp_dir("reaper-whitelist-keep");
        let db = Db::open(&dir);
        let pinned = [0x55u8; 32];

        let mut cfg = test_cfg(&dir);
        cfg.policy = crate::store::policy::PolicyRules::test_owner(pinned);

        db.write(move |c| -> rusqlite::Result<()> {
            for i in 1..=3u8 {
                insert_event(c, i, [0u8; 32], 30, 9_999_999_999);
            }
            insert_event(c, 9, pinned, 30, 9_999_999_999);
            crate::db::bump_counters(c, 120, 0, 0)
        })
        .await
        .unwrap();

        let cfg_evict = cfg.clone();
        db.write(move |c| evict_pass(c, &cfg_evict)).await.unwrap();

        let (pinned_rows, used) = db
            .read(move |c| {
                let rows: i64 = c
                    .query_row(
                        "SELECT COUNT(*) FROM events WHERE owner = ?1",
                        [&pinned[..]],
                        |r| r.get(0),
                    )
                    .unwrap();
                (rows, crate::db::used_bytes(c))
            })
            .await;
        assert_eq!(pinned_rows, 1, "the protected event was evicted");
        assert!(
            used <= cfg.watermark_bytes() as i64,
            "eviction left {used}, watermark {}",
            cfg.watermark_bytes()
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn protected_events_still_expire_on_ttl() {
        let dir = temp_dir("reaper-whitelist-ttl");
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        let pinned = [0x55u8; 32];
        insert_event(&c, 9, pinned, 30, now() - 1);
        crate::db::bump_counters(&c, 30, 0, 0).unwrap();

        let mut cfg = test_cfg(&dir);
        cfg.policy = crate::store::policy::PolicyRules::test_owner(pinned);

        let out = sweep_once(&c, &cfg).unwrap();
        assert_eq!(
            out.events_evicted, 1,
            "TTL must still apply to protected records"
        );
        let remaining: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn insert_event_in(
        c: &Connection,
        id: u8,
        owner: [u8; 32],
        collection: &str,
        size: i64,
        expires_at: i64,
        labels: &[&str],
    ) {
        c.execute(
            "INSERT INTO events(id, owner, collection, created_at, expires_at, data, size)
             VALUES (?1, ?2, ?3, 1, ?4, x'', ?5)",
            rusqlite::params![[id; 32], &owner[..], collection, expires_at, size],
        )
        .unwrap();
        for l in labels {
            c.execute(
                "INSERT OR IGNORE INTO labels(event_id, label) VALUES (?1, ?2)",
                rusqlite::params![[id; 32], l],
            )
            .unwrap();
        }
    }

    type Rules = crate::store::policy::PolicyRules;

    /// A `collection: ["arch*"]` rule protects `archive/*` events only.
    #[tokio::test]
    async fn collection_glob_rule_protects_matching_events() {
        let dir = temp_dir("reaper-policy-collection");
        let db = Db::open(&dir);
        let mut cfg = test_cfg(&dir);
        cfg.policy = Rules::test_rules(vec![crate::store::policy::PolicyRule::test_rule(
            Vec::new(),
            vec!["arch*".into()],
            Vec::new(),
        )]);

        let pinned = [0x55u8; 32];
        db.write(move |c| -> rusqlite::Result<()> {
            insert_event_in(c, 1, [0u8; 32], "notes", 40, 9_999_999_999, &[]);
            insert_event_in(c, 2, [0u8; 32], "other", 40, 9_999_999_999, &[]);
            insert_event_in(c, 3, pinned, "archive/a/b", 30, 9_999_999_999, &[]);
            crate::db::bump_counters(c, 110, 0, 0)
        })
        .await
        .unwrap();

        let cfg_evict = cfg.clone();
        db.write(move |c| evict_pass(c, &cfg_evict)).await.unwrap();

        let (archive_left, notes_left) = db
            .read(move |c| {
                let in_c = |col: &str| -> i64 {
                    c.query_row(
                        "SELECT COUNT(*) FROM events WHERE collection = ?1",
                        [col],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                (in_c("archive/a/b"), in_c("notes"))
            })
            .await;
        assert_eq!(
            archive_left, 1,
            "the collection rule did not protect archive/*"
        );
        assert_eq!(notes_left, 0, "unprotected events escaped eviction");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `labels: ["keep"]` rule protects every event carrying that label.
    #[tokio::test]
    async fn label_rule_protects_matching_events() {
        let dir = temp_dir("reaper-policy-label");
        let db = Db::open(&dir);
        let mut cfg = test_cfg(&dir);
        cfg.policy = Rules::test_rules(vec![crate::store::policy::PolicyRule::test_rule(
            Vec::new(),
            Vec::new(),
            vec!["keep*".into()],
        )]);

        db.write(move |c| -> rusqlite::Result<()> {
            insert_event_in(c, 1, [0u8; 32], "c", 30, 9_999_999_999, &[]);
            insert_event_in(c, 2, [0u8; 32], "c", 30, 9_999_999_999, &["keep"]);
            insert_event_in(c, 3, [0u8; 32], "c", 30, 9_999_999_999, &["keeper"]); // glob arm
            insert_event_in(c, 4, [0u8; 32], "c", 30, 9_999_999_999, &["other"]);
            crate::db::bump_counters(c, 120, 0, 0)
        })
        .await
        .unwrap();

        let cfg_evict = cfg.clone();
        db.write(move |c| evict_pass(c, &cfg_evict)).await.unwrap();

        let keepers: i64 = db
            .read(move |c| {
                c.query_row(
                    "SELECT COUNT(*) FROM events e
                      WHERE EXISTS (SELECT 1 FROM labels l WHERE l.event_id = e.id
                                    AND l.label IN ('keep', 'keeper'))",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
            })
            .await;
        assert_eq!(
            keepers, 2,
            "label-rule events were not both protected by the glob"
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `policy_bytes` sums policy-exempt envelopes and each claimed blob once.
    #[test]
    fn policy_bytes_counts_envelopes_and_claimed_blobs() {
        let dir = temp_dir("reaper-policy-bytes");
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        let pinned = [0x55u8; 32];
        insert_event(&c, 9, pinned, 30, 9_999_999_999);
        insert_blob_ref(&c, 1, 9, 100);
        insert_event(&c, 2, [0u8; 32], 50, 9_999_999_999);
        insert_blob_ref(&c, 3, 2, 70);

        let mut cfg = test_cfg(&dir);
        cfg.policy = Rules::test_owner(pinned);

        let (events, blobs) = policy_bytes(&c, &cfg);
        assert_eq!(events, 30);
        assert_eq!(blobs, 100);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn protected_only_store_refuses_new_writes() {
        let dir = temp_dir("reaper-whitelist-full");
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        // 99 of the 100-byte budget, all protected: the incoming write
        // crosses the admission line and nothing evictable remains.
        let pinned = [0x55u8; 32];
        for i in 1..=3u8 {
            insert_event(&c, i, pinned, 33, 9_999_999_999);
        }
        crate::db::bump_counters(&c, 99, 0, 0).unwrap();

        let mut cfg = test_cfg(&dir);
        cfg.policy = crate::store::policy::PolicyRules::test_owner(pinned);

        assert!(
            event_pressure_check(&c, &cfg, 10).is_err(),
            "a protected-only store must refuse rather than evict pinned data"
        );
        let remaining: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            remaining, 3,
            "protected events were deleted to admit a write"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A lowered unclaimed byte cap takes effect on the next sweep, without
    /// waiting for a new upload, and evicts the oldest orphan first.
    #[tokio::test]
    async fn sweep_enforces_the_unclaimed_byte_cap() {
        let dir = temp_dir("reaper-unclaimed-cap");
        crate::store::blobs::init_dirs(&dir).unwrap();
        let db = Db::open(&dir);
        let mut cfg = test_cfg(&dir);
        cfg.unclaimed_limit_bytes = 10;

        let old = [0x51u8; 32];
        let new = [0x52u8; 32];
        let cfg2 = cfg.clone();
        let dir2 = dir.clone();
        db.write(move |c| -> rusqlite::Result<()> {
            for (hash, stored_at) in [(old, 1), (new, 2)] {
                c.execute(
                    "INSERT INTO blobs(hash,size,stored_at,expires_at)
                     VALUES (?1, 8, ?2, 9999999999)",
                    rusqlite::params![&hash[..], stored_at],
                )?;
                std::fs::write(
                    crate::store::blobs::blob_path(&dir2, &hex::encode(hash)),
                    [0u8; 8],
                )
                .unwrap();
            }
            crate::db::bump_counters(c, 0, 16, 0)?;
            sweep_once(c, &cfg2)?;
            Ok(())
        })
        .await
        .unwrap();

        let (old_row, new_row) = db
            .read(move |c| {
                let exists = |h: &[u8; 32]| -> i64 {
                    c.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
                        [&h[..]],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                (exists(&old), exists(&new))
            })
            .await;
        assert_eq!(old_row, 0, "the sweep did not evict the oldest orphan");
        assert_eq!(new_row, 1, "the sweep over-evicted past the cap");
        assert!(!crate::store::blobs::blob_path(&dir, &hex::encode(old)).exists());
        assert!(crate::store::blobs::blob_path(&dir, &hex::encode(new)).exists());

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
