use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::store::events::live_clause;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeSummary {
    pub start: i64,
    pub end: i64,
    pub count: i64,
    pub digest: String, // 16-hex char string (8-byte XOR fold)
}

/// XOR-fold a 32-byte SHA-256 hash into 8 bytes.
pub fn xor_fold_8(hash: &[u8; 32]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = hash[i] ^ hash[i + 8] ^ hash[i + 16] ^ hash[i + 24];
    }
    out
}

// Tombstones are removed; all live events are visible to reconciliation.
const RECONCILE_VISIBLE: &str = "1=1";

/// Reconciliation covers the LIVE set only — the same rule as the public
/// reads. Expired-but-unswept rows would otherwise make peers diverge purely
/// because their reapers ran at different times, and responders would serve
/// dead-on-arrival events that the other side must reject.
///
/// Compute count and 8-byte XOR digest for live events in [start, end).
pub fn compute_range_summary(
    c: &Connection,
    now: i64,
    start: i64,
    end: i64,
) -> rusqlite::Result<RangeSummary> {
    let sql = format!(
        "SELECT id FROM events WHERE {} AND created_at >= ?2 AND created_at < ?3 AND {RECONCILE_VISIBLE} ORDER BY created_at ASC, id ASC",
        live_clause(1)
    );
    let mut stmt = c.prepare(&sql)?;
    let mut rows = stmt.query(params![now, start, end])?;
    let mut count: i64 = 0;
    let mut digest = [0u8; 8];

    while let Some(r) = rows.next()? {
        let raw: Vec<u8> = r.get(0)?;
        if raw.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&raw);
            let fold = xor_fold_8(&id);
            for i in 0..8 {
                digest[i] ^= fold[i];
            }
            count += 1;
        }
    }

    Ok(RangeSummary {
        start,
        end,
        count,
        digest: hex::encode(digest),
    })
}

/// Fetch all live event IDs in [start, end) up to limit.
pub fn fetch_event_ids_in_range(
    c: &Connection,
    now: i64,
    start: i64,
    end: i64,
    limit: usize,
) -> rusqlite::Result<Vec<[u8; 32]>> {
    let sql = format!(
        "SELECT id FROM events WHERE {} AND created_at >= ?2 AND created_at < ?3 AND {RECONCILE_VISIBLE} ORDER BY created_at ASC, id ASC LIMIT ?4",
        live_clause(1)
    );
    let mut stmt = c.prepare(&sql)?;
    let rows = stmt.query_map(params![now, start, end, limit as i64], |r| {
        let raw: Vec<u8> = r.get(0)?;
        let mut id = [0u8; 32];
        if raw.len() == 32 {
            id.copy_from_slice(&raw);
        }
        Ok(id)
    })?;

    let mut ids = Vec::new();
    for r in rows {
        ids.push(r?);
    }
    Ok(ids)
}

/// Fetch full event JSON values for live events in the given range up to limit.
#[allow(dead_code)]
pub fn fetch_events_in_range(
    c: &Connection,
    now: i64,
    start: i64,
    end: i64,
    limit: usize,
) -> rusqlite::Result<Vec<serde_json::Value>> {
    let sql = format!(
        "SELECT data FROM events WHERE {} AND created_at >= ?2 AND created_at < ?3 AND {RECONCILE_VISIBLE} ORDER BY created_at ASC, id ASC LIMIT ?4",
        live_clause(1)
    );
    let mut stmt = c.prepare(&sql)?;
    let rows = stmt.query_map(params![now, start, end, limit as i64], |r| {
        let raw: Vec<u8> = r.get(0)?;
        Ok(raw)
    })?;

    let mut events = Vec::new();
    for r in rows {
        let bytes = r?;
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            events.push(v);
        }
    }
    Ok(events)
}

/// Fetch full event JSON values for the given list of event IDs, live ones only.
pub fn fetch_events_by_ids(
    c: &Connection,
    now: i64,
    ids: &[[u8; 32]],
) -> rusqlite::Result<Vec<serde_json::Value>> {
    let mut events = Vec::with_capacity(ids.len());
    let sql = format!(
        "SELECT data FROM events WHERE {} AND id = ?2 AND {RECONCILE_VISIBLE}",
        live_clause(1)
    );
    let mut stmt = c.prepare(&sql)?;
    for id in ids {
        if let Ok(raw) = stmt.query_row(params![now, &id[..]], |r| r.get::<_, Vec<u8>>(0))
            && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&raw)
        {
            events.push(v);
        }
    }
    Ok(events)
}

/// Fetch full event JSON values for the most recent live events up to limit.
pub fn fetch_recent_events(
    c: &Connection,
    now: i64,
    limit: usize,
) -> rusqlite::Result<Vec<serde_json::Value>> {
    let sql = format!(
        "SELECT data FROM events WHERE {} ORDER BY created_at DESC, id DESC LIMIT ?2",
        live_clause(1)
    );
    let mut stmt = c.prepare(&sql)?;
    let rows = stmt.query_map(params![now, limit as i64], |r| {
        let raw: Vec<u8> = r.get(0)?;
        Ok(raw)
    })?;

    let mut events = Vec::new();
    for r in rows {
        let bytes = r?;
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            events.push(v);
        }
    }
    Ok(events)
}

/// Compute adaptive range partition.
/// If total events <= 64, returns a single range [0, i64::MAX).
/// If total events > 64, partitions into up to max_ranges slices.
pub fn get_adaptive_ranges(
    c: &Connection,
    now: i64,
    max_ranges: usize,
) -> rusqlite::Result<Vec<RangeSummary>> {
    let total_sql = format!(
        "SELECT COUNT(*) FROM events WHERE {} AND {RECONCILE_VISIBLE}",
        live_clause(1)
    );
    let total_count: i64 = c.query_row(&total_sql, params![now], |r| r.get(0))?;
    if total_count <= 64 {
        let summary = compute_range_summary(c, now, 0, i64::MAX)?;
        return Ok(vec![summary]);
    }

    let k = max_ranges.clamp(2, 32);
    let step = total_count / (k as i64);
    let mut boundaries = Vec::with_capacity(k + 1);
    boundaries.push(0i64);

    for i in 1..k {
        let offset = (i as i64) * step;
        let ts_sql = format!(
            "SELECT created_at FROM events WHERE {} AND {RECONCILE_VISIBLE} ORDER BY created_at ASC, id ASC LIMIT 1 OFFSET ?2",
            live_clause(1)
        );
        let ts: Option<i64> = c
            .query_row(&ts_sql, params![now, offset], |r| r.get(0))
            .ok();
        if let Some(t) = ts
            && t > *boundaries.last().unwrap()
        {
            boundaries.push(t);
        }
    }
    boundaries.push(i64::MAX);

    let mut ranges = Vec::with_capacity(boundaries.len() - 1);
    for i in 0..boundaries.len() - 1 {
        let start = boundaries[i];
        let end = boundaries[i + 1];
        let summary = compute_range_summary(c, now, start, end)?;
        ranges.push(summary);
    }

    Ok(ranges)
}

/// Split a divergent range in half.
pub fn split_range(
    c: &Connection,
    now: i64,
    start: i64,
    end: i64,
) -> rusqlite::Result<Vec<RangeSummary>> {
    let count_sql = format!(
        "SELECT COUNT(*) FROM events WHERE {} AND created_at >= ?2 AND created_at < ?3",
        live_clause(1)
    );
    let count: i64 = c.query_row(&count_sql, params![now, start, end], |r| r.get(0))?;

    if start >= end.saturating_sub(1) {
        let single = compute_range_summary(c, now, start, end)?;
        return Ok(vec![single]);
    }

    let mid_ts: Option<i64> = if count > 1 {
        let mid_offset = count / 2;
        let mid_sql = format!(
            "SELECT created_at FROM events WHERE {} AND created_at >= ?2 AND created_at < ?3 ORDER BY created_at ASC, id ASC LIMIT 1 OFFSET ?4",
            live_clause(1)
        );
        c.query_row(&mid_sql, params![now, start, end, mid_offset], |r| r.get(0))
            .ok()
    } else {
        None
    };

    let split_point = match mid_ts {
        Some(t) if t > start && t < end => t,
        _ => {
            let effective_end = if end == i64::MAX {
                (now + 60).max(start + 2)
            } else {
                end
            };
            let mid = start + (effective_end.saturating_sub(start)) / 2;
            if mid > start && mid < end {
                mid
            } else {
                return Ok(vec![compute_range_summary(c, now, start, end)?]);
            }
        }
    };

    let r1 = compute_range_summary(c, now, start, split_point)?;
    let r2 = compute_range_summary(c, now, split_point, end)?;
    Ok(vec![r1, r2])
}

#[derive(Debug, Default)]
pub struct RangeDiffResult {
    /// Full events local peer has that initiator is missing (peer serves these to initiator)
    pub pull_events: Vec<serde_json::Value>,
    /// Event IDs local peer has in divergent small ranges (so initiator knows what peer has)
    pub known_ids: Vec<String>,
    /// Divergent small ranges (start, end)
    pub divergent_ranges: Vec<(i64, i64)>,
    /// Ranges that need further bisection
    pub sub_ranges: Vec<RangeSummary>,
}

/// Compare remote ranges with local state.
/// For matching ranges: 0 cost, skipped.
/// For small divergent ranges (<= 64 events): fetches local IDs and serves available pull_events.
/// For large divergent ranges: splits the range into sub-ranges.
pub fn reconcile_ranges(
    c: &Connection,
    now: i64,
    remote_ranges: &[RangeSummary],
    max_pull: usize,
) -> rusqlite::Result<RangeDiffResult> {
    let mut result = RangeDiffResult::default();

    for remote in remote_ranges {
        let local = compute_range_summary(c, now, remote.start, remote.end)?;
        if local.count == remote.count && local.digest == remote.digest {
            // Match: 0 work
            continue;
        }

        if local.count <= 64 && remote.count <= 64 {
            result.divergent_ranges.push((remote.start, remote.end));
            let local_ids = fetch_event_ids_in_range(c, now, remote.start, remote.end, 100)?;
            for id in &local_ids {
                result.known_ids.push(hex::encode(id));
            }

            if !local_ids.is_empty() && result.pull_events.len() < max_pull {
                let to_fetch = (max_pull - result.pull_events.len()).min(local_ids.len());
                let events = fetch_events_by_ids(c, now, &local_ids[..to_fetch])?;
                result.pull_events.extend(events);
            }
        } else {
            let splits = split_range(c, now, remote.start, remote.end)?;
            result.sub_ranges.extend(splits);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_fold_8() {
        let h1 = [0xAAu8; 32];
        let f1 = xor_fold_8(&h1);
        // 0xAA ^ 0xAA ^ 0xAA ^ 0xAA = 0
        assert_eq!(f1, [0u8; 8]);

        let mut h2 = [0u8; 32];
        h2[0] = 0x12;
        let f2 = xor_fold_8(&h2);
        assert_eq!(f2[0], 0x12);
    }

    #[test]
    fn test_range_summary_empty_and_insert() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        let initial = compute_range_summary(&c, 0, 0, i64::MAX).unwrap();
        assert_eq!(initial.count, 0);
        assert_eq!(initial.digest, "0000000000000000");

        // Insert a test event with non-cancelling bytes
        let mut id = [0u8; 32];
        id[0] = 42;
        let data = serde_json::to_vec(&serde_json::json!({"test": 1})).unwrap();
        c.execute(
            "INSERT INTO events (id, owner, collection, created_at, expires_at, data, size)
             VALUES (?1, ?2, 'test', 1000, 2000, ?3, 10)",
            params![&id[..], &[1u8; 32][..], &data[..]],
        )
        .unwrap();

        let after = compute_range_summary(&c, 0, 0, i64::MAX).unwrap();
        assert_eq!(after.count, 1);
        assert_ne!(after.digest, "0000000000000000");

        // Out of range query returns 0
        let out_of_range = compute_range_summary(&c, 0, 2000, 3000).unwrap();
        assert_eq!(out_of_range.count, 0);
        assert_eq!(out_of_range.digest, "0000000000000000");
    }

    #[test]
    fn test_reconcile_ranges_diff_detection() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        let id = [77u8; 32];
        let data = serde_json::to_vec(&serde_json::json!({"msg": "hello"})).unwrap();
        c.execute(
            "INSERT INTO events (id, owner, collection, created_at, expires_at, data, size)
             VALUES (?1, ?2, 'chat', 500, 1500, ?3, 10)",
            params![&id[..], &[1u8; 32][..], &data[..]],
        )
        .unwrap();

        // 1. Matching range
        let local_summary = compute_range_summary(&c, 0, 0, 1000).unwrap();
        let diff = reconcile_ranges(&c, 0, std::slice::from_ref(&local_summary), 10).unwrap();
        assert_eq!(diff.pull_events.len(), 0);
        assert_eq!(diff.known_ids.len(), 0);

        // 2. Remote is missing the event (remote count = 0)
        let remote_empty = RangeSummary {
            start: 0,
            end: 1000,
            count: 0,
            digest: "0000000000000000".into(),
        };
        let diff_missing = reconcile_ranges(&c, 0, &[remote_empty], 10).unwrap();
        assert_eq!(diff_missing.pull_events.len(), 1);
        assert_eq!(diff_missing.known_ids.len(), 1);
        assert_eq!(diff_missing.known_ids[0], hex::encode(id));
    }

    #[test]
    fn test_expired_event_is_invisible_to_reconciliation() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        // One live event, one expired-but-unswept: sweep timing must not
        // influence what peers agree on.
        let now = 1_000i64;
        for (id_byte, expires) in [(1u8, now + 1_000), (2u8, now - 1)] {
            let data = serde_json::to_vec(&serde_json::json!({"n": id_byte})).unwrap();
            c.execute(
                "INSERT INTO events (id, owner, collection, created_at, expires_at, data, size)
                 VALUES (?1, ?2, 'chat', ?3, ?4, ?5, 10)",
                params![
                    &[id_byte; 32][..],
                    &[1u8; 32][..],
                    now - 10,
                    expires,
                    &data[..]
                ],
            )
            .unwrap();
        }

        let summary = compute_range_summary(&c, now, 0, i64::MAX).unwrap();
        assert_eq!(summary.count, 1, "expired row counted in range digest");

        let ids = fetch_event_ids_in_range(&c, now, 0, i64::MAX, 100).unwrap();
        assert_eq!(ids, vec![[1u8; 32]], "expired id offered to the peer");
        assert!(
            fetch_events_by_ids(&c, now, &[[2u8; 32]])
                .unwrap()
                .is_empty(),
            "expired event served to the peer"
        );

        // A peer reporting exactly the live set is a clean match: no diff,
        // no bisection, no battery burned on reaper-timing skew.
        let live_only = compute_range_summary(&c, now, 0, i64::MAX).unwrap();
        let diff = reconcile_ranges(&c, now, std::slice::from_ref(&live_only), 10).unwrap();
        assert_eq!(diff.pull_events.len(), 0);
        assert_eq!(diff.known_ids.len(), 0);
    }

    #[test]
    fn test_live_event_reconciliation() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        let mut id = [0u8; 32];
        id[0] = 88;
        let data = serde_json::to_vec(&serde_json::json!({"msg": "hello"})).unwrap();
        c.execute(
            "INSERT INTO events (id, owner, collection, created_at, expires_at, data, size)
             VALUES (?1, ?2, 'chat', 500, 1500, ?3, 10)",
            params![&id[..], &[1u8; 32][..], &data[..]],
        )
        .unwrap();

        let summary = compute_range_summary(&c, 1000, 0, i64::MAX).unwrap();
        assert_eq!(summary.count, 1);
        assert_ne!(summary.digest, "0000000000000000");

        let by_ids = fetch_events_by_ids(&c, 1000, &[id]).unwrap();
        assert_eq!(by_ids.len(), 1);

        let remote_empty = RangeSummary {
            start: 0,
            end: 1000,
            count: 0,
            digest: "0000000000000000".into(),
        };
        let diff = reconcile_ranges(&c, 1000, &[remote_empty], 10).unwrap();
        assert_eq!(diff.pull_events.len(), 1);
        assert_eq!(diff.known_ids.len(), 1);
        assert_eq!(diff.divergent_ranges.len(), 1);
    }
}
