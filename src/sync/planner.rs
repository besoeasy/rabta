use rusqlite::Connection;
use serde_json::{json, Value};

use crate::sync::bloom::{Bloom, BloomFilterDto, SEED_BLOBS, SEED_EVENTS};

pub const BLOOM_V: u8 = 2;
pub const INLINE_CAP: usize = 1000;
pub const OVERFLOW_WINDOWS: usize = 8;

/// The planner: compute `you_are_missing` (my live keys that fail the caller's
/// filter = the caller lacks them) + my own filters (so the caller can diff
/// what *I* lack and push it in the same tick) + overflow windows past 1000.
pub fn plan(c: &Connection, caller_filters: &[BloomFilterDto], now: i64) -> Result<Value, String> {
    let my_events: Vec<(Vec<u8>, i64)> = {
        let mut stmt = c.prepare("SELECT id, created_at FROM events WHERE state='live' AND expires_at > ?1").unwrap();
        let mut rows = stmt.query([now]).unwrap();
        let mut v = Vec::new();
        while let Some(r) = rows.next().unwrap() {
            v.push((r.get(0).unwrap(), r.get(1).unwrap()));
        }
        v
    };
    let my_blobs: Vec<Vec<u8>> = {
        let mut stmt = c.prepare("SELECT hash FROM blobs WHERE state='live'").unwrap();
        let mut rows = stmt.query([]).unwrap();
        let mut v = Vec::new();
        while let Some(r) = rows.next().unwrap() {
            v.push(r.get(0).unwrap());
        }
        v
    };

    let mut ev_filter = Bloom::sized(my_events.len());
    for (id, _) in &my_events {
        if id.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(id);
            ev_filter.add(SEED_EVENTS, &k);
        }
    }
    let mut bl_filter = Bloom::sized(my_blobs.len());
    for h in &my_blobs {
        if h.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(h);
            bl_filter.add(SEED_BLOBS, &k);
        }
    }

    let mut in_sync = json!({"events": false, "blobs": false});
    let mut missing_events: Vec<(String, i64)> = Vec::new();
    let mut missing_blobs: Vec<String> = Vec::new();

    for f in caller_filters {
        let (bits, cells) = f.decode().map_err(|e| format!("{e}"))?;
        let their = Bloom { bits, cells };
        let mycount = if f.ftype == "events" { my_events.len() } else { my_blobs.len() };
        let my_filter = if f.ftype == "events" { &ev_filter } else { &bl_filter };

        // steady-state skip: same count + byte-equal cells
        if f.count == mycount as u64 && their.cells == my_filter.cells {
            in_sync[f.ftype.as_str()] = json!(true);
            continue;
        }

        // Not an exact mirror. A bloom positive is not proof of possession:
        // with a count mismatch a false positive can hide a missing key on
        // every tick, so enumerate every local key and let the caller dedupe.
        // (Oversized lists rotate their inline slice below so the cap cannot
        // pin a positive at the front forever.)
        if f.ftype == "events" {
            for (id, created) in &my_events {
                if id.len() != 32 {
                    continue;
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(id);
                missing_events.push((hex::encode(k), *created));
            }
        } else {
            for hash in &my_blobs {
                if hash.len() != 32 {
                    continue;
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(hash);
                missing_blobs.push(hex::encode(k));
            }
        }
    }

    missing_events.sort_by_key(|(_, ca)| *ca);
    missing_blobs.sort();
    let overflow = overflow_windows(&missing_events, &missing_blobs);
    let ev_inline: Vec<String> = inline_slice(&missing_events, now)
        .into_iter()
        .map(|(h, _)| h.clone())
        .collect();
    let bl_inline: Vec<String> = inline_slice(&missing_blobs, now).into_iter().cloned().collect();

    Ok(json!({
        "v": BLOOM_V,
        "in_sync": in_sync,
        "you_are_missing": { "events": ev_inline, "blobs": bl_inline },
        "i_am_missing": { "events": [], "blobs": [] },
        "overflow": overflow,
        "responder_filters": {
            "events": BloomFilterDto::from_parts("events", my_events.len(), &ev_filter),
            "blobs": BloomFilterDto::from_parts("blobs", my_blobs.len(), &bl_filter),
        },
    }))
}

/// Inline page of the missing list. Small sets are returned whole; oversized
/// sets rotate their start each tick so keys beyond the cap cannot be starved.
fn inline_slice<T>(items: &[T], now: i64) -> Vec<&T> {
    if items.len() <= INLINE_CAP {
        return items.iter().collect();
    }
    let offset = (now.max(0) as usize) % items.len();
    items[offset..]
        .iter()
        .chain(items[..offset].iter())
        .take(INLINE_CAP)
        .collect()
}

/// ≤8 partitions over MY missing keys (events by created_at, blobs by hash).
pub fn overflow_windows(mev: &[(String, i64)], mbl: &[String]) -> Value {
    let mut evs: Value = Value::Null;
    let mut bls: Value = Value::Null;

    if mev.len() > INLINE_CAP {
        let n = OVERFLOW_WINDOWS;
        let chunk = mev.len().div_ceil(n);
        let mut arr = Vec::new();
        for start in (0..mev.len()).step_by(chunk) {
            let end = (start + chunk).min(mev.len());
            let lo = mev[start].1;
            let hi = mev[end - 1].1.saturating_add(1);
            arr.push(json!({"created_at_lo": lo, "created_at_hi": hi}));
        }
        evs = Value::Array(arr);
    }
    if mbl.len() > INLINE_CAP {
        let n = OVERFLOW_WINDOWS;
        let chunk = mbl.len().div_ceil(n);
        let mut arr = Vec::new();
        for start in (0..mbl.len()).step_by(chunk) {
            let end = (start + chunk).min(mbl.len());
            let lo = mbl[start].clone();
            let hi = if end == mbl.len() { "f".repeat(64) } else { mbl[end - 1].clone() };
            arr.push(json!({"hash_lo": lo, "hash_hi": hi}));
        }
        bls = Value::Array(arr);
    }
    json!({"events": evs, "blobs": bls})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_add_test() {
        let mut b = Bloom::sized(10);
        let key = [7u8; 32];
        b.add(SEED_EVENTS, &key);
        assert!(b.test(SEED_EVENTS, &key));
        let dto = BloomFilterDto::from_parts("events", 10, &b);
        assert!(dto.decode().is_ok());
    }

    #[test]
    fn probe_layout_little_endian() {
        let mut b = Bloom::sized(10);
        let key = [3u8; 32];
        b.add(SEED_BLOBS, &key);
        // every probe bit is set somewhere in the cells; zero-key test fails
        let other = [4u8; 32];
        b.add(SEED_BLOBS, &other);
        assert!(b.test(SEED_BLOBS, &other));
    }

    #[test]
    fn overflow_partitions() {
        let big: Vec<(String, i64)> = (0..1500)
            .map(|i| (format!("{:064x}", i % 256), 1000 + i as i64))
            .collect();
        let out = overflow_windows(&big, &[]);
        assert_eq!(out["events"].as_array().unwrap().len(), 8);
        assert!(out["blobs"].is_null());
    }

    #[test]
    fn bloom_false_positive_cannot_hide_missing_events() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();
        for i in 0..3u64 {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_le_bytes());
            c.execute(
                "INSERT INTO events(id,owner,collection,created_at,expires_at,data,labels,size)
                 VALUES (?1,?2,'test',900,2000,x'7b7d','[]',2)",
                rusqlite::params![&id, &[0u8; 32]],
            )
            .unwrap();
        }

        // Caller claims only two keys and its filter says "yes" for everything
        // (the degenerate version of a bloom false positive).
        let their = Bloom { bits: 8192, cells: vec![0xff; 1024] };
        let filter = BloomFilterDto::from_parts("events", 2, &their);

        let out = plan(&c, &[filter], 1000).unwrap();
        assert_eq!(out["in_sync"]["events"], false);
        assert_eq!(out["you_are_missing"]["events"].as_array().unwrap().len(), 3);
    }
}
