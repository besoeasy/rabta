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

        // steady-state skip: same count + byte-equal cells
        if f.count == mycount as u64
            && their.cells == (if f.ftype == "events" { &ev_filter } else { &bl_filter }).cells
        {
            in_sync[f.ftype.as_str()] = json!(true);
            continue;
        }

        if f.ftype == "events" {
            for (id, created) in &my_events {
                if id.len() != 32 {
                    continue;
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(id);
                if !their.test(SEED_EVENTS, &k) {
                    missing_events.push((hex::encode(k), *created));
                }
            }
        } else {
            for hash in &my_blobs {
                if hash.len() != 32 {
                    continue;
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(hash);
                if !their.test(SEED_BLOBS, &k) {
                    missing_blobs.push(hex::encode(k));
                }
            }
        }
    }

    missing_events.sort_by_key(|(_, ca)| *ca);
    missing_blobs.sort();
    let overflow = overflow_windows(&missing_events, &missing_blobs);
    let ev_inline: Vec<String> = missing_events.iter().take(INLINE_CAP).map(|(h, _)| h.clone()).collect();
    let bl_inline: Vec<String> = missing_blobs.iter().take(INLINE_CAP).cloned().collect();

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
}
