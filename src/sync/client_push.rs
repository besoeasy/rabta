use std::time::Duration;

use serde_json::Value;

use super::bloom::{Bloom, BloomFilterDto, SEED_EVENTS};
use crate::api::AppState;

const PAGE: i64 = 500;
const TIMEOUT: Duration = Duration::from_secs(30);
/// Bloom positives are not proof of possession (~1% false positives at the
/// locked sizing). Every positive is re-offered once per rotation window,
/// so a false positive can delay delivery but never hide an event forever.
const POSITIVE_ROTATION: i64 = 8;

fn join(peer: &reqwest::Url, path: &str) -> reqwest::Url {
    peer.join(path).expect("joined url")
}

/// A negative means "definitely absent" → push now. A positive is only
/// trusted for the current rotation slot; over `POSITIVE_ROTATION` ticks every
/// positive is pushed at least once, so the peer's Bloom cannot starve us.
fn should_push(theirs: &Bloom, key: &[u8; 32], seq: i64, rotation: i64) -> bool {
    if !theirs.test(SEED_EVENTS, key) {
        return true;
    }
    seq.rem_euclid(POSITIVE_ROTATION) == rotation
}

/// Phase 2: when the planner reported >1000 missing, re-query with sub-filters
/// built over MY OWN keys in each of its windows (locked recipe; no recursion).
pub async fn phase_two(n: &AppState, peer: &reqwest::Url, reply: &Value) {
    let Some(windows) = reply["overflow"]["events"].as_array() else { return };
    for w in windows.iter().take(8) {
        let lo = w["created_at_lo"].as_i64().unwrap_or(0);
        let hi = w["created_at_hi"].as_i64().unwrap_or(i64::MAX);
        let Some((count, bloom)) = crate::sync::filters::build_sub_filter_time(n, lo, hi).await
        else {
            continue;
        };
        let dto = BloomFilterDto::from_parts("events", count, &bloom);
        let Ok(v) = serde_json::to_value(&dto) else { continue };
        let body = serde_json::json!({"v": 2, "filters": [v]});
        let Ok(resp) = n
            .http
            .post(join(peer, "/sync/bloom"))
            .timeout(TIMEOUT)
            .json(&body)
            .send()
            .await
        else {
            continue;
        };
        let Ok(reply2) = resp.json::<Value>().await else { continue };
        let ids: Vec<String> = reply2["you_are_missing"]["events"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        for id in ids {
            let url = join(peer, &format!("/sync/events/{id}"));
            if let Ok(resp) = n.http.get(url).timeout(TIMEOUT).send().await {
                if resp.status().is_success() {
                    if let Ok(bytes) = resp.bytes().await {
                        let dot = n.clone();
                        let _ = crate::api::sync_ingest::store_envelope(&dot, bytes.to_vec()).await;
                    }
                }
            }
        }
    }
}

/// The push direction: my live events that fail the responder's filter are
/// ones the responder lacks — batch-POST them in the same tick, no fan-out.
pub async fn push_i_hold_events(n: &AppState, peer: &reqwest::Url, reply: &Value) {
    let Ok(dto) = serde_json::from_value::<BloomFilterDto>(reply["responder_filters"]["events"].clone())
    else {
        return;
    };
    let (bits, cells) = match dto.decode() {
        Ok(x) => x,
        Err(_) => return,
    };
    let their = Bloom { bits, cells };
    // Time-based slot: consecutive ticks rotate which positives are re-offered.
    let rotation = (crate::store::reaper::now() / 60).rem_euclid(POSITIVE_ROTATION);

    let mut last_seq = 0i64;
    loop {
        let last = last_seq;
        let page: Vec<(i64, Vec<u8>, Vec<u8>)> = n
            .db
            .read(move |c: &rusqlite::Connection| {
                let mut stmt = c
                    .prepare(
                        "SELECT seq, id, data FROM events WHERE state='live' AND seq > ?1 ORDER BY seq ASC LIMIT ?2",
                    )
                    .ok()?;
                let mut rows = stmt.query([last, PAGE]).ok()?;
                let mut out = Vec::new();
                while let Ok(Some(r)) = rows.next() {
                    let seq: i64 = r.get(0).unwrap_or(0);
                    let id: Vec<u8> = r.get(1).unwrap_or_default();
                    let data: Vec<u8> = r.get(2).unwrap_or_default();
                    out.push((seq, id, data));
                }
                Some(out)
            })
            .await
            .unwrap_or_default();
        if page.is_empty() {
            break;
        }

        let mut batch: Vec<Value> = Vec::new();
        for (seq, id, data) in page {
            last_seq = seq;
            if id.len() != 32 {
                continue;
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&id);
            if !should_push(&their, &k, seq, rotation) {
                continue; // responder has it, or not this rotation's turn
            }
            if let Ok(v) = serde_json::from_slice::<Value>(&data) {
                batch.push(v);
            }
        }
        if !batch.is_empty() {
            let _ = n
                .http
                .post(join(peer, "/sync/events"))
                .timeout(TIMEOUT)
                .json(&batch)
                .send()
                .await;
        }
        if last_seq == last {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_bloom_hit_pushes_immediately() {
        let theirs = Bloom::sized(1);
        for rotation in 0..POSITIVE_ROTATION {
            assert!(should_push(&theirs, &[8u8; 32], 3, rotation));
        }
    }

    #[test]
    fn positive_bloom_hit_is_retried_across_the_rotation() {
        let mut theirs = Bloom::sized(1);
        let key = [7u8; 32];
        theirs.add(SEED_EVENTS, &key);
        assert!(theirs.test(SEED_EVENTS, &key));

        let slots: Vec<i64> = (0..POSITIVE_ROTATION)
            .filter(|rotation| should_push(&theirs, &key, 3, *rotation))
            .collect();
        assert_eq!(slots, vec![3], "positive was skipped for every rotation slot");
    }
}
