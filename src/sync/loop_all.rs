use std::time::Duration;

use futures_util::StreamExt;
use serde_json::{json, Value};

use super::client_push;
use super::filters;
use crate::api::AppState;
use crate::api::sync_ingest;

/// Bound on concurrent blob pulls per peer tick. Pulls are hash-verified and
/// independent; a small window keeps one slow peer from serializing the tick.
const BLOB_PULL_CONCURRENCY: usize = 4;


fn join(peer: &reqwest::Url, path: &str) -> reqwest::Url {
    peer.join(path).expect("joined url")
}

/// Start one independent loop per configured peer (staggered visits).
pub async fn start(n: AppState) {
    for peer in n.cfg.sync_nodes.clone() {
        let n2 = n.clone();
        tokio::spawn(async move { peer_loop(n2, peer).await });
    }
}

/// Cadence with exponential backoff on peer failure (base → … → 1 h cap),
/// reset on the next successful tick.
async fn peer_loop(n: AppState, peer: reqwest::Url) {
    let base = n.cfg.sync_interval;
    let mut failures: u32 = 0;
    loop {
        let ok = tick(&n, &peer).await;
        failures = if ok { 0 } else { failures.saturating_add(1) };
        let wait = if failures == 0 {
            base
        } else {
            (base.saturating_mul(1u32 << failures.min(12))).min(Duration::from_secs(3600))
        };
        tokio::time::sleep(wait).await;
    }
}

/// One tick against one peer — the full bloom exchange.
async fn tick(n: &AppState, peer: &reqwest::Url) -> bool {
    let (ev_dto, bl_dto) = filters::build_my_filters(&n.db).await;
    let Ok(ev_v) = serde_json::to_value(&ev_dto) else { return false };
    let Ok(bl_v) = serde_json::to_value(&bl_dto) else { return false };
    let req_body = json!({ "v": 2, "filters": [ev_v, bl_v] });

    let resp = match n
        .http
        .post(join(peer, "/sync/bloom"))
        .timeout(Duration::from_secs(10))
        .json(&req_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return false,
    };
    if !resp.status().is_success() {
        return false;
    }
    let reply: Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return false,
    };

    let in_sync_ev = reply["in_sync"]["events"].as_bool().unwrap_or(false);
    let in_sync_bl = reply["in_sync"]["blobs"].as_bool().unwrap_or(false);

    // you_are_missing = keys *I* lack (responder has them) → pull.
    if !in_sync_ev {
        let ids = reply["you_are_missing"]["events"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>())
            .unwrap_or_default();
        for id in ids {
            if id.len() != 64 {
                continue;
            }
            let url = join(peer, &format!("/sync/events/{id}"));
            if let Ok(resp) = n.http.get(url).timeout(Duration::from_secs(10)).send().await {
                if resp.status().is_success() {
                    if let Ok(bytes) = resp.bytes().await {
                        let dot = n.clone();
                        let _ = sync_ingest::store_envelope(&dot, bytes.to_vec()).await;
                    }
                }
            }
        }
        client_push::phase_two(n, peer, &reply).await;
    }

    if !in_sync_bl {
        let hashes: Vec<String> = reply["you_are_missing"]["blobs"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let pulls = futures_util::stream::iter(hashes)
            .filter(|hash_hex| {
                let valid = hash_hex.len() == 64
                    && hash_hex.bytes().all(|b| b.is_ascii_hexdigit());
                async move { valid }
            })
            .map(|hash_hex| {
                let app = AppState::clone(n);
                let peer = reqwest::Url::clone(peer);
                async move { super::pulls::pull_blob(&app, &peer, &hash_hex).await }
            })
            .buffer_unordered(BLOB_PULL_CONCURRENCY);
        let _pulled: Vec<bool> = pulls.collect().await;
    }

    // The responder-lacks direction (I hold, it lacks) → push events now;
    // blob bodies never push proactively (decision #16).
    client_push::push_i_hold_events(n, peer, &reply).await;

    true
}

/// Origin fan-out (decision #16): events push to every peer right on accept.
pub fn push_event_to_peers(n: &AppState, served: Vec<u8>) {
    if n.cfg.sync_nodes.is_empty() {
        return;
    }
    let peers = n.cfg.sync_nodes.clone();
    let http = n.http.clone();
    tokio::spawn(async move {
        let parsed: Value = match serde_json::from_slice(&served) {
            Ok(v) => v,
            Err(_) => return,
        };
        let body = json!([parsed]);
        for peer in peers {
            let url = peer.join("/sync/events").expect("joined");
            let _ = http.post(url).timeout(Duration::from_secs(10)).json(&body).send().await;
        }
    });
}

/// Lazy blob fetch-on-read for a GET miss; tries peers in order.
pub async fn fetch_blob_from_peers(n: &AppState, hash_hex: &str) -> bool {
    for peer in &n.cfg.sync_nodes {
        if super::pulls::pull_blob(n, peer, hash_hex).await {
            return true;
        }
    }
    false
}
