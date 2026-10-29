use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

use super::reconcile;
use super::ranges::Kind;
use crate::api::AppState;

/// Lazy read healing (public GET and peer GET) counters for `/stats`.
pub struct HealCounters {
    pub attempts: AtomicU64,
    pub succeeded: AtomicU64,
    pub failed: AtomicU64,
}

pub static HEAL_COUNTERS: HealCounters = HealCounters {
    attempts: AtomicU64::new(0),
    succeeded: AtomicU64::new(0),
    failed: AtomicU64::new(0),
};

#[derive(Debug, Default, Clone, Copy)]
pub struct HealSnapshot {
    pub attempts: u64,
    pub succeeded: u64,
    pub failed: u64,
}

pub fn heal_snapshot() -> HealSnapshot {
    HealSnapshot {
        attempts: HEAL_COUNTERS.attempts.load(Ordering::Relaxed),
        succeeded: HEAL_COUNTERS.succeeded.load(Ordering::Relaxed),
        failed: HEAL_COUNTERS.failed.load(Ordering::Relaxed),
    }
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

/// One tick against one peer: exact range reconciliation for events, then
/// blobs. Events may push and pull; blobs only pull.
async fn tick(n: &AppState, peer: &reqwest::Url) -> bool {
    let events_ok = reconcile::run(n, peer, Kind::Events).await;
    let blobs_ok = reconcile::run(n, peer, Kind::Blobs).await;
    events_ok && blobs_ok
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
    if n.cfg.sync_nodes.is_empty() {
        return false;
    }
    HEAL_COUNTERS.attempts.fetch_add(1, Ordering::Relaxed);
    for peer in &n.cfg.sync_nodes {
        if super::pulls::pull_blob(n, peer, hash_hex).await {
            HEAL_COUNTERS.succeeded.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    HEAL_COUNTERS.failed.fetch_add(1, Ordering::Relaxed);
    false
}
