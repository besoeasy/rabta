use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use crate::api::AppState;
use crate::store::blobs::{BlobOrigin, BlobSink};

/// First retry delay for a blob that a peer could not serve; doubles per
/// consecutive failure up to one hour. This is keyed by (peer, hash), so one
/// absent blob cannot make every tick re-ask the same peer.
pub const PULL_BACKOFF_BASE: Duration = Duration::from_secs(60);
pub const PULL_BACKOFF_MAX: Duration = Duration::from_secs(3600);

/// Upper bound on failure memory. Expired entries are pruned first, then the
/// entry with the earliest retry time is dropped if the map is still full.
const PULL_FAILURE_CAP: usize = 4096;

type PullKey = (String, String);

#[derive(Debug, Clone, Copy)]
struct Failure {
    count: u32,
    retry_at: Instant,
}

pub struct PullCounters {
    pub attempts: AtomicU64,
    pub succeeded: AtomicU64,
    pub failed: AtomicU64,
    pub skipped_backoff: AtomicU64,
}

pub static PULL_COUNTERS: PullCounters = PullCounters {
    attempts: AtomicU64::new(0),
    succeeded: AtomicU64::new(0),
    failed: AtomicU64::new(0),
    skipped_backoff: AtomicU64::new(0),
};

#[derive(Debug, Default, Clone, Copy)]
pub struct PullSnapshot {
    pub attempts: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub skipped_backoff: u64,
    pub in_backoff: u64,
}

fn failures() -> &'static Mutex<HashMap<PullKey, Failure>> {
    static FAILURES: OnceLock<Mutex<HashMap<PullKey, Failure>>> = OnceLock::new();
    FAILURES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_failures() -> MutexGuard<'static, HashMap<PullKey, Failure>> {
    // A panic elsewhere must not turn telemetry into a process-wide failure.
    failures().lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn key_for(peer: &reqwest::Url, hash_hex: &str) -> PullKey {
    (peer.as_str().to_string(), hash_hex.to_ascii_lowercase())
}

/// 60s, 120s, 240s, … capped at 1h. `failures` is 1-based.
fn delay_for(failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(6);
    PULL_BACKOFF_BASE.saturating_mul(1u32 << exp).min(PULL_BACKOFF_MAX)
}

/// True when the key is absent or its TTL has elapsed. Expired entries are
/// removed so the next failure starts a fresh exponential sequence.
fn allow_at(state: &mut HashMap<PullKey, Failure>, key: &PullKey, now: Instant) -> bool {
    match state.get(key) {
        Some(f) if f.retry_at > now => false,
        Some(_) => {
            state.remove(key);
            true
        }
        None => true,
    }
}

fn record_failure_at(state: &mut HashMap<PullKey, Failure>, key: PullKey, now: Instant) {
    let entry = state.entry(key).or_insert(Failure { count: 0, retry_at: now });
    entry.count = entry.count.saturating_add(1);
    entry.retry_at = now + delay_for(entry.count);

    if state.len() > PULL_FAILURE_CAP {
        state.retain(|_, f| f.retry_at > now);
        while state.len() > PULL_FAILURE_CAP {
            let oldest = state
                .iter()
                .min_by_key(|(_, f)| f.retry_at)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    state.remove(&k);
                }
                None => break,
            }
        }
    }
}

fn record_success(peer: &reqwest::Url, hash_hex: &str) {
    lock_failures().remove(&key_for(peer, hash_hex));
}

fn record_failure(peer: &reqwest::Url, hash_hex: &str) {
    let key = key_for(peer, hash_hex);
    record_failure_at(&mut lock_failures(), key, Instant::now());
}

/// Snapshot for `/stats`; expired entries are dropped rather than reported as
/// active backoff.
pub fn snapshot() -> PullSnapshot {
    let in_backoff = {
        let now = Instant::now();
        let mut state = lock_failures();
        state.retain(|_, f| f.retry_at > now);
        state.len() as u64
    };
    PullSnapshot {
        attempts: PULL_COUNTERS.attempts.load(Ordering::Relaxed),
        succeeded: PULL_COUNTERS.succeeded.load(Ordering::Relaxed),
        failed: PULL_COUNTERS.failed.load(Ordering::Relaxed),
        skipped_backoff: PULL_COUNTERS.skipped_backoff.load(Ordering::Relaxed),
        in_backoff,
    }
}

fn join(peer: &reqwest::Url, path: &str) -> reqwest::Url {
    peer.join(path).expect("joined url")
}

fn valid_hash(hash_hex: &str) -> bool {
    hash_hex.len() == 64 && hash_hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Pull ONE blob from a trusted peer, hash-verify while streaming, then
/// install it (orphan clock, or attached when live referrers already exist).
///
/// This is the force path (read healing): it ignores backoff but records the
/// outcome, so a later reconcile pull won't immediately repeat a failed attempt.
pub async fn pull_blob(n: &AppState, peer: &reqwest::Url, hash_hex: &str) -> bool {
    if !valid_hash(hash_hex) {
        return false;
    }
    PULL_COUNTERS.attempts.fetch_add(1, Ordering::Relaxed);
    let ok = transfer_blob(n, peer, hash_hex).await;
    if ok {
        PULL_COUNTERS.succeeded.fetch_add(1, Ordering::Relaxed);
        record_success(peer, hash_hex);
    } else {
        PULL_COUNTERS.failed.fetch_add(1, Ordering::Relaxed);
        record_failure(peer, hash_hex);
    }
    ok
}

/// Reconcile-facing pull: respects the (peer, hash) failure TTL so genuinely
/// absent blobs are not retried on every peer tick.
pub async fn pull_blob_with_backoff(n: &AppState, peer: &reqwest::Url, hash_hex: &str) -> bool {
    if !valid_hash(hash_hex) {
        return false;
    }
    let key = key_for(peer, hash_hex);
    let allowed = allow_at(&mut lock_failures(), &key, Instant::now());
    if !allowed {
        PULL_COUNTERS.skipped_backoff.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    pull_blob(n, peer, hash_hex).await
}

async fn transfer_blob(n: &AppState, peer: &reqwest::Url, hash_hex: &str) -> bool {
    let url = join(peer, &format!("/sync/blobs/{hash_hex}"));
    let Ok(mut resp) = n.http.get(url).timeout(Duration::from_secs(30)).send().await else {
        return false;
    };
    if !resp.status().is_success() {
        return false;
    }

    let (ev, bl) = n.db.read(|c: &rusqlite::Connection| crate::db::live_bytes(c)).await;
    let mut sink = match BlobSink::start(&n.cfg.data_dir, ev + bl, n.cfg.storage_max, n.cfg.max_single_blob) {
        Ok(s) => s,
        Err(_) => return false,
    };
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if sink.push(&chunk).is_err() {
                    sink.discard();
                    return false;
                }
            }
            Ok(None) => break,
            Err(_) => {
                sink.discard();
                return false;
            }
        }
    }
    let staged = match sink.finish() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if staged.hash_hex.to_ascii_lowercase() != hash_hex.to_ascii_lowercase() {
        let _ = std::fs::remove_file(&staged.path);
        return false;
    }
    matches!(
        crate::store::blobs::install_staged(&n.db, &n.cfg, staged, BlobOrigin::Peer).await,
        Ok(crate::store::blobs::Install::Fresh | crate::store::blobs::Install::Deduped)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: &str) -> PullKey {
        (format!("http://peer/{tag}"), "ab".repeat(32))
    }

    #[test]
    fn backoff_delay_doubles_and_caps() {
        assert_eq!(delay_for(0), PULL_BACKOFF_BASE);
        assert_eq!(delay_for(1), Duration::from_secs(60));
        assert_eq!(delay_for(2), Duration::from_secs(120));
        assert_eq!(delay_for(3), Duration::from_secs(240));
        assert_eq!(delay_for(7), PULL_BACKOFF_MAX);
        assert_eq!(delay_for(u32::MAX), PULL_BACKOFF_MAX);
    }

    #[test]
    fn failure_ttl_blocks_then_reopens_and_success_resets() {
        let now = Instant::now();
        let k = key("a");
        let mut state = HashMap::new();

        assert!(allow_at(&mut state, &k, now));
        record_failure_at(&mut state, k.clone(), now);

        assert!(!allow_at(&mut state, &k, now + Duration::from_secs(59)));
        assert!(allow_at(&mut state, &k, now + Duration::from_secs(61)));
        assert!(state.is_empty(), "expired entry was not pruned");

        // A second consecutive failure backs off for two minutes.
        record_failure_at(&mut state, k.clone(), now);
        record_failure_at(&mut state, k.clone(), now + Duration::from_secs(61));
        assert!(!allow_at(&mut state, &k, now + Duration::from_secs(61 + 119)));
        assert!(allow_at(&mut state, &k, now + Duration::from_secs(61 + 121)));

        record_failure_at(&mut state, k.clone(), now);
        state.remove(&k); // what a successful raw pull does
        assert!(allow_at(&mut state, &k, now));
    }

    #[test]
    fn failure_map_is_bounded() {
        let now = Instant::now();
        let mut state = HashMap::new();
        for i in 0..=PULL_FAILURE_CAP {
            record_failure_at(&mut state, key(&i.to_string()), now);
        }
        assert_eq!(state.len(), PULL_FAILURE_CAP);
    }
}
