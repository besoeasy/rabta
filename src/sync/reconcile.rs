use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::ranges::{self, Kind, LEAF_KEYS, MAX_IDS_PER_REPLY, MAX_RANGES};
use crate::api::AppState;
use crate::store::reaper;

/// Whole-tick wall-clock budget per peer and kind.
const TICK_BUDGET: Duration = Duration::from_secs(20);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Probe rounds (one POST may carry up to 128 ranges).
const MAX_PROBE_REQUESTS: usize = 16;
/// All HTTP calls per tick, including id pages and event pushes/pulls.
const MAX_HTTP_REQUESTS: usize = 64;
/// Envelopes are capped at 100 KiB each, so 64 keeps both the fetch reply and
/// the push request far below the 8 MiB client / 32 MiB server body caps.
const EVENT_BATCH: usize = 64;
const BLOB_PULL_CONCURRENCY: usize = 4;
/// Blob bodies are expensive; a slow/failing wave must not pin the whole tick.
const BLOB_PULLS_PER_TICK: usize = 32;
const QUEUE_CAP: usize = 4096;

/// Rotates the blob window so the first few hashes in a page cannot starve
/// every other missing body while their backoff is active.
static BLOB_ROTATION: AtomicU64 = AtomicU64::new(0);

pub struct ReconcileCounters {
    pub probes: AtomicU64,
    pub requests: AtomicU64,
    pub events_pushed: AtomicU64,
    pub events_pulled: AtomicU64,
    pub blobs_pulled: AtomicU64,
    pub skipped_pressure: AtomicU64,
    pub skipped_peer_full: AtomicU64,
    pub queue_overflow: AtomicU64,
}

pub static COUNTERS: ReconcileCounters = ReconcileCounters {
    probes: AtomicU64::new(0),
    requests: AtomicU64::new(0),
    events_pushed: AtomicU64::new(0),
    events_pulled: AtomicU64::new(0),
    blobs_pulled: AtomicU64::new(0),
    skipped_pressure: AtomicU64::new(0),
    skipped_peer_full: AtomicU64::new(0),
    queue_overflow: AtomicU64::new(0),
};

#[derive(Debug, Default, Clone, Copy)]
pub struct Snapshot {
    pub probes: u64,
    pub requests: u64,
    pub events_pushed: u64,
    pub events_pulled: u64,
    pub blobs_pulled: u64,
    pub skipped_pressure: u64,
    pub skipped_peer_full: u64,
    pub queue_overflow: u64,
    pub queued_ranges: u64,
}

pub fn snapshot() -> Snapshot {
    let queued_ranges = match queues().lock() {
        Ok(q) => q.values().map(|w| w.order.len() as u64).sum(),
        Err(p) => p.into_inner().values().map(|w| w.order.len() as u64).sum(),
    };
    Snapshot {
        probes: COUNTERS.probes.load(Ordering::Relaxed),
        requests: COUNTERS.requests.load(Ordering::Relaxed),
        events_pushed: COUNTERS.events_pushed.load(Ordering::Relaxed),
        events_pulled: COUNTERS.events_pulled.load(Ordering::Relaxed),
        blobs_pulled: COUNTERS.blobs_pulled.load(Ordering::Relaxed),
        skipped_pressure: COUNTERS.skipped_pressure.load(Ordering::Relaxed),
        skipped_peer_full: COUNTERS.skipped_peer_full.load(Ordering::Relaxed),
        queue_overflow: COUNTERS.queue_overflow.load(Ordering::Relaxed),
        queued_ranges,
    }
}

/// Hysteresis flag: once a node pauses for pressure it stays paused until the
/// reaper has actually pulled it back below the eviction target.
static PAUSED: AtomicBool = AtomicBool::new(false);

/// Pulls are skipped at the watermark and stay skipped until usage falls to
/// the eviction target. This prevents pull → evict → pull thrash.
pub fn should_pause(total: u64, watermark: u64, target: u64, paused: bool) -> bool {
    if paused {
        total > target
    } else {
        total > watermark
    }
}

/// Last tick's pressure decision, for `/stats`.
pub fn paused() -> bool {
    PAUSED.load(Ordering::Relaxed)
}

async fn local_accepting(n: &AppState) -> bool {
    let (ev, bl) = n.db.read(|c: &rusqlite::Connection| crate::db::live_bytes(c)).await;
    let total = (ev + bl).max(0) as u64;
    let paused = should_pause(
        total,
        n.cfg.watermark_bytes,
        n.cfg.eviction_target_bytes,
        PAUSED.load(Ordering::Relaxed),
    );
    PAUSED.store(paused, Ordering::Relaxed);
    !paused
}

#[derive(Debug, Default)]
struct WorkQueue {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl WorkQueue {
    fn new() -> WorkQueue {
        let mut q = WorkQueue::default();
        q.push(String::new());
        q
    }

    /// Returns false when the bound is reached or the prefix is already queued.
    fn push(&mut self, prefix: String) -> bool {
        if self.set.contains(&prefix) {
            return true;
        }
        if self.order.len() >= QUEUE_CAP {
            COUNTERS.queue_overflow.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.set.insert(prefix.clone());
        self.order.push_back(prefix);
        true
    }

    /// Put the root at the front even when the backlog is at its cap.
    fn force_root(&mut self) {
        if self.set.remove("") {
            self.order.retain(|p| !p.is_empty());
        } else if self.order.len() >= QUEUE_CAP {
            if let Some(dropped) = self.order.pop_back() {
                self.set.remove(&dropped);
            }
        }
        self.order.push_front(String::new());
        self.set.insert(String::new());
    }

    fn pop_batch(&mut self, cap: usize) -> Vec<String> {
        let n = cap.min(self.order.len());
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            if let Some(p) = self.order.pop_front() {
                self.set.remove(&p);
                out.push(p);
            }
        }
        out
    }

    fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

type QueueKey = (String, String);

fn queues() -> &'static Mutex<HashMap<QueueKey, WorkQueue>> {
    static QUEUES: OnceLock<Mutex<HashMap<QueueKey, WorkQueue>>> = OnceLock::new();
    QUEUES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn queue_key(peer: &reqwest::Url, kind: Kind) -> QueueKey {
    (peer.as_str().to_string(), kind.as_str().to_string())
}

fn take_queue(peer: &reqwest::Url, kind: Kind) -> WorkQueue {
    let key = queue_key(peer, kind);
    let mut all = queues()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    all.remove(&key).unwrap_or_else(WorkQueue::new)
}

fn return_queue(peer: &reqwest::Url, kind: Kind, queue: WorkQueue) {
    let key = queue_key(peer, kind);
    let mut all = queues()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if queue.is_empty() {
        all.remove(&key);
    } else {
        // Keep one queue per (peer, kind); a restarting loop must not leak.
        all.insert(key, queue);
    }
}

/// Page cursors survive the tick budget, so a huge remote leaf resumes where
/// it stopped instead of re-reading the same first page forever.
type PageKey = (String, String, String);

const CURSOR_CAP: usize = 4096;

fn page_cursors() -> &'static Mutex<HashMap<PageKey, [u8; 32]>> {
    static CURSORS: OnceLock<Mutex<HashMap<PageKey, [u8; 32]>>> = OnceLock::new();
    CURSORS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn page_key(peer: &reqwest::Url, kind: Kind, prefix: &str) -> PageKey {
    (
        peer.as_str().to_string(),
        kind.as_str().to_string(),
        prefix.to_string(),
    )
}

fn take_page_cursor(peer: &reqwest::Url, kind: Kind, prefix: &str) -> Option<[u8; 32]> {
    let key = page_key(peer, kind, prefix);
    page_cursors()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&key)
}

fn save_page_cursor(peer: &reqwest::Url, kind: Kind, prefix: &str, after: [u8; 32]) {
    let key = page_key(peer, kind, prefix);
    let mut all = page_cursors()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if all.len() >= CURSOR_CAP && !all.contains_key(&key) {
        // Bounded memory beats resumability for pathological peer counts.
        all.clear();
    }
    all.insert(key, after);
}

fn clear_page_cursor(peer: &reqwest::Url, kind: Kind, prefix: &str) {
    let key = page_key(peer, kind, prefix);
    page_cursors()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&key);
}

/// Push cursors are separate: a large local range must not re-send its first
/// pages on every tick while the peer catches up.
fn push_cursors() -> &'static Mutex<HashMap<PageKey, [u8; 32]>> {
    static CURSORS: OnceLock<Mutex<HashMap<PageKey, [u8; 32]>>> = OnceLock::new();
    CURSORS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn take_push_cursor(peer: &reqwest::Url, kind: Kind, prefix: &str) -> Option<[u8; 32]> {
    let key = page_key(peer, kind, prefix);
    push_cursors()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&key)
}

fn save_push_cursor(peer: &reqwest::Url, kind: Kind, prefix: &str, after: [u8; 32]) {
    let key = page_key(peer, kind, prefix);
    let mut all = push_cursors()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if all.len() >= CURSOR_CAP && !all.contains_key(&key) {
        all.clear();
    }
    all.insert(key, after);
}

fn clear_push_cursor(peer: &reqwest::Url, kind: Kind, prefix: &str) {
    let key = page_key(peer, kind, prefix);
    push_cursors()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&key);
}

fn join(peer: &reqwest::Url, path: &str) -> reqwest::Url {
    peer.join(path).expect("joined url")
}

#[derive(Debug, Serialize)]
struct Probe {
    prefix: String,
    count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    fp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ids: Option<Vec<String>>,
    #[serde(default)]
    ids_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct Reply {
    prefix: String,
    #[serde(default)]
    count: Option<u64>,
    #[serde(default)]
    fp: Option<String>,
    #[serde(default)]
    ids: Option<Vec<String>>,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Response {
    v: u8,
    kind: String,
    ranges: Vec<Reply>,
    #[serde(default = "default_true")]
    accepting: bool,
}

fn default_true() -> bool {
    true
}

struct Ctx<'a> {
    n: &'a AppState,
    peer: &'a reqwest::Url,
    kind: Kind,
    deadline: Instant,
    probe_requests: usize,
    http_requests: usize,
    accepting: bool,
    peer_accepting: bool,
    events_pushed: u64,
    events_pulled: u64,
    blobs_pulled: u64,
    skipped_peer_full: u64,
    failed: bool,
}

impl<'a> Ctx<'a> {
    fn probe_ready(&self) -> bool {
        self.probe_requests < MAX_PROBE_REQUESTS && Instant::now() < self.deadline
    }

    fn http_ready(&self) -> bool {
        self.http_requests < MAX_HTTP_REQUESTS && Instant::now() < self.deadline
    }

    async fn post_reconcile(&mut self, probes: &[Probe]) -> Result<Response, String> {
        self.probe_requests += 1;
        self.http_requests += 1;
        COUNTERS.requests.fetch_add(1, Ordering::Relaxed);
        COUNTERS
            .probes
            .fetch_add(probes.len() as u64, Ordering::Relaxed);

        let body = json!({
            "v": ranges::PROTOCOL_V,
            "kind": self.kind.as_str(),
            "ranges": probes,
        });
        let resp = self
            .n
            .http
            .post(join(self.peer, "/sync/reconcile"))
            .timeout(REQUEST_TIMEOUT)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("reconcile status {}", resp.status()));
        }
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err("reconcile response exceeds 8 MiB".into());
        }
        let parsed: Response = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if parsed.v != ranges::PROTOCOL_V {
            return Err(format!("peer protocol version {}", parsed.v));
        }
        if parsed.kind != self.kind.as_str() {
            return Err(format!("peer answered kind {}", parsed.kind));
        }
        self.peer_accepting = parsed.accepting;
        Ok(parsed)
    }

    async fn fetch_ids_page(
        &mut self,
        prefix: &str,
        after: Option<[u8; 32]>,
    ) -> Result<(Vec<[u8; 32]>, Option<[u8; 32]>), String> {
        let probe = Probe {
            prefix: prefix.to_string(),
            count: 0,
            fp: None,
            ids: None,
            ids_only: true,
            after: after.map(|a| ranges::hex32(&a)),
            limit: Some(MAX_IDS_PER_REPLY as u32),
        };
        let mut resp = self.post_reconcile(&[probe]).await?;
        let reply = resp
            .ranges
            .pop()
            .ok_or_else(|| "id page reply missing".to_string())?;
        let mut ids = Vec::new();
        for raw in reply.ids.unwrap_or_default() {
            let id = ranges::parse_hex32(&raw)
                .ok_or_else(|| format!("peer sent invalid id `{raw}`"))?;
            ids.push(id);
        }
        let next = match reply.next.as_deref() {
            Some(raw) => Some(
                ranges::parse_hex32(raw)
                    .ok_or_else(|| format!("peer sent invalid page cursor `{raw}`"))?,
            ),
            None => None,
        };
        Ok((ids, next))
    }

    async fn fetch_events(&mut self, ids: &[[u8; 32]]) -> Result<Vec<Value>, String> {
        self.http_requests += 1;
        COUNTERS.requests.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "ids": ids.iter().map(ranges::hex32).collect::<Vec<_>>(),
        });
        let resp = self
            .n
            .http
            .post(join(self.peer, "/sync/events/fetch"))
            .timeout(REQUEST_TIMEOUT)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("event fetch status {}", resp.status()));
        }
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err("event fetch response exceeds 8 MiB".into());
        }
        #[derive(Deserialize)]
        struct Fetched {
            #[serde(default)]
            events: Vec<Value>,
        }
        let out: Fetched = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        Ok(out.events)
    }

    async fn push_events(&mut self, events: Vec<Value>) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        self.http_requests += 1;
        COUNTERS.requests.fetch_add(1, Ordering::Relaxed);
        let n = events.len() as u64;
        let resp = self
            .n
            .http
            .post(join(self.peer, "/sync/events"))
            .timeout(REQUEST_TIMEOUT)
            .json(&events)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("event push status {}", resp.status()));
        }
        self.events_pushed += n;
        Ok(())
    }
}

pub async fn run(n: &AppState, peer: &reqwest::Url, kind: Kind) -> bool {
    let accepting = local_accepting(n).await;
    let mut ctx = Ctx {
        n,
        peer,
        kind,
        deadline: Instant::now() + TICK_BUDGET,
        probe_requests: 0,
        http_requests: 0,
        accepting,
        peer_accepting: true,
        events_pushed: 0,
        events_pulled: 0,
        blobs_pulled: 0,
        skipped_peer_full: 0,
        failed: false,
    };
    if !accepting {
        COUNTERS.skipped_pressure.fetch_add(1, Ordering::Relaxed);
    }

    let mut queue = take_queue(peer, kind);
    // Always re-check the root so keys published since the last tick are not
    // hidden behind a persisted deep-range backlog.
    queue.force_root();

    while !queue.is_empty() && ctx.probe_ready() && ctx.http_ready() {
        let prefixes = queue.pop_batch(MAX_RANGES);
        if prefixes.is_empty() {
            break;
        }

        let now = reaper::now();
        let batch = prefixes.clone();
        let summaries = n
            .db
            .read(move |c: &rusqlite::Connection| {
                ranges::summary_batch(c, kind, &batch, now)
            })
            .await;
        let summaries = match summaries {
            Ok(s) => s,
            Err(_) => {
                ctx.failed = true;
                for p in prefixes {
                    queue.push(p);
                }
                break;
            }
        };

        let probes: Vec<Probe> = prefixes
            .iter()
            .zip(summaries.iter())
            .map(|(prefix, s)| Probe {
                prefix: prefix.clone(),
                count: s.count,
                fp: if s.count > 0 { Some(s.fp_b64()) } else { None },
                ids: s.ids.as_ref().map(|ids| ids.iter().map(ranges::hex32).collect()),
                ids_only: false,
                after: None,
                limit: None,
            })
            .collect();

        let resp = match ctx.post_reconcile(&probes).await {
            Ok(r) => r,
            Err(_) => {
                ctx.failed = true;
                for p in prefixes {
                    queue.push(p);
                }
                break;
            }
        };
        if resp.ranges.len() != prefixes.len() {
            ctx.failed = true;
            for p in prefixes {
                queue.push(p);
            }
            break;
        }
        if !resp.accepting {
            // A full peer would evict something immediately. Pulls still make
            // room on the peer and are safe; only pushes are suppressed below.
            ctx.skipped_peer_full += 1;
        }

        let mut ranges = prefixes.into_iter().zip(summaries).zip(resp.ranges);
        while let Some(((prefix, local), remote)) = ranges.next() {
            if remote.prefix != prefix {
                ctx.failed = true;
                queue.push(prefix);
                continue;
            }
            if !handle_range(&mut ctx, &mut queue, prefix, local, remote).await {
                ctx.failed = true;
                // Do not lose the rest of this probe batch on a transport
                // failure; the root retry would otherwise rescan it all.
                for ((prefix, _), _) in ranges {
                    queue.push(prefix);
                }
                break;
            }
        }
        if ctx.failed {
            break;
        }
    }

    COUNTERS
        .events_pushed
        .fetch_add(ctx.events_pushed, Ordering::Relaxed);
    COUNTERS
        .events_pulled
        .fetch_add(ctx.events_pulled, Ordering::Relaxed);
    COUNTERS
        .blobs_pulled
        .fetch_add(ctx.blobs_pulled, Ordering::Relaxed);
    COUNTERS
        .skipped_peer_full
        .fetch_add(ctx.skipped_peer_full, Ordering::Relaxed);

    return_queue(peer, kind, queue);
    !ctx.failed
}

/// Returns false only for transport/parse failures (stop this tick).
async fn handle_range(
    ctx: &mut Ctx<'_>,
    queue: &mut WorkQueue,
    prefix: String,
    local: ranges::Summary,
    remote: Reply,
) -> bool {
    let remote_count = remote.count.unwrap_or(0);
    let same_fp = match (&remote.fp, remote_count) {
        (_, 0) => true,
        (Some(fp), _) => *fp == local.fp_b64(),
        (None, _) => false,
    };
    if remote_count == local.count && same_fp {
        return true;
    }

    if remote_count == 0 {
        // Peer has nothing here: push events only (blobs stay pull-only).
        if ctx.kind == Kind::Events {
            match push_prefix_events(ctx, &prefix).await {
                Ok(true) => {}
                Ok(false) => {
                    queue.push(prefix);
                }
                Err(()) => return false,
            }
        }
        return true;
    }

    if local.count == 0 {
        // We have nothing here: page every remote id and pull it.
        return match pull_remote_prefix(ctx, &prefix, None).await {
            Ok(true) => true,
            Ok(false) => {
                queue.push(prefix);
                true
            }
            Err(()) => false,
        };
    }

    if remote_count <= LEAF_KEYS as u64 {
        let Some(remote_ids) = remote.ids else {
            ctx.failed = true;
            return false;
        };
        let remote_set: HashSet<[u8; 32]> = remote_ids
            .iter()
            .filter_map(|raw| ranges::parse_hex32(raw))
            .collect();
        if remote_set.len() != remote_count as usize
            || remote_set
                .iter()
                .any(|id| !ranges::in_prefix(id, &prefix).unwrap_or(false))
        {
            ctx.failed = true;
            return false;
        }

        let mut partial = false;

        // Pull remote-only keys. Ask the local DB which of the (≤64) remote ids
        // we already have instead of materializing the whole local range.
        if ctx.accepting {
            let present = match present_keys(ctx.n, ctx.kind, &remote_set).await {
                Ok(set) => set,
                Err(_) => {
                    ctx.failed = true;
                    return false;
                }
            };
            let missing_here: Vec<[u8; 32]> = remote_set
                .iter()
                .copied()
                .filter(|id| !present.contains(id))
                .collect();
            if !missing_here.is_empty() {
                match pull_ids(ctx, &missing_here).await {
                    Ok(true) => {}
                    Ok(false) => partial = true,
                    Err(()) => return false,
                }
            }
        }

        // Push local-only keys (events; blob bodies never push proactively).
        if ctx.kind == Kind::Events {
            match push_local_missing(ctx, &prefix, &remote_set).await {
                Ok(true) => {}
                Ok(false) => partial = true,
                Err(()) => return false,
            }
        }

        if partial || !ctx.http_ready() || !ctx.probe_ready() {
            queue.push(prefix);
        }
        return true;
    }

    if local.count <= LEAF_KEYS as u64 {
        // We are the small side: push our exact leaf, then page their ids.
        let ids = local.ids.unwrap_or_default();
        if ctx.kind == Kind::Events {
            match push_event_ids(ctx, &ids).await {
                Ok(true) => {}
                Ok(false) => {
                    queue.push(prefix.clone());
                    return true;
                }
                Err(()) => return false,
            }
        }
        match pull_remote_prefix(ctx, &prefix, Some(ids)).await {
            Ok(true) => true,
            Ok(false) => {
                queue.push(prefix);
                true
            }
            Err(()) => false,
        }
    } else if prefix.len() < 64 {
        for child in ranges::children(&prefix) {
            queue.push(child);
        }
        true
    } else {
        // Impossible for unique 32-byte keys, but never loop forever.
        ctx.failed = true;
        false
    }
}

async fn present_keys(
    n: &AppState,
    kind: Kind,
    ids: &HashSet<[u8; 32]>,
) -> Result<HashSet<[u8; 32]>, String> {
    if ids.is_empty() {
        return Ok(HashSet::new());
    }
    let ids: Vec<[u8; 32]> = ids.iter().copied().collect();
    let now = reaper::now();
    n.db.read(move |c: &rusqlite::Connection| {
        let sql = match kind {
            Kind::Events => {
                "SELECT EXISTS(SELECT 1 FROM events WHERE id=?1 AND state='live' AND expires_at>?2)"
            }
            Kind::Blobs => "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash=?1 AND state='live')",
        };
        let mut stmt = c.prepare(sql).map_err(|e| e.to_string())?;
        let mut out = HashSet::new();
        for id in ids {
            let exists: i64 = match kind {
                Kind::Events => stmt
                    .query_row(rusqlite::params![&id[..], now], |r| r.get(0))
                    .unwrap_or(0),
                Kind::Blobs => stmt
                    .query_row(rusqlite::params![&id[..]], |r| r.get(0))
                    .unwrap_or(0),
            };
            if exists != 0 {
                out.insert(id);
            }
        }
        Ok(out)
    })
    .await
}

/// Push local events in `prefix` that the peer's exact leaf does not have.
/// Pages the local range, so memory stays bounded even when local is huge.
async fn push_local_missing(
    ctx: &mut Ctx<'_>,
    prefix: &str,
    remote: &HashSet<[u8; 32]>,
) -> Result<bool, ()> {
    if !ctx.peer_accepting {
        return Ok(true);
    }
    let now = reaper::now();
    let prefix = prefix.to_string();
    let mut after = take_push_cursor(ctx.peer, ctx.kind, &prefix);
    loop {
        if !ctx.http_ready() {
            if let Some(a) = after {
                save_push_cursor(ctx.peer, ctx.kind, &prefix, a);
            }
            return Ok(false);
        }
        let batch_prefix = prefix.clone();
        let page = ctx
            .n
            .db
            .read(move |c: &rusqlite::Connection| {
                ranges::event_page(c, &batch_prefix, after, now, EVENT_BATCH)
            })
            .await
            .map_err(|_| ())?;
        let (rows, next) = page;
        let events: Vec<Value> = rows
            .iter()
            .filter(|(id, _)| !remote.contains(id))
            .filter_map(|(_, data)| serde_json::from_slice::<Value>(data).ok())
            .collect();
        if ctx.push_events(events).await.is_err() {
            if let Some(a) = after {
                save_push_cursor(ctx.peer, ctx.kind, &prefix, a);
            }
            return Err(());
        }
        match next {
            Some(x) => after = Some(x),
            None => {
                clear_push_cursor(ctx.peer, ctx.kind, &prefix);
                return Ok(true);
            }
        }
    }
}

/// Page every id the peer has under `prefix`, pulling events/blobs we lack.
/// `known` is our exact local set when we have one (small side). Pagination
/// resumes across ticks, so a huge remote range cannot restart at zero.
async fn pull_remote_prefix(
    ctx: &mut Ctx<'_>,
    prefix: &str,
    known: Option<Vec<[u8; 32]>>,
) -> Result<bool, ()> {
    if !ctx.accepting {
        return Ok(false);
    }
    let known: Option<HashSet<[u8; 32]>> = known.map(|v| v.into_iter().collect());
    let mut after = take_page_cursor(ctx.peer, ctx.kind, prefix);
    loop {
        if !ctx.probe_ready() || !ctx.http_ready() {
            if let Some(a) = after {
                save_page_cursor(ctx.peer, ctx.kind, prefix, a);
            }
            return Ok(false);
        }
        let (ids, next) = ctx.fetch_ids_page(prefix, after).await.map_err(|_| ())?;
        let wanted: Vec<[u8; 32]> = ids
            .into_iter()
            .filter(|id| known.as_ref().map(|k| !k.contains(id)).unwrap_or(true))
            .collect();
        if !wanted.is_empty() {
            match pull_ids(ctx, &wanted).await {
                Ok(true) => {}
                Ok(false) => {
                    // The current page may be only partly transferred. Replay
                    // from the cursor *before* it; both event ingest and blob
                    // install are idempotent.
                    if let Some(a) = after {
                        save_page_cursor(ctx.peer, ctx.kind, prefix, a);
                    } else {
                        clear_page_cursor(ctx.peer, ctx.kind, prefix);
                    }
                    return Ok(false);
                }
                Err(()) => return Err(()),
            }
        }
        match next {
            Some(x) => after = Some(x),
            None => {
                clear_page_cursor(ctx.peer, ctx.kind, prefix);
                return Ok(true);
            }
        }
    }
}

/// Which of these blob hashes are still referenced by a live, unexpired local
/// event? Crafted reconcile replies cannot make us pull an orphan body.
async fn referenced_blobs(
    n: &AppState,
    ids: &[[u8; 32]],
) -> Result<HashSet<[u8; 32]>, String> {
    if ids.is_empty() {
        return Ok(HashSet::new());
    }
    let ids = ids.to_vec();
    let now = reaper::now();
    n.db.read(move |c: &rusqlite::Connection| {
        let mut stmt = c
            .prepare(
                "SELECT EXISTS(
                   SELECT 1 FROM refs r JOIN events e ON e.id = r.event_id
                   WHERE r.blob_hash = ?1 AND e.state='live' AND e.expires_at > ?2
                 )",
            )
            .map_err(|e| e.to_string())?;
        let mut out = HashSet::new();
        for id in ids {
            let exists: i64 = stmt
                .query_row(rusqlite::params![&id[..], now], |r| r.get(0))
                .unwrap_or(0);
            if exists != 0 {
                out.insert(id);
            }
        }
        Ok(out)
    })
    .await
}

/// Pull a concrete set of remote ids: event envelopes in batches, blob bodies
/// with bounded concurrency and the existing failure backoff. Returns false
/// when the tick budget cut the set short (the caller resumes later).
async fn pull_ids(ctx: &mut Ctx<'_>, ids: &[[u8; 32]]) -> Result<bool, ()> {
    if ids.is_empty() {
        return Ok(true);
    }
    if ctx.kind == Kind::Blobs {
        let referenced = referenced_blobs(ctx.n, ids).await.map_err(|_| ())?;
        let ids: Vec<[u8; 32]> = ids
            .iter()
            .copied()
            .filter(|id| referenced.contains(id))
            .collect();
        if ids.is_empty() {
            return Ok(true);
        }
        if !ctx.http_ready() {
            return Ok(false);
        }
        // One bounded wave per call; a page of 1000 hashes must not turn into a
        // multi-minute tick. Rotate so failing heads cannot starve the tail.
        let slots = (MAX_HTTP_REQUESTS.saturating_sub(ctx.http_requests))
            .min(BLOB_PULLS_PER_TICK)
            .min(ids.len());
        if slots == 0 {
            return Ok(false);
        }
        let start =
            (BLOB_ROTATION.fetch_add(slots as u64, Ordering::Relaxed) as usize) % ids.len();
        let hexes: Vec<String> = ids[start..]
            .iter()
            .chain(ids[..start].iter())
            .take(slots)
            .map(ranges::hex32)
            .collect();
        let n = AppState::clone(ctx.n);
        let peer = reqwest::Url::clone(ctx.peer);
        let pulls = futures_util::stream::iter(hexes)
            .map(|hash| {
                let app = AppState::clone(&n);
                let peer = reqwest::Url::clone(&peer);
                async move {
                    crate::sync::pulls::pull_blob_with_backoff(&app, &peer, &hash).await
                }
            })
            .buffer_unordered(BLOB_PULL_CONCURRENCY);
        let results: Vec<bool> = pulls.collect().await;
        let ok = results.iter().filter(|x| **x).count() as u64;
        ctx.blobs_pulled += ok;
        // HTTP requests are counted inside pulls; charge them to the tick cap.
        ctx.http_requests += results.len();
        return Ok(slots == ids.len());
    }

    for chunk in ids.chunks(EVENT_BATCH) {
        if !ctx.http_ready() {
            return Ok(false);
        }
        let events = ctx.fetch_events(chunk).await.map_err(|_| ())?;
        for bytes in events {
            if let Ok(raw) = serde_json::to_vec(&bytes) {
                if matches!(
                    crate::api::sync_ingest::store_envelope(ctx.n, raw).await,
                    Ok(true)
                ) {
                    ctx.events_pulled += 1;
                }
            }
        }
    }
    Ok(true)
}

async fn push_prefix_events(ctx: &mut Ctx<'_>, prefix: &str) -> Result<bool, ()> {
    if !ctx.peer_accepting {
        return Ok(true);
    }
    let now = reaper::now();
    let prefix = prefix.to_string();
    let mut after = take_push_cursor(ctx.peer, ctx.kind, &prefix);
    loop {
        if !ctx.http_ready() {
            if let Some(a) = after {
                save_push_cursor(ctx.peer, ctx.kind, &prefix, a);
            }
            return Ok(false);
        }
        let batch_prefix = prefix.clone();
        let page = ctx
            .n
            .db
            .read(move |c: &rusqlite::Connection| {
                ranges::event_page(c, &batch_prefix, after, now, EVENT_BATCH)
            })
            .await
            .map_err(|_| ())?;
        let (rows, next) = page;
        let events: Vec<Value> = rows
            .iter()
            .filter_map(|(_, data)| serde_json::from_slice::<Value>(data).ok())
            .collect();
        if ctx.push_events(events).await.is_err() {
            if let Some(a) = after {
                save_push_cursor(ctx.peer, ctx.kind, &prefix, a);
            }
            return Err(());
        }
        match next {
            Some(x) => after = Some(x),
            None => {
                clear_push_cursor(ctx.peer, ctx.kind, &prefix);
                return Ok(true);
            }
        }
    }
}

async fn push_event_ids(ctx: &mut Ctx<'_>, ids: &[[u8; 32]]) -> Result<bool, ()> {
    if !ctx.peer_accepting {
        return Ok(true);
    }
    for chunk in ids.chunks(EVENT_BATCH) {
        if !ctx.http_ready() {
            return Ok(false);
        }
        let wanted: Vec<[u8; 32]> = chunk.to_vec();
        let rows = ctx
            .n
            .db
            .read(move |c: &rusqlite::Connection| {
                let mut stmt = c
                    .prepare("SELECT data FROM events WHERE id = ?1 AND state='live' AND expires_at > ?2")
                    .expect("static query");
                let now = reaper::now();
                let mut out = Vec::new();
                for id in wanted {
                    if let Ok(data) = stmt.query_row(rusqlite::params![&id[..], now], |r| {
                        r.get::<_, Vec<u8>>(0)
                    }) {
                        if let Ok(v) = serde_json::from_slice::<Value>(&data) {
                            out.push(v);
                        }
                    }
                }
                out
            })
            .await;
        ctx.push_events(rows).await.map_err(|_| ())?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{SystemTime, UNIX_EPOCH};

    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rabta-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_cfg(dir: &std::path::Path) -> crate::config::Config {
        crate::config::Config {
            port: 0,
            data_dir: dir.to_path_buf(),
            storage_max: 10 * 1024 * 1024,
            storage_clamped: false,
            storage_max_configured: 10 * 1024 * 1024,
            max_single_blob: 1024 * 1024,
            watermark_bytes: 9 * 1024 * 1024,
            eviction_target_bytes: 8 * 1024 * 1024,
            sse_subscriber_cap: 8,
            sync_nodes: Vec::new(),
            sync_interval: Duration::from_secs(60),
        }
    }

    fn state(dir: &std::path::Path, cfg: crate::config::Config) -> AppState {
        let uploads = crate::store::blobs::UploadGovernor::from_config(&cfg);
        std::sync::Arc::new(crate::api::Node {
            cfg,
            db: crate::db::Db::open(dir),
            http: reqwest::Client::new(),
            started_at: reaper::now(),
            uploads,
        })
    }

    async fn serve(n: AppState) -> reqwest::Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::router(n);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        reqwest::Url::parse(&format!("http://{addr}")).unwrap()
    }

    fn envelope(n: i64, blob: Option<&str>) -> Vec<u8> {
        let now = reaper::now();
        let created_at = now - 10;
        let expires_at = now + 3600;
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let owner = format!("ed25519:{}", hex::encode(key.verifying_key().to_bytes()));
        let data = json!({ "n": n });
        let canonical = crate::canon::digest_value(
            "test",
            created_at,
            expires_at,
            &owner,
            &[],
            &data,
            blob,
        );
        let digest: [u8; 32] = Sha256::digest(crate::canon::canonical_value(&canonical)).into();
        let sig = key.sign(&digest);
        let mut v = json!({
            "collection": "test",
            "created_at": created_at,
            "data": data,
            "expires_at": expires_at,
            "labels": [],
            "owner": owner,
            "id": hex::encode(digest),
            "sig": hex::encode(sig.to_bytes()),
        });
        if let Some(b) = blob {
            v["blob"] = json!(b);
        }
        serde_json::to_vec(&v).unwrap()
    }

    async fn run_until_quiet(a: &AppState, b: &AppState, a_url: &reqwest::Url, b_url: &reqwest::Url) {
        for _ in 0..4 {
            let _ = run(b, a_url, Kind::Events).await;
            let _ = run(b, a_url, Kind::Blobs).await;
            let _ = run(a, b_url, Kind::Events).await;
            let _ = run(a, b_url, Kind::Blobs).await;
        }
    }

    #[tokio::test]
    async fn two_nodes_exchange_events_and_blobs_exactly() {
        let dir_a = temp_dir("sync-a");
        let dir_b = temp_dir("sync-b");
        crate::store::blobs::init_dirs(&dir_a).unwrap();
        crate::store::blobs::init_dirs(&dir_b).unwrap();
        let cfg_a = test_cfg(&dir_a);
        let cfg_b = test_cfg(&dir_b);
        let a = state(&dir_a, cfg_a.clone());
        let b = state(&dir_b, cfg_b.clone());
        let a_url = serve(a.clone()).await;
        let b_url = serve(b.clone()).await;

        // A owns a blob and an event that references it.
        let body = b"rabta-exact-range-test";
        let hash: [u8; 32] = Sha256::digest(body).into();
        let hash_hex = hex::encode(hash);
        let mut sink = crate::store::blobs::BlobSink::start(
            &a.uploads,
            &dir_a,
            0,
            cfg_a.watermark_bytes,
            cfg_a.max_single_blob,
        )
        .await
        .unwrap();
        sink.push(body).unwrap();
        let staged = sink.finish().unwrap();
        assert_eq!(staged.hash, hash);
        assert_eq!(
            crate::store::blobs::install_staged(
                &a.db,
                &cfg_a,
                staged,
                crate::store::blobs::BlobOrigin::Local,
            )
                .await
                .unwrap(),
            crate::store::blobs::Install::Fresh
        );
        assert!(crate::api::sync_ingest::store_envelope(&a, envelope(1, Some(&hash_hex)))
            .await
            .unwrap());

        // A -> B: event first, then the blob body (pull-only).
        let _ = run(&b, &a_url, Kind::Events).await;
        let events_b = b
            .db
            .read(|c| crate::store::queries::count_live(c))
            .await;
        assert_eq!(events_b.0, 1, "B did not pull A's event");
        let _ = run(&b, &a_url, Kind::Blobs).await;
        assert!(crate::store::blobs::blob_path(&dir_b, &hash_hex).is_file());

        // B now owns an event of its own; A must pull it on the reverse tick.
        assert!(crate::api::sync_ingest::store_envelope(&b, envelope(2, None))
            .await
            .unwrap());
        let _ = run(&a, &b_url, Kind::Events).await;
        let events_a = a
            .db
            .read(|c| crate::store::queries::count_live(c))
            .await;
        assert_eq!(events_a.0, 2, "A did not pull B's event");

        // A second pass must be a no-op (counts + fingerprints match).
        run_until_quiet(&a, &b, &a_url, &b_url).await;
        let final_a = a
            .db
            .read(|c| crate::store::queries::count_live(c))
            .await;
        let final_b = b
            .db
            .read(|c| crate::store::queries::count_live(c))
            .await;
        assert_eq!(final_a, final_b);
        assert_eq!(final_a, (2, 1));

        drop(a);
        drop(b);
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[tokio::test]
    async fn split_ranges_converge_with_leaf_exchange() {
        let dir_a = temp_dir("split-a");
        let dir_b = temp_dir("split-b");
        crate::store::blobs::init_dirs(&dir_a).unwrap();
        crate::store::blobs::init_dirs(&dir_b).unwrap();
        let a = state(&dir_a, test_cfg(&dir_a));
        let b = state(&dir_b, test_cfg(&dir_b));
        let a_url = serve(a.clone()).await;
        let b_url = serve(b.clone()).await;

        // Both sides exceed the 64-key leaf threshold at the root.
        for n in 0..80 {
            assert!(crate::api::sync_ingest::store_envelope(&a, envelope(1000 + n, None))
                .await
                .unwrap());
            assert!(crate::api::sync_ingest::store_envelope(&b, envelope(2000 + n, None))
                .await
                .unwrap());
        }

        for _ in 0..4 {
            let _ = run(&b, &a_url, Kind::Events).await;
            let _ = run(&a, &b_url, Kind::Events).await;
        }

        let ca = a.db.read(|c| crate::store::queries::count_live(c)).await;
        let cb = b.db.read(|c| crate::store::queries::count_live(c)).await;
        assert_eq!(ca.0, 160, "A did not converge to the union");
        assert_eq!(cb.0, 160, "B did not converge to the union");

        drop(a);
        drop(b);
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[tokio::test]
    async fn full_peer_serves_pulls_without_receiving_pushes() {
        let dir_a = temp_dir("full-a");
        let dir_b = temp_dir("full-b");
        crate::store::blobs::init_dirs(&dir_a).unwrap();
        crate::store::blobs::init_dirs(&dir_b).unwrap();
        let a = state(&dir_a, test_cfg(&dir_a));
        let b = state(&dir_b, test_cfg(&dir_b));
        assert!(crate::api::sync_ingest::store_envelope(&b, envelope(2, None))
            .await
            .unwrap());
        // Serve B with the same DB under a zero watermark so
        // `/sync/reconcile` reports `accepting: false` without running the
        // reaper. The normal config above let the event be stored first.
        let mut cfg_b = test_cfg(&dir_b);
        cfg_b.watermark_bytes = 0;
        cfg_b.eviction_target_bytes = 0;
        let uploads_b = crate::store::blobs::UploadGovernor::from_config(&cfg_b);
        let b_full = std::sync::Arc::new(crate::api::Node {
            cfg: cfg_b,
            db: b.db.clone(),
            http: reqwest::Client::new(),
            started_at: reaper::now(),
            uploads: uploads_b,
        });
        let b_url = serve(b_full.clone()).await;

        assert!(crate::api::sync_ingest::store_envelope(&a, envelope(1, None))
            .await
            .unwrap());

        let _ = run(&a, &b_url, Kind::Events).await;

        let ca = a.db.read(|c| crate::store::queries::count_live(c)).await;
        let cb = b_full.db.read(|c| crate::store::queries::count_live(c)).await;
        assert_eq!(ca.0, 2, "A should still pull from a full peer");
        assert_eq!(cb.0, 1, "A pushed events to a full peer");

        drop(a);
        drop(b);
        drop(b_full);
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn pressure_pause_has_hysteresis() {
        assert!(!should_pause(80, 90, 85, false));
        assert!(should_pause(91, 90, 85, false));
        // Already paused: stays paused until the target, not just the watermark.
        assert!(should_pause(88, 90, 85, true));
        assert!(!should_pause(85, 90, 85, true));
        assert!(!should_pause(10, 90, 85, true));
    }

    #[test]
    fn work_queue_dedupes_and_keeps_root() {
        let mut q = WorkQueue::new();
        assert!(q.push(String::new()), "root was queued twice");
        assert_eq!(q.order.len(), 1);
        assert!(q.push("a".into()));
        assert_eq!(q.pop_batch(1), vec![String::new()]);
        assert!(q.push(String::new()));
        assert_eq!(q.pop_batch(10), vec!["a".to_string(), String::new()]);
    }

    #[test]
    fn work_queue_is_bounded() {
        let mut q = WorkQueue::default();
        for i in 0..QUEUE_CAP {
            assert!(q.push(format!("{i:x}")));
        }
        assert!(!q.push("overflow".into()));
        assert_eq!(q.order.len(), QUEUE_CAP);
    }
}
