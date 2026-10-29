pub mod blob_get;
pub mod blobs_api;
pub mod events;
pub mod misc;
pub mod sync_bloom;
pub mod sync_ingest;
pub mod sync_pull;
pub mod sync_push;

use std::sync::atomic::{AtomicI64, Ordering};

use crate::config::Config;
use crate::db::Db;

/// Shared node state handed to every handler.
pub struct Node {
    pub cfg: Config,
    pub db: Db,
    pub http: reqwest::Client,
    pub started_at: i64,
}

pub type AppState = std::sync::Arc<Node>;

/// Live SSE subscriber count + the configured cap (set once at boot).
pub static SSE_ACTIVE: AtomicI64 = AtomicI64::new(0);
pub static SSE_CAP_LIMIT: AtomicI64 = AtomicI64::new(256);

pub fn sse_set_cap(cap: usize) {
    SSE_CAP_LIMIT.store(cap as i64, Ordering::Relaxed);
}
