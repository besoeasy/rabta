pub mod blob_get;
pub mod blobs_api;
pub mod events;
pub mod misc;
pub mod sync_ingest;
pub mod sync_pull;
pub mod sync_push;
pub mod sync_ranges;

use std::sync::atomic::AtomicI64;

use crate::config::Config;
use crate::db::Db;

/// Shared node state handed to every handler.
pub struct Node {
    pub cfg: Config,
    pub db: Db,
    pub http: reqwest::Client,
    pub started_at: i64,
    /// Process-wide upload admission (slots, temp bytes, free-space floor).
    pub uploads: std::sync::Arc<crate::store::blobs::UploadGovernor>,
}

pub type AppState = std::sync::Arc<Node>;

/// Live SSE subscriber count. Admission is a CAS against the configured cap.
pub static SSE_ACTIVE: AtomicI64 = AtomicI64::new(0);
