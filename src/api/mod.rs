pub mod blob_get;
pub mod blobs_api;
pub mod events;
pub mod misc;
pub mod openapi;
pub mod routes;
pub mod sync;

use std::sync::Arc;

use tokio::sync::watch;

use crate::config::Config;
use crate::db::Db;
use crate::identity::NodeIdentity;
use crate::store::blobs::UploadGovernor;

/// Shared node state handed to every handler.
pub struct Node {
    pub cfg: Config,
    pub db: Db,
    pub identity: NodeIdentity,
    pub started_at: i64,
    /// Process-wide upload admission (slots, temp bytes, free-space floor).
    pub uploads: Arc<UploadGovernor>,
    /// Fast in-memory duplicate filter for ingress sync.
    pub dedup: Arc<crate::sync::dedup::IngressDedup>,
}

pub type AppState = Arc<Node>;

impl Node {
    pub fn new(cfg: Config, db: Db, identity: NodeIdentity) -> AppState {
        let uploads = UploadGovernor::from_config(&cfg);
        let dedup = Arc::new(crate::sync::dedup::IngressDedup::new());
        Arc::new(Node {
            cfg,
            db,
            identity,
            started_at: crate::store::reaper::now(),
            uploads,
            dedup,
        })
    }
}

/// Resolve when the flag flips to `true` or its sender is dropped.
pub async fn wait_for_shutdown(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}
