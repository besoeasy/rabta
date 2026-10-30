mod api;
mod canon;
mod config;
mod db;
mod error;
mod store;
mod sync;

use std::net::SocketAddr;

use axum::routing::{get, head, post, put};
use axum::Router;
use tower_http::cors::CorsLayer;

use api::AppState;

fn data_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "/data".to_string()))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let dir = data_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        panic!("cannot create data dir {}: {e}", dir.display());
    }
    if let Err(e) = store::blobs::init_dirs(&dir) {
        panic!("cannot initialize blob layout: {e}");
    }

    let cfg = config::Config::load();
    let port = cfg.port;

    let database = db::Db::open(&dir);
    let db2 = database.clone();
    let dir2 = dir.clone();
    if let Err(e) = store::blobs::boot_hygiene(&db2, dir2).await {
        panic!("boot hygiene failed: {e}");
    }

    // Apply expiry + watermark immediately instead of waiting one interval.
    store::reaper::reaper_tick(&database, cfg.clone()).await;

    let uploads = store::blobs::UploadGovernor::from_config(&cfg);
    let state: AppState = std::sync::Arc::new(api::Node {
        cfg: cfg.clone(),
        db: database.clone(),
        http: reqwest::Client::new(),
        started_at: store::reaper::now(),
        uploads,
    });

    let app = router(state.clone());

    // Reaper: expiry sweep (Layer 1) + pressure cleanup every 5 minutes.
    {
        let db = database.clone();
        let rcfg = cfg.clone();
        tokio::spawn(async move {
            let start = tokio::time::Instant::now() + store::reaper::REAPER_INTERVAL;
            let mut ticker = tokio::time::interval_at(start, store::reaper::REAPER_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                store::reaper::reaper_tick(&db, rcfg.clone()).await;
            }
        });
    }

    // Sync client loop: one task per configured peer (NODES).
    if !cfg.sync_nodes.is_empty() {
        tracing::info!(nodes = cfg.sync_nodes.len(), "sync loop starting");
        sync::loop_all::start(state.clone()).await;
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {addr}: {e}"));
    tracing::info!("rabta listening on {addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
    tracing::info!("shutdown complete");
}

fn router(state: AppState) -> Router {
    let big = axum::extract::DefaultBodyLimit::disable();

    let public = Router::new()
        .route("/", get(api::misc::index))
        .route("/healthz", get(api::misc::healthz))
        .route("/stats", get(api::misc::stats))
        .route("/events", post(api::events::publish).layer(big.clone()))
        .route("/events", get(api::events::list))
        .route("/events/stream", get(api::events::stream))
        .route("/events/{id}", get(api::events::get_one))
        .route("/events/{id}/size", get(api::events::size))
        .route("/blobs/{blob}", put(api::blobs_api::put).layer(big.clone()))
        .route("/blobs/{blob}", get(api::blob_get::get))
        .route("/blobs/{blob}", head(api::blob_get::get));

    let sync_routes = Router::new()
        .route("/sync/reconcile", post(api::sync_ranges::reconcile).layer(big.clone()))
        .route("/sync/events", post(api::sync_ingest::post_events).layer(big.clone()))
        .route("/sync/events/fetch", post(api::sync_pull::fetch_events).layer(big.clone()))
        .route("/sync/blobs", post(api::sync_push::post_blobs).layer(big.clone()))
        .route("/sync/events", get(api::sync_pull::pull_events))
        .route("/sync/events/{id}", get(api::sync_pull::get_event))
        .route("/sync/blobs/{hash}", get(api::sync_pull::get_blob));

    public
        .merge(sync_routes)
        .with_state(state)
        .layer(CorsLayer::permissive())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
    tracing::info!("shutdown signal received");
}
