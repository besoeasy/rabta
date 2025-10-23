#![recursion_limit = "256"]

mod api;
mod bitcoin;
mod canon;
mod config;
mod db;
mod error;
mod identity;
mod store;
mod sync;

use std::future::IntoFuture;
use std::net::SocketAddr;

use axum::Router;
use axum::routing::{get, head, post, put};

use api::AppState;
use api::routes;

/// Bound on draining connections after SIGTERM/SIGINT.
const SHUTDOWN_DRAIN: std::time::Duration = std::time::Duration::from_secs(5);

fn data_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("DATA").unwrap_or_else(|_| "/data".to_string()))
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

    let cfg = config::Config::load();
    let port = cfg.port;

    let identity = identity::NodeIdentity::generate();
    let node_id = identity.node_id_hex();
    let public_key = identity.public_key_string();
    tracing::info!(
        node_id = %node_id,
        public_key = %public_key,
        "ephemeral node identity generated for this process"
    );

    if cfg.blobs_enabled()
        && let Err(e) = store::blobs::init_dirs(&dir)
    {
        panic!("cannot initialize blob layout: {e}");
    }

    let database = db::Db::open(&dir);

    // Blob plane boot hygiene: drop crashed temp files and orphan bytes.
    if cfg.blobs_enabled()
        && let Err(e) = store::blobs::boot_hygiene(&database, cfg.data_dir.clone()).await
    {
        tracing::error!("blob boot hygiene: {e}");
    }

    // Apply expiry + watermark immediately instead of waiting one interval.
    store::reaper::reaper_tick(&database, cfg.clone()).await;

    // One flag stops the listener for graceful shutdown.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let state = api::Node::new(cfg.clone(), database.clone(), identity);

    if !cfg.policy.is_empty() {
        tracing::info!(
            rules = cfg.policy.rule_count(),
            global = cfg.policy.matches_everything(),
            "records matching POLICY rules are exempt from pressure eviction"
        );
        if cfg.policy.matches_everything() {
            tracing::warn!(
                "POLICY configures a rule that matches every record; writes will \
                 be refused once the store fills with policy-exempt data"
            );
        }
    }

    if !cfg.sync_nodes.is_empty() {
        tracing::info!(
            nodes = cfg.sync_nodes.len(),
            "peer node URLs exposed via GET /api/v1/node"
        );
        for peer in cfg.sync_nodes.clone() {
            let st = state.clone();
            let rx = shutdown_rx.clone();
            tokio::spawn(async move {
                sync::worker::run_peer_worker(st, peer, rx).await;
            });
        }
    }

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

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {addr}: {e}"));
    tracing::info!("rabta listening on {addr}");

    let serve = axum::serve(listener, app)
        .with_graceful_shutdown({
            let mut rx = shutdown_rx.clone();
            async move { api::wait_for_shutdown(&mut rx).await }
        })
        .into_future();
    tokio::pin!(serve);

    // Flip the flag, then bound the drain so a
    // stuck client cannot turn a clean stop into SIGKILL.
    tokio::select! {
        res = &mut serve => {
            if let Err(e) = res {
                tracing::error!("server error: {e}");
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received");
            let _ = shutdown_tx.send(true);
            match tokio::time::timeout(SHUTDOWN_DRAIN, &mut serve).await {
                Ok(res) => {
                    if let Err(e) = res {
                        tracing::error!("server error during shutdown: {e}");
                    }
                }
                Err(_) => tracing::warn!(
                    "drain timed out after {}s; exiting",
                    SHUTDOWN_DRAIN.as_secs()
                ),
            }
        }
    }
    tracing::info!("shutdown complete");
}

pub(crate) fn router(state: AppState) -> Router {
    let big = axum::extract::DefaultBodyLimit::disable();

    let v1 = Router::new()
        .route(routes::HEALTH, get(api::misc::health))
        .route(routes::NODE, get(api::misc::node))
        .route(routes::OPENAPI, get(api::openapi::serve))
        .route(
            routes::EVENTS,
            post(api::events::publish)
                .get(api::events::list_get)
                .layer(big),
        )
        .route(routes::EVENTS_COUNT, get(api::events::count_get))
        .route(routes::SYNC, post(api::sync::handle).layer(big))
        .route(routes::EVENT_BY_ID, get(api::events::get_one))
        .route(routes::EVENT_SIZE, get(api::events::size))
        .route(routes::BLOBS, put(api::blobs_api::put).layer(big))
        .route(routes::BLOB_BY_HASH, get(api::blob_get::get))
        .route(routes::BLOB_BY_HASH, head(api::blob_get::head));

    let node_id = state.identity.node_id_hex();
    Router::new()
        .route("/", get(api::misc::index))
        .route(routes::INDEX, get(api::misc::api_index))
        .route(routes::OPENAPI, get(api::openapi::serve))
        .nest(routes::PREFIX, v1)
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            node_id,
            api::misc::node_header,
        ))
        .layer(axum::middleware::from_fn(cors_middleware))
}

async fn cors_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if req.method() == axum::http::Method::OPTIONS {
        return axum::response::Response::builder()
            .status(axum::http::StatusCode::NO_CONTENT)
            .header("access-control-allow-origin", "*")
            .header(
                "access-control-allow-methods",
                "GET, POST, PUT, DELETE, HEAD, OPTIONS",
            )
            .header("access-control-allow-headers", "*")
            .header("access-control-max-age", "86400")
            .body(axum::body::Body::empty())
            .unwrap();
    }
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        "access-control-allow-origin",
        axum::http::HeaderValue::from_static("*"),
    );
    h.insert(
        "access-control-allow-methods",
        axum::http::HeaderValue::from_static("GET, POST, PUT, DELETE, HEAD, OPTIONS"),
    );
    h.insert(
        "access-control-allow-headers",
        axum::http::HeaderValue::from_static("*"),
    );
    res
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
}
