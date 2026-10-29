use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use super::AppState;
use crate::store::reaper;

/// `GET /` — minimal JSON route index; no HTML dashboard (decision #14).
pub async fn index(State(n): State<AppState>) -> Json<serde_json::Value> {
    let mut routes = json!({
        "service": "rabta",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "rabta node — events + blobs on one port",
        "routes": {
            "GET /": "this index",
            "GET /healthz": "liveness probe",
            "GET /stats": "storage + eviction counters",
            "POST /events": "publish a signed envelope (application/json; `blob` references raw-PUT bytes)",
            "GET /events": "list (collection, label*, owner, limit, cursor)",
            "GET /events/{id}": "fetch one (ETag / If-None-Match)",
            "GET /events/{id}/size": "envelope + attachment sizes",
            "GET /events/stream": "SSE (Last-Event-ID resume)",
            "PUT /blobs/{name}.blob|bin": "raw blob upload (orphan clock)",
            "GET /blobs/{hash}": "fetch blob (Range / ETag)",
            "HEAD /blobs/{hash}": "probe blob"
        }
    });
    if !n.cfg.sync_nodes.is_empty() {
        routes["routes"]["POST /sync/reconcile"] =
            json!("exact range reconciliation (protocol v1)");
        routes["routes"]["POST /sync/events"] = json!("push event batch (normal validation)");
        routes["routes"]["POST /sync/events/fetch"] = json!("batch event envelopes by id");
        routes["routes"]["POST /sync/blobs"] = json!("push blob bodies (normal caps)");
        routes["routes"]["GET /sync/events/{id}"] = json!("pull one event envelope");
        routes["routes"]["GET /sync/events"] = json!("paged pull (seq cursor)");
        routes["routes"]["GET /sync/blobs/{hash}"] = json!("pull one blob body");
    }
    Json(routes)
}

/// `GET /healthz` — liveness probe.
pub async fn healthz(State(n): State<AppState>) -> impl IntoResponse {
    let data = n
        .db
        .read(|c: &rusqlite::Connection| {
            let (e, b) = crate::store::queries::count_live(c);
            let (lev, lbl) = crate::db::live_bytes(c);
            (e, b, lev, lbl)
        })
        .await;
    (
        StatusCode::OK,
        Json(json!({"status": "ok", "live_events": data.0, "live_blobs": data.1})),
    )
        .into_response()
}

/// `GET /stats` — JSON monitoring (decision #14: no dashboard).
pub async fn stats(State(n): State<AppState>) -> impl IntoResponse {
    let cfg = n.cfg.clone();
    let data = n
        .db
        .read(move |c: &rusqlite::Connection| {
            let (e, b) = crate::store::queries::count_live(c);
            let (lev, lbl) = crate::db::live_bytes(c);
            (e, b, lev, lbl)
        })
        .await;

    let idx = &reaper::COUNTERS;
    let pulls = crate::sync::pulls::snapshot();
    let heals = crate::sync::loop_all::heal_snapshot();
    let rec = crate::sync::reconcile::snapshot();
    let free = crate::config::free_bytes_public(&cfg.data_dir);
    let last_sweep = reaper::last_sweep_at();
    let now = reaper::now();
    let body = json!({
        "events": { "live": data.0, "bytes": data.2 },
        "blobs": { "live": data.1, "bytes": data.3 },
        "storage": {
            "max_bytes": cfg.storage_max,
            "configured_max_bytes": cfg.storage_max_configured,
            "clamped_to_free": cfg.storage_clamped,
            "watermark_bytes": cfg.watermark_bytes,
            "eviction_target_bytes": cfg.eviction_target_bytes,
            "max_single_blob_bytes": cfg.max_single_blob,
            "free_bytes": free,
            "data_dir": cfg.data_dir.to_string_lossy(),
        },
        "reaper": {
            "interval_s": reaper::REAPER_INTERVAL.as_secs(),
            "last_sweep_at": if last_sweep > 0 { json!(last_sweep) } else { json!(null) },
            "last_sweep_age_s": if last_sweep > 0 {
                json!(now.saturating_sub(last_sweep))
            } else {
                json!(null)
            },
        },
        "eviction": {
            "events_evicted": idx.events_evicted.load(std::sync::atomic::Ordering::Relaxed),
            "blobs_evicted": idx.blobs_evicted.load(std::sync::atomic::Ordering::Relaxed),
            "bytes_reclaimed": idx.bytes_reclaimed.load(std::sync::atomic::Ordering::Relaxed),
        },
        "sse": {
            "subscribers": super::SSE_ACTIVE.load(std::sync::atomic::Ordering::Relaxed),
            "cap": cfg.sse_subscriber_cap,
        },
        "sync": {
            "nodes": n.cfg.sync_nodes.len(),
            "interval_s": n.cfg.sync_interval.as_secs(),
            "accepting": !crate::sync::reconcile::paused(),
            "pulls": {
                "attempts": pulls.attempts,
                "succeeded": pulls.succeeded,
                "failed": pulls.failed,
                "skipped_backoff": pulls.skipped_backoff,
                "in_backoff": pulls.in_backoff,
            },
            "reconcile": {
                "probes": rec.probes,
                "requests": rec.requests,
                "events_pushed": rec.events_pushed,
                "events_pulled": rec.events_pulled,
                "blobs_pulled": rec.blobs_pulled,
                "skipped_pressure": rec.skipped_pressure,
                "skipped_peer_full": rec.skipped_peer_full,
                "queue_overflow": rec.queue_overflow,
                "queued_ranges": rec.queued_ranges,
            },
            "heals": {
                "attempts": heals.attempts,
                "succeeded": heals.succeeded,
                "failed": heals.failed,
            },
        },
        "uptime_s": now - n.started_at,
        "version": env!("CARGO_PKG_VERSION"),
    });
    (StatusCode::OK, Json(body)).into_response()
}
