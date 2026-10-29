use axum::body::Body;
use axum::extract::Request;
use axum::extract::{State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use super::events::{read_body_capped, run};
use super::AppState;
use crate::error::{ApiError, ApiResult};
use crate::store::events;
use crate::store::reaper;

type Conn = rusqlite::Connection;

const BATCH_BODY_CAP: usize = 32 * 1024 * 1024;
const BATCH_ITEM_CAP: usize = 1000;

// POST /sync/events — batch push of envelopes, normal validation.
pub async fn post_events(State(n): State<AppState>, req: Request<Body>) -> Response {
    run(post_events_inner(n, req).await)
}

async fn post_events_inner(n: AppState, req: Request<Body>) -> ApiResult<Response> {
    let bytes = read_body_capped(req, BATCH_BODY_CAP).await?;
    let arr: Vec<Value> = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::bad_json(format!("batch must be a JSON array: {e}")))?;
    if arr.len() > BATCH_ITEM_CAP {
        return Err(ApiError::too_large("batch exceeds 1000 events"));
    }

    let now = reaper::now();
    let mut stored = 0usize;
    let mut rejected = 0usize;
    let mut pushed: Vec<Vec<u8>> = Vec::new();

    for item in arr {
        let raw = match serde_json::to_vec(&item) {
            Ok(v) => v,
            Err(_) => {
                rejected += 1;
                continue;
            }
        };
        match events::parse_and_verify(&raw, now) {
            Ok(ev) => {
                match store_envelope(&n, raw).await {
                    Ok(true) => {
                        stored += 1;
                        pushed.push(ev.served_bytes.clone());
                    }
                    _ => rejected += 1,
                }
            }
            Err(_) => rejected += 1,
        }
    }

    // Inbound sync events are NOT re-fanned to other peers; the origin node
    // does the fan-out on its publish path (decision #16).
    let _ = pushed;

    Ok((
        StatusCode::OK,
        axum::Json(json!({"stored": stored, "rejected": rejected})),
    )
        .into_response())
}

/// Store one envelope (sync-plane ingest + client-loop pulls share this):
/// verify → insert in one transaction (refs row for a referenced blob so the
/// bytes ride parenthood when they arrive). Returns Ok(true) when a new row
/// was written. No re-fan-out here.
pub async fn store_envelope(n: &AppState, bytes: Vec<u8>) -> ApiResult<bool> {
    let now = reaper::now();
    let ev = events::parse_and_verify(&bytes, now)?;
    let ev2 = ev.clone();
    let out: ApiResult<bool> = n
        .db
        .write(move |c: &Conn| -> ApiResult<bool> {
            let ins = events::insert_event(c, &ev2)
                .map_err(|e| ApiError::internal(format!("insert: {e}")))?;
            if ins {
                if let Some(b) = ev2.blob {
                    crate::store::blobs::attach_ref(c, &ev2.id, &b)
                        .map_err(|e| ApiError::internal(format!("refs: {e}")))?;
                }
            }
            Ok(ins)
        })
        .await;
    if matches!(out, Ok(true)) {
        // Wake SSE only after the write transaction has committed.
        n.db.notify_event_row();
    }
    out
}
