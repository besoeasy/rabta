use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::error::{ApiError, ApiResult};
use crate::store::blobs::{self, Abort, BlobSink, Install, Staged};
use super::events::run;
use super::AppState;

type Connection = rusqlite::Connection;

// ---------------------------------------------------------------------------
// PUT /blobs/<name>.blob|bin — raw orphan upload (the scripting door)
// ---------------------------------------------------------------------------

pub async fn put(State(n): State<AppState>, Path(name): Path<String>, req: Request<Body>) -> Response {
    run(put_inner(n, name, req).await)
}

async fn put_inner(n: AppState, name: String, req: Request<Body>) -> ApiResult<Response> {
    // Extension gate (decision #6) — filename comes from the URL path.
    if !(name.ends_with(".blob") || name.ends_with(".bin")) {
        return Err(ApiError::bad_extension());
    }

    // Early rejection when Content-Length already says "too big".
    if let Some(cl) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if cl > n.cfg.max_single_blob {
            return Err(ApiError::too_large("single blob exceeds 10% of STORAGE_MAX"));
        }
    }

    let (live_events, live_blobs) = n.db.read(|c: &Connection| crate::db::live_bytes(c)).await;
    let mut sink = BlobSink::start(
        &n.cfg.data_dir,
        live_events + live_blobs,
        n.cfg.watermark_bytes,
        n.cfg.max_single_blob,
    )?;

    let mut stream = req.into_body().into_data_stream();
    loop {
        match futures_util::StreamExt::next(&mut stream).await {
            Some(Ok(chunk)) => {
                if let Err(a) = sink.push(&chunk) {
                    sink.discard();
                    return match a {
                        Abort::TooLarge => Err(ApiError::too_large("single blob exceeds 10% of STORAGE_MAX")),
                        Abort::Watermark => Err(ApiError::at_watermark()),
                        Abort::Io(m) => Err(ApiError::internal(m)),
                    };
                }
            }
            Some(Err(_)) => {
                sink.discard();
                return Err(ApiError::bad_json("body stream error"));
            }
            None => break,
        }
    }
    if sink.written() == 0 {
        sink.discard();
        return Err(ApiError::bad_json("empty upload"));
    }
    let staged = sink.finish().map_err(|a| match a {
        Abort::Io(m) => ApiError::internal(m),
        _ => ApiError::internal("finalize failed"),
    })?;

    respond_stored(&n, staged).await
}

/// Common finalize for both blob doors: one accept-or-refuse transaction,
/// then materialize the file. Paths: public raw `PUT` + peer `POST /sync/blobs`.
pub async fn respond_stored(n: &AppState, staged: Staged) -> ApiResult<Response> {
    let hash_hex = staged.hash_hex.clone();
    let size = staged.size;

    let outcome = blobs::install_staged(&n.db, &n.cfg, staged)
        .await
        .map_err(|e| ApiError::internal(format!("blob row: {e}")))?;

    if outcome == Install::Refused {
        // No row was committed: answer the upload as refused and leave no file.
        return Err(ApiError::at_watermark());
    }

    let status = if outcome == Install::Fresh { StatusCode::CREATED } else { StatusCode::OK };
    let body = json!({
        "hash": hash_hex,
        "size": size,
        "url": format!("/blobs/{hash_hex}"),
    });
    Ok((status, Json(body)).into_response())
}
