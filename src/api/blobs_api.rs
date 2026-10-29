use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::error::{ApiError, ApiResult};
use crate::store::blobs::{self, Abort, BlobInsertResult, BlobSink, Staged};
use crate::store::reaper;
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
            Some(Err(_)) => return Err(ApiError::bad_json("body stream error")),
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
    let cfg = n.cfg.clone();
    let hash = staged.hash;
    let size = staged.size;
    let now = reaper::now();
    let dir = cfg.data_dir.clone();

    let fresh: bool = n
        .db
        .write(move |c: &Connection| -> ApiResult<bool> {
            let (ev, _bl) = crate::db::live_bytes(c);
            if (ev + size as i64) as u64 > cfg.watermark_bytes {
                // evict once for the remaining head-room, then refuse if still full
                reaper::evict_pass(c, &cfg);
                let (ev2, _bl2) = crate::db::live_bytes(c);
                if (ev2 + size as i64) as u64 > cfg.watermark_bytes {
                    return Err(ApiError::at_watermark());
                }
            }
            let insert = blobs::insert_blob_row(c, &hash, size, now, cfg.watermark_bytes)
                .map_err(|e| ApiError::internal(format!("blob row: {e}")))?;
            // mark ever_attached when live referrers already exist (bytes ride parenthood)
            if insert != BlobInsertResult::WatermarkFull {
                c.execute(
                    "UPDATE blobs SET ever_attached=1 WHERE hash=?1 AND EXISTS(SELECT 1 FROM refs WHERE blob_hash=?1)",
                    [&hash],
                )
                .map_err(ApiError::from)?;
            }
            Ok(insert == BlobInsertResult::Inserted)
        })
        .await?;

    if let Err(e) = blobs::materialize(&dir, &staged) {
        tracing::error!("materialize {}: {e}", staged.hash_hex);
    }

    let status = if fresh { StatusCode::CREATED } else { StatusCode::OK };
    let body = json!({
        "hash": staged.hash_hex,
        "size": staged.size,
        "url": format!("/blobs/{}", staged.hash_hex),
    });
    Ok((status, Json(body)).into_response())
}
