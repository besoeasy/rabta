use axum::Json;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::AppState;
use super::events::run;
use super::routes;
use crate::error::{ApiError, ApiResult};
use crate::store::blobs::{self, BlobSink, Install, Staged};
use crate::store::ingest::quota_err;

// ---------------------------------------------------------------------------
// PUT /api/v1/blobs — raw blob upload. The server derives identity from the
// bytes; there is no filename, no extension gate, and no multipart path.
// ---------------------------------------------------------------------------

pub async fn put(State(n): State<AppState>, req: Request<Body>) -> Response {
    run(put_inner(n, req).await)
}

async fn put_inner(n: AppState, req: Request<Body>) -> ApiResult<Response> {
    if !n.cfg.blobs_enabled() {
        return Err(ApiError::blobs_disabled());
    }

    // Fail fast before receiving a large body into a read-only node.
    {
        let regen = n.cfg.battery_regen_per_sec;
        let state =
            n.db.write(move |c| {
                crate::sync::battery::refill_battery(
                    c,
                    crate::store::reaper::now(),
                    crate::sync::battery::SYNC_BATTERY_MAX,
                    regen,
                )
            })
            .await
            .map_err(|e| ApiError::internal(format!("battery refill: {e}")))?;
        if !state.local_admitted() {
            return Err(crate::store::ingest::quota_err(
                state.retry_after_to(crate::sync::battery::READONLY_FLOOR),
                "read-only",
            ));
        }
    }

    // Early rejection when Content-Length already says "too big".
    if let Some(cl) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        && cl > n.cfg.max_single_blob
    {
        return Err(ApiError::too_large("single blob exceeds 0.1% of STORAGE"));
    }

    let staged = stage_body(&n, req.into_body()).await?;
    respond_stored(&n, staged).await
}

/// Stream one raw body into a verified temp file. Shared by the upload door
/// and the blob reconciler.
pub(crate) async fn stage_body(n: &AppState, mut body: Body) -> ApiResult<Staged> {
    use axum::body::HttpBody;
    let mut sink = BlobSink::start(&n.uploads, &n.cfg.data_dir, n.cfg.max_single_blob).await?;

    loop {
        let next = tokio::time::timeout(
            blobs::UPLOAD_IDLE_TIMEOUT,
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)),
        )
        .await;
        match next {
            Err(_) => {
                sink.discard();
                return Err(ApiError::timeout());
            }
            Ok(Some(Ok(frame))) => {
                if let Ok(chunk) = frame.into_data()
                    && let Err(a) = sink.push(&chunk)
                {
                    sink.discard();
                    return Err(a.into());
                }
            }
            Ok(Some(Err(_))) => {
                sink.discard();
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "bad_body",
                    "request body stream failed",
                ));
            }
            Ok(None) => break,
        }
    }

    if sink.written() == 0 {
        sink.discard();
        return Err(ApiError::empty_body());
    }

    sink.finish().map_err(ApiError::from)
}

/// Finalize the public blob door: one accept-or-refuse transaction, then
/// materialize the file. A duplicate refreshes access metadata only; the
/// response always carries the blob's current deadline.
pub async fn respond_stored(n: &AppState, staged: Staged) -> ApiResult<Response> {
    let hash_hex = staged.hash_hex.clone();
    let hash = staged.hash;
    let size = staged.size;

    let outcome = blobs::install_staged(&n.db, &n.cfg, staged, crate::sync::battery::BLOB_COST)
        .await
        .map_err(|e| ApiError::internal(format!("blob row: {e}")))?;

    if let blobs::Install::Quota { retry_after } = outcome {
        return Err(quota_err(retry_after, "ingress"));
    }
    if outcome == blobs::Install::NotEncrypted {
        return Err(ApiError::blob_not_encrypted());
    }
    if outcome == Install::Refused {
        return Err(ApiError::at_watermark());
    }

    let expires_at: i64 =
        n.db.read(move |c: &rusqlite::Connection| {
            c.query_row(
                "SELECT expires_at FROM blobs WHERE hash = ?1",
                [&hash[..]],
                |r| r.get(0),
            )
            .unwrap_or(0)
        })
        .await;

    let status = if outcome == Install::Fresh {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let body = json!({
        "hash": hash_hex,
        "size": size,
        "url": routes::blob_url(&hash_hex),
        "expires_at": expires_at,
    });
    let mut resp = (status, Json(body)).into_response();
    if status == StatusCode::CREATED
        && let Ok(loc) = header::HeaderValue::from_str(&routes::blob_url(&hash_hex))
    {
        resp.headers_mut().insert(header::LOCATION, loc);
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rabta-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An empty upload is refused before staging. A 0-byte blob would be a
    /// meaningless row and would break the unclaimed trim invariant that
    /// every real upload occupies one row.
    #[tokio::test]
    async fn empty_upload_body_is_refused() {
        let dir = temp_dir("blob-api-empty-body");
        crate::store::blobs::init_dirs(&dir).unwrap();
        let cfg = crate::config::Config::test_cfg(dir.clone(), 1_000_000);
        let identity = crate::identity::NodeIdentity::generate();
        let n = crate::api::Node::new(cfg, crate::db::Db::open(&dir), identity);

        let err = stage_body(&n, Body::empty()).await.unwrap_err();
        assert_eq!(err.code, "empty_body");

        drop(n);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
