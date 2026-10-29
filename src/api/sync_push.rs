use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::blobs_api;
use super::events::run;
use super::AppState;
use crate::error::{ApiError, ApiResult};
use crate::store::blobs::{Abort, BlobSink, Staged};

/// POST /sync/blobs — push one blob body as raw bytes. The sync plane is
/// exempt from the public door's `.blob`/`.bin` filename gate (it has no
/// filename); content addressing and every storage cap still apply.
pub async fn post_blobs(State(n): State<AppState>, req: Request<Body>) -> Response {
    run(post_blobs_inner(n, req).await)
}

async fn post_blobs_inner(n: AppState, req: Request<Body>) -> ApiResult<Response> {
    let staged = stream_body(&n, req).await?;
    let hash_hex = staged.hash_hex.clone();
    let mut result = json!({"hash": hash_hex});
    match blobs_api::respond_stored(&n, staged).await {
        Ok(resp) => {
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
                .await
                .unwrap_or_default();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            result["status"] = json!(if status == StatusCode::CREATED { "stored" } else { "duplicate" });
            if let (Some(a), Some(b)) = (result.as_object_mut(), v.as_object()) {
                for (k, val) in b {
                    a.insert(k.clone(), val.clone());
                }
            }
        }
        Err(e) => {
            result["status"] = json!("refused");
            result["code"] = json!(e.code);
        }
    }
    Ok((StatusCode::OK, axum::Json(json!({"blobs": [result]}))).into_response())
}

/// Stream a raw body through the sink.
async fn stream_body(n: &AppState, req: Request<Body>) -> ApiResult<Staged> {
    let (live_events, live_blobs) = n.db.read(|c: &rusqlite::Connection| crate::db::live_bytes(c)).await;
    let mut sink = BlobSink::start(&n.cfg.data_dir, live_events + live_blobs, n.cfg.watermark_bytes, n.cfg.max_single_blob)?;
    let mut stream = req.into_body().into_data_stream();
    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ApiError::bad_json("body stream error"))?;
        if let Err(a) = sink.push(&chunk) {
            sink.discard();
            return Err(match a {
                Abort::TooLarge => ApiError::too_large("single blob exceeds 10% of STORAGE_MAX"),
                Abort::Watermark => ApiError::at_watermark(),
                Abort::Io(m) => ApiError::internal(m),
            });
        }
    }
    sink.finish().map_err(|a| ApiError::internal(match a {
        Abort::Io(m) => m,
        _ => "finalize failed".to_string(),
    }))
}
