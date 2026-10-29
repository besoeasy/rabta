use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use super::events::{read_body_capped, run};
use super::AppState;
use crate::error::{ApiError, ApiResult};
use crate::sync::ranges;

/// 128 ranges × (64 leaf ids × 66 bytes) stays well below this cap.
const RECONCILE_BODY_CAP: usize = 2 * 1024 * 1024;

// POST /sync/reconcile — exact Merkle range exchange (protocol v1).
pub async fn reconcile(State(n): State<AppState>, req: Request<Body>) -> Response {
    run(reconcile_inner(n, req).await)
}

async fn reconcile_inner(n: AppState, req: Request<Body>) -> ApiResult<Response> {
    let bytes = read_body_capped(req, RECONCILE_BODY_CAP).await?;
    let now = crate::store::reaper::now();
    let (ev, bl) = n.db.read(|c: &rusqlite::Connection| crate::db::live_bytes(c)).await;
    let accepting = (ev + bl).max(0) as u64 <= n.cfg.watermark_bytes;

    let out: Result<Value, String> = n
        .db
        .read(move |c: &rusqlite::Connection| ranges::handle(c, &bytes, now))
        .await;
    match out {
        Ok(mut body) => {
            // The caller uses this to stop pushing/pulling at a full node.
            body["accepting"] = json!(accepting);
            Ok(axum::Json(body).into_response())
        }
        Err(e) => Err(ApiError::bad_json(e)),
    }
}
