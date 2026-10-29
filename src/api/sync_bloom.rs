use axum::body::Body;
use axum::extract::Request;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use super::events::{read_body_capped, run};
use super::AppState;
use crate::error::{ApiError, ApiResult};
use crate::sync::bloom_api;

const BLOOM_BODY_CAP: usize = 9 * 1024 * 1024;

pub async fn bloom(State(n): State<AppState>, req: Request<Body>) -> Response {
    run(bloom_inner(n, req).await)
}

async fn bloom_inner(n: AppState, req: Request<Body>) -> ApiResult<Response> {
    let bytes = read_body_capped(req, BLOOM_BODY_CAP).await?;
    let now = crate::store::reaper::now();
    let out: Result<Value, String> = n
        .db
        .read(move |c: &rusqlite::Connection| bloom_api::handle(c, &bytes, now))
        .await;
    match out {
        Ok(body) => Ok(axum::Json(body).into_response()),
        Err(e) => Err(ApiError::bad_json(e)),
    }
}
