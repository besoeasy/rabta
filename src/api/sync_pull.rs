use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use super::events::{parse_id_hex, run};
use super::AppState;
use crate::error::{ApiError, ApiResult};
use crate::store::blobs;
use crate::store::queries;
use crate::store::reaper;

type Conn = rusqlite::Connection;

// GET /sync/events/{id} — one envelope (sync-plane read)
pub async fn get_event(State(n): State<AppState>, Path(id): Path<String>) -> Response {
    run(get_event_inner(n, id).await)
}

async fn get_event_inner(n: AppState, id: String) -> ApiResult<Response> {
    let idb = parse_id_hex(&id)?;
    let now = reaper::now();
    let row = n.db.read(move |c: &Conn| queries::get_event(c, &idb)).await;
    let Some(row) = row else { return Err(ApiError::not_found("no such event")) };
    if row.expires_at <= now {
        return Err(ApiError::not_found("event expired"));
    }
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        row.served,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct PullParams {
    cursor: Option<i64>,
    limit: Option<u32>,
}

// GET /sync/events?cursor=&limit= — fresh-join/catch-up pull (rowid-ordered).
pub async fn pull_events(State(n): State<AppState>, Query(p): Query<PullParams>) -> Response {
    run(pull_inner(n, p).await)
}

async fn pull_inner(n: AppState, p: PullParams) -> ApiResult<Response> {
    let cursor = p.cursor.unwrap_or(0);
    let limit = p.limit.unwrap_or(1000).clamp(1, 1000);
    let rows: Vec<crate::store::events::ListedRow> = n
        .db
        .read(move |c: &Conn| {
            let mut stmt = c
                .prepare("SELECT rowid, id, created_at, data FROM events WHERE state='live' AND rowid > ?1 ORDER BY rowid ASC LIMIT ?2")
                .unwrap();
            let mut rows = stmt.query([cursor, limit as i64]).unwrap();
            let mut out = Vec::new();
            while let Some(r) = rows.next().unwrap() {
                let id_raw: Vec<u8> = r.get(1).unwrap();
                let mut id = [0u8; 32];
                id.copy_from_slice(&id_raw);
                let _ = &id;
                out.push(crate::store::events::ListedRow {
                    rowid: r.get(0).unwrap(),
                    id,
                    created_at: r.get(2).unwrap(),
                    served: r.get(3).unwrap(),
                });
            }
            out
        })
        .await;

    let next_cursor = if rows.len() == limit as usize { rows.last().map(|r| r.rowid) } else { None };
    let items: Vec<serde_json::Value> = rows
        .iter()
        .filter_map(|r| serde_json::from_slice(&r.served).ok())
        .collect();
    Ok((
        StatusCode::OK,
        axum::Json(json!({"count": items.len(), "events": items, "next_cursor": next_cursor})),
    )
        .into_response())
}

// GET /sync/blobs/{hash} — one body (sync-plane read)
pub async fn get_blob(State(n): State<AppState>, Path(hash_hex): Path<String>) -> Response {
    run(get_blob_inner(n, hash_hex).await)
}

async fn get_blob_inner(n: AppState, hash_hex: String) -> ApiResult<Response> {
    if hash_hex.len() != 64 || !hash_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::not_found("not a valid blob hash"));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hex::decode(&hash_hex).expect("checked"));
    let size: i64 = n
        .db
        .read(move |c: &Conn| {
            c.query_row(
                "SELECT size FROM blobs WHERE hash = ?1 AND state='live'",
                [&hash],
                |r| r.get(0),
            )
            .ok()
        })
        .await
        .ok_or_else(|| ApiError::not_found("no such blob"))?;

    let path = blobs::blob_path(&n.cfg.data_dir, &hex::encode(hash));
    let file = tokio::fs::File::open(&path).await.map_err(|_| ApiError::not_found("no such blob"))?;
    Ok(axum::http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CONTENT_LENGTH, size.to_string())
        .body(Body::from_stream(tokio_util::io::ReaderStream::new(file)))
        .expect("static response"))
}
