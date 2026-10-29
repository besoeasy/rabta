use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use super::events::{parse_id_hex, read_body_capped, run};
use super::AppState;
use crate::error::{ApiError, ApiResult};
use crate::store::blobs;
use crate::store::queries;
use crate::store::reaper;

type Conn = rusqlite::Connection;

const FETCH_BODY_CAP: usize = 256 * 1024;
const FETCH_ID_CAP: usize = 1000;

#[derive(Deserialize)]
pub struct FetchRequest {
    ids: Vec<String>,
}

// POST /sync/events/fetch — batch envelope read by exact id (≤1000).
pub async fn fetch_events(State(n): State<AppState>, req: Request<Body>) -> Response {
    run(fetch_events_inner(n, req).await)
}

async fn fetch_events_inner(n: AppState, req: Request<Body>) -> ApiResult<Response> {
    let bytes = read_body_capped(req, FETCH_BODY_CAP).await?;
    let body: FetchRequest = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::bad_json(format!("fetch body must be {{\"ids\":[...]}}: {e}")))?;
    if body.ids.len() > FETCH_ID_CAP {
        return Err(ApiError::too_large("fetch exceeds 1000 ids"));
    }

    let mut ids = Vec::with_capacity(body.ids.len());
    for id in &body.ids {
        ids.push(parse_id_hex(id)?);
    }

    let now = reaper::now();
    let (events, missing): (Vec<Value>, Vec<String>) = n
        .db
        .read(move |c: &Conn| {
            let mut stmt = c
                .prepare("SELECT data FROM events WHERE id = ?1 AND state='live' AND expires_at > ?2")
                .expect("static query");
            let mut events = Vec::new();
            let mut missing = Vec::new();
            for id in ids {
                match stmt.query_row(rusqlite::params![&id[..], now], |r| r.get::<_, Vec<u8>>(0)) {
                    Ok(data) => match serde_json::from_slice::<Value>(&data) {
                        Ok(v) => events.push(v),
                        Err(_) => missing.push(hex::encode(id)),
                    },
                    Err(_) => missing.push(hex::encode(id)),
                }
            }
            (events, missing)
        })
        .await;

    Ok((
        StatusCode::OK,
        axum::Json(json!({"events": events, "missing": missing})),
    )
        .into_response())
}

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

// GET /sync/events?cursor=&limit= — fresh-join/catch-up pull (seq-ordered).
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
                .prepare("SELECT seq, id, created_at, data FROM events WHERE state='live' AND seq > ?1 ORDER BY seq ASC LIMIT ?2")
                .unwrap();
            let mut rows = stmt.query([cursor, limit as i64]).unwrap();
            let mut out = Vec::new();
            while let Some(r) = rows.next().unwrap() {
                let id_raw: Vec<u8> = r.get(1).unwrap();
                let mut id = [0u8; 32];
                id.copy_from_slice(&id_raw);
                let _ = &id;
                out.push(crate::store::events::ListedRow {
                    seq: r.get(0).unwrap(),
                    id,
                    created_at: r.get(2).unwrap(),
                    served: r.get(3).unwrap(),
                });
            }
            out
        })
        .await;

    let next_cursor = if rows.len() == limit as usize { rows.last().map(|r| r.seq) } else { None };
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

async fn blob_size(n: &AppState, hash: [u8; 32]) -> Option<i64> {
    n.db.read(move |c: &Conn| {
        c.query_row(
            "SELECT size FROM blobs WHERE hash = ?1 AND state='live'",
            [&hash],
            |r| r.get(0),
        )
        .ok()
    })
    .await
}

/// One in-flight heal per hash per process: a missing blob asked for by a
/// peer must not recursively fan out through the mesh.
fn healing_set() -> &'static Mutex<HashSet<[u8; 32]>> {
    static HEALING: OnceLock<Mutex<HashSet<[u8; 32]>>> = OnceLock::new();
    HEALING.get_or_init(|| Mutex::new(HashSet::new()))
}

struct HealGuard([u8; 32]);
impl Drop for HealGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = healing_set().lock() {
            set.remove(&self.0);
        }
    }
}

fn begin_heal(hash: &[u8; 32]) -> Option<HealGuard> {
    let mut set = healing_set().lock().ok()?;
    if set.insert(*hash) { Some(HealGuard(*hash)) } else { None }
}

async fn get_blob_inner(n: AppState, hash_hex: String) -> ApiResult<Response> {
    if hash_hex.len() != 64 || !hash_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::not_found("not a valid blob hash"));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hex::decode(&hash_hex).expect("checked"));

    let resolved_hex = hex::encode(hash);
    let path = blobs::blob_path(&n.cfg.data_dir, &resolved_hex);
    let mut size = blob_size(&n, hash).await;
    let mut opened = if size.is_some() {
        Some(tokio::fs::File::open(&path).await)
    } else {
        None
    };

    // Row without bytes (or no row at all): repair from a trusted peer, then
    // serve the request instead of handing the caller a false 404.
    let missing_file =
        matches!(&opened, Some(Err(e)) if e.kind() == std::io::ErrorKind::NotFound);
    if (size.is_none() || missing_file) && !n.cfg.sync_nodes.is_empty() {
        if let Some(_healing) = begin_heal(&hash) {
            if crate::sync::loop_all::fetch_blob_from_peers(&n, &resolved_hex).await {
                size = blob_size(&n, hash).await;
                opened = Some(tokio::fs::File::open(&path).await);
            }
        }
    }

    let Some(size) = size else { return Err(ApiError::not_found("no such blob")) };
    let file = match opened {
        Some(Ok(f)) => f,
        _ => return Err(ApiError::not_found("no such blob")),
    };
    Ok(axum::http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CONTENT_LENGTH, size.to_string())
        .body(Body::from_stream(tokio_util::io::ReaderStream::new(file)))
        .expect("static response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_healing_is_single_flight() {
        let hash = [3u8; 32];
        let guard = begin_heal(&hash).expect("first heal should start");
        assert!(begin_heal(&hash).is_none(), "recursive heal was allowed");
        drop(guard);
        assert!(begin_heal(&hash).is_some(), "heal guard did not release");
    }
}
