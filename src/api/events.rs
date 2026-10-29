use std::sync::atomic::Ordering;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use super::{AppState, SSE_ACTIVE};
use crate::error::{ApiError, ApiResult};
use crate::store::events::{self, ListFilters, ListedRow};
use crate::store::queries;
use crate::store::reaper;

type Connection = rusqlite::Connection;

const MAX_ENVELOPE: usize = crate::db::MAX_ENVELOPE;

// ---------------------------------------------------------------------------
// POST /events — publish (application/json only; attachments arrive via PUT /blobs)
// ---------------------------------------------------------------------------

pub async fn publish(State(n): State<AppState>, req: Request<Body>) -> Response {
    // The one event door: envelope JSON only. Attachment bytes arrive through
    // the blob door (`PUT /blobs/<name>.blob|bin`) — before or after this call;
    // the envelope's `blob` hash is the join point (content addressing).
    let bytes = match read_body_capped(req, MAX_ENVELOPE).await {
        Ok(b) => b.to_vec(),
        Err(e) => return e.into_response(),
    };
    run(publish_envelope(n, bytes).await)
}

pub fn run<T: IntoResponse>(r: ApiResult<T>) -> Response {
    match r {
        Ok(x) => x.into_response(),
        Err(e) => e.into_response(),
    }
}

/// Read the whole body with a hard cap; oversize answers with the contract's
/// JSON error (`too_large`), not the default plaintext 413.
pub async fn read_body_capped(req: Request<Body>, cap: usize) -> ApiResult<axum::body::Bytes> {
    match axum::body::to_bytes(req.into_body(), cap).await {
        Ok(b) => Ok(b),
        Err(_) => Err(ApiError::too_large("request body exceeds the cap")),
    }
}

/// Core publish: validate → one atomic insert. An envelope may carry a `blob`
/// hash whose bytes are not here yet (or already are, via the blob door) —
/// the refs junction is written either way, so when the bytes arrive by that
/// hash they are born attached to this event.
pub async fn publish_envelope(n: AppState, bytes: Vec<u8>) -> ApiResult<Response> {
    let now = reaper::now();
    let ev = events::parse_and_verify(&bytes, now)?;
    let inserted = insert_event_with_blob(&n, &ev).await?;

    // Origin fan-out (decision #16): accepted events push to every trusted
    // peer immediately; inbound sync ingest never re-fans.
    if inserted {
        crate::sync::loop_all::push_event_to_peers(&n, ev.served_bytes.clone());
    }

    let mut body = json!({
        "status": if inserted { "stored" } else { "duplicate" },
        "id": ev.id_hex,
    });
    if let Some(b) = &ev.blob_hex {
        body["blob"] = json!(b);
        body["blob_url"] = json!(format!("/blobs/{b}"));
    }
    let status = if inserted { StatusCode::CREATED } else { StatusCode::OK };
    Ok((status, Json(body)).into_response())
}

/// One transaction: pressure check → event row → refs junction.
/// The refs junction writes for ANY envelope carrying a `blob` hash — bytes
/// may already exist, arrive later by the same hash, or never (honest gap:
/// reads of that hash 404 until a peer serves them).
async fn insert_event_with_blob(n: &AppState, ev: &events::ParsedEvent) -> ApiResult<bool> {
    let cfg = n.cfg.clone();
    let ev2 = ev.clone();

    let out: ApiResult<bool> = n
        .db
        .write(move |c: &rusqlite::Connection| -> ApiResult<bool> {
            reaper::pressure_check(c, &cfg, ev2.size as u64)?;
            let inserted = events::insert_event(c, &ev2)
                .map_err(|e| ApiError::internal(format!("event insert: {e}")))?;
            if inserted {
                if let Some(hash) = &ev2.blob {
                    crate::store::blobs::attach_ref(c, &ev2.id, hash)
                        .map_err(|e| ApiError::internal(format!("refs insert: {e}")))?;
                }
            }
            Ok(inserted)
        })
        .await;
    out
}

// ---------------------------------------------------------------------------
// GET /events — list with filters + opaque cursor
// ---------------------------------------------------------------------------

/// Parsed `GET /events` query. `label` may repeat (AND semantics), so the
/// query string is parsed manually — serde_urlencoded collapses duplicates.
#[derive(Debug, Default, Clone)]
pub struct RawQ {
    pub collection: Option<String>,
    pub labels: Vec<String>,
    pub owner: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

pub fn parse_raw_query(q: Option<&str>) -> RawQ {
    let mut out = RawQ::default();
    let Some(q) = q else { return out };
    for part in q.split('&') {
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (k, v),
            None => (part, ""),
        };
        let val = urldecode(v);
        match k {
            "collection" => out.collection = Some(val),
            "label" => out.labels.push(val),
            "owner" => out.owner = Some(val),
            "limit" => out.limit = val.parse::<u32>().ok(),
            "cursor" => out.cursor = Some(val),
            _ => {}
        }
    }
    out
}

/// Percent-decode (+→space); lone `%` passes through literally.
fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let h = |c: u8| -> Option<u8> { (c as char).to_digit(16).map(|d| d as u8) };
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(hi), Some(lo)) = (h(b[i + 1]), h(b[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        if b[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(b[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub async fn list(State(n): State<AppState>, uri: axum::http::Uri) -> Response {
    run(list_inner(n, parse_raw_query(uri.query())).await)
}

/// `owner` filter takes the canonical `ed25519:<64hex>` form (same as the
/// envelope), normalized lowercase. No bare-hex shorthand.
fn normalize_owner(s: &str) -> Option<String> {
    let hexed = s.strip_prefix("ed25519:")?.to_ascii_lowercase();
    if hexed.len() == 64 && hexed.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(hexed)
    } else {
        None
    }
}

async fn list_inner(n: AppState, p: RawQ) -> ApiResult<Response> {
    let now = reaper::now();
    let filters = ListFilters {
        collection: p.collection.clone(),
        labels: p.labels,
        owner_hex: owner_filter_for(&p.owner),
        limit: p.limit.unwrap_or(20).clamp(1, 100),
    };
    let cursor = match &p.cursor {
        Some(c) => match events::decode_cursor(c) {
            Some(x) => Some(x),
            None => return Err(ApiError::bad_json("invalid cursor")),
        },
        None => None,
    };

    let (pred, mut binds) = events::build_predicate(&filters, now);
    let sql = events::list_sql(pred, &mut binds, cursor, filters.limit);
    let rows: Vec<ListedRow> = n
        .db
        .read(move |c: &Connection| events::run_list(c, &sql, &binds))
        .await
        .map_err(ApiError::from)?;

    let mut items = Vec::with_capacity(rows.len());
    for r in &rows {
        let v: serde_json::Value = serde_json::from_slice(&r.served)
            .map_err(|e| ApiError::internal(format!("stored envelope corrupt: {e}")))?;
        items.push(v);
    }
    let next_cursor = if rows.len() == filters.limit as usize {
        rows.last().map(|r| events::encode_cursor(r.created_at, &r.id))
    } else {
        None
    };
    let body = json!({ "count": items.len(), "events": items, "next_cursor": next_cursor });
    Ok(Json(body).into_response())
}

fn owner_filter_for(s: &Option<String>) -> Option<String> {
    s.as_deref().and_then(normalize_owner)
}

// ---------------------------------------------------------------------------
// GET /events/{id} + GET /events/{id}/size
// ---------------------------------------------------------------------------

pub fn parse_id_hex(s: &str) -> ApiResult<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::not_found("not a valid event id"));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&hex::decode(s).expect("checked"));
    Ok(id)
}

fn if_none_match_ok(headers: &HeaderMap, etag: &str) -> bool {
    let Some(im) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let wanted = format!("\"{etag}\"");
    im.split(',').any(|p| p.trim() == "*" || p.trim() == wanted || p.trim() == etag)
}

fn etag_headers(id_hex: &str) -> (header::HeaderValue, header::HeaderValue) {
    (
        header::HeaderValue::from_str(&format!("\"{id_hex}\"")).unwrap(),
        header::HeaderValue::from_static("application/json"),
    )
}

pub async fn get_one(State(n): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    run(get_one_inner(n, headers, id).await)
}

async fn get_one_inner(n: AppState, headers: HeaderMap, id: String) -> ApiResult<Response> {
    let idb = parse_id_hex(&id)?;
    let now = reaper::now();
    let row: Option<queries::EventRow> = n.db.read(move |c: &Connection| queries::get_event(c, &idb)).await;
    let Some(row) = row else { return Err(ApiError::not_found("no such event")) };
    if row.expires_at <= now {
        return Err(ApiError::not_found("event expired"));
    }
    if if_none_match_ok(&headers, &row.id_hex) {
        let (etag, _ct) = etag_headers(&row.id_hex);
        let mut resp = StatusCode::NOT_MODIFIED.into_response();
        resp.headers_mut().insert(header::ETAG, etag);
        return Ok(resp);
    }
    let (etag, ct) = etag_headers(&row.id_hex);
    let mut resp = axum::http::Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, etag)
        .header(header::CONTENT_TYPE, ct)
        .body(Body::from(row.served))
        .unwrap();
    resp.headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    Ok(resp)
}

pub async fn size(State(n): State<AppState>, Path(id): Path<String>) -> Response {
    run(size_inner(n, id).await)
}

async fn size_inner(n: AppState, id: String) -> ApiResult<Response> {
    let idb = parse_id_hex(&id)?;
    let now = reaper::now();
    let packet: (Option<queries::EventRow>, Vec<queries::AttachmentSize>) = n
        .db
        .read(move |c: &Connection| {
            let row = queries::get_event(c, &idb);
            let att = queries::event_attachments(c, &idb);
            (row, att)
        })
        .await;
    let (row, att) = packet;
    let Some(row) = row else { return Err(ApiError::not_found("no such event")) };
    if row.expires_at <= now {
        return Err(ApiError::not_found("event expired"));
    }
    let mut attachments = Vec::with_capacity(att.len());
    let mut total = row.size;
    for a in att {
        if let Some(s) = a.size {
            total += s;
            attachments.push(json!({"hash": a.hash_hex, "size": s}));
        } else {
            attachments.push(json!({"hash": a.hash_hex, "size": null}));
        }
    }
    let body = json!({
        "id": row.id_hex,
        "envelope_size": row.size,
        "attachments": attachments,
        "total_size": total,
    });
    Ok(Json(body).into_response())
}

// ---------------------------------------------------------------------------
// GET /events/stream — SSE with Last-Event-ID resume + 15s keepalives
// ---------------------------------------------------------------------------

pub async fn stream(State(n): State<AppState>, headers: HeaderMap, uri: axum::http::Uri) -> Response {
    run(stream_inner(n, headers, parse_raw_query(uri.query())).await)
}

struct SseGuard;
impl Drop for SseGuard {
    fn drop(&mut self) {
        SSE_ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn stream_inner(n: AppState, headers: HeaderMap, p: RawQ) -> ApiResult<Response> {
    let cap = n.cfg.sse_subscriber_cap as i64;
    if SSE_ACTIVE.load(Ordering::Relaxed) >= cap {
        return Err(ApiError::subscriber_cap());
    }

    let filters = ListFilters {
        collection: p.collection.clone(),
        labels: p.labels,
        owner_hex: owner_filter_for(&p.owner),
        limit: 100,
    };
    let last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok());

    // resume point: after the given rowid, else the newest row (future tail)
    let start: i64 = match last_event_id {
        Some(x) => x,
        None => {
            n.db
                .read(|c: &Connection| {
                    c.query_row("SELECT COALESCE(MAX(rowid),0) FROM events", [], |r| r.get(0))
                        .unwrap_or(0)
                })
                .await
        }
    };

    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    let (tx, rx) = mpsc::channel::<Result<axum::body::Bytes, axum::Error>>(32);
    let db = n.db.clone();

    tokio::spawn(async move {
        // subscriber accounting lives with the connection, not the response
        SSE_ACTIVE.fetch_add(1, Ordering::Relaxed);
        let _guard = SseGuard;

        let mut next_rowid = start;
        let mut last_keepalive = std::time::Instant::now();
        tracing::debug!(sse_start = next_rowid, "sse worker polling");
        loop {
            // rebuild the predicate each poll (clock moves; binds aren't clonable).
            // run_list wraps the bare predicate into the full SELECT itself.
            let (pred, mut binds) = events::build_predicate(&filters, reaper::now());
            let r_at = events::next_bind(&mut binds, events::SqlParam::I(next_rowid));
            let l_at = events::next_bind(&mut binds, events::SqlParam::I(100));
            let sql = format!("{pred} AND rowid > {r_at} ORDER BY rowid ASC LIMIT {l_at}");
            let batch = db.read(move |c: &Connection| events::run_list(c, &sql, &binds)).await;
            if let Err(e) = &batch {
                tracing::debug!(error = format!("{e}"), "sse poll error");
            }
            match batch {
                Ok(batch) => {
                    next_rowid = batch.last().map(|r| r.rowid).unwrap_or(next_rowid);
                    for r in &batch {
                        let frame = format!(
                            "id: {}\nevent: message\ndata: {}\n\n",
                            r.rowid,
                            String::from_utf8_lossy(&r.served)
                        );
                        if tx.send(Ok(axum::body::Bytes::from(frame))).await.is_err() {
                            return; // client went away
                        }
                    }
                }
                Err(_) => break,
            }

            if last_keepalive.elapsed() >= std::time::Duration::from_secs(15) {
                if tx.send(Ok(axum::body::Bytes::from(": keepalive\n\n"))).await.is_err() {
                    return;
                }
                last_keepalive = std::time::Instant::now();
            }
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            if tx.is_closed() {
                return;
            }
        }
    });

    Ok(axum::http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(ReceiverStream::new(rx)))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let dir = std::env::temp_dir().join(format!("rabta-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn publish_returns_json_content_type() {
        let dir = temp_dir("event-content-type");
        let db = crate::db::Db::open(&dir);
        let cfg = crate::config::Config {
            port: 0,
            data_dir: dir.clone(),
            storage_max: 10_000_000,
            storage_clamped: false,
            storage_max_configured: 10_000_000,
            max_single_blob: 1_000_000,
            watermark_bytes: 9_000_000,
            eviction_target_bytes: 8_500_000,
            sse_subscriber_cap: 1,
            sync_nodes: Vec::new(),
            sync_interval: Duration::from_secs(60),
        };
        let n: AppState = Arc::new(crate::api::Node {
            cfg,
            db,
            http: reqwest::Client::new(),
            started_at: reaper::now(),
        });

        let now = reaper::now();
        let created_at = now - 10;
        let expires_at = now + 3600;
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let owner = format!("ed25519:{}", hex::encode(key.verifying_key().to_bytes()));
        let data = json!({"message": "hello"});
        let canonical = crate::canon::digest_value(
            "test",
            created_at,
            expires_at,
            &owner,
            &[],
            &data,
            None,
        );
        let digest: [u8; 32] =
            Sha256::digest(crate::canon::canonical_value(&canonical)).into();
        let sig = key.sign(&digest);
        let envelope = json!({
            "collection": "test",
            "created_at": created_at,
            "data": data,
            "expires_at": expires_at,
            "labels": [],
            "owner": owner,
            "id": hex::encode(digest),
            "sig": hex::encode(sig.to_bytes()),
        });

        let resp = publish_envelope(n, serde_json::to_vec(&envelope).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
