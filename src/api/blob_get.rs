use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::AppState;
use super::events::run;
use crate::error::{ApiError, ApiResult};
use crate::store::blobs;

type Connection = rusqlite::Connection;

fn parse_hash(s: &str) -> ApiResult<[u8; 32]> {
    if s.len() != 64 {
        return Err(ApiError::not_found("not a valid blob hash"));
    }
    let mut h = [0u8; 32];
    if hex::decode_to_slice(s, &mut h).is_err() {
        return Err(ApiError::not_found("not a valid blob hash"));
    }
    Ok(h)
}

const BLOB_CACHE_CONTROL: &str = "public, max-age=3600";

async fn get_row(n: &AppState, hash: &[u8; 32], now: i64) -> ApiResult<Option<(i64, i64)>> {
    let h = *hash;
    let row =
        n.db.read(move |c: &Connection| {
            c.query_row(
                "SELECT size, last_access_at FROM blobs
                 WHERE hash = ?1 AND expires_at > ?2",
                rusqlite::params![&h, now],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            )
            .ok()
        })
        .await;
    Ok(row)
}

/// `bytes=from-to` single-range parser; malformed or unsatisfiable → None.
fn range_parse(rng: &str, size: u64) -> Option<(u64, u64)> {
    let rest = rng.trim().strip_prefix("bytes=")?;
    let (a, b) = rest.split_once('-')?;
    let from: u64 = a.trim().parse().ok()?;
    if from >= size {
        return None;
    }
    let to: u64 = if b.trim().is_empty() {
        size - 1
    } else {
        b.trim().parse().ok()?
    };
    let to = to.min(size - 1);
    if from > to {
        return None;
    }
    Some((from, to))
}

fn etag_matches(im: &str, etag: &str) -> bool {
    let quoted = format!("\"{etag}\"");
    im.split(',')
        .any(|p| p.trim() == "*" || p.trim() == quoted || p.trim() == etag)
}

/// Access tracking from a successful read. Reads never extend a deadline, so a
/// hot blob costs at most one writer transaction per `BLOB_REFRESH_SECONDS`.
/// Best effort — a bookkeeping failure never fails the read.
async fn record_read(n: &AppState, hash: [u8; 32], last_access_at: i64, now: i64) {
    if now.saturating_sub(last_access_at) < crate::db::BLOB_REFRESH_SECONDS {
        return;
    }
    let _ =
        n.db.write(move |c: &Connection| blobs::touch_blob(c, &hash, now))
            .await;
}

pub async fn get(
    State(n): State<AppState>,
    headers: HeaderMap,
    Path(hash_hex): Path<String>,
) -> Response {
    run(get_inner(n, headers, hash_hex, false).await)
}

pub async fn head(
    State(n): State<AppState>,
    headers: HeaderMap,
    Path(hash_hex): Path<String>,
) -> Response {
    run(get_inner(n, headers, hash_hex, true).await)
}

async fn get_inner(
    n: AppState,
    headers: HeaderMap,
    hash_hex: String,
    head: bool,
) -> ApiResult<Response> {
    let hash = parse_hash(&hash_hex)?;
    if !n.cfg.blobs_enabled() {
        return Err(ApiError::blobs_disabled());
    }
    let hash_hex = hex::encode(hash);
    let now = crate::store::reaper::now();

    if let Some((size, last_access_at)) = get_row(&n, &hash, now).await? {
        return local_response(&n, hash, &hash_hex, size, last_access_at, &headers, head).await;
    }

    Err(ApiError::not_found("no such blob"))
}

async fn local_response(
    n: &AppState,
    hash: [u8; 32],
    hash_hex: &str,
    _row_size: i64,
    last_access_at: i64,
    headers: &HeaderMap,
    head: bool,
) -> ApiResult<Response> {
    let now = crate::store::reaper::now();
    let etag = format!("\"{hash_hex}\"");

    if let Some(im) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        && etag_matches(im, hash_hex)
    {
        // A 304 is still a read: record it before answering.
        record_read(n, hash, last_access_at, now).await;
        let mut resp = StatusCode::NOT_MODIFIED.into_response();
        let etag_val = header::HeaderValue::from_str(&etag)
            .unwrap_or_else(|_| header::HeaderValue::from_static("\"\""));
        resp.headers_mut().insert(header::ETAG, etag_val);
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static(BLOB_CACHE_CONTROL),
        );
        return Ok(resp);
    }

    let path = blobs::blob_path(&n.cfg.data_dir, hash_hex);
    let meta = tokio::fs::metadata(&path)
        .await
        .map_err(|_| ApiError::not_found("no such blob"))?;
    let size = meta.len();

    // Only a read that actually has bytes behind it is recorded.
    record_read(n, hash, last_access_at, now).await;

    let common = [
        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        (header::ETAG, etag),
        (header::CACHE_CONTROL, BLOB_CACHE_CONTROL.to_string()),
        (header::ACCEPT_RANGES, "bytes".to_string()),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
    ];

    let mut builder = Response::builder();
    for (k, v) in common {
        builder = builder.header(k, v);
    }

    if head {
        return builder
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, size.to_string())
            .body(Body::empty())
            .map_err(|_| ApiError::internal("response"));
    }

    let mut file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| ApiError::not_found("no such blob"))?;

    let body: Body = if let Some(rng) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        if let Some((from, to)) = range_parse(rng, size) {
            builder = builder
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_RANGE, format!("bytes {from}-{to}/{size}"))
                .header(header::CONTENT_LENGTH, (to - from + 1).to_string());
            use tokio::io::{AsyncReadExt, AsyncSeekExt};
            if let Err(e) = file.seek(std::io::SeekFrom::Start(from)).await {
                return Err(ApiError::internal(format!("seek: {e}")));
            }
            let reader = AsyncReadExt::take(file, to - from + 1);
            Body::from_stream(tokio_util::io::ReaderStream::new(reader))
        } else {
            // unsatisfiable/ignored range → 200 full body (contract simplification)
            use tokio::io::AsyncSeekExt;
            file.seek(std::io::SeekFrom::Start(0)).await.ok();
            builder = builder
                .status(StatusCode::OK)
                .header(header::CONTENT_LENGTH, size.to_string());
            Body::from_stream(tokio_util::io::ReaderStream::new(file))
        }
    } else {
        builder = builder
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, size.to_string());
        Body::from_stream(tokio_util::io::ReaderStream::new(file))
    };

    builder
        .body(body)
        .map_err(|_| ApiError::internal("response"))
}
