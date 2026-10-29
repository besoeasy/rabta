use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::error::{ApiError, ApiResult};
use crate::store::blobs;
use super::events::run;
use super::AppState;

type Connection = rusqlite::Connection;

fn parse_hash(s: &str) -> ApiResult<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::not_found("not a valid blob hash"));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&hex::decode(s).expect("checked"));
    Ok(h)
}

async fn get_row(n: &AppState, hash: &[u8; 32]) -> ApiResult<Option<(i64, String)>> {
    let h = *hash;
    let size = n
        .db
        .read(move |c: &Connection| {
            c.query_row(
                "SELECT size FROM blobs WHERE hash = ?1 AND state='live'",
                [&h],
                |r| r.get::<_, i64>(0),
            )
            .ok()
        })
        .await;
    Ok(size.map(|s| (s, hex::encode(hash))))
}

/// `bytes=from-to` single-range parser; malformed or unsatisfiable → None.
fn range_parse(rng: &str, size: u64) -> Option<(u64, u64)> {
    let rest = rng.trim().strip_prefix("bytes=")?;
    let (a, b) = rest.split_once('-')?;
    let from: u64 = a.trim().parse().ok()?;
    if from >= size {
        return None;
    }
    let to: u64 = if b.trim().is_empty() { size - 1 } else { b.trim().parse().ok()? };
    let to = to.min(size - 1);
    if from > to {
        return None;
    }
    Some((from, to))
}

fn etag_matches(im: &str, etag: &str) -> bool {
    let quoted = format!("\"{etag}\"");
    im.split(',').any(|p| p.trim() == "*" || p.trim() == quoted || p.trim() == etag)
}

pub async fn get(State(n): State<AppState>, headers: HeaderMap, Path(hash_hex): Path<String>) -> Response {
    run(get_inner(n, headers, hash_hex).await)
}

async fn get_inner(n: AppState, headers: HeaderMap, hash_hex: String) -> ApiResult<Response> {
    let hash = parse_hash(&hash_hex)?;
    let mut row = get_row(&n, &hash).await?;

    // Lazy fetch-on-read (plan.md §Sync): a miss triggers a pull from the
    // trusted peers before the 404 is served. The row is re-read after the
    // pull — the materialized bytes may have landed during it.
    if row.is_none() && !n.cfg.sync_nodes.is_empty() {
        let pulled = crate::sync::loop_all::fetch_blob_from_peers(
            &n,
            &hash_hex.to_ascii_lowercase(),
        )
        .await;
        if pulled {
            row = get_row(&n, &hash).await?;
        }
    }
    let Some((_size, resolved_hex)) = row else {
        return Err(ApiError::not_found("no such blob"));
    };

    let etag = resolved_hex;

    if let Some(im) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if etag_matches(im, &etag) {
            let mut resp = StatusCode::NOT_MODIFIED.into_response();
            resp.headers_mut().insert(header::ETAG, format!("\"{etag}\"").parse().unwrap());
            resp.headers_mut().insert(header::CACHE_CONTROL, "public, max-age=31536000, immutable".parse().unwrap());
            return Ok(resp);
        }
    }

    let file_path = blobs::blob_path(&n.cfg.data_dir, &etag);
    let mut file = match tokio::fs::File::open(&file_path).await {
        Ok(f) => f,
        Err(_) => return Err(ApiError::not_found("no such blob")),
    };
    let size = file
        .metadata()
        .await
        .map_err(|_| ApiError::not_found("no such blob"))?
        .len();

    let common = [
        (header::ETAG, format!("\"{etag}\"")),
        (header::CACHE_CONTROL, "public, max-age=31536000, immutable".to_string()),
        (header::ACCEPT_RANGES, "bytes".to_string()),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
    ];

    let mut builder = axum::http::Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream");
    for (k, v) in common {
        builder = builder.header(k, v);
    }

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

    Ok(builder.body(body).unwrap())
}
