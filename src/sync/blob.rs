use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::Client;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

/// Abort if a chunk stalls for more than 30 seconds
pub const BLOB_STALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct BlobQueueItem {
    pub hash: [u8; 32],
    pub hash_hex: String,
}

/// Enqueue missing blob hashes when an event referencing them is accepted.
/// Returns the list of hashes that were actually missing and newly enqueued.
pub fn enqueue_missing_blobs(
    c: &Connection,
    hashes: &[String],
    now: i64,
) -> rusqlite::Result<Vec<String>> {
    let mut missing = Vec::new();
    for hex_hash in hashes {
        let mut hash = [0u8; 32];
        if hex::decode_to_slice(hex_hash, &mut hash).is_err() {
            continue;
        }

        // Check if already in blobs table
        let exists: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
            params![&hash[..]],
            |r| r.get(0),
        )?;
        if exists {
            continue;
        }

        let inserted = c.execute(
            "INSERT OR IGNORE INTO sync_blob_queue (hash, state, first_seen_at)
             VALUES (?1, 'pending', ?2)",
            params![&hash[..], now],
        )?;
        if inserted > 0 {
            missing.push(hex_hash.clone());
        }
    }
    Ok(missing)
}

/// Fetch next pending blobs for download.
pub fn next_pending_blobs(
    c: &Connection,
    limit: usize,
    now: i64,
) -> rusqlite::Result<Vec<BlobQueueItem>> {
    let mut stmt = c.prepare(
        "SELECT hash FROM sync_blob_queue
         WHERE state = 'pending' AND next_attempt_at <= ?1
         ORDER BY attempts ASC, first_seen_at ASC
         LIMIT ?2",
    )?;

    let rows = stmt.query_map(params![now, limit as i64], |r| {
        let raw: Vec<u8> = r.get(0)?;
        let mut hash = [0u8; 32];
        if raw.len() == 32 {
            hash.copy_from_slice(&raw);
        }
        let hash_hex = hex::encode(hash);
        Ok(BlobQueueItem { hash, hash_hex })
    })?;

    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }
    Ok(items)
}

pub fn mark_blob_downloading(c: &Connection, hash: &[u8; 32]) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE sync_blob_queue SET state = 'downloading' WHERE hash = ?1",
        params![&hash[..]],
    )?;
    Ok(())
}

pub fn mark_blob_completed(c: &Connection, hash: &[u8; 32]) -> rusqlite::Result<()> {
    c.execute(
        "DELETE FROM sync_blob_queue WHERE hash = ?1",
        params![&hash[..]],
    )?;
    Ok(())
}

pub fn mark_blob_failed(c: &Connection, hash: &[u8; 32], now: i64) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE sync_blob_queue
         SET state = 'pending', attempts = attempts + 1,
             next_attempt_at = ?2 + MIN(3600, 30 * (1 << MIN(attempts, 6)))
         WHERE hash = ?1",
        params![&hash[..], now],
    )?;
    Ok(())
}

/// Upload a locally stored blob to a remote peer.
pub async fn upload_blob(
    client: &Client,
    peer_url: &str,
    hash_hex: &str,
    data_dir: &Path,
) -> Result<(), String> {
    let path = crate::store::blobs::blob_path(data_dir, hash_hex);
    if !path.exists() {
        return Err("blob not found locally".into());
    }
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|e| e.to_string())?;
    let stream = tokio_util::io::ReaderStream::new(file);
    let body = reqwest::Body::wrap_stream(stream);
    let url = format!("{}/api/v1/blobs", peer_url.trim_end_matches('/'));
    let resp = client
        .put(&url)
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("upload returned HTTP {}", resp.status()))
    }
}

/// Download a blob from a remote peer with strict chunk stall detection and
/// size bounds (at least 1 byte, at most `max_single_blob`). Designed for
/// low-bandwidth connections (10 KB/s to 100 KB/s); enforces a 30-second
/// chunk stall timeout.
pub async fn download_blob(
    client: &Client,
    peer_url: &str,
    hash_hex: &str,
    data_dir: &Path,
    max_single_blob: u64,
) -> Result<PathBuf, String> {
    let url = format!(
        "{}/api/v1/blobs/{}",
        peer_url.trim_end_matches('/'),
        hash_hex
    );
    let tmp_dir = data_dir.join("tmp");
    tokio::fs::create_dir_all(&tmp_dir)
        .await
        .map_err(|e| e.to_string())?;
    let tmp_file_path = tmp_dir.join(format!("sync-blob-{}.tmp", hash_hex));

    let mut resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("request error: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("peer returned HTTP {}", resp.status()));
    }

    let mut file = tokio::fs::File::create(&tmp_file_path)
        .await
        .map_err(|e| format!("cannot create temp file: {e}"))?;

    let mut hasher = Sha256::new();
    let mut total_bytes: u64 = 0;

    loop {
        // Enforce 30-second stall timeout between chunks
        let next_chunk = match tokio::time::timeout(BLOB_STALL_TIMEOUT, resp.chunk()).await {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => break, // Stream completed
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&tmp_file_path).await;
                return Err(format!("stream read error: {e}"));
            }
            Err(_) => {
                let _ = tokio::fs::remove_file(&tmp_file_path).await;
                return Err("blob transfer stalled for >30s; aborted".to_string());
            }
        };

        total_bytes = total_bytes.saturating_add(next_chunk.len() as u64);
        if total_bytes > max_single_blob {
            let _ = tokio::fs::remove_file(&tmp_file_path).await;
            return Err(format!(
                "blob exceeded maximum allowed size of {max_single_blob} bytes"
            ));
        }

        file.write_all(&next_chunk)
            .await
            .map_err(|e| format!("write error: {e}"))?;
        hasher.update(&next_chunk);
    }

    file.flush().await.map_err(|e| e.to_string())?;

    // The empty input hashes to a well-known digest, so a zero-byte transfer
    // can satisfy the hash check when the requested hash is the empty one.
    // Refuse it before the digest compare: a 0-byte blob would be a
    // meaningless row and would break the unclaimed trim invariant that
    // every real upload occupies one row.
    if total_bytes == 0 {
        let _ = tokio::fs::remove_file(&tmp_file_path).await;
        return Err("peer served an empty blob".to_string());
    }

    let digest: [u8; 32] = hasher.finalize().into();
    let actual_hex = hex::encode(digest);
    if actual_hex != hash_hex {
        let _ = tokio::fs::remove_file(&tmp_file_path).await;
        return Err(format!(
            "sha256 mismatch: expected {hash_hex}, got {actual_hex}"
        ));
    }

    Ok(tmp_file_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rabta-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A peer serving zero bytes is refused before the digest compare: the
    /// empty input hashes to a well-known digest, so only the explicit size
    /// bound stops a 0-byte blob from installing.
    #[tokio::test]
    async fn empty_peer_transfer_is_refused() {
        let app = axum::Router::new().route(
            "/api/v1/blobs/{hash}",
            axum::routing::get(|| async { String::new() }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = temp_dir("sync-empty-blob");
        let client = Client::new();
        let err = download_blob(
            &client,
            &format!("http://{addr}"),
            &hex::encode([7u8; 32]),
            &dir,
            1_000_000,
        )
        .await
        .unwrap_err();
        assert!(err.contains("empty"), "unexpected error: {err}");

        // The refused transfer left no temp file behind.
        let leftovers = std::fs::read_dir(dir.join("tmp")).unwrap().count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
