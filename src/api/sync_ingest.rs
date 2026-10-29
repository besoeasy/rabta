use axum::body::Body;
use axum::extract::Request;
use axum::extract::{State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use super::events::{read_body_capped, run};
use super::AppState;
use crate::error::{ApiError, ApiResult};
use crate::store::events;
use crate::store::reaper;

type Conn = rusqlite::Connection;

const BATCH_BODY_CAP: usize = 32 * 1024 * 1024;
const BATCH_ITEM_CAP: usize = 1000;

// POST /sync/events — batch push of envelopes, normal validation.
pub async fn post_events(State(n): State<AppState>, req: Request<Body>) -> Response {
    run(post_events_inner(n, req).await)
}

async fn post_events_inner(n: AppState, req: Request<Body>) -> ApiResult<Response> {
    let bytes = read_body_capped(req, BATCH_BODY_CAP).await?;
    let arr: Vec<Value> = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::bad_json(format!("batch must be a JSON array: {e}")))?;
    if arr.len() > BATCH_ITEM_CAP {
        return Err(ApiError::too_large("batch exceeds 1000 events"));
    }

    let now = reaper::now();
    let mut stored = 0usize;
    let mut rejected = 0usize;
    let mut pushed: Vec<Vec<u8>> = Vec::new();

    for item in arr {
        let raw = match serde_json::to_vec(&item) {
            Ok(v) => v,
            Err(_) => {
                rejected += 1;
                continue;
            }
        };
        match events::parse_and_verify(&raw, now) {
            Ok(ev) => {
                match store_envelope(&n, raw).await {
                    Ok(true) => {
                        stored += 1;
                        pushed.push(ev.served_bytes.clone());
                    }
                    _ => rejected += 1,
                }
            }
            Err(_) => rejected += 1,
        }
    }

    // Inbound sync events are NOT re-fanned to other peers; the origin node
    // does the fan-out on its publish path (decision #16).
    let _ = pushed;

    Ok((
        StatusCode::OK,
        axum::Json(json!({"stored": stored, "rejected": rejected})),
    )
        .into_response())
}

/// Store one envelope (sync-plane ingest + client-loop pulls share this):
/// verify → insert in one transaction (refs row for a referenced blob so the
/// bytes ride parenthood when they arrive). Returns Ok(true) when a new row
/// was written. No re-fan-out here.
pub async fn store_envelope(n: &AppState, bytes: Vec<u8>) -> ApiResult<bool> {
    let now = reaper::now();
    let ev = events::parse_and_verify(&bytes, now)?;
    let ev2 = ev.clone();
    let cfg = n.cfg.clone();
    let out: ApiResult<bool> = n
        .db
        .write(move |c: &Conn| -> ApiResult<bool> {
            // Retries add no bytes: the duplicate check must run before
            // eviction, otherwise sync ingress can evict data for nothing.
            let exists = events::event_exists(c, &ev2.id)
                .map_err(|e| ApiError::internal(format!("lookup: {e}")))?;
            if !exists {
                reaper::pressure_check(c, &cfg, ev2.size as u64)?;
            }
            let ins = events::insert_event_with_ref(c, &ev2)
                .map_err(|e| ApiError::internal(format!("insert: {e}")))?;
            Ok(ins)
        })
        .await;
    if matches!(out, Ok(true)) {
        // Wake SSE only after the write transaction has committed.
        n.db.notify_event_row();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let dir = std::env::temp_dir().join(format!("rabta-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn envelope(n: i64) -> Vec<u8> {
        let now = reaper::now();
        let created_at = now - 10;
        let expires_at = now + 3600;
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let owner = format!("ed25519:{}", hex::encode(key.verifying_key().to_bytes()));
        let data = json!({"n": n});
        let canonical =
            crate::canon::digest_value("test", created_at, expires_at, &owner, &[], &data, None);
        let digest: [u8; 32] = Sha256::digest(crate::canon::canonical_value(&canonical)).into();
        let sig = key.sign(&digest);
        serde_json::to_vec(&json!({
            "collection": "test",
            "created_at": created_at,
            "data": data,
            "expires_at": expires_at,
            "labels": [],
            "owner": owner,
            "id": hex::encode(digest),
            "sig": hex::encode(sig.to_bytes()),
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn duplicate_retry_skips_admission_and_does_not_evict() {
        let dir = temp_dir("sync-dup");
        let cfg = crate::config::Config {
            port: 0,
            data_dir: dir.clone(),
            storage_max: 1000,
            storage_clamped: false,
            storage_max_configured: 1000,
            max_single_blob: 100,
            watermark_bytes: 1, // nothing new can be admitted
            eviction_target_bytes: 0,
            sse_subscriber_cap: 1,
            sync_nodes: Vec::new(),
            sync_interval: Duration::from_secs(60),
        };
        let n = std::sync::Arc::new(crate::api::Node {
            cfg,
            db: crate::db::Db::open(&dir),
            http: reqwest::Client::new(),
            started_at: reaper::now(),
        });

        let bytes = envelope(1);
        let ev = events::parse_and_verify(&bytes, reaper::now()).unwrap();
        n.db.write(move |c| {
            events::insert_event_with_ref(c, &ev).unwrap();
        })
        .await;

        // Duplicate: the pre-admission existence check must short-circuit
        // pressure, so this succeeds even though the watermark is exhausted.
        assert!(!store_envelope(&n, bytes).await.unwrap());
        let count: i64 = n
            .db
            .read(|c| c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0)).unwrap())
            .await;
        assert_eq!(count, 1);

        // A genuinely new event still hits admission and is refused.
        assert!(store_envelope(&n, envelope(2)).await.is_err());

        drop(n);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
