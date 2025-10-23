use axum::Json;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use super::AppState;
use crate::error::{ApiError, ApiResult};
use crate::sync::auth::verify_sync_request;
use crate::sync::battery::{
    EVENT_COST, SYNC_BATTERY_MAX, SYNC_FLOOR, deduct_battery, refill_battery,
};
use crate::sync::client::{
    BatterySectionResponse, PeerSectionResponse, RejectedItem, SyncRequest, SyncResponse,
};
use crate::sync::penalty::{get_or_create_peer, poll_interval_ms, record_peer_clean};
use crate::sync::range::{RangeDiffResult, compute_range_summary, reconcile_ranges};

pub async fn handle(State(n): State<AppState>, headers: HeaderMap, req: Request<Body>) -> Response {
    let bytes = match axum::body::to_bytes(req.into_body(), crate::sync::MAX_SYNC_WIRE).await {
        Ok(b) => b.to_vec(),
        Err(_) => return ApiError::too_large("sync payload exceeds wire cap").into_response(),
    };

    match sync_inner(n, headers, bytes).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => e.into_response(),
    }
}

struct WritePhaseResult {
    accepted: usize,
    rejected: Vec<RejectedItem>,
    missing_blobs: Vec<String>,
    final_cost: f64,
}

struct ReadPhaseResult {
    local_epoch: String,
    range_diff: RangeDiffResult,
    battery_remaining: f64,
}

async fn sync_inner(
    n: AppState,
    headers: HeaderMap,
    body_bytes: Vec<u8>,
) -> ApiResult<SyncResponse> {
    let now = crate::store::reaper::now();

    let sync_req: SyncRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| ApiError::bad_json(format!("malformed sync request: {e}")))?;

    if sync_req.ranges.len() > 32 {
        return Err(ApiError::bad_json(
            "too many ranges in sync request (max 32)",
        ));
    }

    // 1. Write Phase: Auth, battery check (>= 75%), push event ingestion
    let write_res: WritePhaseResult =
        n.db.write({
            let headers = headers.clone();
            let body_bytes = body_bytes.clone();
            let push_events = sync_req.push_events.clone();
            let cfg = n.cfg.clone();
            let state_clone = n.clone();

            move |c| -> ApiResult<WritePhaseResult> {
                // Authenticate peer and nonce
                let peer_info = verify_sync_request(c, &headers, &body_bytes, now)?;
                let peer_url = format!("peer:{}", peer_info.peer_key_hex);
                let _peer_record = get_or_create_peer(c, &peer_url, now)?;

                // Only sync if battery is >= 75%
                let refill = refill_battery(c, now, SYNC_BATTERY_MAX, cfg.battery_regen_per_sec)
                    .map_err(|e| ApiError::internal(format!("battery refill: {e}")))?;
                if !refill.sync_admitted() {
                    return Err(ApiError::battery_empty(format!(
                        "sync disabled; battery below 75%; retry after {}s",
                        refill.retry_after_to(SYNC_FLOOR)
                    )));
                }

                // Ingest pushed events
                let mut accepted = 0;
                let mut rejected = Vec::new();
                let mut all_missing_blobs = Vec::new();

                for ev_val in push_events {
                    let Ok(bytes) = serde_json::to_vec(&ev_val) else {
                        rejected.push(RejectedItem {
                            id: "unknown".into(),
                            code: "bad_json".into(),
                        });
                        continue;
                    };

                    let parsed = match crate::store::events::parse_and_verify(&bytes, now) {
                        Ok(p) => p,
                        Err(e) => {
                            rejected.push(RejectedItem {
                                id: "unknown".into(),
                                code: e.code.into(),
                            });
                            continue;
                        }
                    };

                    if state_clone.dedup.is_duplicate(&parsed.id) {
                        continue;
                    }
                    state_clone.dedup.record(parsed.id);

                    match crate::store::events::insert_event(c, &parsed) {
                        Ok(true) => {
                            if let Ok(missing) =
                                crate::sync::blob::enqueue_missing_blobs(c, &parsed.blobs, now)
                            {
                                all_missing_blobs.extend(missing);
                            }
                            accepted += 1;
                        }
                        Ok(false) => {}
                        Err(_e) => {
                            rejected.push(RejectedItem {
                                id: parsed.id_hex,
                                code: "insert_failed".into(),
                            });
                        }
                    }
                }

                let final_cost = accepted as f64 * EVENT_COST;
                let _ = deduct_battery(c, final_cost);
                let _ = record_peer_clean(c, &peer_url, now);

                Ok(WritePhaseResult {
                    accepted,
                    rejected,
                    missing_blobs: all_missing_blobs,
                    final_cost,
                })
            }
        })
        .await?;

    // 2. Read Phase: Reconcile ranges + fetch missing events + return diff
    let read_res: ReadPhaseResult =
        n.db.read({
            let sync_req = sync_req.clone();
            move |c| -> rusqlite::Result<ReadPhaseResult> {
                let local_root = compute_range_summary(c, now, 0, i64::MAX)?;
                let range_diff = if local_root == sync_req.root && sync_req.ranges.is_empty() {
                    // Roots match exactly and no specific sub-ranges requested
                    RangeDiffResult::default()
                } else {
                    // Evaluate ranges
                    let target_ranges = if sync_req.ranges.is_empty() {
                        vec![sync_req.root.clone()]
                    } else {
                        sync_req.ranges.clone()
                    };
                    reconcile_ranges(c, now, &target_ranges, 100)?
                };

                let ep: Option<Vec<u8>> = c
                    .query_row("SELECT epoch FROM sync_meta WHERE id = 1", [], |r| r.get(0))
                    .ok();
                let local_epoch = ep.map(hex::encode).unwrap_or_else(|| "0".repeat(32));

                let battery_remaining: f64 = c
                    .query_row("SELECT battery FROM sync_meta WHERE id = 1", [], |r| {
                        r.get(0)
                    })
                    .unwrap_or(0.0);

                Ok(ReadPhaseResult {
                    local_epoch,
                    range_diff,
                    battery_remaining,
                })
            }
        })
        .await
        .map_err(|e| ApiError::internal(format!("sync read error: {e}")))?;

    let next_poll_ms = poll_interval_ms(1.0);

    Ok(SyncResponse {
        epoch: read_res.local_epoch,
        accepted: write_res.accepted,
        rejected: write_res.rejected,
        pull_events: read_res.range_diff.pull_events,
        known_ids: read_res.range_diff.known_ids,
        divergent_ranges: read_res.range_diff.divergent_ranges,
        sub_ranges: read_res.range_diff.sub_ranges,
        missing_blobs: write_res.missing_blobs,
        battery: BatterySectionResponse {
            remaining: read_res.battery_remaining,
            max: SYNC_BATTERY_MAX,
            regen_per_sec: n.cfg.battery_regen_per_sec,
            cost: write_res.final_cost,
            retry_after_s: 0,
        },
        peer: PeerSectionResponse {
            next_poll_after_ms: next_poll_ms,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::auth::create_signed_headers;
    use crate::sync::range::RangeSummary;
    use axum::http::HeaderValue;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rabta-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_state(dir: &std::path::Path) -> AppState {
        let cfg = crate::config::Config::test_cfg(dir, 10_000_000);
        let identity = crate::identity::NodeIdentity::generate();
        crate::api::Node::new(cfg, crate::db::Db::open(dir), identity)
    }

    fn make_test_event(key: &SigningKey, collection: &str, now: i64) -> serde_json::Value {
        let created_at = now - 10;
        let expires_at = now + 3600;
        let owner = format!("ed25519:{}", hex::encode(key.verifying_key().to_bytes()));
        let data = serde_json::json!({"msg": "hello sync"});
        let canonical =
            crate::canon::digest_value(collection, created_at, expires_at, &owner, &[], &data, &[]);
        let digest: [u8; 32] = Sha256::digest(crate::canon::canonical_value(&canonical)).into();
        let sig = key.sign(&digest);
        serde_json::json!({
            "collection": collection,
            "created_at": created_at,
            "data": data,
            "expires_at": expires_at,
            "labels": [],
            "blobs": [],
            "owner": owner,
            "id": hex::encode(digest),
            "sig": hex::encode(sig.to_bytes()),
        })
    }

    fn headers_to_map(headers: Vec<(&'static str, String)>) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            map.insert(
                axum::http::HeaderName::from_static(k),
                HeaderValue::from_str(&v).unwrap(),
            );
        }
        map
    }

    #[tokio::test]
    async fn test_sync_authenticated_push_and_pull() {
        let dir = temp_dir("sync-push-pull");
        let n = test_state(&dir);
        let now = crate::store::reaper::now();

        let client_identity = crate::identity::NodeIdentity::from_seed(&[9u8; 32]);
        let event_key = SigningKey::from_bytes(&[3u8; 32]);
        let event_val = make_test_event(&event_key, "chat", now);

        let req = SyncRequest {
            epoch: "0".repeat(32),
            root: RangeSummary {
                start: 0,
                end: i64::MAX,
                count: 0,
                digest: "0000000000000000".into(),
            },
            ranges: vec![RangeSummary {
                start: 0,
                end: i64::MAX,
                count: 0,
                digest: "0000000000000000".into(),
            }],
            push_events: vec![event_val],
            request_id: "req-1".into(),
        };

        let body_bytes = serde_json::to_vec(&req).unwrap();
        let header_list = create_signed_headers(&client_identity, &body_bytes, now);
        let headers = headers_to_map(header_list);

        let resp = sync_inner(n.clone(), headers, body_bytes).await.unwrap();

        assert_eq!(resp.accepted, 1);
        assert_eq!(resp.rejected.len(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_sync_repulls_missing_event() {
        let dir = temp_dir("sync-repull");
        let n = test_state(&dir);
        let now = crate::store::reaper::now();

        let client_identity = crate::identity::NodeIdentity::from_seed(&[9u8; 32]);
        let event_key = SigningKey::from_bytes(&[3u8; 32]);
        let event_val = make_test_event(&event_key, "notes", now);

        // Pre-insert event on server
        let bytes = serde_json::to_vec(&event_val).unwrap();
        let parsed = crate::store::events::parse_and_verify(&bytes, now).unwrap();
        n.db.write(move |c| crate::store::events::insert_event(c, &parsed))
            .await
            .unwrap();

        // Client has 0 events and sends empty range [0, i64::MAX)
        let req = SyncRequest {
            epoch: "0".repeat(32),
            root: RangeSummary {
                start: 0,
                end: i64::MAX,
                count: 0,
                digest: "0000000000000000".into(),
            },
            ranges: vec![RangeSummary {
                start: 0,
                end: i64::MAX,
                count: 0,
                digest: "0000000000000000".into(),
            }],
            push_events: vec![],
            request_id: "req-repull".into(),
        };

        let body_bytes = serde_json::to_vec(&req).unwrap();
        let header_list = create_signed_headers(&client_identity, &body_bytes, now);
        let headers = headers_to_map(header_list);

        let resp = sync_inner(n.clone(), headers, body_bytes).await.unwrap();

        // Server detects client is missing the event, sends it in pull_events!
        assert_eq!(resp.pull_events.len(), 1);
        assert_eq!(resp.pull_events[0]["id"], event_val["id"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_sync_dedup_rejects_duplicate_pushes() {
        let dir = temp_dir("sync-dedup");
        let n = test_state(&dir);
        let now = crate::store::reaper::now();

        let client_identity = crate::identity::NodeIdentity::from_seed(&[9u8; 32]);
        let event_key = SigningKey::from_bytes(&[4u8; 32]);
        let event_val = make_test_event(&event_key, "notes", now);

        let root = RangeSummary {
            start: 0,
            end: i64::MAX,
            count: 0,
            digest: "0000000000000000".into(),
        };

        // First push
        let req1 = SyncRequest {
            epoch: "0".repeat(32),
            root: root.clone(),
            ranges: vec![],
            push_events: vec![event_val.clone()],
            request_id: "req-1".into(),
        };
        let b1 = serde_json::to_vec(&req1).unwrap();
        let h1 = headers_to_map(create_signed_headers(&client_identity, &b1, now));
        let resp1 = sync_inner(n.clone(), h1, b1).await.unwrap();
        assert_eq!(resp1.accepted, 1);

        // Second push of identical event
        let req2 = SyncRequest {
            epoch: "0".repeat(32),
            root,
            ranges: vec![],
            push_events: vec![event_val],
            request_id: "req-2".into(),
        };
        let b2 = serde_json::to_vec(&req2).unwrap();
        let h2 = headers_to_map(create_signed_headers(&client_identity, &b2, now));
        let resp2 = sync_inner(n.clone(), h2, b2).await.unwrap();
        assert_eq!(resp2.accepted, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_sync_battery_exhaustion_returns_429() {
        let dir = temp_dir("sync-battery-exhaust");
        let cfg = crate::config::Config::test_cfg(&dir, 10_000_000);
        let identity = crate::identity::NodeIdentity::generate();
        let db = crate::db::Db::open(&dir);
        let n = crate::api::Node::new(cfg, db.clone(), identity);

        let now = db
            .write(|c| {
                c.execute(
                    "INSERT INTO sync_meta (id, epoch, battery, battery_at, created_at)
                     VALUES (1, x'00000000000000000000000000000000', 1.0, ?1, ?1)
                     ON CONFLICT(id) DO UPDATE SET battery = 1.0, battery_at = ?1",
                    [crate::store::reaper::now()],
                )
                .unwrap();
                crate::store::reaper::now()
            })
            .await;
        let client_identity = crate::identity::NodeIdentity::from_seed(&[9u8; 32]);
        let event_key = SigningKey::from_bytes(&[4u8; 32]);

        let events = (0..10)
            .map(|_| make_test_event(&event_key, "chat", now))
            .collect();
        let req = SyncRequest {
            epoch: "0".repeat(32),
            root: RangeSummary {
                start: 0,
                end: i64::MAX,
                count: 0,
                digest: "0000000000000000".into(),
            },
            ranges: vec![],
            push_events: events,
            request_id: "req-drain".into(),
        };
        let b = serde_json::to_vec(&req).unwrap();
        let h = headers_to_map(create_signed_headers(&client_identity, &b, now));

        let err = sync_inner(n.clone(), h, b).await.unwrap_err();
        assert_eq!(err.code, "battery_empty");
        assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
