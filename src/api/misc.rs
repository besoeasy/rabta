use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use serde_json::json;

use super::AppState;
use super::routes;
use crate::db::{MAX_TTL_SECONDS, MIN_TTL_SECONDS};
use crate::store::reaper;
use crate::sync::battery::{
    BLOB_COST, EVENT_COST, PUSH_MULTIPLIER, READONLY_FLOOR, SYNC_BATTERY_MAX, SYNC_FLOOR, Tier,
};

fn endpoint(method: &str, path: &str) -> String {
    format!("{method} {}", routes::api_url(path))
}

/// Self-contained node status page (no external assets), embedded at build time.
pub const INDEX_HTML: &str = include_str!("index.html");

/// `GET /` — self-contained HTML status page (UI only).
pub async fn index() -> axum::response::Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // The page is rebuilt with the binary; browsers must not serve
            // a stale copy after an upgrade.
            (header::CACHE_CONTROL, "no-store"),
        ],
        INDEX_HTML,
    )
        .into_response()
}

/// `GET /api/v1/` — JSON route index for API clients.
pub async fn api_index(State(n): State<AppState>) -> Json<serde_json::Value> {
    Json(index_json(&n))
}

fn index_json(n: &AppState) -> serde_json::Value {
    let mut endpoints = serde_json::Map::new();
    endpoints.insert(endpoint("GET", routes::HEALTH), json!("liveness probe"));
    endpoints.insert(
        endpoint("GET", routes::NODE),
        json!("node identity, public key, runtime stats, storage, and peer health"),
    );
    endpoints.insert(
        endpoint("GET", routes::OPENAPI),
        json!("OpenAPI 3.1 description of this API"),
    );
    endpoints.insert(
        endpoint("POST", routes::EVENTS),
        json!("publish a signed envelope (application/json)"),
    );
    endpoints.insert(
        endpoint("GET", routes::EVENTS),
        json!("list live events (query params, ETag / If-None-Match caching)"),
    );
    endpoints.insert(
        endpoint("GET", routes::EVENTS_COUNT),
        json!("count live events matching query parameters"),
    );
    endpoints.insert(
        endpoint("POST", routes::SYNC),
        json!("server-to-server peer sync"),
    );
    endpoints.insert(
        endpoint("GET", routes::EVENT_BY_ID),
        json!("fetch one (ETag / If-None-Match)"),
    );
    endpoints.insert(
        endpoint("GET", routes::EVENT_SIZE),
        json!("envelope size + attached blob bytes"),
    );
    if n.cfg.blobs_enabled() {
        endpoints.insert(
            endpoint("PUT", routes::BLOBS),
            json!("raw blob upload; identity is the sha256 of the body"),
        );
        endpoints.insert(
            endpoint("GET", routes::BLOB_BY_HASH),
            json!("download a blob (Range / ETag)"),
        );
        endpoints.insert(
            endpoint("HEAD", routes::BLOB_BY_HASH),
            json!("blob metadata"),
        );
    }

    json!({
        "service": "rabta",
        "version": env!("CARGO_PKG_VERSION"),
        "api_version": routes::API_VERSION,
        "base_path": routes::PREFIX,
        "description": "signed-event relay with local content-addressed blobs",
        "node_id": n.identity.node_id_hex(),
        "public_key": n.identity.public_key_string(),
        "routes": endpoints,
    })
}

/// `GET /api/v1/health` — liveness probe.
pub async fn health(State(n): State<AppState>) -> impl IntoResponse {
    let events =
        n.db.read(|c: &rusqlite::Connection| crate::store::queries::count_live(c))
            .await;
    let blobs =
        n.db.read(|c: &rusqlite::Connection| crate::store::queries::count_live_blobs(c))
            .await;
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "node_id": n.identity.node_id_hex(),
            "live_events": events,
            "live_blobs": blobs,
        })),
    )
        .into_response()
}

/// `GET /api/v1/node` — unified node identity, runtime telemetry, storage, and peer health.
pub async fn node(State(n): State<AppState>) -> Json<serde_json::Value> {
    let cfg = n.cfg.clone();
    let now = reaper::now();
    let cfg_stats = cfg.clone();
    let data =
        n.db.read(move |c: &rusqlite::Connection| {
            let events = crate::store::queries::count_live(c);
            let blobs = crate::store::queries::count_live_blobs(c);
            let (event_bytes, claimed_bytes) = crate::db::live_bytes(c);
            let blob_bytes = crate::db::blob_bytes(c);
            let (policy_events, policy_blobs) = reaper::policy_bytes(c, &cfg_stats);
            let eviction = reaper::eviction_summary(c, &cfg_stats).unwrap_or_default();
            let unclaimed_count = crate::store::blobs::unclaimed_stats(c)
                .map(|(count, _)| count)
                .unwrap_or(0);
            (
                events,
                blobs,
                event_bytes,
                claimed_bytes,
                blob_bytes,
                policy_events,
                policy_blobs,
                eviction,
                unclaimed_count,
            )
        })
        .await;

    let idx = &reaper::COUNTERS;
    let free = crate::config::free_bytes_public(&cfg.data_dir);
    let last_sweep = reaper::last_sweep_at();
    let cfg_peers = cfg.clone();
    let (peer_items, battery) =
        n.db.read(move |c: &rusqlite::Connection| {
            let mut items = Vec::new();
            if let Ok(mut stmt) = c.prepare(
                "SELECT p.url, p.penalty, p.strikes, p.last_success_at,
                        p.last_error, p.last_error_at, p.next_poll_at,
                        b.remaining, b.max, b.updated_at
                 FROM sync_peers p
                 LEFT JOIN peer_battery b ON b.url = p.url
                 ORDER BY p.url",
            ) && let Ok(rows) = stmt.query_map([], |r| {
                let remaining = r.get::<_, Option<f64>>(7)?;
                let max = r.get::<_, Option<f64>>(8)?;
                let updated_at = r.get::<_, Option<i64>>(9)?;
                let battery = match (remaining, max, updated_at) {
                    (Some(remaining), Some(max), Some(updated_at)) => json!({
                        "remaining": remaining,
                        "max": max,
                        "updated_at": updated_at,
                    }),
                    _ => serde_json::Value::Null,
                };
                Ok(json!({
                    "url": r.get::<_, String>(0)?,
                    "last_success_at": r.get::<_, Option<i64>>(3)?,
                    "last_error": r.get::<_, Option<String>>(4)?,
                    "last_error_at": r.get::<_, Option<i64>>(5)?,
                    "next_poll_at": r.get::<_, i64>(6)?,
                    "battery": battery,
                }))
            }) {
                items = rows.filter_map(|row| row.ok()).collect();
            }
            let battery = c
                .query_row(
                    "SELECT battery, battery_at, tier FROM sync_meta WHERE id = 1",
                    [],
                    |r| {
                        Ok((
                            r.get::<_, f64>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, i64>(2)?,
                        ))
                    },
                )
                .ok()
                .map(|(stored, at, tier_db)| {
                    let elapsed = (now - at).max(0) as f64;
                    let regen = cfg_peers.battery_regen_per_sec;
                    let remaining = (stored + elapsed * regen).min(SYNC_BATTERY_MAX);
                    let tier = Tier::current(remaining, Tier::from_db(tier_db));
                    json!({
                        "remaining": remaining,
                        "max": SYNC_BATTERY_MAX,
                        "regen_per_sec": cfg_peers.battery_regen_per_sec,
                        "mode": tier.as_str(),
                    })
                });
            (items, battery)
        })
        .await;
    let uptime_s = now.saturating_sub(n.started_at);

    Json(json!({
        "node_id": n.identity.node_id_hex(),
        "public_key": n.identity.public_key_string(),
        "algorithm": "ed25519",
        "source": n.identity.source.as_str(),
        "sync": n.cfg.sync_nodes.clone(),
        "donate": n.cfg.bitcoin,
        "started_at": n.started_at,
        "uptime_s": uptime_s,
        "version": env!("CARGO_PKG_VERSION"),
        "api_version": routes::API_VERSION,
        "events": {
            "live": data.0,
            "bytes": data.2,
        },
        "limits": {
            "min_ttl_s": MIN_TTL_SECONDS,
            "max_ttl_s": MAX_TTL_SECONDS,
            "battery": {
                "event_cost": EVENT_COST,
                "blob_cost": BLOB_COST,
                "push_multiplier": PUSH_MULTIPLIER,
                "sync_floor": SYNC_FLOOR,
                "read_only_floor": READONLY_FLOOR,
            },
        },
        "blobs": {
            "enabled": cfg.blobs_enabled(),
            "live": data.1,
            "bytes": data.4,
            "claimed_bytes": data.3,
            "unclaimed": data.8,
            "unclaimed_bytes": data.4.saturating_sub(data.3),
            "unclaimed_limit_bytes": cfg.unclaimed_limit_bytes,
            "unclaimed_max_blobs": cfg.max_unclaimed_blobs,
            "max_single_bytes": cfg.max_single_blob,
        },
        "storage": {
            "budget_bytes": cfg.watermark_bytes(),
            "target_bytes": cfg.target_bytes(),
            "used_bytes": data.2.saturating_add(data.3),
            "store_bytes": cfg.store,
            "configured_bytes": cfg.store_configured,
            "clamped_to_free": cfg.storage_clamped,
            "free_bytes": free,
            "data_dir": cfg.data_dir.to_string_lossy(),
            "policy_rules": cfg.policy.rule_count(),
            "policy_event_bytes": data.5,
            "policy_blob_bytes": data.6,
        },
        "reaper": {
            "interval_s": reaper::REAPER_INTERVAL.as_secs(),
            "last_sweep_at": if last_sweep > 0 { json!(last_sweep) } else { json!(null) },
            "last_sweep_age_s": if last_sweep > 0 {
                json!(now.saturating_sub(last_sweep))
            } else {
                json!(null)
            },
        },
        "eviction": {
            "events_evicted": idx.events_evicted.load(std::sync::atomic::Ordering::Relaxed),
            "blobs_evicted": idx.blobs_evicted.load(std::sync::atomic::Ordering::Relaxed),
            "bytes_reclaimed": idx.bytes_reclaimed.load(std::sync::atomic::Ordering::Relaxed),
            "unclaimed_blobs_evicted": idx
                .unclaimed_blobs_evicted
                .load(std::sync::atomic::Ordering::Relaxed),
            "unclaimed_bytes_reclaimed": idx
                .unclaimed_bytes_reclaimed
                .load(std::sync::atomic::Ordering::Relaxed),
            "candidates": {
                "events": data.7.candidates,
                "envelope_bytes": data.7.envelope_bytes,
                "blob_bytes": data.7.blob_bytes,
                "reclaimable_bytes": data.7.reclaimable_bytes(),
                "largest_bytes": data.7.largest_footprint,
                "largest_event": data.7.largest_event.as_ref().map(|event| json!({
                    "id": event.id,
                    "collection": event.collection,
                    "envelope_bytes": event.envelope_bytes,
                    "blob_bytes": event.blob_bytes,
                    "reclaimable_bytes": event.reclaimable_bytes,
                })),
            },
        },
        "upload": {
            "inflight_bytes": n.uploads.inflight_bytes(),
            "max_single_bytes": cfg.max_single_blob,
        },
        "peers": {
            "battery": battery,
            "items": peer_items,
        },
    }))
}

/// Add `X-Rabta-Node-Id` to every response, including errors and 404s.
pub async fn node_header(
    State(node_id): State<String>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut res = next.run(req).await;
    if let Ok(value) = axum::http::HeaderValue::from_bytes(node_id.as_bytes()) {
        res.headers_mut().insert("x-rabta-node-id", value);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rabta-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn node_route_exposes_identity() {
        let dir = temp_dir("node-route");
        let mut cfg = crate::config::Config::test_cfg(dir.clone(), 1_000_000);
        cfg.sync_nodes = vec![
            "https://peer-a.example.com".into(),
            "https://peer-b.example.com".into(),
        ];
        let identity = crate::identity::NodeIdentity::generate();
        let n = crate::api::Node::new(cfg, crate::db::Db::open(&dir), identity);
        let Json(body) = node(State(n.clone())).await;
        assert_eq!(body["node_id"], n.identity.node_id_hex());
        assert_eq!(body["public_key"], n.identity.public_key_string());
        assert_eq!(body["algorithm"], "ed25519");
        assert_eq!(body["source"], "generated");
        assert_eq!(body["api_version"], routes::API_VERSION);
        assert_eq!(
            body["sync"],
            json!(["https://peer-a.example.com", "https://peer-b.example.com"])
        );
        // Unset `BITCOIN` is an explicit null, never an omission.
        assert!(body["donate"].is_null());
        // Unified telemetry blocks are now present in /node
        assert!(body["events"]["live"].is_number());
        assert!(body["storage"]["budget_bytes"].is_number());
        assert!(body["limits"]["min_ttl_s"].is_number());
        assert!(body["eviction"]["candidates"]["largest_event"].is_null());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn node_route_exposes_donation_address() {
        let dir = temp_dir("node-donate");
        let mut cfg = crate::config::Config::test_cfg(dir.clone(), 1_000_000);
        cfg.bitcoin = Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into());
        let identity = crate::identity::NodeIdentity::generate();
        let n = crate::api::Node::new(cfg, crate::db::Db::open(&dir), identity);
        let Json(body) = node(State(n.clone())).await;
        assert_eq!(body["donate"], "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn node_header_is_stamped_on_success_and_404() {
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                "abc123".to_string(),
                node_header,
            ));

        let ok = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(
            ok.headers()
                .get("x-rabta-node-id")
                .unwrap()
                .to_str()
                .unwrap(),
            "abc123"
        );

        let missing = app
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            missing
                .headers()
                .get("x-rabta-node-id")
                .unwrap()
                .to_str()
                .unwrap(),
            "abc123"
        );
    }

    fn test_state(tag: &str) -> (AppState, std::path::PathBuf) {
        let dir = temp_dir(tag);
        let cfg = crate::config::Config::test_cfg(dir.clone(), 1_000_000);
        let identity = crate::identity::NodeIdentity::generate();
        let state = crate::api::Node::new(cfg, crate::db::Db::open(&dir), identity);
        (state, dir)
    }

    #[tokio::test]
    async fn node_reports_peer_health() {
        let (n, dir) = test_state("stats-peers");
        n.db.write(|c| {
            c.execute(
                "INSERT INTO sync_peers (url, penalty, strikes, last_success_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    "https://peer-a.example.com",
                    1.5_f64,
                    2_i64,
                    1_700_000_000_i64
                ],
            )?;
            c.execute(
                "INSERT INTO peer_battery (url, remaining, max, updated_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    "https://peer-a.example.com",
                    90_000_f64,
                    100_000_f64,
                    1_700_000_010_i64
                ],
            )
        })
        .await
        .unwrap();

        let res = node(State(n.clone())).await.into_response();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["peers"]["items"][0]["url"],
            "https://peer-a.example.com"
        );
        assert_eq!(body["peers"]["items"][0]["battery"]["remaining"], 90_000.0);
        assert_eq!(body["peers"]["items"][0]["battery"]["max"], 100_000.0);
        assert_eq!(
            body["peers"]["items"][0]["battery"]["updated_at"],
            1_700_000_010_i64
        );
        assert!(body["peers"]["battery"].is_null());
        assert_eq!(body["limits"]["min_ttl_s"], 60);
        assert_eq!(body["limits"]["max_ttl_s"], 400 * 86400);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn index_is_html_only_and_api_index_is_json() {
        let (n, dir) = test_state("index-routes");
        let res = index().await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "text/html; charset=utf-8"
        );

        let Json(body) = api_index(State(n.clone())).await;
        assert_eq!(body["service"], "rabta");
        assert!(body["routes"].get("GET /api/v1/health").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_page_is_self_contained() {
        assert!(INDEX_HTML.contains("/api/v1/node"));
        assert!(INDEX_HTML.contains("https://github.com/besoeasy/rabta"));
        assert!(!INDEX_HTML.contains("<script src"));
        assert!(!INDEX_HTML.contains("<link rel=\"stylesheet\""));
        assert!(!INDEX_HTML.contains("fonts.googleapis"));
    }
}
