use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::auth::create_signed_headers;
use super::range::RangeSummary;
use crate::identity::NodeIdentity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub epoch: String,
    pub root: RangeSummary,
    pub ranges: Vec<RangeSummary>,
    pub push_events: Vec<serde_json::Value>,
    pub request_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SyncResponse {
    pub epoch: String,
    pub accepted: usize,
    pub rejected: Vec<RejectedItem>,
    pub pull_events: Vec<serde_json::Value>,
    pub known_ids: Vec<String>,
    #[serde(default)]
    pub divergent_ranges: Vec<(i64, i64)>,
    pub sub_ranges: Vec<RangeSummary>,
    pub missing_blobs: Vec<String>,
    pub battery: BatterySectionResponse,
    pub peer: PeerSectionResponse,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RejectedItem {
    pub id: String,
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BatterySectionResponse {
    pub remaining: f64,
    pub max: f64,
    pub regen_per_sec: f64,
    pub cost: f64,
    pub retry_after_s: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerSectionResponse {
    pub next_poll_after_ms: u64,
}

pub struct SyncClient {
    client: Client,
    identity: NodeIdentity,
}

impl SyncClient {
    pub fn new(identity: NodeIdentity) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            identity,
        }
    }

    pub fn http(&self) -> &Client {
        &self.client
    }

    pub async fn send_sync(
        &self,
        peer_url: &str,
        req: &SyncRequest,
        now: i64,
    ) -> Result<SyncResponse, String> {
        let url = format!("{}/api/v1/sync", peer_url.trim_end_matches('/'));
        let body_bytes = serde_json::to_vec(req).map_err(|e| e.to_string())?;

        let headers = create_signed_headers(&self.identity, &body_bytes, now);
        let mut request_builder = self.client.post(&url);
        for (k, v) in headers {
            request_builder = request_builder.header(k, v);
        }

        let resp = request_builder
            .body(body_bytes)
            .send()
            .await
            .map_err(|e| format!("sync request error: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("peer HTTP status: {}", resp.status()));
        }

        let sync_resp: SyncResponse = resp
            .json()
            .await
            .map_err(|e| format!("cannot parse sync response: {e}"))?;

        Ok(sync_resp)
    }
}
