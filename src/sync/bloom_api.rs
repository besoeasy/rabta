use serde_json::Value;
use rusqlite::Connection;

use crate::sync::bloom::{BloomFilterDto};
use crate::sync::planner;

/// The POST /sync/bloom server body — parse, validate, delegate to the planner.
pub fn handle(c: &Connection, body: &[u8], now: i64) -> Result<Value, String> {
    let req: BloomRequestWire =
        serde_json::from_slice(body).map_err(|e| format!("bad bloom request: {e}"))?;
    if req.v != planner::BLOOM_V {
        return Err(format!("unsupported bloom protocol version {}", req.v));
    }
    if req.filters.len() > 2 {
        return Err("at most two filters (events, blobs)".into());
    }
    planner::plan(c, &req.filters, now)
}

#[derive(serde::Deserialize)]
struct BloomRequestWire {
    v: u8,
    filters: Vec<BloomFilterDto>,
}
