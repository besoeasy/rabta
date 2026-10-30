use std::collections::HashMap;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROTOCOL_V: u8 = 1;
/// A range at or below this size is exchanged as exact IDs, not split again.
pub const LEAF_KEYS: usize = 64;
/// Requests are batched so one message cannot grow without bound.
pub const MAX_RANGES: usize = 128;
pub const MAX_IDS_PER_REPLY: usize = 1000;

const FP_TAG: &[u8] = b"rabta-range-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Events,
    Blobs,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Events => "events",
            Kind::Blobs => "blobs",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "events" => Some(Kind::Events),
            "blobs" => Some(Kind::Blobs),
            _ => None,
        }
    }
}

/// One range summary. `ids` is populated only when `count <= LEAF_KEYS`.
#[derive(Debug, Clone)]
pub struct Summary {
    pub count: u64,
    pub fp: [u8; 16],
    pub ids: Option<Vec<[u8; 32]>>,
}

impl Summary {
    pub fn fp_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(self.fp)
    }
}

#[derive(Debug, Deserialize)]
struct WireRequest {
    v: u8,
    kind: String,
    ranges: Vec<WireProbe>,
}

#[derive(Debug, Deserialize)]
struct WireProbe {
    prefix: String,
    #[serde(default)]
    count: Option<u64>,
    #[serde(default)]
    ids: Option<Vec<String>>,
    #[serde(default)]
    ids_only: bool,
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Debug, Serialize)]
struct WireResponse {
    v: u8,
    kind: String,
    ranges: Vec<Reply>,
}

/// Parse a prefix and return the inclusive key-space bounds it covers.
/// Nibble prefixes are supported (`"a"` covers `a0…` through `af…`).
pub fn prefix_bounds(prefix: &str) -> Result<([u8; 32], [u8; 32]), String> {
    let p = prefix.trim().to_ascii_lowercase();
    if p.len() > 64 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid range prefix `{prefix}`"));
    }
    let pad = 64 - p.len();
    let lo_hex = format!("{p}{}", "0".repeat(pad));
    let hi_hex = format!("{p}{}", "f".repeat(pad));
    let lo: [u8; 32] = hex::decode(lo_hex)
        .map_err(|_| "invalid prefix".to_string())?
        .try_into()
        .map_err(|_| "invalid prefix".to_string())?;
    let hi: [u8; 32] = hex::decode(hi_hex)
        .map_err(|_| "invalid prefix".to_string())?
        .try_into()
        .map_err(|_| "invalid prefix".to_string())?;
    Ok((lo, hi))
}

/// The 16 child prefixes of one range, in lexicographic order.
pub fn children(prefix: &str) -> impl Iterator<Item = String> + '_ {
    (0..16u8).map(move |d| format!("{prefix}{d:x}"))
}

pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

pub fn hex32(id: &[u8; 32]) -> String {
    hex::encode(id)
}

pub fn in_prefix(id: &[u8; 32], prefix: &str) -> Result<bool, String> {
    let (lo, hi) = prefix_bounds(prefix)?;
    Ok(*id >= lo && *id <= hi)
}

/// Exact summary for one range: count + truncated SHA-256 over the sorted IDs.
pub fn summary(
    c: &rusqlite::Connection,
    kind: Kind,
    prefix: &str,
    now: i64,
) -> Result<Summary, String> {
    let prefix = prefix.to_ascii_lowercase();
    let (lo, hi) = prefix_bounds(&prefix)?;
    let mut hasher = Sha256::new();
    hasher.update(FP_TAG);
    hasher.update(kind.as_str().as_bytes());
    hasher.update(prefix.as_bytes());

    let mut count = 0u64;
    let mut ids: Vec<[u8; 32]> = Vec::new();

    match kind {
        Kind::Events => {
            let mut stmt = c
                .prepare(
                    "SELECT id FROM events
                     WHERE state='live' AND expires_at > ?1 AND id >= ?2 AND id <= ?3
                     ORDER BY id",
                )
                .map_err(|e| e.to_string())?;
            let mut rows = stmt
                .query(rusqlite::params![now, &lo[..], &hi[..]])
                .map_err(|e| e.to_string())?;
            while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                let raw: Vec<u8> = row.get(0).map_err(|e| e.to_string())?;
                let Ok(id): Result<[u8; 32], _> = raw.try_into() else { continue };
                count += 1;
                hasher.update(id);
                if (ids.len() as u64) < LEAF_KEYS as u64 {
                    ids.push(id);
                }
            }
        }
        Kind::Blobs => {
            // Only advertise blobs a live, unexpired event still references.
            // Unreferenced uploads must not replicate and consume peer storage.
            let mut stmt = c
                .prepare(
                    "SELECT hash FROM blobs b
                     WHERE b.state='live' AND b.hash >= ?2 AND b.hash <= ?3
                       AND EXISTS (
                         SELECT 1 FROM refs r JOIN events e ON e.id = r.event_id
                         WHERE r.blob_hash = b.hash AND e.state='live' AND e.expires_at > ?1
                       )
                     ORDER BY b.hash",
                )
                .map_err(|e| e.to_string())?;
            let mut rows = stmt
                .query(rusqlite::params![now, &lo[..], &hi[..]])
                .map_err(|e| e.to_string())?;
            while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                let raw: Vec<u8> = row.get(0).map_err(|e| e.to_string())?;
                let Ok(id): Result<[u8; 32], _> = raw.try_into() else { continue };
                count += 1;
                hasher.update(id);
                if (ids.len() as u64) < LEAF_KEYS as u64 {
                    ids.push(id);
                }
            }
        }
    }

    hasher.update(count.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut fp = [0u8; 16];
    fp.copy_from_slice(&digest[..16]);
    Ok(Summary {
        count,
        fp,
        ids: if count <= LEAF_KEYS as u64 { Some(ids) } else { None },
    })
}

pub fn summary_batch(
    c: &rusqlite::Connection,
    kind: Kind,
    prefixes: &[String],
    now: i64,
) -> Result<Vec<Summary>, String> {
    prefixes.iter().map(|p| summary(c, kind, p, now)).collect()
}

/// One exact-ID page for a range, ordered by key. `after` is exclusive.
pub fn ids_page(
    c: &rusqlite::Connection,
    kind: Kind,
    prefix: &str,
    after: Option<[u8; 32]>,
    limit: usize,
    now: i64,
) -> Result<(Vec<[u8; 32]>, Option<[u8; 32]>), String> {
    let prefix = prefix.to_ascii_lowercase();
    let (lo, hi) = prefix_bounds(&prefix)?;
    let limit = limit.clamp(1, MAX_IDS_PER_REPLY);
    let want = (limit + 1) as i64;
    let mut ids: Vec<[u8; 32]> = Vec::new();

    match kind {
        Kind::Events => {
            let sql = if after.is_some() {
                "SELECT id FROM events
                 WHERE state='live' AND expires_at > ?1 AND id >= ?2 AND id <= ?3 AND id > ?4
                 ORDER BY id LIMIT ?5"
            } else {
                "SELECT id FROM events
                 WHERE state='live' AND expires_at > ?1 AND id >= ?2 AND id <= ?3
                 ORDER BY id LIMIT ?4"
            };
            let mut stmt = c.prepare(sql).map_err(|e| e.to_string())?;
            let mut rows = match after {
                Some(a) => stmt
                    .query(rusqlite::params![now, &lo[..], &hi[..], &a[..], want])
                    .map_err(|e| e.to_string())?,
                None => stmt
                    .query(rusqlite::params![now, &lo[..], &hi[..], want])
                    .map_err(|e| e.to_string())?,
            };
            while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                let raw: Vec<u8> = row.get(0).map_err(|e| e.to_string())?;
                if let Ok(id) = raw.try_into() {
                    ids.push(id);
                }
            }
        }
        Kind::Blobs => {
            let sql = if after.is_some() {
                "SELECT hash FROM blobs b
                 WHERE b.state='live' AND b.hash >= ?1 AND b.hash <= ?2 AND b.hash > ?3
                   AND EXISTS (
                     SELECT 1 FROM refs r JOIN events e ON e.id = r.event_id
                     WHERE r.blob_hash = b.hash AND e.state='live' AND e.expires_at > ?4
                   )
                 ORDER BY b.hash LIMIT ?5"
            } else {
                "SELECT hash FROM blobs b
                 WHERE b.state='live' AND b.hash >= ?1 AND b.hash <= ?2
                   AND EXISTS (
                     SELECT 1 FROM refs r JOIN events e ON e.id = r.event_id
                     WHERE r.blob_hash = b.hash AND e.state='live' AND e.expires_at > ?3
                   )
                 ORDER BY b.hash LIMIT ?4"
            };
            let mut stmt = c.prepare(sql).map_err(|e| e.to_string())?;
            let mut rows = match after {
                Some(a) => stmt
                    .query(rusqlite::params![&lo[..], &hi[..], &a[..], now, want])
                    .map_err(|e| e.to_string())?,
                None => stmt
                    .query(rusqlite::params![&lo[..], &hi[..], now, want])
                    .map_err(|e| e.to_string())?,
            };
            while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                let raw: Vec<u8> = row.get(0).map_err(|e| e.to_string())?;
                if let Ok(id) = raw.try_into() {
                    ids.push(id);
                }
            }
        }
    }

    let next = if ids.len() > limit {
        let last = ids[limit - 1];
        ids.truncate(limit);
        Some(last)
    } else {
        None
    };
    Ok((ids, next))
}

/// Live event rows in a prefix, for pushing missing events. Includes the
/// served envelope bytes so one query supports a whole push batch.
pub fn event_page(
    c: &rusqlite::Connection,
    prefix: &str,
    after: Option<[u8; 32]>,
    now: i64,
    limit: usize,
) -> Result<(Vec<([u8; 32], Vec<u8>)>, Option<[u8; 32]>), String> {
    let prefix = prefix.to_ascii_lowercase();
    let (lo, hi) = prefix_bounds(&prefix)?;
    let limit = limit.clamp(1, MAX_IDS_PER_REPLY);
    let want = (limit + 1) as i64;
    let sql = if after.is_some() {
        "SELECT id, data FROM events
         WHERE state='live' AND expires_at > ?1 AND id >= ?2 AND id <= ?3 AND id > ?4
         ORDER BY id LIMIT ?5"
    } else {
        "SELECT id, data FROM events
         WHERE state='live' AND expires_at > ?1 AND id >= ?2 AND id <= ?3
         ORDER BY id LIMIT ?4"
    };
    let mut stmt = c.prepare(sql).map_err(|e| e.to_string())?;
    let mut rows = match after {
        Some(a) => stmt
            .query(rusqlite::params![now, &lo[..], &hi[..], &a[..], want])
            .map_err(|e| e.to_string())?,
        None => stmt
            .query(rusqlite::params![now, &lo[..], &hi[..], want])
            .map_err(|e| e.to_string())?,
    };
    let mut out: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let raw: Vec<u8> = row.get(0).map_err(|e| e.to_string())?;
        let Ok(id): Result<[u8; 32], _> = raw.try_into() else { continue };
        let data: Vec<u8> = row.get(1).map_err(|e| e.to_string())?;
        out.push((id, data));
    }
    let next = if out.len() > limit {
        let last = out[limit - 1].0;
        out.truncate(limit);
        Some(last)
    } else {
        None
    };
    Ok((out, next))
}

/// Server side of POST /sync/reconcile.
pub fn handle(c: &rusqlite::Connection, body: &[u8], now: i64) -> Result<serde_json::Value, String> {
    let req: WireRequest =
        serde_json::from_slice(body).map_err(|e| format!("bad reconcile request: {e}"))?;
    if req.v != PROTOCOL_V {
        return Err(format!("unsupported reconcile protocol version {}", req.v));
    }
    let kind = Kind::parse(&req.kind).ok_or_else(|| "kind must be `events` or `blobs`".to_string())?;
    if req.ranges.len() > MAX_RANGES {
        return Err(format!("too many ranges (max {MAX_RANGES})"));
    }

    let mut replies = Vec::with_capacity(req.ranges.len());
    // One request may repeat a prefix (accidentally or maliciously). Computing
    // each expensive scan once keeps a 128-range request from doing 128 full
    // table scans. Per-probe validation still runs before a cache hit.
    let mut summaries: HashMap<String, Reply> = HashMap::new();
    let mut pages: HashMap<(String, Option<[u8; 32]>, usize), Reply> = HashMap::new();

    for p in req.ranges {
        let prefix = p.prefix.to_ascii_lowercase();
        prefix_bounds(&prefix)?;

        if p.ids_only {
            let after = match p.after.as_deref() {
                Some(s) => Some(parse_hex32(s).ok_or_else(|| "after must be 64 hex".to_string())?),
                None => None,
            };
            let limit = p
                .limit
                .unwrap_or(MAX_IDS_PER_REPLY as u32)
                .clamp(1, MAX_IDS_PER_REPLY as u32) as usize;
            let key = (prefix.clone(), after, limit);
            if let Some(reply) = pages.get(&key) {
                replies.push(reply.clone());
                continue;
            }
            let (ids, next) = ids_page(c, kind, &prefix, after, limit, now)?;
            let reply = Reply {
                prefix,
                count: None,
                fp: None,
                ids: Some(ids.iter().map(hex32).collect()),
                next: next.map(|x| hex32(&x)),
            };
            pages.insert(key, reply.clone());
            replies.push(reply);
            continue;
        }

        let claimed_count = p.count.unwrap_or(0);
        if let Some(ids) = &p.ids {
            if ids.len() as u64 > LEAF_KEYS as u64 {
                return Err(format!("at most {LEAF_KEYS} leaf ids are allowed"));
            }
            if ids.len() as u64 != claimed_count {
                return Err("leaf count does not match ids length".into());
            }
            for id in ids {
                let key = parse_hex32(id).ok_or_else(|| "leaf ids must be 64 hex".to_string())?;
                if !in_prefix(&key, &prefix)? {
                    return Err(format!("leaf id `{id}` is outside prefix `{prefix}`"));
                }
            }
        }
        if let Some(reply) = summaries.get(&prefix) {
            replies.push(reply.clone());
            continue;
        }
        // The caller's `fp` is not trusted for storage decisions; we just
        // return our own exact summary for the same range.
        let s = summary(c, kind, &prefix, now)?;
        let reply = Reply {
            prefix: prefix.clone(),
            count: Some(s.count),
            fp: if s.count > 0 { Some(s.fp_b64()) } else { None },
            ids: if s.count <= LEAF_KEYS as u64 {
                Some(s.ids.unwrap_or_default().iter().map(hex32).collect())
            } else {
                None
            },
            next: None,
        };
        summaries.insert(prefix, reply.clone());
        replies.push(reply);
    }

    serde_json::to_value(WireResponse {
        v: PROTOCOL_V,
        kind: kind.as_str().to_string(),
        ranges: replies,
    })
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memdb() -> rusqlite::Connection {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();
        c
    }

    fn insert_event(c: &rusqlite::Connection, id: [u8; 32], size: i64) {
        c.execute(
            "INSERT INTO events(id,owner,collection,created_at,expires_at,data,labels,size,state)
             VALUES (?1,?2,'c',1,9999999999,x'7b7d','[]',?3,'live')",
            rusqlite::params![&id[..], &[0u8; 32], size],
        )
        .unwrap();
    }

    #[test]
    fn prefix_bounds_cover_nibbles() {
        let (lo, hi) = prefix_bounds("").unwrap();
        assert_eq!(lo, [0u8; 32]);
        assert_eq!(hi, [0xff; 32]);

        let (lo, hi) = prefix_bounds("a").unwrap();
        assert_eq!(lo[0], 0xa0);
        assert_eq!(hi[0], 0xaf);
        assert_eq!(lo[1], 0x00);
        assert_eq!(hi[31], 0xff);

        let (lo, hi) = prefix_bounds("ab").unwrap();
        assert_eq!(lo[0], 0xab);
        assert_eq!(hi[0], 0xab);
        assert_eq!(lo[1], 0x00);
        assert_eq!(hi[1], 0xff);

        assert!(prefix_bounds("xyz").is_err());
        assert!(prefix_bounds(&"a".repeat(65)).is_err());
    }

    #[test]
    fn summary_and_ids_page_are_prefix_exact() {
        let c = memdb();
        let mut a = [0u8; 32];
        a[0] = 0xa1;
        let mut b = [0u8; 32];
        b[0] = 0xa2;
        let mut other = [0u8; 32];
        other[0] = 0xb1;
        insert_event(&c, a, 1);
        insert_event(&c, b, 1);
        insert_event(&c, other, 1);

        let s = summary(&c, Kind::Events, "a", 1000).unwrap();
        assert_eq!(s.count, 2);
        assert_eq!(s.ids.as_ref().unwrap().len(), 2);
        let (page, next) = ids_page(&c, Kind::Events, "a", None, 1, 1000).unwrap();
        assert_eq!(page, vec![a]);
        assert!(next.is_some());
        let (page2, next2) = ids_page(&c, Kind::Events, "a", next, 1, 1000).unwrap();
        assert_eq!(page2, vec![b]);
        assert!(next2.is_none());

        let empty = summary(&c, Kind::Events, "c", 1000).unwrap();
        assert_eq!(empty.count, 0);
        assert_eq!(empty.ids.unwrap().len(), 0);
    }

    #[test]
    fn summary_changes_with_a_key_and_binds_kind_prefix() {
        let c = memdb();
        let mut a = [0u8; 32];
        a[0] = 0x11;
        let before = summary(&c, Kind::Events, "", 1000).unwrap();
        insert_event(&c, a, 1);
        let after = summary(&c, Kind::Events, "", 1000).unwrap();
        assert_ne!(before.fp, after.fp);
        assert_eq!(before.count, 0);
        assert_eq!(after.count, 1);

        let blob_like = summary(&c, Kind::Blobs, "1", 1000).unwrap();
        assert_eq!(blob_like.count, 0);
    }

    #[test]
    fn blob_summaries_only_include_referenced_live_blobs() {
        let c = memdb();
        let mut blob = [0u8; 32];
        blob[0] = 0x11;
        let mut event = [0u8; 32];
        event[0] = 0x22;
        c.execute(
            "INSERT INTO blobs(hash,size,stored_at,ever_attached,state)
             VALUES (?1,10,1,0,'live')",
            [&blob[..]],
        )
        .unwrap();

        let s = summary(&c, Kind::Blobs, "", 1000).unwrap();
        assert_eq!(s.count, 0, "unreferenced blob was advertised");
        let (page, _) = ids_page(&c, Kind::Blobs, "", None, 10, 1000).unwrap();
        assert!(page.is_empty());

        insert_event(&c, event, 10);
        c.execute(
            "INSERT INTO refs(event_id,blob_hash) VALUES (?1,?2)",
            [&event[..], &blob[..]],
        )
        .unwrap();
        let s = summary(&c, Kind::Blobs, "", 1000).unwrap();
        assert_eq!(s.count, 1);
        let (page, _) = ids_page(&c, Kind::Blobs, "", None, 10, 1000).unwrap();
        assert_eq!(page, vec![blob]);

        // An expired event no longer keeps its blob in the sync keyspace.
        c.execute("UPDATE events SET expires_at = 999 WHERE id = ?1", [&event[..]])
            .unwrap();
        let s = summary(&c, Kind::Blobs, "", 1000).unwrap();
        assert_eq!(s.count, 0);
    }

    #[test]
    fn handle_dedupes_repeated_ranges_but_validates_each() {
        let c = memdb();
        let mut id = [0u8; 32];
        id[0] = 0x7a;
        insert_event(&c, id, 1);
        let mut outside = [0u8; 32];
        outside[0] = 0x8a;

        let body = serde_json::json!({
            "v": PROTOCOL_V,
            "kind": "events",
            "ranges": [
                {"prefix": "7", "count": 1, "ids": [hex32(&id)]},
                {"prefix": "7", "count": 0},
                {"prefix": "7", "ids_only": true, "limit": 10},
                {"prefix": "7", "ids_only": true, "limit": 10}
            ]
        });
        let out = handle(&c, &serde_json::to_vec(&body).unwrap(), 1000).unwrap();
        let ranges = out["ranges"].as_array().unwrap();
        assert_eq!(ranges.len(), 4);
        assert_eq!(ranges[0]["count"], 1);
        assert_eq!(ranges[1]["count"], 1);
        assert_eq!(ranges[0]["fp"], ranges[1]["fp"]);
        assert_eq!(ranges[2], ranges[3]);

        // A cached summary must not bypass validation of this probe's ids.
        let bad = serde_json::json!({
            "v": PROTOCOL_V,
            "kind": "events",
            "ranges": [
                {"prefix": "7", "count": 1, "ids": [hex32(&id)]},
                {"prefix": "7", "count": 1, "ids": [hex32(&outside)]}
            ]
        });
        assert!(handle(&c, &serde_json::to_vec(&bad).unwrap(), 1000).is_err());
    }

    #[test]
    fn handle_returns_exact_reply_and_id_pages() {
        let c = memdb();
        let mut id = [0u8; 32];
        id[0] = 0x7a;
        insert_event(&c, id, 1);

        let body = serde_json::json!({
            "v": PROTOCOL_V,
            "kind": "events",
            "ranges": [
                {"prefix": "7", "count": 0},
                {"prefix": "7", "ids_only": true, "limit": 10}
            ]
        });
        let out = handle(&c, &serde_json::to_vec(&body).unwrap(), 1000).unwrap();
        assert_eq!(out["ranges"][0]["count"], 1);
        assert_eq!(out["ranges"][0]["ids"][0], hex32(&id));
        assert_eq!(out["ranges"][1]["ids"][0], hex32(&id));
        assert!(out["ranges"][1].get("next").is_none());
    }
}
