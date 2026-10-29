use std::sync::OnceLock;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canon::digest_value;
use crate::db::{MAX_ENVELOPE, MAX_TTL_SECONDS, MIN_TTL_SECONDS};
use crate::error::{ApiError, ApiResult};

/// Verified event — Clone so the async write transaction can own a copy.
#[derive(Clone)]
pub struct ParsedEvent {
    /// Claimed `id`, lowercase hex, verified to equal the digest.
    pub id_hex: String,
    pub id: [u8; 32],
    pub owner: [u8; 32],
    pub collection: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub labels: Vec<String>,
    pub blob: Option<[u8; 32]>,
    pub blob_hex: Option<String>,
    /// The envelope as we persist and serve it: canonical plus `id` + `sig`.
    pub served_bytes: Vec<u8>,
    pub size: usize,
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn collection_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9/_-]{1,32}$").unwrap())
}

fn label_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9:_\.\-\+\/]{1,64}$").unwrap())
}

/// Full publish-time validation of one envelope (plan.md §Wire format §Events):
/// shape → TTL window → canonical digest → id claim cross-check → sig verify.
/// The received body must be ≤ 100 KB; unknown extra fields are ignored and
/// not persisted (they were never digested).
pub fn parse_and_verify(body: &[u8], now: i64) -> ApiResult<ParsedEvent> {
    if body.len() > MAX_ENVELOPE {
        return Err(ApiError::too_large(format!(
            "event envelope exceeds 100 KB (got {} bytes)",
            body.len()
        )));
    }

    let v: Value = serde_json::from_slice(body)
        .map_err(|e| ApiError::bad_json(format!("envelope is not valid JSON: {e}")))?;
    let obj = v.as_object().ok_or_else(|| ApiError::bad_json("envelope must be a JSON object"))?;

    // ---- decode fields -------------------------------------------------
    let id_claim = get_str(obj, "id").ok_or_else(|| ApiError::bad_sig("envelope has no id"))?;
    if !(id_claim.len() == 64 && is_hex(id_claim)) {
        return Err(ApiError::bad_sig("id must be 64 hex characters"));
    }
    let sig_hex = get_str(obj, "sig").ok_or_else(|| ApiError::bad_sig("envelope has no sig"))?;
    if !(sig_hex.len() == 128 && is_hex(sig_hex)) {
        return Err(ApiError::bad_sig("sig must be 128 hex characters"));
    }

    let owner_str = get_str(obj, "owner").ok_or_else(|| ApiError::bad_sig("envelope has no owner"))?;
    let Some(owner_hex_part) = owner_str.strip_prefix("ed25519:") else {
        return Err(ApiError::bad_sig(
            "owner must be `ed25519:<64-hex pubkey>` (ed25519 is the only algorithm; the prefix is the forward-extension point)",
        ));
    };
    if !(owner_hex_part.len() == 64 && is_hex(owner_hex_part)) {
        return Err(ApiError::bad_sig("owner pubkey must be 64 hex characters"));
    }
    let owner_bytes = hex::decode(owner_hex_part).expect("checked hex");
    let owner: [u8; 32] = owner_bytes.try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&owner)
        .map_err(|_| ApiError::bad_sig("owner is not a valid ed25519 public key"))?;
    let owner_canon = format!("ed25519:{}", owner_hex_part.to_ascii_lowercase());

    let collection = get_str(obj, "collection")
        .filter(|c| collection_re().is_match(c))
        .ok_or(ApiError::bad_collection())?;

    let created_at = obj
        .get("created_at")
        .and_then(Value::as_i64)
        .ok_or_else(|| ApiError::ttl_range("created_at must be an integer (unix seconds)"))?;
    let expires_at = obj
        .get("expires_at")
        .and_then(Value::as_i64)
        .ok_or_else(|| ApiError::ttl_range("expires_at must be an integer (unix seconds)"))?;

    let data = obj.get("data").ok_or_else(|| ApiError::bad_json("envelope has no data"))?;
    if !data.is_object() {
        return Err(ApiError::bad_json("data must be a JSON object"));
    }

    let Value::Array(labels_raw) = obj.get("labels").ok_or_else(|| ApiError::bad_label("envelope has no labels"))?
    else {
        return Err(ApiError::bad_label("labels must be an array of strings"));
    };
    if labels_raw.len() > 10 {
        return Err(ApiError::bad_label("more than 10 labels"));
    }
    let mut labels: Vec<String> = Vec::with_capacity(labels_raw.len());
    for l in labels_raw {
        match l.as_str() {
            Some(s) if label_re().is_match(s) => labels.push(s.to_string()),
            Some(s) => return Err(ApiError::bad_label(format!(
                "label `{s}` does not match the label shape rule"
            ))),
            None => return Err(ApiError::bad_label("labels must be strings")),
        }
    }

    // `blob`: optional; explicit JSON null counts as absent.
    let blob = match obj.get("blob") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            if !(s.len() == 64 && is_hex(s)) {
                return Err(ApiError::bad_blob("blob must be exactly one 64-hex sha256"));
            }
            Some(hex::decode(s).expect("checked hex"))
        }
        Some(_) => return Err(ApiError::bad_blob("blob must be a 64-hex sha256 string")),
    };
    let blob_hex = blob.as_ref().map(|b| hex::encode(b).to_ascii_lowercase());

    // ---- TTL window ----------------------------------------------------
    if created_at > now {
        return Err(ApiError::ttl_range(format!(
            "created_at is in the future ({created_at} > {now})"
        )));
    }
    if expires_at <= now {
        return Err(ApiError::ttl_range("expires_at is not in the future (dead on arrival)"));
    }
    let ttl = expires_at - created_at;
    if ttl <= MIN_TTL_SECONDS {
        return Err(ApiError::ttl_range(format!("ttl must be > {MIN_TTL_SECONDS}s and <= 365d")));
    }
    if ttl > MAX_TTL_SECONDS {
        return Err(ApiError::ttl_range("ttl exceeds max_age (365 days)"));
    }

    // ---- canonical digest + id claim + sig -----------------------------
    let canon_value = digest_value(
        collection,
        created_at,
        expires_at,
        &owner_canon,
        &labels,
        data,
        blob_hex.as_deref(),
    );
    let canon_bytes = crate::canon::canonical_value(&canon_value);
    let digest: [u8; 32] = Sha256::digest(&canon_bytes).into();
    let id_computed = hex::encode(digest);
    if id_claim.to_ascii_lowercase() != id_computed {
        return Err(ApiError::bad_sig("envelope does not hash to its claimed id"));
    }
    let sig_bytes = hex::decode(&sig_hex).expect("checked hex");
    let sig_bytes: [u8; 64] = sig_bytes.try_into().unwrap();
    verify_sig(digest, sig_bytes, &vk)?;

    // ---- persist-shaped envelope: canonical + (id, sig) ----------------
    let mut served = canon_value;
    if let Value::Object(m) = &mut served {
        m.insert("id".into(), Value::String(id_computed.clone()));
        m.insert("sig".into(), Value::String(sig_hex.to_ascii_lowercase()));
    }
    let served_bytes = crate::canon::canonical_value(&served);
    let size = served_bytes.len();

    Ok(ParsedEvent {
        id_hex: id_computed,
        id: digest,
        owner,
        collection: collection.to_string(),
        created_at,
        expires_at,
        labels,
        blob: blob.map(|b| b.try_into().unwrap()),
        blob_hex,
        served_bytes,
        size,
    })
}

fn verify_sig(digest: [u8; 32], sig: [u8; 64], vk: &VerifyingKey) -> ApiResult<()> {
    let sig = Signature::from_bytes(&sig);
    vk.verify(&digest, &sig)
        .map_err(|_| ApiError::bad_sig("signature does not verify"))
}

fn get_str<'a>(obj: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Value::as_str)
}

/// Insert a verified event. Idempotent by id (re-delivery is a no-op).
/// Returns `true` when a new row was written. The blob row + `refs` junction
/// are handled by the caller in the same transaction when this returns true.
pub fn insert_event(c: &rusqlite::Connection, ev: &ParsedEvent) -> rusqlite::Result<bool> {
    let exists: bool = c
        .query_row("SELECT 1 FROM events WHERE id = ?1", [&ev.id], |r| r.get::<_, i64>(0))
        .map(|_| true)
        .unwrap_or(false);
    if exists {
        return Ok(false);
    }

    let labels_json = serde_json::to_string(&ev.labels).unwrap();
    c.execute(
        "INSERT INTO events(id, owner, collection, created_at, expires_at, data, labels, size, mime, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'application/json', 'live')",
        rusqlite::params![
            &ev.id[..],
            &ev.owner[..],
            ev.collection,
            ev.created_at,
            ev.expires_at,
            &ev.served_bytes[..],
            labels_json,
            ev.size as i64
        ],
    )?;
    for l in &ev.labels {
        c.execute(
            "INSERT OR IGNORE INTO labels(event_id, label) VALUES (?1, ?2)",
            rusqlite::params![&ev.id[..], l],
        )?;
    }
    crate::db::bump_counters(c, ev.size as i64, 0);
    Ok(true)
}

// ---------------------------------------------------------------------------
// Listing / paging (events + SSE stream share the predicate builder)
// ---------------------------------------------------------------------------

/// Opaque page cursor: **base64url unpadded** of 8-byte BE `created_at` ++
/// 32-byte id — URL-query-safe by construction, no percent-encoding needed.
pub fn encode_cursor(created_at: i64, id: &[u8; 32]) -> String {
    use base64::Engine;
    let mut b = Vec::with_capacity(40);
    b.extend_from_slice(&created_at.to_be_bytes());
    b.extend_from_slice(id);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Decode a cursor produced by [`encode_cursor`]. One format, no fallbacks.
pub fn decode_cursor(s: &str) -> Option<(i64, [u8; 32])> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let raw = URL_SAFE_NO_PAD.decode(s.trim()).ok()?;
    if raw.len() != 40 {
        return None;
    }
    let mut at = [0u8; 8];
    at.copy_from_slice(&raw[..8]);
    let mut id = [0u8; 32];
    id.copy_from_slice(&raw[8..]);
    Some((i64::from_be_bytes(at), id))
}

#[derive(Debug, Default, Clone)]
pub struct ListFilters {
    pub collection: Option<String>,
    pub labels: Vec<String>,
    pub owner_hex: Option<String>,
    pub limit: u32,
}

#[derive(Debug, Clone)]
pub struct ListedRow {
    pub id: [u8; 32],
    pub rowid: i64,
    pub created_at: i64,
    pub served: Vec<u8>,
}

/// Send + clone-able bind value (rusqlite's boxed ToSql isn't Send).
#[derive(Debug, Clone)]
pub enum SqlParam {
    I(i64),
    S(String),
    B(Vec<u8>),
}

impl rusqlite::ToSql for SqlParam {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        use rusqlite::types::{ToSqlOutput, Value as SV, ValueRef};
        Ok(match self {
            SqlParam::I(v) => ToSqlOutput::Owned(SV::Integer(*v)),
            SqlParam::S(v) => ToSqlOutput::Borrowed(ValueRef::Text(v.as_bytes())),
            SqlParam::B(v) => ToSqlOutput::Borrowed(ValueRef::Blob(v)),
        })
    }
}

/// Push one bind and return its positional placeholder.
pub fn next_bind(binds: &mut Vec<SqlParam>, v: SqlParam) -> String {
    binds.push(v);
    format!("?{}", binds.len())
}

/// Shared WHERE predicate for the events table: live, not-expired, plus the
/// caller's filters. Positional binds; `?1` is always `now`.
pub fn build_predicate(f: &ListFilters, now: i64) -> (String, Vec<SqlParam>) {
    let mut sql = String::from("state='live' AND expires_at > ?1");
    let mut binds: Vec<SqlParam> = vec![SqlParam::I(now)];

    if let Some(col) = &f.collection {
        let p = next_bind(&mut binds, SqlParam::S(col.clone()));
        sql.push_str(&format!(" AND collection = {p}"));
    }
    if let Some(o) = &f.owner_hex {
        let ob = hex::decode(o).expect("owner validated upstream");
        let p = next_bind(&mut binds, SqlParam::B(ob));
        sql.push_str(&format!(" AND owner = {p}"));
    }
    if !f.labels.is_empty() {
        let mut placeholders = Vec::with_capacity(f.labels.len());
        for l in &f.labels {
            placeholders.push(next_bind(&mut binds, SqlParam::S(l.clone())));
        }
        sql.push_str(&format!(
            " AND id IN (SELECT event_id FROM labels WHERE label IN ({}) GROUP BY event_id HAVING COUNT(DISTINCT label) = {})",
            placeholders.join(","),
            f.labels.len()
        ));
    }
    (sql, binds)
}

/// List route finisher: cursor + deterministic order + limit.
/// Newer first; ties ordered by id DESC; cursor = (created_at, id) of the
/// last row on the previous page.
pub fn list_sql(
    mut pred: String,
    binds: &mut Vec<SqlParam>,
    cursor: Option<(i64, [u8; 32])>,
    limit: u32,
) -> String {
    if let Some((c, id)) = cursor {
        let p1 = next_bind(binds, SqlParam::I(c));
        let p2 = next_bind(binds, SqlParam::I(c));
        let p3 = next_bind(binds, SqlParam::B(id.to_vec()));
        pred.push_str(&format!(" AND (created_at < {p1} OR (created_at = {p2} AND id < {p3}))"));
    }
    let lim = next_bind(binds, SqlParam::I(limit as i64));
    pred.push_str(&format!(" ORDER BY created_at DESC, id DESC LIMIT {lim}"));
    pred
}

/// Run a SELECT over (rowid, id, created_at, data); `sql` = predicate + finishers.
pub fn run_list(
    c: &rusqlite::Connection,
    sql: &str,
    binds: &[SqlParam],
) -> rusqlite::Result<Vec<ListedRow>> {
    let full = format!("SELECT rowid, id, created_at, data FROM events WHERE {sql}");
    let refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b as &dyn rusqlite::ToSql).collect();
    let mut stmt = c.prepare(&full)?;
    let mut rows = stmt.query(refs.as_slice())?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let id_raw: Vec<u8> = r.get(1)?;
        let rowid: i64 = r.get(0)?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&id_raw);
        out.push(ListedRow {
            id,
            rowid,
            created_at: r.get(2)?,
            served: r.get(3)?,
        });
    }
    Ok(out)
}
