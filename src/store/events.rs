use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use serde::Deserialize;

use crate::canon::digest_value;
use crate::db::{MAX_BLOB_REFS, MAX_ENVELOPE, MAX_TTL_SECONDS, MIN_TTL_SECONDS};
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
    /// Blob references, in client order; empty means none. Stored in
    /// `blob_refs` so a live event can keep its blobs alive until it expires.
    pub blobs: Vec<String>,
    /// The envelope as we persist and serve it: canonical plus `id` + `sig`.
    pub served_bytes: Vec<u8>,
    pub size: usize,
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Blob references are exact lowercase SHA-256 hex, mirroring the blob routes.
fn is_blob_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_collection(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'/' | b'_' | b'-')
        })
}

fn valid_label(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'.' | b'-' | b'+' | b'/')
        })
}

/// Full publish-time validation of one envelope:
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
    let obj = v
        .as_object()
        .ok_or_else(|| ApiError::bad_json("envelope must be a JSON object"))?;

    // ---- decode fields -------------------------------------------------
    let id_claim = get_str(obj, "id").ok_or_else(|| ApiError::bad_sig("envelope has no id"))?;
    if !(id_claim.len() == 64 && is_hex(id_claim)) {
        return Err(ApiError::bad_sig("id must be 64 hex characters"));
    }
    let sig_hex = get_str(obj, "sig").ok_or_else(|| ApiError::bad_sig("envelope has no sig"))?;
    if !(sig_hex.len() == 128 && is_hex(sig_hex)) {
        return Err(ApiError::bad_sig("sig must be 128 hex characters"));
    }

    let owner_str =
        get_str(obj, "owner").ok_or_else(|| ApiError::bad_sig("envelope has no owner"))?;
    let Some(owner_hex_part) = owner_str.strip_prefix("ed25519:") else {
        return Err(ApiError::bad_sig(
            "owner must be `ed25519:<64-hex pubkey>` (ed25519 is the only algorithm; the prefix is the forward-extension point)",
        ));
    };
    if owner_hex_part.len() != 64 {
        return Err(ApiError::bad_sig("owner pubkey must be 64 hex characters"));
    }
    let mut owner = [0u8; 32];
    hex::decode_to_slice(owner_hex_part, &mut owner)
        .map_err(|_| ApiError::bad_sig("owner pubkey must be 64 hex characters"))?;
    let vk = VerifyingKey::from_bytes(&owner)
        .map_err(|_| ApiError::bad_sig("owner is not a valid ed25519 public key"))?;
    let owner_canon = format!("ed25519:{}", owner_hex_part.to_ascii_lowercase());

    let collection = get_str(obj, "collection")
        .filter(|c| valid_collection(c))
        .ok_or(ApiError::bad_collection())?;

    let created_at = obj
        .get("created_at")
        .and_then(Value::as_i64)
        .ok_or_else(|| ApiError::ttl_range("created_at must be an integer (unix seconds)"))?;
    let expires_at = obj
        .get("expires_at")
        .and_then(Value::as_i64)
        .ok_or_else(|| ApiError::ttl_range("expires_at must be an integer (unix seconds)"))?;

    let data = obj
        .get("data")
        .ok_or_else(|| ApiError::bad_json("envelope has no data"))?;
    if !data.is_object() {
        return Err(ApiError::bad_json("data must be a JSON object"));
    }

    let Value::Array(labels_raw) = obj
        .get("labels")
        .ok_or_else(|| ApiError::bad_label("envelope has no labels"))?
    else {
        return Err(ApiError::bad_label("labels must be an array of strings"));
    };
    if labels_raw.len() > 10 {
        return Err(ApiError::bad_label("more than 10 labels"));
    }
    let mut labels: Vec<String> = Vec::with_capacity(labels_raw.len());
    for l in labels_raw {
        match l.as_str() {
            Some(s) if valid_label(s) => labels.push(s.to_string()),
            Some(s) => {
                return Err(ApiError::bad_label(format!(
                    "label `{s}` does not match the label shape rule"
                )));
            }
            None => return Err(ApiError::bad_label("labels must be strings")),
        }
    }

    // ---- blob references ------------------------------------------------
    // Validated metadata: a live event keeps the named blobs until it expires.
    let blobs_raw = obj
        .get("blobs")
        .ok_or_else(|| ApiError::bad_blobs("envelope has no blobs"))?
        .as_array()
        .ok_or_else(|| ApiError::bad_blobs("blobs must be an array of strings"))?;
    if blobs_raw.len() > MAX_BLOB_REFS {
        return Err(ApiError::bad_blobs(format!(
            "more than {MAX_BLOB_REFS} blob references"
        )));
    }
    let mut blobs: Vec<String> = Vec::with_capacity(blobs_raw.len());
    for item in blobs_raw {
        let Some(s) = item.as_str() else {
            return Err(ApiError::bad_blobs("blobs must be an array of strings"));
        };
        if !is_blob_hash(s) {
            return Err(ApiError::bad_blobs(format!(
                "blob reference `{s}` must be 64 lowercase hex characters"
            )));
        }
        if blobs.iter().any(|prev| prev == s) {
            return Err(ApiError::bad_blobs("blobs contains a duplicate reference"));
        }
        blobs.push(s.to_string());
    }

    // ---- TTL window ----------------------------------------------------
    if created_at > now {
        return Err(ApiError::ttl_range(format!(
            "created_at is in the future ({created_at} > {now})"
        )));
    }
    if expires_at <= now {
        return Err(ApiError::ttl_range(
            "expires_at is not in the future (dead on arrival)",
        ));
    }
    let Some(ttl) = expires_at.checked_sub(created_at) else {
        return Err(ApiError::ttl_range("ttl is out of range"));
    };
    if ttl <= MIN_TTL_SECONDS {
        return Err(ApiError::ttl_range(format!(
            "ttl must be > {MIN_TTL_SECONDS}s and <= {}d",
            MAX_TTL_SECONDS / 86400
        )));
    }
    if ttl > MAX_TTL_SECONDS {
        return Err(ApiError::ttl_range(format!(
            "ttl exceeds max_age ({}d)",
            MAX_TTL_SECONDS / 86400
        )));
    }

    // ---- canonical digest + id claim + sig -----------------------------
    let canon_value = digest_value(
        collection,
        created_at,
        expires_at,
        &owner_canon,
        &labels,
        data,
        &blobs,
    );
    let canon_bytes = crate::canon::canonical_value(&canon_value);
    let digest: [u8; 32] = Sha256::digest(&canon_bytes).into();
    let id_computed = hex::encode(digest);
    if id_claim.to_ascii_lowercase() != id_computed {
        return Err(ApiError::bad_sig(
            "envelope does not hash to its claimed id",
        ));
    }
    let mut sig_bytes = [0u8; 64];
    hex::decode_to_slice(sig_hex, &mut sig_bytes)
        .map_err(|_| ApiError::bad_sig("sig must be 128 hex characters"))?;
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
        blobs,
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

/// Bytes that a new event would add to the combined budget by claiming
/// existing blobs. Blobs already claimed by another live event, missing
/// blobs, and dangling hashes add nothing.
pub fn new_claim_bytes(c: &rusqlite::Connection, blobs: &[String]) -> rusqlite::Result<i64> {
    let mut total = 0i64;
    for hash_hex in blobs {
        let mut hash = [0u8; 32];
        if hex::decode_to_slice(hash_hex, &mut hash).is_err() {
            continue;
        }
        if crate::store::blobs::blob_is_claimed(c, &hash)? {
            continue;
        }
        let size: Option<i64> = c
            .query_row("SELECT size FROM blobs WHERE hash = ?1", [&hash[..]], |r| {
                r.get(0)
            })
            .ok();
        total = total.saturating_add(size.unwrap_or(0));
    }
    Ok(total)
}

/// Global monotonic store mutation version counter.
/// Bumped whenever a new event is inserted or an existing event is deleted.
/// Used for zero-cost HTTP 304 Not Modified fast-path caching.
pub static EVENT_STATE_VERSION: AtomicU64 = AtomicU64::new(1);

#[inline]
pub fn bump_event_version() {
    EVENT_STATE_VERSION.fetch_add(1, Ordering::SeqCst);
}

#[inline]
pub fn current_event_version() -> u64 {
    EVENT_STATE_VERSION.load(Ordering::SeqCst)
}

/// Insert a verified event. Idempotent by id (re-delivery is a no-op).
/// Returns `true` when a new row was written. Blobs are stored separately, but
/// a live event's `blobs` references keep the named blobs until the event
/// expires and charge their bytes to the shared budget.
pub fn insert_event(c: &rusqlite::Connection, ev: &ParsedEvent) -> rusqlite::Result<bool> {
    if event_exists(c, &ev.id)? {
        return Ok(false);
    }

    c.execute(
        "INSERT INTO events(id, owner, collection, created_at, expires_at, data, size)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            &ev.id[..],
            &ev.owner[..],
            ev.collection,
            ev.created_at,
            ev.expires_at,
            &ev.served_bytes[..],
            ev.size as i64
        ],
    )?;
    for l in &ev.labels {
        c.execute(
            "INSERT OR IGNORE INTO labels(event_id, label) VALUES (?1, ?2)",
            rusqlite::params![&ev.id[..], l],
        )?;
    }
    for hash_hex in &ev.blobs {
        let mut hash = [0u8; 32];
        if hex::decode_to_slice(hash_hex, &mut hash).is_err() {
            continue;
        }
        let was_claimed = crate::store::blobs::blob_is_claimed(c, &hash)?;
        c.execute(
            "INSERT OR IGNORE INTO blob_refs(hash, event_id) VALUES (?1, ?2)",
            rusqlite::params![&hash[..], &ev.id[..]],
        )?;
        if !was_claimed {
            let size: Option<i64> = c
                .query_row("SELECT size FROM blobs WHERE hash = ?1", [&hash[..]], |r| {
                    r.get(0)
                })
                .ok();
            if let Some(size) = size {
                crate::db::bump_counters(c, 0, 0, size)?;
            }
        }
        crate::store::blobs::refresh_blob_expiry(c, &hash)?;
    }
    crate::db::bump_counters(c, ev.size as i64, 0, 0)?;
    bump_event_version();
    Ok(true)
}

/// Delete events rows (+ labels, refs, counters) for the given raw ids. Caller
/// owns the transaction boundary.
pub fn delete_events(c: &rusqlite::Connection, ids: &[[u8; 32]]) -> rusqlite::Result<i64> {
    let mut freed = 0i64;
    let mut deleted_any = false;
    for id in ids {
        let size: i64 = c.query_row("SELECT size FROM events WHERE id = ?1", [id], |r| r.get(0))?;

        // Capture the blobs this event was keeping alive, drop its refs, then
        // re-derive each deadline from the remaining live events.
        let mut hashes: Vec<[u8; 32]> = Vec::new();
        {
            let mut stmt = c.prepare("SELECT hash FROM blob_refs WHERE event_id = ?1")?;
            let mut rows = stmt.query([id])?;
            while let Some(r) = rows.next()? {
                let h: Vec<u8> = r.get(0)?;
                if let Ok(hash) = h.try_into() {
                    hashes.push(hash);
                }
            }
        }
        c.execute("DELETE FROM blob_refs WHERE event_id = ?1", [id])?;

        let n = c.execute("DELETE FROM events WHERE id = ?1", [id])?;
        if n == 0 {
            continue;
        }
        deleted_any = true;
        c.execute("DELETE FROM labels WHERE event_id = ?1", [id])?;
        for h in &hashes {
            crate::store::blobs::refresh_blob_expiry(c, h)?;
            if !crate::store::blobs::blob_is_claimed(c, h)? {
                let size: Option<i64> = c
                    .query_row("SELECT size FROM blobs WHERE hash = ?1", [&h[..]], |r| {
                        r.get(0)
                    })
                    .ok();
                if let Some(size) = size {
                    crate::db::bump_counters(c, 0, 0, -size)?;
                }
            }
        }
        crate::db::bump_counters(c, -size, 0, 0)?;
        freed += size;
    }
    if deleted_any {
        bump_event_version();
    }
    Ok(freed)
}

pub fn event_exists(c: &rusqlite::Connection, id: &[u8; 32]) -> rusqlite::Result<bool> {
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM events WHERE id = ?1)",
        [id],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n != 0)
}

// ---------------------------------------------------------------------------
// Listing / paging (typed POST query)
// ---------------------------------------------------------------------------

/// Opaque page cursor: **base64url unpadded** of 8-byte BE `created_at` ++ 32-byte id.
pub fn encode_cursor(created_at: i64, id: &[u8; 32]) -> String {
    use base64::Engine;
    let mut b = Vec::with_capacity(40);
    b.extend_from_slice(&created_at.to_be_bytes());
    b.extend_from_slice(id);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Decode a cursor produced by [`encode_cursor`]. One format, no fallbacks.
pub fn decode_cursor(s: &str) -> Option<(i64, [u8; 32])> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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

/// Half-open time range `[gte, lt)` on a unix-seconds column. Either bound
/// may be absent; the route layer rejects ranges that bind neither side.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeRange {
    pub gte: Option<i64>,
    pub lt: Option<i64>,
}

#[derive(Debug, Default, Clone)]
pub struct ListFilters {
    pub collection: Option<String>,
    /// Wildcard collection match (`*` = zero-or-more, `?` = one char).
    /// Mutually exclusive with `collection`: the route layer guarantees only
    /// one is set.
    pub collection_glob: Option<String>,
    pub labels: Vec<String>,
    pub owner_hex: Option<String>,
    pub limit: u32,
    pub created_at: TimeRange,
    pub expires_at: TimeRange,
}

#[derive(Debug, Clone)]
pub struct ListedRow {
    pub id: [u8; 32],
    pub created_at: i64,
    pub expires_at: i64,
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

/// Single source of the liveness rule for events: a row is readable — by the
/// public reads and by peer reconciliation alike — only while unexpired.
/// `bind` is the 1-based positional placeholder for `now`.
pub fn live_clause(bind: usize) -> String {
    format!("expires_at > ?{bind}")
}

/// Shared WHERE predicate for the events table: live, not-expired, plus the
/// caller's filters. Positional binds; `?1` is always `now`.
pub fn build_predicate(f: &ListFilters, now: i64) -> (String, Vec<SqlParam>) {
    let mut sql = live_clause(1);
    let mut binds: Vec<SqlParam> = vec![SqlParam::I(now)];

    if let Some(col) = &f.collection {
        let p = next_bind(&mut binds, SqlParam::S(col.clone()));
        sql.push_str(&format!(" AND collection = {p}"));
    } else if let Some(pat) = &f.collection_glob {
        push_collection_glob(&mut sql, &mut binds, pat);
    }
    if let Some(o) = &f.owner_hex
        && let Ok(ob) = hex::decode(o)
    {
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
    push_time_range(&mut sql, &mut binds, "created_at", &f.created_at);
    push_time_range(&mut sql, &mut binds, "expires_at", &f.expires_at);
    (sql, binds)
}

/// Half-open `[gte, lt)` clause on a unix-seconds column. Bounds are validated
/// by the route layer (at least one bound, `gte < lt`); this only emits SQL.
fn push_time_range(sql: &mut String, binds: &mut Vec<SqlParam>, col: &str, r: &TimeRange) {
    if let Some(v) = r.gte {
        let p = next_bind(binds, SqlParam::I(v));
        sql.push_str(&format!(" AND {col} >= {p}"));
    }
    if let Some(v) = r.lt {
        let p = next_bind(binds, SqlParam::I(v));
        sql.push_str(&format!(" AND {col} < {p}"));
    }
}

/// First byte offset of `pat`'s first metacharacter (`*` / `?`), or the whole
/// length. Everything before it is an indexable literal prefix (route
/// validation keeps the charset ASCII, so byte offsets are char boundaries).
fn glob_literal_len(pat: &str) -> usize {
    pat.bytes()
        .position(|b| b == b'*' || b == b'?')
        .unwrap_or(pat.len())
}

/// Shortest string strictly greater than every string starting with
/// `prefix`, for the validated printable-ASCII collection charset.
fn excl_upper(prefix: &str) -> Option<String> {
    let mut b = prefix.as_bytes().to_vec();
    let last = b.last_mut()?;
    if *last >= 0x7f {
        return None;
    }
    *last += 1;
    String::from_utf8(b).ok()
}

/// Wildcard `collection` filter: bounds derived from the constant prefix keep
/// the scan index-shaped, and the meta tail becomes a residual GLOB. A
/// pattern that opens with a metacharacter gets no bounds (live-row scan).
fn push_collection_glob(sql: &mut String, binds: &mut Vec<SqlParam>, pat: &str) {
    let lit = pat.get(..glob_literal_len(pat)).unwrap_or(pat);
    if !lit.is_empty() {
        let lo = next_bind(binds, SqlParam::S(lit.to_string()));
        sql.push_str(&format!(" AND collection >= {lo}"));
        if let Some(hi) = excl_upper(lit) {
            let p = next_bind(binds, SqlParam::S(hi));
            sql.push_str(&format!(" AND collection < {p}"));
        }
    }
    let g = next_bind(binds, SqlParam::S(pat.to_string()));
    sql.push_str(&format!(" AND collection GLOB {g}"));
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
        pred.push_str(&format!(
            " AND (created_at < {p1} OR (created_at = {p2} AND id < {p3}))"
        ));
    }
    let lim = next_bind(binds, SqlParam::I(limit as i64));
    pred.push_str(&format!(" ORDER BY created_at DESC, id DESC LIMIT {lim}"));
    pred
}

/// Run a SELECT over (id, created_at, data); `sql` = predicate + finishers.
pub fn run_list(
    c: &rusqlite::Connection,
    sql: &str,
    binds: &[SqlParam],
) -> rusqlite::Result<Vec<ListedRow>> {
    let full = format!("SELECT id, created_at, expires_at, data FROM events WHERE {sql}");
    let refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b as &dyn rusqlite::ToSql).collect();
    let mut stmt = c.prepare(&full)?;
    let mut rows = stmt.query(refs.as_slice())?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let id_raw: Vec<u8> = r.get(0)?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&id_raw);
        out.push(ListedRow {
            id,
            created_at: r.get(1)?,
            expires_at: r.get(2)?,
            served: r.get(3)?,
        });
    }
    Ok(out)
}

/// Run `SELECT COUNT(*)` over the predicate alone: no envelope bytes leave the
/// store and no paging applies. Pair with [`build_predicate`].
pub fn run_count(
    c: &rusqlite::Connection,
    pred: &str,
    binds: &[SqlParam],
) -> rusqlite::Result<i64> {
    let full = format!("SELECT COUNT(*) FROM events WHERE {pred}");
    let refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b as &dyn rusqlite::ToSql).collect();
    c.query_row(&full, refs.as_slice(), |r| r.get(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_event(id_byte: u8) -> ParsedEvent {
        ParsedEvent {
            id_hex: format!("{id_byte:02x}").repeat(32),
            id: [id_byte; 32],
            owner: [7u8; 32],
            collection: "test".into(),
            created_at: 1,
            expires_at: 9_999_999_999,
            labels: vec!["team".into()],
            blobs: vec![],
            served_bytes: br#"{"collection":"test"}"#.to_vec(),
            size: 21,
        }
    }

    #[test]
    fn duplicate_reinsert_is_idempotent() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        let ev = test_event(1);
        assert!(insert_event(&c, &ev).unwrap());
        assert!(
            !insert_event(&c, &ev).unwrap(),
            "duplicate wrote a second row"
        );
        let rows: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(crate::db::live_bytes(&c), (ev.size as i64, 0));
    }

    #[test]
    fn time_range_predicate_bounds_count() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        let insert = |id: u8, created: i64, expires: i64| {
            c.execute(
                "INSERT INTO events(id,owner,collection,created_at,expires_at,data,size)
                 VALUES (?1,?2,'chat',?3,?4,x'7b7d',2)",
                rusqlite::params![&[id; 32][..], &[9u8; 32], created, expires],
            )
            .unwrap();
        };
        insert(1, 100, 9_999_999_999);
        insert(2, 200, 9_999_999_999);
        insert(3, 300, 9_999_999_999);
        insert(4, 200, 0); // already expired

        let filters = |created_at: TimeRange| ListFilters {
            collection: Some("chat".into()),
            created_at,
            ..Default::default()
        };
        let now = 0;
        let count = |f: &ListFilters| -> i64 {
            let (pred, binds) = build_predicate(f, now);
            run_count(&c, &pred, &binds).unwrap()
        };

        assert_eq!(
            count(&filters(Default::default())),
            3,
            "expired row counted"
        );
        // [gte, lt): bucket boundaries never overlap.
        assert_eq!(
            count(&filters(TimeRange {
                gte: Some(100),
                lt: Some(200)
            })),
            1
        );
        assert_eq!(
            count(&filters(TimeRange {
                gte: Some(200),
                lt: None
            })),
            2
        );
        assert_eq!(
            count(&filters(TimeRange {
                gte: None,
                lt: Some(200)
            })),
            1
        );
        assert_eq!(
            count(&filters(TimeRange {
                gte: Some(400),
                lt: Some(500)
            })),
            0
        );
    }

    #[test]
    fn collection_glob_predicate_matches_subtrees() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        for (i, col) in ["chat/room-42", "chat/room-43", "sensor/temp-east"]
            .iter()
            .enumerate()
        {
            c.execute(
                "INSERT INTO events(id,owner,collection,created_at,expires_at,data,size)
                 VALUES (?1,?2,?3,10,9999999999,x'7b7d',2)",
                rusqlite::params![&[i as u8 + 1; 32][..], &[9u8; 32], col],
            )
            .unwrap();
        }

        let count = |pat: &str| -> i64 {
            let f = ListFilters {
                collection_glob: Some(pat.into()),
                ..Default::default()
            };
            let (pred, binds) = build_predicate(&f, 0);
            run_count(&c, &pred, &binds).unwrap()
        };

        // Subtree: `*` matches zero or more chars after the literal prefix.
        assert_eq!(count("chat/*"), 2);
        // Mid-pattern: literal prefix still bounds the scan.
        assert_eq!(count("chat/room-4?"), 2);
        assert_eq!(count("sens*r/*"), 1);
        // Meta-free pattern is a plain equality; no such row.
        assert_eq!(count("chat/room-4"), 0);
        assert_eq!(count("chat/room-42"), 1);
        assert_eq!(count("chat"), 0);
        // Leading metacharacters drop the index bounds but the count holds.
        assert_eq!(count("*"), 3);
        assert_eq!(count("?hat/*"), 2);
    }

    #[test]
    fn blob_reference_controls_blob_expiry() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        let stored_at = 1_700_000_000i64;
        let hash = [0xabu8; 32];
        let hash_hex = hex::encode(hash);
        let unclaimed = stored_at + crate::db::BLOB_UNCLAIMED_TTL_SECONDS;
        c.execute(
            "INSERT INTO blobs(hash, size, stored_at, expires_at)
             VALUES (?1, 4, ?2, ?3)",
            rusqlite::params![&hash[..], stored_at, unclaimed],
        )
        .unwrap();

        let expiry = |c: &rusqlite::Connection| -> i64 {
            c.query_row(
                "SELECT expires_at FROM blobs WHERE hash = ?1",
                [&hash[..]],
                |r| r.get(0),
            )
            .unwrap()
        };

        // A short event pulls the blob down to its own expiry.
        let mut short = test_event(3);
        short.expires_at = stored_at + 5_000;
        short.blobs = vec![hash_hex.clone()];
        assert!(insert_event(&c, &short).unwrap());
        assert_eq!(expiry(&c), stored_at + 5_000);

        // The longest-lived referencing event wins.
        let mut long = test_event(4);
        long.expires_at = stored_at + 9_000;
        long.blobs = vec![hash_hex.clone()];
        assert!(insert_event(&c, &long).unwrap());
        assert_eq!(expiry(&c), stored_at + 9_000);

        // Removing it falls back to the remaining event.
        delete_events(&c, &[long.id]).unwrap();
        assert_eq!(expiry(&c), stored_at + 5_000);

        // With no live references the 6-hour unclaimed window applies again.
        delete_events(&c, &[short.id]).unwrap();
        assert_eq!(expiry(&c), unclaimed);
        let refs: i64 = c
            .query_row("SELECT COUNT(*) FROM blob_refs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(refs, 0, "deleted events left blob references behind");
    }

    #[test]
    fn event_row_and_counters_roll_back_when_labels_fail() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();
        c.execute_batch(
            "CREATE TRIGGER fail_label BEFORE INSERT ON labels
             BEGIN SELECT RAISE(ABORT, 'boom'); END;",
        )
        .unwrap();

        let ev = test_event(2);
        // `insert_event` is a transaction body: the caller owns the boundary.
        let tx = c.unchecked_transaction().unwrap();
        assert!(insert_event(&tx, &ev).is_err());
        drop(tx); // roll back

        let rows: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "partial event row survived a failed insert");
        assert_eq!(crate::db::live_bytes(&c), (0, 0));
    }

    #[test]
    fn failed_admission_rolls_back_eviction() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        let old_id = [1u8; 32];
        c.execute(
            "INSERT INTO events(id,owner,collection,created_at,expires_at,data,size)
             VALUES (?1,?2,'c',1,9999999999,x'7b7d',90)",
            rusqlite::params![&old_id[..], &[0u8; 32]],
        )
        .unwrap();
        crate::db::bump_counters(&c, 90, 0, 0).unwrap();

        let dir = std::env::temp_dir().join(format!(
            "rabta-admission-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = crate::config::Config::test_cfg(dir.clone(), 100);

        c.execute_batch(
            "CREATE TRIGGER fail_label BEFORE INSERT ON labels
             BEGIN SELECT RAISE(ABORT, 'boom'); END;",
        )
        .unwrap();

        let tx = c.unchecked_transaction().unwrap();
        crate::store::reaper::event_pressure_check(&tx, &cfg, 10).unwrap();
        let ev = test_event(2);
        assert!(insert_event(&tx, &ev).is_err());
        drop(tx); // rollback

        let old: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM events WHERE id=?1",
                [&old_id[..]],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(old, 1, "eviction survived a failed admission");
        assert_eq!(crate::db::live_bytes(&c), (90, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ttl_subtraction_overflow_is_rejected_not_panicking() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let owner = format!("ed25519:{}", hex::encode(key.verifying_key().to_bytes()));
        let envelope = serde_json::json!({
            "id": "00".repeat(32),
            "sig": "00".repeat(64),
            "owner": owner,
            "collection": "test",
            "created_at": i64::MIN,
            "expires_at": i64::MAX,
            "data": {},
            "labels": [],
            "blobs": [],
        });
        let err = match parse_and_verify(&serde_json::to_vec(&envelope).unwrap(), 100) {
            Ok(_) => panic!("overflowing ttl was accepted"),
            Err(e) => e,
        };
        assert_eq!(err.code, "ttl_range");
    }

    fn signed_envelope(created_at: i64, expires_at: i64) -> Vec<u8> {
        signed_envelope_blobs(created_at, expires_at, &[])
    }

    fn signed_envelope_blobs(created_at: i64, expires_at: i64, blobs: &[String]) -> Vec<u8> {
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let owner = format!("ed25519:{}", hex::encode(key.verifying_key().to_bytes()));
        let data = serde_json::json!({ "n": 1 });
        let canonical =
            crate::canon::digest_value("test", created_at, expires_at, &owner, &[], &data, blobs);
        let digest: [u8; 32] = Sha256::digest(crate::canon::canonical_value(&canonical)).into();
        let sig = key.sign(&digest);
        let envelope = serde_json::json!({
            "collection": "test",
            "created_at": created_at,
            "data": data,
            "expires_at": expires_at,
            "labels": [],
            "blobs": blobs,
            "owner": owner,
            "id": hex::encode(digest),
            "sig": hex::encode(sig.to_bytes()),
        });
        serde_json::to_vec(&envelope).unwrap()
    }

    /// Envelope with arbitrary `blobs` and otherwise-valid shape. Validation of
    /// `blobs` runs before the digest, so the id/sig can stay dummy values.
    fn envelope_with_blobs(blobs: Value) -> Vec<u8> {
        let now = 1_700_000_000;
        serde_json::to_vec(&serde_json::json!({
            "id": "00".repeat(32),
            "sig": "00".repeat(64),
            "owner": format!("ed25519:{}", "11".repeat(32)),
            "collection": "test",
            "created_at": now,
            "expires_at": now + 3600,
            "data": {},
            "labels": [],
            "blobs": blobs,
        }))
        .unwrap()
    }

    fn expect_bad_blobs(body: &[u8]) {
        let err = match parse_and_verify(body, 1_700_000_000) {
            Ok(_) => panic!("invalid blobs were accepted"),
            Err(e) => e,
        };
        assert_eq!(err.code, "bad_blobs", "unexpected error: {}", err.message);
    }

    #[test]
    fn blobs_round_trip_in_order_and_are_digested() {
        let now = 1_700_000_000;
        let blobs = vec!["b".repeat(64), "a".repeat(64)];
        let body = signed_envelope_blobs(now, now + 3600, &blobs);

        let parsed = parse_and_verify(&body, now).expect("valid blobs were rejected");
        let served: Value = serde_json::from_slice(&parsed.served_bytes).unwrap();
        let served_blobs: Vec<String> = served["blobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(served_blobs, blobs, "client order was not preserved");
        assert_eq!(served["id"].as_str().unwrap(), parsed.id_hex);
        assert_eq!(parsed.blobs, blobs);
    }

    #[test]
    fn blobs_reject_bad_shapes() {
        expect_bad_blobs(&envelope_with_blobs(serde_json::json!(
            (0..9).map(|i| format!("{i:064x}")).collect::<Vec<_>>()
        )));
        expect_bad_blobs(&envelope_with_blobs(serde_json::json!([
            "a".repeat(64),
            "a".repeat(64)
        ])));
        expect_bad_blobs(&envelope_with_blobs(serde_json::json!(["A".repeat(64)])));
        expect_bad_blobs(&envelope_with_blobs(serde_json::json!(["a".repeat(63)])));
        expect_bad_blobs(&envelope_with_blobs(serde_json::json!(["g".repeat(64)])));
        expect_bad_blobs(&envelope_with_blobs(serde_json::json!("a".repeat(64))));
        expect_bad_blobs(&envelope_with_blobs(serde_json::json!([1])));
    }

    #[test]
    fn blobs_are_required() {
        let now = 1_700_000_000;
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "00".repeat(32),
            "sig": "00".repeat(64),
            "owner": format!("ed25519:{}", "11".repeat(32)),
            "collection": "test",
            "created_at": now,
            "expires_at": now + 3600,
            "data": {},
            "labels": [],
        }))
        .unwrap();
        expect_bad_blobs(&body);
    }

    #[test]
    fn empty_blobs_are_valid_and_present() {
        let now = 1_700_000_000;
        let body = signed_envelope(now, now + 3600);
        let parsed = parse_and_verify(&body, now).expect("valid envelope was rejected");
        assert!(parsed.blobs.is_empty());
        let served: Value = serde_json::from_slice(&parsed.served_bytes).unwrap();
        assert_eq!(served["blobs"], serde_json::json!([]));
    }

    #[test]
    fn ttl_accepts_max_days_and_rejects_more() {
        let now = 1_700_000_000;
        let max_ttl = now + MAX_TTL_SECONDS;

        assert!(
            parse_and_verify(&signed_envelope(now, max_ttl), now).is_ok(),
            "max ttl was rejected"
        );

        let err = match parse_and_verify(&signed_envelope(now, max_ttl + 1), now) {
            Ok(_) => panic!("ttl beyond max was accepted"),
            Err(e) => e,
        };
        assert_eq!(err.code, "ttl_range");
    }
}
