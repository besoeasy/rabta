use axum::http::HeaderMap;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

use crate::error::{ApiError, ApiResult};
use crate::identity::NodeIdentity;

pub const TIMESTAMP_TOLERANCE_SECS: i64 = 60;

pub fn build_signature_string(timestamp: i64, nonce: &str, body_hash_hex: &str) -> String {
    format!("rabta-sync-v1\nPOST\n/api/v1/sync\n{timestamp}\n{nonce}\n{body_hash_hex}\n")
}

pub struct AuthenticatedPeer {
    pub peer_key_hex: String,
}

/// Verify request headers, Ed25519 signature, timestamp drift, and nonce freshness.
pub fn verify_sync_request(
    c: &Connection,
    headers: &HeaderMap,
    body: &[u8],
    now: i64,
) -> ApiResult<AuthenticatedPeer> {
    let node_header = headers
        .get("x-rabta-node")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing X-Rabta-Node header"))?;

    let peer_key_hex = node_header
        .strip_prefix("ed25519:")
        .ok_or_else(|| ApiError::unauthorized("X-Rabta-Node must be ed25519:<hex>"))?;

    if peer_key_hex.len() != 64 {
        return Err(ApiError::unauthorized("invalid node key length"));
    }
    let peer_key_bytes =
        hex::decode(peer_key_hex).map_err(|_| ApiError::unauthorized("invalid node key hex"))?;
    let peer_key: [u8; 32] = peer_key_bytes
        .try_into()
        .map_err(|_| ApiError::unauthorized("invalid node key bytes"))?;

    let timestamp_str = headers
        .get("x-rabta-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing X-Rabta-Timestamp header"))?;
    let timestamp: i64 = timestamp_str
        .parse()
        .map_err(|_| ApiError::unauthorized("invalid timestamp"))?;

    if (now - timestamp).abs() > TIMESTAMP_TOLERANCE_SECS {
        return Err(ApiError::unauthorized(
            "timestamp outside acceptable window",
        ));
    }

    let nonce_str = headers
        .get("x-rabta-nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing X-Rabta-Nonce header"))?;
    let nonce_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(nonce_str)
        .map_err(|_| ApiError::unauthorized("invalid base64url nonce"))?;
    if nonce_bytes.len() < 16 || nonce_bytes.len() > 64 {
        return Err(ApiError::unauthorized(
            "nonce length must be between 16 and 64 bytes",
        ));
    }

    // Opportunistically prune expired nonces
    let _ = c.execute(
        "DELETE FROM sync_nonces WHERE expires_at < ?1",
        params![now],
    );

    // Check nonce replay
    let replay_inserted = c.execute(
        "INSERT OR IGNORE INTO sync_nonces (peer_key, nonce, expires_at) VALUES (?1, ?2, ?3)",
        params![
            &peer_key[..],
            &nonce_bytes[..],
            now + TIMESTAMP_TOLERANCE_SECS
        ],
    );
    match replay_inserted {
        Ok(0) => return Err(ApiError::replay("nonce already seen")),
        Err(_) => return Err(ApiError::replay("nonce replay check failed")),
        _ => {}
    }

    let sig_str = headers
        .get("x-rabta-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing X-Rabta-Signature header"))?;
    let sig_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(sig_str)
        .map_err(|_| ApiError::bad_sig("invalid base64url signature"))?;
    if sig_bytes.len() != 64 {
        return Err(ApiError::bad_sig("signature must be 64 bytes"));
    }
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| ApiError::bad_sig("signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_array);

    let body_hash = Sha256::digest(body);
    let body_hash_hex = hex::encode(body_hash);
    let sig_input = build_signature_string(timestamp, nonce_str, &body_hash_hex);

    let vk = VerifyingKey::from_bytes(&peer_key)
        .map_err(|_| ApiError::bad_sig("invalid ed25519 verifying key"))?;

    vk.verify(sig_input.as_bytes(), &sig)
        .map_err(|_| ApiError::bad_sig("signature verification failed"))?;

    Ok(AuthenticatedPeer {
        peer_key_hex: peer_key_hex.to_lowercase(),
    })
}

/// Sign an outbound sync request and populate authentication headers.
pub fn create_signed_headers(
    identity: &NodeIdentity,
    body: &[u8],
    now: i64,
) -> Vec<(&'static str, String)> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).expect("random nonce");
    let nonce_b64 = BASE64_URL_SAFE_NO_PAD.encode(nonce);

    let body_hash = Sha256::digest(body);
    let body_hash_hex = hex::encode(body_hash);

    let sig_input = build_signature_string(now, &nonce_b64, &body_hash_hex);
    let sig = identity.sign(sig_input.as_bytes());
    let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(sig);

    vec![
        ("x-rabta-node", identity.public_key_string()),
        ("x-rabta-timestamp", now.to_string()),
        ("x-rabta-nonce", nonce_b64),
        ("x-rabta-signature", sig_b64),
        ("content-type", "application/json".to_string()),
    ]
}
