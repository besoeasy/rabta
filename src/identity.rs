//! Node identity: an ephemeral Ed25519 keypair generated at boot.
//!
//! This is identification, not authentication. Events remain owner-signed;
//! the node key never signs user data and is not an access control key.
//! Every node generates a fresh ephemeral keypair on start.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Where the node seed came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Generated for this process; changes on restart.
    Generated,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Generated => "generated",
        }
    }
}

#[derive(Clone)]
pub struct NodeIdentity {
    /// SHA-256 of the raw public key.
    pub node_id: [u8; 32],
    pub public_key: [u8; 32],
    pub source: Source,
    signing_key: Arc<SigningKey>,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id_hex())
            .field("public_key", &self.public_key_string())
            .field("source", &self.source)
            .finish()
    }
}

impl NodeIdentity {
    pub fn node_id_hex(&self) -> String {
        hex::encode(self.node_id)
    }

    pub fn public_key_string(&self) -> String {
        format!("ed25519:{}", hex::encode(self.public_key))
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }

    /// Generate an ephemeral identity for this process using OS randomness.
    pub fn generate() -> NodeIdentity {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .expect("OS randomness unavailable for node identity generation");
        Self::from_seed(&seed)
    }

    /// Deterministic seed identity (useful for testing).
    pub fn from_seed(seed: &[u8; 32]) -> NodeIdentity {
        let signing_key = Arc::new(SigningKey::from_bytes(seed));
        let public_key = signing_key.verifying_key().to_bytes();
        NodeIdentity {
            node_id: Sha256::digest(public_key).into(),
            public_key,
            source: Source::Generated,
            signing_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_seed_is_stable() {
        let first = NodeIdentity::from_seed(&[7u8; 32]);
        let second = NodeIdentity::from_seed(&[7u8; 32]);
        assert_eq!(first.source, Source::Generated);
        assert_eq!(first.source.as_str(), "generated");
        assert_eq!(first.node_id, second.node_id);
        assert_eq!(first.public_key, second.public_key);

        let digest: [u8; 32] = Sha256::digest(first.public_key).into();
        assert_eq!(first.node_id, digest);
        assert_eq!(
            first.public_key_string(),
            format!("ed25519:{}", hex::encode(first.public_key))
        );
        assert_eq!(first.node_id_hex(), hex::encode(first.node_id));
    }

    #[test]
    fn distinct_seeds_produce_distinct_nodes() {
        let a = NodeIdentity::from_seed(&[1u8; 32]);
        let b = NodeIdentity::from_seed(&[2u8; 32]);
        assert_ne!(a.node_id, b.node_id);
        assert_ne!(a.public_key, b.public_key);
    }

    #[test]
    fn generate_creates_fresh_ephemeral_identity() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        assert_eq!(a.source, Source::Generated);
        assert_eq!(a.source.as_str(), "generated");
        assert_ne!(a.node_id, b.node_id);
        assert_ne!(a.public_key, b.public_key);
    }
}
