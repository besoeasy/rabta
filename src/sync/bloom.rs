use base64::Engine as _;
use serde::{Deserialize, Serialize};

pub const SEED_EVENTS: &str = "rabta-events-v2";
pub const SEED_BLOBS: &str = "rabta-blobs-v2";

/// One posted filter: type + sizing + base64 cells.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomFilterDto {
    #[serde(rename = "type")]
    pub ftype: String,
    pub count: u64,
    pub bits: u64,
    pub probes: u8,
    pub cells: String,
}

impl BloomFilterDto {
    /// Validate + decode cells (unpadded standard base64, the only form the
    /// peer plane emits).
    pub fn decode(&self) -> Result<(u64, Vec<u8>), String> {
        if self.ftype != "events" && self.ftype != "blobs" {
            return Err("filter.type must be `events` or `blobs`".into());
        }
        if self.probes != 4 {
            return Err("filter.probes must be 4".into());
        }
        if self.bits < 8192 || self.bits > 16_777_216 {
            return Err("filter.bits out of range (8192..=16777216)".into());
        }
        let b = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(self.cells.trim())
            .map_err(|_| "filter.cells is not valid base64".to_string())?;
        let want = self.bits / 8 + u64::from(self.bits % 8 != 0);
        if b.len() as u64 != want {
            return Err("filter.cells length does not match bits".into());
        }
        Ok((self.bits, b))
    }

    pub fn from_parts(ftype: &str, count: usize, bloom: &Bloom) -> Self {
        Self {
            ftype: ftype.to_string(),
            count: count as u64,
            bits: bloom.bits,
            probes: 4,
            cells: base64::engine::general_purpose::STANDARD_NO_PAD.encode(&bloom.cells),
        }
    }
}

/// A 4-probe, sha256-sliced bloom filter over 32-byte keys.
#[derive(Debug, Clone)]
pub struct Bloom {
    pub bits: u64,
    pub cells: Vec<u8>,
}

fn probes(seed: &str, key: &[u8; 32], bits: u64) -> [u64; 4] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(seed.as_bytes());
    h.update(key);
    let d: [u8; 32] = h.finalize().into();
    [
        u64::from_le_bytes(d[0..8].try_into().unwrap()) % bits,
        u64::from_le_bytes(d[8..16].try_into().unwrap()) % bits,
        u64::from_le_bytes(d[16..24].try_into().unwrap()) % bits,
        u64::from_le_bytes(d[24..32].try_into().unwrap()) % bits,
    ]
}

impl Bloom {
    /// bits = clamp(count*10, 8192, 16_777_216) — locked sizing.
    pub fn sized(count: usize) -> Bloom {
        let bits = (count * 10).clamp(8192, 16_777_216) as u64;
        Bloom { bits, cells: vec![0u8; bits.div_ceil(8) as usize] }
    }

    pub fn add(&mut self, seed: &str, key: &[u8; 32]) {
        for p in probes(seed, key, self.bits) {
            self.cells[(p / 8) as usize] |= 1 << (p % 8);
        }
    }

    pub fn test(&self, seed: &str, key: &[u8; 32]) -> bool {
        probes(seed, key, self.bits)
            .iter()
            .all(|p| self.cells[(p / 8) as usize] & (1 << (p % 8)) != 0)
    }
}
