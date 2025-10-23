//! Bitcoin address validation for the operator donation address.
//!
//! On-chain addresses only: legacy base58check (P2PKH `1`/`m`/`n`, P2SH `3`/`2`)
//! and segwit bech32/bech32m per BIP-173/BIP-350 (`bc1…`/`tb1…`). An optional
//! `bitcoin:` URI prefix is stripped. Checksums are verified in full because a
//! mistyped donation address is money lost forever. No network, no new crates.

use sha2::{Digest, Sha256};

/// Bech32 character set (BIP-173).
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Base58 alphabet: excludes `0`, `O`, `I`, `l`.
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Bech32m checksum constant (BIP-350), used by witness version 1+.
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// Validate an operator-provided Bitcoin address and return the canonical bare
/// address (any `bitcoin:` URI prefix stripped).
pub fn validate(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("address is empty".into());
    }
    // The prefix is matched case-insensitively; the address itself is
    // case-sensitive, so only the prefix is lowercased for the comparison.
    let lower = s.to_ascii_lowercase();
    let body = match lower.strip_prefix("bitcoin:") {
        Some(_) => &s["bitcoin:".len()..],
        None => s,
    };
    if body.is_empty() {
        return Err("address is empty after the `bitcoin:` prefix".into());
    }
    if body.len() > 90 {
        return Err("address longer than 90 characters".into());
    }
    if body.chars().any(char::is_whitespace) {
        return Err("address contains whitespace".into());
    }
    let first = body.as_bytes()[0];
    let segwit = matches!(body.get(..3), Some(p) if p.eq_ignore_ascii_case("bc1") || p.eq_ignore_ascii_case("tb1"));
    match (segwit, first) {
        (true, _) => validate_segwit(body)?,
        (false, b'1' | b'3' | b'2' | b'm' | b'n') => validate_base58check(body)?,
        (false, _) => {
            return Err(
                "must be a legacy address (1…, 3…, 2…, m…, n…) or a segwit address (bc1…, tb1…)"
                    .into(),
            );
        }
    }
    Ok(body.to_string())
}

/// Segwit address: BIP-173 (witness v0, bech32) or BIP-350 (v1-16, bech32m).
fn validate_segwit(addr: &str) -> Result<(), String> {
    let has_lower = addr.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = addr.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err("segwit address must be all lowercase or all uppercase".into());
    }
    let lower = addr.to_ascii_lowercase();
    let Some(sep) = lower.rfind('1') else {
        return Err("missing `1` separator".into());
    };
    // Data part needs the witness version plus the 6-character checksum.
    if sep == 0 || sep + 7 > lower.len() {
        return Err("data part too short".into());
    }
    let hrp = &lower[..sep];
    if hrp != "bc" && hrp != "tb" {
        return Err(format!("human-readable part `{hrp}` must be `bc` or `tb`"));
    }
    let mut data = Vec::with_capacity(lower.len() - sep - 1);
    for ch in lower[sep + 1..].bytes() {
        let v = BECH32_CHARSET
            .iter()
            .position(|&c| c == ch)
            .ok_or_else(|| format!("invalid character `{}`", ch as char))?;
        data.push(v as u8);
    }
    let version = data[0];
    if version > 16 {
        return Err(format!("witness version {version} is out of range (0-16)"));
    }
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    let expected = if version == 0 { 1 } else { BECH32M_CONST };
    if polymod(&values) != expected {
        return Err("invalid checksum".into());
    }
    let program = convert_5_to_8(&data[1..data.len() - 6])?;
    if program.is_empty() {
        return Err("empty witness program".into());
    }
    if program.len() < 2 || program.len() > 40 {
        return Err(format!(
            "witness program length {} is out of range (2-40 bytes)",
            program.len()
        ));
    }
    if version == 0 && program.len() != 20 && program.len() != 32 {
        return Err(format!(
            "witness version 0 requires a 20- or 32-byte program, got {}",
            program.len()
        ));
    }
    Ok(())
}

/// Legacy address: base58check with a 25-byte payload
/// (`version || hash160 || checksum`).
fn validate_base58check(addr: &str) -> Result<(), String> {
    // Big-endian base-256 accumulator; multiply by 58 and add each digit.
    let mut num: Vec<u8> = Vec::new();
    for &ch in addr.as_bytes() {
        let digit = BASE58
            .iter()
            .position(|&c| c == ch)
            .ok_or_else(|| format!("invalid character `{}`", ch as char))?;
        let mut carry = digit as u32;
        for byte in num.iter_mut().rev() {
            carry += 58 * u32::from(*byte);
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Leading `1` characters encode leading zero bytes.
    for &ch in addr.as_bytes() {
        if ch == b'1' {
            num.insert(0, 0);
        } else {
            break;
        }
    }
    if num.len() != 25 {
        return Err(format!(
            "legacy address decodes to {} bytes, expected 25",
            num.len()
        ));
    }
    let (payload, checksum) = num.split_at(21);
    let hash = Sha256::digest(Sha256::digest(payload));
    if &hash[..4] != checksum {
        return Err("invalid checksum".into());
    }
    match payload[0] {
        // P2PKH and P2SH, mainnet and testnet.
        0x00 | 0x05 | 0x6f | 0xc4 => Ok(()),
        v => Err(format!("unknown address version byte {v:#04x}")),
    }
}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    bytes
        .iter()
        .map(|b| b >> 5)
        .chain(std::iter::once(0))
        .chain(bytes.iter().map(|b| b & 31))
        .collect()
}

/// Reverse of the BIP-173 8-to-5 conversion: an incomplete final group must be
/// at most 4 bits and all zeroes.
fn convert_5_to_8(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len() / 2 + 1);
    for &v in data {
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 {
        return Err("invalid padding in 5-to-8 conversion".into());
    }
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return Err("non-zero padding in 5-to-8 conversion".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_p2pkh_and_p2sh() {
        assert_eq!(
            validate("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap(),
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        );
        assert_eq!(
            validate("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap(),
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        );
        // Testnet P2PKH.
        assert_eq!(
            validate("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn").unwrap(),
            "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
        );
    }

    #[test]
    fn legacy_bad_checksum_and_charset() {
        assert!(validate("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb").is_err());
        assert!(validate("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfN0").is_err());
        assert!(validate("3OJ98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").is_err());
        assert!(validate("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfm").is_err());
    }

    #[test]
    fn segwit_v0_bech32() {
        assert_eq!(
            validate("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        // BIP-173/BIP-350 valid vector, all uppercase.
        assert_eq!(
            validate("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").unwrap(),
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
        );
        // Mainnet P2WSH (BIP-173 example).
        assert_eq!(
            validate("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3").unwrap(),
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
        );
        // Testnet P2WPKH (BIP-173 example).
        assert_eq!(
            validate("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
    }

    #[test]
    fn segwit_v1_bech32m_taproot() {
        assert_eq!(
            validate("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0").unwrap(),
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
        );
        assert_eq!(
            validate("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c").unwrap(),
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c"
        );
        assert_eq!(
            validate("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs").unwrap(),
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs"
        );
        // Uppercase form of a valid v1 address.
        assert_eq!(
            validate("BC1P0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQZK5JJ0").unwrap(),
            "BC1P0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQZK5JJ0"
        );
    }

    #[test]
    fn segwit_invalid_vectors() {
        // Bad checksum (BIP-173).
        assert!(validate("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5").is_err());
        // Mixed case (BIP-173).
        assert!(
            validate("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7").is_err()
        );
        // Wrong HRP (BIP-173).
        assert!(validate("tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty").is_err());
        // v0 program length not 20/32 (BIP-173).
        assert!(validate("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P").is_err());
        // Bech32 checksum on a v1 address (BIP-350).
        assert!(
            validate("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd").is_err()
        );
        // Bech32m checksum on a v0 address (BIP-350).
        assert!(validate("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh").is_err());
        // Non-zero padding (BIP-350).
        assert!(
            validate("tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j").is_err()
        );
        // 1-byte program (BIP-350).
        assert!(validate("bc1pw5dgrnzv").is_err());
        // Empty data section (BIP-350).
        assert!(validate("bc1gmk9yu").is_err());
        // Witness version out of range.
        assert!(
            validate("BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R").is_err()
        );
    }

    #[test]
    fn uri_prefix_and_trimming() {
        assert_eq!(
            validate("bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        assert_eq!(
            validate("BITCOIN:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap(),
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        );
        assert_eq!(
            validate("  3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy  ").unwrap(),
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        );
        // URI query parameters are not part of a bare address.
        assert!(
            validate("bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.001").is_err()
        );
    }

    #[test]
    fn rejects_garbage_and_blanks() {
        assert!(validate("").is_err());
        assert!(validate("   ").is_err());
        assert!(validate("hello").is_err());
        assert!(validate("bc1q abc").is_err());
        assert!(validate("bitcoin:").is_err());
        assert!(validate("1p2gdwpf").is_err());
        assert!(validate("mzBc4XEFSxECDcUKDifwg9GbdhBh").is_err());
    }
}
