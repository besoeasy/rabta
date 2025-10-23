use crate::store::policy::PolicyRules;
use std::collections::HashMap;
use std::path::PathBuf;

/// Post-eviction target inside the budget: once usage crosses the admission
/// line (the budget itself), the reaper evicts down to this share.
const PLANE_TARGET_PCT: u64 = 85;
/// A single blob may not exceed this share of the budget, in basis points
/// (10 per 10,000 = 0.1%).
const MAX_SINGLE_BLOB_BP: u64 = 10;
/// Default byte ceiling for unclaimed blobs: 10% of the budget. Purely a cap
/// on the unclaimed plane; it never reduces the budget itself.
const UNCLAIMED_BYTES_PCT: u64 = 10;
/// Hard cap on how many unclaimed blobs may exist at once: a staging flood
/// guard independent of the byte cap. Oldest evicted first on breach.
pub const MAX_UNCLAIMED_BLOBS: u64 = 100;
/// Default total storage ceiling for the node.
const DEFAULT_STORE_BYTES: u64 = 20 * 1024 * 1024 * 1024;
/// Maximum number of peer URLs accepted in `SYNC`.
pub const MAX_SYNC_NODES: usize = 4;

/// Node configuration, resolved once at boot.
///
/// Precedence: process environment first,
/// then the optional `/data/config.env` file, then built-in defaults.
/// Invalid values refuse to boot — never a silent fallback.
#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub data_dir: PathBuf,
    /// Effective budget in bytes: `STORAGE` after the boot-time
    /// free-disk clamp. Events plus claimed blobs may fill all of it;
    /// unclaimed blobs are capped separately.
    pub store: u64,
    /// Unclamped total STORAGE asked for by the operator (diagnostics only).
    pub store_configured: u64,
    /// Whether the boot-time clamp to free disk space reduced the budget.
    pub storage_clamped: bool,
    /// Max accepted single blob upload = 0.1% of the effective STORAGE.
    pub max_single_blob: u64,
    /// Byte ceiling for live blobs with no live event reference:
    /// hardcoded to 10% of the effective STORAGE. A cap on the
    /// unclaimed plane only — it does not shrink the event budget.
    pub unclaimed_limit_bytes: u64,
    /// Blob-count ceiling for the unclaimed plane: at most this many
    /// unclaimed blobs may exist at once, regardless of their bytes.
    pub max_unclaimed_blobs: u64,
    /// Records matching these rules — and the blobs their live events
    /// claim — are exempt from pressure eviction. TTL expiry still applies.
    pub policy: PolicyRules,
    /// Other Rabta nodes this node may sync with, from `SYNC`.
    pub sync_nodes: Vec<String>,
    /// Optional donation address from `BITCOIN`, shown at
    /// `GET /api/v1/node` and on the status page. Absent/blank means off.
    pub bitcoin: Option<String>,
    pub battery_regen_per_sec: f64,
}

impl Config {
    /// Admission line: new charged bytes are refused above this. Equals the
    /// effective budget — the configured number is what the panel shows and
    /// what is enforced.
    pub fn watermark_bytes(&self) -> u64 {
        self.store
    }

    /// Post-eviction target.
    pub fn target_bytes(&self) -> u64 {
        pct(self.store, PLANE_TARGET_PCT)
    }

    /// Blobs are always available; the combined budget is always positive.
    pub fn blobs_enabled(&self) -> bool {
        self.store > 0
    }

    /// Free-space floor kept for SQLite/WAL and the operator: 5% of the
    /// budget, never less than 16 MiB.
    pub fn free_floor_bytes(&self) -> u64 {
        (self.store / 20).max(16 * 1024 * 1024)
    }
}

/// Sub-percent share: n * p / 10,000, where p is in basis points.
fn bp(n: u64, p: u64) -> u64 {
    n.saturating_mul(p) / 10_000
}

/// Largest accepted single blob upload for a given effective storage budget.
fn max_single_blob_for(effective_storage: u64) -> u64 {
    bp(effective_storage, MAX_SINGLE_BLOB_BP).max(1)
}

fn pct(n: u64, p: u64) -> u64 {
    n.saturating_mul(p) / 100
}

impl Config {
    pub fn load() -> Config {
        let data_dir = PathBuf::from(env_or("DATA", "/data"));
        let env_file_settings = read_env_file(data_dir.join("config.env"));

        let port: u16 = var_or_err("PORT", &env_file_settings)
            .map(|s| parse_port(&s))
            .unwrap_or(3232);

        let store_configured = var_or_err("STORAGE", &env_file_settings)
            .map(|s| {
                parse_size(&s)
                    .expect("STORAGE: invalid size value (examples: 20GB, 512MiB, 52428800)")
            })
            .unwrap_or(DEFAULT_STORE_BYTES);

        if store_configured == 0 {
            panic!("STORAGE must be greater than zero");
        }

        // Boot-time clamp: never promise more than 90% of free disk.
        let free = free_bytes(&data_dir).unwrap_or(u64::MAX);
        let ninety_pct_free = pct(free, 90);
        let (effective_storage, storage_clamped) =
            if free != u64::MAX && store_configured > ninety_pct_free {
                tracing::warn!(
                    "STORAGE={} but only {} free on {}; clamping to {}",
                    fmt_bytes(store_configured),
                    fmt_bytes(free),
                    data_dir.display(),
                    fmt_bytes(ninety_pct_free)
                );
                (ninety_pct_free, true)
            } else {
                (store_configured, false)
            };

        if effective_storage == 0 {
            panic!("STORAGE clamped to zero: not enough free disk space");
        }

        // Planes are capped individually, not by carving up the budget: the
        // full effective budget is usable by events plus claimed blobs, and
        // unclaimed blobs may never exceed 10% of it.
        let unclaimed_limit_bytes = pct(effective_storage, UNCLAIMED_BYTES_PCT).max(1);
        let store = effective_storage;
        let max_single_blob = max_single_blob_for(effective_storage);

        let policy = PolicyRules::resolve(var_or_err("POLICY", &env_file_settings), "POLICY");
        let sync_nodes = resolve_sync_nodes(var_or_err("SYNC", &env_file_settings));

        let battery_regen_per_sec = match var_or_err("REGEN", &env_file_settings) {
            Some(s) if !s.trim().is_empty() => {
                s.trim().parse::<f64>().unwrap_or_else(|_| random_regen())
            }
            _ => random_regen(),
        };

        // Blank means the donation feature is off; a malformed address
        // refuses to boot, same as every other operator value.
        let bitcoin = match var_or_err("BITCOIN", &env_file_settings) {
            Some(raw) if !raw.trim().is_empty() => match crate::bitcoin::validate(&raw) {
                Ok(addr) => Some(addr),
                Err(e) => panic!("BITCOIN: {e}"),
            },
            _ => None,
        };

        Config {
            port,
            data_dir,
            store,
            store_configured,
            storage_clamped,
            max_single_blob,
            unclaimed_limit_bytes,
            max_unclaimed_blobs: MAX_UNCLAIMED_BLOBS,
            policy,
            sync_nodes,
            bitcoin,
            battery_regen_per_sec,
        }
    }
}

fn var_or_err(name: &str, env_file: &HashMap<String, String>) -> Option<String> {
    if let Ok(v) = std::env::var(name) {
        return Some(v);
    }
    env_file.get(name).cloned()
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// `/data/config.env`: `KEY=VALUE` lines, `#` comments, blank lines ignored.
/// Never executed as a shell script; pure textual key/value parsing.
fn read_env_file(path: PathBuf) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Ok(body) = std::fs::read_to_string(&path) else {
        return map;
    };
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        map.insert(k.trim().to_string(), v.trim().to_string());
    }
    if !map.is_empty() {
        tracing::info!("loaded {} settings from {}", map.len(), path.display());
    }
    map
}

fn random_regen() -> f64 {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).expect("OS randomness unavailable for random REGEN");
    let rand_val = u32::from_ne_bytes(buf);
    20.0 + (rand_val % 21) as f64
}

fn parse_port(s: &str) -> u16 {
    s.parse::<u16>().expect("PORT: invalid port number")
}

/// Resolve `SYNC` at the environment boundary: absent, empty, or
/// whitespace-only means no peers. Entries are comma-separated node base URLs,
/// at most four, returned in configured order without duplicates.
fn resolve_sync_nodes(raw: Option<String>) -> Vec<String> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    let mut nodes = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let url = parse_node_url(entry);
        if !nodes.contains(&url) {
            nodes.push(url);
        }
    }
    if nodes.len() > MAX_SYNC_NODES {
        panic!("SYNC: at most {MAX_SYNC_NODES} node URLs are allowed");
    }
    nodes
}

/// A `SYNC` entry is an absolute `http://` or `https://` base URL.
/// A trailing slash is dropped.
fn parse_node_url(url: &str) -> String {
    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .unwrap_or_else(|| panic!("SYNC: `{url}` must start with http:// or https://"));
    if rest.is_empty() || rest.starts_with('/') || url.chars().any(char::is_whitespace) {
        panic!("SYNC: `{url}` is not a valid URL");
    }
    url.trim_end_matches('/').to_string()
}

/// Human-readable size parsing: `20MB`, `20GB`, `20TB`, `512MiB`, plain bytes,
/// lowercase, `KB`/`m/G` variants. `M`/`G` without `i` = binary (2^20 / 2^30).
pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim().to_ascii_uppercase();
    let (num_part, mult) = if let Some(rest) = t.strip_suffix("KIB") {
        (rest, 1024u64)
    } else if let Some(rest) = t.strip_suffix("MIB") {
        (rest, 1024u64 * 1024)
    } else if let Some(rest) = t.strip_suffix("GIB") {
        (rest, 1024u64 * 1024 * 1024)
    } else if let Some(rest) = t.strip_suffix("TIB") {
        (rest, 1024u64 * 1024 * 1024 * 1024)
    } else if let Some(rest) = t.strip_suffix("KB") {
        (rest, 1024)
    } else if let Some(rest) = t.strip_suffix("MB") {
        (rest, 1024 * 1024)
    } else if let Some(rest) = t.strip_suffix("GB") {
        (rest, 1024 * 1024 * 1024)
    } else if let Some(rest) = t.strip_suffix("TB") {
        (rest, 1024 * 1024 * 1024 * 1024)
    } else if let Some(rest) = t.strip_suffix('K') {
        (rest, 1024)
    } else if let Some(rest) = t.strip_suffix('M') {
        (rest, 1024 * 1024)
    } else if let Some(rest) = t.strip_suffix('G') {
        (rest, 1024 * 1024 * 1024)
    } else if let Some(rest) = t.strip_suffix('T') {
        (rest, 1024 * 1024 * 1024 * 1024)
    } else {
        (t.as_str(), 1u64)
    };
    let raw = num_part.trim();
    if raw.is_empty() {
        return Err(format!("no number in `{s}`"));
    }
    let f: f64 = raw.parse().map_err(|_| format!("not a number: `{raw}`"))?;
    if !f.is_finite() || f < 0.0 || f > 1.0e18 {
        return Err(format!("size out of range: `{s}`"));
    }
    let scaled = (f * mult as f64).floor();
    // f64::MAX and NaN would both saturate on cast; reject anything that does
    // not fit u64 instead of silently storing a bogus budget.
    if !scaled.is_finite() || scaled >= u64::MAX as f64 {
        return Err(format!("size overflows u64: `{s}`"));
    }
    Ok(scaled as u64)
}

/// Available bytes on the device holding `dir`. Public wrapper reused by /api/v1/node.
pub fn free_bytes_public(dir: &std::path::Path) -> u64 {
    free_bytes(dir).unwrap_or(0)
}

/// Available bytes on the device holding `dir`, or `None` when it cannot be
/// determined. Used by blob uploads to fail closed on the disk floor.
pub(crate) fn free_bytes_opt(dir: &std::path::Path) -> Option<u64> {
    free_bytes(dir)
}

/// Available bytes on the device holding `dir`. Computed on demand.
fn free_bytes(dir: &std::path::Path) -> Option<u64> {
    // Make sure the path exists (data dir is created before config load in main).
    std::fs::create_dir_all(dir).ok()?;
    let cdir = std::ffi::CString::new(dir.to_str()?).ok()?;
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(cdir.as_ptr(), &mut st) != 0 {
            return None;
        }
        let avail = st.f_bavail as u64;
        let bsize = st.f_bsize as u64;
        Some(avail.saturating_mul(bsize))
    }
}

pub fn fmt_bytes(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n}B")
    } else {
        format!("{v:.1}{}", units[i])
    }
}

#[cfg(test)]
impl Config {
    /// Build a deterministic config for unit tests.
    pub fn test_cfg(data_dir: impl Into<PathBuf>, store: u64) -> Config {
        let data_dir = data_dir.into();
        Config {
            port: 0,
            data_dir,
            store,
            store_configured: store,
            storage_clamped: false,
            max_single_blob: bp(store, MAX_SINGLE_BLOB_BP).max(1),
            unclaimed_limit_bytes: u64::MAX,
            max_unclaimed_blobs: u64::MAX,
            policy: PolicyRules::default(),
            sync_nodes: Vec::new(),
            bitcoin: None,
            battery_regen_per_sec: 30.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("20GB").unwrap(), 20 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("20gb").unwrap(), 20 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("512MiB").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("52428800").unwrap(), 52_428_800);
        assert_eq!(parse_size("2k").unwrap(), 2048);
        assert_eq!(parse_size("1.5MB").unwrap(), 1_572_864); // floored
        assert_eq!(parse_size("20MB").unwrap(), 20 * 1024 * 1024);
        assert!(parse_size("20").is_ok());
        assert!(parse_size("abc").is_err());
        assert!(parse_size("").is_err());
        assert!(parse_size("NaN").is_err());
        assert!(parse_size("inf").is_err());
        assert!(parse_size("1e309").is_err());
        assert!(parse_size("18446744073709551616").is_err());
        assert!(parse_size("1e18TB").is_err());
    }

    #[test]
    fn budget_watermark_and_target() {
        let cfg = Config::test_cfg("/tmp/rabta-config-test", 100);
        // The admission line is the budget itself: you get what you set.
        assert_eq!(cfg.watermark_bytes(), 100);
        assert_eq!(cfg.target_bytes(), 85);
        // 0.1% of 100 is 0; the 1-byte admission floor applies.
        assert_eq!(cfg.max_single_blob, 1);
        assert_eq!(cfg.store, 100);
    }

    #[test]
    fn single_blob_cap_is_zero_point_one_percent() {
        let cfg = Config::test_cfg("/tmp/rabta-blob-cap-test", 10_000);
        assert_eq!(cfg.max_single_blob, 10);
        assert_eq!(max_single_blob_for(20 * 1024 * 1024 * 1024), 21_474_836);
    }

    #[test]
    fn plane_caps_are_individual_not_subtractive() {
        let cfg = Config::test_cfg("/tmp/rabta-plane-caps-test", 1000);
        // Unclaimed blobs are capped at 10% of the budget.
        assert_eq!(pct(cfg.store, UNCLAIMED_BYTES_PCT), 100);
        // The cap does not shrink the event/claimed budget: the configured
        // number stays usable and enforceable in full.
        assert_eq!(cfg.store, 1000);
        assert_eq!(cfg.watermark_bytes(), 1000);
    }

    #[test]
    fn proportional_clamp_preserves_the_ratio() {
        assert_eq!(pct(1000, 90), 900);
        assert_eq!(pct(0, 90), 0);
    }

    fn key_hex(seed: u8) -> String {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        hex::encode(sk.verifying_key().to_bytes())
    }

    #[test]
    fn blank_policy_pins_nothing() {
        assert!(PolicyRules::resolve(None, "POLICY").is_empty());
        assert!(PolicyRules::resolve(Some(String::new()), "POLICY").is_empty());
        assert!(PolicyRules::resolve(Some("   ".into()), "POLICY").is_empty());
        assert!(PolicyRules::parse("").is_err());
    }

    #[test]
    fn policy_accepts_owner_collection_and_label_rules() {
        let body = format!(
            r#"{{"rules":[{{"owner":["ed25519:{}"],"collection":["notes*"],"labels":["keep"]}}]}}"#,
            key_hex(1)
        );
        let rules = PolicyRules::resolve(Some(body), "POLICY");
        assert_eq!(rules.rule_count(), 1);
    }

    #[test]
    #[should_panic(expected = "POLICY")]
    fn malformed_policy_refuses_boot() {
        PolicyRules::resolve(Some("not json".into()), "POLICY");
    }

    #[test]
    fn sync_accepts_up_to_four_urls_in_order() {
        let nodes = resolve_sync_nodes(Some(
            " https://a.example.com/ , http://b.example.com:3232,https://c.example.com,,https://d.example.com ".into(),
        ));
        assert_eq!(
            nodes,
            vec![
                "https://a.example.com",
                "http://b.example.com:3232",
                "https://c.example.com",
                "https://d.example.com",
            ]
        );
    }

    #[test]
    fn sync_blank_means_none() {
        assert!(resolve_sync_nodes(None).is_empty());
        assert!(resolve_sync_nodes(Some(String::new())).is_empty());
        assert!(resolve_sync_nodes(Some("  ,  ".into())).is_empty());
    }

    #[test]
    fn sync_collapses_duplicates() {
        let nodes = resolve_sync_nodes(Some("https://a.example.com,https://a.example.com/".into()));
        assert_eq!(nodes, vec!["https://a.example.com"]);
    }

    #[test]
    #[should_panic(expected = "SYNC")]
    fn sync_caps_at_four_nodes() {
        resolve_sync_nodes(Some(
            "https://a.example.com,https://b.example.com,https://c.example.com,https://d.example.com,https://e.example.com"
                .into(),
        ));
    }

    #[test]
    #[should_panic(expected = "SYNC")]
    fn malformed_sync_url_refuses_boot() {
        resolve_sync_nodes(Some("node.example.com".into()));
    }

    #[test]
    fn test_random_regen_bounds() {
        for _ in 0..100 {
            let r = random_regen();
            assert!((20.0..=40.0).contains(&r));
        }
    }
}
