use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Locked peer-visit cadence. Not configurable: every tick is 60 s apart,
/// with exponential backoff (×2 per consecutive failure, cap 1 h) on top.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(60);

/// Node configuration, resolved once at boot.
///
/// Precedence per plan.md §Storage layout: process environment first,
/// then the optional `/data/config.env` file, then built-in defaults.
/// Invalid values refuse to boot — never a silent fallback.
#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub data_dir: PathBuf,
    /// Effective storage ceiling in bytes (already min()ed with 90% free space).
    pub storage_max: u64,
    /// Whether the boot-time clamp to free disk space actually reduced the value.
    pub storage_clamped: bool,
    /// Unclamped value the operator asked for (diagnostics only).
    pub storage_max_configured: u64,
    /// Max accepted single blob upload = 10% of storage_max.
    pub max_single_blob: u64,
    /// Admission watermark = 90% of storage_max.
    pub watermark_bytes: u64,
    /// Eviction target after a pressure pass = 85% of storage_max.
    pub eviction_target_bytes: u64,
    pub sse_subscriber_cap: usize,
    pub sync_nodes: Vec<reqwest::Url>,
    pub sync_interval: Duration,
}

pub const MAX_NODES: usize = 8;

impl Config {
    pub fn load() -> Config {
        let data_dir = PathBuf::from(env_or("DATA_DIR", "/data"));
        let env_file_settings = read_env_file(data_dir.join("config.env"));

        let port: u16 = var_or_err("PORT", &env_file_settings).map(|s| parse_port(&s)).unwrap_or(3232);

        let storage_raw = var_or_err("STORAGE_MAX", &env_file_settings)
            .map(|s| parse_size(&s).expect("STORAGE_MAX: invalid size value (examples: 20GB, 512MiB, 52428800)"))
            .unwrap_or(20u64.saturating_mul(1024 * 1024 * 1024));
        let storage_max_configured = storage_raw;

        // Boot-time clamp: min(STORAGE_MAX, 90% of free space on the data dir).
        let free = free_bytes(&data_dir).unwrap_or(u64::MAX);
        let ninety_pct_free = (free / 100).saturating_mul(90);
        let (storage_max, storage_clamped) = if ninety_pct_free < storage_max_configured && free != u64::MAX {
            tracing::warn!(
                "STORAGE_MAX={} but only {} free on {}; clamping to {}",
                fmt_bytes(storage_max_configured),
                fmt_bytes(free),
                data_dir.display(),
                fmt_bytes(ninety_pct_free)
            );
            (ninety_pct_free, true)
        } else {
            (storage_max_configured, false)
        };

        let watermark_bytes = (storage_max / 100).saturating_mul(90);
        let eviction_target_bytes = (storage_max / 100).saturating_mul(85);
        let max_single_blob = (storage_max / 10).saturating_mul(1); // 10% of STORAGE_MAX

        let sse_subscriber_cap: usize = var_or_err("SSE_SUBSCRIBER_CAP", &env_file_settings)
            .map(|s| s.parse().expect("SSE_SUBSCRIBER_CAP: invalid integer"))
            .unwrap_or(256);

        let sync_nodes = match var_or_err("NODES", &env_file_settings) {
            None => Vec::new(),
            Some(s) => parse_nodes(&s).expect("NODES: malformed or listed beyond max 8"),
        };

        // Locked cadence: 60 s per peer tick, exponential backoff on failure (cap 1 h).
        let sync_interval = crate::config::SYNC_INTERVAL;

        Config {
            port,
            data_dir,
            storage_max,
            storage_clamped,
            storage_max_configured,
            max_single_blob,
            watermark_bytes,
            eviction_target_bytes,
            sse_subscriber_cap,
            sync_nodes,
            sync_interval,
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
        let Some((k, v)) = line.split_once('=') else { continue };
        map.insert(k.trim().to_string(), v.trim().to_string());
    }
    if !map.is_empty() {
        tracing::info!("loaded {} settings from {}", map.len(), path.display());
    }
    map
}

fn parse_port(s: &str) -> u16 {
    s.parse::<u16>().expect("PORT: invalid port number")
}

/// `NODES` parsing: comma-separated plain URLs, max 8, http(s) only.
pub fn parse_nodes(s: &str) -> Result<Vec<reqwest::Url>, String> {
    let mut nodes = Vec::new();
    for raw in s.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let url = reqwest::Url::parse(raw).map_err(|e| format!("bad NODES entry `{raw}`: {e}"))?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(format!("bad NODES entry `{raw}`: scheme must be http(s)"));
        }
        nodes.push(url);
        if nodes.len() > MAX_NODES {
            return Err(format!("NODES: more than {MAX_NODES} entries"));
        }
    }
    if nodes.is_empty() {
        return Err("NODES: set to nothing (provide at least one URL)".into());
    }
    Ok(nodes)
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
    if f < 0.0 || f > 1.0e18 {
        return Err(format!("size out of range: `{s}`"));
    }
    Ok((f * mult as f64).floor() as u64)
}

/// 90% of the device holding `dir`. Public wrapper reused by /stats.
pub fn free_bytes_public(dir: &std::path::Path) -> u64 {
    free_bytes(dir).unwrap_or(0)
}

/// 90% of the device holding `dir`. Computed once at boot, never re-evaluated.
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
    }

    #[test]
    fn nodes() {
        assert!(parse_nodes("").is_err());
        assert!(parse_nodes("not a url").is_err());
        assert_eq!(parse_nodes("http://a:1, https://b:2").unwrap().len(), 2);
        assert!(parse_nodes("ftp://x").is_err());
        let many = (0..9).map(|i| format!("http://p{i}.example")).collect::<Vec<_>>().join(",");
        assert!(parse_nodes(&many).is_err());
    }
}
