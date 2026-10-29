use std::time::Duration;

use crate::api::AppState;
use crate::store::blobs::BlobSink;

fn join(peer: &reqwest::Url, path: &str) -> reqwest::Url {
    peer.join(path).expect("joined url")
}

/// Pull ONE blob from a trusted peer, hash-verify while streaming, then
/// install it (orphan clock, or attached when live referrers already exist).
pub async fn pull_blob(n: &AppState, peer: &reqwest::Url, hash_hex: &str) -> bool {
    if hash_hex.len() != 64 || !hash_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }

    let url = join(peer, &format!("/sync/blobs/{hash_hex}"));
    let Ok(mut resp) = n.http.get(url).timeout(Duration::from_secs(30)).send().await else {
        return false;
    };
    if !resp.status().is_success() {
        return false;
    }

    let (ev, bl) = n.db.read(|c: &rusqlite::Connection| crate::db::live_bytes(c)).await;
    let mut sink = match BlobSink::start(&n.cfg.data_dir, ev + bl, n.cfg.storage_max, n.cfg.max_single_blob) {
        Ok(s) => s,
        Err(_) => return false,
    };
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if sink.push(&chunk).is_err() {
                    sink.discard();
                    return false;
                }
            }
            Ok(None) => break,
            Err(_) => {
                sink.discard();
                return false;
            }
        }
    }
    let staged = match sink.finish() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if staged.hash_hex.to_ascii_lowercase() != hash_hex.to_ascii_lowercase() {
        let _ = std::fs::remove_file(&staged.path);
        return false;
    }
    matches!(
        crate::store::blobs::install_staged(&n.db, &n.cfg, staged).await,
        Ok(crate::store::blobs::Install::Fresh | crate::store::blobs::Install::Deduped)
    )
}

// push_event_to_peers / fetch_blob_from_peers live in loop_all.rs (single source).
