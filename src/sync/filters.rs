use super::bloom::{Bloom, BloomFilterDto, SEED_BLOBS, SEED_EVENTS};
use crate::api::AppState;
use crate::store::reaper;

/// Build my live-set filters (event ids, blob hashes) for the planner POST.
pub async fn build_my_filters(db: &crate::db::Db) -> (BloomFilterDto, BloomFilterDto) {
    let now = reaper::now();
    db.read(move |c: &rusqlite::Connection| {
        let mut ev = Bloom::sized(0);
        let mut count = 0usize;
        if let Ok(mut stmt) = c.prepare("SELECT id FROM events WHERE state='live' AND expires_at > ?1") {
            if let Ok(mut rows) = stmt.query([now]) {
                while let Ok(Some(r)) = rows.next() {
                    if let Ok(id) = r.get::<_, Vec<u8>>(0) {
                        if id.len() == 32 {
                            let mut k = [0u8; 32];
                            k.copy_from_slice(&id);
                            ev.add(SEED_EVENTS, &k);
                        }
                    }
                    count += 1;
                }
            }
        }
        let mut bl = Bloom::sized(0);
        let mut blcount = 0usize;
        if let Ok(mut stmt) = c.prepare("SELECT hash FROM blobs WHERE state='live'") {
            if let Ok(mut rows) = stmt.query([]) {
                while let Ok(Some(r)) = rows.next() {
                    if let Ok(h) = r.get::<_, Vec<u8>>(0) {
                        if h.len() == 32 {
                            let mut k = [0u8; 32];
                            k.copy_from_slice(&h);
                            bl.add(SEED_BLOBS, &k);
                        }
                    }
                    blcount += 1;
                }
            }
        }
        (
            BloomFilterDto::from_parts("events", count, &ev),
            BloomFilterDto::from_parts("blobs", blcount, &bl),
        )
    })
    .await
}

/// My live events inside a created_at window, as a phase-2 sub-filter.
pub async fn build_sub_filter_time(n: &AppState, lo: i64, hi: i64) -> Option<(usize, Bloom)> {
    let n2 = n.clone();
    n2.db
        .read(move |c: &rusqlite::Connection| {
            let mut bloom = Bloom::sized(0);
            let mut count = 0usize;
            let Ok(mut stmt) =
                c.prepare("SELECT id FROM events WHERE state='live' AND created_at >= ?1 AND created_at < ?2")
            else {
                return None;
            };
            let Ok(mut rows) = stmt.query([lo, hi]) else { return None };
            while let Ok(Some(r)) = rows.next() {
                if let Ok(id) = r.get::<_, Vec<u8>>(0) {
                    if id.len() == 32 {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(&id);
                        bloom.add(SEED_EVENTS, &k);
                        count += 1;
                    }
                }
            }
            Some((count, bloom))
        })
        .await
}
