#![allow(dead_code)]
use rusqlite::{Connection, OptionalExtension, params};

pub const BASE_POLL_MS: u64 = 5_000;

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub penalty: f64,
    pub strikes: u32,
}

pub fn multiplier_for_strikes(_strikes: u32) -> f64 {
    1.0
}

pub fn poll_interval_ms(_penalty: f64) -> u64 {
    BASE_POLL_MS
}

pub fn get_or_create_peer(c: &Connection, url: &str, now: i64) -> rusqlite::Result<PeerRecord> {
    let row = c
        .query_row(
            "SELECT penalty, strikes FROM sync_peers WHERE url = ?1",
            [url],
            |r| {
                Ok(PeerRecord {
                    penalty: r.get(0)?,
                    strikes: r.get::<_, f64>(1)? as u32,
                })
            },
        )
        .optional()?;

    match row {
        Some(p) => Ok(p),
        None => {
            c.execute(
                "INSERT INTO sync_peers (url, penalty, strikes, penalty_at, next_poll_at)
                 VALUES (?1, 1.0, 0, ?2, ?2)",
                params![url, now],
            )?;
            Ok(PeerRecord {
                penalty: 1.0,
                strikes: 0,
            })
        }
    }
}

pub fn record_peer_error(
    c: &Connection,
    url: &str,
    now: i64,
    error: &str,
) -> rusqlite::Result<f64> {
    let _ = get_or_create_peer(c, url, now)?;
    let next_poll_at = now + (BASE_POLL_MS / 1000) as i64;
    let error: String = error.chars().take(300).collect();

    c.execute(
        "UPDATE sync_peers
         SET strikes = 0, penalty = 1.0, penalty_at = ?1, next_poll_at = ?2,
             last_error = ?3, last_error_at = ?1
         WHERE url = ?4",
        params![now, next_poll_at, error, url],
    )?;

    Ok(1.0)
}

pub fn record_peer_clean(c: &Connection, url: &str, now: i64) -> rusqlite::Result<f64> {
    let _ = get_or_create_peer(c, url, now)?;
    let next_poll_at = now + (BASE_POLL_MS / 1000) as i64;

    c.execute(
        "UPDATE sync_peers
         SET strikes = 0, penalty = 1.0, penalty_at = ?1, next_poll_at = ?2, last_success_at = ?1
         WHERE url = ?3",
        params![now, next_poll_at, url],
    )?;

    Ok(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_poll_and_penalty() {
        assert_eq!(multiplier_for_strikes(0), 1.0);
        assert_eq!(multiplier_for_strikes(5), 1.0);
        assert_eq!(poll_interval_ms(1.0), 5_000);
        assert_eq!(poll_interval_ms(64.0), 5_000);
    }
}
