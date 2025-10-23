use rusqlite::{Connection, params};

/// Raw helpers shared by api handlers: get/count/size — the O(1) reads.
pub struct EventRow {
    pub id_hex: String,
    pub served: Vec<u8>,
    pub expires_at: i64,
    pub size: i64,
}

pub fn get_event(c: &Connection, id: &[u8; 32]) -> Option<EventRow> {
    let row = c
        .query_row(
            "SELECT rowid, owner, collection, created_at, expires_at, data, size
             FROM events WHERE id = ?1",
            params![id],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            },
        )
        .ok()?;
    let (_rowid, _owner, _collection, _created_at, expires_at, data, size) = row;
    Some(EventRow {
        id_hex: hex::encode(id),
        served: data,
        expires_at,
        size,
    })
}

/// Sum of the live blobs an event references. Dangling or expired blob hashes
/// contribute nothing, so this is the attachment bytes currently on disk.
pub fn attached_blob_bytes(c: &Connection, event_id: &[u8; 32]) -> i64 {
    c.query_row(
        "SELECT COALESCE(SUM(b.size), 0)
           FROM blob_refs r
           JOIN blobs b ON b.hash = r.hash
          WHERE r.event_id = ?1
            AND b.expires_at > ?2",
        params![event_id, crate::store::reaper::now()],
        |r| r.get(0),
    )
    .unwrap_or(0)
}

// count for /api/v1/node and tests
pub fn count_live(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap_or(0)
}

/// Live blob rows, for /api/v1/node.
pub fn count_live_blobs(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attached_bytes_count_live_references_only() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        let event_id = [1u8; 32];
        let live_a = [2u8; 32];
        let live_b = [3u8; 32];
        let expired = [4u8; 32];
        let now = crate::store::reaper::now();

        for (hash, size, expires) in [
            (live_a, 100i64, now + 3600),
            (live_b, 250i64, now + 3600),
            (expired, 999i64, now - 1),
        ] {
            c.execute(
                "INSERT INTO blobs(hash, size, stored_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![&hash[..], size, now, expires],
            )
            .unwrap();
        }
        for hash in [live_a, live_b, expired, [5u8; 32]] {
            c.execute(
                "INSERT INTO blob_refs(hash, event_id) VALUES (?1, ?2)",
                rusqlite::params![&hash[..], &event_id[..]],
            )
            .unwrap();
        }

        assert_eq!(
            attached_blob_bytes(&c, &event_id),
            350,
            "live attachments were not summed or dangling/expired hashes counted"
        );
        assert_eq!(attached_blob_bytes(&c, &[9u8; 32]), 0);
    }
}
