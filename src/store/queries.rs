use rusqlite::{params, Connection};



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
             FROM events WHERE id = ?1 AND state='live'",
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

// counts for /stats
pub fn count_live(c: &Connection) -> (i64, i64) {
    let ev: i64 = c.query_row("SELECT COUNT(*) FROM events WHERE state='live'", [], |r| r.get(0)).unwrap_or(0);
    let bl: i64 = c.query_row("SELECT COUNT(*) FROM blobs WHERE state='live'", [], |r| r.get(0)).unwrap_or(0);
    (ev, bl)
}

/// Size route data: envelope row + the stored/not-stored attachment list.
pub struct AttachmentSize {
    pub hash_hex: String,
    pub size: Option<i64>,
}

pub fn event_attachments(c: &Connection, id: &[u8; 32]) -> Vec<AttachmentSize> {
    let mut out = Vec::new();
    let Ok(mut stmt) = c.prepare(
        "SELECT r.blob_hash, b.size FROM refs r
         LEFT JOIN blobs b ON b.hash = r.blob_hash AND b.state='live'
         WHERE r.event_id = ?1",
    ) else {
        return out;
    };
    let Ok(mut rows) = stmt.query(params![id] ) else { return out };
    while let Ok(Some(r)) = rows.next() {
        let hash: Vec<u8> = r.get(0).unwrap_or_default();
        let size: Option<i64> = r.get(1).ok();
        out.push(AttachmentSize { hash_hex: hex::encode(hash), size });
    }
    out
}

