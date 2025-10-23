use std::collections::HashSet;
use std::sync::RwLock;

pub const DEDUP_CAPACITY: usize = 64_000;

/// Fast in-memory duplicate filter for incoming event IDs.
/// Uses a circular ring buffer + HashSet capped at 64,000 entries
/// to reject duplicate flood attacks in microseconds before touching SQLite.
pub struct IngressDedup {
    inner: RwLock<DedupState>,
}

struct DedupState {
    seen: HashSet<[u8; 32]>,
    ring: Vec<[u8; 32]>,
    pos: usize,
}

impl Default for IngressDedup {
    fn default() -> Self {
        Self::new()
    }
}

impl IngressDedup {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(DedupState {
                seen: HashSet::with_capacity(DEDUP_CAPACITY),
                ring: Vec::with_capacity(DEDUP_CAPACITY),
                pos: 0,
            }),
        }
    }

    /// Returns `true` if the event ID is already in the filter (a duplicate).
    pub fn is_duplicate(&self, id: &[u8; 32]) -> bool {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .seen
            .contains(id)
    }

    /// Records an event ID. Returns `true` if newly recorded, or `false` if it was already present.
    pub fn record(&self, id: [u8; 32]) -> bool {
        let mut state = self.inner.write().unwrap_or_else(|p| p.into_inner());
        if state.seen.contains(&id) {
            return false;
        }
        if state.ring.len() < DEDUP_CAPACITY {
            state.ring.push(id);
        } else {
            let pos = state.pos;
            let evicted = state.ring[pos];
            state.seen.remove(&evicted);
            state.ring[pos] = id;
            state.pos = (pos + 1) % DEDUP_CAPACITY;
        }
        state.seen.insert(id);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_basic() {
        let dedup = IngressDedup::new();
        let id1 = [1u8; 32];
        let id2 = [2u8; 32];

        assert!(!dedup.is_duplicate(&id1));
        assert!(dedup.record(id1));
        assert!(dedup.is_duplicate(&id1));
        assert!(!dedup.record(id1));

        assert!(!dedup.is_duplicate(&id2));
        assert!(dedup.record(id2));
        assert!(dedup.is_duplicate(&id2));
    }
}
