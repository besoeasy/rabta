#![allow(dead_code)]
use rusqlite::{Connection, OptionalExtension, params};

/// Sync request budget. Hardcoded — not a config knob.
pub const SYNC_BATTERY_MAX: f64 = 1_000_000.0;

// Ingress cost model: simple unit costs, no penalty surcharges.
pub const EVENT_COST: f64 = 1.0;
pub const BLOB_COST: f64 = 100.0;
pub const PUSH_MULTIPLIER: f64 = 1.0;

// Read-side serve protection (per sync request)
pub const REQUEST_COST: f64 = 0.0;
pub const RANGE_EVAL_COST: f64 = 0.0;
pub const EVENT_SERVE_COST: f64 = 0.0;

// Sync is only permitted at or above 75% battery capacity.
pub const SYNC_FLOOR: f64 = SYNC_BATTERY_MAX * 0.75; // 750,000
pub const READONLY_FLOOR: f64 = 0.0;
pub const TIER_EXIT_MARGIN: f64 = 0.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    ReadWrite,
    SyncDisabled,
    ReadOnly,
}

impl Tier {
    pub fn from_db(v: i64) -> Self {
        match v {
            1 => Tier::SyncDisabled,
            2 => Tier::ReadOnly,
            _ => Tier::ReadWrite,
        }
    }

    pub fn as_db(self) -> i64 {
        match self {
            Tier::ReadWrite => 0,
            Tier::SyncDisabled => 1,
            Tier::ReadOnly => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::ReadWrite => "readwrite",
            Tier::SyncDisabled => "sync_disabled",
            Tier::ReadOnly => "read_only",
        }
    }

    pub fn current(remaining: f64, _stored: Tier) -> Tier {
        if remaining <= 0.0 {
            Tier::ReadOnly
        } else if remaining < SYNC_FLOOR {
            Tier::SyncDisabled
        } else {
            Tier::ReadWrite
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BatteryState {
    pub remaining: f64,
    pub regen_per_sec: f64,
    pub tier: Tier,
}

impl BatteryState {
    /// Seconds until the battery regenerates past the given floor.
    pub fn retry_after_to(&self, floor: f64) -> u64 {
        let deficit = (floor - self.remaining).max(0.0);
        let per_sec = self.regen_per_sec.max(0.1);
        (deficit / per_sec).ceil() as u64
    }

    /// Sync ingress and egress are admitted ONLY when battery >= 75%.
    pub fn sync_admitted(&self) -> bool {
        self.remaining >= SYNC_FLOOR
    }

    /// Local writes are permitted as long as battery > 0.
    pub fn local_admitted(&self) -> bool {
        self.remaining > 0.0
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReconcileWork {
    pub plain_events: usize,
    pub blob_events: usize,
    pub ranges_evaluated: usize,
    pub events_served: usize,
}

impl ReconcileWork {
    pub fn compute_cost(&self, _penalty: f64) -> f64 {
        ((self.plain_events + self.blob_events) as f64 * EVENT_COST).ceil()
    }
}

/// Refill the global battery lazily based on elapsed seconds.
pub fn refill_battery(
    c: &Connection,
    now: i64,
    max_battery: f64,
    regen_per_sec: f64,
) -> rusqlite::Result<BatteryState> {
    let row: Option<(f64, i64, i64)> = c
        .query_row(
            "SELECT battery, battery_at, tier FROM sync_meta WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;

    let (mut battery, battery_at, stored_tier) = match row {
        Some((b, at, tier)) => (b, at, tier),
        None => {
            let mut epoch = [0u8; 16];
            getrandom::getrandom(&mut epoch).expect("random epoch");
            c.execute(
                "INSERT INTO sync_meta (id, epoch, battery, battery_at, created_at)
                 VALUES (1, ?1, ?2, ?3, ?3)",
                params![&epoch[..], max_battery, now],
            )?;
            (max_battery, now, 0)
        }
    };

    let elapsed = (now - battery_at).max(0) as f64;
    battery = (battery + elapsed * regen_per_sec).min(max_battery);

    let tier = Tier::current(battery, Tier::from_db(stored_tier));

    c.execute(
        "UPDATE sync_meta SET battery = ?1, battery_at = ?2, tier = ?3 WHERE id = 1",
        params![battery, now, tier.as_db()],
    )?;

    Ok(BatteryState {
        remaining: battery,
        regen_per_sec,
        tier,
    })
}

/// Deduct actual battery consumed.
pub fn deduct_battery(c: &Connection, amount: f64) -> rusqlite::Result<()> {
    if amount <= 0.0 {
        return Ok(());
    }
    c.execute(
        "UPDATE sync_meta SET battery = MAX(0.0, battery - ?1) WHERE id = 1",
        params![amount],
    )?;
    Ok(())
}

/// Simple battery reservation: checks if battery >= cost and deducts it.
pub fn reserve_battery(
    c: &Connection,
    cost: f64,
    now: i64,
    max_battery: f64,
    regen_per_sec: f64,
) -> Result<f64, u64> {
    let state = refill_battery(c, now, max_battery, regen_per_sec).map_err(|_| 1u64)?;

    if state.remaining < cost {
        let deficit = cost - state.remaining;
        let per_sec = regen_per_sec.max(0.1);
        let retry_after = (deficit / per_sec).ceil() as u64;
        return Err(retry_after.max(1));
    }

    deduct_battery(c, cost).map_err(|_| 1u64)?;
    Ok(cost)
}

/// Refund battery (e.g. on operation cancel or failure).
pub fn refund_battery(
    c: &Connection,
    refund_amount: f64,
    max_battery: f64,
) -> rusqlite::Result<()> {
    if refund_amount <= 0.0 {
        return Ok(());
    }
    c.execute(
        "UPDATE sync_meta SET battery = MIN(?1, battery + ?2) WHERE id = 1",
        params![max_battery, refund_amount],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_admitted_only_at_or_above_75_percent() {
        let state_full = BatteryState {
            remaining: 750_000.0,
            regen_per_sec: 10.0,
            tier: Tier::ReadWrite,
        };
        assert!(state_full.sync_admitted());

        let state_above = BatteryState {
            remaining: 800_000.0,
            regen_per_sec: 10.0,
            tier: Tier::ReadWrite,
        };
        assert!(state_above.sync_admitted());

        let state_below = BatteryState {
            remaining: 749_999.0,
            regen_per_sec: 10.0,
            tier: Tier::SyncDisabled,
        };
        assert!(!state_below.sync_admitted());
    }

    #[test]
    fn test_refill_and_deduct() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();

        let state = refill_battery(&c, 1_000, SYNC_BATTERY_MAX, 10.0).unwrap();
        assert_eq!(state.remaining, SYNC_BATTERY_MAX);
        assert!(state.sync_admitted());

        deduct_battery(&c, 300_000.0).unwrap();
        let remaining: f64 = c
            .query_row("SELECT battery FROM sync_meta WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(remaining, 700_000.0);
        assert!(remaining < SYNC_FLOOR);
    }
}
