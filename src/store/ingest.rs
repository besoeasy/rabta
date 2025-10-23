use crate::api::AppState;
use crate::error::{ApiError, ApiResult};
use crate::store::events::{self, ParsedEvent};
use crate::sync::battery::{self, BatteryState, EVENT_COST, SYNC_BATTERY_MAX};

/// Admission refused because the battery sits below the caller's floor.
pub fn quota_err(retry_after: u64, scope: &str) -> ApiError {
    ApiError::battery_empty(format!(
        "battery below {scope} floor; retry after {retry_after}s"
    ))
}

/// Read the battery (lazy-regenerating it) and refuse below the caller's
/// floor. Local writes work below the sync floor; sync ingress does not.
pub fn check_admission(state: &BatteryState, local: bool) -> Result<(), ApiError> {
    let floor = if local {
        battery::READONLY_FLOOR
    } else {
        battery::SYNC_FLOOR
    };
    let admitted = if local {
        state.local_admitted()
    } else {
        state.sync_admitted()
    };
    if admitted {
        return Ok(());
    }
    Err(quota_err(
        state.retry_after_to(floor),
        if local { "read-only" } else { "sync" },
    ))
}

/// Core submission chokepoint for events: dedup → battery → pressure →
/// insert in one transaction, so a rollback refunds the charge.
/// Duplicates are free. Returns whether the event was newly stored.
pub async fn event(n: &AppState, ev: ParsedEvent) -> ApiResult<bool> {
    let cfg = n.cfg.clone();
    let regen = cfg.battery_regen_per_sec;
    let ev2 = ev.clone();

    n.db.write(move |c: &rusqlite::Connection| -> ApiResult<bool> {
        let tx = c
            .unchecked_transaction()
            .map_err(|e| ApiError::internal(format!("event begin: {e}")))?;
        let now = crate::store::reaper::now();

        // Duplicates add no bytes: no battery, no pressure, no eviction.
        let exists = events::event_exists(&tx, &ev2.id)
            .map_err(|e| ApiError::internal(format!("event lookup: {e}")))?;
        if exists {
            return Ok(false);
        }

        let state = battery::refill_battery(&tx, now, SYNC_BATTERY_MAX, regen)
            .map_err(|e| ApiError::internal(format!("battery refill: {e}")))?;
        check_admission(&state, true)?;

        battery::reserve_battery(&tx, EVENT_COST, now, SYNC_BATTERY_MAX, regen)
            .map_err(|retry| quota_err(retry, "ingress"))?;

        let claims = events::new_claim_bytes(&tx, &ev2.blobs)
            .map_err(|e| ApiError::internal(format!("claim lookup: {e}")))?;
        crate::store::reaper::event_pressure_check(
            &tx,
            &cfg,
            ev2.size as u64 + claims.max(0) as u64,
        )?;

        let inserted = events::insert_event(&tx, &ev2)
            .map_err(|e| ApiError::internal(format!("event insert: {e}")))?;
        tx.commit()
            .map_err(|e| ApiError::internal(format!("event commit: {e}")))?;
        Ok(inserted)
    })
    .await
}
