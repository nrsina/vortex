use std::time::{Duration, Instant};

use bevy_ecs::prelude::*;

use crate::core::flows::FlowIndex;
use crate::core::flows::components::{Expired, FlowKey, LastSeen, TrafficStats};
use crate::core::settings::settings;

/// Cadence at which we walk the flow table to mark idle flows expired and to
/// enforce the retained-expired cap. The idle timeout is tens of seconds and
/// the cap is checked lazily, so a 1 Hz sweep is plenty. Wired into the
/// scheduler via `.run_if(on_timer(SWEEP_INTERVAL))` in `core/flows/mod.rs`,
/// so each system's resource slots are only reserved on firing ticks instead
/// of every tick.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Mark — but do *not* despawn — flows that have received no packets for longer
/// than the configured idle timeout. The entity and its `FlowIndex` entry stay
/// in place: a returning packet revives the flow (see `ingest`), and the user
/// can still inspect it. We zero `bps` here so a dead flow reads 0 B/s instead
/// of freezing at its last rate (it's excluded from `aggregate::tick`'s EWMA
/// pass via `Without<Expired>`, so nothing else would update it).
pub fn expire_idle(
    mut commands: Commands,
    mut q: Query<(Entity, &LastSeen, &mut TrafficStats), Without<Expired>>,
) {
    let idle_timeout = Duration::from_secs(settings().flows.idle_timeout_seconds);
    let now = Instant::now();
    for (entity, seen, mut stats) in &mut q {
        if now.duration_since(seen.0) > idle_timeout {
            stats.bps = 0.0;
            commands.entity(entity).insert(Expired);
        }
    }
}

/// Bound memory by hard-evicting the *oldest* expired flows once the retained
/// set exceeds `expired_cap`. This is the only place an expired flow is truly
/// removed (entity despawned + dropped from `FlowIndex`). There is no
/// time-based hard delete — retaining expired flows is the feature, so we only
/// evict under cap pressure, dropping the least-recently-active first.
pub fn evict_expired(
    mut commands: Commands,
    mut index: ResMut<FlowIndex>,
    q: Query<(Entity, &FlowKey, &LastSeen), With<Expired>>,
) {
    let cap = settings().flows.expired_cap;
    // Collect the expired set; bail early on the common (under-cap) path.
    let mut expired: Vec<(Entity, FlowKey, Instant)> =
        q.iter().map(|(e, k, s)| (e, *k, s.0)).collect();
    if expired.len() <= cap {
        return;
    }
    // Oldest last-packet first, so the surplus we drop is the stalest tail.
    expired.sort_by_key(|(_, _, last_seen)| *last_seen);
    let surplus = expired.len() - cap;
    for (entity, key, _) in expired.into_iter().take(surplus) {
        index.0.remove(&key);
        commands.entity(entity).despawn();
    }
}
