use std::time::{Duration, Instant};

use bevy_ecs::prelude::*;

use crate::core::flows::FlowIndex;
use crate::core::flows::components::{Expired, FlowKey, LastSeen, TrafficStats};
use crate::core::settings::FlowSettings;

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
    flow_cfg: Res<FlowSettings>,
    mut q: Query<(Entity, &LastSeen, &mut TrafficStats), Without<Expired>>,
) {
    let idle_timeout = Duration::from_secs(flow_cfg.idle_timeout_seconds);
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
    flow_cfg: Res<FlowSettings>,
    mut index: ResMut<FlowIndex>,
    q: Query<(Entity, &FlowKey, &LastSeen), With<Expired>>,
) {
    let cap = flow_cfg.expired_cap;
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

#[cfg(test)]
mod tests {
    use super::*;
    use bevy_ecs::system::RunSystemOnce;

    use crate::core::flows::test_support::flow_key;

    fn cfg(timeout_secs: u64, cap: usize) -> FlowSettings {
        FlowSettings { idle_timeout_seconds: timeout_secs, expired_cap: cap }
    }

    fn ago(secs: u64) -> Instant {
        Instant::now().checked_sub(Duration::from_secs(secs)).unwrap()
    }

    // --- expire_idle ---

    #[test]
    fn expire_idle_marks_flow_expired_past_timeout() {
        let mut world = World::new();
        world.insert_resource(cfg(10, 10_000));
        let e = world.spawn((
            TrafficStats { bps: 50.0, ..Default::default() },
            LastSeen(ago(20)), // 20 s idle, timeout = 10 s
        )).id();
        world.run_system_once(expire_idle).unwrap();
        assert!(world.get::<Expired>(e).is_some(), "should be marked Expired");
        assert_eq!(world.get::<TrafficStats>(e).unwrap().bps, 0.0, "bps should be zeroed");
    }

    #[test]
    fn expire_idle_leaves_recent_flow_active() {
        let mut world = World::new();
        world.insert_resource(cfg(30, 10_000));
        let e = world.spawn((
            TrafficStats { bps: 100.0, ..Default::default() },
            LastSeen(ago(5)), // 5 s idle, timeout = 30 s
        )).id();
        world.run_system_once(expire_idle).unwrap();
        assert!(world.get::<Expired>(e).is_none(), "recent flow must stay active");
    }

    // --- evict_expired ---

    #[test]
    fn evict_expired_under_cap_does_not_evict() {
        let mut world = World::new();
        world.insert_resource(cfg(30, 10));
        world.insert_resource(FlowIndex::default());
        for i in 0..3u8 {
            let k = flow_key("1.2.3.4", 1000 + i as u16, "5.6.7.8", 80, 6);
            let e = world.spawn((k, LastSeen(ago(i as u64 + 1)), Expired)).id();
            world.resource_mut::<FlowIndex>().0.insert(k, e);
        }
        world.run_system_once(evict_expired).unwrap();
        // cap=10, only 3 expired: nothing evicted
        assert_eq!(world.resource::<FlowIndex>().0.len(), 3);
    }

    #[test]
    fn evict_expired_removes_oldest_surplus_flows() {
        let mut world = World::new();
        world.insert_resource(cfg(30, 2)); // cap = 2
        world.insert_resource(FlowIndex::default());

        // 5 expired flows with last-seen 50 s, 40 s, 30 s, 20 s, 10 s ago.
        // Oldest (50, 40, 30) should be evicted; newest (20, 10) should survive.
        let keys: Vec<_> = (0..5u8)
            .map(|i| flow_key("1.2.3.4", 2000 + i as u16, "5.6.7.8", 80, 6))
            .collect();
        let ages = [50u64, 40, 30, 20, 10];
        for (k, age) in keys.iter().zip(ages) {
            let e = world.spawn((*k, LastSeen(ago(age)), Expired)).id();
            world.resource_mut::<FlowIndex>().0.insert(*k, e);
        }

        world.run_system_once(evict_expired).unwrap();

        let index = world.resource::<FlowIndex>();
        // The 3 oldest must be evicted.
        for k in &keys[0..3] {
            assert!(!index.0.contains_key(k), "oldest flows should be evicted");
        }
        // The 2 newest must survive.
        for k in &keys[3..5] {
            assert!(index.0.contains_key(k), "newest flows should survive");
        }
        assert_eq!(index.0.len(), 2);
    }
}
