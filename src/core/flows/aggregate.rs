use std::time::{Duration, Instant};

use bevy_ecs::prelude::*;

use crate::core::flows::LiveMetrics;
use crate::core::flows::components::{Direction, Expired, Timeline, TrafficStats};
use crate::core::settings::TickRate;

pub(crate) const BUCKET_DURATION: Duration = Duration::from_secs(1);
pub(crate) const EWMA_ALPHA: f32 = 0.3;

/// Recompute each *active* flow's smoothed bps and rotate its timeline ring,
/// while rolling the per-direction throughput and the active/expired flow
/// counts up into `LiveMetrics` for the header. One pass over the live flow
/// set; the directional sums cost only a branch per flow. Expired flows are
/// excluded (`Without<Expired>`) — their bps was zeroed at expiry and their
/// timeline intentionally freezes — and counted separately via `q_expired`.
pub fn tick(
    rate: Res<TickRate>,
    mut metrics: ResMut<LiveMetrics>,
    mut q: Query<(&mut TrafficStats, &mut Timeline, &Direction), Without<Expired>>,
    q_expired: Query<(), With<Expired>>,
) {
    let now = Instant::now();
    let hz = rate.0 as f32;

    let mut tx_bps = 0.0_f32;
    let mut rx_bps = 0.0_f32;
    let mut active = 0_usize;

    for (mut stats, mut timeline, dir) in &mut q {
        let instantaneous = stats.bytes_since_last_tick as f32 * hz;
        stats.bps = EWMA_ALPHA * instantaneous + (1.0 - EWMA_ALPHA) * stats.bps;
        stats.bytes_since_last_tick = 0;

        active += 1;
        match dir {
            Direction::Outbound => tx_bps += stats.bps,
            Direction::Inbound => rx_bps += stats.bps,
            // Loopback + unattributable flows aren't "to/from the network",
            // so they count toward the active total but neither tx nor rx.
            Direction::Local | Direction::Unknown => {}
        }

        // Rotate the per-second timeline ring.
        while now.duration_since(timeline.last_rotate) >= BUCKET_DURATION {
            let head = timeline.head as usize;
            timeline.buckets[head] = timeline.current_bucket_bytes;
            timeline.current_bucket_bytes = 0;
            timeline.head = ((head + 1) % timeline.buckets.len()) as u8;
            timeline.last_rotate += BUCKET_DURATION;
        }
    }

    metrics.tx_bps = tx_bps;
    metrics.rx_bps = rx_bps;
    metrics.active_flows = active;
    metrics.expired_flows = q_expired.iter().count();
    // `dropped_total` is mirrored from the shared atomic by `ingest`.
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy_ecs::system::RunSystemOnce;

    fn setup_world(hz: u8) -> World {
        let mut w = World::new();
        w.insert_resource(crate::core::flows::LiveMetrics::default());
        w.insert_resource(TickRate(hz));
        w
    }

    fn spawn_active(world: &mut World, bytes_since: u64, bps: f32, dir: Direction) -> Entity {
        world.spawn((
            TrafficStats { bytes_since_last_tick: bytes_since, bps, ..Default::default() },
            Timeline::default(),
            dir,
        )).id()
    }

    #[test]
    fn tick_ewma_blends_bytes_since_last_tick() {
        // hz=10, bytes_since=100 → instantaneous = 1000 bps
        // bps = 0.3 * 1000 + 0.7 * 0 = 300
        let mut world = setup_world(10);
        let e = spawn_active(&mut world, 100, 0.0, Direction::Unknown);
        world.run_system_once(tick).unwrap();
        let stats = world.get::<TrafficStats>(e).unwrap();
        let expected = EWMA_ALPHA * 1000.0;
        assert!((stats.bps - expected).abs() < 1.0, "bps = {}", stats.bps);
    }

    #[test]
    fn tick_resets_bytes_since_last_tick_to_zero() {
        let mut world = setup_world(30);
        let e = spawn_active(&mut world, 9000, 0.0, Direction::Unknown);
        world.run_system_once(tick).unwrap();
        assert_eq!(world.get::<TrafficStats>(e).unwrap().bytes_since_last_tick, 0);
    }

    #[test]
    fn tick_outbound_increments_tx_bps_inbound_increments_rx_bps() {
        let mut world = setup_world(10);
        spawn_active(&mut world, 100, 0.0, Direction::Outbound);
        spawn_active(&mut world, 200, 0.0, Direction::Inbound);
        world.run_system_once(tick).unwrap();
        let m = world.resource::<LiveMetrics>();
        // Both flows have bps = 0.3 * (bytes * 10); Outbound → tx, Inbound → rx.
        assert!(m.tx_bps > 0.0, "tx_bps should be > 0, got {}", m.tx_bps);
        assert!(m.rx_bps > 0.0, "rx_bps should be > 0, got {}", m.rx_bps);
        // Inbound flow had more bytes, so rx_bps > tx_bps.
        assert!(m.rx_bps > m.tx_bps, "rx_bps ({}) should exceed tx_bps ({})", m.rx_bps, m.tx_bps);
    }

    #[test]
    fn tick_active_and_expired_counts() {
        let mut world = setup_world(30);
        spawn_active(&mut world, 0, 0.0, Direction::Unknown);
        spawn_active(&mut world, 0, 0.0, Direction::Unknown);
        world.spawn((
            TrafficStats::default(),
            Timeline::default(),
            Direction::Unknown,
            Expired,
        ));
        world.run_system_once(tick).unwrap();
        let m = world.resource::<LiveMetrics>();
        assert_eq!(m.active_flows, 2);
        assert_eq!(m.expired_flows, 1);
    }

    #[test]
    fn tick_expired_flows_excluded_from_bps_rollup() {
        // An expired flow's bps must not contribute to tx/rx totals.
        let mut world = setup_world(10);
        world.spawn((
            TrafficStats { bytes_since_last_tick: 1000, bps: 500.0, ..Default::default() },
            Timeline::default(),
            Direction::Outbound,
            Expired, // excluded from the `Without<Expired>` query
        ));
        world.run_system_once(tick).unwrap();
        let m = world.resource::<LiveMetrics>();
        assert_eq!(m.tx_bps, 0.0, "expired flow must not contribute to tx_bps");
    }

    #[test]
    fn tick_rotates_timeline_ring_when_behind() {
        let mut world = setup_world(30);
        let e = world.spawn((
            TrafficStats::default(),
            Timeline {
                buckets: [0u32; 60],
                head: 0,
                current_bucket_bytes: 42,
                // Backdate by > 1 s to force at least one rotation.
                last_rotate: Instant::now()
                    .checked_sub(Duration::from_millis(1100))
                    .unwrap(),
            },
            Direction::Unknown,
        )).id();
        world.run_system_once(tick).unwrap();
        let t = world.get::<Timeline>(e).unwrap();
        // head must have advanced and the captured bucket must contain 42.
        assert!(t.head >= 1, "expected rotation, head = {}", t.head);
        assert_eq!(t.buckets[0], 42, "bucket[0] should hold pre-rotation value");
        assert_eq!(t.current_bucket_bytes, 0);
    }
}
