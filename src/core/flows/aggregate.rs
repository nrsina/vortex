use std::time::{Duration, Instant};

use bevy_ecs::prelude::*;

use crate::core::flows::LiveMetrics;
use crate::core::flows::components::{Direction, Expired, Timeline, TrafficStats};
use crate::core::settings::settings;

const BUCKET_DURATION: Duration = Duration::from_secs(1);
const EWMA_ALPHA: f32 = 0.3;

/// Recompute each *active* flow's smoothed bps and rotate its timeline ring,
/// while rolling the per-direction throughput and the active/expired flow
/// counts up into `LiveMetrics` for the header. One pass over the live flow
/// set; the directional sums cost only a branch per flow. Expired flows are
/// excluded (`Without<Expired>`) — their bps was zeroed at expiry and their
/// timeline intentionally freezes — and counted separately via `q_expired`.
pub fn tick(
    mut metrics: ResMut<LiveMetrics>,
    mut q: Query<(&mut TrafficStats, &mut Timeline, &Direction), Without<Expired>>,
    q_expired: Query<(), With<Expired>>,
) {
    let now = Instant::now();
    let hz = settings().tick_rate_hz as f32;

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
