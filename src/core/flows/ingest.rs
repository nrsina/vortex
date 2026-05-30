use std::sync::atomic::Ordering;
use std::time::Instant;

use bevy_ecs::prelude::*;

use crate::core::flows::aggregator::DeltaChannel;
use crate::core::flows::components::{
    Direction, Expired, FirstSeen, LastSeen, Metadata, Timeline, TrafficStats,
};
use crate::core::flows::{FlowIndex, LiveMetrics, LocalAddrs};

pub fn ingest(
    mut commands: Commands,
    chan: Res<DeltaChannel>,
    local: Res<LocalAddrs>,
    mut index: ResMut<FlowIndex>,
    mut metrics: ResMut<LiveMetrics>,
    mut q: Query<(
        &mut TrafficStats,
        &mut Timeline,
        &mut LastSeen,
        &mut Metadata,
        Has<Expired>,
    )>,
) {
    // The system is gated on `DeltaChannel` existing (see `FlowsPlugin` in
    // `core/flows/mod.rs`), so if we got here the capture pipeline is up.
    let now = Instant::now();

    while let Ok(batch) = chan.rx.try_recv() {
        for d in batch {
            let entity = *index.0.entry(d.key).or_insert_with(|| {
                // `Direction` is classified once here from the host's local
                // addresses and never changes for the flow's lifetime.
                commands
                    .spawn((
                        d.key,
                        TrafficStats::default(),
                        Timeline::default(),
                        Metadata::default(),
                        Direction::classify(&d.key, &local),
                        LastSeen(now),
                        FirstSeen(now),
                    ))
                    .id()
            });

            if let Ok((mut stats, mut timeline, mut seen, mut meta, was_expired)) =
                q.get_mut(entity)
            {
                stats.bytes += d.bytes;
                stats.packets += d.packets;
                stats.bytes_since_last_tick += d.bytes;
                let bucket_add: u32 = d.bytes.try_into().unwrap_or(u32::MAX);
                timeline.current_bucket_bytes =
                    timeline.current_bucket_bytes.saturating_add(bucket_add);
                seen.0 = now;
                if d.last_summary.is_some() {
                    meta.last_summary = d.last_summary;
                }
                // DPI host: first sighting wins, never overwritten.
                if meta.app_host.is_none() && d.app_host.is_some() {
                    meta.app_host = d.app_host;
                }
                // Revival: traffic returned to a flow we'd marked expired, so
                // it's live again. Drop the marker (its `bps` recomputes next
                // `aggregate::tick`) — the entity and history are preserved.
                if was_expired {
                    commands.entity(entity).remove::<Expired>();
                }
            }
        }
    }

    // Mirror the shared (cumulative) drop counter into the resource the header
    // reads. Cheap relaxed load — exact ordering doesn't matter for a display.
    metrics.dropped_total = chan.dropped.load(Ordering::Relaxed);
}
