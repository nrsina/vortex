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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    use bevy_ecs::system::RunSystemOnce;
    use crossbeam_channel;

    use super::*;
    use crate::core::flows::aggregator::FlowDelta;
    use crate::core::flows::components::{Direction, FirstSeen, FlowKey, Metadata, Timeline};
    use crate::core::flows::dpi::AppKind;
    use crate::core::flows::test_support::flow_key;

    fn make_channel() -> (crossbeam_channel::Sender<Vec<FlowDelta>>, DeltaChannel) {
        let (tx, rx) = crossbeam_channel::unbounded();
        let dropped = Arc::new(AtomicU64::new(0));
        (tx, DeltaChannel { rx, dropped })
    }

    fn setup_world(chan: DeltaChannel) -> World {
        let mut world = World::new();
        world.insert_resource(FlowIndex::default());
        world.insert_resource(LiveMetrics::default());
        world.insert_resource(LocalAddrs::default());
        world.insert_resource(chan);
        world
    }

    fn delta(key: FlowKey, bytes: u64, packets: u64) -> FlowDelta {
        FlowDelta { key, bytes, packets, last_summary: None, app_host: None }
    }

    // Pre-populate a world with an entity that is already in FlowIndex so that
    // the next ingest call finds it via `q.get_mut` (rather than needing two
    // ticks for the deferred Commands::spawn to flush).
    fn spawn_indexed(world: &mut World, key: FlowKey) -> Entity {
        let e = world.spawn((
            key,
            TrafficStats::default(),
            Timeline::default(),
            Metadata::default(),
            Direction::default(),
            LastSeen::default(),
            FirstSeen::default(),
        )).id();
        world.resource_mut::<FlowIndex>().0.insert(key, e);
        e
    }

    #[test]
    fn ingest_new_delta_spawns_entity_and_indexes_it() {
        // Run 1: delta for a brand-new key → entity is spawned via Commands
        // (deferred). Commands are applied after `run_system_once`, so the
        // entity exists in the world afterwards. Note: the first batch's bytes
        // are intentionally "lost" (q.get_mut fails on a pending entity); they
        // start accumulating from the second run.
        let (tx, chan) = make_channel();
        let key = flow_key("1.2.3.4", 1000, "5.6.7.8", 443, 6);
        tx.send(vec![delta(key, 500, 3)]).unwrap();
        drop(tx);
        let mut world = setup_world(chan);
        world.run_system_once(ingest).unwrap();

        let index = world.resource::<FlowIndex>();
        assert!(index.0.contains_key(&key), "key must be indexed after first ingest");
        // Direction component must exist (classified at spawn).
        let &entity = index.0.get(&key).unwrap();
        assert!(world.get::<Direction>(entity).is_some());
    }

    #[test]
    fn ingest_stats_accumulate_from_second_run_onwards() {
        // First ingest: entity spawned (bytes of this batch are not accumulated
        // because q.get_mut fails for a pending entity).
        // Second ingest: entity is in world → bytes accumulated.
        let (tx, chan) = make_channel();
        let key = flow_key("10.0.0.1", 5000, "10.0.0.2", 80, 6);
        let mut world = setup_world(chan);

        tx.send(vec![delta(key, 0, 0)]).unwrap(); // tick 1: create entity
        world.run_system_once(ingest).unwrap();

        tx.send(vec![delta(key, 300, 3)]).unwrap(); // tick 2: accumulate
        world.run_system_once(ingest).unwrap();

        let &entity = world.resource::<FlowIndex>().0.get(&key).unwrap();
        let stats = world.get::<TrafficStats>(entity).unwrap();
        assert_eq!(stats.bytes, 300);
        assert_eq!(stats.packets, 3);
        assert_eq!(stats.bytes_since_last_tick, 300);
    }

    #[test]
    fn ingest_revives_expired_flow() {
        // Entity is pre-populated (already committed to the world) so that
        // q.get_mut succeeds and `commands.entity(e).remove::<Expired>()` fires.
        let key = flow_key("2.2.2.2", 2000, "3.3.3.3", 443, 6);
        let (tx, chan) = make_channel();
        let mut world = setup_world(chan);
        let entity = world.spawn((
            key,
            TrafficStats::default(),
            Timeline::default(),
            Metadata::default(),
            Direction::default(),
            LastSeen::default(),
            FirstSeen::default(),
            Expired,
        )).id();
        world.resource_mut::<FlowIndex>().0.insert(key, entity);

        tx.send(vec![delta(key, 1, 1)]).unwrap();
        drop(tx);
        world.run_system_once(ingest).unwrap();

        assert!(world.get::<Expired>(entity).is_none(), "Expired marker must be removed on revival");
    }

    #[test]
    fn ingest_app_host_first_write_wins() {
        // Pre-populate entity so both ingest runs find it via q.get_mut.
        let key = flow_key("4.4.4.4", 4000, "8.8.8.8", 53, 17);
        let (tx, chan) = make_channel();
        let mut world = setup_world(chan);
        spawn_indexed(&mut world, key);

        // First run: sets app_host to "first.example".
        tx.send(vec![FlowDelta {
            key,
            bytes: 1,
            packets: 1,
            last_summary: None,
            app_host: Some((AppKind::Dns, "first.example".to_string())),
        }]).unwrap();
        world.run_system_once(ingest).unwrap();

        // Second run: tries to overwrite — must be blocked by first-write-wins.
        tx.send(vec![FlowDelta {
            key,
            bytes: 1,
            packets: 1,
            last_summary: None,
            app_host: Some((AppKind::Dns, "second.example".to_string())),
        }]).unwrap();
        drop(tx);
        world.run_system_once(ingest).unwrap();

        let &entity = world.resource::<FlowIndex>().0.get(&key).unwrap();
        let meta = world.get::<Metadata>(entity).unwrap();
        let (_, host) = meta.app_host.as_ref().unwrap();
        assert_eq!(host, "first.example", "first-write-wins: app_host must not be overwritten");
    }

    #[test]
    fn ingest_bucket_bytes_saturate_at_u32_max() {
        // A delta whose byte count exceeds u32::MAX is clamped to u32::MAX in
        // the timeline bucket (saturating_add). Document the design limitation:
        // a single 1-second bucket is capped at ~4 GB (~34 Gbps).
        let key = flow_key("9.9.9.9", 9000, "1.1.1.1", 443, 6);
        let (tx, chan) = make_channel();
        let mut world = setup_world(chan);
        spawn_indexed(&mut world, key);

        tx.send(vec![FlowDelta {
            key,
            bytes: u32::MAX as u64 + 1, // overflows u32 → clamped to u32::MAX
            packets: 1,
            last_summary: None,
            app_host: None,
        }]).unwrap();
        drop(tx);
        world.run_system_once(ingest).unwrap();

        let &entity = world.resource::<FlowIndex>().0.get(&key).unwrap();
        let t = world.get::<Timeline>(entity).unwrap();
        assert_eq!(t.current_bucket_bytes, u32::MAX, "bucket bytes must saturate at u32::MAX");
    }
}
