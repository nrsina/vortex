pub mod aggregate;
pub mod aggregator;
pub mod capture;
pub mod cleanup;
pub mod components;
pub mod dpi;
pub mod ingest;
pub mod ipclass;
pub mod packet;
pub mod service;

#[cfg(test)]
pub mod test_support;

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use anyhow::Result;
use bevy_app::{App, Plugin, PreUpdate, Update};
use bevy_ecs::prelude::*;
use bevy_ecs::schedule::common_conditions::resource_exists;
use bevy_time::common_conditions::on_timer;
use rustc_hash::{FxHashMap, FxHashSet};

use aggregator::{DeltaChannel, FlowDelta};
use components::FlowKey;
use crate::core::flows::cleanup::SWEEP_INTERVAL;
use crate::core::settings::{settings, TickRate};

#[derive(Resource, Default)]
pub struct FlowIndex(pub FxHashMap<FlowKey, Entity>);

/// Interface-wide live metrics, surfaced in the dashboard header. The
/// directional throughput split is rolled up each tick by `aggregate::tick`
/// from every flow's `Direction`; `dropped_total` is read by `ingest` from the
/// shared capture/aggregator drop counter (so silent loss under load becomes
/// visible). Replaces the former `CaptureMetrics` placeholder.
#[derive(Resource, Default)]
pub struct LiveMetrics {
    /// Cumulative packets discarded at a full channel (capture→aggregator or
    /// aggregator→ECS) since capture started.
    pub dropped_total: u64,
    /// Summed EWMA throughput of outbound flows, bytes/s.
    pub tx_bps: f32,
    /// Summed EWMA throughput of inbound flows, bytes/s.
    pub rx_bps: f32,
    /// Count of active (non-expired) flows this tick.
    pub active_flows: usize,
    /// Count of retained expired (idle past timeout) flows this tick. Header
    /// total = `active_flows + expired_flows`.
    pub expired_flows: usize,
}

/// The set of IP addresses belonging to this host on the captured interface.
/// Built once when the pipeline starts and read by `ingest` to tag each flow's
/// `Direction`. Reuses `InterfaceInfo.ipv4/ipv6` from `list_interfaces`.
#[derive(Resource, Default, Debug, Clone)]
pub struct LocalAddrs(pub FxHashSet<IpAddr>);

impl LocalAddrs {
    /// Collect this host's addresses for the chosen capture target. For a named
    /// device we take that device's addrs; for the `any` pseudo-device we union
    /// every interface's addrs (since `any` itself reports none).
    pub fn for_interface(iface: &str) -> Self {
        let mut set = FxHashSet::default();
        if let Ok(ifaces) = capture::list_interfaces() {
            for i in &ifaces {
                if iface == "any" || i.name == iface {
                    if let Some(v4) = i.ipv4 {
                        set.insert(v4);
                    }
                    if let Some(v6) = i.ipv6 {
                        set.insert(v6);
                    }
                }
            }
        }
        LocalAddrs(set)
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.0.contains(ip)
    }
}

const DELTA_CHANNEL_CAPACITY: usize = 64;
const PACKET_CHANNEL_CAPACITY: usize = 32_768;

pub struct FlowsPlugin;

impl Plugin for FlowsPlugin {
    fn build(&self, app: &mut App) {
        let world = app.world_mut();
        world.insert_resource(FlowIndex::default());
        world.insert_resource(LiveMetrics::default());
        // Always present so `ingest`'s `Res<LocalAddrs>` never goes missing;
        // `start_pipeline` overwrites it with the real set when capture begins.
        world.insert_resource(LocalAddrs::default());
        // Flow-lifecycle settings injected as resources so system tests can
        // override them without touching the global `settings()` OnceLock.
        world.insert_resource(settings().flows);
        world.insert_resource(TickRate(settings().tick_rate_hz));

        // `ingest` only fires once the user picks an interface and the
        // capture pipeline has been started (`start_pipeline` inserts the
        // `DeltaChannel` resource). Gating at registration time keeps the
        // system body free of `Option<Res<…>>` bail-outs.
        app.add_systems(
            PreUpdate,
            crate::core::flows::ingest::ingest.run_if(resource_exists::<DeltaChannel>),
        );
        // `expire_idle` (marks idle flows expired) and `evict_expired` (caps
        // the retained-expired set) are both gated by `on_timer(SWEEP_INTERVAL)`
        // so they only claim their `Commands`/`ResMut<FlowIndex>` slots on the
        // firing tick — every other tick their conflict-graph footprint is
        // zero, freeing the scheduler to parallelise neighbours.
        app.add_systems(
            Update,
            (
                crate::core::flows::aggregate::tick,
                crate::core::flows::cleanup::expire_idle.run_if(on_timer(SWEEP_INTERVAL)),
                crate::core::flows::cleanup::evict_expired.run_if(on_timer(SWEEP_INTERVAL)),
            ),
        );
    }
}

/// Everything `start_pipeline` produces for the caller to insert into the ECS
/// world: the delta channel (carrying its shared drop counter) and the set of
/// local addresses used for per-flow direction classification.
pub struct CapturePipeline {
    pub channel: DeltaChannel,
    pub local_addrs: LocalAddrs,
}

pub fn start_pipeline(iface: &str, filter: Option<&str>) -> Result<CapturePipeline> {
    let cfg = settings().capture;
    // Shared loss counter: bumped by the capture thread and the aggregator
    // thread on a full channel, read back into `LiveMetrics` by `ingest`.
    let dropped = Arc::new(AtomicU64::new(0));
    let packets = capture::start(
        iface,
        PACKET_CHANNEL_CAPACITY,
        filter,
        cfg.snaplen,
        cfg.promisc,
        Arc::clone(&dropped),
    )?;
    let flush_interval = Duration::from_secs_f64(1.0 / settings().tick_rate_hz as f64);
    let (delta_tx, delta_rx) =
        crossbeam_channel::bounded::<Vec<FlowDelta>>(DELTA_CHANNEL_CAPACITY);
    aggregator::spawn(packets, delta_tx, flush_interval, Arc::clone(&dropped));
    Ok(CapturePipeline {
        channel: DeltaChannel {
            rx: delta_rx,
            dropped,
        },
        local_addrs: LocalAddrs::for_interface(iface),
    })
}

pub fn stop_pipeline(commands: &mut Commands) {
    commands.remove_resource::<DeltaChannel>();
    // Reset (rather than remove) so the always-present `LocalAddrs` invariant
    // holds for `ingest` even between captures.
    commands.insert_resource(LocalAddrs::default());
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    use bevy_ecs::prelude::*;
    use bevy_ecs::schedule::ExecutorKind;

    use super::*;
    use crate::core::flows::aggregate::tick;
    use crate::core::flows::aggregator::{DeltaChannel, FlowDelta};
    use crate::core::flows::ingest::ingest;
    use crate::core::flows::test_support::flow_key;
    use crate::core::settings::{FlowSettings, TickRate};

    /// Two-tick integration test: `ingest` spawns an entity (tick 1), then
    /// `tick` processes its `bytes_since_last_tick` and writes `bps` (tick 2).
    /// Validates that the two systems can run in a shared `Schedule` without
    /// resource conflicts and that their hand-off semantics are correct.
    #[test]
    fn two_tick_schedule_ingest_then_aggregate() {
        let (tx, rx) = crossbeam_channel::unbounded::<Vec<FlowDelta>>();
        let dropped = Arc::new(AtomicU64::new(0));

        let mut world = World::new();
        world.insert_resource(FlowIndex::default());
        world.insert_resource(LiveMetrics::default());
        world.insert_resource(LocalAddrs::default());
        world.insert_resource(DeltaChannel { rx, dropped });
        // Hz=10 so bytes_since_last_tick * 10 is the instantaneous bps.
        world.insert_resource(TickRate(10));
        world.insert_resource(FlowSettings::default());

        let mut schedule = Schedule::default();
        schedule.set_executor_kind(ExecutorKind::SingleThreaded);
        // Chain ensures ingest runs before tick in every schedule execution.
        schedule.add_systems((ingest, tick).chain());

        let key = flow_key("10.0.0.1", 5000, "10.0.0.2", 443, 6);

        // Tick 1: send batch so ingest spawns the entity (via deferred Commands).
        // tick sees 0 active flows this round; deferred spawn flushes at end of run.
        tx.send(vec![FlowDelta {
            key,
            bytes: 1000,
            packets: 1,
            last_summary: None,
            app_host: None,
        }]).unwrap();
        schedule.run(&mut world);

        // Entity should now exist in FlowIndex.
        assert!(
            world.resource::<FlowIndex>().0.contains_key(&key),
            "entity must be indexed after tick 1"
        );

        // Tick 2: ingest has nothing new; tick processes the entity. The
        // bytes_since_last_tick from tick 1 (0, first-batch is lost for a new
        // entity) will be processed. Send another batch so tick 2 has
        // bytes_since_last_tick = 2000 which feeds the EWMA.
        tx.send(vec![FlowDelta {
            key,
            bytes: 2000,
            packets: 2,
            last_summary: None,
            app_host: None,
        }]).unwrap();
        schedule.run(&mut world);

        // After tick 2 the entity has bps > 0 (2000 bytes × 10 Hz × EWMA).
        let &entity = world.resource::<FlowIndex>().0.get(&key).unwrap();
        let stats = world.get::<crate::core::flows::components::TrafficStats>(entity).unwrap();
        assert!(stats.bps > 0.0, "bps should be > 0 after two ticks, got {}", stats.bps);
        assert_eq!(stats.bytes_since_last_tick, 0, "tick must reset bytes_since_last_tick");

        // LiveMetrics must reflect the one active flow.
        let m = world.resource::<LiveMetrics>();
        assert_eq!(m.active_flows, 1);
    }
}
