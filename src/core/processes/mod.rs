pub mod components;
pub mod enrich;
pub mod snapshot;

use std::time::Duration;

use bevy_app::{App, Plugin, Update};
use bevy_ecs::prelude::*;
use bevy_ecs::schedule::common_conditions::resource_exists;
use crossbeam_channel::Receiver;
use rustc_hash::FxHashMap;

use crate::core::settings::settings;
use enrich::{aggregate_processes, enrich_flows};
use snapshot::ProcessSnapshot;

pub use components::{FlowProcess, ProcessInfo};

/// Latest known PID → process metadata. Replaced wholesale every snapshot so
/// dead processes drop out automatically; consulted by the dashboard for the
/// Process column and by the Processes screen for the per-process rows.
#[derive(Resource, Default)]
pub struct ProcessTable(pub FxHashMap<u32, ProcessInfo>);

/// Per-process aggregates (summed across all attributed flows). Rebuilt every
/// tick by `aggregate_processes`; ordered by the Processes screen's sort.
#[derive(Resource, Default)]
pub struct ProcessStats {
    pub by_pid: FxHashMap<u32, ProcessAggregate>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessAggregate {
    pub bps: f32,
    pub bytes: u64,
    pub packets: u64,
    pub conn_count: u32,
}

/// Receiver end of the snapshot-thread → ECS channel. Optional resource — when
/// `[processes].enabled = false` we never insert it, and the enrichment
/// systems no-op.
#[derive(Resource)]
pub struct ProcessSnapshotChannel(pub Receiver<ProcessSnapshot>);

/// Capacity 2 — drop-oldest semantics on the producer side, so a stalled UI
/// can never block the snapshot thread.
const SNAPSHOT_CHANNEL_CAPACITY: usize = 2;

pub struct ProcessesPlugin;

impl Plugin for ProcessesPlugin {
    fn build(&self, app: &mut App) {
        app.insert_resource(ProcessTable::default());
        app.insert_resource(ProcessStats::default());

        let cfg = settings().processes;
        if !cfg.enabled {
            tracing::info!("process attribution disabled via [processes].enabled = false");
            return;
        }

        let (tx, rx) = crossbeam_channel::bounded::<ProcessSnapshot>(SNAPSHOT_CHANNEL_CAPACITY);
        let handle = snapshot::spawn(tx, Duration::from_millis(cfg.poll_interval_ms));
        // Detach: the thread terminates when the sender drops (which happens
        // at process exit because the channel sits in a resource). Keeping the
        // join handle around would require teardown plumbing we don't need.
        std::mem::drop(handle);
        app.insert_resource(ProcessSnapshotChannel(rx));

        // Both run in `Update`. `enrich_flows` no longer needs an explicit
        // `.after(ingest)` edge — `ingest` stays in `PreUpdate`, so cross-phase
        // ordering (and the `Added<FlowKey>` visibility it relies on) is
        // automatic. Gated on `ProcessSnapshotChannel` existing so the system
        // body stays free of `Option<Res<…>>` checks — the resource is only
        // inserted when `[processes].enabled = true`.
        //
        // `aggregate_processes` runs after `flows::aggregate::tick` (so the bps
        // it sums matches what the dashboard sees this frame) AND after
        // `enrich_flows` — the latter is now required: `enrich_flows` inserts
        // `FlowProcess` via deferred `Commands`, and the explicit edge forces a
        // sync point that flushes those inserts before `aggregate_processes`
        // reads them. Previously the `PreUpdate`→`Update` phase boundary
        // provided this ordering for free.
        app.add_systems(
            Update,
            (
                enrich_flows.run_if(resource_exists::<ProcessSnapshotChannel>),
                aggregate_processes
                    .after(crate::core::flows::aggregate::tick)
                    .after(enrich_flows),
            ),
        );

        tracing::info!(
            "process attribution enabled (poll = {} ms)",
            cfg.poll_interval_ms
        );
    }
}
