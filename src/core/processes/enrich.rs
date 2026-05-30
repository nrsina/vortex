use bevy_ecs::prelude::*;

use crate::core::flows::FlowIndex;
use crate::core::flows::components::{FlowKey, TrafficStats};
use crate::core::processes::components::FlowProcess;
use crate::core::processes::{ProcessSnapshotChannel, ProcessStats, ProcessTable, ProcessAggregate};

/// Drain whatever the snapshot thread has produced since the last tick and:
///   1. Replace `ProcessTable` with the new PID → metadata view.
///   2. Tag matching flow entities with `FlowProcess(pid)`.
///
/// We deliberately don't *clear* `FlowProcess` when a flow falls out of the
/// snapshot — a short-lived process can exit before its packets stop flowing,
/// and the last-known PID is more useful than nothing. The flow itself expires
/// after 30 s of idleness via `cleanup::expire_idle`, which takes the stale
/// `FlowProcess` with it.
pub fn enrich_flows(
    mut commands: Commands,
    chan: Res<ProcessSnapshotChannel>,
    mut table: ResMut<ProcessTable>,
    index: Res<FlowIndex>,
    existing: Query<&FlowProcess>,
) {
    // System is gated on `ProcessSnapshotChannel` existing — see
    // `ProcessesPlugin` in `core/processes/mod.rs`. Drain to the most recent
    // snapshot; if the channel held multiple, older ones are stale.
    let mut latest = None;
    while let Ok(snap) = chan.0.try_recv() {
        latest = Some(snap);
    }
    let Some(snap) = latest else { return };

    tracing::debug!(
        "enrich_flows: snapshot sockets={} processes={} flow_index_len={}",
        snap.sockets.len(),
        snap.processes.len(),
        index.0.len(),
    );

    // Merge instead of replace. Mark every existing entry as dead first; any
    // PID present in the new snapshot revives back to alive in the next pass.
    // Dead entries linger so flows referencing a just-exited process can still
    // render the original name and a visible "dead" status (rather than `?`).
    for info in table.0.values_mut() {
        info.alive = false;
    }
    for (pid, info) in snap.processes {
        table.0.insert(pid, info);
    }
    // Garbage-collect dead entries that no longer have a referencing flow.
    // Without this the table would grow unbounded over long sessions.
    let referenced: rustc_hash::FxHashSet<u32> = existing.iter().map(|fp| fp.pid).collect();
    table.0.retain(|pid, info| info.alive || referenced.contains(pid));

    let mut matched = 0usize;
    let mut sample_flow: Option<crate::core::flows::components::FlowKey> = None;
    for (key, entity) in index.0.iter() {
        if sample_flow.is_none() {
            sample_flow = Some(*key);
        }
        let src = (key.src_ip, key.src_port, key.proto);
        let dst = (key.dst_ip, key.dst_port, key.proto);
        let Some(&pid) = snap.sockets.get(&src).or_else(|| snap.sockets.get(&dst)) else {
            continue;
        };
        matched += 1;
        match existing.get(*entity) {
            Ok(fp) if fp.pid == pid => {} // unchanged
            _ => {
                commands.entity(*entity).insert(FlowProcess { pid });
            }
        }
    }
    if let Some(s) = sample_flow {
        let sample_sock: Vec<_> = snap.sockets.iter().take(3).collect();
        tracing::debug!(
            "enrich_flows: matched={}/{} sample_flow=src={}:{} dst={}:{} proto={} sample_sockets={:?}",
            matched,
            index.0.len(),
            s.src_ip, s.src_port, s.dst_ip, s.dst_port, s.proto,
            sample_sock,
        );
    }
}

/// Recompute per-process aggregates from the current set of attributed flows.
/// Cheap: O(flows) per tick with no allocations after the first run because we
/// reuse the same `HashMap`.
pub fn aggregate_processes(
    mut stats: ResMut<ProcessStats>,
    flows: Query<(&FlowProcess, &TrafficStats), With<FlowKey>>,
) {
    stats.by_pid.clear();
    for (fp, ts) in &flows {
        let agg = stats.by_pid.entry(fp.pid).or_insert(ProcessAggregate {
            bps: 0.0,
            bytes: 0,
            packets: 0,
            conn_count: 0,
        });
        agg.bps += ts.bps;
        agg.bytes += ts.bytes;
        agg.packets += ts.packets;
        agg.conn_count += 1;
    }
}
