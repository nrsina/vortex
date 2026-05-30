//! Shared row builders/helpers for the Dashboard screen.
//!
//! Mirrors the role of `screens::processes::tree`: both the live and frozen
//! paths materialise the same owned `FlowRow` shape, so the renderer and
//! sort logic don't have to branch on the source. Centralising the build
//! here gives `keys.rs` (pause snapshot) and `render.rs` (per-frame) a
//! single source of truth.

use bevy_ecs::prelude::{Has, Query};

use crate::core::flows::components::{
    Direction, Expired, FirstSeen, FlowKey, LastSeen, Metadata, TrafficStats,
};
use crate::core::processes::{FlowProcess, ProcessTable};
use crate::screens::dashboard::state::{DashboardState, FlowRow};

/// Return the rows the dashboard should render this frame: the frozen
/// snapshot when paused, freshly built from live ECS state otherwise.
#[allow(clippy::type_complexity)]
pub fn current_rows(
    state: &DashboardState,
    flows: &Query<(
        &FlowKey,
        &TrafficStats,
        &Metadata,
        &FirstSeen,
        &LastSeen,
        &Direction,
        Has<Expired>,
        Option<&FlowProcess>,
    )>,
    table: &ProcessTable,
) -> Vec<FlowRow> {
    match state.frozen.as_deref() {
        Some(frozen) => frozen.to_vec(),
        None => build_live_rows(flows, table),
    }
}

/// Walk the live flow query once and clone each row into an owned `FlowRow`.
/// Resolving the process name here means the frozen view stays stable even
/// if `enrich_flows` GCs the PID out of `ProcessTable` during pause.
#[allow(clippy::type_complexity)]
pub fn build_live_rows(
    flows: &Query<(
        &FlowKey,
        &TrafficStats,
        &Metadata,
        &FirstSeen,
        &LastSeen,
        &Direction,
        Has<Expired>,
        Option<&FlowProcess>,
    )>,
    table: &ProcessTable,
) -> Vec<FlowRow> {
    flows
        .iter()
        .map(|(key, stats, meta, first_seen, last_seen, direction, expired, fp)| {
            let pid = fp.map(|f| f.pid);
            let process_name = pid
                .and_then(|p| table.0.get(&p))
                .map(|info| info.name.clone());
            FlowRow {
                key: *key,
                stats: stats.clone(),
                direction: *direction,
                last_summary: meta.last_summary.clone(),
                app_host: meta.app_host.clone(),
                first_seen: first_seen.0,
                last_seen: last_seen.0,
                expired,
                pid,
                process_name,
            }
        })
        .collect()
}

/// Render a flow's owning process as `name(pid)`. Falls back to `pid:N` when
/// we have a PID but no name (e.g. ProcessTable hasn't caught up), and to
/// `-` when there's no attribution at all. Shape matches the 22-cell column.
pub fn process_label(row: &FlowRow) -> String {
    format_process(row.pid, row.process_name.as_deref())
}

/// Shared `name(pid)` formatter so the per-flow table and the merged
/// connection table render attribution identically. See [`process_label`].
pub fn format_process(pid: Option<u32>, name: Option<&str>) -> String {
    let Some(pid) = pid else {
        return "-".to_string();
    };
    match name {
        Some(name) => {
            // Names on Linux are capped at 15 chars; on macOS / Windows they
            // can be longer. Truncate so the `(pid)` always stays visible.
            let mut name = name.to_string();
            if name.chars().count() > 14 {
                name = name.chars().take(13).chain(std::iter::once('…')).collect();
            }
            format!("{name}({pid})")
        }
        None => format!("pid:{pid}"),
    }
}

/// Order processes by name then PID; unattributed flows sort last so the
/// attributed ones cluster together at the top in ascending mode. Borrows
/// the name out of the row so callers can sort without cloning.
pub fn process_sort_key(row: &FlowRow) -> (u8, &str, u32) {
    match row.pid {
        Some(pid) => (0, row.process_name.as_deref().unwrap_or(""), pid),
        None => (1, "", u32::MAX),
    }
}
