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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use crate::core::flows::components::Direction;
    use crate::core::flows::test_support::{flow_key, traffic_stats};

    fn row_with_process(pid: Option<u32>, name: Option<&str>) -> FlowRow {
        FlowRow {
            key: flow_key("1.2.3.4", 1234, "5.6.7.8", 443, 6),
            stats: traffic_stats(0, 0.0, 0),
            direction: Direction::Unknown,
            last_summary: None,
            app_host: None,
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            expired: false,
            pid,
            process_name: name.map(String::from),
        }
    }

    // --- format_process ---

    #[test]
    fn format_process_short_name_with_pid() {
        assert_eq!(format_process(Some(42), Some("firefox")), "firefox(42)");
    }

    #[test]
    fn format_process_long_name_truncated_at_14_chars() {
        // Name > 14 chars gets truncated to 13 + '…', then (pid) appended.
        let long = "verylongprocess"; // 15 chars
        let result = format_process(Some(7), Some(long));
        // First 13 chars of "verylongprocess" + '…' + "(7)"
        assert!(result.starts_with("verylongproce…"), "got: {result:?}");
        assert!(result.ends_with("(7)"), "got: {result:?}");
    }

    #[test]
    fn format_process_pid_fallback_when_no_name() {
        assert_eq!(format_process(Some(99), None), "pid:99");
    }

    #[test]
    fn format_process_dash_when_no_pid() {
        assert_eq!(format_process(None, None), "-");
        assert_eq!(format_process(None, Some("ignored")), "-");
    }

    // --- process_sort_key ---

    #[test]
    fn process_sort_key_attributed_before_unattributed() {
        let attributed = row_with_process(Some(1), Some("curl"));
        let unattributed = row_with_process(None, None);
        // Attributed row's key bucket (0 < 1) sorts before unattributed.
        assert!(process_sort_key(&attributed) < process_sort_key(&unattributed));
    }

    #[test]
    fn process_sort_key_orders_by_name_then_pid() {
        let a = row_with_process(Some(10), Some("alpha"));
        let b = row_with_process(Some(20), Some("beta"));
        let a2 = row_with_process(Some(20), Some("alpha")); // same name, higher pid
        // "alpha" < "beta" alphabetically.
        assert!(process_sort_key(&a) < process_sort_key(&b));
        // Same name: lower pid first.
        assert!(process_sort_key(&a) < process_sort_key(&a2));
    }
}
