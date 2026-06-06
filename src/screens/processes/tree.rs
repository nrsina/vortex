//! Shared tree-flattening helpers for the Processes screen.
//!
//! Both `render.rs` and `keys.rs` need to walk parents in the same order,
//! with the same children, so cursor navigation (in `keys.rs`) stays aligned
//! with what the user sees on screen (drawn by `render.rs`). Centralising
//! the build + sort logic here removes the risk of the two going out of
//! sync, and gives both call sites a single source of truth for the
//! paused/live branch.

use std::cmp::Ordering;
use std::net::IpAddr;
use std::time::Instant;

use bevy_ecs::prelude::{Has, Query};
use rustc_hash::FxHashMap;

use crate::core::flows::components::{Direction, Expired, FirstSeen, FlowKey, TrafficStats};
use crate::core::processes::{FlowProcess, ProcessStats, ProcessTable};
use crate::screens::common::{ConnKey, SortDirection, conn_key, orient};
use crate::screens::processes::state::{
    FrozenProcessRow, ProcSortColumn, ProcessesState,
};

/// Return the parent list the screen should render this frame: the frozen
/// snapshot when paused, freshly built from live ECS state otherwise.
/// `Has<Expired>` rides the flow query so each child can be tagged for the
/// show/hide-expired filter and dimmed style.
#[allow(clippy::type_complexity)]
pub fn current_parents(
    state: &ProcessesState,
    stats: &ProcessStats,
    table: &ProcessTable,
    flows: &Query<(
        &FlowKey,
        &TrafficStats,
        &FlowProcess,
        &FirstSeen,
        &Direction,
        Has<Expired>,
    )>,
) -> Vec<FrozenProcessRow> {
    match state.frozen.as_deref() {
        Some(frozen) => frozen.to_vec(),
        None => build_live_parents(stats, table, flows),
    }
}

/// Materialise the live ECS state into the same owned `FrozenProcessRow`
/// shape the frozen path uses. Children come out unsorted — `sort_parents`
/// owns the final ordering so the live and frozen paths share one sort site.
#[allow(clippy::type_complexity)]
pub fn build_live_parents(
    stats: &ProcessStats,
    table: &ProcessTable,
    flows: &Query<(
        &FlowKey,
        &TrafficStats,
        &FlowProcess,
        &FirstSeen,
        &Direction,
        Has<Expired>,
    )>,
) -> Vec<FrozenProcessRow> {
    let mut by_pid: rustc_hash::FxHashMap<
        u32,
        Vec<(FlowKey, TrafficStats, Instant, bool, Direction)>,
    > = rustc_hash::FxHashMap::default();
    for (key, ts, fp, first_seen, dir, expired) in flows.iter() {
        by_pid
            .entry(fp.pid)
            .or_default()
            .push((*key, ts.clone(), first_seen.0, expired, *dir));
    }

    stats
        .by_pid
        .iter()
        .map(|(pid, agg)| {
            let info = table.0.get(pid);
            let name = info.map(|i| i.name.clone()).unwrap_or_else(|| "?".to_string());
            let user = info.and_then(|i| i.user.clone());
            let cmd = info
                .map(|i| {
                    if i.cmdline.is_empty() {
                        i.exe
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default()
                    } else {
                        i.cmdline.join(" ")
                    }
                })
                .unwrap_or_default();
            let alive = info.map(|i| i.alive).unwrap_or(false);
            let children = by_pid.remove(pid).unwrap_or_default();
            FrozenProcessRow {
                pid: *pid,
                name,
                user,
                cmd,
                alive,
                agg: *agg,
                children,
            }
        })
        .collect()
}

/// Sort parents by the user's chosen column/direction. `Fixed` is
/// direction-less and falls back to PID-ascending order so rows don't
/// shuffle on every snapshot. Each parent's children are sorted in the
/// same pass so the entire tree obeys one unified sort selection.
pub fn sort_parents(
    parents: &mut [FrozenProcessRow],
    column: ProcSortColumn,
    direction: SortDirection,
) {
    parents.sort_by(|a, b| {
        let primary = match column {
            ProcSortColumn::Fixed => Ordering::Equal,
            ProcSortColumn::Pid => a.pid.cmp(&b.pid),
            ProcSortColumn::Name => a.name.cmp(&b.name),
            ProcSortColumn::ConnCount => a.agg.conn_count.cmp(&b.agg.conn_count),
            ProcSortColumn::Bps => a
                .agg
                .bps
                .partial_cmp(&b.agg.bps)
                .unwrap_or(Ordering::Equal),
            ProcSortColumn::Bytes => a.agg.bytes.cmp(&b.agg.bytes),
            ProcSortColumn::User => {
                let au = a.user.as_deref().unwrap_or("");
                let bu = b.user.as_deref().unwrap_or("");
                au.cmp(bu)
            }
        };
        let primary = if column == ProcSortColumn::Fixed {
            primary
        } else if direction == SortDirection::Desc {
            primary.reverse()
        } else {
            primary
        };
        primary.then_with(|| a.pid.cmp(&b.pid))
    });

    for parent in parents.iter_mut() {
        sort_children(&mut parent.children, column, direction);
    }
}

/// Apply the parent's sort selection to a single parent's flow children.
/// Only `Bps` and `Bytes` map to per-flow values; everything else (including
/// `Fixed`) falls back to `FirstSeen` ascending, which is also used as the
/// stable tiebreaker so equal-traffic rows never jitter.
fn sort_children(
    children: &mut [(FlowKey, TrafficStats, Instant, bool, Direction)],
    column: ProcSortColumn,
    direction: SortDirection,
) {
    use ProcSortColumn::*;
    children.sort_by(|a, b| {
        let primary = match column {
            Bps => a.1.bps.partial_cmp(&b.1.bps).unwrap_or(Ordering::Equal),
            Bytes => a.1.bytes.cmp(&b.1.bytes),
            _ => Ordering::Equal,
        };
        let primary = if matches!(column, Bps | Bytes) && direction == SortDirection::Desc {
            primary.reverse()
        } else {
            primary
        };
        primary.then_with(|| a.2.cmp(&b.2))
    });
}

/// One rendered child line beneath a process. In the per-flow view it's a
/// single directed flow (`src → dst:dport`); in the connection view (`a`) it's
/// a connection's two opposing flows merged into one `local ⇄ remote:rport`
/// row with combined throughput (the ↑ tx / ↓ rx split shows in the details
/// overlay, since the tree's columns are shared with the process rows).
#[derive(Debug, Clone)]
pub enum ChildRow {
    Flow {
        key: FlowKey,
        stats: TrafficStats,
        expired: bool,
    },
    Conn {
        proto: u8,
        local: (IpAddr, u16),
        remote: (IpAddr, u16),
        bytes: u64,
        bps: f32,
        expired: bool,
        first_seen: Instant,
        /// Flow whose details open on Enter (the outbound half when present);
        /// its `conn_key` recovers both halves for the connection overlay.
        detail_key: FlowKey,
    },
}

/// Build the visible child rows for one parent: filter expired children
/// (unless `e`), and — when `aggregate` (`a`) is on — fold each connection's
/// two opposing flows into a single merged row. Called identically by the
/// renderer and the key handler so the flattened-tree cursor stays aligned
/// with what's drawn. The per-flow path preserves `sort_children`'s order; the
/// merged path re-sorts (Bps/Bytes by total, else by first-seen).
pub fn child_rows(
    parent: &FrozenProcessRow,
    show_expired: bool,
    aggregate: bool,
    column: ProcSortColumn,
    direction: SortDirection,
) -> Vec<ChildRow> {
    if !aggregate {
        return parent
            .children
            .iter()
            .filter(|(_, _, _, expired, _)| show_expired || !*expired)
            .map(|(key, stats, _first_seen, expired, _dir)| ChildRow::Flow {
                key: *key,
                stats: stats.clone(),
                expired: *expired,
            })
            .collect();
    }

    // Group the parent's children by canonical connection key. Merge from the
    // full set (expired included) so a connection counts as expired only when
    // *every* half is — matching the dashboard's semantics.
    let mut out: Vec<ChildRow> = Vec::new();
    let mut index: FxHashMap<ConnKey, usize> = FxHashMap::default();
    for (key, stats, first_seen, expired, dir) in &parent.children {
        let ck = conn_key(key);
        let ep = orient(key, *dir);
        let idx = *index.entry(ck).or_insert_with(|| {
            out.push(ChildRow::Conn {
                proto: key.proto,
                local: ep.local,
                remote: ep.remote,
                bytes: 0,
                bps: 0.0,
                expired: true,
                first_seen: *first_seen,
                detail_key: *key,
            });
            out.len() - 1
        });
        if let ChildRow::Conn {
            bytes,
            bps,
            expired: cexp,
            first_seen: cfs,
            detail_key,
            local,
            ..
        } = &mut out[idx]
        {
            *bytes += stats.bytes;
            *bps += stats.bps;
            *cexp = *cexp && *expired;
            *cfs = (*cfs).min(*first_seen);
            // Anchor the overlay on the outbound (tx) half: the one whose src
            // is the local endpoint.
            if (key.src_ip, key.src_port) == *local {
                *detail_key = *key;
            }
        }
    }

    if !show_expired {
        out.retain(|c| !matches!(c, ChildRow::Conn { expired: true, .. }));
    }

    out.sort_by(|a, b| {
        let (ab, abps, afs) = conn_sort_fields(a);
        let (bb, bbps, bfs) = conn_sort_fields(b);
        let primary = match column {
            ProcSortColumn::Bps => abps.partial_cmp(&bbps).unwrap_or(Ordering::Equal),
            ProcSortColumn::Bytes => ab.cmp(&bb),
            _ => Ordering::Equal,
        };
        let primary = if matches!(column, ProcSortColumn::Bps | ProcSortColumn::Bytes)
            && direction == SortDirection::Desc
        {
            primary.reverse()
        } else {
            primary
        };
        primary.then_with(|| afs.cmp(&bfs))
    });

    out
}

/// `(bytes, bps, first_seen)` sort fields for a merged child. Only `Conn` rows
/// reach this (the merged path produces nothing else).
fn conn_sort_fields(c: &ChildRow) -> (u64, f32, Instant) {
    match c {
        ChildRow::Conn {
            bytes,
            bps,
            first_seen,
            ..
        } => (*bytes, *bps, *first_seen),
        ChildRow::Flow { stats, .. } => (stats.bytes, stats.bps, Instant::now()),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::core::common::IPPROTO_TCP;
    use crate::core::processes::ProcessAggregate;
    use crate::core::flows::test_support::{flow_key, traffic_stats};
    use crate::screens::common::SortDirection;
    use crate::screens::processes::state::{FrozenProcessRow, ProcSortColumn};

    fn make_parent(pid: u32, name: &str, bps: f32, bytes: u64) -> FrozenProcessRow {
        FrozenProcessRow {
            pid,
            name: name.to_string(),
            user: None,
            cmd: String::new(),
            alive: true,
            agg: ProcessAggregate { bps, bytes, packets: 0, conn_count: 1 },
            children: vec![],
        }
    }

    fn child(bytes: u64, bps: f32, expired: bool, ago_secs: u64) -> (FlowKey, TrafficStats, Instant, bool, Direction) {
        let first_seen = Instant::now()
            .checked_sub(Duration::from_secs(ago_secs))
            .unwrap_or_else(Instant::now);
        (
            flow_key("10.0.0.1", 1234, "8.8.8.8", 53, IPPROTO_TCP),
            traffic_stats(bytes, bps, 0),
            first_seen,
            expired,
            Direction::Outbound,
        )
    }

    // --- sort_parents ---

    #[test]
    fn sort_parents_fixed_orders_by_pid_asc() {
        let mut parents = vec![
            make_parent(30, "c", 0.0, 0),
            make_parent(10, "a", 0.0, 0),
            make_parent(20, "b", 0.0, 0),
        ];
        sort_parents(&mut parents, ProcSortColumn::Fixed, SortDirection::Asc);
        let pids: Vec<u32> = parents.iter().map(|p| p.pid).collect();
        assert_eq!(pids, [10, 20, 30]);
    }

    #[test]
    fn sort_parents_by_bps_desc() {
        let mut parents = vec![
            make_parent(1, "low", 10.0, 0),
            make_parent(2, "high", 100.0, 0),
            make_parent(3, "mid", 50.0, 0),
        ];
        sort_parents(&mut parents, ProcSortColumn::Bps, SortDirection::Desc);
        let bps: Vec<u32> = parents.iter().map(|p| p.agg.bps as u32).collect();
        assert_eq!(bps, [100, 50, 10]);
    }

    #[test]
    fn sort_parents_by_name_asc() {
        let mut parents = vec![
            make_parent(1, "zsh", 0.0, 0),
            make_parent(2, "curl", 0.0, 0),
            make_parent(3, "bash", 0.0, 0),
        ];
        sort_parents(&mut parents, ProcSortColumn::Name, SortDirection::Asc);
        let names: Vec<&str> = parents.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["bash", "curl", "zsh"]);
    }

    #[test]
    fn sort_parents_direction_reversal() {
        let mut asc = vec![
            make_parent(1, "a", 10.0, 0),
            make_parent(2, "b", 50.0, 0),
            make_parent(3, "c", 30.0, 0),
        ];
        let mut desc = asc.clone();
        sort_parents(&mut asc, ProcSortColumn::Bps, SortDirection::Asc);
        sort_parents(&mut desc, ProcSortColumn::Bps, SortDirection::Desc);
        let pids_asc: Vec<u32> = asc.iter().map(|p| p.pid).collect();
        let pids_desc: Vec<u32> = desc.iter().map(|p| p.pid).collect();
        assert_ne!(pids_asc, pids_desc);
        // Desc reverses Asc (reversed order).
        let mut reversed = pids_asc.clone();
        reversed.reverse();
        assert_eq!(pids_desc, reversed);
    }

    #[test]
    fn sort_parents_also_sorts_children_by_bps() {
        let mut parent = make_parent(1, "p", 0.0, 0);
        parent.children = vec![
            child(100, 10.0, false, 3),
            child(500, 80.0, false, 1),
            child(200, 40.0, false, 2),
        ];
        sort_parents(
            std::slice::from_mut(&mut parent),
            ProcSortColumn::Bps,
            SortDirection::Desc,
        );
        let bps: Vec<u32> = parent.children.iter().map(|(_, s, _, _, _)| s.bps as u32).collect();
        assert_eq!(bps, [80, 40, 10]);
    }

    // --- child_rows ---

    #[test]
    fn child_rows_non_aggregate_returns_flows() {
        let mut parent = make_parent(1, "p", 0.0, 0);
        parent.children = vec![
            child(100, 10.0, false, 2),
            child(200, 20.0, false, 1),
        ];
        let rows = child_rows(&parent, true, false, ProcSortColumn::Fixed, SortDirection::Asc);
        assert_eq!(rows.len(), 2);
        for r in &rows {
            assert!(matches!(r, ChildRow::Flow { .. }));
        }
    }

    #[test]
    fn child_rows_filters_expired_when_hidden() {
        let mut parent = make_parent(1, "p", 0.0, 0);
        parent.children = vec![
            child(100, 10.0, false, 2), // alive
            child(200, 20.0, true, 1),  // expired
        ];
        let visible = child_rows(&parent, false, false, ProcSortColumn::Fixed, SortDirection::Asc);
        assert_eq!(visible.len(), 1);
        if let ChildRow::Flow { expired, .. } = &visible[0] {
            assert!(!expired);
        }
    }

    #[test]
    fn child_rows_aggregate_merges_opposing_flows_into_conn() {
        let outbound_key = flow_key("10.0.0.1", 1234, "8.8.8.8", 53, IPPROTO_TCP);
        let inbound_key  = flow_key("8.8.8.8", 53, "10.0.0.1", 1234, IPPROTO_TCP);
        let t = Instant::now().checked_sub(Duration::from_secs(5)).unwrap();

        let mut parent = make_parent(1, "p", 0.0, 0);
        parent.children = vec![
            (outbound_key, traffic_stats(1000, 100.0, 10), t, false, Direction::Outbound),
            (inbound_key,  traffic_stats(500,  50.0,  5),  t, false, Direction::Inbound),
        ];

        let rows = child_rows(&parent, true, true, ProcSortColumn::Fixed, SortDirection::Asc);
        // Two opposing flows should merge into a single Conn row.
        assert_eq!(rows.len(), 1);
        if let ChildRow::Conn { bytes, bps, expired, .. } = &rows[0] {
            assert_eq!(*bytes, 1500);
            assert!((bps - 150.0).abs() < 0.01, "bps={bps}");
            assert!(!expired);
        } else {
            panic!("expected ChildRow::Conn, got Flow");
        }
    }
}
