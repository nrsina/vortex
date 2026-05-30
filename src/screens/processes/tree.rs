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
