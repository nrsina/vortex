use std::time::Instant;

use bevy_ecs::prelude::Resource;
use rustc_hash::FxHashSet;

use crate::core::flows::components::{Direction, FlowKey, TrafficStats};
use crate::core::processes::ProcessAggregate;
use crate::screens::common::SortDirection;

/// Sort key for the Processes table. Defaults to `Fixed` (PID ascending, the
/// closest thing to insertion order we have for processes) so the screen
/// doesn't shuffle the moment it opens — the user opts into a sort by pressing
/// `s`. The cycle walks visible columns left-to-right.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcSortColumn {
    #[default]
    Fixed,
    Pid,
    Name,
    ConnCount,
    Bps,
    Bytes,
    User,
}

impl ProcSortColumn {
    /// Advance to the next column, wrapping back to `Fixed`. Matches the
    /// header's left-to-right order — `status` and `cmd` aren't sortable so
    /// the cycle skips them.
    pub fn next(self) -> Self {
        use ProcSortColumn::*;
        match self {
            Fixed => Pid,
            Pid => Name,
            Name => ConnCount,
            ConnCount => Bps,
            Bps => Bytes,
            Bytes => User,
            User => Fixed,
        }
    }
}

/// Snapshot of a parent process row captured at the instant pause was toggled
/// on. Owns its data so the live pipeline can keep mutating underneath. `cmd`
/// is pre-formatted; each child is `(key, stats, first_seen, expired, dir)` —
/// the `FirstSeen` instant feeds the renderer's `sort_parents` stable
/// tiebreaker, `expired` drives the show/hide filter + dimmed row style, and
/// `dir` lets the connection view orient endpoints into local/remote (`a`).
#[derive(Debug, Clone)]
pub struct FrozenProcessRow {
    pub pid: u32,
    pub name: String,
    pub user: Option<String>,
    pub cmd: String,
    pub alive: bool,
    pub agg: ProcessAggregate,
    pub children: Vec<(FlowKey, TrafficStats, Instant, bool, Direction)>,
}

#[derive(Resource, Default)]
#[allow(dead_code)]
pub struct ProcessesState {
    /// Selected row in the flattened parent+child list. Saturated to the
    /// list's length on render to survive expansion/collapse without going OOB.
    pub selected: usize,
    /// PIDs whose flow children are currently rendered beneath the parent row.
    /// A `FxHashSet` so toggling is O(1); persists across ticks so a user
    /// expanding `firefox` doesn't see it snap shut every time the snapshot
    /// reshuffles.
    pub expanded: FxHashSet<u32>,
    pub sort_column: ProcSortColumn,
    pub sort_direction: SortDirection,
    /// Display-only freeze. When `true`, render reads from `frozen` instead of
    /// live ECS state. Capture, aggregator, snapshot thread, and enrichment
    /// keep running in the background — on unpause the screen jumps to current
    /// values.
    pub paused: bool,
    /// Frozen snapshot of parents + their (sorted) flow children, taken when
    /// pause was toggled on. `Some` iff `paused` is true.
    pub frozen: Option<Vec<FrozenProcessRow>>,
    /// Wrap long cmdline strings across multiple lines instead of truncating.
    /// Off by default — wrapping grows row heights, which trades vertical
    /// density for full visibility of long process arguments.
    pub wrap: bool,
    /// When true the screen renders the details overlay (`details_flow`) in
    /// place of the tree. Toggled by `Enter` on a *child* row (parent-row
    /// Enter keeps its expand/collapse behaviour). Closed by `Esc`.
    pub show_details: bool,
    /// The flow whose details we're showing. Captured the moment Enter was
    /// pressed so the overlay sticks to one row even if the underlying tree
    /// rearranges (process exits, child re-sorts, etc.).
    pub details_flow: Option<FlowKey>,
}

/// Direction-aware default: numeric/bandwidth columns sort high-to-low because
/// the user wants the loudest process at the top; `Fixed`/`Pid`/`Name` are
/// ascending.
pub fn initial_sort_direction(column: ProcSortColumn) -> SortDirection {
    match column {
        ProcSortColumn::Bps | ProcSortColumn::Bytes | ProcSortColumn::ConnCount => {
            SortDirection::Desc
        }
        _ => SortDirection::Asc,
    }
}
