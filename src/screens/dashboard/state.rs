use std::time::Instant;

use bevy_ecs::prelude::Resource;

use crate::core::flows::components::{Direction, FlowKey, TrafficStats};
use crate::core::flows::dpi::AppKind;
use crate::screens::common::SortDirection;

/// Column the dashboard table is sorted by. `Fixed` keeps rows in the order
/// flows first appeared so the user can follow a row without it jumping.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    #[default]
    Fixed,
    SrcIp,
    SrcPort,
    DstIp,
    DstPort,
    Proto,
    Process,
    Bps,
    Bytes,
    Packets,
    FirstSeen,
    LastPacket,
}

impl SortColumn {
    /// Advance to the next column in the cycle (wraps back to `Fixed`).
    pub fn next(self) -> Self {
        use SortColumn::*;
        match self {
            Fixed => SrcIp,
            SrcIp => SrcPort,
            SrcPort => DstIp,
            DstIp => DstPort,
            DstPort => Proto,
            Proto => Process,
            Process => Bps,
            Bps => Bytes,
            Bytes => Packets,
            Packets => FirstSeen,
            FirstSeen => LastPacket,
            LastPacket => Fixed,
        }
    }
}

/// Owned, renderable shape of a flow row. Used for both live ticks and the
/// frozen pause snapshot — the source differs but the shape doesn't. Owning
/// `process_name` (resolved when the row is built) keeps the label stable
/// even if `ProcessTable` GCs the PID while a snapshot is on screen.
#[derive(Debug, Clone)]
pub struct FlowRow {
    pub key: FlowKey,
    pub stats: TrafficStats,
    /// Per-flow direction (immutable, classified once at spawn). Carried so the
    /// connection view can orient endpoints into local/remote and split tx/rx
    /// without a second lookup. See `screens::common::orient`.
    pub direction: Direction,
    pub last_summary: Option<String>,
    /// DPI-extracted app-layer host, captured into the snapshot so the frozen
    /// (paused) details overlay still shows it.
    pub app_host: Option<(AppKind, String)>,
    pub first_seen: Instant,
    /// Instant of the most recent packet, for the "last pkt" column + sort.
    pub last_seen: Instant,
    /// Whether the flow is currently expired (carries an `Expired` marker).
    /// Drives the show/hide filter and the dimmed row style.
    pub expired: bool,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

#[derive(Resource, Default)]
#[allow(dead_code)]
pub struct DashboardState {
    /// Interface the dashboard is currently bound to. `None` while in the
    /// picker; set to `Some` once capture has started successfully.
    pub selected_interface: Option<String>,
    pub selected: usize,
    /// When true the dashboard renders the details overlay for the selected
    /// row in place of the flow table. Toggled by `Enter`; `esc` closes it
    /// without going back to the picker.
    pub show_details: bool,
    /// The flow whose details we're showing. Captured the moment `Enter` was
    /// pressed so the overlay stays pinned to that one flow/connection even if
    /// the table re-sorts, new flows arrive, or it expires — the overlay looks
    /// the flow up live by key, never by list index. In the aggregate view
    /// this holds one half of the connection (the anchor); the overlay re-folds
    /// both halves by `conn_key` at render time. Mirrors
    /// `ProcessesState.details_flow`.
    pub details_flow: Option<FlowKey>,
    /// Active BPF filter applied to the running capture. Empty means no
    /// filter. Surfaced in the dashboard header so the user always sees
    /// which filter is in effect.
    pub filter: String,
    pub paused: bool,
    /// Frozen snapshot of the flow rows at the moment pause was toggled on.
    /// `Some` iff `paused` is true. Render reads from this when set; capture
    /// and aggregation keep running regardless so unpause shows live state.
    pub frozen: Option<Vec<FlowRow>>,
    /// Currently active sort column. Defaults to `Fixed` (insertion order).
    pub sort_column: SortColumn,
    /// Sort direction for the active column. Ignored when `sort_column` is
    /// `Fixed` — fixed order is always oldest-first.
    pub sort_direction: SortDirection,
}

