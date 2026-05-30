use bevy_app::AppExit;
use bevy_ecs::prelude::*;
use bevy_state::prelude::NextState;
use crossterm::event::{KeyCode, KeyModifiers};

use crate::core::flows::components::{Direction, Expired, FirstSeen, FlowKey, TrafficStats};
use crate::core::processes::{FlowProcess, ProcessStats, ProcessTable};
use crate::core::terminal::input::KeyEvent;
use crate::screens::Screen;
use crate::screens::prefs::UiPrefs;
use crate::screens::processes::state::{ProcessesState, initial_sort_direction};
use crate::screens::processes::tree::{
    ChildRow, build_live_parents, child_rows, current_parents, sort_parents,
};

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn processes_keys(
    mut exit: MessageWriter<AppExit>,
    mut keys: MessageReader<KeyEvent>,
    mut state: ResMut<ProcessesState>,
    mut prefs: ResMut<UiPrefs>,
    stats: Res<ProcessStats>,
    table: Res<ProcessTable>,
    flows: Query<(
        &FlowKey,
        &TrafficStats,
        &FlowProcess,
        &FirstSeen,
        &Direction,
        Has<Expired>,
    )>,
    mut next_screen: ResMut<NextState<Screen>>,
) {
    for KeyEvent(k) in keys.read() {
        // Ctrl-C handled by `global_keys`.
        if matches!(k.code, KeyCode::Char('c')) && k.modifiers.contains(KeyModifiers::CONTROL) {
            continue;
        }
        if matches!(k.code, KeyCode::Char('q')) {
            exit.write(AppExit::Success);
            continue;
        }
        handle(k, &mut state, &mut prefs, &stats, &table, &flows, &mut next_screen);
    }
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn handle(
    k: &crossterm::event::KeyEvent,
    state: &mut ProcessesState,
    prefs: &mut UiPrefs,
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
    next_screen: &mut NextState<Screen>,
) {
    // While the details overlay is open the screen is pinned to one
    // flow/connection — every tree-manipulation key (enter, e, s, S, space,
    // w, navigation, …) is intentionally inert so the overlay can't drift.
    // Only closing it is allowed (`q` / Ctrl-C are handled by the caller).
    if state.show_details {
        if matches!(k.code, KeyCode::Esc | KeyCode::Char('b')) {
            state.show_details = false;
            state.details_flow = None;
        }
        return;
    }

    // Build the same parent ordering — and per-parent child rows — the renderer
    // uses so cursor navigation stays aligned with what's on screen.
    // `current_parents` already picks the frozen snapshot when paused, falling
    // back to live ECS state otherwise. `child_rows` mirrors the renderer's
    // expired filter and connection-merge so the cursor counts exactly the rows
    // actually drawn (see `render_tree`).
    let mut parents = current_parents(state, stats, table, flows);
    sort_parents(&mut parents, state.sort_column, state.sort_direction);
    let child_lists: Vec<Vec<ChildRow>> = parents
        .iter()
        .map(|p| {
            child_rows(
                p,
                prefs.show_expired,
                prefs.aggregate,
                state.sort_column,
                state.sort_direction,
            )
        })
        .collect();
    let row_count = flat_row_count(&parents, &child_lists, state);

    match k.code {
        KeyCode::Down | KeyCode::Char('j') if row_count > 0 => {
            state.selected = (state.selected + 1).min(row_count - 1);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            state.selected = state.selected.saturating_sub(1);
        }
        KeyCode::Enter => {
            // Parent row: expand/collapse. Child row: open details overlay
            // and stash the FlowKey so the overlay stays pinned to that one
            // flow/connection even if the tree rearranges underneath.
            if let Some(pid) = parent_pid_at(&parents, &child_lists, state) {
                if !state.expanded.insert(pid) {
                    state.expanded.remove(&pid);
                }
            } else if let Some(key) = child_flow_at(&parents, &child_lists, state) {
                state.details_flow = Some(key);
                state.show_details = true;
            }
        }
        KeyCode::Char('n') => {
            // Shared across screens via `UiPrefs` so the dashboard and this
            // tree stay in sync.
            prefs.names_mode = !prefs.names_mode;
        }
        KeyCode::Char('e') => {
            // Show/hide expired flow children. Shared via `UiPrefs` so the
            // dashboard and this tree stay in sync.
            prefs.show_expired = !prefs.show_expired;
        }
        KeyCode::Char('a') => {
            // Toggle the merged connection view. Shared via `UiPrefs` so both
            // screens agree on per-flow vs per-connection.
            prefs.aggregate = !prefs.aggregate;
        }
        KeyCode::Char('s') => {
            state.sort_column = state.sort_column.next();
            // Reset direction to the column's natural default so the user
            // doesn't have to press `S` after every cycle to get a sensible
            // ordering for bandwidth-flavoured columns.
            state.sort_direction = initial_sort_direction(state.sort_column);
        }
        KeyCode::Char('S') => {
            state.sort_direction = state.sort_direction.toggle();
        }
        // Pause is display-only: snapshot the parents + their (sorted) child
        // flows. Pipeline keeps running; on unpause we discard the snapshot
        // and the next render reflects current live state.
        KeyCode::Char(' ') => {
            if state.paused {
                state.paused = false;
                state.frozen = None;
            } else {
                state.paused = true;
                // Build directly from live state — `parents` above may have
                // been sorted by user choice, but the snapshot should be in
                // canonical (PID) order so toggling sort while paused stays
                // deterministic.
                let mut snapshot = build_live_parents(stats, table, flows);
                snapshot.sort_by_key(|r| r.pid);
                state.frozen = Some(snapshot);
            }
        }
        KeyCode::Char('w') => state.wrap = !state.wrap,
        KeyCode::Char('?') => {
            prefs.show_help = !prefs.show_help;
        }
        KeyCode::Esc | KeyCode::Char('b') => {
            // Esc dismisses the help overlay first and only on the next press
            // goes back to the dashboard. `b` skips straight to back. (The
            // details overlay is closed by the pinned-overlay guard at the top
            // of this fn, so it never reaches here while open.)
            if prefs.show_help && k.code == KeyCode::Esc {
                prefs.show_help = false;
                return;
            }
            // Clear the snapshot so re-entering the screen is live.
            state.paused = false;
            state.frozen = None;
            state.show_details = false;
            state.details_flow = None;
            next_screen.set(Screen::Dashboard);
        }
        _ => {}
    }
}

/// Walk the same flattened tree the renderer produces and count the total
/// rows. Sum of parents plus, for each expanded parent, its visible child
/// count (from the matching `child_lists` entry).
fn flat_row_count(
    parents: &[crate::screens::processes::state::FrozenProcessRow],
    child_lists: &[Vec<ChildRow>],
    state: &ProcessesState,
) -> usize {
    let mut total = 0;
    for (p, children) in parents.iter().zip(child_lists) {
        total += 1;
        if state.expanded.contains(&p.pid) {
            total += children.len();
        }
    }
    total
}

/// Resolve the currently-selected row to a parent PID. Returns `None` when
/// the cursor sits on a child row — Enter is a no-op there.
fn parent_pid_at(
    parents: &[crate::screens::processes::state::FrozenProcessRow],
    child_lists: &[Vec<ChildRow>],
    state: &ProcessesState,
) -> Option<u32> {
    let mut idx = 0;
    for (p, children) in parents.iter().zip(child_lists) {
        if idx == state.selected {
            return Some(p.pid);
        }
        idx += 1;
        if state.expanded.contains(&p.pid) {
            let n = children.len();
            if state.selected < idx + n {
                return None;
            }
            idx += n;
        }
    }
    None
}

/// Resolve the currently-selected row to the underlying child flow key (the
/// connection's anchor half in the merged view). Returns `None` when the
/// cursor sits on a parent row — dual of `parent_pid_at`, used by Enter to
/// open the details overlay only when there's a flow/connection to describe.
fn child_flow_at(
    parents: &[crate::screens::processes::state::FrozenProcessRow],
    child_lists: &[Vec<ChildRow>],
    state: &ProcessesState,
) -> Option<FlowKey> {
    let mut idx = 0;
    for (p, children) in parents.iter().zip(child_lists) {
        if idx == state.selected {
            return None; // parent row
        }
        idx += 1;
        if state.expanded.contains(&p.pid) {
            for ch in children {
                if idx == state.selected {
                    return Some(match ch {
                        ChildRow::Flow { key, .. } => *key,
                        ChildRow::Conn { detail_key, .. } => *detail_key,
                    });
                }
                idx += 1;
            }
        }
    }
    None
}
