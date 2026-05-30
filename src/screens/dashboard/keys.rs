use bevy_app::AppExit;
use bevy_ecs::prelude::*;
use bevy_state::prelude::NextState;
use crossterm::event::{KeyCode, KeyModifiers};

use crate::core::flows::FlowIndex;
use crate::core::flows::components::{
    Direction, Expired, FirstSeen, FlowKey, LastSeen, Metadata, TrafficStats,
};
use crate::core::flows::stop_pipeline;
use crate::core::processes::{FlowProcess, ProcessTable};
use crate::core::terminal::input::KeyEvent;
use crate::screens::Screen;
use crate::screens::dashboard::conn::{merge_flow_rows, sort_conns};
use crate::screens::dashboard::render::sort_entries;
use crate::screens::dashboard::rows::{build_live_rows, current_rows};
use crate::screens::dashboard::state::DashboardState;
use crate::screens::prefs::UiPrefs;

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn dashboard_keys(
    mut commands: Commands,
    mut exit: MessageWriter<AppExit>,
    mut keys: MessageReader<KeyEvent>,
    mut state: ResMut<DashboardState>,
    mut prefs: ResMut<UiPrefs>,
    entities: Query<Entity, With<FlowKey>>,
    flows: Query<(
        &FlowKey,
        &TrafficStats,
        &Metadata,
        &FirstSeen,
        &LastSeen,
        &Direction,
        Has<Expired>,
        Option<&FlowProcess>,
    )>,
    table: Res<ProcessTable>,
    mut index: ResMut<FlowIndex>,
    mut next_screen: ResMut<NextState<Screen>>,
) {
    for KeyEvent(k) in keys.read() {
        // Ctrl-C handled by `global_keys`.
        if matches!(k.code, KeyCode::Char('c')) && k.modifiers.contains(KeyModifiers::CONTROL) {
            continue;
        }
        // `q` on the dashboard is an unconditional quit (no filter editor here).
        if matches!(k.code, KeyCode::Char('q')) {
            exit.write(AppExit::Success);
            continue;
        }
        handle_dashboard_key(
            k,
            &mut commands,
            &mut state,
            &mut prefs,
            &entities,
            &flows,
            &table,
            &mut index,
            &mut next_screen,
        );
    }
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn handle_dashboard_key(
    k: &crossterm::event::KeyEvent,
    commands: &mut Commands,
    state: &mut DashboardState,
    prefs: &mut UiPrefs,
    entities: &Query<Entity, With<FlowKey>>,
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
    index: &mut FlowIndex,
    next_screen: &mut NextState<Screen>,
) {
    // While the details overlay is open the screen is pinned to one
    // flow/connection — every table-manipulation key (enter, e, s, S, space,
    // navigation, …) is intentionally inert so the overlay can't drift. Only
    // closing it is allowed here (`q` / Ctrl-C are handled by the caller).
    if state.show_details {
        if matches!(k.code, KeyCode::Esc | KeyCode::Char('b')) {
            state.show_details = false;
            state.details_flow = None;
        }
        return;
    }
    match k.code {
        // Pause is display-only: we snapshot the current rows so the user can
        // read them without churn. Capture, aggregation, and EWMA keep running
        // in the background; on unpause the screen jumps back to live state.
        KeyCode::Char(' ') => {
            if state.paused {
                state.paused = false;
                state.frozen = None;
            } else {
                state.paused = true;
                state.frozen = Some(build_live_rows(flows, table));
            }
        }
        KeyCode::Char('?') => {
            prefs.show_help = !prefs.show_help;
        }
        // Open the details overlay for the currently-selected row. We capture
        // the row's `FlowKey` now (resolving `state.selected` against the same
        // visible list the renderer builds) so the overlay stays pinned to
        // that one flow/connection even as the table re-sorts or it expires.
        // Pressing Enter while help is visible is a no-op — the user can't see
        // the table to know what they'd be opening details on.
        KeyCode::Enter if !prefs.show_help => {
            if let Some(key) = selected_flow_key(state, prefs, flows, table) {
                state.details_flow = Some(key);
                state.show_details = true;
            }
        }
        KeyCode::Char('n') => {
            // Flip the dst column between hostnames and raw IPs. Shared
            // across screens via `UiPrefs` so the two views stay in sync.
            prefs.names_mode = !prefs.names_mode;
        }
        KeyCode::Char('e') => {
            // Show/hide expired (idle) flows. Shared across screens via
            // `UiPrefs` so the dashboard and processes tree stay in sync.
            prefs.show_expired = !prefs.show_expired;
        }
        KeyCode::Char('a') => {
            // Toggle the merged connection view (pairs each connection's two
            // opposing flows). Shared via `UiPrefs` so both screens agree.
            prefs.aggregate = !prefs.aggregate;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.selected = state.selected.saturating_add(1);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            state.selected = state.selected.saturating_sub(1);
        }
        // Lowercase `s` advances to the next sort column (wraps to Fixed).
        // Switching the column does not reset the direction so toggling
        // back-and-forth with `S` keeps a sticky preference.
        KeyCode::Char('s') => {
            state.sort_column = state.sort_column.next();
        }
        // Uppercase `S` flips asc/desc for the current column. No-op while
        // the column is `Fixed` (insertion order is direction-less).
        KeyCode::Char('S') => {
            state.sort_direction = state.sort_direction.toggle();
        }
        // `p` jumps to the Processes screen; capture and flow state are
        // preserved so the user can flip back with `b` / Esc without losing
        // context.
        KeyCode::Char('p') => {
            next_screen.set(Screen::Processes);
        }
        KeyCode::Esc | KeyCode::Char('b') => {
            // Esc closes the help overlay first — pressing it again (or `b`)
            // then triggers the actual back-to-picker teardown. (The details
            // overlay is closed by the pinned-overlay guard at the top of this
            // fn, so it never reaches here while open.)
            if prefs.show_help {
                prefs.show_help = false;
                return;
            }
            // Back to picker: tear down capture and reset flow state. The
            // picker resource itself is reset by `handle_picker_key`'s `r`
            // path on demand; here we only clear what the dashboard owns.
            // `ensure_probe_running` reconciles the empty probe-handle map on
            // the next tick and restarts probing. `picker.filter` is
            // intentionally *not* cleared so the user can adjust the interface
            // and reuse the same expression.
            stop_pipeline(commands);
            for entity in entities {
                commands.entity(entity).despawn();
            }
            index.0.clear();
            next_screen.set(Screen::Picker);
            state.selected_interface = None;
            state.filter.clear();
            // Drop any frozen snapshot so re-entering the dashboard is live.
            state.paused = false;
            state.frozen = None;
        }
        _ => {}
    }
}

/// Resolve the currently-selected row to the `FlowKey` to pin the details
/// overlay to. Rebuilds the exact visible list the renderer draws — same
/// source (frozen snapshot when paused, else live), same expired filter, same
/// sort — so `state.selected` lines up with what's on screen. In the merged
/// connection view it returns the connection's anchor half (`tx_key`, else
/// `rx_key`); the overlay re-folds both halves by `conn_key` at render time.
#[allow(clippy::type_complexity)]
fn selected_flow_key(
    state: &DashboardState,
    prefs: &UiPrefs,
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
) -> Option<FlowKey> {
    let entries_all = current_rows(state, flows, table);
    if prefs.aggregate {
        let mut conns = merge_flow_rows(entries_all);
        if !prefs.show_expired {
            conns.retain(|c| !c.expired);
        }
        sort_conns(&mut conns, state.sort_column, state.sort_direction);
        let idx = state.selected.min(conns.len().saturating_sub(1));
        conns.get(idx).and_then(|c| c.tx_key.or(c.rx_key))
    } else {
        let mut entries = entries_all;
        if !prefs.show_expired {
            entries.retain(|r| !r.expired);
        }
        sort_entries(&mut entries, state.sort_column, state.sort_direction);
        let idx = state.selected.min(entries.len().saturating_sub(1));
        entries.get(idx).map(|r| r.key)
    }
}


