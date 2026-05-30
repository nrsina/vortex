use bevy_app::AppExit;
use bevy_ecs::prelude::*;
use bevy_state::prelude::NextState;
use crossterm::event::{KeyCode, KeyModifiers};

use crate::core::flows::start_pipeline;
use crate::core::terminal::input::KeyEvent;
use crate::screens::Screen;
use crate::screens::dashboard::state::DashboardState;
use crate::screens::picker::state::PickerState;
use crate::screens::prefs::UiPrefs;

pub fn picker_keys(
    mut commands: Commands,
    mut exit: MessageWriter<AppExit>,
    mut keys: MessageReader<KeyEvent>,
    mut state: ResMut<DashboardState>,
    mut prefs: ResMut<UiPrefs>,
    mut picker: ResMut<PickerState>,
    mut next_screen: ResMut<NextState<Screen>>,
) {
    for KeyEvent(k) in keys.read() {
        // Ctrl-C handled by `global_keys`.
        if matches!(k.code, KeyCode::Char('c')) && k.modifiers.contains(KeyModifiers::CONTROL) {
            continue;
        }
        // `q` quits unless the BPF filter editor is active, in which case it
        // is a legitimate character the user might type into the expression.
        if matches!(k.code, KeyCode::Char('q')) && !picker.editing_filter {
            exit.write(AppExit::Success);
            continue;
        }
        handle_picker_key(k, &mut commands, &mut state, &mut prefs, &mut picker, &mut next_screen);
    }
}

fn handle_picker_key(
    k: &crossterm::event::KeyEvent,
    commands: &mut Commands,
    state: &mut DashboardState,
    prefs: &mut UiPrefs,
    picker: &mut PickerState,
    next_screen: &mut NextState<Screen>,
) {
    // Filter-editing branch: keystrokes mutate `picker.filter` and table
    // navigation is suppressed. Enter still triggers capture-open (so the
    // user types their filter and hits Enter once), Esc bails out without
    // disturbing the existing filter contents.
    if picker.editing_filter {
        match k.code {
            KeyCode::Esc => {
                picker.editing_filter = false;
            }
            KeyCode::Backspace => {
                picker.filter.pop();
            }
            KeyCode::Enter => {
                picker.editing_filter = false;
                open_selected_interface(commands, state, prefs, picker, next_screen);
            }
            // Ignore control-modified printable keys so e.g. Ctrl-L or Alt-X
            // don't smuggle stray bytes into the filter.
            KeyCode::Char(c)
                if !k.modifiers.contains(KeyModifiers::CONTROL)
                    && !k.modifiers.contains(KeyModifiers::ALT) =>
            {
                picker.filter.push(c);
            }
            _ => {}
        }
        return;
    }

    match k.code {
        KeyCode::Char('?') => {
            picker.show_help = !picker.show_help;
        }
        // Esc dismisses help without affecting anything else — the picker
        // itself has no back action, so esc is otherwise a no-op here.
        KeyCode::Esc if picker.show_help => {
            picker.show_help = false;
        }
        KeyCode::Down | KeyCode::Char('j') => picker.select_next(),
        KeyCode::Up | KeyCode::Char('k') => picker.select_prev(),
        KeyCode::Char('f') | KeyCode::Char('/') => {
            picker.editing_filter = true;
            // A stale error from the previous attempt would be confusing
            // while the user is still rewriting the filter.
            picker.last_error = None;
        }
        KeyCode::Char('r') => {
            // Rescan: tear down probes, clear any stale error, and re-list
            // interfaces right now. `ensure_probe_running` respawns probes for
            // the fresh active set on the next tick. Filter is intentionally
            // preserved — rescan is about the interface list, not the filter.
            picker.interfaces.clear();
            picker.probe.clear();
            picker.reset_probes();
            picker.last_error = None;
            picker.rescan_interfaces();
        }
        KeyCode::Enter => {
            open_selected_interface(commands, state, prefs, picker, next_screen);
        }
        _ => {}
    }
}

fn open_selected_interface(
    commands: &mut Commands,
    state: &mut DashboardState,
    prefs: &mut UiPrefs,
    picker: &mut PickerState,
    next_screen: &mut NextState<Screen>,
) {
    let Some(iface) = picker.selected_iface().map(|i| i.name.clone()) else {
        return;
    };
    let trimmed_filter = picker.filter.trim();
    let filter_arg = if trimmed_filter.is_empty() {
        None
    } else {
        Some(trimmed_filter)
    };
    match start_pipeline(&iface, filter_arg) {
        Ok(pipeline) => {
            // The delta channel drives `ingest`; `LocalAddrs` lets it classify
            // each flow's direction. Both inserted together so they're present
            // before `ingest` next runs.
            commands.insert_resource(pipeline.channel);
            commands.insert_resource(pipeline.local_addrs);
            next_screen.set(Screen::Dashboard);
            state.selected_interface = Some(iface);
            state.selected = 0;
            // Picker's own help may have been open; the dashboard's help
            // overlay shares this flag via `UiPrefs`, so reset it explicitly
            // to avoid jumping straight into dashboard-help on transition.
            prefs.show_help = false;
            state.paused = false;
            state.frozen = None;
            state.filter = trimmed_filter.to_string();
            picker.last_error = None;
            // Stop the probes — capture and probe both want exclusive
            // access to the chosen interface, and the picker is now
            // off-screen anyway.
            picker.reset_probes();
        }
        Err(e) => {
            tracing::error!("failed to start capture on {iface}: {e:#}");
            picker.last_error = Some(format!("{e}"));
        }
    }
}
