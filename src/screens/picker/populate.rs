use std::collections::HashSet;

use bevy_ecs::prelude::*;

use crate::core::flows::capture;
use crate::screens::picker::state::PickerState;

/// Populate the interface list when the picker is first shown (at startup
/// and on back-navigation from the dashboard). Wired into
/// `OnEnter(Screen::Picker)`. There is no periodic re-list — the user presses
/// `r` to rescan for hot-plugged devices.
pub fn populate_interfaces(mut picker: ResMut<PickerState>) {
    picker.rescan_interfaces();
}

/// Drain whatever probe samples have arrived since the previous tick into
/// `PickerState`. Gated at the registration site by `run_if(probe_attached)`
/// so it drops out of the picker's serial chain entirely when no probe channel
/// exists yet (e.g. right after picker entry before the first reconcile, after
/// `r` resets the probes, or after `list_interfaces` failed).
pub fn drain_probe(mut picker: ResMut<PickerState>) {
    picker.drain_probe_reports();
}

/// `run_if` condition for `drain_probe`: only run when there's actually a
/// probe receiver to read from.
pub fn probe_attached(picker: Res<PickerState>) -> bool {
    picker.probe_rx.is_some()
}

/// Reconcile the running probe threads against the current active-interface
/// set. Runs every tick (cheap when nothing changed — two set comparisons):
///   * spawns a probe for every active interface that doesn't have one yet
///     (after `r` rescan, after back-navigation, or when a device hot-plugs);
///   * drops the probe for every interface that is no longer active (went
///     down, disconnected, or vanished from the list).
///
/// Crucially, interfaces present before *and* after a change keep their
/// existing probe thread untouched, so their sampling — and the sparkline
/// trend built from it — never skips a beat when an unrelated interface
/// appears or disappears.
pub fn ensure_probe_running(mut picker: ResMut<PickerState>) {
    if picker.last_error.is_some() {
        return;
    }

    // Only probe interfaces that could realistically carry traffic. Down /
    // disconnected devices would just report `Sampled { pps: 0 }` and slow
    // the pass for live interfaces — and on some platforms pcap's `open()`
    // blocks on bad devices, stalling everything behind them. Inactive
    // interfaces are rendered with a "—" placeholder by `render::render_table`,
    // so they never reach the probe path.
    let active: HashSet<String> = picker
        .interfaces
        .iter()
        .filter(|i| i.is_active())
        .map(|i| i.name.clone())
        .collect();

    // Stop probes for interfaces that are no longer active. Dropping the
    // handle flips that thread's stop flag at its next checkpoint.
    picker.probe_handles.retain(|name, _| active.contains(name));

    // Start a probe for each active interface that doesn't have one yet,
    // wiring it into the shared channel so `drain_probe` sees its reports.
    let missing: Vec<String> = active
        .into_iter()
        .filter(|name| !picker.probe_handles.contains_key(name))
        .collect();
    for name in missing {
        let tx = picker.probe_sender();
        let handle = capture::spawn_probe_one(name.clone(), tx);
        picker.probe_handles.insert(name, handle);
    }
}
