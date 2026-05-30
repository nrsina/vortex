use std::collections::VecDeque;

use bevy_ecs::prelude::Resource;
use crossbeam_channel::{Receiver, Sender};
use rustc_hash::FxHashMap;

use crate::core::flows::capture::{self, InterfaceInfo, ProbeReport, ProbeStatus, probe::ProbeHandle};

/// Number of recent probe samples retained per interface for the sparkline.
/// At ~400 ms per probe window this is ~13 s of trend, enough to show a burst
/// without making the cell so wide it crowds the rest of the row.
pub const TRAFFIC_HISTORY_LEN: usize = 32;

/// Capacity of the shared probe→picker channel: one report per interface per
/// ~400 ms window. A queue of 64 swallows a slow render across many
/// interfaces without blocking any probe thread.
const PROBE_CHANNEL_CAP: usize = 64;

/// How many zero samples to push per idle probe report. Multiplying by the
/// probe window (400 ms) gives the drain time: 32 / 4 × 400 ms ≈ 3.2 s.
const IDLE_DRAIN_ZEROS: usize = 4;

/// All state owned by the picker screen. Inserted as a resource by
/// `PickerPlugin` at boot and refreshed when the user navigates back from the
/// dashboard.
#[derive(Resource, Default)]
pub struct PickerState {
    pub interfaces: Vec<InterfaceInfo>,
    pub selected: usize,
    pub probe: FxHashMap<String, ProbeStatus>,
    /// Rolling per-interface history of pps samples (oldest → newest). Driven
    /// by `drain_probe_reports`; consumed by the picker's sparkline overlay.
    pub traffic_history: FxHashMap<String, VecDeque<u64>>,
    /// Receiving end of the shared probe channel. Every per-interface probe
    /// thread sends into the matching `probe_tx`; `drain_probe_reports` reads
    /// from here. Created lazily on the first reconcile and reused for the
    /// life of the picker so probes can be added/removed without rebuilding
    /// the channel.
    pub probe_rx: Option<Receiver<ProbeReport>>,
    /// Sending end of the shared probe channel, cloned into each probe thread
    /// as it is spawned. Persisted (not just handed to a thread) so a probe
    /// for a newly-appeared interface can be wired into the same channel.
    pub probe_tx: Option<Sender<ProbeReport>>,
    /// One probe handle per actively-probed interface, keyed by name. Held to
    /// keep each thread alive; dropping an entry flips that interface's stop
    /// flag. Reconciled against the active-interface set every tick by
    /// `ensure_probe_running`, so a single interface appearing or vanishing
    /// never restarts (and visually resets) the others' sampling.
    pub probe_handles: FxHashMap<String, ProbeHandle>,
    /// Surfaced to the user when `Capture::open` fails after pressing Enter.
    pub last_error: Option<String>,
    /// Optional BPF filter expression (`tcp port 443`, `host 1.1.1.1`, …).
    /// Empty means "no filter". Persisted across back-navigation so the user
    /// doesn't lose their typed filter when switching interfaces.
    pub filter: String,
    /// `true` while the filter input has keyboard focus. In this mode printable
    /// keys append to `filter` and table-navigation keys are inert.
    pub editing_filter: bool,
    /// When true the picker draws the shared help overlay over its main area.
    /// Toggled by `?` (only outside filter-edit mode, where `?` is a literal
    /// character).
    pub show_help: bool,
}

impl PickerState {
    pub fn select_next(&mut self) {
        if self.interfaces.is_empty() {
            return;
        }
        self.selected = (self.selected + 1).min(self.interfaces.len() - 1);
    }

    pub fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn selected_iface(&self) -> Option<&InterfaceInfo> {
        self.interfaces.get(self.selected)
    }

    /// Drain the probe channel. Called once per tick from a system before
    /// rendering so the live indicator catches up with what the probe threads
    /// have produced since the previous frame.
    pub fn drain_probe_reports(&mut self) {
        let Some(rx) = self.probe_rx.as_ref() else {
            return;
        };
        while let Ok(report) = rx.try_recv() {
            // Only `Sampled` reports contribute to the trend; `Pending` and
            // terminal `Error` states would otherwise leave gaps or a flat
            // tail in the sparkline that mean nothing.
            if let ProbeStatus::Sampled { pps } = report.status {
                let sample = pps.max(0.0).round() as u64;
                let buf = self
                    .traffic_history
                    .entry(report.iface.clone())
                    .or_insert_with(|| VecDeque::with_capacity(TRAFFIC_HISTORY_LEN));

                // Push more zeros per idle report so the chart drains in ~3 s
                // instead of ~13 s. Active samples are always pushed once.
                let push_count = if sample == 0 { IDLE_DRAIN_ZEROS } else { 1 };
                for _ in 0..push_count {
                    if buf.len() == TRAFFIC_HISTORY_LEN {
                        buf.pop_front();
                    }
                    buf.push_back(sample);
                }
            }
            self.probe.insert(report.iface, report.status);
        }
    }

    /// Ensure the shared probe channel exists and return a sender clone for a
    /// newly-spawned probe thread. Created lazily so the picker holds no
    /// channel until the first interface is actually probed, and reused across
    /// reconciles so adding a probe never disturbs the existing ones.
    pub fn probe_sender(&mut self) -> Sender<ProbeReport> {
        if self.probe_tx.is_none() {
            let (tx, rx) = crossbeam_channel::bounded(PROBE_CHANNEL_CAP);
            self.probe_tx = Some(tx);
            self.probe_rx = Some(rx);
        }
        self.probe_tx
            .as_ref()
            .expect("probe_tx set above")
            .clone()
    }

    /// Re-list the system's network interfaces into `interfaces`. Called once
    /// when the picker is first shown (and on back-navigation) and again when
    /// the user presses `r`. It only swaps in the fresh list — probe lifecycle
    /// is reconciled separately by `ensure_probe_running`, so re-listing never
    /// tears down (and thus never visually resets) a running probe's sparkline.
    pub fn rescan_interfaces(&mut self) {
        match capture::list_interfaces() {
            Ok(list) => self.interfaces = list,
            Err(e) => {
                tracing::error!("interface list failed: {e:#}");
                self.last_error = Some(format!("listing interfaces: {e}"));
            }
        }
    }

    /// Tear down all probe threads and the shared channel. Used by the `r`
    /// rescan and on interface selection (capture wants exclusive access).
    /// Dropping the handles flips each thread's stop flag; dropping the
    /// sender lets `ensure_probe_running` rebuild a fresh channel on its next
    /// reconcile pass.
    pub fn reset_probes(&mut self) {
        self.probe_handles.clear();
        self.probe_rx = None;
        self.probe_tx = None;
    }
}
