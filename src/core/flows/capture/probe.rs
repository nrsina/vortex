use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{Sender, TrySendError};

use crate::core::common::spawn_named;
use crate::core::flows::capture::thread;

/// Per-interface result of one probe window. `pps` is packets observed
/// divided by the window duration in seconds, so values are comparable across
/// interfaces even if a window is cut short.
#[derive(Debug, Clone)]
pub enum ProbeStatus {
    /// Not yet measured — render as "scanning…".
    Pending,
    /// Probe completed at least one window; `pps` is the live packet rate.
    Sampled { pps: f32 },
    /// `Capture::open` failed for this interface (permission, no link, …).
    /// We keep the message so the user understands why traffic shows nothing.
    Error(String),
}

#[derive(Debug, Clone)]
pub struct ProbeReport {
    pub iface: String,
    pub status: ProbeStatus,
}

/// How long each probe window runs. Short enough that the live indicator
/// feels real-time; long enough that a single stray packet doesn't dominate
/// the pps reading (1 pkt / 400 ms ≈ 2.5 pkt/s).
const PROBE_WINDOW: Duration = Duration::from_millis(400);

/// Snaplen for probe handles. Probing only counts packets — it never parses
/// payload — so the smallest useful capture keeps the picker cheap regardless
/// of the (possibly much larger) configured capture snaplen.
const PROBE_SNAPLEN: u16 = 96;

/// Handle to a single interface's probe thread. Drop it to stop that probe
/// at the next cooperative checkpoint. The `JoinHandle` is held so the thread
/// isn't detached at construction; `Drop` only flips the stop flag — matching
/// the rest of the app where we don't block shutdown on threads observing
/// their wake-up signals.
///
/// The picker keeps one handle *per interface* (in a map) rather than one
/// shared handle for the whole set, so a single interface appearing or
/// vanishing can be reconciled in isolation without restarting — and visually
/// resetting — every other interface's sampling.
pub struct ProbeHandle {
    stop: Arc<AtomicBool>,
    #[allow(dead_code)]
    join: JoinHandle<()>,
}

impl Drop for ProbeHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Spawn one probe thread for a single interface. The thread holds its own
/// long-lived pcap handle (opened once and reused — re-opening pcap each
/// window was a measurable source of slowness). Callers spawn one per
/// interface so every interface is sampled over the *same* wall-clock window:
/// a sequential probe (the previous design) would sample `any` at t=0 and
/// `wlan0` at t=400ms, so different bursts hit different windows, making `any`
/// appear idle while a per-interface row showed traffic.
///
/// All threads send `ProbeReport`s into the one shared `tx` the picker drains;
/// the report's `iface` field disambiguates the source.
pub fn spawn_probe_one(iface: String, tx: Sender<ProbeReport>) -> ProbeHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let name = format!("probe-{iface}");
    let join = spawn_named(&name, move || run_one(iface, tx, thread_stop));
    ProbeHandle { stop, join }
}

/// One probe thread's main loop. Opens pcap once, then alternates between
/// "drain packets for one window" and "emit one report".
fn run_one(iface: String, tx: Sender<ProbeReport>, stop: Arc<AtomicBool>) {
    let mut cap = match thread::open(&iface, None, PROBE_SNAPLEN, false) {
        Ok(c) => c,
        Err(e) => {
            // Emit one terminal error report so the cell stops saying
            // "scanning…", then exit. The handle is dropped on return.
            let _ = tx.try_send(ProbeReport {
                iface,
                status: ProbeStatus::Error(short_error(&e.to_string())),
            });
            return;
        }
    };

    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        let mut count: u32 = 0;
        while started.elapsed() < PROBE_WINDOW && !stop.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(_) => count = count.saturating_add(1),
                Err(pcap::Error::TimeoutExpired) => continue,
                // Capture handle went bad — exit; the cell keeps its last
                // value rather than churning between "Sampled" and "Error".
                Err(_) => return,
            }
        }
        let secs = started.elapsed().as_secs_f32().max(0.001);
        let report = ProbeReport {
            iface: iface.clone(),
            status: ProbeStatus::Sampled {
                pps: count as f32 / secs,
            },
        };
        match tx.try_send(report) {
            Ok(()) => {}
            // UI is briefly behind; dropping a stale report is correct —
            // the next window will overwrite it anyway.
            Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Disconnected(_)) => return,
        }
    }
}

/// pcap's chained errors are noisy in a TUI cell; keep the first line only.
fn short_error(s: &str) -> String {
    s.lines().next().unwrap_or(s).to_string()
}
