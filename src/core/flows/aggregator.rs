use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bevy_ecs::prelude::Resource;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TrySendError};
use rustc_hash::FxHashMap;

use crate::core::common::spawn_named;
use crate::core::flows::components::FlowKey;
use crate::core::flows::dpi::AppKind;
use crate::core::flows::packet::ParsedPacket;

/// Off-thread accumulator state for a single flow. Only the aggregator
/// thread touches this; ECS never sees `FlowAccumulator`.
#[derive(Default)]
pub struct FlowAccumulator {
    pub bytes: u64,
    pub packets: u64,
    pub last_summary: Option<String>,
    /// DPI-extracted app-layer host (TLS SNI / DNS qname). Captured from the
    /// first packet that carries one and never overwritten — a flow's intent
    /// is fixed at the handshake/query, so later packets can't change it.
    pub app_host: Option<(AppKind, String)>,
}

/// A coalesced update for one flow over a single aggregator flush window.
/// Many packets collapse into a single `FlowDelta`; the ECS thread applies
/// each delta with O(1) work per active flow rather than per packet.
#[derive(Debug)]
pub struct FlowDelta {
    pub key: FlowKey,
    pub bytes: u64,
    pub packets: u64,
    pub last_summary: Option<String>,
    /// First DPI-extracted app-layer host seen this window (if any). `ingest`
    /// writes it into `Metadata` only when that flow's host is still unset.
    pub app_host: Option<(AppKind, String)>,
}

/// Receiver half of the aggregator → ECS channel. Inserted as a resource by
/// `start_pipeline`; drained each tick by `flows::ingest::ingest`. Carries the
/// shared `dropped` counter (bumped by both the capture and aggregator threads
/// on a full channel) so `ingest` can read cumulative packet loss into
/// `LiveMetrics`.
#[derive(Resource)]
pub struct DeltaChannel {
    pub rx: Receiver<Vec<FlowDelta>>,
    pub dropped: Arc<AtomicU64>,
}

/// Spawn the aggregator OS thread.
///
/// `rx` is the high-rate packet channel from the pcap thread; `tx` is the
/// low-rate batch channel feeding the ECS world. `flush_interval` is both
/// the cadence at which the accumulator is drained and the maximum time the
/// loop will block waiting for a packet — so a quiet capture still flushes
/// (an empty batch is suppressed) and wakes up promptly when traffic starts.
pub fn spawn(
    rx: Receiver<ParsedPacket>,
    tx: Sender<Vec<FlowDelta>>,
    flush_interval: Duration,
    dropped: Arc<AtomicU64>,
) -> JoinHandle<()> {
    spawn_named("flow-aggregator", move || {
        run(rx, tx, flush_interval, dropped)
    })
}

fn run(
    rx: Receiver<ParsedPacket>,
    tx: Sender<Vec<FlowDelta>>,
    flush_interval: Duration,
    dropped: Arc<AtomicU64>,
) {
    let mut acc: FxHashMap<FlowKey, FlowAccumulator> = FxHashMap::default();
    let mut last_flush = Instant::now();

    loop {
        match rx.recv_timeout(flush_interval) {
            Ok(p) => fold(&mut acc, &p),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }

        if last_flush.elapsed() >= flush_interval {
            if !acc.is_empty() {
                let batch: Vec<FlowDelta> = acc
                    .drain()
                    .map(|(key, a)| FlowDelta {
                        key,
                        bytes: a.bytes,
                        packets: a.packets,
                        last_summary: a.last_summary,
                        app_host: a.app_host,
                    })
                    .collect();
                match tx.try_send(batch) {
                    Ok(()) => {}
                    Err(TrySendError::Full(stale)) => {
                        // ECS thread is far enough behind that a queue of
                        // pre-aggregated batches is full. The data we just
                        // dropped is already stale; the next batch will carry
                        // fresh totals. Count the lost packets (summed across
                        // the dropped batch) so the loss is visible.
                        let lost: u64 = stale.iter().map(|d| d.packets).sum();
                        dropped.fetch_add(lost, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => return,
                }
            }
            last_flush = Instant::now();
        }
    }
}

fn fold(acc: &mut FxHashMap<FlowKey, FlowAccumulator>, p: &ParsedPacket) {
    let entry = acc.entry(p.key).or_default();
    entry.bytes += p.bytes as u64;
    entry.packets += 1;

    if p.summary_len > 0 {
        let len = (p.summary_len as usize).min(p.summary.len());
        if let Ok(s) = std::str::from_utf8(&p.summary[..len])
            && entry.last_summary.as_deref() != Some(s)
        {
            entry.last_summary = Some(s.to_owned());
        }
    }

    // First DPI hit wins — a flow's SNI/DNS intent is set at the handshake and
    // never changes, so we don't pay to re-copy it on later packets.
    if entry.app_host.is_none()
        && let Some((kind, host)) = p.app_host()
    {
        entry.app_host = Some((kind, host.to_owned()));
    }
}
