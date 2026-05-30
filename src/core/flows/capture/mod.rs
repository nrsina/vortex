pub mod interfaces;
pub mod probe;
pub mod thread;

pub use interfaces::{InterfaceInfo, list_interfaces};
pub use probe::{ProbeReport, ProbeStatus, spawn_probe_one};

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyhow::Result;
use crossbeam_channel::Receiver;

use crate::core::flows::packet::ParsedPacket;

/// Open pcap on `iface`, spawn the capture thread, and return the receiving
/// end of the bounded packet channel. Not modelled as a `bevy_app::Plugin`
/// because it contributes no resources or systems to the ECS world —
/// wiring it explicitly from `main` keeps the receiver out of the world
/// and makes the dependency on `flows` visible at the call site.
///
/// `filter` is an optional BPF expression compiled into the pcap handle
/// before the capture thread starts. An empty string is treated as no filter.
///
/// `snaplen`/`promisc` come from `[capture]` in `Settings.toml` and are
/// threaded straight through to `thread::open`. `dropped` is the shared
/// loss counter the capture thread bumps when the packet channel is full.
pub fn start(
    iface: &str,
    queue_size: usize,
    filter: Option<&str>,
    snaplen: u16,
    promisc: bool,
    dropped: Arc<AtomicU64>,
) -> Result<Receiver<ParsedPacket>> {
    let cap = thread::open(iface, filter, snaplen, promisc)?;
    tracing::info!(
        "pcap capture opened on '{}' (datalink {:?}, filter {:?})",
        iface,
        cap.get_datalink(),
        filter.map(str::trim).filter(|s| !s.is_empty()),
    );
    let (tx, rx) = crossbeam_channel::bounded(queue_size);
    thread::spawn(cap, tx, dropped);
    Ok(rx)
}
