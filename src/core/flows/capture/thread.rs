use std::fmt::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;

use anyhow::{Context, Result};
use crossbeam_channel::{Sender, TrySendError};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Active, Capture, Linktype};

use crate::core::common::spawn_named;
use crate::core::flows::components::FlowKey;
use crate::core::flows::dpi::{self, AppKind};
use crate::core::flows::packet::ParsedPacket;
use crate::core::settings::settings;

/// Open a live pcap handle for the given interface name. `iface` may be
/// `"any"` (Linux pseudo-device that captures on every interface) or a real
/// device name like `"eth0"`. Requires `CAP_NET_RAW` (or root); if the open
/// fails the error message includes a hint.
///
/// `filter` is an optional BPF expression (`tcp port 443`, `host 1.1.1.1`, …).
/// When `Some` and non-empty after trimming, it is compiled and applied to the
/// capture handle; a syntax error from libpcap surfaces as an `Err` so the
/// caller can render it inline rather than crashing.
///
/// `snaplen` caps how many bytes of each frame libpcap copies to us — it
/// bounds DPI's reach into the payload but not byte accounting, which uses the
/// original wire length. `promisc` toggles promiscuous mode. Both come from
/// `[capture]` in `Settings.toml` (see `CaptureSettings`).
pub fn open(iface: &str, filter: Option<&str>, snaplen: u16, promisc: bool) -> Result<Capture<Active>> {
    let mut cap = Capture::from_device(iface)
        .with_context(|| format!("pcap: lookup of interface '{iface}' failed"))?
        .promisc(promisc)
        .snaplen(snaplen as i32)
        .immediate_mode(true)
        .timeout(100)
        .open()
        .with_context(|| {
            format!(
                "pcap: failed to open '{iface}' \
                 (try `sudo setcap cap_net_raw,cap_net_admin=eip target/debug/vortex` \
                 or run as root)"
            )
        })?;
    if let Some(expr) = filter.map(str::trim).filter(|s| !s.is_empty()) {
        cap.filter(expr, true)
            .with_context(|| format!("pcap: invalid BPF filter '{expr}'"))?;
    }
    Ok(cap)
}

/// `dropped` is a shared counter incremented whenever the packet channel is
/// full and a parsed packet has to be discarded — surfaced in the UI so silent
/// loss under load becomes visible (see `LiveMetrics`).
pub fn spawn(
    mut cap: Capture<Active>,
    tx: Sender<ParsedPacket>,
    dropped: Arc<AtomicU64>,
) -> JoinHandle<()> {
    let dl = cap.get_datalink();
    spawn_named("pcap-capture", move || run(&mut cap, dl, tx, dropped))
}

fn run(cap: &mut Capture<Active>, dl: Linktype, tx: Sender<ParsedPacket>, dropped: Arc<AtomicU64>) {
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                // `header.len` is the *original* wire length; `data` is capped
                // at the configured snaplen. Account bytes from the wire length
                // so throughput stays correct regardless of snaplen.
                let Some(parsed) = parse(packet.data, dl, packet.header.len) else {
                    continue;
                };
                match tx.try_send(parsed) {
                    Ok(()) => {}
                    // ECS thread is behind: count the dropped packet so the
                    // header can show loss instead of swallowing it silently.
                    Err(TrySendError::Full(_)) => {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => return,
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap::Error::NoMorePackets) => return,
            Err(e) => {
                tracing::error!("pcap capture stopped: {e}");
                return;
            }
        }
    }
}

fn parse(data: &[u8], dl: Linktype, wire_len: u32) -> Option<ParsedPacket> {
    let l3 = strip_link_header(data, dl)?;
    let sliced = SlicedPacket::from_ip(l3).ok()?;

    let (src_ip, dst_ip, proto) = match sliced.net.as_ref()? {
        NetSlice::Ipv4(v4) => {
            let h = v4.header();
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
                h.protocol().0,
            )
        }
        NetSlice::Ipv6(v6) => {
            let h = v6.header();
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
                h.next_header().0,
            )
        }
        _ => return None,
    };

    let (src_port, dst_port) = match sliced.transport.as_ref() {
        Some(TransportSlice::Tcp(t)) => (t.source_port(), t.destination_port()),
        Some(TransportSlice::Udp(u)) => (u.source_port(), u.destination_port()),
        _ => (0, 0),
    };

    let key = FlowKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
    };

    let mut pkt = ParsedPacket::new(key, wire_len);
    pkt.write_summary(&format_summary(&sliced));
    // DPI enrichment: pull the app-layer hostname (TLS SNI / DNS qname) from the
    // transport payload when enabled. Cheap for non-matching traffic — the SNI
    // path bails on the first byte, the DNS path only runs on DNS/mDNS ports.
    if settings().dpi.enabled {
        extract_app_host(&mut pkt, &sliced, src_port, dst_port);
    }
    Some(pkt)
}

/// Attempt to extract an app-layer hostname into `pkt`. SNI is tried on every
/// non-empty TCP payload (the TLS record-type byte rejects non-TLS for ~free,
/// so HTTPS on non-standard ports is still caught); a DNS qname is tried only
/// on UDP DNS/mDNS ports. Misses leave `pkt` untouched.
fn extract_app_host(pkt: &mut ParsedPacket, sliced: &SlicedPacket, src_port: u16, dst_port: u16) {
    match sliced.transport.as_ref() {
        Some(TransportSlice::Tcp(t)) => {
            let payload = t.payload();
            if !payload.is_empty()
                && let Some(host) = dpi::parse_tls_sni(payload)
            {
                pkt.write_app_host(AppKind::Sni, host);
            }
        }
        Some(TransportSlice::Udp(u)) => {
            let payload = u.payload();
            if !payload.is_empty()
                && (is_dns_port(dst_port) || is_dns_port(src_port))
                && let Some(host) = dpi::parse_dns_qname(payload)
            {
                pkt.write_app_host(AppKind::Dns, &host);
            }
        }
        _ => {}
    }
}

/// Ports carrying plaintext DNS / mDNS query traffic we can parse.
fn is_dns_port(port: u16) -> bool {
    port == 53 || port == 5353
}

fn strip_link_header(data: &[u8], dl: Linktype) -> Option<&[u8]> {
    // 1=DLT_EN10MB (Ethernet), 113=DLT_LINUX_SLL, 276=DLT_LINUX_SLL2,
    // 0=DLT_NULL, 12=DLT_LOOP, 101=DLT_RAW.
    match dl.0 {
        1 => {
            // Skip the Ethernet II header (14 bytes); also skip a single 802.1Q
            // VLAN tag if present so etherparse sees the IP frame directly.
            let mut off = 14;
            if data.len() >= off + 2 {
                let etype = u16::from_be_bytes([data[12], data[13]]);
                if etype == 0x8100 && data.len() >= off + 4 {
                    off += 4;
                }
            }
            data.get(off..)
        }
        113 => data.get(16..),
        276 => data.get(20..),
        0 | 12 => data.get(4..),
        101 => Some(data),
        _ => None,
    }
}

fn format_summary(p: &SlicedPacket) -> String {
    let mut s = String::with_capacity(crate::core::flows::packet::SUMMARY_CAP);
    match p.transport.as_ref() {
        Some(TransportSlice::Tcp(t)) => {
            s.push_str("TCP [");
            if t.cwr() { s.push('W'); }
            if t.ece() { s.push('E'); }
            if t.urg() { s.push('U'); }
            if t.ack() { s.push('.'); }
            if t.psh() { s.push('P'); }
            if t.rst() { s.push('R'); }
            if t.syn() { s.push('S'); }
            if t.fin() { s.push('F'); }
            if s.len() == 5 {
                s.push('-');
            }
            s.push(']');
        }
        Some(TransportSlice::Udp(u)) => {
            let _ = write!(s, "UDP len={}", u.length());
        }
        Some(TransportSlice::Icmpv4(_)) => s.push_str("ICMPv4"),
        Some(TransportSlice::Icmpv6(_)) => s.push_str("ICMPv6"),
        None => match p.net.as_ref() {
            Some(NetSlice::Ipv4(v4)) => {
                let _ = write!(s, "IPv4 proto={}", v4.header().protocol().0);
            }
            Some(NetSlice::Ipv6(v6)) => {
                let _ = write!(s, "IPv6 next={}", v6.header().next_header().0);
            }
            _ => s.push('?'),
        },
    }
    s
}
