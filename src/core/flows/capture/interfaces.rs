use std::net::IpAddr;

use anyhow::{Context, Result};
use pcap::ConnectionStatus;

/// A snapshot of one interface as reported by `pcap_findalldevs`. Stable across
/// the lifetime of the picker (refreshed only when the user explicitly
/// reloads); the live traffic indicator is tracked separately by the probe.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    /// pcap's human description (e.g. "Wi-Fi"). Captured for completeness but
    /// not yet surfaced in the picker, hence the narrow allow.
    #[allow(dead_code)]
    pub description: Option<String>,
    pub ipv4: Option<IpAddr>,
    pub ipv6: Option<IpAddr>,
    pub is_up: bool,
    pub is_running: bool,
    pub is_loopback: bool,
    pub is_wireless: bool,
    pub connection: ConnectionStatus,
}

impl InterfaceInfo {
    /// Whether the interface is in a state where it could carry packets.
    /// A `down` link or a `disconnected` carrier (e.g. unplugged ethernet,
    /// wifi not associated) will never produce traffic, so probing it just
    /// burns a probe window — and worse, can stall the sequential probe loop
    /// if pcap blocks on opening the bad device. The picker uses this to
    /// filter the probe candidate list and to render a quiet placeholder in
    /// the traffic column instead of an indefinite "scanning…".
    pub fn is_active(&self) -> bool {
        self.is_up && !matches!(self.connection, ConnectionStatus::Disconnected)
    }

    /// Two-line status for the picker's status column. Line 1 carries the link
    /// characteristics (loopback / wireless / up-down / running); line 2 carries
    /// the connection status on its own row. Splitting them keeps the combined
    /// label (up to ~38 chars) from clipping the fixed-width column — the picker
    /// rows are already two cells tall, so the second row is free real estate.
    /// The connection line is empty when the carrier state is unknown or not
    /// applicable (e.g. the `any` pseudo-device), leaving that row blank.
    pub fn status_lines(&self) -> [String; 2] {
        let mut flags: Vec<&str> = Vec::with_capacity(4);
        if self.is_loopback {
            flags.push("loopback");
        }
        if self.is_wireless {
            flags.push("wireless");
        }
        flags.push(if self.is_up { "up" } else { "down" });
        if self.is_running {
            flags.push("running");
        }
        let connection = match self.connection {
            ConnectionStatus::Connected => "connected",
            ConnectionStatus::Disconnected => "disconnected",
            ConnectionStatus::Unknown | ConnectionStatus::NotApplicable => "",
        };
        [flags.join(" · "), connection.to_string()]
    }
}

/// Enumerate all interfaces pcap can see, plus the synthetic `any` device that
/// captures across every interface. `any` is always inserted at index 0 even
/// if pcap already returned it, so the picker has a predictable default.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let raw = pcap::Device::list().context("pcap_findalldevs failed")?;

    let mut out: Vec<InterfaceInfo> = Vec::with_capacity(raw.len() + 1);
    let mut seen_any = false;

    for d in raw {
        let mut ipv4 = None;
        let mut ipv6 = None;
        for a in &d.addresses {
            match a.addr {
                IpAddr::V4(_) if ipv4.is_none() => ipv4 = Some(a.addr),
                IpAddr::V6(_) if ipv6.is_none() => ipv6 = Some(a.addr),
                _ => {}
            }
        }
        if d.name == "any" {
            seen_any = true;
        }
        out.push(InterfaceInfo {
            name: d.name,
            description: d.desc,
            ipv4,
            ipv6,
            is_up: d.flags.is_up(),
            is_running: d.flags.is_running(),
            is_loopback: d.flags.is_loopback(),
            is_wireless: d.flags.is_wireless(),
            connection: d.flags.connection_status,
        });
    }

    if !seen_any {
        out.insert(
            0,
            InterfaceInfo {
                name: "any".into(),
                description: Some("Pseudo-device: capture on every interface".into()),
                ipv4: None,
                ipv6: None,
                is_up: true,
                is_running: true,
                is_loopback: false,
                is_wireless: false,
                connection: ConnectionStatus::NotApplicable,
            },
        );
    } else {
        // Stable ordering: "any" at index 0, others in pcap-reported order.
        if let Some(pos) = out.iter().position(|i| i.name == "any") {
            let any = out.remove(pos);
            out.insert(0, any);
        }
    }

    Ok(out)
}
