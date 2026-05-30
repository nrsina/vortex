use crate::core::flows::components::FlowKey;
use crate::core::flows::dpi::AppKind;

pub const SUMMARY_CAP: usize = 32;

/// Capacity of the inline app-layer hostname buffer carried per packet. Sized
/// to cover the vast majority of real SNI / DNS names while keeping
/// `ParsedPacket` small enough to stay cheap to copy across the capture →
/// aggregator channel. Longer names are truncated (display-only enrichment).
pub const APP_HOST_CAP: usize = 128;

#[derive(Clone, Copy, Debug)]
pub struct ParsedPacket {
    pub key: FlowKey,
    pub bytes: u32,
    /// Human-readable description of the packet produced by `etherparse` —
    /// e.g. `TCP [S.]`, `UDP len=512`, `ICMPv4 type=8`. The first
    /// `summary_len` bytes of `summary` are valid UTF-8.
    pub summary_len: u8,
    pub summary: [u8; SUMMARY_CAP],
    /// App-layer hostname extracted by DPI (TLS SNI / DNS qname). Valid only
    /// when `app_host_len > 0`; `app_kind` then tags which kind it is (see
    /// `AppKind::from_u8`). Kept as a fixed array so `ParsedPacket` stays
    /// `Copy` and stack-allocated across the thread boundary.
    pub app_host_len: u8,
    pub app_host: [u8; APP_HOST_CAP],
    pub app_kind: u8,
}

impl ParsedPacket {
    /// Construct an empty packet for `key`/`bytes` — DPI/summary fields unset.
    pub fn new(key: FlowKey, bytes: u32) -> Self {
        Self {
            key,
            bytes,
            summary_len: 0,
            summary: [0u8; SUMMARY_CAP],
            app_host_len: 0,
            app_host: [0u8; APP_HOST_CAP],
            app_kind: 0,
        }
    }

    pub fn write_summary(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let n = bytes.len().min(self.summary.len());
        self.summary[..n].copy_from_slice(&bytes[..n]);
        self.summary_len = n as u8;
    }

    /// Stamp the DPI-extracted hostname + its kind, truncating to `APP_HOST_CAP`.
    pub fn write_app_host(&mut self, kind: AppKind, host: &str) {
        let bytes = host.as_bytes();
        let n = bytes.len().min(self.app_host.len());
        self.app_host[..n].copy_from_slice(&bytes[..n]);
        self.app_host_len = n as u8;
        self.app_kind = kind.as_u8();
    }

    /// Decode the DPI hostname if one was stamped and the bytes are valid UTF-8.
    /// A name truncated mid–multi-byte char (rare — hostnames are ASCII) yields
    /// `None` rather than mojibake.
    pub fn app_host(&self) -> Option<(AppKind, &str)> {
        if self.app_host_len == 0 {
            return None;
        }
        let len = (self.app_host_len as usize).min(self.app_host.len());
        let kind = AppKind::from_u8(self.app_kind)?;
        let host = std::str::from_utf8(&self.app_host[..len]).ok()?;
        Some((kind, host))
    }
}
