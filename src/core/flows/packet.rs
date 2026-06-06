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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::flows::dpi::AppKind;
    use crate::core::flows::test_support::flow_key;

    fn dummy_key() -> FlowKey {
        flow_key("127.0.0.1", 1234, "8.8.8.8", 443, 6)
    }

    // --- write_summary ---

    #[test]
    fn write_summary_short_stored_verbatim() {
        let mut pkt = ParsedPacket::new(dummy_key(), 100);
        pkt.write_summary("TCP [S.]");
        assert_eq!(pkt.summary_len, 8);
        assert_eq!(&pkt.summary[..8], b"TCP [S.]");
    }

    #[test]
    fn write_summary_truncates_at_capacity() {
        // Must not panic; summary_len is capped at SUMMARY_CAP.
        let long = "X".repeat(SUMMARY_CAP + 10);
        let mut pkt = ParsedPacket::new(dummy_key(), 0);
        pkt.write_summary(&long);
        assert_eq!(pkt.summary_len as usize, SUMMARY_CAP);
    }

    // --- write_app_host / app_host ---

    #[test]
    fn write_app_host_round_trips() {
        let mut pkt = ParsedPacket::new(dummy_key(), 0);
        pkt.write_app_host(AppKind::Sni, "example.com");
        assert_eq!(pkt.app_host(), Some((AppKind::Sni, "example.com")));
    }

    #[test]
    fn write_app_host_dns_kind_round_trips() {
        let mut pkt = ParsedPacket::new(dummy_key(), 0);
        pkt.write_app_host(AppKind::Dns, "fonts.googleapis.com");
        assert_eq!(pkt.app_host(), Some((AppKind::Dns, "fonts.googleapis.com")));
    }

    #[test]
    fn write_app_host_truncates_at_capacity() {
        // Must not panic; app_host_len is capped at APP_HOST_CAP.
        let long = "a".repeat(APP_HOST_CAP + 20);
        let mut pkt = ParsedPacket::new(dummy_key(), 0);
        pkt.write_app_host(AppKind::Dns, &long);
        assert_eq!(pkt.app_host_len as usize, APP_HOST_CAP);
    }

    #[test]
    fn app_host_returns_none_when_empty() {
        let pkt = ParsedPacket::new(dummy_key(), 0);
        assert_eq!(pkt.app_host(), None);
    }

    #[test]
    fn app_host_rejects_invalid_utf8() {
        let mut pkt = ParsedPacket::new(dummy_key(), 0);
        pkt.app_host[0] = 0xFF; // not valid UTF-8 (lone continuation-less byte)
        pkt.app_host_len = 1;
        pkt.app_kind = AppKind::Sni.as_u8();
        assert_eq!(pkt.app_host(), None);
    }

    #[test]
    fn app_host_rejects_invalid_kind_byte() {
        let mut pkt = ParsedPacket::new(dummy_key(), 0);
        pkt.write_app_host(AppKind::Sni, "example.com");
        pkt.app_kind = 0; // 0 is "no kind" — not a valid AppKind
        assert_eq!(pkt.app_host(), None);
    }

    #[test]
    fn app_host_truncated_multibyte_returns_none() {
        // "é" is 2 bytes (0xC3 0xA9). Place it starting at byte APP_HOST_CAP-1 so
        // write_app_host copies only the first byte → str::from_utf8 rejects the
        // incomplete sequence and app_host() returns None rather than mojibake.
        let mut s = "a".repeat(APP_HOST_CAP - 1);
        s.push('é'); // 2-byte char: total len = APP_HOST_CAP + 1
        let mut pkt = ParsedPacket::new(dummy_key(), 0);
        pkt.write_app_host(AppKind::Sni, &s);
        assert_eq!(pkt.app_host_len as usize, APP_HOST_CAP);
        assert_eq!(pkt.app_host(), None, "truncated multibyte char must yield None");
    }
}
