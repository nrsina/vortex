//! Pure deep-packet-inspection parsers — zero I/O, zero allocation on the hot
//! path (the SNI parser borrows from its input; only the DNS name, which must
//! join dot-separated labels, allocates a `String`).
//!
//! Mirrors the `service.rs` / `ipclass.rs` style: small, self-contained, and
//! exhaustively unit-tested with hand-built wire fixtures. A hand-rolled binary
//! parser must never be shipped untested, so the `#[cfg(test)]` block carries
//! representative ClientHello / DNS-query byte layouts.
//!
//! Both parsers are *strictly* bounds-checked: any malformed, truncated, or
//! non-matching payload yields `None` rather than panicking. The capture thread
//! attempts SNI extraction on every TCP payload (the TLS record-type byte gates
//! out non-TLS traffic for ~free) and DNS extraction on UDP DNS/mDNS ports.

/// Which application-layer protocol an extracted hostname came from. Stored on
/// the flow alongside the host string so the details overlay can label the row
/// (`sni` vs `dns query`). Round-trips through a `u8` tag so it can ride inside
/// the `Copy` `ParsedPacket` across the capture→aggregator thread boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppKind {
    /// TLS Server Name Indication from a ClientHello.
    Sni,
    /// First QNAME of a DNS / mDNS query.
    Dns,
}

impl AppKind {
    /// Encode for the `ParsedPacket.app_kind` byte. Non-zero so a zeroed field
    /// is unambiguously "no kind".
    pub fn as_u8(self) -> u8 {
        match self {
            AppKind::Sni => 1,
            AppKind::Dns => 2,
        }
    }

    /// Decode the `ParsedPacket.app_kind` byte; `None` for any other value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(AppKind::Sni),
            2 => Some(AppKind::Dns),
            _ => None,
        }
    }

    /// Lower-case label for the details overlay row.
    pub fn label(self) -> &'static str {
        match self {
            AppKind::Sni => "sni",
            AppKind::Dns => "dns query",
        }
    }
}

/// Read a big-endian `u16` from the first two bytes of `b`, or `None` if `b`
/// is shorter than two bytes.
fn be16(b: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
}

/// Extract the SNI `host_name` from a TLS ClientHello carried in `payload`.
///
/// `payload` must start at the TLS record layer — i.e. the first byte of TCP
/// application data. Returns the borrowed host name (e.g. `example.com`) when
/// the payload is a handshake record holding a ClientHello whose extensions
/// include a `server_name` entry of type `host_name`. Anything else (non-TLS
/// data, a different handshake message, a truncated record, a missing
/// extension) yields `None`.
///
/// We do not require the full record to be present: snaplen may cut the
/// ClientHello short, but SNI sits early in the extensions, so we parse as far
/// as the captured bytes allow and bail cleanly the moment a field runs past
/// the end.
pub fn parse_tls_sni(payload: &[u8]) -> Option<&str> {
    // TLS record header (5 bytes): [0] content_type (22 = handshake),
    // [1..3] legacy_version, [3..5] record length.
    if payload.len() < 5 || payload[0] != 0x16 {
        return None;
    }
    let body = payload.get(5..)?;

    // Handshake header (4 bytes): [0] msg_type (1 = ClientHello),
    // [1..4] body length (u24, unused — we parse defensively past the end).
    if body.len() < 4 || body[0] != 0x01 {
        return None;
    }
    let mut p = body.get(4..)?;

    // ClientHello prefix: client_version (2) + random (32).
    p = p.get(34..)?;
    // session_id: 1-byte length + that many bytes.
    let sid_len = *p.first()? as usize;
    p = p.get(1 + sid_len..)?;
    // cipher_suites: 2-byte length + that many bytes.
    let cs_len = be16(p)? as usize;
    p = p.get(2 + cs_len..)?;
    // compression_methods: 1-byte length + that many bytes.
    let cm_len = *p.first()? as usize;
    p = p.get(1 + cm_len..)?;
    // extensions: 2-byte total length, then the extensions block. Cap the block
    // to what we actually captured so a snaplen cut just shortens the walk.
    let ext_total = be16(p)? as usize;
    p = p.get(2..)?;
    let mut ext = p.get(..ext_total.min(p.len()))?;

    // Walk extensions: each is type (2) + length (2) + data. Stop at the first
    // server_name extension (type 0x0000).
    while ext.len() >= 4 {
        let etype = be16(ext)?;
        let elen = be16(&ext[2..])? as usize;
        let edata = ext.get(4..4 + elen)?;
        if etype == 0x0000 {
            return parse_sni_extension(edata);
        }
        ext = &ext[4 + elen..];
    }
    None
}

/// Parse the body of a `server_name` extension: a 2-byte `server_name_list`
/// length followed by entries of `name_type (1) + name_len (2) + name`. Return
/// the first `host_name`-typed (0x00) entry as UTF-8.
fn parse_sni_extension(data: &[u8]) -> Option<&str> {
    // Skip the redundant list-length field; we walk to the first host_name.
    let _list_len = be16(data)?;
    let mut p = data.get(2..)?;
    while p.len() >= 3 {
        let name_type = p[0];
        let name_len = be16(&p[1..])? as usize;
        let name = p.get(3..3 + name_len)?;
        if name_type == 0x00 {
            return std::str::from_utf8(name).ok();
        }
        p = &p[3 + name_len..];
    }
    None
}

/// Extract the first QNAME from a DNS (or mDNS) message in `payload`.
///
/// `payload` must start at the DNS message header — i.e. the UDP payload of a
/// query. Returns the dotted name (`example.org`) of the first question when
/// `QDCOUNT >= 1` and the QNAME is a plain sequence of length-prefixed labels.
///
/// Compression pointers (top two bits of a length byte set) never appear in a
/// query's first QNAME — compression points *backward*, and the question is the
/// first record — so we treat one as malformed and bail. Allocates a `String`
/// because labels are joined with `.`; the caller copies it into the flow.
pub fn parse_dns_qname(payload: &[u8]) -> Option<String> {
    // DNS header is 12 bytes; QDCOUNT is at [4..6].
    if payload.len() < 12 {
        return None;
    }
    if be16(&payload[4..])? == 0 {
        return None;
    }

    // QNAME starts right after the header. Walk labels until the zero-length
    // root label.
    let mut pos = 12usize;
    let mut name = String::new();
    loop {
        let len = *payload.get(pos)? as usize;
        if len == 0 {
            break;
        }
        // Top two bits set => compression pointer; unexpected in a question.
        if len & 0xc0 != 0 {
            return None;
        }
        let label = payload.get(pos + 1..pos + 1 + len)?;
        let label = std::str::from_utf8(label).ok()?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(label);
        pos += 1 + len;
        // A DNS name is at most 255 bytes; guard against a runaway loop on
        // adversarial input.
        if name.len() > 255 {
            return None;
        }
    }
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but wire-valid TLS ClientHello record carrying `host` as
    /// its SNI. Constructing it programmatically keeps the byte arithmetic
    /// honest while still exercising the parser against real record framing.
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let host = host.as_bytes();

        // server_name extension data: list_length + (name_type, name_len, name).
        let mut sni_data = Vec::new();
        let entry_len = 1 + 2 + host.len();
        sni_data.extend_from_slice(&(entry_len as u16).to_be_bytes());
        sni_data.push(0x00); // name_type = host_name
        sni_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(host);

        // One extension: type 0x0000 (server_name) + length + data.
        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_data);

        // ClientHello body.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id length = 0
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // cipher suites: len 2 + one suite
        body.extend_from_slice(&[0x01, 0x00]); // compression methods: len 1 + null
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes()); // extensions length
        body.extend_from_slice(&ext);

        // Handshake header: msg_type + u24 length.
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let blen = body.len();
        handshake.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
        handshake.extend_from_slice(&body);

        // TLS record header: content_type + version + u16 length.
        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&[0x03, 0x01]); // record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni_from_client_hello() {
        let hello = client_hello_with_sni("example.com");
        assert_eq!(parse_tls_sni(&hello), Some("example.com"));
    }

    #[test]
    fn extracts_long_sni() {
        let host = "very-long-subdomain.cdn.provider.example.com";
        let hello = client_hello_with_sni(host);
        assert_eq!(parse_tls_sni(&hello), Some(host));
    }

    #[test]
    fn rejects_non_handshake_record() {
        // Application-data record (0x17), not a handshake.
        assert_eq!(parse_tls_sni(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]), None);
    }

    #[test]
    fn rejects_truncated_client_hello() {
        let hello = client_hello_with_sni("example.com");
        // Cut the record off before the extensions/SNI are reached.
        assert_eq!(parse_tls_sni(&hello[..20]), None);
    }

    #[test]
    fn rejects_empty_and_short_tls() {
        assert_eq!(parse_tls_sni(&[]), None);
        assert_eq!(parse_tls_sni(&[0x16, 0x03]), None);
    }

    /// A real DNS standard query for `example.org` (A/IN), header + one
    /// question, hand-laid byte by byte.
    const DNS_QUERY_EXAMPLE_ORG: &[u8] = &[
        0x12, 0x34, // ID
        0x01, 0x00, // flags: standard query, recursion desired
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // label "example"
        0x03, b'o', b'r', b'g', // label "org"
        0x00, // root label
        0x00, 0x01, // QTYPE = A
        0x00, 0x01, // QCLASS = IN
    ];

    #[test]
    fn extracts_dns_qname() {
        assert_eq!(
            parse_dns_qname(DNS_QUERY_EXAMPLE_ORG).as_deref(),
            Some("example.org")
        );
    }

    #[test]
    fn rejects_dns_with_no_questions() {
        let mut q = DNS_QUERY_EXAMPLE_ORG.to_vec();
        q[4] = 0; // QDCOUNT high byte already 0
        q[5] = 0; // QDCOUNT = 0
        assert_eq!(parse_dns_qname(&q), None);
    }

    #[test]
    fn rejects_dns_compression_pointer_in_question() {
        let q: &[u8] = &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xc0, 0x0c, // compression pointer where a label length is expected
        ];
        assert_eq!(parse_dns_qname(q), None);
    }

    #[test]
    fn rejects_short_dns() {
        assert_eq!(parse_dns_qname(&[]), None);
        assert_eq!(parse_dns_qname(&[0x12, 0x34, 0x01, 0x00]), None);
    }

    #[test]
    fn app_kind_round_trips() {
        for k in [AppKind::Sni, AppKind::Dns] {
            assert_eq!(AppKind::from_u8(k.as_u8()), Some(k));
        }
        assert_eq!(AppKind::from_u8(0), None);
        assert_eq!(AppKind::from_u8(99), None);
    }
}
