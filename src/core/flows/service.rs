//! Small static mapping of well-known ports to service names.
//!
//! Used only by the details overlay to annotate the `Port` row (e.g. render
//! `443 (https)` rather than just `443`). Keeping this in a `match` rather
//! than a `HashMap` lets the compiler turn it into a jump table — no runtime
//! cost, no allocations, no startup work.
//!
//! Coverage is intentionally limited to the ~50 ports a network monitor would
//! plausibly want to annotate; obscure ports render as the bare number.

use crate::core::common::{IPPROTO_TCP, IPPROTO_UDP};

/// Return the IANA-ish service name for `port` on `proto`, or `None` for ports
/// we don't bother annotating.
pub fn well_known(port: u16, proto: u8) -> Option<&'static str> {
    // Most well-known ports work on both TCP and UDP (the service is the same
    // even when only one transport is common). Where they differ we branch.
    match port {
        20 => Some("ftp-data"),
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        67 => Some("dhcp-server"),
        68 => Some("dhcp-client"),
        69 => Some("tftp"),
        80 => Some("http"),
        88 => Some("kerberos"),
        110 => Some("pop3"),
        111 => Some("rpc"),
        119 => Some("nntp"),
        123 => Some("ntp"),
        135 => Some("rpc-epmap"),
        137 => Some("netbios-ns"),
        138 => Some("netbios-dgm"),
        139 => Some("netbios-ssn"),
        143 => Some("imap"),
        161 => Some("snmp"),
        162 => Some("snmp-trap"),
        179 => Some("bgp"),
        194 => Some("irc"),
        389 => Some("ldap"),
        443 => Some("https"),
        445 => Some("smb"),
        465 => Some("smtps"),
        500 => Some("ipsec"),
        514 if proto == IPPROTO_UDP => Some("syslog"),
        514 if proto == IPPROTO_TCP => Some("shell"),
        515 => Some("printer"),
        587 => Some("smtp-submission"),
        631 => Some("ipp"),
        636 => Some("ldaps"),
        853 => Some("dns-over-tls"),
        873 => Some("rsync"),
        989 => Some("ftps-data"),
        990 => Some("ftps"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1080 => Some("socks"),
        1194 => Some("openvpn"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        1701 => Some("l2tp"),
        1723 => Some("pptp"),
        1812 => Some("radius"),
        1813 => Some("radius-acct"),
        2049 => Some("nfs"),
        3128 => Some("squid"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5060 => Some("sip"),
        5061 => Some("sips"),
        5222 => Some("xmpp-client"),
        5353 => Some("mdns"),
        5432 => Some("postgresql"),
        5672 => Some("amqp"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        6443 => Some("kubernetes"),
        6667 => Some("irc"),
        8080 => Some("http-alt"),
        8443 => Some("https-alt"),
        8883 => Some("mqtts"),
        9000 => Some("http-alt"),
        9092 => Some("kafka"),
        9200 => Some("elasticsearch"),
        9418 => Some("git"),
        11211 => Some("memcached"),
        27017 => Some("mongodb"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_ports_annotated() {
        assert_eq!(well_known(443, IPPROTO_TCP), Some("https"));
        assert_eq!(well_known(53, IPPROTO_UDP), Some("dns"));
        assert_eq!(well_known(22, IPPROTO_TCP), Some("ssh"));
    }

    #[test]
    fn proto_specific_dispatch() {
        assert_eq!(well_known(514, IPPROTO_UDP), Some("syslog"));
        assert_eq!(well_known(514, IPPROTO_TCP), Some("shell"));
    }

    #[test]
    fn unknown_port() {
        assert_eq!(well_known(54321, IPPROTO_TCP), None);
    }

    #[test]
    fn spot_check_additional_ports() {
        assert_eq!(well_known(80, IPPROTO_TCP), Some("http"));
        assert_eq!(well_known(25, IPPROTO_TCP), Some("smtp"));
        assert_eq!(well_known(3306, IPPROTO_TCP), Some("mysql"));
        assert_eq!(well_known(5432, IPPROTO_TCP), Some("postgresql"));
        assert_eq!(well_known(6379, IPPROTO_TCP), Some("redis"));
        assert_eq!(well_known(27017, IPPROTO_TCP), Some("mongodb"));
    }

    #[test]
    fn udp_only_ports_annotated() {
        assert_eq!(well_known(67, IPPROTO_UDP), Some("dhcp-server"));
        assert_eq!(well_known(68, IPPROTO_UDP), Some("dhcp-client"));
        assert_eq!(well_known(123, IPPROTO_UDP), Some("ntp"));
    }
}
