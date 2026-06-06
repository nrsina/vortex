use bevy_ecs::prelude::Resource;
use config::Config;
use std::sync::OnceLock;

static SETTINGS: OnceLock<Settings> = OnceLock::new();

#[derive(Debug)]
pub struct Settings {
    pub tick_rate_hz: u8,
    pub debug_enabled: bool,
    pub capture: CaptureSettings,
    pub processes: ProcessesSettings,
    pub dns: DnsSettings,
    pub dpi: DpiSettings,
    pub flows: FlowSettings,
}

/// Knobs for the flow lifecycle (expiry + retention). Read from `[flows]` in
/// `Settings.toml`; falls back to sane defaults when the section is absent.
///
/// A flow that stops receiving packets isn't deleted — it's marked *expired*
/// after `idle_timeout_seconds` and kept around so the user can still inspect
/// it. Memory is bounded only by `expired_cap`: there is no time-based hard
/// delete, since the whole point of retaining expired flows is to not lose
/// them. Once the expired set exceeds the cap, the oldest (by last packet) are
/// evicted.
#[derive(Resource, Debug, Clone, Copy)]
pub struct FlowSettings {
    /// Seconds of silence before a flow is marked expired (dimmed, dropped
    /// from the "active" count, but still retained). Clamped to `[5, 86_400]`.
    pub idle_timeout_seconds: u64,
    /// Upper bound on retained expired flows. Once exceeded, the oldest
    /// expired flows (by last-packet time) are hard-evicted to bound memory on
    /// hosts that see many short-lived peers. Clamped to `[100, 1_000_000]`.
    pub expired_cap: usize,
}

impl Default for FlowSettings {
    fn default() -> Self {
        Self {
            idle_timeout_seconds: 30,
            expired_cap: 10_000,
        }
    }
}

/// ECS resource carrying the configured tick rate. Inserted once at startup
/// by `FlowsPlugin` so `aggregate::tick` can read it without touching the
/// global `settings()` `OnceLock` — making system tests injectable.
#[derive(Resource, Debug, Clone, Copy)]
pub struct TickRate(pub u8);

/// Knobs for the packet-capture handle. Read from `[capture]` in
/// `Settings.toml`; falls back to sane defaults when the section is absent.
#[derive(Debug, Clone, Copy)]
pub struct CaptureSettings {
    /// Bytes captured per packet (libpcap snaplen). Higher lets DPI read
    /// deeper into the payload — TLS SNI / DNS query names live well past
    /// byte 96 — at the cost of more bytes copied per frame. Bandwidth
    /// accounting always uses the original wire length, so this only bounds
    /// how much payload we can inspect, never the reported throughput.
    /// Clamped to `[96, 65_535]`.
    pub snaplen: u16,
    /// Put the interface into promiscuous mode (capture frames not addressed
    /// to this host). Off by default — on a switched network it mostly adds
    /// noise, and some environments disallow it.
    pub promisc: bool,
}

impl Default for CaptureSettings {
    fn default() -> Self {
        Self {
            snaplen: 512,
            promisc: false,
        }
    }
}

/// Knobs for the process-attribution subsystem. Read from `[processes]` in
/// `Settings.toml`; falls back to sane defaults when the section is absent.
#[derive(Debug, Clone, Copy)]
pub struct ProcessesSettings {
    /// `false` skips spawning the snapshot thread entirely — useful when
    /// running in an environment where sock_diag / libproc is unavailable or
    /// disallowed. Flows still display, just without process attribution.
    pub enabled: bool,
    /// Cadence of the background snapshot loop. Clamped to `[250, 10_000]` ms
    /// to keep the worker from spinning or going so quiet that the UI sits on
    /// stale attribution for tens of seconds.
    pub poll_interval_ms: u64,
}

impl Default for ProcessesSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_ms: 1000,
        }
    }
}

/// Knobs for the rDNS enrichment subsystem. Read from `[dns]` in
/// `Settings.toml`; falls back to sane defaults when the section is absent.
///
/// The default values are tuned for "eager lookup with safety rails": each
/// new flow's IPs get queued on first sight, but a token-bucket rate cap and
/// per-thread failure backoff keep us friendly to a stressed resolver.
#[derive(Debug, Clone, Copy)]
pub struct DnsSettings {
    /// `false` skips spawning DNS workers entirely. Flows render raw IPs;
    /// the overlay shows `(disabled)` for hostname rows.
    pub enabled: bool,
    /// Re-query each IP at most once per this many seconds. Bounds churn
    /// when a flow is long-lived. Clamped to `[60, 86_400]`.
    pub cache_ttl_seconds: u64,
    /// Number of worker threads. ≥ 2 so a single stalled query can't
    /// bottleneck enrichment. Clamped to `[1, 16]`.
    pub worker_threads: usize,
    /// Bound on the pending-request channel depth. Beyond this the
    /// `request_lookups` system drops new enqueues and warns. Clamped to
    /// `[256, 100_000]`.
    pub request_queue_cap: usize,
    /// Global token-bucket rate cap, queries-per-second, shared across all
    /// worker threads. Smooths bursts. Clamped to `[1, 10_000]`.
    pub dns_qps_cap: u32,
    /// A worker sleeps `failure_backoff_seconds` after this many consecutive
    /// `Failed` outcomes. A single success resets the counter. Clamped to
    /// `[1, 1000]`.
    pub failure_backoff_threshold: u32,
    /// Duration of the backoff sleep, in seconds. Clamped to `[1, 600]`.
    pub failure_backoff_seconds: u64,
    /// Upper bound on `RdnsCache` size. Once exceeded, the least-recently
    /// inserted entries are evicted. Prevents unbounded growth on hosts that
    /// see many short-lived peers (scanners, P2P, port scans). Clamped to
    /// `[256, 1_000_000]`.
    pub cache_cap: usize,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_ttl_seconds: 3600,
            worker_threads: 2,
            request_queue_cap: 10_000,
            dns_qps_cap: 50,
            failure_backoff_threshold: 10,
            failure_backoff_seconds: 30,
            cache_cap: 10_000,
        }
    }
}

/// Knobs for deep-packet inspection (app-layer hostname enrichment). Read from
/// `[dpi]` in `Settings.toml`; falls back to sane defaults when absent.
#[derive(Debug, Clone, Copy)]
pub struct DpiSettings {
    /// `false` skips all payload inspection in the capture thread — flows still
    /// render, just without the `sni` / `dns query` rows in the details
    /// overlay. Note DPI also needs enough `[capture].snaplen` to reach the
    /// payload (TLS SNI / DNS names live well past byte 96).
    pub enabled: bool,
}

impl Default for DpiSettings {
    fn default() -> Self {
        Self { enabled: true }
    }
}

pub fn settings() -> &'static Settings {
    SETTINGS.get_or_init(|| {
        let config = Config::builder()
            .add_source(config::File::with_name("Settings").format(config::FileFormat::Toml))
            .build()
            .unwrap();
        let capture_defaults = CaptureSettings::default();
        let capture = CaptureSettings {
            snaplen: config
                .get::<u16>("capture.snaplen")
                .unwrap_or(capture_defaults.snaplen)
                .clamp(96, 65_535),
            promisc: config
                .get_bool("capture.promisc")
                .unwrap_or(capture_defaults.promisc),
        };
        let processes = ProcessesSettings {
            enabled: config.get_bool("processes.enabled").unwrap_or(true),
            poll_interval_ms: config
                .get::<u64>("processes.poll_interval_ms")
                .unwrap_or(1000)
                .clamp(250, 10_000),
        };
        let dns_defaults = DnsSettings::default();
        let dns = DnsSettings {
            enabled: config
                .get_bool("dns.enabled")
                .unwrap_or(dns_defaults.enabled),
            cache_ttl_seconds: config
                .get::<u64>("dns.cache_ttl_seconds")
                .unwrap_or(dns_defaults.cache_ttl_seconds)
                .clamp(60, 86_400),
            worker_threads: config
                .get::<usize>("dns.worker_threads")
                .unwrap_or(dns_defaults.worker_threads)
                .clamp(1, 16),
            request_queue_cap: config
                .get::<usize>("dns.request_queue_cap")
                .unwrap_or(dns_defaults.request_queue_cap)
                .clamp(256, 100_000),
            dns_qps_cap: config
                .get::<u32>("dns.dns_qps_cap")
                .unwrap_or(dns_defaults.dns_qps_cap)
                .clamp(1, 10_000),
            failure_backoff_threshold: config
                .get::<u32>("dns.failure_backoff_threshold")
                .unwrap_or(dns_defaults.failure_backoff_threshold)
                .clamp(1, 1000),
            failure_backoff_seconds: config
                .get::<u64>("dns.failure_backoff_seconds")
                .unwrap_or(dns_defaults.failure_backoff_seconds)
                .clamp(1, 600),
            cache_cap: config
                .get::<usize>("dns.cache_cap")
                .unwrap_or(dns_defaults.cache_cap)
                .clamp(256, 1_000_000),
        };
        let dpi = DpiSettings {
            enabled: config
                .get_bool("dpi.enabled")
                .unwrap_or(DpiSettings::default().enabled),
        };
        let flow_defaults = FlowSettings::default();
        let flows = FlowSettings {
            idle_timeout_seconds: config
                .get::<u64>("flows.idle_timeout_seconds")
                .unwrap_or(flow_defaults.idle_timeout_seconds)
                .clamp(5, 86_400),
            expired_cap: config
                .get::<usize>("flows.expired_cap")
                .unwrap_or(flow_defaults.expired_cap)
                .clamp(100, 1_000_000),
        };
        Settings {
            tick_rate_hz: config.get("tick_rate_hz").unwrap_or(30),
            debug_enabled: config.get_bool("debug_enabled").unwrap_or(false),
            capture,
            processes,
            dns,
            dpi,
            flows,
        }
    })
}
