/// Human-readable bytes-per-second. Cyan-cell consumers want a compact string
/// that fits a ~12-char column; we pick the largest suffix that keeps the
/// numeric part under three significant digits.
pub fn format_bps(bps: f32) -> String {
    if bps >= 1_000_000.0 {
        format!("{:.2} MB/s", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.1} KB/s", bps / 1_000.0)
    } else {
        format!("{:.0} B/s", bps)
    }
}

/// Compact decimal count (`1.2k`, `3.4M`) for header tallies like flow and
/// drop counts where the exact figure matters less than the order of
/// magnitude. Values under 1000 render as-is.
pub fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Human-readable byte total using binary (1024) units. Same compactness goal
/// as `format_bps` but for cumulative totals where MB/GB rollover matters.
pub fn format_bytes(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.2} GB", b as f64 / (1u64 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.2} MB", b as f64 / (1u64 << 20) as f64)
    } else if b >= 1 << 10 {
        format!("{:.2} KB", b as f64 / (1u64 << 10) as f64)
    } else {
        format!("{} B", b)
    }
}

/// Compact "X ago" for elapsed-since-instant. Used by the details overlay to
/// annotate first-seen / last-packet timestamps. Picks the largest unit that
/// keeps the leading number under three digits.
pub fn format_duration_since(t: std::time::Instant) -> String {
    let elapsed = t.elapsed();
    let secs = elapsed.as_secs();
    if secs >= 86_400 {
        let d = secs / 86_400;
        let h = (secs % 86_400) / 3600;
        format!("{d}d {h}h")
    } else if secs >= 3600 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{h}h {m}m")
    } else if secs >= 60 {
        let m = secs / 60;
        let s = secs % 60;
        format!("{m}m {s}s")
    } else if secs >= 1 {
        format!("{secs}s")
    } else {
        // Sub-second: show one decimal so the overlay's "last packet" reading
        // visibly ticks instead of sitting on "0s" for a whole second.
        let ms = elapsed.subsec_millis();
        format!("0.{:01}s", ms / 100)
    }
}

/// Wall-clock representation of an `Instant`, in the form `HH:MM:SS`. We
/// compute this by anchoring the running app's `Instant::now()` to
/// `SystemTime::now()` once per call — `Instant` itself has no wall-clock
/// notion, but the difference between two `Instant`s is meaningful, so we
/// pretend a single `SystemTime` read is "now" and shift relative to it.
pub fn format_clock(t: std::time::Instant) -> String {
    let now_inst = std::time::Instant::now();
    let now_sys = std::time::SystemTime::now();
    // How far in the past `t` is.
    let back = now_inst.saturating_duration_since(t);
    let absolute = now_sys
        .checked_sub(back)
        .unwrap_or(std::time::UNIX_EPOCH);
    let secs = absolute
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Convert to local-ish wall-clock — we deliberately use UTC arithmetic
    // and trust the user reading the overlay to mentally apply their offset,
    // since pulling in a tz crate just for one row isn't worth it.
    let (h, m, s) = (
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60,
    );
    format!("{h:02}:{m:02}:{s:02}")
}
