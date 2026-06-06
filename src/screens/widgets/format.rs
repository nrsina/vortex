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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    // --- format_bps ---

    #[test]
    fn format_bps_bytes_range() {
        assert_eq!(format_bps(0.0), "0 B/s");
        assert_eq!(format_bps(999.0), "999 B/s");
    }

    #[test]
    fn format_bps_rolls_over_to_kb_at_1000() {
        assert_eq!(format_bps(1_000.0), "1.0 KB/s");
    }

    #[test]
    fn format_bps_sub_mb_stays_in_kb() {
        assert!(format_bps(999_999.0).ends_with("KB/s"), "expected KB/s below 1 MB/s");
    }

    #[test]
    fn format_bps_rolls_over_to_mb_at_1000000() {
        assert_eq!(format_bps(1_000_000.0), "1.00 MB/s");
    }

    // --- format_count ---

    #[test]
    fn format_count_small_values_exact() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
    }

    #[test]
    fn format_count_rolls_over_to_k_at_1000() {
        assert_eq!(format_count(1_000), "1.0k");
    }

    #[test]
    fn format_count_rolls_over_to_m_at_1000000() {
        assert_eq!(format_count(1_000_000), "1.0M");
    }

    // --- format_bytes ---

    #[test]
    fn format_bytes_raw_bytes_range() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn format_bytes_rolls_over_to_kb_at_1kib() {
        assert_eq!(format_bytes(1 << 10), "1.00 KB");
    }

    #[test]
    fn format_bytes_just_under_mib_stays_in_kb() {
        let s = format_bytes((1 << 20) - 1);
        assert!(s.ends_with("KB"), "expected KB for {}, got {s}", (1u64 << 20) - 1);
    }

    #[test]
    fn format_bytes_rolls_over_to_mb_at_1mib() {
        assert_eq!(format_bytes(1 << 20), "1.00 MB");
    }

    #[test]
    fn format_bytes_rolls_over_to_gb_at_1gib() {
        assert_eq!(format_bytes(1 << 30), "1.00 GB");
    }

    // --- format_duration_since ---

    #[test]
    fn format_duration_sub_second() {
        // elapsed < 1s → "0.Xs" branch
        let t = Instant::now();
        let s = format_duration_since(t);
        assert!(s.starts_with("0.") && s.ends_with('s'), "expected 0.Xs, got {s:?}");
    }

    #[test]
    fn format_duration_whole_seconds() {
        let t = Instant::now() - Duration::from_secs(2);
        assert_eq!(format_duration_since(t), "2s");
    }

    #[test]
    fn format_duration_minutes_and_seconds() {
        let t = Instant::now() - Duration::from_secs(90);
        assert_eq!(format_duration_since(t), "1m 30s");
    }

    #[test]
    fn format_duration_hours_and_minutes() {
        let t = Instant::now() - Duration::from_secs(3661);
        assert_eq!(format_duration_since(t), "1h 1m");
    }

    #[test]
    fn format_duration_days_and_hours() {
        let t = Instant::now() - Duration::from_secs(86_400 + 3_600);
        assert_eq!(format_duration_since(t), "1d 1h");
    }

    // --- format_clock ---

    #[test]
    fn format_clock_hh_mm_ss_structure() {
        // Output must be exactly "HH:MM:SS" — 8 chars with colons at [2] and [5].
        let s = format_clock(Instant::now());
        assert_eq!(s.len(), 8, "expected 8-char HH:MM:SS, got {s:?}");
        assert_eq!(s.as_bytes()[2], b':', "colon expected at position 2");
        assert_eq!(s.as_bytes()[5], b':', "colon expected at position 5");
        for (i, b) in s.bytes().enumerate() {
            if i != 2 && i != 5 {
                assert!(b.is_ascii_digit(), "expected digit at pos {i} in {s:?}");
            }
        }
    }
}
