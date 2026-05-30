use std::path::PathBuf;

use bevy_ecs::prelude::Component;

/// Snapshot of a process's identifying metadata at the moment the last socket
/// snapshot was taken. Lives in the `ProcessTable` resource keyed by PID — one
/// copy per process, not one per flow, so wide cmdlines don't bloat the ECS.
#[derive(Clone, Debug)]
#[allow(dead_code)] // `pid` mirrors the map key; `ppid` reserved for future tree view
pub struct ProcessInfo {
    pub pid: u32,
    /// Short comm-style name (`chrome`, `curl`). On Linux capped at 15 chars by
    /// the kernel; on macOS / Windows it's the full image name.
    pub name: String,
    pub exe: Option<PathBuf>,
    pub cmdline: Vec<String>,
    /// Resolved username; `None` when the UID isn't known to `Users` (e.g. on
    /// platforms where sysinfo doesn't expose it, or the user was deleted).
    pub user: Option<String>,
    pub ppid: Option<u32>,
    /// `true` if the process appeared in the most recent snapshot. Dead-but-
    /// still-referenced entries linger in the table until the last attributed
    /// flow goes away, so the UI can keep showing the original name (instead
    /// of `?`) and flag the process as gone.
    pub alive: bool,
}

/// Authoritative process attribution for a flow entity. Attached by
/// `enrich_flows` once a snapshot returns a matching socket. We deliberately
/// keep the rich `ProcessInfo` out of the component (it lives in
/// `ProcessTable`) so flow entities stay small and copyable.
#[derive(Component, Clone, Copy, Debug)]
pub struct FlowProcess {
    pub pid: u32,
}
