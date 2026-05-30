//! Cross-`core` helpers shared by the flows, processes, and capture
//! submodules. Anything here must be submodule-agnostic — types or
//! functions belonging to a single submodule should live there instead.

use std::thread::{Builder, JoinHandle};

/// IP protocol numbers as they appear in the IP header (and in `FlowKey.proto`).
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Spawn an OS thread with a `"vortex-"`-prefixed name. Panics on failure
/// with a message that names the thread, matching the previous inline
/// `expect(..)` calls at each call site.
pub fn spawn_named<F, T>(name: &str, f: F) -> JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    Builder::new()
        .name(format!("vortex-{name}"))
        .spawn(f)
        .unwrap_or_else(|e| panic!("failed to spawn vortex-{name} thread: {e}"))
}
