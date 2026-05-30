use std::collections::HashSet;
use std::net::IpAddr;
use std::thread::JoinHandle;
use std::time::Duration;

use crossbeam_channel::{Sender, TrySendError};
use netstat2::{
    AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo, get_sockets_info,
};
use rustc_hash::FxHashMap;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

use crate::core::common::{IPPROTO_TCP, IPPROTO_UDP, spawn_named};
use crate::core::processes::components::ProcessInfo;

/// One full poll's worth of OS-level state. Built on the snapshot thread and
/// shipped to the ECS world for `enrich_flows` to consume.
#[derive(Debug, Default)]
pub struct ProcessSnapshot {
    /// `(local_ip, local_port, proto)` → owning PID. We index by local endpoint
    /// because that's what the kernel actually knows; the flow's "local" side
    /// might be src *or* dst depending on direction, so the enrich step probes
    /// both.
    pub sockets: FxHashMap<(IpAddr, u16, u8), u32>,
    /// PID → process metadata for every PID referenced in `sockets`. Old PIDs
    /// drop out naturally because we only insert ones that own a current
    /// socket.
    pub processes: FxHashMap<u32, ProcessInfo>,
}

/// Spawn the snapshot worker. The handle is held by `ProcessesPlugin` for the
/// process lifetime; the thread observes a disconnected sender to exit.
pub fn spawn(tx: Sender<ProcessSnapshot>, poll_interval: Duration) -> JoinHandle<()> {
    spawn_named("process-snapshot", move || run(tx, poll_interval))
}

fn run(tx: Sender<ProcessSnapshot>, poll_interval: Duration) {
    // Reuse `System` + `Users` across iterations so sysinfo can do incremental
    // refreshes — much cheaper than `new_all()` every second.
    let mut system = System::new();
    let mut users = Users::new_with_refreshed_list();
    // Refresh only the cheap, stable bits: name/exe/cmdline/user/parent. Skip
    // CPU/memory/disk which we never display.
    let refresh = ProcessRefreshKind::nothing()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet)
        .with_user(UpdateKind::OnlyIfNotSet);

    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;

    loop {
        let snapshot = match build_snapshot(af, proto, &mut system, &mut users, refresh) {
            Ok(s) => s,
            Err(e) => {
                // Log once per failure but keep looping — sock_diag can fail
                // transiently (permission, namespace, kernel mismatch). The
                // UI degrades to "no attribution" until it recovers.
                tracing::warn!("process snapshot failed: {e}");
                ProcessSnapshot::default()
            }
        };

        match tx.try_send(snapshot) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // ECS hasn't drained the previous snapshot yet. Drop this one
                // — the next pass will produce a fresher view anyway.
            }
            Err(TrySendError::Disconnected(_)) => return,
        }

        std::thread::sleep(poll_interval);
    }
}

fn build_snapshot(
    af: AddressFamilyFlags,
    proto: ProtocolFlags,
    system: &mut System,
    users: &mut Users,
    refresh: ProcessRefreshKind,
) -> Result<ProcessSnapshot, netstat2::error::Error> {
    let raw = get_sockets_info(af, proto)?;

    let mut sockets: FxHashMap<(IpAddr, u16, u8), u32> = FxHashMap::default();
    let mut pids: HashSet<u32> = HashSet::new();

    for si in &raw {
        let Some(pid) = pick_pid(si) else { continue };
        let (local_ip, local_port, p) = local_endpoint(si);
        // First writer wins. netstat2 occasionally lists multiple PIDs for the
        // same socket on Linux (forks, fd inheritance); the order is stable
        // enough that locking in the first lookup gives consistent UI.
        sockets.entry((local_ip, local_port, p)).or_insert(pid);
        pids.insert(pid);
    }

    // Refresh only the PIDs we care about — both faster and avoids dragging
    // every kernel thread into the table.
    let pid_vec: Vec<Pid> = pids.iter().map(|p| Pid::from(*p as usize)).collect();
    system.refresh_processes_specifics(ProcessesToUpdate::Some(&pid_vec), false, refresh);

    // Refresh the user list lazily; it's only used to map UID → username and
    // changes rarely. Skipping the refresh when the cache is non-empty keeps
    // the steady-state cost negligible.
    if users.list().is_empty() {
        users.refresh();
    }

    let mut processes: FxHashMap<u32, ProcessInfo> = FxHashMap::default();
    for pid_raw in &pids {
        let pid = Pid::from(*pid_raw as usize);
        let Some(proc) = system.process(pid) else { continue };
        let name = proc.name().to_string_lossy().into_owned();
        let exe = proc.exe().map(|p| p.to_path_buf());
        let cmdline = proc
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        let user = proc
            .user_id()
            .and_then(|uid| users.get_user_by_id(uid))
            .map(|u| u.name().to_string());
        let ppid = proc.parent().map(|p| p.as_u32());

        processes.insert(
            *pid_raw,
            ProcessInfo {
                pid: *pid_raw,
                name,
                exe,
                cmdline,
                user,
                ppid,
                alive: true,
            },
        );
    }

    Ok(ProcessSnapshot { sockets, processes })
}

/// Some sockets (e.g. orphaned TIME_WAIT entries on Linux) have an empty PID
/// list; skip those rather than fabricating an owner.
fn pick_pid(si: &SocketInfo) -> Option<u32> {
    si.associated_pids.first().copied()
}

fn local_endpoint(si: &SocketInfo) -> (IpAddr, u16, u8) {
    match &si.protocol_socket_info {
        ProtocolSocketInfo::Tcp(t) => (t.local_addr, t.local_port, IPPROTO_TCP),
        ProtocolSocketInfo::Udp(u) => (u.local_addr, u.local_port, IPPROTO_UDP),
    }
}
