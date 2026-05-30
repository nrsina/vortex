# Vortex

**Vortex** is a terminal-based, real-time network monitor and traffic analyzer.
It captures packets straight off your network interfaces, decodes them, tracks
live connections, attributes traffic to the processes responsible, and renders
everything in a fast, keyboard-driven dashboard — a focused blend of `iftop`,
`nethogs`, and a lightweight packet inspector, all inside your terminal.

The interface is a **TUI** (terminal user interface) built with
[Ratatui](https://ratatui.rs), following a minimal, monochrome design with a
single blue accent and semantic status colours.

## Video Showcase

![Vortex showcase](https://github.com/user-attachments/assets/a4185b8d-b86b-4503-9bf2-1e7b727b9409)

## Features

- **Interface picker** that lists every device, with addresses, link status, and
  a live per-interface packet-rate trend sparkline.
- **BPF filter support** — type expressions like `tcp port 443` or
  `host 1.1.1.1 and not arp` before opening an interface.
- **Live flow dashboard** — a sortable table of connections with real-time
  throughput, packet counts, and traffic history.
- **Connection view** that pairs the two directions of a conversation and splits
  transmit/receive bandwidth.
- **Process attribution** — every flow is mapped to the owning OS process, with a
  dedicated tree view that aggregates bandwidth, connections, user, and command
  line per process.
- **Reverse-DNS resolution** of remote addresses, resolved in the background.
- **Deep packet inspection** for app-layer hostnames (TLS SNI, DNS query names).
- **Connection lifecycle tracking** with automatic expiry of idle flows.
- **A details overlay** for any flow or connection, with per-flow sparklines and
  service/endpoint classification.
- **Fully keyboard-driven** navigation — no mouse required.
- Cross-platform: **Linux, macOS, and Windows**.

## Why ECS (Bevy ECS)?

Under the hood, Vortex is built on an **ECS (Entity-Component-System)**
architecture using [Bevy ECS](https://bevyengine.org) — just the standalone ECS
crates, not the full game engine (no graphics, windowing, or rendering pulled
in).

Most network tools grow into a tangle of shared structs guarded by mutexes.
Vortex takes a different path: every observable thing — a connection, an
interface, a process attribution, a DNS record — is an **entity** made of small,
composable **components**, and all behaviour lives in independent **systems** that
run each tick. The win:

- **A uniform data model.** Everything is just an entity with components, so
  there's no rigid type hierarchy to fight as the tool grows.
- **Composable behaviour.** Capture, aggregation, expiry, enrichment, and
  rendering are separate systems that touch only the data they care about. Adding
  a feature (say, GeoIP) means a new component and a new system — not a rewrite.
- **Speed.** Components live in dense arrays, and the scheduler runs disjoint
  systems in parallel, so scanning thousands of live flows every frame stays
  fast and predictable.
- **A clear data flow.** Each frame is a simple pipeline — ingest → aggregate →
  expire → enrich → render — with state held in components rather than tangled
  shared structures. Background threads (capture, DNS, process snapshots) feed
  the ECS world over lock-free channels, so the UI loop never blocks.

The result is a network monitor that's fast, easy to reason about, and simple to
extend.

## Usage

1. Install [Rust](https://www.rust-lang.org/tools/install) on your system.

   On Linux/macOS the easiest way is [rustup](https://rustup.rs):

   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

   On Windows, download and run the installer from
   [rustup.rs](https://rustup.rs).

2. Clone the repository and go to the root directory. Make sure the
   `Settings.toml` file is present.

3. Configure the application through the `Settings.toml` file (tick rate, capture
   options, DNS, process attribution, etc.).

4. Build the project with `cargo build --release`. The binary will be at
   `target/release/vortex`.

   **Windows only:** before building, install the
   [Npcap SDK](https://npcap.com/#download) and set the `LIB` environment
   variable to its `Lib\x64` directory (e.g.
   `set LIB=C:\npcap-sdk\Lib\x64`). The SDK provides the headers and import
   libraries that the packet-capture crate links against at compile time.

5. Run it. Because Vortex captures raw packets, it needs elevated privileges:

   - **Linux / macOS** — run with `sudo`:

     ```bash
     sudo ./target/release/vortex
     ```

   - **Windows** — first install [Npcap](https://npcap.com) (the packet-capture
     library Vortex relies on), then run the executable from an **Administrator**
     terminal.

## Version

**0.1** — initial release.
