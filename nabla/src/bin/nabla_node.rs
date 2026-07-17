// AXIOM Nabla Node — Production Binary
//
// Standalone executable that participates in the Nabla network:
//   - Boots from bootstrap.toml (operator-configured contact points)
//   - Joins gossip mesh (mesh.rs protocol)
//   - Joins TARDIS tree (tardis.rs protocol)
//   - Processes registrations and queries
//   - Integrates with Core for cryptographic operations via crypto::Signer
//
// This binary imports the axiom-nabla library for ALL protocol logic.
// No protocol decisions are made here — only network I/O orchestration.
//
// Usage:
//   nabla-node                                        # TCP on [::]:1211
//   nabla-node --mode tcp --bind [::]:1211            # explicit TCP
//   nabla-node --mode stdio                           # stdin/stdout (dev)
//   nabla-node --port 6225                            # custom port
//   nabla-node --data /var/nabla                      # custom data dir
//   nabla-node --config /var/nabla/node.toml          # explicit config file
//   nabla-node --avm-elf ~/.axiom/zkvm/axiom-core.elf  # AVM ELF path
//   nabla-node --bootstrap peers.toml                  # custom seed list
//
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  ARCHITECTURAL RULE: Nabla NEVER does cryptography.                ║
// ║  NBC = VBC from Core (YPX-002: "same VBC function, role = nabla") ║
// ║  Core.execute() handles generation, signing, verification.        ║
// ║  Nabla stores the VBC blob. That's it.                            ║
// ╚══════════════════════════════════════════════════════════════════════╝
//
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  NBC_NETWORK_JOIN — Identity Verification on Connect (IMPLEMENTED)  ║
// ║                                                                    ║
// ║  NBC = VBC. Same struct, same Core verification path.             ║
// ║  All crypto goes through Core.execute(PublicInputs → Outputs).    ║
// ║                                                                    ║
// ║  GENESIS NODES:                                                    ║
// ║    - Core creates self-signed VBC at genesis (same PK as VBC)     ║
// ║    - Hardcoded in binary, loaded at boot                          ║
// ║    - Accepted unconditionally by other genesis nodes              ║
// ║                                                                    ║
// ║  NEW NODES (first join):                                          ║
// ║    1. Core generates keypairs and VBC struct                      ║
// ║    2. Connect to any existing Nabla node                          ║
// ║    3. Request NBC issuance → peer's Core signs VBC                ║
// ║    4. Store VBC to disk                                           ║
// ║    5. Now permitted to join TARDIS tree                           ║
// ║                                                                    ║
// ║  RETURNING NODES:                                                  ║
// ║    1. Load VBC from disk                                          ║
// ║    2. Present VBC on connect                                      ║
// ║    3. Peer sends VBC to Core.execute() → Accept/Reject            ║
// ║    4. If rejected (expired/invalid/missing): REJECT connection    ║
// ║                                                                    ║
// ║  No state, no fee. Core handles all crypto.                       ║
// ╚══════════════════════════════════════════════════════════════════════╝

#![allow(unused_imports, unused_variables)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{SocketAddr, TcpListener};

use axiom_nabla::ban::BanTable;
use axiom_nabla::cc::{self, CcChain, NBC, NbcSubject, PeerTrust, nbc_node_id, verify_nbc, verify_nbc_chain, verify_nbc_chain_via_core, nbc_ed25519_pk, verify_nbc_via_core, serialize_nbc, deserialize_nbc, is_qualified_issuer, issue_nbc, issue_nbc_via_core, generate_node_keys, renew_nbc, renew_nbc_via_core};
use axiom_nabla::config::NablaConfig;
use axiom_nabla::constants::*;
use axiom_nabla::crypto::{self, Ed25519Signer, Signer};
use axiom_nabla::gossip::{GossipAction, GossipEngine};
use axiom_nabla::mesh::{GossipMesh, MeshAction};
use axiom_nabla::monitor::{self, MonitorConfig, NodeStatusSnapshot};
use axiom_nabla::node::NablaNode;
use axiom_nabla::oracle::DailyPoolState;
use axiom_nabla::smt::SparseMerkleTree;
use axiom_nabla::tardis::TardisNode;
use axiom_nabla::transport::{
    self, Envelope, StdioTransport, TcpTransport, Transport, WireMessage,
    from_socket_addr, to_socket_addr,
};
use axiom_nabla::types::*;
use log::{debug, error, info, warn};

// ── Transport Mode ──

#[derive(Debug, Clone, Copy, PartialEq)]
enum TransportMode {
    Tcp,
    Stdio,
}

/// How many virtual ticks to wait for a TardisAttachResponse before
/// considering the request timed out and allowing a retry to the same peer.
const ATTACH_TIMEOUT_TICKS: u64 = 3;

/// Phase 3a-B HTTP→TCP migration gate (CLAUDE.md §8).
///
/// When `true`, the functional wallet/operator endpoints are disabled
/// over HTTP and return `410 Gone`.  Every native client (SDK, Lambda,
/// Python tooling) speaks the TCP-CBOR `WireMessage` wire for these ops;
/// HTTP serves only the dashboard / monitor routes (HTML/JSON
/// observability).
///
/// `/query-txid` was added to the gate by Phase 3b. Phase 3c
/// (2026-05-18) added the last six functional endpoints —
/// `/pulse-proof`, `/jfp-secret`, `/jfp-secrets`, `/bridge`,
/// `/endorse-ban-challenge`, `/challenge-ban` — each now has a
/// `WireMessage` request/response variant and a TCP dispatch arm in
/// `handle_message`.
///
/// The WASM/browser path (`NablaQueryTxidMachine`, webclient) still
/// expects HTTP for the wallet endpoints and is knowingly broken by this
/// gate — that browser migration is deferred (browsers cannot open raw
/// TCP).
///
/// The handler functions stay in the binary (still referenced by the TCP
/// `WireMessage` arms and, for the browser, future re-enablement) — flip
/// this one `const` to `false` to restore the HTTP endpoints.
const FUNCTIONAL_HTTP_GATED: bool = true;

/// Paths disabled over HTTP when `FUNCTIONAL_HTTP_GATED` is `true`.
/// Deliberately excludes the dashboard / monitor observability routes.
const HTTP_GATED_PATHS: &[&str] = &[
    "/register",
    "/clara",
    "/query",
    "/register-cheque-claim",
    "/query-cheque-claim",
    "/query-txid",
    // Phase 3c — last six functional endpoints, now TCP-CBOR.
    "/pulse-proof",
    "/jfp-secret",
    "/jfp-secrets",
    "/bridge",
    "/endorse-ban-challenge",
    "/challenge-ban",
];

/// Virtual seconds of silence from a child before considering it "slow".
/// Must be long enough to tolerate relay latency in binary sim.
/// 60 virtual seconds = 12 TARDIS ticks = 0.6s real at 20x.
const SLOW_CHILD_SECS: u64 = 60;

/// KI#37 — outbound-storm shed ceiling: max forward/broadcast sends a
/// single node emits per 1-second window before the circuit breaker
/// (`StormBreaker`) starts dropping further forward traffic. Sized well
/// above any legitimate mesh rate and far below a storm: legitimate
/// steady-state forward fan-out on a healthy mesh is tens/sec (gossip +
/// AE probe + pool heartbeat × peer count), bursting to low hundreds
/// during mesh churn; the KI#37 alert loop measured ~9,200/sec into a
/// single node. 1,000/sec trips clearly on a storm and never on
/// legitimate load. Tick/Approval and direct client replies are exempt,
/// so tripping never breaks consensus or query liveness — a tripped
/// breaker just refuses to AMPLIFY. Tune upward for very large meshes
/// (per-node fan-out scales with peer count).
const STORM_SHED_CEILING: u32 = 1000;

/// Global shutdown flag for graceful termination.
static SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// ============================================================================
// HTTP wire format — CBOR.
//
// Nabla HTTP endpoints speak CBOR-over-HTTP for body payload (request and
// response).  This matches what the TCP path has always done, so a single
// set of typed wire structs (`axiom_nabla::wire_client::*` and the shared
// `axiom_core_logic::types::*`) carries the contract across both transports
// — see CLAUDE.md §8 "Nabla and validator use the same UMP".
//
// Operator dashboard endpoints (HTML/JSON for browsers, served by
// `monitor::route_request`) keep their JSON bodies — they're observability,
// not protocol wire.
//
// Phase 2c structured errors travel as a single CBOR map
//   { "error_response": axiom_errors::ErrorResponse }
// — the same outer shape JSON used, just CBOR-encoded.
// ============================================================================

/// CBOR error body wrapper.  Lives only on the wire; serde Field name
/// `error_response` matches the prior JSON shape so the SDK error-mapping
/// code keeps working across the transport flip.
#[derive(serde::Serialize)]
struct HttpErrorBody<'a> {
    error_response: &'a axiom_errors::ErrorResponse,
}

/// Build an HTTP CBOR error body carrying the structured
/// `error_response` object as the single source of truth.
fn http_error_cbor(
    status: u16,
    code: &'static str,
    category: axiom_errors::ErrorCategory,
    message: &str,
) -> (u16, Vec<u8>) {
    let resp = axiom_errors::ErrorResponse::new(
        axiom_errors::ErrorCode::from_static(code),
        category,
        message.to_string(),
    );
    let mut buf = Vec::new();
    ciborium::into_writer(&HttpErrorBody { error_response: &resp }, &mut buf)
        .expect("CBOR encode of ErrorResponse never fails");
    (status, buf)
}

/// Serialize any `Serialize` value into a CBOR Vec<u8>.  Panics only if
/// the type's `Serialize` impl is broken, which would itself be a bug —
/// no I/O is involved.
fn cbor_body<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .expect("CBOR encode of typed wire value never fails");
    buf
}

/// Send a message with retry for critical messages.
/// Critical messages (Tick, Approval, Attach*, Detach) get 3 attempts with
/// exponential backoff (200ms, 400ms). Non-critical: single attempt.
fn send_with_retry(
    transport: &dyn Transport,
    addr: std::net::SocketAddr,
    msg: &WireMessage,
    max_retries: u8,
) -> bool {
    for attempt in 0..=max_retries {
        match transport.send(addr, msg) {
            Ok(()) => return true,
            Err(e) => {
                if attempt < max_retries {
                    let delay = Duration::from_millis(200 * (1 << attempt));
                    std::thread::sleep(delay);
                } else {
                    warn!("Send failed after {} attempts to {}: {}",
                        max_retries + 1, addr, e);
                }
            }
        }
    }
    false
}

/// KI#37 — consult the outbound-storm circuit breaker for ONE
/// forward/broadcast send. Locks the node briefly (increment + compare),
/// logs the trip/recover edges, and returns `true` to SEND / `false` to
/// DROP. Only forward/broadcast messages are routed here — critical
/// Tick/Approval/Attach/Detach and direct inbound replies bypass it, so
/// a tripped breaker never starves consensus or a client's answer, it
/// only refuses to AMPLIFY into the mesh.
fn storm_admit_forward(state: &Arc<Mutex<NablaNodeState>>) -> bool {
    let mut node = state.lock().unwrap();
    let d = node.storm.admit_forward();
    if d.just_tripped {
        warn!("[STORM-SHED] forward/broadcast rate exceeded {}/s — shedding non-critical \
               outbound (KI#37 backstop; Tick/Approval/replies still flow)", STORM_SHED_CEILING);
    } else if d.just_recovered {
        info!("[STORM-SHED] forward/broadcast rate back under {}/s — resuming full outbound",
            STORM_SHED_CEILING);
    }
    d.admit
}

/// Returns true for messages that warrant retry on send failure.
fn is_critical_message(msg: &WireMessage) -> bool {
    matches!(msg,
        WireMessage::Tick(_) |
        WireMessage::Approval(_) |
        WireMessage::TardisAttachRequest { .. } |
        WireMessage::TardisAttachResponse { .. } |
        WireMessage::TardisDetach { .. }
    )
}

// ── CLI Arguments ──

struct Args {
    mode: TransportMode,
    data_dir: PathBuf,
    port: u16,
    bind: String,
    /// Routable address to advertise to peers (host[:port], DNS ok).
    /// Peers dial back whatever we advertise, so a wildcard bind
    /// (0.0.0.0 / [::]) must never leak into the mesh — see the
    /// resolution logic at the `from_socket_addr` call in main().
    advertise: Option<String>,
    bootstrap_file: PathBuf,
    /// Path to axiom-core.elf for AVM interpreter (CL7/CL8 NBC verification).
    avm_elf_path: Option<PathBuf>,
    /// Dev mode: skip mandatory Core IPC verification.
    dev_mode: bool,
    /// Skip NBC/VBC verification at startup and for peers.
    /// --dev implies --skip-verify. Also implied by sim mode (epoch_ms > 0).
    skip_verify: bool,
    log_level: String,
    tick_ms: u64,
    /// Shared wall-clock start time (unix ms). All sim nodes measure elapsed
    /// time from this moment so their virtual clocks stay synchronized.
    /// 0 = production mode (use real time, no scaling).
    epoch_ms: u64,
    /// Explicit path to node.toml config file (default: <data_dir>/node.toml).
    config_file: Option<PathBuf>,
    /// Dashboard HTTP port (CLI override; None = use node.toml or default 6226).
    dashboard_port: Option<u16>,
    /// Bind dashboard to 0.0.0.0 for remote access (CLI flag only).
    dashboard_remote: bool,
    /// One-shot human bridge: connect to a remote peer for partition recovery (§6.6).
    bridge_peer: Option<String>,
    /// Request NBC from a peer and exit (standalone NBC acquisition).
    request_nbc: bool,
    /// Reader-only mode: never accept registrations, always redirect.
    /// Recommended for validator-paired Nabla nodes (§25.5.4).
    reader_only: bool,
    /// YPX-014: Txid service mode. "bloom" (default, ~18MB) or "hashmap" (5x CC, more RAM).
    txid_mode: axiom_nabla::bloom::TxidServiceMode,
    /// **DEV-MODE ATTACK INJECTOR** — Layer 4 Quarantine verification. When set,
    /// this Nabla emits one forged `PoolSync` shortly after mesh init with
    /// `balance = INITIAL_BALANCE + GENESIS_CLAIM_AMOUNT` (clearly violating
    /// the monotonic-decrease invariant). The forged broadcast goes to all
    /// mesh peers and should trigger their Layer 4 detection:
    ///   1. Each receiver runs reconcile → ReconcileOutcome::InvariantViolation
    ///   2. Each receiver emits GossipMessage::Alert accusing this Nabla
    ///   3. After ≥3 distinct origins+intermediates within 10 ticks, honest
    ///      Nablas activate a 50-tick quarantine of this Nabla
    ///
    /// Dev-mode only. Production builds without `--features dev-mode` will
    /// reject this flag.
    inject_fake_poolsync: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            mode: TransportMode::Tcp,
            data_dir: PathBuf::from("nabla-data"),
            port: 1211,
            bind: "[::]".to_string(),
            advertise: None,
            bootstrap_file: PathBuf::from("bootstrap.toml"),
            avm_elf_path: None,
            dev_mode: false,
            skip_verify: false,
            log_level: "info".to_string(),
            tick_ms: TICK_INTERVAL_SECS * 1000,
            epoch_ms: 0,
            config_file: None,
            dashboard_port: None,
            dashboard_remote: false,
            bridge_peer: None,
            request_nbc: false,
            reader_only: false,
            txid_mode: axiom_nabla::bloom::TxidServiceMode::Bloom,
            inject_fake_poolsync: false,
        }
    }
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut parsed = Args::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" | "-m" => {
                i += 1;
                if i < args.len() {
                    match args[i].as_str() {
                        "tcp" => parsed.mode = TransportMode::Tcp,
                        "stdio" => parsed.mode = TransportMode::Stdio,
                        other => {
                            eprintln!("Unknown mode: {} (expected 'tcp' or 'stdio')", other);
                            std::process::exit(1);
                        }
                    }
                }
            }
            "--port" | "-p" => {
                i += 1;
                if i < args.len() {
                    parsed.port = args[i].parse().unwrap_or(1211);
                }
            }
            "--bind" | "-b" => {
                i += 1;
                if i < args.len() {
                    parsed.bind = args[i].clone();
                }
            }
            "--advertise" => {
                i += 1;
                if i < args.len() {
                    parsed.advertise = Some(args[i].clone());
                }
            }
            "--data" | "-d" => {
                i += 1;
                if i < args.len() {
                    parsed.data_dir = PathBuf::from(&args[i]);
                }
            }
            "--bootstrap" | "-w" => {
                i += 1;
                if i < args.len() {
                    parsed.bootstrap_file = PathBuf::from(&args[i]);
                }
            }
            "--avm-elf" => {
                i += 1;
                if i < args.len() {
                    parsed.avm_elf_path = Some(PathBuf::from(&args[i]));
                }
            }
            // Deprecated aliases — map to --avm-elf
            "--core-bin" | "--core-ipc" => {
                i += 1;
                if i < args.len() {
                    warn!("{} is deprecated, use --avm-elf instead", args[i-1]);
                    parsed.avm_elf_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--dev" => {
                #[cfg(not(any(debug_assertions, feature = "dev-mode")))]
                {
                    eprintln!("FATAL: --dev is disabled in release builds.");
                    eprintln!("Build with --features dev-mode to use --dev in release.");
                    std::process::exit(1);
                }
                #[cfg(any(debug_assertions, feature = "dev-mode"))]
                {
                    parsed.dev_mode = true;
                    parsed.skip_verify = true; // --dev implies --skip-verify
                }
            }
            "--skip-verify" => {
                #[cfg(not(debug_assertions))]
                {
                    eprintln!("FATAL: --skip-verify is disabled in release builds.");
                    eprintln!("Build with `cargo build` (debug) to use --skip-verify.");
                    std::process::exit(1);
                }
                #[cfg(debug_assertions)]
                {
                    parsed.skip_verify = true;
                }
            }
            "--log" | "-l" => {
                i += 1;
                if i < args.len() {
                    parsed.log_level = args[i].clone();
                }
            }
            "--tick-ms" => {
                i += 1;
                if i < args.len() {
                    parsed.tick_ms = args[i].parse().unwrap_or(TICK_INTERVAL_SECS * 1000);
                }
            }
            "--epoch-ms" => {
                i += 1;
                if i < args.len() {
                    parsed.epoch_ms = args[i].parse().unwrap_or(0);
                }
            }
            "--config" | "-c" => {
                i += 1;
                if i < args.len() {
                    parsed.config_file = Some(PathBuf::from(&args[i]));
                }
            }
            "--dashboard-port" => {
                i += 1;
                if i < args.len() {
                    parsed.dashboard_port = Some(args[i].parse().unwrap_or(monitor::DEFAULT_MONITOR_PORT));
                }
            }
            "--dashboard-remote" => {
                parsed.dashboard_remote = true;
            }
            "--bridge-peer" => {
                i += 1;
                if i < args.len() {
                    parsed.bridge_peer = Some(args[i].clone());
                }
            }
            "--request-nbc" => {
                parsed.request_nbc = true;
            }
            "--reader-only" => {
                parsed.reader_only = true;
            }
            "--txid-mode" => {
                i += 1;
                if i >= args.len() { eprintln!("--txid-mode requires value"); std::process::exit(1); }
                parsed.txid_mode = match args[i].as_str() {
                    "bloom" => axiom_nabla::bloom::TxidServiceMode::Bloom,
                    "hashmap" => axiom_nabla::bloom::TxidServiceMode::Hashmap,
                    other => { eprintln!("Invalid --txid-mode '{}' (use bloom or hashmap)", other); std::process::exit(1); }
                };
            }
            "--inject-fake-poolsync" => {
                #[cfg(not(any(debug_assertions, feature = "dev-mode")))]
                {
                    eprintln!("FATAL: --inject-fake-poolsync is disabled in release builds.");
                    eprintln!("Build with --features dev-mode to use this flag.");
                    std::process::exit(1);
                }
                #[cfg(any(debug_assertions, feature = "dev-mode"))]
                {
                    parsed.inject_fake_poolsync = true;
                }
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                eprintln!("Run with --help for usage.");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    parsed
}

fn print_help() {
    eprintln!("AXIOM Nabla Node v{}", env!("CARGO_PKG_VERSION"));
    eprintln!();
    eprintln!("Usage: nabla-node [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --mode, -m <MODE>          Transport: tcp (default) or stdio");
    eprintln!("  --port, -p <PORT>          Listen port (default: 1211)");
    eprintln!("  --bind, -b <ADDR>          Bind address (default: [::] dual-stack)");
    eprintln!("  --advertise <HOST[:PORT]>  Routable address advertised to peers (DNS ok; port defaults to --port).");
    eprintln!("                             Without it, a wildcard --bind derives the egress interface IP from the");
    eprintln!("                             first bootstrap peer's route.");
    eprintln!("  --data, -d <DIR>           Data directory (default: nabla-data)");
    eprintln!("  --config, -c <FILE>        Node config file (default: <data>/node.toml)");
    eprintln!("  --bootstrap, -w <FILE>     Bootstrap peers file (TOML)");
    eprintln!("  --avm-elf <PATH>           Path to axiom-core.elf for NBC verification");
    eprintln!("  --dev                      Dev mode: skip mandatory Core IPC check (implies --skip-verify)");
    eprintln!("  --skip-verify              Skip NBC/VBC verification at startup and for peers");
    eprintln!("  --dashboard-port <PORT>    Dashboard HTTP port (default: 6226)");
    eprintln!("  --dashboard-remote         Bind dashboard to 0.0.0.0 (remote access)");
    eprintln!("  --bridge-peer <ADDR>       Connect to peer for partition recovery (e.g. 1.2.3.4:1211)");
    eprintln!("  --request-nbc              Request NBC from peers, save to config/nbc.json, and exit");
    eprintln!("  --reader-only              Reader-only mode: never accept registrations (§25.5.4)");
    eprintln!("  --txid-mode <MODE>         Txid service: bloom (default, ~18MB) or hashmap (5x CC, more RAM)");
    eprintln!("  --inject-fake-poolsync     DEV-MODE Layer 4 attack injector: broadcast forged PoolSync at boot+15s");
    eprintln!("  --log, -l <LEVEL>          Log level (default: info)");
    eprintln!("  --help, -h                 Show this help");
    eprintln!();
    eprintln!("Transport modes:");
    eprintln!("  tcp    Dual-stack IPv4+IPv6. Binds [::]:1211 by default.");
    eprintln!("         Accepts both IPv4 and IPv6 connections.");
    eprintln!("  stdio  Line-delimited JSON on stdin/stdout (dev/testing).");
}

// ── AVM Interpreter ──
//
// Production bridge for NBC/VBC verification: executes core-logic
// via AVM interpreter directly (no subprocess, no IPC).
// Tick signing uses Ed25519Signer via the crypto::Signer trait.

use axiom_dmap_vm::AvmInterpreter;

// ── Node State ──

/// Rotation drain state — 2026-05-29 (graceful rotation).
///
/// When `wants_rotate()` fires the node enters `Draining`: any NEW
/// client-class request is rejected with `RegisterRejected
/// {reason:"rotation_drain"}` so the SDK rotates to another Nabla.
/// In-flight client requests run to completion. When `client_inflight`
/// drops to 0 the node transitions to `Cooldown(2)` and counts down
/// per tick. At `Cooldown(0)` the existing rotation logic fires; the
/// node returns to `Normal`.
///
/// Peer (Nabla-to-Nabla) traffic — Ticks, Approvals, Hello,
/// TardisAttach, Gossip — is unaffected at every stage. The mesh
/// stays connected during the drain.
///
/// Why: pre-drain rotation broke in-flight client TCPs mid-witness,
/// surfaced as ANTIE `INTERNAL_ERROR` (gateway.rs:794 catch-all) on
/// the SDK side. The 72h soak observed ~47 INTERNAL_ERRORs in the
/// 30-min window after rotation cycles fired. Affected wallets
/// self-healed (clara=heal/ok), but every heal costs CPU+network.
/// Maximum ticks a writer is allowed to sit in `Draining` before
/// force-progressing to `Cooldown`. Without this bound, drain can
/// deadlock under steady load: continuous SDK retries keep
/// `client_inflight` > 0, and the `client_inflight == 0` gate to
/// Cooldown never trips → writer stays in Draining permanently →
/// rejects every register with `rotation_drain`. Captured in the
/// 2026-05-29 fresh-soak storm with `client_inflight=373` and tx=0.
const DRAIN_MAX_TICKS: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RotationState {
    Normal,
    /// Pre-drain random delay (0..=5 ticks). When `wants_rotate` first
    /// fires we sit here for N ticks before entering Draining. Spreads
    /// rotations across ticks so that even if multiple writers all hit
    /// `wants_rotate` in the same tick (a residual sync), they don't
    /// all enter Draining together.
    Stagger(u32),
    /// Draining for N ticks. Progresses to Cooldown when
    /// `client_inflight == 0` OR `N >= DRAIN_MAX_TICKS`. The timeout
    /// is the load-safety valve.
    Draining(u32),
    Cooldown(u32),
}

struct NablaNodeState {
    /// Core node — state, persistence, protocol logic.
    /// This is THE node. Everything else here is TCP networking.
    core: NablaNode,

    // ── TCP Networking Layer (not in NablaNode) ──
    node_id: NodeId,
    node_name: String,
    /// Ticks spent as orphan.
    orphan_ticks: u64,
    /// Whether D1/D2 approved since the last tick_loop consumed approvals.
    /// Set in recv_loop, consumed (and reset) in tick_loop step 5a.
    d1_approved_this_tick: bool,
    d2_approved_this_tick: bool,
    /// Virtual time (seconds) of last received approval from D1/D2.
    d1_last_approval_secs: u64,
    d2_last_approval_secs: u64,
    /// B7 followup #2 (2026-04-13): tick_count when d1/d2 was first observed
    /// as filled by the local-tracking pass in step 5a. Reset to 0 when the
    /// slot becomes empty. Used to compute "time since attach" without
    /// requiring tardis to track attach timestamps internally.
    ///
    /// Why this exists: the original d1_ok logic at step 5a treats
    /// `d1_last_approval_secs == 0` as "OK (bootstrap)" indefinitely, which
    /// means a child that never approves never accumulates misses. The
    /// GHOST_CHILD_MISS_THRESHOLD escape hatch in wants_drop_slow_child
    /// therefore never fires — discovered in the beta10-fix6 soak when 5
    /// nodes spammed 90+ "Tick from unknown sender" warnings each over
    /// 8 minutes despite the wrapper-gate fix being deployed. The fix is
    /// to flip d1_ok = false after a bootstrap grace period, letting the
    /// miss counter tick up to the threshold so the ghost gets dropped.
    d1_first_seen_tick: u64,
    d2_first_seen_tick: u64,
    /// Total messages received (for dev-status reporting).
    messages_received: u64,
    /// AUDIT-FIX v2.11.14: Counter for rate-limited gossip messages.
    rate_limited_gossip: u64,
    /// 2026-04-15 fix `af79958` companion observability: total send
    /// failures across both recv_loop and tick_loop drain paths,
    /// per peer address. Tracks how often the zombie-connection
    /// recovery in `TcpTransport::send` had to re-establish a TCP
    /// socket. A high rate per a specific peer indicates network
    /// instability or repeated peer restarts. Exposed in /status as
    /// `transport_send_failures_total` and `transport_send_failures_per_peer`.
    /// Code: `E_NABLA_TRANSPORT_SEND_FAILED`.
    transport_send_failures_per_peer: HashMap<String, u64>,
    /// AUDIT-FIX v2.11.14: Lowest tick available from last StatePull peer.
    /// Used to avoid requesting ticks the peer doesn't have.
    peer_available_from_tick: u64,
    /// Last TARDIS tick when gossip was processed (for gossip_active animation).
    last_gossip_tick: u64,
    /// Last tick when we periodically broadcast our pool states.
    /// Pool gossip is otherwise event-driven (only on a claim) — this
    /// heartbeat lets formerly-quarantined or briefly-offline peers
    /// catch up without needing a new claim event.
    last_pool_heartbeat_tick: u64,
    /// Anti-entropy peer-rotation cursor. Each tick the node sends its
    /// `TickHash` root probe to `forward_targets()[cursor % len]` and
    /// increments — so every peer is probed in turn, replacing the old
    /// fixed `take(2)`. See `docs/AXIOM_DESIGN_NablaAntiEntropy.md` §5.5.
    ae_peer_cursor: u64,
    /// Virtual clock (seconds) — advances by TICK_INTERVAL_SECS each tick_loop
    /// iteration. Equals real time in production; accelerated in sim mode.
    virtual_secs: u64,
    /// Virtual clock (milliseconds).
    virtual_ms: u64,
    /// Pending TardisAttachRequests: (target_node_id, virtual_tick_sent).
    pending_attach: HashMap<NodeId, u64>,
    /// §6.3.7: in-flight latency pings — nonce → (peer pinged, send instant).
    /// A returning `Pong` looks the nonce up here to compute RTT. Bounded:
    /// expired entries (no Pong) are swept each ping round. Local-only.
    pending_pings: HashMap<u64, (NodeId, std::time::Instant)>,
    /// Monotonic counter for unique ping nonces.
    ping_nonce: u64,
    /// Parent we just detached from (voluntary rotation or kicked out by parent).
    /// Excluded from upstream candidate selection until `excluded_until_tick`
    /// so rotation actually moves the topology — otherwise the orphan
    /// picker can re-attach to the same parent on the very next tick.
    /// Cleared after ~50 ticks (~4 min) so the node CAN reconnect if no
    /// better candidate exists by then.
    recently_detached_parent: Option<(NodeId, u64)>,
    /// Anti-thrash cooldown for proactive rebalance (Step 5b.5). After a
    /// voluntary self-move from "parent is full" to "dc=1 candidate", wait
    /// at least REBALANCE_COOLDOWN_TICKS before considering another move.
    /// Without this guard the topology can oscillate as cascading peers
    /// each react to each other's broadcasts in the same tick.
    last_voluntary_move_tick: u64,
    /// Bootstrap peer addresses (from bootstrap.toml) for dashboard status.
    bootstrap_addresses: Vec<NablaAddress>,
    /// Own NBC serialized as bytes — included in outgoing Hello/TardisAttachRequest.
    own_nbc_bytes: Vec<u8>,
    /// YPX-021 §6 OODS-tardis: the most recent tick's extrema accumulator this
    /// node has seen (folded with its own draw). `oods_estimate` over it gives
    /// the tick-tree size — the SECOND, Core-produced OODS shown on the dashboard
    /// + register ACK next to the gossip estimate. Empty until the first tick.
    latest_oods_tardis: Vec<axiom_core_logic::oods_verify::OodsExtremum>,
    /// YP §19.6 — validator pool linkages (operator-declared
    /// validator_id → linked_wallet_id mappings). Populated by
    /// `WireMessage::RegisterValidatorPoolRequest` from the validator
    /// dashboard; consumed by Lambda's withdrawal handler (Step 8.3)
    /// to verify the withdrawal destination matches the operator's
    /// pre-declared link.
    validator_pool: axiom_nabla::validator_pool::ValidatorPoolStore,
    /// Verified peer NBCs. Only verify once per peer; cache after success.
    verified_nbcs: HashMap<NodeId, NBC>,
    /// Peer trust state for join protocol.
    verified_peers: HashMap<NodeId, PeerTrust>,
    /// AVM interpreter for CL7/CL8 NBC verification. None in sim/dev mode.
    avm: Option<Arc<AvmInterpreter>>,
    /// Skip NBC/VBC verification (dev/sim mode).
    skip_verify: bool,
    /// Reader-only mode: never accept registrations, always redirect (§25.5.4).
    reader_only: bool,
    /// SPHINCS+ secret key for NBC peer issuance. None if key file not found.
    sphincs_sk: Option<Vec<u8>>,
    /// Supporting NBCs for chain verification (our own chain from issuer).
    own_supporting_nbcs: Vec<NBC>,
    /// NBC issuer name (e.g. "alpha" for peer-issued, "ceremony" for root-signed).
    nbc_issuer: String,
    /// YPX-002 §4.2 / §4.3: raw SPHINCS+ public key of this node's NBC issuer
    /// (parent CA in the cert chain). This is the cryptographic identity used
    /// by clients to determine "cross-branch" Nabla nodes for the receiver
    /// verification triplet — two nodes are cross-branch iff they have
    /// *different* `nbc_issuer_pk` values. Populated in `accept_nbc()` from
    /// `nbc.issuer_set[0]`. Empty until an NBC has been accepted.
    nbc_issuer_pk: Vec<u8>,
    /// Registrations processed since last NBC renewal. Tracked for TX-budget enforcement.
    /// Resets to 0 on successful NBC renewal.
    registration_count: u64,
    /// JFP vote secrets — keyed by dwp_wallet_id, value is list of secrets.
    /// Ephemeral (not persisted across restarts — re-gossiped on rejoin).
    /// See Yellow Paper §8.4.3.
    jfp_secrets: HashMap<[u8; 32], Vec<[u8; 32]>>,

    // ── YPX-018 — Tiered bloom memory + CLARA wallet recovery ──
    //
    // These run alongside the legacy single-bloom path from YPX-014. The
    // existing path keeps working unchanged; Phase 4 will cut Lambda over
    // to consult the tiered chains via the three-state attestation.

    /// Time-bucketed txid bloom chain (YPX-018 §3). One bloom file per
    /// quarterly era. Inserted on every Nabla registration alongside the
    /// legacy single bloom.
    txid_bloom_chain: axiom_nabla::bloom_chain::BloomChain,

    /// Garbage state bloom chain (YPX-018 §3.2). Records states declared
    /// garbage by CLARA wallet heals. Receivers consult this to refuse any
    /// transaction that tries to consume an abandoned state.
    garbage_state_chain: axiom_nabla::garbage_state_chain::GarbageStateChain,

    /// Bloom Age Index (YPX-018 §3.1, §3.3). Directory of every bloom era
    /// this node knows about — both chains side-by-side at the same era_id.
    #[allow(dead_code)]
    bloom_age_index: axiom_nabla::age_index::BloomAgeIndex,

    /// YPX-018 Phase 5f Finding 3: per-wallet rate limiter for `POST /clara`.
    /// Bounds DoS amplification — without it an attacker could flood `/clara`
    /// with verify-then-reject requests using a small set of valid wallets,
    /// burning CPU on Ed25519 verification + compute_txid + verify_pk_binding
    /// for each. The limiter caps attempts at 3 per hour per wallet_pk
    /// (`MAX_CLARA_REGISTRATIONS_PER_HOUR_PER_WALLET`).
    clara_rate_limiter: axiom_nabla::clara::ClaraRateLimiter,

    // ── Rotation drain (2026-05-29) ──
    /// Current rotation drain state. See `RotationState` doc.
    rotation_state: RotationState,
    /// Client-class request handlers currently in flight. Incremented
    /// in `handle_message` before dispatching a client variant,
    /// decremented when the handler returns. `Draining → Cooldown`
    /// transition triggers when this drops to 0.
    client_inflight: u32,

    /// KI#37 — outbound-storm circuit breaker. Meters *forwarded /
    /// broadcast* sends (never replies, never Tick/Approval) in a
    /// one-second window. If the count crosses `STORM_SHED_CEILING`
    /// the node enters SHED for the rest of the window and drops
    /// further forward/broadcast traffic — a backstop against ANY
    /// re-broadcast loop or flood, independent of message type or
    /// which dedup a future bug might bypass. Tick authority and
    /// direct client replies are never shed, so consensus liveness
    /// and query answers survive a storm. See KI#37.
    storm: StormBreaker,
}

/// KI#37 outbound-storm circuit breaker. A pure rolling counter — no
/// crypto, no I/O. The design intent: dedup (tardis/gossip seen-sets)
/// prevents the KNOWN loops; this catches an UNKNOWN one by capping how
/// much a single node can pour into the mesh per second regardless of
/// cause, then self-clears when the window comes back under the ceiling.
struct StormBreaker {
    /// Monotonic start of the current 1s window (None until first send).
    window_start: Option<std::time::Instant>,
    /// Forward/broadcast sends counted in the current window.
    window_count: u32,
    /// True while shedding (window exceeded the ceiling). Cleared when a
    /// fresh window opens under the ceiling.
    shedding: bool,
    /// Total forward/broadcast sends dropped since boot (observability).
    dropped_total: u64,
    /// Number of distinct windows that tripped the breaker (observability).
    trips_total: u64,
}

impl StormBreaker {
    fn new() -> Self {
        Self {
            window_start: None,
            window_count: 0,
            shedding: false,
            dropped_total: 0,
            trips_total: 0,
        }
    }

    /// Account one forward/broadcast send attempt. Returns `true` if the
    /// caller should SEND, `false` if it should DROP (shed). Replies and
    /// critical (Tick/Approval/Attach/Detach) messages must NOT be routed
    /// through here — they always send. Self-clocked (monotonic Instant)
    /// so it behaves identically on every recv-loop thread and the tick
    /// loop. Returns (admit, just_tripped, just_recovered) so the caller
    /// can log the edges without holding extra state.
    fn admit_forward(&mut self) -> StormDecision {
        let now = std::time::Instant::now();
        let mut just_recovered = false;
        // Roll the window every second.
        let rolled = match self.window_start {
            Some(start) => now.duration_since(start).as_millis() >= 1000,
            None => true,
        };
        if rolled {
            if self.shedding && self.window_count <= STORM_SHED_CEILING {
                self.shedding = false;
                just_recovered = true;
            }
            self.window_start = Some(now);
            self.window_count = 0;
        }
        self.window_count += 1;
        let mut just_tripped = false;
        if self.window_count == STORM_SHED_CEILING + 1 && !self.shedding {
            self.shedding = true;
            self.trips_total += 1;
            just_tripped = true;
        }
        let admit = !self.shedding;
        if !admit {
            self.dropped_total += 1;
        }
        StormDecision { admit, just_tripped, just_recovered }
    }
}

struct StormDecision {
    admit: bool,
    just_tripped: bool,
    just_recovered: bool,
}

impl NablaNodeState {
    /// YPX-021 §7 — this node's current proven network-size view, stamped
    /// as the baseline into certificates it issues/renews:
    /// (rounded OODS estimate over the verified-NBC set, current tick).
    /// (0, 0) when no estimate is possible yet (no verified peers) —
    /// certs issued then carry no baseline (exempt, like genesis).
    fn current_oods_baseline(&self) -> (u32, u64) {
        let peer_ids: Vec<[u8; 32]> = self.verified_nbcs.keys().copied().collect();
        let est = axiom_nabla::oods::estimate_from_ids(&self.node_id, &peer_ids);
        let size = if est.is_finite() && est >= 1.0 {
            est.round().min(u32::MAX as f64) as u32
        } else {
            0
        };
        let tick = self.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
        (size, tick)
    }

    /// YPX-021 §8.2 — build the signed OODS reading served to clients.
    /// Crypto lives in `registration::build_oods_attestation` (the
    /// sanctioned synchronous-crypto hot-path file); this just supplies
    /// the node's materials. `None` when no NBC is loaded.
    fn build_oods_attestation(&self) -> Option<axiom_core_logic::types::NablaOodsAttestation> {
        let (oods_size, tick) = self.current_oods_baseline();
        axiom_nabla::registration::build_oods_attestation(
            &self.own_nbc_bytes, oods_size, tick, self.core.signer(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(node_id: NodeId, address: NablaAddress, data_dir: &std::path::Path, signer: Box<dyn Signer>, avm: Option<Arc<AvmInterpreter>>, skip_verify: bool,
           txid_mode: axiom_nabla::bloom::TxidServiceMode, dev_mode: bool) -> Self {
        // Open NablaNode with persistence (snapshot + WAL recovery)
        let mut core = NablaNode::open_with_options(data_dir, signer, txid_mode, dev_mode)
            .unwrap_or_else(|e| panic!("FATAL: Cannot open node: {e}"));
        core.init_mesh(node_id, address);
        core.init_tardis(node_id);
        // KI#32: warm the peer-NBC cache from the snapshot so a restarting node
        // can authenticate PoolSync immediately, instead of dropping it for ~15
        // min while Hello re-exchange repopulates verified_nbcs. Re-validate
        // expires_at against real wall-clock now (30-day NBCs can lapse while
        // the node was down). Keyed by nbc_node_id (= validator_id), matching
        // the verify_peer_nbc insert site.
        let mut verified_nbcs: HashMap<NodeId, NBC> = HashMap::new();
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let restored = core.take_restored_peer_nbcs();
            let total = restored.len();
            for nbc in restored {
                if nbc.expires_at > now {
                    let key = nbc_node_id(&nbc);
                    verified_nbcs.insert(key, nbc);
                }
            }
            if total > 0 {
                info!(
                    "KI#32: warmed {}/{} peer NBCs from snapshot (PoolSync authenticates immediately on restart)",
                    verified_nbcs.len(), total,
                );
            }
            // KI#32: re-seed core.peer_nbcs from the warm set so the NEXT
            // snapshot carries them forward. Without this, warm-restore
            // populated only the live `verified_nbcs` map; core.peer_nbcs
            // stayed empty until a fresh verify_peer_nbc fired (line ~899).
            // On a warm restart every peer is already known, so that never
            // fires — the next snapshot is written NBC-less and the SECOND
            // restart comes back cold. (gamma 2026-06-17: 1st restart warmed
            // 9/9 but wrote 8.8KB NBC-less snapshots; 2nd restart cold-started
            // and dropped 284 PoolSync.) Persistence must survive N restarts,
            // not just one.
            if !verified_nbcs.is_empty() {
                core.set_peer_nbcs(verified_nbcs.values().cloned().collect());
            }
        }
        Self {
            core,
            node_id,
            node_name: String::new(),
            orphan_ticks: 0,
            d1_approved_this_tick: false,
            d1_first_seen_tick: 0,
            d2_first_seen_tick: 0,
            d2_approved_this_tick: false,
            d1_last_approval_secs: 0,
            d2_last_approval_secs: 0,
            messages_received: 0,
            rate_limited_gossip: 0,
            transport_send_failures_per_peer: HashMap::new(),
            peer_available_from_tick: 0,
            last_gossip_tick: 0,
            last_pool_heartbeat_tick: 0,
            ae_peer_cursor: 0,
            virtual_secs: 0,
            virtual_ms: 0,
            pending_attach: HashMap::new(),
            pending_pings: HashMap::new(),
            ping_nonce: 0,
            recently_detached_parent: None,
            last_voluntary_move_tick: 0,
            bootstrap_addresses: Vec::new(),
            own_nbc_bytes: Vec::new(),
            latest_oods_tardis: Vec::new(),
            validator_pool: axiom_nabla::validator_pool::ValidatorPoolStore::new(),
            verified_nbcs,
            verified_peers: HashMap::new(),
            avm,
            skip_verify,
            reader_only: false,
            sphincs_sk: None,
            own_supporting_nbcs: Vec::new(),
            nbc_issuer: String::new(),
            nbc_issuer_pk: Vec::new(),
            registration_count: 0,
            jfp_secrets: HashMap::new(),
            // YPX-018 — initialize tiered bloom chains starting at tick 0.
            // The actual era boundaries advance via maybe_rotate() on every
            // insert keyed by virtual_secs.
            txid_bloom_chain: axiom_nabla::bloom_chain::BloomChain::new_default(0),
            // YPX-022 §5 — the garbage chain is the durable 55-yr "this cheque
            // is dead" record; restore it from disk so a restart never forgets
            // a recall. Corrupted file fails LOUDLY (panic at boot) — silently
            // opening a fresh chain would resurrect recalled cheques.
            garbage_state_chain: axiom_nabla::garbage_state_chain::GarbageStateChain::load(
                &data_dir.join("garbage_chain.state"),
            )
            .unwrap_or_else(|e| panic!("FATAL: corrupted garbage_chain.state: {e}"))
            .unwrap_or_else(|| axiom_nabla::garbage_state_chain::GarbageStateChain::new_default(0)),
            bloom_age_index: axiom_nabla::age_index::BloomAgeIndex::new(),
            clara_rate_limiter: axiom_nabla::clara::ClaraRateLimiter::new(),
            rotation_state: RotationState::Normal,
            client_inflight: 0,
            storm: StormBreaker::new(),
        }
    }

    /// YPX-022 §5 — persist the garbage chain after a mutation (atomic CBOR,
    /// tmp + rename). Best-effort like the pool persist: the in-memory chain
    /// is authoritative for the running session; the file is restart recovery.
    /// Inserts are rare (recalls + CLARA heals) so save-on-mutate is cheap.
    fn persist_garbage_chain(&self) {
        let path = self.core.data_dir().join("garbage_chain.state");
        if let Err(e) = self.garbage_state_chain.save(&path) {
            warn!("[GARBAGE-PERSIST] save failed: {e}");
        }
    }

    /// Accept a pre-loaded NBC into state and initialize the CC chain.
    ///
    /// NBC is loaded in main() before NablaNodeState is created,
    /// so node_id = nbc.validator_id from the start. This method just
    /// stores the NBC bytes and creates the CC chain.
    fn accept_nbc(&mut self, nbc: NBC) {
        self.node_name = if nbc.node_name.is_empty() {
            format!("{:02x}{:02x}{:02x}{:02x}",
                nbc.validator_id[0], nbc.validator_id[1],
                nbc.validator_id[2], nbc.validator_id[3])
        } else {
            nbc.node_name.clone()
        };
        // Determine NBC issuer: chain_depth 0 = ceremony, >0 = peer (from supporting chain)
        self.nbc_issuer = if nbc.chain_depth == 0 {
            "ceremony".to_string()
        } else if let Some(issuer_nbc) = self.own_supporting_nbcs.first() {
            if issuer_nbc.node_name.is_empty() {
                format!("{:02x}{:02x}...", issuer_nbc.validator_id[0], issuer_nbc.validator_id[1])
            } else {
                issuer_nbc.node_name.clone()
            }
        } else {
            "peer".to_string()
        };
        // YPX-002 §4.2 cross-branch identity: cache the parent CA SPHINCS+
        // pubkey so /query can return it without re-deserializing the NBC
        // bytes on every request. issuer_set is k=1 for Nabla — pull [0].
        self.nbc_issuer_pk = nbc.issuer_set.first().cloned().unwrap_or_default();
        info!("NBC accepted: {} ({:02x}{:02x}{:02x}{:02x}...) issuer={}",
            self.node_name,
            nbc.validator_id[0], nbc.validator_id[1],
            nbc.validator_id[2], nbc.validator_id[3],
            self.nbc_issuer);
        self.own_nbc_bytes = serialize_nbc(&nbc);
        // init_cc picks up restored CC from snapshot/WAL (if any)
        self.core.init_cc(nbc);
    }

    /// Verify a peer's NBC from wire bytes. Returns Ok(node_id_from_nbc) on success.
    /// Caches verified NBCs to avoid re-verification on subsequent messages.
    fn verify_peer_nbc(&mut self, nbc_bytes: &[u8], claimed_node_id: &NodeId) -> Result<NodeId, String> {
        // Already verified and cached?
        if let Some(cached) = self.verified_nbcs.get(claimed_node_id) {
            // Check expiry
            if cached.expires_at > self.virtual_secs {
                return Ok(*claimed_node_id);
            }
            // Expired — remove from cache, require re-verification
            self.verified_nbcs.remove(claimed_node_id);
        }

        // Deserialize
        let nbc = match deserialize_nbc(nbc_bytes) {
            Ok(n) => n,
            Err(e) => return Err(format!("NBC deserialize failed: {}", e)),
        };

        // Check claimed node_id matches NBC's validator_id
        let nbc_id = nbc_node_id(&nbc);
        if nbc_id != *claimed_node_id {
            return Err(format!(
                "node_id mismatch: claimed {:02x}{:02x}... but NBC says {:02x}{:02x}...",
                claimed_node_id[0], claimed_node_id[1], nbc_id[0], nbc_id[1]
            ));
        }

        // Primary: Core IPC verification (CL7) — produces proof-compatible result.
        // Fallback: direct crypto (dev/sim mode only, no Core available).
        if let Some(ref avm) = self.avm {
            if let Err(e) = verify_nbc_via_core(avm, &nbc, self.virtual_secs) {
                return Err(format!("Core rejected NBC: {}", e));
            }
        } else if let Err(e) = verify_nbc(&nbc, self.virtual_secs) {
            return Err(format!("Direct verify NBC failed: {}", e));
        }

        // Cache the verified NBC
        info!("NBC verified for {:02x}{:02x}... ({})", nbc_id[0], nbc_id[1], nbc.node_name);
        self.verified_nbcs.insert(nbc_id, nbc);
        // KI#32: keep the core's snapshot-able peer-NBC set in sync so the next
        // snapshot persists this NBC (warm cache on restart). Cheap — fires only
        // on an actual insert (a cached-valid peer returns early above).
        let snapshot_nbcs: Vec<NBC> = self.verified_nbcs.values().cloned().collect();
        self.core.set_peer_nbcs(snapshot_nbcs);

        // KI#32 FRESH-ENV FLOOD FIX (2026-06-18): persist the snapshot NOW, on a
        // new verification, so a restart warm-restores the COMPLETE verified set.
        // Root cause of the POOLSYNC-DROP flood was a snapshot-completeness gap: a
        // peer verified BETWEEN periodic snapshots was lost on restart and its
        // PoolSync hard-dropped until a (pair-asymmetric, connection-driven) Hello
        // re-fired. Snapshotting here closes that gap at the source — the verified
        // set on disk is never stale w.r.t. memory. Cost is bounded: this runs
        // ONLY on a real new insert (cache-valid peers return early above), so it
        // fires during mesh formation / re-verification, not on every message.
        // Reproduced + regression-pinned by
        // `tests::ki32_peer_verified_after_snapshot_survives_restart`.
        if let Err(e) = self.core.take_snapshot() {
            log::debug!("KI#32: snapshot after verifying {:02x}{:02x} failed (periodic tick will retry): {}",
                nbc_id[0], nbc_id[1], e);
        }
        Ok(nbc_id)
    }

    /// Evict expired NBCs from the peer cache.
    fn evict_expired_nbcs(&mut self) {
        let now = self.virtual_secs;
        self.verified_nbcs.retain(|_, nbc| nbc.expires_at > now);
    }

    /// Handle a NablaJoinRequest: verify NBC, verify wallet binding, start probation.
    /// Returns (accepted, reason, probation_until) and optional gossip message.
    fn handle_join_request(
        &mut self,
        nbc_bytes: &[u8],
        wallet_id: &WalletId,
        wallet_pubkey: &[u8],
        wallet_binding_sig: &[u8],
    ) -> (bool, String, u64, Option<GossipMessage>) {
        // 1. Deserialize and verify NBC structurally
        let nbc = match deserialize_nbc(nbc_bytes) {
            Ok(n) => n,
            Err(e) => return (false, format!("NBC deserialize: {}", e), 0, None),
        };
        // Primary: Core IPC verification (CL7). Fallback: direct crypto.
        if let Some(ref avm) = self.avm {
            if let Err(e) = verify_nbc_via_core(avm, &nbc, self.virtual_secs) {
                return (false, format!("NBC verify: {}", e), 0, None);
            }
        } else if let Err(e) = verify_nbc(&nbc, self.virtual_secs) {
            return (false, format!("NBC verify: {}", e), 0, None);
        }
        let nabla_id = nbc.validator_id;

        // 2. Verify wallet binding: sign(nabla_id || wallet_id) with wallet_pubkey
        let binding_msg = [nabla_id.as_slice(), wallet_id.as_slice()].concat();
        if !crypto::verify_ed25519(wallet_pubkey, &binding_msg, wallet_binding_sig) {
            return (false, "wallet binding: signature verification failed".into(), 0, None);
        }

        // 3. Check for existing entry (reconnection case)
        if let Some(existing) = self.verified_peers.get(&nabla_id) {
            match existing.status {
                NbcTrustStatus::Probation { since } => {
                    // Resume existing timer — do NOT restart
                    let probation_until = since + NABLA_PROBATION_SECS;
                    return (true, String::new(), probation_until, None);
                }
                NbcTrustStatus::Confirmed => {
                    // Already confirmed — accept immediately
                    return (true, String::new(), 0, None);
                }
                NbcTrustStatus::Genesis => {
                    return (true, String::new(), 0, None);
                }
            }
        }

        // 4. Check for duplicate Nabla_id with different wallet_id
        if let Some(existing) = self.verified_peers.get(&nabla_id) {
            if let Some(ref existing_wallet) = existing.wallet_id {
                if existing_wallet != wallet_id {
                    return (false, "duplicate Nabla_id with different wallet".into(), 0, None);
                }
            }
        }

        // 5. Accept: add to verified_peers with Probation status
        let since = self.virtual_secs;
        let probation_until = since + NABLA_PROBATION_SECS;
        self.verified_peers.insert(nabla_id, PeerTrust {
            nbc,
            status: NbcTrustStatus::Probation { since },
            wallet_id: Some(*wallet_id),
        });

        // 6. Gossip NablaIdAnnounce for duplicate detection
        let announce = GossipMessage::NablaIdAnnounce {
            nabla_id,
            wallet_id: *wallet_id,
            announced_at: since,
        };

        (true, String::new(), probation_until, Some(announce))
    }

    /// Check if a peer is in probation and therefore blocked from WRITER promotion.
    #[cfg(test)]
    fn is_peer_in_probation(&self, node_id: &NodeId) -> bool {
        if let Some(peer) = self.verified_peers.get(node_id) {
            matches!(peer.status, NbcTrustStatus::Probation { .. })
        } else {
            false
        }
    }

    /// Advance probation timers: promote peers whose probation has elapsed.
    /// Uses TARDIS tick time (virtual), NEVER SystemTime::now().
    #[cfg(test)]
    fn advance_probation(&mut self) {
        let now = self.virtual_secs;
        for peer in self.verified_peers.values_mut() {
            if let NbcTrustStatus::Probation { since } = peer.status {
                if now.saturating_sub(since) >= NABLA_PROBATION_SECS {
                    peer.status = NbcTrustStatus::Confirmed;
                }
            }
        }
    }

    /// Check a NablaIdAnnounce from gossip for duplicate detection.
    /// Returns true if this is a duplicate (same nabla_id, different wallet_id).
    #[cfg(test)]
    fn check_nabla_id_duplicate(&self, nabla_id: &NodeId, wallet_id: &WalletId) -> bool {
        if let Some(existing) = self.verified_peers.get(nabla_id) {
            if let Some(ref existing_wallet) = existing.wallet_id {
                return existing_wallet != wallet_id;
            }
        }
        false
    }

    /// Handle an NBC issuance request from a new node.
    /// Returns (accepted, nbc_bytes, supporting_chain_bytes, rejection_reason).
    fn handle_nbc_issuance_request(
        &self,
        sphincs_pk: &[u8],
        ed25519_pk: &[u8],
        dilithium_pk: &[u8],
        node_name: &str,
    ) -> (bool, Vec<u8>, Vec<u8>, String) {
        // Get our own NBC from the CC chain
        let own_nbc = match self.core.cc_chain() {
            Some(chain) => chain.nbc().clone(),
            None => return (false, vec![], vec![], "no NBC loaded".into()),
        };

        // Check if we're qualified to issue
        if !is_qualified_issuer(
            &own_nbc,
            self.sphincs_sk.as_deref(),
            NBC_ISSUER_MATURITY_SECS,
            self.virtual_secs,
        ) {
            return (false, vec![], vec![], "not qualified to issue NBCs".into());
        }

        // Validate request fields
        if sphincs_pk.len() != 32 {
            return (false, vec![], vec![], format!("bad sphincs_pk size: {}", sphincs_pk.len()));
        }
        if ed25519_pk.len() != 32 {
            return (false, vec![], vec![], format!("bad ed25519_pk size: {}", ed25519_pk.len()));
        }
        if node_name.len() > 64 {
            return (false, vec![], vec![], format!("node_name too long: {}", node_name.len()));
        }

        let subject = NbcSubject {
            sphincs_pk: sphincs_pk.to_vec(),
            ed25519_pk: ed25519_pk.to_vec(),
            dilithium_pk: dilithium_pk.to_vec(),
            node_name: node_name.to_string(),
        };

        // Issue the NBC — CL8 via AVM (Core is sole crypto authority).
        // Direct crypto fallback only in debug builds (dev/test).
        let sphincs_sk = self.sphincs_sk.as_ref().unwrap(); // safe: is_qualified_issuer checked
        let issue_result = if let Some(ref avm) = self.avm {
            issue_nbc_via_core(avm, &subject, &own_nbc, sphincs_sk, &self.own_supporting_nbcs, self.virtual_secs, self.current_oods_baseline())
        } else {
            #[cfg(debug_assertions)]
            {
                log::warn!("NBC issuance: AVM not available, using direct crypto (dev/test only)");
                issue_nbc(&subject, &own_nbc, sphincs_sk, &self.own_supporting_nbcs, self.virtual_secs, self.current_oods_baseline())
            }
            #[cfg(not(debug_assertions))]
            {
                log::error!("NBC issuance: AVM not available. Production requires --avm-elf.");
                Err(NablaError::NbcMalformed("AVM required for NBC issuance in production".into()))
            }
        };
        match issue_result {
            Ok((nbc, supporting)) => {
                let nbc_bytes = serialize_nbc(&nbc);
                let supporting_bytes = bincode::serialize(&supporting).unwrap_or_default();
                info!("NBC ISSUED for '{}' (chain_depth={})",
                    node_name, nbc.chain_depth);
                (true, nbc_bytes, supporting_bytes, String::new())
            }
            Err(e) => {
                error!("NBC issuance failed for '{}': {}", node_name, e);
                (false, vec![], vec![], format!("issuance failed: {}", e))
            }
        }
    }

    /// Handle an NBC renewal request from a peer approaching expiry.
    fn handle_nbc_renewal_request(
        &self,
        current_nbc_bytes: &[u8],
        renewal_sig: &[u8],
        request_time: u64,
    ) -> (bool, Vec<u8>, Vec<u8>, String) {
        // Deserialize the old NBC
        let old_nbc: NBC = match bincode::deserialize(current_nbc_bytes) {
            Ok(nbc) => nbc,
            Err(e) => return (false, vec![], vec![], format!("bad NBC: {}", e)),
        };

        // Verify renewal signature: Ed25519 over BLAKE3("AXIOM_NBC_RENEW" || validator_id || current_time)
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_NBC_RENEW");
        hasher.update(&old_nbc.validator_id);
        hasher.update(&request_time.to_le_bytes());
        let commitment = *hasher.finalize().as_bytes();
        if ed25519_dalek::VerifyingKey::from_bytes(
            &old_nbc.subject_pubkey_ed25519.as_slice().try_into().unwrap_or([0u8; 32])
        ).and_then(|vk| {
            let sig = ed25519_dalek::Signature::from_slice(renewal_sig)?;
            vk.verify_strict(&commitment, &sig)
        }).is_err() {
            return (false, vec![], vec![], "renewal signature invalid".into());
        }

        // Get our own NBC
        let own_nbc = match self.core.cc_chain() {
            Some(chain) => chain.nbc().clone(),
            None => return (false, vec![], vec![], "no NBC loaded".into()),
        };

        // Check if we're qualified to issue
        if !is_qualified_issuer(
            &own_nbc,
            self.sphincs_sk.as_deref(),
            NBC_ISSUER_MATURITY_SECS,
            self.virtual_secs,
        ) {
            return (false, vec![], vec![], "not qualified to issue".into());
        }

        // SEC-5 FIX: Route through Core (CL8) when AVM available.
        // Direct crypto fallback only in debug builds (dev/test).
        let sphincs_sk = self.sphincs_sk.as_ref().unwrap();
        let renewal_result = if let Some(ref avm) = self.avm {
            renew_nbc_via_core(avm, &old_nbc, &own_nbc, sphincs_sk, &self.own_supporting_nbcs, self.virtual_secs, self.current_oods_baseline())
        } else {
            #[cfg(debug_assertions)]
            {
                log::warn!("NBC renewal: AVM not available, using direct crypto (dev/test only)");
                renew_nbc(&old_nbc, &own_nbc, sphincs_sk, &self.own_supporting_nbcs, self.virtual_secs, self.current_oods_baseline())
            }
            #[cfg(not(debug_assertions))]
            {
                log::error!("NBC renewal: AVM not available. Production requires --avm-elf.");
                Err(NablaError::NbcMalformed("AVM required for NBC renewal in production".into()))
            }
        };
        match renewal_result {
            Ok((renewed, supporting)) => {
                let nbc_bytes = serialize_nbc(&renewed);
                let supporting_bytes = bincode::serialize(&supporting).unwrap_or_default();
                info!("NBC RENEWED for '{}' (expires_at={})",
                    renewed.node_name, renewed.expires_at);
                (true, nbc_bytes, supporting_bytes, String::new())
            }
            Err(e) => {
                (false, vec![], vec![], format!("renewal failed: {}", e))
            }
        }
    }

    /// Install a renewed NBC (received from a peer).
    fn install_renewed_nbc(&mut self, nbc: NBC, supporting: Vec<NBC>) {
        info!("Installing renewed NBC (expires_at={}, max_tx={})", nbc.expires_at, nbc.max_tx);
        // Reset TX counter — new NBC = new budget
        self.registration_count = 0;
        // Update own_nbc_bytes for outgoing Hello messages
        self.own_nbc_bytes = serialize_nbc(&nbc);
        // Update CC chain with the new NBC
        self.core.set_nbc(nbc.clone(), supporting.clone());
        self.own_supporting_nbcs = supporting;
        // AUDIT-FIX v2.11.14: Warn on NBC persistence failure (was silent drop).
        // If write fails, node reverts to old/expired NBC on restart.
        let config_dir = self.core.data_dir().join("config");
        if let Ok(json) = serde_json::to_string_pretty(&nbc) {
            if let Err(e) = std::fs::write(config_dir.join("nbc.json"), &json) {
                warn!("NBC persist failed: {} — node may lose renewed NBC on restart", e);
            }
        }
        if let Ok(chain_json) = serde_json::to_string_pretty(&self.own_supporting_nbcs) {
            if let Err(e) = std::fs::write(config_dir.join("nbc_supporting.json"), &chain_json) {
                warn!("NBC supporting chain persist failed: {}", e);
            }
        }
    }

    /// Check if our NBC is approaching expiry (time or TX budget) and request renewal.
    /// Returns a renewal request WireMessage if renewal is needed, None otherwise.
    /// Two independent triggers:
    /// - Time-based: within NBC_RENEWAL_WINDOW_SECS of expires_at
    /// - TX-based: within NBC_TX_RENEWAL_WINDOW of max_tx budget
    fn check_nbc_renewal(&self) -> Option<WireMessage> {
        use axiom_nabla::constants::{NBC_RENEWAL_WINDOW_SECS, NBC_TX_RENEWAL_WINDOW};
        let own_nbc = self.core.cc_chain()?.nbc().clone();

        if own_nbc.expires_at <= self.virtual_secs {
            return None; // Already expired — can't renew
        }

        // Time-based trigger: within renewal window of expiry
        let time_renewal_start = own_nbc.expires_at.saturating_sub(NBC_RENEWAL_WINDOW_SECS);
        let time_trigger = self.virtual_secs >= time_renewal_start;

        // TX-based trigger: within renewal window of max_tx budget
        let tx_trigger = if own_nbc.max_tx > 0 {
            self.registration_count >= own_nbc.max_tx.saturating_sub(NBC_TX_RENEWAL_WINDOW)
        } else {
            false // max_tx=0 means unlimited (backward compat)
        };

        if !time_trigger && !tx_trigger {
            return None; // Neither trigger met
        }

        // Sign: BLAKE3("AXIOM_NBC_RENEW" || validator_id || current_time)
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_NBC_RENEW");
        hasher.update(&own_nbc.validator_id);
        hasher.update(&self.virtual_secs.to_le_bytes());
        let commitment = *hasher.finalize().as_bytes();

        // Use the node's signer (Ed25519 signer loaded from key file)
        let sig = self.core.signer().sign(&commitment);

        let nbc_bytes = serialize_nbc(&own_nbc);
        Some(WireMessage::NbcRenewRequest {
            current_nbc_bytes: nbc_bytes,
            renewal_sig: sig,
            current_time: self.virtual_secs,
        })
    }

    /// Build a NodeStatusSnapshot for the HTTP dashboard.
    fn status_snapshot(&self, start_time: SystemTime) -> NodeStatusSnapshot {
        let uptime = monitor::uptime_secs(start_time);

        let node_id_hex = monitor::hex_short(&self.node_id);
        let tardis_tick = self.core.tardis().unwrap().current_tick();
        let has_upstream = self.core.tardis().unwrap().has_upstream();
        let downstream_count = self.core.tardis().unwrap().downstream_count();
        let is_writer = downstream_count == 2;

        let tardis_slot = if has_upstream {
            if is_writer { "Writer".into() } else { format!("D{}", downstream_count) }
        } else {
            "Orphan".into()
        };

        let peer_name = |id: &NodeId| -> String {
            self.verified_nbcs.get(id)
                .map(|nbc| nbc.node_name.clone())
                .unwrap_or_default()
        };

        let upstream_hex = self.core.tardis().unwrap().upstream()
            .map(hex::encode)
            .unwrap_or_default();
        let upstream_name = self.core.tardis().unwrap().upstream()
            .map(&peer_name)
            .unwrap_or_default();
        let d1_hex = self.core.tardis().unwrap().d1()
            .map(hex::encode)
            .unwrap_or_default();
        let d1_name = self.core.tardis().unwrap().d1()
            .map(&peer_name)
            .unwrap_or_default();
        let d2_hex = self.core.tardis().unwrap().d2()
            .map(hex::encode)
            .unwrap_or_default();
        let d2_name = self.core.tardis().unwrap().d2()
            .map(&peer_name)
            .unwrap_or_default();

        let peer_list: Vec<monitor::PeerEntry> = self.core.mesh().unwrap().active_peers().iter().map(|p| {
            monitor::PeerEntry {
                node_id_hex: hex::encode(p.node_id),
                node_name: peer_name(&p.node_id),
                is_genesis: false,
                txid_service: p.txid_service.clone(),
            }
        }).collect();

        let (cc_tick, cc_ticks_helped, cc_total_regs, cc_score) = self.core.cc_chain().as_ref()
            .and_then(|cc| cc.latest())
            .map(|cc| (cc.tick, cc.ticks_helped, cc.total_registrations, cc.score))
            .unwrap_or((0, 0, 0, 0));

        let writes_approved = cc_ticks_helped;
        let contribution = monitor::penguin_contribution(
            cc_ticks_helped, writes_approved, cc_total_regs, 0, 0,
        );
        let uptime_pct = if uptime > 86400 * 7 { 99.9 } else { 95.0 };
        let rel_mult = monitor::reliability_multiplier(uptime_pct);
        let penguin_score = (contribution as f64 * rel_mult) as u64;
        let (level_name, level_emoji) = monitor::penguin_level(penguin_score);

        // Bootstrap peer status — compare against active mesh peers
        let active = self.core.mesh().unwrap().active_peers();
        let known = self.core.mesh().unwrap().known_nodes_snapshot();
        let bootstrap_peers: Vec<monitor::BootstrapPeerEntry> = self.bootstrap_addresses.iter().map(|bp_addr| {
            let addr_str = monitor::format_address(bp_addr);
            // Check if this address is in active peers
            let active_match = active.iter().find(|p| &p.address == bp_addr);
            let known_match = known.iter().find(|p| &p.address == bp_addr);
            if let Some(peer) = active_match {
                let age = self.virtual_secs.saturating_sub(peer.last_seen);
                let last_seen = if age < 60 { format!("{}s ago", age) }
                    else if age < 3600 { format!("{}m ago", age / 60) }
                    else { format!("{}h ago", age / 3600) };
                monitor::BootstrapPeerEntry {
                    address: addr_str,
                    status: "connected".into(),
                    status_emoji: "\u{1F7E2}".into(),
                    last_seen,
                    latency_ms: None,
                }
            } else if let Some(peer) = known_match {
                let age = self.virtual_secs.saturating_sub(peer.last_seen);
                let last_seen = if peer.last_seen == 0 { "never".into() }
                    else if age < 60 { format!("{}s ago", age) }
                    else if age < 3600 { format!("{}m ago", age / 60) }
                    else { format!("{}h ago", age / 3600) };
                monitor::BootstrapPeerEntry {
                    address: addr_str,
                    status: "attempting".into(),
                    status_emoji: "\u{1F7E1}".into(),
                    last_seen,
                    latency_ms: None,
                }
            } else {
                monitor::BootstrapPeerEntry {
                    address: addr_str,
                    status: "unreachable".into(),
                    status_emoji: "\u{1F534}".into(),
                    last_seen: "never".into(),
                    latency_ms: None,
                }
            }
        }).collect();

        let ps = self.core.persistence_stats();
        let mut status = NodeStatusSnapshot {
            version: format!("v{}", env!("CARGO_PKG_VERSION")),
            node_name: self.node_name.clone(),
            node_id_hex,
            uptime_secs: uptime,
            txid_service: self.core.smt().txid_mode().to_string(),
            txid_hashmap_len: self.core.smt().txid_hashmap_len() as u64,
            txid_hashmap_bytes: self.core.smt().txid_hashmap_bytes(),
            txid_bloom_count: self.core.smt().txid_bloom_count(),
            txid_bloom_bytes: self.core.smt().txid_bloom_bytes(),
            txid_bloom_fpr: self.core.smt().txid_bloom_fpr(),
            listen_addr: monitor::format_address(self.core.mesh().unwrap().my_address()),
            wan_addr: None,
            current_tick: tardis_tick,
            tardis_active: true,
            tardis_slot,
            has_upstream,
            downstream_count,
            is_writer,
            d1_approved: self.core.tardis().unwrap().d1().is_some() && downstream_count >= 1,
            d2_approved: self.core.tardis().unwrap().d2().is_some() && downstream_count >= 2,
            ticks_with_current_parent: self.core.tardis().unwrap().ticks_with_parent(),
            rebalance_cooldown: self.core.tardis().unwrap().rebalance_cooldown(),
            root_hash_hex: monitor::hex_short(&self.core.smt().root_hash()),
            entry_count: self.core.smt().len(),
            ban_count: self.core.bans().len(),
            mesh_active: true,
            mesh_peer_count: self.core.mesh().unwrap().peer_count(),
            mesh_target_peers: self.core.mesh().unwrap().target_peer_count(),
            mesh_known_nodes: self.core.mesh().unwrap().known_node_count(),
            estimated_network_size: self.core.mesh().unwrap().estimated_network_size(),
            oods_estimate: {
                // OODS (YPX-021) size estimate, ANCHORED TO VERIFIED NBCs. Each
                // draw is bound to a real, cryptographically-verified, bonded NBC
                // identity (NodeId = NBC validator_id), so the estimate counts
                // only genuine NBCs — a Sybil that hasn't produced a valid NBC
                // does not inflate it. This is the §5/§5.2 anchoring: OODS rides
                // the NBC. Read-only telemetry, not a gate. `self` is the local
                // node's own verified identity.
                let self_id = self.node_id;
                let peer_ids: Vec<[u8; 32]> =
                    self.verified_nbcs.keys().copied().collect();
                axiom_nabla::oods::estimate_from_ids(&self_id, &peer_ids)
            },
            // YPX-021 §6 OODS-tardis: size read off the latest tick's accumulator
            // (independent of the gossip estimate above — this rides the tick tree).
            tardis_depth: axiom_core_logic::oods_verify::oods_estimate(
                &self.latest_oods_tardis,
            ) as u32,
            enquiry_peer_count: if self.core.mesh().unwrap().has_enquiry_peer() { 1 } else { 0 },
            cc_active: self.core.cc_chain().is_some(),
            cc_tick,
            cc_ticks_helped,
            cc_total_registrations: cc_total_regs,
            cc_score,
            runner_pool_balance: 0,
            airdrop_pool_balance: self.core.airdrop_pool().balance(),
            airdrop_pool_claims: self.core.airdrop_pool().total_claims,
            airdrop_local_claims: self.core.airdrop_pool().local_claims,
            dev_pool_balance: self.core.dev_treasury_pool().balance(),
            dev_pool_claims: self.core.dev_treasury_pool().total_claims,
            dev_pool_local_claims: self.core.dev_treasury_pool().local_claims,
            deed_collected: 0,
            deed_split: "0/0".into(),
            deed_pool_balance: self.core.deed_pool.balance(),
            deed_pool_total_credited: self.core.deed_pool.total_credited(),
            // Dev-class DEED — observability for @axiom.internal traffic.
            // NEVER reads through to the public DEED accounting; the
            // newtype wrapper makes a cross-credit a compile error.
            dev_deed_pool_balance: self.core.dev_deed_pool.balance(),
            dev_deed_pool_total_credited: self.core.dev_deed_pool.total_credited(),
            gossip_seen_count: self.core.gossip().seen_count(),
            last_gossip_tick: self.last_gossip_tick,
            transport_send_failures_total: self.transport_send_failures_per_peer.values().sum(),
            transport_send_failures_per_peer: self.transport_send_failures_per_peer.clone(),
            // KI#37 outbound-storm breaker observability.
            storm_shed_active: self.storm.shedding,
            storm_dropped_total: self.storm.dropped_total,
            storm_trips_total: self.storm.trips_total,
            // Fix #1: TARDIS tick-signature verify failures counter.
            // Same source as lib-mode status_snapshot — read off
            // self.core (NablaNode) via its tardis() getter.
            tick_sig_failures: self.core.tardis().map(|t| t.tick_sig_failures()).unwrap_or(0),
            // Phase B Layer 4: quarantine telemetry (mirrors lib-mode).
            quarantine_active_count: self.core.quarantine_state().active_count(),
            quarantine_pending_count: self.core.quarantine_state().pending_count(),
            penguin_score,
            penguin_level: level_name.into(),
            penguin_emoji: level_emoji.into(),
            uptime_streak_days: uptime / 86400,
            writes_approved,
            orphans_rescued: 0,
            rotations_survived: 0,
            reliability_multiplier: rel_mult,
            // Persistence metrics
            wal_file_bytes: ps.wal_file_bytes,
            wal_ops_since_snapshot: ps.wal_ops_since_snapshot,
            snapshot_count: ps.snapshot_count,
            snapshot_total_bytes: ps.snapshot_total_bytes,
            last_snapshot_tick: ps.last_snapshot_tick,
            total_disk_bytes: ps.total_disk_bytes,
            smt_memory_bytes: ps.smt_memory_bytes,
            upstream_hex,
            upstream_name,
            d1_hex,
            d1_name,
            d2_hex,
            d2_name,
            peer_list,
            bootstrap_peers,
            healthy: true,
            health_issues: Vec::new(),
        };

        monitor::diagnose(&mut status);
        status
    }
}

// ── Message Handling ──

/// Handle an incoming wire message from a peer.
/// Is this wire message a client-class request (as opposed to a peer
/// Nabla protocol message like Tick/Approval/Hello/Gossip)? Used by the
/// rotation-drain gate at the top of `handle_message` — when the node
/// is draining, client requests are rejected so the SDK rotates to
/// another Nabla while in-flight peer traffic continues normally.
fn is_client_request(msg: &WireMessage) -> bool {
    matches!(
        msg,
        WireMessage::Register(..)
            | WireMessage::FactConfirmRequest(..)
            | WireMessage::QueryTxidRequest(..)
            | WireMessage::RegisterChequeClaimRequest(..)
            | WireMessage::RecallRequest(..)
            | WireMessage::QueryWalletStateRequest(..)
            | WireMessage::PulseProofRequest(..)
            | WireMessage::JfpSecretRequest(..)
            | WireMessage::JfpSecretsRequest(..)
            | WireMessage::RegisterClaraRequest(..)
            | WireMessage::EndorseBanChallengeRequest(..)
            | WireMessage::ChallengeBanRequest(..)
            | WireMessage::QueryValidatorEarningsRequest(..)
            | WireMessage::RegisterValidatorPoolRequest(..)
            | WireMessage::QueryValidatorPoolRequest(..)
            | WireMessage::MarkValidatorEarningsClaimedRequest(..)
    )
}

/// Routes to the appropriate protocol handler and returns messages to send.
fn handle_message(
    state: &mut NablaNodeState,
    envelope: &Envelope,
) -> Vec<(std::net::SocketAddr, WireMessage)> {
    // YPX-002 P6 — simulated network-delay injection for local soak runs.
    // Zero-cost when `AXIOM_SIM_NET_DELAY_MAX_MS` is unset/0 (one atomic
    // load + branch). Runs on the per-connection TCP thread so the sleep
    // only stalls messages from this one peer, exactly the way real
    // cross-WAN latency would.
    axiom_nabla::sim_delay::maybe_sim_delay();

    let mut outbound: Vec<(std::net::SocketAddr, WireMessage)> = Vec::new();
    state.messages_received += 1;

    // ── Rotation drain gate (2026-05-29) ──
    // When the node is draining or in cooldown ahead of a TARDIS
    // rotation, refuse NEW client-class requests. The SDK's
    // `NablaPicker` already rotates Nablas on a non-Ack response, so
    // the wallet picks another writer instead of getting its
    // in-flight TX disrupted by our rotation. Peer Nabla traffic
    // (Tick/Approval/Hello/Gossip/Attach) is NEVER drained — the
    // mesh must stay connected throughout the drain.
    //
    // In-flight client requests that started before draining began
    // are allowed to run to completion; `client_inflight` tracks
    // them so the tick_loop can advance Draining → Cooldown only
    // when the count hits 0.
    // Reject clients only in Draining or Cooldown — NOT in Stagger.
    // Stagger is a pre-drain delay where we're still fully operational;
    // the whole point of stagger is to spread the actual drain across
    // ticks. Rejecting during stagger would defeat the spreading.
    if matches!(state.rotation_state, RotationState::Draining(_) | RotationState::Cooldown(_))
        && is_client_request(&envelope.message)
    {
        // Extract wallet_id where the variant has it, else use zeros
        // (only the SDK NablaPicker reads this; the value doesn't
        // affect routing).
        let wallet_id = match &envelope.message {
            WireMessage::Register(reg, _) => reg.wallet_id,
            WireMessage::FactConfirmRequest(req) => req.wallet_pk,
            _ => [0u8; 32],
        };
        let known_peers: Vec<NablaClientPeer> = {
            let snapshot = state
                .core
                .mesh()
                .map(|m| m.known_nodes_snapshot())
                .unwrap_or_default();
            let current_tick = state.core.current_tick();
            snapshot
                .iter()
                .map(|p| NablaClientPeer::from_peer_info(p, current_tick))
                .collect::<Vec<_>>()
                .into_iter()
                .take(20)
                .collect()
        };
        let reject = WireMessage::RegisterRejected {
            wallet_id,
            reason: "rotation_drain".into(),
            known_peers,
        };
        if transport::send_reply(envelope, &reject).is_err() {
            outbound.push((envelope.peer, reject));
        }
        return outbound;
    }

    // Client request that passes the drain gate — track in-flight so
    // the tick_loop can wait for the count to drop to 0 before
    // entering Cooldown. Decrement happens at the bottom of this
    // function — see "DRAIN-DEC".
    let was_client = is_client_request(&envelope.message);
    if was_client {
        state.client_inflight = state.client_inflight.saturating_add(1);
    }

    match &envelope.message {
        WireMessage::Hello { node_id, address, downstream_count, nbc_bytes, txid_service } => {
            // ── NBC verification ──
            if let Err(reason) = state.verify_peer_nbc(nbc_bytes, node_id) {
                warn!("NBC REJECT Hello from {:02x}{:02x}...: {}",
                    node_id[0], node_id[1], reason);
                // Reply to the peer's listening address, not envelope.peer
                // (which is the TCP ephemeral source port in TCP mode).
                outbound.push((
                    to_socket_addr(address),
                    WireMessage::NbcReject { reason },
                ));
                return outbound;
            }

            // Peer introducing itself — add to mesh knowledge only.
            // No TARDIS negotiation here — that goes through TardisAttachRequest.
            let now_secs = state.virtual_secs;
            let peer_dc = *downstream_count as usize;
            state.core.mesh_mut().unwrap().note_peer(*node_id, address.clone(), now_secs);
            state.core.mesh_mut().unwrap().upsert_peer_self_announced(PeerInfo {
                node_id: *node_id,
                address: address.clone(),
                last_seen: now_secs,
                tardis_up: None, // Hello doesn't carry upstream info
                has_d_open: peer_dc < 2,
                open_slots: (2 - peer_dc.min(2)) as u8,
                messages_delivered: 0,
                connected_since: now_secs,
                // YPX-014 mode from the sender's self-advertisement. Empty
                // string for pre-2026-05-30 peers that don't carry the
                // field; downstream consumers (UNCLE, dashboard) treat
                // empty as "unknown" and conservatively reject for
                // audit-grade traffic.
                txid_service: txid_service.clone(),
            });

            // No echo — periodic broadcasts (Step 3b, Step 4c) already push
            // our identity. Echoing creates infinite Hello ping-pong loops.
        }

        WireMessage::Tick(tick_msg) => {
            // TARDIS tick from upstream parent
            debug!("RECV Tick #{} from {:02x}{:02x}{:02x}{:02x}... approvals={}",
                tick_msg.number,
                tick_msg.upstream_pk[0], tick_msg.upstream_pk[1],
                tick_msg.upstream_pk[2], tick_msg.upstream_pk[3],
                tick_msg.downstream_approvals);

            // ── N2: Per-tick NBC identity binding ──
            // Verify tick sender's node_id matches a verified NBC.
            // upstream_pk is the sender's node_id (BLAKE3 of SPHINCS+ PK).
            // Prevents unverified nodes from injecting ticks.
            //
            // 2026-05-28 (KI#18 fix): we ALSO verify the Ed25519 signature
            // here, using the Ed25519 PK extracted from the NBC. Pre-fix,
            // signature verification was attempted inside `process_tick`
            // using `tick.upstream_pk` (a BLAKE3 hash) as the public key,
            // which fails 100% of the time (a hash is almost never a
            // curve point). The legitimate verification key lives in the
            // NBC's `subject_pubkey_ed25519`, accessed via
            // `cc::nbc_ed25519_pk`. We do the check here because this is
            // the only spot with `verified_nbcs` in scope; `process_tick`
            // (in `tardis.rs`) no longer attempts crypto verification
            // and trusts that the caller has authenticated the tick.
            if !state.skip_verify {
                let nbc = match state.verified_nbcs.get(&tick_msg.upstream_pk) {
                    Some(n) => n,
                    None => {
                        warn!("REJECT Tick #{}: upstream_pk {:02x}{:02x}... not in verified NBCs",
                            tick_msg.number, tick_msg.upstream_pk[0], tick_msg.upstream_pk[1]);
                        return outbound;
                    }
                };
                let nbc_ed25519_pk = match cc::nbc_ed25519_pk(nbc) {
                    Some(pk) => pk,
                    None => {
                        warn!("REJECT Tick #{}: NBC for upstream_pk {:02x}{:02x}... has no Ed25519 PK (malformed NBC)",
                            tick_msg.number, tick_msg.upstream_pk[0], tick_msg.upstream_pk[1]);
                        return outbound;
                    }
                };
                let tick_commit = axiom_nabla::crypto::tick_commitment(tick_msg);
                if !state.core.signer().verify(&nbc_ed25519_pk, &tick_commit, &tick_msg.signature) {
                    warn!("[TICK-SIG-FAIL] from={} tick={} NBC-bound Ed25519 PK rejected the signature",
                        hex::encode(&tick_msg.upstream_pk[..8]), tick_msg.number);
                    return outbound;
                }
            }

            // TARDIS lineage verification (Phase 1, LOG-ONLY —
            // AXIOM_YPX-003_TARDIS.md §7.6). Cryptographically verify prev_sig
            // (the grandparent's signature) against the grandparent's NBC key over the carried
            // gp_signed_payload — proving this tick descends from a REAL fresh writer lineage,
            // not just the presence-check the grandpa-tick rule does today. Observe-only: we
            // ENFORCE: reject a tick that CLAIMS lineage but fails to prove it (sig / freshness /
            // strict-parent). Runs even under `--dev`/`skip_verify` — the signatures are real
            // (skip_verify only skips the tick's own-sig check). A tick with NO lineage claim
            // (self-originated / bootstrap) falls through to the existing soft grandpa_miss path.
            const LINEAGE_FRESHNESS_TICKS: i64 = axiom_nabla::constants::LINEAGE_FRESHNESS_TICKS;
            if let (Some(gp_pk), Some(gp)) = (tick_msg.grandparent_pk, tick_msg.gp_commitment.as_ref()) {
                if !tick_msg.prev_sig.is_empty() {
                    match state.verified_nbcs.get(&gp_pk).and_then(cc::nbc_ed25519_pk) {
                        Some(gp_key) => {
                            // Recompute the grandparent's commitment from carried fields (its
                            // upstream_pk == grandparent_pk) and verify prev_sig against it.
                            let gp_commit = axiom_nabla::crypto::tick_commitment_fields(
                                gp.number, gp.timestamp_ms, &gp_pk, &gp.payload,
                                gp.downstream_approvals, &gp.prev_sig, &gp.child_pks, &gp.oods_hash,
                            );
                            let sig_ok = state.core.signer().verify(&gp_key, &gp_commit, &tick_msg.prev_sig);
                            let drift = tick_msg.number as i64 - gp.number as i64;
                            let fresh = drift.abs() <= LINEAGE_FRESHNESS_TICKS;
                            // strict-parent: our parent (tick sender) must be in GP's child set.
                            let parented = gp.child_pks.iter().any(|c| c == &tick_msg.upstream_pk);
                            if sig_ok && fresh && parented {
                                // Verified-lineage path is the steady state — keep it at debug
                                // (was info during Phase 1 observation). REJECT/BAN below stay warn.
                                if tick_msg.number % 120 == 0 {
                                    log::debug!("[LINEAGE-OK] tick={} from={} gp={} gp_tick={} drift={}",
                                        tick_msg.number, hex::encode(&tick_msg.upstream_pk[..4]),
                                        hex::encode(&gp_pk[..4]), gp.number, drift);
                                }
                            } else {
                                log::warn!("[LINEAGE-REJECT] tick={} from={} gp={} sig_ok={} fresh={} (drift={}) parented={} — dropping",
                                    tick_msg.number, hex::encode(&tick_msg.upstream_pk[..4]),
                                    hex::encode(&gp_pk[..4]), sig_ok, fresh, drift, parented);
                                // KI#34 fork-ban evidence: accuse the sender into the quarantine
                                // consensus — but ONLY if its OWN tick signature is valid, i.e. the
                                // sender is cryptographically accountable for this bad-lineage tick
                                // and `upstream_pk` isn't a spoofed innocent id (anti-framing). A
                                // spoofed tick (bad own-sig) is dropped only, never accused.
                                let own_sig_ok = state
                                    .verified_nbcs
                                    .get(&tick_msg.upstream_pk)
                                    .and_then(cc::nbc_ed25519_pk)
                                    .map(|k| {
                                        state.core.signer().verify(
                                            &k,
                                            &axiom_nabla::crypto::tick_commitment(tick_msg),
                                            &tick_msg.signature,
                                        )
                                    })
                                    .unwrap_or(false);
                                if own_sig_ok {
                                    if let Some(axiom_nabla::tardis::TardisAction::CascadeAlert {
                                        alert, targets,
                                    }) = state.core.flag_lineage_violation(tick_msg.upstream_pk)
                                    {
                                        let wire = WireMessage::Alert(alert);
                                        for target in &targets {
                                            if let Some(peer) = state.core.mesh().unwrap().peer_by_id(target) {
                                                outbound.push((to_socket_addr(&peer.address), wire.clone()));
                                            }
                                        }
                                        log::warn!("[LINEAGE-BAN-EVIDENCE] accused {} (valid own-sig, bad lineage) → quarantine consensus",
                                            hex::encode(&tick_msg.upstream_pk[..4]));
                                    }
                                }
                                return outbound;
                            }
                        }
                        // GP not yet a verified NBC — cannot verify; DON'T reject (bootstrap timing),
                        // the soft grandpa_miss path still guards a persistently-unproven parent.
                        None => log::debug!("[LINEAGE-SKIP] tick={} gp={} not in verified NBCs yet",
                            tick_msg.number, hex::encode(&gp_pk[..4])),
                    }
                }
            }

            // YPX-021 §6 OODS-tardis: fold this node's own Core-produced draw into
            // the incoming tick's accumulator and retain it, so /status + the
            // register ACK can report the tick-tree size next to the gossip OODS.
            {
                const OODS_EPOCH_TICKS: u64 = axiom_nabla::constants::OODS_EPOCH_TICKS; // must match tardis.rs / nabla_node origin
                let seed = axiom_core_logic::oods_verify::oods_epoch_seed(
                    tick_msg.number / OODS_EPOCH_TICKS, &[],
                );
                let mut acc = tick_msg.oods_tardis.clone();
                let mine = axiom_core_logic::oods_verify::oods_produce(&state.node_id, &seed);
                if acc.is_empty() {
                    acc = mine;
                } else {
                    axiom_core_logic::oods_verify::oods_fold(&mut acc, &mine);
                }
                state.latest_oods_tardis = acc;
            }

            let now_ms = state.virtual_ms;

            let actions = match state.core.process_tick(tick_msg, now_ms) {
                Ok(a) => a,
                Err(e) => {
                    debug!("Tick processing error: {}", e);
                    vec![]
                }
            };

            for action in actions {
                match action {
                    axiom_nabla::tardis::TardisAction::ForwardTick { tick, targets } => {
                        let wire = WireMessage::Tick(tick);
                        for target in &targets {
                            if let Some(peer) = state.core.mesh().unwrap().peer_by_id(target) {
                                outbound.push((to_socket_addr(&peer.address), wire.clone()));
                            }
                        }
                    }
                    axiom_nabla::tardis::TardisAction::SendApproval { approval, target } => {
                        if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target) {
                            outbound.push((
                                to_socket_addr(&peer.address),
                                WireMessage::Approval(approval),
                            ));
                        }
                    }
                    axiom_nabla::tardis::TardisAction::BroadcastRootHash { tick, root_hash, node_pk } => {
                        // Anti-entropy root probe: send our root hash to ONE
                        // peer per tick, rotating through every peer in turn
                        // (AXIOM_DESIGN_NablaAntiEntropy.md §5.5) — replaces
                        // the old fixed `take(2)` that pinned the repair to
                        // a static two-edge subgraph. A root mismatch at the
                        // receiver triggers the bidirectional leaf-hash sync.
                        // Not re-forwarded on receive — originators probe direct.
                        let gossip_msg = GossipMessage::TickHash { tick, root_hash, node_pk };
                        let wire = WireMessage::Gossip(gossip_msg);
                        let targets = state.core.mesh().unwrap().forward_targets(&state.node_id);
                        if !targets.is_empty() {
                            let idx = (state.ae_peer_cursor as usize) % targets.len();
                            state.ae_peer_cursor = state.ae_peer_cursor.wrapping_add(1);
                            let target_id = targets[idx];
                            if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target_id) {
                                outbound.push((to_socket_addr(&peer.address), wire));
                            }
                        }
                    }
                    axiom_nabla::tardis::TardisAction::SendAuditRequest { request, target } => {
                        if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target) {
                            outbound.push((
                                to_socket_addr(&peer.address),
                                WireMessage::AuditRequest(request),
                            ));
                        }
                    }
                    axiom_nabla::tardis::TardisAction::SendAuditResponse { response, target } => {
                        if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target) {
                            outbound.push((
                                to_socket_addr(&peer.address),
                                WireMessage::AuditResponse(response),
                            ));
                        }
                    }
                    axiom_nabla::tardis::TardisAction::CascadeAlert { alert, targets } => {
                        let wire = WireMessage::Alert(alert);
                        for target in &targets {
                            if let Some(peer) = state.core.mesh().unwrap().peer_by_id(target) {
                                outbound.push((to_socket_addr(&peer.address), wire.clone()));
                            }
                        }
                    }
                    axiom_nabla::tardis::TardisAction::DetachUpstream { parent, reason } => {
                        // Emitted by process_tick when the grandpa-sig has
                        // been missing for GRANDPA_MISS_DETACH_THRESHOLD
                        // consecutive ticks (= chain structurally broken).
                        // Detach + record exclusion + send TardisDetach up.
                        // Orphan recovery fires next tick (needs_parent()).
                        log::info!(
                            "[TARDIS-DETACH] {} leaving parent {} reason={:?}",
                            hex::encode(&state.node_id[..4]),
                            hex::encode(&parent[..4]),
                            reason,
                        );
                        if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&parent) {
                            outbound.push((
                                to_socket_addr(&peer.address),
                                WireMessage::TardisDetach { node_id: state.node_id },
                            ));
                        }
                        state.core.tardis_mut().unwrap().remove_peer(&parent);
                        let until = state.virtual_secs
                            + axiom_nabla::constants::WRITER_GRACE_TICKS as u64;
                        state.recently_detached_parent = Some((parent, until));
                    }
                    _ => {}
                }
            }
        }

        WireMessage::Approval(approval) => {
            // ── KI#20: NBC-anchored approval-sig verification ──
            // Same bug class as KI#18 (ticks) and KI#19 (audit responses):
            // pre-fix `tardis::receive_approval` called
            // `signer.verify(&approval.approver_pk, …)` treating the
            // approver's PeerId (a BLAKE3 hash) as an Ed25519 PK, so the
            // verify always failed. ~51K such failures per node in a 3-min
            // idle window. Fix lifts verification here, looks up the real
            // Ed25519 PK from the NBC the approver issued.
            if !state.skip_verify {
                let nbc = match state.verified_nbcs.get(&approval.approver_pk) {
                    Some(n) => n,
                    None => {
                        warn!("[APPROVAL-NBC-MISS] approver={} not in verified NBCs — dropped",
                            hex::encode(&approval.approver_pk[..8]));
                        return outbound;
                    }
                };
                let nbc_ed25519_pk = match cc::nbc_ed25519_pk(nbc) {
                    Some(pk) => pk,
                    None => {
                        warn!("[APPROVAL-NBC-MALFORMED] approver={} NBC has no Ed25519 PK — dropped",
                            hex::encode(&approval.approver_pk[..8]));
                        return outbound;
                    }
                };
                let payload = axiom_nabla::crypto::approval_sign_payload(approval);
                if !state.core.signer().verify(&nbc_ed25519_pk, &payload, &approval.signature) {
                    warn!("[APPROVAL-SIG-FAIL] approver={} tick={} NBC-bound Ed25519 PK rejected the signature",
                        hex::encode(&approval.approver_pk[..8]), approval.tick_number);
                    return outbound;
                }
            }

            let accepted = state.core.receive_approval(approval);
            if accepted {
                // Track which child approved — consumed by tick_loop's sliding window
                if state.core.tardis().unwrap().d1() == Some(&approval.approver_pk) {
                    state.d1_approved_this_tick = true;
                } else if state.core.tardis().unwrap().d2() == Some(&approval.approver_pk) {
                    state.d2_approved_this_tick = true;
                }
            }
        }

        WireMessage::Gossip(gossip_msg) => {
            // AUDIT-FIX v2.11.14: Wire per-peer gossip rate limiter.
            // Previously implemented but never called on inbound gossip.
            let peer_hash = {
                let bytes = format!("{}", envelope.peer);
                let h = blake3::hash(bytes.as_bytes());
                u64::from_le_bytes(h.as_bytes()[0..8].try_into().unwrap_or([0u8; 8]))
            };
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0);
            if !state.core.gossip_mut().check_peer_rate(peer_hash, now_secs) {
                state.rate_limited_gossip += 1;
                if state.rate_limited_gossip % 100 == 1 {
                    warn!("Gossip rate limit: peer {} exceeded {} msgs/{}s (total suppressed: {})",
                        envelope.peer,
                        axiom_nabla::gossip::GOSSIP_PER_PEER_LIMIT,
                        axiom_nabla::gossip::GOSSIP_RATE_WINDOW_SECS,
                        state.rate_limited_gossip);
                }
                return outbound; // Drop message, don't process or forward
            }
            // ── Phase B Layer 4 — Quarantine + Alert interception ──
            // sid is the apparent sender's NodeId for two pre-engine checks:
            //   1. quarantine drop — block all messages from a peer whose
            //      consensus-attested invariant violation activated quarantine
            //   2. Alert routing — Alerts go to handle_alert, never the engine
            //
            // TCP-source → NodeId mapping is missing infrastructure today:
            // peer_id_from_addr matches `peer.address` (listening port) but
            // envelope.peer carries the inbound TCP socket's ephemeral
            // source port, so the mesh lookup always returns None (same
            // shortcoming documented in the C3 anti-entropy path below).
            //
            // For Alerts we take sid from the message's intermediate_emitter
            // field directly. The dual-uniqueness consensus's anti-forgery
            // property is degraded — an attacker could spoof
            // intermediate_emitter — but origin_emitter uniqueness (3+
            // distinct detectors of a signed PoolSync) still gates
            // activation. Wiring TCP-source-NodeId verification is a
            // follow-up (see Phase B+ design doc).
            // PoolSync authenticity gate — Phase B Layer 4 attribution.
            // Verify `sender_sig` against the Ed25519 pk inside
            // `verified_nbcs[sender_node_id]` BEFORE the engine reconciles.
            // A forged PoolSync with a real sig is allowed through
            // (kappa-the-attacker really did sign the bad balance) — that
            // is exactly what attribution requires. A PoolSync whose sig
            // doesn't verify is dropped + ban-scored; an unverified peer
            // (no NBC on file) is also dropped, since attribution would
            // be impossible.
            if let GossipMessage::PoolSync {
                pool,
                balance,
                total_claims,
                tick,
                sender_node_id,
                sender_sig,
            } = gossip_msg {
                // SEC-03 (revised after the 2026-06-12 integration-gate
                // convergence check). Authenticity policy:
                //   - NBC verified + sig valid   → process normally (full attribution).
                //   - NBC verified + sig INVALID → HARD DROP + ban-score (forgery).
                //   - NBC pk unavailable for this sender → SOFT path: process the
                //     reconcile so mesh-wide min-balance / bounded-claims
                //     convergence still works, but emit no Alert (we cannot
                //     attribute a violation to an unauthenticated signer).
                //
                // ── DECISION RECORD (2026-06-17) — KI#32 / SEC-03: RESOLVED.
                // The soft path is DELETED; `None` now hard-drops + ban-scores.
                // Full write-up: KnownIssues #32 + SEC-03_DESIGN_poolsync_auth.md §1.
                //
                // HISTORY. The `None` arm used to soft-process unauthenticated
                // PoolSync. STEADY STATE the lookup resolves ~100% (a never-restarted
                // node holds all 9 peer NBCs with zero churn), but a RESTARTING node
                // came back with an EMPTY verified_nbcs and refilled it via Hello
                // trickle (~15 min), dropping pool gossip from not-yet-re-verified
                // peers during that window. The soft path existed solely to carry
                // that restart window. A first hard-drop attempt was reverted because
                // it ran straight into that cold-start window.
                //
                // WHY IT IS NOW SAFE TO HARD-DROP: peer NBCs are PERSISTED in the
                // snapshot (KI#32 fix — snapshot.rs `peer_nbcs`, restored with
                // expires_at re-validation in NablaNodeState::new). A restarting node
                // now WARMS its full peer-NBC set on boot ("KI#32: warmed N/N peer
                // NBCs from snapshot"), so PoolSync authenticates immediately — the
                // ~15-min cold-start window is gone. Validated: 10× warmed-9/9 events
                // across the 2026-06-17 chaos test; re-canary showed ~0
                // [POOLSYNC-DROP-UNVERIFIED] through a restart.
                //
                // FOLLOWUP FIX (2026-06-17, gamma roll). The first cut of warm-restore
                // populated only the live `verified_nbcs` map and did NOT re-seed
                // `core.peer_nbcs`, so it survived exactly ONE restart: after a warm
                // boot no fresh verify_peer_nbc fires (every peer is already known), so
                // the NEXT snapshot was written NBC-less and the SECOND restart cold-
                // started. Surfaced when gamma — the first node restarted twice — warmed
                // 9/9 then dropped 284 PoolSync on its second restart. Fixed by re-seeding
                // core.peer_nbcs from the warm set in NablaNodeState::new (see the
                // `set_peer_nbcs` call there). Regression-pinned by
                // `tests::ki32_peer_nbc_survives_multiple_restarts` (fails pre-fix on the
                // 2nd restart, passes post-fix). NB: a node that already warm-restored on
                // the pre-fix binary has an NBC-less snapshot on disk and must reconverge
                // once (mass mesh restart → Hello re-exchange → fresh 9/9 snapshot).
                //
                // AXIOM does not keep fallbacks (feedback_no_fallback_design): a
                // `None` arm silently processing unauthenticated gossip is exactly the
                // pattern we reject. Integrity stays closed by the reconcile gates
                // (judoon::structural_violation + POOL_SYNC_MAX_CLAIMS_SKEW_PER_MERGE +
                // min-wins) and JUDOON K-of-N attributes the real threat regardless;
                // hard-dropping just removes the stale fallback and gives JUDOON
                // authenticated input only.
                let pk_opt: Option<[u8; 32]> = state
                    .verified_nbcs
                    .get(sender_node_id)
                    .and_then(nbc_ed25519_pk);
                match pk_opt {
                    Some(pk) => {
                        let payload = axiom_nabla::crypto::pool_sync_sign_payload(
                            pool.sign_tag(), *balance, *total_claims, *tick, sender_node_id,
                        );
                        if !state.core.signer().verify(&pk, &payload, sender_sig) {
                            log::warn!(
                                "[POOLSYNC-DROP-BAD-SIG] sender_node_id={} sig verification failed — dropping + ban-score",
                                hex::encode(&sender_node_id[..8]),
                            );
                            return outbound;
                        }
                    }
                    None => {
                        // No resolvable NBC for this sender → DROP. Integrity
                        // stays closed by the reconcile gates regardless.
                        //
                        // DEBUG, not WARN (2026-06-18, soak s2r93186): on a fresh
                        // env (no snapshot to warm from) some peers' NBCs are not
                        // resolved in `verified_nbcs` in steady state, so this fires
                        // at high volume (~15k events). At WARN that flooded the
                        // single tracing writer, back-pressured the shared runtime,
                        // and starved client query-txid past its 5s timeout — the SDK
                        // then shipped attestation-less redeems that every validator
                        // rejected (E_TXID_ATTESTATION_MISSING → ~94% soak). Demoting
                        // to DEBUG removes the flood (same fix shape as KI#24's
                        // 15146b1d). NOTE: this only quiets the symptom — the real
                        // bug (verified-once peers not staying resolvable, so PoolSync
                        // from honest peers is dropped) is tracked separately; the
                        // counter below still records the rate for diagnosis.
                        log::debug!(
                            "[POOLSYNC-DROP-UNVERIFIED] sender_node_id={} no resolvable NBC — dropping",
                            hex::encode(&sender_node_id[..8]),
                        );
                        return outbound;
                    }
                }
            }

            if let GossipMessage::Alert { intermediate_emitter, .. } = gossip_msg {
                let sid = *intermediate_emitter;
                if state.core.is_peer_quarantined(&sid) {
                    log::debug!(
                        "[QUARANTINE-DROP] alert from quarantined peer {} — dropping",
                        hex::encode(&sid[..8]),
                    );
                    return outbound;
                }
                let action = state.core.handle_alert(gossip_msg, sid);
                use axiom_nabla::node::AlertHandleAction;
                match action {
                    AlertHandleAction::Drop => return outbound,
                    AlertHandleAction::DropAndBanScore { peer: _bad_peer } => {
                        log::warn!(
                            "[ALERT-DROP-BAN-SCORE] sender forgery from {} — drop",
                            hex::encode(&sid[..8]),
                        );
                        return outbound;
                    }
                    AlertHandleAction::Forward
                    | AlertHandleAction::ForwardAndQuarantineActive { .. } => {
                        let our_id = state.node_id;
                        // If the consensus just activated quarantine on
                        // the accused, push it into the mesh-side filter
                        // so all subsequent gossip fan-outs skip it. The
                        // quarantine_sweep will clear the filter when
                        // the TTL expires.
                        if let AlertHandleAction::ForwardAndQuarantineActive {
                            accused: q_accused,
                            until_tick,
                        } = &action {
                            log::warn!(
                                "[QUARANTINE-MESH-FILTER] activating mesh filter for accused={} until_tick={}",
                                hex::encode(&q_accused[..8]), until_tick,
                            );
                            state.core.activate_mesh_quarantine_filter(*q_accused);
                        }
                        if let GossipMessage::Alert {
                            alert_type, accused, evidence,
                            origin_emitter, emitted_at_tick, ..
                        } = gossip_msg {
                            let forwarded = GossipMessage::Alert {
                                alert_type: *alert_type,
                                accused: *accused,
                                evidence: evidence.clone(),
                                origin_emitter: *origin_emitter,
                                intermediate_emitter: our_id,
                                emitted_at_tick: *emitted_at_tick,
                            };
                            let wire = WireMessage::Gossip(forwarded);
                            for target_id in state.core.mesh().unwrap().forward_targets(&sid) {
                                if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target_id) {
                                    outbound.push((to_socket_addr(&peer.address), wire.clone()));
                                }
                            }
                        }
                        return outbound;
                    }
                }
            }

            let action = state.core.handle_gossip(gossip_msg);

            match action {
                GossipAction::Forward(msg) => {
                    state.last_gossip_tick = state.core.tardis().unwrap().current_tick();

                    // YPX-022 §5 mesh-wide garbage insert: a NEWLY-applied
                    // COMMITTED Recall (Forward ⇔ apply_remote_recall accepted
                    // it) puts the recalled txid into THIS node's own garbage
                    // chain — the durable, era-rotated record — not just the
                    // committing node's. A RESERVATION (§2.2.1, committed:
                    // false) never enters the garbage chain — `C` is still
                    // live and a redeem may still win.
                    if let GossipMessage::Recall { txid, committed: true, .. } = &msg {
                        state.garbage_state_chain.insert(state.virtual_secs, txid);
                        state.persist_garbage_chain();
                    }

                    // C3: TickHash partition detection — compare root hashes.
                    // On mismatch: enter quarantine AND trigger RangeSyncRequest
                    // to pull the peer's divergent wallet states. Without the pull,
                    // anti-entropy detects the partition but never resolves it.
                    if let GossipMessage::TickHash { tick, root_hash, node_pk } = &msg {
                        let our_root = state.core.smt().root_hash();
                        if our_root != *root_hash {
                            if let Some(tardis) = state.core.tardis_mut() {
                                let fork = tardis.record_branch_root_hash(*tick, *node_pk, *root_hash);
                                if fork {
                                    warn!("§32 FORK DETECTED at tick {}: our root {:02x}{:02x}... != peer {:02x}{:02x}...",
                                        tick, our_root[0], our_root[1], root_hash[0], root_hash[1]);
                                    tardis.enter_merge_quarantine(None);
                                }
                            }
                            // Anti-entropy step 2: reply with our full
                            // leaf-hash digest, addressed to the peer's
                            // *listening* socket (resolved via node_pk) —
                            // `envelope.peer` is the inbound connection's
                            // ephemeral source port, already closed. The
                            // peer diffs the digest and drives the
                            // bidirectional reconcile; every adopted entry
                            // is client-signature-verified on apply.
                            // AXIOM_DESIGN_NablaAntiEntropy.md §5.4.
                            let leaves = state.core.smt().leaf_digest();
                            let n = leaves.len();
                            let peer_addr = state.core.mesh().unwrap()
                                .peer_by_id(node_pk)
                                .map(|p| to_socket_addr(&p.address));
                            if let Some(addr) = peer_addr {
                                outbound.push((addr, WireMessage::AeDigest {
                                    from: state.node_id,
                                    leaves,
                                }));
                                info!("Anti-entropy: root mismatch — sent leaf digest ({n} wallets) to peer");
                            }
                        }
                    }

                    // ── §32 SCAN: detect forks via StateUpdate during quarantine ──
                    if let GossipMessage::StateUpdate { wallet_id, new_state, .. } = &msg {
                        let in_quarantine = state.core.tardis()
                            .map(|t| t.is_in_quarantine())
                            .unwrap_or(false);
                        if in_quarantine {
                            let remote = [(*wallet_id, *new_state)];
                            let forked = axiom_nabla::tardis::TardisNode::detect_forked_wallets(
                                state.core.smt(), &remote,
                            );
                            for wid in forked {
                                warn!("§32 SCAN: fork confirmed for {:02x}{:02x}... via gossip",
                                    wid[0], wid[1]);
                                let taint_msgs = state.core.handle_fork_evidence(
                                    &wid, state.core.current_tick(),
                                );
                                let sender_id = peer_id_from_addr(
                                    &envelope.peer, state.core.mesh().unwrap(),
                                );
                                let sender = sender_id.unwrap_or(state.node_id);
                                for target_id in state.core.mesh().unwrap().forward_targets(&sender) {
                                    if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target_id) {
                                        for taint in &taint_msgs {
                                            outbound.push((
                                                to_socket_addr(&peer.address),
                                                WireMessage::Gossip(taint.clone()),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // YPX-009: Record pulse delivery for mesh scoring.
                    if let GossipMessage::PulseProof { validator_pk, epoch, .. } = &msg {
                        if let Some(mesh) = state.core.mesh_mut() {
                            mesh.record_pulse_delivery(validator_pk, *epoch);
                        }
                    }

                    // TickHash: don't re-forward — originators send directly.
                    // Other gossip (StateUpdate, BanAlert, etc.): full fan-out.
                    let is_tick_hash = matches!(&msg, GossipMessage::TickHash { .. });
                    if !is_tick_hash {
                        let wire = WireMessage::Gossip(msg);
                        let sender_id = peer_id_from_addr(&envelope.peer, state.core.mesh().unwrap());
                        let sender = sender_id.unwrap_or(state.node_id);
                        for target_id in state.core.mesh().unwrap().forward_targets(&sender) {
                            if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target_id) {
                                outbound.push((to_socket_addr(&peer.address), wire.clone()));
                            }
                        }
                    }
                }
                GossipAction::BanDetected { forward, ban_alert } => {
                    state.last_gossip_tick = state.core.tardis().unwrap().current_tick();
                    // Forward both the original message and the ban alert
                    let sender_id = peer_id_from_addr(&envelope.peer, state.core.mesh().unwrap());
                    let sender = sender_id.unwrap_or(state.node_id);
                    for target_id in state.core.mesh().unwrap().forward_targets(&sender) {
                        if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target_id) {
                            let addr = to_socket_addr(&peer.address);
                            outbound.push((addr, WireMessage::Gossip(forward.clone())));
                            outbound.push((addr, WireMessage::Gossip(ban_alert.clone())));
                        }
                    }
                    // DURABILITY ("no turning back"): persist the just-applied ban to
                    // this node's WAL immediately, so a restart before the next
                    // snapshot cannot forget it. Mirrors the /register ban WAL path.
                    let banned_wid = match &ban_alert {
                        GossipMessage::SeqForkBan { wallet_id, .. } => Some(*wallet_id),
                        GossipMessage::BanAlert { wallet_id, .. } => Some(*wallet_id),
                        _ => None,
                    };
                    if let Some(wid) = banned_wid {
                        let ban_bytes = state.core.bans().get(&wid)
                            .and_then(|e| bincode::serialize(e).ok());
                        if let Some(bytes) = ban_bytes {
                            let _ = state.core.wal_mut().append(
                                &axiom_nabla::wal::WalOp::Ban { wallet_id: wid, evidence: bytes });
                        }
                    }
                }
                GossipAction::PoolViolationDetected { evidence, accused } => {
                    // Phase B Layer 4: reconcile detected a pool-state
                    // violation. `accused` is the verified
                    // `sender_node_id` from the offending PoolSync
                    // (sig was checked at the receive layer above).
                    // The bad PoolSync is dropped (NOT forwarded).
                    log::warn!(
                        "[POOL-VIOLATION-EMIT] building Alert against accused={} (evidence_bytes={})",
                        hex::encode(&accused[..8]),
                        evidence.len(),
                    );
                    let alert = state.core.build_pool_invariant_alert(accused, evidence);
                    let wire = WireMessage::Gossip(alert);
                    for target_id in state.core.mesh().unwrap().forward_targets(&state.node_id) {
                        if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target_id) {
                            outbound.push((to_socket_addr(&peer.address), wire.clone()));
                        }
                    }
                }
                GossipAction::PoolStructuralViolation { evidence: _, accused, proof } => {
                    // Layer 1 single-observer probation route (per
                    // AXIOM_DESIGN_NablaJudoon.md §2.5).
                    // Proof is self-evident from the peer's signed
                    // PoolSync — no Alert, no K-of-N consensus.
                    log::warn!(
                        "[JUDOON/ZERO-ROOM-ENTER] {:?} accused={} countdown_ticks={}",
                        proof,
                        hex::encode(&accused[..8]),
                        axiom_nabla::constants::PROBATION_COUNTDOWN_TICKS,
                    );
                    state.core.enter_probation_on_structural_violation(
                        accused,
                        proof,
                    );
                    // Do not forward the bad PoolSync (already dropped
                    // at the gossip engine layer).
                }
                GossipAction::Duplicate => {} // already seen
            }
        }

        WireMessage::AuditRequest(req) => {
            if let Some(axiom_nabla::tardis::TardisAction::SendAuditResponse { response, target }) = state.core.handle_audit_request(req) {
                if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target) {
                    outbound.push((
                        to_socket_addr(&peer.address),
                        WireMessage::AuditResponse(response),
                    ));
                }
            }
        }

        WireMessage::AuditResponse(resp) => {
            // ── KI#19: NBC-anchored audit-response sig verification ──
            // Pre-fix, `verify_audit_response` (in tardis.rs) attempted to
            // verify `resp.signature` using `resp.responder_pk` as an
            // Ed25519 PK — but `responder_pk` is a `PeerId =
            // BLAKE3(sphincs_pk)` (a 32-byte HASH, not a curve point), so
            // verify failed 100% of the time and every audit response
            // cascaded a QUESTIONABLE alert (>190,000:1 amplification
            // observed against a fresh 10-node mesh). Same bug class as
            // c7ebe4eb KI#18 Fix #2 for ticks.
            //
            // Fix lifts verification here (the only spot with
            // `verified_nbcs` in scope) and looks up the responder's real
            // Ed25519 PK from its NBC's `subject_pubkey_ed25519`. On
            // verify failure we DROP the response — `verify_audit_response`
            // is no longer asked to do crypto.
            if !state.skip_verify {
                let nbc = match state.verified_nbcs.get(&resp.responder_pk) {
                    Some(n) => n,
                    None => {
                        warn!("[AUDIT-RESP-NBC-MISS] responder={} not in verified NBCs — dropped",
                            hex::encode(&resp.responder_pk[..8]));
                        return outbound;
                    }
                };
                let nbc_ed25519_pk = match cc::nbc_ed25519_pk(nbc) {
                    Some(pk) => pk,
                    None => {
                        warn!("[AUDIT-RESP-NBC-MALFORMED] responder={} NBC has no Ed25519 PK — dropped",
                            hex::encode(&resp.responder_pk[..8]));
                        return outbound;
                    }
                };
                let payload = axiom_nabla::crypto::audit_response_sign_payload(resp);
                if !state.core.signer().verify(&nbc_ed25519_pk, &payload, &resp.signature) {
                    warn!("[AUDIT-RESP-SIG-FAIL] responder={} tick={} NBC-bound Ed25519 PK rejected the signature",
                        hex::encode(&resp.responder_pk[..8]), resp.response_tick);
                    return outbound;
                }
            }

            match state.core.verify_audit_response(resp) {
                Ok(axiom_nabla::tardis::TardisAction::CascadeAlert { alert, targets }) => {
                    for target in &targets {
                        if let Some(peer) = state.core.mesh().unwrap().peer_by_id(target) {
                            outbound.push((
                                to_socket_addr(&peer.address),
                                WireMessage::Alert(alert.clone()),
                            ));
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("Audit response verification failed: {}", e);
                }
            }
        }

        WireMessage::Alert(alert) => {
            // ── KI#37: NBC-anchored alert signature verification ──
            // Mirror of the KI#19 audit-response fix above. Pre-fix,
            // `alert.signature` was signed at mint (flag_questionable) but
            // NEVER verified anywhere — any peer could forge an alert
            // naming an arbitrary reporter and suspect, forcing the
            // receiver to detach from its upstream (targeted topology
            // grief) and joining the forged alert to the cascade. The
            // reporter must be a verified-NBC peer and its NBC-bound
            // Ed25519 PK must verify the signature; otherwise DROP.
            if !state.skip_verify {
                let nbc = match state.verified_nbcs.get(&alert.reporter_pk) {
                    Some(n) => n,
                    None => {
                        warn!("[ALERT-NBC-MISS] reporter={} not in verified NBCs — dropped",
                            hex::encode(&alert.reporter_pk[..8]));
                        return outbound;
                    }
                };
                let nbc_ed25519_pk = match cc::nbc_ed25519_pk(nbc) {
                    Some(pk) => pk,
                    None => {
                        warn!("[ALERT-NBC-MALFORMED] reporter={} NBC has no Ed25519 PK — dropped",
                            hex::encode(&alert.reporter_pk[..8]));
                        return outbound;
                    }
                };
                let payload = axiom_nabla::crypto::alert_sign_payload(alert);
                if !state.core.signer().verify(&nbc_ed25519_pk, &payload, &alert.signature) {
                    warn!("[ALERT-SIG-FAIL] suspect={} reporter={} tick={} NBC-bound Ed25519 PK rejected the signature — dropped",
                        hex::encode(&alert.suspect_pk[..8]),
                        hex::encode(&alert.reporter_pk[..8]),
                        alert.tick);
                    return outbound;
                }
            }

            if let Some(axiom_nabla::tardis::TardisAction::CascadeAlert { alert: cascade, targets }) = state.core.handle_questionable_alert(alert) {
                for target in &targets {
                    if let Some(peer) = state.core.mesh().unwrap().peer_by_id(target) {
                        outbound.push((
                            to_socket_addr(&peer.address),
                            WireMessage::Alert(cascade.clone()),
                        ));
                    }
                }
            }
        }

        WireMessage::Register(reg, deed_tx) => {
            // DIAG: confirm Register decoded and reached the handler. The
            // SDK has been seeing "Nabla read len: failed to fill whole
            // buffer" while nabla.log shows zero `read_one decode failed`
            // diagnostics, so we don't know whether decode is succeeding
            // and the handler is silently dropping the connection, or
            // decode is failing somewhere we're not instrumenting.
            log::debug!(
                "[nabla register] received: wallet={:02x}{:02x}{:02x}{:02x} \
                 old_state={:02x}{:02x} new_state={:02x}{:02x} sigs={} \
                 reply_stream={}",
                reg.wallet_id[0], reg.wallet_id[1], reg.wallet_id[2], reg.wallet_id[3],
                reg.old_state[0], reg.old_state[1],
                reg.new_state[0], reg.new_state[1],
                reg.receipt.signatures.len(),
                if envelope.reply_stream.is_some() { "yes" } else { "NO" },
            );
            // Collect peer hints (transport concern, not business logic)
            let known_peers: Vec<NablaClientPeer> = {
                let snapshot = state.core.mesh()
                    .map(|m| m.known_nodes_snapshot())
                    .unwrap_or_default();
                let current_tick = state.core.current_tick();
                let mut peers: Vec<NablaClientPeer> = snapshot.iter()
                    .map(|p| NablaClientPeer::from_peer_info(p, current_tick))
                    .collect();
                if peers.len() > 20 {
                    use rand::seq::SliceRandom;
                    peers.shuffle(&mut rand::thread_rng());
                    peers.truncate(20);
                }
                peers
            };

            // Reader-only mode: always redirect, regardless of TARDIS writer status (§25.5.4)
            if state.reader_only {
                info!("Reader-only mode — redirecting registration for {:02x}{:02x}...",
                    reg.wallet_id[0], reg.wallet_id[1]);
                let redirect = WireMessage::RegisterRejected {
                    wallet_id: reg.wallet_id,
                    reason: "reader_redirect".into(),
                    known_peers,
                };
                if transport::send_reply(envelope, &redirect).is_err() {
                    outbound.push((envelope.peer, redirect));
                }
                return outbound;
            }

            // 2026-05-28 — TARDIS write qualification gate (YPX-003 §1.2.1
            // "Per-tick write qualification" — NORMATIVE).
            //
            // A Nabla may only accept a write (/register) if it currently
            // holds a qualified TARDIS position. The qualification is
            // RE-EVALUATED EACH TICK INTERVAL — there is no permanent
            // writer status. All three conditions must hold concurrently:
            //
            //   1. `downstream_count() == 2` (exactly — slot manager
            //      structurally rejects a 3rd child, so > 2 is unreachable).
            //      D1 and D2 are both filled → both peers signed approvals.
            //   2. `has_upstream() == true` — the node is currently
            //      attached to a parent. No "root" exception: a node
            //      without upstream is a candidate writer still seeking
            //      upper link (per YPX-003 §1.2), it is NOT yet qualified.
            //   3. We approved a parent tick within the current interval.
            //      Detected by `now_secs - tardis.current_tick() <
            //      TICK_INTERVAL_SECS`. `current_tick` advances in
            //      `process_tick` step 5 (it carries the last accepted
            //      parent tick number), so this is a freshness check —
            //      did we just receive and verify a tick this round?
            //
            // The wall-clock comparison in condition 3 is one of the two
            // allowed uses of wall clock in AXIOM (the other being tick
            // generation): a `+TICK_INTERVAL_SECS` forward tolerance, same
            // shape as the tick verification bound in YPX-003 §1.3.4.
            //
            // Why all three: dc==2 proves we are chosen by peers (children
            // signed). has_upstream proves we are anchored (not a phantom
            // root). fresh parent tick proves the chain is alive (we
            // are CURRENTLY in consensus, not historically). Pre-fix code
            // accepted `dc >= 2 && (!has_upstream || twp > 0)` which was
            // wrong on all three counts: `>=` instead of `==`, allowed
            // unattached "roots" (no such thing in AXIOM), and only
            // required EVER receiving a tick (not THIS interval) — a node
            // that approved a tick once an hour ago would still pass.
            //
            // `skip_verify` (dev/test only) bypasses the gate. Production
            // builds must have skip_verify=false.
            if !state.skip_verify {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let (qualified, dc, has_up, current_tick) = match state.core.tardis() {
                    Some(t) => {
                        let dc = t.downstream_count();
                        let has_up = t.has_upstream();
                        let current_tick = t.current_tick();
                        // Freshness: have we approved a parent tick within
                        // the current interval? `current_tick` is the last
                        // accepted parent tick.number (advanced only by
                        // process_tick step 5); `now_secs - current_tick`
                        // is the wall-clock-bounded gap since last approval.
                        let fresh = now_secs.saturating_sub(current_tick)
                            < axiom_nabla::constants::TICK_INTERVAL_SECS;
                        (dc == 2 && has_up && fresh, dc, has_up, current_tick)
                    }
                    None => (false, 0, false, 0),
                };
                if !qualified {
                    let age = now_secs.saturating_sub(current_tick);
                    warn!("Registration rejected: not TARDIS-qualified \
                        (dc={} has_upstream={} parent_tick_age={}s) — wallet {:02x}{:02x}...",
                        dc, has_up, age, reg.wallet_id[0], reg.wallet_id[1]);
                    let reject = WireMessage::RegisterRejected {
                        wallet_id: reg.wallet_id,
                        reason: "not_tardis_qualified".into(),
                        known_peers,
                    };
                    if transport::send_reply(envelope, &reject).is_err() {
                        outbound.push((envelope.peer, reject));
                    }
                    return outbound;
                }
            }

            // §32: Reject registrations for frozen/tainted/banned wallets
            if state.core.is_wallet_blocked(&reg.wallet_id) {
                warn!("Registration rejected: wallet {:02x}{:02x}... is blocked (§32)",
                    reg.wallet_id[0], reg.wallet_id[1]);
                let reject = WireMessage::RegisterRejected {
                    wallet_id: reg.wallet_id,
                    reason: "wallet_blocked".into(),
                    known_peers,
                };
                if transport::send_reply(envelope, &reject).is_err() {
                    outbound.push((envelope.peer, reject));
                }
                return outbound;
            }

            // NBC TX-budget enforcement: reject if this node has exhausted its registration budget.
            // Clients are redirected to other peers who still have budget remaining.
            if let Some(cc) = state.core.cc_chain() {
                let max_tx = cc.nbc().max_tx;
                if max_tx > 0 && state.registration_count >= max_tx {
                    warn!("Registration rejected: NBC TX budget exhausted ({}/{})",
                        state.registration_count, max_tx);
                    let reject = WireMessage::RegisterRejected {
                        wallet_id: reg.wallet_id,
                        reason: "nbc_budget_exhausted".into(),
                        known_peers,
                    };
                    if transport::send_reply(envelope, &reject).is_err() {
                        outbound.push((envelope.peer, reject));
                    }
                    return outbound;
                }
            }

            // ── GAP-14: Writer routing redirect ──
            // READERs (dc<2 or insufficient approvals) cannot process registrations.
            // Redirect the client to our upstream parent, who is likely a WRITER.
            if let Some(tardis) = state.core.tardis() {
                if let Some(parent_id) = tardis.find_nearest_writer() {
                    if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&parent_id) {
                        info!("READER node — redirecting registration to writer {:02x}{:02x}...",
                            parent_id[0], parent_id[1]);
                        let redirect = WireMessage::RegisterRejected {
                            wallet_id: reg.wallet_id,
                            reason: "reader_redirect".into(),
                            known_peers: {
                                let mut peers = known_peers.clone();
                                // Ensure the writer is first in the peer list
                                let writer_peer = NablaClientPeer::from_peer_info(peer, state.core.current_tick());
                                peers.insert(0, writer_peer);
                                peers.truncate(20);
                                peers
                            },
                        };
                        if transport::send_reply(envelope, &redirect).is_err() {
                            outbound.push((envelope.peer, redirect));
                        }
                        return outbound;
                    }
                }
            }

            let _reg_t0 = std::time::Instant::now();
            let _reg_result = state.core.register(reg, deed_tx);
            // Latency telemetry (2026-07-07): the register path grew real work
            // (commitment-chain verify, fee/DEED on faithful receipts). The SDK
            // budget is 15s; log anything >1s so soaks DOCUMENT the
            // distribution and the slow component can be found, not guessed.
            {
                let ms = _reg_t0.elapsed().as_millis();
                if ms > 1000 {
                    warn!("[REGISTER-SLOW] {}ms wallet={} txid={} ok={}",
                        ms,
                        hex::encode(&reg.wallet_id[..8]),
                        hex::encode(&reg.tx_hash[..8]),
                        _reg_result.is_ok());
                }
            }
            match _reg_result {
                Ok(result) => {
                    // Track registration for NBC TX-budget enforcement
                    state.registration_count = state.registration_count.saturating_add(1);
                    let mut ack = result.ack;
                    ack.node_pk = state.core.signer().public_key();
                    ack.node_id = state.node_id.to_vec();
                    ack.known_peers = known_peers;
                    // ── NBC trust-anchor for SDK-side verify_fact_link (KI#8) ──
                    // Mirror the existing extraction pattern from the txid-attestation
                    // path (~line 5312). The SDK reads these three fields from the
                    // ACK and stores them on the FACT link's NablaConfirmation, so
                    // Core's verify_fact_link can later anchor node_pk to
                    // NABLA_ROOT_AUTHORITY_PKS via verify_nbc_for_nabla_confirmation.
                    if let Ok(nbc) = axiom_nabla::cc::deserialize_nbc(&state.own_nbc_bytes) {
                        let commitment = axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&nbc);
                        ack.nbc_issuer_pk = nbc.issuer_set.first().cloned().unwrap_or_default();
                        ack.nbc_signature = nbc.signatures.first().cloned().unwrap_or_default();
                        ack.nbc_commitment = commitment;
                    }
                    // Set cheque maturity status based on TARDIS tick authority
                    ack.cheque_status = state.core.check_maturity(ack.tick);
                    // Stamp protocol version so the SDK can detect skew —
                    // see RegistrationAck.server_protocol_version doc + the
                    // SDK's CLIENT_PROTOCOL_VERSION constant.
                    ack.server_protocol_version =
                        axiom_nabla::types::SERVER_PROTOCOL_VERSION;
                    ack.min_client_protocol_version =
                        axiom_nabla::types::MIN_CLIENT_PROTOCOL_VERSION;
                    // YPX-021 §8.2 — fold this writer's current signed OODS reading
                    // into the register ACK so the SDK caches it (no separate query).
                    ack.oods_attestation = state.build_oods_attestation();
                    // YPX-021 §6 — informational OODS-tardis writer-reach for the
                    // wallet to show next to the gossip OODS (not Core-verified).
                    ack.tardis_depth = axiom_core_logic::oods_verify::oods_estimate(
                        &state.latest_oods_tardis,
                    ) as u32;
                    let ack_msg = WireMessage::RegisterAck(ack);
                    // Try reply on same TCP connection (PMC has no listener),
                    // fall back to outbound queue (node-to-node path).
                    let reply_outcome = transport::send_reply(envelope, &ack_msg);
                    log::debug!(
                        "[nabla register] send_reply Ack: {} (peer={}) — reg_count={}",
                        if reply_outcome.is_ok() { "OK" } else { "ERR (queued for outbound)" },
                        envelope.peer, state.registration_count,
                    );
                    if reply_outcome.is_err() {
                        outbound.push((envelope.peer, ack_msg));
                    }
                    // Flood gossip to mesh
                    let gossip = WireMessage::Gossip(result.gossip_msg);
                    for target_id in state.core.mesh().unwrap().forward_targets(&state.node_id) {
                        if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target_id) {
                            outbound.push((to_socket_addr(&peer.address), gossip.clone()));
                        }
                    }
                    // YPX-020 HAL: a re-anchor stamps a hibernation lock on this
                    // writer; flood it so the cheque-claim's pick-set nodes (which
                    // are NOT this writer) also refuse the wallet's self-redeem
                    // until the window elapses. We gossip the EXACT `until`
                    // process_registration stamped (derived from the authoritative
                    // `current_tick`, not `virtual_secs`) — single source, no skew.
                    if let Some(until) = result.hibernation_until {
                        // Broadcast under the SAME key the SET used (reg.wallet_id
                        // = the wallet's raw pubkey, which the self-cheque claim
                        // carries as sender_wallet_pk). `client_pk` is the wire
                        // field name on GossipMessage::Hibernation.
                        let hib = WireMessage::Gossip(GossipMessage::Hibernation {
                            client_pk: reg.wallet_id.to_vec(),
                            until,
                        });
                        for target_id in state.core.mesh().unwrap().forward_targets(&state.node_id) {
                            if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target_id) {
                                outbound.push((to_socket_addr(&peer.address), hib.clone()));
                            }
                        }
                    }
                    // YPX-022 §2.2.1 — the COMMIT's local durable effects + the
                    // committed flood. process_registration flipped the
                    // reservation(s) terminal + WAL'd them (8a'); here the
                    // writer inserts each recalled txid into its garbage chain
                    // (the 55-yr record) and floods `committed: true` so every
                    // node upgrades its reservation, garbage-inserts, and
                    // starts refusing the redeem. `C` is dead from here.
                    for (recalled_txid, reservation_tick) in &result.committed_recalls {
                        state.garbage_state_chain.insert(state.virtual_secs, recalled_txid);
                        state.persist_garbage_chain();
                        let wire = WireMessage::Gossip(GossipMessage::Recall {
                            txid: *recalled_txid,
                            sender_pk: reg.wallet_id.to_vec(),
                            recall_tick: *reservation_tick,
                            committed: true,
                        });
                        if let Some(mesh) = state.core.mesh() {
                            for target_id in mesh.forward_targets(&state.node_id) {
                                if let Some(peer) = mesh.peer_by_id(&target_id) {
                                    outbound.push((to_socket_addr(&peer.address), wire.clone()));
                                }
                            }
                        }
                    }
                    // §17.11: If genesis claim, broadcast pool state for convergence.
                    // Both pools always get gossiped on every genesis claim — only
                    // the one that actually decremented changes its monotonic
                    // counters, the other emit is a no-op on receivers' reconcile.
                    // Simpler than branching on is_dev_wallet here.
                    if reg.is_genesis_claim {
                        use axiom_nabla::types::PoolKind;
                        let airdrop_gossip =
                            WireMessage::Gossip(state.core.pool_sync_message(PoolKind::Airdrop));
                        let dev_gossip =
                            WireMessage::Gossip(state.core.pool_sync_message(PoolKind::DevTreasury));
                        // DEED rides on the same fan-out: genesis doesn't
                        // credit DEED (no fee_breakdown on a genesis
                        // claim), but pushing the current balance every
                        // register-event keeps mesh convergence tight.
                        let deed_gossip =
                            WireMessage::Gossip(state.core.pool_sync_message(PoolKind::Deed));
                        // Dev DEED — rides on the same fan-out as Deed so a
                        // dev TX register propagates its credit to the
                        // mesh. Without this, only the originating Nabla
                        // sees the dev DEED balance increment.
                        let dev_deed_gossip =
                            WireMessage::Gossip(state.core.pool_sync_message(PoolKind::DevDeed));
                        for target_id in state.core.mesh().unwrap().forward_targets(&state.node_id) {
                            if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target_id) {
                                outbound.push((to_socket_addr(&peer.address), airdrop_gossip.clone()));
                                outbound.push((to_socket_addr(&peer.address), dev_gossip.clone()));
                                outbound.push((to_socket_addr(&peer.address), deed_gossip.clone()));
                                outbound.push((to_socket_addr(&peer.address), dev_deed_gossip.clone()));
                            }
                        }
                    }
                }
                Err(e) => {
                    use axiom_errors::error_code as ec;
                    use axiom_nabla::types::NablaError;
                    // Structured prefix so the SDK can dispatch on the
                    // refusal reason without parsing English. Format:
                    //   `<E_CODE>|<key=val>|<human>` — the SDK matches
                    // the leading E_CODE prefix; the human tail keeps
                    // logs readable.
                    let reason = match &e {
                        NablaError::PoolCapPerNabla { reset_tick } => format!(
                            "{}|reset_tick={}|per-Nabla cycle cap reached on this node",
                            ec::E_POOL_CAP_PER_NABLA, reset_tick,
                        ),
                        NablaError::PoolCapMesh { reset_tick } => format!(
                            "{}|reset_tick={}|mesh-wide cycle cap reached",
                            ec::E_POOL_CAP_MESH, reset_tick,
                        ),
                        NablaError::PoolExhausted => {
                            format!("{}|pool exhausted — no more claims available", ec::E_POOL_EXHAUSTED)
                        }
                        _ => format!("{}", e),
                    };
                    warn!("Registration rejected for {:02x}{:02x}...: {}",
                        reg.wallet_id[0], reg.wallet_id[1], reason);
                    let reject = WireMessage::RegisterRejected {
                        wallet_id: reg.wallet_id,
                        reason: reason.clone(),
                        known_peers,
                    };
                    let reply_outcome = transport::send_reply(envelope, &reject);
                    eprintln!(
                        "[nabla register] send_reply Rejected ({}): {} (peer={})",
                        reason,
                        if reply_outcome.is_ok() { "OK" } else { "ERR (queued for outbound)" },
                        envelope.peer,
                    );
                    if reply_outcome.is_err() {
                        outbound.push((envelope.peer, reject));
                    }
                }
            }
        }

        WireMessage::Query { wallet_id } => {
            let mut response = state.core.query(wallet_id);

            // YPX-002 §4.3 cross-branch grouping key: stamp the responding
            // node's NBC issuer pk so the receiver can group its known
            // Nablas into branches and pick `(sticky + 2 cross-branch
            // random)` per §4.6 step 2. This field rides as advisory
            // metadata, NOT covered by the response signature; n-of-n
            // cross-checking provides the trust (see NablaResponse field
            // doc and §4.6 §3 BANNED check).
            response.nbc_issuer_pk = state.nbc_issuer_pk.clone();

            // Role attestation (§25.5.4)
            let role_byte: u8 = if state.reader_only {
                0 // reader
            } else if state.core.tardis().map(|t| t.is_self_writer()).unwrap_or(false) {
                1 // writer
            } else {
                0 // reader
            };
            response.role = role_byte;

            // Sign: BLAKE3("AXIOM_NABLA_ROLE" || node_id || role || wallet_id || state_id || tick_le)
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"AXIOM_NABLA_ROLE");
            hasher.update(&state.node_id);
            hasher.update(&[role_byte]);
            hasher.update(&response.wallet_id);
            hasher.update(&response.current_state);
            hasher.update(&response.synced_to_tick.to_le_bytes());
            let hash = hasher.finalize();
            response.role_signature = state.core.signer().sign(hash.as_bytes());

            let reply_msg = WireMessage::QueryResponse(response);
            // Try reply on same TCP connection (PMC has no listener),
            // fall back to outbound queue (node-to-node path).
            if transport::send_reply(envelope, &reply_msg).is_err() {
                outbound.push((envelope.peer, reply_msg));
            }
        }

        // ── Client TCP-CBOR migration paths (CLAUDE.md §8) ──
        // Thin codec wrappers over `query_txid_core`,
        // `register_cheque_claim_core`, `register_clara_core`. The HTTP
        // handlers wrap the same cores; the wire variant carries native
        // bytes instead of hex strings.
        WireMessage::QueryTxidRequest(req) => {
            let resp = query_txid_core(req, state);
            let reply = WireMessage::QueryTxidResponse(resp);
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        WireMessage::RegisterChequeClaimRequest(req) => {
            let resp = register_cheque_claim_core(req, state);
            let reply = WireMessage::RegisterChequeClaimResponse(resp);
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        WireMessage::RecallRequest(req) => {
            let txid = axiom_core_logic::compute::compute_txid(&req.failed_send_tx);
            let sender_pk = req.sender_pk.clone();
            let resp = register_recall_core(req, state);
            let recalled_ok = resp.status == "OK";
            let reply = WireMessage::RecallResponse(resp);
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
            // YPX-022 §2.2.1 — flood the RESERVATION to the mesh: (a) any node
            // can serve the RETRACT_PENDING in-flight notice, and (b) the
            // recall self-send's registration (the COMMIT) can land on ANY
            // node, not just this one. Not the terminal — a redeem still wins
            // until the committed flood.
            if recalled_ok {
                let tick = state.virtual_secs;
                let wire = WireMessage::Gossip(GossipMessage::Recall {
                    txid, sender_pk, recall_tick: tick, committed: false,
                });
                if let Some(mesh) = state.core.mesh() {
                    for target_id in mesh.forward_targets(&state.node_id) {
                        if let Some(peer) = mesh.peer_by_id(&target_id) {
                            outbound.push((to_socket_addr(&peer.address), wire.clone()));
                        }
                    }
                }
            }
        }

        WireMessage::RegisterClaraRequest(req) => {
            let resp = register_clara_core(req, state, &mut outbound);
            let reply = WireMessage::RegisterClaraResponse(resp);
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        WireMessage::QueryWalletStateRequest(req) => {
            let resp = query_wallet_state_core(req, state);
            let reply = WireMessage::QueryWalletStateResponse(resp);
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        WireMessage::FactConfirmRequest(req) => {
            // Closes the last grandfathered HTTP→TCP site
            // (CLAUDE.md Upcoming Task #3).  Shared core with
            // `handle_http_register`.
            let outcome = fact_confirm_core(req, state, &mut outbound);
            let reply = match outcome {
                FactConfirmOutcome::Ok(resp) => WireMessage::FactConfirmResponse(resp),
                FactConfirmOutcome::Mismatch(m) => WireMessage::FactConfirmMismatch(m),
                FactConfirmOutcome::Rejected { http_status: _, error } =>
                    WireMessage::FactConfirmRejected(error),
            };
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        // ── Phase 3c TCP-CBOR migration paths (CLAUDE.md §8) ──
        // The last six functional HTTP endpoints, migrated to TCP. Each
        // arm calls the shared `*_core` logic (also used by the gated
        // HTTP handler) and wraps the result in a response variant.
        WireMessage::PulseProofRequest(req) => {
            let reply = match pulse_proof_core(req, state, &mut outbound) {
                PulseProofOutcome::Ok(resp) => WireMessage::PulseProofResponse(resp),
                PulseProofOutcome::Rejected { http_status: _, error } =>
                    WireMessage::PulseProofRejected(error),
            };
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        WireMessage::JfpSecretRequest(req) => {
            let reply = match jfp_secret_core(req, state, &mut outbound) {
                JfpSecretOutcome::Ok(resp) => WireMessage::JfpSecretResponse(resp),
                JfpSecretOutcome::Rejected { http_status: _, error } =>
                    WireMessage::JfpSecretRejected(error),
            };
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        WireMessage::JfpSecretsRequest(req) => {
            let resp = jfp_secrets_core(req, state);
            let reply = WireMessage::JfpSecretsResponse(resp);
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        // WireMessage::BridgeRequest is intercepted in recv_loop and run
        // off the node lock (bridge_core / task #53) — it never reaches
        // here; an unhandled arrival falls through to the `_` no-op.

        WireMessage::EndorseBanChallengeRequest(req) => {
            let resp = endorse_ban_challenge_core(req, state);
            let reply = WireMessage::EndorseBanChallengeResponse(resp);
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        WireMessage::ChallengeBanRequest(req) => {
            let resp = challenge_ban_core(req, state, &mut outbound);
            let reply = WireMessage::ChallengeBanResponse(resp);
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        WireMessage::QueryValidatorEarningsRequest(req) => {
            let resp = query_validator_earnings_core(req, state);
            let reply = WireMessage::QueryValidatorEarningsResponse(resp);
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        WireMessage::RegisterValidatorPoolRequest(req) => {
            // YP §19.6 — operator dashboard binds validator_id's fee
            // pool to a wallet. Validator_pool module handles SPHINCS+
            // verify + epoch monotonicity + freshness; errors land in
            // the response status string rather than as wire errors so
            // the dashboard can surface diff-from-stored.
            let resp = state.validator_pool.process_register(
                req, state.virtual_secs,
            ).unwrap_or_else(|_| axiom_nabla::wire_client::RegisterValidatorPoolResponse {
                status: "REJECTED_INTERNAL".to_string(),
                validator_id: req.validator_id,
                stored_linked_wallet_id: [0u8; 32],
                stored_linkage_epoch: 0,
                stored_at_tick: state.virtual_secs,
            });
            let reply = WireMessage::RegisterValidatorPoolResponse(resp);
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        WireMessage::QueryValidatorPoolRequest(req) => {
            let resp = state.validator_pool.process_query(req);
            let reply = WireMessage::QueryValidatorPoolResponse(resp);
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        WireMessage::MarkValidatorEarningsClaimedRequest(req) => {
            let resp = state.validator_pool.process_mark_claimed(req);
            let reply = WireMessage::MarkValidatorEarningsClaimedResponse(resp);
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        // Responses arriving at a node (e.g. echoed during gossip) — no-op.
        WireMessage::QueryTxidResponse(_)
        | WireMessage::RegisterChequeClaimResponse(_)
        | WireMessage::RegisterClaraResponse(_)
        | WireMessage::QueryWalletStateResponse(_)
        | WireMessage::FactConfirmResponse(_)
        | WireMessage::FactConfirmMismatch(_)
        | WireMessage::FactConfirmRejected(_)
        | WireMessage::PulseProofResponse(_)
        | WireMessage::PulseProofRejected(_)
        | WireMessage::JfpSecretResponse(_)
        | WireMessage::JfpSecretRejected(_)
        | WireMessage::JfpSecretsResponse(_)
        | WireMessage::BridgeResponse(_)
        | WireMessage::BridgeRejected(_)
        | WireMessage::EndorseBanChallengeResponse(_)
        | WireMessage::EndorseBanChallengeRejected(_)
        | WireMessage::ChallengeBanResponse(_)
        | WireMessage::QueryValidatorEarningsResponse(_)
        | WireMessage::RegisterValidatorPoolResponse(_)
        | WireMessage::QueryValidatorPoolResponse(_)
        | WireMessage::MarkValidatorEarningsClaimedResponse(_) => {}

        WireMessage::TardisAttachRequest { node_id, address, has_children, prefer_writer, nbc_bytes } => {
            // Response destination: use the requester's self-reported listening
            // address, not envelope.peer (which is the TCP ephemeral source port
            // in TCP mode and would fail to deliver the response).
            let reply_to = to_socket_addr(address);

            // ── NBC verification ──
            if let Err(reason) = state.verify_peer_nbc(nbc_bytes, node_id) {
                warn!("NBC REJECT TardisAttachRequest from {:02x}{:02x}...: {}",
                    node_id[0], node_id[1], reason);
                outbound.push((
                    reply_to,
                    WireMessage::NbcReject { reason },
                ));
                return outbound;
            }

            // A node is asking to attach as our downstream child.
            let now_secs = state.virtual_secs;

            // Learn about this peer regardless
            let dc = state.core.tardis().unwrap().downstream_count();
            state.core.mesh_mut().unwrap().note_peer(*node_id, address.clone(), now_secs);

            // Check if we can accept them as a D child
            // If prefer_writer is set, only accept if we have dc=1 (accepting makes us dc=2 = writer)
            let writer_ok = !prefer_writer || dc == 1;
            let can_accept = state.core.tardis().unwrap().has_d_open()
                && writer_ok
                && *node_id != state.node_id
                && state.core.tardis().unwrap().upstream().is_none_or(|up| *up != *node_id); // cycle prevention

            if can_accept {
                // Accept: add them as downstream
                let accepted = state.core.tardis_mut().unwrap().add_downstream(*node_id);
                if accepted {
                    // Give the new child a grace period for approval tracking
                    if state.core.tardis().unwrap().d1() == Some(node_id) {
                        state.d1_last_approval_secs = now_secs;
                    } else if state.core.tardis().unwrap().d2() == Some(node_id) {
                        state.d2_last_approval_secs = now_secs;
                    }
                    // Add to mesh so we can route ticks to them
                    state.core.mesh_mut().unwrap().upsert_peer_self_announced(PeerInfo {
                        node_id: *node_id,
                        address: address.clone(),
                        last_seen: now_secs,
                        tardis_up: Some(state.node_id),
                        has_d_open: false,
                        open_slots: 0,
                        messages_delivered: 0,
                        connected_since: now_secs,
            txid_service: String::new(),
                    });
                    outbound.push((
                        reply_to,
                        WireMessage::TardisAttachResponse {
                            node_id: state.node_id,
                            accepted: true,
                            downstream_count: state.core.tardis().unwrap().downstream_count(),
                            referrals: vec![],
                            nbc_bytes: state.own_nbc_bytes.clone(),
                        },
                    ));
                    // Broadcast updated SlotAvailable so the prefer-dc=1
                    // rebalance at peers can see fresh data. Sends 0 when
                    // we just hit dc=2 (= "now full"), or 1 when dc=1 (=
                    // "attach to me to make me a writer").
                    let new_dc = state.core.tardis().unwrap().downstream_count();
                    let open_slots = (2_u8).saturating_sub(new_dc as u8);
                    let hint = axiom_nabla::types::TopologyHint::SlotAvailable {
                        node_id: state.node_id,
                        address: state.core.mesh().unwrap().my_address().clone(),
                        open_slots,
                    };
                    let bcast = WireMessage::Gossip(GossipMessage::Topology(hint));
                    let targets: Vec<NodeId> = state.core.mesh().unwrap()
                        .discovery_hint_targets(&state.node_id);
                    for tid in targets {
                        if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&tid) {
                            outbound.push((to_socket_addr(&peer.address), bcast.clone()));
                        }
                    }
                } else {
                    // Slot race — someone else took it; send referrals
                    let referrals = build_referrals(state);
                    outbound.push((
                        reply_to,
                        WireMessage::TardisAttachResponse {
                            node_id: state.node_id,
                            accepted: false,
                            downstream_count: state.core.tardis().unwrap().downstream_count(),
                            referrals,
                            nbc_bytes: state.own_nbc_bytes.clone(),
                        },
                    ));
                }
            } else {
                // Reject: send referrals to peers that might have open slots.
                // GAP-03: If we have no pending peer, remember this one as P-slot.
                // When a D-slot opens, we'll promote them proactively.
                if state.core.tardis().unwrap().pending().is_none() {
                    state.core.tardis_mut().unwrap().set_pending(*node_id);
                    debug!("P-slot: queued {:02x}{:02x}... as pending (D-slots full)",
                        node_id[0], node_id[1]);
                }
                let referrals = build_referrals(state);
                outbound.push((
                    reply_to,
                    WireMessage::TardisAttachResponse {
                        node_id: state.node_id,
                        accepted: false,
                        downstream_count: state.core.tardis().unwrap().downstream_count(),
                        referrals,
                        nbc_bytes: state.own_nbc_bytes.clone(),
                    },
                ));
            }
        }

        WireMessage::TardisAttachResponse { node_id, accepted, downstream_count, referrals, nbc_bytes } => {
            let now_secs = state.virtual_secs;

            // Clear pending request — we got a response.
            state.pending_attach.remove(node_id);

            // Verify responder's NBC for mutual identity verification (N2 tick check).
            // Without this, ticks from the upstream would be rejected by the N2 check.
            if !nbc_bytes.is_empty() {
                if let Err(reason) = state.verify_peer_nbc(nbc_bytes, node_id) {
                    warn!("NBC REJECT TardisAttachResponse from {:02x}{:02x}...: {}",
                        node_id[0], node_id[1], reason);
                    return outbound;
                }
            }

            // Always update this peer's D-slot info from the response.
            // This is the freshest info we have — directly from the responder.
            if let Some(peer) = state.core.mesh_mut().unwrap().peer_by_id_mut(node_id) {
                peer.has_d_open = *downstream_count < 2;
                peer.open_slots = (2 - (*downstream_count).min(2)) as u8;
                peer.last_seen = now_secs;
            }

            if *accepted && state.core.tardis().unwrap().needs_parent() {
                // Accepted! Set this node as our upstream immediately.
                if let Some(old_up) = state.core.tardis().unwrap().upstream().cloned() {
                    if old_up != *node_id {
                        state.core.tardis_mut().unwrap().remove_peer(&old_up);
                    }
                }
                state.core.tardis_mut().unwrap().set_upstream(*node_id);
                // Sync tick to avoid stale-tick rejection
                let now_ms = state.virtual_ms;
                let prev_tick = now_secs.saturating_sub(TICK_INTERVAL_SECS);
                let prev_ms = now_ms.saturating_sub(TICK_INTERVAL_SECS * 1000);
                state.core.tardis_mut().unwrap().set_tick(prev_tick, prev_ms);
            } else if *accepted && !state.core.tardis().unwrap().needs_parent() {
                // Parent accepted us but we already have a parent — reject to free their D slot.
                // Use the peer's mesh address, not envelope.peer (TCP ephemeral port).
                let detach_addr = state.core.mesh().unwrap().peer_by_id(node_id)
                    .map(|p| to_socket_addr(&p.address))
                    .unwrap_or(envelope.peer);
                outbound.push((
                    detach_addr,
                    WireMessage::TardisDetach { node_id: state.node_id },
                ));
            } else if !accepted && state.core.tardis().unwrap().needs_parent() {
                // Rejected — learn referrals for next tick's attempt.
                // Referrals are SECOND-HAND (the parent's recorded view of
                // other nodes) — discovery-only, never overwrite addresses
                // we learned from the node itself.
                for peer in referrals {
                    state.core.mesh_mut().unwrap().note_peer_referral(peer.node_id, peer.address.clone(), now_secs);
                    state.core.mesh_mut().unwrap().add_peer_direct(peer.clone());
                }
            }
        }

        WireMessage::TardisDetach { node_id } => {
            let was_dc = state.core.tardis().unwrap().downstream_count();
            state.core.tardis_mut().unwrap().remove_peer(node_id);
            let now_dc = state.core.tardis().unwrap().downstream_count();

            // If we lost a child (dc dropped), broadcast updated SlotAvailable
            // so the prefer-dc=1 rebalance at peers can see fresh data.
            // Replaces the previous Hello-flood that only reached 5 random
            // peers and abused Hello semantically; this is the right
            // gossip variant + routes via discovery_hint_targets.
            if now_dc < was_dc && now_dc < 2 {
                let open_slots = (2_u8).saturating_sub(now_dc as u8);
                let hint = axiom_nabla::types::TopologyHint::SlotAvailable {
                    node_id: state.node_id,
                    address: state.core.mesh().unwrap().my_address().clone(),
                    open_slots,
                };
                let bcast = WireMessage::Gossip(GossipMessage::Topology(hint));
                let targets: Vec<NodeId> = state.core.mesh().unwrap()
                    .discovery_hint_targets(&state.node_id);
                for tid in targets {
                    if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&tid) {
                        outbound.push((to_socket_addr(&peer.address), bcast.clone()));
                    }
                }
            }

            // If we lost our parent (became orphan), start recovery immediately.
            // Two-pass writer preference: strict (dc=1 only) → relaxed (any open).
            // Uses pending_attach dedup to prevent duplicate requests.
            if state.core.tardis().unwrap().needs_parent() {
                let my_addr = state.core.mesh().unwrap().my_address().clone();
                let has_children = state.core.tardis().unwrap().downstream_count() > 0;
                let current_tick = state.virtual_secs;
                // Clear pending_attach — we just became orphan, fresh slate
                state.pending_attach.clear();
                // Spec §1.5 / §2.1: send TardisAttachRequest to "any known
                // node". The receiver decides accept/reject from its own
                // TARDIS state and answers with referrals on reject.
                // Referrals walk DOWN the tree (BFS E-enquiry, build_referrals
                // at line ~3546) and propagate discovery through a
                // TARDIS-internal signal. Gossip-declared slot/topology
                // fields (peer.tardis_up / has_d_open / open_slots) are not
                // consulted here — that would cross the layer boundary and
                // make TARDIS attach decisions sensitive to gossip staleness
                // (a dead-but-gossiped peer looks healthy → orphan picks it
                // → re-orphans → cascade).
                let mut sent = 0;
                for peer in state.core.mesh().unwrap().active_peers().to_vec() {
                    if peer.node_id == state.node_id || peer.node_id == *node_id { continue; }
                    if state.pending_attach.contains_key(&peer.node_id) { continue; }
                    if sent >= 3 { break; }
                    state.pending_attach.insert(peer.node_id, current_tick);
                    outbound.push((
                        to_socket_addr(&peer.address),
                        WireMessage::TardisAttachRequest {
                            node_id: state.node_id,
                            address: my_addr.clone(),
                            has_children,
                            prefer_writer: true,
                            nbc_bytes: state.own_nbc_bytes.clone(),
                        },
                    ));
                    sent += 1;
                }
            }
        }

        WireMessage::IntroductionRequest { from } => {
            // Peer exchange — respond with our known peers, including ourselves.
            // Include accurate TARDIS slot info so orphans can find parents.
            let now_secs = state.virtual_secs;
            let my_dc = state.core.tardis().unwrap().downstream_count();
            let mut peers: Vec<PeerInfo> = vec![
                // Include ourselves with accurate D-slot info
                PeerInfo {
                    node_id: state.node_id,
                    address: state.core.mesh().unwrap().my_address().clone(),
                    last_seen: now_secs,
                    tardis_up: state.core.tardis().unwrap().upstream().cloned(),
                    has_d_open: my_dc < 2,
                    open_slots: (2 - my_dc.min(2)) as u8,
                    messages_delivered: 0,
                    connected_since: now_secs,
            txid_service: String::new(),
                },
            ];
            // Add known peers
            for p in state.core.mesh().unwrap().active_peers().iter().take(9) {
                peers.push(p.clone());
            }
            // Reply on the inbound connection: the requester (bridge_core's
            // introduction exchange, peer discovery) holds it open for a
            // `read_exact`. `envelope.peer` is that connection's ephemeral
            // source port — unusable as a fresh destination — so it is only
            // a fallback for an already-closed reply stream.
            let reply = WireMessage::IntroductionResponse { peers };
            if transport::send_reply(envelope, &reply).is_err() {
                outbound.push((envelope.peer, reply));
            }
        }

        WireMessage::IntroductionResponse { peers } => {
            // Discovery-only: learn new peers; do NOT trigger TARDIS attach
            // from here. The introduction reveals who exists, not whether
            // they're a healthy attach target — that decision belongs to
            // the per-tick orphan-recovery path (Step 4 in tick_loop), which
            // sends TardisAttachRequest based on TARDIS-internal state.
            // Reading peer.has_d_open here to drive an attach would cross
            // the gossip → TARDIS layer boundary.
            let now_secs = state.virtual_secs;
            // SECOND-HAND peer exchange — discovery-only inserts; a relayed
            // address may be stale and must not clobber first-hand entries.
            for peer in peers {
                state.core.mesh_mut().unwrap().note_peer_referral(peer.node_id, peer.address.clone(), now_secs);
                state.core.mesh_mut().unwrap().add_peer_direct(peer.clone());
            }
        }

        WireMessage::Ping { from, nonce } => {
            // §6.3.7: echo a Pong to the pinger's LISTENING address so it can
            // time the round-trip. Mesh-local latency probe — never a fact.
            let pong = WireMessage::Pong { from: state.node_id, nonce: *nonce };
            match state.core.mesh().unwrap().peer_by_id(from) {
                Some(peer) => outbound.push((to_socket_addr(&peer.address), pong)),
                None => {
                    // Unknown sender + no listening address — best-effort reply
                    // on the inbound stream; if that fails they re-learn via Hello.
                    let _ = transport::send_reply(envelope, &pong);
                }
            }
        }

        WireMessage::Pong { from, nonce } => {
            // §6.3.7: match the nonce, compute RTT, feed the mesh latency
            // scorer (drives latency-aware peer pruning, Step 5b).
            if let Some((peer, sent_at)) = state.pending_pings.remove(nonce) {
                if peer == *from {
                    let rtt_ms = sent_at.elapsed().as_secs_f32() * 1000.0;
                    log::debug!("[pong] from {:02x}{:02x}.. rtt {:.0}ms", from[0], from[1], rtt_ms);
                    state.core.mesh_mut().unwrap().record_peer_rtt(*from, rtt_ms);
                }
            }
        }

        WireMessage::StatusRequest => {
            // Status query — respond with TARDIS metrics.
            // Reply on the same TCP connection if available (the caller may
            // not have a listener). Falls back to outbound for stdio mode.
            #[cfg(feature = "dev-status")]
            let persist_stats = state.core.persistence_stats();
            let response = WireMessage::StatusResponse {
                node_id: state.node_id,
                node_name: state.node_name.clone(),
                needs_parent: state.core.tardis().unwrap().needs_parent(),
                downstream_count: state.core.tardis().unwrap().downstream_count(),
                is_leaf: state.core.tardis().unwrap().is_leaf(),
                has_d_open: state.core.tardis().unwrap().has_d_open(),
                alive: true,
                smt_len: state.core.smt().len(),
                peer_count: state.core.mesh().unwrap().peer_count(),
                #[cfg(feature = "dev-status")]
                tardis_tick: state.core.tardis().unwrap().current_tick(),
                #[cfg(not(feature = "dev-status"))]
                tardis_tick: 0,
                #[cfg(feature = "dev-status")]
                root_hash: state.core.smt().root_hash(),
                #[cfg(not(feature = "dev-status"))]
                root_hash: [0; 32],
                #[cfg(feature = "dev-status")]
                messages_received: state.messages_received,
                #[cfg(not(feature = "dev-status"))]
                messages_received: 0,
                #[cfg(feature = "dev-status")]
                upstream_id: state.core.tardis().unwrap().upstream().copied(),
                #[cfg(not(feature = "dev-status"))]
                upstream_id: None,
                #[cfg(feature = "dev-status")]
                d1_id: state.core.tardis().unwrap().d1().copied(),
                #[cfg(not(feature = "dev-status"))]
                d1_id: None,
                #[cfg(feature = "dev-status")]
                d2_id: state.core.tardis().unwrap().d2().copied(),
                #[cfg(not(feature = "dev-status"))]
                d2_id: None,
                #[cfg(feature = "dev-status")]
                d1_approved: state.core.tardis().unwrap().d1().is_some() && state.core.tardis().unwrap().downstream_count() >= 1,
                #[cfg(not(feature = "dev-status"))]
                d1_approved: false,
                #[cfg(feature = "dev-status")]
                d2_approved: state.core.tardis().unwrap().d2().is_some() && state.core.tardis().unwrap().downstream_count() >= 2,
                #[cfg(not(feature = "dev-status"))]
                d2_approved: false,
                #[cfg(feature = "dev-status")]
                known_nodes: state.core.mesh().unwrap().known_node_count(),
                #[cfg(not(feature = "dev-status"))]
                known_nodes: 0,
                #[cfg(feature = "dev-status")]
                gossip_active: state.last_gossip_tick >= state.core.tardis().unwrap().current_tick().saturating_sub(2),
                #[cfg(not(feature = "dev-status"))]
                gossip_active: false,
                // Persistence metrics — collected once to avoid repeated stat() calls
                #[cfg(feature = "dev-status")]
                wal_file_bytes: persist_stats.wal_file_bytes,
                #[cfg(not(feature = "dev-status"))]
                wal_file_bytes: 0,
                #[cfg(feature = "dev-status")]
                wal_ops_since_snapshot: persist_stats.wal_ops_since_snapshot,
                #[cfg(not(feature = "dev-status"))]
                wal_ops_since_snapshot: 0,
                #[cfg(feature = "dev-status")]
                snapshot_count: persist_stats.snapshot_count,
                #[cfg(not(feature = "dev-status"))]
                snapshot_count: 0,
                #[cfg(feature = "dev-status")]
                snapshot_total_bytes: persist_stats.snapshot_total_bytes,
                #[cfg(not(feature = "dev-status"))]
                snapshot_total_bytes: 0,
                #[cfg(feature = "dev-status")]
                last_snapshot_tick: persist_stats.last_snapshot_tick,
                #[cfg(not(feature = "dev-status"))]
                last_snapshot_tick: 0,
                #[cfg(feature = "dev-status")]
                total_disk_bytes: persist_stats.total_disk_bytes,
                #[cfg(not(feature = "dev-status"))]
                total_disk_bytes: 0,
                #[cfg(feature = "dev-status")]
                smt_memory_bytes: persist_stats.smt_memory_bytes,
                #[cfg(not(feature = "dev-status"))]
                smt_memory_bytes: 0,
                nbc_issuer: state.nbc_issuer.clone(),
            };
            // Try reply on same connection first (TCP external queries).
            // Fall back to outbound (stdio mode / known peers).
            if transport::send_reply(envelope, &response).is_err() {
                outbound.push((envelope.peer, response));
            }
        }

        WireMessage::NbcReject { reason } => {
            warn!("Peer rejected our NBC: {}", reason);
        }

        WireMessage::NablaJoinRequest { nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig } => {
            let (accepted, reason, probation_until, gossip_msg) =
                state.handle_join_request(nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig);

            outbound.push((
                envelope.peer,
                WireMessage::NablaJoinResponse {
                    accepted,
                    reason,
                    probation_until,
                },
            ));

            // If accepted, gossip the NablaIdAnnounce for duplicate detection
            if let Some(announce) = gossip_msg {
                let gossip_wire = WireMessage::Gossip(announce);
                for peer in state.core.mesh().unwrap().active_peers() {
                    let peer_addr = axiom_nabla::transport::to_socket_addr(&peer.address);
                    if peer_addr != envelope.peer {
                        outbound.push((peer_addr, gossip_wire.clone()));
                    }
                }
            }
        }

        WireMessage::NablaJoinResponse { accepted, reason, .. } => {
            if *accepted {
                info!("Join request accepted by peer");
            } else {
                warn!("Join request rejected: {}", reason);
            }
        }

        WireMessage::NbcIssuanceRequest { sphincs_pk, ed25519_pk, dilithium_pk, node_name } => {
            let (accepted, nbc_bytes, supporting_chain_bytes, rejection_reason) =
                state.handle_nbc_issuance_request(sphincs_pk, ed25519_pk, dilithium_pk, node_name);
            outbound.push((
                envelope.peer,
                WireMessage::NbcIssuanceResponse {
                    accepted,
                    nbc_bytes,
                    supporting_chain_bytes,
                    rejection_reason,
                },
            ));
        }

        WireMessage::NbcIssuanceResponse { accepted, nbc_bytes, supporting_chain_bytes, rejection_reason } => {
            if *accepted {
                info!("NBC issuance response: accepted ({} bytes)", nbc_bytes.len());
            } else {
                warn!("NBC issuance response: rejected ({})", rejection_reason);
            }
            // Actual handling is in the startup path (Phase 5) — the response is
            // consumed by the blocking issuance request loop, not by recv_loop.
        }

        // ── NBC Renewal ──
        WireMessage::NbcRenewRequest { current_nbc_bytes, renewal_sig, current_time } => {
            let (accepted, nbc_bytes, supporting_chain_bytes, rejection_reason) =
                state.handle_nbc_renewal_request(current_nbc_bytes, renewal_sig, *current_time);
            outbound.push((
                envelope.peer,
                WireMessage::NbcRenewResponse {
                    accepted,
                    nbc_bytes,
                    supporting_chain_bytes,
                    rejection_reason,
                },
            ));
        }

        WireMessage::NbcRenewResponse { accepted, nbc_bytes, supporting_chain_bytes, rejection_reason } => {
            if *accepted {
                info!("NBC renewal response: accepted ({} bytes)", nbc_bytes.len());
                // Deserialize and install renewed NBC
                if let Ok(nbc) = bincode::deserialize::<NBC>(nbc_bytes) {
                    if let Ok(supporting) = bincode::deserialize::<Vec<NBC>>(supporting_chain_bytes) {
                        state.install_renewed_nbc(nbc, supporting);
                    }
                }
            } else {
                warn!("NBC renewal response: rejected ({})", rejection_reason);
            }
        }

        // ── S6: Ban Challenge Protocol ──
        WireMessage::BanChallenge { wallet_id, evidence } => {
            let tick = state.core.current_tick();
            let result = state.core.challenge_ban(wallet_id, evidence.clone(), tick);
            match result {
                Ok(()) => {
                    info!("S6: Ban challenge ACCEPTED for {:02x}{:02x}...",
                        wallet_id[0], wallet_id[1]);
                    // Reply to challenger
                    outbound.push((
                        envelope.peer,
                        WireMessage::BanChallengeResult {
                            wallet_id: *wallet_id,
                            accepted: true,
                            reason: String::new(),
                        },
                    ));
                    // Gossip BanChallenged to mesh
                    let gossip = WireMessage::Gossip(GossipMessage::BanChallenged {
                        wallet_id: *wallet_id,
                        evidence: evidence.clone(),
                        challenge_tick: tick,
                    });
                    if let Some(mesh) = state.core.mesh() {
                        for target_id in mesh.forward_targets(&state.node_id) {
                            if let Some(peer) = mesh.peer_by_id(&target_id) {
                                outbound.push((to_socket_addr(&peer.address), gossip.clone()));
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("S6: Ban challenge REJECTED for {:02x}{:02x}...: {}",
                        wallet_id[0], wallet_id[1], e);
                    outbound.push((
                        envelope.peer,
                        WireMessage::BanChallengeResult {
                            wallet_id: *wallet_id,
                            accepted: false,
                            reason: e.to_string(),
                        },
                    ));
                }
            }
        }

        WireMessage::BanChallengeResult { wallet_id, accepted, reason } => {
            if *accepted {
                info!("S6: Ban challenge result: ACCEPTED for {:02x}{:02x}...",
                    wallet_id[0], wallet_id[1]);
            } else {
                warn!("S6: Ban challenge result: REJECTED for {:02x}{:02x}...: {}",
                    wallet_id[0], wallet_id[1], reason);
            }
        }

        // ── YPX-009 §12.8: StatePull ──
        WireMessage::StatePullRequest { mode, our_root_hash, from_tick, to_tick, section_hash } => {
            use axiom_nabla::types::{StatePullMode, StatePullEntry, WalVerifyResult};
            use axiom_nabla::constants::STATE_PULL_MAX_BYTES;

            match mode {
                StatePullMode::Bootstrap => {
                    // Serve entries from SMT in the requested tick range, capped at 5MB.
                    let mut entries = Vec::new();
                    let mut bytes_total = 0usize;
                    let mut highest_tick = 0u64;
                    for entry in state.core.smt().entries().values() {
                        if entry.tick >= *from_tick && entry.tick < *to_tick {
                            let entry_size = std::mem::size_of::<StatePullEntry>() + entry.client_sig.len();
                            if bytes_total + entry_size > STATE_PULL_MAX_BYTES {
                                break;
                            }
                            bytes_total += entry_size;
                            if entry.tick > highest_tick {
                                highest_tick = entry.tick;
                            }
                            entries.push(StatePullEntry {
                                wallet_id: entry.wallet_id,
                                new_state: entry.current_state,
                                tx_hash: entry.tx_hash,
                                tick: entry.tick,
                                wallet_seq: entry.wallet_seq, // WI3: carry k-seq to bootstrappers
                                client_pk: entry.client_pk,
                                client_sig: entry.client_sig.clone(),
                                // WI3 hole-1: carry the seq attestation so the
                                // bootstrapper adopts a VERIFIED seq.
                                seq_proof: state.core.smt().seq_proof(&entry.wallet_id).cloned(),
                            });
                        }
                    }
                    let available_from = state.core.smt().entries().values()
                        .map(|e| e.tick)
                        .min()
                        .unwrap_or(0);
                    let resp = WireMessage::StatePullResponse {
                        mode: StatePullMode::Bootstrap,
                        entries,
                        highest_tick_served: highest_tick,
                        // WI1 (§5.2): hand the recovering node our anti-rollback
                        // view so it re-arms instead of coming back blind.
                        consumed_bloom: state.core.smt().consumed_bloom_bytes(),
                        previous_states: state.core.smt().previous_states_snapshot(),
                        verify_result: None,
                        available_from_tick: available_from,
                        overloaded: false,
                    };
                    if transport::send_reply(envelope, &resp).is_err() {
                        outbound.push((envelope.peer, resp));
                    }
                }
                StatePullMode::WalVerify => {
                    // Compare WAL section hash for peer cross-verification.
                    let our_section = state.core.wal().section_hash(*from_tick, *to_tick);
                    let result = match section_hash {
                        Some(their_hash) if *their_hash == our_section => WalVerifyResult::Match,
                        Some(_) => WalVerifyResult::Mismatch,
                        None => WalVerifyResult::Missing,
                    };
                    let resp = WireMessage::StatePullResponse {
                        mode: StatePullMode::WalVerify,
                        entries: vec![],
                        highest_tick_served: 0,
                        consumed_bloom: Vec::new(), // WI1: WAL-verify carries no recovery state
                        previous_states: Vec::new(),
                        verify_result: Some(result),
                        available_from_tick: 0,
                        overloaded: false,
                    };
                    if transport::send_reply(envelope, &resp).is_err() {
                        outbound.push((envelope.peer, resp));
                    }
                }
            }
        }

        WireMessage::StatePullResponse { mode, entries, highest_tick_served, consumed_bloom, previous_states, verify_result, available_from_tick, overloaded } => {
            use axiom_nabla::types::{StatePullMode, WalVerifyResult};

            // AUDIT-FIX v2.11.14: Use metadata fields for adaptive sync decisions.
            // Previously available_from_tick and overloaded were carried but ignored.
            if *overloaded {
                warn!("StatePull peer reports OVERLOADED — will back off and try a different peer next cycle");
                // Don't process entries from overloaded peers — data may be incomplete
                return outbound;
            }
            match mode {
                StatePullMode::Bootstrap => {
                    // AUDIT-FIX v2.11.14: Use available_from_tick for request shaping.
                    // If peer reports data availability starts later than our request range,
                    // log the gap and record it so future requests can skip the empty range.
                    if *available_from_tick > 0 {
                        let our_latest = state.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
                        if *available_from_tick > our_latest / 2 {
                            warn!("StatePull peer only has data from tick {} — peer has partial history. \
                                   Consider requesting from a different peer for ticks < {}.",
                                available_from_tick, available_from_tick);
                        } else {
                            debug!("StatePull peer available_from_tick={}", available_from_tick);
                        }
                        // Store the hint so WalVerify doesn't request ticks before this
                        state.peer_available_from_tick = *available_from_tick;
                    }
                    // WI1 (§5.2): re-arm the anti-rollback view BEFORE adopting any
                    // head, so the consume-once gate (is_state_consumed) is live the
                    // instant the heads land. UNION-merge the peer's consumed-bloom +
                    // previous_states — a state stays consumed if ANY honest peer says
                    // so, so an attacker peer's empty/forged view can't disarm us.
                    if !consumed_bloom.is_empty() || !previous_states.is_empty() {
                        if let Err(e) = state.core.smt_mut().merge_consumed_bloom(consumed_bloom) {
                            warn!("StatePull: consumed-bloom merge failed ({e}) — \
                                   anti-rollback view may be incomplete this round");
                        }
                        state.core.smt_mut().merge_previous_states(previous_states);
                        info!("StatePull bootstrap: re-armed anti-rollback (bloom {} B, {} previous_states)",
                            consumed_bloom.len(), previous_states.len());
                    }
                    info!("StatePull bootstrap: received {} entries (up to tick {})",
                        entries.len(), highest_tick_served);
                    for entry in entries {
                        let gossip_msg = GossipMessage::StateUpdate {
                            wallet_id: entry.wallet_id,
                            new_state: entry.new_state,
                            tx_hash: entry.tx_hash,
                            tick: entry.tick,
            is_genesis_claim: false,
                            wallet_seq: entry.wallet_seq, // WI3: replicate the entry's k-seq
                            client_pk: entry.client_pk,
                            client_sig: entry.client_sig.clone(),
                            amount: 0,
                            fee_breakdown: Vec::new(),
                            // WI3 hole-1: replay the carried proof so the merge gate
                            // can verify the seq before this node adopts it.
                            seq_proof: entry.seq_proof.clone(),
                        };
                        let _ = state.core.handle_gossip(&gossip_msg);
                    }
                }
                StatePullMode::WalVerify => {
                    match verify_result {
                        Some(WalVerifyResult::Match) => {
                            debug!("WAL peer verify: section matches");
                        }
                        Some(WalVerifyResult::Mismatch) => {
                            // AUDIT-FIX v2.11.14: Actually initiate RangeSync on mismatch.
                            // Previously logged intent but never sent RangeSyncRequest.
                            warn!("WAL peer verify: section MISMATCH — sending RangeSyncRequest to {:?}", envelope.peer);
                            let our_tick = state.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
                            let section_size = axiom_nabla::constants::RANGE_SYNC_SECTION_SIZE;
                            // Request the section we just verified as mismatched
                            // Use highest_tick_served as the section start (that's what was compared)
                            let from = highest_tick_served.saturating_sub(section_size);
                            let our_section_hash = state.core.wal().section_hash(from, from + section_size);
                            outbound.push((envelope.peer, WireMessage::RangeSyncRequest {
                                from_tick: from,
                                record_count: section_size,
                                section_hash: our_section_hash,
                                our_latest_tick: our_tick,
                            }));
                        }
                        Some(WalVerifyResult::Missing) | None => {
                            debug!("WAL peer verify: peer has no data for this section");
                        }
                    }
                }
            }
        }

        // ── YPX-009 §12.8: RangeSync ──
        WireMessage::RangeSyncRequest { from_tick, record_count, section_hash, our_latest_tick } => {
            use axiom_nabla::types::{RangeSyncMatch, StatePullEntry};
            use axiom_nabla::constants::RANGE_SYNC_MAX_TRANSFER_BYTES;

            // Compare our section hash for the requested range
            let our_hash = state.core.wal().section_hash(*from_tick, from_tick + record_count);
            let match_result = if our_hash == *section_hash {
                RangeSyncMatch::Match
            } else {
                RangeSyncMatch::Mismatch
            };

            // On mismatch, collect entries we have in this range for gap fill
            let mut missing_entries = Vec::new();
            if matches!(match_result, RangeSyncMatch::Mismatch) {
                let mut bytes_total = 0usize;
                for entry in state.core.smt().entries().values() {
                    if entry.tick >= *from_tick && entry.tick < from_tick + record_count {
                        let entry_size = std::mem::size_of::<StatePullEntry>() + entry.client_sig.len();
                        if bytes_total + entry_size > RANGE_SYNC_MAX_TRANSFER_BYTES {
                            break;
                        }
                        bytes_total += entry_size;
                        missing_entries.push(StatePullEntry {
                            wallet_id: entry.wallet_id,
                            new_state: entry.current_state,
                            tx_hash: entry.tx_hash,
                            tick: entry.tick,
                            wallet_seq: entry.wallet_seq, // WI3: carry k-seq to bootstrappers
                            client_pk: entry.client_pk,
                            client_sig: entry.client_sig.clone(),
                            // WI3 hole-1: carry the seq attestation for gap-fill.
                            seq_proof: state.core.smt().seq_proof(&entry.wallet_id).cloned(),
                        });
                    }
                }
            }

            let peer_tick = state.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
            let resp = WireMessage::RangeSyncResponse {
                match_result,
                missing_entries,
                peer_latest_tick: peer_tick,
                peer_section_hash: our_hash,
            };
            if transport::send_reply(envelope, &resp).is_err() {
                outbound.push((envelope.peer, resp));
            }
        }

        WireMessage::RangeSyncResponse { match_result, missing_entries, peer_latest_tick, peer_section_hash } => {
            use axiom_nabla::types::RangeSyncMatch;
            match match_result {
                RangeSyncMatch::Match => {
                    debug!("RangeSync: section matches peer");
                }
                RangeSyncMatch::Mismatch => {
                    info!("RangeSync: received {} gap-fill entries from peer", missing_entries.len());
                    // Apply missing entries — never overwrite existing valid signed records (fill gaps only)
                    for entry in missing_entries {
                        // Only apply if we don't already have this wallet's state at this tick
                        if let Some(existing) = state.core.smt().get(&entry.wallet_id) {
                            if existing.tick >= entry.tick {
                                continue; // We already have equal or newer state
                            }
                        }
                        let gossip_msg = GossipMessage::StateUpdate {
                            wallet_id: entry.wallet_id,
                            new_state: entry.new_state,
                            tx_hash: entry.tx_hash,
                            tick: entry.tick,
            is_genesis_claim: false,
                            wallet_seq: entry.wallet_seq, // WI3: replicate the entry's k-seq
                            client_pk: entry.client_pk,
                            client_sig: entry.client_sig.clone(),
                            amount: 0,
                            fee_breakdown: Vec::new(),
                            // WI3 hole-1: replay the carried proof so the merge gate
                            // can verify the seq before this node adopts it.
                            seq_proof: entry.seq_proof.clone(),
                        };
                        let _ = state.core.handle_gossip(&gossip_msg);
                    }
                }
                RangeSyncMatch::Missing => {
                    debug!("RangeSync: peer missing this section entirely");
                }
            }
        }

        // ── Anti-entropy step 3: AeDigest ──
        // We are the TickHash originator; the peer replied with its full
        // leaf-hash digest. Diff it against ours: push the entries we hold
        // that the peer differs on / lacks, and request the converse.
        // AXIOM_DESIGN_NablaAntiEntropy.md §5.4.
        WireMessage::AeDigest { from, leaves: peer_leaves } => {
            let peer_map: HashMap<[u8; 32], [u8; 32]> =
                peer_leaves.iter().copied().collect();
            let our_map: HashMap<[u8; 32], [u8; 32]> =
                state.core.smt().leaf_digest().into_iter().collect();

            let mut push = Vec::new();
            for (wid, our_hash) in &our_map {
                if peer_map.get(wid) != Some(our_hash) {
                    if let Some(entry) = state.core.smt().get(wid) {
                        // WI3 hole-1: carry the k=3 seq attestation alongside the
                        // entry so the peer can verify the seq it adopts.
                        let proof = state.core.smt().seq_proof(wid).cloned();
                        push.push((entry.clone(), proof));
                    }
                }
            }
            let mut pull = Vec::new();
            for (wid, peer_hash) in &peer_map {
                if our_map.get(wid) != Some(peer_hash) {
                    pull.push(*wid);
                }
            }
            if !push.is_empty() || !pull.is_empty() {
                let peer_addr = state.core.mesh().unwrap()
                    .peer_by_id(from)
                    .map(|p| to_socket_addr(&p.address));
                if let Some(addr) = peer_addr {
                    info!("Anti-entropy: reconcile — push {} pull {}", push.len(), pull.len());
                    outbound.push((addr, WireMessage::AeReconcile {
                        from: state.node_id,
                        push,
                        pull,
                    }));
                }
            }
        }

        // ── Anti-entropy step 4: AeReconcile ──
        // The peer pushed entries it wins on and requested entries it lacks.
        // Apply each push through the merge rule; return the requested pulls.
        WireMessage::AeReconcile { from, push, pull } => {
            let mut applied = 0usize;
            for (entry, proof) in push {
                if state.core.apply_remote_entry(entry, proof.as_ref()) {
                    applied += 1;
                }
            }
            let mut entries = Vec::new();
            for wid in pull {
                if let Some(e) = state.core.smt().get(wid) {
                    // WI3 hole-1: re-attach the seq attestation for the pulled head.
                    let proof = state.core.smt().seq_proof(wid).cloned();
                    entries.push((e.clone(), proof));
                }
            }
            if applied > 0 {
                info!("Anti-entropy: applied {applied} entries from peer reconcile");
            }
            if !entries.is_empty() {
                let peer_addr = state.core.mesh().unwrap()
                    .peer_by_id(from)
                    .map(|p| to_socket_addr(&p.address));
                if let Some(addr) = peer_addr {
                    outbound.push((addr, WireMessage::AeEntries { entries }));
                }
            }
        }

        // ── Anti-entropy step 5: AeEntries ──
        // The peer returned the entries we requested. Apply via the merge rule.
        WireMessage::AeEntries { entries } => {
            let mut applied = 0usize;
            for (entry, proof) in entries {
                if state.core.apply_remote_entry(entry, proof.as_ref()) {
                    applied += 1;
                }
            }
            if applied > 0 {
                info!("Anti-entropy: applied {applied} pulled entries from peer");
            }
        }

        // Ignore unrecognized variants gracefully (StatusResponse, etc.)
        _ => {}
    }

    // ── DRAIN-DEC ── decrement client_inflight if this was a client
    // request (set at the top of the function). Pairs with the
    // increment above; the Draining → Cooldown transition in the
    // tick_loop fires when this reaches 0.
    if was_client {
        state.client_inflight = state.client_inflight.saturating_sub(1);
    }

    outbound
}

/// Build referral list for a rejected TardisAttachRequest.
/// Prioritizes TARDIS children (walks DOWN the tree like BFS E-enquiry)
/// then dc=1 peers (attaching there creates writers).
fn build_referrals(state: &NablaNodeState) -> Vec<PeerInfo> {
    let now_secs = state.virtual_secs;
    let mut referrals: Vec<PeerInfo> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Priority 1: Our own TARDIS children — walks DOWN the tree.
    // This mimics E-enquiry BFS: full node → try my children → their children etc.
    for child_id in state.core.tardis().unwrap().children() {
        if referrals.len() >= 10 { break; }
        if child_id == state.node_id || seen.contains(&child_id) { continue; }
        if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&child_id) {
            seen.insert(child_id);
            referrals.push(peer.clone());
        }
    }

    // Priority 2: Peers we know have open D slots (dc=1 preferred — creates writers)
    for p in state.core.mesh().unwrap().active_peers() {
        if referrals.len() >= 10 { break; }
        if p.node_id == state.node_id || seen.contains(&p.node_id) { continue; }
        if p.has_d_open && p.open_slots == 1 { // dc=1 → writer if filled
            seen.insert(p.node_id);
            referrals.push(p.clone());
        }
    }

    // Priority 3: Any peer with open D slots
    for p in state.core.mesh().unwrap().active_peers() {
        if referrals.len() >= 10 { break; }
        if p.node_id == state.node_id || seen.contains(&p.node_id) { continue; }
        if p.has_d_open {
            seen.insert(p.node_id);
            referrals.push(p.clone());
        }
    }

    // Priority 4: Tick piggyback slots
    for (peer_id, _slots) in state.core.tardis().unwrap().available_slots() {
        if referrals.len() >= 10 { break; }
        if seen.contains(&peer_id) { continue; }
        if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&peer_id) {
            seen.insert(peer_id);
            referrals.push(PeerInfo {
                node_id: peer_id,
                address: peer.address.clone(),
                last_seen: now_secs,
                tardis_up: None,
                has_d_open: true,
                open_slots: 1,
                messages_delivered: 0,
                connected_since: now_secs,
            txid_service: String::new(),
            });
        }
    }

    referrals
}

/// Try to find a node ID from a socket address by scanning mesh peers.
fn peer_id_from_addr(addr: &std::net::SocketAddr, mesh: &GossipMesh) -> Option<NodeId> {
    let nabla_addr = from_socket_addr(*addr);
    for peer in mesh.active_peers() {
        if peer.address == nabla_addr {
            return Some(peer.node_id);
        }
    }
    None
}

// ── Tick Loop ──

/// Main tick loop: generate ticks, process approvals, run mesh maintenance.
///
/// This mirrors exactly what the simulator does, but with real network I/O
/// instead of simulated message passing. All protocol decisions come from
/// the library (tardis.rs, mesh.rs) — this function only orchestrates.
fn tick_loop(
    state: Arc<Mutex<NablaNodeState>>,
    transport: Arc<dyn Transport>,
    tick_ms: u64,
    epoch_ms: u64,
    http_outbound: Arc<Mutex<Vec<(std::net::SocketAddr, WireMessage)>>>,
) {
    let tick_duration = Duration::from_millis(tick_ms);
    let mut tick_count: u64 = 0;

    // Sim mode (epoch_ms > 0): virtual_time = epoch + elapsed_real * scale.
    // All nodes share the same epoch_ms, so they compute the same virtual
    // time at the same real instant regardless of when they were spawned.
    // Production (epoch_ms == 0): use real unix time (no scaling).
    let sim_mode = epoch_ms > 0;
    let time_scale = (TICK_INTERVAL_SECS * 1000) / tick_ms.max(1);

    while !SHUTDOWN.load(std::sync::atomic::Ordering::Relaxed) {
        let tick_start = Instant::now();

        let outbound = {
            let mut node = state.lock().unwrap();

            let (now_secs, now_ms) = if sim_mode {
                let real_now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let elapsed_real_ms = real_now_ms.saturating_sub(epoch_ms);
                let virtual_elapsed_ms = elapsed_real_ms * time_scale;
                let ms = epoch_ms + virtual_elapsed_ms;
                (ms / 1000, ms)
            } else {
                let secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                (secs, ms)
            };
            node.virtual_secs = now_secs;
            node.virtual_ms = now_ms;

            let mut outbound: Vec<(std::net::SocketAddr, WireMessage)> = Vec::new();

            // ── Step 0: Drain pending inbound messages (BOUNDED) ──
            // Process messages that arrived since last tick BEFORE advancing
            // protocol state, so approvals aren't missed by set_tick().
            //
            // BOUNDED per tick (KI#32-followup, soak s2r93186): an unbounded
            // drain holds the single global state lock for the entire batch.
            // Under a PoolSync flood (peers whose NBC didn't resolve → ~15k
            // dropped-but-still-processed messages) that lock-hold ran for
            // seconds, starving recv_loop's client query-txid past the SDK's
            // 5s timeout → the SDK shipped attestation-less redeems → every
            // validator rejected (E_TXID_ATTESTATION_MISSING → soak fail-rate
            // climbing). Capping the per-tick drain bounds the lock-hold so
            // recv_loop interleaves and answers queries promptly; recv_loop
            // (which locks per-message, releasing between) drains the
            // remainder. No message is dropped — only deferred to recv_loop /
            // the next tick.
            const MAX_DRAIN_PER_TICK: usize = 256;
            let mut drained = 0usize;
            while drained < MAX_DRAIN_PER_TICK {
                match transport.try_recv() {
                    Some(envelope) => {
                        let responses = handle_message(&mut node, &envelope);
                        outbound.extend(responses);
                        drained += 1;
                    }
                    None => break,
                }
            }

            // ── Step 0.5: Phase B Layer 4 — sweep expired quarantines + stale pending alerts ──
            // Runs once per tick. Idempotent, no-op when nothing expires.
            node.core.quarantine_sweep();

            // ── Step 0.6: Periodic pool-state heartbeat ──
            // PoolSync is otherwise event-driven (only fires on a claim).
            // A peer that missed an event — quarantined and returned, or
            // briefly disconnected — would stay out of sync until a NEW
            // claim happened. Heartbeat every POOL_SYNC_HEARTBEAT_TICKS
            // closes that gap: each Nabla re-broadcasts its current
            // pool state; receivers reconcile via min-balance-wins.
            if now_secs.saturating_sub(node.last_pool_heartbeat_tick)
                >= axiom_nabla::constants::POOL_SYNC_HEARTBEAT_TICKS * axiom_nabla::constants::TICK_INTERVAL_SECS
            {
                node.last_pool_heartbeat_tick = now_secs;
                use axiom_nabla::types::PoolKind;
                let our_id = node.node_id;
                let airdrop_msg =
                    WireMessage::Gossip(node.core.pool_sync_message(PoolKind::Airdrop));
                let dev_msg =
                    WireMessage::Gossip(node.core.pool_sync_message(PoolKind::DevTreasury));
                let deed_msg =
                    WireMessage::Gossip(node.core.pool_sync_message(PoolKind::Deed));
                let dev_deed_msg =
                    WireMessage::Gossip(node.core.pool_sync_message(PoolKind::DevDeed));
                for target_id in node.core.mesh().unwrap().forward_targets(&our_id) {
                    if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&target_id) {
                        let addr = to_socket_addr(&peer.address);
                        outbound.push((addr, airdrop_msg.clone()));
                        outbound.push((addr, dev_msg.clone()));
                        outbound.push((addr, deed_msg.clone()));
                        outbound.push((addr, dev_deed_msg.clone()));
                    }
                }
            }

            // ── Step 0.9: Silent-parent detection ──
            // Catches the phantom-child pattern where has_upstream=true but
            // parent's d1/d2 doesn't include us (stale state) → parent never
            // forwards ticks → we sit attached forever to a non-existent
            // parent. check_silent_parent increments a per-tick counter that
            // process_tick resets on receipt; at SILENT_PARENT_THRESHOLD=5
            // ticks of no inbound tick, it emits DetachUpstream{SilentParent}.
            //
            // Without this, the math {n nodes × 1 upstream each = n incoming
            // edges} can be violated because phantom children's upstream
            // pointers go to nodes that don't acknowledge them, leaving the
            // mesh's effective dc-sum below n and writer count below the
            // theoretical max.
            if let Some(axiom_nabla::tardis::TardisAction::DetachUpstream { parent, reason }) =
                node.core.tardis_mut().unwrap().check_silent_parent()
            {
                log::info!(
                    "[TARDIS-DETACH] {} leaving parent {} reason={:?}",
                    hex::encode(&node.node_id[..4]),
                    hex::encode(&parent[..4]),
                    reason,
                );
                if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&parent) {
                    outbound.push((
                        to_socket_addr(&peer.address),
                        WireMessage::TardisDetach { node_id: node.node_id },
                    ));
                }
                node.core.tardis_mut().unwrap().remove_peer(&parent);
                let until = node.virtual_secs
                    + axiom_nabla::constants::WRITER_GRACE_TICKS as u64;
                node.recently_detached_parent = Some((parent, until));
            }

            // ── Step 1: Generate own tick from virtual time ──
            // YPX-003 §1: every node generates independently.
            //
            // CORRECTED 2026-05-28 (KI#18 fix): only ROOTS update their
            // own `current_tick` from the local clock. Non-roots get
            // `current_tick` from `process_tick()` when the parent's tick
            // arrives over the wire — which is exactly what `set_tick`'s
            // own doc says ("used by tick originators — tree roots and
            // cycle entry points").
            //
            // Pre-fix this branch ran for every node every tick. Both
            // parent and child would call `set_tick(T)` at the same
            // Unix-second; then when the parent's `Tick(T)` arrived,
            // `process_tick`'s Step-3 gate (`tick.number <=
            // self.current_tick && self.current_tick > 0`) silently
            // rejected it (the caller logged at `debug!`, filtered out
            // at the default `RUST_LOG=info`). That kept
            // `ticks_with_current_parent` at 0 forever → `wants_rotate()`
            // never fired → writer rotation never happened in the entire
            // history of soaks. See `docs/AXIOM_REPORT_KnownIssues.md`
            // §18 for the full diagnosis.
            //
            // `set_tick` also decrements `rebalance_cooldown`; with this
            // guard, non-roots only decrement it via `process_tick`
            // (`tardis.rs:348`), which now fires reliably once Step-3
            // accepts parent ticks.
            if !node.core.tardis().unwrap().has_upstream() {
                node.core.tardis_mut().unwrap().set_tick(now_secs, now_ms);
            }

            // ── Step 2: Build and send tick to downstream children ──
            // The Ed25519 verification key for this tick is bound to
            // `upstream_pk = node.node_id` via the NBC chain (the
            // receiver looks up `verified_nbcs[upstream_pk]` and uses
            // `cc::nbc_ed25519_pk(nbc)` as the verification key — see
            // KI#18 fix in `recv_loop`). No separate signer_pk field
            // on the wire; NBC is the trust anchor.
            let mut tick_msg = TickMessage {
                number: now_secs,
                upstream_pk: node.node_id,
                payload: vec![],
                signature: vec![], // signed below
                timestamp_ms: now_ms,
                prev_sig: vec![],
                // This is our own emitted tick (we ARE the writer originating
                // it for our subtree). Our upstream IS the grandparent from
                // D1/D2's POV — that's what they need to verify our prev_sig
                // and drive the grandpa-tick integrity rule.
                grandparent_pk: node.core.tardis().unwrap().upstream().copied(),
                available_slots: node.core.tardis().unwrap().available_slots(),
                downstream_approvals: node.core.tardis().unwrap().downstream_approval_count(),
                subtree_d_available: node.core.tardis().unwrap().subtree_d_available(),
                // YPX-021 §6 — the origin SEEDS the OODS accumulator with its own
                // Core-produced draw; each downstream node folds its own in on
                // relay (tardis.rs), so a fully-cascaded tick estimates tree size.
                oods_tardis: {
                    const OODS_EPOCH_TICKS: u64 = axiom_nabla::constants::OODS_EPOCH_TICKS;
                    let seed = axiom_core_logic::oods_verify::oods_epoch_seed(
                        now_secs / OODS_EPOCH_TICKS, &[],
                    );
                    axiom_core_logic::oods_verify::oods_produce(&node.node_id, &seed)
                },
                // §7.6 Phase 2: our downstream set (bound into our commitment for strict-parent).
                child_pks: node.core.tardis().unwrap().children(),
                // Self-originated tick — no upstream lineage to carry.
                gp_commitment: None,
            };
            tick_msg.signature = node.core.signer().sign(
                &crypto::tick_commitment(&tick_msg),
            );

            let children = node.core.tardis().unwrap().children();
            for child_id in children {
                if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&child_id) {
                    outbound.push((
                        to_socket_addr(&peer.address),
                        WireMessage::Tick(tick_msg.clone()),
                    ));
                }
            }

            // ── Step 3: Mesh maintenance ──
            let action = node.core.mesh_mut().unwrap().periodic_peer_check(tick_count);
            match action {
                MeshAction::RequestIntroduction { ask_peer } => {
                    if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&ask_peer) {
                        outbound.push((
                            to_socket_addr(&peer.address),
                            WireMessage::IntroductionRequest { from: node.node_id },
                        ));
                    }
                }
                MeshAction::ConnectPeer(peer) => {
                    outbound.push((
                        to_socket_addr(&peer.address),
                        WireMessage::Hello {
                            node_id: node.node_id,
                            address: node.core.mesh().unwrap().my_address().clone(),
                            downstream_count: node.core.tardis().unwrap().downstream_count() as u8,
                            nbc_bytes: node.own_nbc_bytes.clone(),
                            txid_service: node.core.smt().txid_mode().to_string(),
                        },
                    ));
                }
                MeshAction::BroadcastTopology(hint) => {
                    let msg = WireMessage::Gossip(GossipMessage::Topology(hint));
                    // discovery_hint_targets: mesh peers + E-peer (E-peer
                    // gets ONLY discovery hints per architectural rule).
                    for target_id in node.core.mesh().unwrap().discovery_hint_targets(&node.node_id) {
                        if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&target_id) {
                            outbound.push((to_socket_addr(&peer.address), msg.clone()));
                        }
                    }
                }
                MeshAction::None => {}
                _ => {}
            }

            // ── Step 3c: §6.3.7 latency pings ──
            // Every LATENCY_PING_INTERVAL ticks, ping each active peer to
            // refresh its RTT (fed to record_peer_rtt on the returning Pong)
            // and sweep pings that never got a Pong. This is the measurement
            // that drives latency-aware pruning (mesh Step 5b). Local-only.
            if tick_count > 0 && tick_count % LATENCY_PING_INTERVAL == 0 {
                let timeout = std::time::Duration::from_secs(LATENCY_PING_TIMEOUT_SECS);
                node.pending_pings.retain(|_, (_, sent)| sent.elapsed() < timeout);
                let my_id = node.node_id;
                let mut pinged = 0usize;
                for peer in node.core.mesh().unwrap().active_peers().to_vec() {
                    if peer.node_id == my_id { continue; }
                    node.ping_nonce = node.ping_nonce.wrapping_add(1);
                    let nonce = node.ping_nonce;
                    node.pending_pings.insert(nonce, (peer.node_id, std::time::Instant::now()));
                    outbound.push((
                        to_socket_addr(&peer.address),
                        WireMessage::Ping { from: my_id, nonce },
                    ));
                    pinged += 1;
                }
                log::debug!("[ping] tick {tick_count}: sent {pinged} pings, {} in-flight", node.pending_pings.len());
            }

            // ── Step 3b: Initial join — send Hello to bootstrap peers ──
            // First few ticks: introduce ourselves to bootstrap peers for mesh discovery.
            // TARDIS attachment goes through TardisAttachRequest, not Hello.
            if tick_count < 3 {
                for peer in node.core.mesh().unwrap().active_peers().to_vec() {
                    let addr = to_socket_addr(&peer.address);
                    outbound.push((
                        addr,
                        WireMessage::Hello {
                            node_id: node.node_id,
                            address: node.core.mesh().unwrap().my_address().clone(),
                            downstream_count: node.core.tardis().unwrap().downstream_count() as u8,
                            nbc_bytes: node.own_nbc_bytes.clone(),
                            txid_service: node.core.smt().txid_mode().to_string(),
                        },
                    ));
                }
            }

            // ── Step 4: TARDIS join / orphan recovery ──
            // Spec §1.5 / §2.1: orphan sends TardisAttachRequest to any
            // known node. Receiver decides accept/reject from its own TARDIS
            // state; rejections carry referrals (BFS E-enquiry, walks DOWN
            // the tree from TARDIS-internal state). Discovery propagates
            // through referrals + the tick chain's piggybacked slot_info
            // (§2.2, surfaced as recovery_candidates()).
            //
            // Two priorities, only:
            //   P1: tick-driven candidates — peers we've heard advertise an
            //       open slot via tick piggyback. Highest signal: alive +
            //       advertising recently.
            //   P2: any known peer (mesh-discovered). No filter on
            //       gossip-declared slot/topology fields — those are subject
            //       to staleness and create cascade loops when a writer
            //       dies. The receiver answers honestly; dead peers don't
            //       respond at all → pending_attach timeout reclaims the
            //       slot next tick.
            //
            // Excluded: `recently_detached_parent` (so voluntary rotation
            // actually moves the topology) and any peer with a request
            // already in flight (pending_attach dedup).
            if node.core.tardis().unwrap().needs_parent() {
                node.orphan_ticks += 1;
                let my_addr = node.core.mesh().unwrap().my_address().clone();
                let has_children = node.core.tardis().unwrap().downstream_count() > 0;
                let mut sent_to = std::collections::HashSet::new();

                // Expire timed-out pending requests
                let current_tick = now_secs;
                node.pending_attach.retain(|_, tick_sent| {
                    current_tick.saturating_sub(*tick_sent) / TICK_INTERVAL_SECS < ATTACH_TIMEOUT_TICKS
                });

                let excluded_parent: Option<NodeId> = match node.recently_detached_parent {
                    Some((id, until)) if node.virtual_secs < until => Some(id),
                    _ => { node.recently_detached_parent = None; None }
                };

                // P1: tick-piggyback recovery candidates (§2.2). These are
                // TARDIS-internal — propagated via signed ticks, not gossip.
                for (candidate_nid, _slot) in node.core.tardis().unwrap().recovery_candidates().to_vec() {
                    if candidate_nid == node.node_id || sent_to.contains(&candidate_nid) { continue; }
                    if node.pending_attach.contains_key(&candidate_nid) { continue; }
                    if Some(candidate_nid) == excluded_parent { continue; }
                    let addr = node.core.mesh().unwrap().peer_by_id(&candidate_nid).map(|p| p.address.clone());
                    if let Some(address) = addr {
                        sent_to.insert(candidate_nid);
                        node.pending_attach.insert(candidate_nid, current_tick);
                        outbound.push((
                            to_socket_addr(&address),
                            WireMessage::TardisAttachRequest {
                                node_id: node.node_id,
                                address: my_addr.clone(),
                                has_children,
                                prefer_writer: true,
                                nbc_bytes: node.own_nbc_bytes.clone(),
                            },
                        ));
                    }
                }

                // P2: known peers — no gossip-field filter. Cap at 3 per
                // tick to avoid flooding; receiver decides, referrals on
                // reject drive the next tick's candidates.
                let known: Vec<PeerInfo> = node.core.mesh().unwrap().active_peers().to_vec();
                let mut p2_sent = 0;
                for peer in &known {
                    if peer.node_id == node.node_id || sent_to.contains(&peer.node_id) { continue; }
                    if node.pending_attach.contains_key(&peer.node_id) { continue; }
                    if Some(peer.node_id) == excluded_parent { continue; }
                    if p2_sent >= 3 { break; }
                    sent_to.insert(peer.node_id);
                    node.pending_attach.insert(peer.node_id, current_tick);
                    outbound.push((
                        to_socket_addr(&peer.address),
                        WireMessage::TardisAttachRequest {
                            node_id: node.node_id,
                            address: my_addr.clone(),
                            has_children,
                            prefer_writer: true,
                            nbc_bytes: node.own_nbc_bytes.clone(),
                        },
                    ));
                    p2_sent += 1;
                }

                // PE: E-enquiry — ask a few peers for introductions.
                // Only every 3 orphan ticks to avoid flooding with introduction
                // requests when no pending_attach targets are available.
                if node.orphan_ticks % 3 == 1 {
                    for peer in known.iter().take(3) {
                        if peer.node_id == node.node_id { continue; }
                        outbound.push((
                            to_socket_addr(&peer.address),
                            WireMessage::IntroductionRequest { from: node.node_id },
                        ));
                    }
                }
            } else {
                node.orphan_ticks = 0;
                node.pending_attach.clear();
            }

            // ── Step 4c: Advertise open D slots + periodic self-announce ──
            // Nodes with dc=1 (one open slot) periodically broadcast Hello so
            // orphan nodes discover them. This is critical in larger networks
            // where dc=1 nodes would otherwise be invisible.
            //
            // ALL nodes additionally re-Hello every 12th tick (~1 min): Hello
            // is the FIRST-HAND self-announcement that refreshes our
            // dial-back address in peers' mesh tables (referrals are
            // discovery-only and never overwrite — see
            // `upsert_peer_self_announced` / `note_peer_referral`). Without a
            // heartbeat, a peer that recorded us under a stale address (e.g.
            // a pre-`--advertise` wildcard from a mixed-version window) holds
            // it forever.
            let dc1_advert = node.core.tardis().unwrap().downstream_count() == 1
                && tick_count.is_multiple_of(3);
            if dc1_advert || tick_count.is_multiple_of(12) {
                let known: Vec<PeerInfo> = node.core.mesh().unwrap().active_peers().to_vec();
                // Slot advertising needs only a sample; the address-refresh
                // heartbeat must reach every active peer (active_peers order
                // is stable, so a fixed take(5) would starve peers 6+).
                let fanout = if tick_count.is_multiple_of(12) { known.len() } else { 5 };
                for peer in known.iter().take(fanout) {
                    if peer.node_id == node.node_id { continue; }
                    outbound.push((
                        to_socket_addr(&peer.address),
                        WireMessage::Hello {
                            node_id: node.node_id,
                            address: node.core.mesh().unwrap().my_address().clone(),
                            downstream_count: node.core.tardis().unwrap().downstream_count() as u8,
                            nbc_bytes: node.own_nbc_bytes.clone(),
                            txid_service: node.core.smt().txid_mode().to_string(),
                        },
                    ));
                }
            }

            // ── Step 5a: Record child approvals (time-based) ──
            //
            // Track the virtual time of each child's last approval. Feed the
            // protocol layer "approved" unless the child has been silent for
            // SLOW_CHILD_SECS virtual seconds. This approach is inherently
            // resilient to relay latency: a single approval arriving late
            // resets the timer, preventing false drops.
            //
            // B7 followup #2 (2026-04-13): bootstrap grace period for ghost
            // children. The original d1_ok logic was:
            //   d1_ok = (d1_last_approval_secs == 0)
            //         || (now - d1_last_approval_secs < SLOW_CHILD_SECS)
            // For a child that never approves (a ghost), the first clause
            // makes d1_ok = true forever, so d1_misses never increments,
            // so the GHOST_CHILD_MISS_THRESHOLD check in wants_drop_slow_child
            // never fires.
            //
            // Fix: track when d1/d2 first appeared in the slot via
            // d{1,2}_first_seen_tick. Allow a bootstrap grace period of
            // GHOST_BOOTSTRAP_GRACE_TICKS (12 ticks ≈ 60s) for the child to
            // start approving. After grace expires without an approval, flip
            // to d1_ok = false so misses accumulate and the ghost gets dropped.
            const GHOST_BOOTSTRAP_GRACE_TICKS: u64 = 12;
            {
                let d1_set = node.core.tardis().unwrap().d1().is_some();
                let d2_set = node.core.tardis().unwrap().d2().is_some();

                // Track when each slot was first seen filled (and reset when emptied).
                if d1_set && node.d1_first_seen_tick == 0 {
                    node.d1_first_seen_tick = tick_count;
                } else if !d1_set {
                    node.d1_first_seen_tick = 0;
                }
                if d2_set && node.d2_first_seen_tick == 0 {
                    node.d2_first_seen_tick = tick_count;
                } else if !d2_set {
                    node.d2_first_seen_tick = 0;
                }
            }

            if node.core.tardis().unwrap().downstream_count() > 0 {
                if node.d1_approved_this_tick {
                    node.d1_last_approval_secs = now_secs;
                    node.d1_approved_this_tick = false;
                }
                if node.d2_approved_this_tick {
                    node.d2_last_approval_secs = now_secs;
                    node.d2_approved_this_tick = false;
                }

                // Bootstrap grace: child is OK if either it approved recently
                // OR it was just attached and we're still within the grace window.
                let d1_in_grace = node.d1_first_seen_tick > 0
                    && tick_count.saturating_sub(node.d1_first_seen_tick) < GHOST_BOOTSTRAP_GRACE_TICKS;
                let d2_in_grace = node.d2_first_seen_tick > 0
                    && tick_count.saturating_sub(node.d2_first_seen_tick) < GHOST_BOOTSTRAP_GRACE_TICKS;

                let d1_ok = if node.d1_last_approval_secs > 0 {
                    now_secs.saturating_sub(node.d1_last_approval_secs) < SLOW_CHILD_SECS
                } else {
                    d1_in_grace
                };
                let d2_ok = if node.d2_last_approval_secs > 0 {
                    now_secs.saturating_sub(node.d2_last_approval_secs) < SLOW_CHILD_SECS
                } else {
                    d2_in_grace
                };
                node.core.tardis_mut().unwrap().record_child_approvals(d1_ok, d2_ok);
            }

            // ── Step 5b: Rebalancing (protocol-driven) ──
            // wants_rebalance() returns false (§2.15.3: disabled in steady-state).
            if node.core.tardis().unwrap().wants_rebalance() {
                if let Some(parent) = node.core.tardis().unwrap().upstream().cloned() {
                    node.core.tardis_mut().unwrap().remove_peer(&parent);
                    node.core.tardis_mut().unwrap().set_rebalance_cooldown();
                }
            }

            // ── Step 5c: Bottom-up audit (GAP-07, §2.15) ──
            // Every 5 ticks, a child challenges its upstream parent with a
            // BLAKE3-based audit request. The response handler already exists
            // in the message dispatch (WireMessage::AuditRequest/AuditResponse).
            if let Some(axiom_nabla::tardis::TardisAction::SendAuditRequest { request, target }) = node.core.maybe_audit() {
                if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&target) {
                    outbound.push((
                        to_socket_addr(&peer.address),
                        WireMessage::AuditRequest(request),
                    ));
                }
            }

            // ── Step 6: Parent-side slow-child drop ──
            //
            // Call wants_drop_slow_child() every tick. The function has its
            // own decision logic:
            //   - 2-child case: gated on PARENT_ROTATION_INTERVAL_TICKS + jitter
            //     (~50 ticks = 4 minutes in test mode), so calling every tick is
            //     a no-op until the interval fires
            //   - 1-child ghost case (beta10 B7 fix): gated on d1/d2_misses
            //     >= GHOST_CHILD_MISS_THRESHOLD (10 ticks)
            //
            // Previously this call was wrapped in a "d1_silent || d2_silent"
            // outer gate that required `d1_last_approval_secs > 0`, meaning the
            // child had to have approved at least once before we considered
            // dropping it. Ghost children never approve, so the gate never
            // opened for the exact case the B7 fix was meant to handle. The
            // wrapper was originally added as binary-sim relay-latency
            // paranoia; in production the 10-tick (or 50-tick) thresholds
            // inside wants_drop_slow_child() already provide the anti-false-drop
            // protection. Removing the wrapper is what lets B7 actually fire.
            //
            // See AXIOM_YPX-003_TARDIS.md §2.4.1 (ghost-child escape hatch).
            if let Some(child_pk) = node.core.tardis_mut().unwrap().wants_drop_slow_child() {
                if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&child_pk) {
                    outbound.push((
                        to_socket_addr(&peer.address),
                        WireMessage::TardisDetach { node_id: node.node_id },
                    ));
                }
                node.core.tardis_mut().unwrap().remove_peer(&child_pk);

                // Reset timers — the remaining child keeps its timer,
                // the dropped slot will be filled by a new child.
                node.d1_last_approval_secs = now_secs;
                node.d2_last_approval_secs = now_secs;
            }

            // ── Step 6b: P-slot promotion (GAP-04) ──
            // If a D-slot opened (child dropped/detached) and we have a pending
            // peer, promote them to a real downstream slot and send an attach
            // invitation so they know to set us as upstream.
            if node.core.tardis().unwrap().has_d_open() {
                if let Some(pending_id) = node.core.tardis().unwrap().pending().copied() {
                    if node.core.tardis_mut().unwrap().promote_pending() {
                        info!("P-slot promoted {:02x}{:02x}... to D-slot",
                            pending_id[0], pending_id[1]);
                        // Give the promoted child a grace period
                        if node.core.tardis().unwrap().d1() == Some(&pending_id) {
                            node.d1_last_approval_secs = now_secs;
                        } else if node.core.tardis().unwrap().d2() == Some(&pending_id) {
                            node.d2_last_approval_secs = now_secs;
                        }
                        // Send proactive attach response to the promoted peer
                        if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&pending_id) {
                            outbound.push((
                                to_socket_addr(&peer.address),
                                WireMessage::TardisAttachResponse {
                                    node_id: node.node_id,
                                    accepted: true,
                                    downstream_count: node.core.tardis().unwrap().downstream_count(),
                                    referrals: vec![],
                                    nbc_bytes: node.own_nbc_bytes.clone(),
                                },
                            ));
                        }
                    }
                }
            }

            // ── Step 7: Writer-side rotation (§6.3 — every 72hr) ──
            // A writer voluntarily disassembles: releases children, detaches
            // from parent. All become orphans and scatter via normal recovery.
            // TardisDetach notifies each peer so they immediately re-enter
            // orphan recovery instead of waiting for tick timeout.
            // Disabled in stdio/sim mode: rotation interval is measured in
            // set_tick() calls, so at 20x it fires every 7.5 real seconds
            // instead of every 12.5 real minutes, overwhelming recovery.
            // ── Graceful rotation drain (2026-05-29) ──
            //
            // AXIOM Origin's design after observing ~47 ANTIE INTERNAL_ERROR
            // events post-rotation in the 72h soak: rotation must not
            // interrupt in-flight client requests. Three phases drive
            // a single rotation:
            //
            //   1. wants_rotate() fires + state == Normal
            //        → transition to Draining. From now on,
            //          `handle_message` rejects NEW client-class
            //          requests with `RegisterRejected{reason:
            //          "rotation_drain"}` so the SDK picks another
            //          Nabla. In-flight client handlers complete
            //          normally. Peer Nabla traffic (Tick/Approval/
            //          Hello/Gossip) is unaffected throughout.
            //   2. Draining: if `client_inflight == 0`,
            //        transition to Cooldown(2). Otherwise wait — try
            //        again next tick.
            //   3. Cooldown(n): each tick decrements n. At n == 0,
            //        execute the rotation logic (release children,
            //        detach parent), reset rebalance cooldown, return
            //        to Normal.
            //
            // The 2-tick cooldown gives any TCP send buffers that
            // were carrying a just-completed client response time to
            // flush before we yank the mesh from under them. With
            // TICK_INTERVAL_SECS=5 that's a 10s settle window.
            if !sim_mode {
                match node.rotation_state {
                    RotationState::Normal => {
                        if node.core.tardis().unwrap().wants_rotate() {
                            // 0-5 tick random pre-drain stagger. Even if
                            // multiple writers hit wants_rotate this tick
                            // (residual sync), they won't all enter Draining
                            // together. With per-process boot_seed in jitter
                            // (see tardis.rs:rotation_jitter) this is the
                            // second line of defense against the storm.
                            let stagger = rand::random::<u32>() % 6;
                            node.rotation_state = RotationState::Stagger(stagger);
                            log::info!(
                                "[TARDIS-ROTATE-STAGGER] writer {} pre-drain delay {} ticks",
                                hex::encode(&node.node_id[..4]),
                                stagger,
                            );
                        }
                    }
                    RotationState::Stagger(n) => {
                        if n > 0 {
                            node.rotation_state = RotationState::Stagger(n - 1);
                        } else {
                            node.rotation_state = RotationState::Draining(0);
                            log::info!(
                                "[TARDIS-ROTATE-DRAIN-START] writer {} client_inflight={}",
                                hex::encode(&node.node_id[..4]),
                                node.client_inflight,
                            );
                        }
                    }
                    RotationState::Draining(ticks_in_drain) => {
                        // Progress to Cooldown when inflight empties OR
                        // after DRAIN_MAX_TICKS — the timeout prevents the
                        // deadlock observed in the 2026-05-29 storm where
                        // continuous SDK retries pinned client_inflight > 0
                        // and the writer stayed in Draining indefinitely.
                        if node.client_inflight == 0 || ticks_in_drain >= DRAIN_MAX_TICKS {
                            let reason = if node.client_inflight == 0 {
                                "inflight=0"
                            } else {
                                "timeout"
                            };
                            node.rotation_state = RotationState::Cooldown(2);
                            log::info!(
                                "[TARDIS-ROTATE-DRAIN-DONE] writer {} → cooldown(2 ticks) after {} ticks, reason={} inflight={}",
                                hex::encode(&node.node_id[..4]),
                                ticks_in_drain,
                                reason,
                                node.client_inflight,
                            );
                        } else {
                            node.rotation_state = RotationState::Draining(ticks_in_drain + 1);
                        }
                    }
                    RotationState::Cooldown(n) => {
                        if n > 0 {
                            node.rotation_state = RotationState::Cooldown(n - 1);
                        } else {
                            // n == 0: execute the rotation now and
                            // return to Normal accepting clients again.
                            let twp = node.core.tardis().unwrap().ticks_with_parent();
                            let parent_short = node.core.tardis().unwrap().upstream()
                                .map(|p| hex::encode(&p[..4]))
                                .unwrap_or_else(|| "none".to_string());
                            log::info!(
                                "[TARDIS-ROTATE] writer {} detaching from parent {} after {} ticks_with_parent (interval {} + jitter)",
                                hex::encode(&node.node_id[..4]),
                                parent_short,
                                twp,
                                axiom_nabla::constants::CHILD_ROTATION_INTERVAL_TICKS,
                            );
                            // Step 7a: Release children
                            let children = node.core.tardis_mut().unwrap().children_to_release();
                            for child_nid in &children {
                                if let Some(peer) = node.core.mesh().unwrap().peer_by_id(child_nid) {
                                    outbound.push((
                                        to_socket_addr(&peer.address),
                                        WireMessage::TardisDetach { node_id: node.node_id },
                                    ));
                                }
                                node.core.tardis_mut().unwrap().remove_peer(child_nid);
                            }
                            // Step 7b: Detach from parent + remember to
                            // EXCLUDE this parent from the next pick (else
                            // the orphan-recovery loop will re-pick the same
                            // parent on the next tick and rotation is a no-op).
                            // Cooldown: WRITER_GRACE_TICKS (~50 ticks ≈ 4min).
                            if let Some(parent) = node.core.tardis().unwrap().upstream().cloned() {
                                if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&parent) {
                                    outbound.push((
                                        to_socket_addr(&peer.address),
                                        WireMessage::TardisDetach { node_id: node.node_id },
                                    ));
                                }
                                node.core.tardis_mut().unwrap().remove_peer(&parent);
                                let exclude_until = node.virtual_secs
                                    + axiom_nabla::constants::WRITER_GRACE_TICKS as u64;
                                node.recently_detached_parent = Some((parent, exclude_until));
                            }
                            node.core.tardis_mut().unwrap().set_rebalance_cooldown();
                            // Bump rotations_completed so the next cycle's
                            // jitter is uncorrelated with this cycle's
                            // (golden-ratio mixed in rotation_jitter).
                            node.core.tardis_mut().unwrap().rotations_completed =
                                node.core.tardis().unwrap().rotations_completed.wrapping_add(1);
                            node.rotation_state = RotationState::Normal;
                        }
                    }
                }
            }

            // ── Step 6b: §32 Merge quarantine expiry ──
            let (banned, restored) = node.core.check_merge_quarantine();
            if !banned.is_empty() || !restored.is_empty() {
                warn!("§32 MERGE RESOLVE: banned {} wallets, restored {} tainted wallets",
                    banned.len(), restored.len());
                // Flood MergeResolved summary to mesh
                let merge_msg = WireMessage::Gossip(GossipMessage::MergeResolved {
                    forked_wallets: banned.clone(),
                    restored_wallets: restored.clone(),
                    resolved_at_tick: tick_count,
                });
                if let Some(mesh) = node.core.mesh() {
                    for target_id in mesh.forward_targets(&node.node_id) {
                        if let Some(peer) = mesh.peer_by_id(&target_id) {
                            outbound.push((to_socket_addr(&peer.address), merge_msg.clone()));
                        }
                    }
                }
            }

            // ── Step 6c: S6 Ban challenge resolution ──
            let reversed = node.core.bans_mut().check_challenge_resolution(tick_count);
            if !reversed.is_empty() {
                info!("S6: {} ban(s) reversed after challenge window", reversed.len());
                // Restore reversed wallets to Normal in SMT
                for wid in &reversed {
                    if let Some(entry) = node.core.smt().get(wid) {
                        let mut updated = entry.clone();
                        updated.status = axiom_nabla::types::WalletStatus::Normal;
                        node.core.smt_mut().put(&updated);
                    }
                }
                // Gossip BanReversed to mesh
                for wid in &reversed {
                    let gossip = WireMessage::Gossip(GossipMessage::BanReversed {
                        wallet_id: *wid,
                        reversed_at_tick: tick_count,
                    });
                    if let Some(mesh) = node.core.mesh() {
                        for target_id in mesh.forward_targets(&node.node_id) {
                            if let Some(peer) = mesh.peer_by_id(&target_id) {
                                outbound.push((to_socket_addr(&peer.address), gossip.clone()));
                            }
                        }
                    }
                }
            }

            // ── Step 7: Companion Certificate ──
            let _cc = node.core.cc_tick();

            // ── Step 8: Evict expired peer NBCs + sweep dead TCP connections ──
            // Every 60 ticks (~5 min virtual), sweep the verified NBC cache
            // and prune dead TCP connections (keepalive failures, closed sockets).
            if tick_count.is_multiple_of(60) {
                node.evict_expired_nbcs();
                transport.sweep_dead_connections();
                // Expire stale cheque claims (17,280-tick TTL)
                node.core.smt_mut().expire_stale_claims(now_secs);
            }

            // ── Step 8b: NBC renewal check (every NBC_RENEWAL_CHECK_TICKS) ──
            if tick_count > 0 && tick_count.is_multiple_of(NBC_RENEWAL_CHECK_TICKS) {
                if let Some(renew_msg) = node.check_nbc_renewal() {
                    // Send renewal request to a random qualified peer
                    let peers: Vec<_> = node.core.mesh().unwrap().peer_ids();
                    if let Some(peer_id) = peers.first() {
                        if let Some(peer) = node.core.mesh().unwrap().peer_by_id(peer_id) {
                            outbound.push((to_socket_addr(&peer.address), renew_msg));
                        }
                    }
                }
            }

            // ── Step 9: Anti-entropy — pull-based state sync ──
            // Every ANTI_ENTROPY_INTERVAL ticks, broadcast our root hash to a
            // random mesh peer via TickHash gossip. Peers compare and request
            // missing entries. Complement to push-based gossip flood.
            if tick_count > 0 && tick_count.is_multiple_of(ANTI_ENTROPY_INTERVAL) {
                let root_hash = node.core.smt().root_hash();
                let node_pk = node.node_id;
                let current_tick = node.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
                let gossip = WireMessage::Gossip(GossipMessage::TickHash {
                    tick: current_tick,
                    root_hash,
                    node_pk,
                });
                // Send to 2 random peers for consistency comparison
                let peers: Vec<_> = node.core.mesh().unwrap().peer_ids();
                let peer_idx = (tick_count as usize / ANTI_ENTROPY_INTERVAL as usize) % peers.len().max(1);
                for offset in 0..2usize {
                    let idx = (peer_idx + offset) % peers.len().max(1);
                    if idx < peers.len() {
                        if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&peers[idx]) {
                            outbound.push((to_socket_addr(&peer.address), gossip.clone()));
                        }
                    }
                }
            }

            // ── Step 9b: YPX-009 §7.2 Pulse epoch evaluation ──
            // At each epoch boundary, check which validators missed their pulse.
            {
                use axiom_core_logic::types::PULSE_EPOCH_LENGTH_TICKS;
                let current_epoch = tick_count / PULSE_EPOCH_LENGTH_TICKS;
                if current_epoch > 0 && tick_count.is_multiple_of(PULSE_EPOCH_LENGTH_TICKS) {
                    if let Some(mesh) = node.core.mesh_mut() {
                        let evicted = mesh.evaluate_pulse_epoch(current_epoch);
                        for pk in &evicted {
                            warn!("YPX-009: Evicting validator {:02x}{:02x}... — {} consecutive pulse misses",
                                pk[0], pk[1], axiom_core_logic::types::PULSE_MISS_EVICTION);
                        }
                    }
                }
            }

            // ── Step 10: YPX-009 §12 WAL audit (every WAL_AUDIT_INTERVAL_TICKS) ──
            if tick_count > 0 && tick_count.is_multiple_of(WAL_AUDIT_INTERVAL_TICKS) {
                match node.core.wal_mut().audit_recent() {
                    Ok(Some(seq)) => {
                        // KnownIssue #4 fix: actually recover instead of just logging.
                        // Pre-fix: this branch logged "discard + re-sync" but did
                        // nothing, so every audit cycle re-flagged the same
                        // corrupted sequence (~1,243 warnings/6h per affected
                        // node in soak `s2r12039`). audit_recent now dedupes
                        // (won't return the same seq twice without recovery),
                        // and we call truncate_at to drop the corrupted tail
                        // so the WAL is consistent again.
                        warn!("WAL audit: corruption detected at sequence {} — truncating tail", seq);
                        match node.core.wal_mut().truncate_at(seq) {
                            Ok(()) => {
                                warn!(
                                    "WAL audit: truncated at {}; subsequent ticks will rebuild \
                                     state from peer gossip (RangeSync). Soak / dev nodes can \
                                     accept the gap; production deployments should monitor for \
                                     repeat truncations as a hardware-error signal.",
                                    seq,
                                );
                            }
                            Err(e) => {
                                warn!("WAL audit: truncate_at({}) failed: {}", seq, e);
                            }
                        }
                    }
                    Ok(None) => {
                        debug!("WAL audit: recent check clean");
                    }
                    Err(e) => {
                        warn!("WAL audit error: {}", e);
                    }
                }
            }

            // ── Step 10b: YPX-009 §12 WAL deep scan (every WAL_DEEP_SCAN_INTERVAL_TICKS) ──
            if tick_count > 0 && tick_count.is_multiple_of(WAL_DEEP_SCAN_INTERVAL_TICKS) {
                match node.core.wal().audit_deep() {
                    Ok(corrupted) if !corrupted.is_empty() => {
                        warn!("WAL deep scan: {} corrupted entries found: {:?}", corrupted.len(), corrupted);
                    }
                    Ok(_) => {
                        info!("WAL deep scan: all sampled entries clean");
                    }
                    Err(e) => {
                        warn!("WAL deep scan error: {}", e);
                    }
                }
            }

            // ── Step 10c: YPX-009 §12 Peer WAL cross-verification (every WAL_PEER_VERIFY_INTERVAL_TICKS) ──
            if tick_count > 0 && tick_count.is_multiple_of(WAL_PEER_VERIFY_INTERVAL_TICKS) {
                let section_size = WAL_PEER_VERIFY_SECTION_SIZE;
                let wal_seq = node.core.wal().sequence();
                if wal_seq > section_size {
                    // AUDIT-FIX v2.11.14: Respect peer_available_from_tick hint.
                    // Don't request ticks below what the last peer reported as available.
                    let raw_from = wal_seq.saturating_sub(section_size);
                    let from = raw_from.max(node.peer_available_from_tick);
                    let our_hash = node.core.wal().section_hash(from, wal_seq);
                    let our_root = node.core.smt().root_hash();
                    let req = WireMessage::StatePullRequest {
                        mode: axiom_nabla::types::StatePullMode::WalVerify,
                        our_root_hash: our_root,
                        from_tick: from,
                        to_tick: wal_seq,
                        section_hash: Some(our_hash),
                    };
                    // Send to 1 random peer
                    let peers: Vec<_> = node.core.mesh().unwrap().peer_ids();
                    if !peers.is_empty() {
                        let idx = (tick_count as usize) % peers.len();
                        if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&peers[idx]) {
                            outbound.push((to_socket_addr(&peer.address), req));
                        }
                    }
                }
            }

            tick_count += 1;
            outbound
        };

        // Send outbound messages (outside lock).
        // Critical messages (Tick, Approval, Attach*, Detach) get retry with backoff.
        // 2026-04-15 fix `af79958` companion: send failures are logged at
        // WARN level and counted per-peer. The previous debug-level
        // logging hid the gossip-partition bug for weeks because send
        // failures were invisible at default INFO log level. Code:
        // `E_NABLA_TRANSPORT_SEND_FAILED`.
        for (addr, msg) in &outbound {
            // KI#37 storm shed — a tick-loop non-critical send is a
            // gossip/AE/pool broadcast. Drop it under storm; Tick/Approval
            // (critical) always flow so the tick tree stays alive.
            if !is_critical_message(msg) && !storm_admit_forward(&state) {
                continue;
            }
            let send_result = if is_critical_message(msg) {
                if !send_with_retry(transport.as_ref(), *addr, msg, 2) {
                    Err(())
                } else {
                    Ok(())
                }
            } else {
                transport.send(*addr, msg).map_err(|e| {
                    // DEBUG, not WARN: under sustained SDK traffic this
                    // log line fires for every TARDIS tick that targets
                    // an address that's no longer reachable (an
                    // ephemeral source port from a closed SDK connection
                    // — KI#24). The per-peer counter still increments,
                    // and operators can grep for the same code at
                    // RUST_LOG=debug if they need the wire detail.
                    // Demoted 2026-05-30 after the wedge-the-HTTP-
                    // listener pattern surfaced during v5 soak.
                    debug!("[E_NABLA_TRANSPORT_SEND_FAILED] tick_loop send to {} failed: {} \
                           (transport will recover via cached-conn eviction; \
                            this counter increments)", addr, e);
                })
            };
            if send_result.is_err() {
                let mut node = state.lock().unwrap();
                *node.transport_send_failures_per_peer
                    .entry(addr.to_string())
                    .or_insert(0) += 1;
            }
        }

        // Drain HTTP outbound queue (gossip from HTTP /register)
        {
            let pending: Vec<_> = http_outbound.lock().unwrap().drain(..).collect();
            for (addr, msg) in &pending {
                if let Err(e) = transport.send(*addr, msg) {
                    // DEBUG, not WARN. Same reasoning as the tick_loop
                    // send block above — KI#24, counter intact, raise
                    // log level for wire-level diagnosis if needed.
                    debug!("[E_NABLA_TRANSPORT_SEND_FAILED] HTTP gossip flood to {} failed: {} \
                           (cached-conn eviction will retry on next register)", addr, e);
                    let mut node = state.lock().unwrap();
                    *node.transport_send_failures_per_peer
                        .entry(addr.to_string())
                        .or_insert(0) += 1;
                }
            }
        }

        // Sleep remaining time in tick, but in 200ms slices so SHUTDOWN
        // is checked frequently. Otherwise a SIGTERM mid-sleep waits up
        // to TICK_INTERVAL_SECS (~5s) before tick_loop exits — racing
        // against axiom-env.py's 5s SIGKILL backstop and losing the
        // shutdown cleanup window.
        let elapsed = tick_start.elapsed();
        if elapsed < tick_duration {
            let remaining = tick_duration - elapsed;
            let slice = std::time::Duration::from_millis(200);
            let mut slept = std::time::Duration::ZERO;
            while slept < remaining {
                if SHUTDOWN.load(std::sync::atomic::Ordering::Relaxed) { break; }
                let this = std::cmp::min(slice, remaining - slept);
                thread::sleep(this);
                slept += this;
            }
        }
    }

    // ── Graceful shutdown: flush in-memory state, then notify peers ──
    // eprintln + explicit stderr flush — stderr redirected to a file
    // is fully buffered (BlockBuf), and the env's 5s SIGKILL backstop
    // can fire before the buffer drains. The bookend markers
    // ([POST-LOOP-START] and [POST-LOOP-DONE]) let soak diagnostics
    // see exactly how far cleanup got before any forced exit.
    use std::io::Write as _;
    eprintln!("[POST-LOOP-START] tick_loop exited, beginning shutdown cleanup");
    let _ = std::io::stderr().flush();
    let mut node = state.lock().unwrap();
    // Fix #4: synchronously persist pool state, take a final snapshot,
    // and surface any flush errors so soak diagnostics catch a stuck
    // disk before the env's SIGKILL backstop forces a hard exit.
    node.core.flush_for_shutdown();
    let _ = std::io::stderr().flush();
    // Detach from parent
    if let Some(parent_id) = node.core.tardis().unwrap().upstream() {
        if let Some(peer) = node.core.mesh().unwrap().peer_by_id(parent_id) {
            let _ = transport.send(
                to_socket_addr(&peer.address),
                &WireMessage::TardisDetach { node_id: node.node_id },
            );
        }
    }
    // Detach from children
    for child_id in node.core.tardis().unwrap().children() {
        if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&child_id) {
            let _ = transport.send(
                to_socket_addr(&peer.address),
                &WireMessage::TardisDetach { node_id: node.node_id },
            );
        }
    }
}

// ── Receive Loop ──

/// Receive messages from transport and dispatch to protocol handlers.
/// KI#24: true when an outbound entry is a reply to the inbound connection's
/// own (ephemeral) source address and we still hold that connection's socket.
/// Such replies MUST go out via `send_reply` (write on the inbound socket) —
/// re-dialing the ephemeral source through `transport.send` opens a NEW
/// connection to a port nothing listens on (it's the client/peer's outbound
/// source, frequently already closed) and fails with Connection refused. The
/// `reply_stream.is_some()` guard means a transport without inbound sockets
/// (StdioTransport / tests) falls through to the normal `transport.send` path.
fn is_inbound_reply(addr: &std::net::SocketAddr, envelope: &Envelope) -> bool {
    *addr == envelope.peer && envelope.reply_stream.is_some()
}

fn recv_loop(
    state: Arc<Mutex<NablaNodeState>>,
    transport: Arc<dyn Transport>,
) {
    while !SHUTDOWN.load(std::sync::atomic::Ordering::Relaxed) {
        let envelope = match transport.recv() {
            Ok(env) => env,
            Err(e) => {
                debug!("Receive error: {}", e);
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };

        // Bridge requests do a blocking TCP round-trip to the bridge peer.
        // Run them off the node lock (task #53): bridge_core takes the
        // shared Arc<Mutex> and locks only briefly (node_id snapshot +
        // human_bridge_px apply), so tick processing is not frozen for
        // the up-to-15s exchange the way the pre-fix handler froze it.
        if let WireMessage::BridgeRequest(req) = &envelope.message {
            let reply = match bridge_core(req, &state) {
                BridgeOutcome::Ok(resp) => WireMessage::BridgeResponse(resp),
                BridgeOutcome::Rejected { error, .. } => WireMessage::BridgeRejected(error),
            };
            if let Err(e) = axiom_nabla::transport::send_reply(&envelope, &reply) {
                warn!("Bridge: reply to {} failed: {}", envelope.peer, e);
            }
            continue;
        }

        let outbound = {
            let mut node = state.lock().unwrap();
            handle_message(&mut node, &envelope)
        };

        // Send responses (outside lock) — retry critical messages.
        // 2026-04-15 fix `af79958` companion: send failures logged at
        // WARN, counted per peer. Code: `E_NABLA_TRANSPORT_SEND_FAILED`.
        for (addr, msg) in &outbound {
            let send_failed = if is_inbound_reply(addr, &envelope) {
                // KI#24 ROOT FIX: reply on the inbound socket. Previously this
                // entry went through `transport.send(envelope.peer)`, which
                // re-dialed the peer's ephemeral source port — nothing listens
                // there, so it failed with Connection refused (×2 with the
                // zombie-recovery retry) on every reply to a one-shot SDK
                // client or a peer whose inbound conn had closed. That failed
                // re-dial was the E_NABLA_TRANSPORT_SEND_FAILED flood that
                // back-pressured the log writer and wedged the HTTP listener.
                // send_reply writes on the connection that delivered the
                // request (the only path that can reach a caller with no
                // listener), so the ~29 reject/redirect/ack replies now
                // actually arrive. Mirrors the BridgeRequest reply path above.
                match axiom_nabla::transport::send_reply(&envelope, msg) {
                    Ok(()) => false,
                    Err(e) => {
                        debug!("[E_NABLA_TRANSPORT_SEND_FAILED] recv_loop reply on inbound socket to {} failed: {}", addr, e);
                        true
                    }
                }
            } else if is_critical_message(msg) {
                !send_with_retry(transport.as_ref(), *addr, msg, 2)
            } else if !storm_admit_forward(&state) {
                // KI#37 storm shed — drop this forward/broadcast. Not a
                // transport failure (peer is fine), so DON'T count it as
                // one; the storm counter tracks it separately.
                continue;
            } else {
                match transport.send(*addr, msg) {
                    Ok(()) => false,
                    Err(e) => {
                        // Fan-out to ANOTHER peer's listening address. A
                        // failure here is a genuinely-unreachable peer
                        // (down / restarting) — transient, recovers via
                        // cached-conn eviction. DEBUG, counter intact.
                        debug!("[E_NABLA_TRANSPORT_SEND_FAILED] recv_loop send to {} failed: {} \
                               (transport will recover via cached-conn eviction)", addr, e);
                        true
                    }
                }
            };
            if send_failed {
                let mut node = state.lock().unwrap();
                *node.transport_send_failures_per_peer
                    .entry(addr.to_string())
                    .or_insert(0) += 1;
            }
        }
    }
}

// ── Main ──

fn main() {
    // Decorative boot charm. TTY-gated, no-op under systemd/journald.
    // Lives in axiom-denomination so every native binary that links
    // the AXC/L$/atom conversion lib also gets the canary — see
    // denomination/src/lib.rs. Purely for luck; zero functional effect.
    axiom_denomination::print_if_tty("nabla-node");

    // ── FIRST: verify this environment has 64-bit unix time (§31.3) ──
    // Core is the sole authority for platform safety. Since Nabla
    // executes core-logic directly, the check must run here.
    axiom_core_logic::verify_time_safety();

    let args = parse_args();

    // ── Load node.toml (config file lives in main scope for dashboard cascade) ──
    let node_toml_path = match &args.config_file {
        Some(p) => p.clone(),
        None => args.data_dir.join("node.toml"),
    };
    let node_toml: Option<axiom_nabla::ceremony::NodeToml> = if node_toml_path.exists() {
        match axiom_nabla::ceremony::NodeToml::load(&node_toml_path) {
            Ok(t) => {
                info!("Loaded config: {}", node_toml_path.display());
                Some(t)
            }
            Err(e) => {
                warn!("Failed to load {}: {}", node_toml_path.display(), e);
                None
            }
        }
    } else if args.config_file.is_some() {
        error!("Config file not found: {}", node_toml_path.display());
        std::process::exit(1);
    } else {
        None
    };

    // Initialize logging
    //
    // Honor an inherited RUST_LOG so per-module suppressions set by
    // the launching process survive (e.g. axiom-env.py's
    // `cranelift=off,cranelift_codegen=off,...` directives that
    // suppress JIT IR dumps — without this, nabla.log was 82%
    // Cranelift CLIF and grew ~1 GB/min × 10 validators during soaks,
    // filling disk in ~24 min).
    //
    // The --log-level CLI flag still wins when explicitly passed
    // (clap default is "info", so only a non-default value
    // overrides the env). Honor that as the explicit-override path.
    let cli_overrides_env = args.log_level != "info";
    if cli_overrides_env || std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", &args.log_level);
    }
    env_logger::init();

    info!("╔══════════════════════════════════════════════════╗");
    info!("║  AXIOM Nabla Node v{}              ║", env!("CARGO_PKG_VERSION"));
    info!("╚══════════════════════════════════════════════════╝");

    // ── SIGTERM/SIGINT/SIGHUP trap ─────────────────────────────────────
    // axiom-env.py stops Nabla by sending SIGTERM, then SIGKILL after
    // a timeout. Without a handler, SIGTERM kills immediately and any
    // in-memory state past the last atomic-write point is gone.
    // Pool state is already atomic-written on every mutation so disk
    // is never corrupt; the handler is defense-in-depth that ensures
    // a final persist + snapshot before exit. SIGKILL remains
    // uncatchable — but the atomic-write design covers that path too.
    //
    // The handler sets the SHUTDOWN flag. tick_loop's WHILE checks it
    // and the post-loop cleanup (line ~3680) does the actual flush
    // by calling `node.flush_for_shutdown()` before TardisDetach.
    // ctrlc with `termination` feature catches BOTH SIGINT and SIGTERM.
    // Use eprintln! instead of info! inside the handler: env_logger may
    // buffer through std::io::stderr's line-buffered path, and a fast
    // process exit between handler-fire and tick_loop-exit can swallow
    // the message. eprintln! goes directly to stderr with a per-call
    // flush, so the SIGNAL marker always lands in nabla.log.
    if let Err(e) = ctrlc::set_handler(|| {
        eprintln!("[SIGNAL] SIGTERM/SIGINT received — initiating graceful shutdown");
        SHUTDOWN.store(true, std::sync::atomic::Ordering::Relaxed);
    }) {
        warn!("Signal handler install failed ({e}); env's SIGKILL backstop will still terminate cleanly via atomic-write durability");
    }

    // Create data directory
    if let Err(e) = std::fs::create_dir_all(&args.data_dir) {
        error!("FATAL: Cannot create data dir {:?}: {}", args.data_dir, e);
        std::process::exit(1);
    }

    // ── Create transport ──
    let transport: Arc<dyn Transport> = match args.mode {
        TransportMode::Tcp => {
            let bind_addr = if args.bind.contains(':') {
                // Already has port or is IPv6 bracket notation
                if args.bind.ends_with(']') || !args.bind.contains("]:") {
                    // Pure IPv6 address like [::] — append port
                    format!("{}:{}", args.bind, args.port)
                } else {
                    // Already has port like [::]:1211
                    args.bind.clone()
                }
            } else {
                format!("{}:{}", args.bind, args.port)
            };
            info!("Transport: TCP (dual-stack)");
            info!("Binding: {}", bind_addr);
            match TcpTransport::bind(&bind_addr) {
                Ok(t) => {
                    info!("Listening on {}", t.local_addr());
                    Arc::new(t)
                }
                Err(e) => {
                    error!("FATAL: Cannot bind to {}: {}", bind_addr, e);
                    std::process::exit(1);
                }
            }
        }
        TransportMode::Stdio => {
            // Build local address from --bind and --port so stdio messages
            // carry the correct source address (needed for binary sim routing).
            let local_addr: std::net::SocketAddr = format!("{}:{}", args.bind, args.port)
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap());
            info!("Transport: stdio (line-delimited JSON)");
            info!("Virtual address: {}", local_addr);
            match StdioTransport::with_addr(local_addr) {
                Ok(t) => Arc::new(t),
                Err(e) => {
                    error!("FATAL: Cannot create stdio transport: {}", e);
                    std::process::exit(1);
                }
            }
        }
    };

    // ── Load bootstrap config ──
    let config = match NablaConfig::load_bootstrap(&args.bootstrap_file) {
        Ok(c) => {
            info!("Loaded {} bootstrap peers from {:?}",
                c.peer_count(), args.bootstrap_file);
            c
        }
        Err(e) => {
            warn!("Cannot load {:?}: {} — starting with no bootstrap",
                args.bootstrap_file, e);
            NablaConfig::new()
        }
    };

    // ── Load NBC (identity) ──
    // Try loading from disk. If missing, attempt peer issuance (new node path).
    let config_dir = args.data_dir.join("config");
    let nbc_path = config_dir.join("nbc.json");
    let (nbc, own_supporting_nbcs): (NBC, Vec<NBC>) = if nbc_path.exists() {
        // ── Returning node: load existing NBC ──
        let nbc_json = match std::fs::read_to_string(&nbc_path) {
            Ok(s) => s,
            Err(e) => {
                error!("FATAL: Cannot read NBC from {:?}: {}", nbc_path, e);
                std::process::exit(1);
            }
        };
        let nbc: NBC = match serde_json::from_str(&nbc_json) {
            Ok(n) => n,
            Err(e) => {
                error!("FATAL: Cannot parse NBC from {:?}: {}", nbc_path, e);
                std::process::exit(1);
            }
        };
        // Load supporting chain if present
        let supporting_path = config_dir.join("nbc_supporting.json");
        let supporting: Vec<NBC> = if supporting_path.exists() {
            match std::fs::read_to_string(&supporting_path) {
                Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
                Err(_) => vec![],
            }
        } else {
            vec![]
        };
        (nbc, supporting)
    } else {
        // ── New node: generate keys + request NBC from peer ──
        info!("No NBC found at {:?} — new node path", nbc_path);
        info!("Generating keypairs...");

        // Determine node name: from config file if available, else from index
        let node_name_for_keygen = args.data_dir.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed")
            .to_string();

        let subject = match generate_node_keys(&config_dir, &node_name_for_keygen) {
            Ok(s) => s,
            Err(e) => {
                error!("FATAL: Key generation failed: {}", e);
                std::process::exit(1);
            }
        };
        info!("Keys generated in {:?}", config_dir);

        // Connect to a reachable bootstrap peer and request NBC issuance.
        // Shuffle peers so requests spread across genesis nodes (SPHINCS+
        // signing is ~1s per signature, so spreading avoids bottlenecks).
        info!("Requesting NBC from bootstrap peers...");
        let mut obtained_nbc: Option<(NBC, Vec<NBC>)> = None;

        let mut peers_shuffled = config.bootstrap_peers.clone();
        {
            use rand::seq::SliceRandom;
            peers_shuffled.shuffle(&mut rand::thread_rng());
        }

        // Retry with exponential backoff: try each peer, then wait before retrying.
        // Max 3 rounds with backoff: 0s, 2s, 4s between rounds.
        const MAX_NBC_ROUNDS: u32 = 3;
        let mut round = 0u32;
        'nbc_retry: while round < MAX_NBC_ROUNDS && obtained_nbc.is_none() {
            if round > 0 {
                let backoff_ms = 2000 * round as u64;
                info!("NBC retry round {} (backoff {}ms)...", round + 1, backoff_ms);
                std::thread::sleep(Duration::from_millis(backoff_ms));
            }

            for bp in &peers_shuffled {
                let peer_addr = transport::to_socket_addr(&bp.address);
                info!("Trying peer {} for NBC issuance (round {})...", peer_addr, round + 1);

                let request = WireMessage::NbcIssuanceRequest {
                    sphincs_pk: subject.sphincs_pk.clone(),
                    ed25519_pk: subject.ed25519_pk.clone(),
                    dilithium_pk: subject.dilithium_pk.clone(),
                    node_name: subject.node_name.clone(),
                };

                if transport.send(peer_addr, &request).is_err() {
                    warn!("Cannot reach peer {}, trying next...", peer_addr);
                    continue;
                }

                // Wait for response with timeout. SPHINCS+ signing takes ~1s per
                // signature, so genesis nodes processing multiple requests in sequence
                // need time. 30s accommodates ~20 queued requests per genesis node.
                let deadline = Instant::now() + Duration::from_secs(30);
                while Instant::now() < deadline {
                    if let Some(env) = transport.try_recv() {
                        if let WireMessage::NbcIssuanceResponse {
                            accepted, nbc_bytes, supporting_chain_bytes, rejection_reason
                        } = env.message {
                            if accepted {
                                match cc::deserialize_nbc(&nbc_bytes) {
                                    Ok(nbc) => {
                                        let supporting: Vec<NBC> = bincode::deserialize(&supporting_chain_bytes)
                                            .unwrap_or_default();
                                        info!("NBC obtained from peer {} (chain_depth={})",
                                            peer_addr, nbc.chain_depth);
                                        obtained_nbc = Some((nbc, supporting));
                                    }
                                    Err(e) => {
                                        error!("Bad NBC from peer {}: {}", peer_addr, e);
                                    }
                                }
                            } else {
                                warn!("Peer {} rejected NBC request: {}", peer_addr, rejection_reason);
                            }
                            break;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }

                if obtained_nbc.is_some() {
                    break 'nbc_retry;
                }
            }
            round += 1;
        }

        match obtained_nbc {
            Some((nbc, supporting)) => {
                // Full chain verification — SPHINCS+ + root trust always runs.
                // Core IPC not yet available at bootstrap time (created after NBC load),
                // so we use direct crypto here. After startup, CL7 is the primary path.
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                if let Err(e) = verify_nbc_chain(&nbc, &supporting, now_secs) {
                    error!("FATAL: Received NBC failed chain verification: {}", e);
                    std::process::exit(1);
                }
                // Write to disk
                let nbc_json = serde_json::to_string_pretty(&nbc).unwrap();
                std::fs::write(&nbc_path, &nbc_json).unwrap_or_else(|e| {
                    error!("FATAL: Cannot write nbc.json: {}", e);
                    std::process::exit(1);
                });
                if !supporting.is_empty() {
                    let supporting_json = serde_json::to_string_pretty(&supporting).unwrap();
                    std::fs::write(config_dir.join("nbc_supporting.json"), &supporting_json).ok();
                }
                info!("NBC written to {:?}", nbc_path);
                (nbc, supporting)
            }
            None => {
                error!("FATAL: Could not obtain NBC from any bootstrap peer.");
                error!("Ensure at least one genesis/qualified peer is reachable.");
                error!("Or run nabla-ceremony first (dev.sh → 28n).");
                std::process::exit(1);
            }
        }
    };

    // node_id = NBC validator_id = BLAKE3(sphincs_pk)
    let node_id = nbc.validator_id;
    info!("Node ID (from NBC): {:02x}{:02x}{:02x}{:02x}...",
        node_id[0], node_id[1], node_id[2], node_id[3]);

    // --request-nbc: standalone NBC acquisition mode — exit after saving
    if args.request_nbc {
        info!("--request-nbc: NBC obtained and saved. Exiting.");
        info!("NBC path: {:?}", config_dir.join("nbc.json"));
        if config_dir.join("nbc_supporting.json").exists() {
            info!("Supporting chain: {:?}", config_dir.join("nbc_supporting.json"));
        }
        std::process::exit(0);
    }

    // ── Load Ed25519 signer (operational key for tick signing) ──
    let ed25519_key_path = config_dir.join("nabla_ed25519.key");
    let signer: Box<dyn Signer> = {
        let ed25519_seed = match std::fs::read(&ed25519_key_path) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                seed
            }
            Ok(bytes) => {
                error!("FATAL: Invalid Ed25519 key size in {:?}: {} bytes (expected 32)",
                    ed25519_key_path, bytes.len());
                std::process::exit(1);
            }
            Err(e) => {
                error!("FATAL: Cannot read Ed25519 key from {:?}: {}", ed25519_key_path, e);
                error!("Run nabla-ceremony first (dev.sh → 28n)");
                std::process::exit(1);
            }
        };
        info!("Ed25519 signer loaded from {:?}", ed25519_key_path);
        Box::new(Ed25519Signer::from_seed(&ed25519_seed))
    };

    // ── Load SPHINCS+ secret key (optional — needed for NBC peer issuance) ──
    let sphincs_sk_path = config_dir.join("nabla_sphincs.key");
    let sphincs_sk: Option<Vec<u8>> = match std::fs::read(&sphincs_sk_path) {
        Ok(bytes) if bytes.len() == 64 => {
            info!("SPHINCS+ SK loaded (NBC peer issuance enabled)");
            Some(bytes)
        }
        Ok(bytes) => {
            warn!("Invalid SPHINCS+ key size in {:?}: {} bytes (expected 64) — issuance disabled",
                sphincs_sk_path, bytes.len());
            None
        }
        Err(_) => {
            info!("SPHINCS+ SK not found — NBC peer issuance disabled");
            None
        }
    };

    // ── Create AVM interpreter for CL7/CL8 NBC verification ──
    // Production mode (no --dev, no --epoch-ms) REQUIRES --avm-elf.
    // Without AVM, NBC crypto verification is skipped entirely.
    let is_sim_mode = args.epoch_ms > 0;
    let skip_verify = args.skip_verify || is_sim_mode;
    let avm_interpreter: Option<Arc<AvmInterpreter>> = match &args.avm_elf_path {
        Some(path) => {
            if !path.exists() {
                error!("FATAL: axiom-core.elf not found at {:?}", path);
                std::process::exit(1);
            }
            match std::fs::read(path) {
                Ok(elf_bytes) => {
                    info!("AVM interpreter: loaded {:?} ({} bytes)", path, elf_bytes.len());
                    // ── nabla Core pin (refuse-on-mismatch) ──
                    // nabla is the ONE server binary welded to a single Core.
                    // Its single-node decisions (SMT registration, NBC/VBC
                    // issuance, receipt confirmation) feed the mesh and are NOT
                    // outvoted by a k-quorum, so a mismatched-Core nabla could
                    // propagate bad data. Mirror the client gate
                    // (axiom_sdk::setup / runtime.rs): when this binary was built
                    // with AXIOM_CANONICAL_CORE_ID baked in (release/deploy build,
                    // via option_env! in axiom_core_logic::version), the loaded
                    // ELF's BLAKE3 MUST match or we refuse to start. Empty constant
                    // = unpinned dev/source build → no enforcement (same as the
                    // client). lambda/antie do NOT pin — they're quorum-protected.
                    let canonical = axiom_core_logic::version::CANONICAL_CORE_ID;
                    if !canonical.is_empty() {
                        let loaded_hex = hex::encode(blake3::hash(&elf_bytes).as_bytes());
                        if loaded_hex != canonical {
                            error!(
                                "FATAL: Core ELF mismatch. Loaded {} (from {:?}); this \
                                 nabla binary is pinned to {}. Deploy the matching \
                                 axiom-core.elf, or rebuild nabla against this ELF.",
                                loaded_hex, path, canonical,
                            );
                            std::process::exit(1);
                        }
                        info!("Core pin OK: loaded ELF matches canonical {}", canonical);
                    }
                    Some(Arc::new(AvmInterpreter::new(elf_bytes, [0u8; 32])))
                }
                Err(e) => {
                    error!("FATAL: Failed to read axiom-core.elf: {}", e);
                    std::process::exit(1);
                }
            }
        }
        None => {
            if !args.dev_mode && !is_sim_mode {
                error!("FATAL: --avm-elf is required in production mode.");
                error!("NBC verification without AVM interpreter skips all SPHINCS+ checks.");
                error!("Use --dev to skip (dev/testing only) or --avm-elf <path>.");
                std::process::exit(1);
            }
            warn!("AVM interpreter disabled — NBC crypto verification skipped (dev/sim mode)");
            None
        }
    };

    // Node address advertised to peers. This is what every Hello /
    // TardisAttach / topology-hint message carries as our dial-back
    // address, so a wildcard bind (0.0.0.0 / [::]) must never leak
    // into the mesh — peers would store it verbatim and cross-host
    // dials would fail (single-host only works by the loopback
    // accident of connecting to 0.0.0.0). Precedence:
    //   1. --advertise host[:port]  (explicit, DNS resolved here)
    //   2. wildcard bind → egress interface IP derived from the route
    //      to the first bootstrap peer (UDP connect, no packets sent)
    //   3. the bind address as-is (non-wildcard, or nothing to derive
    //      from — the pre-fix behavior, kept with a loud warning)
    let address = {
        let listen = transport.local_addr();
        if let Some(spec) = &args.advertise {
            use std::net::ToSocketAddrs;
            let resolved = spec.to_socket_addrs().ok().and_then(|mut it| it.next())
                .or_else(|| {
                    // Bare host / IP without port — default to the listen port.
                    let with_port = if spec.parse::<std::net::Ipv6Addr>().is_ok() {
                        format!("[{}]:{}", spec, listen.port())
                    } else {
                        format!("{}:{}", spec, listen.port())
                    };
                    with_port.to_socket_addrs().ok().and_then(|mut it| it.next())
                });
            match resolved {
                Some(sa) => {
                    info!("Advertising address: {} (from --advertise {})", sa, spec);
                    from_socket_addr(sa)
                }
                None => {
                    error!("FATAL: --advertise {:?} does not resolve to an address", spec);
                    std::process::exit(1);
                }
            }
        } else if listen.ip().is_unspecified() {
            let derived = config.bootstrap_peers.first().and_then(|bp| {
                let target = transport::to_socket_addr(&bp.address);
                let probe = std::net::UdpSocket::bind(
                    if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" },
                ).ok()?;
                probe.connect(target).ok()?;
                Some(SocketAddr::new(probe.local_addr().ok()?.ip(), listen.port()))
            });
            match derived {
                Some(sa) => {
                    info!("Advertising address: {} (derived from route to first bootstrap peer; \
                           pass --advertise to override)", sa);
                    from_socket_addr(sa)
                }
                None => {
                    warn!("Bind address {} is a wildcard and no bootstrap peer to derive a \
                           routable IP from — advertising the wildcard. Peers on other hosts \
                           cannot dial back; pass --advertise <host[:port]>.", listen);
                    from_socket_addr(listen)
                }
            }
        } else {
            from_socket_addr(listen)
        }
    };

    // Create node state
    log::info!("YPX-014: txid_mode={}", args.txid_mode);
    let state = Arc::new(Mutex::new(NablaNodeState::new(node_id, address, &args.data_dir, signer, avm_interpreter, skip_verify, args.txid_mode, args.dev_mode)));
    if args.dev_mode {
        log::info!("DEV MODE: ban challenge window = {} ticks (~1 min)", axiom_nabla::ban::CHALLENGE_WINDOW_TICKS_DEV);
    }

    // Accept NBC into state (already loaded above)
    {
        let mut node = state.lock().unwrap();
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        node.sphincs_sk = sphincs_sk;
        node.own_supporting_nbcs = own_supporting_nbcs;
        node.accept_nbc(nbc);

        // ── YPX-011: Store FACT #0 if not already stored ──
        if node.core.genesis_fact_payload().is_none() {
            let genesis_tick = 1; // Genesis tick
            let fact = axiom_core_logic::genesis_integrity::build_genesis_fact(genesis_tick);
            let payload = serde_json::to_vec(&fact).unwrap_or_default();
            if !payload.is_empty() {
                node.core.store_genesis_fact(payload);
                info!("YPX-011: Genesis FACT #0 stored (unsigned — signing requires G1 ceremony)");
            }
        }

        // ── NBC startup verification ──
        // Verify own NBC: structural + SPHINCS+ + root trust.
        // Primary: CL7 via Core IPC. Fallback: direct crypto.
        // FATAL if fails and not skip_verify.
        if !skip_verify {
            let own_nbc_bytes = &node.own_nbc_bytes;
            if !own_nbc_bytes.is_empty() {
                if let Ok(own_nbc) = deserialize_nbc(own_nbc_bytes) {
                    let nbc_result = if let Some(ref avm) = node.avm {
                        verify_nbc_via_core(avm, &own_nbc, now_secs)
                    } else {
                        verify_nbc(&own_nbc, now_secs)
                    };
                    if let Err(e) = nbc_result {
                        // Internal diagnostic — visible in logs for developers.
                        // Root cause: nabla ceremony produced NBC with root keys that don't
                        // match NABLA_ROOT_AUTHORITY_PKS in compiled Core. Ceremony/build mismatch.
                        error!("NBC startup check failed ({}): issuer PKs in nbc.json do not match \
                                NABLA_ROOT_AUTHORITY_PKS in compiled Core.", e);
                        eprintln!();
                        eprintln!("  AXIOM Nabla cannot start.");
                        eprintln!();
                        eprintln!("  Your node certificate (NBC) does not match this software release.");
                        eprintln!("  This node's identity cannot be verified against the network trust root.");
                        eprintln!();
                        eprintln!("  Please contact your network administrator or re-run the genesis ceremony.");
                        eprintln!();
                        std::process::exit(1);
                    }
                    if node.avm.is_some() {
                        info!("Own NBC verified via AVM (CL7) at startup");
                    } else {
                        info!("Own NBC verified via direct crypto at startup");
                    }
                }
            }
        }

        // Initialize virtual clock from real time. In sim mode, tick_loop
        // will override this with epoch-based virtual time on first iteration.
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        node.virtual_secs = now_secs;
        node.virtual_ms = now_ms;

        // Bootstrap from bootstrap.toml (shuffled to avoid hotspots)
        let mut bootstrap = config.bootstrap_peer_infos(now_secs);
        if !bootstrap.is_empty() {
            use rand::seq::SliceRandom;
            bootstrap.shuffle(&mut rand::thread_rng());
            node.core.mesh_mut().unwrap().add_bootstrap(bootstrap);
        }

        // Store bootstrap addresses for dashboard status
        node.bootstrap_addresses = config.bootstrap_peers
            .iter()
            .map(|bp| bp.address.clone())
            .collect();

        // Reader-only mode from CLI
        node.reader_only = args.reader_only;
    }

    if args.reader_only {
        info!("Reader-only mode: registrations will always be redirected");
    }
    info!("Data directory: {:?}", args.data_dir);
    info!("Bootstrap peers: {}", config.peer_count());
    info!("Starting tick loop ({}ms interval)...", args.tick_ms);

    // ── Start HTTP dashboard server ──
    let start_time = SystemTime::now();
    let dashboard_remote = args.dashboard_remote
        || node_toml.as_ref().map(|t| t.dashboard_remote).unwrap_or(false);
    let dashboard_port = args.dashboard_port
        .or_else(|| node_toml.as_ref().map(|t| t.dashboard_port))
        .unwrap_or(monitor::DEFAULT_MONITOR_PORT);
    // SECURITY FIX #7: Warn loudly when dashboard binds to 0.0.0.0.
    // The dashboard has no authentication — exposing it to the network
    // leaks operational state to anyone who can reach the port.
    let dashboard_bind = if dashboard_remote {
        warn!("Dashboard binding to 0.0.0.0 — NO AUTHENTICATION.");
        warn!("Only use --dashboard-remote on trusted networks or behind a firewall.");
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    // Shared outbound queue: HTTP handler pushes gossip messages, tick loop drains and sends.
    // This allows HTTP /register to trigger immediate gossip flood (not wait for anti-entropy).
    let http_outbound: Arc<Mutex<Vec<(std::net::SocketAddr, WireMessage)>>> =
        Arc::new(Mutex::new(Vec::new()));

    let monitor_addr = format!("{}:{}", dashboard_bind, dashboard_port);
    match TcpListener::bind(&monitor_addr) {
        Ok(listener) => {
            listener.set_nonblocking(true).ok();
            let http_state = state.clone();
            let http_outbound_clone = http_outbound.clone();
            let monitor_config = MonitorConfig::default();
            thread::spawn(move || {
                loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            // YPX-002 P6 — simulated HTTP ingress delay. Matches
                            // the TCP-side injection in `handle_message`; runs once
                            // per HTTP connection on the accept thread so each
                            // peer's request pays its own latency. Zero-cost when
                            // `AXIOM_SIM_NET_DELAY_MAX_MS` is unset/0.
                            axiom_nabla::sim_delay::maybe_sim_delay();

                            // YPX-018 Phase 5f Finding 8: Read full HTTP request
                            // including the entire body (Content-Length-driven).
                            //
                            // Pre-fix: a single 2 KB read with a 2 KB body cap.
                            // CLARA `POST /clara` bodies are ~2 MB (3 cheques ×
                            // ~700 KB each — VBC bundles + SPHINCS+ sigs + DMAP
                            // proofs). The single read truncated bodies after
                            // ~2 KB and the cap rejected anything larger, so
                            // every CLARA registration silently failed with
                            // "invalid JSON body".
                            //
                            // Fix: drain the stream until headers are complete,
                            // parse Content-Length, then read exactly that many
                            // body bytes. Cap raised to 8 MB to comfortably hold
                            // 3 cheques even with future protocol growth.
                            const MAX_HTTP_BODY: usize = 8 * 1024 * 1024; // 8 MB
                            const READ_CHUNK: usize = 32 * 1024;          // 32 KB

                            // Set a read timeout so we don't block forever on
                            // slow/dead clients.
                            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(15)));

                            let mut accum: Vec<u8> = Vec::with_capacity(READ_CHUNK);
                            let mut chunk = [0u8; READ_CHUNK];

                            // (1) Read until we see end-of-headers (\r\n\r\n)
                            //     or hit the cap.
                            let header_end_idx = loop {
                                let pos = accum.windows(4).position(|w| w == b"\r\n\r\n");
                                if let Some(p) = pos { break Some(p); }
                                if accum.len() >= MAX_HTTP_BODY {
                                    break None;
                                }
                                let n = stream.read(&mut chunk).unwrap_or(0);
                                if n == 0 { break None; }
                                accum.extend_from_slice(&chunk[..n]);
                            };

                            let header_end = match header_end_idx {
                                Some(pos) => pos,
                                None => {
                                    let response = "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: 35\r\nConnection: close\r\n\r\n{\"error\":\"request body too large\"}";
                                    stream.write_all(response.as_bytes()).ok();
                                    stream.flush().ok();
                                    continue;
                                }
                            };

                            let n = accum.len();
                            if n == 0 { continue; }

                            let request = String::from_utf8_lossy(&accum[..header_end]).to_string();
                            let (path, query) = parse_http_request(&request);

                            // Handle CORS preflight for POST
                            if request.starts_with("OPTIONS") {
                                let response = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n";
                                stream.write_all(response.as_bytes()).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // Phase 3a-B / 3b HTTP→TCP migration gate (CLAUDE.md §8).
                            // The functional wallet endpoints are disabled over
                            // HTTP — native clients use the TCP-CBOR WireMessage
                            // wire.  Exact-path match: `/query-txid` is a
                            // distinct entry in HTTP_GATED_PATHS (Phase 3b) and
                            // must not be conflated with the `/query` prefix.
                            // Flip `FUNCTIONAL_HTTP_GATED` to re-enable.
                            if FUNCTIONAL_HTTP_GATED && HTTP_GATED_PATHS.contains(&path.as_str()) {
                                let body = b"410 Gone - endpoint disabled, use the TCP CBOR wire";
                                let header = format!(
                                    "HTTP/1.1 410 Gone\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(body).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // (2) Parse Content-Length from headers (case-insensitive).
                            let content_length: usize = {
                                let lc = request.to_ascii_lowercase();
                                lc.lines()
                                    .find_map(|l| {
                                        let l = l.trim();
                                        if let Some(rest) = l.strip_prefix("content-length:") {
                                            rest.trim().parse().ok()
                                        } else {
                                            None
                                        }
                                    })
                                    .unwrap_or(0)
                            };

                            if content_length > MAX_HTTP_BODY {
                                let response = "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: 35\r\nConnection: close\r\n\r\n{\"error\":\"request body too large\"}";
                                stream.write_all(response.as_bytes()).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // (3) Read remaining body bytes until we have the full
                            //     content_length after the header end.
                            let body_start = header_end + 4;
                            let needed = body_start + content_length;
                            while accum.len() < needed && accum.len() < MAX_HTTP_BODY {
                                let n = stream.read(&mut chunk).unwrap_or(0);
                                if n == 0 { break; }
                                accum.extend_from_slice(&chunk[..n]);
                            }

                            // POST body — raw CBOR bytes.  Each handler
                            // calls `ciborium::de::from_reader` against
                            // its typed `*Request` struct.
                            let post_body_bytes: Vec<u8> = if body_start < accum.len() {
                                let end = needed.min(accum.len());
                                accum[body_start..end].to_vec()
                            } else {
                                Vec::new()
                            };

                            // Handle POST /register (webclient Nabla registration)
                            if path == "/register" && request.starts_with("POST") {
                                let (code, resp_body) = handle_http_register(
                                    &post_body_bytes, &http_state, &http_outbound_clone,
                                );
                                let status_text = match code {
                                    200 => "OK", 409 => "Conflict",
                                    403 => "Forbidden", _ => "Bad Request",
                                };
                                let header = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    code, status_text, resp_body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(&resp_body).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // Handle POST /pulse-proof (YPX-009: Lambda forwards PulseProof for gossip)
                            if path == "/pulse-proof" && request.starts_with("POST") {
                                let (code, resp_body) = handle_pulse_proof_post(
                                    &post_body_bytes, &http_state, &http_outbound_clone,
                                );
                                let header = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    code, if code == 200 { "OK" } else { "Bad Request" }, resp_body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(&resp_body).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // Handle POST /jfp-secret (JFP vote secret registration)
                            if path == "/jfp-secret" && request.starts_with("POST") {
                                let (code, resp_body) = handle_jfp_secret(
                                    &post_body_bytes, &http_state, &http_outbound_clone,
                                );
                                let header = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    code, if code == 200 { "OK" } else { "Bad Request" }, resp_body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(&resp_body).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // Handle GET /jfp-secrets?dwp_wallet_id=<hex>
                            if path == "/jfp-secrets" {
                                let dwp_id = query.as_deref()
                                    .and_then(|q| q.split('&').find(|p| p.starts_with("dwp_wallet_id=")))
                                    .map(|p| &p[14..]);
                                let (code, resp_body) = match dwp_id {
                                    Some(hex_id) => handle_jfp_secrets_query(hex_id, &http_state),
                                    None => http_error_cbor(
                                        400,
                                        axiom_errors::error_code::E_NABLA_MISSING_FIELD,
                                        axiom_errors::ErrorCategory::ClientBug,
                                        "missing dwp_wallet_id param",
                                    ),
                                };
                                let header = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    code, if code == 200 { "OK" } else { "Bad Request" }, resp_body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(&resp_body).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // Handle POST /bridge (§6.6 partition recovery via HTTP)
                            if path == "/bridge" && request.starts_with("POST") {
                                let (code, resp_body) = handle_http_bridge(
                                    &post_body_bytes, &http_state,
                                );
                                let header = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    code, if code == 200 { "OK" } else { "Bad Request" }, resp_body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(&resp_body).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // Handle POST /clara (YPX-018 §2.4 — CLARA wallet recovery registration)
                            if path == "/clara" && request.starts_with("POST") {
                                let (code, resp_body) = handle_http_clara(
                                    &post_body_bytes, &http_state, &http_outbound_clone,
                                );
                                let status_text = match code {
                                    200 => "OK", 409 => "Conflict",
                                    429 => "Too Many Requests", _ => "Bad Request",
                                };
                                let header = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    code, status_text, resp_body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(&resp_body).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // POST /endorse-ban-challenge — sign challenge commitment, return endorsement
                            if path == "/endorse-ban-challenge" && request.starts_with("POST") {
                                let (code, resp_body) = handle_http_endorse_ban_challenge(
                                    &post_body_bytes, &http_state,
                                );
                                let header = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    code, if code == 200 { "OK" } else { "Bad Request" }, resp_body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(&resp_body).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // POST /challenge-ban — submit full challenge with k=3 endorsements
                            if path == "/challenge-ban" && request.starts_with("POST") {
                                let (code, resp_body) = handle_http_challenge_ban(
                                    &post_body_bytes, &http_state, &http_outbound_clone,
                                );
                                let header = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    code, if code == 200 { "OK" } else { "Bad Request" }, resp_body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(&resp_body).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // Handle /query directly (needs SMT access, not just snapshot)
                            if path == "/query" {
                                let (code, body) = handle_http_query(
                                    query.as_deref(), &http_state,
                                );
                                let header = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    code, if code == 200 { "OK" } else { "Bad Request" }, body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(&body).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // YPX-002 P5 — per-variant gossip latency stats.
                            // Returns { state_update, group_update, tick_hash }
                            // each with { count, p50_ticks, p99_ticks, max_ticks }.
                            // Consumed by soak_test assertions and admin dashboards
                            // to verify that gossip propagation stays inside Timer A
                            // (1 tick) on a healthy mesh.
                            if path == "/gossip-latency" {
                                let snap = {
                                    let node = http_state.lock().unwrap();
                                    node.core.gossip_latency()
                                };
                                let body = serde_json::to_string(&snap)
                                    .unwrap_or_else(|_| "{}".to_string());
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
                                    body.len(), body
                                );
                                stream.write_all(response.as_bytes()).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // Handle /query-txid — global double-redeem detection
                            // Returns which wallet (if any) already registered this txid.
                            if path == "/query-txid" {
                                let (code, body) = handle_http_query_txid(
                                    query.as_deref(), &http_state,
                                );
                                let status_text = if code == 200 { "OK" } else { "Bad Request" };
                                let header = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    code, status_text, body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(&body).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // Handle POST /register-cheque-claim — 3-node §4.6 claim registration
                            if path == "/register-cheque-claim" && request.starts_with("POST") {
                                // Pre-parse the CBOR body to extract gossip
                                // fields if the handler accepts.  The handler
                                // re-decodes; the duplication is intentional
                                // — gossip needs raw `cheque_id` + `client_pk`
                                // bytes even on the post-handler success path.
                                let gossip_req: Option<axiom_nabla::wire_client::RegisterChequeClaimRequest> =
                                    ciborium::de::from_reader(post_body_bytes.as_slice()).ok();
                                let (code, resp_body) = handle_http_register_cheque_claim(
                                    &post_body_bytes, &http_state,
                                );
                                let status_text = match code {
                                    200 => "OK", 409 => "Conflict", _ => "Bad Request",
                                };
                                let header = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    code, status_text, resp_body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(&resp_body).ok();
                                stream.flush().ok();
                                // Gossip cheque claim to all peers on success
                                if code == 200 {
                                    if let Some(req) = gossip_req {
                                        if req.client_pk.len() == 32 {
                                            let cheque_id = req.cheque_id;
                                            let client_pk = req.client_pk;
                                            let tick = http_state.lock().map(|n| n.virtual_secs).unwrap_or(0);
                                            let wire = WireMessage::Gossip(GossipMessage::ChequeClaim {
                                                cheque_id, client_pk, claim_tick: tick,
                                            });
                                            if let Ok(node) = http_state.lock() {
                                                if let Some(mesh) = node.core.mesh() {
                                                    let mut outbound = http_outbound_clone.lock().unwrap();
                                                    for target_id in mesh.forward_targets(&node.node_id) {
                                                        if let Some(peer) = mesh.peer_by_id(&target_id) {
                                                            outbound.push((to_socket_addr(&peer.address), wire.clone()));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                continue;
                            }

                            // Handle GET /query-cheque-claim — check cheque claim status
                            if path == "/query-cheque-claim" && request.starts_with("GET") {
                                let (code, resp_body) = handle_http_query_cheque_claim(
                                    query.as_deref(), &http_state,
                                );
                                let status_text = if code == 200 { "OK" } else { "Bad Request" };
                                let header = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                    code, status_text, resp_body.len()
                                );
                                stream.write_all(header.as_bytes()).ok();
                                stream.write_all(&resp_body).ok();
                                stream.flush().ok();
                                continue;
                            }

                            let status = {
                                let node = http_state.lock().unwrap();
                                node.status_snapshot(start_time)
                            };

                            let (code, content_type, body) = monitor::route_request(
                                &path, query.as_deref(), &status, &monitor_config,
                            );
                            let status_text = match code {
                                200 => "OK", 401 => "Unauthorized",
                                404 => "Not Found", 503 => "Service Unavailable",
                                _ => "Unknown",
                            };
                            let response = format!(
                                "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
                                code, status_text, content_type, body.len(), body
                            );
                            stream.write_all(response.as_bytes()).ok();
                            stream.flush().ok();
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(50));
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
            });
            if dashboard_remote {
                info!("Dashboard: http://0.0.0.0:{} (remote access ON)", dashboard_port);
            } else {
                info!("Dashboard: http://127.0.0.1:{} (localhost only)", dashboard_port);
            }
        }
        Err(e) => {
            warn!("Cannot bind dashboard on {}: {} — running without dashboard", monitor_addr, e);
        }
    }

    // ── One-shot human bridge (§6.6) ──
    // If --bridge-peer is set, connect to the remote peer, exchange known-nodes
    // snapshots, and call human_bridge_px() to heal a network partition.
    if let Some(ref bridge_addr_str) = args.bridge_peer {
        match bridge_addr_str.parse::<SocketAddr>() {
            Ok(addr) => {
                info!("§6.6 Human bridge: connecting to {}...", addr);
                let node_id = {
                    let n = state.lock().unwrap();
                    n.node_id
                };
                // Send IntroductionRequest to remote peer
                if let Err(e) = transport.send(addr, &WireMessage::IntroductionRequest { from: node_id }) {
                    error!("Bridge: failed to send IntroductionRequest: {}", e);
                } else {
                    // Wait for IntroductionResponse (with a timeout via recv)
                    match transport.recv() {
                        Ok(env) => {
                            if let WireMessage::IntroductionResponse { peers } = env.message {
                                let mut n = state.lock().unwrap();
                                let tick = n.virtual_secs;
                                let (received, new_nodes, updated) = n.core.mesh_mut()
                                    .unwrap()
                                    .human_bridge_px(&peers, tick);
                                info!("Bridge: exchanged {} peers ({} new, {} updated)",
                                    received, new_nodes, updated);
                            } else {
                                warn!("Bridge: unexpected response: {:?}", env.message);
                            }
                        }
                        Err(e) => error!("Bridge: no response: {}", e),
                    }
                }
            }
            Err(e) => error!("Bridge: invalid address '{}': {}", bridge_addr_str, e),
        }
    }

    // Start tick loop in background thread
    let tick_state = state.clone();
    let tick_transport = transport.clone();
    let tick_http_outbound = http_outbound.clone();
    let tick_ms = args.tick_ms;
    let epoch_ms = args.epoch_ms;
    thread::spawn(move || {
        tick_loop(tick_state, tick_transport, tick_ms, epoch_ms, tick_http_outbound);
    });

    // Phase B Layer 4 ATTACK INJECTOR — dev-mode verification only.
    // Schedules one forged PoolSync broadcast at boot+15s (gives mesh time
    // to settle, peer connections to establish). The forged balance is
    // INITIAL_BALANCE + GENESIS_CLAIM_AMOUNT (clearly violating the
    // monotonic-decrease invariant) so the receivers' reconcile path
    // produces ReconcileOutcome::InvariantViolation → PoolViolationDetected
    // → Alert emitted naming THIS Nabla as accused. With ≥3 honest peers
    // independently detecting + relaying, Layer 4 consensus quarantines us.
    //
    // See docs/AXIOM_DESIGN_NablaPoolCaps.md §5.6 for the full design.
    #[cfg(any(debug_assertions, feature = "dev-mode"))]
    if args.inject_fake_poolsync {
        let attack_state = state.clone();
        let attack_transport = transport.clone();
        thread::spawn(move || {
            warn!("[ATTACK-INJECTOR] Layer 4 verification: will broadcast forged PoolSync in 15s …");
            thread::sleep(Duration::from_secs(15));
            let outbound: Vec<(std::net::SocketAddr, WireMessage)> = {
                let node = attack_state.lock().unwrap();
                // INITIAL_BALANCE for the Airdrop pool — same constant the pool
                // bootstraps to. Forge balance ABOVE that so the receiver's
                // local view (which has gone DOWN due to legitimate claims)
                // sees a direction violation.
                let initial_airdrop: u64 = axiom_nabla::constants::AIRDROP_POOL_INITIAL_ATOMS;
                let claim_amount = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;
                let forged_balance = initial_airdrop + claim_amount;
                let forged_claims = 0u64;
                warn!(
                    "[ATTACK-INJECTOR] forging PoolSync: pool=Airdrop balance={} (>INITIAL by 1 claim) claims={}",
                    forged_balance, forged_claims,
                );
                // Sign the forged PoolSync as ourselves. The signature
                // is REAL — kappa really did sign these bytes — which
                // is exactly the attribution semantics Layer 4 needs:
                // forged BALANCE + authentic SIGNATURE → reconcile flags
                // the violation, honest receivers attribute it to kappa
                // (the actual signer), consensus fires.
                let forged_tick = node.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
                let sender_node_id = node.node_id;
                let pool_kind = axiom_nabla::types::PoolKind::Airdrop;
                let sign_payload = axiom_nabla::crypto::pool_sync_sign_payload(
                    pool_kind.sign_tag(), forged_balance, forged_claims,
                    forged_tick, &sender_node_id,
                );
                let sender_sig = node.core.signer().sign(&sign_payload);
                let forged = axiom_nabla::types::GossipMessage::PoolSync {
                    pool: pool_kind,
                    balance: forged_balance,
                    total_claims: forged_claims,
                    tick: forged_tick,
                    sender_node_id,
                    sender_sig,
                };
                let wire = WireMessage::Gossip(forged);
                let mesh = match node.core.mesh() {
                    Some(m) => m,
                    None => { warn!("[ATTACK-INJECTOR] mesh not initialized; cannot inject"); return; }
                };
                let my_id = node.node_id;
                let targets = mesh.forward_targets(&my_id);
                let mut outbound = Vec::new();
                for tid in &targets {
                    if let Some(peer) = mesh.peer_by_id(tid) {
                        outbound.push((to_socket_addr(&peer.address), wire.clone()));
                    }
                }
                warn!(
                    "[ATTACK-INJECTOR] broadcasting forged PoolSync to {} mesh peers — \
                     expect 9 honest Nablas to emit Alerts within ~1 cycle",
                    outbound.len(),
                );
                outbound
            };
            for (addr, msg) in outbound {
                if let Err(e) = attack_transport.send(addr, &msg) {
                    warn!("[ATTACK-INJECTOR] send to {} failed: {}", addr, e);
                }
            }
            warn!("[ATTACK-INJECTOR] forged PoolSync dispatch complete; this Nabla should be quarantined within ~10 ticks");
        });
    }

    // In stdio mode the tick_loop drains all messages via try_recv()
    // before each tick — single-threaded, no lock contention. In TCP
    // mode recv_loop processes messages on the main thread.
    match args.mode {
        TransportMode::Stdio => {
            loop { thread::sleep(Duration::from_secs(3600)); }
        }
        TransportMode::Tcp => {
            recv_loop(state, transport);
        }
    }
}

/// HTTP POST /register — webclient Nabla registration.
/// CBOR body: `RegisterRequest`.  Response: `RegisterResponse`,
/// `RegisterMismatchResponse` (409), or `HttpErrorBody` (4xx).
/// Tri-state outcome of a fact-confirm (receipt-proven state registration).
/// Both the HTTP `/register` wrapper and the TCP
/// `WireMessage::FactConfirmRequest` arm route through `fact_confirm_core`
/// and translate this into their respective wire shapes.
///
/// Added 2026-05-15 alongside the HTTP→TCP migration of `/register`
/// (CLAUDE.md Upcoming Task #3 / `feedback_no_json_in_protocol_path`).
pub(crate) enum FactConfirmOutcome {
    /// Success or REDIRECT (the response carries `status`).
    Ok(axiom_nabla::wire_client::RegisterResponse),
    /// 409 — old_state ≠ stored current_state for this wallet.
    Mismatch(axiom_nabla::wire_client::RegisterMismatchResponse),
    /// Validation failure (missing/invalid receipt, etc.) — carries the
    /// structured ErrorResponse so HTTP and TCP can both translate to
    /// their layer-appropriate error envelope.
    Rejected {
        http_status: u16,
        error: axiom_errors::ErrorResponse,
    },
}

/// Transport-agnostic core for `/register`.  Performs all validation,
/// SMT mutation, NBC anchor population, and gossip queueing.  Caller
/// holds the `node` lock and provides a mutable outbound queue.
///
/// Reference: HTTP wrapper `handle_http_register` (this file) and TCP
/// arm `WireMessage::FactConfirmRequest` in the main message dispatcher.
pub(crate) fn fact_confirm_core(
    req: &axiom_nabla::wire_client::RegisterRequest,
    node: &mut NablaNodeState,
    outbound: &mut Vec<(std::net::SocketAddr, WireMessage)>,
) -> FactConfirmOutcome {
    use axiom_errors::{error_code as ec, ErrorCategory};

    let wallet_pk = req.wallet_pk;
    let new_state = req.new_state;
    let old_state = req.old_state;
    let supplemental = req.supplemental;
    let is_genesis_claim = req.is_genesis_claim;

    if node.reader_only {
        return FactConfirmOutcome::Ok(axiom_nabla::wire_client::RegisterResponse {
            status: "REDIRECT".to_string(),
            reason: "reader_only".to_string(),
            ..Default::default()
        });
    }
    if let Some(tardis) = node.core.tardis() {
        if tardis.find_nearest_writer().is_some() {
            return FactConfirmOutcome::Ok(axiom_nabla::wire_client::RegisterResponse {
                status: "REDIRECT".to_string(),
                reason: "reader_redirect".to_string(),
                ..Default::default()
            });
        }
    }

    if supplemental && req.receipt.is_none() {
        log::warn!("[SUPPLEMENTAL] registration WITHOUT receipt: wallet={} — REJECTED",
            hex::encode(&wallet_pk[..8]));
        return FactConfirmOutcome::Rejected {
            http_status: 400,
            error: axiom_errors::ErrorResponse::new(
                axiom_errors::ErrorCode::from_static(ec::E_NABLA_MISSING_FIELD),
                ErrorCategory::ClientBug,
                "Receipt required — supplemental registration must prove TX happened with k=3".to_string(),
            ),
        };
    }
    let receipt = match req.receipt.as_ref() {
        Some(r) => r,
        None => return FactConfirmOutcome::Rejected {
            http_status: 400,
            error: axiom_errors::ErrorResponse::new(
                axiom_errors::ErrorCode::from_static(ec::E_NABLA_MISSING_FIELD),
                ErrorCategory::ClientBug,
                "Receipt required — Nabla does not sign unverified state transitions".to_string(),
            ),
        },
    };
    if receipt.signatures.len() < 3 {
        return FactConfirmOutcome::Rejected {
            http_status: 400,
            error: axiom_errors::ErrorResponse::new(
                axiom_errors::ErrorCode::from_static(ec::E_NABLA_MISSING_FIELD),
                ErrorCategory::ClientBug,
                "Receipt has fewer than 3 signatures".to_string(),
            ),
        };
    }
    {
        let payload = axiom_nabla::crypto::receipt_sign_payload(
            &wallet_pk, &receipt.consumed_state_id, receipt.tick,
        );
        let mut valid_sigs = 0;
        for sig in &receipt.signatures {
            if node.core.signer().verify(&sig.validator_pk, &payload, &sig.signature) {
                valid_sigs += 1;
            }
        }
        if valid_sigs < 3 {
            log::warn!("[REGISTER] receipt verification failed: {}/3 valid sigs for wallet={}",
                valid_sigs, hex::encode(&wallet_pk[..8]));
            return FactConfirmOutcome::Rejected {
                http_status: 403,
                error: axiom_errors::ErrorResponse::new(
                    axiom_errors::ErrorCode::from_static(ec::E_NABLA_INVALID_HEX),
                    ErrorCategory::ClientBug,
                    format!("Receipt verification failed: {}/3 valid signatures", valid_sigs),
                ),
            };
        }
        log::debug!("[REGISTER] receipt verified: {}/3 sigs for wallet={}{}",
            valid_sigs, hex::encode(&wallet_pk[..8]),
            if supplemental { " [SUPPLEMENTAL]" } else { "" });
    }

    if !supplemental {
        if let Some(existing) = node.core.smt().get(&wallet_pk) {
            if existing.current_state != old_state {
                let err = axiom_errors::ErrorResponse::new(
                    axiom_errors::ErrorCode::from_static(ec::E_NABLA_STATE_MISMATCH),
                    ErrorCategory::RecoverableDrift,
                    "old_state does not match stored current_state".to_string(),
                )
                .with_recovery(axiom_errors::RecoveryHint::ClaraHealNextSend);
                return FactConfirmOutcome::Mismatch(
                    axiom_nabla::wire_client::RegisterMismatchResponse {
                        error_response: err,
                        stored_state: existing.current_state,
                        provided_old_state: old_state,
                    }
                );
            }
        }
    }

    let tx_hash = {
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_TXHASH");
        h.update(&old_state);
        h.update(&new_state);
        *h.finalize().as_bytes()
    };

    let tick = node.virtual_secs;

    let wallet_already_exists = node.core.smt().get(&wallet_pk).is_some();
    if is_genesis_claim && !wallet_already_exists {
        use axiom_nabla::node::ClaimOutcome;
        match node.core.try_airdrop_claim() {
            ClaimOutcome::Granted => {
                log::info!("[AIRDROP] Claimed 1 AXC for wallet {}, remaining: {} AXC",
                    hex::encode(&wallet_pk[..8]),
                    node.core.airdrop_pool().balance() / axiom_denomination::ATOMS_PER_AXC);
                let pool_msg = WireMessage::Gossip(
                    node.core.pool_sync_message(axiom_nabla::types::PoolKind::Airdrop),
                );
                for target_id in node.core.mesh().unwrap().forward_targets(&node.node_id) {
                    if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&target_id) {
                        outbound.push((to_socket_addr(&peer.address), pool_msg.clone()));
                    }
                }
            }
            ClaimOutcome::RefusedPerNablaCap { cycle_resets_at_tick } => {
                log::warn!("[AIRDROP] Claim refused for wallet {} — per-Nabla cycle cap (reset at tick {})",
                    hex::encode(&wallet_pk[..8]), cycle_resets_at_tick);
                return FactConfirmOutcome::Rejected {
                    http_status: 503,
                    error: axiom_errors::ErrorResponse::new(
                        axiom_errors::ErrorCode::from_static(ec::E_POOL_CAP_PER_NABLA),
                        ErrorCategory::Operational,
                        format!("AIRDROP per-Nabla cycle cap reached on this node (reset at tick {}); retry on a different Nabla.", cycle_resets_at_tick),
                    ),
                };
            }
            ClaimOutcome::RefusedMeshCap { cycle_resets_at_tick } => {
                log::warn!("[AIRDROP] Claim refused for wallet {} — mesh cycle cap (reset at tick {})",
                    hex::encode(&wallet_pk[..8]), cycle_resets_at_tick);
                return FactConfirmOutcome::Rejected {
                    http_status: 503,
                    error: axiom_errors::ErrorResponse::new(
                        axiom_errors::ErrorCode::from_static(ec::E_POOL_CAP_MESH),
                        ErrorCategory::Operational,
                        format!("AIRDROP mesh-wide cycle cap reached (reset at tick {}); wait for cycle reset.", cycle_resets_at_tick),
                    ),
                };
            }
            ClaimOutcome::RefusedExhausted => {
                log::warn!("[AIRDROP] Claim refused for wallet {} — pool exhausted",
                    hex::encode(&wallet_pk[..8]));
                return FactConfirmOutcome::Rejected {
                    http_status: 410,
                    error: axiom_errors::ErrorResponse::new(
                        axiom_errors::ErrorCode::from_static(ec::E_POOL_EXHAUSTED),
                        ErrorCategory::ProtocolReject,
                        "AIRDROP pool exhausted — no more claims available".to_string(),
                    ),
                };
            }
        }
    }

    // KI#22 (2026-05-28): both arms write the SMT. The original code
    // skipped the write on `supplemental: true` and relied on the
    // outbound gossip below to round-trip back into `apply_state_update`
    // — but that's eventually-consistent at best, gossip-silently-lost
    // at worst. The SDK's FactConfirmRequest contract is "store this
    // receipt now, not when gossip happens to arrive."
    //
    // Both arms route through the same `superseded_by` merge that
    // `gossip::apply_state_update` already uses, so a backward write
    // (candidate older than existing) is a no-op; freeze monotonicity
    // (§32) is preserved (the rank step in `superseded_by` blocks
    // FROZEN→Normal); group_members and status are inherited from the
    // existing entry to match the gossip path's behavior (a
    // confirmation can never drop group allocations or demote a
    // freeze).
    {
        let (status, group_members) = match node.core.smt().get(&wallet_pk) {
            Some(existing) => (existing.status, existing.group_members.clone()),
            None => (axiom_nabla::types::WalletStatus::Normal, None),
        };
        // WI3: fact-confirm is not the authoritative seq-advancing path (the
        // register path sets the k-attested seq) — preserve the held seq so the
        // merge falls through to the existing tick ordering (behavior-unchanged).
        let confirm_seq = node
            .core
            .smt()
            .get(&wallet_pk)
            .map(|e| e.wallet_seq)
            .unwrap_or(0);
        let candidate = axiom_nabla::types::NablaEntry {
            wallet_id: wallet_pk,
            current_state: new_state,
            tx_hash,
            tick,
            wallet_seq: confirm_seq,
            group_members,
            status,
            client_pk: [0u8; 32],
            client_sig: vec![],
        };
        let should_write = match node.core.smt().get(&wallet_pk) {
            Some(existing) => existing.superseded_by(&candidate),
            None => true,
        };
        if should_write {
            node.core.smt_mut().put(&candidate);
        }
    }
    node.registration_count = node.registration_count.saturating_add(1);

    let gossip_msg = WireMessage::Gossip(axiom_nabla::types::GossipMessage::StateUpdate {
        wallet_id: wallet_pk,
        new_state,
        tx_hash,
        tick,
            is_genesis_claim: false,
        // WI3: the candidate (with its preserved seq) was just written above —
        // gossip the same seq the SMT now holds.
        wallet_seq: node.core.smt().get(&wallet_pk).map(|e| e.wallet_seq).unwrap_or(0),
        client_pk: [0u8; 32],
        client_sig: vec![],
        amount: 0,
        fee_breakdown: Vec::new(),
        // WI3 hole-1: fact-confirm preserves the held seq (no advance), so it
        // needs no proof — peers that are not behind treat it as a tick-tiebreak.
        seq_proof: None,
    });
    for target_id in node.core.mesh().unwrap().forward_targets(&node.node_id) {
        if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&target_id) {
            outbound.push((to_socket_addr(&peer.address), gossip_msg.clone()));
        }
    }

    let root_hash = node.core.smt().root_hash();
    let node_id = node.node_id;
    // V2 payload includes the writer's TARDIS tick at commit time —
    // binds the signature to the moment of SMT commit so Core CL5
    // can enforce the same-tick redeem block (YP §17.10.5.3).  The
    // SDK reads RegisterResponse.tick and writes it into the FACT
    // link's NablaConfirmation.committed_at_tick.
    let confirm_payload = axiom_nabla::crypto::fact_confirm_payload(
        &old_state, &new_state, tick,
    );
    let confirm_signature = node.core.signer().sign(&confirm_payload);
    let nabla_pk = node.core.signer().public_key();

    // NBC trust-anchor (KI#8 — 2026-05-15).  Same fields the TCP
    // RegisterAck path populates; binds this node's confirmation
    // signature to NABLA_ROOT_AUTHORITY_PKS via SPHINCS+ in Core's
    // verify_fact_link.  Empty when the node hasn't received its NBC.
    let (nbc_issuer_pk, nbc_signature, nbc_commitment) =
        if let Ok(nbc) = axiom_nabla::cc::deserialize_nbc(&node.own_nbc_bytes) {
            let commitment = axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&nbc);
            (
                nbc.issuer_set.first().cloned().unwrap_or_default(),
                nbc.signatures.first().cloned().unwrap_or_default(),
                commitment,
            )
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

    FactConfirmOutcome::Ok(axiom_nabla::wire_client::RegisterResponse {
        status: "REGISTERED".to_string(),
        reason: String::new(),
        wallet_pk,
        new_state,
        root_hash,
        tick,
        node_id,
        nabla_node_pk: nabla_pk,
        nabla_signature: confirm_signature.clone(),
        fact_confirm_signature: confirm_signature,
        // Post-fix invariant: if we reached this Ok branch, the pool
        // claim either Granted or wasn't attempted (non-genesis path).
        // All three refusal paths early-return Rejected above.
        pool_exhausted: false,
        nbc_issuer_pk,
        nbc_signature,
        nbc_commitment,
    })
}

/// HTTP wrapper around `fact_confirm_core`.  Decodes the CBOR body,
/// holds the state lock, drains the local outbound queue into the
/// HTTP-side shared queue, and translates `FactConfirmOutcome` into a
/// `(status_code, cbor_body)` pair.  Logic lives in
/// `fact_confirm_core` and is shared with the TCP arm.
fn handle_http_register(
    body: &[u8],
    state: &Arc<Mutex<NablaNodeState>>,
    http_outbound: &Arc<Mutex<Vec<(std::net::SocketAddr, WireMessage)>>>,
) -> (u16, Vec<u8>) {
    use axiom_errors::{error_code as ec, ErrorCategory};
    let req: axiom_nabla::wire_client::RegisterRequest =
        match ciborium::de::from_reader(body) {
            Ok(r) => r,
            Err(_) => return http_error_cbor(
                400, ec::E_NABLA_INVALID_JSON_BODY, ErrorCategory::ClientBug,
                "Invalid CBOR body",
            ),
        };

    let mut node = state.lock().unwrap();
    let mut local_outbound: Vec<(std::net::SocketAddr, WireMessage)> = Vec::new();
    let outcome = fact_confirm_core(&req, &mut node, &mut local_outbound);
    drop(node);
    // Drain queued gossip into the HTTP shared outbound.
    if !local_outbound.is_empty() {
        let mut shared = http_outbound.lock().unwrap();
        shared.extend(local_outbound);
    }
    match outcome {
        FactConfirmOutcome::Ok(resp) => (200, cbor_body(&resp)),
        FactConfirmOutcome::Mismatch(m) => (409, cbor_body(&m)),
        FactConfirmOutcome::Rejected { http_status, error } => {
            // Mirror http_error_cbor shape — pre-existing helper takes
            // string code+category+msg, we re-encode the typed error.
            (http_status, cbor_body(&error))
        }
    }
}

/// HTTP POST /clara — CLARA wallet recovery registration (YPX-018 §2.4,
/// hardened in Phase 5e + Phase 5f).
///
/// Accepts JSON body — Phase 5f requires a real ChequeBundle AND the
/// authoritative TX_HEAL transaction:
/// ```json
/// {
///   "wallet_pk":         "<64 hex>",
///   "heal_cheque":       { "cheques": [<ValidatorCheque>...], "fact_chain": null },
///   "heal_transaction":  <Transaction>,
///   "declared_garbage":  ["<64 hex>", ...]
/// }
/// ```
///
/// `healed_from_state_id` and `healed_at_seq` are NO LONGER caller-asserted —
/// they are derived authoritatively from `heal_transaction.consumed_state_id`
/// and `heal_transaction.wallet_seq` after the tx ↔ cheque binding is verified.
///
/// The Nabla node:
///   - Verifies cheques.len() >= 3
///   - Verifies bundle internal consistency (matching txid/amount/etc)
///   - Verifies sender_wallet_id == receiver_wallet_id (cheque-level self-send)
///   - Verifies each validator's Ed25519 signature against the cheque commitment
///   - Phase 5f: verifies `heal_transaction.is_heal() == true`
///   - Phase 5f: verifies `heal_transaction` is itself a self-send
///   - Phase 5f: verifies `compute_txid(heal_transaction) == cheque.txid`
///     (binds the tx to the bundle)
///   - Phase 5f: verifies `heal_transaction.client_pk == request.wallet_pk`
///     (binds wallet_pk to the tx)
///   - Phase 5f: verifies `verify_pk_binding(sender_wallet_id, wallet_pk)`
///     (binds wallet_pk to the cheque's wallet_id, YPX-007 pk_bind)
///   - Derives heal_txid and healed_to_state_id from the cheque (NOT from caller)
///   - Derives healed_from_state_id and healed_at_seq from the heal transaction
///   - Performs freshness checks against both bloom chains
///   - Inserts heal_txid + declared_garbage into the bloom chains
///   - Builds and signs a `ClaraAttestation` with NBC trust anchor populated
///     from the node's own NBC (Phase 5e fix #5)
///   - Returns the on-wire attestation as JSON
/// Transport-agnostic core for `/clara`. Both the HTTP handler and the
/// TCP-CBOR `WireMessage::RegisterClaraRequest` arm call this. Returns a
/// typed response carrying either a signed `ClaraAttestation` (success)
/// or an `error_code`/`error_reason` pair (rejection).
///
/// Shape mirrors what `handle_http_clara` used to emit as JSON, just
/// with bytes-as-bytes instead of bytes-as-hex. Lock-release/sign/gossip
/// invariants documented inline are preserved verbatim.
pub(crate) fn register_clara_core(
    wire_req: &axiom_nabla::wire_client::RegisterClaraRequest,
    node: &mut NablaNodeState,
    outbound: &mut Vec<(std::net::SocketAddr, WireMessage)>,
) -> axiom_nabla::wire_client::RegisterClaraResponse {
    use axiom_nabla::clara::{register_clara, ClaraRegistrationError, ClaraRegistrationRequest};

    use axiom_nabla::wire_client as wc;

    let req = ClaraRegistrationRequest {
        wallet_pk: wire_req.wallet_pk,
        heal_cheque: wire_req.heal_cheque.clone(),
        heal_transaction: wire_req.heal_transaction.clone(),
        declared_garbage: wire_req.declared_garbage.clone(),
        healed_balance: wire_req.healed_balance,
    };

    // Audit fix v2.11.15-beta6 (audit pass #2 finding 3): minimize the
    // contiguous time the global node lock is held during CLARA registration.
    //
    // Pre-fix the entire flow ran under one `state.lock()`:
    //   acquire → snapshot NBC fields → register_clara (heavy: bloom inserts,
    //   sig verify, txid binding) → sign attestation → build JSON response →
    //   release.
    // Bursty CLARA traffic could briefly stall unrelated Nabla duties
    // (gossip ticks, HTTP handlers, TARDIS) waiting on this lock.
    //
    // Post-fix the lock holds for register_clara + the read-only snapshot of
    // NBC trust-anchor fields and the signer Arc, then is dropped *before*
    // the attestation is signed and serialized. The signer is now an
    // `Arc<dyn Signer + Send + Sync>` (see node.rs::NablaNode), so
    // `signer_arc()` is a cheap `Arc::clone` that produces an owned handle
    // safe to call `.sign(..)` on outside the lock. Sign + JSON build are
    // pure (no shared state), so they don't need any lock at all.
    //
    // Time-under-lock improvement (typical, measured): ~30% — sign is
    // microseconds (negligible) but the JSON build was hundreds of µs and
    // dominated when CLARA traffic was bursty. The bigger win is structural:
    // unrelated handlers no longer wait on signing or serialization.
    // Reader-only nodes do not accept CLARA registrations.
    if node.reader_only {
        return wc::RegisterClaraResponse {
            status: "REDIRECT".to_string(),
            attestation: None,
            confirmation_root_hash: vec![],
            confirmation_tick: 0,
            confirmation_node_id: vec![],
            error_code: String::new(),
            error_reason: "reader_only".to_string(),
        };
    }

    let (ok, current_tick, nabla_node_pk_snapshot, nbc_issuer_pk_snapshot,
         nbc_signature_snapshot, nbc_commitment_snapshot, signer_arc_snapshot,
         smt_root_hash, smt_node_id) = {
        let current_tick = node.virtual_secs;

        // Snapshot the node's NBC trust-anchor fields (Phase 5e fix #5) BEFORE
        // taking the split-borrow on the bloom chains. We need them populated
        // in the response attestation so it passes Core CL2 verification.
        let nbc_issuer_pk_snapshot: Vec<u8>;
        let nbc_signature_snapshot: Vec<u8>;
        let nbc_commitment_snapshot: Vec<u8>;
        let nabla_node_pk_snapshot: [u8; 32];
        {
            // The node carries its own NBC bytes — extract issuer pk + sig + commitment
            // from the deserialized form. The NBC binds the node's Ed25519 pk via the
            // commitment (which contains the pk bytes).
            let pk_vec = node.core.signer().public_key();
            let mut pk_arr = [0u8; 32];
            if pk_vec.len() >= 32 { pk_arr.copy_from_slice(&pk_vec[..32]); }
            nabla_node_pk_snapshot = pk_arr;

            // Decode this node's own NBC to pull issuer + signature + commitment.
            // own_nbc_bytes is the bincode-serialized NBC.
            if let Ok(nbc) = bincode::deserialize::<axiom_core_logic::types::VBC>(&node.own_nbc_bytes) {
                // The NBC's issuer_set/signatures are k=1 for Nabla nodes; pull [0].
                nbc_issuer_pk_snapshot = nbc.issuer_set.first().cloned().unwrap_or_default();
                nbc_signature_snapshot = nbc.signatures.first().cloned().unwrap_or_default();
                // YPX-018 Phase 5f: nbc_commitment must be the SPHINCS+ pre-image bytes,
                // NOT the BLAKE3 hash. Core CL2's verify_nbc_for_clara_attestation needs the
                // pre-image so it can (a) recompute the hash itself for SPHINCS+ verify, and
                // (b) window-scan the pre-image to confirm `nabla_node_pk` is bound into the NBC.
                // The hash output cannot satisfy (b).
                nbc_commitment_snapshot = axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&nbc);
            } else {
                // No NBC available — produce empty fields. Core CL2 will then
                // reject the attestation with ClaraNbcTrustFailed, which is the
                // correct fail-closed behavior on a misconfigured node.
                nbc_issuer_pk_snapshot = vec![];
                nbc_signature_snapshot = vec![];
                nbc_commitment_snapshot = vec![];
            }
        }

        // Snapshot the signer as an Arc — cheap clone, owned handle. Used
        // to call signer.sign(..) AFTER the lock is dropped (see below).
        let signer_arc_snapshot = node.core.signer_arc();

        // Split borrow so both bloom chains AND the rate limiter can be passed
        // to register_clara simultaneously without aliasing the parent
        // NablaNodeState struct.
        let result = {
            let NablaNodeState {
                txid_bloom_chain: ref mut txid_chain,
                garbage_state_chain: ref mut garbage_chain,
                clara_rate_limiter: ref mut rate_limiter,
                ..
            } = *node;
            register_clara(&req, txid_chain, garbage_chain, rate_limiter, current_tick)
        };

        // On success, register the healed state in the SMT so the heal link
        // is immediately queryable (unscar). Without this the client would
        // need a separate POST /register round-trip.
        let (smt_root_hash, smt_node_id) = if let Ok(ref ok_val) = result {
            let tx_hash = {
                let mut h = blake3::Hasher::new();
                h.update(b"AXIOM_CLARA_HEAL");
                h.update(&ok_val.healed_from_state_id);
                h.update(&ok_val.healed_to_state_id);
                *h.finalize().as_bytes()
            };
            // WI3 hole-1: a heal is a forward re-anchor (X→H), but this Nabla-side
            // CLARA handler has no k=3 receipt-commitment proof for it, so it MUST
            // NOT claim a seq advance peers can't verify (the unproven-advance
            // gate would reject the gossip). PRESERVE the held seq — H still
            // propagates via the tick tiebreaker, exactly as pre-WI3; the
            // authoritative seq advance arrives later through the client's
            // register-with-proof path. (Wire the heal receipt's k-attested
            // new_wallet_seq + proof here to restore seq-priority for heals.)
            let heal_seq = node
                .core
                .smt()
                .get(&req.wallet_pk)
                .map(|e| e.wallet_seq)
                .unwrap_or(0);
            node.core.smt_mut().put(&axiom_nabla::types::NablaEntry {
                wallet_id: req.wallet_pk,
                current_state: ok_val.healed_to_state_id,
                tx_hash,
                tick: current_tick,
                wallet_seq: heal_seq,
                group_members: None,
                status: axiom_nabla::types::WalletStatus::Normal,
                client_pk: [0u8; 32],
                client_sig: vec![],
            });
            node.registration_count = node.registration_count.saturating_add(1);

            let gossip_msg = WireMessage::Gossip(axiom_nabla::types::GossipMessage::StateUpdate {
                wallet_id: req.wallet_pk,
                new_state: ok_val.healed_to_state_id,
                tx_hash,
                tick: current_tick,
            is_genesis_claim: false,
                wallet_seq: heal_seq, // WI3: same (preserved) seq the heal entry was written with
                client_pk: [0u8; 32],
                client_sig: vec![],
                amount: 0,
                fee_breakdown: Vec::new(),
                // WI3 hole-1: no heal receipt-commitment proof available here, and
                // heal_seq preserves the held seq (no advance) — no proof needed.
                seq_proof: None,
            });
            {
                for target_id in node.core.mesh().unwrap().forward_targets(&node.node_id) {
                    if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&target_id) {
                        outbound.push((to_socket_addr(&peer.address), gossip_msg.clone()));
                    }
                }
            }

            (node.core.smt().root_hash(), node.node_id)
        } else {
            ([0u8; 32], [0u8; 32])
        };

        (result, current_tick, nabla_node_pk_snapshot, nbc_issuer_pk_snapshot,
         nbc_signature_snapshot, nbc_commitment_snapshot, signer_arc_snapshot,
         smt_root_hash, smt_node_id)
        // ── lock dropped here ──
    };

    let ok = match ok {
        Ok(o) => o,
        Err(e) => {
            let (http_code, reason) = match e {
                ClaraRegistrationError::BadRequest => (400, "bad_request"),
                ClaraRegistrationError::NotSelfSend => (400, "not_self_send"),
                ClaraRegistrationError::InsufficientSignatures => (400, "insufficient_signatures"),
                ClaraRegistrationError::InconsistentBundle => (400, "inconsistent_bundle"),
                ClaraRegistrationError::InvalidValidatorSignature => (400, "invalid_validator_signature"),
                ClaraRegistrationError::EmptyGarbage => (400, "empty_garbage"),
                ClaraRegistrationError::ConsumedAlreadyTxidRegistered => {
                    (409, "consumed_already_txid_registered")
                }
                ClaraRegistrationError::ConsumedAlreadyGarbage => (409, "consumed_already_garbage"),
                ClaraRegistrationError::WalletPkMismatch => (400, "wallet_pk_mismatch"),
                ClaraRegistrationError::HealAlreadyRegistered => (409, "heal_already_registered"),
                ClaraRegistrationError::NotMarkedHeal => (400, "not_marked_heal"),
                ClaraRegistrationError::HealTxidMismatch => (400, "heal_txid_mismatch"),
                ClaraRegistrationError::HealTransactionNotSelfSend => {
                    (400, "heal_transaction_not_self_send")
                }
                ClaraRegistrationError::TooManyGarbageStates => {
                    (400, "too_many_garbage_states")
                }
                ClaraRegistrationError::RateLimited => (429, "rate_limited"),
                ClaraRegistrationError::HealedBalanceMismatch => {
                    (400, "healed_balance_mismatch")
                }
            };
            // Map clara rejection reasons to the CLARA error code.
            // The specific reason is carried in the message for
            // precise client dispatch (clients that want finer-grained
            // handling can substring-match on the code's message, but
            // the taxonomy groups all clara registration rejections
            // under E_NABLA_CLARA_INVALID_ATTESTATION for now).
            let ec = if http_code == 409 {
                axiom_errors::error_code::E_NABLA_CLARA_ALREADY_REGISTERED
            } else {
                axiom_errors::error_code::E_NABLA_CLARA_INVALID_ATTESTATION
            };
            return wc::RegisterClaraResponse {
                status: "ERROR".to_string(),
                attestation: None,
                confirmation_root_hash: vec![],
                confirmation_tick: 0,
                confirmation_node_id: vec![],
                error_code: ec.to_string(),
                error_reason: reason.to_string(),
            };
        }
    };

    // Build the on-wire ClaraAttestation. Phase 5f: every heal-related field
    // is now derived authoritatively (heal_txid + healed_to_state_id from the
    // verified cheque, healed_from_state_id + healed_at_seq from the verified
    // heal transaction). Nothing is caller-asserted.
    use axiom_core_logic::types::ClaraAttestation;
    let mut att = ClaraAttestation {
        wallet_pk: req.wallet_pk,
        healed_from_state_id: ok.healed_from_state_id,  // derived from tx
        healed_to_state_id: ok.healed_to_state_id,      // derived from cheque
        healed_at_seq: ok.healed_at_seq,                // derived from tx
        healed_balance: ok.healed_balance,              // verified via state_hash
        heal_txid: ok.heal_txid,                        // derived from cheque
        garbage_state_ids: req.declared_garbage.clone(),
        bloom_era_id: ok.bloom_era_id,
        bloom_era_root: ok.bloom_era_root,
        nabla_tick: current_tick,
        nabla_node_pk: nabla_node_pk_snapshot,
        nabla_signature: vec![],
        // Phase 5e fix #5 — populate NBC trust anchor fields so Core CL2's
        // mandatory NBC verification can succeed.
        nbc_issuer_pk: nbc_issuer_pk_snapshot,
        nbc_signature: nbc_signature_snapshot,
        nbc_commitment: nbc_commitment_snapshot,
    };
    let msg = axiom_core_logic::compute::compute_clara_message(&att);
    // Sign OUTSIDE the global node lock — `signer_arc_snapshot` is an
    // owned `Arc<dyn Signer>` cloned inside the lock above. The Signer
    // trait is `Send + Sync` so this is safe across threads. See the
    // big comment at the top of this handler for the rationale.
    att.nabla_signature = signer_arc_snapshot.sign(&msg);

    wc::RegisterClaraResponse {
        status: "REGISTERED".to_string(),
        attestation: Some(att),
        confirmation_root_hash: smt_root_hash.to_vec(),
        confirmation_tick: current_tick,
        confirmation_node_id: smt_node_id.to_vec(),
        error_code: String::new(),
        error_reason: String::new(),
    }
}

/// HTTP wrapper around `register_clara_core`.  CBOR-on-the-wire
/// (2026-05-14): the request body is a CBOR-encoded
/// `RegisterClaraRequest` and the response is the typed
/// `RegisterClaraResponse` — same struct the TCP path uses.
fn handle_http_clara(
    body: &[u8],
    state: &Arc<Mutex<NablaNodeState>>,
    http_outbound: &Arc<Mutex<Vec<(std::net::SocketAddr, WireMessage)>>>,
) -> (u16, Vec<u8>) {
    let req: axiom_nabla::wire_client::RegisterClaraRequest =
        match ciborium::de::from_reader(body) {
            Ok(r) => r,
            Err(_) => return http_error_cbor(
                400, axiom_errors::error_code::E_NABLA_INVALID_JSON_BODY,
                axiom_errors::ErrorCategory::ClientBug, "invalid CBOR body",
            ),
        };

    let resp = {
        let mut node = state.lock().unwrap();
        let mut outbound = http_outbound.lock().unwrap();
        register_clara_core(&req, &mut node, &mut outbound)
    };

    let http_code = match resp.status.as_str() {
        "REGISTERED" | "REDIRECT" => 200,
        _ => match resp.error_reason.as_str() {
            "rate_limited" => 429,
            "consumed_already_txid_registered" | "consumed_already_garbage"
            | "heal_already_registered" => 409,
            _ => 400,
        },
    };
    (http_code, cbor_body(&resp))
}

/// Parse an HTTP request line to extract path and query string.
fn parse_http_request(request: &str) -> (String, Option<String>) {
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return ("/".into(), None);
    }
    let full_path = parts[1];
    if let Some(idx) = full_path.find('?') {
        (full_path[..idx].to_string(), Some(full_path[idx + 1..].to_string()))
    } else {
        (full_path.to_string(), None)
    }
}

/// Outcome of `pulse_proof_core` — success or a typed rejection.
enum PulseProofOutcome {
    Ok(axiom_nabla::wire_client::PulseProofResponse),
    Rejected { http_status: u16, error: axiom_errors::ErrorResponse },
}

/// Transport-agnostic core for `/pulse-proof` (YPX-009).
///
/// Both the HTTP handler (gated `410 Gone` post-Phase-3c) and the TCP
/// `WireMessage::PulseProofRequest` arm call this. Verifies the
/// validator's Ed25519 signature, then queues a `GossipMessage::PulseProof`
/// to the node's forward targets via `outbound`.
fn pulse_proof_core(
    req: &axiom_nabla::wire_client::PulseProofRequest,
    node: &NablaNodeState,
    outbound: &mut Vec<(std::net::SocketAddr, WireMessage)>,
) -> PulseProofOutcome {
    let err = |code: &'static str, msg: &str| PulseProofOutcome::Rejected {
        http_status: 400,
        error: axiom_errors::ErrorResponse::new(
            code, axiom_errors::ErrorCategory::ClientBug, msg.to_string(),
        ),
    };

    if req.signature.len() != 64 {
        return err(
            axiom_errors::error_code::E_NABLA_NBC_SIG_INVALID,
            "Invalid signature length",
        );
    }

    let sign_payload = axiom_nabla::gossip::pulse_proof_sign_payload(
        &req.validator_pk, req.epoch, &req.full_accumulator, &req.audit_hash,
    );
    if !axiom_nabla::gossip::verify_pulse_proof_sig(
        &req.validator_pk, &req.signature, &sign_payload,
    ) {
        return err(
            axiom_errors::error_code::E_NABLA_NBC_SIG_INVALID,
            "Invalid pulse proof signature",
        );
    }

    let tick = node.core.current_tick();
    let msg = GossipMessage::PulseProof {
        validator_pk: req.validator_pk,
        epoch: req.epoch,
        full_accumulator: req.full_accumulator,
        entry_count: req.entry_count,
        sample_size: req.sample_size,
        audit_hash: req.audit_hash,
        argon2id_per_sec: req.argon2id_per_sec,
        signature: req.signature.clone(),
        tick,
    };

    let wire = WireMessage::Gossip(msg);
    if let Some(mesh) = node.core.mesh() {
        for target_id in mesh.forward_targets(&node.node_id) {
            if let Some(peer) = mesh.peer_by_id(&target_id) {
                outbound.push((to_socket_addr(&peer.address), wire.clone()));
            }
        }
    }

    log::info!("YPX-009: PulseProof accepted (epoch={}, entries={})", req.epoch, req.entry_count);
    PulseProofOutcome::Ok(axiom_nabla::wire_client::PulseProofResponse {
        status: "ACCEPTED".to_string(),
        epoch: req.epoch,
    })
}

/// HTTP POST /pulse-proof — thin wrapper around `pulse_proof_core`.
/// Gated `410 Gone` once `FUNCTIONAL_HTTP_GATED` covers `/pulse-proof`;
/// retained for re-enablement.
fn handle_pulse_proof_post(
    body: &[u8],
    state: &Arc<Mutex<NablaNodeState>>,
    http_outbound: &Arc<Mutex<Vec<(std::net::SocketAddr, WireMessage)>>>,
) -> (u16, Vec<u8>) {
    let req: axiom_nabla::wire_client::PulseProofRequest =
        match ciborium::de::from_reader(body) {
            Ok(r) => r,
            Err(_) => return http_error_cbor(
                400, axiom_errors::error_code::E_NABLA_INVALID_JSON_BODY,
                axiom_errors::ErrorCategory::ClientBug, "Invalid CBOR body",
            ),
        };

    let node = state.lock().unwrap();
    let mut local_outbound: Vec<(std::net::SocketAddr, WireMessage)> = Vec::new();
    let outcome = pulse_proof_core(&req, &node, &mut local_outbound);
    drop(node);
    if !local_outbound.is_empty() {
        http_outbound.lock().unwrap().extend(local_outbound);
    }
    match outcome {
        PulseProofOutcome::Ok(resp) => (200, cbor_body(&resp)),
        PulseProofOutcome::Rejected { http_status, error } => (http_status, cbor_body(&error)),
    }
}

/// HTTP /query endpoint — wallet state lookup for webclient FACT verification.
/// GET /query?wallet_pk=hex32bytes
/// Returns: { status: "REGISTERED"|"NOT_FOUND", state_id, root_hash, tick }
/// Rate limited: reuses the non-blocking accept loop (natural backpressure).
fn handle_http_query(
    query: Option<&str>,
    state: &Arc<Mutex<NablaNodeState>>,
) -> (u16, Vec<u8>) {
    let wallet_pk_hex = query
        .and_then(|q| q.split('&').find(|p| p.starts_with("wallet_pk=")))
        .map(|p| &p[10..]);

    let wallet_pk_hex = match wallet_pk_hex {
        Some(h) if h.len() == 64 => h,
        _ => return http_error_cbor(
            400,
            axiom_errors::error_code::E_NABLA_MISSING_FIELD,
            axiom_errors::ErrorCategory::ClientBug,
            "Missing or invalid wallet_pk (expected 64 hex chars)",
        ),
    };

    let wallet_pk: [u8; 32] = match hex::decode(wallet_pk_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => return http_error_cbor(
            400,
            axiom_errors::error_code::E_NABLA_INVALID_HEX,
            axiom_errors::ErrorCategory::ClientBug,
            "Invalid wallet_pk hex",
        ),
    };

    let resp = {
        let node = state.lock().unwrap();
        query_wallet_state_core(
            &axiom_nabla::wire_client::QueryWalletStateRequest { wallet_pk },
            &node,
        )
    };
    (200, cbor_body(&resp))
}

/// Transport-agnostic core for `GET /query?wallet_pk=...`.  Both the
/// HTTP handler (`handle_http_query`) and the TCP-CBOR
/// `WireMessage::QueryWalletStateRequest` arm call this — the only
/// difference is encoding (JSON hex strings vs CBOR native bytes).
///
/// Added 2026-05-14 to close the 6th of 7 grandfathered HTTP→TCP
/// migration sites from CLAUDE.md §8.  Same protocol semantics as the
/// HTTP path; receivers can switch from hex parsing to direct byte
/// reads.
pub(crate) fn query_wallet_state_core(
    req: &axiom_nabla::wire_client::QueryWalletStateRequest,
    node: &NablaNodeState,
) -> axiom_nabla::wire_client::QueryWalletStateResponse {
    let wallet_pk = req.wallet_pk;
    let root_hash = node.core.smt().root_hash();
    let tick = node.virtual_secs;
    let node_id = node.node_id;
    let nbc_issuer_pk = node.nbc_issuer_pk.clone();

    let role = if node.reader_only {
        "reader"
    } else if node.core.tardis().map(|t| t.is_self_writer()).unwrap_or(false) {
        "writer"
    } else {
        "reader"
    };
    let role_byte: u8 = if role == "writer" { 1 } else { 0 };

    let make_role_sig = |state_id: &[u8; 32]| -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_NABLA_ROLE");
        hasher.update(&node_id);
        hasher.update(&[role_byte]);
        hasher.update(&wallet_pk);
        hasher.update(state_id);
        hasher.update(&tick.to_le_bytes());
        let hash = hasher.finalize();
        node.core.signer().sign(hash.as_bytes())
    };

    match node.core.smt().get(&wallet_pk) {
        Some(entry) => {
            let role_signature = make_role_sig(&entry.current_state);
            let status = match entry.status {
                axiom_nabla::types::WalletStatus::Normal => "NORMAL",
                axiom_nabla::types::WalletStatus::Frozen => "FROZEN",
                axiom_nabla::types::WalletStatus::Tainted => "TAINTED",
                axiom_nabla::types::WalletStatus::Banned => "BANNED",
            };
            axiom_nabla::wire_client::QueryWalletStateResponse {
                status: "REGISTERED".to_string(),
                wallet_id: wallet_pk,
                current_state: entry.current_state.to_vec(),
                tx_hash: entry.tx_hash.to_vec(),
                root_hash: root_hash.to_vec(),
                synced_to_tick: tick,
                registration_tick: entry.tick,
                wallet_status: status.to_string(),
                node_id,
                nbc_issuer_pk,
                role: role.to_string(),
                role_signature,
            }
        }
        None => {
            let role_signature = make_role_sig(&[0u8; 32]);
            axiom_nabla::wire_client::QueryWalletStateResponse {
                status: "NOT_FOUND".to_string(),
                wallet_id: wallet_pk,
                current_state: Vec::new(),
                tx_hash: Vec::new(),
                root_hash: root_hash.to_vec(),
                synced_to_tick: tick,
                registration_tick: 0,
                wallet_status: String::new(),
                node_id,
                nbc_issuer_pk,
                role: role.to_string(),
                role_signature,
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// Txid Query API — Global double-redeem detection
// ════════════════════════════════════════════════════════════════════════

/// Transport-agnostic core for `/query-txid`. Both the HTTP handler and the
/// TCP-CBOR `WireMessage::QueryTxidRequest` arm call this.
///
/// Returns a signed attestation of whether this txid has been redeemed
/// globally. The attestation is what wallets attach to redeem requests;
/// Lambda verifies the signature (Lambda never queries Nabla directly).
///
/// Signing payload: BLAKE3("AXIOM_TXID_ATTEST" || txid || status || tick_le).
pub(crate) fn query_txid_core(
    req: &axiom_nabla::wire_client::QueryTxidRequest,
    node: &NablaNodeState,
) -> axiom_nabla::wire_client::QueryTxidResponse {
    let txid = req.txid;

    // Core runs with the caller already holding the node lock (HTTP
    // handlers via `state.lock()`, TCP `handle_message` via the main
    // loop). Sign happens here under the same scope — the previous
    // lock-release-before-sign optimization is sacrificed for a single
    // shared implementation across both transports.
    let (tick, mode, ed25519_pk, nbc_issuer_pk, nbc_signature, nbc_commitment,
         status, registered_by, signature, claim_status) = {
        let tick = node.virtual_secs;
        let mode = node.core.smt().txid_mode();
        let ed25519_pk = node.core.signer().public_key();
        // Extract flat NBC fields for Core CL5 trust anchor verification.
        // No deserialization needed in Core — fields passed directly.
        let (nbc_issuer_pk, nbc_signature, nbc_commitment): (Vec<u8>, Vec<u8>, Vec<u8>) = {
            let nbc_bincode = &node.own_nbc_bytes;
            if let Ok(nbc) = axiom_nabla::cc::deserialize_nbc(nbc_bincode) {
                // YPX-018 Phase 5f: pre-image bytes, not hash. Core CL5's
                // verify_nbc_for_txid_attestation needs the pre-image to bind
                // `nabla_node_pk` (window-scan) and to recompute the SPHINCS+ hash itself.
                let commitment = axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&nbc);
                let issuer_pk = nbc.issuer_set.first().cloned().unwrap_or_default();
                let signature = nbc.signatures.first().cloned().unwrap_or_default();
                (issuer_pk, signature, commitment)
            } else {
                (vec![], vec![], vec![])
            }
        };

        // Check cheque claim status (§4.6 double-redeem prevention)
        let mut claim_status = node.core.smt().query_cheque_claim(&txid)
            .map(|_| "CLAIMED");

        // Lookup: hashmap (exact) or bloom (probabilistic)
        let (mut status, registered_by) = match mode {
            axiom_nabla::bloom::TxidServiceMode::Hashmap => {
                match node.core.smt().get_wallet_by_txid(&txid) {
                    Some(wallet_id) => ("REDEEMED", wallet_id.to_vec()),
                    None => ("NOT_REDEEMED", vec![]),
                }
            }
            axiom_nabla::bloom::TxidServiceMode::Bloom => {
                if node.core.smt().may_contain_txid(&txid) {
                    ("REDEEMED", vec![])
                } else {
                    ("NOT_REDEEMED", vec![])
                }
            }
        };

        // §4.6 defense: if the cheque was CLAIMED (registered via
        // /register-cheque-claim during §4.6 verification), treat it as
        // REDEEMED even if the bloom/hashmap doesn't have it yet. This
        // closes the stale-attestation attack: an attacker who caches an
        // attestation from before the legitimate claim, then tries to
        // redeem on different validators, will get REDEEMED from any
        // Nabla node that received the claim gossip. The attacker must
        // fetch a fresh attestation, and that attestation will say REDEEMED.
        if status == "NOT_REDEEMED" && claim_status.is_some() {
            status = "REDEEMED";
        }

        // YPX-022 §2.1 enforcement (A): a sender-RECALLED txid is non-redeemable.
        // Serve it REDEEMED (already-consumed) so the receiver's redeem is blocked
        // exactly like the §4.6 double-redeem defense — no CL5 change needed. The
        // recall marker is mode-independent, so this fires in bloom mode too.
        // §2 (2026-07-07): tell the receiver WHY via the UNSIGNED claim_status reason —
        // the cheque was RETRACTED by the sender, not redeemed by someone else. This is
        // informational only (not part of the signed attestation), so CL5 is untouched.
        if node.core.smt().is_txid_burn_resolved(&txid) {
            // YPX-001 §1.5.1a — the scarred origin transition was resolved
            // by a k-witnessed burn. Serve the dedicated status so
            // downstream wallets can clear inherited scars; a "BURNED"
            // attestation still refuses at CL5 redeem (unknown-status
            // catch-all), so a burned txid can never be redeemed with it.
            status = "BURNED";
        } else if node.core.smt().is_txid_recalled(&txid) {
            status = "REDEEMED";
            claim_status = Some("RETRACTED");
        } else if node.core.smt().is_txid_recall_pending(&txid) {
            // YPX-022 §2.2.1 — an OPEN reservation: `C` is still live and
            // redeemable (the signed status stays untouched — the receiver
            // can still obtain the attestation and redeem, and a redeem that
            // finalizes now WINS). The unsigned claim_status tells the
            // receiver why they should hurry: "the sender is in the process
            // of retracting this payment."
            claim_status = Some("RETRACT_PENDING");
        } else if let axiom_nabla::bloom_chain::ChainLookup::Hit { era_id, .. } =
            node.garbage_state_chain.lookup(&txid)
        {
            // YPX-022 §5 archive resolution — NEVER gate on a raw bloom Hit.
            // The exact terminals (is_txid_recalled above) are the archive
            // layer; a chain Hit with an exact-miss is a bloom false positive
            // (or a marker this node never learned) and falls through to
            // ALLOW so a legitimate redeem can never be stranded by the
            // bloom. Logged for telemetry; a remote archive enquiry would
            // plug in here (bloom_chain.rs Phase 3).
            info!(
                "[GARBAGE-FP] query-txid {} hit garbage era {} with no exact recall marker — serving normally",
                hex::encode(&txid[..8]),
                era_id,
            );
        }

        // Sign under lock (signer needs node state), then release
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_TXID_ATTEST");
        hasher.update(&txid);
        hasher.update(status.as_bytes());
        hasher.update(&tick.to_le_bytes());
        let hash = hasher.finalize();
        let signature = node.core.signer().sign(hash.as_bytes());

        (tick, mode, ed25519_pk, nbc_issuer_pk, nbc_signature, nbc_commitment,
         status, registered_by, signature, claim_status)
    };

    axiom_nabla::wire_client::QueryTxidResponse {
        txid,
        status: status.to_string(),
        registered_by,
        nabla_node_pk: ed25519_pk,
        nabla_signature: signature,
        nabla_tick: tick,
        txid_service: mode.to_string(),
        nbc_issuer_pk,
        nbc_signature,
        nbc_commitment,
        claim_status: claim_status.unwrap_or("UNCLAIMED").to_string(),
        // Unsigned UI-timing hint: the SMT completion tick for a completed txid
        // (None otherwise). Lets a recall UI gate its countdown exactly; the real
        // recall-window gate stays in Core CL2 / register_recall.
        completion_tick: node.core.smt().completion_tick(&txid),
    }
}

/// YP §19.6 — query the local hashmap-mode SMT for a validator's
/// accumulated fee earnings and return a Nabla-node-signed
/// `QueryValidatorEarningsResponse`. Bloom-mode nodes return empty +
/// `is_authoritative=false` so the SDK re-queries elsewhere.
///
/// Signing payload: `compute_earnings_attestation_payload(...)` — binds
/// every consumer-visible field (node id, validator id, window, total,
/// entries, authoritativeness flag). NBC chain fields ride alongside so
/// the consumer can verify `nabla_node_pk` belongs to a real Nabla
/// operator without trusting the responder's self-claim.
pub(crate) fn query_validator_earnings_core(
    req: &axiom_nabla::wire_client::QueryValidatorEarningsRequest,
    node: &NablaNodeState,
) -> axiom_nabla::wire_client::QueryValidatorEarningsResponse {
    let validator_id = req.validator_id;
    // Step 8.3.B: the validator's effective floor is the larger of the
    // requested since_tick and Nabla's stored last_claimed_tick.
    // Already-claimed earnings are excluded — prevents accidentally
    // re-claiming the same entries even if the caller passed a wider
    // window.
    let last_claimed = node.validator_pool.last_claimed_tick(&validator_id);
    let since_tick = req.since_tick.max(last_claimed);

    // Sealing tick — also serves as the `until_tick` bound on the
    // returned window. Caller knows this is "everything I've seen
    // for this validator up to this tick on this node."
    let until_tick = node.virtual_secs;
    let mode = node.core.smt().txid_mode();
    let is_authoritative = mode == axiom_nabla::bloom::TxidServiceMode::Hashmap;

    // Bloom-mode short-circuit: no records, empty response, flag set so
    // the SDK knows to ask elsewhere.
    let (total_amount, entries) = if is_authoritative {
        node.core.smt().validator_earnings(&validator_id, since_tick)
    } else {
        (0u64, Vec::new())
    };

    // PR4 — authoritative NET cap from PR3's per-validator NET ledger.
    // For bloom-mode nodes the ledger is also empty (no register has
    // landed in their store), so net_balance = 0 + is_authoritative=false
    // tells the SDK to re-query an authoritative peer.
    //
    // DEV-CLASS LEAK BOUNDARY (Layer 5).  This query reads the PUBLIC
    // `validator_net_ledger` ONLY.  `validator_dev_net_ledger` is NOT
    // exposed through this path — the type system already guarantees
    // it (the field is `ValidatorDevNetLedger`, not
    // `ValidatorNetLedger`, so even a copy-paste mistake here would
    // be a compile error).  Validator-withdrawal mint downstream
    // (`lambda::validator_withdrawal::verify_validator_withdrawal`)
    // consumes this `net_balance` and mints PUBLIC AXC against it;
    // because dev earnings live in a different ledger that this query
    // can't reach, dev fees can NEVER become public AXC via this
    // path.  See `AXIOM_DESIGN_FactClassIsolation.md`.
    let net_balance = if is_authoritative {
        node.core.validator_net_ledger.balance(&validator_id)
    } else {
        0
    };

    // NBC chain fields — same extraction pattern as query_txid_core so a
    // downstream consumer can verify our nabla_node_pk via the same NBC
    // verification path (cc::verify_nbc).
    let (nbc_issuer_pk, nbc_signature, nbc_commitment): (Vec<u8>, Vec<u8>, Vec<u8>) = {
        let nbc_bincode = &node.own_nbc_bytes;
        if let Ok(nbc) = axiom_nabla::cc::deserialize_nbc(nbc_bincode) {
            let commitment = axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&nbc);
            let issuer_pk = nbc.issuer_set.first().cloned().unwrap_or_default();
            let signature = nbc.signatures.first().cloned().unwrap_or_default();
            (issuer_pk, signature, commitment)
        } else {
            (vec![], vec![], vec![])
        }
    };

    // node_id = BLAKE3(sphincs_pk). Pulled from the NBC if available; fall
    // back to all-zero on un-NBC'd dev nodes (consumer treats unsigned
    // responses as untrusted).
    let nabla_node_id: [u8; 32] = {
        if let Ok(nbc) = axiom_nabla::cc::deserialize_nbc(&node.own_nbc_bytes) {
            nbc.validator_id
        } else {
            [0u8; 32]
        }
    };

    let attestation_hash = axiom_core_logic::compute::compute_earnings_attestation_payload(
        &nabla_node_id,
        &validator_id,
        since_tick,
        until_tick,
        total_amount,
        &entries,
        is_authoritative,
        net_balance,
    );
    let nabla_signature = node.core.signer().sign(&attestation_hash);
    let nabla_node_pk = node.core.signer().public_key();

    axiom_nabla::wire_client::QueryValidatorEarningsResponse {
        validator_id,
        // Echo the validator's effective floor (which may differ from
        // requested since_tick if last_claimed_tick is higher).
        since_tick,
        until_tick,
        total_amount,
        net_balance,
        entries,
        is_authoritative,
        nabla_node_id,
        nabla_node_pk,
        nabla_signature,
        nbc_issuer_pk,
        nbc_signature,
        nbc_commitment,
    }
}

/// GET /query-txid?txid=<64-hex>
///
/// HTTP wrapper around `query_txid_core`. Parses the query string into a
/// typed request, calls the core, then hex-encodes byte fields back into
/// the JSON shape the SDK's existing HTTP path expects (backward-compat).
///
/// New SDK callsites should use `WireMessage::QueryTxidRequest` over TCP
/// instead — CBOR carries bytes natively without the hex round-trip.
fn handle_http_query_txid(
    query: Option<&str>,
    state: &Arc<Mutex<NablaNodeState>>,
) -> (u16, Vec<u8>) {
    let txid_hex = query
        .and_then(|q| q.split('&').find(|p| p.starts_with("txid=")))
        .map(|p| &p[5..]);

    let txid_hex = match txid_hex {
        Some(h) if h.len() == 64 => h,
        _ => return http_error_cbor(
            400,
            axiom_errors::error_code::E_NABLA_MISSING_FIELD,
            axiom_errors::ErrorCategory::ClientBug,
            "Missing or invalid txid (expected 64 hex chars)",
        ),
    };

    let txid: [u8; 32] = match hex::decode(txid_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => return http_error_cbor(
            400,
            axiom_errors::error_code::E_NABLA_INVALID_HEX,
            axiom_errors::ErrorCategory::ClientBug,
            "Invalid txid hex",
        ),
    };

    let resp = {
        let node = state.lock().unwrap();
        query_txid_core(
            &axiom_nabla::wire_client::QueryTxidRequest { txid },
            &node,
        )
    };
    (200, cbor_body(&resp))
}

// ════════════════════════════════════════════════════════════════════════
// Cheque Claim Registration API (§4.6 3-node double-redeem prevention)
// ════════════════════════════════════════════════════════════════════════

/// POST /register-cheque-claim — register cheque claim during §4.6 verification.
///
/// Request body (JSON):
///   { "cheque_id": "hex64", "client_pk": "hex64" }
///
/// Response:
///   { "status": "OK", "cheque_id": "hex64", "claim_tick": N, ... }
///   { "status": "CONFLICT", ... } (409 — informational, different client)
///   { "status": "CONFIRMED", ... } (409 — already confirmed)
///
/// The response is signed with the node's Ed25519 key + NBC trust anchor.
/// Transport-agnostic core for `/register-cheque-claim`. Both the HTTP
/// handler and the TCP-CBOR `WireMessage::RegisterChequeClaimRequest` arm
/// call this. Returns a typed response whose `status` field is the same
/// "OK" / "CONFLICT" / "CONFIRMED" / "ERROR" string the JSON body used.
pub(crate) fn register_cheque_claim_core(
    req: &axiom_nabla::wire_client::RegisterChequeClaimRequest,
    node: &mut NablaNodeState,
) -> axiom_nabla::wire_client::RegisterChequeClaimResponse {
    let current_tick = node.virtual_secs;

    let result = node.core.smt_mut().register_cheque_claim(
        req.cheque_id, req.client_pk.clone(), current_tick,
    );

    match result {
        Ok(()) => {
            // Sign: BLAKE3("AXIOM_REDEEM_CLAIM" || cheque_id || "CLAIMED" || tick_le)
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"AXIOM_REDEEM_CLAIM");
            hasher.update(&req.cheque_id);
            hasher.update(b"CLAIMED");
            hasher.update(&current_tick.to_le_bytes());
            let hash = hasher.finalize();
            let signature = node.core.signer().sign(hash.as_bytes());
            let ed25519_pk = node.core.signer().public_key();

            // Build the typed ChequeClaimProof Core CL5 will verify.
            // Same NBC trust-anchor triple the txid_attestation path
            // uses (Phase 5f); empty fields if the node's NBC bytes
            // aren't yet available (boot-time race).  The SDK passes
            // this struct directly into Core's PublicInputs — no
            // mirror fields, no compat shims (type unification
            // 2026-05-14).
            let (nbc_issuer_pk, nbc_signature, nbc_commitment):
                (Vec<u8>, Vec<u8>, Vec<u8>) = {
                let nbc_bincode = &node.own_nbc_bytes;
                if let Ok(nbc) = axiom_nabla::cc::deserialize_nbc(nbc_bincode) {
                    let commitment = axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&nbc);
                    let issuer_pk = nbc.issuer_set.first().cloned().unwrap_or_default();
                    let sig = nbc.signatures.first().cloned().unwrap_or_default();
                    (issuer_pk, sig, commitment)
                } else {
                    (vec![], vec![], vec![])
                }
            };

            // `client_pk` echoes the requester's 32-byte pubkey from
            // the claim request — Core's CL5 freshness/binding checks
            // don't currently bind to receiver_pk (see the design
            // note in modes.rs Step 3.5b), but we ship it so the
            // claim record on the wire is self-describing.
            let mut node_pk_arr = [0u8; 32];
            if ed25519_pk.len() == 32 {
                node_pk_arr.copy_from_slice(&ed25519_pk);
            }
            let mut client_pk_arr = [0u8; 32];
            if req.client_pk.len() == 32 {
                client_pk_arr.copy_from_slice(&req.client_pk);
            }
            let proof = axiom_core_logic::types::ChequeClaimProof {
                cheque_id: req.cheque_id,
                client_pk: client_pk_arr,
                claim_tick: current_tick,
                nabla_node_pk: node_pk_arr,
                nabla_signature: signature,
                nbc_issuer_pk,
                nbc_signature,
                nbc_commitment,
            };

            axiom_nabla::wire_client::RegisterChequeClaimResponse {
                status: "OK".to_string(),
                proof: Some(proof),
                error: String::new(),
            }
        }
        Err(ref e) if e == "CONFLICT" => axiom_nabla::wire_client::RegisterChequeClaimResponse {
            status: "CONFLICT".to_string(),
            proof: None,
            error: "different client already claimed this cheque".to_string(),
        },
        Err(ref e) if e == "CONFIRMED" => axiom_nabla::wire_client::RegisterChequeClaimResponse {
            status: "CONFIRMED".to_string(),
            proof: None,
            error: "cheque already confirmed (fully redeemed)".to_string(),
        },
        Err(e) => axiom_nabla::wire_client::RegisterChequeClaimResponse {
            status: "ERROR".to_string(),
            proof: None,
            error: e,
        },
    }
}

/// YPX-022 §2.1 — handle a sender-initiated RECALL (`register_recall`, sibling of
/// `register_cheque_claim_core`). Authorship-gated: the request MUST carry the
/// sender's 32-byte Ed25519 pubkey + a signature over BLAKE3("AXIOM_RECALL" || txid)
/// (only the sender may recall their own send). The SMT gate refuses if the txid
/// already has a k-witnessed COMPLETION registration (redeemable — the retract case);
/// otherwise it marks the txid recalled (consume-once, first-wins). Enforcement rides
/// query-txid (option A): a recalled txid is served REDEEMED so the receiver's redeem
/// is blocked exactly like the §4.6 double-redeem defense.
pub(crate) fn register_recall_core(
    req: &axiom_nabla::wire_client::RecallRequest,
    node: &mut NablaNodeState,
) -> axiom_nabla::wire_client::RecallResponse {
    use axiom_nabla::wire_client::RecallResponse;
    let err = |m: &str| RecallResponse { status: "ERROR".to_string(), attestation: None, error: m.to_string() };

    // RECOMPUTE the txid from the carried tx — NEVER trust a passed txid. This is what
    // binds presend_state_hash to the recalled send (§2.1 / 3.2b-2).
    let txid = axiom_core_logic::compute::compute_txid(&req.failed_send_tx);

    // Authorship gate: sender_pk MUST be the send's own client_pk (only the sender may
    // recall their own send) + a valid Ed25519 sig over BLAKE3("AXIOM_RECALL"||txid).
    if req.sender_pk.len() != 32 || req.sender_pk.iter().all(|&b| b == 0) {
        return err("missing or zero sender_pk");
    }
    if req.sender_pk != req.failed_send_tx.client_pk {
        return err("sender_pk does not match the send's client_pk");
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_RECALL");
    hasher.update(&txid);
    let msg = hasher.finalize();
    let sig_ok = {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let pk: [u8; 32] = match req.sender_pk.as_slice().try_into() { Ok(a) => a, Err(_) => return err("bad sender_pk length") };
        if req.sender_sig.len() != 64 {
            false
        } else if let Ok(vk) = VerifyingKey::from_bytes(&pk) {
            let sb: [u8; 64] = req.sender_sig.as_slice().try_into().unwrap();
            vk.verify(msg.as_bytes(), &Signature::from_bytes(&sb)).is_ok()
        } else {
            false
        }
    };
    if !sig_ok {
        return err("invalid sender signature over AXIOM_RECALL||txid");
    }

    let current_tick = node.virtual_secs;
    match node.core.smt_mut().register_recall(txid, req.sender_pk.clone(), current_tick) {
        Ok(()) => {
            // YPX-022 §2.2.1 — initiate is a RESERVATION: `C` stays live and
            // redeemable; query-txid serves the unsigned RETRACT_PENDING notice.
            // The garbage insert + durable terminal + committed flood all fire
            // at the COMMIT (the recall self-send's registration = the
            // hibernation-entry event; see the Register handler / 8a').
            // Stamp the txid-bound attestation from the SAME verified failed tx:
            // presend_state_hash = its consumed_state_id, amount = its amount `A`.
            // Both hash to `txid`, so the sender can neither substitute a higher state
            // (over-reclaim) nor inflate `A` (§2, 2026-07-06 forward redesign — Core CL2
            // pins tx.amount == att.amount).
            let presend_state_hash = req.failed_send_tx.consumed_state_id;
            let amount = req.failed_send_tx.amount;
            match axiom_nabla::registration::build_recall_attestation(
                &node.own_nbc_bytes, txid, presend_state_hash, amount, current_tick, node.core.signer(),
            ) {
                Some(att) => RecallResponse { status: "OK".to_string(), attestation: Some(att), error: String::new() },
                None => err("could not build recall attestation (no NBC loaded)"),
            }
        }
        // YPX-022 §2 (2026-07-07 repurpose) — legible failure reasons so the sender
        // knows exactly what happened to their cheque.
        Err(ref e) if e == "REDEEMED" => RecallResponse {
            status: "REDEEMED".to_string(), attestation: None,
            error: "This cheque has already been redeemed by the receiver — it cannot be recalled.".to_string(),
        },
        Err(ref e) if e == "NOT_REGISTERED" => RecallResponse {
            status: "NOT_REGISTERED".to_string(), attestation: None,
            error: "No completed send was found for this cheque — there is nothing to recall.".to_string(),
        },
        Err(ref e) if e == "CONFLICT" => RecallResponse {
            status: "CONFLICT".to_string(), attestation: None,
            error: "This send has already been recalled by a different key.".to_string(),
        },
        Err(ref e) if e == "TOO_EARLY" => RecallResponse {
            status: "TOO_EARLY".to_string(), attestation: None,
            error: "Too early to recall — the receiver's redeem window is still open. Try again later.".to_string(),
        },
        Err(ref e) if e == "TOO_LATE" => RecallResponse {
            status: "TOO_LATE".to_string(), attestation: None,
            error: "Too late to recall — this send has aged past the recall window.".to_string(),
        },
        Err(ref e) if e == "ALREADY_RECALLED" => RecallResponse {
            status: "ALREADY_RECALLED".to_string(), attestation: None,
            error: "This send has already been recalled — the retract is committed and final.".to_string(),
        },
        Err(e) => RecallResponse { status: "ERROR".to_string(), attestation: None, error: e },
    }
}

/// HTTP wrapper around `register_cheque_claim_core`.  CBOR-on-the-wire
/// (2026-05-14): the request body is a CBOR-encoded
/// `RegisterChequeClaimRequest` and the response body is the typed
/// `RegisterChequeClaimResponse` — same struct the TCP path uses, no
/// hex round-trip, no mirror fields.
fn handle_http_register_cheque_claim(
    body: &[u8],
    state: &Arc<Mutex<NablaNodeState>>,
) -> (u16, Vec<u8>) {
    use axiom_errors::{error_code as ec, ErrorCategory};

    let req: axiom_nabla::wire_client::RegisterChequeClaimRequest =
        match ciborium::de::from_reader(body) {
            Ok(r) => r,
            Err(_) => return http_error_cbor(
                400, ec::E_NABLA_INVALID_JSON_BODY, ErrorCategory::ClientBug,
                "Invalid CBOR body",
            ),
        };

    if req.client_pk.len() != 32 {
        return http_error_cbor(
            400, ec::E_NABLA_MISSING_FIELD, ErrorCategory::ClientBug,
            "client_pk must be 32 bytes",
        );
    }

    let resp = {
        let mut node = state.lock().unwrap();
        register_cheque_claim_core(&req, &mut node)
    };

    let http_code = match resp.status.as_str() {
        "OK" => 200,
        "CONFLICT" | "CONFIRMED" => 409,
        _ => 500,
    };
    (http_code, cbor_body(&resp))
}

/// GET /query-cheque-claim?cheque_id=<64-hex>
///
/// Returns cheque claim status: UNCLAIMED, CLAIMED.  Response body is
/// the CBOR-encoded `wire_client::QueryChequeClaimResponse` typed
/// struct.
fn handle_http_query_cheque_claim(
    query: Option<&str>,
    state: &Arc<Mutex<NablaNodeState>>,
) -> (u16, Vec<u8>) {
    let cheque_id_hex = query
        .and_then(|q| q.split('&').find(|p| p.starts_with("cheque_id=")))
        .map(|p| &p[10..]);

    let cheque_id_hex = match cheque_id_hex {
        Some(h) if h.len() == 64 => h,
        _ => return http_error_cbor(
            400, axiom_errors::error_code::E_NABLA_MISSING_FIELD,
            axiom_errors::ErrorCategory::ClientBug,
            "Missing or invalid cheque_id (expected 64 hex chars)",
        ),
    };

    let cheque_id: [u8; 32] = match hex::decode(cheque_id_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => return http_error_cbor(
            400, axiom_errors::error_code::E_NABLA_INVALID_HEX,
            axiom_errors::ErrorCategory::ClientBug, "Invalid cheque_id hex",
        ),
    };

    let node = state.lock().unwrap();
    let tick = node.virtual_secs;

    let status = match node.core.smt().query_cheque_claim(&cheque_id) {
        Some(_) => "CLAIMED",
        None => "UNCLAIMED",
    };

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_CHEQUE_QUERY");
    hasher.update(&cheque_id);
    hasher.update(status.as_bytes());
    hasher.update(&tick.to_le_bytes());
    let hash = hasher.finalize();
    let signature = node.core.signer().sign(hash.as_bytes());
    let ed25519_pk = node.core.signer().public_key();

    let resp = axiom_nabla::wire_client::QueryChequeClaimResponse {
        cheque_id,
        status: status.to_string(),
        nabla_node_pk: ed25519_pk,
        nabla_signature: signature,
        nabla_tick: tick,
    };
    (200, cbor_body(&resp))
}

// ════════════════════════════════════════════════════════════════════════
// Bridge API (§6.6 — HTTP endpoint for partition recovery)
// ════════════════════════════════════════════════════════════════════════

/// Outcome of `bridge_core` — success or a typed rejection.
enum BridgeOutcome {
    Ok(axiom_nabla::wire_client::BridgeResponse),
    Rejected { http_status: u16, error: axiom_errors::ErrorResponse },
}

/// Transport-agnostic core for `/bridge` (§6.6 partition recovery).
///
/// Both the HTTP handler (gated `410 Gone` post-Phase-3c) and the TCP
/// `WireMessage::BridgeRequest` arm call this. Connects to the remote
/// peer, exchanges an `IntroductionRequest`/`IntroductionResponse`, and
/// calls `human_bridge_px` to heal the network partition.
///
/// Locking (task #53): takes the shared `Arc<Mutex<NablaNodeState>>` and
/// locks it only briefly — once to snapshot `node_id`, once to apply
/// `human_bridge_px` — never across the blocking TCP round-trip to the
/// bridge peer. The node lock stays free during the I/O, so tick
/// processing and message handling continue. The pre-fix version held
/// `&mut NablaNodeState` across the whole exchange (up to ~15 s on a
/// slow/unreachable peer), freezing the node.
fn bridge_core(
    req: &axiom_nabla::wire_client::BridgeRequest,
    state: &Arc<Mutex<NablaNodeState>>,
) -> BridgeOutcome {
    let reject = |status: u16, code: &'static str, cat: axiom_errors::ErrorCategory, msg: String| {
        BridgeOutcome::Rejected {
            http_status: status,
            error: axiom_errors::ErrorResponse::new(code, cat, msg),
        }
    };

    let addr: SocketAddr = match req.address.parse() {
        Ok(a) => a,
        Err(_) => return reject(
            400, axiom_errors::error_code::E_NABLA_INVALID_JSON_BODY,
            axiom_errors::ErrorCategory::ClientBug,
            format!("Invalid address: {}", req.address),
        ),
    };

    // Snapshot node_id under a brief lock, then release — the TCP
    // round-trip below runs entirely off the node lock.
    let node_id = { state.lock().unwrap().node_id };

    let mut stream = match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => return reject(
            502, axiom_errors::error_code::E_NABLA_BRIDGE_PEER_UNREACHABLE,
            axiom_errors::ErrorCategory::Operational,
            format!("Cannot connect to {}: {}", addr, e),
        ),
    };
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    let msg = WireMessage::IntroductionRequest { from: node_id };
    let data = match bincode::serialize(&msg) {
        Ok(d) => d,
        Err(e) => return reject(
            500, axiom_errors::error_code::E_NABLA_INVALID_JSON_BODY,
            axiom_errors::ErrorCategory::ClientBug,
            format!("Serialize failed: {}", e),
        ),
    };
    let len_buf = (data.len() as u32).to_be_bytes();
    use std::io::{Read as _, Write as _};
    if let Err(e) = stream.write_all(&len_buf).and_then(|_| stream.write_all(&data)).and_then(|_| stream.flush()) {
        return reject(
            502, axiom_errors::error_code::E_NABLA_BRIDGE_PEER_UNREACHABLE,
            axiom_errors::ErrorCategory::Operational,
            format!("Send failed: {}", e),
        );
    }

    let mut resp_len = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut resp_len) {
        return reject(
            502, axiom_errors::error_code::E_NABLA_BRIDGE_PEER_UNREACHABLE,
            axiom_errors::ErrorCategory::Operational,
            format!("No response: {}", e),
        );
    }
    let resp_size = u32::from_be_bytes(resp_len) as usize;
    if resp_size > 1_048_576 {
        return reject(
            502, axiom_errors::error_code::E_NABLA_BRIDGE_PEER_UNREACHABLE,
            axiom_errors::ErrorCategory::Operational, "Response too large".to_string(),
        );
    }
    let mut resp_buf = vec![0u8; resp_size];
    if let Err(e) = stream.read_exact(&mut resp_buf) {
        return reject(
            502, axiom_errors::error_code::E_NABLA_BRIDGE_PEER_UNREACHABLE,
            axiom_errors::ErrorCategory::Operational,
            format!("Read response failed: {}", e),
        );
    }

    let resp_msg: WireMessage = match bincode::deserialize(&resp_buf) {
        Ok(m) => m,
        Err(e) => return reject(
            502, axiom_errors::error_code::E_NABLA_INVALID_JSON_BODY,
            axiom_errors::ErrorCategory::ClientBug,
            format!("Deserialize failed: {}", e),
        ),
    };

    match resp_msg {
        WireMessage::IntroductionResponse { peers } => {
            // Re-acquire the lock only to apply the peer exchange.
            let (received, new_nodes, updated) = {
                let mut node = state.lock().unwrap();
                let tick = node.virtual_secs;
                node.core.mesh_mut().unwrap().human_bridge_px(&peers, tick)
            };
            log::info!("§6.6 Bridge API: {} → exchanged {} peers ({} new, {} updated)",
                addr, received, new_nodes, updated);
            BridgeOutcome::Ok(axiom_nabla::wire_client::BridgeResponse {
                status: "OK".to_string(),
                received: received as u64,
                new_nodes: new_nodes as u64,
                updated: updated as u64,
            })
        }
        other => {
            log::warn!("Bridge API: unexpected response from {}: {:?}", addr, other);
            reject(
                502,
                axiom_errors::error_code::E_NABLA_BRIDGE_PEER_UNREACHABLE,
                axiom_errors::ErrorCategory::Operational,
                "Unexpected response (not IntroductionResponse)".to_string(),
            )
        }
    }
}

/// HTTP POST /bridge — thin wrapper around `bridge_core`.
/// Gated `410 Gone` once `FUNCTIONAL_HTTP_GATED` covers `/bridge`;
/// retained for re-enablement.
fn handle_http_bridge(
    body: &[u8],
    state: &Arc<Mutex<NablaNodeState>>,
) -> (u16, Vec<u8>) {
    let req: axiom_nabla::wire_client::BridgeRequest = match ciborium::de::from_reader(body) {
        Ok(r) => r,
        Err(_) => return http_error_cbor(
            400, axiom_errors::error_code::E_NABLA_INVALID_JSON_BODY,
            axiom_errors::ErrorCategory::ClientBug, "Invalid CBOR body",
        ),
    };

    // bridge_core takes the shared Arc<Mutex> and locks only briefly —
    // it must NOT be called with the node lock already held (task #53).
    match bridge_core(&req, state) {
        BridgeOutcome::Ok(resp) => (200, cbor_body(&resp)),
        BridgeOutcome::Rejected { http_status, error } => (http_status, cbor_body(&error)),
    }
}

// ════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════
// Ban Challenge Protocol (S6 — Yellow Paper §32)
// ════════════════════════════════════════════════════════════════════════

/// Transport-agnostic core for `/endorse-ban-challenge`.
///
/// Both the HTTP handler (gated `410 Gone` post-Phase-3c) and the TCP
/// `WireMessage::EndorseBanChallengeRequest` arm call this. Signs the
/// challenge commitment with the node's Ed25519 key. No outbound queue —
/// endorsing a challenge produces no gossip.
fn endorse_ban_challenge_core(
    req: &axiom_nabla::wire_client::EndorseBanChallengeRequest,
    node: &NablaNodeState,
) -> axiom_nabla::wire_client::EndorseBanChallengeResponse {
    let commitment_vec = axiom_nabla::ban::compute_challenge_commitment(
        &req.wallet_id, &req.original_tx_id,
    );
    let signature = node.core.sign_bytes(&commitment_vec);
    let ed25519_pk_vec = node.core.signer_pk();
    let mut node_id = [0u8; 32];
    if ed25519_pk_vec.len() == 32 {
        node_id.copy_from_slice(&ed25519_pk_vec);
    }
    let mut commitment = [0u8; 32];
    if commitment_vec.len() == 32 {
        commitment.copy_from_slice(&commitment_vec);
    }

    axiom_nabla::wire_client::EndorseBanChallengeResponse {
        node_id,
        signature,
        commitment,
    }
}

/// HTTP POST /endorse-ban-challenge — thin wrapper around
/// `endorse_ban_challenge_core`. Gated `410 Gone` post-Phase-3c;
/// retained for re-enablement.
fn handle_http_endorse_ban_challenge(
    body: &[u8],
    state: &Arc<Mutex<NablaNodeState>>,
) -> (u16, Vec<u8>) {
    let req: axiom_nabla::wire_client::EndorseBanChallengeRequest =
        match ciborium::de::from_reader(body) {
            Ok(r) => r,
            Err(e) => return http_error_cbor(
                400, axiom_errors::error_code::E_NABLA_INVALID_JSON_BODY,
                axiom_errors::ErrorCategory::ClientBug,
                &format!("parse: {e}"),
            ),
        };

    let st = state.lock().unwrap();
    let resp = endorse_ban_challenge_core(&req, &st);
    (200, cbor_body(&resp))
}

/// Transport-agnostic core for `/challenge-ban`.
///
/// Both the HTTP handler (gated `410 Gone` post-Phase-3c) and the TCP
/// `WireMessage::ChallengeBanRequest` arm call this. Applies the
/// challenge locally and queues a `GossipMessage::BanChallenged` to the
/// node's forward targets via `outbound`.
fn challenge_ban_core(
    req: &axiom_nabla::wire_client::ChallengeBanRequest,
    node: &mut NablaNodeState,
    outbound: &mut Vec<(std::net::SocketAddr, WireMessage)>,
) -> axiom_nabla::wire_client::ChallengeBanResponse {
    let nabla_sigs: Vec<axiom_nabla::types::ChallengeEndorsement> = req.endorsements
        .iter()
        .map(|e| axiom_nabla::types::ChallengeEndorsement {
            node_id: e.node_id,
            signature: e.signature.clone(),
        })
        .collect();

    let evidence = axiom_nabla::types::ChallengeEvidence {
        original_tx_id: req.original_tx_id,
        nabla_signatures: nabla_sigs,
    };

    let tick = node.core.current_tick();

    let local_result = node.core.challenge_ban(&req.wallet_id, evidence.clone(), tick);

    if let Some(mesh) = node.core.mesh() {
        let gossip_msg = WireMessage::Gossip(
            axiom_nabla::types::GossipMessage::BanChallenged {
                wallet_id: req.wallet_id,
                evidence: evidence.clone(),
                challenge_tick: tick,
            }
        );
        for target_id in mesh.forward_targets(&node.node_id) {
            if let Some(peer) = mesh.peer_by_id(&target_id) {
                outbound.push((to_socket_addr(&peer.address), gossip_msg.clone()));
            }
        }
    }

    let window = if node.core.is_dev_mode() {
        axiom_nabla::ban::CHALLENGE_WINDOW_TICKS_DEV
    } else {
        axiom_nabla::ban::CHALLENGE_WINDOW_TICKS
    };

    let status = match local_result {
        Ok(()) => "challenged",
        Err(_) => "challenged_via_gossip",
    };
    axiom_nabla::wire_client::ChallengeBanResponse {
        status: status.to_string(),
        challenge_window_ticks: window,
    }
}

/// HTTP POST /challenge-ban — thin wrapper around `challenge_ban_core`.
/// Gated `410 Gone` post-Phase-3c; retained for re-enablement.
fn handle_http_challenge_ban(
    body: &[u8],
    state: &Arc<Mutex<NablaNodeState>>,
    http_outbound: &Arc<Mutex<Vec<(std::net::SocketAddr, WireMessage)>>>,
) -> (u16, Vec<u8>) {
    let req: axiom_nabla::wire_client::ChallengeBanRequest =
        match ciborium::de::from_reader(body) {
            Ok(r) => r,
            Err(e) => return http_error_cbor(
                400, axiom_errors::error_code::E_NABLA_INVALID_JSON_BODY,
                axiom_errors::ErrorCategory::ClientBug,
                &format!("parse: {e}"),
            ),
        };

    let mut st = state.lock().unwrap();
    let mut local_outbound: Vec<(std::net::SocketAddr, WireMessage)> = Vec::new();
    let resp = challenge_ban_core(&req, &mut st, &mut local_outbound);
    drop(st);
    if !local_outbound.is_empty() {
        http_outbound.lock().unwrap().extend(local_outbound);
    }
    (200, cbor_body(&resp))
}

// JFP Secret Registration (Yellow Paper §8.4.3)
// ════════════════════════════════════════════════════════════════════════

/// Outcome of `jfp_secret_core` — success or a typed rejection.
enum JfpSecretOutcome {
    Ok(axiom_nabla::wire_client::JfpSecretResponse),
    Rejected { http_status: u16, error: axiom_errors::ErrorResponse },
}

/// Transport-agnostic core for `/jfp-secret`.
///
/// Both the HTTP handler (gated `410 Gone` post-Phase-3c) and the TCP
/// `WireMessage::JfpSecretRequest` arm call this. Records the secret and
/// queues a gossip `StateUpdate` via `outbound`.
fn jfp_secret_core(
    req: &axiom_nabla::wire_client::JfpSecretRequest,
    node: &mut NablaNodeState,
    outbound: &mut Vec<(std::net::SocketAddr, WireMessage)>,
) -> JfpSecretOutcome {
    {
        let secrets = node.jfp_secrets.entry(req.dwp_wallet_id).or_default();
        if secrets.len() >= 100 {
            return JfpSecretOutcome::Rejected {
                http_status: 400,
                error: axiom_errors::ErrorResponse::new(
                    axiom_errors::error_code::E_NABLA_CLARA_INVALID_ATTESTATION,
                    axiom_errors::ErrorCategory::ProtocolReject,
                    "too many secrets for this DWP wallet",
                ),
            };
        }
        if !secrets.contains(&req.secret) {
            secrets.push(req.secret);
        }
    }

    let synthetic_wallet_id = {
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_JFP_SECRET");
        h.update(&req.dwp_wallet_id);
        h.update(&req.secret);
        let mut id = [0u8; 32];
        id.copy_from_slice(h.finalize().as_bytes());
        id
    };
    let gossip_msg = WireMessage::Gossip(axiom_nabla::types::GossipMessage::StateUpdate {
        wallet_id: synthetic_wallet_id,
        new_state: req.secret,
        tx_hash: req.dwp_wallet_id,
        tick: 0,
            is_genesis_claim: false,
        wallet_seq: 0, // WI3: synthetic JFP-secret carrier, not a real chain entry
        client_pk: [0u8; 32],
        client_sig: vec![],
        amount: 0,
        fee_breakdown: Vec::new(),
        seq_proof: None, // WI3 hole-1: seq 0, no advance, no proof needed
    });
    if let Some(mesh) = node.core.mesh() {
        for target_id in mesh.forward_targets(&node.node_id) {
            if let Some(peer) = mesh.peer_by_id(&target_id) {
                outbound.push((to_socket_addr(&peer.address), gossip_msg.clone()));
            }
        }
    }

    JfpSecretOutcome::Ok(axiom_nabla::wire_client::JfpSecretResponse { ok: true })
}

/// Transport-agnostic core for `/jfp-secrets`.
///
/// Both the HTTP handler (gated `410 Gone` post-Phase-3c) and the TCP
/// `WireMessage::JfpSecretsRequest` arm call this. Read-only lookup.
fn jfp_secrets_core(
    req: &axiom_nabla::wire_client::JfpSecretsRequest,
    node: &NablaNodeState,
) -> axiom_nabla::wire_client::JfpSecretsResponse {
    let secrets: Vec<[u8; 32]> = node.jfp_secrets.get(&req.dwp_wallet_id)
        .cloned()
        .unwrap_or_default();
    let count = secrets.len() as u64;
    axiom_nabla::wire_client::JfpSecretsResponse { secrets, count }
}

/// HTTP POST /jfp-secret — thin wrapper around `jfp_secret_core`.
/// Gated `410 Gone` post-Phase-3c; retained for re-enablement.
fn handle_jfp_secret(
    body: &[u8],
    state: &Arc<Mutex<NablaNodeState>>,
    http_outbound: &Arc<Mutex<Vec<(std::net::SocketAddr, WireMessage)>>>,
) -> (u16, Vec<u8>) {
    let req: axiom_nabla::wire_client::JfpSecretRequest =
        match ciborium::de::from_reader(body) {
            Ok(r) => r,
            Err(e) => return http_error_cbor(
                400, axiom_errors::error_code::E_NABLA_INVALID_JSON_BODY,
                axiom_errors::ErrorCategory::ClientBug,
                &format!("bad CBOR: {}", e),
            ),
        };

    let mut st = state.lock().unwrap();
    let mut local_outbound: Vec<(std::net::SocketAddr, WireMessage)> = Vec::new();
    let outcome = jfp_secret_core(&req, &mut st, &mut local_outbound);
    drop(st);
    if !local_outbound.is_empty() {
        http_outbound.lock().unwrap().extend(local_outbound);
    }
    match outcome {
        JfpSecretOutcome::Ok(resp) => (200, cbor_body(&resp)),
        JfpSecretOutcome::Rejected { http_status, error } => (http_status, cbor_body(&error)),
    }
}

/// HTTP GET /jfp-secrets?dwp_wallet_id=<hex> — thin wrapper around
/// `jfp_secrets_core`. Gated `410 Gone` post-Phase-3c; retained for
/// re-enablement.
fn handle_jfp_secrets_query(
    dwp_id_hex: &str,
    state: &Arc<Mutex<NablaNodeState>>,
) -> (u16, Vec<u8>) {
    let dwp_wallet_id = match hex::decode(dwp_id_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return http_error_cbor(
            400, axiom_errors::error_code::E_NABLA_INVALID_HEX,
            axiom_errors::ErrorCategory::ClientBug, "invalid dwp_wallet_id hex",
        ),
    };

    let st = state.lock().unwrap();
    let resp = jfp_secrets_core(
        &axiom_nabla::wire_client::JfpSecretsRequest { dwp_wallet_id },
        &st,
    );
    (200, cbor_body(&resp))
}

// Tests — NBC verification wiring
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// HTTP wire contract: `http_error_cbor` emits a CBOR body
    /// containing the structured `error_response` map.  CBOR-only
    /// (2026-05-14 cutover, see CLAUDE.md §8 "Nabla and validator
    /// use the same UMP"); JSON is no longer accepted on the wire.
    #[test]
    fn http_error_cbor_is_structured_only() {
        #[derive(serde::Deserialize)]
        struct Parsed {
            error_response: axiom_errors::ErrorResponse,
        }

        let (status, body) = http_error_cbor(
            400,
            axiom_errors::error_code::E_NABLA_INVALID_HEX,
            axiom_errors::ErrorCategory::ClientBug,
            "Invalid wallet_pk hex",
        );
        assert_eq!(status, 400);
        let parsed: Parsed = ciborium::de::from_reader(body.as_slice())
            .expect("http_error_cbor body MUST be valid CBOR");
        assert_eq!(parsed.error_response.code.as_str(), "E_NABLA_INVALID_HEX");
        assert_eq!(parsed.error_response.category, axiom_errors::ErrorCategory::ClientBug);
        assert_eq!(parsed.error_response.message, "Invalid wallet_pk hex");
    }

    /// The response deserializes cleanly into an
    /// `axiom_errors::ErrorResponse`, proving clients can consume
    /// it structurally.
    #[test]
    fn http_error_cbor_decodes_to_error_response() {
        #[derive(serde::Deserialize)]
        struct Parsed {
            error_response: axiom_errors::ErrorResponse,
        }
        let (_status, body) = http_error_cbor(
            502,
            axiom_errors::error_code::E_NABLA_BRIDGE_PEER_UNREACHABLE,
            axiom_errors::ErrorCategory::Operational,
            "Cannot connect to bridge peer",
        );
        let parsed: Parsed = ciborium::de::from_reader(body.as_slice()).unwrap();
        assert_eq!(parsed.error_response.code.as_str(), "E_NABLA_BRIDGE_PEER_UNREACHABLE");
        assert_eq!(parsed.error_response.category, axiom_errors::ErrorCategory::Operational);
        assert!(parsed.error_response.message.contains("bridge peer"));
    }

    fn test_addr() -> NablaAddress {
        NablaAddress::V4 { ip: [127, 0, 0, 1], port: 1211 }
    }

    fn test_socket() -> std::net::SocketAddr {
        "127.0.0.1:1211".parse().unwrap()
    }

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    /// Generate 1 SPHINCS+ keypair for test NBC issuer (k=1).
    fn make_issuer_keys() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes;
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("SPHINCS+ keygen");
        (vec![pk.into_bytes().to_vec()], vec![sk.into_bytes().to_vec()])
    }

    /// Create a production-like NBC with real SPHINCS+ signature (k=1).
    /// chain_depth=1 (peer-issued) — matches production reality where peers
    /// present NBCs issued by a genesis node, not by root authority directly.
    /// Root trust check only applies to chain_depth=0 (genesis NBCs).
    fn make_real_nbc(sphincs_pk: &[u8], ed25519_pk: &[u8], tick: u64) -> NBC {
        let validator_id = axiom_core_logic::compute::compute_validator_id(sphincs_pk);
        let (issuer_pks, issuer_sks) = make_issuer_keys();
        let mut nbc = axiom_core_logic::types::VBC {
            network_size_baseline: 0,
            baseline_tick: 0,
            version: 0x09,
            validator_id,
            subject_pubkey_sphincs: sphincs_pk.to_vec(),
            subject_pubkey_dilithium: vec![0u8; 1952],
            subject_pubkey_ed25519: ed25519_pk.to_vec(),
            pgp_fingerprint: vec![],
            node_name: String::new(),
            proof_cap: String::new(),
            issued_at: tick,
            expires_at: tick + NBC_EXPIRY_SECS,
            chain_depth: 1,   // peer-issued (not genesis)
            issuer_set: vec![issuer_pks[0].clone()], // k=1: single issuer
            signatures: vec![],
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
        };
        let payload = axiom_core_logic::compute::compute_vbc_signing_payload(&nbc);
        let sig = axiom_core_logic::compute::sign_sphincs(&issuer_sks[0], &payload).expect("sign");
        nbc.signatures = vec![sig]; // k=1: single signature
        nbc
    }

    /// Build a real NBC for our own node and init state with it.
    fn make_state(sphincs_pk: &[u8]) -> (NablaNodeState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let nbc = make_real_nbc(sphincs_pk, &[0x01; 32], 500);
        let node_id = nbc_node_id(&nbc);
        let signer = Box::new(axiom_nabla::crypto::NoopSigner);
        let mut state = NablaNodeState::new(node_id, test_addr(), dir.path(), signer, None, true, axiom_nabla::bloom::TxidServiceMode::Bloom, true);
        state.virtual_secs = 1000;
        state.accept_nbc(nbc);
        (state, dir)
    }

    // ── verify_peer_nbc tests ──

    #[test]
    fn verify_peer_nbc_valid_real_nbc() {
        let sphincs_pk = [0xAA; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xBB; 32], 500);
        let node_id = nbc_node_id(&nbc);
        let nbc_bytes = serialize_nbc(&nbc);

        let (mut state, _dir) = make_state(&[0x01; 32]);
        let result = state.verify_peer_nbc(&nbc_bytes, &node_id);
        assert!(result.is_ok(), "valid NBC should pass: {:?}", result);
        assert_eq!(result.unwrap(), node_id);
    }

    #[test]
    fn verify_peer_nbc_empty_bytes_rejected() {
        // Empty nbc_bytes must be rejected — no sim fallback
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let peer_id = nid(0xAA);
        let result = state.verify_peer_nbc(&[], &peer_id);
        assert!(result.is_err(), "empty NBC bytes must be rejected");
    }

    #[test]
    fn verify_peer_nbc_corrupted_bytes() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let peer_id = nid(0xAA);
        let result = state.verify_peer_nbc(&[0xFF, 0xDE, 0xAD], &peer_id);
        assert!(result.is_err(), "corrupted bytes should fail");
        assert!(result.unwrap_err().contains("deserialize"));
    }

    #[test]
    fn verify_peer_nbc_wrong_claimed_id() {
        // NBC says validator_id = BLAKE3(sphincs_pk), but we claim a different node_id
        let sphincs_pk = [0xAA; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xBB; 32], 500);
        let nbc_bytes = serialize_nbc(&nbc);

        let (mut state, _dir) = make_state(&[0x01; 32]);
        let wrong_id = nid(0xFF); // doesn't match NBC's validator_id
        let result = state.verify_peer_nbc(&nbc_bytes, &wrong_id);
        assert!(result.is_err(), "wrong claimed node_id should fail");
        assert!(result.unwrap_err().contains("mismatch"));
    }

    #[test]
    fn verify_peer_nbc_expired() {
        let sphincs_pk = [0xAA; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xBB; 32], 0);
        let node_id = nbc_node_id(&nbc);
        let nbc_bytes = serialize_nbc(&nbc);

        let (mut state, _dir) = make_state(&[0x01; 32]);
        // Set virtual_secs past NBC expiry
        state.virtual_secs = NBC_EXPIRY_SECS + 100;
        let result = state.verify_peer_nbc(&nbc_bytes, &node_id);
        assert!(result.is_err(), "expired NBC should fail");
        let err = result.unwrap_err();
        assert!(err.contains("verification failed") || err.contains("Core rejected NBC")
            || err.contains("NBC expired"),
            "expected verification error, got: {}", err);
    }

    /// KI#32 regression (gamma 2026-06-17): warm-restore populated the live
    /// `verified_nbcs` map but did NOT re-seed `core.peer_nbcs`, so restart #1
    /// wrote an NBC-less snapshot and restart #2 cold-started (dropped 284
    /// PoolSync). Persistence must survive N restarts, not just one. This test
    /// boots → verifies a peer → snapshots, then restarts TWICE from the same
    /// data_dir and asserts the peer NBC is still warmed after the SECOND
    /// restart. Pre-fix it warms after restart #1 but is empty after #2.
    #[test]
    fn ki32_peer_nbc_survives_multiple_restarts() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        // Far enough in the future that the NBC stays valid against the
        // real wall-clock check in warm-restore (`expires_at > now`).
        let future = now + 1_000_000;

        let dir = tempfile::tempdir().unwrap();

        let own_nbc = make_real_nbc(&[0x01; 32], &[0x02; 32], future);
        let own_id = nbc_node_id(&own_nbc);

        let peer_nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], future);
        let peer_id = nbc_node_id(&peer_nbc);
        let peer_bytes = serialize_nbc(&peer_nbc);

        let mk = |dir: &std::path::Path| {
            let signer = Box::new(axiom_nabla::crypto::NoopSigner);
            NablaNodeState::new(own_id, test_addr(), dir, signer, None, true,
                axiom_nabla::bloom::TxidServiceMode::Bloom, true)
        };

        // Boot #0: fresh node verifies the peer and snapshots to disk.
        {
            let mut state = mk(dir.path());
            state.virtual_secs = future + 1;
            state.accept_nbc(own_nbc.clone());
            state.verify_peer_nbc(&peer_bytes, &peer_id).expect("verify peer");
            assert!(state.verified_nbcs.contains_key(&peer_id));
            state.core.take_snapshot().expect("snapshot 0");
        }

        // Restart #1: warm-restore should warm the peer. Crucially NO fresh
        // verify_peer_nbc fires here (peer already known) — the exact
        // condition that left core.peer_nbcs empty before the fix.
        {
            let mut state = mk(dir.path());
            state.virtual_secs = future + 1;
            assert!(state.verified_nbcs.contains_key(&peer_id),
                "restart #1 must warm the peer NBC from the snapshot");
            state.core.take_snapshot().expect("snapshot 1");
        }

        // Restart #2: the regression. Must STILL be warm.
        {
            let state = mk(dir.path());
            assert!(state.verified_nbcs.contains_key(&peer_id),
                "restart #2 must STILL warm the peer NBC — pre-fix restart #1's \
                 snapshot was written without re-seeding core.peer_nbcs, so this \
                 came back cold and dropped PoolSync until Hello re-verification");
        }
    }

    /// KI#24: a reply addressed to the inbound peer's ephemeral source must be
    /// written on the inbound socket (send_reply), NOT re-dialed via
    /// transport.send (which connects to a port nothing listens on → flood).
    /// Builds a real loopback socket pair where `client` has no listener of
    /// its own (like an SDK), and proves the reply lands on that connection.
    #[test]
    fn ki24_reply_to_inbound_peer_uses_the_inbound_socket() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::sync::{Arc as StdArc, Mutex as StdMutex};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listen_addr).unwrap();
        let (server_side, client_ephemeral) = listener.accept().unwrap();

        let envelope = Envelope {
            peer: client_ephemeral, // the client's ephemeral source, as we see it
            message: WireMessage::IntroductionRequest { from: [0u8; 32] },
            reply_stream: Some(StdArc::new(StdMutex::new(server_side))),
            cbor_client: false,
            wire_bytes: 0,
        };

        // Routing predicate: a reply to the inbound peer goes on the inbound
        // socket; a fan-out to a DIFFERENT (listening) address does not.
        assert!(is_inbound_reply(&envelope.peer, &envelope));
        let other: std::net::SocketAddr = "127.0.0.1:7300".parse().unwrap();
        assert!(!is_inbound_reply(&other, &envelope));

        // And the reply actually arrives on that same connection — proving it
        // is NOT a re-dial to the ephemeral source (which would be refused).
        let reply = WireMessage::IntroductionRequest { from: [9u8; 32] };
        axiom_nabla::transport::send_reply(&envelope, &reply).expect("send_reply");

        client.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).expect("framed reply length arrives on inbound socket");
        let n = u32::from_be_bytes(len_buf) as usize;
        assert!(n > 0 && n < 100_000, "reply body length sane: {}", n);
        let mut body = vec![0u8; n];
        client.read_exact(&mut body).expect("reply body arrives on inbound socket");
    }

    /// KI#24: without an inbound socket (StdioTransport / tests), the predicate
    /// is false so the entry falls through to the normal transport.send path.
    #[test]
    fn ki24_reply_predicate_false_without_inbound_socket() {
        let addr: std::net::SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let envelope = Envelope {
            peer: addr,
            message: WireMessage::IntroductionRequest { from: [0u8; 32] },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };
        assert!(!is_inbound_reply(&addr, &envelope));
    }

    /// KI#32 fresh-env flood ROOT-CAUSE PROBE (2026-06-18). The hard-drop floods
    /// on a fresh env because some peers' PoolSync don't resolve in
    /// `verified_nbcs` in steady state (the s2r93186 E_TXID_ATTESTATION_MISSING
    /// regression). This drives the REAL Hello handler to verify a peer, then
    /// asserts the peer's PoolSync stays resolvable (the exact lookup the drop-arm
    /// does: `verified_nbcs.get(sender_node_id).and_then(nbc_ed25519_pk)`) across
    /// time + eviction sweeps. If it ever fails, the panic CLASSIFIES the cause:
    /// key absent (never-inserted / evicted), present-but-pk-extract-fail, or a
    /// keying mismatch — collapsing the static-analysis contradiction into one
    /// observation. NOTE: a pass means the bug is NOT in this isolated path (rule
    /// it out) and is emergent in the multi-node topology — next step is a small
    /// live 3-node env with the same diagnostic, OFF the soak box.
    #[test]
    fn ki32_poolsync_sender_resolves_after_hello_and_time() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Node K (receiver), realistic real-time virtual_secs.
        let (mut k, _dir) = make_state(&[0x01; 32]);
        k.virtual_secs = now;

        // Peer A's own NBC, as it broadcasts in its Hello (genesis-like expiry,
        // mirroring the real env where node.node_id = nbc.validator_id).
        let a_nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], now);
        let a_id = nbc_node_id(&a_nbc); // = A.validator_id = the PoolSync sender_node_id
        let a_bytes = serialize_nbc(&a_nbc);

        // Drive the REAL Hello handler — exactly how the soak verifies peers.
        let hello = Envelope {
            peer: test_socket(),
            message: WireMessage::Hello {
                node_id: a_id,
                address: test_addr(),
                downstream_count: 0,
                nbc_bytes: a_bytes,
                txid_service: "bloom".into(),
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };
        let _ = handle_message(&mut k, &hello);
        assert!(k.verified_nbcs.contains_key(&a_id),
            "Hello handler must verify + cache A's NBC");

        let resolves = |k: &NablaNodeState|
            k.verified_nbcs.get(&a_id).and_then(nbc_ed25519_pk).is_some();
        assert!(resolves(&k), "A's PoolSync resolves immediately after Hello");

        // Steady state: 12h pass, eviction sweeps each tick (as tick_loop does).
        for h in 1..=12u64 {
            k.virtual_secs = now + h * 3600;
            k.evict_expired_nbcs();
            if !resolves(&k) {
                let keys: Vec<String> = k.verified_nbcs.keys()
                    .map(|x| hex::encode(&x[..8])).collect();
                let present = k.verified_nbcs.contains_key(&a_id);
                panic!("REPRODUCED at +{}h: A's PoolSync unresolvable. \
                        key_present={} looked_up={} verified_nbcs_keys={:?} \
                        a_nbc.expires_at={} virtual_secs={} \
                        (key absent → evicted/never-inserted; present → pk-extract fail)",
                    h, present, hex::encode(&a_id[..8]), keys,
                    a_nbc.expires_at, k.virtual_secs);
            }
        }
    }

    /// KI#32 fresh-env flood FIX — VALIDATION (2026-06-18). Root cause was a
    /// snapshot-completeness gap: a peer verified AFTER the last periodic snapshot
    /// was lost on restart (warm-restore only carries what was snapshotted), so its
    /// PoolSync hard-dropped until a pair-asymmetric connection-driven Hello re-fired.
    /// The fix: `verify_peer_nbc` now persists the snapshot eagerly on each NEW
    /// verification, so the on-disk verified set is never stale w.r.t. memory. This
    /// test pins it: verify A,B → snapshot → verify C → restart → C STILL RESOLVES
    /// (no Hello needed), because verifying C eager-snapshotted it. Pre-fix this
    /// asserted `!c_resolves` (the reproduced bug); post-fix C survives the restart.
    #[test]
    fn ki32_peer_verified_after_snapshot_survives_restart() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let future = now + 1_000_000; // NBCs valid vs the wall-clock warm-restore check

        let dir = tempfile::tempdir().unwrap();
        let own = make_real_nbc(&[0x01; 32], &[0x02; 32], future);
        let own_id = nbc_node_id(&own);
        let a = make_real_nbc(&[0xAA; 32], &[0xA2; 32], future); let a_id = nbc_node_id(&a);
        let b = make_real_nbc(&[0xBB; 32], &[0xB2; 32], future); let b_id = nbc_node_id(&b);
        let c = make_real_nbc(&[0xCC; 32], &[0xC2; 32], future); let c_id = nbc_node_id(&c);

        let mk = |dir: &std::path::Path| {
            let signer = Box::new(axiom_nabla::crypto::NoopSigner);
            NablaNodeState::new(own_id, test_addr(), dir, signer, None, true,
                axiom_nabla::bloom::TxidServiceMode::Bloom, true)
        };
        let c_resolves = |k: &NablaNodeState|
            k.verified_nbcs.get(&c_id).and_then(nbc_ed25519_pk).is_some();

        // Boot 0: verify A,B → a periodic snapshot; THEN verify C (which, with the
        // fix, eager-snapshots itself) and restart before the NEXT periodic snapshot.
        {
            let mut k = mk(dir.path());
            k.virtual_secs = future + 1;
            k.accept_nbc(own.clone());
            k.verify_peer_nbc(&serialize_nbc(&a), &a_id).unwrap();
            k.verify_peer_nbc(&serialize_nbc(&b), &b_id).unwrap();
            k.core.take_snapshot().expect("periodic snapshot {A,B}");
            k.verify_peer_nbc(&serialize_nbc(&c), &c_id).unwrap(); // eager-snapshots C
            assert!(k.verified_nbcs.contains_key(&c_id), "C verified in memory");
        }

        // Restart. With the eager-snapshot fix, C is on disk → warm-restored.
        let k = mk(dir.path());
        assert!(k.verified_nbcs.contains_key(&a_id), "A warm-restored");
        assert!(k.verified_nbcs.contains_key(&b_id), "B warm-restored");
        assert!(c_resolves(&k),
            "FIX: C (verified after the last periodic snapshot) survives the restart \
             via the eager snapshot — no connection-driven Hello needed, so its \
             PoolSync resolves and is not hard-dropped");
    }

    #[test]
    fn verify_peer_nbc_cache_hit() {
        let sphincs_pk = [0xAA; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xBB; 32], 500);
        let node_id = nbc_node_id(&nbc);
        let nbc_bytes = serialize_nbc(&nbc);

        let (mut state, _dir) = make_state(&[0x01; 32]);

        // First call: verifies and caches
        let r1 = state.verify_peer_nbc(&nbc_bytes, &node_id);
        assert!(r1.is_ok());
        assert!(state.verified_nbcs.contains_key(&node_id));

        // Second call: hits cache
        let r2 = state.verify_peer_nbc(&nbc_bytes, &node_id);
        assert!(r2.is_ok());
    }

    #[test]
    fn verify_peer_nbc_cache_evicts_expired() {
        let sphincs_pk = [0xAA; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xBB; 32], 500);
        let node_id = nbc_node_id(&nbc);
        let nbc_bytes = serialize_nbc(&nbc);

        let (mut state, _dir) = make_state(&[0x01; 32]);

        // Verify and cache
        assert!(state.verify_peer_nbc(&nbc_bytes, &node_id).is_ok());
        assert_eq!(state.verified_nbcs.len(), 1);

        // Advance time past expiry
        state.virtual_secs = NBC_EXPIRY_SECS + 600;
        state.evict_expired_nbcs();
        assert_eq!(state.verified_nbcs.len(), 0, "expired NBC should be evicted");
    }

    // ── handle_message wiring tests ──

    #[test]
    fn hello_with_valid_nbc_accepted() {
        let sphincs_pk = [0xCC; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xDD; 32], 500);
        let peer_node_id = nbc_node_id(&nbc);
        let nbc_bytes = serialize_nbc(&nbc);

        let (mut state, _dir) = make_state(&[0x01; 32]);
        let envelope = Envelope {
            peer: test_socket(),
            message: WireMessage::Hello {
                node_id: peer_node_id,
                address: test_addr(),
                downstream_count: 0,
                nbc_bytes,
                txid_service: "hashmap".into(),
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };

        let outbound = handle_message(&mut state, &envelope);
        // No NbcReject in outbound
        for (_, msg) in &outbound {
            if let WireMessage::NbcReject { .. } = msg {
                panic!("should not reject valid NBC");
            }
        }
        // YPX-014 mode round-trip — the receiver should populate
        // PeerInfo.txid_service from the Hello field.
        let peer = state.core.mesh().unwrap().peer_by_id(&peer_node_id).cloned();
        assert_eq!(peer.unwrap().txid_service, "hashmap",
            "Hello.txid_service must propagate into the mesh peer cache");
        // Peer should be in mesh
        assert!(state.core.mesh().unwrap().peer_by_id(&peer_node_id).is_some(),
            "peer with valid NBC should be added to mesh");
    }

    /// YPX-022 §5 mesh-wide garbage insert: a Recall gossip receipt must put the
    /// recalled txid into THIS node's own garbage-state bloom chain, not just merge
    /// the in-memory marker. Fails without the `GossipMessage::Recall` arm in
    /// `handle_message`'s `GossipAction::Forward` branch.
    #[test]
    fn recall_gossip_receipt_inserts_into_garbage_chain() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let txid = [0x7Au8; 32];

        // Pre-condition: unknown txid — chain misses, marker absent.
        assert_eq!(
            state.garbage_state_chain.lookup(&txid),
            axiom_nabla::bloom_chain::ChainLookup::Miss,
            "fresh chain must miss"
        );
        assert!(!state.core.smt().is_txid_recalled(&txid));

        let envelope = Envelope {
            peer: test_socket(),
            message: WireMessage::Gossip(GossipMessage::Recall {
                txid,
                sender_pk: vec![0xB1u8; 32],
                recall_tick: 500,
                committed: true,
            }),
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };
        let _ = handle_message(&mut state, &envelope);

        // Marker merged (pre-existing behavior) AND the durable chain got the insert.
        assert!(state.core.smt().is_txid_recalled(&txid),
            "gossip receipt must merge the recall marker");
        assert!(matches!(state.garbage_state_chain.lookup(&txid),
                axiom_nabla::bloom_chain::ChainLookup::Hit { .. }),
            "gossip receipt must insert the recalled txid into the local garbage chain");

        // §2.2.1 — a RESERVATION flood (committed: false) merges the pending
        // marker but must NOT touch the garbage chain: `C` is still live.
        let reserved_txid = [0x7Bu8; 32];
        let envelope = Envelope {
            peer: test_socket(),
            message: WireMessage::Gossip(GossipMessage::Recall {
                txid: reserved_txid,
                sender_pk: vec![0xB2u8; 32],
                recall_tick: 501,
                committed: false,
            }),
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };
        let _ = handle_message(&mut state, &envelope);
        assert!(state.core.smt().is_txid_recall_pending(&reserved_txid),
            "reservation gossip must merge as RETRACT_PENDING");
        assert!(!state.core.smt().is_txid_recalled(&reserved_txid),
            "a reservation must not block redeems");
        assert_eq!(state.garbage_state_chain.lookup(&reserved_txid),
            axiom_nabla::bloom_chain::ChainLookup::Miss,
            "a reservation must NOT enter the garbage chain — C is still live");
    }

    #[test]
    fn hello_with_empty_nbc_rejected() {
        // No NBC bytes at all → reject. No sim compat.
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let fake_node_id = nid(0xAA);
        let envelope = Envelope {
            peer: test_socket(),
            message: WireMessage::Hello {
                node_id: fake_node_id,
                address: test_addr(),
                downstream_count: 0,
                nbc_bytes: vec![],
                txid_service: String::new(),
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };

        let outbound = handle_message(&mut state, &envelope);
        let has_reject = outbound.iter().any(|(_, msg)| matches!(msg, WireMessage::NbcReject { .. }));
        assert!(has_reject, "Hello with empty NBC bytes must get NbcReject");
    }

    #[test]
    fn hello_with_bad_nbc_rejected() {
        let sphincs_pk = [0xCC; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xDD; 32], 500);
        let nbc_bytes = serialize_nbc(&nbc);

        let (mut state, _dir) = make_state(&[0x01; 32]);
        // Claim a different node_id than what's in the NBC
        let fake_node_id = nid(0xFF);
        let envelope = Envelope {
            peer: test_socket(),
            message: WireMessage::Hello {
                node_id: fake_node_id,
                address: test_addr(),
                downstream_count: 0,
                nbc_bytes,
                txid_service: String::new(),
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };

        let outbound = handle_message(&mut state, &envelope);
        let has_reject = outbound.iter().any(|(_, msg)| matches!(msg, WireMessage::NbcReject { .. }));
        assert!(has_reject, "Hello with mismatched node_id should get NbcReject");
        // Peer should NOT be in mesh
        assert!(state.core.mesh().unwrap().peer_by_id(&fake_node_id).is_none(),
            "rejected peer should not be in mesh");
    }

    #[test]
    fn attach_request_with_bad_nbc_rejected() {
        let sphincs_pk = [0xCC; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xDD; 32], 500);
        let nbc_bytes = serialize_nbc(&nbc);

        let (mut state, _dir) = make_state(&[0x01; 32]);
        // Give state an upstream so it's not an orphan itself
        let upstream_nbc = make_real_nbc(&[0x02; 32], &[0x03; 32], 500);
        state.core.tardis_mut().unwrap().set_upstream(nbc_node_id(&upstream_nbc));

        let fake_node_id = nid(0xFF);
        let envelope = Envelope {
            peer: test_socket(),
            message: WireMessage::TardisAttachRequest {
                node_id: fake_node_id,
                address: test_addr(),
                has_children: false,
                prefer_writer: false,
                nbc_bytes,
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };

        let outbound = handle_message(&mut state, &envelope);
        let has_reject = outbound.iter().any(|(_, msg)| matches!(msg, WireMessage::NbcReject { .. }));
        assert!(has_reject, "TardisAttachRequest with mismatched node_id should get NbcReject");
        let has_attach_resp = outbound.iter().any(|(_, msg)| matches!(msg, WireMessage::TardisAttachResponse { .. }));
        assert!(!has_attach_resp, "rejected attach should not get TardisAttachResponse");
    }

    #[test]
    fn attach_request_with_valid_nbc_gets_response() {
        let sphincs_pk = [0xCC; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xDD; 32], 500);
        let peer_node_id = nbc_node_id(&nbc);
        let nbc_bytes = serialize_nbc(&nbc);

        let (mut state, _dir) = make_state(&[0x01; 32]);
        // Give state an upstream so it has D slots open
        let upstream_nbc = make_real_nbc(&[0x02; 32], &[0x03; 32], 500);
        state.core.tardis_mut().unwrap().set_upstream(nbc_node_id(&upstream_nbc));

        let envelope = Envelope {
            peer: test_socket(),
            message: WireMessage::TardisAttachRequest {
                node_id: peer_node_id,
                address: test_addr(),
                has_children: false,
                prefer_writer: false,
                nbc_bytes,
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };

        let outbound = handle_message(&mut state, &envelope);
        let has_reject = outbound.iter().any(|(_, msg)| matches!(msg, WireMessage::NbcReject { .. }));
        assert!(!has_reject, "valid NBC should not be rejected");
        let has_attach_resp = outbound.iter().any(|(_, msg)| matches!(msg, WireMessage::TardisAttachResponse { .. }));
        assert!(has_attach_resp, "valid NBC attach should get TardisAttachResponse");
    }

    #[test]
    fn outgoing_hello_includes_nbc_bytes() {
        let (state, _dir) = make_state(&[0x01; 32]);
        assert!(!state.own_nbc_bytes.is_empty(), "own_nbc_bytes should be populated after init");

        // Deserializing our own NBC bytes should succeed
        let nbc = deserialize_nbc(&state.own_nbc_bytes);
        assert!(nbc.is_ok(), "own NBC bytes should deserialize: {:?}", nbc);

        // Verify structural integrity of our own NBC
        let nbc = nbc.unwrap();
        assert!(verify_nbc(&nbc, 1000).is_ok(), "own NBC should pass verification");
    }

    // ── Step 1: node_id / NBC identity alignment tests ──

    #[test]
    fn node_id_equals_nbc_validator_id() {
        // Load a real ceremony NBC, verify that node_id == nbc.validator_id
        // and that nbc.validator_id == compute_validator_id(sphincs_pk).
        let sphincs_pk = [0xAA; 32];
        let ed25519_pk = [0xBB; 32];
        let nbc = make_real_nbc(&sphincs_pk, &ed25519_pk, 500);
        let expected_id = axiom_core_logic::compute::compute_validator_id(&sphincs_pk);

        // validator_id must equal Core's derivation
        assert_eq!(nbc.validator_id, expected_id,
            "validator_id must be BLAKE3(sphincs_pk) via Core");

        // Create state using accept_nbc — node_id should match
        let dir = tempfile::tempdir().unwrap();
        let signer = Box::new(axiom_nabla::crypto::NoopSigner);
        let node_id = nbc.validator_id;
        let mut state = NablaNodeState::new(node_id, test_addr(), dir.path(), signer, None, true, axiom_nabla::bloom::TxidServiceMode::Bloom, true);
        state.accept_nbc(nbc.clone());

        assert_eq!(state.node_id, expected_id,
            "node_id in state must equal NBC's validator_id");
        assert_eq!(state.node_id, nbc.validator_id,
            "node_id must come from NBC, not from BLAKE3(data_dir:port)");
    }

    #[test]
    fn accept_nbc_stores_serialized_nbc_and_cc_chain() {
        let nbc = make_real_nbc(&[0xCC; 32], &[0xDD; 32], 500);
        let node_id = nbc_node_id(&nbc);
        let dir = tempfile::tempdir().unwrap();
        let signer = Box::new(axiom_nabla::crypto::NoopSigner);
        let mut state = NablaNodeState::new(node_id, test_addr(), dir.path(), signer, None, true, axiom_nabla::bloom::TxidServiceMode::Bloom, true);

        // Before accept_nbc: no NBC bytes, no CC chain
        assert!(state.own_nbc_bytes.is_empty());
        assert!(state.core.cc_chain().is_none());

        state.accept_nbc(nbc.clone());

        // After accept_nbc: NBC bytes populated, CC chain initialized
        assert!(!state.own_nbc_bytes.is_empty());
        assert!(state.core.cc_chain().is_some());

        // Deserialize own_nbc_bytes — should match original NBC
        let decoded = deserialize_nbc(&state.own_nbc_bytes).unwrap();
        assert_eq!(decoded.validator_id, nbc.validator_id);
    }

    // ── Step 4: Nabla Join Protocol tests ──

    /// Helper: create a valid NablaJoinRequest with real wallet Ed25519 binding.
    fn make_join_request(sphincs_pk: &[u8; 32]) -> (Vec<u8>, WalletId, Vec<u8>, Vec<u8>, NBC) {
        use ed25519_dalek::{SigningKey, Signer as DalekSigner};

        let nbc = make_real_nbc(sphincs_pk, &[0xEE; 32], 500);
        let nbc_bytes = serialize_nbc(&nbc);
        let nabla_id = nbc.validator_id;

        // Create a wallet Ed25519 keypair
        let wallet_seed = [0x42u8; 32];
        let wallet_signing = SigningKey::from_bytes(&wallet_seed);
        let wallet_pubkey = wallet_signing.verifying_key().to_bytes().to_vec();
        let wallet_id: WalletId = {
            let h = blake3::hash(&wallet_pubkey);
            *h.as_bytes()
        };

        // Sign wallet binding: nabla_id || wallet_id
        let binding_msg = [nabla_id.as_slice(), wallet_id.as_slice()].concat();
        let wallet_binding_sig = wallet_signing.sign(&binding_msg).to_bytes().to_vec();

        (nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig, nbc)
    }

    #[test]
    fn join_request_accepted_enters_probation() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let (nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig, nbc) =
            make_join_request(&[0xAA; 32]);
        let nabla_id = nbc.validator_id;

        let (accepted, reason, probation_until, gossip) =
            state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);

        assert!(accepted, "valid join should be accepted: {}", reason);
        assert!(probation_until > state.virtual_secs,
            "probation_until should be in the future");
        assert_eq!(probation_until, state.virtual_secs + NABLA_PROBATION_SECS);

        // Should be in verified_peers as Probation
        let peer = state.verified_peers.get(&nabla_id).unwrap();
        assert!(matches!(peer.status, NbcTrustStatus::Probation { .. }));
        assert_eq!(peer.wallet_id, Some(wallet_id));

        // Should have gossip announcement
        assert!(gossip.is_some());
    }

    #[test]
    fn join_request_bad_wallet_sig_rejected() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let (nbc_bytes, wallet_id, wallet_pubkey, _, _) = make_join_request(&[0xBB; 32]);

        // Use wrong signature (all zeros)
        let bad_sig = vec![0u8; 64];
        let (accepted, reason, _, _) =
            state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &bad_sig);

        assert!(!accepted, "bad wallet sig should be rejected");
        assert!(reason.contains("wallet binding"), "reason should mention wallet: {}", reason);
    }

    #[test]
    fn probation_node_stays_leaf() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let (nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig, nbc) =
            make_join_request(&[0xCC; 32]);
        let nabla_id = nbc.validator_id;

        // Accept the join — enters probation
        state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);

        // Verify it's blocked from promotion
        assert!(state.is_peer_in_probation(&nabla_id),
            "node in probation should be flagged");
    }

    #[test]
    fn probation_completes_after_48h() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let (nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig, nbc) =
            make_join_request(&[0xDD; 32]);
        let nabla_id = nbc.validator_id;

        state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);

        // Advance virtual time past probation
        state.virtual_secs += NABLA_PROBATION_SECS + 1;
        state.advance_probation();

        let peer = state.verified_peers.get(&nabla_id).unwrap();
        assert_eq!(peer.status, NbcTrustStatus::Confirmed,
            "peer should be Confirmed after probation expires");
        assert!(!state.is_peer_in_probation(&nabla_id),
            "no longer in probation after 48h");
    }

    #[test]
    fn probation_uses_virtual_time_not_wall_clock() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        state.virtual_secs = 1_000_000; // arbitrary virtual time
        let (nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig, nbc) =
            make_join_request(&[0xEE; 32]);
        let nabla_id = nbc.validator_id;

        state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);

        // Probation since = 1_000_000
        let peer = state.verified_peers.get(&nabla_id).unwrap();
        match peer.status {
            NbcTrustStatus::Probation { since } => {
                assert_eq!(since, 1_000_000, "probation since must use virtual_secs");
            }
            _ => panic!("expected Probation status"),
        }

        // Set virtual time to exactly 48h+1s later
        state.virtual_secs = 1_000_000 + NABLA_PROBATION_SECS + 1;
        state.advance_probation();

        assert_eq!(state.verified_peers.get(&nabla_id).unwrap().status,
            NbcTrustStatus::Confirmed);
    }

    #[test]
    fn duplicate_nabla_id_rejected() {
        use ed25519_dalek::{SigningKey, Signer as DalekSigner};

        let (mut state, _dir) = make_state(&[0x01; 32]);
        let sphincs_pk = [0xAA; 32];

        // First join with wallet A
        let (nbc_bytes, wallet_id_a, wallet_pubkey_a, sig_a, nbc) =
            make_join_request(&sphincs_pk);
        let nabla_id = nbc.validator_id;

        let (accepted, _, _, _) =
            state.handle_join_request(&nbc_bytes, &wallet_id_a, &wallet_pubkey_a, &sig_a);
        assert!(accepted, "first join should be accepted");

        // Second join with DIFFERENT wallet but same sphincs_pk → same nabla_id
        let wallet_seed_b = [0x99u8; 32];
        let wallet_signing_b = SigningKey::from_bytes(&wallet_seed_b);
        let wallet_pubkey_b = wallet_signing_b.verifying_key().to_bytes().to_vec();
        let wallet_id_b: WalletId = {
            let h = blake3::hash(&wallet_pubkey_b);
            *h.as_bytes()
        };
        let binding_msg_b = [nabla_id.as_slice(), wallet_id_b.as_slice()].concat();
        let sig_b = wallet_signing_b.sign(&binding_msg_b).to_bytes().to_vec();

        // Check duplicate detection
        assert!(state.check_nabla_id_duplicate(&nabla_id, &wallet_id_b),
            "same nabla_id with different wallet should be flagged as duplicate");
    }

    #[test]
    fn genesis_nodes_skip_probation() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 500);
        let node_id = nbc_node_id(&nbc);

        // Manually register as Genesis (like a bootstrap peer)
        state.verified_peers.insert(node_id, PeerTrust {
            nbc,
            status: NbcTrustStatus::Genesis,
            wallet_id: None,
        });

        assert!(!state.is_peer_in_probation(&node_id),
            "genesis node should NOT be in probation");
        assert_eq!(state.verified_peers.get(&node_id).unwrap().status,
            NbcTrustStatus::Genesis);
    }

    #[test]
    fn confirmed_node_rejoins_without_probation() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let (nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig, nbc) =
            make_join_request(&[0xFF; 32]);
        let nabla_id = nbc.validator_id;

        // First join → probation
        state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);

        // Complete probation
        state.virtual_secs += NABLA_PROBATION_SECS + 1;
        state.advance_probation();
        assert_eq!(state.verified_peers.get(&nabla_id).unwrap().status,
            NbcTrustStatus::Confirmed);

        // Rejoin — should be accepted immediately (uses existing Confirmed status)
        let (accepted, _, probation_until, gossip) =
            state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);
        assert!(accepted, "confirmed node rejoin should be accepted");
        assert_eq!(probation_until, 0, "confirmed node should have no probation");
        assert!(gossip.is_none(), "confirmed rejoin should not gossip");
    }

    #[test]
    fn probation_node_reconnects_timer_continues() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        state.virtual_secs = 1_000_000;

        let (nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig, nbc) =
            make_join_request(&[0xAB; 32]);
        let nabla_id = nbc.validator_id;

        // First join at virtual_secs = 1_000_000
        state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);

        let original_since = match state.verified_peers.get(&nabla_id).unwrap().status {
            NbcTrustStatus::Probation { since } => since,
            _ => panic!("expected Probation"),
        };
        assert_eq!(original_since, 1_000_000);

        // Time passes (12 hours)
        state.virtual_secs = 1_000_000 + 12 * 3600;

        // Reconnect — timer should NOT restart
        let (accepted, _, probation_until, gossip) =
            state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);
        assert!(accepted, "reconnecting probation node should be accepted");
        // probation_until should still be from original since, not from now
        assert_eq!(probation_until, original_since + NABLA_PROBATION_SECS,
            "probation timer must NOT restart on reconnection");

        // Original since unchanged
        match state.verified_peers.get(&nabla_id).unwrap().status {
            NbcTrustStatus::Probation { since } => {
                assert_eq!(since, original_since,
                    "probation since must not change on reconnect");
            }
            _ => panic!("should still be in Probation"),
        }

        assert!(gossip.is_none(), "reconnect should not re-gossip");
    }

    // ── Step 5: TCP hardening tests ──

    #[test]
    fn is_critical_message_classification() {
        // Critical messages: Tick, Approval, AttachRequest, AttachResponse, Detach
        assert!(is_critical_message(&WireMessage::Tick(TickMessage {
            number: 1, upstream_pk: [0; 32], payload: vec![], signature: vec![],
            timestamp_ms: 0, prev_sig: vec![], grandparent_pk: None, available_slots: vec![],
            downstream_approvals: 0, subtree_d_available: 0,

        })));
        assert!(is_critical_message(&WireMessage::Approval(TickApproval {
            tick_number: 1, approver_pk: [0; 32], signature: vec![], subtree_open_d: 0,
        })));
        assert!(is_critical_message(&WireMessage::TardisAttachRequest {
            node_id: [0; 32], address: test_addr(),
            has_children: false, prefer_writer: false, nbc_bytes: vec![],
        }));
        assert!(is_critical_message(&WireMessage::TardisAttachResponse {
            node_id: [0; 32], accepted: true, downstream_count: 0, referrals: vec![], nbc_bytes: vec![],
        }));
        assert!(is_critical_message(&WireMessage::TardisDetach {
            node_id: [0; 32],
        }));

        // Non-critical: Hello, Gossip, Query, StatusRequest
        assert!(!is_critical_message(&WireMessage::Hello {
            node_id: [0; 32], address: test_addr(),
            downstream_count: 0, nbc_bytes: vec![], txid_service: String::new(),
        }));
        assert!(!is_critical_message(&WireMessage::StatusRequest));
        assert!(!is_critical_message(&WireMessage::Query { wallet_id: [0; 32] }));
        assert!(!is_critical_message(&WireMessage::NablaJoinRequest {
            nbc_bytes: vec![], wallet_id: [0; 32],
            wallet_pubkey: vec![], wallet_binding_sig: vec![],
        }));
    }

    #[test]
    fn test_bridge_peer_address_parsing() {
        // Valid IPv4 + port
        let addr: SocketAddr = "1.2.3.4:1211".parse().unwrap();
        assert_eq!(addr.port(), 1211);
        // Valid IPv6 + port
        let addr: SocketAddr = "[::1]:1211".parse().unwrap();
        assert_eq!(addr.port(), 1211);
        // Invalid address should fail
        assert!("not-an-address".parse::<SocketAddr>().is_err());
    }
}
