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

// KI#86: jemalloc returns freed memory to the OS; glibc arena fragments under
// gossip allocation churn (~60 MB/hr/node RSS creep, live-A/B-confirmed). Host-side,
// CoreID-neutral — no ELF/wire/protocol impact.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
// KI#92 #2: the global node-state lock uses parking_lot's Mutex (EVENTUAL
// FAIRNESS) instead of std::sync::Mutex. std's Mutex is unfair, so on the busy
// hashmap recorders the high-frequency tick loop + gossip starved the
// low-frequency client register/query threads indefinitely (they timed out).
// parking_lot forces a handoff to a thread that has waited >0.5ms, bounding a
// waiter's stall to ~one critical section instead of forever. Aliased so ONLY
// the node state changes — transport Mutexes stay std.
use parking_lot::Mutex as PlMutex;
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

/// Nabla's only HTTP listener is the LOCAL operator dashboard (YP "Transport
/// — functional endpoints", amended 2026-09-26): loopback, no remote option.
const DASHBOARD_BIND: &str = "127.0.0.1";

/// The dashboard's request gate. `head` is the request line + headers (no
/// body is ever read). Only `GET` is served — every functional Nabla
/// operation is TCP-CBOR, so any other method is refused with `405` before
/// routing. Returns `(path, query)` for `monitor::route_request`, which
/// answers `404` for anything that is not a dashboard route.
fn dashboard_request(head: &[u8]) -> Result<(String, Option<String>), &'static str> {
    let request = String::from_utf8_lossy(head);
    if !request.starts_with("GET ") {
        return Err("HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
    Ok(parse_http_request(&request))
}

/// Global shutdown flag for graceful termination.
static SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

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
fn storm_admit_forward(state: &Arc<PlMutex<NablaNodeState>>) -> bool {
    let mut node = state.lock();
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
/// KI#43b — one in-flight/settled heal adjudication (§12.4.4). The verdict
/// is the model-checked conjunction: acquit iff EVERY recording peer
/// answered `recorded: false, clean: true` AND this node's own record says
/// the same. Any `recorded: true` finalizes REFUSED immediately (the
/// consumption is real); any `clean: false` finalizes REFUSED (that peer
/// can never vouch — absence of proof rejects).
struct Adjudication {
    started_tick: u64,
    /// The consumed state's BIRTH tick (§12.4.4 item 4), sourced from the
    /// serving node's SMT entry for the healing wallet at trigger time and
    /// carried on every `ExactConsumedQuery` so peers scope cleanliness to
    /// `[born_era ..= active]` on the global era grid. 0 = birth unknown =
    /// whole-history (the conservative fallback). Fixed for the barrier's
    /// life — the pump re-sends it unchanged every tick.
    born_tick: u64,
    /// This node's own half, computed at creation from its exact store.
    own_recorded: bool,
    own_clean: bool,
    /// Distinct recording peers' answers: NodeId -> (recorded, clean).
    answers: std::collections::HashMap<NodeId, (bool, bool)>,
    /// None = barrier still collecting. Some(true) = ACQUITTED (proven
    /// bloom false positive). Some(false) = REFUSED.
    verdict: Option<bool>,
}

/// KI#43b — this node's `(recorded, clean)` half of the §12.4.4 barrier for a
/// consumed-bloom hit on `state_id`, scoped to the state's birth era.
///
/// * `recorded` — is `state_id` ANYWHERE in the exact record? Whole-history
///   and unchanged (counterexample 3: blooms are RAM, a restart can wipe the
///   firing bit while the exact mark survives, so membership is era-blind).
///   A real consumption refuses regardless of birth era.
/// * `clean`  — is the record trustworthy for the range x could have been
///   consumed in, i.e. `[born_era ..= active]`? `born_tick == 0` falls back
///   to the whole-history answer. KI#199: idle eras in the range are clean,
///   so this can now actually return `true` on a real node.
///
/// The exact store shares the consumed bloom chain's era ids by construction,
/// so `born_tick` maps through that chain's own duration (unit-safe, KI#47).
fn exact_barrier_answer(
    store: &axiom_nabla::consumed_exact::ConsumedExactStore,
    consumed_chain: &axiom_nabla::bloom_chain::BloomChain,
    state_id: &[u8; 32],
    born_tick: u64,
) -> (bool, bool) {
    let recorded = store.contains_anywhere(state_id).unwrap_or(true);
    let clean = if born_tick == 0 {
        store.clean_whole_history()
    } else {
        store.clean_from(consumed_chain.era_id_for_tick(born_tick))
    };
    (recorded, clean)
}

impl Adjudication {
    /// Recompute the verdict. `needed_peers` = RECORDING_NODES_TOTAL - 1.
    fn settle(&mut self, needed_peers: usize) {
        if self.verdict.is_some() {
            return;
        }
        if self.own_recorded
            || !self.own_clean
            || self.answers.values().any(|(rec, clean)| *rec || !*clean)
        {
            self.verdict = Some(false);
            return;
        }
        if self.answers.len() >= needed_peers {
            self.verdict = Some(true);
        }
    }
}

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
            bootstrap_file: PathBuf::from("bootstrap.toml"),
            avm_elf_path: None,
            dev_mode: false,
            skip_verify: false,
            log_level: "info".to_string(),
            tick_ms: TICK_INTERVAL_SECS * 1000,
            epoch_ms: 0,
            config_file: None,
            dashboard_port: None,
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
                    // G16: name what this actually switches off. `--dev` implies
                    // `--skip-verify`, and that is not a performance flag — it
                    // disables NBC-anchored signature verification on APPROVALS,
                    // which feed YPX-003 writer qualification, and on audit
                    // responses. Every soak and every measurement taken on a
                    // `--dev` mesh is taken with those checks OFF.
                    eprintln!(
                        "WARNING: --dev implies --skip-verify. Approval and \
                         audit-response signatures are NOT verified. Approvals \
                         feed writer qualification (YPX-003), so writer status \
                         on this node rests on unauthenticated messages. \
                         Watch `approvals_unverified` on /status."
                    );
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
            // Contribution emission (YP §25.2.4): consumed later, after the NBC is
            // loaded (see `--emission-bundle` below).
            "--emission-bundle" => {}
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
    eprintln!("  --data, -d <DIR>           Data directory (default: nabla-data)");
    eprintln!("  --config, -c <FILE>        Node config file (default: <data>/node.toml)");
    eprintln!("  --bootstrap, -w <FILE>     Bootstrap peers file (TOML)");
    eprintln!("  --avm-elf <PATH>           Path to axiom-core.elf for NBC verification");
    eprintln!("  --dev                      Dev mode: skip mandatory Core IPC check (implies --skip-verify)");
    eprintln!("  --skip-verify              Skip NBC/VBC verification at startup and for peers");
    eprintln!("  --dashboard-port <PORT>    Local dashboard HTTP port, 127.0.0.1 only (default: 6226)");
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

/// A FOB tranche statement being AGGREGATED from independent single-signer
/// broadcasts (§3: "no vote, no coordination" — each of the 3 committee movers
/// derives the identical `(epoch, entries)` and signs it alone). Keyed by the
/// statement payload, a node collects distinct verified movers until it has a
/// full committee, judges ONCE, then marks `applied` so re-gossiped partials
/// are no-ops. Bounded by eviction of stale epochs.
struct FobPendingStatement {
    epoch_id: u64,
    entries: Vec<axiom_nabla::fob::TrancheEntry>,
    /// Distinct crypto-verified movers collected so far (dedup by node_pk).
    movers: Vec<axiom_nabla::fob::VerifiedMover>,
    /// True once judged (accepted or quarantined) — stops re-judging on replay.
    resolved: bool,
}

struct NablaNodeState {
    /// Core node — state, persistence, protocol logic.
    /// This is THE node. Everything else here is TCP networking.
    core: NablaNode,

    /// YPX-025 — ATRAXI hold index (per-node, beside the SMT). Records HOLDS on a
    /// (wallet, state) that this node refuses to advance. Increment 2: populated at
    /// the KI#205 register-door refusal. In-memory for now (WAL persistence lands
    /// with the consolidation increment; a hold missed on restart is re-derived when
    /// the evidence re-arrives — fail-safe, the register-door gate still refuses).
    atraxi: axiom_nabla::atraxi::AtraxiIndex,

    // ── TCP Networking Layer (not in NablaNode) ──
    node_id: NodeId,
    node_name: String,
    /// The port PEERS reach us on — operator-declared (`node.toml`), the ONLY
    /// thing we state about our own reachability (§5.6a-bis).
    ///
    /// ⚠ We never announce an address. Peers compose `observed source IP : this
    /// port` from the connection they received, which is the one part of our
    /// location they can verify for themselves.
    external_port: u16,
    /// Ticks spent as orphan.
    orphan_ticks: u64,
    /// §7.6 lineage-verification outcomes, so the check is OBSERVABLE at the
    /// production `info` level. `[LINEAGE-OK]` is debug + rate-limited
    /// (`number % 120`), so on a normal mesh there is no positive evidence the
    /// verification is alive — silence reads identically to dead code. Proving
    /// it ran on 2026-08-06 required restarting a node with debug logging.
    /// These counters remove that: /status answers it directly.
    lineage_ok: u64,
    lineage_reject: u64,
    lineage_skip: u64,
    /// TickHash advertisements accepted / rejected as audit evidence.
    /// BOTH are needed: `unverified=0` alone cannot distinguish "everything
    /// verified" from "nothing arrived", and the rejection log is debug while
    /// production runs at info.
    tickhash_verified: u64,
    tickhash_unverified: u64,
    /// QuestionableAlerts whose evidence proved / failed to prove the claim.
    alert_proven: u64,
    alert_unproven: u64,
    /// G8 — PoolSync messages dropped for an unresolvable sender NBC. The drop
    /// is `debug!` and production runs at `info!`, so without this counter a
    /// 100% honest-PoolSync loss and a healthy mesh look identical.
    poolsync_drop_unverified: u64,
    /// Whether D1/D2 approved since the last tick_loop consumed approvals.
    /// Set in recv_loop, consumed (and reset) in tick_loop step 5a.
    d1_approved_this_tick: bool,
    /// G16 — approvals accepted WITHOUT signature verification because
    /// `--skip-verify` (implied by `--dev`) is set. Non-zero means writer
    /// qualification on this node rests on unauthenticated approvals.
    approvals_unverified: u64,
    /// KI#72 — Alert hops whose `intermediate_emitter` was PROVEN via its
    /// NBC-bound Ed25519 key, vs. hops we could not prove. `unproven` non-zero
    /// means someone is forwarding alerts we cannot attribute.
    alert_identity_proven: u64,
    alert_identity_unproven: u64,
    /// GUIDE §5.6c (KI#75) — refusals issued BECAUSE of probation, one
    /// counter per refusing lever; `/status probation_refusals` is their sum.
    /// (1) TardisAttachRequests we refused while OUR OWN NBC was probationary;
    /// (3) EmissionNabla claims answered NOT_ELIGIBLE for a probationary cert;
    /// (4) Alerts withheld because the proven sender's NBC is probationary.
    probation_attach_refusals: u64,
    probation_emission_refusals: u64,
    probation_alert_refusals: u64,
    /// YPX-003 §2.1 (KI#48, RULED 2026-09-25) — P-slot grants this node
    /// ACCEPTED as a requester (parked), and parks that ended by landing a
    /// real D slot elsewhere (`TardisDetach` sent to the P host). Both on
    /// `/status`; `grants - to_seated` ≈ parks that ended by host promotion
    /// or host loss. Observability only.
    tardis_parked_grants: u64,
    tardis_parked_to_seated: u64,
    /// YPX-002 §9.1.1a — `NbcIssuanceRequest`s answered `ISSUER_CAP_REACHED`
    /// (the budget itself lives in the lib and is snapshotted).
    nbc_issuance_refused_cap: u64,
    /// §9.1.1a peer alarm — verified citizen certificates per (issuer, epoch),
    /// and how many took an issuer ABOVE the cap (`[NBC-ISSUER-OVER-CAP]`).
    /// Observability only; never a refusal.
    nbc_issuer_epoch_seen: HashMap<(NodeId, u64), u64>,
    nbc_issuer_over_cap_seen: u64,
    /// GUIDE §5.6c — peers that were probationary at the last tick pass, so
    /// the pass can log the moment each one crosses OUT of probation (there is
    /// no promotion message; expiry is computed per tick from the cert).
    probationary_last_pass: std::collections::HashSet<NodeId>,
    /// GUIDE §5.6c lever 5 — pool kinds for which an AUTHENTICATED PoolSync
    /// (sender NBC on file, signature verified) has been applied since start.
    /// The serve-gate stays closed until every `PoolKind::SERVE_GATE_KINDS`
    /// entry is present (`pool_sync_gate_open`).
    pool_synced_kinds: std::collections::HashSet<PoolKind>,
    /// GUIDE §5.6c lever 5 — the first node of a mesh has nobody to sync
    /// from; set true alongside the KI#42 `anti_rollback_armed` exemption
    /// (bootstrap list empty) and nowhere else.
    pool_sync_gate_exempt: bool,
    /// G11 — cumulative corrupted entries reported by the WAL DEEP scan, which
    /// has no recovery path. `audit_recent` only samples the recent window, so
    /// an old corrupted entry is detectable nowhere else.
    wal_deep_scan_corrupt: u64,
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
    /// CLARA's txid bloom chain (`register_clara` looks up + inserts heal txids).
    ///
    /// KI#42 note: this is NOT dead scaffolding — I mis-read it as inert while
    /// surveying, and it is in active use by the CLARA heal path. It is, however,
    /// a SECOND chain over the same "was this txid seen" domain as the SMT's
    /// `txid_chain`, which is the duplication step 5 still has to resolve.
    /// Unifying them is not a rename: the split-borrow below exists precisely so
    /// CLARA can hold this chain, the garbage chain and the rate limiter at once,
    /// and the SMT's chain sits behind `node.core`, so `register_clara` would have
    /// to take the SMT rather than a bare chain. Left as-is deliberately rather
    /// than half-done.
    txid_bloom_chain: axiom_nabla::bloom_chain::BloomChain,
    /// KI#42: highest fill-ratio bucket (tenths) already warned about, so each
    /// threshold crossing logs once instead of every tick.
    bloom_fill_warn_bucket: u64,
    /// KI#42 serve-gate: has this node re-armed its anti-rollback view from a
    /// peer yet?
    ///
    /// A freshly-started node has an EMPTY `consumed_state_bloom`, so
    /// `is_state_consumed` answers "never seen it" for every state — i.e. the
    /// A12 anti-rollback gate (`registration.rs`) is wide open, and nothing
    /// previously stopped the node serving while blind. A blind node is not
    /// lying, it simply has no knowledge, but to a client its answer is
    /// indistinguishable from an armed node's "clean" — which is exactly what a
    /// rollback attacker wants. So: refuse client registrations until a
    /// Bootstrap StatePull has completed, and say so, rather than answering
    /// from an empty view.
    ///
    /// Set true when a Bootstrap StatePull response is processed — including one
    /// with an EMPTY payload, which is an honest peer saying "there is nothing
    /// to know yet" (a fresh mesh). Set true at construction when
    /// `bootstrap_addresses` is empty: a node with nobody to ask is the first
    /// node, and gating it would deadlock network start.
    anti_rollback_armed: bool,
    /// KI#79 — consecutive bootstrap-pull rounds spent UNARMED. delta sat
    /// unarmed for 8 hours (2026-08-07) with nothing counting the rounds, so
    /// a livelock and a healthy 2-minute re-arm produced identical log
    /// shapes. Reset to 0 on arming; drives log escalation
    /// (UNARMED_ESCALATION_ROUNDS) and /status.
    unarmed_rounds: u64,
    /// KI#79 — TARDIS tick (tick VALUE = unix secs, KI#47) when the current
    /// unarmed episode began; 0 = armed or not yet stamped. Stamped lazily on
    /// the first unarmed pull round (TARDIS may not be up at construction).
    unarmed_since_tick: u64,
    /// Log coalescing (design decision 2026-08-08: gamma's livelock emitted 2,254 warn
    /// lines — "too much to handle when trying to deal with debug"). The
    /// [REARM-PARTIAL] line emits on CHANGE of the missing set or on the
    /// escalation heartbeat, with a ×suppressed count; these carry the state.
    rearm_last_missing: Vec<u64>,
    rearm_suppressed: u64,
    /// Log coalescing — "peer only has data from tick N" advisories: emitted
    /// once per distinct N (a per-peer-history EDGE fact), debug! after.
    partial_history_seen: std::collections::HashSet<u64>,
    /// KI#63 §3.3 — AE outcomes in the current alarm window. Replication can be
    /// DEAD while looking busy: on 2026-08-04 anti-entropy rejected 115,054 of
    /// 115,054 entries over six hours and nothing said so. Counting only
    /// attempts would have looked healthy; the ratio is the signal.
    ae_applied_window: u64,
    ae_rejected_window: u64,
    /// KI#63(c) — lifetime count of `[AE-STALL]` windows (surfaced on /status).
    ae_stall_windows: u64,
    /// KI#63 §3.3 — §32 fork detections in the current alarm window. This is
    /// the DIVERGENCE signal, and without it the alarm is wrong: on a CONVERGED
    /// mesh `applied == 0` is the normal steady state (every entry a peer
    /// offers is already held, so it is correctly rejected as not-superseding /
    /// consumed-state). Applying nothing means there was nothing NEW to apply.
    /// Measured 2026-08-05: a healthy soak ran ~2 forks per 5-min window; the
    /// 2026-08-04 incident ran ~208.
    ae_forks_window: u64,
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
    /// ForkSettlement §2.4 [R9, R13, R34] — the BOOT FLOOR of this node's
    /// origin vouch: `virtual_secs` at the first tick-loop iteration after
    /// `recv_loop` went live (`recv_loop_live`), RE-FLOORED to `now` whenever
    /// two consecutive tick-loop iterations are further apart than the DEV
    /// settle twin (a stall under the global lock). `None` = not yet
    /// listening → the node vouches for no origin. A vouched attestation's
    /// `sender_registered_at_tick = max(record.first_seen_secs, this)`, so a
    /// node that was down (or stalled) since accepting a leg waits one full
    /// settle before vouching — time in which AE can deliver the ban.
    origin_boot_secs: Option<u64>,
    /// "Listening" — set by `recv_loop` before its first `recv` (plan A6: no
    /// "listener accepts" event exists; `recv_loop` is the inbound handler).
    recv_loop_live: bool,
    /// R13 re-floors taken (cumulative). On `/status` `origin_boot_refloors`.
    origin_boot_refloors: u64,
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
    /// Parents we recently detached from — excluded from upstream candidate
    /// selection until each entry's deadline, so rotation actually moves the
    /// topology instead of the orphan picker re-attaching to the same parent
    /// on the very next tick. Entries expire after ~`WRITER_GRACE_TICKS`, so a
    /// node CAN reconnect if no better candidate exists by then.
    ///
    /// ⚠ **CANONICAL — this is the parent-exclusion list. Use it.** If you need
    /// "do not re-attach to X for a while", add an entry here via
    /// `note_recently_detached()`. Do NOT introduce a second list (an earlier
    /// attempt at this added a parallel ring inside `TardisNode`; it was
    /// deleted as a duplicate before it shipped).
    ///
    /// **Why three and not one.** This was a single `Option`, which cannot
    /// break a 2-cycle: leaving A excludes A, then leaving B excludes B and
    /// *frees A*, so the picker returns to A — and the node ping-pongs. Traced
    /// live on run s2r85930598: `eta` cycled 9303 → 472b → 9303 → 472b, and
    /// `kappa`/`zeta` returned to parents they had just left. Three slots break
    /// 2- and 3-cycles; the FIFO rotation bounds the list so it can never grow
    /// into a de-facto ban list.
    ///
    /// It is a PREFERENCE, never a ban — recovery falls back to the unfiltered
    /// candidate set if filtering leaves nothing, so this cannot strand a node.
    recently_detached_parents: [Option<(NodeId, u64)>; 3],
    /// FIFO write cursor into `recently_detached_parents`.
    recently_detached_next: usize,

    /// KI#48 / YPX-003 §2.16.5 — an in-flight REATTACH (tree merge).
    /// `(target, tick_sent)`. Distinguishes "I asked to MOVE" from "I am an
    /// orphan asking for any parent": on accept, an orphan sets its upstream,
    /// but a reattacher must also DETACH from the parent it still has.
    reattach_pending: Option<(NodeId, u64)>,
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
    /// GUIDE §5.6a — are WE a genesis node (own NBC `chain_depth == 0`)?
    ///
    /// A genesis node is exempt from the peer-observed address mechanism on the
    /// SELF side, and the reason is specific: **its IP is published in
    /// `seeds/nabla-nodes.list`** — operator-controlled, curated, and already
    /// known to every node before contact. It does not need peers to discover
    /// what is already written down, so it never demotes itself on a
    /// disagreement it has no use for.
    ///
    /// ⚠ THIS IS TRANSITIONAL, NOT A PRIVILEGE (design ruling, 2026-08-26): *"It is
    /// fully controlled by me. And will retire as soon as the mesh grows to a
    /// certain size."* The exemption exists only while a curated seed list
    /// exists. When genesis retires there is no exempt class left — every node
    /// is a citizen learning its address from observation, which is the
    /// steady state this mechanism is actually for. Do not build anything that
    /// assumes a permanently-exempt tier, and do not widen this to "trusted"
    /// or "pinned" nodes generally — an exemption is only safe when the
    /// attacker cannot enter it, and the seed list is the only thing keeping
    /// this one closed.
    ///
    /// ⚠ CORRECTED 2026-08-26. This exemption used to sit on the OBSERVER side —
    /// a node DISCARDED any address report made by a genesis peer
    /// (`reporter_is_genesis`). Design ruling: *"It is that genesis does not require
    /// peers to tell its IP as special case, not node ignore genesis's advice."*
    /// The original 2026-08-20 ruling — *"If sees peer is a genesis, do not
    /// verify ip"* — reads at least as naturally as "do not police the IP OF a
    /// genesis peer", and was implemented the other way.
    ///
    /// Why the observer-side version was wrong: a genesis node is an ordinary
    /// node on the real internet, and its observation of "your connection
    /// reached me from X" is a plain fact about a TCP connection. The recorded
    /// justification for discarding it — that OUR genesis fleet is seven boxes
    /// on one LAN plus three remotes, so a citizen peering with both sees a
    /// permanent split — is a fact about this deployment, not about the
    /// protocol ([[feedback_assume_other_operators_not_our_deployment]],
    /// [[feedback_never_make_a_node_special]]). Worse, that "false positive" is
    /// the TRUE ANSWER: a node reachable at one address from the LAN and another
    /// from the WAN genuinely is not consistently reachable, and Read is the
    /// correct outcome.
    ///
    /// MEASURED consequence of the old rule: the Pi peers ONLY with genesis, so
    /// it had `address_reports: 0` — the check was structurally INERT for the
    /// one node in the mesh actually asserting a private VPN address, and it sat
    /// write-eligible for six days while its own counters logged ~10,000 failed
    /// sends to `172.20.0.42:730x`.
    own_nbc_is_genesis: bool,
    /// GUIDE §5.6a — peers AGREE on our address, but it is not globally
    /// routable. A demotion reason distinct from disagreement; surfaced on
    /// /status so an operator can tell which rule demoted them.
    address_unroutable: bool,
    /// Own NBC validity window + depth, captured at accept time so `/status`
    /// never has to deserialize the NBC on a request path.
    own_nbc_issued_at: u64,
    own_nbc_expires_at: u64,
    own_nbc_chain_depth: u8,
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
    /// ForkSettlement R50 (wave 4a) — the witness-directory AE ledger: nonces
    /// this node issued, nonces it answered, the per-`from` budget.
    directory_ae: axiom_nabla::vbc_directory::AeGuard,
    /// ForkSettlement R42 (wave 4a) — the OFF-LOCK directory verification of
    /// the message `handle_message` is about to process (`prelock_directory_
    /// verify`). Set and cleared by `recv_loop` inside ONE lock scope around
    /// `handle_message`, so it never outlives its message.
    directory_precheck: Option<DirectoryPrecheck>,
    /// ForkSettlement [R18] — the OFF-LOCK screen of the fork bans carried by
    /// the `AeReconcile` / `AeEntries` message `handle_message` is about to
    /// process (`prelock_ae_fork_bans`). Set and cleared by `recv_loop` inside
    /// ONE lock scope around `handle_message`, so it never outlives its
    /// message; `None` (`tick_loop`'s inbox drain) screens under the lock.
    ae_ban_precheck: Option<Vec<axiom_nabla::ban::AeBanScreen>>,
    /// Fork Settlement §9o [R58/R59] (W1) — the record-AE answer `handle_
    /// message` is about to process, ALREADY authenticated and its legs
    /// verified OFF the node lock (`prelock_record_ae`). Set and cleared by
    /// `recv_loop` inside ONE lock scope around `handle_message`; `None` on
    /// `tick_loop`'s inbox drain, which prepares under the lock (bounded by
    /// `RECORD_AE_MAX_LEGS_PER_ANSWER`, the `adopt_ae_fork_bans` precedent).
    /// Outer `Some` = the pre-lock stage RAN for this message; inner `None` =
    /// it refused the answer (already counted) — the arm must then NOT accept
    /// it again (a second verify would double-count the refusal).
    record_ae_precheck: Option<Option<axiom_nabla::record_sync::PreparedAnswer>>,
    /// Peer trust state for join protocol.
    verified_peers: HashMap<NodeId, PeerTrust>,
    /// AVM interpreter for CL7/CL8 NBC verification. None in sim/dev mode.
    avm: Option<Arc<AvmInterpreter>>,
    /// Skip NBC/VBC verification (dev/sim mode).
    skip_verify: bool,
    /// Reader-only mode: never accept registrations, always redirect (§25.5.4).
    reader_only: bool,
    /// GUIDE §5.6a — the source IP we observed for each peer on its INBOUND
    /// connection to us. We report this back to that peer so it can learn its
    /// own WAN address, which it cannot see from the inside.
    observed_sources: HashMap<NodeId, [u8; 16]>,
    /// GUIDE §5.6a — what our peers report OUR source address to be, keyed by
    /// the reporting peer. Only ever written after that peer's NBC verified,
    /// so every entry is attributable to an identity (RULE 3 shape 5).
    my_addr_reports: HashMap<NodeId, [u8; 16]>,
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

    // ── FOB (Fixed Outflow Balance) runtime counters — /status observability
    //    (RULE 3: a security-relevant reject needs a COUNTER, not just a log).
    /// Tranche statements this node AUTHORED + broadcast (recording nodes only).
    fob_tranches_authored: u64,
    /// Received tranche statements JUDGED valid and applied to local pools.
    fob_tranches_applied: u64,
    /// Received tranche statements REJECTED (crypto/judge failure) — not applied.
    /// A real reject (no-apply + logged); JUDOON signer-probation is a separate,
    /// not-yet-wired hardening step (see BoundedPools §4).
    fob_tranches_rejected: u64,
    /// KI#84 conservation guard — refused over-withdrawing ledger facts.
    fob_conservation_rejects: u64,
    /// In-flight tranche statements being aggregated toward a full committee
    /// (§3 no-coordination model), keyed by `tranche_statement_payload`.
    fob_pending: HashMap<[u8; 32], FobPendingStatement>,
    /// The last FOB epoch this node authored for. The epoch is derived from the
    /// SHARED TARDIS tick (unix seconds, §6) — NOT the local per-boot
    /// `tick_count` — so every mover computes the same epoch; authoring triggers
    /// on epoch ADVANCE. `u64::MAX` = uninitialized (author on the first epoch).
    fob_last_epoch: [u64; 2],  // [real, dev] — per-class epoch (§10.2a)

    // ── YPX-018 — Tiered bloom memory + CLARA wallet recovery ──
    //
    // These run alongside the legacy single-bloom path from YPX-014. The
    // existing path keeps working unchanged; Phase 4 will cut Lambda over
    // to consult the tiered chains via the three-state attestation.

    /// Time-bucketed txid bloom chain (YPX-018 §3). One bloom file per
    /// quarterly era. Inserted on every Nabla registration alongside the
    /// legacy single bloom.

    /// Garbage state bloom chain (YPX-018 §3.2). Records states declared
    /// garbage by CLARA wallet heals. Receivers consult this to refuse any
    /// transaction that tries to consume an abandoned state.
    garbage_state_chain: axiom_nabla::garbage_state_chain::GarbageStateChain,

    /// KI#43a — exact consumed-state record (hashmap mode only; None on
    /// bloom-mode nodes). Drained from the SMT's event buffer on the tick
    /// cadence; the durable record that makes a future consumed-bloom hit
    /// adjudicable (KI#43b). See `AXIOM_DESIGN_NablaAntiEntropy.md` §12.4.1.
    consumed_exact: Option<axiom_nabla::consumed_exact::ConsumedExactStore>,

    /// KI#43b — heal-adjudication barrier state, keyed by the healed-from
    /// state that HIT the consumed bloom. Created when a CLARA heal trips
    /// `ConsumedHealedFromHit` with no verdict; the tick loop pumps
    /// `ExactConsumedQuery` to every recording peer until the barrier
    /// completes; the CLARA handler consults the verdict on retry. Verdicts
    /// are retained for the process lifetime (a refusal is permanent truth;
    /// an acquittal can only be invalidated by the wallet advancing, which
    /// the head check catches anyway). §12.4.4.
    adjudications: std::collections::HashMap<axiom_nabla::types::StateId, Adjudication>,

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
    // ══════════════════════════════════════════════════════════════════
    //  CANONICAL parent-exclusion list — see `recently_detached_parents`.
    //  Every "don't re-attach to this parent yet" goes through these two.
    //  Do NOT keep a second list anywhere.
    // ══════════════════════════════════════════════════════════════════

    /// Record a parent we just left. FIFO — a 4th entry evicts the oldest.
    ///
    /// Refreshes the deadline in place if the parent is already listed, so a
    /// flapping parent extends its own exclusion instead of consuming three
    /// slots and evicting the memory of the other two.
    fn note_recently_detached(&mut self, parent: NodeId, until: u64) {
        for slot in self.recently_detached_parents.iter_mut() {
            if let Some((id, deadline)) = slot {
                if *id == parent {
                    *deadline = until;
                    return;
                }
            }
        }
        self.recently_detached_parents[self.recently_detached_next] = Some((parent, until));
        self.recently_detached_next =
            (self.recently_detached_next + 1) % self.recently_detached_parents.len();
    }

    /// Parents currently excluded from upstream selection. Expired entries are
    /// dropped as a side effect, which is why this takes `&mut self`.
    ///
    /// **Never starves recovery.** The list is trimmed so at least two peers
    /// remain selectable: on a small or shrinking mesh, exclusion yields rather
    /// than leaving an orphan with nobody to ask. That is what makes this a
    /// preference and not a ban — and it is enforced here, not merely asserted
    /// in a doc comment.
    fn excluded_parents(&mut self) -> Vec<NodeId> {
        let now = self.virtual_secs;
        let mut out = Vec::new();
        for slot in self.recently_detached_parents.iter_mut() {
            match slot {
                Some((id, until)) if now < *until => out.push(*id),
                Some(_) => *slot = None,
                None => {}
            }
        }
        // Keep >= 2 candidates. `active_peers` includes peers that are not
        // viable parents, so this is a floor, not a guarantee of choice — but
        // it removes the degenerate case where every known peer is excluded.
        let peers = self.core.mesh().map(|m| m.active_peers().len()).unwrap_or(0);
        let max_excluded = peers.saturating_sub(2);
        if out.len() > max_excluded {
            // Drop the OLDEST exclusions first: the most recent detach is the
            // one most likely to still be a bad parent.
            let drop_n = out.len() - max_excluded;
            log::debug!(
                "[TARDIS-EXCLUDE] trimming {} of {} exclusions — only {} peers known",
                drop_n, out.len(), peers
            );
            out.drain(0..drop_n);
        }
        out
    }

    /// YPX-021 §7 — this node's current proven network-size view, stamped
    /// as the baseline into certificates it issues/renews:
    /// (rounded OODS estimate over the verified-NBC set, current tick).
    /// (0, 0) when no estimate is possible yet (no verified peers) —
    /// certs issued then carry no baseline (exempt, like genesis).
    ///
    /// GUIDE §5.6c lever 2 — the identity set fed to the estimator EXCLUDES
    /// probationary NBCs (`oods_baseline_ids`): a flood of fresh certificates
    /// must not inflate the YPX-021 size the health flag / partition
    /// arithmetic rests on.
    fn oods_baseline_ids(&self) -> Vec<[u8; 32]> {
        let now = self.virtual_secs;
        self.verified_nbcs.iter()
            .filter(|(_, nbc)| !cc::is_probationary(nbc, now))
            .map(|(id, _)| *id)
            .collect()
    }

    fn current_oods_baseline(&self) -> (u32, u64) {
        let peer_ids = self.oods_baseline_ids();
        let est = axiom_nabla::oods::estimate_from_ids(&self.node_id, &peer_ids);
        let size = if est.is_finite() && est >= 1.0 {
            est.round().min(u32::MAX as f64) as u32
        } else {
            0
        };
        let tick = self.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
        (size, tick)
    }

    /// ForkSettlement §9h [R53] — this node's OWN OODS reading for the signed
    /// txid attestation: the SAME live estimate its `OodsReadingRequest`
    /// handler serves (`current_oods_baseline`, RULE 1), judged HEALTHY by
    /// Core's ONE rule `validation::oods_healthy(size, baseline)` (YPX-021:
    /// `size·3 ≥ baseline`) against the baseline its OWN NBC carries — the
    /// value `build_oods_attestation` signs for a client-facing reading. A
    /// baseline-0 (genesis) NBC reads healthy — R53a, by YPX-021, not
    /// special-cased here. No NBC loaded → no baseline to judge against →
    /// UNHEALTHY (fail closed: a node that cannot show its reading is sound
    /// must not help settle an origin). In-memory reads only; nothing blocks.
    fn current_oods_reading(&self) -> axiom_nabla::node::OodsReading {
        let (size, _tick) = self.current_oods_baseline();
        let healthy = cc::deserialize_nbc(&self.own_nbc_bytes)
            .map(|nbc| axiom_core_logic::validation::oods_healthy(size, nbc.network_size_baseline))
            .unwrap_or(false);
        axiom_nabla::node::OodsReading { size, healthy }
    }

    /// YPX-021 §8.2 — build the signed OODS reading served to clients.
    /// Crypto lives in `registration::build_oods_attestation` (the
    /// sanctioned synchronous-crypto hot-path file); this just supplies
    /// the node's materials. `None` when no NBC is loaded.
    fn build_oods_attestation(&self) -> Option<axiom_core_logic::types::NablaOodsAttestation> {
        let (oods_size, tick) = self.current_oods_baseline();
        axiom_nabla::registration::build_oods_attestation(
            &self.own_nbc_bytes, oods_size, tick, self.core.signer(), false,
        )
    }

    /// FOB mover-eligibility attestation. Identical to `build_oods_attestation`
    /// EXCEPT in DEV builds (core/logic `dev-mode`, KI#240), where a genesis (baseline-0) NBC gets the
    /// `DEV_OODS_BASELINE` floor so the dev mesh can author a FOB tranche and
    /// validate the path (§10.2a). RELEASE stamps the real NBC baseline — this
    /// is byte-identical to `build_oods_attestation` in release. Kept separate
    /// so client-facing OODS readings (which reach the committed ELF's §7 gate)
    /// are never given a dev baseline the ELF would reject.
    fn build_fob_oods_attestation(&self) -> Option<axiom_core_logic::types::NablaOodsAttestation> {
        let (oods_size, tick) = self.current_oods_baseline();
        axiom_nabla::registration::build_oods_attestation(
            &self.own_nbc_bytes, oods_size, tick, self.core.signer(), true,
        )
    }

    /// The FOB mover roster (§3, RECORDING-restricted). Only RECORDING (hashmap)
    /// nodes hold the convergent accumulator (`smt::validator_earnings` is
    /// recording-only), so only they can author a tranche — a bloom node's
    /// `fob_available` is 0 and it produces an empty statement. Selecting the
    /// committee from ALL OODS-eligible nodes (as the first pass did) means a
    /// mixed committee can never assemble `FOB_COMMITTEE_SIZE` signatures.
    /// Returns this node's mover pk (iff recording) plus every recording peer's
    /// Ed25519 pk (mesh `txid_service == "hashmap"`, joined to its NBC on the
    /// shared `NodeId`); every recording node computes the identical set, so the
    /// sortition is deterministic mesh-wide. Per-mover §5 OODS-eligibility is
    /// still enforced inside `judge_tranche_statement`.
    fn fob_recording_roster(&self, my_pk: [u8; 32]) -> Vec<[u8; 32]> {
        let mut roster: Vec<[u8; 32]> = Vec::new();
        if self.core.smt().txid_mode() == axiom_nabla::bloom::TxidServiceMode::Hashmap {
            roster.push(my_pk);
        }
        if let Some(mesh) = self.core.mesh() {
            for id in mesh.peer_ids() {
                if let Some(p) = mesh.peer_by_id(&id) {
                    if p.txid_service == "hashmap" {
                        if let Some(pk) =
                            self.verified_nbcs.get(&id).and_then(cc::nbc_ed25519_pk)
                        {
                            if pk != my_pk && !roster.contains(&pk) {
                                roster.push(pk);
                            }
                        }
                    }
                }
            }
        }
        roster
    }

    #[allow(clippy::too_many_arguments)]
    fn new(node_id: NodeId, address: NablaAddress, data_dir: &std::path::Path, signer: Box<dyn Signer>, avm: Option<Arc<AvmInterpreter>>, skip_verify: bool,
           txid_mode: axiom_nabla::bloom::TxidServiceMode, dev_mode: bool) -> Self {
        // Captured before `address` is moved into the mesh below.
        let bind_port_placeholder = to_socket_addr(&address).port();
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
        // §9.1.1a peer alarm — the restored (warm-cache) certificates count
        // against their issuers too, so a restart does not blind the alarm.
        let mut nbc_issuer_epoch_seen: HashMap<(NodeId, u64), u64> = HashMap::new();
        let mut nbc_issuer_over_cap_seen: u64 = 0;
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
                    if let Some((issuer, epoch, seen)) = cc::note_issuer_certificate(
                        &mut nbc_issuer_epoch_seen, &nbc, NBC_ISSUANCE_MAX_PER_EPOCH,
                    ) {
                        nbc_issuer_over_cap_seen = nbc_issuer_over_cap_seen.saturating_add(1);
                        warn!("[NBC-ISSUER-OVER-CAP] issuer={} epoch={} seen={} cap={} (restored cache)",
                            hex::encode(&issuer[..8]), epoch, seen, NBC_ISSUANCE_MAX_PER_EPOCH);
                    }
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
            atraxi: axiom_nabla::atraxi::AtraxiIndex::new(),
            node_id,
            node_name: String::new(),
            // Placeholder — main() overwrites this from node.toml's
            // `external_port` before the node ever speaks (§5.6a-bis). It is
            // seeded from the bind port only so the struct is constructible;
            // a node that somehow reached the wire on this value would
            // advertise its BIND port, which is exactly the NAT bug the
            // operator-declared field exists to prevent.
            external_port: bind_port_placeholder,
            orphan_ticks: 0,
            lineage_ok: 0,
            lineage_reject: 0,
            lineage_skip: 0,
            tickhash_verified: 0,
            tickhash_unverified: 0,
            alert_proven: 0,
            alert_unproven: 0,
            poolsync_drop_unverified: 0,
            reattach_pending: None,
            d1_approved_this_tick: false,
            approvals_unverified: 0,
            alert_identity_proven: 0,
            alert_identity_unproven: 0,
            probation_attach_refusals: 0,
            probation_emission_refusals: 0,
            probation_alert_refusals: 0,
            tardis_parked_grants: 0,
            tardis_parked_to_seated: 0,
            nbc_issuance_refused_cap: 0,
            nbc_issuer_epoch_seen: nbc_issuer_epoch_seen,
            nbc_issuer_over_cap_seen,
            probationary_last_pass: std::collections::HashSet::new(),
            pool_synced_kinds: std::collections::HashSet::new(),
            pool_sync_gate_exempt: false,
            wal_deep_scan_corrupt: 0,
            d1_first_seen_tick: 0,
            d2_first_seen_tick: 0,
            d2_approved_this_tick: false,
            d1_last_approval_secs: 0,
            d2_last_approval_secs: 0,
            messages_received: 0,
            rate_limited_gossip: 0,
            transport_send_failures_per_peer: HashMap::new(),
            peer_available_from_tick: 0,
            // KI#42: start UNARMED. `bootstrap_addresses` is populated after
            // construction (from config), so the "first node has nobody to ask"
            // exemption is applied where that happens, not here.
            anti_rollback_armed: false,
            unarmed_rounds: 0,
            unarmed_since_tick: 0,
            rearm_last_missing: Vec::new(),
            rearm_suppressed: 0,
            partial_history_seen: std::collections::HashSet::new(),
            ae_applied_window: 0,
            ae_rejected_window: 0,
            ae_stall_windows: 0,
            ae_forks_window: 0,
            txid_bloom_chain: axiom_nabla::bloom_chain::BloomChain::new_default(0),
            bloom_fill_warn_bucket: 0,
            last_gossip_tick: 0,
            last_pool_heartbeat_tick: 0,
            ae_peer_cursor: 0,
            virtual_secs: 0,
            origin_boot_secs: None,
            recv_loop_live: false,
            origin_boot_refloors: 0,
            virtual_ms: 0,
            pending_attach: HashMap::new(),
            pending_pings: HashMap::new(),
            ping_nonce: 0,
            recently_detached_parents: [None, None, None],
            recently_detached_next: 0,
            last_voluntary_move_tick: 0,
            bootstrap_addresses: Vec::new(),
            own_nbc_bytes: Vec::new(),
            own_nbc_is_genesis: false,
            address_unroutable: false,
            own_nbc_issued_at: 0,
            own_nbc_expires_at: 0,
            own_nbc_chain_depth: 0,
            latest_oods_tardis: Vec::new(),
            validator_pool: axiom_nabla::validator_pool::ValidatorPoolStore::new(),
            verified_nbcs,
            directory_ae: axiom_nabla::vbc_directory::AeGuard::directory(),
            directory_precheck: None,
            ae_ban_precheck: None,
            record_ae_precheck: None,
            verified_peers: HashMap::new(),
            avm,
            skip_verify,
            reader_only: false,
            observed_sources: HashMap::new(),
            my_addr_reports: HashMap::new(),
            sphincs_sk: None,
            own_supporting_nbcs: Vec::new(),
            nbc_issuer: String::new(),
            nbc_issuer_pk: Vec::new(),
            registration_count: 0,
            jfp_secrets: HashMap::new(),
            fob_tranches_authored: 0,
            fob_tranches_applied: 0,
            fob_tranches_rejected: 0,
            fob_conservation_rejects: 0,
            fob_pending: HashMap::new(),
            fob_last_epoch: [u64::MAX; 2],
            // YPX-018 — initialize tiered bloom chains starting at tick 0.
            // The actual era boundaries advance via maybe_rotate() on every
            // insert keyed by virtual_secs.
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
            consumed_exact: None,
            adjudications: std::collections::HashMap::new(),
        }
    }

    /// KI#43a — open the exact consumed-state store (hashmap mode only) and
    /// switch the SMT's event buffer on. Called once after construction; a
    /// failure to open is FATAL by design: a hashmap node that silently runs
    /// without its exact record defeats the point of the record (the missing
    /// history is not recoverable — §12.4's data dependency).
    fn init_consumed_exact(&mut self, data_dir: &std::path::Path) {
        if self.core.smt().txid_mode() != axiom_nabla::bloom::TxidServiceMode::Hashmap {
            return;
        }
        // Recording was enabled BEFORE snapshot restore + WAL replay (inside
        // `NablaNode::open_with_options`), so the buffer now holds the marks
        // the replay re-derived — the continuity evidence that lets a CLEAN
        // restart not count as a recording gap (2026-07-29 fix; without it,
        // every coordinated full-mesh restart gapped the active era on all
        // nodes at once, leaving the mesh unadjudicable for up to 90 days).
        let replayed = self.core.smt_mut().drain_exact_pending();
        let continuity = self.core.wal_replay_clean();
        let era = self.core.smt().consumed_chain().active_era_id();
        let store = axiom_nabla::consumed_exact::ConsumedExactStore::open_at_boot(
            data_dir.join("consumed_exact"),
            era,
            continuity,
            &replayed,
        )
        .unwrap_or_else(|e| panic!("FATAL: cannot open consumed_exact store: {e}"));
        log::info!(
            "[KI#43a] exact consumed-state record ACTIVE (eras on disk: {:?}, \
             boot replay: {} mark(s), continuity {})",
            store.era_ids(),
            replayed.len(),
            if continuity { "PROVEN (clean WAL) — restart is not a gap" }
            else { "NOT proven — restart counted as a gap" },
        );
        self.consumed_exact = Some(store);
    }

    /// KI#43a — drain the SMT's buffered consumption events into the exact
    /// store and fsync. Tick-cadence; bounded loss window (WAL replay
    /// re-feeds it). No-op on bloom-mode nodes (buffer stays empty).
    fn drain_consumed_exact(&mut self) {
        let events = self.core.smt_mut().drain_exact_pending();
        let Some(store) = self.consumed_exact.as_mut() else {
            debug_assert!(events.is_empty(), "exact events buffered with no store");
            return;
        };
        for (era_id, state) in &events {
            if let Err(e) = store.record(*era_id, state) {
                // Loud, and counted where operators look — a hashmap node
                // failing to append its exact record is degrading toward
                // "bloom-only evidence" silently otherwise.
                log::error!("[KI#43a] exact-record append FAILED (era {era_id}): {e}");
            }
        }
        if !events.is_empty() {
            if let Err(e) = store.flush() {
                log::error!("[KI#43a] exact-record fsync FAILED: {e}");
            }
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
        // GUIDE §5.6a — record whether WE are genesis. Set HERE because this is
        // the one place our own NBC is accepted and its chain_depth is already
        // in hand; deriving it per-Hello would mean deserializing our own NBC on
        // every inbound message.
        self.own_nbc_is_genesis = nbc.chain_depth == 0;
        self.own_nbc_issued_at = nbc.issued_at;
        self.own_nbc_expires_at = nbc.expires_at;
        self.own_nbc_chain_depth = nbc.chain_depth;
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
        self.verify_peer_nbc_with_supporting(nbc_bytes, &[], claimed_node_id)
    }

    /// As `verify_peer_nbc`, but with the sender's supporting NBC chain so a
    /// chain_depth>0 (validator-issued citizen) NBC can be walked to a Nabla
    /// root. `supporting_bytes` is the peer's `Hello.nbc_supporting_bytes`
    /// (bincode `Vec<NBC>`); empty for genesis peers. Passing the chain to Core
    /// is what fixes the 2026-08-16 Pi join gap: `verify_nbc_via_core` supplied
    /// an EMPTY supporting set, so Core's CL7 rejected every citizen NBC as
    /// InvalidVBC even though the leaf's own self-verify (native `verify_nbc_chain`
    /// WITH supporting, at startup) passed. Now the peer path carries the chain.
    fn verify_peer_nbc_with_supporting(
        &mut self,
        nbc_bytes: &[u8],
        supporting_bytes: &[u8],
        claimed_node_id: &NodeId,
    ) -> Result<NodeId, String> {
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

        // Deserialize the supporting chain (empty for genesis peers). A decode
        // failure is fail-closed: an unusable chain leaves `supporting` empty, so
        // a chain_depth>0 NBC will reject with a missing-issuer error below rather
        // than silently verify against a truncated chain.
        let supporting: Vec<NBC> = if supporting_bytes.is_empty() {
            Vec::new()
        } else {
            match bincode::deserialize::<Vec<NBC>>(supporting_bytes) {
                Ok(v) => v,
                Err(e) => return Err(format!("NBC supporting chain deserialize failed: {}", e)),
            }
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
        // This is the PRODUCTION path (validators and citizens always launch with
        // `--avm-elf`), and it now carries the supporting chain so a
        // validator-issued (chain_depth>0) citizen NBC verifies to a Nabla root
        // via Core `verify_nbc_bundle` (the 2026-08-16 Pi join fix).
        //
        // Fallback: single-hop native crypto — DEV/SIM ONLY (no AVM). Deliberately
        // lax (leaf structure + issuer signature; no chain-of-trust walk), exactly
        // as before this fix. It is never a production security boundary because
        // production always takes the AVM branch above; sim/tests build
        // self-contained NBCs that carry no supporting chain.
        if let Some(ref avm) = self.avm {
            if let Err(e) = verify_nbc_chain_via_core(avm, &nbc, &supporting, self.virtual_secs) {
                return Err(format!("Core rejected NBC: {}", e));
            }
        } else if let Err(e) = verify_nbc(&nbc, self.virtual_secs) {
            return Err(format!("Direct verify NBC failed: {}", e));
        }

        // Cache the verified NBC
        info!("NBC verified for {:02x}{:02x}... ({})", nbc_id[0], nbc_id[1], nbc.node_name);
        // §9.1.1a peer alarm — fires only on a FRESH insert (a cached-valid
        // peer returned early above), so one certificate counts once here.
        self.note_issuer_certificate(&nbc);
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

    /// Serialized supporting NBC chain for outgoing Hello / TardisAttach*
    /// messages. EMPTY for a genesis (chain_depth 0) node — it needs no
    /// supporting chain to verify — so genesis mesh traffic stays lean; a
    /// citizen (chain_depth>0) ships its issuer chain (bincode `Vec<NBC>`) so
    /// peers can walk its NBC to a Nabla root (2026-08-16 join fix).
    fn own_nbc_supporting_bytes(&self) -> Vec<u8> {
        if self.own_supporting_nbcs.is_empty() {
            Vec::new()
        } else {
            bincode::serialize(&self.own_supporting_nbcs).unwrap_or_default()
        }
    }

    /// Evict expired NBCs from the peer cache.
    fn evict_expired_nbcs(&mut self) {
        let now = self.virtual_secs;
        self.verified_nbcs.retain(|_, nbc| nbc.expires_at > now);
    }

    /// Handle a NablaJoinRequest: verify NBC, verify wallet binding, cache the
    /// peer. Returns (accepted, reason, probation_until) and optional gossip
    /// message. `probation_until` is `issued_at + projected window` when the
    /// joiner's certificate is inside probation (GUIDE §5.6c) and 0 otherwise
    /// — derived from the certificate, so a re-join reports the SAME value
    /// (nothing here starts or resumes a timer).
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

        // 3. The joiner's probation end, from ITS CERTIFICATE (GUIDE §5.6c).
        // Until 2026-09-25 this path wrote `Probation { since: virtual_secs }`
        // — a local clock — and a reconnect "resumed" that timer; nothing in
        // production ever read it (KI#75). Now the window is a pure function
        // of the signed `issued_at`, identical on every node and every hop.
        let probation_until = if cc::is_probationary(&nbc, self.virtual_secs) {
            cc::probation_ends_at(&nbc)
        } else {
            0
        };

        // 4. Reconnection: already cached under the SAME wallet → accept, no
        // re-announce. A different wallet on the same Nabla_id is a duplicate.
        if let Some(existing) = self.verified_peers.get(&nabla_id) {
            if let Some(ref existing_wallet) = existing.wallet_id {
                if existing_wallet != wallet_id {
                    return (false, "duplicate Nabla_id with different wallet".into(), 0, None);
                }
            }
            return (true, String::new(), probation_until, None);
        }

        // 5. Accept: cache the certificate + wallet binding. No status field —
        // `PeerTrust::trust_status(now)` derives it on read.
        let announced_at = self.virtual_secs;
        self.verified_peers.insert(nabla_id, PeerTrust {
            nbc,
            wallet_id: Some(*wallet_id),
        });

        // 6. Gossip NablaIdAnnounce for duplicate detection
        let announce = GossipMessage::NablaIdAnnounce {
            nabla_id,
            wallet_id: *wallet_id,
            announced_at,
        };

        (true, String::new(), probation_until, Some(announce))
    }

    // ── GUIDE §5.6c join probation — the bin-side readers of the ONE predicate ──
    //
    // `is_peer_in_probation` / `advance_probation` (Phase 7, 2026-02-28) used
    // to live here, `#[cfg(test)]` since 2026-03-26 (KI#75): a status written
    // at join from the local clock, never read, never expired. Deleted — the
    // status is now DERIVED from the certificate wherever it is read, so there
    // is no timer to advance and nothing to promote.

    /// Are WE probationary — is our own NBC inside the window? Lever 1(a):
    /// a probationary node refuses to take TARDIS children, so its
    /// `downstream_count` stays 0 and `is_self_writer()` can never hold.
    fn own_nbc_probationary(&self) -> bool {
        self.core.cc_chain()
            .map(|chain| cc::is_probationary(chain.nbc(), self.virtual_secs))
            .unwrap_or(false)
    }

    /// Is this peer's VERIFIED NBC inside the window? `false` for a peer we
    /// hold no NBC for — the caller's own fail-closed rule (no NBC → not a
    /// candidate / dropped) already covers that case; this predicate answers
    /// only the §5.6c question.
    fn peer_nbc_probationary(&self, node_id: &NodeId) -> bool {
        self.verified_nbcs.get(node_id)
            .map(|nbc| cc::is_probationary(nbc, self.virtual_secs))
            .unwrap_or(false)
    }

    /// Lever 1(b) — the ONE rule every upstream-candidate loop applies (P1
    /// tick-piggyback, P2 known peers, the reattach merge move): skip a
    /// candidate whose verified NBC is probationary. Extracted so a test can
    /// drive it directly (RULE 6 §3a) instead of re-deriving it beside the
    /// loops.
    fn upstream_candidate_probationary(&self, candidate: &NodeId) -> bool {
        self.peer_nbc_probationary(candidate)
    }

    /// `/status probationary_peers` — count over `verified_nbcs` at now.
    fn probationary_peer_count(&self) -> usize {
        self.verified_nbcs.values()
            .filter(|nbc| cc::is_probationary(nbc, self.virtual_secs))
            .count()
    }

    /// `/status probation_refusals` — the three refusing levers, summed.
    fn probation_refusals_total(&self) -> u64 {
        self.probation_attach_refusals
            .saturating_add(self.probation_emission_refusals)
            .saturating_add(self.probation_alert_refusals)
    }

    /// Lever 5 — has this node applied an authenticated PoolSync for EVERY
    /// serve-gate pool kind since start (or is it the first node of its mesh,
    /// exempt exactly as KI#42 exempts it from `anti_rollback_armed`)?
    fn pool_sync_gate_open(&self) -> bool {
        self.pool_sync_gate_exempt
            || PoolKind::SERVE_GATE_KINDS.iter().all(|k| self.pool_synced_kinds.contains(k))
    }

    /// `/status pool_synced_kinds` — sorted, deduplicated names.
    fn pool_synced_kind_names(&self) -> Vec<String> {
        let names: std::collections::BTreeSet<&'static str> =
            self.pool_synced_kinds.iter().map(|k| k.status_name()).collect();
        names.into_iter().map(String::from).collect()
    }

    /// Lever 5 — record an authenticated PoolSync's kind. Returns true the
    /// first time this call completes the serve-gate set (for the log line).
    fn note_pool_synced(&mut self, kind: PoolKind) -> bool {
        let was_open = self.pool_sync_gate_open();
        self.pool_synced_kinds.insert(kind);
        !was_open && self.pool_sync_gate_open()
    }

    /// Once per tick: log each peer crossing OUT of probation (§5.6c
    /// "a log line at each peer's confirmation"). There is no promotion
    /// message — each node computes the crossing from the certificate, so
    /// the only way to observe it is to compare consecutive passes.
    fn probation_tick_pass(&mut self) {
        let now: std::collections::HashSet<NodeId> = self.verified_nbcs.iter()
            .filter(|(_, nbc)| cc::is_probationary(nbc, self.virtual_secs))
            .map(|(id, _)| *id)
            .collect();
        for id in self.probationary_last_pass.difference(&now) {
            // Still verified (not expired/removed) and no longer probationary.
            if let Some(nbc) = self.verified_nbcs.get(id) {
                info!("[PROBATION-CONFIRMED] peer {:02x}{:02x}… ({}) left join probation \
                       (issued_at={} window={} s, §5.6c) — now a full peer",
                    id[0], id[1], nbc.node_name, nbc.issued_at, nabla_probation_span_secs());
            }
        }
        self.probationary_last_pass = now;
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
    /// YPX-002 §9.1.1a peer alarm — count a verified citizen certificate
    /// against its issuer for the epoch its `issued_at` names; above the cap,
    /// log `[NBC-ISSUER-OVER-CAP]` and count it. OBSERVABILITY ONLY — the
    /// certificate is still accepted. Prunes epochs older than the previous
    /// one so the map stays bounded by (issuers × 2).
    fn note_issuer_certificate(&mut self, nbc: &NBC) {
        if let Some((issuer, epoch, seen)) = cc::note_issuer_certificate(
            &mut self.nbc_issuer_epoch_seen, nbc, NBC_ISSUANCE_MAX_PER_EPOCH,
        ) {
            self.nbc_issuer_over_cap_seen = self.nbc_issuer_over_cap_seen.saturating_add(1);
            warn!("[NBC-ISSUER-OVER-CAP] issuer={} epoch={} seen={} cap={}",
                hex::encode(&issuer[..8]), epoch, seen, NBC_ISSUANCE_MAX_PER_EPOCH);
        }
        let current = axiom_nabla::constants::nbc_issuance_epoch(self.virtual_secs);
        self.nbc_issuer_epoch_seen.retain(|(_, e), _| *e + 1 >= current);
    }

    fn handle_nbc_issuance_request(
        &mut self,
        sphincs_pk: &[u8],
        ed25519_pk: &[u8],
        dilithium_pk: &[u8],
        node_name: &str,
        operator_wallet: &str,
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

        // ── YPX-002 §9.1.1a ISSUER SELF-CAP (RULED 2026-09-25) ──
        // The N+1-th certificate this node would SIGN inside one FOB epoch is
        // refused. The epoch is the one our own `issued_at` stamp (= virtual
        // now, passed to `issue_nbc`) falls in; the budget is lib state and
        // snapshotted, so a restart does not reset it. Checked BEFORE signing,
        // recorded AFTER a successful signature (a failed signing consumes no
        // budget). Refusal shape mirrors every other refusal here: `accepted:
        // false` + `rejection_reason`.
        let issuance_epoch = axiom_nabla::constants::nbc_issuance_epoch(self.virtual_secs);
        if self.core.nbc_issuance_budget().at_cap(issuance_epoch, NBC_ISSUANCE_MAX_PER_EPOCH) {
            self.nbc_issuance_refused_cap = self.nbc_issuance_refused_cap.saturating_add(1);
            warn!("[NBC-ISSUER-CAP] refusing '{}': {} certificate(s) already signed in FOB epoch {}                    (cap {}, §9.1.1a) — total refused {}",
                node_name, self.core.nbc_issuance_budget().count_in(issuance_epoch), issuance_epoch,
                NBC_ISSUANCE_MAX_PER_EPOCH, self.nbc_issuance_refused_cap);
            return (false, vec![], vec![], NBC_ISSUER_CAP_REACHED.into());
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
            // The requester's declared operator wallet (from its node.toml,
            // carried in the NBC request). `build_unsigned_nbc` rejects a dev
            // operator (the owner 2026-09-20). Empty = not declared (grandfathered).
            // This is the issuance-time check (honest issuer, k=1 Nabla trust);
            // the tamper-proof preimage binding is the genesis-ceremony follow-up.
            wallet_id: operator_wallet.to_string(),
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
                // §9.1.1a — consume budget for the epoch of the stamp we SIGNED,
                // then make it durable now: the periodic snapshot could be
                // minutes away and a restart in between would forget the count.
                self.core.nbc_issuance_budget_mut().record(
                    axiom_nabla::constants::nbc_issuance_epoch(nbc.issued_at));
                if let Err(e) = self.core.take_snapshot() {
                    warn!("[NBC-ISSUER-CAP] snapshot after issuance failed: {} — the budget                            persists at the next periodic snapshot", e);
                }
                info!("NBC ISSUED for '{}' (chain_depth={}) — {}/{} in FOB epoch {}",
                    node_name, nbc.chain_depth,
                    self.core.nbc_issuance_budget().count_in(issuance_epoch),
                    NBC_ISSUANCE_MAX_PER_EPOCH, issuance_epoch);
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
        // — the ONE builder (KI#55), shared with the signer in `check_nbc_renewal`.
        let commitment = crypto::nbc_renew_sign_payload(&old_nbc.validator_id, request_time);
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

        // Sign: BLAKE3("AXIOM_NBC_RENEW" || validator_id || current_time) — the ONE
        // builder (KI#55), shared with the verifier in `handle_nbc_renewal_request`.
        let commitment = crypto::nbc_renew_sign_payload(&own_nbc.validator_id, self.virtual_secs);

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
        let is_parked = self.core.tardis().unwrap().is_parked();
        let downstream_count = self.core.tardis().unwrap().downstream_count();
        // ONE predicate with the register door (RULE 6, 2026-10-01): see
        // TardisNode::writer_status. `is_parked` / `has_upstream` stay for other fields.
        let (is_writer, tardis_slot) = self.core.tardis().unwrap().writer_status();
        let _ = (is_parked, has_upstream);

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
                // ⚠ THIS WAS THE LITERAL `false` (RULE 3 shape 4, found
                // 2026-08-26). It is the ONLY site that builds a `PeerEntry` in
                // production, and the only `is_genesis: true` in the tree is a
                // `monitor.rs` test fixture — so the dashboard's genesis marker
                // (`monitor.rs:1145` renders `genesis: p.is_genesis`) was
                // structurally incapable of ever being true. A reader checking
                // "which of my peers are genesis?" got "none", always, on a mesh
                // that is nine-tenths genesis.
                //
                // Correct reading: genesis is DERIVABLE and already derived for
                // the §5.6a reporter check at the `reporter_is_genesis` site
                // below — a chain_depth 0 NBC is issued by a root authority,
                // i.e. genesis; anything deeper is a citizen.
                //
                // `false` for an unknown peer means "not KNOWN to be genesis",
                // not "proven citizen": a peer we have not NBC-verified has no
                // entry in `verified_nbcs`. That is the same fail-closed
                // convention as `reporter_is_genesis`, and it is the safe
                // direction — this field must never assert genesis authority
                // that has not been verified.
                is_genesis: self.verified_nbcs.get(&p.node_id)
                    .map(|n| n.chain_depth == 0)
                    .unwrap_or(false),
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
                    // §6.3.7 measured RTT. `None` = UNMEASURED, never "fast".
                    latency_ms: self.core.mesh()
                        .and_then(|m| m.peer_rtt_ms(&peer.node_id))
                        .map(|r| r.round() as u64),
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
                    latency_ms: self.core.mesh()
                        .and_then(|m| m.peer_rtt_ms(&peer.node_id))
                        .map(|r| r.round() as u64),
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

        // Dev-only flood chaos: the watched wallets' BanTable evidence for `/status`
        // (`flood_chaos.evidence`) — what a live gate reads as "banned on Fork EVIDENCE".
        #[cfg(feature = "flood-chaos")]
        axiom_nabla::flood_chaos::set_evidence(
            axiom_nabla::flood_chaos::watched_wallets().into_iter()
                .map(|w| (w, axiom_nabla::flood_chaos::evidence_kind(self.core.bans().get(&w).map(|b| &b.evidence))))
                .collect(),
        );
        let ps = self.core.persistence_stats();
        let (same_seq_manufactured, same_seq_cleared, same_seq_active) =
            self.core.smt().same_seq_mark_counters();
        let mut status = NodeStatusSnapshot {
            // §5.6a — READ THE REAL STATE. An earlier draft hardcoded
            // `false, 0` here as a "placeholder", which would have pinned the
            // counter to a constant on the very endpoint the dashboard serves —
            // RULE 3 shape 4, and a ghost inside the counter whose entire job is
            // to stop "never disputed" and "never ran" looking identical.
            address_disputed: self.core.tardis().map(|t| t.address_disputed()).unwrap_or(false),
            address_reports: self.core.tardis().map(|t| t.address_report_count()).unwrap_or(0),
            slot_hints_dropped_unobserved: self.core.mesh()
                .map(|m| m.slot_hints_dropped_unobserved()).unwrap_or(0),
            // GUIDE §5.6a — the EVIDENCE behind address_reports/address_disputed.
            // A verdict without its inputs cannot be diagnosed; see the field doc.
            address_unroutable: self.address_unroutable,
            address_observers: self.my_addr_reports.iter().map(|(nid, ip)| {
                let v6 = std::net::Ipv6Addr::from(*ip);
                monitor::AddressObservation {
                    node_id_hex: hex::encode(nid),
                    node_name: peer_name(nid),
                    observed_ip: match v6.to_ipv4_mapped() {
                        Some(v4) => v4.to_string(),
                        None => v6.to_string(),
                    },
                }
            }).collect(),
            nbc_issued_at: self.own_nbc_issued_at,
            nbc_expires_at: self.own_nbc_expires_at,
            // Signed: negative = ALREADY EXPIRED, which is operationally
            // different from "expires in 0s" and must not be clamped away.
            nbc_expires_in_secs: self.own_nbc_expires_at as i64 - self.virtual_secs as i64,
            nbc_chain_depth: self.own_nbc_chain_depth,
            nbc_issuer: self.nbc_issuer.clone(),
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
            txid_bloom_fill_ratio: self.core.smt().txid_bloom_fill_ratio(),
            consumed_bloom_count: self.core.smt().consumed_bloom_count(),
            consumed_bloom_fpr: self.core.smt().consumed_bloom_fpr(),
            consumed_bloom_fill_ratio: self.core.smt().consumed_bloom_fill_ratio(),
            listen_addr: monitor::format_address(self.core.mesh().unwrap().my_address()),
            // GUIDE §5.6a — our WAN address as OBSERVED BY PEERS, which is the
            // only party that can see it: `getsockname()` returns the pre-NAT
            // tuple and the rewrite happens off-host.
            //
            // Reported ONLY when the observers agree. A split view is exactly
            // the `address_disputed` condition, and printing one of two
            // conflicting answers as "our WAN address" would assert a fact the
            // node does not have — `None` there means "peers disagree, see
            // address_observers", not "unknown".
            //
            // Was a hardcoded `None` (RULE 3 shape 4). It only became derivable
            // on 2026-08-26, when the §5.6a exemption moved to the self side and
            // genesis observations started counting — before that the report map
            // was empty on every citizen whose peers were all genesis.
            wan_addr: {
                let distinct: std::collections::HashSet<&[u8; 16]> =
                    self.my_addr_reports.values().collect();
                if distinct.len() == 1 {
                    distinct.into_iter().next().map(|ip| {
                        let v6 = std::net::Ipv6Addr::from(*ip);
                        match v6.to_ipv4_mapped() {
                            Some(v4) => v4.to_string(),
                            None => v6.to_string(),
                        }
                    })
                } else {
                    None
                }
            },
            built_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
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
            orphan_causes: self.core.tardis().unwrap().orphan_causes().as_pairs()
                .iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            lineage_ok: self.lineage_ok,
            lineage_reject: self.lineage_reject,
            lineage_skip: self.lineage_skip,
            tickhash_verified: self.tickhash_verified,
            tickhash_unverified: self.tickhash_unverified,
            alert_proven: self.alert_proven,
            alert_unproven: self.alert_unproven,
            poolsync_drop_unverified: self.poolsync_drop_unverified,
            approvals_unverified: self.approvals_unverified,
            alert_identity_proven: self.alert_identity_proven,
            alert_identity_unproven: self.alert_identity_unproven,
            wal_deep_scan_corrupt: self.wal_deep_scan_corrupt,
            h3_unbuilt_dropped: self.core.gossip().h3_unbuilt_dropped(),
            ki222_banalert_dropped: self.core.gossip().ki222_banalert_dropped(),
            quarantine_withheld: self.core.quarantine_withheld_activations(),
            ae_stall_windows: self.ae_stall_windows,
            // KI#132 — non-zero means a Core gate leaked (see the field doc).
            stake_lock_observed_not_own_claim:
                axiom_nabla::registration::stake_lock_observations(),
            audit_resp_unauthorized: self.core.tardis().map(|t| t.audit_responses_unauthorized()).unwrap_or(0),
            audit_resp_unmatched: self.core.tardis().map(|t| t.audit_responses_unmatched()).unwrap_or(0),
            audit_exonerated: self.core.tardis().map(|t| t.audit_exonerated()).unwrap_or(0),
            tardis_audit: self.core.tardis()
                .map(|t| t.audit_counters().iter().map(|(k, v)| (k.to_string(), *v)).collect())
                .unwrap_or_default(),
            root_hash_hex: monitor::hex_short(&self.core.smt().root_hash()),
            entry_count: self.core.smt().len(),
            ban_count: self.core.bans().len(),
            // Derived, not asserted. This was a hardcoded `true`, so /status
            // reported the mesh ACTIVE even when it was not — RULE 3 shape 4,
            // the same defect as `is_genesis` on this page (found 2026-08-26).
            mesh_active: self.core.mesh().is_some(),
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
            // ALLOW_UNWIRED_FIELD — there is NO runner pool in nabla. Nothing
            // credits or debits one anywhere in this crate, so this is not a
            // balance that happens to be zero; it is a field with no subject.
            // Left rather than deleted because the dashboard renders it and
            // removing it is a surface change; marked so it is not mistaken for
            // a measurement (RULE 3 shape 4, swept 2026-08-26).
            runner_pool_balance: 0,
            airdrop_pool_balance: self.core.airdrop_pool().balance(),
            airdrop_pool_claims: self.core.airdrop_pool().total_claims,
            airdrop_local_claims: self.core.airdrop_pool().local_claims,
            dev_pool_balance: self.core.dev_treasury_pool().balance(),
            dev_pool_claims: self.core.dev_treasury_pool().total_claims,
            dev_pool_local_claims: self.core.dev_treasury_pool().local_claims,
            bootstrap_pool_balance: self.core.bootstrap_pool().balance(),
            bootstrap_pool_claims: self.core.bootstrap_pool().total_claims,
            foundation_pool_balance: self.core.foundation_bootstrap_pool().balance(),
            foundation_pool_claims: self.core.foundation_bootstrap_pool().total_claims,
            // ALLOW_UNWIRED_FIELD — documented as "the 1000-atom write fee on
            // every register", but NOTHING counts it. Real semantics, absent
            // plumbing: it needs a per-register fee counter that does not exist.
            // ⚠ A permanently-zero fee counter reads as "no fees collected"
            // rather than "never wired" — do not cite it as evidence of either.
            // `deed_pool_balance` / `deed_pool_total_credited` immediately below
            // ARE derived and are the numbers to trust.
            deed_collected: 0,
            // ALLOW_UNWIRED_FIELD — same gap as `deed_collected`; the split is
            // never computed. YP §25.4 fixed DEED at a single 10% share, so even
            // the "a/b" shape here predates the current rule.
            deed_split: "0/0".into(),
            deed_pool_balance: self.core.deed_pool.balance(),
            deed_pool_total_credited: self.core.deed_pool.total_credited(),
            // Dev-class DEED — observability for @axiom.internal traffic.
            // NEVER reads through to the public DEED accounting; the
            // newtype wrapper makes a cross-credit a compile error.
            dev_deed_pool_balance: self.core.dev_deed_pool.balance(),
            dev_deed_pool_total_credited: self.core.dev_deed_pool.total_credited(),
            fob_pools: self.core.fob_pools_snapshot().iter()
                .map(|(vid, is_dev, bal)| format!(
                    "{}:{}:{}", hex::encode(&vid[..8]),
                    if *is_dev { "dev" } else { "real" }, bal,
                ))
                .collect(),
            fob_tranches_authored: self.fob_tranches_authored,
            fob_tranches_applied: self.fob_tranches_applied,
            fob_tranches_rejected: self.fob_tranches_rejected,
            fob_conservation_rejects: self.core.fob_conservation_rejects(),
            emission_epoch: self.core.emission().epoch,
            emission_rolls: self.core.emission().rolls,
            emission_top_up_atoms: self.core.emission().top_up_atoms,
            emission_claims_ok: self.core.emission().claims_ok,
            emission_claims_refused: self.core.emission().claims_refused,
            emission_conservation_refusals: self.core.emission().conservation_refusals,
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
            // KI#48 P slot (RULED 2026-09-25) — parked flag + the bin's counters.
            tardis_parked: is_parked,
            tardis_parked_grants: self.tardis_parked_grants,
            tardis_parked_to_seated: self.tardis_parked_to_seated,
            // Phase B Layer 4: quarantine telemetry (mirrors lib-mode).
            quarantine_active_count: self.core.quarantine_state().active_count(),
            quarantine_pending_count: self.core.quarantine_state().pending_count(),
            // KI#191 residual — emission-pool structural escalations (lib-owned).
            emission_structural_violations: self.core.emission_structural_violations(),
            // YPX-002 §9.1.1a — issuer self-cap + peer alarm.
            nbc_issued_this_epoch: self.core.nbc_issuance_budget().count_in(
                axiom_nabla::constants::nbc_issuance_epoch(self.virtual_secs)),
            nbc_issuance_refused_cap: self.nbc_issuance_refused_cap,
            nbc_issuer_over_cap_seen: self.nbc_issuer_over_cap_seen,
            // GUIDE §5.6c join probation (KI#75) — the bin owns all four.
            probationary_peers: self.probationary_peer_count(),
            probation_refusals: self.probation_refusals_total(),
            pool_synced_kinds: self.pool_synced_kind_names(),
            pool_sync_gate_open: self.pool_sync_gate_open(),
            penguin_score,
            penguin_level: level_name.into(),
            penguin_emoji: level_emoji.into(),
            uptime_streak_days: uptime / 86400,
            writes_approved,
            // ALLOW_UNWIRED_FIELD — no production counter. `nabla/src/node.rs`
            // is explicit: "tracked by sim only for now". Feeds `penguin_score`,
            // so a node can never earn credit for a rescue it actually performed.
            orphans_rescued: 0,
            // ALLOW_UNWIRED_FIELD — no production counter (sim only, as above).
            // Also feeds `penguin_score`. ⚠ Note this fleet HAS survived
            // rotations — three today alone — so zero here is provably wrong
            // rather than merely unpopulated.
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
            // KI#79 — the serve-gate on /status: UNARMED must be visible
            // (and, via diagnose(), a health_issue) instead of coexisting
            // with `healthy: true` as it did for delta's 8-hour episode.
            anti_rollback_armed: self.anti_rollback_armed,
            unarmed_rounds: self.unarmed_rounds,
            unarmed_ticks: if self.unarmed_since_tick > 0 {
                tardis_tick.saturating_sub(self.unarmed_since_tick)
            } else {
                0
            },
            // KI#65 — same-seq falsifiable-mark observability (RULE 3 §2).
            same_seq_marks_manufactured: same_seq_manufactured,
            same_seq_marks_cleared: same_seq_cleared,
            same_seq_marks_active: same_seq_active as u64,
            // YPX-022 §2.1.2a (KI#205) — claim authentication + CLAIMED recall
            // refusals (RULE 3 §2). Same sources the lib builder reads.
            claims_unauthenticated: axiom_nabla::registration::claims_unauthenticated_total(),
            recalls_refused_claimed: self.core.smt().recalls_refused_claimed(),
            // ForkSettlement wave 2a — refused legs (door/flood/AE) and refused
            // snapshots (persisted-shape hazard). Same sources as the lib builder.
            leg_preimage_refused: axiom_nabla::registration::leg_preimage_refused_total(),
            witness_not_in_directory_refused: axiom_nabla::registration::witness_not_in_directory_refused_total(),
            declared_state_unanchored: axiom_nabla::registration::declared_state_unanchored_total(),
            wal_checksum_missing_refused: axiom_nabla::wal::wal_checksum_missing_refused_total(),
            snapshot_decode_refused: axiom_nabla::snapshot::snapshot_decode_refused_total(),
            vbc_directory_refused: axiom_nabla::vbc_directory::directory_refused_total(),
            vbc_stamp_refused_no_floor: axiom_nabla::registration::vbc_stamp_refused_no_floor_total(),
            vbc_stamp_refused_held: axiom_nabla::registration::vbc_stamp_refused_held_total(),
            vbc_stamp_refused_wait: axiom_nabla::registration::vbc_stamp_refused_wait_total(),
            vbc_registry_decode_refused: axiom_nabla::vbc_directory::registry_decode_refused_total(),
            vbc_directory_ae_refused: axiom_nabla::vbc_directory::directory_ae_refused_total(),
            vbc_directory_entries: self.core.vbc_directory().len() as u64,
            // ForkSettlement wave 3 — ONE builder (the lib's), plus this
            // binary's R13 boot floor / re-floor count.
            origin: self.core.origin_status(self.origin_boot_secs, self.origin_boot_refloors),
            atraxi_open_keys: self.atraxi.open_keys() as u64,
            atraxi_claims_opened: self.atraxi.opened_total(),
            atraxi_held_refusals: self.atraxi.held_refusals(),
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
/// GUIDE §5.6a — IPv6-mapped bytes of a socket's IP. The port is deliberately
/// dropped: what we observe is the ephemeral NAT-translated source port, not the
/// port the peer listens on. Peers must dial `WAN_IP : forwarded_port`, so the
/// port comes from the peer's own config, never from an observation.
/// GUIDE §5.6a — can a client on the open internet reach this address?
///
/// Used to answer "does this node have a WAN address at all?" Agreement among
/// peers is necessary but NOT sufficient: if every peer observed us over a
/// private path, they agree precisely that we are unreachable from outside it.
///
/// ⚠ FAIL-CLOSED BY CONSTRUCTION: this returns false for anything it does not
/// positively recognise as globally routable. A new reserved range appearing in
/// a future RFC therefore demotes a node to Read rather than silently
/// qualifying it — the safe direction, since a wrongly-demoted node still
/// gossips, relays ticks and keeps children (§5.6a demotes, never disconnects).
///
/// ⚠ WHY THE RANGES ARE HAND-ROLLED — and what to delete when they need not be.
///
/// `Ipv4Addr::is_global()` answers this entire question in one call and would
/// replace the whole function. It is UNSTABLE (feature `ip`) and does not
/// compile — verified on rustc 1.93.1, 2026-08-26, not assumed. Same for
/// `is_shared()` (CGNAT 100.64/10), `is_reserved()` (240/4), and the IPv6
/// `is_unique_local()` / `is_unicast_link_local()`.
///
/// What IS stable and therefore NOT hand-rolled: `is_private`, `is_loopback`,
/// `is_link_local`, and `is_documentation` — the last is what rejects RFC 5737
/// (192.0.2/24, 198.51.100/24, 203.0.113/24), so those ranges are std's call,
/// not ours.
///
/// ⚠ WHEN `is_global()` STABILISES, DELETE THE HAND-ROLLED MASKS AND CALL IT.
/// Every mask below is a rule std already owns; keeping a second copy is RULE 1,
/// and a mask maintained by hand is one that eventually disagrees with the RFC.
fn addr_is_wan_routable(ip: &[u8; 16]) -> bool {
    let v6 = std::net::Ipv6Addr::from(*ip);
    match v6.to_ipv4_mapped() {
        Some(v4) => {
            let o = v4.octets();
            !(v4.is_private()          // RFC1918 10/8, 172.16/12, 192.168/16
                || v4.is_loopback()    // 127/8
                || v4.is_link_local()  // 169.254/16
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                // CGNAT 100.64.0.0/10 — the operator does not control the NAT,
                // so inbound is not deliverable. Reachable OUT is not reachable IN.
                || (o[0] == 100 && (64..128).contains(&o[1]))
                // 0.0.0.0/8 "this network", and 240/4 reserved.
                || o[0] == 0
                || o[0] >= 240)
        }
        None => {
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (seg[0] & 0xfe00) == 0xfc00   // fc00::/7 unique-local
                || (seg[0] & 0xffc0) == 0xfe80   // fe80::/10 link-local
                || (seg[0] == 0x2001 && seg[1] == 0x0db8)) // 2001:db8::/32 doc
        }
    }
}

fn ip_bytes(addr: &std::net::SocketAddr) -> [u8; 16] {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(v6) => v6.octets(),
    }
}

fn is_client_request(msg: &WireMessage) -> bool {
    matches!(
        msg,
        WireMessage::Register(..)
            | WireMessage::FactConfirmRequest(..)
            | WireMessage::OodsReadingRequest(..)
            | WireMessage::QueryTxidRequest(..)
            | WireMessage::RegisterChequeClaimRequest(..)
            | WireMessage::RecallRequest(..)
            | WireMessage::QueryWalletStateRequest(..)
            | WireMessage::PulseProofRequest(..)
            | WireMessage::JfpSecretRequest(..)
            | WireMessage::JfpSecretsRequest(..)
            | WireMessage::RegisterClaraRequest(..)
            | WireMessage::QueryValidatorEarningsRequest(..)
            | WireMessage::RegisterValidatorPoolRequest(..)
            | WireMessage::QueryValidatorPoolRequest(..)
            | WireMessage::FobClaimAttestationRequest(..)
            | WireMessage::RegisterVbcRequest(..)
    )
}

// Fork Settlement §9q (B2, 2026-09-30): `prelock_hal_verify` — the off-lock
// k3 verify + per-peer verify budget for a `HalAdvance` CONFLICT (the E3 arm)
// — was DELETED with that arm. `HalAdvance` is a tombstone (dropped unverified
// by `GossipEngine::process`, counted `haladvance_dropped`); a HAL re-anchor
// floods as `StateUpdate` with its leg. The off-lock pattern it established
// lives on in `prelock_directory_verify`, `prelock_ae_fork_bans` and
// `prelock_record_ae`.

/// KI#71 — route the §5.5 audit answers that `advertise_root` built to each
/// requester's mesh address (the requester is a TARDIS child; the answer is a
/// mesh message, never a reply on the request's socket).
fn push_audit_responses(
    core: &axiom_nabla::node::NablaNode,
    actions: Vec<axiom_nabla::tardis::TardisAction>,
    outbound: &mut Vec<(std::net::SocketAddr, WireMessage)>,
) {
    for action in actions {
        if let axiom_nabla::tardis::TardisAction::SendAuditResponse { response, target } = action {
            if let Some(peer) = core.mesh().and_then(|m| m.peer_by_id(&target)) {
                outbound.push((to_socket_addr(&peer.address), WireMessage::AuditResponse(response)));
            }
        }
    }
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
        outbound.push((envelope.peer, reject));
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
        WireMessage::Hello { node_id, external_port, downstream_count, nbc_bytes, txid_service, nbc_supporting_bytes, observed_peer_ip } => {
            // ── §5.6a-bis: COMPOSE, never adopt a claim ──
            // The peer told us only a PORT. Its address is what WE observed
            // on this connection, joined to that port. This is the whole
            // point: a node cannot put itself anywhere it is not, because the
            // IP half never comes from the node.
            let address = &from_socket_addr(std::net::SocketAddr::new(
                envelope.peer.ip(), *external_port));
            // ── NBC verification ── (carry the supporting chain so a citizen's
            // chain_depth>0 NBC verifies to a Nabla root — 2026-08-16 join fix)
            if let Err(reason) = state.verify_peer_nbc_with_supporting(nbc_bytes, nbc_supporting_bytes, node_id) {
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

            // ── GUIDE §5.6a — peer-observed addressing ──
            // Reached ONLY once the NBC above verified, so BOTH directions of
            // this exchange are attributable to an identity. Acting on an
            // unauthenticated peer's claim about our own address would be
            // unauthenticated input driving a consequential decision — RULE 3
            // shape 5, the KI#72 shape.
            //
            // (a) What WE observe of THEM — reported back on our next Hello so
            //     a NAT'd peer can learn its WAN address, which it cannot see
            //     from the inside.
            state.observed_sources.insert(*node_id, ip_bytes(&envelope.peer));
            // (b) What THEY observe of US — one attributable report about our
            //     own address.
            // ── THE EXEMPTION IS ON THE SELF SIDE, NOT THE OBSERVER SIDE ──
            // (CORRECTED 2026-08-26)
            //
            // A GENESIS node skips this check for itself, because its IP is
            // PUBLISHED IN THE SEED LIST — operator-curated and known to every
            // node before contact. It does not need peers to discover what is
            // already written down. Transitional: genesis retires as the mesh
            // grows, and with it this exemption.
            //
            // ⚠ WHAT THIS REPLACED, AND WHY IT WAS WRONG. Until today the test
            // here was `reporter_is_genesis` — a node DISCARDED any report made
            // BY a genesis peer, deserializing the sender's NBC to check
            // `chain_depth == 0`. That came from reading the 2026-08-20 ruling
            // ("If sees peer is a genesis, do not verify ip") as "ignore what
            // genesis tells me", when it reads at least as naturally as "do not
            // police the IP OF a genesis peer". The correction: *"It is
            // that genesis does not require peers to tell its IP as special
            // case, not node ignore genesis's advice."*
            //
            // The old justification was that our genesis fleet is co-located
            // (seven on one LAN + three remotes), so counting it makes a citizen
            // peering with both see a permanent split and demote forever. That
            // is a fact about THIS DEPLOYMENT, not the protocol
            // ([[feedback_assume_other_operators_not_our_deployment]]) — and the
            // "false positive" it feared is the TRUE ANSWER: a node reachable at
            // one address from the LAN and another from the WAN is genuinely not
            // consistently reachable, and Read is correct.
            //
            // MEASURED, 2026-08-26: under the old rule the Pi — whose peers are
            // ALL genesis — carried `address_reports: 0`. The check policing
            // self-asserted addresses was structurally blind to the one node
            // actually asserting a private VPN address, which sat write-eligible
            // for six days while logging ~10,000 failed sends to 172.20.0.42.
            //
            // A genesis peer's observation is now ordinary evidence: it is a
            // plain fact about a TCP connection that reached it.
            if let (Some(seen), false) = (observed_peer_ip, state.own_nbc_is_genesis) {
                state.my_addr_reports.insert(*node_id, *seen);
                // ── AGREEMENT IS NOT ENOUGH: THE ADDRESS MUST BE ROUTABLE ──
                // (design ruling, 2026-08-26: "Even address was agreed. If no wan
                // address it should still [be] sent to read only.")
                //
                // The original gate was `disputed = distinct.len() > 1` — it
                // asked only whether observers AGREED. But unanimity about an
                // RFC1918 address is unanimity that the node is UNREACHABLE:
                // every peer got there over a private path, and no client on
                // the open internet can follow them. A node with no WAN address
                // has nothing to serve clients WITH, so write-qualifying it
                // publishes a writer that public traffic can never reach.
                //
                // MEASURED, 2026-08-26: the Pi sat write-eligible with EIGHT
                // unanimous reports of 172.20.0.61 — a VPN address. Agreement
                // was total and the answer was still wrong.
                //
                // Two DISTINCT reasons to demote, kept distinguishable rather
                // than collapsed into one boolean (RULE 3 — an operator must be
                // able to tell WHY they are a reader):
                //   * disagreement  -> peers see different addresses
                //   * unroutable    -> peers agree, on an address the internet
                //                      cannot reach
                let distinct_now: std::collections::HashSet<&[u8; 16]> =
                    state.my_addr_reports.values().collect();
                let unroutable = distinct_now.len() == 1
                    && distinct_now.iter().next().is_some_and(|ip| !addr_is_wan_routable(ip));
                // UNANIMITY — never a majority. A farm node's peer set is
                // roughly 1 local + 8 external, so a majority vote discards the
                // lone local dissenter and the farm passes, getting WEAKER as
                // the farm scales. Any disagreement demotes (GUIDE §5.6a).
                let distinct: std::collections::HashSet<&[u8; 16]> =
                    state.my_addr_reports.values().collect();
                let disagreed = distinct.len() > 1;
                // EITHER condition demotes. `address_disputed` remains the ONE
                // predicate the write gate reads (`is_self_writer`), so no call
                // site has to learn a second rule — but the REASON is logged and
                // surfaced separately, because "peers disagree" and "peers agree
                // you are unreachable" need different operator responses.
                let disputed = disagreed || unroutable;
                let was = state.core.tardis().map(|t| t.address_disputed()).unwrap_or(false);
                if was != disputed {
                    let reason = if disagreed {
                        "DISAGREEMENT — peers report different source addresses"
                    } else if unroutable {
                        "NO WAN ADDRESS — peers agree, but on an address the \
                         internet cannot reach (private/loopback/link-local/CGNAT). \
                         Agreement that a node is unreachable is not qualification"
                    } else {
                        "routable and agreed"
                    };
                    warn!("[ADDR-{}] {} distinct source address(es) from {} peer(s) — {} — {}",
                          if disputed { "DEMOTE" } else { "OK" },
                          distinct.len(), state.my_addr_reports.len(), reason,
                          if disputed { "READ node; client writes REDIRECT (§5.6a)" }
                          else { "write-qualified" });
                }
                if let Some(t) = state.core.tardis_mut() {
                    t.set_address_disputed(disputed, state.my_addr_reports.len());
                }
                state.address_unroutable = unroutable;
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
                                state.lineage_ok = state.lineage_ok.saturating_add(1);
                                if tick_msg.number % 120 == 0 {
                                    log::debug!("[LINEAGE-OK] tick={} from={} gp={} gp_tick={} drift={}",
                                        tick_msg.number, hex::encode(&tick_msg.upstream_pk[..4]),
                                        hex::encode(&gp_pk[..4]), gp.number, drift);
                                }
                            } else {
                                state.lineage_reject = state.lineage_reject.saturating_add(1);
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
                        None => { state.lineage_skip = state.lineage_skip.saturating_add(1);
                            log::debug!("[LINEAGE-SKIP] tick={} gp={} not in verified NBCs yet",
                            tick_msg.number, hex::encode(&gp_pk[..4])); }
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
                        // KI#48 instrumentation. This used to be a bare
                        // `if let Some(peer)` — when the target could not be
                        // resolved in the mesh the approval was DROPPED SILENTLY.
                        // That matters because a parent's writer status is its
                        // count of children that approved last round: lose the
                        // approvals and the parent never reaches 2, so every
                        // child detaches with GrandpaTickMissing even though the
                        // attach itself succeeded. A drop here is invisible in
                        // every log we have — which is why the cause of the churn
                        // could not be seen.
                        match state.core.mesh().unwrap().peer_by_id(&target) {
                            Some(peer) => {
                                outbound.push((
                                    to_socket_addr(&peer.address),
                                    WireMessage::Approval(approval),
                                ));
                            }
                            None => {
                                warn!("[APPROVAL-UNSENT] cannot resolve upstream \
                                       {:02x}{:02x}… in mesh — approval DROPPED. Our \
                                       parent will not count us, and will lose writer \
                                       status through no fault of its own.",
                                    target[0], target[1]);
                            }
                        }
                    }
                    axiom_nabla::tardis::TardisAction::BroadcastRootHash { tick, root_hash, node_pk, signature } => {
                        // Anti-entropy root probe: send our root hash to ONE
                        // peer per tick, rotating through every peer in turn
                        // (AXIOM_DESIGN_NablaAntiEntropy.md §5.5) — replaces
                        // the old fixed `take(2)` that pinned the repair to
                        // a static two-edge subgraph. A root mismatch at the
                        // receiver triggers the bidirectional leaf-hash sync.
                        // Not re-forwarded on receive — originators probe direct.
                        // KI#71: `signature` was produced ONCE by
                        // `TardisNode::advertise_root` — never re-sign here.
                        let gossip_msg =
                            GossipMessage::TickHash { tick, root_hash, node_pk, signature };
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
                        state.note_recently_detached(parent, until);
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
            // ── ghost audit G16 ────────────────────────────────────────────
            // `--dev` implies `--skip-verify`, and this branch is what it
            // skips. That is NOT a performance shortcut: an accepted approval
            // sets `d1/d2_approved_this_tick`, which the tick loop's sliding
            // window feeds into YPX-003 writer qualification
            // ("approved-tick-this-interval"). So with `--dev` a node can be
            // qualified as a WRITER on approvals nobody authenticated.
            //
            // `--dev` is fatal in a release build UNLESS compiled with
            // `--features dev-mode` — which is exactly how this mesh is built
            // and run. So the check is OFF in every soak and every measurement
            // taken here. Counted and announced rather than silent: a reader
            // must never mistake a dev run for a verified one.
            if state.skip_verify {
                state.approvals_unverified = state.approvals_unverified.saturating_add(1);
            }
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
                paid_out,
                topped_up,
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
                        // KI#191 — the conservation terms are inside the signed
                        // payload, so a peer cannot forge the numbers JUDOON
                        // judges it by.
                        let payload = axiom_nabla::crypto::pool_sync_sign_payload(
                            pool.sign_tag(), *balance, *total_claims, *paid_out,
                            *topped_up, *tick, sender_node_id,
                            pool.bounded_fee_key(),
                        );
                        if !state.core.signer().verify(&pk, &payload, sender_sig) {
                            log::warn!(
                                "[POOLSYNC-DROP-BAD-SIG] sender_node_id={} sig verification failed — dropping + ban-score",
                                hex::encode(&sender_node_id[..8]),
                            );
                            return outbound;
                        }
                        // GUIDE §5.6c lever 5 — an AUTHENTICATED PoolSync for
                        // this kind has arrived and is about to be reconciled;
                        // the serve-gate opens once every serve-gate kind has.
                        if state.note_pool_synced(*pool) {
                            info!("[POOL-SYNC-GATE] every pool kind synced ({:?}) — \
                                   registrations now served (§5.6c lever 5)",
                                state.pool_synced_kind_names());
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
                        // counter below records the rate for diagnosis.
                        //
                        // RULE 0 marker (2026-08-07, ghost audit G8). That last
                        // sentence used to read "the counter below still records the
                        // rate" and THERE WAS NO COUNTER — the only trace was this
                        // `debug!`, and production runs at `info!`. So 100% loss of
                        // honest PoolSync and a perfectly healthy mesh produced the
                        // identical observation: silence. The comment described a
                        // diagnostic that did not exist, on the drop that hides a
                        // known-open bug. The counter is real now and on /status.
                        state.poolsync_drop_unverified =
                            state.poolsync_drop_unverified.saturating_add(1);
                        log::debug!(
                            "[POOLSYNC-DROP-UNVERIFIED] sender_node_id={} no resolvable NBC — dropping (total={})",
                            hex::encode(&sender_node_id[..8]),
                            state.poolsync_drop_unverified,
                        );
                        return outbound;
                    }
                }
            }

            if let GossipMessage::Alert { intermediate_emitter, .. } = gossip_msg {
                let sid = *intermediate_emitter;
                // ── ghost audit G4 ──────────────────────────────────────────
                // `sid` is the value the PACKET asserts, not a proven identity.
                // It used to be passed to `handle_alert` as the "TCP source",
                // so §5.6.4 step 1 compared it to itself and could never fail.
                //
                // The transport cannot prove a sender: `Envelope` carries only
                // a `SocketAddr`, there is no NBC handshake, and an inbound
                // connection's ephemeral source port never equals the peer's
                // listen address that `peer_id_from_addr` matches on. So we
                // pass `None` and `handle_alert` fails closed — recorded and
                // forwarded, never quarantine-activating. KI#72.
                // KI#72 — prove WHO forwarded this hop. The NBC is not on the
                // wire: we look the signer's Ed25519 key up in our OWN
                // `verified_nbcs` (warm from the KI#32 snapshot) and verify the
                // 64-byte `intermediate_sig`. Same pattern as ticks (KI#18),
                // audit responses (KI#19) and approvals (KI#20).
                //
                // A peer claiming to be someone else fails here: the signature
                // is checked against the key of the node it NAMES (§5.6.7 A6).
                // With this, §5.6.5's dual-uniqueness count is finally over
                // PROVEN identities and quarantine activation can be honoured.
                let verified_sender: Option<NodeId> = if state.skip_verify {
                    // --dev: no verification anywhere (see G16). Do NOT hand
                    // back a fake identity — that would re-open exactly the hole
                    // this closes. Stay fail-closed.
                    None
                } else if let GossipMessage::Alert {
                    alert_type, accused, evidence, origin_emitter,
                    intermediate_emitter, emitted_at_tick, intermediate_sig,
                } = gossip_msg {
                    let payload = axiom_nabla::crypto::pool_alert_sign_payload(
                        *alert_type as u8, accused, evidence,
                        origin_emitter, intermediate_emitter, *emitted_at_tick,
                    );
                    match state.verified_nbcs.get(intermediate_emitter)
                        .and_then(cc::nbc_ed25519_pk)
                    {
                        Some(pk) if state.core.signer()
                            .verify(&pk, &payload, intermediate_sig) => {
                            state.alert_identity_proven =
                                state.alert_identity_proven.saturating_add(1);
                            Some(*intermediate_emitter)
                        }
                        Some(_) => {
                            state.alert_identity_unproven =
                                state.alert_identity_unproven.saturating_add(1);
                            warn!("[ALERT-SIG-FAIL] claimed intermediate={} — its \
                                   NBC-bound key rejected the signature; treating \
                                   as unproven (KI#72)",
                                  hex::encode(&intermediate_emitter[..8]));
                            None
                        }
                        None => {
                            state.alert_identity_unproven =
                                state.alert_identity_unproven.saturating_add(1);
                            warn!("[ALERT-NBC-MISS] claimed intermediate={} not in \
                                   verified NBCs — cannot prove identity (KI#72)",
                                  hex::encode(&intermediate_emitter[..8]));
                            None
                        }
                    }
                } else {
                    None
                };
                // ── ghost audit G7 ──────────────────────────────────────────
                // This is the ONLY `is_peer_quarantined` call site, and it is
                // nested inside the Alert arm — so quarantine never blocked
                // "all messages" as documented; StateUpdate / PoolSync / Recall
                // / TickHash / ticks from a quarantined peer were processed and
                // written to the SMT. Worse, it is keyed on the attacker-chosen
                // `sid`, so a quarantined peer evaded it by naming someone else.
                // Keyed on a proven identity it would be a real filter; with
                // none available it is left explicitly inert rather than
                // reading as a control that works. KI#72.
                match verified_sender {
                    Some(proven) if state.core.is_peer_quarantined(&proven) => {
                        log::info!(
                            "[QUARANTINE-DROP] alert from quarantined peer {} — dropping",
                            hex::encode(&proven[..8]),
                        );
                        return outbound;
                    }
                    // GUIDE §5.6c lever 4 — the same gate ignores a
                    // PROBATIONARY peer's Alert: Sybil ban evidence from a
                    // flood of fresh certificates is withheld exactly like a
                    // quarantined peer's. Counted (RULE 3 §2).
                    Some(proven) if state.peer_nbc_probationary(&proven) => {
                        state.probation_alert_refusals =
                            state.probation_alert_refusals.saturating_add(1);
                        log::info!(
                            "[PROBATION-DROP] alert from probationary peer {} — withheld \
                             (§5.6c lever 4, total={})",
                            hex::encode(&proven[..8]), state.probation_alert_refusals,
                        );
                        return outbound;
                    }
                    _ => {}
                }
                let action = state.core.handle_alert(gossip_msg, verified_sender);
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
                            // KI#72: we become the intermediate for the next
                            // hop, so we must sign for OURSELVES. Forwarding the
                            // upstream's signature unchanged would fail at the
                            // next receiver (it verifies against the NAMED node's
                            // key), which is exactly the property that stops a
                            // forwarder impersonating anyone.
                            let fwd_payload = axiom_nabla::crypto::pool_alert_sign_payload(
                                *alert_type as u8, accused, evidence,
                                origin_emitter, &our_id, *emitted_at_tick,
                            );
                            let forwarded = GossipMessage::Alert {
                                alert_type: *alert_type,
                                accused: *accused,
                                evidence: evidence.clone(),
                                origin_emitter: *origin_emitter,
                                intermediate_emitter: our_id,
                                emitted_at_tick: *emitted_at_tick,
                                intermediate_sig: state.core.signer().sign(&fwd_payload),
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

            // ForkSettlement §2.4 [R13]: origin records stamp THIS node's wall
            // clock (`virtual_secs`, sampled once per tick-loop iteration).
            let now_secs = state.virtual_secs;
            let action = state.core.handle_gossip(gossip_msg, now_secs);

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
                    // YP §8.4.3 JFP vote-secret propagation: store on THIS node
                    // so `JfpSecretsRequest` is answerable mesh-wide, mirroring
                    // the registration handler (`jfp_secret_core`) — same
                    // 100-per-DWP-wallet cap, same dedupe. The engine already
                    // deduped the message; re-forward happens in the shared
                    // fan-out below.
                    if let GossipMessage::JfpSecret { dwp_wallet_id, secret } = &msg {
                        let secrets = state.jfp_secrets.entry(*dwp_wallet_id).or_default();
                        if secrets.len() < 100 && !secrets.contains(secret) {
                            secrets.push(*secret);
                        }
                    }

                    if let GossipMessage::Recall { txid, committed: true, .. } = &msg {
                        state.garbage_state_chain.insert(state.virtual_secs, txid);
                        state.persist_garbage_chain();
                    }

                    // FOB (§4/§5) — a mover committee's batched tranche statement.
                    // Verify each signer's crypto (Core `verify_oods_attestation`
                    // proves an NBC-blessed identity + its attested oods_size /
                    // baseline; the statement sig proves it authored THIS
                    // statement), then judge PURELY (eligibility floor + committee
                    // + EXACT math over the PINNED balance_used — the amount is
                    // Core's `compute_fob_tranche`, re-verified here on EVERY node
                    // incl. bloom, RULE 5). On Accept, adopt the pre-verified
                    // credits into the local two-state pools (a DEBIT against the
                    // convergent accumulator; no mint). On Quarantine, count +
                    // log and do NOT apply. (Relay-suppression + JUDOON
                    // signer-probation are separate hardening — BoundedPools §4.)
                    if let GossipMessage::FobTranche { epoch_id, is_dev, entries, movers } = &msg {
                        let payload =
                            axiom_nabla::fob::tranche_statement_payload(*epoch_id, *is_dev, entries);
                        // (1) Crypto-verify each incoming signer: Core
                        //     verify_oods_attestation (NBC-blessed identity +
                        //     attested oods_size/baseline) + the statement sig
                        //     over the canonical payload. A single bad sig voids
                        //     this partial (an honest mover never emits one).
                        let mut incoming: Vec<axiom_nabla::fob::VerifiedMover> =
                            Vec::with_capacity(movers.len());
                        let mut crypto_ok = true;
                        for m in movers {
                            let att_ok =
                                axiom_core_logic::validation::verify_oods_attestation(&m.att)
                                    .is_ok();
                            let sig_ok = att_ok
                                && state.core.signer().verify(
                                    &m.att.nabla_node_pk,
                                    &payload,
                                    &m.statement_sig,
                                );
                            if !sig_ok {
                                crypto_ok = false;
                                break;
                            }
                            incoming.push(axiom_nabla::fob::VerifiedMover {
                                node_pk: m.att.nabla_node_pk,
                                oods_size: m.att.oods_size as u64,
                                baseline: m.att.baseline_size as u64,
                            });
                        }
                        if !crypto_ok {
                            state.fob_tranches_rejected += 1;
                            warn!(
                                "[FOB] tranche epoch={} partial REJECTED — mover crypto invalid",
                                epoch_id
                            );
                        } else {
                            // (2) Aggregate distinct movers toward a full committee
                            //     (§3 no-coordination). Judge ONCE at committee size.
                            let (ready, j_entries, j_movers) = {
                                let pend = state
                                    .fob_pending
                                    .entry(payload)
                                    .or_insert_with(|| FobPendingStatement {
                                        epoch_id: *epoch_id,
                                        entries: entries.clone(),
                                        movers: Vec::new(),
                                        resolved: false,
                                    });
                                for vm in incoming {
                                    if !pend.movers.iter().any(|e| e.node_pk == vm.node_pk) {
                                        pend.movers.push(vm);
                                    }
                                }
                                if !pend.resolved
                                    && pend.movers.len()
                                        >= axiom_nabla::fob::FOB_COMMITTEE_SIZE
                                {
                                    pend.resolved = true;
                                    (true, pend.entries.clone(), pend.movers.clone())
                                } else {
                                    (false, Vec::new(), Vec::new())
                                }
                            };
                            if ready {
                                // This node's mover pk (for the roster + the
                                // mover check below), computed once.
                                let my_pk_opt =
                                    state.build_oods_attestation().map(|a| a.nabla_node_pk);
                                // §3 committee-match roster = the RECORDING mover
                                // set (only recording nodes hold the accumulator,
                                // so only they author). Per-mover §5 eligibility is
                                // still enforced inside judge.
                                let roster: Vec<[u8; 32]> = match my_pk_opt {
                                    Some(pk) => state.fob_recording_roster(pk),
                                    None => Vec::new(),
                                };
                                let is_recording = state.core.smt().txid_mode()
                                    == axiom_nabla::bloom::TxidServiceMode::Hashmap;
                                let skew_tol = if is_recording {
                                    axiom_nabla::fob::FOB_SKEW_ALERT_TOLERANCE_ATOMS
                                } else {
                                    u64::MAX
                                };
                                // Same settled watermark the author used — the
                                // floor of the epoch two back `(epoch-2)*epoch_len`
                                // — so the judge's accumulator view matches what
                                // the committee tranched (§3 convergence).
                                let watermark = (*epoch_id).saturating_sub(2)
                                    .saturating_mul(axiom_nabla::constants::fob_epoch_span_secs(*is_dev)); // KI#165: epoch × VALUE-span = a tick VALUE
                                let verdict = axiom_nabla::fob::judge_tranche_statement(
                                    *epoch_id,
                                    &j_entries,
                                    &j_movers,
                                    &roster,
                                    |pid| state.core.fob_available(pid, *is_dev, watermark),
                                    skew_tol,
                                );
                                match verdict {
                                    axiom_nabla::fob::StatementVerdict::Accept {
                                        credits,
                                        alerted,
                                    } => {
                                        // Store the verified credits so the
                                        // PoolSync BoundedFee arm can authorise
                                        // the matching increases (§7). The pool
                                        // BALANCE propagates via PoolSync — NOT
                                        // applied directly here — EXCEPT on the
                                        // committee MOVERS, which originate the
                                        // movement: they apply their own pools
                                        // and advertise via PoolSync so every
                                        // non-mover adopts through the arm
                                        // (§8.1 movement-only).
                                        // Key the credits by (vid, is_dev) — the
                                        // class is the statement's, applied to
                                        // every entry (§10.2a).
                                        let keyed: Vec<(([u8; 32], bool), u64)> = credits
                                            .iter()
                                            .map(|(v, a)| ((*v, *is_dev), *a))
                                            .collect();
                                        state.core.fob_store_credits(*epoch_id, &keyed);
                                        state.fob_tranches_applied += 1;

                                        // Am I a committee mover this epoch?
                                        // (same RECORDING roster the authoring
                                        // hook uses — only recording nodes author)
                                        let is_mover = match my_pk_opt {
                                            Some(my_pk) => axiom_nabla::fob::rank_committee(
                                                &roster,
                                                *epoch_id,
                                                axiom_nabla::fob::FOB_COMMITTEE_SIZE,
                                            )
                                            .contains(&my_pk),
                                            None => false,
                                        };
                                        if is_mover {
                                            let mut moved: Vec<[u8; 32]> = Vec::new();
                                            for (pool_id, amount) in &credits {
                                                // KI#84 — epoch-keyed PLUS fact
                                                // (idempotent per (epoch,vid,dev)).
                                                if state.core.fob_apply_tranche_epoch(
                                                    *epoch_id, *pool_id, *is_dev, *amount,
                                                ) {
                                                    moved.push(*pool_id);
                                                }
                                            }
                                            for vid in &moved {
                                                let sync = state.core.pool_sync_message(
                                                    axiom_nabla::types::PoolKind::BoundedFee(
                                                        *vid, *is_dev,
                                                    ),
                                                );
                                                let wire = WireMessage::Gossip(sync);
                                                if let Some(mesh) = state.core.mesh() {
                                                    for peer in mesh.active_peers() {
                                                        outbound.push((
                                                            to_socket_addr(&peer.address),
                                                            wire.clone(),
                                                        ));
                                                    }
                                                }
                                            }
                                        }
                                        info!(
                                            "[FOB] tranche epoch={} ACCEPTED ({} pools, \
                                             mover={}{})",
                                            epoch_id,
                                            credits.len(),
                                            is_mover,
                                            if alerted { ", alert" } else { "" }
                                        );
                                    }
                                    axiom_nabla::fob::StatementVerdict::Quarantine(v) => {
                                        state.fob_tranches_rejected += 1;
                                        warn!(
                                            "[FOB] tranche epoch={} QUARANTINE {:?} ({} signers)",
                                            epoch_id,
                                            v,
                                            j_movers.len()
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // C3: TickHash partition detection — compare root hashes.
                    // On mismatch: enter quarantine AND trigger RangeSyncRequest
                    // to pull the peer's divergent wallet states. Without the pull,
                    // anti-entropy detects the partition but never resolves it.
                    if let GossipMessage::TickHash { tick, root_hash, node_pk, signature } = &msg {
                        // AUTHENTICATE BEFORE USE. `node_pk` is a claim; without
                        // this check any peer could emit a TickHash naming our
                        // upstream with a bogus root, and the §5.5 audit would
                        // then detach us from a healthy parent and cascade an
                        // alert that detaches its whole subtree — targeted
                        // topology grief from one forged packet. Same
                        // NBC-anchored binding the tick and alert paths use
                        // (§5.5.1 point 8, applied to the input that GENERATES
                        // those alerts).
                        let advertiser_key = state
                            .verified_nbcs
                            .get(node_pk)
                            .and_then(cc::nbc_ed25519_pk);
                        let sig_ok = match &advertiser_key {
                            Some(k) => state.core.signer().verify(
                                k,
                                &axiom_nabla::crypto::tickhash_sign_payload(*tick, root_hash, node_pk),
                                signature,
                            ),
                            // Advertiser not yet a verified NBC — cannot
                            // authenticate, so this MUST NOT become audit
                            // evidence. Bootstrap timing, not an accusation.
                            None => false,
                        };
                        if sig_ok {
                            state.tickhash_verified = state.tickhash_verified.saturating_add(1);
                        } else {
                            state.tickhash_unverified =
                                state.tickhash_unverified.saturating_add(1);
                            log::debug!(
                                "[TICKHASH-UNVERIFIED] advertiser={} tick={} — not recorded as audit evidence",
                                hex::encode(&node_pk[..4]),
                                tick,
                            );
                        }
                        let our_root = state.core.smt().root_hash();
                        // KI#48: record EVERY advertisement, matching or not —
                        // the §5.5 audit self-consistency check compares the
                        // upstream's audit answer against what it advertised
                        // here, so advertisements equal to our own root must
                        // be recorded too. Quarantine/AE stay mismatch-gated.
                        let fork = match (sig_ok, state.core.tardis_mut()) {
                            (true, Some(tardis)) => tardis.record_branch_root_hash(
                                *tick,
                                *node_pk,
                                *root_hash,
                                signature.clone(),
                            ),
                            _ => false,
                        };
                        if our_root != *root_hash {
                            if fork {
                                state.ae_forks_window = state.ae_forks_window.saturating_add(1);
                                // ForkSettlement §9r-E4: a root mismatch is a VIEW
                                // divergence — it is logged, counted and reconciled by
                                // AE below, and it holds NOTHING (the §32 quarantine it
                                // used to enter is deleted, D-E4-1).
                                warn!("§32 FORK DETECTED at tick {}: our root {:02x}{:02x}... != peer {:02x}{:02x}... \
                                       (root view divergence — holds nothing; AE reconciles)",
                                    tick, our_root[0], our_root[1], root_hash[0], root_hash[1]);
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

                    // RULE 0 §4 (ForkSettlement §9r-E4, 2026-10-02): the §32 SCAN that
                    // stood here (`detect_forked_wallets` on a forwarded StateUpdate →
                    // `handle_fork_evidence` → Frozen + TaintAlert) was DELETED. It
                    // ran AFTER `handle_gossip` had made the update the head, so it
                    // compared the head with itself and never fired (a ghost). Forks:
                    // A1 (`ban::apply_fork_verdict`); downstream: A5 (`provenance.rs`).

                    // YPX-009: Record pulse delivery for mesh scoring.
                    if let GossipMessage::PulseProof { validator_pk, epoch, .. } = &msg {
                        if let Some(mesh) = state.core.mesh_mut() {
                            mesh.record_pulse_delivery(validator_pk, *epoch);
                        }
                    }

                    // TickHash: don't re-forward — originators send directly.
                    // Other gossip (StateUpdate, an adopted ForkBan, etc.): full
                    // fan-out. (A retired
                    // KI#222 `BanAlert` never gets here — the engine drops it.)
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
                // `GossipAction::BanDetected` (forward + `SeqForkBan` flood + WAL
                // `Ban`) was DELETED 2026-09-30 (Fork Settlement §9o [R56], W2):
                // its only origin, check-3, was retired as a ban source (KI#235).
                // Every verdict is an A1 `Fork` claim, WAL-logged by the lib drain
                // (`drain_fork_side_effects`) and fanned out from
                // `take_pending_fork_floods` — ONE emission path.
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
            // KI#71 (option A, 2026-10-01): QUEUED, not answered live. The answer
            // is built at our next root-advertisement instant
            // (`TardisNode::advertise_root`: process_tick step 9, or the tick
            // loop's Step 1b for a self-originating node) from the SAME SMT
            // borrow that samples the root we sign for that tick. A live answer
            // here sampled the SMT at a later instant than our advertisement
            // under the same tick label, so an honest busy writer contradicted
            // its own gossip and was detached (YPX-003 §1.3.5).
            state.core.queue_audit_request(req);
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

            // ── VERIFY THE ACCUSATION BEFORE ACTING ON IT ──
            // The alert signature above proves only WHO accused. §5.5.1 had a
            // receiver whose upstream was named run flag_questionable itself —
            // detaching a working parent on the reporter's word alone. The
            // suspect's own signed statements are now carried in `evidence`, so
            // the receiver can check the accusation instead of trusting it.
            //
            // An alert with no evidence, or evidence that does not prove the
            // claim, MUST NOT detach anyone. It still cascades: a warning that
            // cannot be verified is still worth propagating to nodes that CAN
            // audit the suspect themselves.
            let proven = match (&alert.evidence, state.verified_nbcs.get(&alert.suspect_pk)) {
                (Some(ev), Some(nbc)) => match cc::nbc_ed25519_pk(nbc) {
                    Some(k) => axiom_nabla::crypto::verify_questionable_evidence(
                        ev,
                        &alert.suspect_pk,
                        &k,
                        &|key: &[u8], msg: &[u8], sig: &[u8]| {
                            state.core.signer().verify(key, msg, sig)
                        },
                    ),
                    None => None,
                },
                _ => None,
            };
            if proven.is_none() && state.core.tardis().map(|t| t.upstream() == Some(&alert.suspect_pk)).unwrap_or(false) {
                warn!("[ALERT-UNPROVEN] suspect={} reporter={} tick={} names OUR upstream but carries no proof \
                       (evidence={}) — NOT detaching; cascading only",
                    hex::encode(&alert.suspect_pk[..8]),
                    hex::encode(&alert.reporter_pk[..8]),
                    alert.tick,
                    alert.evidence.is_some());
                state.alert_unproven = state.alert_unproven.saturating_add(1);
            } else if let Some(why) = proven {
                state.alert_proven = state.alert_proven.saturating_add(1);
                warn!("[ALERT-PROVEN] suspect={} reporter={} tick={} reason={} — accusation verified against the suspect's own signatures",
                    hex::encode(&alert.suspect_pk[..8]),
                    hex::encode(&alert.reporter_pk[..8]),
                    alert.tick, why);
            }
            let alert = &{
                let mut a = alert.clone();
                if proven.is_none() { a.evidence = None; }
                a
            };

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
                outbound.push((envelope.peer, redirect));
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
                    outbound.push((envelope.peer, reject));
                    return outbound;
                }
            }

            // KI#42 serve-gate: refuse rather than answer from an empty view.
            //
            // Until a Bootstrap StatePull lands, `consumed_state_bloom` is empty,
            // so the A12 anti-rollback check inside `register` would pass ANY
            // rolled-back state — the node is not lying, it simply knows nothing,
            // but the client cannot tell those apart. Reply `not_ready_syncing`
            // and hand back `known_peers` so the client immediately retries against
            // an armed node; this is a liveness cost measured in seconds at
            // startup, versus a silent hole in the rollback defence.
            //
            // GUIDE §5.6c lever 5 — ADDITIONALLY, the node must have applied an
            // authenticated PoolSync for every serve-gate pool kind ("WAL/
            // PoolSync up to date"): a node whose pool view is incomplete is
            // not lying either, but it would register claims against a pool
            // state it has not seen. Same reply, same known_peers hand-off.
            if !state.anti_rollback_armed || !state.pool_sync_gate_open() {
                if !state.anti_rollback_armed {
                    warn!("[SERVE-GATE] registration refused: node not yet re-armed \
                           (no Bootstrap StatePull completed) — wallet {:02x}{:02x}...",
                        reg.wallet_id[0], reg.wallet_id[1]);
                } else {
                    warn!("[SERVE-GATE] registration refused: pool view incomplete \
                           ({}/{} pool kinds synced: {:?}, §5.6c lever 5) — wallet {:02x}{:02x}...",
                        state.pool_synced_kind_names().len(), PoolKind::SERVE_GATE_KINDS.len(),
                        state.pool_synced_kind_names(), reg.wallet_id[0], reg.wallet_id[1]);
                }
                let reject = WireMessage::RegisterRejected {
                    wallet_id: reg.wallet_id,
                    reason: "not_ready_syncing".into(),
                    known_peers,
                };
                outbound.push((envelope.peer, reject));
                return outbound;
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
                outbound.push((envelope.peer, reject));
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
                    outbound.push((envelope.peer, reject));
                    return outbound;
                }
            }

            // ── GAP-14: Writer routing redirect (KI#69) ──
            // READERs cannot process registrations. Only a write-qualified node
            // may adjudicate a registration against its SMT head.
            //
            // This was three nested `if let`s with NO else, falling through to
            // `state.core.register()`. Any failure — orphaned, writer missing from
            // the peer table, no tardis — silently turned a READER into an
            // adjudicator, which is exactly what this block's comment forbids. An
            // orphan then rejected a CORRECT wallet with StateMismatch computed
            // against its own stale head, wedging the wallet permanently (KI#68)
            // and forcing a burn (KI#67). Traced end-to-end in KI#69.
            //
            // Now exhaustive: every non-writer path returns. Falling through to
            // register is reachable ONLY via IAmWriter.
            match state.core.tardis().map(|t| t.writer_routing()) {
                // Write-qualified — fall through and record the registration.
                Some(axiom_nabla::tardis::WriterRouting::IAmWriter) => {}

                Some(axiom_nabla::tardis::WriterRouting::RedirectTo(parent_id)) => {
                    // Point the sender at our parent. If the parent is not in our
                    // peer table we still MUST NOT adjudicate — redirect with the
                    // peers we do know and let the sender pick another node.
                    let writer_peer = state.core.mesh()
                        .and_then(|m| m.peer_by_id(&parent_id))
                        .map(|p| NablaClientPeer::from_peer_info(p, state.core.current_tick()));
                    info!("READER node — redirecting registration to writer {:02x}{:02x}... (known={})",
                        parent_id[0], parent_id[1], writer_peer.is_some());
                    let redirect = WireMessage::RegisterRejected {
                        wallet_id: reg.wallet_id,
                        reason: "reader_redirect".into(),
                        known_peers: {
                            let mut peers = known_peers.clone();
                            // Ensure the writer is first in the peer list
                            if let Some(wp) = writer_peer {
                                peers.insert(0, wp);
                            }
                            peers.truncate(20);
                            peers
                        },
                    };
                    outbound.push((envelope.peer, redirect));
                    return outbound;
                }

                // Orphan, or no TARDIS at all. NO AUTHORITY — refuse.
                //
                // Reuses the existing `reader_redirect` reason deliberately: the
                // SDK already treats it as "try another node" and does NOT set
                // needs_resync, whereas a StateMismatch is recorded as a real
                // divergence. That distinction is the whole point, and it means
                // no new wire variant (bincode is positional) and no SDK change.
                Some(axiom_nabla::tardis::WriterRouting::NoWriterKnown) | None => {
                    warn!("ORPHAN/no-TARDIS node — REFUSING registration for {:02x}{:02x}... \
                           (no write authority; head may be stale — KI#69)",
                        reg.wallet_id[0], reg.wallet_id[1]);
                    let refuse = WireMessage::RegisterRejected {
                        wallet_id: reg.wallet_id,
                        reason: "reader_redirect".into(),
                        known_peers: known_peers.clone(),
                    };
                    outbound.push((envelope.peer, refuse));
                    return outbound;
                }
            }

            let _reg_t0 = std::time::Instant::now();
            // §10.0 FOB fee-claim verify #1 (BEFORE the register commits): the
            // claim registration must match this node's OWN pool view exactly —
            // full sweep only. An empty/mismatched pool = already-swept replay
            // or divergence → REFUSE the whole register (the consume-once leg).
            // Contribution emission claim (design §5 rule 1): the writer
            // RECOMPUTES this epoch's share from its own counter and refuses a
            // mismatch or a second claim by the identity — before the register
            // commits, so a refused claim can never redeem (CL5 needs the txid
            // attestation, KI#144).
            if let Some(att) = reg.fob_claim.as_ref().filter(|a| axiom_core_logic::types::is_emission_pool(a.pool)) {
                let att_ok = axiom_core_logic::validation::verify_fob_claim_attestation(att).is_ok();
                let check = state.core.emission().check_claim(att.pool, att.validator_id, att.amount);
                if !att_ok || check.is_err() {
                    warn!("[EMISSION-CLAIM] register REFUSED — att_ok={} pool={} amount={} why={:?} (verify #1)",
                        att_ok, att.pool, att.amount, check.err());
                    let reply = WireMessage::RegisterRejected {
                        wallet_id: reg.wallet_id,
                        reason: format!("emission claim verify #1 failed: att_ok={} {}", att_ok, check.err().unwrap_or("")),
                        known_peers: Vec::new(),
                    };
                    outbound.push((envelope.peer, reply));
                    return outbound;
                }
            }
            if let Some(att) = reg.fob_claim.as_ref().filter(|a| !axiom_core_logic::types::is_emission_pool(a.pool)) {
                let pool = state.core.fob_pool_balance(&att.validator_id, att.is_dev);
                let att_ok = axiom_core_logic::validation::verify_fob_claim_attestation(att).is_ok();
                // OWNERSHIP defense-in-depth (design ruling 2026-08-11 — "this touches
                // money, multiple layers"): Core CL2 pins tx.sender ==
                // att.linked_wallet_id, but Core TRUSTS att.linked_wallet_id, so
                // a malicious issuer could forge it. If THIS node holds the
                // SPHINCS+-verified pool linkage (registered via
                // RegisterValidatorPoolRequest), the attestation's claimant MUST
                // match it — catching a forged owner at every honest recorder.
                // A node without the linkage relies on Core CL2 + the k=3
                // witnesses (fail-safe, not fail-open here: mismatch REFUSES).
                let owner_ok = match state.validator_pool.get(&att.validator_id) {
                    Some((linked, _, _)) => linked == att.linked_wallet_id,
                    None => true, // no local linkage to check against — Core enforces
                };
                if !att_ok || pool == 0 || pool != att.amount || !owner_ok {
                    warn!(
                        "[FOB-CLAIM] register REFUSED — att_ok={} pool={} att.amount={} owner_ok={} (verify #1)",
                        att_ok, pool, att.amount, owner_ok,
                    );
                    let reply = WireMessage::RegisterRejected {
                        wallet_id: reg.wallet_id,
                        reason: format!(
                            "FOB claim verify #1 failed: pool={} att={} att_ok={} owner_ok={}",
                            pool, att.amount, att_ok, owner_ok,
                        ),
                        known_peers: Vec::new(),
                    };
                    outbound.push((envelope.peer, reply));
                    return outbound;
                }
            }
            let now_secs = state.virtual_secs; // [R13] origin record first_seen_secs
            let _reg_result = state.core.register(reg, deed_tx, now_secs);
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
                    // §10.0 FOB fee-claim: the register committed — SWEEP the
                    // pool (consume-once), record the claim (verify #2 keys off
                    // it at cheque-claim), and advertise balance 0 via PoolSync
                    // so every peer's AdoptWithdrawal converges the sweep.
                    if let Some(att) = reg.fob_claim.as_ref().filter(|a| axiom_core_logic::types::is_emission_pool(a.pool)) {
                        let out = state.core.emission_record_claim(att.pool, att.validator_id, att.amount);
                        info!("[EMISSION-CLAIM] pool={} identity={:02x}{:02x} amount={} -> {:?}",
                            att.pool, att.validator_id[0], att.validator_id[1], att.amount, out);
                    }
                    if let Some(att) = reg.fob_claim.as_ref().filter(|a| !axiom_core_logic::types::is_emission_pool(a.pool)) {
                        // KI#84 — the sweep is a MINUS fact keyed by the claim
                        // tx_hash. `fob_record_claim` derives balance→0 and is
                        // idempotent; the fact replicates via ledger AE so a
                        // node that missed this register still sweeps.
                        let swept = state.core.fob_pool_balance(&att.validator_id, att.is_dev);
                        state.core.fob_record_claim(reg.tx_hash, att.validator_id, att.is_dev, swept);
                        info!(
                            "[FOB-CLAIM] swept pool vid={:02x}{:02x} class={} amount={} tx={:02x}{:02x}",
                            att.validator_id[0], att.validator_id[1],
                            if att.is_dev { "dev" } else { "real" },
                            swept, reg.tx_hash[0], reg.tx_hash[1],
                        );
                        let sync = state.core.pool_sync_message(
                            axiom_nabla::types::PoolKind::BoundedFee(att.validator_id, att.is_dev),
                        );
                        let gossip = WireMessage::Gossip(sync);
                        let targets = state.core.mesh().map(|m| m.forward_targets(&state.node_id)).unwrap_or_default();
                        for target_id in targets {
                            if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target_id) {
                                outbound.push((to_socket_addr(&peer.address), gossip.clone()));
                            }
                        }
                    }
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
                    // Fork Settlement W7d (§9k rulings 1 + 3) — the DERIVED
                    // provenance of the registrant's new state, read after the
                    // register's drain: a held redeem/send is ACCEPTED and
                    // MARKED here (never refused). Covers the 5d retry too
                    // (it returns its ack through this same arm).
                    ack.provenance = state.core.provenance_view(&reg.client_pk, &reg.new_state);
                    let ack_msg = WireMessage::RegisterAck(ack);
                    // KI#63 — INFO, not debug. Rejections are `log::warn!` and the
                    // env runs at INFO, so with this at debug the nabla logs contain
                    // ONLY failures: no accept/reject rate can be computed from them,
                    // and any "% rejected" derived from them is 100% BY CONSTRUCTION.
                    // That trap cost a full investigation. An ACCEPTED register is the
                    // denominator; it must be visible at the level the env runs at.
                    log::info!(
                        "[nabla register] ACCEPTED wallet={} old={} new={} (peer={}) — reg_count={}",
                        hex::encode(&reg.wallet_id[..4]),
                        hex::encode(&reg.old_state[..4]),
                        hex::encode(&reg.new_state[..4]),
                        envelope.peer, state.registration_count,
                    );
                    // KI#92: the Ack is RETURNED, not written here under the node
                    // lock — `dispatch_outbound` writes it on the request's own
                    // connection after the lock is released (state is committed
                    // first, acked after: the same commit-then-ack order as before).
                    // A failed write is counted (`transport_send_failures_per_peer`)
                    // and logged `[E_NABLA_TRANSPORT_SEND_FAILED]` there.
                    outbound.push((envelope.peer, ack_msg));
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
                            // YPX-025 A2 — the COMMIT carries no attestation; a node
                            // applies it only where it already holds the VERIFIED
                            // reservation marker (GossipEngine::process).
                            attestation: None,
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
                        // Validator-join subsidy pools — gossiped so a joining
                        // candidate converges on the true remaining slots
                        // instead of trusting its own local file.
                        let bootstrap_gossip =
                            WireMessage::Gossip(state.core.pool_sync_message(PoolKind::Bootstrap));
                        let foundation_gossip = WireMessage::Gossip(
                            state.core.pool_sync_message(PoolKind::FoundationBootstrap));
                        // Contribution emission pools ride the same fan-out.
                        let em_v_gossip = WireMessage::Gossip(
                            state.core.pool_sync_message(PoolKind::EmissionValidators));
                        let em_n_gossip = WireMessage::Gossip(
                            state.core.pool_sync_message(PoolKind::EmissionNabla));
                        for target_id in state.core.mesh().unwrap().forward_targets(&state.node_id) {
                            if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&target_id) {
                                outbound.push((to_socket_addr(&peer.address), airdrop_gossip.clone()));
                                outbound.push((to_socket_addr(&peer.address), dev_gossip.clone()));
                                outbound.push((to_socket_addr(&peer.address), deed_gossip.clone()));
                                outbound.push((to_socket_addr(&peer.address), dev_deed_gossip.clone()));
                                outbound.push((to_socket_addr(&peer.address), bootstrap_gossip.clone()));
                                outbound.push((to_socket_addr(&peer.address), foundation_gossip.clone()));
                                outbound.push((to_socket_addr(&peer.address), em_v_gossip.clone()));
                                outbound.push((to_socket_addr(&peer.address), em_n_gossip.clone()));
                            }
                        }
                    }
                }
                Err(e) => {
                    use axiom_errors::error_code as ec;
                    use axiom_nabla::types::NablaError;
                    // YPX-025 ATRAXI (A2, KI#205): the register door refused a
                    // redeem of a committed-recalled txid. Record the HOLD on the
                    // (wallet, state) so it is tracked and observable (/status).
                    // The refusal itself is already done inside process_registration;
                    // this makes ATRAXI's index the running record of it. Idempotent,
                    // so a retried refusal does not double-count.
                    if matches!(e, NablaError::RedeemAfterRecallCommitted) {
                        let tick = state.core.current_tick();
                        let opened = state.atraxi.open(
                            (reg.wallet_id, reg.new_state),
                            axiom_nabla::atraxi::AtraxiClaimKind::RecalledTxidRedeem { txid: reg.tx_hash },
                            tick,
                        );
                        state.atraxi.note_held_refusal();
                        if opened {
                            warn!("[ATRAXI] A2 hold opened wallet={:02x}{:02x} txid={:02x}{:02x} \
                                   (KI#205 recalled-txid redeem refused; scar stays, no ban)",
                                reg.wallet_id[0], reg.wallet_id[1], reg.tx_hash[0], reg.tx_hash[1]);
                        }
                    }
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
                        // ForkSettlement [R17] door step 5b′ — name WHICH binding
                        // broke so a refused client (and a soak log) can tell a
                        // tampered preimage from a missing witness quorum.
                        NablaError::LegUnverifiable(reason) => format!(
                            "{}|reason={}|{}",
                            ec::E_NABLA_LEG_UNVERIFIABLE, reason, e,
                        ),
                        // KI#224 door step 5b⁗ — RETRYABLE: the SDK walk moves
                        // on to the next Nabla (this node's directory may still
                        // be filling) instead of counting a hard failure.
                        NablaError::WitnessNotInDirectory(pk) => format!(
                            "{}|key={}|{}",
                            ec::E_NABLA_WITNESS_NOT_IN_DIRECTORY, hex::encode(pk), e,
                        ),
                        _ => format!("{}", e),
                    };
                    warn!("Registration rejected for {:02x}{:02x}...: {}",
                        reg.wallet_id[0], reg.wallet_id[1], reason);
                    let reject = WireMessage::RegisterRejected {
                        wallet_id: reg.wallet_id,
                        reason: reason.clone(),
                        known_peers,
                    };
                    // KI#92: returned, written off-lock by `dispatch_outbound`.
                    eprintln!(
                        "[nabla register] Rejected ({}) — reply queued (peer={})",
                        reason,
                        envelope.peer,
                    );
                    outbound.push((envelope.peer, reject));
                }
            }
        }

        WireMessage::Query { wallet_id } => {
            // YPX-002 §4.3 cross-branch grouping key: the responding node's
            // NBC issuer pk, so the receiver can group its known Nablas into
            // branches and pick `(sticky + 2 cross-branch random)` per §4.6
            // step 2.
            //
            // G18: this is passed IN so it is covered by the response
            // signature. It used to be assigned AFTER `query()` had already
            // signed, which left the signature over an empty issuer while the
            // wire carried a real one — and the comment here claimed the field
            // was "NOT covered by the response signature" while `types.rs`
            // claimed the opposite and `response_sign_payload` hashed it.
            let mut response =
                state.core.query_with_issuer(wallet_id, state.nbc_issuer_pk.clone());

            // Role (§25.5.4) — INFORMATIONAL, unsigned: no reader of this
            // response gates on it. KI#247 (owner ruling 2026-10-02): the
            // separate `AXIOM_NABLA_ROLE` signature this arm used to add had
            // signers and NO verifier anywhere (a RULE 3 ghost) and was
            // DELETED — signer, builder and wire field.
            let role_byte: u8 = if state.reader_only {
                0 // reader
            } else if state.core.tardis().map(|t| t.is_self_writer()).unwrap_or(false) {
                1 // writer
            } else {
                0 // reader
            };
            response.role = role_byte;

            let reply_msg = WireMessage::QueryResponse(response);
            // Reply to the request's own connection: `dispatch_outbound` writes an
            // `envelope.peer` entry on the inbound socket OFF the node lock
            // (KI#92), or dials it when there is no inbound socket.
            outbound.push((envelope.peer, reply_msg));
        }

        WireMessage::OodsReadingRequest(_req) => {
            // YPX-021 §8.2 / Ark L Phase 2 — sign this node's CURRENT OODS
            // reading (live network-size estimate + its NBC baseline; the tick
            // is Nabla-signed and NBC/grandparent-anchored). The receiver
            // verifies it with `validation::verify_oods_attestation` before
            // trusting the tick to justify the Confidence Index (liveness gate L).
            let attestation = state.build_oods_attestation();
            let reply_msg = WireMessage::OodsReadingResponse(
                axiom_nabla::wire_client::OodsReadingResponse { attestation },
            );
            outbound.push((envelope.peer, reply_msg));
        }

        // ── Client TCP-CBOR migration paths (CLAUDE.md §8) ──
        // Thin codec wrappers over `query_txid_core`,
        // `register_cheque_claim_core`, `register_clara_core`. The HTTP
        // handlers wrap the same cores; the wire variant carries native
        // bytes instead of hex strings.
        WireMessage::QueryTxidRequest(req) => {
            let resp = query_txid_core(req, state);
            let reply = WireMessage::QueryTxidResponse(resp);
            outbound.push((envelope.peer, reply));
        }

        WireMessage::RegisterChequeClaimRequest(req) => {
            let (resp, announce) = register_cheque_claim_core(req, state);
            let reply = WireMessage::RegisterChequeClaimResponse(resp);
            outbound.push((envelope.peer, reply));
            // YPX-022 §2.1.2a item 3 (KI#205) — THE live emitter of
            // `ChequeClaimAnnounce`: flood a newly stored, authenticated claim
            // so every recorder holds the delivery terminal `register_recall`
            // reads. Receivers re-verify before applying (gossip.rs).
            if let Some(msg) = announce {
                let wire = WireMessage::Gossip(msg);
                if let Some(mesh) = state.core.mesh() {
                    for target_id in mesh.forward_targets(&state.node_id) {
                        if let Some(peer) = mesh.peer_by_id(&target_id) {
                            outbound.push((to_socket_addr(&peer.address), wire.clone()));
                        }
                    }
                }
            }
        }

        WireMessage::OooConfirmRequest(req) => {
            // KI#59 — verify the link's k-witness quorum, mark ooo-attested (NO
            // head advance), return a signed OutOfOrderConfirmation. No mesh
            // flood: the attestation is self-contained + Core-verified; other
            // nodes need not know this node marked it.
            let resp = ooo_confirm_core(req, state);
            let reply = WireMessage::OooConfirmResponse(resp);
            outbound.push((envelope.peer, reply));
        }
        WireMessage::RecallRequest(req) => {
            let txid = axiom_core_logic::compute::compute_txid(&req.failed_send_tx);
            let sender_pk = req.sender_pk.clone();
            let resp = register_recall_core(req, state);
            let recalled_ok = resp.status == "OK";
            // YPX-025 A2 — capture the reserver's attestation BEFORE `resp` is moved
            // into the reply; it rides the RESERVATION flood so every node verifies
            // this recall (binds T, reserver's NBC key) before applying the marker.
            let reservation_attestation = resp.attestation.clone();
            let reply = WireMessage::RecallResponse(resp);
            outbound.push((envelope.peer, reply));
            // YPX-022 §2.2.1 — flood the RESERVATION to the mesh: (a) any node
            // can serve the RETRACT_PENDING in-flight notice, and (b) the
            // recall self-send's registration (the COMMIT) can land on ANY
            // node, not just this one. Not the terminal — a redeem still wins
            // until the committed flood.
            if recalled_ok {
                let tick = state.virtual_secs;
                let wire = WireMessage::Gossip(GossipMessage::Recall {
                    txid, sender_pk, recall_tick: tick, committed: false,
                    attestation: reservation_attestation,
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
            outbound.push((envelope.peer, reply));
        }

        WireMessage::QueryWalletStateRequest(req) => {
            let resp = query_wallet_state_core(req, state);
            let reply = WireMessage::QueryWalletStateResponse(resp);
            outbound.push((envelope.peer, reply));
        }

        WireMessage::FactConfirmRequest(req) => {
            // Runs `fact_confirm_core` (receipt-proven registration).
            let outcome = fact_confirm_core(req, state, &mut outbound);
            let reply = match outcome {
                FactConfirmOutcome::Ok(resp) => WireMessage::FactConfirmResponse(resp),
                FactConfirmOutcome::Mismatch(m) => WireMessage::FactConfirmMismatch(m),
                FactConfirmOutcome::Rejected { error } =>
                    WireMessage::FactConfirmRejected(error),
            };
            outbound.push((envelope.peer, reply));
        }

        // ── Phase 3c TCP-CBOR migration paths (CLAUDE.md §8) ──
        // Each arm calls its `*_core` logic and wraps the result in a
        // response variant. Nabla has no functional HTTP (YP "Transport —
        // functional endpoints", amended 2026-09-26).
        WireMessage::PulseProofRequest(req) => {
            let reply = match pulse_proof_core(req, state, &mut outbound) {
                PulseProofOutcome::Ok(resp) => WireMessage::PulseProofResponse(resp),
                PulseProofOutcome::Rejected { error } =>
                    WireMessage::PulseProofRejected(error),
            };
            outbound.push((envelope.peer, reply));
        }

        WireMessage::JfpSecretRequest(req) => {
            let reply = match jfp_secret_core(req, state, &mut outbound) {
                JfpSecretOutcome::Ok(resp) => WireMessage::JfpSecretResponse(resp),
                JfpSecretOutcome::Rejected { error } =>
                    WireMessage::JfpSecretRejected(error),
            };
            outbound.push((envelope.peer, reply));
        }

        WireMessage::JfpSecretsRequest(req) => {
            let resp = jfp_secrets_core(req, state);
            let reply = WireMessage::JfpSecretsResponse(resp);
            outbound.push((envelope.peer, reply));
        }

        // WireMessage::BridgeRequest is intercepted in recv_loop and run
        // off the node lock (bridge_core / task #53) — it never reaches
        // here; an unhandled arrival falls through to the `_` no-op.


        WireMessage::QueryValidatorEarningsRequest(req) => {
            let resp = query_validator_earnings_core(req, state);
            let reply = WireMessage::QueryValidatorEarningsResponse(resp);
            outbound.push((envelope.peer, reply));
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
                stored_linked_wallet_id: String::new(),
                stored_linkage_epoch: 0,
                stored_at_tick: state.virtual_secs,
            });
            let reply = WireMessage::RegisterValidatorPoolResponse(resp);
            outbound.push((envelope.peer, reply));
        }

        WireMessage::QueryValidatorPoolRequest(req) => {
            let resp = state.validator_pool.process_query(req);
            let reply = WireMessage::QueryValidatorPoolResponse(resp);
            outbound.push((envelope.peer, reply));
        }

        // §10.0 FOB fee-claim — serve the claim attestation (hashmap only).
        WireMessage::FobClaimAttestationRequest(req) => {
            use axiom_nabla::wire_client::FobClaimAttestationResponse;
            let resp = if state.core.smt().txid_mode()
                != axiom_nabla::bloom::TxidServiceMode::Hashmap
            {
                FobClaimAttestationResponse { status: "NOT_AUTHORITATIVE".into(), attestation: None }
            } else {
                match state.validator_pool.get(&req.validator_id) {
                    None => FobClaimAttestationResponse { status: "NOT_LINKED".into(), attestation: None },
                    Some((linked_wallet_id, _epoch, _at)) => {
                        let amount = state.core.fob_pool_balance(&req.validator_id, req.is_dev);
                        if amount == 0 {
                            FobClaimAttestationResponse { status: "NO_POOL".into(), attestation: None }
                        } else {
                            let tick = state.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
                            match axiom_nabla::registration::build_fob_claim_attestation(
                                &state.own_nbc_bytes,
                                axiom_core_logic::types::FOB_CLAIM_POOL_BOUNDED_FEE,
                                req.validator_id, req.is_dev,
                                amount, &linked_wallet_id, tick, 0, state.core.signer(),
                            ) {
                                Some(att) => FobClaimAttestationResponse { status: "OK".into(), attestation: Some(att) },
                                None => FobClaimAttestationResponse { status: "NOT_AUTHORITATIVE".into(), attestation: None },
                            }
                        }
                    }
                }
            };
            let reply = WireMessage::FobClaimAttestationResponse(resp);
            outbound.push((envelope.peer, reply));
        }

        // Contribution emission (`AXIOM_DESIGN_ValidatorEmission.md` §4.2): serve
        // this epoch's claim attestation to an eligible identity's Operational
        // wallet. Eligibility is checked HERE (issuance) and the amount again at
        // register (verify #1). Hashmap nodes only, like the fee claim.
        WireMessage::EmissionClaimAttestationRequest(req) => {
            use axiom_nabla::wire_client::FobClaimAttestationResponse;
            let refuse = |s: &str| FobClaimAttestationResponse { status: s.into(), attestation: None };
            let tick = state.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
            let resp = if state.core.smt().txid_mode() != axiom_nabla::bloom::TxidServiceMode::Hashmap {
                refuse("NOT_AUTHORITATIVE")
            } else {
                match emission_claim_identity(req, tick) {
                    // GUIDE §5.6c lever 3 — a probationary certificate answers
                    // the spec's `NOT_ELIGIBLE`; the internal marker exists so
                    // the refusal is COUNTED separately (RULE 3 §2).
                    Err(EMISSION_PROBATION_REFUSAL) => {
                        state.probation_emission_refusals =
                            state.probation_emission_refusals.saturating_add(1);
                        info!("[PROBATION-EMISSION-REFUSED] EmissionNabla claim from a \
                               probationary certificate — NOT_ELIGIBLE (§5.6c lever 3, total={})",
                            state.probation_emission_refusals);
                        refuse("NOT_ELIGIBLE")
                    }
                    Err(why) => refuse(why),
                    Ok(identity) => {
                        let share = state.core.emission().share(req.pool);
                        match state.core.emission().check_claim(req.pool, identity, share) {
                            Err("already claimed this epoch") => refuse("ALREADY_CLAIMED"),
                            Err(_) => refuse("NO_POOL"),
                            Ok(()) => match axiom_nabla::registration::build_fob_claim_attestation(
                                &state.own_nbc_bytes, req.pool, identity, false, share,
                                &req.claimant_wallet_id, tick, req.epoch, state.core.signer(),
                            ) {
                                Some(att) => FobClaimAttestationResponse { status: "OK".into(), attestation: Some(att) },
                                None => refuse("NOT_AUTHORITATIVE"),
                            },
                        }
                    }
                }
            };
            let reply = WireMessage::FobClaimAttestationResponse(resp);
            outbound.push((envelope.peer, reply));
        }

        WireMessage::RegisterVbcRequest(req) => {
            let resp = register_vbc_core(req, state);
            let reply = WireMessage::RegisterVbcResponse(resp);
            outbound.push((envelope.peer, reply));
        }

        // Responses arriving at a node (e.g. echoed during gossip) — no-op.
        WireMessage::QueryTxidResponse(_)
        | WireMessage::RegisterVbcResponse(_)
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
        | WireMessage::QueryValidatorEarningsResponse(_)
        | WireMessage::RegisterValidatorPoolResponse(_)
        | WireMessage::QueryValidatorPoolResponse(_) => {}

        WireMessage::TardisAttachRequest { node_id, external_port, has_children, prefer_writer, nbc_bytes, nbc_supporting_bytes } => {
            // ── §5.6a-bis: COMPOSE, never adopt a claim ──
            // Identical to the Hello receiver above: the requester told us only
            // a PORT, and its address is what WE observed on this connection
            // joined to that port. The IP half never comes from the node.
            //
            // ⚠ THIS ARM USED TO READ `let reply_to = to_socket_addr(address)`,
            // where `address` was the requester's own claim, and the comment
            // here called that "the requester's self-reported listening
            // address" as though self-reporting were the point. It was the bug:
            // a self-asserted address stored verbatim (see `note_peer` and the
            // two `upsert_peer_self_announced` sites below) is exactly what
            // §5.6a-bis exists to remove, and fixing only Hello left it alive
            // on this message. Correct reading: the address is COMPOSED here
            // and the claim no longer reaches the mesh.
            //
            // Composing also kills the same reflection vector the NBC issuance
            // reply closed — a forged `address` could aim our attach response
            // (and our NBC) at a third party. It can now only reach whoever
            // actually connected.
            let address = &from_socket_addr(std::net::SocketAddr::new(
                envelope.peer.ip(), *external_port));
            let reply_to = to_socket_addr(address);

            // ── NBC verification ── (carry supporting chain — 2026-08-16 join fix)
            if let Err(reason) = state.verify_peer_nbc_with_supporting(nbc_bytes, nbc_supporting_bytes, node_id) {
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

            // ── GUIDE §5.6c lever 1(a): a probationary node is NEVER a writer ──
            // While OUR OWN NBC is inside the window we take no child at all —
            // not a D slot and not the P slot either (a P child receives our
            // ticks, and the point is that fresh nodes "cannot form writer
            // sub-trees or carry ticks"). Reply refused WITH referrals, as the
            // P branch does, so the joiner keeps looking. `downstream_count`
            // stays 0, so `is_self_writer()` can never hold for us. We may
            // still attach UPWARD as a leaf and receive ticks (we sync).
            if state.own_nbc_probationary() {
                state.probation_attach_refusals =
                    state.probation_attach_refusals.saturating_add(1);
                info!("[PROBATION-ATTACH-REFUSED] {:02x}{:02x}… asked to attach under us \
                       while our NBC is probationary (§5.6c lever 1) — refused with \
                       referrals (total={})",
                    node_id[0], node_id[1], state.probation_attach_refusals);
                let referrals = build_referrals(state);
                outbound.push((
                    reply_to,
                    WireMessage::TardisAttachResponse {
                        node_id: state.node_id,
                        accepted: false,
                        // KI#75 rule kept under the KI#48 P grant: a
                        // PROBATIONARY host grants NEITHER D nor P.
                        pending: false,
                        downstream_count: dc,
                        referrals,
                        nbc_bytes: state.own_nbc_bytes.clone(),
                        nbc_supporting_bytes: state.own_nbc_supporting_bytes(),
                    },
                ));
                return outbound;
            }

            // Check if we can accept them as a D child
            // If prefer_writer is set, only accept if we have dc=1 (accepting makes us dc=2 = writer)
            // Use the SHARED protocol helper rather than restating the rule.
            // `writer_ok = !prefer_writer || dc == 1` duplicated
            // `TardisNode::recovery_candidate_acceptable` exactly — and a rule
            // written twice is a rule that eventually disagrees with itself
            // (the same reasoning as the one-builder rule in CLAUDE.md §12).
            // tardis.rs is also where the spec says this decision belongs:
            // "a PROTOCOL DECISION about tree topology optimization … it lives
            // here, not in the simulator".
            let writer_ok = axiom_nabla::tardis::TardisNode::recovery_candidate_acceptable(
                dc, *prefer_writer,
            );
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
                            pending: false,
                            downstream_count: state.core.tardis().unwrap().downstream_count(),
                            referrals: vec![],
                            nbc_bytes: state.own_nbc_bytes.clone(),
                            nbc_supporting_bytes: state.own_nbc_supporting_bytes(),
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
                            pending: false,
                            downstream_count: state.core.tardis().unwrap().downstream_count(),
                            referrals,
                            nbc_bytes: state.own_nbc_bytes.clone(),
                            nbc_supporting_bytes: state.own_nbc_supporting_bytes(),
                        },
                    ));
                }
            } else {
                // ── E → P → D: GRANT THE PENDING SLOT (YPX-003 §2.1 step 2) ──
                // RULED 2026-09-25 (the owner, KI#48) — BUILT as designed, with the
                // one rule the 08-01 attempt lacked.
                //
                // Our D slots are full (or writer-preference declined), so the
                // spec's answer is NOT "rejected" — it is "become my PENDING
                // child": "Z receives ticks from its host (fully functional) …
                // Z is NOT degraded — it participates in the network", and it
                // is promoted to D by `promote_pending()` when a slot opens.
                //
                // HISTORY (why this is a NEW wire field and not a bare
                // `accepted: true`). On 2026-08-01 the grant was tried as
                // `accepted: true` and reverted the same day: the requester
                // called `set_upstream` (status Connected), `needs_parent()`
                // went false, the node STOPPED seeking a D slot, and on a
                // cold-started mesh (every node dc=0, strict pass accepts only
                // dc==1) EVERY attach fell here — 10 nodes parked, no D
                // children, no writers, ticks frozen. Orphan-free but tickless.
                //
                // THE ONE RULE (§2.1 ruling block): the requester adopts us as
                // its TICK SOURCE with `upstream_status = Pending`
                // (`set_upstream_pending`), so `needs_parent()` stays TRUE and
                // it keeps seeking a real D slot through SlotAvailable hints and
                // the two-pass relax; when it lands one it sends us
                // `TardisDetach` (which clears `pending` via `remove_peer`) and
                // seats there. P is NEVER counted in `downstream_count` /
                // `is_self_writer`, so writers still form only through real D
                // attaches. `pending: true` on the wire is what tells the
                // requester which of the two it was granted.
                //
                // KI#75 (§5.6c lever 1) is preserved above: a PROBATIONARY host
                // returned before reaching this branch and grants neither.
                let already_ours =
                    state.core.tardis().unwrap().pending() == Some(node_id);
                let mut grant_pending = already_ours;
                if !already_ours
                    && state.core.tardis().unwrap().pending().is_none()
                    && *node_id != state.node_id
                    && state.core.tardis().unwrap().upstream().is_none_or(|up| *up != *node_id)
                {
                    state.core.tardis_mut().unwrap().set_pending(*node_id);
                    grant_pending = true;
                    // Register in the mesh so ForwardTick can resolve an
                    // address for them — without this the P child is in the
                    // tick target list but unreachable, which starves it
                    // exactly like an orphan.
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
                    info!("[TARDIS-PENDING] granted P slot to {:02x}{:02x}… \
                           (D full/declined) — it now receives ticks, keeps \
                           seeking a D slot, and is promoted when ours opens",
                        node_id[0], node_id[1]);
                }

                // Referrals still ride along: a P host is a waypoint, not a
                // destination — the child keeps looking for a real D slot.
                let referrals = build_referrals(state);
                outbound.push((
                    reply_to,
                    WireMessage::TardisAttachResponse {
                        node_id: state.node_id,
                        accepted: grant_pending,
                        pending: grant_pending,
                        downstream_count: state.core.tardis().unwrap().downstream_count(),
                        referrals,
                        nbc_bytes: state.own_nbc_bytes.clone(),
                        nbc_supporting_bytes: state.own_nbc_supporting_bytes(),
                    },
                ));
            }
        }

        WireMessage::TardisAttachResponse { node_id, accepted, pending, downstream_count, referrals, nbc_bytes, nbc_supporting_bytes } => {
            let now_secs = state.virtual_secs;

            // Clear pending request — we got a response.
            state.pending_attach.remove(node_id);

            // Verify responder's NBC for mutual identity verification (N2 tick check).
            // Without this, ticks from the upstream would be rejected by the N2 check.
            // Carry the supporting chain so a citizen-parent's chain_depth>0 NBC
            // verifies to a Nabla root (2026-08-16 join fix).
            if !nbc_bytes.is_empty() {
                if let Err(reason) = state.verify_peer_nbc_with_supporting(nbc_bytes, nbc_supporting_bytes, node_id) {
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

            if *accepted && *pending {
                // ── P GRANT (YPX-003 §2.1 step 2, KI#48 RULED 2026-09-25) ──
                // The host could not seat us as D but its P slot was free. We
                // adopt it as our TICK SOURCE with `upstream_status = Pending`:
                // ticks are received and validated like a D child's, while
                // `needs_parent()` stays TRUE so the orphan-recovery loop keeps
                // seeking a real D slot (hints + two-pass relax). ONE predicate
                // for "parked": `TardisNode::is_parked`.
                let (up_is_host, parked, seated) = {
                    let t = state.core.tardis().unwrap();
                    (t.upstream() == Some(node_id), t.is_parked(), !t.needs_parent())
                };
                if up_is_host {
                    // Re-grant from our current host (the recovery loop asks it
                    // again while parked) or a late duplicate — nothing to do,
                    // and NEVER a detach (KI#48 guard, same as the D case).
                    return outbound;
                }
                if seated || parked {
                    // We already hold a D seat, or are already parked at a
                    // different host: free THIS host's P slot so it stays
                    // available to a real orphan. One P host at a time.
                    let detach_addr = state.core.mesh().unwrap().peer_by_id(node_id)
                        .map(|p| to_socket_addr(&p.address))
                        .unwrap_or(envelope.peer);
                    outbound.push((
                        detach_addr,
                        WireMessage::TardisDetach { node_id: state.node_id },
                    ));
                    return outbound;
                }
                state.core.tardis_mut().unwrap().set_upstream_pending(*node_id);
                // Sync tick to avoid stale-tick rejection — exactly as a D grant.
                let now_ms = state.virtual_ms;
                let prev_tick = now_secs.saturating_sub(TICK_INTERVAL_SECS);
                let prev_ms = now_ms.saturating_sub(TICK_INTERVAL_SECS * 1000);
                state.core.tardis_mut().unwrap().set_tick(prev_tick, prev_ms);
                state.tardis_parked_grants = state.tardis_parked_grants.saturating_add(1);
                info!("[TARDIS-PARKED] parked in P slot of {:02x}{:02x}… — receiving its \
                       ticks; still seeking a D slot (needs_parent stays true)",
                    node_id[0], node_id[1]);
            } else if *accepted && state.core.tardis().unwrap().needs_parent() {
                // Accepted as D! Set this node as our upstream immediately.
                if let Some(old_up) = state.core.tardis().unwrap().upstream().cloned() {
                    if old_up != *node_id {
                        // KI#48 (§2.1 step 3): if we were PARKED at `old_up`,
                        // we just landed a real D slot elsewhere — tell the P
                        // host so it clears `pending` (`remove_peer`) and its
                        // P slot is free again. A Questionable old upstream
                        // takes the existing silent path.
                        let was_parked = state.core.tardis().unwrap().is_parked();
                        state.core.tardis_mut().unwrap().remove_peer(&old_up);
                        if was_parked {
                            match state.core.mesh().unwrap().peer_by_id(&old_up) {
                                Some(peer) => outbound.push((
                                    to_socket_addr(&peer.address),
                                    WireMessage::TardisDetach { node_id: state.node_id },
                                )),
                                // The host's P slot then frees only when its
                                // silent-child/approval timers drop us. Loud,
                                // because a leaked P slot is invisible otherwise.
                                None => warn!("[TARDIS-UNPARKED] P host {:02x}{:02x}… not in mesh — \
                                               TardisDetach NOT sent; its P slot frees on timeout",
                                    old_up[0], old_up[1]),
                            }
                            state.tardis_parked_to_seated = state.tardis_parked_to_seated.saturating_add(1);
                            info!("[TARDIS-UNPARKED] left P slot of {:02x}{:02x}… for a D slot at \
                                   {:02x}{:02x}…",
                                old_up[0], old_up[1], node_id[0], node_id[1]);
                        }
                    }
                    // `old_up == node_id`: our P host promoted us itself
                    // (`promote_pending`) — `set_upstream` flips Pending →
                    // Connected in place.
                }
                state.core.tardis_mut().unwrap().set_upstream(*node_id);
                // Sync tick to avoid stale-tick rejection
                let now_ms = state.virtual_ms;
                let prev_tick = now_secs.saturating_sub(TICK_INTERVAL_SECS);
                let prev_ms = now_ms.saturating_sub(TICK_INTERVAL_SECS * 1000);
                state.core.tardis_mut().unwrap().set_tick(prev_tick, prev_ms);
            } else if *accepted
                && state.reattach_pending.map(|(t, _)| t == *node_id).unwrap_or(false)
            {
                // ── REATTACH ACCEPTED (YPX-003 §2.16.5) ──
                // We asked to MOVE, and a dc=1 node took us. Detach from the old
                // parent and adopt the new one. Without this branch the reattach
                // would fall into "already have a parent -> decline", below, and
                // the tree could never merge — which is precisely the state the
                // mesh was stuck in (KI#48).
                let old_up = state.core.tardis().unwrap().upstream().copied();
                if let Some(old) = old_up {
                    if old != *node_id {
                        // KI#72: CHOSEN move (§2.16.5 tree-merge reattach), not a
                        // forced loss. Marked HERE, on the path that actually
                        // fires — an earlier version marked wants_rebalance(),
                        // which §2.15.3 disables in steady state, so 15 real
                        // rebalance moves counted zero. Verify the live path
                        // before attaching a counter to it.
                        state.core.tardis_mut().unwrap().note_voluntary_move();
                        state.core.tardis_mut().unwrap().remove_peer(&old);
                        if let Some(peer) = state.core.mesh().unwrap().peer_by_id(&old) {
                            outbound.push((
                                to_socket_addr(&peer.address),
                                WireMessage::TardisDetach { node_id: state.node_id },
                            ));
                        }
                    }
                }
                state.core.tardis_mut().unwrap().set_upstream(*node_id);
                let now_ms = state.virtual_ms;
                let prev_tick = now_secs.saturating_sub(TICK_INTERVAL_SECS);
                let prev_ms = now_ms.saturating_sub(TICK_INTERVAL_SECS * 1000);
                state.core.tardis_mut().unwrap().set_tick(prev_tick, prev_ms);
                state.reattach_pending = None;
                info!("[TARDIS-REATTACH] moved to {:02x}{:02x}… (dc=1 target) — \
                       it becomes a writer, tree merges by one",
                    node_id[0], node_id[1]);
            } else if *accepted && !state.core.tardis().unwrap().needs_parent() {
                // Parent accepted us but we already have a parent — reject to free their D slot.
                // Use the peer's mesh address, not envelope.peer (TCP ephemeral port).
                //
                // KI#48 guard: if the responder IS our current upstream (a late /
                // duplicate response to the attach we already completed), sending
                // TardisDetach here makes the parent evict US from its D slot
                // while we still hold `up` = parent — ticks stop, we go silent-
                // parent, and the tree churns with no detach line on our side.
                if state.core.tardis().unwrap().upstream() == Some(node_id) {
                    info!(
                        "[TARDIS-DUP-ACCEPT] late accept from current parent {} — ignoring, NOT detaching",
                        hex::encode(&node_id[..4]),
                    );
                    return outbound;
                }
                let detach_addr = state.core.mesh().unwrap().peer_by_id(node_id)
                    .map(|p| to_socket_addr(&p.address))
                    .unwrap_or(envelope.peer);
                outbound.push((
                    detach_addr,
                    WireMessage::TardisDetach { node_id: state.node_id },
                ));
            } else if !accepted
                && state.reattach_pending.map(|(t, _)| t == *node_id).unwrap_or(false)
            {
                // Target was not dc=1 after all (or filled up). Clear and retry
                // later — an honest refusal from the peer's OWN state, which is
                // the whole point of not trusting gossip slot claims.
                state.reattach_pending = None;
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
            // KI#48: a TardisDetach from our own PARENT orphans us silently —
            // remove_peer clears `up` with no [TARDIS-DETACH] line on our side.
            // Make that visible; the sender's log says WHY it dropped us.
            if state.core.tardis().unwrap().upstream() == Some(node_id) {
                info!(
                    "[TARDIS-PARENT-DROPPED-US] parent {} sent TardisDetach — we are now orphaned",
                    hex::encode(&node_id[..4]),
                );
            }
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
                let has_children = state.core.tardis().unwrap().downstream_count() > 0;
                let current_tick = state.virtual_secs;
                // ── KI#48: DO NOT CLEAR THE DEDUP HERE ──────────────────────
                // This used to `state.pending_attach.clear()` with the comment
                // "we just became orphan, fresh slate". But the handler runs on
                // EVERY TardisDetach received while `needs_parent()` — not only
                // on the transition into orphanhood. An orphan whose children
                // keep leaving therefore wiped its in-flight dedup on every
                // detach and immediately re-blasted 3 more requests.
                //
                // That is the attach storm. Measured in the sim reproduction:
                // AttachReq 1,187 (T15) -> 14,087 (T20) -> 129,739 (T25), ~10x
                // per 5 ticks with only 10 nodes, until the process is OOM-killed.
                // The traffic starves tick/approval delivery, so parents never
                // accumulate approvals, so children detach — which clears the
                // dedup again. The storm feeds the churn that feeds the storm.
                //
                // Entries expire on their own via the ATTACH_TIMEOUT_TICKS retain
                // in tick_loop, which is the correct "fresh slate" mechanism: it
                // is time-bounded rather than event-triggered. A genuinely new
                // orphan has an empty or already-stale map anyway.
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
                            external_port: state.external_port,
                            has_children,
                            prefer_writer: true,
                            nbc_bytes: state.own_nbc_bytes.clone(),
                            nbc_supporting_bytes: state.own_nbc_supporting_bytes(),
                        },
                    ));
                    sent += 1;
                }
            }
        }

        WireMessage::IntroductionRequest { from } => {
            // Peer exchange — respond with peers WE HAVE OBSERVED.
            //
            // ── §5.6a-bis: we do not put ourselves in this list ──
            // ⚠ This block used to lead with a self-entry carrying
            // `address: my_address()`, i.e. our own claim about where we live,
            // shipped to every peer that asked. The receiver files PX entries
            // via `note_peer_referral` — explicitly SECOND-HAND, "a relayed
            // address may be stale" — so a first-person assertion was riding in
            // on the one channel built for third-party observations. That is
            // the same self-assertion Hello / TardisAttachRequest /
            // TopologyHint were fixed to remove; PX was the last one.
            //
            // Nothing is lost by dropping it:
            //   * ADDRESS — the requester DIALLED us. It already holds our
            //     address first-hand, from its own connection, which is
            //     strictly better evidence than our say-so.
            //   * SLOT INFO — `Hello` already carries `downstream_count`, and a
            //     PX exchange is preceded by a connection. The requester learns
            //     our open slots there; this entry was duplicating it.
            //
            // The remaining entries are peers we observed, relayed onward —
            // permitted by §5.6a-bis point 3 ("an observer may propagate what
            // it plainly saw") and already correctly marked second-hand by the
            // receiver.
            let mut peers: Vec<PeerInfo> = Vec::new();
            for p in state.core.mesh().unwrap().active_peers().iter().take(9) {
                peers.push(p.clone());
            }
            // Reply on the inbound connection: the requester (bridge_core's
            // introduction exchange, peer discovery) holds it open for a
            // `read_exact`. `envelope.peer` is that connection's ephemeral
            // source port — unusable as a fresh destination — so it is only
            // a fallback for an already-closed reply stream.
            let reply = WireMessage::IntroductionResponse { peers };
            outbound.push((envelope.peer, reply));
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
                    // on the inbound stream (KI#92: written off-lock by
                    // `dispatch_outbound`); if that fails they re-learn via Hello.
                    outbound.push((envelope.peer, pong));
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
                upstream_pending: state.core.tardis().unwrap().is_parked(),
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
            // Reply to the request's own connection: `dispatch_outbound` writes an
            // `envelope.peer` entry on the inbound socket OFF the node lock
            // (KI#92), or dials it when there is no inbound socket.
            outbound.push((envelope.peer, response));
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

        WireMessage::NbcIssuanceRequest { sphincs_pk, ed25519_pk, dilithium_pk, node_name, external_port, operator_wallet } => {
            let (accepted, nbc_bytes, supporting_chain_bytes, rejection_reason) =
                state.handle_nbc_issuance_request(sphincs_pk, ed25519_pk, dilithium_pk, node_name, operator_wallet);
            let response = WireMessage::NbcIssuanceResponse {
                accepted,
                nbc_bytes,
                supporting_chain_bytes,
                rejection_reason,
            };
            // Route the reply to the requester's LISTENER (KI#42): a
            // bootstrapping node is not yet in our peer table and never reads its
            // outbound socket, so `envelope.peer` (its ephemeral source port) is
            // unreachable. We therefore compose the destination as
            // `observed connection IP : declared external_port`, and fall back to
            // `send_reply` on the inbound stream only for a true external client
            // with no listener (`external_port == 0`).
            //
            // GUIDE §5.6a-bis: the PORT is declared by the requester, the IP
            // comes from the CONNECTION. Two properties fall out, and both are
            // now STRUCTURAL — there is no host on the wire to mishandle:
            //
            // 1. NO REFLECTION. When this carried a claimed host, dialing it let
            //    any joiner aim our response — a full SPHINCS+ NBC plus
            //    supporting chain, i.e. a large amplified payload — at a third
            //    party, using a genesis node as the amplifier. Composing from
            //    `envelope.peer.ip()` makes that impossible: the reply can only
            //    reach whoever actually connected.
            // 2. NO DNS UNDER THE NODE MUTEX. The original code called
            //    `to_socket_addrs()` on an ATTACKER-SUPPLIED name while
            //    `handle_message` holds the node mutex. A blocking getaddrinfo on
            //    that lock is what killed 3/10 nodes on 2026-08-18 (KI#92/#96).
            //    A `u16` needs no syscall and no parsing at all.
            //
            // History, so the shrinkage is legible: this was
            // `reply_addr: Option<String>`, defended by a `reply_port()` helper
            // that parsed the port and discarded the host. The helper and its
            // edge-case tests (bracketed IPv6, bare names, zero ports) went with
            // the field on 2026-08-26 — they guarded a value no longer sent.
            let routed = (*external_port != 0)
                .then(|| std::net::SocketAddr::new(envelope.peer.ip(), *external_port));
            match routed {
                Some(addr) => outbound.push((addr, response)),
                None => {
                    // No usable reply port: reply on the inbound stream — KI#92:
                    // written off-lock by `dispatch_outbound`, which counts and
                    // logs a failure (`[E_NABLA_TRANSPORT_SEND_FAILED]`).
                    outbound.push((envelope.peer, response));
                }
            }
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

        // ── YPX-009 §12.8: StatePull ──
        // ── KI#43b live-gate instrument (DEV MODE ONLY) ──
        WireMessage::DevInjectConsumedBloomFp { state_id } => {
            let injected = if state.core.is_dev_mode() {
                let tick = state.virtual_secs;
                state.core.smt_mut().dev_inject_consumed_bloom_fp(tick, state_id);
                warn!("[KI#43b GATE] DEV FP injected into consumed bloom for state {} \
                       (exact record deliberately untouched)",
                    hex::encode(&state_id[..8]));
                true
            } else {
                warn!("[KI#43b GATE] DevInjectConsumedBloomFp REFUSED — not a dev node");
                false
            };
            let resp = WireMessage::DevInjectConsumedBloomFpAck { injected };
            outbound.push((envelope.peer, resp));
        }

        WireMessage::DevInjectConsumedBloomFpAck { .. } => {}

        // ── KI#43b heal-adjudication barrier (§12.4.4) ──
        WireMessage::ExactConsumedQuery { from, state_id, born_tick } => {
            // §12.4.4 item 4: scope cleanliness to the state's birth era, which
            // the requester carries as a global-grid tick VALUE. This peer maps
            // it against its OWN consumed chain (same grid, KI#44), so the era
            // never crosses the wire. born_tick == 0 = whole history.
            let (recorded, clean) = match state.consumed_exact.as_ref() {
                // an IO error inside the helper fails toward REFUSE
                // (recorded=true / clean=false) — absence of proof rejects.
                Some(store) => exact_barrier_answer(
                    store,
                    state.core.smt().consumed_chain(),
                    state_id,
                    *born_tick,
                ),
                // bloom-mode node: honest — it can never vouch.
                None => (false, false),
            };
            let resp = WireMessage::ExactConsumedAnswer {
                responder: state.node_id,
                state_id: *state_id,
                recorded,
                clean,
            };
            let mesh_reply_addr = from.as_ref().and_then(|f| {
                state.core.mesh()
                    .and_then(|m| m.peer_by_id(f))
                    .map(|p| to_socket_addr(&p.address))
            });
            match mesh_reply_addr {
                Some(addr) => outbound.push((addr, resp)),
                None => {
                    outbound.push((envelope.peer, resp));
                }
            }
        }

        WireMessage::ExactConsumedAnswer { responder, state_id, recorded, clean } => {
            // Count ONLY answers from peers the mesh knows as hashmap-mode —
            // a bloom node or an unknown sender must never fill the barrier.
            let is_recording_peer = state.core.mesh()
                .and_then(|m| m.peer_by_id(responder))
                .map(|p| p.txid_service == "hashmap")
                .unwrap_or(false);
            if is_recording_peer {
                if let Some(adj) = state.adjudications.get_mut(state_id) {
                    adj.answers.insert(*responder, (*recorded, *clean));
                    adj.settle(axiom_nabla::constants::RECORDING_NODES_TOTAL.saturating_sub(1));
                    if let Some(acquitted) = adj.verdict {
                        if acquitted {
                            warn!("[KI#43b] BLOOM-FP confirmed: state {} acquitted by the \
                                   full recording barrier — heal will proceed on retry",
                                hex::encode(&state_id[..8]));
                        } else {
                            info!("[KI#43b] adjudication REFUSED for state {} \
                                   (recorded or unclean recorder)",
                                hex::encode(&state_id[..8]));
                        }
                    }
                }
            }
        }

        WireMessage::StatePullRequest { mode, from, our_root_hash, from_tick, to_tick, section_hash, have_era_ids, have_consumed_era_ids } => {
            use axiom_nabla::types::{StatePullMode, StatePullEntry, WalVerifyResult};
            use axiom_nabla::constants::STATE_PULL_MAX_BYTES;

            // Mesh requester (`from: Some`) → reply to its LISTENING socket via
            // peer_by_id, exactly like AeDigest/AeReconcile: a node never reads
            // its outbound connections, so send_reply would write the response
            // into a buffer nobody drains (the 2026-07-28 rotation-restart
            // deadlock: all 10 nodes UNARMED forever, every registration
            // refused). Client requester (`from: None`) → send_reply on the
            // request's own connection, which the client is blocking on.
            let mesh_reply_addr = from.as_ref().and_then(|f| {
                state.core.mesh()
                    .and_then(|m| m.peer_by_id(f))
                    .map(|p| to_socket_addr(&p.address))
            });

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
                    // KI#42 step 4b: send txid bloom eras the requester lacks,
                    // oldest-first (history is what a fresh node is missing), and
                    // stop at the byte budget — an era is ~1.7 MiB and the cap is
                    // 5 MiB, so a mature chain converges over several pulls rather
                    // than in one oversized message.
                    let bloom_eras = {
                        let have: std::collections::HashSet<u64> =
                            have_era_ids.iter().copied().collect();
                        let mut out: Vec<Vec<u8>> = Vec::new();
                        let mut budget = STATE_PULL_MAX_BYTES;
                        for meta in state.core.smt().txid_chain().metadata() {
                            if have.contains(&meta.era_id) {
                                continue;
                            }
                            let Some(era) = state.core.smt().txid_chain().era(meta.era_id) else {
                                // KI#79: metadata and payload come from the SAME
                                // map, so this arm should be unreachable — but if
                                // it ever fires, the manifest is advertising what
                                // we cannot serve, which is the exact silent-
                                // starvation shape that livelocked re-arm. LOUD.
                                warn!("[ERA-SYNC] txid era {} in metadata but not servable — \
                                       requester cannot converge on it", meta.era_id);
                                continue;
                            };
                            let mut bytes = Vec::new();
                            match ciborium::into_writer(era, &mut bytes).map(|_| bytes) {
                                Ok(bytes) => {
                                    if bytes.len() > budget {
                                        // KI#79: budget exhaustion for THIS pull is
                                        // normal (remainder next pull) — but a single
                                        // era over the FULL budget can never ship, and
                                        // that starved silently for months. LOUD.
                                        if out.is_empty() {
                                            warn!("[ERA-SYNC] txid era {} ({} B) exceeds the FULL \
                                                   StatePull budget ({} B) — NOTHING can be served; \
                                                   *_ERA_REAL_ITEMS outgrew STATE_PULL_MAX_BYTES \
                                                   (KI#79). The boot guard should have caught this.",
                                                meta.era_id, bytes.len(),
                                                axiom_nabla::constants::STATE_PULL_MAX_BYTES);
                                        }
                                        break; // remainder arrives on the next pull
                                    }
                                    budget -= bytes.len();
                                    out.push(bytes);
                                }
                                Err(e) => {
                                    warn!("[ERA-SYNC] failed to encode era {}: {e}", meta.era_id);
                                }
                            }
                        }
                        if !out.is_empty() {
                            info!("[ERA-SYNC] serving {} txid bloom era(s) ({} B) to a peer \
                                   missing them", out.len(), STATE_PULL_MAX_BYTES - budget);
                        }
                        out
                    };
                    let resp = WireMessage::StatePullResponse {
                        mode: StatePullMode::Bootstrap,
                        entries,
                        highest_tick_served: highest_tick,
                        bloom_eras,
                        // WI1 (§5.2): hand the recovering node our anti-rollback
                        // view so it re-arms instead of coming back blind.
                        // KI#42 step 4d: consumed-state eras + the FULL manifest.
                        // The manifest is what lets the requester know when it is
                        // COMPLETE — a fail-closed filter cannot be partially armed,
                        // so it must not arm until it holds every era we hold.
                        consumed_era_manifest: state.core.smt().consumed_era_ids(),
                        consumed_eras: {
                            let have: std::collections::HashSet<u64> =
                                have_consumed_era_ids.iter().copied().collect();
                            let mut out: Vec<Vec<u8>> = Vec::new();
                            let mut budget = STATE_PULL_MAX_BYTES;
                            for id in state.core.smt().consumed_era_ids() {
                                if have.contains(&id) { continue; }
                                let Some(bytes) = state.core.smt().consumed_era_bytes(id) else {
                                    // KI#79: should be unreachable (manifest and
                                    // payload share one map) — loud if it fires,
                                    // because the requester's completeness gate
                                    // will wait forever on this id.
                                    warn!("[ERA-SYNC] consumed era {id} in manifest but not \
                                           servable — requester cannot converge on it");
                                    continue;
                                };
                                if bytes.len() > budget {
                                    // KI#79: a single era over the FULL budget is the
                                    // silent-starvation condition that livelocked
                                    // re-arm (delta 8h, gamma 2026-08-08). LOUD.
                                    if out.is_empty() {
                                        warn!("[ERA-SYNC] consumed era {id} ({} B) exceeds the FULL \
                                               StatePull budget ({} B) — NOTHING can be served and \
                                               the requester can NEVER arm (KI#79). The boot guard \
                                               should have caught this.",
                                            bytes.len(),
                                            axiom_nabla::constants::STATE_PULL_MAX_BYTES);
                                    }
                                    break;
                                }
                                budget -= bytes.len();
                                out.push(bytes);
                            }
                            out
                        },
                        previous_states: state.core.smt().previous_states_snapshot(),
                        verify_result: None,
                        available_from_tick: available_from,
                        // ⚠ ghost audit G10: ALWAYS false — the load-shed
                        // SENDER was never built. The receiver IS wired (the
                        // StatePullResponse arm acts on `overloaded` and skips
                        // the entries), and `STATE_PULL_MAX_CONCURRENT_SERVE`
                        // plus the three StatePull timeout constants exist —
                        // but nothing counts concurrent serves, so this never
                        // turns true and those four constants have ZERO reads.
                        //
                        // Left unwired deliberately: signalling overload needs
                        // a concurrent-serve counter and a shed policy, which
                        // is a feature, not a bug fix. The constants stay in
                        // scripts/ghost_baseline.txt so the RULE 3 gate keeps
                        // them visible until someone builds it or deletes them.
                        overloaded: false,
                    };
                    match mesh_reply_addr {
                        Some(addr) => outbound.push((addr, resp)),
                        None => {
                            outbound.push((envelope.peer, resp));
                        }
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
                        // WalVerify is a targeted section check, not a bootstrap —
                        // era history is not part of its contract.
                        bloom_eras: Vec::new(),
                        entries: vec![],
                        highest_tick_served: 0,
                        consumed_eras: Vec::new(),  // WI1: WAL-verify carries no recovery state
                        consumed_era_manifest: Vec::new(),
                        previous_states: Vec::new(),
                        verify_result: Some(result),
                        available_from_tick: 0,
                        // ⚠ ghost audit G10 — see the sibling serve site above:
                        // the load-shed sender was never built.
                        overloaded: false,
                    };
                    match mesh_reply_addr {
                        Some(addr) => outbound.push((addr, resp)),
                        None => {
                            outbound.push((envelope.peer, resp));
                        }
                    }
                }
            }
        }

        WireMessage::StatePullResponse { mode, entries, highest_tick_served, consumed_eras, consumed_era_manifest, previous_states, verify_result, available_from_tick, overloaded, bloom_eras } => {
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
                            // Coalesced (design decision 2026-08-08): a peer's history
                            // horizon is a per-value EDGE fact, not a per-5s
                            // event — 1,255 identical lines in one soak window.
                            // warn! once per distinct tick value, debug! after.
                            if state.partial_history_seen.insert(*available_from_tick) {
                                warn!("StatePull peer only has data from tick {} — peer has partial history. \
                                       Consider requesting from a different peer for ticks < {}. \
                                       (further repeats of this value at debug!)",
                                    available_from_tick, available_from_tick);
                            } else {
                                debug!("StatePull peer only has data from tick {} (repeat)", available_from_tick);
                            }
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
                    let mut rearm_ok = true;
                    for raw in consumed_eras.iter() {
                        match ciborium::from_reader::<axiom_nabla::bloom_era::BloomEra, _>(
                            raw.as_slice(),
                        ) {
                            Ok(era) => {
                                if let Err(e) = state.core.smt_mut().merge_consumed_era(era) {
                                    // KI#42 step 3: a failed merge leaves us DISARMED —
                                    // a security state, not a cosmetic one. Do not arm
                                    // on it; the peer cursor moves us on next round.
                                    rearm_ok = false;
                                    warn!("[REARM-FAIL] consumed-era merge refused ({e}) — \
                                           staying UNARMED, will retry against another peer");
                                }
                            }
                            Err(e) => {
                                rearm_ok = false;
                                warn!("[REARM-FAIL] undecodable consumed era ({e}) — staying UNARMED");
                            }
                        }
                    }
                    if !previous_states.is_empty() {
                        // Recovered marks carry no per-entry tick; file them in the
                        // active era (lookup unions every era, so placement never
                        // affects whether a mark is found).
                        let now = state.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
                        state.core.smt_mut().merge_previous_states(previous_states, now);
                    }

                    // KI#42 step 4d — COMPLETENESS GATE. A fail-closed filter cannot
                    // be partially armed: holding 39 of 40 eras means being silently
                    // blind to whatever lived in the 40th, which would pass a
                    // rollback. So we arm only once we hold EVERY era the peer
                    // advertised. Anything missing means another pull is needed, and
                    // the startup-pull loop keeps asking because we stay unarmed.
                    let ours: std::collections::HashSet<u64> =
                        state.core.smt().consumed_era_ids().into_iter().collect();
                    let missing: Vec<u64> = consumed_era_manifest
                        .iter()
                        .copied()
                        .filter(|id| !ours.contains(id))
                        .collect();
                    if !missing.is_empty() {
                        rearm_ok = false;
                        // KI#79: log the era IDs THEMSELVES and the answering
                        // peer, not just the count. delta sat UNARMED for 8
                        // hours (2026-08-07) and the root cause is
                        // undeterminable from those logs because only
                        // `missing.len()` was recorded — the four era IDs that
                        // would identify it were computed and thrown away.
                        // The manifest comes from the answering PEER, so which
                        // peer replied is part of the same diagnostic.
                        // Escalates info! -> warn! past the bound: an episode
                        // that long is a livelock, not a startup delay.
                        // Coalesced (design decision 2026-08-08): emit on CHANGE of the
                        // missing set, plus one heartbeat per escalation period;
                        // suppressed repeats are COUNTED so nothing is lost.
                        let bound = axiom_nabla::constants::UNARMED_ESCALATION_ROUNDS;
                        let r = state.unarmed_rounds;
                        let changed = missing != state.rearm_last_missing;
                        let heartbeat = r > bound && (r - bound - 1) % bound == 0;
                        if changed || heartbeat || r <= 2 {
                            let msg = format!(
                                "[REARM-PARTIAL] hold {}/{} consumed eras — still missing {:?} \
                                 (manifest from peer {}, unarmed {} round(s), ×{} suppressed \
                                 since last); staying UNARMED until complete",
                                ours.len(), consumed_era_manifest.len(), missing, envelope.peer,
                                r, state.rearm_suppressed,
                            );
                            if r > bound { warn!("{msg}"); } else { info!("{msg}"); }
                            state.rearm_last_missing = missing.clone();
                            state.rearm_suppressed = 0;
                        } else {
                            state.rearm_suppressed += 1;
                        }
                    } else if rearm_ok && !consumed_era_manifest.is_empty() {
                        info!("StatePull bootstrap: re-armed anti-rollback COMPLETE \
                               ({} consumed era(s), {} previous_states)",
                            ours.len(), previous_states.len());
                    }
                    // KI#42 step 4b: adopt the peer's txid bloom eras. Monotonic
                    // union (BloomChain::merge), so a partial or empty payload can
                    // only fail to add — never disarm us. A size/boundary mismatch
                    // is an ERROR, not a skip: two nodes disagreeing on an era's
                    // dimensions is the mesh-wide disarm failure, and it must be
                    // loud rather than silently leaving a hole.
                    if !bloom_eras.is_empty() {
                        let mut adopted = 0usize;
                        let mut failed = 0usize;
                        for raw in bloom_eras.iter() {
                            match ciborium::from_reader::<axiom_nabla::bloom_era::BloomEra, _>(
                                raw.as_slice(),
                            ) {
                                Ok(era) => {
                                    match state.core.smt_mut().txid_chain_mut().merge_era(era) {
                                        Ok(true) => adopted += 1,
                                        Ok(false) => {}
                                        Err(e) => {
                                            failed += 1;
                                            warn!("[ERA-SYNC-FAIL] era merge rejected ({e}) — \
                                                   per-era sizing must be deterministic \
                                                   across nodes; NOT adopting this era");
                                        }
                                    }
                                }
                                Err(e) => {
                                    failed += 1;
                                    warn!("[ERA-SYNC-FAIL] undecodable era payload ({e})");
                                }
                            }
                        }
                        info!("[ERA-SYNC] adopted {} txid bloom era(s), {} rejected \
                               ({} era(s) now held)",
                            adopted, failed, state.core.smt().txid_chain().era_count());
                    }

                    // KI#42 serve-gate: arm on a COMPLETED bootstrap exchange, which
                    // includes an empty payload — an honest peer on a fresh mesh
                    // legitimately has nothing to send, and refusing to arm on that
                    // would wedge a new network shut.
                    if rearm_ok && !state.anti_rollback_armed {
                        state.anti_rollback_armed = true;
                        // KI#79 — close the unarmed episode and say how long it was.
                        info!("[ARMED] anti-rollback view established from peer — now serving \
                               registrations (was unarmed {} round(s))", state.unarmed_rounds);
                        state.unarmed_rounds = 0;
                        state.unarmed_since_tick = 0;
                    }
                    // Bound the replay under the lock (goal C, sibling of the
                    // merge_previous_states cap): an oversized StatePull `entries`
                    // payload must not tie up the global node lock in an unbounded
                    // apply loop. Cap at AE_MERGE_MAX_BATCH; the overflow re-arrives
                    // on the next pull or reconciles via leaf-hash anti-entropy.
                    let total_entries = entries.len();
                    let entry_cap = axiom_nabla::smt::AE_MERGE_MAX_BATCH;
                    if total_entries > entry_cap {
                        warn!("[AE-MERGE-BOUND] StatePull entries {} > cap {} — replaying first {} \
                               under the lock; remainder re-arrives next pull / via AE",
                            total_entries, entry_cap, entry_cap);
                    }
                    info!("StatePull bootstrap: received {} entries (up to tick {})",
                        total_entries, highest_tick_served);
                    for entry in entries.into_iter().take(entry_cap) {
                        let gossip_msg = GossipMessage::StateUpdate {
                            wallet_id: entry.wallet_id,
                            // KI#46: reconstruction/no-advance path — parent unknown, never ban material.
                            old_state: [0u8; 32],
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
                            // ForkSettlement wave 2a: the LEG rides inside this proof
                            // (`SeqProof::preimage`) and is forwarded as-is; the
                            // flood gate re-verifies it (`verify_seq_proof_leg`).
                            // `old_state` deliberately stays zero ("parent unknown"):
                            // the preimage carries the signed parent. (Until W2 a
                            // filled `old_state` would have made this replay
                            // ban-capable through check-3 — retired, §9o [R56].)
                            // It IS covered: `handle_gossip` → the flood hook
                            // records this leg from the preimage INSIDE the
                            // proof (parent = the signed `consumed_state_id`,
                            // never this zero `old_state`) and a second txid
                            // under its key opens the claim — ForkSettlement
                            // §2.3 [R10]. The discarded action is irrelevant for
                            // bans: verdicts leave through the node's drain.
                            seq_proof: entry.seq_proof.clone(),
                        };
                        let now_secs = state.virtual_secs; // [R13]
                        let _ = state.core.handle_gossip(&gossip_msg, now_secs);
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
            outbound.push((envelope.peer, resp));
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
                            // KI#46: reconstruction/no-advance path — parent unknown, never ban material.
                            old_state: [0u8; 32],
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
                            // ForkSettlement wave 2a: the LEG rides inside this proof
                            // (`SeqProof::preimage`) and is forwarded as-is; the
                            // flood gate re-verifies it (`verify_seq_proof_leg`).
                            // `old_state` deliberately stays zero ("parent unknown"):
                            // the preimage carries the signed parent. (Until W2 a
                            // filled `old_state` would have made this replay
                            // ban-capable through check-3 — retired, §9o [R56].)
                            // It IS covered: `handle_gossip` → the flood hook
                            // records this leg from the preimage INSIDE the
                            // proof (parent = the signed `consumed_state_id`,
                            // never this zero `old_state`) and a second txid
                            // under its key opens the claim — ForkSettlement
                            // §2.3 [R10]. The discarded action is irrelevant for
                            // bans: verdicts leave through the node's drain.
                            seq_proof: entry.seq_proof.clone(),
                        };
                        let now_secs = state.virtual_secs; // [R13]
                        let _ = state.core.handle_gossip(&gossip_msg, now_secs);
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
            // ForkSettlement [R18] — our fork bans WITH their evidence ride
            // the reconcile (bounded, cursor-rotated), so a peer holding one
            // leg of a fork learns the verdict in this exchange.
            let fork_bans = state.core.ae_fork_bans_out();
            if !push.is_empty() || !pull.is_empty() || !fork_bans.is_empty() {
                let peer_addr = state.core.mesh().unwrap()
                    .peer_by_id(from)
                    .map(|p| to_socket_addr(&p.address));
                if let Some(addr) = peer_addr {
                    info!("Anti-entropy: reconcile — push {} pull {} fork_bans {}",
                        push.len(), pull.len(), fork_bans.len());
                    outbound.push((addr, WireMessage::AeReconcile {
                        from: state.node_id,
                        push,
                        pull,
                        fork_bans,
                    }));
                }
            }
        }

        // ── Anti-entropy step 4: AeReconcile ──
        // The peer pushed entries it wins on and requested entries it lacks.
        // Apply each push through the merge rule; return the requested pulls.
        WireMessage::AeReconcile { from, push, pull, fork_bans } => {
            let mut applied = 0usize;
            for (entry, proof) in push {
                if state.core.apply_remote_entry(entry, proof.as_ref(), state.virtual_secs) {
                    applied += 1;
                    state.ae_applied_window = state.ae_applied_window.saturating_add(1);
                } else {
                    state.ae_rejected_window = state.ae_rejected_window.saturating_add(1);
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
            // ForkSettlement [R18] — adopt the carried bans AFTER the entries
            // (a head the push delivered is then flipped `Banned` in place).
            adopt_ae_fork_bans(state, fork_bans);
            // [R25] our bans go back on the reply — computed AFTER the push
            // was applied, so a fork the push revealed here reaches the offerer.
            let reply_bans = state.core.ae_fork_bans_out();
            if !entries.is_empty() || !reply_bans.is_empty() {
                let peer_addr = state.core.mesh().unwrap()
                    .peer_by_id(from)
                    .map(|p| to_socket_addr(&p.address));
                if let Some(addr) = peer_addr {
                    outbound.push((addr, WireMessage::AeEntries { entries, fork_bans: reply_bans }));
                }
            }
        }

        // ── Anti-entropy step 5: AeEntries ──
        // The peer returned the entries we requested. Apply via the merge rule.
        WireMessage::AeEntries { entries, fork_bans } => {
            let mut applied = 0usize;
            for (entry, proof) in entries {
                if state.core.apply_remote_entry(entry, proof.as_ref(), state.virtual_secs) {
                    applied += 1;
                    state.ae_applied_window = state.ae_applied_window.saturating_add(1);
                } else {
                    state.ae_rejected_window = state.ae_rejected_window.saturating_add(1);
                }
            }
            if applied > 0 {
                info!("Anti-entropy: applied {applied} pulled entries from peer");
            }
            adopt_ae_fork_bans(state, fork_bans);
        }

        // ── KI#82 fee-ledger AE step 1: TxidAeDigest ──
        // A peer advertised its per-bucket txid_records digest. Push our records
        // in every bucket whose digest differs from (or is absent in) the peer's
        // — it adopts what it lacks; the reverse is covered when we probe it in
        // the rotation. Union, not merge (records immutable). §13.
        WireMessage::TxidAeDigest { from, buckets: peer_buckets } => {
            if state.core.smt().txid_mode()
                == axiom_nabla::bloom::TxidServiceMode::Hashmap
            {
                let peer_map: HashMap<u64, [u8; 32]> =
                    peer_buckets.iter().copied().collect();
                let bucket_ticks = axiom_nabla::constants::TXID_AE_BUCKET_TICKS;
                let divergent: std::collections::HashSet<u64> = state
                    .core
                    .smt()
                    .txid_bucket_digests(bucket_ticks)
                    .into_iter()
                    .filter(|(b, d)| peer_map.get(b) != Some(d))
                    .map(|(b, _)| b)
                    .collect();
                if !divergent.is_empty() {
                    let records = state
                        .core
                        .smt()
                        .txid_records_in_buckets(&divergent, bucket_ticks);
                    if !records.is_empty() {
                        if let Some(addr) = state
                            .core
                            .mesh()
                            .unwrap()
                            .peer_by_id(from)
                            .map(|p| to_socket_addr(&p.address))
                        {
                            info!(
                                "Fee-ledger AE: pushing {} record(s) across {} divergent bucket(s)",
                                records.len(),
                                divergent.len()
                            );
                            outbound.push((addr, WireMessage::TxidAeEntries { records }));
                        }
                    }
                }
            }
        }

        // ── KI#82 fee-ledger AE step 2: TxidAeEntries ──
        // Adopt each fee record through the SAME cap-revalidating chokepoint the
        // gossip path uses (dedup on tx_hash; forged caps rejected). §13.
        WireMessage::TxidAeEntries { records } => {
            if state.core.smt().txid_mode()
                == axiom_nabla::bloom::TxidServiceMode::Hashmap
            {
                let before = state.core.smt().tx_records_len();
                for (tx_hash, record) in records {
                    axiom_nabla::gossip::apply_fee_record_from_gossip(
                        state.core.smt_mut(),
                        &tx_hash,
                        &record.receiver_wallet_id,
                        record.amount,
                        &record.fee_breakdown,
                        record.tick,
                    );
                }
                let adopted = state.core.smt().tx_records_len().saturating_sub(before);
                if adopted > 0 {
                    info!("Fee-ledger AE: adopted {adopted} new fee record(s) from peer");
                }
            }
        }

        // ── KI#84 FOB ledger AE step 1: FobLedgerDigest ──
        // A peer advertised its FOB ledger digest. If it differs from ours,
        // push BOTH our ledgers back — the peer set-unions what it lacks (the
        // reverse is covered when we probe it in the rotation). Hashmap only.
        WireMessage::FobLedgerDigest { from, digest } => {
            if state.core.smt().txid_mode()
                == axiom_nabla::bloom::TxidServiceMode::Hashmap
                && state.core.fob_ledger_digest() != *digest
            {
                let (plus, minus) = state.core.fob_ledgers();
                if !plus.is_empty() || !minus.is_empty() {
                    if let Some(addr) = state
                        .core
                        .mesh()
                        .and_then(|m| m.peer_by_id(from))
                        .map(|p| to_socket_addr(&p.address))
                    {
                        info!(
                            "FOB ledger AE: pushing {} tranche + {} claim fact(s)",
                            plus.len(),
                            minus.len()
                        );
                        outbound.push((addr, WireMessage::FobLedgerEntries { plus, minus }));
                    }
                }
            }
        }

        // ── KI#84 FOB ledger AE step 2: FobLedgerEntries ──
        // Set-union both ledgers (idempotent per key) and rebuild every touched
        // pool: balance = Σplus − Σminus. This is what heals a reset/behind
        // recorder — it adopts the tranches it missed (PLUS) and the sweeps it
        // missed (MINUS) and derives the identical pool state. Hashmap only.
        WireMessage::FobLedgerEntries { plus, minus } => {
            if state.core.smt().txid_mode()
                == axiom_nabla::bloom::TxidServiceMode::Hashmap
            {
                let adopted = state.core.fob_adopt_ledgers(&plus, &minus);
                if adopted > 0 {
                    info!("FOB ledger AE: adopted {adopted} new fact(s) from peer — pools rebuilt");
                }
            }
        }
        // ── KI#170 witness-directory AE (every node stamps, so every node syncs) ──
        // ForkSettlement R50 (wave 4a): the request is SIGNED by `from`'s NBC key
        // and answered with ONE page of the per-entry diff, addressed to the
        // AUTHENTICATED `from` via `peer_by_id` — never `send_reply` (a node never
        // reads its outbound sockets: KI#42), never an unauthenticated field.
        WireMessage::VbcRegistrationDigest { from, nonce, have, sig } => {
            if let Some(reply) = answer_directory_request(state, from, *nonce, have, sig) {
                if let Some(addr) = state.core.mesh().and_then(|m| m.peer_by_id(from)).map(|p| to_socket_addr(&p.address)) {
                    outbound.push((addr, reply));
                }
            }
        }
        // R42: every record was authenticated (R50) and verified OFF the lock in
        // `prelock_directory_verify`; here they are only inserted (set-union).
        WireMessage::VbcRegistrationEntries { from, nonce, .. } => {
            match state.directory_precheck.take() {
                Some(DirectoryPrecheck::Entries { from: f, nonce: n, verified }) if f == *from && n == *nonce => {
                    let adopted = state.core.adopt_verified_directory_entries(verified);
                    if adopted > 0 {
                        info!("VBC directory AE: adopted {adopted} verified registration(s) from {}", hex::encode(&from[..8]));
                    }
                }
                // Refused in the pre-lock stage (counted there) — or no pre-lock
                // stage ran, which only a non-`recv_loop` caller can cause: nothing
                // unverified is ever adopted.
                _ => {}
            }
        }
        // ── Fork Settlement §9o [R58/R59] (W1) — R48 record-AE ──
        // The responder: authenticate against `verified_nbcs[from]`, nonce
        // dedupe, per-`from` budget, global cap (all counted inside the lib),
        // then ONE bounded, signed answer — addressed to `peer_by_id(from)` of
        // the AUTHENTICATED `from`, never `send_reply` (KI#42).
        WireMessage::RecordAeAsk { from, nonce, ask, sig } => {
            let pk = state.verified_nbcs.get(from).and_then(nbc_ed25519_pk);
            let (me, now) = (state.node_id, state.virtual_secs);
            if let Some(reply) = state.core.record_ae_handle_ask(me, from, *nonce, ask, sig, pk, now) {
                if let Some(addr) = state.core.mesh().and_then(|m| m.peer_by_id(from)).map(|p| to_socket_addr(&p.address)) {
                    outbound.push((addr, reply));
                }
            }
        }
        // The asker: the answer was authenticated and its legs verified OFF
        // the lock in `prelock_record_ae`; here they are graded and recorded,
        // and the descent's next ask goes to `peer_by_id(from)`.
        WireMessage::RecordAeAnswer { from, nonce, answer, sig } => {
            let (me, now) = (state.node_id, state.virtual_secs);
            let prepared = match state.record_ae_precheck.take() {
                Some(Some(p)) if p.from == *from && p.nonce == *nonce => Some(p),
                // Refused in the pre-lock stage (counted there), or not this message.
                Some(_) => None,
                // `tick_loop`'s inbox drain has no pre-lock stage: accept and
                // prepare here (bounded — ≤ RECORD_AE_MAX_LEGS_PER_ANSWER legs).
                None => {
                    let pk = state.verified_nbcs.get(from).and_then(nbc_ed25519_pk);
                    state
                        .core
                        .record_ae_accept_answer(from, *nonce, answer, sig, pk, now)
                        .map(|acc| axiom_nabla::record_sync::prepare_answer(acc, answer.clone()))
                }
            };
            if let Some(p) = prepared {
                if let Some(next) = state.core.record_ae_apply_answer(me, p, now) {
                    if let Some(addr) = state.core.mesh().and_then(|m| m.peer_by_id(from)).map(|p| to_socket_addr(&p.address)) {
                        outbound.push((addr, next));
                    }
                }
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
    // Compare RESOLVED addresses, not stored forms: a peer that advertises a
    // name stores a `Name`, which can never equal an observed socket, so
    // matching on the stored value would silently stop identifying exactly the
    // peers this change is for.
    for peer in mesh.active_peers() {
        if to_socket_addr(&peer.address) == *addr {
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
    state: Arc<PlMutex<NablaNodeState>>,
    transport: Arc<dyn Transport>,
    tick_ms: u64,
    epoch_ms: u64,
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
        // KI#92 — each drained envelope KEEPS its own outbound list, so its
        // replies go out on ITS inbound socket (`dispatch_outbound`'s
        // `is_inbound_reply` branch) after the lock is released. Merging them
        // into the tick's `outbound` lost the reply handle: the replies were
        // re-dialed to the client's ephemeral source port (the KI#24 shape).
        let mut drained_replies: Vec<(Envelope, Vec<(std::net::SocketAddr, WireMessage)>)> =
            Vec::new();

        let outbound = {
            let mut node = state.lock();

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
            // ForkSettlement §2.4 [R9/R13/R34] — the origin-vouch boot floor:
            // stamped on the first iteration once `recv_loop` is live, and
            // re-floored after a stall (the gap between consecutive
            // iterations — `prev` is the previous iteration's sample).
            let prev_secs = node.virtual_secs;
            let (boot, refloored) = origin_boot_step(
                prev_secs, now_secs, node.origin_boot_secs, node.recv_loop_live,
                origin_refloor_secs(),
            );
            if refloored {
                node.origin_boot_refloors = node.origin_boot_refloors.saturating_add(1);
                warn!(
                    "[ORIGIN-REFLOOR] tick loop stalled {}s (> {}s, the DEV settle twin) —                      origin vouch boot floor re-set to {} (ForkSettlement R13)",
                    now_secs.saturating_sub(prev_secs), origin_refloor_secs(), now_secs,
                );
            }
            node.origin_boot_secs = boot;
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
                        drained_replies.push((envelope, responses));
                        drained += 1;
                    }
                    None => break,
                }
            }
            // ForkSettlement §2.3 — once per iteration: flood every A1 verdict
            // the lib drain queued (claims from the drain above, from HTTP
            // paths, and those re-derived at `open()` [R28]).
            outbound.extend(fork_ban_fanout(&mut node));

            // ── Step 0.5: Phase B Layer 4 — sweep expired quarantines + stale pending alerts ──
            // Runs once per tick. Idempotent, no-op when nothing expires.
            node.core.quarantine_sweep();
            // GUIDE §5.6c — log each peer that crossed out of join probation
            // since the last pass (derived from the certificate; no message).
            node.probation_tick_pass();

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
                let bootstrap_msg =
                    WireMessage::Gossip(node.core.pool_sync_message(PoolKind::Bootstrap));
                let foundation_msg =
                    WireMessage::Gossip(node.core.pool_sync_message(PoolKind::FoundationBootstrap));
                let em_v_msg =
                    WireMessage::Gossip(node.core.pool_sync_message(PoolKind::EmissionValidators));
                let em_n_msg =
                    WireMessage::Gossip(node.core.pool_sync_message(PoolKind::EmissionNabla));
                for target_id in node.core.mesh().unwrap().forward_targets(&our_id) {
                    if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&target_id) {
                        let addr = to_socket_addr(&peer.address);
                        outbound.push((addr, airdrop_msg.clone()));
                        outbound.push((addr, dev_msg.clone()));
                        outbound.push((addr, deed_msg.clone()));
                        outbound.push((addr, dev_deed_msg.clone()));
                        outbound.push((addr, bootstrap_msg.clone()));
                        outbound.push((addr, foundation_msg.clone()));
                        outbound.push((addr, em_v_msg.clone()));
                        outbound.push((addr, em_n_msg.clone()));
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
                node.note_recently_detached(parent, until);
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
            // KI#48 (RULED 2026-09-25): a PARKED node has a tick source (its
            // P host) even though `has_upstream()` is false — it must NOT
            // self-originate on top of the host's tick, or `process_tick`'s
            // replay bound rejects every host tick as a backward step and the
            // node reads as a silent orphan with a frozen tick. `has_tick_source`
            // = seated OR parked, the one composition of `is_parked()`.
            if !node.core.tardis().unwrap().has_tick_source() {
                node.core.tardis_mut().unwrap().set_tick(now_secs, now_ms);
            }

            // ── Step 1b: root advertisement instant (KI#71) ──
            // A no-op (cached) when process_tick already advertised this tick
            // label; for a self-originating node this IS the instant — it samples
            // the root once and answers every queued §5.5 AuditRequest from the
            // same SMT borrow. Step 9 re-uses the same cached advert.
            if let Some((_, audit_responses)) = node.core.advertise_root() {
                push_audit_responses(&node.core, audit_responses, &mut outbound);
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
                            external_port: node.external_port,
                            downstream_count: node.core.tardis().unwrap().downstream_count() as u8,
                            nbc_bytes: node.own_nbc_bytes.clone(),
                            nbc_supporting_bytes: node.own_nbc_supporting_bytes(),
                            txid_service: node.core.smt().txid_mode().to_string(),
                            // §5.6a — tell this peer where we see it coming from.
                            observed_peer_ip: node.observed_sources.get(&peer.node_id).copied(),
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
                            external_port: node.external_port,
                            downstream_count: node.core.tardis().unwrap().downstream_count() as u8,
                            nbc_bytes: node.own_nbc_bytes.clone(),
                            nbc_supporting_bytes: node.own_nbc_supporting_bytes(),
                            txid_service: node.core.smt().txid_mode().to_string(),
                            // §5.6a — tell this peer where we see it coming from.
                            observed_peer_ip: node.observed_sources.get(&peer.node_id).copied(),
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
            // Excluded: `recently_detached_parents` (so voluntary rotation
            // actually moves the topology) and any peer with a request
            // already in flight (pending_attach dedup).
            if node.core.tardis().unwrap().needs_parent() {
                node.orphan_ticks += 1;
                // ── TWO-PASS ORPHAN RECOVERY (YPX-003 §2.15.2 'Recovery Placement Fix') ──
                // Pass 0 (strict): only a dc=1 parent is acceptable — filling
                //   it creates a writer, which is why it is preferred.
                // Pass 1 (relaxed): accept ANY open D slot. The spec's rule is
                //   "never stay orphan".
                //
                // The relaxed pass existed in the SIMULATOR (`sim.rs`,
                // `for pass in 0..2`) and in `recovery_candidate_acceptable`'s
                // unit tests, but NEVER in this node: every production
                // TardisAttachRequest hardcoded `prefer_writer: true`, and the
                // receiver accepts only `dc == 1` when it is set. Strict-only
                // recovery DEADLOCKS — when every dc=1 node is itself orphaned,
                // the orphan attaches to a parent with no upstream, gets no
                // grandpa tick, detaches at GRANDPA_MISS_DETACH_THRESHOLD, and
                // repeats forever while looking merely "intermittent" to peers
                // (YPX-003 §1.7.4, "treat as a node-killing bug"). Observed
                // live 2026-08-01: 8 of 10 nodes orphaned and cascading, both
                // dc=1 candidates orphans themselves.
                let prefer_writer_pass =
                    node.orphan_ticks <= axiom_nabla::constants::ORPHAN_STRICT_PASS_TICKS;
                if node.orphan_ticks == axiom_nabla::constants::ORPHAN_STRICT_PASS_TICKS + 1 {
                    log::warn!(
                        "[TARDIS-RELAX] orphaned {} ticks with no dc=1 parent — relaxing \
                         to accept any open D slot (YPX-003 §2.15.2 pass 1)",
                        node.orphan_ticks,
                    );
                }
                let has_children = node.core.tardis().unwrap().downstream_count() > 0;
                let mut sent_to = std::collections::HashSet::new();

                // Expire timed-out pending requests
                let current_tick = now_secs;
                node.pending_attach.retain(|_, tick_sent| {
                    current_tick.saturating_sub(*tick_sent) / TICK_INTERVAL_SECS < ATTACH_TIMEOUT_TICKS
                });

                // Canonical exclusion list (3 slots, FIFO). Was a single
                // Option, which cannot break a 2-cycle — leaving A excluded A,
                // then leaving B freed A again and the node ping-ponged.
                let excluded_parents: Vec<NodeId> = node.excluded_parents();

                // P1: tick-piggyback recovery candidates (§2.2). These are
                // TARDIS-internal — propagated via signed ticks, not gossip.
                // Belt-and-braces bound on the SEND side too. Even with the
                // list capped at source, an unbounded `for` over recovery
                // candidates is the wrong shape for a network send loop.
                let mut p1_sent = 0usize;
                for (candidate_nid, _slot) in node.core.tardis().unwrap()
                    .recovery_candidates().to_vec()
                    .into_iter()
                    .take(axiom_nabla::constants::TICK_SLOT_PIGGYBACK_MAX)
                {
                    if p1_sent >= axiom_nabla::constants::TICK_SLOT_PIGGYBACK_MAX { break; }
                    p1_sent += 1;
                    if candidate_nid == node.node_id || sent_to.contains(&candidate_nid) { continue; }
                    if node.pending_attach.contains_key(&candidate_nid) { continue; }
                    if excluded_parents.contains(&candidate_nid) { continue; }
                    // §5.6c lever 1(b): a probationary peer is never our upstream.
                    if node.upstream_candidate_probationary(&candidate_nid) { continue; }
                    let addr = node.core.mesh().unwrap().peer_by_id(&candidate_nid).map(|p| p.address.clone());
                    if let Some(address) = addr {
                        sent_to.insert(candidate_nid);
                        node.pending_attach.insert(candidate_nid, current_tick);
                        outbound.push((
                            to_socket_addr(&address),
                            WireMessage::TardisAttachRequest {
                                node_id: node.node_id,
                                external_port: node.external_port,
                                has_children,
                                prefer_writer: prefer_writer_pass,
                                nbc_bytes: node.own_nbc_bytes.clone(),
                                nbc_supporting_bytes: node.own_nbc_supporting_bytes(),
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
                    if excluded_parents.contains(&peer.node_id) { continue; }
                    // §5.6c lever 1(b): a probationary peer is never our upstream.
                    if node.upstream_candidate_probationary(&peer.node_id) { continue; }
                    if p2_sent >= 3 { break; }
                    sent_to.insert(peer.node_id);
                    node.pending_attach.insert(peer.node_id, current_tick);
                    outbound.push((
                        to_socket_addr(&peer.address),
                        WireMessage::TardisAttachRequest {
                            node_id: node.node_id,
                            external_port: node.external_port,
                            has_children,
                            prefer_writer: prefer_writer_pass,
                            nbc_bytes: node.own_nbc_bytes.clone(),
                            nbc_supporting_bytes: node.own_nbc_supporting_bytes(),
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

                // ── REATTACH / TREE MERGE (YPX-003 §2.16.5, KI#48) ──────────
                //
                // The one move that CREATES writers, and the only thing that
                // heals a degraded tree. A dc=0 leaf sitting under a dc=1 parent
                // moves to another dc=1 node:
                //     old parent  dc=1 -> dc=0   (was a reader, stays a reader)
                //     new parent  dc=1 -> dc=2   (becomes a WRITER)   net +1
                // The leaf then sits under a dc=2 parent and never moves again —
                // one-shot, and self-limiting: a healthy tree has ~0 dc=1 nodes
                // so this is inert; a degraded tree has many and it fires until
                // healed.
                //
                // This existed ONLY in nabla/src/sim.rs. The node never had it,
                // which is why a fragmented mesh could not merge: 5 orphan roots,
                // every free D slot inside their own subtrees.
                //
                // DISCOVERY IS SPEC-CONFORMANT, NOT THE SIM'S. `sim.rs` uses
                // `Mesh::find_reattach_target`, which reads
                // `known_nodes[..].has_d_open / open_slots` — GOSSIP-declared slot
                // state. §1.7 forbids exactly that for attach decisions and §1.7.4
                // calls crossing the boundary "a node-killing bug" (it caused the
                // 2026-05-29 cascade). So we do not consult gossip slot fields at
                // all: we send `TardisAttachRequest { prefer_writer: true }` to
                // peers from the mesh CONTACT LIST (addresses only — its
                // legitimate role) and let the RECEIVER decide from its own TARDIS
                // state. Its handler already accepts only when `dc == 1`
                // (`recovery_candidate_acceptable(dc, true)`), which IS the
                // reattach-target condition. Honest signal, no stale claims.
                //
                // Only dc=0 leaves reattach, so no subtree travels and no cycle
                // can be created by the move.
                let can_reattach = node.core.tardis().unwrap().downstream_count() == 0
                    && node.core.tardis().unwrap().upstream().is_some()
                    && node.core.tardis().unwrap().ticks_with_parent()
                        >= axiom_nabla::constants::REATTACH_STABILITY_TICKS
                    && node.reattach_pending.is_none();

                if can_reattach {
                    let my_up = node.core.tardis().unwrap().upstream().copied();
                    let peers: Vec<PeerInfo> = node.core.mesh().unwrap().active_peers().to_vec();
                    let mut sent = 0usize;
                    for peer in &peers {
                        if sent >= axiom_nabla::constants::REATTACH_MAX_PER_TICK { break; }
                        if peer.node_id == node.node_id { continue; }
                        if Some(peer.node_id) == my_up { continue; }
                        // §5.6c lever 1(b): never merge under a probationary peer.
                        if node.upstream_candidate_probationary(&peer.node_id) { continue; }
                        node.reattach_pending = Some((peer.node_id, now_secs));
                        outbound.push((
                            to_socket_addr(&peer.address),
                            WireMessage::TardisAttachRequest {
                                node_id: node.node_id,
                                external_port: node.external_port,
                                has_children: false,
                                prefer_writer: true, // dc==1 only — the merge move
                                nbc_bytes: node.own_nbc_bytes.clone(),
                                nbc_supporting_bytes: node.own_nbc_supporting_bytes(),
                            },
                        ));
                        sent += 1;
                        break; // one target at a time; a move is not a broadcast
                    }
                }
            }

            // Expire a reattach that drew no accept, so the node can try again.
            if let Some((_, sent_tick)) = node.reattach_pending {
                if now_secs.saturating_sub(sent_tick) / TICK_INTERVAL_SECS
                    >= ATTACH_TIMEOUT_TICKS
                {
                    node.reattach_pending = None;
                }
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
                            external_port: node.external_port,
                            downstream_count: node.core.tardis().unwrap().downstream_count() as u8,
                            nbc_bytes: node.own_nbc_bytes.clone(),
                            nbc_supporting_bytes: node.own_nbc_supporting_bytes(),
                            txid_service: node.core.smt().txid_mode().to_string(),
                            // §5.6a — tell this peer where we see it coming from.
                            observed_peer_ip: node.observed_sources.get(&peer.node_id).copied(),
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
                        // Send proactive attach response to the promoted peer.
                        // `pending: false` — this is the D seat; the child's
                        // `set_upstream` flips its Pending → Connected in place.
                        if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&pending_id) {
                            outbound.push((
                                to_socket_addr(&peer.address),
                                WireMessage::TardisAttachResponse {
                                    node_id: node.node_id,
                                    accepted: true,
                                    pending: false,
                                    downstream_count: node.core.tardis().unwrap().downstream_count(),
                                    referrals: vec![],
                                    nbc_bytes: node.own_nbc_bytes.clone(),
                                    nbc_supporting_bytes: node.own_nbc_supporting_bytes(),
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
                                node.note_recently_detached(parent, exclude_until);
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

            // (Step 6b, the §32 merge-quarantine expiry — restore `Tainted`,
            // flood `MergeResolved` — was deleted 2026-10-02: ForkSettlement
            // §9r-E4 / D-E4-1. Nothing writes `Tainted`; the timer acted on
            // nothing. A view never holds anyone.)

            // ── Step 6c: KI#42 bloom-saturation watch ──
            // Both SMT blooms are LIFETIME filters with a fixed ceiling and no
            // rollover, so fill only ever climbs. Warn once per threshold crossing
            // rather than every tick. The consumed-state filter is the serious one:
            // its false positives fail CLOSED at the A12 anti-rollback gate, so
            // saturation there refuses legitimate registrations.
            // Fix plan: AXIOM_DESIGN_NablaAntiEntropy.md §12.
            {
                let consumed_fill = node.core.smt().consumed_bloom_fill_ratio();
                let txid_fill = node.core.smt().txid_bloom_fill_ratio();
                let worst = consumed_fill.max(txid_fill);
                // Thresholds as tenths, so each crossing warns exactly once.
                let bucket = (worst * 10.0) as u64;
                if bucket >= 5 && bucket > node.bloom_fill_warn_bucket {
                    node.bloom_fill_warn_bucket = bucket;
                    warn!("[BLOOM-FILL] consumed={:.1}% (fpr {:.4}%) txid={:.1}% (fpr {:.4}%) \
                           — lifetime filters, they do not roll over. See KI#42 / \
                           NablaAntiEntropy §12. Past 100% the consumed-state filter \
                           starts refusing LEGITIMATE registrations.",
                        consumed_fill * 100.0, node.core.smt().consumed_bloom_fpr() * 100.0,
                        txid_fill * 100.0, node.core.smt().txid_bloom_fpr() * 100.0);
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
                // YPX-022 §2.1.2a item 2 (KI#205) — evict claims whose send has
                // aged past the recall window (`claim_is_stale`; account-keyed
                // `recall_init_window_high`). The old fixed 17,280-tick TTL
                // evicted BEFORE the window opened at 18,000 — the hole.
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
            // KI#71: the (tick, root, sig) comes from the ONE advertisement
            // builder (`advertise_root`), never a fresh sample — this probe is the
            // only advertisement a self-originating node makes, and a second
            // sampling under the same tick label is exactly what manufactured the
            // honest-writer SELF-CONTRADICTION (two signed roots for one tick).
            if tick_count > 0 && tick_count.is_multiple_of(ANTI_ENTROPY_INTERVAL) {
                let (advert, audit_responses) = node
                    .core
                    .advertise_root()
                    .expect("TARDIS is initialised at startup (init_tardis)");
                push_audit_responses(&node.core, audit_responses, &mut outbound);
                let node_pk = node.node_id;
                let gossip = WireMessage::Gossip(GossipMessage::TickHash {
                    tick: advert.tick,
                    root_hash: advert.root_hash,
                    node_pk,
                    signature: advert.signature,
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
                // KI#82 — fee-ledger anti-entropy: advertise our per-bucket
                // txid_records digest to the SAME rotating peer, so a recorder that
                // missed a §19.6 fee-record gossip converges over the rotation
                // (AXIOM_DESIGN_NablaAntiEntropy.md §13). RECORDING (hashmap) nodes
                // only — bloom nodes hold no records.
                if node.core.smt().txid_mode()
                    == axiom_nabla::bloom::TxidServiceMode::Hashmap
                {
                    let buckets = node
                        .core
                        .smt()
                        .txid_bucket_digests(axiom_nabla::constants::TXID_AE_BUCKET_TICKS);
                    if !buckets.is_empty() && !peers.is_empty() {
                        let msg = WireMessage::TxidAeDigest { from: node_pk, buckets };
                        if let Some(peer) =
                            node.core.mesh().unwrap().peer_by_id(&peers[peer_idx % peers.len()])
                        {
                            outbound.push((to_socket_addr(&peer.address), msg));
                        }
                    }
                    // KI#84 — FOB ledger AE: advertise our plus+minus ledger
                    // digest to the same rotating peer. A recorder that missed a
                    // tranche (PLUS) or a claim sweep (MINUS) converges over the
                    // rotation — pools are derived from the two sets, so union
                    // heals them. Recording (hashmap) nodes only.
                    if !peers.is_empty() {
                        let digest = node.core.fob_ledger_digest();
                        let msg = WireMessage::FobLedgerDigest { from: node_pk, digest };
                        if let Some(peer) =
                            node.core.mesh().unwrap().peer_by_id(&peers[peer_idx % peers.len()])
                        {
                            outbound.push((to_socket_addr(&peer.address), msg));
                        }
                    }
                }
                // KI#170 — the VBC registry AE runs on EVERY node, not only recorders:
                // every node stamps and every node refuses a second live stamp. A digest
                // only makes its receiver push entries back, so a node that never
                // advertises never learns (measured 2026-09-14: a stamp reached the two
                // recorders and no bloom node in 6 minutes). Same rotating peer.
                // ForkSettlement R50 (wave 4a): a SIGNED request carrying our `have`
                // list; the peer answers with one page of what we lack.
                if !peers.is_empty() {
                    let peer_id = peers[peer_idx % peers.len()];
                    let addr = node.core.mesh().unwrap().peer_by_id(&peer_id).map(|p| to_socket_addr(&p.address));
                    if let Some(addr) = addr {
                        let reg_msg = build_directory_request(&mut node, peer_id);
                        outbound.push((addr, reg_msg));
                    }
                }
            }

            // ── Step 9a: Fork Settlement §9o [R58/R59] (W1) — R48 record-AE walk ──
            // EVERY tick: one step of the per-boot R51 walk over the peers whose
            // NBC this node verified (a peer we cannot authenticate is a peer
            // whose answers we would refuse). Aborts timed-out descents
            // (counted) and starts at most ONE new descent — never a second
            // one with a peer that has one in flight. A converged pair costs
            // one ask/answer (the root hashes match).
            {
                let peers: Vec<NodeId> = node
                    .core
                    .mesh()
                    .map(|m| m.peer_ids())
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|id| node.verified_nbcs.contains_key(id))
                    .collect();
                // Fable 2026-10-01 F-5: the connected peers whose verified NBC
                // names a PINNED genesis Nabla key are walked first each window
                // (an ORDER only — zero genesis peers ⇒ the old walk exactly).
                let genesis: Vec<NodeId> = peers
                    .iter()
                    .filter(|id| node.verified_nbcs.get(*id).is_some_and(cc::nbc_is_pinned_genesis))
                    .copied()
                    .collect();
                let (me, now) = (node.node_id, node.virtual_secs);
                for (peer, msg) in node.core.record_ae_tick(me, &peers, &genesis, now) {
                    if let Some(addr) = node.core.mesh().and_then(|m| m.peer_by_id(&peer)).map(|p| to_socket_addr(&p.address)) {
                        outbound.push((addr, msg));
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

            // ── Step 9c: FOB (§3/§4) tranche authoring ──
            // A RECORDING node (only it holds the convergent accumulator) that is
            // a committee mover for the current epoch builds + signs + broadcasts
            // its OWN single-signer partial statement (§3 "no vote, no
            // coordination" — every mover derives the identical entries and signs
            // alone; the receive path aggregates 3 into a full committee). The
            // amount is Core's `compute_fob_tranche`; balance_used is the
            // convergent net accumulator DEBITED (via the pool's tranched_total)
            // when the statement is later applied — no mint here. Tick-derived
            // epoch boundary, no timers.
            {
                use axiom_nabla::fob;
                // Contribution emission epoch roll — EVERY node, idempotent per
                // epoch, the one rule from the same inputs (design §4.3). The
                // balances then ride the PoolSync heartbeat.
                if let Some(roll) = node.core.emission_maybe_roll() {
                    info!(
                        "[EMISSION-ROLL] epoch={} share_v={} share_n={} draw_v={} draw_n={} pool_v={} pool_n={} deed={}",
                        roll.epoch, roll.share_v, roll.share_n, roll.draw_v, roll.draw_n,
                        node.core.emission().validators.balance(), node.core.emission().nabla.balance(),
                        node.core.deed_pool().balance(),
                    );
                }
                let is_recording = node.core.smt().txid_mode()
                    == axiom_nabla::bloom::TxidServiceMode::Hashmap;
                // §6: epoch = the SHARED TARDIS tick (unix seconds) bucketed, so
                // every mover computes the identical number. Trigger on epoch
                // ADVANCE — the local per-boot `tick_count` would give each node
                // a different epoch (they boot at different times) and the 3
                // statements would never aggregate.
                let tardis_tick =
                    node.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
                // §10.2a: ONE codepath for BOTH funds — the class is a data bit.
                // Dev fund and real fund each use their own epoch cadence
                // (`fob_epoch_ticks`), so the dev fund tranches frequently for
                // testing while the real fund waits the week. `continue` skips a
                // fund that has not crossed its own boundary.
                for is_dev in [false, true] {
                  // KI#165: the divisor is the register PROJECTED to a tick-VALUE span (unix
                  // secs), the unit `tardis_tick` is in — the raw COUNT made the epoch 5× short.
                  let epoch_ticks = axiom_nabla::constants::fob_epoch_span_secs(is_dev);
                  let epoch = fob::epoch_id(tardis_tick, epoch_ticks.max(1));
                  if is_recording
                    && epoch_ticks > 0
                    && tardis_tick > 0
                    && epoch != node.fob_last_epoch[is_dev as usize]
                  {
                    node.fob_last_epoch[is_dev as usize] = epoch;
                    // Bound the aggregation buffer: drop resolved/older-epoch state.
                    node.fob_pending.retain(|_, p| p.epoch_id >= epoch && !p.resolved);
                    if let Some(att) = node.build_fob_oods_attestation() {
                        let my_pk = att.nabla_node_pk;
                        let eligible = axiom_core_logic::validation::fob_mover_eligible(
                            att.oods_size as u64,
                            att.baseline_size as u64,
                        );
                        // Roster = the RECORDING mover set (§3): only recording
                        // nodes hold the accumulator, so the committee is drawn
                        // from them — else a mixed committee never assembles
                        // FOB_COMMITTEE_SIZE sigs. Per-peer §5 OODS-eligibility is
                        // enforced by the receiver's judge; this only decides
                        // whether *I* attempt.
                        let roster = node.fob_recording_roster(my_pk);
                        let committee =
                            fob::rank_committee(&roster, epoch, fob::FOB_COMMITTEE_SIZE);
                        let in_committee = committee.contains(&my_pk);
                        // Diagnostic: one line per epoch advance on a recorder, so
                        // an idle FOB path is explainable (eligible? committee?
                        // earners?) without guessing.
                        info!(
                            "[FOB-AUTHOR] class={} epoch={} recorders={} eligible={} \
                             in_committee={} oods={} baseline={} earners={}",
                            if is_dev { "dev" } else { "real" },
                            epoch,
                            roster.len(),
                            eligible,
                            in_committee,
                            att.oods_size,
                            att.baseline_size,
                            node.core.smt().validator_ids_with_earnings().len()
                        );
                        if eligible && in_committee {
                            // One entry per validator whose Fee pool is EMPTY and
                            // whose available net clears the tranche floor.
                            let mut entries: Vec<fob::TrancheEntry> = Vec::new();
                            for vid in node.core.smt().validator_ids_with_earnings() {
                                if node.core.fob_pool_balance(&vid, is_dev) != 0 {
                                    continue; // refill-requires-empty
                                }
                                // Settled watermark = floor of the epoch TWO back
                                // `(epoch-2)*epoch_len` — a value every recorder
                                // authoring `epoch` derives identically, with two
                                // full epochs of replication margin below it, so
                                // everything counted is settled on all recorders
                                // whose fee ledger actually received it. §3
                                // convergence. (NOTE: a persistent txid_records
                                // replication gap — no anti-entropy backstop on
                                // the §19.6 fee ledger — can STILL desync the
                                // accumulator regardless of margin; that is KI#82,
                                // separate from FOB. The margin only removes the
                                // lag-band source of divergence.)
                                let watermark =
                                    epoch.saturating_sub(2).saturating_mul(epoch_ticks);
                                let available = node.core.fob_available(&vid, is_dev, watermark);
                                let amount =
                                    axiom_core_logic::validation::compute_fob_tranche(available);
                                if amount == 0 {
                                    continue; // rule-3 skip
                                }
                                entries.push(fob::TrancheEntry {
                                    pool_id: vid,
                                    balance_used: available,
                                    amount,
                                });
                            }
                            if !entries.is_empty() {
                                let payload =
                                    fob::tranche_statement_payload(epoch, is_dev, &entries);
                                let statement_sig = node.core.signer().sign(&payload);
                                let mine = fob::FobMoverSig {
                                    att: att.clone(),
                                    statement_sig,
                                };
                                let gossip = WireMessage::Gossip(GossipMessage::FobTranche {
                                    epoch_id: epoch,
                                    is_dev,
                                    entries: entries.clone(),
                                    movers: vec![mine],
                                });
                                if let Some(mesh) = node.core.mesh() {
                                    for peer in mesh.active_peers() {
                                        outbound.push((
                                            to_socket_addr(&peer.address),
                                            gossip.clone(),
                                        ));
                                    }
                                }
                                // Seed my own aggregation so I complete when the
                                // other two movers' partials arrive.
                                let vm = fob::VerifiedMover {
                                    node_pk: my_pk,
                                    oods_size: att.oods_size as u64,
                                    baseline: att.baseline_size as u64,
                                };
                                let pend = node
                                    .fob_pending
                                    .entry(payload)
                                    .or_insert_with(|| FobPendingStatement {
                                        epoch_id: epoch,
                                        entries: entries.clone(),
                                        movers: Vec::new(),
                                        resolved: false,
                                    });
                                if !pend.movers.iter().any(|e| e.node_pk == my_pk) {
                                    pend.movers.push(vm);
                                }
                                node.fob_tranches_authored += 1;
                                let dbg_total: u64 =
                                    entries.iter().map(|e| e.amount).sum();
                                info!(
                                    "[FOB] authored tranche epoch={} pools={} total={} payload={:02x}{:02x}{:02x}{:02x}",
                                    epoch,
                                    entries.len(),
                                    dbg_total,
                                    payload[0], payload[1], payload[2], payload[3],
                                );
                            }
                        }
                    }
                  }
                } // for is_dev in [false, true] (§10.2a one codepath, both funds)
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
                        // KI#81 — recover at the reader's CLEAN PREFIX, never at the
                        // sampled seq. `audit_deep_and_recover`'s own comment explains
                        // why: the sampled seq is usually PAST the real break (the
                        // reader stops early, so later samples read missing), and
                        // truncating there either keeps the corrupt record (re-flag
                        // loop) or — when the reference list is wrong — destroys
                        // GOOD records the file still serves.
                        warn!("WAL audit: corruption detected at sequence {} — running deep-scan recovery", seq);
                        match node.core.wal_mut().audit_deep_and_recover() {
                            Ok(Some(clean_len)) => {
                                warn!(
                                    "WAL audit: recovered at clean prefix {}; subsequent ticks \
                                     rebuild from peer gossip (RangeSync). Repeat truncations \
                                     are a hardware-error signal.",
                                    clean_len,
                                );
                            }
                            Ok(None) => {
                                warn!(
                                    "WAL audit: recent sample flagged seq {} but the deep scan \
                                     verified the file CLEAN — transient mismatch, nothing \
                                     truncated.",
                                    seq,
                                );
                            }
                            Err(e) => {
                                warn!("WAL audit: deep-scan recovery failed: {}", e);
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
            //
            // ghost audit G11. Step 10 above RECOVERS (truncate_at, the KI#4
            // fix); this one only logs — it takes `&self` and structurally
            // cannot. That is the exact pre-KI#4 shape, left unfixed in the
            // sibling.
            //
            // It matters more than "a duplicate detector", because the two
            // cover different ranges: `audit_recent` samples ONE entry from the
            // last `WAL_AUDIT_WINDOW` entries, so it never reaches an old one.
            // `audit_deep` samples across the WHOLE file. A corrupted OLD entry
            // is therefore detectable ONLY here — and alpha found exactly that
            // on 2026-07-31 (`corrupted entries found: [15, 20]`, low sequence
            // numbers) with nothing done about it.
            //
            // Recovery WAS deliberately withheld while KI#74 was open: the
            // checksum machinery was reporting corruption on a healthy mesh
            // (19 warnings per roll), and truncating on a false positive would
            // have turned a bug in our own sequence accounting into real data
            // loss. KI#74 is fixed and a full 10-node roll now reports ZERO
            // warnings, so the signal is trustworthy and recovery is wired
            // (2026-08-07). `wal_deep_scan_corrupt` now counts RECOVERIES.
            if tick_count > 0 && tick_count.is_multiple_of(WAL_DEEP_SCAN_INTERVAL_TICKS) {
                match node.core.wal_mut().audit_deep_and_recover() {
                    Ok(Some(seq)) => {
                        node.wal_deep_scan_corrupt =
                            node.wal_deep_scan_corrupt.saturating_add(1);
                        warn!("WAL deep scan: recovered by truncating at sequence {} \
                               (cumulative recoveries={})",
                              seq, node.wal_deep_scan_corrupt);
                    }
                    Ok(_) => {
                        info!("WAL deep scan: all sampled entries clean");
                    }
                    Err(e) => {
                        warn!("WAL deep scan error: {}", e);
                    }
                }
            }

            // ── KI#43a — drain buffered consumption events to the exact record ──
            // Every tick, before anything else that could grow the buffer
            // further. No-op on bloom-mode nodes.
            node.drain_consumed_exact();

            // ── KI#43b — pump pending heal adjudications (§12.4.4) ──
            // Re-query every recording peer each tick until the barrier
            // settles. Idempotent on the peer side; traffic exists only
            // while a consumed-bloom hit is pending (~1-in-8000 heals).
            {
                let pending: Vec<(axiom_nabla::types::StateId, u64)> = node.adjudications.iter()
                    .filter(|(_, a)| a.verdict.is_none())
                    .map(|(sid, a)| (*sid, a.born_tick))
                    .collect();
                if !pending.is_empty() {
                    let rec_peers: Vec<_> = node.core.mesh()
                        .map(|m| m.peer_ids().iter()
                            .filter_map(|id| m.peer_by_id(id))
                            .filter(|p| p.txid_service == "hashmap")
                            .map(|p| to_socket_addr(&p.address))
                            .collect())
                        .unwrap_or_default();
                    let needed = axiom_nabla::constants::RECORDING_NODES_TOTAL
                        .saturating_sub(1);
                    if rec_peers.len() < needed && tick_count.is_multiple_of(12) {
                        warn!("[KI#43b] {} adjudication(s) pending but only {} of {} \
                               recording peers known — barrier cannot settle (fail-closed)",
                            pending.len(), rec_peers.len(), needed);
                    }
                    for (sid, born_tick) in pending {
                        for addr in &rec_peers {
                            outbound.push((*addr, WireMessage::ExactConsumedQuery {
                                from: Some(node.node_id),
                                state_id: sid,
                                born_tick, // §12.4.4 item 4 — 0 iff birth unknown
                            }));
                        }
                    }
                }
            }

            // ── KI#63 §3.3 — AE stall alarm ──
            //
            // Anti-entropy can be DEAD while looking busy. On 2026-08-04 it
            // rejected 115,054 of 115,054 entries over six hours — every node
            // refusing every peer — and nothing anywhere said so. The soak
            // printed "Real protocol: 100.00%" and `diverged_stuck_count` read
            // 0. An outage must never again be able to read as a healthy run.
            //
            // Applied NOTHING while rejecting a meaningful number is the
            // signal; a quiet mesh (both zero) is silent by construction.
            if tick_count > 0 && tick_count.is_multiple_of(AE_STALL_ALARM_INTERVAL_TICKS) {
                let (ap, rj, fk) = (node.ae_applied_window, node.ae_rejected_window, node.ae_forks_window);
                if ae_stall_detected(ap, rj, fk) {
                    // KI#63(c): the verdict as a COUNTER, not only a log line.
                    node.ae_stall_windows = node.ae_stall_windows.saturating_add(1);
                    error!(
                        "[AE-STALL] anti-entropy applied NOTHING in the last {} ticks while \
                         rejecting {} entries. Replication is not converging — this node is \
                         refusing every peer, or every peer is refusing it. Check for a \
                         partition, a stale advertised address, or same-seq forks (KI#65). \
                         This is the condition that went unreported for six hours on \
                         2026-08-04.",
                        AE_STALL_ALARM_INTERVAL_TICKS, rj,
                    );
                } else if rj > 0 {
                    debug!("[AE-HEALTH] applied={ap} rejected={rj} forks={fk} over {} ticks \
                            (applied=0 on a CONVERGED mesh is normal — nothing new to apply)",
                        AE_STALL_ALARM_INTERVAL_TICKS);
                }
                node.ae_applied_window = 0;
                node.ae_rejected_window = 0;
                node.ae_forks_window = 0;
            }

            // ── GUIDE §6.1.2 own-address change — REMOVED by §5.6a-bis ──
            //
            // A ~110-line block lived here: every ADDRESS_RECHECK_INTERVAL_TICKS
            // it re-resolved our own `--advertise` NAME off the node lock
            // (KI#92 #2), and on a different answer it dropped ALL TARDIS links,
            // set the new address, dis-armed, and re-announced (KI#64, written
            // after the 2026-08-04 outage where every node advertised a name
            // pinned in /etc/hosts to an address the machine no longer had).
            //
            // It is gone because the problem it solved cannot occur any more,
            // not because it was skipped. The block existed to keep a
            // SELF-ASSERTED address fresh. Under §5.6a-bis a node asserts no
            // address at all: peers compose ours as `observed source IP :
            // declared external_port` on every Hello / TardisAttachRequest they
            // receive from us. Our IP moving is therefore detected BY THE PEERS,
            // from the connection itself, with no self-monitoring, no DNS, and
            // no re-resolve on the tick path — which also retires the blocking
            // `getaddrinfo` this code had to work so hard to keep off the mutex.
            //
            // Residual, stated rather than hidden: peers refresh their composed
            // record when we next CONTACT them, so a node that moves and then
            // sends nothing stays stale in their tables until it speaks. The
            // tick loop's ordinary Hello/attach traffic closes that in seconds;
            // there is no silent multi-hour window like 2026-08-04, because the
            // refresh no longer depends on anyone noticing anything.
            //
            // ⚠ Do NOT re-add a self-address recheck here. Re-resolving a name
            // we no longer advertise would compare our bind address against
            // nothing meaningful, and the "drop ALL TARDIS links" response was
            // only ever safe because a stale self-assertion made those links
            // provably dead. They are not dead now.

            // ── Step 10b: KI#42 — issue a Bootstrap StatePull until we are armed ──
            //
            // Nothing in production ever sent a Bootstrap StatePullRequest. The
            // serve path, the response handler and the flat-bloom re-arm were all
            // written, but the only caller was a manual example
            // (`examples/ki34_wi1_recover.rs`) — so a fresh or wiped node never
            // re-armed automatically, and the WalVerify pull that IS sent
            // deliberately carries no recovery state ("WI1: WAL-verify carries no
            // recovery state"). That is the missing trigger behind KI#42's bootstrap
            // gap, and it is also what would have made the serve-gate a PERMANENT
            // refusal rather than a startup delay.
            //
            // Ask once per tick while unarmed, then stop: an armed node never sends
            // this again, so steady-state cost is zero. Advertise the eras we already
            // hold so the peer sends only what we lack (an era is ~1.7 MiB against a
            // 5 MiB cap, so a mature chain converges over several pulls).
            if !node.anti_rollback_armed {
                // KI#79 — count the round and stamp the episode start. The
                // counter is what separates an 8-hour livelock from a healthy
                // 2-minute re-arm; both looked identical before it existed.
                node.unarmed_rounds += 1;
                if node.unarmed_since_tick == 0 {
                    node.unarmed_since_tick =
                        node.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
                }
                {
                    // Coalesced: first fire at the bound, then one heartbeat per
                    // escalation period (~5 min) instead of every 5s round —
                    // 2,254 lines during gamma's livelock carried ~4 facts.
                    let bound = axiom_nabla::constants::UNARMED_ESCALATION_ROUNDS;
                    let r = node.unarmed_rounds;
                    if r > bound && (r - bound - 1) % bound == 0 {
                        warn!(
                            "[KI#79] UNARMED for {} consecutive round(s) (episode began \
                             tick {}) — still refusing all registrations; the retry is \
                             NOT converging (next heartbeat in {} rounds)",
                            r, node.unarmed_since_tick, bound,
                        );
                    }
                }
                let have_era_ids: Vec<u64> = node
                    .core
                    .smt()
                    .txid_chain()
                    .metadata()
                    .iter()
                    .map(|m| m.era_id)
                    .collect();
                let req = WireMessage::StatePullRequest {
                    mode: axiom_nabla::types::StatePullMode::Bootstrap,
                    from: Some(node.node_id),
                    our_root_hash: node.core.smt().root_hash(),
                    from_tick: 0,
                    // Entries carry TARDIS ticks; `tick_count` is this loop's
                    // local iteration counter, so using it here filtered out
                    // every entry a peer held. Bootstrap wants everything —
                    // the byte cap bounds the response, not the tick range.
                    to_tick: u64::MAX,
                    section_hash: None,
                    have_era_ids,
                    // Advertise the consumed eras we hold, so the peer sends only
                    // what we lack and we converge toward COMPLETE over pulls.
                    have_consumed_era_ids: node.core.smt().consumed_era_ids(),
                };
                // Rotate over peers so one unresponsive or hostile peer cannot hold
                // us unarmed — the same cursor discipline as §5.5 anti-entropy.
                let peers: Vec<_> = node
                    .core
                    .mesh()
                    .map(|m| m.peer_ids())
                    .unwrap_or_default();
                if peers.is_empty() {
                    debug!("[BOOTSTRAP-PULL] unarmed but no peers known yet — waiting");
                } else {
                    let idx = (node.ae_peer_cursor as usize) % peers.len();
                    node.ae_peer_cursor = node.ae_peer_cursor.wrapping_add(1);
                    if let Some(peer) = node.core.mesh().and_then(|m| m.peer_by_id(&peers[idx])) {
                        info!("[BOOTSTRAP-PULL] unarmed — requesting anti-rollback state \
                               from peer {:?} ({} of {})", peer.address, idx + 1, peers.len());
                        outbound.push((to_socket_addr(&peer.address), req));
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
                        from: Some(node.node_id),
                        our_root_hash: our_root,
                        from_tick: from,
                        to_tick: wal_seq,
                        section_hash: Some(our_hash),
                        // WalVerify is a targeted section check; era history is not
                        // part of its contract, so advertise nothing and get nothing.
                        have_era_ids: Vec::new(),
                        have_consumed_era_ids: Vec::new(),
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
        // Dev-only flood chaos (feature `flood-chaos`, ForkSettlement §9o live gate): drop /
        // hold the named wallets' floods + head-AE entries, then append floods whose `hold`
        // line was removed (newest first — the reorder). OUTSIDE the node lock; record-AE and
        // ForkBan are never touched (`flood_chaos::tests`).
        #[cfg(feature = "flood-chaos")]
        let outbound = {
            let mut o = axiom_nabla::flood_chaos::filter_outbound(outbound);
            o.extend(axiom_nabla::flood_chaos::take_released());
            o
        };

        // Send outbound messages (outside lock) — KI#92: through the ONE
        // dispatcher both loops share. The drained envelopes' replies first
        // (each on its own inbound socket), then the tick's own traffic.
        for (envelope, responses) in &drained_replies {
            #[cfg(feature = "flood-chaos")]
            let responses = &axiom_nabla::flood_chaos::filter_outbound(responses.clone());
            dispatch_outbound(transport.as_ref(), &state, Some(envelope), responses, "tick_loop");
        }
        dispatch_outbound(transport.as_ref(), &state, None, &outbound, "tick_loop");

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
    let mut node = state.lock();
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

/// KI#92 (2026-10-01) — THE one outbound dispatcher, used by BOTH send loops
/// (`recv_loop` and `tick_loop`; they were drifted duplicates — the tick loop
/// lacked the `is_inbound_reply` branch and re-dialed a client's ephemeral port).
/// Always called OUTSIDE the node lock: `handle_message` never writes a socket
/// (zero `send_reply(` in its body, pinned by
/// `ki92_handle_message_never_writes_a_socket_under_the_node_lock`), it RETURNS
/// its replies, so a client that never reads costs one off-lock write timeout
/// instead of pinning the node mutex.
///
/// - `reply_to` = the envelope whose handler produced `outbound` (None for the
///   tick's own traffic). Entries addressed to its `peer` while it still holds
///   its socket are written ON that socket (`send_reply`), FIRST and in Vec
///   order — per-connection reply order is preserved, and a client is not kept
///   waiting behind mesh floods (before KI#92 the reply was written before any
///   other send).
/// - A failed reply write shuts that socket (`send_reply`) and is counted; it is
///   NOT re-queued (the pre-KI#92 in-handler fallback re-wrote it on the same
///   socket: a second stall and a possible duplicate frame).
/// - Critical messages (Tick, Approval, Attach*, Detach) retry with backoff;
///   other forwards pass the KI#37 storm breaker.
/// - Failures are counted per peer (`transport_send_failures_per_peer`,
///   `E_NABLA_TRANSPORT_SEND_FAILED`, DEBUG — see KI#24 for why not WARN).
fn dispatch_outbound(
    transport: &dyn Transport,
    state: &Arc<PlMutex<NablaNodeState>>,
    reply_to: Option<&Envelope>,
    outbound: &[(std::net::SocketAddr, WireMessage)],
    site: &'static str,
) {
    let reply_env = |addr: &std::net::SocketAddr| reply_to.filter(|env| is_inbound_reply(addr, env));
    let replies = outbound.iter().filter(|(a, _)| reply_env(a).is_some());
    let others = outbound.iter().filter(|(a, _)| reply_env(a).is_none());
    for (addr, msg) in replies.chain(others) {
        let send_failed = if let Some(env) = reply_env(addr) {
            match axiom_nabla::transport::send_reply(env, msg) {
                Ok(()) => false,
                Err(e) => {
                    debug!("[E_NABLA_TRANSPORT_SEND_FAILED] {site} reply on inbound socket to {addr} \
                            failed: {e} (connection shut; not re-queued)");
                    true
                }
            }
        } else if is_critical_message(msg) {
            !send_with_retry(transport, *addr, msg, 2)
        } else if !storm_admit_forward(state) {
            // KI#37 storm shed — not a transport failure, not counted as one.
            continue;
        } else {
            match transport.send(*addr, msg) {
                Ok(()) => false,
                Err(e) => {
                    // A genuinely-unreachable peer (down / restarting) —
                    // transient, recovers via cached-conn eviction.
                    debug!("[E_NABLA_TRANSPORT_SEND_FAILED] {site} send to {addr} failed: {e} \
                            (transport will recover via cached-conn eviction)");
                    true
                }
            }
        };
        if send_failed {
            let mut node = state.lock();
            *node.transport_send_failures_per_peer.entry(addr.to_string()).or_insert(0) += 1;
        }
    }
}

/// ForkSettlement R50 (wave 4a) — answer a witness-directory AE REQUEST, or
/// refuse it (counted, `vbc_directory_ae_refused`): oversize `have` list →
/// unknown sender (no verified NBC) → bad signature over `(from, nonce, have)`
/// → replayed nonce / over the per-`from` budget. Returns the SIGNED reply page
/// — the records this node holds that `have` lacks — or `None` (refused, or
/// nothing to send). The caller addresses it to `peer_by_id(from)`.
fn answer_directory_request(
    state: &mut NablaNodeState,
    from: &NodeId,
    nonce: u64,
    have: &[[u8; 32]],
    sig: &[u8],
) -> Option<WireMessage> {
    use axiom_nabla::vbc_directory as dir;
    let auth = if have.len() > dir::MAX_DIRECTORY_HAVE_LEN {
        Err(dir::AeRefusal::Oversize)
    } else {
        let pk = state.verified_nbcs.get(from).and_then(nbc_ed25519_pk);
        let now = state.virtual_secs;
        dir::verify_ae_signature(pk, dir::DIRECTORY_AE_KIND_HAVE, from, nonce, &dir::have_body_hash(have), sig)
            .and_then(|()| state.directory_ae.admit_request(*from, nonce, now))
    };
    if let Err(r) = auth {
        dir::note_ae_refused(r, from);
        return None;
    }
    let entries = state.core.vbc_directory().page_missing_from(have);
    if entries.is_empty() {
        return None;
    }
    let me = state.node_id;
    let payload = axiom_nabla::crypto::ae_sign_payload(
        dir::DIRECTORY_AE_KIND_ENTRIES, &me, nonce, &dir::entries_body_hash(&entries),
    );
    let sig = state.core.signer().sign(&payload);
    Some(WireMessage::VbcRegistrationEntries { from: me, nonce, entries, sig })
}

/// ForkSettlement R50 (wave 4a) — build this node's SIGNED directory AE request
/// to `to`: its sorted `have` list under a fresh nonce (recorded, so only the
/// reply to it is accepted). Called by the tick loop's anti-entropy round.
fn build_directory_request(state: &mut NablaNodeState, to: NodeId) -> WireMessage {
    use axiom_nabla::vbc_directory as dir;
    let have = state.core.vbc_directory().sorted_keys();
    let now = state.virtual_secs;
    let nonce = state.directory_ae.issue(to, now);
    let me = state.node_id;
    let payload = axiom_nabla::crypto::ae_sign_payload(
        dir::DIRECTORY_AE_KIND_HAVE, &me, nonce, &dir::have_body_hash(&have),
    );
    let sig = state.core.signer().sign(&payload);
    WireMessage::VbcRegistrationDigest { from: me, nonce, have, sig }
}

/// ForkSettlement R42 (wave 4a) — the result of a witness-directory
/// verification run OFF the node lock, handed to the locked `handle_message`
/// through `NablaNodeState::directory_precheck` (set and cleared by
/// `recv_loop` in one lock scope).
#[derive(Debug)]
enum DirectoryPrecheck {
    /// `RegisterVbcRequest`: the certificate stamped by THIS node (from the
    /// declared balance — `register_vbc_core` proves that balance against the
    /// head before recording) and admitted or refused. `None` = this node holds
    /// no NBC to anchor a stamp to.
    Register {
        vbc_hash: [u8; 32],
        verdict: Option<Result<axiom_nabla::vbc_directory::VerifiedDirectoryEntry, axiom_nabla::vbc_directory::DirectoryRefusal>>,
    },
    /// `VbcRegistrationEntries`: an AUTHENTICATED reply to a nonce this node
    /// issued; `verified` = the records that passed `admit` (refusals counted
    /// there). Held keys were skipped before any verification.
    Entries { from: NodeId, nonce: u64, verified: Vec<axiom_nabla::vbc_directory::VerifiedDirectoryEntry> },
}

/// ForkSettlement R42 + R50 (wave 4a) — run the SPHINCS+-heavy witness-directory
/// verification WITHOUT the node lock (the pattern the retired `prelock_hal_verify` set, §9q): a
/// directory bundle is up to 3 × (3 + 30) SPHINCS+ checks, and under the lock
/// that would stall the TARDIS tick loop on a flood of junk bundles. Brief
/// locks take only snapshots (held keys, NBC bytes, signer, the sender's NBC
/// key) and the R50 reply ledger.
///
/// `verify` is `vbc_directory::DIRECTORY_VERIFIER` in production (`recv_loop`);
/// tests pass a fixture verifier (no unit test can root-sign a VBC).
fn prelock_directory_verify(
    state: &Arc<PlMutex<NablaNodeState>>,
    envelope: &Envelope,
    verify: axiom_nabla::vbc_directory::DirectoryVerifier,
) -> Option<DirectoryPrecheck> {
    use axiom_nabla::vbc_directory as dir;
    match &envelope.message {
        WireMessage::RegisterVbcRequest(req) => {
            let vbc = &req.vbc;
            if vbc.nabla_registration.is_some() {
                return None; // register_vbc_core refuses a stamped presentation
            }
            let wallet_pk: [u8; 32] = vbc.subject_pubkey_ed25519.as_slice().try_into().ok()?;
            let vbc_hash = axiom_core_logic::compute::compute_vbc_signing_payload(vbc);
            // Only the certificate's own stake key can make this node verify.
            let req_payload = axiom_core_logic::compute::compute_vbc_register_request_payload(
                &vbc_hash, &req.wallet_id, req.k_tier,
            );
            if !axiom_nabla::crypto::verify_ed25519(&wallet_pk, &req_payload, &req.client_sig) {
                return None; // register_vbc_core refuses it (step 0)
            }
            let (held, own_nbc, signer, tick) = {
                let node = state.lock();
                (
                    node.core.vbc_registration(&vbc_hash).is_some(),
                    node.own_nbc_bytes.clone(),
                    node.core.signer_arc(),
                    node.core.tardis().map(|t| t.current_tick()).unwrap_or(0),
                )
            };
            if held {
                return None; // owner re-issue path — the held entry was verified when it entered
            }
            let verdict = axiom_nabla::registration::build_vbc_stamp(
                &own_nbc, vbc_hash, vbc.validator_id, wallet_pk, req.declared_balance, tick, signer.as_ref(),
            ).map(|stamp| {
                let mut target = vbc.clone();
                target.nabla_registration = Some(stamp);
                dir::admit(dir::VbcRegistrationRecord { target_vbc: target, supporting_vbcs: req.supporting_vbcs.clone() }, verify)
            });
            Some(DirectoryPrecheck::Register { vbc_hash, verdict })
        }
        WireMessage::VbcRegistrationEntries { from, nonce, entries, sig } => {
            if entries.len() > dir::MAX_DIRECTORY_ENTRIES_PER_PAGE {
                dir::note_ae_refused(dir::AeRefusal::Oversize, from);
                return None;
            }
            let body = dir::entries_body_hash(entries);
            let todo: Vec<dir::VbcRegistrationRecord> = {
                let mut node = state.lock();
                let pk = node.verified_nbcs.get(from).and_then(nbc_ed25519_pk);
                let now = node.virtual_secs;
                let auth = dir::verify_ae_signature(pk, dir::DIRECTORY_AE_KIND_ENTRIES, from, *nonce, &body, sig)
                    .and_then(|()| node.directory_ae.accept_reply(*from, *nonce, now));
                if let Err(r) = auth {
                    dir::note_ae_refused(r, from);
                    return None;
                }
                // The directory is the success cache: a held key is never re-verified.
                entries.iter().filter(|r| !node.core.vbc_directory().contains(&r.vbc_hash())).cloned().collect()
            };
            // OFF the lock: the SPHINCS+ work. A failure is counted in `admit`
            // and never remembered (a bad copy cannot poison a genuine cert).
            let verified = todo.into_iter().filter_map(|r| dir::admit(r, verify).ok()).collect();
            Some(DirectoryPrecheck::Entries { from: *from, nonce: *nonce, verified })
        }
        _ => None,
    }
}

/// ForkSettlement [R18] — screen the fork bans an `AeReconcile` / `AeEntries`
/// carries WITHOUT the node lock (the retired `prelock_hal_verify` shape, §9q): a brief lock
/// asks which claims name only keys already banned here (skipped — the steady
/// state, since every exchange carries every ban), then `verify_fork_claim`
/// runs on the rest off the lock. `None` for every other message.
fn prelock_ae_fork_bans(
    state: &Arc<PlMutex<NablaNodeState>>,
    envelope: &Envelope,
) -> Option<Vec<axiom_nabla::ban::AeBanScreen>> {
    let claims = match &envelope.message {
        WireMessage::AeReconcile { fork_bans, .. } | WireMessage::AeEntries { fork_bans, .. } => fork_bans,
        _ => return None,
    };
    let known = state.lock().core.ae_fork_bans_known(claims);
    Some(axiom_nabla::ban::screen_ae_fork_bans(claims, &known))
}

/// Fork Settlement §9o [R58/R59] (W1) — the OFF-LOCK stage of a record-AE
/// ANSWER (the `prelock_ae_fork_bans` shape): a BRIEF lock authenticates it
/// (`verified_nbcs[from]`, the nonce this node issued, the descent's in-flight
/// ask — `record_ae_accept_answer`, refusals counted there), then every asked
/// leg is verified WITHOUT the lock (`record_sync::prepare_answer` —
/// `verify_fork_leg`, ≈178 µs each, ≤ 64 per answer); an unrequested leg is
/// refused unverified. `None` for every other message, or a refused answer.
fn prelock_record_ae(
    state: &Arc<PlMutex<NablaNodeState>>,
    envelope: &Envelope,
) -> Option<axiom_nabla::record_sync::PreparedAnswer> {
    let WireMessage::RecordAeAnswer { from, nonce, answer, sig } = &envelope.message else { return None };
    let accepted = {
        let mut node = state.lock();
        let pk = node.verified_nbcs.get(from).and_then(nbc_ed25519_pk);
        let now = node.virtual_secs;
        node.core.record_ae_accept_answer(from, *nonce, answer, sig, pk, now)?
    };
    Some(axiom_nabla::record_sync::prepare_answer(accepted, answer.clone()))
}

/// ForkSettlement [R18] — the locked half: adopt the screened AE-carried bans
/// (`NablaNode::adopt_ae_fork_bans`). The screen was stashed by `recv_loop`
/// for THIS message. A message `tick_loop`'s bounded inbox drain handles
/// (it shares the inbox with `recv_loop` and calls `handle_message` under
/// its lock with no pre-lock stage) is screened HERE by the same two
/// functions — bounded by `AE_FORK_BANS_MAX` and the known-ban skip — rather
/// than dropped: a ban lost on that path would be the S4b gap again.
fn adopt_ae_fork_bans(state: &mut NablaNodeState, fork_bans: &[axiom_nabla::types::ForkClaim]) {
    if fork_bans.is_empty() {
        return;
    }
    let screen = match state.ae_ban_precheck.take() {
        Some(s) => s,
        None => {
            let known = state.core.ae_fork_bans_known(fork_bans);
            axiom_nabla::ban::screen_ae_fork_bans(fork_bans, &known)
        }
    };
    let now = state.virtual_secs;
    let adopted = state.core.adopt_ae_fork_bans(fork_bans, &screen, now);
    if adopted > 0 {
        info!("Anti-entropy: adopted {adopted} fork ban(s) with evidence from peer [R18]");
    }
}

fn recv_loop(
    state: Arc<PlMutex<NablaNodeState>>,
    transport: Arc<dyn Transport>,
) {
    // ForkSettlement §2.4 [R34] — "listening" is THIS: the inbound handler is
    // live. The next tick-loop iteration stamps the origin-vouch boot floor.
    state.lock().recv_loop_live = true;
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

        // ForkSettlement R42 — witness-directory verification, OFF the lock.
        let dir_pc = prelock_directory_verify(&state, &envelope, axiom_nabla::vbc_directory::DIRECTORY_VERIFIER);
        // ForkSettlement R18 — AE-carried fork bans, screened OFF the lock.
        let ae_ban_pc = prelock_ae_fork_bans(&state, &envelope);
        // Fork Settlement §9o [R58] — record-AE answer: authenticated under a
        // brief lock, its legs verified OFF the lock.
        let record_pc = matches!(envelope.message, WireMessage::RecordAeAnswer { .. })
            .then(|| prelock_record_ae(&state, &envelope));
        let outbound = {
            let mut node = state.lock();
            // Set and cleared inside THIS lock scope — never outlives its message.
            node.directory_precheck = dir_pc;
            node.ae_ban_precheck = ae_ban_pc;
            node.record_ae_precheck = record_pc;
            let mut out = handle_message(&mut node, &envelope);
            node.directory_precheck = None;
            node.ae_ban_precheck = None;
            node.record_ae_precheck = None;
            // ForkSettlement §2.3 — flood the A1 verdicts this message produced
            // (door / flood / AE detection, or an adopted `ForkBan`) at once.
            out.extend(fork_ban_fanout(&mut node));
            out
        };
        // Dev-only flood chaos — the same filter as the tick loop (floods and head-AE replies
        // this message produced), outside the node lock.
        #[cfg(feature = "flood-chaos")]
        let outbound = axiom_nabla::flood_chaos::filter_outbound(outbound);

        // Send responses (outside lock) — KI#92: the ONE dispatcher.
        dispatch_outbound(transport.as_ref(), &state, Some(&envelope), &outbound, "recv_loop");
    }
}

/// ForkSettlement §2.3 — drain the A1 verdicts the lib queued
/// (`NablaNode::take_pending_fork_floods`, already WAL-logged by
/// `drain_fork_side_effects`) and address each as `GossipMessage::ForkBan` to
/// every `forward_targets` peer. No network I/O under the lock (the drain's
/// WAL appends and its ban-file rewrite, when the table grew, are local disk): the caller
/// sends outside it. With no mesh (never in the running binary) the claims are
/// dropped from the queue — the bans themselves are already applied and
/// WAL-logged, and every peer detects from its own records.
fn fork_ban_fanout(node: &mut NablaNodeState) -> Vec<(std::net::SocketAddr, WireMessage)> {
    // Fork Settlement W7c/W7d — drain the provenance cascade's remainder
    // (budgeted; pure CPU, no I/O beyond the WAL appends every drain makes)
    // after each handled message and once per tick, so a large late-fork
    // re-derivation finishes and the vouch's fail-closed gate re-opens.
    node.core.drain_fork_side_effects();
    let claims = node.core.take_pending_fork_floods();
    let mut out = Vec::new();
    if claims.is_empty() {
        return out;
    }
    let Some(mesh) = node.core.mesh() else { return out };
    let targets = mesh.forward_targets(&node.node_id);
    for claim in claims {
        let wire = WireMessage::Gossip(GossipMessage::ForkBan { claim });
        for target_id in &targets {
            if let Some(peer) = mesh.peer_by_id(target_id) {
                out.push((to_socket_addr(&peer.address), wire.clone()));
            }
        }
    }
    out
}

/// ForkSettlement §2.4 [R13/R34] — the stall re-floor threshold: the SMALLER
/// (DEV) settle twin, projected to seconds. The node serves both classes, so
/// a stall longer than the dev settle is already unsafe for dev-class
/// vouching. Selected through `dev_or_real` (the ONE selection site,
/// `check_dev_timing.py` rule 2) with `is_dev_class = true` BY DESIGN.
fn origin_refloor_secs() -> u64 {
    axiom_core_logic::types::dev_or_real(
        true,
        axiom_core_logic::validation::SCAR_SETTLE_TICKS_DEV,
        axiom_core_logic::validation::SCAR_SETTLE_TICKS,
    )
    .to_secs()
}

/// ForkSettlement §2.4 [R9/R13/R34] — ONE tick-loop step of the origin-vouch
/// boot floor, pure so a test can drive it (RULE 6 §3a). Returns the new
/// floor and whether this step re-floored.
/// - not listening (`recv_loop_live == false`) → `None` (vouch nothing);
/// - listening, no floor yet → `Some(now)` (the boot stamp, not a re-floor);
/// - floor set and `now - prev > threshold` → `Some(now)`, re-floored (the
///   tick loop stalled — a leg may have gone un-flooded/un-AE'd meanwhile);
/// - a BACKWARD jump (`now < prev`) never re-floors (plan A5: it can only
///   delay vouching — `registered_at = max(first_seen, boot)` never moves back).
/// `prev == 0` is the first sample of the process (no previous iteration) —
/// never a stall.
fn origin_boot_step(
    prev_secs: u64,
    now_secs: u64,
    boot: Option<u64>,
    recv_loop_live: bool,
    threshold_secs: u64,
) -> (Option<u64>, bool) {
    if !recv_loop_live {
        return (None, false);
    }
    match boot {
        None => (Some(now_secs), false),
        Some(b) => {
            if prev_secs != 0 && now_secs.saturating_sub(prev_secs) > threshold_secs {
                (Some(now_secs), true)
            } else {
                (Some(b), false)
            }
        }
    }
}

// ── Main ──

/// KI#63 §3.3 — is anti-entropy stalled over this window?
///
/// TRUE when AE applied NOTHING, rejected a meaningful number, **AND the mesh
/// is diverging**. All three are required.
///
/// ⚠ THE THIRD CONDITION IS NOT OPTIONAL, and omitting it was a real bug
/// (deployed 2026-08-05, caught within two hours). **On a CONVERGED mesh
/// `applied == 0` is the normal steady state**: every entry a peer offers is
/// already held, so it is correctly rejected as `not-superseding` /
/// `consumed-state`. Applying nothing means there was nothing NEW to apply —
/// that is convergence, not a stall. The first version fired on two healthy
/// nodes during a clean soak (1 root hash, 0 orphans, 0 failures) and would
/// have cried wolf on every healthy run, which is worse than no alarm.
///
/// The divergence signal separates them cleanly:
///
/// ```text
///                     forks per 5-min window
///   2026-08-04 incident   ~208     (11,215 over 6h, 9 distinct roots)
///   healthy soak          ~2       (38 total, 1 distinct root)
/// ```
///
/// A quiet mesh (all zero) is silent by construction — the alarm needs
/// evidence, not absence.
///
/// ⚠ KNOWN LIMIT: a single successful apply in a window silences it. A
/// near-total stall (1 applied, 10,000 rejected) therefore does NOT alarm. The
/// live incident was exactly zero so the rule catches it, but if a
/// trickle-stall is ever observed this wants a RATIO, not a zero-test.
fn ae_stall_detected(applied: u64, rejected: u64, forks: u64) -> bool {
    applied == 0
        && rejected >= AE_STALL_ALARM_MIN_REJECTS
        && forks >= AE_STALL_ALARM_MIN_FORKS
}

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
    // KI#240: name the register twin set this binary was compiled with. The print is
    // also what keeps the marker bytes in the binary, which verify_deploy.sh greps
    // and compares against the ELF's profile — do not remove it.
    eprintln!("core/logic tuning profile: {}", axiom_core_logic::version::TUNING_PROFILE_MARKER);

    let args = parse_args();

    // ── Load node.toml (config file lives in main scope for dashboard cascade) ──
    let node_toml_path = match &args.config_file {
        Some(p) => p.clone(),
        None => args.data_dir.join("node.toml"),
    };
    let node_toml: Option<axiom_nabla::ceremony::NodeToml> = if node_toml_path.exists() {
        // A node.toml that EXISTS but does not load is fatal. It used to warn
        // and fall back to None — but this runs before the logger is
        // initialised, so the warning went nowhere and the node started
        // WITHOUT its config (name, ports, operator wallet) and nobody could
        // see why. eprintln: the logger is not up yet.
        match axiom_nabla::ceremony::NodeToml::load(&node_toml_path) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("FATAL: {} is present but invalid: {}", node_toml_path.display(), e);
                eprintln!("       Fix or delete it; a node never runs with its config silently dropped.");
                std::process::exit(1);
            }
        }
    } else if args.config_file.is_some() {
        eprintln!("FATAL: config file not found: {}", node_toml_path.display());
        std::process::exit(1);
    } else {
        None
    };
    // The dashboard is loopback-only (YP "Transport — functional endpoints",
    // amended 2026-09-26). Refuse a leftover remote-bind request rather than
    // silently ignore it. eprintln: the logger is not initialised yet.
    if node_toml.as_ref().and_then(|t| t.dashboard_remote) == Some(true) {
        eprintln!(
            "{}: `dashboard_remote = true` is no longer supported — Nabla's HTTP \
             dashboard binds 127.0.0.1 only. Delete the key; read a remote node's \
             state over the TCP-CBOR wire.",
            node_toml_path.display()
        );
        std::process::exit(1);
    }
    // node.toml is REQUIRED (§5.6a-bis: `external_port` has no default). Refuse
    // HERE, not later: without this the node fetched its NBC first and then
    // panicked on the `external_port` expect() below. The one exemption is
    // `--emission-bundle`, which only prints the NBC already on disk.
    if node_toml.is_none() && !std::env::args().any(|a| a == "--emission-bundle") {
        eprintln!(
            "FATAL: {} not found — node.toml is required (it carries external_port, \
             §5.6a-bis). Generate it with scripts/axiom-env.py (local fleet) or the \
             installer, or pass --config <path>.",
            node_toml_path.display()
        );
        std::process::exit(1);
    }

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
    if node_toml.is_some() {
        info!("Loaded config: {}", node_toml_path.display());
    }

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
    let config = match bootstrap_config_for(&args.bootstrap_file) {
        Ok(Some(c)) => {
            info!("Loaded {} bootstrap peers from {:?}",
                c.peer_count(), args.bootstrap_file);
            c
        }
        Ok(None) => {
            info!("No bootstrap file at {:?} — starting with no bootstrap (first node)",
                args.bootstrap_file);
            NablaConfig::new()
        }
        Err(e) => {
            // FAIL CLOSED (KI#230). This used to warn and continue with an EMPTY
            // peer set, and an empty peer set is the KI#42 "first node of the
            // mesh" exemption: the node armed immediately and served
            // registrations with no anti-rollback view. Hit live 2026-09-29 on
            // theta: after a power-cycle DNS was not up yet, one seed failed to
            // resolve, and the node armed alone. Exit non-zero so the supervisor
            // retries once the network is up.
            error!("FATAL: bootstrap file {:?} exists but cannot be loaded: {} — \
                    refusing to start as a first node", args.bootstrap_file, e);
            std::process::exit(1);
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

        // Node name for keygen + the NBC issuance request: the OPERATOR'S
        // configured `name` from node.toml, falling back to the data-dir
        // basename only when no config supplies one.
        //
        // ⚠ This previously read the data-dir basename UNCONDITIONALLY, while
        // the comment above it claimed "from config file if available" — a
        // stale comment asserting behaviour the code did not have (RULE 3
        // shape 7). `node_toml` was already loaded and in scope; it was simply
        // never consulted, so an operator's chosen name was silently discarded
        // at the one moment it is durable: the name is bound into the SIGNED
        // NBC at issuance, so it cannot be corrected later without re-issuing
        // (which regenerates keys and yields a NEW node id).
        //
        // The default data dir is `~/.axiom`, so EVERY citizen installed via
        // `curl | bash` came up named ".axiom" — one shared name across every
        // citizen on the network, which makes peer lists, dashboards and logs
        // unreadable exactly when they are needed. Found 2026-08-25 on the Pi
        // (node.toml said "nabla-pi-Orthanc"; the NBC said ".axiom").
        let node_name_for_keygen = node_toml.as_ref()
            .map(|t| t.name.trim())
            .filter(|n| !n.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                args.data_dir.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unnamed")
                    .to_string()
            });

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
                    // Tell the issuer which PORT to reply on. The issuer joins it
                    // to the IP it observes for this connection (§5.6a-bis), so
                    // we never state where we are — only how to get back in.
                    // Without it the issuer would reply to our ephemeral source
                    // port, which we never read (KI#42), and the request would
                    // time out.
                    external_port: node_toml.as_ref()
                        .map(|t| t.external_port)
                        .expect("node.toml is required and carries external_port (\u{a7}5.6a-bis)"),
                    // The node's ONE operator wallet (node.toml::operator_wallet).
                    // The issuer rejects a dev operator at build_unsigned_nbc.
                    operator_wallet: node_toml.as_ref()
                        .map(|t| t.operator_wallet.clone())
                        .unwrap_or_default(),
                };

                if transport.send(peer_addr, &request).is_err() {
                    warn!("Cannot reach peer {}, trying next...", peer_addr);
                    continue;
                }

                // Wait for response with timeout. CL8 NBC issuance runs a full
                // SLH-DSA (SPHINCS+) sign INSIDE the AVM — expensive even under
                // Cranelift JIT (billions of guest instructions; the AVM ceiling
                // MAX_INSTRUCTIONS had to be raised past 4B for it). 90s gives the
                // issuer room to sign, plus a queue of concurrent joiners, without
                // the requester abandoning a peer that is about to answer.
                let deadline = Instant::now() + Duration::from_secs(90);
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
    // Contribution emission (YP §25.2.4, design §4.2a): `--emission-bundle`
    // prints this node's NBC + supporting chain as the `identity_cert` bundle
    // (hex) and exits. The claim itself is sent by the wallet of THIS node's
    // key (`nabla_ed25519.key`) — the SDK signs the request with it; no voucher.
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.iter().any(|a| a == "--emission-bundle") {
        let bundle = axiom_core_logic::types::VBCProofBundle {
            target_vbc: nbc.clone(), supporting_vbcs: own_supporting_nbcs.clone(), candidacy_pulse: None, renewal_work_receipt: None,
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&bundle, &mut cbor).expect("NBC bundle encodes");
        println!("{}", hex::encode(cbor));
        std::process::exit(0);
    }

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

    // ── §5.6a-bis: our own address is LOCAL BOOKKEEPING, not a claim ──
    //
    // This used to be the "address advertised to peers", chosen by a three-way
    // precedence: `--advertise` (DNS-resolved), else a UDP-connect probe against
    // the first bootstrap peer to guess the egress interface IP, else the bind
    // address with a loud warning. Every branch was the node GUESSING at a fact
    // only the network holds, and the result went onto the wire in Hello,
    // TardisAttachRequest and the topology hints.
    //
    // All of that is gone. A node states only its `external_port`; peers compose
    // `observed source IP : that port`. So this value is no longer advertised
    // anywhere — it is kept solely for local display (`/status` `listen_addr`)
    // and for the mesh's own self-identity slot, and it is simply what we bound.
    //
    // ⚠ DO NOT reintroduce a guess here. The ipify one-shot, `hostname -I`, and
    // the `getsockname`/UDP-probe trick were all removed deliberately: each
    // returns the PRE-NAT tuple, so each is wrong precisely where it matters. On
    // 2026-08-18 a resolved-here address (private 172.20.0.42) was gossiped to
    // the whole mesh and iota — correctly configured on public DNS — could not
    // route to it and flapped. A wildcard bind showing up here is now HARMLESS,
    // because it never leaves the process.
    let address = from_socket_addr(transport.local_addr());

    // Create node state
    log::info!("YPX-014: txid_mode={}", args.txid_mode);
    let state = Arc::new(PlMutex::new(NablaNodeState::new(node_id, address, &args.data_dir, signer, avm_interpreter, skip_verify, args.txid_mode, args.dev_mode)));

    // ── §5.6a-bis: the ONE thing we assert about our own reachability ──
    //
    // Set BEFORE any message is processed, so no Hello can ever leave carrying
    // the bind-port placeholder. `node.toml` is required and validated
    // (ceremony::NodeToml), so a node that got this far HAS an operator-declared
    // external_port; the expect() documents that invariant rather than papering
    // over a missing value with a default — a wrong port silently strands the
    // node behind its own NAT, which is precisely what has no default.
    {
        let ext = node_toml.as_ref()
            .map(|t| t.external_port)
            .expect("node.toml is required and carries external_port (\u{a7}5.6a-bis)");
        state.lock().external_port = ext;
        log::info!(
            "\u{a7}5.6a-bis: advertising external_port={} (bind port={}); peers compose our address as observed-IP:{}",
            ext, args.port, ext);
    }

    // KI#43a — hashmap nodes open the exact consumed-state record and turn
    // on the SMT's event buffer BEFORE any message is processed, so the
    // exact file never misses a consumption the bloom saw.
    state.lock().init_consumed_exact(&args.data_dir);
    // Dev-only flood chaos (feature `flood-chaos`): the switch file lives in the data dir.
    #[cfg(feature = "flood-chaos")]
    {
        let p = args.data_dir.join(axiom_nabla::flood_chaos::SWITCH_FILE);
        axiom_nabla::flood_chaos::set_switch_path(p.clone());
        warn!("FLOOD-CHAOS build: switch file {:?} (dev-only; src/flood_chaos.rs, ForkSettlement §9o)", p);
    }

    // KI#79 — ENFORCED transfer invariant (the assumption fix (b) rests on,
    // made checked instead of assumed): a fully-allocated bloom era MUST fit
    // one StatePull section budget, and a worst-case StatePull response MUST
    // fit one wire frame. Until 2026-08-08 this was silently false — every
    // era serialized to ~5.41 MiB against a 5 MiB budget and a 1 MiB wire,
    // so era transfer NEVER shipped a frame and lagging nodes livelocked
    // UNARMED (KI#79). Measured on the REAL active eras, not recomputed
    // from constants, so a sizing change cannot drift past it. A panic here
    // is the intended loud release-boundary failure: raise
    // STATE_PULL_MAX_BYTES + WIRE_MAX_MSG_BYTES with *_ERA_REAL_ITEMS in
    // the same commit, or build chunked era transfer (KI#79 option (a)).
    {
        let node = state.lock();
        let smt = node.core.smt();
        let consumed_len = smt
            .consumed_era_bytes(smt.consumed_chain().active_era_id())
            .map(|b| b.len())
            .unwrap_or(0);
        let txid_len = smt
            .txid_chain()
            .era(smt.txid_chain().active_era_id())
            .and_then(|era| {
                let mut buf = Vec::new();
                ciborium::into_writer(era, &mut buf).ok().map(|_| buf.len())
            })
            .unwrap_or(0);
        let worst_era = consumed_len.max(txid_len);
        assert!(
            worst_era > 0 && worst_era <= axiom_nabla::constants::STATE_PULL_MAX_BYTES,
            "KI#79 transfer invariant BROKEN: a serialized bloom era is {} B but \
             STATE_PULL_MAX_BYTES is {} B — era transfer would starve silently and \
             lagging nodes could never re-arm. Raise the transfer caps with \
             *_ERA_REAL_ITEMS in the same commit, or build chunked transfer.",
            worst_era, axiom_nabla::constants::STATE_PULL_MAX_BYTES,
        );
        // entries + bloom_eras + consumed_eras each budget a full section;
        // previous_states + framing get the slack.
        assert!(
            3 * axiom_nabla::constants::STATE_PULL_MAX_BYTES + 2 * 1024 * 1024
                <= axiom_nabla::transport::WIRE_MAX_MSG_BYTES,
            "KI#79 transfer invariant BROKEN: worst-case StatePull response \
             (3 × {} B sections + slack) exceeds WIRE_MAX_MSG_BYTES ({} B) — \
             the frame could never leave the socket.",
            axiom_nabla::constants::STATE_PULL_MAX_BYTES,
            axiom_nabla::transport::WIRE_MAX_MSG_BYTES,
        );
        log::info!(
            "[KI#79] transfer invariant OK: worst era {} B ≤ section budget {} B; \
             worst response ≤ wire frame {} B",
            worst_era,
            axiom_nabla::constants::STATE_PULL_MAX_BYTES,
            axiom_nabla::transport::WIRE_MAX_MSG_BYTES,
        );
    }

    // KI#78 — consume the WAL truncation marker ONLY now: the gap it
    // signals has been durably recorded (a hashmap node's open_at_boot
    // wrote the era meta above — a failure there panics before this
    // line; a bloom node keeps no exact record, so forcing this boot's
    // continuity NOT-proven was the marker's whole effect). Left in
    // place it would gap every subsequent boot — the over-flagging the
    // 2026-07-29 continuity fix exists to avoid.
    {
        let node = state.lock();
        if let Err(e) = node.core.wal().clear_truncation_marker() {
            log::warn!(
                "[KI#78] failed to clear WAL truncation marker: {e} — the next \
                 boot will count one extra recording gap (the safe direction)"
            );
        }
    }

    // Accept NBC into state (already loaded above)
    {
        let mut node = state.lock();
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
                    // Verify own NBC. A GENESIS node's NBC (chain_depth==0) is signed
                    // directly by the root authorities, so Core CL7 verifies it in one
                    // hop (the trusted path). A NON-GENESIS node's NBC (chain_depth>0)
                    // is issued by a genesis peer, so root trust requires WALKING the
                    // supporting chain (peer's NBC ← root) — which CL7 does not do (it
                    // only checks the target VBC roots directly). Use the chain-aware
                    // direct verification for joiners, exactly as the acquisition path
                    // (verify_nbc_chain) does; it re-checks every SPHINCS+ hop to root.
                    let nbc_result = if own_nbc.chain_depth == 0 {
                        if let Some(ref avm) = node.avm {
                            verify_nbc_via_core(avm, &own_nbc, now_secs)
                        } else {
                            verify_nbc(&own_nbc, now_secs)
                        }
                    } else {
                        verify_nbc_chain(&own_nbc, &node.own_supporting_nbcs, now_secs)
                    };
                    if let Err(e) = nbc_result {
                        // Internal diagnostic — visible in logs for developers.
                        // Either the NBC chain does not root to NABLA_ROOT_AUTHORITY_PKS
                        // in compiled Core (ceremony/build mismatch), or the supporting
                        // chain is missing/incomplete for a non-genesis node.
                        error!("NBC startup check failed ({}): NBC chain does not verify against \
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

        // KI#42 serve-gate: a node with no bootstrap peers has nobody to re-arm
        // FROM — it is the first node of a mesh. Gating it would deadlock network
        // start, and there is no rollback history for it to be blind to, so it is
        // armed by definition. Every other node must complete a Bootstrap
        // StatePull before it will answer registrations.
        if node.bootstrap_addresses.is_empty() {
            node.anti_rollback_armed = true;
            // GUIDE §5.6c lever 5 — the same node has nobody to PoolSync from
            // either; the pool-sync half of the gate is exempt on the same
            // ground, and nowhere else.
            node.pool_sync_gate_exempt = true;
            log::info!("[ARMED] no bootstrap peers configured — first node of the mesh, \
                        serving immediately (KI#42 serve-gate exempt, §5.6c pool-sync gate exempt)");
        } else {
            log::info!("[UNARMED] awaiting Bootstrap StatePull from {} peer(s) before \
                        serving registrations (KI#42 serve-gate)",
                node.bootstrap_addresses.len());
        }

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
    let dashboard_port = args.dashboard_port
        .or_else(|| node_toml.as_ref().map(|t| t.dashboard_port))
        .unwrap_or(monitor::DEFAULT_MONITOR_PORT);
    // The dashboard is LOCAL ONLY — no authentication, and no remote-bind
    // option (YP "Transport — functional endpoints", amended 2026-09-26).
    // A remote operator reads node state over the TCP-CBOR wire.
    let dashboard_bind = DASHBOARD_BIND;
    let monitor_addr = format!("{}:{}", dashboard_bind, dashboard_port);
    match TcpListener::bind(&monitor_addr) {
        Ok(listener) => {
            listener.set_nonblocking(true).ok();
            let http_state = state.clone();
            let monitor_config = MonitorConfig::default();

            // ── Status refresher (2026-09-01) ────────────────────────────
            // The accept loop must never touch the node lock (see its own
            // comment below), but `try_lock` was the wrong way to honour
            // that: it never BLOCKS, so it never enters parking_lot's
            // eventual-fairness queue and gets no benefit from the KI#92
            // switch away from std::sync::Mutex. Under real load it simply
            // loses. MEASURED on zeta 2026-09-01: over a 62 s poll the
            // dashboard produced 4 distinct snapshots (~15 s apart) and was
            // seen up to 4509 s stale on a single sweep, while the node's
            // own snapshot log proved it was ticking normally the whole
            // time. Contention is BURSTY, so a non-blocking probe is at the
            // mercy of luck.
            //
            // Fix: ONE thread does the blocking acquire — parking_lot then
            // FORCES a handoff after 0.5 ms of waiting, so this thread does
            // not have to win a race — and publishes into a tiny separate
            // mutex the accept loop reads. The accept loop stops competing
            // for the node lock entirely, which removes the wedge class
            // rather than trading against it, and staleness is bounded by
            // the refresh period instead of being unbounded.
            //
            // Request-gated: a recorder under load should not take the node
            // lock once a second to build a snapshot nobody is reading, so
            // the accept loop raises a flag and the refresher clears it.
            let status_cell = {
                let node = http_state.lock();
                Arc::new(Mutex::new(node.status_snapshot(start_time)))
            };
            let status_wanted = Arc::new(std::sync::atomic::AtomicBool::new(false));
            {
                let refresher_state = http_state.clone();
                let refresher_cell = status_cell.clone();
                let refresher_wanted = status_wanted.clone();
                // KI#128: request-gating alone starves a ONE-SHOT observer —
                // it raises the flag and reads the cell in the same breath, so
                // it always sees the previous value. `driver.py tardis` polls
                // exactly once per node and was therefore quarantining a
                // healthy zeta on every sweep (measured 359s, 2026-09-01).
                // Keep the 1s fast path while watched, but refresh
                // unconditionally every FLOOR ticks so a cold read is never
                // older than that. Idle cost: 0.1 node-lock acquisitions/sec.
                const REFRESH_FLOOR_TICKS: u32 = 10;
                let mut idle_ticks: u32 = 0;
                thread::spawn(move || loop {
                    thread::sleep(Duration::from_millis(1000));
                    if refresher_wanted.swap(false, std::sync::atomic::Ordering::Relaxed) {
                        idle_ticks = 0;
                    } else {
                        idle_ticks += 1;
                        if idle_ticks < REFRESH_FLOOR_TICKS {
                            continue;                // nobody watching, cell still young
                        }
                        idle_ticks = 0;
                    }
                    let snap = {
                        let node = refresher_state.lock();
                        node.status_snapshot(start_time)
                    };
                    if let Ok(mut cell) = refresher_cell.lock() {
                        *cell = snap;
                    }
                });
            }
            let accept_cell = status_cell.clone();
            let accept_wanted = status_wanted.clone();

            thread::spawn(move || {
                // KI#92: prime a status-snapshot cache once at dashboard start
                // (the node lock is free here), then serve observability routes
                // from cache whenever the global `state` lock is momentarily
                // contended. This single accept thread must NEVER block on
                // `state.lock()` — on the busy hashmap recorders the unfair
                // mutex starved it indefinitely, wedging the accept loop and
                // piling ~100 connections into the kernel accept queue
                // (CLOSE-WAIT), so `/status` was dead for days. A read-only,
                // seconds-stale snapshot is correct for a dashboard that
                // auto-refreshes every 2 s anyway.
                // Seeded from the refresher's cell — the accept loop never
                // acquires the node lock, not even once at startup.
                let mut last_status = {
                    let c = accept_cell.lock().expect("status cell poisoned");
                    c.clone()
                };
                loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            // YPX-002 P6 — simulated HTTP ingress delay. Matches
                            // the TCP-side injection in `handle_message`; runs once
                            // per HTTP connection on the accept thread so each
                            // peer's request pays its own latency. Zero-cost when
                            // `AXIOM_SIM_NET_DELAY_MAX_MS` is unset/0.
                            axiom_nabla::sim_delay::maybe_sim_delay();

                            // Local operator dashboard ONLY (YP "Transport —
                            // functional endpoints", amended 2026-09-26): GET,
                            // headers only — no request body is ever read, and
                            // there is no functional route. Every wallet /
                            // validator / operator operation is TCP-CBOR.
                            const MAX_HTTP_HEADER: usize = 16 * 1024;
                            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(15)));
                            let mut accum: Vec<u8> = Vec::with_capacity(2048);
                            let mut chunk = [0u8; 2048];
                            let header_end = loop {
                                if let Some(p) = accum.windows(4).position(|w| w == b"\r\n\r\n") {
                                    break Some(p);
                                }
                                if accum.len() >= MAX_HTTP_HEADER { break None; }
                                let n = stream.read(&mut chunk).unwrap_or(0);
                                if n == 0 { break None; }
                                accum.extend_from_slice(&chunk[..n]);
                            };
                            let Some(header_end) = header_end else {
                                if !accum.is_empty() {
                                    let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                    stream.write_all(response.as_bytes()).ok();
                                    stream.flush().ok();
                                }
                                continue;
                            };
                            let (path, query) = match dashboard_request(&accum[..header_end]) {
                                Ok(pq) => pq,
                                Err(response) => {
                                    stream.write_all(response.as_bytes()).ok();
                                    stream.flush().ok();
                                    continue;
                                }
                            };

                            // YPX-002 P5 — per-variant gossip latency stats.
                            // Returns { state_update, group_update, tick_hash }
                            // each with { count, p50_ticks, p99_ticks, max_ticks }.
                            // Consumed by soak_test assertions and admin dashboards
                            // to verify that gossip propagation stays inside Timer A
                            // (1 tick) on a healthy mesh.
                            //
                            // KI#203: the ring is a LIFETIME ring, so the bare
                            // endpoint reports history. `?since_tick=T` /
                            // `?window_ticks=N` restrict it to samples OBSERVED in
                            // that window, and the body echoes `since_tick` so a
                            // consumer can tell a node that honoured the window
                            // from an older one that ignored it. A malformed
                            // window is a 400 — never a silent whole-ring answer.
                            if path == "/gossip-latency" {
                                let answer = {
                                    let node = http_state.lock();
                                    let now = node.core.current_tick_for_latency();
                                    axiom_nabla::gossip::parse_latency_window(query.as_deref(), now)
                                        .map(|since| node.core.gossip_latency(since))
                                };
                                let (status, body) = match answer {
                                    Ok(snap) => ("200 OK", serde_json::to_string(&snap)
                                        .unwrap_or_else(|_| "{}".to_string())),
                                    Err(e) => ("400 Bad Request", serde_json::json!({ "error": e }).to_string()),
                                };
                                let response = format!(
                                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
                                    status, body.len(), body
                                );
                                stream.write_all(response.as_bytes()).ok();
                                stream.flush().ok();
                                continue;
                            }

                            // KI#92: never block the accept thread on the global
                            // node lock for observability. try_lock and refresh
                            // the cache on success; serve the last good snapshot
                            // when the lock is contended (recorder under tick/
                            // wire load). Prevents the accept-loop wedge +
                            // CLOSE-WAIT pileup that killed the dashboard.
                            // Serve from the refresher's cell — NEVER the node
                            // lock. Raise the flag first so the refresher knows
                            // someone is watching and keeps the cell warm.
                            accept_wanted.store(true, std::sync::atomic::Ordering::Relaxed);
                            let status = match accept_cell.lock() {
                                Ok(cell) => {
                                    last_status = cell.clone();
                                    cell.clone()
                                }
                                // Poisoned only if the refresher panicked mid-write;
                                // the last good snapshot is still the honest answer,
                                // and `built_at` tells the reader how old it is.
                                Err(_) => last_status.clone(),
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
            info!("Dashboard: http://127.0.0.1:{} (localhost only)", dashboard_port);
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
                    let n = state.lock();
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
                                let mut n = state.lock();
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
    let tick_ms = args.tick_ms;
    let epoch_ms = args.epoch_ms;
    thread::spawn(move || {
        tick_loop(tick_state, tick_transport, tick_ms, epoch_ms);
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
                let node = attack_state.lock();
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
                // KI#191 — the forged snapshot must be internally coherent or
                // it trips the conservation check before the scenario under
                // test is reached: a forged BALANCE with honest conservation
                // terms is a different injection than the one this exercises.
                let forged_paid_out = 0u64;
                let forged_topped_up = 0u64;
                let sign_payload = axiom_nabla::crypto::pool_sync_sign_payload(
                    pool_kind.sign_tag(), forged_balance, forged_claims,
                    forged_paid_out, forged_topped_up,
                    forged_tick, &sender_node_id,
                    pool_kind.bounded_fee_key(),
                );
                let sender_sig = node.core.signer().sign(&sign_payload);
                let forged = axiom_nabla::types::GossipMessage::PoolSync {
                    pool: pool_kind,
                    balance: forged_balance,
                    total_claims: forged_claims,
                    paid_out: forged_paid_out,
                    topped_up: forged_topped_up,
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

/// Tri-state outcome of a fact-confirm (receipt-proven state registration).
/// The TCP `WireMessage::FactConfirmRequest` arm routes through `fact_confirm_core`
/// and translates this into its wire shape.
///
/// Added 2026-05-15 alongside the HTTP→TCP migration of `/register`
/// (CLAUDE.md Upcoming Task #3 / `feedback_no_json_in_protocol_path`).
pub(crate) enum FactConfirmOutcome {
    /// Success or REDIRECT (the response carries `status`).
    Ok(axiom_nabla::wire_client::RegisterResponse),
    /// 409 — old_state ≠ stored current_state for this wallet.
    Mismatch(axiom_nabla::wire_client::RegisterMismatchResponse),
    /// Validation failure (missing/invalid receipt, etc.) — carries the
    /// structured ErrorResponse for the TCP reply envelope.
    Rejected {
        error: axiom_errors::ErrorResponse,
    },
}

/// Transport-agnostic core for `/register`.  Performs all validation,
/// SMT mutation, NBC anchor population, and gossip queueing.  Caller
/// holds the `node` lock and provides a mutable outbound queue.
///
/// Caller: the TCP arm `WireMessage::FactConfirmRequest` in the main
/// message dispatcher.
/// KI#46 zero-pk flip: pick the authorship a fact-confirm may re-carry.
///
/// The confirm changes neither `current_state` nor `tx_hash` relative to the
/// register that preceded it, so the wallet's ORIGINAL sig (stored on the entry
/// by the register path) still verifies — carry it on both the SMT write and
/// the gossip re-advertisement instead of stamping zero-pk. The pre-flip code
/// clobbered stored authorship to zero on EVERY confirm, erasing the very field
/// the dsfork ban gates on and shipping an unverifiable flood.
///
/// Carried ONLY when the stored entry matches the confirmed
/// `(new_state, tx_hash)` — a sig taken from a different head would not verify,
/// so re-carrying it would be noise. Returns zero-pk + empty sig when there is
/// nothing valid to carry; the caller then SKIPS the gossip emission entirely,
/// because post-flip an unauthored StateUpdate is dropped by every receiver
/// (emitting one is guaranteed-dead traffic, not merely unverified).
///
/// Extracted as a pure fn so the choice is unit-testable: the surrounding
/// `fact_confirm_core` sits behind full registration validation (k=3 receipt,
/// DEED tx, quota gates), which no unit fixture should have to reproduce just
/// to assert which sig gets carried.
fn confirm_authorship(
    stored: Option<&axiom_nabla::types::NablaEntry>,
    new_state: &[u8; 32],
    tx_hash: &[u8; 32],
) -> ([u8; 32], Vec<u8>) {
    match stored {
        Some(e)
            if e.current_state == *new_state
                && e.tx_hash == *tx_hash
                && e.client_pk != [0u8; 32] =>
        {
            (e.client_pk, e.client_sig.clone())
        }
        _ => ([0u8; 32], Vec::new()),
    }
}

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
    // ╔═ BOOTSTRAP SUBSIDY — REMOVE WHEN POOLS DRAIN ═══════════════╗
    // Design: AXIOM_DESIGN_ValidatorJoin.md §4 step 3 / §5.2.3
    // ╚═════════════════════════════════════════════════════════════╝
    let stake_claim_tier = req.stake_claim_tier;

    if node.reader_only {
        return FactConfirmOutcome::Ok(axiom_nabla::wire_client::RegisterResponse {
            status: "REDIRECT".to_string(),
            reason: "reader_only".to_string(),
            ..Default::default()
        });
    }
    // KI#69: same conflation as the TCP register path. `find_nearest_writer()`
    // returned None for BOTH "I am the writer" and "I am an orphan", so an orphan
    // fell through and confirmed against its own possibly-stale head. Only
    // IAmWriter may proceed.
    match node.core.tardis().map(|t| t.writer_routing()) {
        Some(axiom_nabla::tardis::WriterRouting::IAmWriter) => {}
        _ => {
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
            error: axiom_errors::ErrorResponse::new(
                axiom_errors::ErrorCode::from_static(ec::E_NABLA_MISSING_FIELD),
                ErrorCategory::ClientBug,
                "Receipt required — Nabla does not sign unverified state transitions".to_string(),
            ),
        },
    };
    // KI#150 (YP §17.3.1.4 v2.19.0): `RegisterReceipt` carries NO k (Core
    // wire_client.rs) — this is the floor only; a k≥4 registration on this
    // door is judged at 3 until the wire carries `required_k`.
    if receipt.signatures.len() < 3 {
        return FactConfirmOutcome::Rejected {
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

    // Pattern 1 sweep — ONE builder, owned by Core (re-exported through
    // `registration.rs`, which is crypto-boundary exempt).
    let tx_hash = axiom_nabla::registration::fact_tx_hash(&old_state, &new_state);

    let tick = node.virtual_secs;

    let wallet_already_exists = node.core.smt().get(&wallet_pk).is_some();

    // ╔═ BOOTSTRAP SUBSIDY — REMOVE WHEN POOLS DRAIN ═══════════════╗
    // Removal: delete this block. Pools: Bootstrap (community_subsidised_slots x
    // tier3_claim_axc), FoundationBootstrap (foundation_subsidised_slots x
    // tier2_claim_axc) — registers in protocol_core.toml.
    // Design: AXIOM_DESIGN_ValidatorJoin.md §4 step 3
    // ╚═════════════════════════════════════════════════════════════╝
    //
    // §4 step 3 — the validator-join subsidy grant. Deliberately the SAME SHAPE
    // as the airdrop arm below (`try_airdrop_claim`), because it is the same
    // gear: a drain-only pool, a consume-once txid, and a PoolSync fan-out so
    // the mesh converges on the remaining slots. `try_validator_join_claim`
    // routes tier -> pool and refuses tier 1 / unknown tiers rather than
    // defaulting (ledger row 6, already built).
    //
    // `!wallet_already_exists` mirrors the airdrop guard: a claim is seq 1
    // against a wallet the mesh has never seen. Core independently pins the
    // shape (seq == 1, amount == the kind's floor) — this is Nabla's own
    // fail-closed copy of the same fact, not a substitute for it (RULE 5:
    // Nabla is infrastructure, Core is the authority).
    if stake_claim_tier != 0 && !wallet_already_exists {
        use axiom_nabla::node::ClaimOutcome;
        use axiom_nabla::types::PoolKind;
        let pool_kind = match stake_claim_tier {
            2 => PoolKind::FoundationBootstrap,
            3 => PoolKind::Bootstrap,
            other => {
                log::warn!("[JOIN-CLAIM] refusing tier {other} for wallet {} — only tiers 2 and 3 \
                            are pool-funded (tier 1 is ceremony-minted)",
                    hex::encode(&wallet_pk[..8]));
                return FactConfirmOutcome::Rejected {
                    error: axiom_errors::ErrorResponse::new(
                        axiom_errors::ErrorCode::from_static(ec::E_POOL_EXHAUSTED),
                        ErrorCategory::ProtocolReject,
                        format!("stake_claim_tier {other} is not pool-funded (expected 2 or 3)"),
                    ),
                };
            }
        };
        match node.core.try_validator_join_claim(stake_claim_tier) {
            ClaimOutcome::Granted => {
                log::info!("[JOIN-CLAIM] tier-{} grant for wallet {} from {:?}",
                    stake_claim_tier, hex::encode(&wallet_pk[..8]), pool_kind);
                // The pool sync is ONE existing call — the same API every pool
                // rides. A drain-only pool converges min-wins/max-claims, so
                // nothing new is needed for the mesh to agree on the slots.
                let pool_msg = WireMessage::Gossip(node.core.pool_sync_message(pool_kind));
                for target_id in node.core.mesh().unwrap().forward_targets(&node.node_id) {
                    if let Some(peer) = node.core.mesh().unwrap().peer_by_id(&target_id) {
                        outbound.push((to_socket_addr(&peer.address), pool_msg.clone()));
                    }
                }
            }
            ClaimOutcome::RefusedExhausted => {
                log::warn!("[JOIN-CLAIM] tier-{} refused for wallet {} — pool exhausted",
                    stake_claim_tier, hex::encode(&wallet_pk[..8]));
                // §6: pool empty is NOT an error that blocks joining — the
                // candidate self-funds at the same floor. This refuses the
                // SUBSIDY, never the JOIN.
                return FactConfirmOutcome::Rejected {
                    error: axiom_errors::ErrorResponse::new(
                        axiom_errors::ErrorCode::from_static(ec::E_POOL_EXHAUSTED),
                        ErrorCategory::ProtocolReject,
                        format!("validator-join tier-{stake_claim_tier} pool exhausted — \
                                 the subsidy is gone; join self-funded at the same floor"),
                    ),
                };
            }
            other => {
                log::warn!("[JOIN-CLAIM] tier-{} refused for wallet {} — {:?}",
                    stake_claim_tier, hex::encode(&wallet_pk[..8]), other);
                return FactConfirmOutcome::Rejected {
                    error: axiom_errors::ErrorResponse::new(
                        axiom_errors::ErrorCode::from_static(ec::E_POOL_CAP_PER_NABLA),
                        ErrorCategory::Operational,
                        "validator-join claim refused by pool cap — retry".to_string(),
                    ),
                };
            }
        }
    }

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
    let (confirm_pk, confirm_sig) =
        confirm_authorship(node.core.smt().get(&wallet_pk), &new_state, &tx_hash);
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
            client_pk: confirm_pk,
            client_sig: confirm_sig.clone(),
            // §32.3 — fact-confirm is not the authoritative redeem path and
            // carries no receipt lineage; preserve the held entry's lineage.
            received_from: node.core.smt().get(&wallet_pk).and_then(|e| e.received_from),
        };
        // AE-convergence fix (2026-08-01): when `confirm_authorship` found no
        // stored authorship to carry (node doesn't hold this wallet yet, or
        // the confirm names a different tx_hash), the candidate is zero-pk —
        // an entry every peer REJECTS ([AE-REJECT] client-sig) and this node
        // itself would reject over AE. Writing it anyway is the same fault
        // CLARA's deleted healed-head write had (KI#46): the entry is
        // structurally unreplicable, it pre-empts/outranks the wallet's own
        // authored register locally, and the node wedges in a permanent AE
        // re-offer loop. Observed live: one node per seed wallet held such a
        // debris variant; mesh froze at 7 distinct roots, 6-8k reconciles,
        // 0 applied. A node must not store what it would reject from a peer
        // — skip the write; the authored head arrives via the wallet's own
        // register / flood / AE. (Group-wallet inherits keep their by-design
        // zero pk and still write.)
        let unauthored_non_group =
            candidate.client_pk == [0u8; 32] && candidate.group_members.is_none();
        let should_write = !unauthored_non_group
            && match node.core.smt().get(&wallet_pk) {
                Some(existing) => {
                    // KI#77 — a locally-built fact-confirm candidate carries NO
                    // seq proof, so it is unattested by construction. It must
                    // therefore never displace an attested head; that is the
                    // same "must not store what it would reject" rule this site
                    // already enforces for authorship (KI#46, above).
                    //
                    // §5.2.4 (KI#123) — rank 1c alone did NOT close that: it is
                    // deliberately one-directional (`!self_attested &&
                    // incoming_attested`), so an unattested differing-tx
                    // candidate at EQUAL seq fell through to the tick
                    // tiebreaker, won on freshness, and `put`'s KI#38
                    // lock-step then (correctly) dropped the proof the head
                    // was attested by — with nothing to re-establish it. That
                    // is the 2026-08-25 stripping path that stranded epsilon
                    // at 630/635. The predicate below DECLINES exactly that
                    // shape; same-tx confirms (the site's intended purpose)
                    // and merges against unattested heads are unchanged.
                    let self_attested =
                        node.core.smt().seq_proof(&wallet_pk).is_some();
                    axiom_nabla::types::fact_confirm_may_displace(
                        existing,
                        self_attested,
                        &candidate,
                    )
                }
                None => true,
            };
        if should_write {
            // §5.2.4 disposition: a same-tx write is a confirmation of the
            // head we hold (proof retained by the KI#38 lock-step); anything
            // else that survived the predicate is a merge win against an
            // unattested head, or first sight — proof-less by construction.
            let disposition = match node.core.smt().get(&wallet_pk) {
                Some(existing) if existing.tx_hash == candidate.tx_hash => {
                    axiom_nabla::smt::PutProof::SameHeadStatusChange
                }
                _ => axiom_nabla::smt::PutProof::ProoflessByDesign(
                    axiom_nabla::smt::ProoflessKind::MergeWinner,
                ),
            };
            node.core.smt_mut().put_with_proof(&candidate, disposition);
        } else if unauthored_non_group {
            log::info!(
                "[FACT-CONFIRM] no stored authorship for wallet={:02x}{:02x} \
                 (state={:02x}{:02x} tx={:02x}{:02x}) — SMT write skipped, \
                 authored head will arrive via register/flood/AE",
                wallet_pk[0], wallet_pk[1],
                new_state[0], new_state[1],
                tx_hash[0], tx_hash[1],
            );
        } else {
            // §5.2.4 (KI#123): either an ordinary merge loss (candidate older
            // than held — always a silent no-op) or the DECLINED stripping
            // shape. Name the latter so a live decline is attributable — the
            // Aug-25 strip ran silently on every node at once.
            if node
                .core
                .smt()
                .get(&wallet_pk)
                .is_some_and(|e| e.tx_hash != tx_hash)
                && node.core.smt().seq_proof(&wallet_pk).is_some()
            {
                log::info!(
                    "[FACT-CONFIRM] DECLINED (KI#123): differing-tx unattested \
                     candidate vs attested head — wallet={:02x}{:02x} \
                     held_tx={:02x}{:02x} confirm_tx={:02x}{:02x}; proof retained",
                    wallet_pk[0], wallet_pk[1],
                    node.core.smt().get(&wallet_pk).map(|e| e.tx_hash[0]).unwrap_or(0),
                    node.core.smt().get(&wallet_pk).map(|e| e.tx_hash[1]).unwrap_or(0),
                    tx_hash[0], tx_hash[1],
                );
            }
        }
    }

    node.registration_count = node.registration_count.saturating_add(1);

    // Post-flip, an unauthored StateUpdate is REJECTED by every receiver, so
    // emitting one when we have no stored authorship to carry is guaranteed
    // dead traffic — silently ineffective rather than merely unverified (the
    // pre-flip behaviour). Skip the re-advertisement in that case and say so.
    // Nothing is lost: the confirm re-advertises a head the register path
    // already flooded SIGNED, and the local SMT write above still stands.
    if confirm_pk == [0u8; 32] {
        log::debug!(
            "[FACT-CONFIRM] no stored authorship for wallet {:02x}{:02x}.. state \
             {:02x}{:02x}.. — skipping re-advertisement (a zero-pk flood would be \
             dropped mesh-wide post-YPX-009-enforcement)",
            wallet_pk[0], wallet_pk[1], new_state[0], new_state[1],
        );
    } else {
        let gossip_msg = WireMessage::Gossip(axiom_nabla::types::GossipMessage::StateUpdate {
            wallet_id: wallet_pk,
            // KI#46: reconstruction/no-advance path — parent unknown, never ban material.
            old_state: [0u8; 32],
            new_state,
            tx_hash,
            tick,
            is_genesis_claim: false,
            // WI3: the candidate (with its preserved seq) was just written above —
            // gossip the same seq the SMT now holds.
            wallet_seq: node.core.smt().get(&wallet_pk).map(|e| e.wallet_seq).unwrap_or(0),
            client_pk: confirm_pk,
            client_sig: confirm_sig,
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

/// CLARA wallet recovery registration (YPX-018 §2.4, hardened in Phase 5e +
/// Phase 5f). The request carries a real ChequeBundle AND the authoritative
/// TX_HEAL transaction, plus the declared garbage state ids.
///
/// `healed_from_state_id` and `healed_at_seq` are NO LONGER caller-asserted —
/// they are derived authoritatively from `heal_transaction.consumed_state_id`
/// and `heal_transaction.wallet_seq` after the tx ↔ cheque binding is verified.
///
/// The Nabla node:
///   - Verifies cheques.len() >= max(receiver tier k, 3) (KI#150)
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
///   - Returns the signed attestation
///
/// Called by the TCP-CBOR `WireMessage::RegisterClaraRequest` arm. Returns a
/// typed response carrying either a signed `ClaraAttestation` (success)
/// or an `error_code`/`error_reason` pair (rejection).
///
/// Shape mirrors what the retired HTTP `/clara` handler emitted as JSON, just
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
        declared_emission_claimed_epoch: wire_req.declared_emission_claimed_epoch, // §4.2a
        declared_stake_floor_until: wire_req.declared_stake_floor_until,
        declared_wallet_format: wire_req.declared_wallet_format,
    };

    // Audit fix v2.11.15-beta6 (audit pass #2 finding 3): minimize the
    // contiguous time the global node lock is held during CLARA registration.
    //
    // Pre-fix the entire flow ran under one `state.lock()`:
    //   acquire → snapshot NBC fields → register_clara (heavy: bloom inserts,
    //   sig verify, txid binding) → sign attestation → build JSON response →
    //   release.
    // Bursty CLARA traffic could briefly stall unrelated Nabla duties
    // (gossip ticks, the dashboard refresher, TARDIS) waiting on this lock.
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
    // KI#43b — a heal must be ADJUDICABLE. Only a recording (hashmap) node
    // holds the exact consumed-state record that can refute a consumed-bloom
    // false positive, so a bloom-mode node refuses the CLARA registration and
    // points the client at recorders it knows. Without this, a heal fans out
    // to arbitrary nablas, usually lands where no exact record exists, and the
    // §12.4.4 barrier never engages (found by the 2026-07-29 live gate).
    if node.core.smt().txid_mode() != axiom_nabla::bloom::TxidServiceMode::Hashmap {
        let recording_peers: Vec<String> = node.core.mesh()
            .map(|m| m.peer_ids().iter()
                .filter_map(|id| m.peer_by_id(id))
                .filter(|p| p.txid_service == "hashmap")
                .map(|p| {
                    let a = to_socket_addr(&p.address);
                    format!("{}:{}", a.ip(), a.port())
                })
                .collect())
            .unwrap_or_default();
        log::debug!("[KI#43b] CLARA redirect: not a recording node, offering {} recorder(s)",
            recording_peers.len());
        return wc::RegisterClaraResponse {
            status: "REDIRECT".to_string(),
            attestation: None,
            confirmation_root_hash: vec![],
            confirmation_tick: 0,
            confirmation_node_id: vec![],
            error_code: String::new(),
            // The address list rides in the reason string rather than a new
            // wire field: RegisterClaraResponse lives in core/logic (compiled
            // into the guest ELF), so adding a field there would rotate the
            // CoreID for a Nabla-layer routing fix. Format:
            // "not_recording_node:host:port,host:port".
            error_reason: if recording_peers.is_empty() {
                "not_recording_node".to_string()
            } else {
                format!("not_recording_node:{}", recording_peers.join(","))
            },
        };
    }

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

    // KI#43b: set under the lock when a healed-from consumed-hit has an
    // UNSETTLED barrier — maps to the retryable "adjudicating" reason
    // instead of the terminal consumed_already refusal.
    let mut hit_adjudicating = false;
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
            // Split borrow: CLARA's heal chain + garbage chain + limiter mutably,
            // and `core` immutably for the REDEEMED set it must now read. Disjoint
            // fields, so the borrow checker is satisfied without cloning anything.
            // KI#43b: if the healed-from state already has an ACQUITTED
            // barrier verdict, pass it through so the freshness check skips
            // the proven bloom false positive (§12.4.4). Refused/pending
            // verdicts are handled on the error path below.
            let healed_from = req.heal_transaction.consumed_state_id;
            let acquitted = matches!(
                node.adjudications.get(&healed_from).and_then(|a| a.verdict),
                Some(true)
            );
            let NablaNodeState {
                core: ref core_ref,
                txid_bloom_chain: ref mut heal_chain,
                garbage_state_chain: ref mut garbage_chain,
                clara_rate_limiter: ref mut rate_limiter,
                ..
            } = *node;
            let r = register_clara(
                &req,
                heal_chain,
                core_ref.smt().txid_chain(),
                core_ref.smt().consumed_chain(),
                garbage_chain,
                rate_limiter,
                current_tick,
                if acquitted { Some(&healed_from) } else { None },
            );
            // KI#43b/KI#199: positive proof that CLARA actually REGISTERED past
            // an acquitted false positive — distinct from the barrier's
            // "BLOOM-FP confirmed" (which only records the verdict). This fires
            // exactly when the heal completes its CLARA leg on the acquitted
            // state, closing YPX-018 §2.4 step 5 (a heal whose CLARA leg failed
            // is not a completed heal). The live gate asserts this line so an
            // acquittal followed by a no-op short-circuit can no longer read as
            // recovery.
            if acquitted && r.is_ok() {
                log::info!(
                    "[KI#43b] CLARA registered heal past acquitted FP on state {} \
                     — heal complete (attestation issued)",
                    hex::encode(&healed_from[..8]),
                );
            }
            r
        };

        // KI#43b: a healed-from consumed-hit with NO settled verdict opens
        // (or continues) an adjudication — the tick loop pumps the barrier
        // queries; the client retries and finds the verdict. Done here,
        // under the lock, where the node state lives.
        if matches!(result, Err(ClaraRegistrationError::ConsumedHealedFromHit)) {
            let healed_from = req.heal_transaction.consumed_state_id;
            if !node.adjudications.contains_key(&healed_from) {
                // Birth era of the consumed state (§12.4.4 item 4). Source: the
                // healing wallet's own SMT entry, keyed the register path's way
                // (`blake3(wallet_pk)`, nabla_node.rs:13926). GUARDED on
                // `current_state == healed_from` so a wrong/absent entry yields
                // born_tick 0 (whole-history) rather than an unsound narrowing —
                // a 32-byte state collision on a foreign entry is negligible, so
                // the match proves the entry is about x. At CLARA-serve time the
                // node still holds x as head (§12.4.6 pre-register), so a
                // recorder that saw x's registration has it.
                let born_tick = {
                    let key = *blake3::hash(&req.wallet_pk).as_bytes();
                    node.core.smt().get(&key)
                        .filter(|e| e.current_state == healed_from)
                        .map(|e| e.tick)
                        .unwrap_or(0)
                };
                let (own_recorded, own_clean) = match (
                    node.consumed_exact.as_ref(),
                    node.core.smt().consumed_chain(),
                ) {
                    (Some(store), chain) => {
                        exact_barrier_answer(store, chain, &healed_from, born_tick)
                    }
                    // bloom-mode node: honest — it can never vouch.
                    (None, _) => (false, false),
                };
                let mut adj = Adjudication {
                    started_tick: current_tick,
                    born_tick,
                    own_recorded,
                    own_clean,
                    answers: std::collections::HashMap::new(),
                    verdict: None,
                };
                // A locally-recorded or locally-unclean node can settle
                // REFUSED without any network round-trip.
                adj.settle(axiom_nabla::constants::RECORDING_NODES_TOTAL.saturating_sub(1));
                log::info!(
                    "[KI#43b] consumed-check hit on heal-from {} — adjudication {} \
                     (own: recorded={} clean={} born_tick={})",
                    hex::encode(&healed_from[..8]),
                    if adj.verdict == Some(false) { "settled REFUSED locally" }
                    else { "OPENED, pumping barrier" },
                    own_recorded, own_clean, born_tick,
                );
                node.adjudications.insert(healed_from, adj);
            }
            hit_adjudicating = node.adjudications.get(&healed_from)
                .map(|a| a.verdict.is_none())
                .unwrap_or(false);
        }

        // On success, register the healed state in the SMT so the heal link
        // is immediately queryable (unscar). Without this the client would
        // need a separate POST /register round-trip.
        // KI#46 (2026-07-30): CLARA no longer writes the healed head into the
        // SMT, and no longer floods it. Both were found by the CLARA
        // propagation gate (`tests/clara_propagation_gate.py`), which measured
        // the healed head on 1/10 nodes after a full AE settle.
        //
        //  1. The write was UNAUTHORED (`client_pk: [0;32]`). Post-YPX-009
        //     enforcement a node must not store what it would REJECT from a
        //     peer, and an unauthored entry can never be adopted over
        //     anti-entropy — so the healed head was structurally
        //     unreplicable. Flood-only scope is precisely the KI#46 fault
        //     this arc exists to close.
        //  2. Worse, the write PRE-EMPTED the wallet's own register. §12.4.6
        //     runs CLARA pre-register, so this node already held H when the
        //     wallet's signed X→H register arrived → "state mismatch:
        //     registration does not match receipt" → needs_resync → the
        //     register ABORTED, and H never flooded SIGNED anywhere.
        //
        // The write's original justification — "immediately queryable (unscar)
        // without a second register round-trip" — is obsolete post-KI#45: the
        // wallet's own register is the very next step in this same call, and it
        // carries the authorship AND the k-attested seq, so it writes the head,
        // floods it mesh-wide, and leaves an entry anti-entropy can repair.
        // Serving a head that is not yet network-registered was never correct.
        //
        // `registration_count` still increments — CLARA is real work this node
        // performed and counts against its NBC `max_tx` quota (see the renewal
        // gate) — only the state write is gone. `confirmation_root_hash` below
        // is this node's current root; nothing verifies it (the field has no
        // consumer outside its struct definition).
        let (smt_root_hash, smt_node_id) = if result.is_ok() {
            node.registration_count = node.registration_count.saturating_add(1);
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
                // KI#43b: barrier pending => retryable; barrier refused =>
                // the terminal consumed_already reason (same wire reason the
                // SDK already maps to HealConsumedCheckHit).
                ClaraRegistrationError::ConsumedHealedFromHit => {
                    if hit_adjudicating {
                        (409, "consumed_check_adjudicating")
                    } else {
                        (409, "consumed_already_txid_registered")
                    }
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
    Rejected { error: axiom_errors::ErrorResponse },
}

/// Transport-agnostic core for `/pulse-proof` (YPX-009).
///
/// Called by the TCP `WireMessage::PulseProofRequest` arm. Verifies the
/// validator's Ed25519 signature, then queues a `GossipMessage::PulseProof`
/// to the node's forward targets via `outbound`.
fn pulse_proof_core(
    req: &axiom_nabla::wire_client::PulseProofRequest,
    node: &NablaNodeState,
    outbound: &mut Vec<(std::net::SocketAddr, WireMessage)>,
) -> PulseProofOutcome {
    let err = |code: &'static str, msg: &str| PulseProofOutcome::Rejected {
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
        &req.validator_pk, req.epoch, &req.full_accumulator, &req.audit_hash, req.attested_tick,
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

/// Core for the TCP-CBOR `WireMessage::QueryWalletStateRequest` arm —
/// the wallet-state query (bytes as CBOR native bytes).
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
    // (KI#247, 2026-10-02: the `AXIOM_NABLA_ROLE` signature over this reply —
    // signed here and in the TCP `Query` arm, verified NOWHERE — was deleted.
    // `role` stays as unsigned, informational text.)

    match node.core.smt().get(&wallet_pk) {
        Some(entry) => {
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
            }
        }
        None => {
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
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// Txid Query API — Global double-redeem detection
// ════════════════════════════════════════════════════════════════════════

/// Core for the TCP-CBOR `WireMessage::QueryTxidRequest` arm (native SDK,
/// and the browser via TOT's `/nabla/<n>` tunnel).
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
    // implementation.
    let (tick, mode, ed25519_pk, nbc_issuer_pk, nbc_signature, nbc_commitment,
         status, registered_by, signature, claim_status, attest_origin, attest_registered_at_tick, attest_oods,
         attest_origin_status) = {
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
                // Exact index first — it also yields the wallet id, which is the
                // whole point of paying 5x memory for this mode.
                match node.core.smt().get_wallet_by_txid(&txid) {
                    Some(wallet_id) => ("REDEEMED", wallet_id.to_vec()),
                    // KI#42: a MISS in the index is NOT proof of absence. The index
                    // is populated only by our OWN record_txid; era sync (step 4b)
                    // fills the CHAIN, and eras carry no wallet mapping. So a
                    // re-armed hashmap node holds knowledge it would otherwise
                    // ignore, and would answer NOT_REDEEMED for a txid it knows was
                    // redeemed. That is a false NEGATIVE on the §4.6
                    // already-redeemed check — it could let a double-redeem
                    // through, which is the dangerous direction. Fall back to the
                    // chain: REDEEMED without a wallet id beats a wrong NO.
                    None => {
                        if node.core.smt().may_contain_txid(&txid) {
                            ("REDEEMED", vec![])
                        } else {
                            ("NOT_REDEEMED", vec![])
                        }
                    }
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

        // Sign under lock (signer needs node state), then release.
        // Pattern 1 sweep — ONE builder, owned by Core: this node SIGNS what
        // Core and the SDK both verify (`txid_attest_payload`, re-exported via
        // `registration.rs`). ForkSettlement §2.4 / §3.2 — the payload binds
        // the ORIGIN this node vouches for and the wall-clock second it began
        // holding it uncontested while listening: `NablaNode::
        // sign_txid_attestation` → `origin_vouch` (record held ∧ ¬contested ∧
        // registrant pk/bucket not banned ∧ key not held ∧ listening), else the
        // honest "none" (`origin = None`, 0) that Core's `origin_settled_link`
        // reads as NOT settled. Deliberately NOT membership
        // (`cheque_sender_registered`). Pure reads under the lock — nothing
        // here blocks (reference_never_block_under_nabla_node_mutex).
        // `tick` = `virtual_secs`, the SAME clock as `first_seen_secs`.
        // ForkSettlement §9h [R53] — the node's own OODS reading, signed in.
        let oods = node.current_oods_reading();
        let signed = node.core.sign_txid_attestation(&txid, status, tick, node.origin_boot_secs, oods);
        let attest_origin = signed.vouch.origin;
        let attest_registered_at_tick = signed.vouch.registered_at_secs;
        let attest_oods = signed.oods;
        // ForkSettlement §9p — the SAME status the signature bound.
        let attest_origin_status = signed.vouch.status;
        let signature = signed.signature;

        (tick, mode, ed25519_pk, nbc_issuer_pk, nbc_signature, nbc_commitment,
         status, registered_by, signature, claim_status, attest_origin, attest_registered_at_tick, attest_oods,
         attest_origin_status)
    };

    axiom_nabla::wire_client::QueryTxidResponse {
        txid,
        status: status.to_string(),
        registered_by,
        nabla_node_pk: ed25519_pk,
        nabla_signature: signature,
        nabla_tick: tick,
        // Signed above (the SAME values the payload bound — `origin_vouch`,
        // ForkSettlement §2.4).
        origin: attest_origin,
        sender_registered_at_tick: attest_registered_at_tick,
        // ForkSettlement §9h [R53] — the SAME reading the signature bound.
        oods_size: attest_oods.size,
        oods_healthy: attest_oods.healthy,
        // ForkSettlement §9p — Vouched / Held / Unknown, signed above.
        origin_status: attest_origin_status,
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
    // (The pre-KI#83 last_claimed_tick floor is GONE with the mark-claimed
    // machinery: under §10.0 the FOB pool's tranched_total is the claim
    // cursor — earnings feed tranches, tranches are swept consume-once — so
    // the earnings query serves exactly the requested window.)
    let since_tick = req.since_tick;

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
///
/// The response is signed with the node's Ed25519 key + NBC trust anchor.
/// Transport-agnostic core for `/register-cheque-claim`. Both the HTTP
/// handler and the TCP-CBOR `WireMessage::RegisterChequeClaimRequest` arm
/// call this. Returns a typed response whose `status` field is
/// "OK" / "CONFLICT" / "CLAIM_UNAUTHENTICATED" / "ERROR", plus the
/// `ChequeClaimAnnounce` to flood when the claim was NEWLY stored (`None`
/// otherwise) — the caller on the live TCP path emits it (YPX-022 §2.1.2a
/// item 3; RULE 3: the receiver arm in `gossip.rs` has THIS sender).
/// (KI#156 item 2: the "CONFIRMED" outcome was deleted — nothing produced it.)
///
/// YPX-022 §2.1.2a (KI#205, RULED 2026-09-25) — the claim is AUTHENTICATED
/// before anything is stored: `registration::verify_cheque_claim` (claimant
/// signature over Core's one builder, address↔key binding, equality with the
/// head this node holds). A refused claim stores nothing — not the claim, not
/// the YPX-010 §14 chain entry — and is counted (`claims_unauthenticated`).
pub(crate) fn register_cheque_claim_core(
    req: &axiom_nabla::wire_client::RegisterChequeClaimRequest,
    node: &mut NablaNodeState,
) -> (axiom_nabla::wire_client::RegisterChequeClaimResponse, Option<GossipMessage>) {
    let current_tick = node.virtual_secs;

    // YPX-022 §2.1.2a item 1 — authenticate FIRST. `sender_registered` is
    // reported as false on refusal: an unauthenticated claimant learns nothing
    // about the cheque it is not entitled to.
    let head_pk = node.core.smt().head_client_pk_for_claimant(&req.client_pk, req.k_tier);
    if let Err(reason) = axiom_nabla::registration::verify_cheque_claim(req, head_pk.as_ref()) {
        axiom_nabla::registration::note_claim_unauthenticated(reason, &req.cheque_id, "tcp");
        return (
            axiom_nabla::wire_client::RegisterChequeClaimResponse {
                status: "CLAIM_UNAUTHENTICATED".to_string(),
                proof: None,
                error: reason.message().to_string(),
                sender_registered: false,
            },
            None,
        );
    }

    // §10.0 FOB fee-claim verify #2 ("check twice: register AND claim"): a
    // cheque whose txid is a recorded FOB claim gets its sweep re-confirmed
    // here — the record must exist (the register-time sweep happened on this
    // node or replicated via PoolSync/AE) — and the existing single-writer
    // claim registration below is the per-cheque consume-once. Purely
    // informational on a non-FOB cheque (no record → no-op).
    if let Some((vid, is_dev, amount)) = node.core.fob_claim_record(&req.cheque_id) {
        log::info!(
            "[FOB-CLAIM] cheque-claim verify #2: vid={:02x}{:02x} class={} swept={} — record present",
            vid[0], vid[1], if is_dev { "dev" } else { "real" }, amount,
        );
    }

    // YPX-010 §14 — readiness, computed BEFORE the claim so every outcome
    // carries it (including CONFLICT: a receiver still wants to know whether
    // the cheque it lost the race for was even backed).
    //
    // This REPORTS; it does not gate. The claim proceeds exactly as before.
    let sender_registered = node.core.smt()
        .cheque_sender_registered(&req.cheque_id);
    if !sender_registered {
        log::info!(
            "[CLAIM-NOT-READY] cheque={} — sender's tx is not registered here. The claim \
             still succeeds (the receiver decides). The receiver's redeem WILL register \
             normally, but the link inherits the sender's unresolved scar (YPX-001 \
             §1.5.1a) and only the ORIGIN can clear it — heal cannot, so the exit is a \
             burn that destroys the value.",
            hex::encode(&req.cheque_id[..4]),
        );
    }

    let result = node.core.smt_mut().register_cheque_claim(
        req.cheque_id,
        axiom_nabla::smt::ChequeClaim::from_request(req, current_tick),
        current_tick,
    );

    // YPX-010 §14 — record this claim in the claimant's ordered chain and
    // re-derive readiness across the whole chain (the lazy recheck: this touch
    // refreshes every entry, so a client returning after a long absence learns
    // everything that changed while it was away).
    //
    // Runs regardless of the claim's own outcome: a CONFLICT still means the
    // client asked about this cheque, and it still wants to know what is
    // redeemable.
    let chain = node.core.smt_mut().record_claim_in_chain(
        &req.client_pk, &req.cheque_id, current_tick,
    );
    let ready_count = chain.iter().filter(|e| e.sender_registered).count();
    if chain.len() > 1 {
        log::info!(
            "[CLAIM-CHAIN] claimant={} tier={} chain={} ready={} not_ready={} — a wallet \
             working a backlog should redeem ONLY the ready ones; an unready cheque \
             redeemed now becomes a scar only its SENDER can clear",
            hex::encode(&req.client_pk[..4.min(req.client_pk.len())]),
            req.k_tier,
            chain.len(), ready_count, chain.len() - ready_count,
        );
    }

    match result {
        Ok(newly_stored) => {
            // Sign Core's ONE builder (Pattern 1): `redeem_claim_nabla_payload`
            // = BLAKE3("AXIOM_REDEEM_CLAIM" || cheque_id || "CLAIMED" || tick_le
            // || claim_sig). It COVERS the claimant's `claim_sig`, so Core CL5
            // (which verifies claim_sig by client_pk, then this signature over
            // the same bytes) cannot be handed a proof resting on a claim the
            // receiver's key did not make (YPX-022 §2.1.2a item 5 — the RULE 5
            // half). The hand-assembled preimage that used to sit here is gone.
            let payload = axiom_core_logic::compute::redeem_claim_nabla_payload(
                &req.cheque_id, current_tick, &req.claim_sig,
            );
            let signature = node.core.signer().sign(&payload);
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
                k_tier: req.k_tier,
                wallet_address: req.wallet_address.clone(),
                claim_sig: req.claim_sig.clone(),
                claim_tick: current_tick,
                nabla_node_pk: node_pk_arr,
                nabla_signature: signature,
                nbc_issuer_pk,
                nbc_signature,
                nbc_commitment,
            };

            // YPX-022 §2.1.2a item 3 — flood a NEWLY stored claim so every
            // recorder holds the delivery terminal (the sender's recall can
            // land on any node). An idempotent re-claim by the same key is
            // already mesh-known; not re-flooded.
            let announce = newly_stored.then(|| GossipMessage::ChequeClaimAnnounce {
                cheque_id: req.cheque_id,
                client_pk: req.client_pk.clone(),
                k_tier: req.k_tier,
                wallet_address: req.wallet_address.clone(),
                claim_sig: req.claim_sig.clone(),
                claim_tick: current_tick,
            });

            (
                axiom_nabla::wire_client::RegisterChequeClaimResponse {
                    status: "OK".to_string(),
                    proof: Some(proof),
                    error: String::new(),
                    sender_registered,
                },
                announce,
            )
        }
        Err(ref e) if e == "CONFLICT" => (
            axiom_nabla::wire_client::RegisterChequeClaimResponse {
                status: "CONFLICT".to_string(),
                proof: None,
                error: "different client already claimed this cheque".to_string(),
                sender_registered,
            },
            None,
        ),
        Err(e) => (
            axiom_nabla::wire_client::RegisterChequeClaimResponse {
                status: "ERROR".to_string(),
                proof: None,
                error: e,
                sender_registered,
            },
            None,
        ),
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
/// KI#59 — handle an `OooConfirmRequest`: verify the submitted link's k-witness
/// quorum, mark the txid out-of-order-attested (NO head advance), and return a
/// signed `OutOfOrderConfirmation`. Nabla can only WITHHOLD (garbage/under-
/// witnessed → refused); Core independently re-verifies the link + the ooo sig
/// when the wallet presents the chain (RULE 5). Mirrors `register_recall_core`.
pub(crate) fn ooo_confirm_core(
    req: &axiom_nabla::wire_client::OooConfirmRequest,
    node: &mut NablaNodeState,
) -> axiom_nabla::wire_client::OooConfirmResponse {
    // The whole KI#59 decision lives in the lib (`registration::ooo_confirm`) so
    // the lib tests drive the SAME function this handler runs (RULE 1) —
    // `registration::tests::ki59_scarred_gap_ooo_confirmed_then_wallet_resumes`.
    let current_tick = node.virtual_secs;
    let (smt, signer) = node.core.smt_mut_and_signer();
    axiom_nabla::registration::ooo_confirm(req, smt, &node.own_nbc_bytes, current_tick, signer)
}

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
    // AXIOM_DESIGN_AccountKeyedDevTiming.md — the recall's class is the sender's:
    // is_dev_wallet(the failed send's sender_wallet_id). The tx is the SAME one whose
    // txid was recomputed above (zero sender-trust), so the class is bound to it.
    let is_dev_class = axiom_core_logic::wallet_id::is_dev_wallet(&req.failed_send_tx.sender_wallet_id);
    match node.core.smt_mut().register_recall(txid, req.sender_pk.clone(), current_tick, is_dev_class) {
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
        // YPX-022 §2.1.2a (KI#205) — the authenticated claim is the delivery
        // terminal: the addressed receiver holds the cheque, so there is
        // nothing to recall. Counted on /status as `recalls_refused_claimed`.
        Err(ref e) if e == "CLAIMED" => RecallResponse {
            status: "CLAIMED".to_string(), attestation: None,
            error: "This cheque has been claimed by its addressed receiver — it was delivered and cannot be recalled.".to_string(),
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

/// §6b — VBC REGISTRATION. The operator presents a candidate certificate;
/// this node checks ITS OWN state for the stake wallet the certificate names
/// (`AXIOM_DESIGN_ValidatorJoin.md` §6b.4) and stamps or refuses. PASS/FAIL —
/// no partial, no warning, no degraded mode.
///
/// What is checked, in order, and against what:
///   0. the request is signed by the certificate's OWN stake key
///      (`subject_pubkey_ed25519`) — a stranger who saw the certificate on the
///      wire cannot spend its one registration;
///   1. the stake wallet EXISTS in this SMT (`smt_bucket(wallet_id, k_tier)`),
///      and its registered `client_pk` IS the certificate's stake key;
///   2. the DECLARED state reproduces the registered head's k-ATTESTED anchor —
///      `compute_state_hash(client_pk, balance, wallet_seq, hib, wcl, epoch,
///      stake_floor_until, wallet_format) == seq_proof.state_hash`, where the `SeqProof` is the k=3 receipt
///      attestation THIS NODE retained when the head registered (KI#38).
///      Declared, not trusted: a lie changes the hash. ⚠ NOT `entry.current_state`
///      — that is the produced STATE ID, a different value (the first live run
///      compared against it and refused an honest wallet, 2026-09-08).
///      This is also the §6b.4(3) SCAR ZERO-CHECK as Nabla can make it: a scar
///      is a link Nabla never confirmed, so the registered head IS the
///      scar-free frontier, and the stake the certificate rests on must sit
///      exactly AT it. (Implementation reading, Claude 2026-09-08, recorded in
///      the handoff for the owner's confirmation: a link the wallet made and never
///      registered is invisible to Nabla BY DEFINITION; what stops the stake
///      leaving after the stamp is Core's stake lock, not this check.)
///   2b. §6b.4 check 5 (ValidatorJoin §6b.13, KI#225) — the PROVEN head's
///      `stake_floor_until >= vbc.expires_at`: the certificate came from this
///      wallet's own floor-bearing `VbcRequest`, so its 500 cannot leave while
///      the certificate can live. Refused otherwise, counted
///      (`/status vbc_stamp_refused_no_floor`). A genesis DERIVED head carries
///      `genesis::derived_head_stake_floor_until` (= `expires_at`).
///   2c. (ForkSettlement §9r F-1(c), KI#244 — evaluated AFTER 3 and 4 so their
///      refusals keep their meaning; ValidatorJoin §6b.4 check 6) the stake
///      wallet's REGISTERED head VOUCHES at this node: `stake_head_provenance`
///      = `ProvenanceView::Ok`. `Held` ⇒ `REFUSED` (counted
///      `vbc_stamp_refused_held`); no verdict yet ⇒ the retryable `WAIT`
///      (counted `vbc_stamp_refused_wait`), never a stamp. Not applied to the
///      §6c genesis DERIVED head (no SMT entry) nor to the owner re-issue;
///   3. `balance >= required_stake_atoms(vbc)` — the ONE floor (`validator_stake_floor_axc`)
///      for every subject (ruled 2026-09-13, KI#161; this is one of the two points the
///      floor binds — registration here, renewal in CL8);
///   4. OODS baseline (§6b.4a): SKIPPED iff `is_genesis_validator(subject
///      sphincs pk)` — genesis MEMBERSHIP, never the zero value; otherwise the
///      certificate must carry a non-zero baseline and this node's LIVE reading
///      must be healthy against it (`oods_healthy(live, baseline)`);
///   5. consume-once on `vbc_hash` (§6b.4(4)), PER PRESENTER — recorded and
///      persisted. The owner, 2026-09-08: the protocol is async; an SDK timeout must
///      not render a registration failed, the harness retries. So the SAME stake
///      wallet re-presenting gets the SAME stamp (checked right after the
///      signature, before the state checks — the stamp was already issued);
///      a DIFFERENT presenter is refused `CONSUMED`.
///   0b. (ForkSettlement R42, wave 4a — checked right after the re-issue path)
///      the certificate, stamped by THIS node, passes `vbc_directory::admit`
///      WITH the request's `supporting_vbcs`: `verify_vbc_bundle(bundle, 0)`
///      (issuer chain to the roots, lineage, stamps on the target and every
///      supporting cert), provisional refused. Run OFF the node lock by
///      `prelock_directory_verify`; this function only reads the verdict and
///      refuses when none ran. What it records is the verified entry itself.
///
/// ⚠ FAILS OPEN like every Nabla check (RULE 5): a patched node stamps
/// anything. The stamp's TRUST comes from the NBC anchor Core verifies in
/// `validation::verify_vbc_stamp` — a hostile Nabla can only WITHHOLD.
/// ~~That Core check was also this path's whole defence against a junk
/// certificate~~ — true for a validator RELYING on the stamp, false for what
/// this node RECORDED: the registry is the witness directory (R37) and the
/// KI#170 AE source, so step 0b now verifies the chain before recording
/// (ForkSettlement §9c/§9d, KI#223).
/// `register_vbc_core` step 2c (ForkSettlement §9r F-1(c), KI#244) — the
/// stamp's provenance gate, split out so the genesis-derived exemption is
/// drivable in a unit test (a derived head needs a genesis stake key's SECRET
/// to get past step 0, which no test holds). `None` = pass; `Some((status,
/// why))` = the refusal. `derived_head` (the §6c branch, no SMT entry) always
/// passes; otherwise only `ProvenanceView::Ok` passes — `Held` ⇒ `REFUSED`
/// (counted `vbc_stamp_refused_held`), `Wait` / no entry ⇒ the retryable
/// `WAIT` (counted `vbc_stamp_refused_wait`).
fn stake_head_stamp_gate(
    derived_head: bool,
    view: Option<axiom_nabla::types::ProvenanceView>,
) -> Option<(&'static str, String)> {
    use axiom_nabla::types::ProvenanceView;
    if derived_head {
        return None;
    }
    match view {
        Some(ProvenanceView::Ok) => None,
        Some(ProvenanceView::Held(cheques)) => {
            axiom_nabla::registration::note_vbc_stamp_refused_held();
            Some(("REFUSED", format!(
                "stake wallet's head is HELD by this node's provenance (ATRAXI A5) — held cheque(s) [{}]; \
                 burn the held amount, then request and register a new certificate (ForkSettlement §9r F-1(c))",
                cheques.iter().map(|c| hex::encode(&c[..4])).collect::<Vec<_>>().join(", "),
            )))
        }
        Some(ProvenanceView::Wait) | None => {
            axiom_nabla::registration::note_vbc_stamp_refused_wait();
            Some(("WAIT", "this node has no provenance verdict for the stake wallet's head yet \
                 (an ancestor not recorded here, or derivation queued) — retry; a stamp is signed only \
                 on a head that vouches (ForkSettlement §9r F-1(c))".into()))
        }
    }
}

pub(crate) fn register_vbc_core(
    req: &axiom_nabla::wire_client::RegisterVbcRequest,
    node: &mut NablaNodeState,
) -> axiom_nabla::wire_client::RegisterVbcResponse {
    use axiom_nabla::wire_client::RegisterVbcResponse;
    fn refuse(status: &str, why: String) -> RegisterVbcResponse {
        log::info!("[VBC-REGISTER] {}: {}", status, why);
        RegisterVbcResponse { status: status.into(), stamp: None, error: why }
    }
    let vbc = &req.vbc;
    if vbc.nabla_registration.is_some() {
        return refuse("REFUSED", "certificate already carries a stamp — present the candidate, not a stamped copy".into());
    }
    let wallet_pk: [u8; 32] = match vbc.subject_pubkey_ed25519.as_slice().try_into() {
        Ok(pk) => pk,
        Err(_) => return refuse("REFUSED", "certificate subject_pubkey_ed25519 is not 32 bytes".into()),
    };
    // The document being registered — the issuer-signed commitment. Core's
    // verifier recomputes the same value (ONE builder).
    let vbc_hash = axiom_core_logic::compute::compute_vbc_signing_payload(vbc);

    // 0. Only the stake wallet named by the certificate may register it.
    let req_payload = axiom_core_logic::compute::compute_vbc_register_request_payload(
        &vbc_hash, &req.wallet_id, req.k_tier,
    );
    if !axiom_nabla::crypto::verify_ed25519(&wallet_pk, &req_payload, &req.client_sig) {
        return refuse("REFUSED", "request is not signed by the certificate's stake key".into());
    }

    // 5 (early). Already registered? The OWNER gets the same stamp again — a
    //    late reply is not a failed registration (ruling above). A stranger who
    //    holds the certificate is refused.
    if let Some((owner, tick, balance)) = node.core.vbc_registration(&vbc_hash) {
        if owner != wallet_pk {
            return refuse("CONSUMED", "this certificate has already been registered by another wallet".into());
        }
        return match axiom_nabla::registration::build_vbc_stamp(
            &node.own_nbc_bytes, vbc_hash, vbc.validator_id, wallet_pk, balance, tick, node.core.signer(),
        ) {
            Some(stamp) => {
                log::info!("[VBC-REGISTER] OK (re-issued to owner): vbc_hash={} tick={}", hex::encode(&vbc_hash[..4]), tick);
                RegisterVbcResponse { status: "OK".into(), stamp: Some(stamp), error: String::new() }
            }
            None => refuse("ERROR", "this node has no NBC loaded — nothing to anchor a stamp to".into()),
        };
    }

    // 0b. ForkSettlement R42/R42a (wave 4a) — the WITNESS-DIRECTORY verdict,
    //     computed OFF the node lock by `prelock_directory_verify`: this node's
    //     stamp attached to the candidate, and the whole stamped bundle (with
    //     the request's `supporting_vbcs`) through `vbc_directory::admit` —
    //     `verify_vbc_bundle(bundle, 0)`: chain, lineage, the stamp on the target
    //     AND every supporting cert, no time bound; provisional refused. A
    //     certificate that cannot enter the directory is not stamped at all.
    //     ⚠ Before wave 4a this path never checked the issuer chain (its doc
    //     said Core's stamp check covered it — true for RELIANCE, not for what
    //     Nabla records): any subject-signed junk cert could be registered.
    let verified = match node.directory_precheck.take() {
        Some(DirectoryPrecheck::Register { vbc_hash: h, verdict: Some(v) }) if h == vbc_hash => match v {
            Ok(entry) => entry,
            Err(r) => return refuse("REFUSED", format!(
                "certificate refused by the witness directory (ForkSettlement R42): {}", r.reason(),
            )),
        },
        Some(DirectoryPrecheck::Register { vbc_hash: h, verdict: None }) if h == vbc_hash => {
            return refuse("ERROR", "this node has no NBC loaded — nothing to anchor a stamp to".into());
        }
        _ => return refuse("ERROR",
            "no off-lock directory verification ran for this request — refusing rather than stamping unverified".into()),
    };

    // 1. The wallet exists here, and it is the certificate's wallet.
    //
    //    §6c — a GENESIS STAKE WALLET is the exception, by derivation not by
    //    trust: its key is pk-bound to the compile-time list, its opening state
    //    is a function of that list (1,000,000 AXC, seq 0, no lock, and the
    //    §6b.13 floor = the certificate's expiry), and it
    //    cannot have transacted (the genesis lock forbids a SEND). So with no
    //    SMT entry, the head IS the derived opening state and the anchor is
    //    `compute_state_hash` over it — nothing the candidate supplies.
    let bucket = axiom_nabla::registration::smt_bucket(&req.wallet_id, req.k_tier);
    let genesis_opening = axiom_core_logic::genesis::genesis_opening_balance(&wallet_pk);
    // `derived_head` — the §6c genesis branch below (no SMT entry): step 2c
    // does not apply to it (no entry ⇒ never transacted; its opening state is a
    // structural provenance root).
    let (wallet_seq, client_pk, anchor, derived_head) = match node.core.smt().get(&bucket) {
        Some(e) => {
            if e.client_pk != wallet_pk {
                return refuse("REFUSED", "registered wallet is not the certificate's stake wallet".into());
            }
            // 2. The declared state IS the registered head (scar zero-check, and
            //    the only way the declared balance becomes a verified one). The
            //    comparand is the §15 anchor `state_hash` inside the k=3 SeqProof
            //    THIS node retained for the head — its own evidence, not the
            //    candidate's.
            match node.core.smt().seq_proof(&bucket) {
                Some(p) if p.state_hash != [0u8; 32] => (e.wallet_seq, e.client_pk, p.state_hash, false),
                _ => return refuse("REFUSED",
                    "no k-attested state anchor is retained for this wallet's head — the declared state cannot be verified".into()),
            }
        }
        None if genesis_opening > 0 => {
            // ValidatorJoin §6b.13 — the derived head carries
            // `stake_floor_until = vbc.expires_at` (and the current format
            // block), so check 5 below holds uniformly and nothing is
            // special-cased. The genesis stake lock (3 years) is stronger than
            // the floor; the derived head is a function of compile-time
            // constants plus the certificate presented — never of anything the
            // candidate DECLARES.
            let derived = axiom_core_logic::compute::compute_state_hash(
                &wallet_pk, genesis_opening, 0, 0, 0, 0,
                axiom_core_logic::genesis::derived_head_stake_floor_until(vbc),
                &axiom_core_logic::types::WalletFormat::CURRENT,
            );
            log::info!("[VBC-REGISTER] genesis stake wallet {} has no SMT entry — head DERIVED (§6c): balance={} seq=0 floor_until={}",
                hex::encode(&wallet_pk[..4]), genesis_opening, vbc.expires_at);
            (0u64, wallet_pk, derived, true)
        }
        None => return refuse("REFUSED", "stake wallet is not registered at this Nabla".into()),
    };
    let recomputed = axiom_core_logic::compute::compute_state_hash(
        &client_pk, req.declared_balance, wallet_seq,
        req.declared_hibernation_until, req.declared_wall_clock_lock,
        req.declared_emission_claimed_epoch, // §4.2a
        req.declared_stake_floor_until,      // §6b.13 — proven here, read by check 5
        &req.declared_wallet_format,
    );
    if recomputed != anchor {
        return refuse("REFUSED", format!(
            "declared state (balance={} seq={} hib={} wcl={} floor_until={}) does not reproduce the \
             registered head's k-attested anchor — the wallet is not at its Nabla-confirmed frontier",
            req.declared_balance, wallet_seq,
            req.declared_hibernation_until, req.declared_wall_clock_lock,
            req.declared_stake_floor_until,
        ));
    }
    // 2b. (§6b.4 check 5, ValidatorJoin §6b.13 — KI#225). The registered head
    //    must carry a STAKE FLOOR reaching the certificate's expiry: Core sets
    //    it only on the wallet's OWN floor-bearing `VbcRequest`, so a head
    //    without it means the certificate did not come from this wallet's
    //    floor-setting request — and the 500 it rests on could leave the
    //    moment it is stamped (one float, many keys). The value is PROVEN, not
    //    declared: step 2 just re-derived the k-attested anchor with it.
    //    ⚠ FAILS OPEN like every Nabla check (RULE 5): the floor's
    //    ENFORCEMENT is Core's debit gate (`validation::verify_stake_floor`);
    //    this stops an honest node stamping a certificate whose stake is free.
    if !axiom_nabla::registration::stake_floor_covers_certificate(
        req.declared_stake_floor_until, vbc.expires_at,
    ) {
        axiom_nabla::registration::note_vbc_stamp_refused_no_floor();
        return refuse("REFUSED", format!(
            "stake wallet's floor (stake_floor_until={}) does not reach the certificate's \
             expires_at={} — request the certificate from this wallet (VbcRequest at or \
             above the floor) before registering it (ValidatorJoin §6b.13)",
            req.declared_stake_floor_until, vbc.expires_at,
        ));
    }

    // 3. Floor — ONE derivation, shared with CL8 and Core's stamp verifier.
    let floor = axiom_core_logic::validation::required_stake_atoms(vbc);
    if req.declared_balance < floor {
        return refuse("REFUSED", format!(
            "stake {} atoms is below the floor {} atoms for this subject",
            req.declared_balance, floor,
        ));
    }

    // 4. OODS baseline — exemption keyed on GENESIS MEMBERSHIP (§6b.4a).
    if !axiom_core_logic::genesis::is_genesis_validator(&vbc.subject_pubkey_sphincs) {
        if vbc.network_size_baseline == 0 || vbc.baseline_tick == 0 {
            return refuse("REFUSED", "non-genesis certificate carries no OODS baseline".into());
        }
        let (live_size, _tick) = node.current_oods_baseline();
        if !axiom_core_logic::validation::oods_healthy(live_size, vbc.network_size_baseline) {
            return refuse("REFUSED", format!(
                "live OODS reading {} is not healthy against the certificate's baseline {}",
                live_size, vbc.network_size_baseline,
            ));
        }
    }

    // 2c. ForkSettlement §9r F-1(c) (KI#244; ValidatorJoin §6b.4 check 6) — NO
    //    STAMP ON HELD MONEY. A stamp is the one Nabla signature that turns
    //    stake into validator power; steps 2–4 prove the stake EXISTS at the
    //    head, never that it is clean. Before this step a stake balance
    //    downstream of a fork — or of a rewind (a held receive) — was stamped,
    //    which is how a rewind fork became a validator key. The head must VOUCH
    //    at this node: `stake_head_provenance` = `provenance_view` of the
    //    registered head (ATRAXI A5 — the same rule as `origin_vouch`, nothing
    //    copied). `Held` ⇒ REFUSED (burn the held amount, then re-request);
    //    `Wait` (no verdict yet: an ancestor unrecorded here, derivation queued
    //    — record-AE fills it) ⇒ the retryable `WAIT`, never a stamp.
    //    Not applied: the §6c genesis DERIVED head (`derived_head`, no SMT
    //    entry ⇒ it never transacted; its opening state is a provenance root),
    //    and the owner RE-ISSUE above (step 5 early — it returns a stamp that
    //    was already issued and adds no information; D-F1-2).
    //    Placed after check 5 / 3 / 4 so their refusals keep their meaning.
    //    ⚠ Tension named for the owner (KI#244): §9k ruling 1 says a held
    //    REGISTER is never refused; this refuses a STAMP — a different door,
    //    and refusing it strands nothing (the head is unchanged).
    let head_view = if derived_head { None } else { node.core.stake_head_provenance(&bucket) };
    if let Some((status, why)) = stake_head_stamp_gate(derived_head, head_view) {
        return refuse(status, why);
    }

    // 5. Record, then stamp. Recorded BEFORE signing so a signing fault cannot
    //    leave a stamp out with no record of it; the record is what lets the
    //    owner fetch the same stamp again after a lost reply.
    let tick = node.core.tardis().map(|t| t.current_tick()).unwrap_or(0);
    // §6b.10 (KI#169) — ONE live stamp per stake wallet: a second IDENTITY on
    // this wallet is refused; a renewal (same validator_id) is not.
    if let Some(other) = node.core.vbc_registration_conflict(&wallet_pk, &vbc.validator_id, tick) {
        return refuse("REFUSED", format!(
            "stake wallet already stakes another live certificate (validator {}) — one stake, one identity (§6b.10)",
            hex::encode(&other[..8]),
        ));
    }
    // The stamp was built off-lock from `req.declared_balance` — the balance
    // step 2 just proved against the head — so the verified entry IS the
    // registration. Recorded BEFORE the stamp leaves, as before.
    let stamp = verified.stamp_clone();
    debug_assert!(stamp.balance == req.declared_balance && stamp.wallet_pk == wallet_pk);
    if !node.core.record_vbc_registration(verified) {
        return refuse("CONSUMED", "this certificate has already been registered".into());
    }
    log::info!(
        "[VBC-REGISTER] OK: validator_id={} wallet={} balance={} tick={} vbc_hash={} (directory-verified)",
        hex::encode(&vbc.validator_id[..4]), hex::encode(&wallet_pk[..4]),
        req.declared_balance, stamp.tick, hex::encode(&vbc_hash[..4]),
    );
    RegisterVbcResponse { status: "OK".into(), stamp: Some(stamp), error: String::new() }
}

// ════════════════════════════════════════════════════════════════════════
// Bridge API (§6.6 — partition recovery, TCP-CBOR `BridgeRequest`)
// ════════════════════════════════════════════════════════════════════════

/// Outcome of `bridge_core` — success or a typed rejection.
enum BridgeOutcome {
    Ok(axiom_nabla::wire_client::BridgeResponse),
    Rejected { error: axiom_errors::ErrorResponse },
}

/// Transport-agnostic core for `/bridge` (§6.6 partition recovery).
///
/// Called by the TCP `WireMessage::BridgeRequest` arm. Connects to the remote
/// peer, exchanges an `IntroductionRequest`/`IntroductionResponse`, and
/// calls `human_bridge_px` to heal the network partition.
///
/// Locking (task #53): takes the shared `Arc<PlMutex<NablaNodeState>>` and
/// locks it only briefly — once to snapshot `node_id`, once to apply
/// `human_bridge_px` — never across the blocking TCP round-trip to the
/// bridge peer. The node lock stays free during the I/O, so tick
/// processing and message handling continue. The pre-fix version held
/// `&mut NablaNodeState` across the whole exchange (up to ~15 s on a
/// slow/unreachable peer), freezing the node.
fn bridge_core(
    req: &axiom_nabla::wire_client::BridgeRequest,
    state: &Arc<PlMutex<NablaNodeState>>,
) -> BridgeOutcome {
    let reject = |status: u16, code: &'static str, cat: axiom_errors::ErrorCategory, msg: String| {
        BridgeOutcome::Rejected {
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
    let node_id = { state.lock().node_id };

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
                let mut node = state.lock();
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

// ════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════
// Ban Challenge Protocol (S6 — Yellow Paper §32)
// ════════════════════════════════════════════════════════════════════════


// JFP Secret Registration (Yellow Paper §8.4.3)
// ════════════════════════════════════════════════════════════════════════

/// Outcome of `jfp_secret_core` — success or a typed rejection.
enum JfpSecretOutcome {
    Ok(axiom_nabla::wire_client::JfpSecretResponse),
    Rejected { error: axiom_errors::ErrorResponse },
}

/// Transport-agnostic core for `/jfp-secret`.
///
/// Called by the TCP `WireMessage::JfpSecretRequest` arm. Records the secret and
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

    // KI#46 zero-pk flip: dedicated variant, not a synthetic zero-pk
    // StateUpdate — the old carrier planted junk SMT entries mesh-wide and
    // never populated any receiver's secret store. Receivers apply this in
    // the Forward arm (store + re-forward), so `JfpSecretsRequest` against
    // ANY node now serves the secret.
    let gossip_msg = WireMessage::Gossip(axiom_nabla::types::GossipMessage::JfpSecret {
        dwp_wallet_id: req.dwp_wallet_id,
        secret: req.secret,
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
/// Called by the TCP `WireMessage::JfpSecretsRequest` arm. Read-only lookup.
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

// Tests — NBC verification wiring
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod nbc_issuance_reply_tests {
    /// GUIDE §5.6a-bis — the issuance reply is addressed to the OBSERVED
    /// connection source, joined to the requester's declared port. A requester
    /// must never be able to aim our reply (a full SPHINCS+ NBC plus supporting
    /// chain — a large, amplified response) at a third party.
    ///
    /// ⚠ HOW THIS PROPERTY IS NOW ENFORCED, and why the old tests went away.
    /// Until 2026-08-26 the wire carried `reply_addr: Option<String>`, a full
    /// "host:port" claim, and the issuer defended itself by parsing out the port
    /// and DISCARDING the host (`reply_port`). That defence needed a test suite
    /// of its own — bracketed IPv6, bare names, zero ports, "host:notaport" —
    /// because the dangerous value was still being transmitted and parsed.
    ///
    /// The field is now `external_port: u16`. There is no host on the wire to
    /// discard, so the entire class is gone by CONSTRUCTION rather than by
    /// check, and the parsing tests that pinned `reply_port`'s edge cases now
    /// pin nothing. Deleting them with the function is correct; keeping them
    /// against a deleted function would have been a suite that cannot fail.
    ///
    /// What still needs pinning is the CALL SITE, below: that the issuer takes
    /// the IP from the connection and never re-introduces a name lookup under
    /// the node mutex (KI#92/#96).

    /// The wire type cannot carry a host. If someone re-adds one, this stops
    /// compiling — which is the point.
    #[test]
    fn issuance_request_carries_a_port_and_nothing_else_locational() {
        let msg = axiom_nabla::transport::WireMessage::NbcIssuanceRequest {
            sphincs_pk: vec![], ed25519_pk: vec![], dilithium_pk: vec![],
            node_name: "n".into(),
            external_port: 7300,
            operator_wallet: String::new(),
        };
        match msg {
            axiom_nabla::transport::WireMessage::NbcIssuanceRequest { external_port, .. } => {
                assert_eq!(external_port, 7300);
            }
            _ => panic!("wrong variant"),
        }
    }

    /// Mutation check: point the handler at anything other than
    /// `envelope.peer.ip()`, or reintroduce a resolver, and this goes red.
    #[test]
    fn call_site_composes_from_envelope_peer_ip() {
        let src = include_str!("nabla_node.rs");
        let i = src.find("WireMessage::NbcIssuanceRequest {")
            .expect("NBC issuance handler must exist");
        // CODE ONLY. The comment above this arm explains the removal and names
        // `to_socket_addrs()` in prose; matching that made the first version of
        // this assertion fail against correct code — the same
        // comment-false-positive that bit the preflight timer check. Prose
        // describing a rule is not the rule.
        let arm: String = src[i..i + 3000]
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(arm.contains("envelope.peer.ip()"),
                "issuance reply must use the OBSERVED connection IP");
        assert!(arm.contains("external_port"),
                "issuance reply must take the port from the declared external_port");
        assert!(!arm.contains("to_socket_addrs"),
                "issuance reply must not resolve an attacker-supplied name \
                 under the node mutex (KI#92/#96)");
        assert!(!arm.contains("reply_port"),
                "reply_port was deleted with the String field — a call to it \
                 means the host half came back onto the wire");
    }
}

#[cfg(test)]
mod tests {
    // ── KI#63 §3.3 — the AE stall alarm ──
    //
    // These pin the rule that six hours of 100% AE rejection must not be able
    // to read as a healthy run again.
    #[test]
    fn ae_stall_alarm_fires_on_the_live_incident_shape() {
        // 2026-08-04, sustained six hours: 0 applied, 115k rejected, and the
        // mesh in pieces (9 distinct roots, ~208 fork detections per window).
        assert!(super::ae_stall_detected(0, 115_054, 208),
            "0 applied / 115,054 rejected WITH heavy divergence MUST alarm — this \
             is the exact condition that went unreported and let an outage print \
             'Real protocol: 100.00%'");
    }

    /// THE REGRESSION THIS RULE WAS BORN WITH.
    ///
    /// The first version omitted the fork condition and fired on two healthy
    /// nodes during a clean soak — 1 root hash, 0 orphans, 0 failures, 0 burns.
    /// On a CONVERGED mesh `applied == 0` is the normal steady state: every
    /// entry a peer offers is already held, so it is correctly rejected. An
    /// alarm that fires on healthy operation is worse than no alarm, because it
    /// trains you to ignore it.
    #[test]
    fn ae_stall_alarm_is_SILENT_on_a_converged_mesh_applying_nothing() {
        // Measured live 2026-08-05: alpha rejected 104 and kappa 114 in a window
        // while the mesh held ONE root hash and ~2 forks per window.
        assert!(!super::ae_stall_detected(0, 104, 2),
            "CONVERGED + applying nothing is HEALTHY, not a stall — nothing new \
             to apply. The first version of this rule fired here and would have \
             cried wolf on every healthy run.");
        assert!(!super::ae_stall_detected(0, 114, 1), "same, kappa's numbers");
        assert!(!super::ae_stall_detected(0, 10_000, 0),
            "no divergence at all: however many rejections, a converged mesh is \
             not stalled");
    }

    #[test]
    fn ae_stall_alarm_is_silent_on_a_quiet_mesh() {
        assert!(!super::ae_stall_detected(0, 0, 0),
            "no traffic is not a stall — the alarm needs evidence, not absence");
    }

    #[test]
    fn ae_stall_alarm_needs_enough_rejections_to_be_evidence() {
        let min = super::AE_STALL_ALARM_MIN_REJECTS;
        let f = super::AE_STALL_ALARM_MIN_FORKS;
        assert!(!super::ae_stall_detected(0, min - 1, f), "below the reject floor");
        assert!(super::ae_stall_detected(0, min, f), "at the reject floor");
    }

    #[test]
    fn ae_stall_alarm_needs_divergence_not_just_rejections() {
        let f = super::AE_STALL_ALARM_MIN_FORKS;
        assert!(!super::ae_stall_detected(0, 100_000, f - 1),
            "below the fork floor the mesh is converging — not a stall");
        assert!(super::ae_stall_detected(0, 100_000, f),
            "at the fork floor it is diverging — alarm");
    }

    #[test]
    fn ae_stall_alarm_is_silent_while_anything_is_converging() {
        assert!(!super::ae_stall_detected(1, 10_000, 500),
            "KNOWN LIMIT, pinned deliberately: one apply silences the window. \
             If a trickle-stall is ever observed this must become a RATIO test \
             rather than a zero-test.");
    }

    use super::*;

    /// The dashboard is LOCAL ONLY — a remote bind would re-expose an
    /// unauthenticated HTTP surface the YP removed.
    #[test]
    fn dashboard_binds_loopback_only() {
        assert_eq!(DASHBOARD_BIND, "127.0.0.1");
    }

    /// GET is routed; every other method is refused before routing — the
    /// former functional POST endpoints included.
    #[test]
    fn dashboard_serves_get_only() {
        let (path, query) = dashboard_request(b"GET /status?x=1 HTTP/1.1\r\nHost: a").unwrap();
        assert_eq!(path, "/status");
        assert_eq!(query.as_deref(), Some("x=1"));
        for head in [
            &b"POST /register HTTP/1.1\r\nContent-Length: 1"[..],
            b"POST /clara HTTP/1.1",
            b"OPTIONS /status HTTP/1.1",
            b"PUT /status HTTP/1.1",
            b"",
        ] {
            let err = dashboard_request(head).expect_err("non-GET must be refused");
            assert!(err.starts_with("HTTP/1.1 405"), "{err}");
        }
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
    /// GUIDE §5.6a — genesis is `chain_depth == 0`, citizen is > 0.
    ///
    /// ⚠ The depth MUST be set before signing. The first version of this helper
    /// built a depth-1 NBC, signed it, then overwrote `chain_depth` — which
    /// invalidated the signature, so every Hello using it was NBC-REJECTED
    /// before reaching the §5.6a block. The tests then measured zero reports and
    /// two of them went red; the third ("genesis collects no reports") went
    /// GREEN VACUOUSLY, because it asserts zero and zero is what a broken
    /// fixture returns. A test whose pass condition is indistinguishable from
    /// total breakage is [[feedback_checks_that_cannot_fail]].
    fn make_real_nbc(sphincs_pk: &[u8], ed25519_pk: &[u8], tick: u64) -> NBC {
        make_real_nbc_at_depth(sphincs_pk, ed25519_pk, tick, 1)
    }

    fn make_real_nbc_at_depth(sphincs_pk: &[u8], ed25519_pk: &[u8], tick: u64, chain_depth: u8) -> NBC {
        let validator_id = axiom_core_logic::compute::compute_validator_id(sphincs_pk);
        let (issuer_pks, issuer_sks) = make_issuer_keys();
        let mut nbc = axiom_core_logic::types::VBC {
            // §5.3 — an NBC has no genesis-family concept (different root set),
            // so the lineage is zero here. ⚠ This test target had not compiled
            // since the field landed; `--tests` is not part of the ordinary
            // per-package run, so nothing said so (RULE 6, fourth instance
            // found 2026-09-04).
            genesis_lineage: [0u8; 32],
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
            chain_depth,   // 0 = genesis, >0 = peer-issued citizen (§5.6a)
            issuer_set: vec![issuer_pks[0].clone()], // k=1: single issuer
            signatures: vec![],
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
            nabla_registration: None,
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

    /// Code lines of the top-level fn `name` in this file (comments dropped:
    /// prose naming a call is not the call).
    fn ki92_fn_code(src: &str, name: &str) -> String {
        let start = src.find(&format!("\nfn {name}(")).unwrap_or_else(|| panic!("fn {name} must exist"));
        let end = start + 1 + src[start + 1..].find("\n}\n").expect("fn end");
        src[start..end]
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// KI#92 (b) source gate: `handle_message` runs under the ONE node mutex,
    /// so it must never write a socket — every reply is RETURNED and written by
    /// `dispatch_outbound` off the lock. And there is ONE dispatcher: both send
    /// loops call it, and neither keeps its own send loop (they had drifted —
    /// the tick loop lacked the `is_inbound_reply` branch).
    ///
    /// MUTATION: put any `transport::send_reply(envelope, …)` back into
    /// `handle_message`, or a private `for (addr, msg) in &outbound` loop back
    /// into either loop → RED.
    #[test]
    fn ki92_handle_message_never_writes_a_socket_under_the_node_lock() {
        let src = include_str!("nabla_node.rs");
        let hm = ki92_fn_code(src, "handle_message");
        assert!(hm.len() > 50_000, "walked the real handle_message body ({} bytes)", hm.len());
        assert_eq!(hm.matches("send_reply(").count(), 0,
            "handle_message holds the node lock: a reply written here can pin it \
             for TCP_WRITE_TIMEOUT per request — RETURN it in `outbound`");
        for lp in ["recv_loop", "tick_loop"] {
            let body = ki92_fn_code(src, lp);
            assert!(body.contains("dispatch_outbound("), "{lp} must send through dispatch_outbound");
            assert!(!body.contains("for (addr, msg) in &outbound"),
                "{lp} has its own send loop again — one dispatcher (RULE 1)");
        }
        // KI#71: no live audit answer and no second root sample in the binary.
        let code: String = src.lines().filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>().join("\n");
        // Production code only: cut at the first TOP-LEVEL test module.
        let code = &code[..code.find("\n#[cfg(test)]\nmod ").expect("test modules exist")];
        assert!(!code.contains(".handle_audit_request("),
            "KI#71: AuditRequests are QUEUED and answered by advertise_root");
        assert_eq!(code.matches("tickhash_sign_payload(").count(), 1,
            "KI#71: the binary only VERIFIES TickHash signatures; signing is advertise_root's");
    }

    /// KI#92 (b) behaviour: the handler writes NOTHING (the client reads no
    /// bytes after `handle_message` returns); the reply arrives on the request's
    /// own socket only when `dispatch_outbound` runs, and is never re-dialed
    /// through `transport.send` (the KI#24 ephemeral-port shape).
    ///
    /// MUTATIONS: (1) write the StatusRequest reply with `send_reply` inside
    /// `handle_message` → the first read gets bytes → RED. (2) drop the
    /// `is_inbound_reply` branch from `dispatch_outbound` → the recorder sees a
    /// send to the client's ephemeral address → RED.
    #[test]
    fn ki92_reply_is_returned_then_written_off_lock_on_the_inbound_socket() {
        use std::io::Read;
        use std::sync::{Arc as StdArc, Mutex as StdMutex};
        struct Recorder(StdMutex<Vec<std::net::SocketAddr>>);
        impl Transport for Recorder {
            fn send(&self, addr: std::net::SocketAddr, _msg: &WireMessage) -> std::io::Result<()> {
                self.0.lock().unwrap().push(addr);
                Ok(())
            }
            fn recv(&self) -> std::io::Result<Envelope> {
                Err(std::io::Error::other("test transport"))
            }
            fn local_addr(&self) -> std::net::SocketAddr {
                "127.0.0.1:1".parse().unwrap()
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        let envelope = Envelope {
            peer,
            message: WireMessage::StatusRequest,
            reply_stream: Some(StdArc::new(StdMutex::new(server))),
            cbor_client: false,
            wire_bytes: 0,
        };
        let (st, _dir) = make_state(&[0x01; 32]);
        let state = Arc::new(PlMutex::new(st));
        let out = {
            let mut node = state.lock();
            handle_message(&mut node, &envelope)
        };
        let mut len_buf = [0u8; 4];
        client.set_read_timeout(Some(std::time::Duration::from_millis(300))).unwrap();
        assert!(client.read_exact(&mut len_buf).is_err(),
            "handle_message wrote a reply on the socket while holding the node lock");
        assert!(out.iter().any(|(a, _)| *a == peer), "the reply is RETURNED");

        let rec = Recorder(StdMutex::new(Vec::new()));
        dispatch_outbound(&rec, &state, Some(&envelope), &out, "test");
        assert!(!rec.0.lock().unwrap().contains(&peer),
            "an inbound reply must never be re-dialed to the ephemeral source");
        client.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        client.read_exact(&mut len_buf).expect("the reply arrives on the inbound socket");
        assert!(u32::from_be_bytes(len_buf) > 0);
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
                external_port: 6225,
                downstream_count: 0,
                nbc_bytes: a_bytes,
                nbc_supporting_bytes: vec![],
                txid_service: "bloom".into(),
                observed_peer_ip: None,
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
                external_port: 6225,
                downstream_count: 0,
                nbc_bytes,
                nbc_supporting_bytes: vec![],
                txid_service: "hashmap".into(),
                observed_peer_ip: None,
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

    // ══════════════════════════════════════════════════════════════════════
    // GUIDE §5.6a-bis — FIRST-CONTACT DIALBACK
    //
    // The handoff flagged this as the untested half of the change, and option 1
    // (identity-only topology hints, 2026-08-26) made it MORE load-bearing, not
    // less: a node nobody has observed can no longer be reached through a
    // relayed hint at all, so a joiner's own outbound dial — and the seed's
    // ability to dial BACK at a composed address — is now the only way in.
    //
    // The property under test, stated once: a first message arrives from an
    // EPHEMERAL source port (the joiner's kernel picked it; NAT may have
    // rewritten it again). The receiver must record and dial
    // `observed source IP : DECLARED external_port`, never `envelope.peer` as
    // it stands. Get this wrong and every third-party join fails, while the
    // existing genesis mesh — which already knows everyone — stays green and
    // hides it.
    //
    // RFC 5737 TEST-NET addresses throughout, per house rule: never a real one.
    // ══════════════════════════════════════════════════════════════════════

    // ══════════════════════════════════════════════════════════════════════
    // GUIDE §5.6a — THE EXEMPTION IS ON THE SELF SIDE, NOT THE OBSERVER SIDE
    //
    // Corrected 2026-08-26. The observer-side version (discard reports made BY
    // genesis peers) had NO test at all, which is part of why it survived: it
    // produced `address_reports: 0` on the Pi and nothing ever asserted that
    // zero was wrong. These pin the corrected rule in both directions.
    // ══════════════════════════════════════════════════════════════════════

    /// Build a Hello from `peer` reporting that it observed US at `seen_ip`.
    fn hello_reporting_our_address(
        peer_sphincs: &[u8], peer_depth: u8, seen_ip: &str,
    ) -> (NodeId, WireMessage) {
        let nbc = make_real_nbc_at_depth(peer_sphincs, &[0xDD; 32], 500, peer_depth);
        let node_id = nbc_node_id(&nbc);
        let seen: std::net::SocketAddr = format!("{seen_ip}:6225").parse().unwrap();
        (node_id, WireMessage::Hello {
            node_id,
            external_port: 6225,
            downstream_count: 0,
            nbc_bytes: serialize_nbc(&nbc),
            nbc_supporting_bytes: vec![],
            txid_service: "bloom".into(),
            observed_peer_ip: Some(ip_bytes(&seen)),
        })
    }

    fn deliver(state: &mut NablaNodeState, msg: WireMessage, from: &str) {
        let envelope = Envelope {
            peer: format!("{from}:40000").parse().unwrap(),
            message: msg,
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };
        let _ = handle_message(state, &envelope);
    }

    /// GUIDE §5.6a — AGREEMENT IS NOT QUALIFICATION.
    ///
    /// Design ruling, 2026-08-26: *"Even address was agreed. If no wan address it should
    /// still [be] sent to read only."* Found by reading the live Pi: EIGHT
    /// unanimous reports of `172.20.0.61`, `address_disputed: false`, node
    /// write-eligible. Total agreement, wrong answer — every peer had reached it
    /// over the VPN, so they agreed precisely that it was unreachable from
    /// anywhere else.
    #[test]
    fn unanimous_but_private_address_still_demotes_to_read() {
        let (mut state, _dir) = make_state(&[0x11; 32]);

        // Three peers, all agreeing on an RFC1918 address.
        for (i, pk) in [[0xA0u8; 32], [0xB0; 32], [0xC0; 32]].iter().enumerate() {
            let (_id, h) = hello_reporting_our_address(pk, 1, "172.20.0.61");
            deliver(&mut state, h, &format!("172.20.0.{}", 70 + i));
        }

        let t = state.core.tardis().unwrap();
        assert_eq!(t.address_report_count(), 3, "all three reports must be counted");
        assert!(t.address_disputed(),
            "unanimity on a PRIVATE address must still demote: agreement that a node \
             is unreachable is not qualification to serve clients");
        assert!(state.address_unroutable,
            "the REASON must be distinguishable — an operator seeing `disputed` needs \
             to know whether peers disagreed or whether they have no WAN address");
    }

    /// POSITIVE CONTROL for the above: the same unanimous shape on a PUBLIC
    /// address must NOT demote. Without this, the test above would pass against
    /// code that demoted every node unconditionally.
    #[test]
    fn unanimous_public_address_stays_write_qualified() {
        let (mut state, _dir) = make_state(&[0x12; 32]);

        for (i, pk) in [[0xA1u8; 32], [0xB1; 32], [0xC1; 32]].iter().enumerate() {
            let (_id, h) = hello_reporting_our_address(pk, 1, "172.32.0.5");
            deliver(&mut state, h, &format!("172.32.0.{}", 70 + i));
        }

        let t = state.core.tardis().unwrap();
        assert_eq!(t.address_report_count(), 3);
        assert!(!t.address_disputed(),
            "a routable address agreed by every observer is exactly what qualifies");
        assert!(!state.address_unroutable);
    }

    /// The routability predicate itself. These are the ranges that mean "no WAN
    /// address"; getting one wrong silently qualifies an unreachable node.
    #[test]
    fn wan_routability_classifies_reserved_ranges() {
        fn ip(s: &str) -> [u8; 16] {
            ip_bytes(&format!("{s}:1").parse::<std::net::SocketAddr>().unwrap())
        }
        // ⚠ BOUNDARY TESTS, deliberately. An earlier version sampled arbitrary
        // "public" addresses and used RFC 5737 ranges (198.51.100/24,
        // 203.0.113/24) as the stand-ins — which is self-contradictory, because
        // those ARE documentation ranges and the predicate correctly rejects
        // them. Testing the EDGES proves the range arithmetic instead of
        // trusting a sample, and needs no real third-party address.
        //
        // NOT routable — inside a reserved block.
        for a in ["10.0.0.0", "10.255.255.255",
                  "172.16.0.0", "172.31.255.255", "172.20.0.61",
                  "192.168.0.0", "192.168.255.255",
                  "127.0.0.1", "169.254.1.1",
                  "100.64.0.0", "100.127.255.255",   // CGNAT
                  "0.1.2.3", "240.0.0.1",
                  "198.51.100.7", "203.0.113.9"] {   // RFC 5737 documentation
            assert!(!addr_is_wan_routable(&ip(a)), "{a} must NOT be WAN-routable");
        }
        // Routable — one step OUTSIDE each reserved block. These are the cases a
        // sloppy mask would wrongly capture, taking a legitimate node offline.
        for a in ["9.255.255.255", "11.0.0.0",
                  "172.15.255.255", "172.32.0.0",
                  "192.167.255.255", "192.169.0.0",
                  "100.63.255.255", "100.128.0.0",
                  "126.255.255.255", "128.0.0.1"] {
            assert!(addr_is_wan_routable(&ip(a)), "{a} must be WAN-routable");
        }
    }

    /// THE CORRECTION. A citizen MUST count an address report made by a genesis
    /// peer. Before today this report was discarded because the reporter was
    /// genesis, which is why the Pi — whose peers are all genesis — carried
    /// `address_reports: 0` and could never be disputed.
    #[test]
    fn citizen_counts_an_address_report_made_by_a_genesis_peer() {
        let (mut state, _dir) = make_state(&[0x01; 32]);   // chain_depth 1 = citizen
        assert!(!state.own_nbc_is_genesis, "fixture must be a CITIZEN for this test to mean anything");

        let (_id, hello) = hello_reporting_our_address(&[0xC0; 32], 0, "203.0.113.9"); // depth 0 = GENESIS peer
        deliver(&mut state, hello, "203.0.113.9");

        let reports = state.core.tardis().map(|t| t.address_report_count()).unwrap_or(0);
        assert_eq!(reports, 1,
            "a genesis peer's observation is ordinary evidence — a TCP connection reached it. \
             Discarding it is what made the check inert for the one node asserting a VPN address");
    }

    /// Two peers reporting DIFFERENT source addresses for us ⇒ disputed ⇒ Read.
    /// This is exactly the Pi's live situation: local genesis observe it at its
    /// VPN address, remote genesis at its public one.
    #[test]
    fn disagreeing_reports_demote_even_when_all_reporters_are_genesis() {
        let (mut state, _dir) = make_state(&[0x02; 32]);

        // ⚠ ROUTABLE addresses on purpose. This test isolates the REPORTER-FLOOR
        // property (one agreeing report must not demote), so the address must be
        // WAN-routable or the unroutable rule fires and the two properties become
        // impossible to tell apart. It previously used 198.51.100.5 / 203.0.113.77
        // — RFC 5737 documentation ranges, which `addr_is_wan_routable` correctly
        // rejects — and started failing the moment routability began to count.
        // Third time today that RFC 5737 addresses have been mistaken for "public".
        let (_a, h1) = hello_reporting_our_address(&[0xA0; 32], 0, "172.32.0.5");
        deliver(&mut state, h1, "172.32.0.5");
        assert!(!state.core.tardis().unwrap().address_disputed(),
            "one consistent report must NOT dispute — default-allow, no reporter floor");

        let (_b, h2) = hello_reporting_our_address(&[0xB0; 32], 0, "11.0.0.77");
        deliver(&mut state, h2, "11.0.0.77");
        assert!(state.core.tardis().unwrap().address_disputed(),
            "two distinct observed addresses ⇒ DISPUTED ⇒ demote to Read. This is not a \
             false positive: a node seen at different addresses from different vantage \
             points genuinely is not consistently reachable");
    }

    /// The self-side exemption: a GENESIS node ignores this mechanism entirely,
    /// because its address is published in the curated seed list. Transitional —
    /// it retires with genesis itself.
    #[test]
    fn genesis_node_collects_no_reports_about_its_own_address() {
        let dir = tempfile::tempdir().unwrap();
        let nbc = make_real_nbc_at_depth(&[0x03; 32], &[0x01; 32], 500, 0);  // depth 0 = WE are genesis
        let node_id = nbc_node_id(&nbc);
        let mut state = NablaNodeState::new(
            node_id, test_addr(), dir.path(), Box::new(axiom_nabla::crypto::NoopSigner),
            None, true, axiom_nabla::bloom::TxidServiceMode::Bloom, true);
        state.virtual_secs = 1000;
        state.accept_nbc(nbc);
        assert!(state.own_nbc_is_genesis, "fixture must be GENESIS for this test to mean anything");

        // Two CONFLICTING reports — enough to dispute any citizen.
        let (_a, h1) = hello_reporting_our_address(&[0xA1; 32], 1, "198.51.100.5");
        deliver(&mut state, h1, "198.51.100.5");
        let (_b, h2) = hello_reporting_our_address(&[0xB1; 32], 1, "203.0.113.77");
        deliver(&mut state, h2, "203.0.113.77");

        assert_eq!(state.core.tardis().map(|t| t.address_report_count()).unwrap_or(99), 0,
            "genesis must collect NO reports — its IP is in the seed list, it needs no discovery");
        assert!(!state.core.tardis().unwrap().address_disputed(),
            "genesis must never demote itself on an address it did not need peers to learn");
    }

    /// A joiner's first `Hello` must land in the peer table at the COMPOSED
    /// address, not at the ephemeral port it happened to dial out from.
    #[test]
    fn first_contact_hello_is_recorded_at_composed_address_not_source_port() {
        const JOINER_IP: &str = "198.51.100.7";
        const EPHEMERAL: u16 = 54321;   // kernel-picked, meaningless as a dest
        const DECLARED: u16 = 7300;     // node.toml external_port

        let sphincs_pk = [0xCC; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xDD; 32], 500);
        let peer_node_id = nbc_node_id(&nbc);
        let nbc_bytes = serialize_nbc(&nbc);

        let (mut state, _dir) = make_state(&[0x01; 32]);
        let envelope = Envelope {
            peer: format!("{JOINER_IP}:{EPHEMERAL}").parse().unwrap(),
            message: WireMessage::Hello {
                node_id: peer_node_id,
                external_port: DECLARED,
                downstream_count: 0,
                nbc_bytes,
                nbc_supporting_bytes: vec![],
                txid_service: "bloom".into(),
                observed_peer_ip: None,
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };
        let _ = handle_message(&mut state, &envelope);

        let peer = state.core.mesh().unwrap().peer_by_id(&peer_node_id).cloned()
            .expect("a valid-NBC joiner must enter the peer table on first contact");
        let stored = to_socket_addr(&peer.address);

        assert_eq!(stored.ip().to_string(), JOINER_IP,
            "the IP must come from the CONNECTION — it is the half a node can never assert");
        assert_eq!(stored.port(), DECLARED,
            "the port must come from the DECLARED external_port");
        assert_ne!(stored.port(), EPHEMERAL,
            "dialling the ephemeral source port is the bug this whole section exists to prevent: \
             it is not a listener, and NAT rewrites it again in flight");
    }

    /// The same property on `TardisAttachRequest`, and the reply must be
    /// ADDRESSED to the composed socket — this is the actual dialback.
    ///
    /// ⚠ Pinned separately from `Hello` on purpose. Until 2026-08-26 this
    /// message carried `address: NablaAddress` — the requester's own claim —
    /// and the receiver used it verbatim as `reply_to`. Fixing `Hello` alone
    /// left that live, so a test that only covers `Hello` would have gone green
    /// against a mesh that still trusted a stranger's self-assertion.
    #[test]
    fn first_contact_attach_reply_dials_composed_address_not_source_port() {
        const JOINER_IP: &str = "198.51.100.23";
        const EPHEMERAL: u16 = 61000;
        const DECLARED: u16 = 7301;

        let sphincs_pk = [0xAB; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xCD; 32], 500);
        let peer_node_id = nbc_node_id(&nbc);
        let nbc_bytes = serialize_nbc(&nbc);

        let (mut state, _dir) = make_state(&[0x02; 32]);
        let envelope = Envelope {
            peer: format!("{JOINER_IP}:{EPHEMERAL}").parse().unwrap(),
            message: WireMessage::TardisAttachRequest {
                node_id: peer_node_id,
                external_port: DECLARED,
                has_children: false,
                prefer_writer: false,
                nbc_bytes,
                nbc_supporting_bytes: vec![],
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };
        let outbound = handle_message(&mut state, &envelope);

        assert!(!outbound.is_empty(),
            "an attach request must be answered — accepted or refused, the joiner \
             is waiting on a reply it can only receive at its listener");

        // Whatever the verdict (accept / refuse / NbcReject), EVERY reply on
        // this path must be aimed at the composed address.
        for (dest, _msg) in &outbound {
            assert_eq!(dest.ip().to_string(), JOINER_IP,
                "reply IP must be the observed connection source");
            assert_eq!(dest.port(), DECLARED,
                "reply port must be the joiner's DECLARED external_port");
            assert_ne!(dest.port(), EPHEMERAL,
                "replying to the ephemeral source port strands every joiner behind NAT");
        }
    }

    /// POSITIVE CONTROL. The two tests above would both pass against code that
    /// ignored `external_port` and hardcoded the right answer by luck, so vary
    /// the declared port and prove the composition actually tracks it — while
    /// the IP stays pinned to the connection either way.
    #[test]
    fn composition_tracks_the_declared_port_and_never_lets_it_move_the_ip() {
        for declared in [7300u16, 6225, 9999] {
            let sphincs_pk = [0xEE; 32];
            let nbc = make_real_nbc(&sphincs_pk, &[0xEF; 32], 500);
            let peer_node_id = nbc_node_id(&nbc);
            let nbc_bytes = serialize_nbc(&nbc);

            let (mut state, _dir) = make_state(&[0x03; 32]);
            let envelope = Envelope {
                peer: "203.0.113.44:50000".parse().unwrap(),  // RFC 5737 TEST-NET-3
                message: WireMessage::Hello {
                    node_id: peer_node_id,
                    external_port: declared,
                    downstream_count: 0,
                    nbc_bytes,
                    nbc_supporting_bytes: vec![],
                    txid_service: "bloom".into(),
                    observed_peer_ip: None,
                },
                reply_stream: None,
                cbor_client: false,
                wire_bytes: 0,
            };
            let _ = handle_message(&mut state, &envelope);

            let peer = state.core.mesh().unwrap().peer_by_id(&peer_node_id).cloned()
                .expect("joiner must be recorded");
            let stored = to_socket_addr(&peer.address);
            assert_eq!(stored.port(), declared,
                "composed port must follow the declared external_port ({declared})");
            assert_eq!(stored.ip().to_string(), "203.0.113.44",
                "the declared port must never be able to move the observed IP");
        }
    }

    /// KI#42 serve-gate regression (2026-07-28 rotation-restart deadlock): a
    /// Bootstrap StatePullRequest from a MESH PEER (`from: Some`) must be
    /// answered at the peer's LISTENING address via `peer_by_id` — never via
    /// `send_reply` on the request's connection, which a node never reads
    /// (the response sat in an undrained socket buffer, so no restarted node
    /// could ever re-arm and the whole mesh refused registrations forever).
    /// A client requester (`from: None`, live reply_stream contract) keeps
    /// the send_reply path; with no reply_stream it falls back to the
    /// envelope's source address.
    #[test]
    fn bootstrap_state_pull_from_mesh_peer_replies_to_listen_addr() {
        // Register a peer whose LISTEN address (port 7777) differs from the
        // ephemeral source address its request arrives on (port 55555).
        let sphincs_pk = [0xCC; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xDD; 32], 500);
        let peer_node_id = nbc_node_id(&nbc);
        let nbc_bytes = serialize_nbc(&nbc);
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let hello = Envelope {
            peer: test_socket(),
            message: WireMessage::Hello {
                node_id: peer_node_id,
                // §5.6a-bis: the peer declares a PORT; its listening address is
                // COMPOSED as observed-IP:this-port. The assertion below proves the
                // reply dials that composed socket, not the ephemeral source.
                external_port: 7777,
                downstream_count: 0,
                nbc_bytes,
                nbc_supporting_bytes: vec![],
                txid_service: "hashmap".into(),
                observed_peer_ip: None,
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };
        let _ = handle_message(&mut state, &hello);
        assert!(state.core.mesh().unwrap().peer_by_id(&peer_node_id).is_some());

        let ephemeral: std::net::SocketAddr = "127.0.0.1:55555".parse().unwrap();
        let pull = |from: Option<NodeId>| Envelope {
            peer: ephemeral,
            message: WireMessage::StatePullRequest {
                mode: axiom_nabla::types::StatePullMode::Bootstrap,
                from,
                our_root_hash: [0u8; 32],
                from_tick: 0,
                to_tick: u64::MAX,
                section_hash: None,
                have_era_ids: Vec::new(),
                have_consumed_era_ids: Vec::new(),
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };

        // Mesh peer: response must go to the LISTEN address, not the source.
        let outbound = handle_message(&mut state, &pull(Some(peer_node_id)));
        let resp_addrs: Vec<_> = outbound.iter()
            .filter(|(_, m)| matches!(m, WireMessage::StatePullResponse { .. }))
            .map(|(a, _)| *a)
            .collect();
        assert_eq!(resp_addrs, vec!["127.0.0.1:7777".parse().unwrap()],
            "mesh-peer bootstrap response must dial the peer's listening socket");

        // Client (from: None, no reply stream): falls back to the source addr.
        let outbound = handle_message(&mut state, &pull(None));
        let resp_addrs: Vec<_> = outbound.iter()
            .filter(|(_, m)| matches!(m, WireMessage::StatePullResponse { .. }))
            .map(|(a, _)| *a)
            .collect();
        assert_eq!(resp_addrs, vec![ephemeral],
            "client bootstrap response must stay on the request's connection path");
    }

    /// KI#43b: an ExactConsumedQuery from a mesh peer must be answered at the
    /// peer's LISTENING address (the KI#42 rule); a bloom-mode node answers
    /// the honest "can never vouch" pair (recorded=false, clean=false).
    #[test]
    fn exact_consumed_query_replies_to_listen_addr_with_honest_answer() {
        let sphincs_pk = [0xCC; 32];
        let nbc = make_real_nbc(&sphincs_pk, &[0xDD; 32], 500);
        let peer_node_id = nbc_node_id(&nbc);
        let nbc_bytes = serialize_nbc(&nbc);
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let hello = Envelope {
            peer: test_socket(),
            message: WireMessage::Hello {
                node_id: peer_node_id,
                // §5.6a-bis: the peer declares a PORT; its listening address is
                // COMPOSED as observed-IP:this-port. The assertion below proves the
                // reply dials that composed socket, not the ephemeral source.
                external_port: 7788,
                downstream_count: 0,
                nbc_bytes,
                nbc_supporting_bytes: vec![],
                txid_service: "hashmap".into(),
                observed_peer_ip: None,
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };
        let _ = handle_message(&mut state, &hello);

        let q = Envelope {
            peer: "127.0.0.1:55666".parse().unwrap(),
            message: WireMessage::ExactConsumedQuery {
                from: Some(peer_node_id),
                state_id: [0x42; 32],
                born_tick: 0,
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };
        let outbound = handle_message(&mut state, &q);
        let answers: Vec<_> = outbound.iter()
            .filter_map(|(a, m)| match m {
                WireMessage::ExactConsumedAnswer { recorded, clean, .. } =>
                    Some((*a, *recorded, *clean)),
                _ => None,
            })
            .collect();
        assert_eq!(answers.len(), 1);
        let (addr, recorded, clean) = answers[0];
        assert_eq!(addr, "127.0.0.1:7788".parse().unwrap(),
            "answer must dial the peer's listening socket");
        assert!(!recorded && !clean,
            "a bloom-mode node can never vouch: recorded=false, clean=false");
    }

    /// KI#43b: the barrier settles ACQUITTED only on clean answers from the
    /// required count of DISTINCT known-recording peers; a recorded=true
    /// answer settles REFUSED immediately; unknown responders are ignored.
    #[test]
    fn adjudication_barrier_verdict_logic() {
        let needed = axiom_nabla::constants::RECORDING_NODES_TOTAL - 1;
        assert_eq!(needed, 2, "test written for a 3-recorder deployment");

        // Acquittal path.
        let mut adj = Adjudication {
            started_tick: 0,
            born_tick: 0,
            own_recorded: false,
            own_clean: true,
            answers: std::collections::HashMap::new(),
            verdict: None,
        };
        adj.settle(needed);
        assert_eq!(adj.verdict, None, "no answers yet — still collecting");
        adj.answers.insert([1u8; 32], (false, true));
        adj.settle(needed);
        assert_eq!(adj.verdict, None, "one of two peers — still collecting");
        adj.answers.insert([2u8; 32], (false, true));
        adj.settle(needed);
        assert_eq!(adj.verdict, Some(true), "full clean barrier acquits");

        // Any recorded answer refuses immediately, regardless of count.
        let mut adj = Adjudication {
            started_tick: 0, born_tick: 0, own_recorded: false, own_clean: true,
            answers: std::collections::HashMap::new(), verdict: None,
        };
        adj.answers.insert([1u8; 32], (true, true));
        adj.settle(needed);
        assert_eq!(adj.verdict, Some(false), "recorded consumption refuses");

        // Any unclean recorder refuses (absence of proof rejects).
        let mut adj = Adjudication {
            started_tick: 0, born_tick: 0, own_recorded: false, own_clean: true,
            answers: std::collections::HashMap::new(), verdict: None,
        };
        adj.answers.insert([1u8; 32], (false, false));
        adj.settle(needed);
        assert_eq!(adj.verdict, Some(false), "unclean recorder refuses");

        // Own unclean record refuses without any network.
        let mut adj = Adjudication {
            started_tick: 0, born_tick: 0, own_recorded: false, own_clean: false,
            answers: std::collections::HashMap::new(), verdict: None,
        };
        adj.settle(needed);
        assert_eq!(adj.verdict, Some(false), "own unclean record refuses");
    }

    /// KI#43b: answers from responders the mesh does NOT know as
    /// hashmap-mode must never fill the barrier.
    #[test]
    fn adjudication_ignores_unknown_and_bloom_responders() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let sid = [0x77u8; 32];
        state.adjudications.insert(sid, Adjudication {
            started_tick: 0, born_tick: 0, own_recorded: false, own_clean: true,
            answers: std::collections::HashMap::new(), verdict: None,
        });
        // Unknown responder (never Hello'd): ignored.
        let ans = Envelope {
            peer: test_socket(),
            message: WireMessage::ExactConsumedAnswer {
                responder: [0x99; 32], state_id: sid, recorded: false, clean: true,
            },
            reply_stream: None, cbor_client: false, wire_bytes: 0,
        };
        let _ = handle_message(&mut state, &ans);
        let adj = state.adjudications.get(&sid).unwrap();
        assert!(adj.answers.is_empty(), "unknown responder must not count");
        assert_eq!(adj.verdict, None);
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
                attestation: None,
            }),
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };
        let _ = handle_message(&mut state, &envelope);

        // YPX-025 A2 — a COMMIT with no prior VERIFIED reservation is DROPPED: no
        // marker, no garbage insert (a forged commit can't take effect on bare word).
        assert!(!state.core.smt().is_txid_recalled(&txid),
            "a commit with no prior reservation must be dropped");
        assert_eq!(state.garbage_state_chain.lookup(&txid),
            axiom_nabla::bloom_chain::ChainLookup::Miss,
            "a dropped commit must NOT touch the garbage chain");

        // A DIFFERENT txid (a fresh gossip message — reusing the one above would be
        // deduped by the engine's `seen` set before the gate). Seed a VERIFIED
        // reservation directly (apply_remote_recall is the smt method the engine calls
        // AFTER its verify gate — seeding it represents a reservation whose attestation
        // this node already verified). Now the commit applies.
        let txid2 = [0x7Cu8; 32];
        assert!(state.core.smt_mut().apply_remote_recall(&txid2, &[0xB1u8; 32], 500, false));
        let commit2 = Envelope {
            peer: test_socket(),
            message: WireMessage::Gossip(GossipMessage::Recall {
                txid: txid2, sender_pk: vec![0xB1u8; 32], recall_tick: 500,
                committed: true, attestation: None,
            }),
            reply_stream: None, cbor_client: false, wire_bytes: 0,
        };
        let _ = handle_message(&mut state, &commit2);
        assert!(state.core.smt().is_txid_recalled(&txid2),
            "a commit WITH a prior verified reservation must merge the terminal marker");
        assert!(matches!(state.garbage_state_chain.lookup(&txid2),
                axiom_nabla::bloom_chain::ChainLookup::Hit { .. }),
            "a committed recall must insert the recalled txid into the local garbage chain");

        // YPX-025 A2 — a RESERVATION flood WITHOUT a valid attestation is DROPPED
        // (never applied on a peer's word — the mesh-wide griefing hole is closed).
        let reserved_txid = [0x7Bu8; 32];
        let envelope = Envelope {
            peer: test_socket(),
            message: WireMessage::Gossip(GossipMessage::Recall {
                txid: reserved_txid,
                sender_pk: vec![0xB2u8; 32],
                recall_tick: 501,
                committed: false,
                attestation: None,
            }),
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };
        let _ = handle_message(&mut state, &envelope);
        assert!(!state.core.smt().is_txid_recall_pending(&reserved_txid),
            "a reservation with no verified attestation must be dropped, not applied");
        assert_eq!(state.garbage_state_chain.lookup(&reserved_txid),
            axiom_nabla::bloom_chain::ChainLookup::Miss,
            "a dropped reservation must NOT enter the garbage chain");
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
                external_port: 6225,
                downstream_count: 0,
                nbc_bytes: vec![],
                nbc_supporting_bytes: vec![],
                txid_service: String::new(),
                observed_peer_ip: None,
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
                external_port: 6225,
                downstream_count: 0,
                nbc_bytes,
                nbc_supporting_bytes: vec![],
                txid_service: String::new(),
                observed_peer_ip: None,
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
                external_port: 7300,
                has_children: false,
                prefer_writer: false,
                nbc_bytes,
                nbc_supporting_bytes: vec![],
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
                external_port: 7300,
                has_children: false,
                prefer_writer: false,
                nbc_bytes,
                nbc_supporting_bytes: vec![],
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
        make_join_request_at(sphincs_pk, 500)
    }

    /// Same, with the NBC's `issued_at` chosen — §5.6c judges probation from
    /// that stamp, so the tests below place it relative to `virtual_secs`.
    fn make_join_request_at(sphincs_pk: &[u8; 32], issued_at: u64) -> (Vec<u8>, WalletId, Vec<u8>, Vec<u8>, NBC) {
        use ed25519_dalek::{SigningKey, Signer as DalekSigner};

        let nbc = make_real_nbc(sphincs_pk, &[0xEE; 32], issued_at);
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
        // Certificate issued NOW → inside the §5.6c window.
        let (nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig, nbc) =
            make_join_request_at(&[0xAA; 32], state.virtual_secs);
        let nabla_id = nbc.validator_id;

        let (accepted, reason, probation_until, gossip) =
            state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);

        assert!(accepted, "valid join should be accepted: {}", reason);
        assert!(probation_until > state.virtual_secs,
            "probation_until should be in the future");
        assert_eq!(probation_until, nbc.issued_at + nabla_probation_span_secs(),
            "probation_until = the certificate's issued_at + the projected window (§5.6c)");

        // Cached; status DERIVED from the certificate.
        let peer = state.verified_peers.get(&nabla_id).unwrap();
        assert_eq!(peer.trust_status(state.virtual_secs), NbcTrustStatus::Probation);
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

    /// GUIDE §5.6c lever 1(b) — the ONE rule the three upstream-candidate
    /// loops apply (P1 piggyback, P2 known peers, reattach merge): a peer
    /// whose VERIFIED NBC is inside the window is skipped; a confirmed peer
    /// and an unknown peer are not (the unknown case is the loops' own
    /// fail-closed "no NBC → no address" rule, not this one). Mutating
    /// `upstream_candidate_probationary` to `false` goes red here.
    #[test]
    fn upstream_candidate_skips_probationary_peer() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        // KI#240: the clock must be past ONE whole probation span or `aged`
        // saturates to issued_at 0 and is still probationary. Under the old
        // always-dev twin (60 ticks) the fixture's clock happened to clear it;
        // the REAL 48 h span (nabla `dev-tuning` off) exposed the assumption.
        state.virtual_secs = state.virtual_secs.max(2 * nabla_probation_span_secs());
        let now = state.virtual_secs;
        let fresh = make_real_nbc(&[0xC1; 32], &[0xC1; 32], now);
        let aged = make_real_nbc(&[0xC2; 32], &[0xC2; 32], now.saturating_sub(nabla_probation_span_secs()));
        let (fresh_id, aged_id) = (nbc_node_id(&fresh), nbc_node_id(&aged));
        state.verified_nbcs.insert(fresh_id, fresh);
        state.verified_nbcs.insert(aged_id, aged);

        assert!(state.upstream_candidate_probationary(&fresh_id),
            "a fresh citizen NBC is never chosen as upstream");
        assert!(!state.upstream_candidate_probationary(&aged_id),
            "a confirmed peer is a normal candidate");
        assert!(!state.upstream_candidate_probationary(&nid(0x77)),
            "no NBC on file → not THIS rule's concern");

        // Expiry is automatic — the same peer is a candidate one window later.
        state.virtual_secs = now + nabla_probation_span_secs();
        assert!(!state.upstream_candidate_probationary(&fresh_id));
    }

    #[test]
    fn probation_completes_after_window() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let (nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig, nbc) =
            make_join_request_at(&[0xDD; 32], state.virtual_secs);
        let nabla_id = nbc.validator_id;

        state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);
        assert_eq!(state.verified_peers.get(&nabla_id).unwrap().trust_status(state.virtual_secs),
            NbcTrustStatus::Probation);

        // Advance virtual time to the window's end — NO promotion call exists;
        // the status is recomputed from the certificate on read.
        state.virtual_secs = nbc.issued_at + nabla_probation_span_secs();
        let peer = state.verified_peers.get(&nabla_id).unwrap();
        assert_eq!(peer.trust_status(state.virtual_secs), NbcTrustStatus::Confirmed,
            "peer is Confirmed once its certificate has aged past the window");
    }

    /// The window is anchored to the CERTIFICATE's `issued_at`, not to the
    /// receiving node's clock at join — a certificate issued half a window
    /// ago reports a `probation_until` half a window away, whatever
    /// `virtual_secs` says.
    #[test]
    fn probation_uses_certificate_stamp_not_join_clock() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        state.virtual_secs = 1_000_000; // arbitrary virtual time
        let issued_at = 1_000_000 - nabla_probation_span_secs() / 2;
        let (nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig, nbc) =
            make_join_request_at(&[0xEE; 32], issued_at);
        let nabla_id = nbc.validator_id;

        let (accepted, _, probation_until, _) =
            state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);
        assert!(accepted);
        assert_eq!(probation_until, issued_at + nabla_probation_span_secs(),
            "anchored to issued_at");
        assert_ne!(probation_until, state.virtual_secs + nabla_probation_span_secs(),
            "NOT anchored to the join clock (the pre-§5.6c behaviour)");

        state.virtual_secs = issued_at + nabla_probation_span_secs();
        assert_eq!(state.verified_peers.get(&nabla_id).unwrap().trust_status(state.virtual_secs),
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
        // A genesis certificate (`chain_depth == 0`) issued NOW is still exempt.
        let nbc = make_real_nbc_at_depth(&[0xAA; 32], &[0xBB; 32], state.virtual_secs, 0);
        let node_id = nbc_node_id(&nbc);
        assert!(!cc::is_probationary(&nbc, state.virtual_secs), "genesis is exempt at issue");

        state.verified_peers.insert(node_id, PeerTrust { nbc: nbc.clone(), wallet_id: None });
        assert_eq!(state.verified_peers.get(&node_id).unwrap().trust_status(state.virtual_secs),
            NbcTrustStatus::Genesis);

        // And it is neither skipped as an upstream nor excluded from OODS.
        state.verified_nbcs.insert(node_id, nbc);
        assert!(!state.upstream_candidate_probationary(&node_id));
        assert!(state.oods_baseline_ids().contains(&node_id));
    }

    #[test]
    fn confirmed_node_rejoins_without_probation() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let (nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig, nbc) =
            make_join_request_at(&[0xFF; 32], state.virtual_secs);
        let nabla_id = nbc.validator_id;

        // First join → probation
        let (_, _, first_until, _) =
            state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);
        assert_eq!(first_until, nbc.issued_at + nabla_probation_span_secs());

        // The window elapses (no promotion call — derived on read)
        state.virtual_secs = nbc.issued_at + nabla_probation_span_secs();
        assert_eq!(state.verified_peers.get(&nabla_id).unwrap().trust_status(state.virtual_secs),
            NbcTrustStatus::Confirmed);

        // Rejoin — accepted, no window reported, no re-announce
        let (accepted, _, probation_until, gossip) =
            state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);
        assert!(accepted, "confirmed node rejoin should be accepted");
        assert_eq!(probation_until, 0, "confirmed node should have no probation");
        assert!(gossip.is_none(), "confirmed rejoin should not gossip");
    }

    /// A re-join cannot reset the window: there is no local `since` any more,
    /// so a reconnect half-way reports the SAME `probation_until` as the
    /// first join (anchored to the certificate).
    #[test]
    fn probation_node_reconnects_window_does_not_reset() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        state.virtual_secs = 1_000_000;

        let (nbc_bytes, wallet_id, wallet_pubkey, wallet_binding_sig, nbc) =
            make_join_request_at(&[0xAB; 32], 1_000_000);
        let nabla_id = nbc.validator_id;

        // First join at virtual_secs = 1_000_000
        let (_, _, first_until, _) =
            state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);
        assert_eq!(first_until, 1_000_000 + nabla_probation_span_secs());

        // Half the window passes
        state.virtual_secs = 1_000_000 + nabla_probation_span_secs() / 2;

        // Reconnect — the reported end must NOT move
        let (accepted, _, probation_until, gossip) =
            state.handle_join_request(&nbc_bytes, &wallet_id, &wallet_pubkey, &wallet_binding_sig);
        assert!(accepted, "reconnecting probation node should be accepted");
        assert_eq!(probation_until, first_until,
            "probation window must NOT restart on reconnection");
        assert_eq!(state.verified_peers.get(&nabla_id).unwrap().trust_status(state.virtual_secs),
            NbcTrustStatus::Probation);
        assert!(gossip.is_none(), "reconnect should not re-gossip");
    }

    // ── GUIDE §5.6c — the five levers, driven ──────────────────────────────

    /// Build a state whose OWN NBC was issued at `issued_at` (citizen, depth 1).
    fn make_state_issued_at(sphincs_pk: &[u8], issued_at: u64) -> (NablaNodeState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let nbc = make_real_nbc(sphincs_pk, &[0x01; 32], issued_at);
        let node_id = nbc_node_id(&nbc);
        let signer = Box::new(axiom_nabla::crypto::NoopSigner);
        let mut state = NablaNodeState::new(node_id, test_addr(), dir.path(), signer, None, true, axiom_nabla::bloom::TxidServiceMode::Bloom, true);
        state.virtual_secs = issued_at;
        state.accept_nbc(nbc);
        (state, dir)
    }

    fn attach_request_from(peer_sphincs: &[u8; 32]) -> Envelope {
        let nbc = make_real_nbc(peer_sphincs, &[0xCD; 32], 500);
        Envelope {
            peer: "198.51.100.23:61000".parse().unwrap(),
            message: WireMessage::TardisAttachRequest {
                node_id: nbc_node_id(&nbc),
                external_port: 7301,
                has_children: false,
                prefer_writer: false,
                nbc_bytes: serialize_nbc(&nbc),
                nbc_supporting_bytes: vec![],
            },
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        }
    }

    fn attach_verdict(outbound: &[(std::net::SocketAddr, WireMessage)]) -> bool {
        outbound.iter().find_map(|(_, m)| match m {
            WireMessage::TardisAttachResponse { accepted, .. } => Some(*accepted),
            _ => None,
        }).expect("an attach request must be answered")
    }

    /// Lever 1(a): while OUR NBC is inside the window we refuse every
    /// TardisAttachRequest (accepted: false, downstream stays 0 — never a
    /// writer), count it, and take no P child either; the same request is
    /// accepted once the window has passed. Mutating `own_nbc_probationary`
    /// to `false` goes red on the first half; deleting the counter increment
    /// goes red on the count.
    #[test]
    fn probationary_node_refuses_attach_then_accepts_after_window() {
        let (mut state, _dir) = make_state_issued_at(&[0x02; 32], 1000);
        assert!(state.own_nbc_probationary(), "premise: our NBC was issued now");

        let outbound = handle_message(&mut state, &attach_request_from(&[0xAB; 32]));
        assert!(!attach_verdict(&outbound), "refused while probationary");
        assert_eq!(state.core.tardis().unwrap().downstream_count(), 0, "no D child taken");
        assert!(state.core.tardis().unwrap().pending().is_none(), "no P child taken either");
        assert_eq!(state.probation_attach_refusals, 1);
        assert_eq!(state.probation_refusals_total(), 1);

        // The window passes — the SAME node now accepts the SAME request.
        state.virtual_secs = 1000 + nabla_probation_span_secs();
        assert!(!state.own_nbc_probationary());
        let outbound = handle_message(&mut state, &attach_request_from(&[0xAB; 32]));
        assert!(attach_verdict(&outbound), "accepted after the window");
        assert_eq!(state.core.tardis().unwrap().downstream_count(), 1);
        assert_eq!(state.probation_attach_refusals, 1, "no new refusal");
    }

    // ── YPX-003 §2.1 P slot (KI#48, RULED 2026-09-25) — the wire half ──────

    /// The P grant on the wire: `accepted: true, pending: true`. A probationary
    /// host grants NEITHER (KI#75 rule kept — asserted by `pending == false` on
    /// its refusal), and the same host, out of probation with both D slots
    /// full, parks the requester: `pending()` is the requester and
    /// `downstream_count` is unchanged (P is never a D).
    #[test]
    fn p_slot_host_grants_pending_when_d_full_never_when_probationary() {
        fn verdict(outbound: &[(std::net::SocketAddr, WireMessage)]) -> (bool, bool) {
            outbound.iter().find_map(|(_, m)| match m {
                WireMessage::TardisAttachResponse { accepted, pending, .. } => Some((*accepted, *pending)),
                _ => None,
            }).expect("an attach request must be answered")
        }
        // Probationary host: neither D nor P.
        let (mut state, _dir) = make_state_issued_at(&[0x02; 32], 1000);
        assert!(state.own_nbc_probationary());
        let out = handle_message(&mut state, &attach_request_from(&[0xAB; 32]));
        assert_eq!(verdict(&out), (false, false), "KI#75: a probationary host grants neither");
        assert!(state.core.tardis().unwrap().pending().is_none());

        // Out of probation, D slots full → P grant.
        state.virtual_secs = 1000 + nabla_probation_span_secs();
        state.core.tardis_mut().unwrap().set_upstream(nid(0x0A));
        assert!(state.core.tardis_mut().unwrap().add_downstream(nid(0xD1)));
        assert!(state.core.tardis_mut().unwrap().add_downstream(nid(0xD2)));
        assert!(!state.core.tardis().unwrap().has_d_open());
        let req = attach_request_from(&[0xAB; 32]);
        let requester = match &req.message {
            WireMessage::TardisAttachRequest { node_id, .. } => *node_id,
            _ => unreachable!(),
        };
        let out = handle_message(&mut state, &req);
        assert_eq!(verdict(&out), (true, true), "D full, P free ⇒ accepted+pending");
        assert_eq!(state.core.tardis().unwrap().pending(), Some(&requester));
        assert_eq!(state.core.tardis().unwrap().downstream_count(), 2, "P is never a D");
        assert!(state.core.tardis().unwrap().children().contains(&requester), "…but a tick target");

        // A second orphan finds the P slot taken → plain refusal with referrals.
        let out = handle_message(&mut state, &attach_request_from(&[0xAC; 32]));
        assert_eq!(verdict(&out), (false, false), "one P slot per host");
        // The parked requester asking again is re-granted, not refused.
        let out = handle_message(&mut state, &attach_request_from(&[0xAB; 32]));
        assert_eq!(verdict(&out), (true, true), "re-grant to the current P child");
    }

    /// The requester half: on `pending: true` an ORPHAN parks (`is_parked`,
    /// `needs_parent` STILL TRUE, tick source = host); a later D acceptance
    /// from another node seats it and sends `TardisDetach` to the P host
    /// (§2.1 step 3), counted on `/status`. A seated node answers a stray P
    /// grant with `TardisDetach` so the host's P slot is not leaked.
    ///
    /// MUTATION: drop the `was_parked` detach → the P-host detach assertion
    /// goes red (the host would keep a phantom P child).
    #[test]
    fn p_slot_requester_parks_keeps_seeking_and_detaches_when_seated() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let host = nid(0xA0);
        let seat = nid(0xB0);
        let host_addr: std::net::SocketAddr = "198.51.100.10:6225".parse().unwrap();
        let host_nabla_addr = from_socket_addr(host_addr);
        state.core.mesh_mut().unwrap().add_peer_direct(PeerInfo {
            node_id: host, address: host_nabla_addr.clone(), last_seen: 1000,
            tardis_up: None, has_d_open: false, open_slots: 0,
            messages_delivered: 0, connected_since: 1000, txid_service: String::new(),
        });
        let resp = |node_id: NodeId, pending: bool| Envelope {
            peer: "198.51.100.10:61001".parse().unwrap(),
            message: WireMessage::TardisAttachResponse {
                node_id, accepted: true, pending, downstream_count: 2,
                referrals: vec![], nbc_bytes: vec![], nbc_supporting_bytes: vec![],
            },
            reply_stream: None, cbor_client: false, wire_bytes: 0,
        };

        assert!(state.core.tardis().unwrap().needs_parent(), "premise: orphan");
        let out = handle_message(&mut state, &resp(host, true));
        assert!(out.is_empty(), "parking sends nothing: {out:?}");
        let t = state.core.tardis().unwrap();
        assert!(t.is_parked(), "parked on pending:true");
        assert_eq!(t.upstream(), Some(&host), "the host is the tick source");
        assert!(t.needs_parent(), "§2.1: still seeking a D slot while parked");
        assert!(!t.has_upstream() && !t.is_self_writer());
        assert_eq!(state.tardis_parked_grants, 1);

        // A re-grant from the same host: no-op, never a detach (KI#48 guard).
        let out = handle_message(&mut state, &resp(host, true));
        assert!(out.is_empty(), "re-grant from our host is a no-op: {out:?}");

        // A D slot elsewhere: seat there, tell the P host we left.
        let out = handle_message(&mut state, &resp(seat, false));
        let t = state.core.tardis().unwrap();
        assert!(t.has_upstream() && !t.is_parked() && !t.needs_parent());
        assert_eq!(t.upstream(), Some(&seat));
        let detach_to_host = out.iter().any(|(addr, m)|
            *addr == host_addr && matches!(m, WireMessage::TardisDetach { node_id } if *node_id == state.node_id));
        assert!(detach_to_host, "landing a D slot must send TardisDetach to the P host: {out:?}");
        assert_eq!(state.tardis_parked_to_seated, 1);

        // Seated: a stray P grant is declined by freeing the host's slot.
        let out = handle_message(&mut state, &resp(host, true));
        assert!(out.iter().any(|(addr, m)| *addr == host_addr && matches!(m, WireMessage::TardisDetach { .. })),
            "a seated node frees a P slot it did not ask for: {out:?}");
        assert!(state.core.tardis().unwrap().has_upstream(), "…and stays seated");
    }

    /// YPX-002 §9.1.1a wiring: with the current epoch's budget SPENT, the
    /// handler refuses with `ISSUER_CAP_REACHED` (counted, nothing signed);
    /// one epoch later the SAME request is signed and the budget for the new
    /// epoch reads 1. Also proves the budget survives a restart through the
    /// snapshot the handler writes (a fresh `NablaNodeState` over the same
    /// data dir reads the count back).
    ///
    /// MUTATION: delete the `at_cap` check in `handle_nbc_issuance_request` →
    /// the refusal assertion goes red (a certificate is signed instead).
    #[test]
    fn nbc_issuance_refused_at_cap_then_signed_next_epoch_and_budget_persists() {
        // A QUALIFIED issuer: SPHINCS+ SK loaded, own NBC mature + unexpired.
        // The own NBC's subject key must be the pk of the sk we sign with —
        // `issue_nbc` verifies its own signature against it after signing.
        let (pks, sks) = make_issuer_keys();
        let dir = tempfile::tempdir().unwrap();
        let own = make_real_nbc(&pks[0], &[0x0B; 32], 500);
        let node_id = nbc_node_id(&own);
        let mut state = NablaNodeState::new(node_id, test_addr(), dir.path(),
            Box::new(axiom_nabla::crypto::NoopSigner), None, true,
            axiom_nabla::bloom::TxidServiceMode::Bloom, true);
        state.accept_nbc(own);
        state.sphincs_sk = Some(sks[0].clone());
        let span = axiom_nabla::constants::fob_epoch_span_secs(false);
        // Land inside an epoch well past maturity.
        let epoch = (500 + NBC_ISSUER_MATURITY_SECS) / span + 2;
        state.virtual_secs = epoch * span + 1;
        assert!(is_qualified_issuer(state.core.cc_chain().unwrap().nbc(),
            state.sphincs_sk.as_deref(), NBC_ISSUER_MATURITY_SECS, state.virtual_secs), "premise");

        // Spend the budget for THIS epoch (N certificates already signed).
        for _ in 0..NBC_ISSUANCE_MAX_PER_EPOCH {
            state.core.nbc_issuance_budget_mut().record(epoch);
        }
        let (ok, bytes, _, reason) = state.handle_nbc_issuance_request(
            &[0x11; 32], &[0x22; 32], &[0u8; 1952], "citizen-x", "");
        assert!(!ok && bytes.is_empty(), "the N+1-th in the epoch is REFUSED, nothing signed");
        assert_eq!(reason, NBC_ISSUER_CAP_REACHED);
        assert_eq!(state.nbc_issuance_refused_cap, 1);

        // Next epoch: signed, and the new epoch's count is 1.
        state.virtual_secs = (epoch + 1) * span + 1;
        let (ok, bytes, _, reason) = state.handle_nbc_issuance_request(
            &[0x11; 32], &[0x22; 32], &[0u8; 1952], "citizen-x", "");
        assert!(ok && !bytes.is_empty(), "the N+1-th in the NEXT epoch is signed: {reason}");
        assert_eq!(state.core.nbc_issuance_budget().count_in(epoch + 1), 1);
        assert_eq!(state.nbc_issuance_refused_cap, 1, "no new refusal");

        // Restart over the same data dir: the budget came back from the snapshot
        // the handler wrote after signing.
        drop(state);
        let restarted = NablaNodeState::new(node_id, test_addr(), dir.path(),
            Box::new(axiom_nabla::crypto::NoopSigner), None, true,
            axiom_nabla::bloom::TxidServiceMode::Bloom, true);
        assert_eq!(restarted.core.nbc_issuance_budget().count_in(epoch + 1), 1,
            "a restart must not reset the issuer budget (§9.1.1a)");
    }

    /// The host promotes its P child itself (`promote_pending`, existing) and
    /// tells it with `accepted: true, pending: false`; the child's
    /// `set_upstream` flips Pending → Connected in place, no detach.
    #[test]
    fn p_slot_host_promotion_seats_the_parked_child_in_place() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let host = nid(0xA0);
        let resp = |pending: bool| Envelope {
            peer: "198.51.100.10:61001".parse().unwrap(),
            message: WireMessage::TardisAttachResponse {
                node_id: host, accepted: true, pending, downstream_count: 1,
                referrals: vec![], nbc_bytes: vec![], nbc_supporting_bytes: vec![],
            },
            reply_stream: None, cbor_client: false, wire_bytes: 0,
        };
        handle_message(&mut state, &resp(true));
        assert!(state.core.tardis().unwrap().is_parked());
        let out = handle_message(&mut state, &resp(false));
        assert!(!out.iter().any(|(_, m)| matches!(m, WireMessage::TardisDetach { .. })),
            "promotion by our own host is not a move — no detach: {out:?}");
        let t = state.core.tardis().unwrap();
        assert!(t.has_upstream() && !t.is_parked() && t.upstream() == Some(&host));
        assert_eq!(state.tardis_parked_to_seated, 0, "not counted as a move");
    }

    /// Lever 2: a probationary NBC is not in the identity set the OODS
    /// baseline is estimated over; it appears once the window passes.
    /// Mutating the filter in `oods_baseline_ids` goes red here.
    #[test]
    fn oods_baseline_excludes_probationary_nbcs() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        // KI#240: the clock must be past ONE whole probation span or `aged`
        // saturates to issued_at 0 and is still probationary. Under the old
        // always-dev twin (60 ticks) the fixture's clock happened to clear it;
        // the REAL 48 h span (nabla `dev-tuning` off) exposed the assumption.
        state.virtual_secs = state.virtual_secs.max(2 * nabla_probation_span_secs());
        let now = state.virtual_secs;
        let aged = make_real_nbc(&[0xD1; 32], &[0xD1; 32], now.saturating_sub(nabla_probation_span_secs()));
        let fresh = make_real_nbc(&[0xD2; 32], &[0xD2; 32], now);
        let (aged_id, fresh_id) = (nbc_node_id(&aged), nbc_node_id(&fresh));
        state.verified_nbcs.insert(aged_id, aged);
        state.verified_nbcs.insert(fresh_id, fresh);

        let ids = state.oods_baseline_ids();
        assert!(ids.contains(&aged_id), "confirmed peer counted");
        assert!(!ids.contains(&fresh_id), "probationary peer NOT counted");
        assert_eq!(state.probationary_peer_count(), 1, "/status probationary_peers");

        state.virtual_secs = now + nabla_probation_span_secs();
        let ids = state.oods_baseline_ids();
        assert!(ids.contains(&fresh_id), "counted once confirmed");
        assert_eq!(state.probationary_peer_count(), 0);
    }

    /// Lever 3: the subject check a chain-verified EmissionNabla certificate
    /// must pass — NOT_ELIGIBLE (internally marked as probation, so the
    /// dispatcher can count it) inside the window, eligible after; a genesis
    /// Nabla is refused regardless. Mutating `is_probationary` out of
    /// `nabla_emission_subject_eligible` goes red on the first assert.
    #[test]
    fn emission_nabla_subject_not_eligible_inside_probation_eligible_after() {
        let tick = 1_000_000u64;
        let cert = make_real_nbc(&[0xE1; 32], &[0xE1; 32], tick);
        assert_eq!(nabla_emission_subject_eligible(&cert, tick), Err(EMISSION_PROBATION_REFUSAL),
            "inside the window");
        assert_eq!(nabla_emission_subject_eligible(&cert, tick + nabla_probation_span_secs() - 1),
            Err(EMISSION_PROBATION_REFUSAL), "one second before expiry");
        assert_eq!(nabla_emission_subject_eligible(&cert, tick + nabla_probation_span_secs()), Ok(()),
            "eligible at expiry");
        // The wire never sees the internal marker: the dispatcher maps it to
        // the spec's NOT_ELIGIBLE (asserted by prefix so the mapping site
        // cannot be forgotten silently).
        assert!(EMISSION_PROBATION_REFUSAL.starts_with("NOT_ELIGIBLE"));

        let mut genesis = cert.clone();
        genesis.subject_pubkey_sphincs =
            axiom_core_logic::nabla_genesis::NABLA_GENESIS_VALIDATOR_PKS[0].to_vec();
        assert_eq!(nabla_emission_subject_eligible(&genesis, tick + nabla_probation_span_secs()),
            Err("NOT_ELIGIBLE"), "a genesis Nabla never shares the emission");
    }

    /// Lever 4: an Alert whose PROVEN intermediate sender holds a
    /// probationary NBC is withheld (not handed to `handle_alert`, not
    /// forwarded) and counted; the same alert is processed once the sender's
    /// window has passed. Mutating the `peer_nbc_probationary` arm out of the
    /// Alert gate goes red on the count.
    #[test]
    fn alert_from_probationary_peer_is_withheld() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        state.skip_verify = false; // the KI#72 proof path (NoopSigner verifies)
        let now = state.virtual_secs;
        let sender = make_real_nbc(&[0xA1; 32], &[0xA1; 32], now);
        let sender_id = nbc_node_id(&sender);
        state.verified_nbcs.insert(sender_id, sender);

        let alert = || Envelope {
            peer: "198.51.100.9:50000".parse().unwrap(),
            message: WireMessage::Gossip(GossipMessage::Alert {
                alert_type: AlertType::PoolInvariantViolation,
                accused: nid(0xBB),
                evidence: vec![1, 2, 3],
                origin_emitter: nid(0xCC),
                intermediate_emitter: sender_id,
                emitted_at_tick: now,
                intermediate_sig: vec![0u8; 64],
            }),
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        };

        let outbound = handle_message(&mut state, &alert());
        assert_eq!(state.alert_identity_proven, 1, "premise: the sender was proven");
        assert_eq!(state.probation_alert_refusals, 1, "withheld and counted");
        assert!(outbound.is_empty(), "nothing forwarded");

        state.virtual_secs = now + nabla_probation_span_secs();
        let _ = handle_message(&mut state, &alert());
        assert_eq!(state.alert_identity_proven, 2);
        assert_eq!(state.probation_alert_refusals, 1, "processed once confirmed — no new refusal");
    }

    /// Lever 5: the serve-gate's pool half stays closed until an
    /// authenticated PoolSync has been applied for EVERY serve-gate kind
    /// (a BoundedFee sync does not count toward it), opens exactly when the
    /// last one lands, and is exempt only for the first node of a mesh.
    /// Mutating `pool_sync_gate_open` to `true` goes red on the first assert.
    #[test]
    fn serve_gate_pool_half_opens_only_when_every_kind_synced() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        assert!(!state.pool_sync_gate_open(), "closed at start");
        assert!(state.pool_synced_kind_names().is_empty());

        state.note_pool_synced(PoolKind::BoundedFee([0x55; 32], false));
        assert!(!state.pool_sync_gate_open(), "a per-validator pool is not a serve-gate kind");
        assert_eq!(state.pool_synced_kind_names(), vec!["bounded_fee".to_string()]);

        let kinds = PoolKind::SERVE_GATE_KINDS;
        for (i, kind) in kinds.iter().enumerate() {
            let completed = state.note_pool_synced(*kind);
            if i + 1 < kinds.len() {
                assert!(!state.pool_sync_gate_open(), "still missing {} kind(s)", kinds.len() - i - 1);
                assert!(!completed);
            } else {
                assert!(completed, "the last kind completes the set exactly once");
                assert!(state.pool_sync_gate_open());
            }
        }
        assert!(!state.note_pool_synced(PoolKind::Airdrop), "a repeat does not re-complete");
        assert_eq!(state.pool_synced_kind_names().len(), kinds.len() + 1);

        // First node of a mesh: exempt (nobody to sync from), mirroring KI#42.
        let (mut first, _d) = make_state(&[0x03; 32]);
        assert!(!first.pool_sync_gate_open());
        first.pool_sync_gate_exempt = true;
        assert!(first.pool_sync_gate_open());
    }

    /// The tick pass logs a crossing exactly once: a peer probationary on
    /// pass N and confirmed on pass N+1 leaves the tracked set (the log line
    /// fires on that transition); it is not re-added.
    #[test]
    fn probation_tick_pass_tracks_crossings() {
        let (mut state, _dir) = make_state(&[0x01; 32]);
        let now = state.virtual_secs;
        let fresh = make_real_nbc(&[0xF1; 32], &[0xF1; 32], now);
        let fresh_id = nbc_node_id(&fresh);
        state.verified_nbcs.insert(fresh_id, fresh);

        state.probation_tick_pass();
        assert!(state.probationary_last_pass.contains(&fresh_id));
        state.virtual_secs = now + nabla_probation_span_secs();
        state.probation_tick_pass();
        assert!(!state.probationary_last_pass.contains(&fresh_id), "crossed out");
        state.probation_tick_pass();
        assert!(state.probationary_last_pass.is_empty());
    }

    // ── ForkSettlement wave 3 S8 — the origin-vouch boot floor [R9/R13/R34] ──

    /// The floor is UNSET until `recv_loop` is live — a node that is not yet
    /// listening vouches for nothing, whatever its clock says — and is stamped
    /// on the first step after (a stamp, not a re-floor). MUTATION: ignore
    /// `recv_loop_live` in `origin_boot_step` ⇒ RED.
    #[test]
    fn origin_boot_unset_until_recv_loop_live() {
        let t = origin_refloor_secs();
        assert_eq!(origin_boot_step(0, 1_000, None, false, t), (None, false), "startup, not listening");
        assert_eq!(origin_boot_step(1_000, 1_005, None, false, t), (None, false), "still not listening");
        assert_eq!(origin_boot_step(1_005, 1_010, None, true, t), (Some(1_010), false), "stamped when live");
        assert_eq!(origin_boot_step(1_010, 1_015, Some(1_010), true, t), (Some(1_010), false), "then held");
    }

    /// A tick-loop STALL longer than the DEV settle twin re-floors the boot to
    /// `now` (a leg may have gone un-flooded / un-AE'd meanwhile); a gap of
    /// exactly the threshold does not. The threshold IS the smaller (dev)
    /// twin [R34]. MUTATION: compare against the real twin, or `>=` → `>` flip
    /// at the boundary, or never re-floor ⇒ RED.
    #[test]
    fn origin_boot_refloors_on_stall_gt_threshold() {
        let t = origin_refloor_secs();
        let dev = axiom_core_logic::validation::SCAR_SETTLE_TICKS_DEV.to_secs();
        let real = axiom_core_logic::validation::SCAR_SETTLE_TICKS.to_secs();
        assert_eq!(t, dev.min(real), "the threshold is the SMALLER (dev) settle twin");
        assert!(dev < real, "fixture: the twins differ");
        let boot = Some(5_000);
        assert_eq!(origin_boot_step(6_000, 6_000 + t, boot, true, t), (boot, false), "== threshold: no re-floor");
        assert_eq!(origin_boot_step(6_000, 6_000 + t + 1, boot, true, t), (Some(6_000 + t + 1), true),
            "stall > threshold: re-floored to now");
    }

    /// A BACKWARD wall-clock jump never re-floors (plan A5) — it could only
    /// delay vouching, never advance it, so there is nothing to protect.
    /// MUTATION: use an absolute difference ⇒ RED.
    #[test]
    fn origin_boot_no_refloor_on_backward_jump() {
        let t = origin_refloor_secs();
        let boot = Some(5_000);
        assert_eq!(origin_boot_step(9_000, 1_000, boot, true, t), (boot, false));
    }

    // ── Step 5: TCP hardening tests ──

    #[test]
    fn is_critical_message_classification() {
        // Critical messages: Tick, Approval, AttachRequest, AttachResponse, Detach
        assert!(is_critical_message(&WireMessage::Tick(TickMessage {
            child_pks: vec![],
            gp_commitment: None,
            oods_tardis: vec![],
            number: 1, upstream_pk: [0; 32], payload: vec![], signature: vec![],
            timestamp_ms: 0, prev_sig: vec![], grandparent_pk: None, available_slots: vec![],
            downstream_approvals: 0, subtree_d_available: 0,

        })));
        assert!(is_critical_message(&WireMessage::Approval(TickApproval {
            tick_number: 1, approver_pk: [0; 32], signature: vec![], subtree_open_d: 0,
        })));
        assert!(is_critical_message(&WireMessage::TardisAttachRequest {
            node_id: [0; 32], external_port: 7300,
            has_children: false, prefer_writer: false, nbc_bytes: vec![],
            nbc_supporting_bytes: vec![],
        }));
        assert!(is_critical_message(&WireMessage::TardisAttachResponse {
            node_id: [0; 32], accepted: true, pending: false, downstream_count: 0, referrals: vec![], nbc_bytes: vec![],
            nbc_supporting_bytes: vec![],
        }));
        assert!(is_critical_message(&WireMessage::TardisDetach {
            node_id: [0; 32],
        }));

        // Non-critical: Hello, Gossip, Query, StatusRequest
        assert!(!is_critical_message(&WireMessage::Hello {
            node_id: [0; 32], external_port: 6225,
            downstream_count: 0, nbc_bytes: vec![], txid_service: String::new(),
            observed_peer_ip: None,
            nbc_supporting_bytes: vec![],
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

    // ── KI#46 fact-confirm authorship carry (zero-pk flip) ──────────────
    //
    // Behaviour under test: which sig a fact-confirm re-carries, and hence
    // whether it emits a gossip re-advertisement at all. Pre-flip this site
    // clobbered stored authorship to zero on EVERY confirm; post-flip a
    // zero-pk StateUpdate is dropped by every receiver, so emitting one is
    // guaranteed-dead traffic. These pin both halves.

    fn ca_entry(state: u8, tx: u8, pk: u8) -> axiom_nabla::types::NablaEntry {
        axiom_nabla::types::NablaEntry {
            received_from: None,
            wallet_id: [0xAA; 32],
            current_state: [state; 32],
            tx_hash: [tx; 32],
            tick: 7,
            wallet_seq: 3,
            group_members: None,
            status: axiom_nabla::types::WalletStatus::Normal,
            client_pk: [pk; 32],
            client_sig: vec![pk; 64],
        }
    }

    #[test]
    fn confirm_authorship_carries_matching_stored_sig() {
        // The head the confirm names IS the stored head → carry its authorship,
        // so the re-advertisement is verifiable and the entry stays AE-adoptable.
        let e = ca_entry(0x11, 0x22, 0xC0);
        let (pk, sig) = confirm_authorship(Some(&e), &[0x11; 32], &[0x22; 32]);
        assert_eq!(pk, [0xC0; 32], "must re-carry the stored client_pk");
        assert_eq!(sig, vec![0xC0u8; 64], "must re-carry the stored client_sig");
    }

    #[test]
    fn confirm_authorship_refuses_mismatched_state_or_txid() {
        // A sig taken from a DIFFERENT head cannot verify against this one, so
        // carrying it would ship noise. Both discriminators must match.
        let e = ca_entry(0x11, 0x22, 0xC0);
        let (pk, sig) = confirm_authorship(Some(&e), &[0x99; 32], &[0x22; 32]);
        assert_eq!(pk, [0u8; 32], "state mismatch must not carry the sig");
        assert!(sig.is_empty());
        let (pk, sig) = confirm_authorship(Some(&e), &[0x11; 32], &[0x99; 32]);
        assert_eq!(pk, [0u8; 32], "tx_hash mismatch must not carry the sig");
        assert!(sig.is_empty());
    }

    #[test]
    fn confirm_authorship_zero_when_unauthored_or_absent() {
        // A stored-but-unauthored entry (legacy debris) and a missing entry both
        // yield zero — which is the caller's signal to SKIP the emission rather
        // than flood something every receiver drops.
        let legacy = ca_entry(0x11, 0x22, 0x00);
        let (pk, sig) = confirm_authorship(Some(&legacy), &[0x11; 32], &[0x22; 32]);
        assert_eq!(pk, [0u8; 32], "zero-pk stored entry carries nothing");
        assert!(sig.is_empty());
        let (pk, sig) = confirm_authorship(None, &[0x11; 32], &[0x22; 32]);
        assert_eq!(pk, [0u8; 32], "absent entry carries nothing");
        assert!(sig.is_empty());
    }

    /// ForkSettlement wave 4a — the witness directory on the WIRE: R50
    /// authenticated AE (spoofed `from`, replies to the LISTEN address, never
    /// `send_reply`), off-lock adoption, and the register path's R42 verdict.
    /// Real keys: Ed25519 node / subject keys, real-SPHINCS+ NBCs
    /// (`make_real_nbc`). Each test names the mutation that must turn it RED.
    mod vbc_directory_wire {
        use super::*;
        use axiom_nabla::vbc_directory as dir;
        use ed25519_dalek::{Signer as _, SigningKey};

        /// A node whose signer is a REAL Ed25519 key and whose own NBC names it
        /// (the production shape — `make_state` uses `NoopSigner`, whose empty
        /// signatures no peer could verify).
        fn signed_state(seed: u8) -> (NablaNodeState, tempfile::TempDir) {
            let dir = tempfile::tempdir().unwrap();
            let signer = axiom_nabla::crypto::Ed25519Signer::from_seed(&[seed; 32]);
            let pk = axiom_nabla::crypto::Signer::public_key(&signer);
            let nbc = make_real_nbc(&[seed; 32], &pk, 500);
            let mut state = NablaNodeState::new(nbc_node_id(&nbc), test_addr(), dir.path(), Box::new(signer), None, true,
                axiom_nabla::bloom::TxidServiceMode::Bloom, true);
            state.virtual_secs = 1000;
            state.accept_nbc(nbc);
            (state, dir)
        }

        /// Register peer `key` via Hello (verified NBC, LISTEN port 7777).
        fn hello_peer(state: &mut NablaNodeState, key: &SigningKey) -> NodeId {
            let nbc = make_real_nbc(&[key.to_bytes()[0] ^ 0x5A; 32], &key.verifying_key().to_bytes(), 500);
            let id = nbc_node_id(&nbc);
            let _ = handle_message(state, &Envelope {
                peer: test_socket(),
                message: WireMessage::Hello {
                    node_id: id, external_port: 7777, downstream_count: 0, nbc_bytes: serialize_nbc(&nbc),
                    nbc_supporting_bytes: vec![], txid_service: "hashmap".into(), observed_peer_ip: None,
                },
                reply_stream: None, cbor_client: false, wire_bytes: 0,
            });
            assert!(state.verified_nbcs.contains_key(&id) && state.core.mesh().unwrap().peer_by_id(&id).is_some());
            id
        }

        fn env(message: WireMessage) -> Envelope {
            // The EPHEMERAL source of the delivering connection — never a reply target.
            Envelope { peer: "127.0.0.1:55555".parse().unwrap(), message, reply_stream: None, cbor_client: false, wire_bytes: 0 }
        }

        fn sign(key: &SigningKey, kind: u8, from: &NodeId, nonce: u64, body: &[u8; 32]) -> Vec<u8> {
            key.sign(&axiom_nabla::crypto::ae_sign_payload(kind, from, nonce, body)).to_bytes().to_vec()
        }

        /// A structurally sound, stamp-BOUND record (the fields bind; its
        /// signatures are not root-verifiable — no unit test holds the roots).
        fn record(tag: u8) -> dir::VbcRegistrationRecord {
            let subject = SigningKey::from_bytes(&[tag; 32]).verifying_key().to_bytes();
            let mut v = axiom_core_logic::types::VBC {
                genesis_lineage: [0u8; 32], network_size_baseline: 0, baseline_tick: 0, version: 0x09,
                validator_id: [tag; 32], subject_pubkey_sphincs: vec![tag; 32], subject_pubkey_dilithium: vec![],
                subject_pubkey_ed25519: subject.to_vec(), pgp_fingerprint: vec![], node_name: String::new(),
                proof_cap: String::new(), issued_at: 1_000, expires_at: 0, chain_depth: 0,
                issuer_set: vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]], signatures: vec![], max_tx: 0,
                founding_vbc_hash: [0u8; 32], nabla_registration: None,
            };
            v.nabla_registration = Some(axiom_core_logic::types::NablaVbcStamp {
                vbc_hash: axiom_core_logic::compute::compute_vbc_signing_payload(&v), wallet_pk: subject,
                balance: 600_000_000_000, tick: 7, nabla_node_pk: [0u8; 32], nabla_signature: vec![],
                nbc_issuer_pk: vec![], nbc_signature: vec![], nbc_commitment: vec![],
            });
            dir::VbcRegistrationRecord { target_vbc: v, supporting_vbcs: vec![] }
        }
        /// Stands in for Core's ACCEPT only (routing/auth tests, not admission).
        fn core_accepts(_: &axiom_core_logic::types::VBCProofBundle) -> axiom_core_logic::errors::CoreResult<()> { Ok(()) }

        fn entries_out(out: &[(std::net::SocketAddr, WireMessage)]) -> Vec<(std::net::SocketAddr, &WireMessage)> {
            out.iter().filter(|(_, m)| matches!(m, WireMessage::VbcRegistrationEntries { .. })).map(|(a, m)| (*a, m)).collect()
        }

        /// R50 responder: a request whose `from` is SPOOFED (signed by another
        /// key) gets NO reply and is counted; the genuine request gets exactly
        /// one page, SIGNED by this node, addressed to the peer's LISTEN socket
        /// (7777) — never the delivering connection's ephemeral source (55555);
        /// a replay of the genuine nonce gets nothing.
        /// Mutations: verify against a key from the message / skip the
        /// signature → the spoof gets a reply (red); reply to `envelope.peer`
        /// → wrong address (red); drop the nonce dedupe → the replay replies.
        #[test]
        fn spoofed_from_gets_no_reply_and_the_genuine_reply_dials_the_listen_addr() {
            let (mut state, _d) = signed_state(0x31);
            let peer_key = SigningKey::from_bytes(&[0x44; 32]);
            let peer = hello_peer(&mut state, &peer_key);
            let e = dir::admit(record(0x10), core_accepts).unwrap();
            assert_eq!(state.core.adopt_verified_directory_entries(vec![e]), 1);

            let have: Vec<[u8; 32]> = vec![];
            let body = dir::have_body_hash(&have);
            let attacker = SigningKey::from_bytes(&[0x66; 32]);
            let before = dir::directory_ae_refused_total();
            let spoof = WireMessage::VbcRegistrationDigest { from: peer, nonce: 1, have: have.clone(),
                sig: sign(&attacker, dir::DIRECTORY_AE_KIND_HAVE, &peer, 1, &body) };
            assert!(entries_out(&handle_message(&mut state, &env(spoof))).is_empty(), "a spoofed from gets NOTHING");
            assert!(dir::directory_ae_refused_total() > before, "COUNTED");

            let genuine = WireMessage::VbcRegistrationDigest { from: peer, nonce: 2, have: have.clone(),
                sig: sign(&peer_key, dir::DIRECTORY_AE_KIND_HAVE, &peer, 2, &body) };
            let out = handle_message(&mut state, &env(genuine.clone()));
            let got = entries_out(&out);
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].0, "127.0.0.1:7777".parse().unwrap(), "reply dials the AUTHENTICATED from's listen socket");
            let WireMessage::VbcRegistrationEntries { from, nonce, entries, sig } = got[0].1 else { unreachable!() };
            assert_eq!((*from, *nonce, entries.len()), (state.node_id, 2, 1));
            let my_pk: [u8; 32] = axiom_nabla::crypto::Signer::public_key(state.core.signer()).try_into().unwrap();
            assert_eq!(dir::verify_ae_signature(Some(my_pk), dir::DIRECTORY_AE_KIND_ENTRIES, from, 2,
                &dir::entries_body_hash(entries), sig), Ok(()), "the reply page is signed by the responder");

            assert!(entries_out(&handle_message(&mut state, &env(genuine))).is_empty(), "a replayed nonce gets nothing");
        }

        /// R50 + R42 requester: a reply is adopted only as the AUTHENTICATED
        /// answer to a nonce this node issued to that peer, and only records the
        /// verifier admits (off the lock). Unsolicited (wrong nonce), spoofed
        /// (wrong key) and replayed replies adopt nothing and are counted; with
        /// the PRODUCTION verifier an unanchored record is refused.
        /// Mutations: drop `accept_reply` → the unsolicited page is adopted
        /// (red); adopt without the pre-lock verdict → the production-verifier
        /// case adopts (red).
        #[test]
        fn a_reply_is_adopted_only_as_the_verified_answer_to_our_own_request() {
            let (state, _d) = signed_state(0x32);
            let state = Arc::new(PlMutex::new(state));
            let peer_key = SigningKey::from_bytes(&[0x45; 32]);
            let peer = hello_peer(&mut state.lock(), &peer_key);
            let WireMessage::VbcRegistrationDigest { nonce, .. } = build_directory_request(&mut state.lock(), peer)
                else { unreachable!() };
            let page = vec![record(0x20)];
            let body = dir::entries_body_hash(&page);
            let deliver = |nonce: u64, key: &SigningKey, verify: dir::DirectoryVerifier| -> usize {
                let msg = WireMessage::VbcRegistrationEntries { from: peer, nonce, entries: page.clone(),
                    sig: sign(key, dir::DIRECTORY_AE_KIND_ENTRIES, &peer, nonce, &body) };
                let e = env(msg);
                let pc = prelock_directory_verify(&state, &e, verify);
                let mut node = state.lock();
                node.directory_precheck = pc;
                let _ = handle_message(&mut node, &e);
                node.directory_precheck = None;
                node.core.vbc_directory().len()
            };
            let before = dir::directory_ae_refused_total();
            assert_eq!(deliver(nonce.wrapping_add(1), &peer_key, core_accepts), 0, "unsolicited");
            assert_eq!(deliver(nonce, &SigningKey::from_bytes(&[0x66; 32]), core_accepts), 0, "spoofed responder");
            assert!(dir::directory_ae_refused_total() >= before + 2, "both COUNTED");
            // The spoofed attempt did not consume the nonce (auth before accept_reply).
            let refused = dir::directory_refused_total();
            assert_eq!(deliver(nonce, &peer_key, dir::DIRECTORY_VERIFIER), 0, "production verifier refuses the unanchored record");
            assert!(dir::directory_refused_total() > refused, "refusal COUNTED");
            // A fresh request, answered genuinely, is adopted.
            let WireMessage::VbcRegistrationDigest { nonce: n2, .. } = build_directory_request(&mut state.lock(), peer)
                else { unreachable!() };
            assert_eq!(deliver(n2, &peer_key, core_accepts), 1, "the verified answer to our own request is adopted");
            assert_eq!(deliver(n2, &peer_key, core_accepts), 1, "a replayed reply adopts nothing new");
        }

        fn register_request(subject: &SigningKey, vbc: &axiom_core_logic::types::VBC) -> axiom_nabla::wire_client::RegisterVbcRequest {
            let wallet_id = subject.verifying_key().to_bytes();
            let h = axiom_core_logic::compute::compute_vbc_signing_payload(vbc);
            let payload = axiom_core_logic::compute::compute_vbc_register_request_payload(&h, &wallet_id, 3);
            axiom_nabla::wire_client::RegisterVbcRequest {
                vbc: vbc.clone(), wallet_id, k_tier: 3, declared_balance: 600_000_000_000,
                declared_hibernation_until: 0, declared_wall_clock_lock: 0, declared_emission_claimed_epoch: 0,
                // §6b.13 — a floor reaching the certificate's expiry (check 5).
                declared_stake_floor_until: vbc.expires_at,
                declared_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
                client_sig: subject.sign(&payload).to_bytes().to_vec(), supporting_vbcs: vec![],
            }
        }

        /// ForkSettlement §9h [R53] — the node's OWN OODS reading, as signed
        /// into every txid attestation: judged by Core's `oods_healthy` against
        /// the node's own NBC baseline. A node whose live estimate is below
        /// ⅓ of its baseline (here: no peers vs a 1000-node baseline) reads
        /// UNHEALTHY, and `query_txid_core` ships exactly that reading; a
        /// baseline-0 (genesis) NBC reads HEALTHY (R53a, not special-cased).
        /// The node's own NBC is a real-SPHINCS+ NBC; its baseline field is set
        /// after signing (only this node's local reading reads it).
        /// MUTATION: `current_oods_reading` returning `healthy: true` ⇒ RED.
        #[test]
        fn current_oods_reading_is_unhealthy_below_its_nbc_baseline_and_rides_query_txid() {
            let (mut state, _d) = signed_state(0x34);
            let mut nbc = deserialize_nbc(&state.own_nbc_bytes).unwrap();
            assert_eq!(nbc.network_size_baseline, 0);
            let genesis = state.current_oods_reading();
            assert!(genesis.healthy, "a baseline-0 NBC reads healthy (R53a)");
            nbc.network_size_baseline = 1000;
            state.accept_nbc(nbc);
            let r = state.current_oods_reading();
            assert!((r.size as u64) * 3 < 1000, "fixture: the live estimate is far below the baseline ({})", r.size);
            assert!(!r.healthy, "below 1/3 of its baseline the node is UNHEALTHY");
            let resp = query_txid_core(&axiom_nabla::wire_client::QueryTxidRequest { txid: [0x5C; 32] }, &state);
            assert_eq!((resp.oods_size, resp.oods_healthy), (r.size, false), "the shipped attestation carries the reading");
        }

        /// R42 at the register door: a subject-signed certificate whose chain
        /// does not verify is REFUSED by the off-lock directory verdict, and
        /// nothing is recorded (it can neither enter the directory nor block
        /// anyone). Without an off-lock verdict the door refuses rather than
        /// stamping unverified. Mutation: delete step 0b → the request passes
        /// to the state checks and the refusal reason is no longer the
        /// directory's (red).
        #[test]
        fn register_vbc_refuses_chain_unverifiable_certificate() {
            let (state, _d) = signed_state(0x33);
            let state = Arc::new(PlMutex::new(state));
            let subject = SigningKey::from_bytes(&[0x10; 32]);
            let mut vbc = record(0x10).target_vbc;
            vbc.nabla_registration = None; // the operator presents the CANDIDATE
            let req = register_request(&subject, &vbc);
            let e = env(WireMessage::RegisterVbcRequest(req.clone()));
            let pc = prelock_directory_verify(&state, &e, dir::DIRECTORY_VERIFIER);
            assert!(matches!(pc, Some(DirectoryPrecheck::Register { verdict: Some(Err(_)), .. })), "{pc:?}");
            let mut node = state.lock();
            node.directory_precheck = pc;
            let resp = register_vbc_core(&req, &mut node);
            assert_eq!(resp.status, "REFUSED");
            assert!(resp.error.contains("witness directory"), "{}", resp.error);
            assert!(resp.stamp.is_none());
            assert!(node.core.vbc_directory().is_empty(), "nothing recorded");

            node.directory_precheck = None;
            let resp = register_vbc_core(&req, &mut node);
            assert_eq!(resp.status, "ERROR");
            assert!(resp.error.contains("no off-lock directory verification"), "{}", resp.error);
        }

        /// ValidatorJoin §6b.13 — drive `register_vbc_core` THROUGH the state
        /// checks to stamp check 5 (§6b.4): a registered head whose k-attested
        /// anchor carries `head_floor` (SMT entry + retained SeqProof), a
        /// non-provisional certificate expiring at `expires_at`, and a request
        /// DECLARING that head (so step 2 passes and check 5 decides). The
        /// subject's SPHINCS+ key is a genesis key only to skip the OODS
        /// baseline step (§6b.4a) — the head is a REAL SMT entry, not derived.
        /// The chain verifier is `core_accepts` (no unit test holds the roots).
        fn stamp_with_head_floor(seed: u8, head_floor: u64, expires_at: u64) -> (axiom_nabla::wire_client::RegisterVbcResponse, u64) {
            stamp_with_head_floor_pre(seed, head_floor, expires_at, false)
        }

        /// As `stamp_with_head_floor`; `pre_recorded` first records THIS
        /// certificate's verified entry for the same owner (a stamp issued
        /// earlier), so the request takes the owner RE-ISSUE path (step 5 early).
        fn stamp_with_head_floor_pre(seed: u8, head_floor: u64, expires_at: u64, pre_recorded: bool) -> (axiom_nabla::wire_client::RegisterVbcResponse, u64) {
            let (state, _d) = signed_state(seed);
            let state = Arc::new(PlMutex::new(state));
            let subject = SigningKey::from_bytes(&[seed ^ 0x33; 32]);
            let pk = subject.verifying_key().to_bytes();
            let mut vbc = record(seed ^ 0x33).target_vbc;
            vbc.nabla_registration = None;
            vbc.subject_pubkey_sphincs = axiom_core_logic::genesis::GENESIS_VALIDATORS[0].to_vec();
            vbc.issued_at = 1_000;
            vbc.expires_at = expires_at;
            let mut req = register_request(&subject, &vbc);
            req.declared_stake_floor_until = head_floor; // the head's value, proven below
            req.declared_balance = axiom_core_logic::types::VALIDATOR_STAKE_FLOOR_ATOMS; // step 3 passes
            let balance = req.declared_balance;
            let seq = 4u64;
            let bucket = axiom_nabla::registration::smt_bucket(&req.wallet_id, req.k_tier);
            {
                let mut node = state.lock();
                let entry = axiom_nabla::types::NablaEntry {
                    received_from: None, wallet_id: bucket, current_state: [0x44; 32], tx_hash: [0x45; 32],
                    tick: 7, wallet_seq: seq, group_members: None,
                    status: axiom_nabla::types::WalletStatus::Normal, client_pk: pk, client_sig: vec![0u8; 64],
                };
                // Installed as this node's OWN restored state (the retained head
                // + its proof, atomically) — the door reads exactly these two.
                node.core.smt_mut().put_with_proof(&entry, axiom_nabla::smt::PutProof::RestoredFromLocalState(Some(axiom_nabla::types::SeqProof {
                    state_hash: axiom_core_logic::compute::compute_state_hash(
                        &pk, balance, seq, 0, 0, 0, head_floor, &axiom_core_logic::types::WalletFormat::CURRENT),
                    commitment_hash: [0u8; 32], epoch: 0, is_dev_class: false, oods_flag: None,
                    confidence_index: None, sender_state: None, sigs: vec![], required_k: 3,
                    // KI#241 F-2: a signature-free restored-head fixture — the
                    // leg is never re-verified here, so its cheque origin is a
                    // placeholder (it does not reproduce `cheque_txid`).
                    preimage: axiom_core_logic::nabla_wire::LegPreimage::Redeem {
                        redeem: axiom_core_logic::types::RedeemPreimage {
                            cheque_txid: [0x45; 32], receiver_pk: pk, new_balance: balance,
                            new_state_id: [0x44; 32], consumed_state_id: [0x43; 32],
                        },
                        cheque: axiom_core_logic::types::OriginRecord {
                            preimage: axiom_core_logic::types::WitnessPreimage {
                                consumed_state_id: [0x46; 32], client_pk: [0x47; 32], wallet_seq: 1,
                                receiver_wallet_id: String::new(), amount: 0, nonce: 0,
                            },
                            epoch: 0,
                            kind: axiom_core_logic::types::LegKind::Send,
                        },
                    },
                    declared: axiom_nabla::types::DeclaredState { balance, wallet_seq: seq },
                })));
            }
            let e = env(WireMessage::RegisterVbcRequest(req.clone()));
            let pc = prelock_directory_verify(&state, &e, core_accepts);
            assert!(matches!(pc, Some(DirectoryPrecheck::Register { verdict: Some(Ok(_)), .. })), "{pc:?}");
            let mut node = state.lock();
            if pre_recorded {
                let Some(DirectoryPrecheck::Register { verdict: Some(Ok(entry)), .. }) = pc else { unreachable!() };
                assert!(node.core.record_vbc_registration(entry), "fixture: the earlier stamp's record");
                node.directory_precheck = None;
            } else {
                node.directory_precheck = pc;
            }
            let before = axiom_nabla::registration::vbc_stamp_refused_no_floor_total();
            let resp = register_vbc_core(&req, &mut node);
            (resp, axiom_nabla::registration::vbc_stamp_refused_no_floor_total() - before)
        }

        /// §6b.4 check 5 — a head WITHOUT a floor (0), or with a floor SHORT of
        /// the certificate's expiry, is refused a stamp and COUNTED; a head
        /// whose floor reaches `expires_at` is stamped. MUTATION (run
        /// 2026-10-01): make `stake_floor_covers_certificate` return `true` ⇒
        /// the two refusals go RED; delete the check-5 block ⇒ RED.
        #[test]
        fn stamp_check_5_refuses_a_head_without_a_floor_reaching_expiry() {
            let expires = 1_000 + axiom_core_logic::validation::PROVISIONAL_VBC_EXPIRY_SECS + 50_000;
            let (none, counted) = stamp_with_head_floor(0x61, 0, expires);
            assert_eq!(none.status, "REFUSED", "{}", none.error);
            assert!(none.error.contains("stake_floor_until=0"), "{}", none.error);
            assert!(none.stamp.is_none());
            assert_eq!(counted, 1, "the refusal is counted on /status");
            let (short, _) = stamp_with_head_floor(0x62, expires - 1, expires);
            assert_eq!(short.status, "REFUSED", "a floor one tick short of expiry: {}", short.error);
            assert!(short.error.contains("§6b.13"), "{}", short.error);
            // A floor reaching expiry PASSES check 5 — and the request then
            // reaches step 2c (§9r F-1(c)), which comes AFTER check 5: this
            // fixture's head has no recorded producer leg, so the node has no
            // provenance verdict and answers the retryable WAIT (was "OK"
            // before 2c). The check-5 refusal counter does not move.
            let (ok, counted) = stamp_with_head_floor(0x63, expires, expires);
            assert_eq!(ok.status, "WAIT", "check 5 passed; 2c decides: {}", ok.error);
            assert!(ok.stamp.is_none());
            assert_eq!(counted, 0);
        }

        /// ForkSettlement §9r F-1(c) (KI#244) — a registered stake head that
        /// passes every state check (2, check 5, 3, 4) but has NO provenance
        /// verdict at this node (the fixture installs the head + SeqProof with
        /// no recorded producer leg) gets the retryable `WAIT`, no stamp,
        /// counted `vbc_stamp_refused_wait` — nothing is recorded.
        /// MUTATION (run 2026-10-02): delete step 2c in `register_vbc_core` ⇒
        /// status "OK" ⇒ RED.
        #[test]
        fn register_vbc_refuses_a_stake_head_with_no_provenance_verdict() {
            let expires = 1_000 + axiom_core_logic::validation::PROVISIONAL_VBC_EXPIRY_SECS + 50_000;
            let before = axiom_nabla::registration::vbc_stamp_refused_wait_total();
            let (resp, _) = stamp_with_head_floor(0x64, expires, expires);
            assert_eq!(resp.status, "WAIT", "{}", resp.error);
            assert!(resp.error.contains("provenance"), "{}", resp.error);
            assert!(resp.stamp.is_none(), "no stamp on an unjudged head");
            assert!(axiom_nabla::registration::vbc_stamp_refused_wait_total() > before, "counted");
        }

        /// ForkSettlement §9r F-1(c), D-F1-2 — the OWNER RE-ISSUE (step 5
        /// early: the same stake wallet re-presenting a certificate this node
        /// already stamped, after a lost reply) is UNCHANGED: it returns the
        /// stamp already issued even though the head now has no `Ok` verdict
        /// here (step 2c would answer WAIT) — it adds no information.
        /// MUTATION (run 2026-10-02): move step 2c's gate (with the head
        /// lookup) above the early re-issue ⇒ status "WAIT" ⇒ RED.
        #[test]
        fn owner_reissue_unchanged_when_head_later_held() {
            let expires = 1_000 + axiom_core_logic::validation::PROVISIONAL_VBC_EXPIRY_SECS + 50_000;
            let (resp, _) = stamp_with_head_floor_pre(0x65, expires, expires, true);
            assert_eq!(resp.status, "OK", "{}", resp.error);
            assert!(resp.stamp.is_some(), "the owner gets the SAME stamp again");
        }

        /// ForkSettlement §9r F-1(c) — the gate itself: the §6c genesis
        /// DERIVED head (no SMT entry, `derived_head`) passes whatever the view
        /// (it never transacted; its opening state is a provenance root); a
        /// registered head passes ONLY on `Ok`: `Held` ⇒ REFUSED naming the
        /// held cheque, `Wait` / no entry ⇒ WAIT. (A full `register_vbc_core`
        /// run on a derived head needs a genesis stake key's secret to pass
        /// step 0 — no test holds one — so the exemption is pinned here.)
        /// MUTATION (run 2026-10-02): drop the `derived_head` early return ⇒
        /// RED at "derived head refused".
        #[test]
        fn genesis_derived_head_stamps_without_provenance() {
            use axiom_nabla::types::ProvenanceView;
            assert_eq!(stake_head_stamp_gate(true, None), None, "derived head refused");
            assert_eq!(stake_head_stamp_gate(false, Some(ProvenanceView::Ok)), None);
            let (st, why) = stake_head_stamp_gate(false, Some(ProvenanceView::Held(vec![[0xAB; 32]]))).expect("held refused");
            assert_eq!(st, "REFUSED");
            assert!(why.contains("HELD") && why.contains("abababab"), "{why}");
            assert_eq!(stake_head_stamp_gate(false, Some(ProvenanceView::Wait)).map(|r| r.0), Some("WAIT"));
            assert_eq!(stake_head_stamp_gate(false, None).map(|r| r.0), Some("WAIT"), "fail closed");
        }
    }

    /// Fork Settlement §9o [R58/R59] (W1) — the record-AE TRANSPORT GLUE:
    /// `handle_message`'s `RecordAeAsk` / `RecordAeAnswer` arms and the
    /// off-lock `prelock_record_ae`. Real Ed25519 node keys and real NBCs; the
    /// descent logic itself is tested in the lib (`node::record_ae_tests`).
    /// Each test names the mutation that turns it RED (run 2026-09-30).
    mod record_ae_wire {
        use super::*;
        use axiom_nabla::record_sync::{self as rs, Answer, Ask, NodeView, Prefix, ViewBody};
        use axiom_nabla::vbc_directory as dir;
        use ed25519_dalek::{Signer as _, SigningKey};

        fn signed_state(seed: u8) -> (NablaNodeState, tempfile::TempDir) {
            let dir = tempfile::tempdir().unwrap();
            let signer = axiom_nabla::crypto::Ed25519Signer::from_seed(&[seed; 32]);
            let pk = axiom_nabla::crypto::Signer::public_key(&signer);
            let nbc = make_real_nbc(&[seed; 32], &pk, 500);
            let mut state = NablaNodeState::new(nbc_node_id(&nbc), test_addr(), dir.path(), Box::new(signer), None, true,
                axiom_nabla::bloom::TxidServiceMode::Bloom, true);
            state.virtual_secs = 1000;
            state.accept_nbc(nbc);
            (state, dir)
        }

        fn hello_peer(state: &mut NablaNodeState, key: &SigningKey) -> NodeId {
            let nbc = make_real_nbc(&[key.to_bytes()[0] ^ 0x5A; 32], &key.verifying_key().to_bytes(), 500);
            let id = nbc_node_id(&nbc);
            let _ = handle_message(state, &Envelope {
                peer: test_socket(),
                message: WireMessage::Hello {
                    node_id: id, external_port: 7777, downstream_count: 0, nbc_bytes: serialize_nbc(&nbc),
                    nbc_supporting_bytes: vec![], txid_service: "hashmap".into(), observed_peer_ip: None,
                },
                reply_stream: None, cbor_client: false, wire_bytes: 0,
            });
            assert!(state.verified_nbcs.contains_key(&id) && state.core.mesh().unwrap().peer_by_id(&id).is_some());
            id
        }

        fn env(message: WireMessage) -> Envelope {
            // The EPHEMERAL source of the delivering connection — never a reply target.
            Envelope { peer: "127.0.0.1:55555".parse().unwrap(), message, reply_stream: None, cbor_client: false, wire_bytes: 0 }
        }

        fn ask_msg(key: &SigningKey, from: NodeId, nonce: u64, ask: Ask) -> WireMessage {
            let sig = key.sign(&axiom_nabla::crypto::ae_sign_payload(rs::RECORD_AE_KIND_ASK, &from, nonce, &rs::ask_body_hash(&ask)));
            WireMessage::RecordAeAsk { from, nonce, ask, sig: sig.to_bytes().to_vec() }
        }

        fn answer_msg(key: &SigningKey, from: NodeId, nonce: u64, answer: Answer) -> WireMessage {
            let sig = key.sign(&axiom_nabla::crypto::ae_sign_payload(rs::RECORD_AE_KIND_ANSWER, &from, nonce, &rs::answer_body_hash(&answer)));
            WireMessage::RecordAeAnswer { from, nonce, answer, sig: sig.to_bytes().to_vec() }
        }

        fn of_kind<'a>(out: &'a [(std::net::SocketAddr, WireMessage)], answers: bool) -> Vec<(std::net::SocketAddr, &'a WireMessage)> {
            out.iter()
                .filter(|(_, m)| if answers { matches!(m, WireMessage::RecordAeAnswer { .. }) } else { matches!(m, WireMessage::RecordAeAsk { .. }) })
                .map(|(a, m)| (*a, m))
                .collect()
        }

        /// R59 responder: an ask whose `from` is SPOOFED (signed by another
        /// key) gets NO answer and is counted; the genuine ask gets exactly one
        /// answer, SIGNED by this node, addressed to the peer's LISTEN socket
        /// (7777) — never the delivering connection's ephemeral source (55555);
        /// a replay of the genuine nonce gets nothing.
        /// MUTATION (run): address the answer to `envelope.peer` ⇒ RED.
        #[test]
        fn record_ae_ask_spoofed_from_gets_no_answer_genuine_answer_dials_the_listen_addr() {
            let (mut state, _d) = signed_state(0x33);
            let peer_key = SigningKey::from_bytes(&[0x47; 32]);
            let peer = hello_peer(&mut state, &peer_key);
            let root = Ask::Nodes(vec![Prefix::root()]);
            let spoof = ask_msg(&SigningKey::from_bytes(&[0x66; 32]), peer, 1, root.clone());
            assert!(of_kind(&handle_message(&mut state, &env(spoof)), true).is_empty(), "a spoofed from gets NOTHING");
            assert_eq!(state.core.record_ae_counters().refused_bad_signature, 1, "COUNTED");
            let genuine = ask_msg(&peer_key, peer, 2, root);
            let out = handle_message(&mut state, &env(genuine.clone()));
            let got = of_kind(&out, true);
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].0, "127.0.0.1:7777".parse().unwrap(), "answer dials the AUTHENTICATED from's listen socket");
            let WireMessage::RecordAeAnswer { from, nonce, answer, sig } = got[0].1 else { unreachable!() };
            assert_eq!((*from, *nonce), (state.node_id, 2));
            let my_pk: [u8; 32] = axiom_nabla::crypto::Signer::public_key(state.core.signer()).try_into().unwrap();
            assert_eq!(dir::verify_ae_signature(Some(my_pk), rs::RECORD_AE_KIND_ANSWER, from, 2, &rs::answer_body_hash(answer), sig),
                Ok(()), "the answer is signed by the responder");
            assert!(of_kind(&handle_message(&mut state, &env(genuine)), true).is_empty(), "a replayed nonce gets nothing");
            assert_eq!(state.core.record_ae_counters().refused_replayed_nonce, 1);
        }

        /// R59 asker: the answer is authenticated under a brief lock and
        /// prepared OFF it (`prelock_record_ae`); a spoofed answer is refused
        /// (counted) and changes nothing; the genuine one advances the descent
        /// and its NEXT ask dials the peer's LISTEN socket. The `tick_loop`
        /// inbox-drain path (no pre-lock stage) processes an answer too.
        /// MUTATION (run): address the next ask to `envelope.peer` ⇒ RED.
        /// FOUND by this test (2026-09-30, first cut): a pre-lock REFUSAL left
        /// the stash `None`, so the arm re-accepted under the lock and counted
        /// the spoof twice — the stash is now `Some(None)` for "ran, refused".
        #[test]
        fn record_ae_answer_prepared_off_lock_next_ask_dials_the_listen_addr() {
            let (state, _d) = signed_state(0x34);
            let state = Arc::new(PlMutex::new(state));
            let peer_key = SigningKey::from_bytes(&[0x48; 32]);
            let peer = hello_peer(&mut state.lock(), &peer_key);
            let first = {
                let mut n = state.lock();
                let (me, now) = (n.node_id, n.virtual_secs);
                n.core.record_ae_tick(me, &[peer], &[], now)
            };
            assert_eq!(first.len(), 1, "the walk starts one descent");
            let WireMessage::RecordAeAsk { nonce, ask, .. } = &first[0].1 else { unreachable!() };
            assert_eq!(ask, &Ask::Nodes(vec![Prefix::root()]));
            // The peer's root: one non-empty child we lack.
            let mut children = vec![rs::EMPTY_HASH; 16];
            children[3] = [0xAB; 32];
            let view = Answer::Nodes(vec![NodeView { prefix: Prefix::root(), body: ViewBody::Internal(children) }]);
            let run = |msg: WireMessage| -> Vec<(std::net::SocketAddr, WireMessage)> {
                let e = env(msg);
                let pc = prelock_record_ae(&state, &e);
                let mut n = state.lock();
                n.record_ae_precheck = Some(pc);
                let out = handle_message(&mut n, &e);
                n.record_ae_precheck = None;
                out
            };
            let spoof = answer_msg(&SigningKey::from_bytes(&[0x66; 32]), peer, *nonce, view.clone());
            assert!(of_kind(&run(spoof), false).is_empty(), "a spoofed answer moves nothing");
            assert_eq!(state.lock().core.record_ae_counters().refused_bad_signature, 1);
            let out = run(answer_msg(&peer_key, peer, *nonce, view));
            let next = of_kind(&out, false);
            assert_eq!(next.len(), 1, "the descent goes one level down");
            assert_eq!(next[0].0, "127.0.0.1:7777".parse().unwrap(), "next ask dials the listen socket");
            let WireMessage::RecordAeAsk { nonce: n2, ask, .. } = next[0].1 else { unreachable!() };
            assert_eq!(ask, &Ask::Nodes(vec![Prefix::root().child(3)]));
            // tick_loop inbox-drain path: no pre-lock stage, prepared under the lock.
            let empty = Answer::Nodes(vec![NodeView { prefix: Prefix::root().child(3), body: ViewBody::Empty }]);
            let out = handle_message(&mut state.lock(), &env(answer_msg(&peer_key, peer, *n2, empty)));
            assert!(of_kind(&out, false).is_empty(), "nothing left to ask");
            assert_eq!(state.lock().core.record_ae_counters().descents_completed, 1);
        }
    }

    // ── KI#55 (Pattern 1) — ONE builder each for `AXIOM_NBC_RENEW` and
    // `AXIOM_NABLA_ROLE` (`axiom_nabla::crypto`; the ROLE builder and its
    // signers were DELETED 2026-10-02, KI#247 — no verifier existed). The hex constants were
    // computed in Python (`blake3`) from the YP layouts (§25 domain table:
    // `validator_id ‖ request_time_le`; §17083 `node_id ‖ role ‖ wallet_id ‖
    // state_id ‖ tick_le`) — NOT from this crate. Each test drives a PRODUCTION
    // path (signer or verifier) against the constant, so it was a step-0 anchor
    // before the inline copies were folded (green on the inline code) and is the
    // byte-identity guard after. ──
    mod ki55_anchor {
        use super::*;

        const TS: u64 = 1774070000;
        fn h32(s: &str) -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() }

        fn ed_state(seed: u8, sphincs: [u8; 32]) -> (NablaNodeState, tempfile::TempDir, Ed25519Signer, NBC) {
            let dir = tempfile::tempdir().unwrap();
            let key = Ed25519Signer::from_seed(&[seed; 32]);
            let mut nbc = make_real_nbc(&sphincs, &key.public_key_bytes(), 500);
            nbc.expires_at = TS + 1; // inside the renewal window at virtual_secs = TS
            let node_id = nbc_node_id(&nbc);
            let signer = Box::new(Ed25519Signer::from_seed(&[seed; 32]));
            let mut state = NablaNodeState::new(node_id, test_addr(), dir.path(), signer, None, true,
                axiom_nabla::bloom::TxidServiceMode::Bloom, true);
            state.accept_nbc(nbc.clone());
            (state, dir, key, nbc)
        }

        /// SIGN side of `AXIOM_NBC_RENEW` (`check_nbc_renewal`): the renewal
        /// signature verifies over `BLAKE3("AXIOM_NBC_RENEW" ‖ BLAKE3(0xCC×32) ‖
        /// TS_le)`, Python constant.
        /// MUTATION (run 2026-10-02): `check_nbc_renewal` passes
        /// `self.virtual_secs + 1` to the builder ⇒ red.
        #[test]
        fn ki55_nbc_renew_sign_site_matches_independent_constant() {
            let (mut state, _dir, key, _nbc) = ed_state(0x42, [0xCC; 32]);
            state.virtual_secs = TS;
            let Some(WireMessage::NbcRenewRequest { renewal_sig, current_time, .. }) = state.check_nbc_renewal()
                else { panic!("inside the renewal window a request is built") };
            assert_eq!(current_time, TS);
            let kat = h32("5aef1fdd4c794fd063f572dc50c973f38affbdbcc5277885ea0b460f0dd6edf2");
            assert!(crypto::verify_ed25519(&key.public_key_bytes(), &kat, &renewal_sig),
                "renewal sig must be over the YP preimage");
        }

        /// VERIFY side of `AXIOM_NBC_RENEW` (`handle_nbc_renewal_request`): a sig
        /// over the Python KAT (`validator_id = 0xAB×32`, `TS`) passes the
        /// signature check; the same sig at `TS + 1` is "renewal signature
        /// invalid". MUTATION (run 2026-10-02): the verify site passes
        /// `request_time + 1` ⇒ red.
        #[test]
        fn ki55_nbc_renew_verify_site_matches_independent_constant() {
            let (state, _dir, key, mut old) = ed_state(0x43, [0xCD; 32]);
            old.validator_id = [0xAB; 32];
            let old_bytes = serialize_nbc(&old);
            let kat = h32("9b4781dd94490861ac7c9bc91996764ebb635243fa30c96f4e25cd23f5ef86e9");
            let sig = key.sign(&kat);
            let (_, _, _, err) = state.handle_nbc_renewal_request(&old_bytes, &sig, TS);
            assert_ne!(err, "renewal signature invalid", "the KAT payload IS what the verifier checks");
            let (ok, _, _, err) = state.handle_nbc_renewal_request(&old_bytes, &sig, TS + 1);
            assert!(!ok);
            assert_eq!(err, "renewal signature invalid", "control: a different time is a different payload");
        }

        /// KI#247 (owner ruling 2026-10-02) — the `AXIOM_NABLA_ROLE` signature
        /// was DELETED (signers, `crypto::role_attestation_sign_payload`, the
        /// `role_signature` wire fields): nothing verified it. What remains at
        /// BOTH former sign sites is the unsigned, informational `role`; this
        /// pins that both still report it (reader here). That no signature is
        /// produced is enforced by the type — the field no longer exists.
        #[test]
        fn ki247_both_query_sites_report_the_unsigned_role() {
            let (mut state, _dir, _key, _nbc) = ed_state(0x44, [0xCE; 32]);
            state.node_id = [0x01; 32];
            state.reader_only = true;
            state.virtual_secs = TS;
            let req = axiom_nabla::wire_client::QueryWalletStateRequest { wallet_pk: [0x02; 32] };
            let resp = query_wallet_state_core(&req, &state);
            assert_eq!((resp.status.as_str(), resp.role.as_str(), resp.synced_to_tick), ("NOT_FOUND", "reader", TS));
            let env = Envelope { peer: test_socket(), message: WireMessage::Query { wallet_id: [0x02; 32] },
                reply_stream: None, cbor_client: false, wire_bytes: 0 };
            let out = handle_message(&mut state, &env);
            let resp = out.iter().find_map(|(_, m)| match m { WireMessage::QueryResponse(r) => Some(r.clone()), _ => None })
                .expect("Query answers QueryResponse");
            assert_eq!((resp.role, resp.wallet_id), (0, [0x02; 32]));
        }
    }
}


/// Contribution emission — who may claim, checked at attestation issuance
/// (`AXIOM_DESIGN_ValidatorEmission.md` §4.2). Returns the claiming identity
/// (the certificate's `validator_id`) or the refusal status string.
///   validators (pool 1): a VBC that is stamped and above the floor
///     (`verify_vbc_stamp`), whose subject is NOT a genesis validator;
///   Nabla nodes (pool 2): an NBC anchored to the root authority, whose
///     subject is NOT a genesis Nabla node;
///   both: the request names THIS epoch, the Operational wallet id is pk-bound
///     to `operational_pk`, and the subject's Ed25519 key signed the voucher
///     over (operational_pk ‖ epoch).
fn emission_claim_identity(
    req: &axiom_nabla::wire_client::EmissionClaimAttestationRequest,
    tick: u64,
) -> Result<[u8; 32], &'static str> {
    use axiom_core_logic::types::{FOB_CLAIM_POOL_EMISSION, FOB_CLAIM_POOL_EMISSION_NABLA};
    if req.epoch != axiom_nabla::emission::epoch_of(tick) {
        return Err("WRONG_EPOCH");
    }
    // The certificate is presented ABOUT ITSELF, NOW, by a party asking for
    // value — so it gets the full live verification, never a stamp-only or a
    // by-value root check (the owner: "validator claim needs to verify its VBC and
    // Nabla needs NBC to be verified"). Same verifiers as the witness path
    // (`verify_vbc_bundle`: every SPHINCS+ hop to a root authority, expiry,
    // §5.3 lineage, reserved names, AND the Nabla stamp) and the peer-admission
    // path (`verify_nbc_chain`: structure, SPHINCS+ per hop, expiry, root trust).
    let bundle: axiom_core_logic::types::VBCProofBundle =
        ciborium::from_reader(req.identity_cert.as_slice()).map_err(|_| "BAD_CERT")?;
    let cert = &bundle.target_vbc;
    match req.pool {
        FOB_CLAIM_POOL_EMISSION => {
            if axiom_core_logic::vbc::verify_vbc_bundle(&bundle, tick).is_err() {
                return Err("NOT_ELIGIBLE");
            }
            if axiom_core_logic::genesis::is_genesis_validator(&cert.subject_pubkey_sphincs) {
                return Err("NOT_ELIGIBLE"); // "the genesis validator does not receive the emission"
            }
        }
        FOB_CLAIM_POOL_EMISSION_NABLA => {
            if verify_nbc_chain(cert, &bundle.supporting_vbcs, tick).is_err() {
                return Err("NOT_ELIGIBLE");
            }
            nabla_emission_subject_eligible(cert, tick)?;
        }
        _ => return Err("BAD_POOL"),
    }
    // §4.2a — the claimant IS the certificate's key wallet: same pk, bound to
    // the wallet id, and in possession of the key (signature over pk ‖ epoch).
    if cert.subject_pubkey_ed25519.as_slice() != req.claimant_pk.as_slice() {
        return Err("BAD_WALLET");
    }
    if axiom_core_logic::wallet_id::verify_pk_binding(&req.claimant_wallet_id, &req.claimant_pk).is_err() {
        return Err("BAD_WALLET");
    }
    let payload = axiom_core_logic::compute::compute_emission_voucher_payload(&req.claimant_pk, req.epoch);
    axiom_core_logic::verify::verify_ed25519(&req.claimant_pk, &payload, &req.possession_sig)
        .map_err(|_| "BAD_VOUCHER")?;
    Ok(cert.validator_id)
}

/// Internal refusal marker for GUIDE §5.6c lever 3. The dispatcher maps it to
/// the spec's `NOT_ELIGIBLE` on the wire and counts it as a probation refusal;
/// it never leaves the process.
const EMISSION_PROBATION_REFUSAL: &str = "NOT_ELIGIBLE:probation";

/// YPX-002 §9.1.1a — the `rejection_reason` an issuer answers when its
/// per-epoch signing budget is spent. The requester sees it verbatim in
/// `NbcIssuanceResponse` and should try another issuer or the next epoch.
const NBC_ISSUER_CAP_REACHED: &str = "ISSUER_CAP_REACHED";

/// The SUBJECT checks on a chain-verified Nabla certificate presenting for
/// the EmissionNabla pool — the part of `emission_claim_identity` that is
/// about WHO the certificate names rather than whether it verifies:
///   - a genesis Nabla node has no share ("both genesis validator and nabla
///     does not has the rights to share");
///   - GUIDE §5.6c lever 3: a certificate inside join probation answers
///     `NOT_ELIGIBLE` — "minting nodes does not mint a share of the emission".
/// Split out so the probation gate is drivable in a unit test with a
/// self-built certificate: `verify_nbc_chain` needs a chain to a Nabla ROOT
/// AUTHORITY, whose secret keys no test in this crate can hold, so the gate
/// cannot be reached through `emission_claim_identity` with a cert that ALSO
/// verifies. The caller invokes this ONLY after the chain verified.
fn nabla_emission_subject_eligible(cert: &NBC, tick: u64) -> Result<(), &'static str> {
    if cc::nbc_is_pinned_genesis(cert) {
        return Err("NOT_ELIGIBLE");
    }
    if cc::is_probationary(cert, tick) {
        return Err(EMISSION_PROBATION_REFUSAL);
    }
    Ok(())
}

#[cfg(test)]
mod emission_identity_tests {
    //! The hole the owner named (2026-09-14): a certificate that merely NAMES a root
    //! authority as issuer (keys are public constants) with garbage signatures
    //! must never be an eligible emission claimant. Both groups.
    use super::emission_claim_identity;
    use axiom_core_logic::types::{FOB_CLAIM_POOL_EMISSION, FOB_CLAIM_POOL_EMISSION_NABLA, VBCProofBundle};

    fn forged(issuers: &[[u8; 32]], tick: u64) -> axiom_nabla::cc::NBC {
        let sphincs = [0x5Au8; 32];
        let mut c = axiom_nabla::cc::sim_nbc(*blake3::hash(&sphincs).as_bytes(), tick.saturating_sub(10));
        c.subject_pubkey_sphincs = sphincs.to_vec();
        c.issuer_set = issuers.iter().map(|k| k.to_vec()).collect();
        c.signatures = issuers.iter().map(|_| vec![0u8; 64]).collect();
        c
    }
    fn req(pool: u8, cert: axiom_nabla::cc::NBC, tick: u64) -> axiom_nabla::wire_client::EmissionClaimAttestationRequest {
        let bundle = VBCProofBundle { target_vbc: cert, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
        let mut cbor = Vec::new();
        ciborium::into_writer(&bundle, &mut cbor).unwrap();
        axiom_nabla::wire_client::EmissionClaimAttestationRequest {
            pool, identity_cert: cbor, claimant_wallet_id: String::new(), claimant_pk: [7u8; 32],
            epoch: axiom_nabla::emission::epoch_of(tick), possession_sig: vec![0u8; 64],
        }
    }

    #[test]
    fn nabla_claim_refuses_a_certificate_that_only_names_root_keys() {
        let tick = 1_000_000;
        let roots: Vec<[u8; 32]> = axiom_core_logic::nabla_genesis::NABLA_ROOT_AUTHORITY_PKS[..1].to_vec();
        let cert = forged(&roots, tick);
        // The by-value check alone would have passed this forgery.
        assert!(axiom_nabla::cc::verify_nbc_root_trust(&cert).is_ok(), "premise: issuer IS a root key by value");
        assert_eq!(emission_claim_identity(&req(FOB_CLAIM_POOL_EMISSION_NABLA, cert, tick), tick), Err("NOT_ELIGIBLE"));
    }

    #[test]
    fn validator_claim_refuses_a_certificate_that_only_names_root_keys() {
        let tick = 1_000_000;
        let roots: Vec<[u8; 32]> = axiom_core_logic::genesis::ROOT_AUTHORITY_PKS[..3].to_vec();
        let cert = forged(&roots, tick);
        assert_eq!(emission_claim_identity(&req(FOB_CLAIM_POOL_EMISSION, cert, tick), tick), Err("NOT_ELIGIBLE"));
    }

    #[test]
    fn wrong_epoch_and_garbage_bytes_are_refused_before_any_crypto() {
        let tick = 1_000_000;
        let mut r = req(FOB_CLAIM_POOL_EMISSION_NABLA, forged(&[], tick), tick);
        r.epoch += 1;
        assert_eq!(emission_claim_identity(&r, tick), Err("WRONG_EPOCH"));
        let mut r = req(FOB_CLAIM_POOL_EMISSION_NABLA, forged(&[], tick), tick);
        r.identity_cert = vec![0xFF; 5];
        assert_eq!(emission_claim_identity(&r, tick), Err("BAD_CERT"));
    }
}


/// KI#230: the bootstrap file decides between "first node of the mesh" (armed
/// immediately, KI#42 exemption) and "join and re-arm from peers". Only an
/// ABSENT file means first node. A file that exists but cannot be loaded (parse
/// error, a seed name that does not resolve yet) is an error — never an empty
/// peer set, which would silently grant the first-node exemption.
fn bootstrap_config_for(path: &std::path::Path) -> Result<Option<NablaConfig>, String> {
    if !path.exists() {
        return Ok(None);
    }
    NablaConfig::load_bootstrap(path).map(Some)
}

#[cfg(test)]
mod ki230_bootstrap_fail_closed {
    use super::bootstrap_config_for;

    #[test]
    fn absent_file_is_first_node() {
        let p = std::env::temp_dir().join("ki230-definitely-absent-bootstrap.toml");
        let _ = std::fs::remove_file(&p);
        assert!(matches!(bootstrap_config_for(&p), Ok(None)));
    }

    #[test]
    fn unresolvable_peer_is_an_error_not_an_empty_peer_set() {
        let p = std::env::temp_dir().join(format!("ki230-bad-{}.toml", std::process::id()));
        std::fs::write(&p, "[[peer]]\naddress = \"no-such-host.invalid:7300\"\n").unwrap();
        let r = bootstrap_config_for(&p);
        let _ = std::fs::remove_file(&p);
        assert!(r.is_err(), "an unloadable bootstrap must not read as first node");
    }

    #[test]
    fn loadable_file_yields_its_peers() {
        let p = std::env::temp_dir().join(format!("ki230-ok-{}.toml", std::process::id()));
        std::fs::write(&p, "[[peer]]\naddress = \"127.0.0.1:7300\"\n").unwrap();
        let r = bootstrap_config_for(&p);
        let _ = std::fs::remove_file(&p);
        assert_eq!(r.unwrap().unwrap().peer_count(), 1);
    }
}
