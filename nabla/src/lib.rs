// AXIOM Nabla — Citizen Infrastructure Library
//
// This crate provides the Nabla protocol implementation as a library.
// Both the production binary (nabla_node) and the simulator (nabla_sim)
// import this library for protocol logic.
//
// Reference: AXIOM_GUIDE_Nabla.md
//            AXIOM_YPX-003_TARDIS.md
//
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  ARCHITECTURAL RULE: Nabla NEVER does cryptography directly.       ║
// ║                                                                    ║
// ║  Core is the sole cryptographic authority. Nabla talks to Core     ║
// ║  through the crypto::Signer trait:                                 ║
// ║    - signer.sign(payload) → signature bytes                       ║
// ║    - signer.verify(pk, payload, sig) → true/false                 ║
// ║                                                                    ║
// ║  Nabla does NOT know which algorithm Core uses internally.        ║
// ║  Production: CoreIpcSigner delegates to AVM interpreter            ║
// ║              (axiom-core.elf loaded at runtime).                   ║
// ║  Sim/Test: Ed25519Signer with real keypairs for verification.     ║
// ╚══════════════════════════════════════════════════════════════════════╝
//
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  PROTOCOL / SIMULATOR BOUNDARY (YPX-003 §2.6)                    ║
// ║                                                                    ║
// ║  Protocol layer (this library's public API):                      ║
// ║    tardis.rs    — tick authority, recovery, rotation, rebalancing  ║
// ║    mesh.rs      — gossip mesh topology, peer management           ║
// ║    constants.rs — ALL protocol constants                          ║
// ║    types.rs     — shared types, messages                          ║
// ║                                                                    ║
// ║  Protocol decisions ALWAYS live here. Sim NEVER decides.          ║
// ║  Sim calls protocol methods and executes returned actions.        ║
// ╚══════════════════════════════════════════════════════════════════════╝

// ── Protocol Layer (Public API) ──
// These modules form the Nabla protocol. External consumers (production
// binary, test harnesses, other crates) import from here.

// Wire-boundary functions (process_registration, advance-on-proof
// verification) take >7 args by design. Allow.
#![allow(clippy::too_many_arguments)]

/// Protocol types: NodeId, PeerId, messages, addresses.
pub mod types;

/// Protocol constants: all thresholds, intervals, limits.
pub mod constants;

/// JUDOON — Judgment Upon Divergent Or Offending Nablas. Pool
/// quarantine subsystem: `DrainOnlyPool` trait, depletion-aware
/// threshold curve, structural-violation detection (Layer 1), D2 slack
/// scaling (Layer 2), per-pool dispatch. Three-layer defense in depth
/// per `docs/AXIOM_DESIGN_NablaJudoon.md`.
pub mod judoon;

/// FOB (Fixed Outflow Balance) — Bounded Pools value-logic core: the two-state
/// pool, the pure tranche function, mover sortition + the §5 eligibility gate.
/// Self-contained + native-tested (Phase 1a); wiring into PoolKind/PoolSync is
/// Phase 1b–d. Design `docs/AXIOM_DESIGN_BoundedPools.md`, model
/// `docs/models/fob_bounded_pools/`.
pub mod fob;
pub mod emission;

/// TARDIS: tick authority, approval chain, tree topology, recovery,
/// rotation, rebalancing. ALL tree-level protocol decisions live here.
pub mod tardis;

/// Gossip mesh: adaptive peer management, topology hints, scoring,
/// anti-ossification rotation. ALL mesh-level protocol decisions live here.
pub mod mesh;

/// Gossip engine: message processing, deduplication, forwarding.
pub mod gossip;

/// Sparse Merkle Tree: wallet state verification.
pub mod smt;

/// KI#43a — exact consumed-state record (per-era append-only files).
pub mod consumed_exact;

/// Write-ahead log: crash recovery for SMT operations.
pub mod wal;

/// Snapshot: periodic SMT persistence.
pub mod snapshot;

/// Registration: wallet registration protocol.
pub mod registration;

/// Query: wallet state query protocol.
pub mod query;

/// Client wire protocol: typed request/response envelopes for the
/// HTTP→TCP migration paths (CLAUDE.md §8). Both HTTP and TCP transports
/// operate on these types; HTTP serializes via serde_json, TCP via
/// ciborium.
pub mod wire_client;

/// Ban detection: conflicting state detection and evidence propagation.
pub mod ban;

// Fork Settlement W7c/W7d (minimal) — the derived provenance verdict behind
// `NablaNode::origin_vouch` and `RegistrationAck.provenance`.
pub mod provenance;

/// Fork Settlement §9o [R58/R59] (W1) — R48 record-AE: the record trie, the
/// receiver-driven descent, the R51 walk and the R50 session.
pub mod record_sync;

// Dev-only live-gate switch (ForkSettlement §9o proof obligations, KI#235/#236): feature
// `flood-chaos` (dev build only — scripts/check_flood_chaos_dev_only.sh) + this crate's tests.
#[cfg(any(test, feature = "flood-chaos"))]
pub mod flood_chaos;

/// Nabla node: orchestrates protocol components for a single node.
pub mod node;
/// ForkSettlement wave 4a (R42/R50) — the self-proving validator witness
/// directory (KI#170 registry verified; KI#223 fixed).
pub mod vbc_directory;
/// KI#182 — THE list of what a node persists under its data dir (wipe / retain set).
pub mod persistence;

/// Configuration: runtime config loading from file.
pub mod config;

/// Companion Certificate: NBC issuance, CC chaining, DEED runner rewards.
pub mod cc;

/// Compaction: periodic SMT compaction and cleanup.
pub mod compaction;

/// Monitoring: health metrics, HTTP status endpoint.
pub mod monitor;

/// Oracle distribution: daily emission pool sync (YPX-005).
pub mod oracle;

/// Resilience: partition detection, recovery strategies.
pub mod resilience;

/// OODS (YPX-021): Operational Observer Determination System — gossip-native
/// network-size estimator for partition/eclipse detection. Estimator primitive
/// only; NOT wired to any consensus path (see YPX-021 §12).
pub mod oods;

/// Cryptographic interface: Signer trait, Ed25519 test impl, canonical payloads.
/// This is how Nabla talks to Core for all sign/verify operations.
pub mod crypto;

/// Ceremony: real VBC generation for sim nodes using Core's SPHINCS+ signing.
/// Generates actual root authority keys + per-node VBCs with valid signatures.
pub mod ceremony;

/// Transport layer: pluggable message transport (TCP, stdio).
/// Wire protocol envelope (WireMessage) and address conversion helpers.
pub mod transport;

/// Bloom filter for txid double-redeem detection (YPX-014).
pub mod bloom;

/// YPX-018 §3.3 — Time-bucketed bloom era (one bloom file per quarter).
/// Eras freeze at end_tick, locking their FPR forever.
pub mod bloom_era;

/// YPX-018 §3 — Bloom chain. Sequence of eras with rotation logic.
/// Used by both the txid chain and the garbage state chain.
pub mod bloom_chain;

/// YPX-025 — ATRAXI: the Nabla hold/ban index (claims open + close on evidence).
pub mod atraxi;

/// YPX-018 §3.1, §3.3 — Bloom Age Index. Directory of every bloom era this
/// node knows about (txid + garbage chain metadata side-by-side).
pub mod age_index;

/// YPX-018 §3.2 — Garbage state bloom chain. Records states declared garbage
/// by CLARA wallet heals (YPX-018 §2 / Yellow Paper §17.10.14).
pub mod garbage_state_chain;

/// YPX-018 §2.4 — CLARA registration logic. Pure protocol function used by
/// the `POST /clara` HTTP handler in `bin/nabla_node.rs`. Verifies the
/// heal cheque shape, checks freshness in both bloom chains, and inserts.
pub mod clara;

/// YP §19.6 fee ledger — validator pool registration handler + storage.
/// Validators declare which wallet receives their fee withdrawals via
/// `WireMessage::RegisterValidatorPoolRequest`; this module verifies the
/// SPHINCS+ binding + linkage_epoch + freshness, then persists.
/// Operator-driven (per-validator dashboard); wallet SDK is not a consumer.
pub mod validator_pool;

/// YPX-002 P6 — simulated network-delay injection for local soak runs.
/// See `sim_delay.rs` for the contract.
pub mod sim_delay;

// ── Simulator (Not public API — used by nabla-sim binary) ──
// The simulator uses the protocol library but is NOT part of the stable API.
// External consumers should not depend on sim internals.
// Internal to this crate: only nabla-sim binary imports this module.
#[doc(hidden)]
pub mod sim;

/// Binary simulator: spawns real nabla-node processes and routes messages.
/// Used by nabla-sim --mode=binary.
#[doc(hidden)]
pub mod binary_sim;

/// ForkSettlement §7 — in-process multi-node fork-detection gate: N real
/// `NablaNode`s, a router calling the binary's own lib entry points, shed /
/// delay / crash / restart adversary. Test-only (the leg builder is
/// `#[cfg(test)]`).
#[cfg(test)]
mod fork_detection_mesh;

// ── Core Integration ──
// All cryptographic operations go through crypto::Signer trait.
// See crypto.rs for the trait definition, Ed25519 test impl, and canonical payloads.
// Production binary uses CoreIpcSigner (nabla_node.rs) → delegates to axiom-core.
