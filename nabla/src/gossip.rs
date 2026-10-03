// AXIOM Nabla — Basic Gossip (Phase 1)
// Reference: AXIOM_GUIDE_Nabla.md Section 6.3-6.4
//
// Phase 1 Task 8: Basic gossip (flood fill state updates)
//
// Flood fill through mesh peers. Every Nabla node forwards to all mesh
// peers except the sender. No routing table. No assignments.
// Deduplication via message hash set.
//
// Phase 4 adds: adaptive peers, topology hints, partition recovery.
// This module is the minimal gossip engine for Phase 1.

use std::collections::{HashMap, HashSet};

use crate::ban::BanTable;
use crate::oracle::{DailyPoolState, reconcile_pool};
use crate::smt::SparseMerkleTree;
#[allow(unused_imports)]
use crate::types::*;

/// YPX-009 §5.3 — the payload builder and signature check are CORE's
/// (`axiom_core_logic::pulse`, one builder for Lambda, Nabla and CL8's
/// §5.2.2e candidacy rule; moved 2026-09-08). Re-exported for the callers
/// and tests in this crate.
pub use axiom_core_logic::pulse::{pulse_proof_sign_payload, verify_pulse_proof_sig};

/// YPX-009: Compute the BLAKE3 domain-tagged payload for client state signatures.
/// Payload = BLAKE3("AXIOM_WALLET_STATE" || wallet_id || new_state || tx_hash).
///
/// NO TICK (KI#46, 2026-07-29). The commit tick is stamped by the NODE at
/// registration, so a client cannot know it at signing time — binding it
/// here is exactly why the client sig stayed unwired for months while the
/// gossip flood dropped every SDK register as "invalid client sig". Dropping
/// the tick is sound: the signature attests "this wallet's key authorizes
/// head `new_state` via `tx_hash`"; replaying it can only re-assert the same
/// idempotent transition, and staleness/ordering are governed by the WI3
/// seq gate + the A12/AE consumed-state gates, never by this signature.
///
/// MIRRORED byte-for-byte in `axiom-sdk` (`sdk/client/src/nabla.rs`
/// `client_state_sign_payload`) — the two sides are pinned to the same test
/// vector (`client_state_payload_pinned_vector` in both crates). Change one,
/// change both.
// KI#53: the payload is defined ONCE, in Core (`crypto::client_state_sign_payload`).
// This was a second, independent copy — a parallel builder of a cryptographically
// bound hash, which CLAUDE.md forbids and which has cost this codebase six
// incidents. Re-exported so existing `gossip::client_state_sign_payload` call
// sites keep resolving.
pub use crate::registration::client_state_sign_payload;

/// YP §19.6 fee ledger — record a per-tx fee_breakdown received via
/// gossip into hashmap-mode storage. Called only after the parent SMT
/// state-update merge wins, so we never persist fee records for stale
/// state transitions.
///
/// Gossip-driven mutations are in-memory only (matches the existing
/// SMT.put pattern at this layer — durability is via periodic snapshot,
/// not per-message WAL append). The originating `/register` handler
/// (Step 5) is the WAL-writing producer; gossip is the cross-mesh
/// propagation path that reconstructs in-memory state on peer nodes.
///
/// Trust model: the gossip carries the SDK-proposed fee_breakdown
/// without an explicit per-message signature chain (the proof rides on
/// the receipt_commitment that k Lambdas signed; this gossip is a
/// trusted-mesh broadcast of data that was already consensus-verified
/// at its origin). Defense-in-depth: caps are re-validated at every
/// hop, and `record_tx_meta` dedups on tx_hash so the first-seen
/// (legitimate, gossiped from origin) record wins races against any
/// later forgery. Step 6's signed query response is the layer where a
/// downstream consumer cryptographically verifies hashmap-node output.
///
/// `pub` so the KI#82 fee-ledger anti-entropy handler (`bin/nabla_node.rs`) can
/// adopt AE-transferred records through this SAME cap-revalidating chokepoint —
/// one adoption path for both flood and AE (RULE 1). See
/// AXIOM_DESIGN_NablaAntiEntropy.md §13.
pub fn apply_fee_record_from_gossip(
    smt: &mut SparseMerkleTree,
    tx_hash: &TxHash,
    receiver_wallet_id: &WalletId,
    amount: u64,
    fee_breakdown: &[axiom_core_logic::types::FeeShare],
    tick: u64,
) {
    if fee_breakdown.is_empty() {
        return; // no-fee path (heal / genesis / pre-step-4 senders)
    }
    if smt.txid_mode() != crate::bloom::TxidServiceMode::Hashmap {
        return; // bloom-mode nodes pay no storage cost
    }
    // Re-validate caps independently — never trust gossip for cap
    // enforcement, defense-in-depth atop Step 5's /register check
    // and Lambda's slot verification.
    if axiom_core_logic::validation::validate_fee_breakdown(amount, fee_breakdown).is_err() {
        log::warn!(
            "Gossip fee_breakdown failed cap validation (tx_hash={:02x}{:02x}…) — dropping record",
            tx_hash[0], tx_hash[1],
        );
        return;
    }
    smt.record_tx_meta(
        *tx_hash,
        crate::types::TxRecord {
            receiver_wallet_id: *receiver_wallet_id,
            amount,
            fee_breakdown: fee_breakdown.to_vec(),
            tick,
        },
    );
}

/// YPX-009: Verify client Ed25519 signature over state record.
/// ⚠ KI#226 (RULE 0 §4 marker, 2026-09-28): WRONG READING — "a valid sig
/// here means `client_pk` owns `wallet_id`". RIGHT READING — this proves only
/// that `client_pk` signed over `wallet_id`; ownership is a SEPARATE check,
/// `registration::bucket_derives_from_key` (flood `apply_state_update`, AE
/// `apply_remote_entry`) / the door's step 0b (bucket derived from
/// `reg.client_pk`), which every caller that takes both fields from one
/// message now runs BEFORE this. Without it any key's leg re-signed over a
/// victim's id replaced the victim's head
/// (`fork_detection_mesh::s8b_framing_legs_do_not_replace_victim_head`).
/// FIXED (pending rotation).
pub fn verify_client_state_sig(
    client_pk: &[u8; 32],
    client_sig: &[u8],
    wallet_id: &[u8; 32],
    new_state: &[u8; 32],
    tx_hash: &[u8; 32],
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    if client_sig.len() != 64 {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(client_pk) else {
        return false;
    };
    let sig_bytes: [u8; 64] = client_sig.try_into().unwrap();
    let sig = Signature::from_bytes(&sig_bytes);
    let payload = client_state_sign_payload(wallet_id, new_state, tx_hash);
    vk.verify(&payload, &sig).is_ok()
}

/// SECURITY FIX #6: Maximum gossip messages accepted per peer per window.
/// Prevents a single malicious node from flooding the network with unique
/// messages that pass dedup but consume forwarding bandwidth and CPU.
pub const GOSSIP_PER_PEER_LIMIT: u64 = 500;

/// Window duration for per-peer gossip rate limiting (seconds).
pub const GOSSIP_RATE_WINDOW_SECS: u64 = 60;

// Fork Settlement §9q (B2, 2026-09-30): `GOSSIP_VERIFY_BUDGET_PER_WINDOW`,
// `HalPrecheck` and the per-peer verify budget were DELETED with the E3
// `HalAdvance` arm they served (docs/AXIOM_DESIGN_NablaAntiEntropy.md §11.2
// parts A/B, struck). A `HalAdvance` is now dropped unverified (O(1)); the
// HAL leg rides `StateUpdate` and pays the same flood-path leg verification
// as every other register (the ForkSettlement §9b R36 cost, unchanged).

/// YPX-002 P5 — per-variant gossip latency instrumentation.
///
/// Records `current_tick - message_tick` observations into a fixed-size
/// ring buffer per variant, exposing p50/p99 for soak assertions and
/// admin dashboards. The observation is purely passive: the caller
/// (nabla_node.rs::handle_message) invokes `observe` for every gossip
/// message it actually applies, passing the node's current tick. The
/// stats struct never mutates any protocol state, so it can be polled
/// from an HTTP handler without locking anything heavy.
///
/// Ring buffer size chosen so 10 nodes gossiping at ~10 msg/s take ~100s
/// to roll over — long enough to produce a stable p99 even during
/// steady-state traffic lulls, short enough to reflect recent network
/// health rather than historical averages.
const GOSSIP_LATENCY_RING: usize = 1024;

/// One latency observation: how old the message was, and WHEN we saw it.
///
/// ⚠ KI#203 — `observed_at` is what makes this instrument judgeable. The ring
/// used to store the age alone, so a snapshot could not say when its samples
/// were taken: it is a LIFETIME ring of 1024 slots, `observe` counts every
/// StateUpdate it is handed INCLUDING re-floods that carry their ORIGINAL tick,
/// and a quiet dev mesh produces ~30 fresh StateUpdates an hour. MEASURED
/// 2026-09-18, one hour after a fleet restart: `state_update` count=998
/// p50=12737 p99=340994 max=342876 ticks (≈4 days) on every node, identical
/// across two runs 50 minutes apart — while the `tick_hash` ring beside it, fed
/// every tick over the same gossip path, read p50=0 p99=1. The instrument was
/// reporting its own history as the mesh's health, and nothing in the answer
/// said so (RULE 6 §1: an instrument must be able to say "I am stale").
/// A state update observed more than this many ticks after its own tick is named
/// in the log (see `observe`). Timer A is 1 tick; the sandbox threshold is 6.
const STALE_STATE_UPDATE_TICKS: u32 = 60;

#[derive(Debug, Clone, Copy)]
struct LatencySample {
    age: u32,
    observed_at: u64,
}

#[derive(Debug, Clone, Default)]
pub struct GossipLatencyStats {
    /// Ring buffer of observations per variant. Writes wrap via modular index
    /// into `*_idx` once the ring is full.
    state_update: Vec<LatencySample>,
    group_update: Vec<LatencySample>,
    tick_hash:    Vec<LatencySample>,
    state_update_idx: usize,
    group_update_idx: usize,
    tick_hash_idx:    usize,
}

impl GossipLatencyStats {
    pub fn new() -> Self { Self::default() }

    fn push(buf: &mut Vec<LatencySample>, idx: &mut usize, sample: LatencySample) {
        if buf.len() < GOSSIP_LATENCY_RING {
            buf.push(sample);
        } else {
            buf[*idx] = sample;
            *idx = (*idx + 1) % GOSSIP_LATENCY_RING;
        }
    }

    /// Observe one gossip message. `current_tick` is the node's local
    /// TARDIS tick at the moment the message was applied. Variants
    /// without a `tick` field (BanAlert, TaintAlert, etc.) are
    /// skipped — their absence is intentional and documented.
    pub fn observe(&mut self, msg: &GossipMessage, current_tick: u64) {
        // `saturating_sub` because a clock skew can produce msg.tick
        // > current_tick in rare cases (new tick observed via gossip
        // before the local TARDIS state machine caught up). That's
        // still a useful signal (== 0 age), not an error.
        let sample = |tick: u64| LatencySample {
            age: current_tick.saturating_sub(tick) as u32,
            observed_at: current_tick,
        };
        match msg {
            GossipMessage::StateUpdate { tick, wallet_id, tx_hash, wallet_seq,
            is_genesis_claim: false, .. } => {
                let s = sample(*tick);
                // RULE 6: an aggregate p99 cannot say WHICH update was stale. Live
                // 2026-09-24 the sandbox read p99 = 264 then 291 ticks (p50 = 0) from ONE
                // sample whose age grew with wall time — a state update gossiped with
                // an old origin tick (AE re-push of an entry a peer keeps missing, or a
                // registration stamped with a stale tick). Name it, once per observation,
                // so the next run can read the wallet / tx / tick instead of guessing.
                if s.age > STALE_STATE_UPDATE_TICKS {
                    log::warn!(
                        "[GOSSIP-LATENCY] stale state_update: wallet={} tx={} seq={} msg_tick={} observed_at={} age={} ticks",
                        hex::encode(&wallet_id[..8]),
                        hex::encode(&tx_hash[..core::cmp::min(8, tx_hash.len())]),
                        wallet_seq, tick, current_tick, s.age,
                    );
                }
                Self::push(&mut self.state_update, &mut self.state_update_idx, s);
            }
            GossipMessage::GroupUpdate { tick, .. } => {
                Self::push(&mut self.group_update, &mut self.group_update_idx, sample(*tick));
            }
            GossipMessage::TickHash { tick, .. } => {
                Self::push(&mut self.tick_hash, &mut self.tick_hash_idx, sample(*tick));
            }
            // Variants without tick: explicitly not instrumented.
            // Adding tick fields to BanAlert / ForkEvidence / ForkBan et al. would
            // require touching serialized protocol state and is out of
            // scope for an instrumentation-only change.
            _ => {}
        }
    }

    /// Percentiles over the samples OBSERVED at or after `since_tick`
    /// (`None` = the whole ring). An empty selection returns all zeros with
    /// `count == 0` — the consumer must read `count` before any percentile.
    fn variant(buf: &[LatencySample], since_tick: Option<u64>) -> GossipLatencyVariant {
        let picked: Vec<&LatencySample> = buf
            .iter()
            .filter(|s| since_tick.is_none_or(|t| s.observed_at >= t))
            .collect();
        if picked.is_empty() {
            return GossipLatencyVariant {
                count: 0, p50_ticks: 0, p99_ticks: 0, max_ticks: 0,
                oldest_observed_tick: 0, newest_observed_tick: 0,
            };
        }
        let mut ages: Vec<u32> = picked.iter().map(|s| s.age).collect();
        ages.sort_unstable();
        let n = ages.len();
        GossipLatencyVariant {
            count: n,
            p50_ticks: ages[n * 50 / 100],
            // clamp p99 to the last index so a ring of 1..100 still returns the top
            p99_ticks: ages[(n * 99 / 100).min(n - 1)],
            max_ticks: ages[n - 1],
            oldest_observed_tick: picked.iter().map(|s| s.observed_at).min().unwrap_or(0),
            newest_observed_tick: picked.iter().map(|s| s.observed_at).max().unwrap_or(0),
        }
    }

    /// Return a serializable snapshot. Used by the /gossip-latency
    /// HTTP endpoint and by soak test assertions.
    ///
    /// `since_tick = None` is the whole (lifetime) ring — the historical
    /// behaviour, now carrying `oldest/newest_observed_tick` so a reader can
    /// see how old the evidence is. `Some(t)` restricts every variant to
    /// samples observed at tick ≥ `t`, and the snapshot ECHOES `since_tick`:
    /// a binary that predates KI#203 ignores the query parameter and answers
    /// with the whole ring, so a consumer that asked for a window MUST check
    /// the echo before trusting the numbers.
    pub fn snapshot(&self, current_tick: u64, since_tick: Option<u64>) -> GossipLatencySnapshot {
        GossipLatencySnapshot {
            current_tick,
            since_tick,
            state_update: Self::variant(&self.state_update, since_tick),
            group_update: Self::variant(&self.group_update, since_tick),
            tick_hash:    Self::variant(&self.tick_hash, since_tick),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GossipLatencyVariant {
    pub count: usize,
    pub p50_ticks: u32,
    pub p99_ticks: u32,
    pub max_ticks: u32,
    /// Node tick at which the OLDEST / NEWEST selected sample was observed
    /// (0 when `count == 0`). `current_tick - oldest_observed_tick` is how far
    /// back this evidence reaches (KI#203).
    pub oldest_observed_tick: u64,
    pub newest_observed_tick: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GossipLatencySnapshot {
    /// The node's tick when the snapshot was taken.
    pub current_tick: u64,
    /// The window actually applied; `null` = whole ring. See `snapshot`.
    pub since_tick: Option<u64>,
    pub state_update: GossipLatencyVariant,
    pub group_update: GossipLatencyVariant,
    pub tick_hash:    GossipLatencyVariant,
}

/// Resolve the `/gossip-latency` query string to the window to apply (KI#203).
///
///   (none)            → `Ok(None)`   the whole ring
///   `since_tick=T`    → `Ok(Some(T))` samples observed at tick ≥ T
///   `window_ticks=N`  → `Ok(Some(current_tick − N))` the last N ticks
///
/// A parameter that is present but unparseable — or both at once — is an
/// ERROR, never a silent fall-back to the whole ring: a consumer that asked for
/// a window and was handed history is exactly the defect KI#203 records.
pub fn parse_latency_window(query: Option<&str>, current_tick: u64) -> Result<Option<u64>, String> {
    let param = |name: &str| -> Option<&str> {
        query.and_then(|q| {
            q.split('&').find_map(|p| p.strip_prefix(name).and_then(|r| r.strip_prefix('=')))
        })
    };
    let num = |name: &str, v: &str| -> Result<u64, String> {
        v.parse::<u64>().map_err(|_| format!("{name} must be an unsigned integer, got {v:?}"))
    };
    match (param("since_tick"), param("window_ticks")) {
        (Some(_), Some(_)) => Err("pass since_tick OR window_ticks, not both".to_string()),
        (Some(v), None) => Ok(Some(num("since_tick", v)?)),
        (None, Some(v)) => Ok(Some(current_tick.saturating_sub(num("window_ticks", v)?))),
        (None, None) => Ok(None),
    }
}

/// Gossip engine — manages message deduplication and processing.
///
/// Dedup uses two-generation HashSets: `seen` (current) and `prev_seen` (previous).
/// Messages are checked against both. When `seen` fills up, `prev_seen` is replaced
/// by `seen` and a fresh set starts. This ensures at most 50% dedup loss on rotation
/// (vs 100% loss with clear-all). Memory: max 2 × max_seen × 32 bytes = 6.4MB.
pub struct GossipEngine {
    /// Current generation of seen message hashes.
    seen: HashSet<Hash256>,
    /// Previous generation — still checked for dedup, discarded on next rotation.
    prev_seen: HashSet<Hash256>,
    /// Maximum size per generation before rotation.
    max_seen: usize,
    /// SECURITY FIX #6: Per-peer gossip rate counters (peer_addr → (count, window_start)).
    /// Prevents gossip flood from a single source.
    peer_gossip_counts: HashMap<u64, (u64, u64)>,
    /// ForkSettlement §9r-E4 (2026-10-02) — `TaintAlert` messages received and
    /// DROPPED. The arm is a tombstone: its only effect was a hostile-triggered
    /// door block (`Tainted` → `is_wallet_blocked`) on the downstream wallet
    /// §9k ruling 1 says must be ACCEPTED and MARKED, and its only emitter (the
    /// §32 SCAN → `handle_fork_evidence`) never fired. No node of this build
    /// emits it, so non-zero = a pre-E4 build or a hostile party. Never
    /// tainted on, never forwarded. On `/status` as `taintalert_dropped`.
    /// (Replaces `taint_applied` / `taint_unconfirmed`.)
    taintalert_dropped: u64,
    /// ForkSettlement §9r-E4 (D-E4-1) — `MergeResolved` messages received and
    /// DROPPED. Its only emitter (the 75 s quarantine expiry) is deleted; the
    /// summary was unauthenticated and acted on nothing. Never forwarded. On
    /// `/status` as `mergeresolved_dropped`.
    mergeresolved_dropped: u64,
    /// G15 — H3 data-availability messages received for a protocol that has no
    /// emitter, no window constant and no SCAR path. Non-zero means something
    /// is sending them; they are dropped, never relayed.
    h3_unbuilt_dropped: u64,
    /// KI#222 — `BanAlert` messages received and DROPPED since the receiver was
    /// retired (2026-09-28). The E1 proof (`ConflictProof` pair) is forgeable
    /// from one genuine registration receipt and no honest node emits it, so a
    /// non-zero value means something on the mesh is sending one — either a
    /// pre-KI#222 test build or an attacker trying the false-ban door. Surfaced
    /// on `/status` as `ki222_banalert_dropped` (RULE 3 §2).
    ki222_banalert_dropped: u64,
    /// Fork Settlement §9o [R56] (W2, 2026-09-30) — `SeqForkBan` messages
    /// received and DROPPED. check-3, the only emitter, was retired as a ban
    /// source (KI#235: it banned honest wallets after a same-seq jump or a
    /// flood reorder); no honest node of this build sends one, so a non-zero
    /// value means a pre-W2 build or a hostile party is on the mesh. Never
    /// adopted, never forwarded. Surfaced on `/status` as `seqforkban_dropped`
    /// (RULE 3 §2).
    seqforkban_dropped: u64,
    /// Fork Settlement §9q (B2, 2026-09-30) — `HalAdvance` messages received
    /// and DROPPED. The E3 arm (KI#34 check-3's `previous_states` freeze) is
    /// retired and no node of this build emits the variant (HAL re-anchors
    /// flood as `StateUpdate` with their leg), so a non-zero value means a
    /// pre-B2 build or a hostile party is on the mesh. Never verified,
    /// adopted, frozen on or forwarded. Surfaced on `/status` as
    /// `haladvance_dropped` (RULE 3 §2).
    haladvance_dropped: u64,
}

/// Result of processing a gossip message.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum GossipAction {
    /// Forward this message to all mesh peers except sender.
    Forward(GossipMessage),
    /// Message was a duplicate — do nothing.
    Duplicate,
    // `BanDetected { forward, ban_alert }` was DELETED 2026-09-30 (Fork
    // Settlement §9o [R56], W2): its only origin was check-3's `SeqForkBan`
    // ban in `apply_state_update`, retired as a ban source (KI#235). Verdicts
    // leave a node only through `NablaNode::drain_fork_side_effects` (WAL +
    // `ForkBan` fan-out).
    /// Phase B Layer 4: an incoming PoolSync triggered a pool-state
    /// violation (direction or magnitude). Caller (binary) should
    /// build + broadcast a `GossipMessage::Alert` naming `accused`
    /// (the verified `sender_node_id` from the offending PoolSync).
    /// The bad PoolSync itself is NOT forwarded (this is also a
    /// "drop" action for the original message).
    PoolViolationDetected {
        /// CBOR-serialized offending PoolSync — becomes Alert.evidence.
        evidence: Vec<u8>,
        /// Verified sender of the offending PoolSync. Used directly
        /// as `Alert.accused` — sig was checked at the binary layer
        /// before the message reached `engine.process`.
        accused: crate::types::NodeId,
    },
    /// Layer 1 single-observer structural violation detected by
    /// `judoon::structural_violation`. The binary routes
    /// the offender into probation (suppress relay for 10 ticks; if
    /// the next PoolSync from this peer is still bad, escalate to
    /// quarantine via the WAL/TTL/cooldown machinery — no Alert /
    /// K-of-N consensus required, since the proof is self-evident).
    /// See `AXIOM_DESIGN_NablaJudoon.md` §2.5.
    PoolStructuralViolation {
        /// CBOR-serialized offending PoolSync — carries the proof.
        evidence: Vec<u8>,
        /// Verified sender of the offending PoolSync.
        accused: crate::types::NodeId,
        /// Which structural impossibility was detected. Logged on
        /// probation entry and escalation for operator dashboards.
        proof: crate::judoon::ProofKind,
    },
}

impl GossipEngine {
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            prev_seen: HashSet::new(),
            max_seen: 100_000, // rotate after 100k messages per generation
            peer_gossip_counts: HashMap::new(),
            taintalert_dropped: 0,
            mergeresolved_dropped: 0,
            h3_unbuilt_dropped: 0,
            ki222_banalert_dropped: 0,
            seqforkban_dropped: 0,
            haladvance_dropped: 0,
        }
    }

    /// §9r-E4 — `TaintAlert` messages dropped (the variant is a tombstone).
    pub fn taintalert_dropped(&self) -> u64 {
        self.taintalert_dropped
    }

    /// §9r-E4 (D-E4-1) — `MergeResolved` messages dropped (tombstone).
    pub fn mergeresolved_dropped(&self) -> u64 {
        self.mergeresolved_dropped
    }

    /// H3 data-availability messages dropped as unbuilt (G15).
    pub fn h3_unbuilt_dropped(&self) -> u64 {
        self.h3_unbuilt_dropped
    }

    /// KI#222 — `BanAlert` messages dropped by the retired receiver.
    pub fn ki222_banalert_dropped(&self) -> u64 {
        self.ki222_banalert_dropped
    }

    /// §9o [R56] — `SeqForkBan` messages dropped (the variant is a tombstone).
    pub fn seqforkban_dropped(&self) -> u64 {
        self.seqforkban_dropped
    }

    /// §9q (B2) — `HalAdvance` messages dropped (the variant is a tombstone).
    pub fn haladvance_dropped(&self) -> u64 {
        self.haladvance_dropped
    }

    /// SECURITY FIX #6: Check per-peer gossip rate limit.
    /// Returns true if this peer is within the allowed rate.
    /// `peer_hash` is a u64 hash of the peer's address/identity.
    pub fn check_peer_rate(&mut self, peer_hash: u64, now_secs: u64) -> bool {
        let entry = self.peer_gossip_counts.entry(peer_hash).or_insert((0, now_secs));
        if now_secs.saturating_sub(entry.1) >= GOSSIP_RATE_WINDOW_SECS {
            // Window expired — reset
            *entry = (1, now_secs);
            true
        } else if entry.0 >= GOSSIP_PER_PEER_LIMIT {
            false
        } else {
            entry.0 += 1;
            true
        }
    }

    /// Prune stale peer rate entries (called periodically).
    pub fn prune_peer_rates(&mut self, now_secs: u64) {
        self.peer_gossip_counts.retain(|_, (_, start)| {
            now_secs.saturating_sub(*start) < GOSSIP_RATE_WINDOW_SECS * 2
        });
    }

    /// Process an incoming gossip message.
    ///
    /// Returns the action to take: forward, ignore (duplicate), or ban.
    /// The caller (NablaNode) is responsible for actually forwarding
    /// and applying state changes.
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        &mut self,
        msg: &GossipMessage,
        smt: &mut SparseMerkleTree,
        bans: &mut BanTable,
        pool: &mut DailyPoolState,
        airdrop_pool: &mut crate::node::AirdropPool,
        dev_treasury_pool: &mut crate::node::DevTreasuryPool,
        // Validator-join subsidy pools (AXIOM_DESIGN_ValidatorJoin.md §2).
        // Same AirdropPool type — drain-only, min-wins — distinguished by
        // PoolKind on the wire and on disk, never by Rust type.
        bootstrap_pool: &mut crate::node::AirdropPool,
        foundation_bootstrap_pool: &mut crate::node::AirdropPool,
        deed_pool: &mut crate::node::DeedPool,
        dev_deed_pool: &mut crate::node::DevDeedPool,
        // KI#191 residual (RULED 2026-09-25, NablaJudoon §2.5): the contribution
        // emission pools are reconciled HERE, in the same match as every other
        // pool, so their `ReconcileOutcome` takes the same escalation path.
        // `deed_pool` above is the epoch-roll source `EmissionPools::reconcile`
        // draws from.
        emission: &mut crate::emission::EmissionPools,
        // FOB (§7): the per-validator Bounded-Fee pool map, and the verified
        // tranche credits per epoch (`epoch → {validator_id → amount}`,
        // populated when this node judges a `FobTranche` statement). The
        // PoolSync BoundedFee arm reconciles the map against these — an INCREASE
        // is authorised iff the epoch's credit matches.
        fob_pools: &mut std::collections::HashMap<([u8; 32], bool), crate::fob::FobPool>,
        fob_credits: &std::collections::HashMap<u64, std::collections::HashMap<([u8; 32], bool), u64>>,
        // (`signer: &dyn Signer` was removed 2026-09-30, §9q: its only reader
        // was the retired E3 `HalAdvance` k3 verify.)
        current_tick: u64,
        // ForkSettlement §2.4 [R13] — the binary's wall clock (`virtual_secs`),
        // stamped on origin records the flood hook / `ForkBan` adoption create.
        // Never `current_tick` (TARDIS) and never the message's `tick`.
        now_secs: u64,
        n_validators: usize,
        // KI#224 — THIS node's R42 witness directory (`VbcDirectory::
        // is_witness`, read live). A carried SeqProof counts as attesting a
        // head only if EVERY witness key walks back to the root through it
        // (`ban::seq_proof_is_directory_witnessed`) — the same predicate as
        // register door step 5b⁗ and head-AE.
        is_witness: &dyn Fn(&[u8; 32]) -> bool,
    ) -> GossipAction {
        // ── Deduplicate (two-generation) ──
        let msg_hash = self.hash_message(msg);
        if self.seen.contains(&msg_hash) || self.prev_seen.contains(&msg_hash) {
            return GossipAction::Duplicate;
        }
        self.seen.insert(msg_hash);
        self.maybe_prune();

        // ── Process by type ──
        match msg {
            GossipMessage::StateUpdate {
                wallet_id,
                new_state,
                old_state,
                tx_hash,
                tick,
                is_genesis_claim,
                wallet_seq,
                client_pk,
                client_sig,
                amount,
                fee_breakdown,
                seq_proof,
            } => self.apply_state_update(
                smt, bans, wallet_id, new_state, old_state, tx_hash, tick, *is_genesis_claim,
                wallet_seq, client_pk, client_sig, amount, fee_breakdown, seq_proof, msg,
                now_secs, is_witness,
            ),

            // Fork Settlement §9q (design B2, owner ruling 2026-09-30 "fix it
            // with ATRAXI") — `HalAdvance` is a TOMBSTONE, like `BanAlert` and
            // `SeqForkBan`. The register door no longer emits it: a HAL
            // re-anchor floods as a plain `StateUpdate` carrying its SeqProof
            // (`registration.rs` step 10), so every receiver runs the ONE flood
            // record hook on the HAL leg and a revival X→X′ beside a recorded
            // X→Y is judged as an A1 `ForkClaim` (`ban::apply_fork_verdict`,
            // permanent ban on evidence) — and R48 record-AE carries the two
            // legs where no flood brings them together.
            //
            // RULE 0 §4 — the WRONG reading this arm encoded (YPX-025 E3, KI#34
            // check-3): "`held_current != new_state ∧ previous_states[W] ==
            // old_state` plus k3 sigs over `receipt_sign_payload(W, old_state,
            // tick)` proves X was spent twice — freeze W and forward". Three
            // defects, each measured (§9q): (1) the door stamped `tick =
            // current_tick` but Lambda signs that payload with tick 0, so a
            // GENUINE door-emitted revival never verified — the freeze never
            // fired on a real fork (a GHOST; `fork_detection_mesh::
            // b2_a2_*` records the §9q probe); (2) `previous_states[W]`
            // is the head this node's last put OVERWROTE (a VIEW, KI#235), so an
            // honest HAL chain learned by a jump satisfied it; (3) the freeze
            // was a local judgment no peer could verify. The correct reading:
            // a revival is two wallet-signed, k-witnessed legs under one
            // `(pk, consumed)` key — the A1 standard every other fork meets.
            //
            // So this arm verifies nothing, adopts nothing, freezes nothing and
            // never forwards. It counts (`haladvance_dropped`, on /status) and
            // warns at power-of-two counts. A non-zero value means a pre-B2 build
            // (whose HAL heads then reach this node by head-AE + record-AE, both
            // leg-carrying) or a hostile party. The variant stays in the enum
            // only because bincode is positional (`types.rs`).
            GossipMessage::HalAdvance { .. } => {
                self.haladvance_dropped = self.haladvance_dropped.saturating_add(1);
                if self.haladvance_dropped.is_power_of_two() {
                    log::warn!(
                        "[B2] HalAdvance received — the E3 arm is retired (HAL re-anchors \
                         flood as StateUpdate with their leg, §9q); dropped, not \
                         forwarded (total dropped: {})",
                        self.haladvance_dropped,
                    );
                }
                GossipAction::Duplicate
            }

            // KI#222 (2026-09-28) — the E1 `BanAlert` receiver is RETIRED.
            //
            // RULE 0 marker — the WRONG reading this arm used to encode: "two
            // ConflictProofs with the same old_state, different new_state /
            // tx_hash and k valid sigs each are a proof of double-spend". They
            // are not. `verify_conflict` checked the sigs over
            // `receipt_sign_payload(wallet_id, consumed_state, tick)`
            // (`crypto.rs`), which binds NEITHER `new_state` NOR `tx_hash`, and
            // Lambda signs it with `tick = 0` on every send
            // (`lambda/src/consensus.rs` "produced_state and txid are both
            // intentionally NOT in the payload"). So the k sigs of ONE genuine
            // registration receipt satisfy BOTH halves of a fabricated pair: any
            // Nabla peer that ever saw W's receipt could permanently ban W (and,
            // via the §10.4 pair-ban, its `client_pk`) mesh-wide, and this arm
            // FORWARDED the forgery. No honest node ever emitted `BanAlert` (its
            // only constructor is in `mod tests`) — a receiver with no sender
            // (RULE 3 shape 3) that kept a weak verifier alive.
            //
            // The correct reading: a ban needs a SELF-PROVING fork — a
            // `ForkClaim` of two wallet-signed, k-witnessed legs from one parent
            // (`docs/AXIOM_DESIGN_ForkSettlement.md` Part A, `ForkLeg` standard;
            // `ban::verify_fork_claim`). See `docs/AXIOM_REPORT_KnownIssues.md`
            // KI#222. (This comment used to name the E2 `SeqForkBan` detection
            // too — retired 2026-09-30, §9o [R56], KI#235.)
            //
            // So this arm VERIFIES NOTHING, BANS NOTHING and does NOT forward. It
            // counts (`ki222_banalert_dropped`, on /status) and warns at
            // power-of-two counts so a flood cannot spam the log. The variant
            // itself stays in the enum as a TOMBSTONE only because bincode is
            // positional (see `types.rs`).
            GossipMessage::BanAlert { .. } => {
                self.ki222_banalert_dropped = self.ki222_banalert_dropped.saturating_add(1);
                if self.ki222_banalert_dropped.is_power_of_two() {
                    log::warn!(
                        "[KI#222] BanAlert received — receiver retired (forgeable proof, \
                         no honest emitter); dropped (total dropped: {})",
                        self.ki222_banalert_dropped,
                    );
                }
                GossipAction::Duplicate
            }

            // Fork Settlement §9o [R56] (W2, 2026-09-30) — `SeqForkBan` is a
            // TOMBSTONE, like `BanAlert`. Its only emitter was check-3 in
            // `apply_state_update` (same seq ∧ `old_state == previous_states[W]`),
            // RETIRED as a ban source: `previous_states[W]` is the head this
            // node's last put overwrote, a VIEW, not evidence, and it banned
            // honest wallets after a same-seq jump or a flood reorder (KI#235,
            // `fork_detection_mesh::fork_retire_proof_b_*` / `_b2_*`). Remote
            // adoption had already been removed (KI#46 follow-up, 2026-07-30:
            // its evidence carries no parent binding). Forks are now judged only
            // on self-proving `ForkClaim` evidence (flood / door / AE records +
            // R48 record-AE → `ban::apply_fork_verdict`).
            //
            // So this arm verifies nothing, bans nothing and never forwards. It
            // counts (`seqforkban_dropped`, on /status) and warns at
            // power-of-two counts so a flood cannot spam the log. The variant
            // stays in the enum only because bincode is positional.
            GossipMessage::SeqForkBan { .. } => {
                self.seqforkban_dropped = self.seqforkban_dropped.saturating_add(1);
                if self.seqforkban_dropped.is_power_of_two() {
                    log::warn!(
                        "[R56] SeqForkBan received — check-3 retired as a ban source \
                         (KI#235); dropped, not forwarded (total dropped: {})",
                        self.seqforkban_dropped,
                    );
                }
                GossipAction::Duplicate
            }

            GossipMessage::TickHash { .. } => {
                // Phase 1: just forward. Partition detection is Phase 4.
                GossipAction::Forward(msg.clone())
            }

            GossipMessage::GroupUpdate {
                wallet_id,
                new_state,
                tx_hash,
                members,
                tick,
            } => self.apply_group_update(smt, bans, wallet_id, new_state, tx_hash, members, tick, msg),

            GossipMessage::ApprovedTick { .. } => {
                // Phase 4: forward approved ticks via gossip as redundant path.
                // Orphaned TARDIS nodes can see ticks but cannot produce them.
                GossipAction::Forward(msg.clone())
            }

            GossipMessage::Topology(_) => {
                // Phase 4: topology hints are forwarded; mesh.rs handles processing.
                GossipAction::Forward(msg.clone())
            }

            GossipMessage::NablaIdAnnounce { .. } => {
                // Forward NablaIdAnnounce for duplicate detection during probation.
                // Receiving nodes check their verified_peers for conflicts.
                GossipAction::Forward(msg.clone())
            }

            // ForkSettlement §9r-E4 (owner ruling 2026-10-01; YPX-025 E4/E6
            // RETIRED) — `TaintAlert` is a TOMBSTONE, like `BanAlert`,
            // `SeqForkBan` and `HalAdvance`.
            //
            // RULE 0 §4 marker — the WRONG reading this arm encoded: "a
            // downstream wallet of a forked source is re-derived from this
            // node's `received_from` graph (`propagate_taint`), written
            // `Tainted`, and so blocked at the door (`is_wallet_blocked`) until
            // the quarantine expiry restores it". Its live condition was
            // `source ∈ {Frozen, Banned}`, and `Banned` IS written in production
            // (`ban::apply_fork_verdict`), so ANY party could send
            // `TaintAlert{Q, A}` for a proven forker A and its genuine downstream
            // Q: every node confirmed it from its own graph, refused Q's
            // registrations, and FORWARDED it — with no exit, because the expiry
            // needed a TickHash mismatch first. A free DoS on exactly the wallet
            // §9k ruling 1 says must be ACCEPTED and MARKED.
            //
            // The CORRECT reading: a downstream hold is ATRAXI A5 only — derived
            // per node from its own records (`provenance.rs`), read where it
            // matters (the withheld vouch at `origin_vouch` → `judge_send`, and
            // `RegistrationAck.provenance`); the register is accepted and marked,
            // never refused (ForkSettlement §9k ruling 1, §9r-E4; YPX-025 A5).
            // A view never holds anyone. Proof:
            // `fork_detection_mesh::e4_c_downstream_of_proven_forker_held_by_a5_not_blocked`.
            //
            // So this arm taints nothing, blocks nothing and never forwards. It
            // counts (`taintalert_dropped`, on /status) and warns at power-of-two
            // counts. The variant stays only because bincode is positional.
            GossipMessage::TaintAlert { .. } => {
                self.taintalert_dropped = self.taintalert_dropped.saturating_add(1);
                if self.taintalert_dropped.is_power_of_two() {
                    log::warn!(
                        "[E4] TaintAlert received — §32 taint retired into ATRAXI A5 \
                         (provenance.rs); dropped, not forwarded (total dropped: {})",
                        self.taintalert_dropped,
                    );
                }
                GossipAction::Duplicate
            }

            // ForkSettlement §9r-E4 (D-E4-1) — `MergeResolved` is a TOMBSTONE.
            // Its only emitter was the 75 s §32 quarantine expiry
            // (`check_merge_quarantine`, deleted with the SCAN: after the SCAN
            // and `TaintAlert` retirement nothing wrote the `Tainted` it
            // restored). This arm used to FORWARD an unauthenticated summary;
            // now it counts (`mergeresolved_dropped`) and drops.
            GossipMessage::MergeResolved { .. } => {
                self.mergeresolved_dropped = self.mergeresolved_dropped.saturating_add(1);
                if self.mergeresolved_dropped.is_power_of_two() {
                    log::warn!(
                        "[E4] MergeResolved received — §32 quarantine expiry retired; \
                         dropped, not forwarded (total dropped: {})",
                        self.mergeresolved_dropped,
                    );
                }
                GossipAction::Duplicate
            }

            // ── H3 data availability: UNBUILT (ghost audit G15) ─────────────
            //
            // `types.rs` documents this as enforcement: "If the challenged
            // validator doesn't respond with the withheld data within
            // CHALLENGE_WINDOW_TICKS, they receive a SCAR (same enforcement as
            // JFP)." Verified 2026-08-07, none of that exists:
            //
            //   * `CHALLENGE_WINDOW_TICKS` is not a constant anywhere in the
            //     tree — it appears ONLY inside the two doc comments citing it;
            //   * neither `DataWithholdChallenge` nor `DataWithholdResponse` is
            //     ever constructed — no production emitter, not even a test;
            //   * there is no SCAR path: nothing links a withhold to a scar;
            //   * no timer exists to expire a challenge.
            //
            // So the protocol is a receiver with no sender, a deadline with no
            // clock, and a penalty with no code. It is left INERT rather than
            // deleted because bincode encodes variants positionally — removing
            // these two would shift every later discriminant and break the wire
            // for all ten nodes (see the `HalAdvance` note in `types.rs`).
            //
            // What IS fixed: these arms used to FORWARD. A protocol with no
            // emitter that still fans messages out mesh-wide is pure
            // amplification surface — the response arm's only gate was
            // `sig.len() == 64`, so anyone could flood it. Now dropped and
            // counted, so if anything ever sends one we find out instead of
            // relaying it.
            GossipMessage::DataWithholdChallenge { .. }
            | GossipMessage::DataWithholdResponse { .. } => {
                self.h3_unbuilt_dropped = self.h3_unbuilt_dropped.saturating_add(1);
                log::warn!(
                    "[H3-UNBUILT] data-availability message received, but H3 has no \
                     emitter, no CHALLENGE_WINDOW_TICKS, and no SCAR path — dropped, \
                     NOT forwarded (ghost audit G15)"
                );
                GossipAction::Duplicate
            }

            GossipMessage::PulseProof {
                validator_pk,
                epoch,
                full_accumulator,
                entry_count,
                sample_size: _,
                audit_hash,
                argon2id_per_sec,
                signature,
                tick: _,
            } => {
                // YPX-009 §5.3: Verify Ed25519 signature over pulse proof payload.
                // Nabla only checks the signature (proves this validator produced the proof).
                // The audit_hash validity was verified by AVM — Nabla trusts the signature.
                if *entry_count == 0 {
                    return GossipAction::Duplicate; // empty audit = no work
                }
                // YPX-009 §8.5: Sanity check — reported throughput must be plausible.
                // Zero throughput means benchmark never ran (protocol violation).
                if *argon2id_per_sec == 0 {
                    log::warn!("PulseProof: zero argon2id_per_sec from {:02x}{:02x}...",
                        validator_pk[0], validator_pk[1]);
                    return GossipAction::Duplicate;
                }
                let payload = pulse_proof_sign_payload(validator_pk, *epoch, full_accumulator, audit_hash, None);
                if !verify_pulse_proof_sig(validator_pk, signature, &payload) {
                    log::warn!("PulseProof: invalid signature from {:02x}{:02x}...", validator_pk[0], validator_pk[1]);
                    return GossipAction::Duplicate; // drop invalid
                }
                // Valid pulse — forward to mesh peers for scoring + propagation.
                // Mesh scoring update happens in nabla_node.rs after gossip processing.
                GossipAction::Forward(msg.clone())
            }

            GossipMessage::PoolSync {
                pool,
                balance,
                total_claims,
                paid_out,
                topped_up: _,
                tick,
                sender_node_id,
                sender_sig: _,
            } => {
                // §17.11 + FACT class isolation §6: monotonic-decrease gate,
                // smallest balance wins. Phase B promoted reconcile's
                // return to ReconcileOutcome so the caller can dispatch
                // on InvariantViolation / MagnitudeViolation and emit
                // Layer 4 Alerts (PoolCaps design §5.6.4). SEC-03: a sender
                // whose NBC pk resolves is signature-verified at the binary
                // layer before this function; one whose pk does NOT resolve
                // takes the soft path (processed for convergence, NOT
                // attributable). So `accused` is only safe to act on for an
                // authenticated sender — the soft-path caller suppresses the
                // Alert (no K-of-N) so a spoofed sender_node_id cannot produce
                // a false accusation. The damage an unauthenticated sender can
                // do is bounded at the reconcile layer (total_claims skew bound
                // + structural conservation), so processing it is safe even
                // when it is not attributable.
                let outcome = match pool {
                    PoolKind::Airdrop => airdrop_pool.reconcile(*balance, *total_claims, *paid_out),
                    // Validator-join subsidy pools: drain-only, identical
                    // min-wins convergence to the airdrop pool.
                    PoolKind::Bootstrap => bootstrap_pool.reconcile(*balance, *total_claims, *paid_out),
                    PoolKind::FoundationBootstrap =>
                        foundation_bootstrap_pool.reconcile(*balance, *total_claims, *paid_out),
                    // ── RULE 0 §4 marker (KI#191 residual, RULED 2026-09-25) ──
                    // WRONG READING (this arm until 2026-09-25): "the emission
                    // pools are reconciled by the node BEFORE this call, so this
                    // arm is `NoOp`; the Layer-1 identity false-positives on
                    // them by construction". That described the PRE-09-16
                    // identity (`initial_atoms` = current balance). The arm
                    // hard-coded `NoOp`, so an emission `StructuralViolation`
                    // never became `GossipAction::PoolStructuralViolation` —
                    // 5,166 `[JUDOON/POOL-STRUCTURAL]` warnings in soak_r22
                    // produced zero probations.
                    // RIGHT READING: `EmissionPools::reconcile` delegates to the
                    // same corrected `AirdropPool::reconcile` (genesis opening,
                    // `paid_out`/`topped_up`) as every drain pool, and the live
                    // fleet logged zero emission structural warnings after the
                    // fix. ONE RULE FOR EVERY POOL: the outcome flows through
                    // the single dispatch below like any other pool.
                    // AUTHORITY: AXIOM_DESIGN_NablaJudoon.md §2.5 ruling block;
                    // KI#191 in AXIOM_REPORT_KnownIssues.md.
                    PoolKind::EmissionValidators | PoolKind::EmissionNabla => {
                        let kind = if matches!(pool, PoolKind::EmissionValidators) {
                            axiom_core_logic::types::FOB_CLAIM_POOL_EMISSION
                        } else {
                            axiom_core_logic::types::FOB_CLAIM_POOL_EMISSION_NABLA
                        };
                        emission.reconcile(kind, *balance, *total_claims, *paid_out, *tick, deed_pool)
                    }
                    PoolKind::DevTreasury => {
                        dev_treasury_pool.reconcile(*balance, *total_claims)
                    }
                    PoolKind::Deed => deed_pool.reconcile(*balance, *total_claims),
                    PoolKind::DevDeed => dev_deed_pool.reconcile(*balance, *total_claims),
                    // ── §7 the ONE new arm: Bounded-Fee reconcile ──
                    // Monotone two-state, with the increase gated on a verified
                    // current-epoch TrancheStatement (the credit this node
                    // derived when it judged the statement). §4.1: an increase
                    // whose authorising statement we have NOT yet judged is HELD
                    // (NoOp), never accused — only a disprovable increase (epoch
                    // judged, credit absent/mismatched) is a StructuralViolation.
                    PoolKind::BoundedFee(vid, is_dev) => {
                        // ONE codepath; the class is a data bit in the key, and it
                        // only selects the epoch cadence + which pool entry.
                        let key = (*vid, *is_dev);
                        let epoch =
                            *tick / crate::constants::fob_epoch_span_secs(*is_dev).max(1); // KI#165: VALUE ÷ VALUE-span
                        let local = fob_pools.get(&key).map(|p| p.balance()).unwrap_or(0);
                        let judged = fob_credits.get(&epoch);
                        if *balance > local && judged.is_none() {
                            // authorising statement not seen yet — hold + wait
                            // for it / the next re-advertisement (§4.1, §8.1).
                            crate::node::ReconcileOutcome::NoOp
                        } else {
                            let verified = judged.and_then(|m| m.get(&key)).copied();
                            match crate::fob::fob_reconcile(local, *balance, verified) {
                                crate::fob::FobReconcile::NoOp => {
                                    crate::node::ReconcileOutcome::NoOp
                                }
                                crate::fob::FobReconcile::AdoptTranche(amt) => {
                                    // RESYNC-adopt: sweeps a stale full balance
                                    // (missed-withdrawal, §7 convergence) so a
                                    // withdrawal can never strand this pool.
                                    let _ = fob_pools
                                        .entry(key)
                                        .or_default()
                                        .adopt_tranche_resync(amt);
                                    crate::node::ReconcileOutcome::Updated
                                }
                                crate::fob::FobReconcile::AdoptWithdrawal => {
                                    if let Some(p) = fob_pools.get_mut(&key) {
                                        p.withdraw_full();
                                    }
                                    crate::node::ReconcileOutcome::Updated
                                }
                                crate::fob::FobReconcile::StructuralViolation(_fv) => {
                                    crate::node::ReconcileOutcome::StructuralViolation {
                                        proof: crate::judoon::ProofKind::BoundedFeeConservation,
                                        peer_balance: *balance,
                                        peer_claims: *total_claims,
                                    }
                                }
                            }
                        }
                    }
                };
                // KI#28 — increase pools (Deed, DevDeed) are monotonic-
                // INCREASE, so the drain-pool exact-equality detector above
                // false-positives on gossip lag. Instead of the old blanket
                // downgrade-to-NoOp workaround (fd1bcad6), consult the
                // rate-based detector: in-range (or sample-starved) → NoOp
                // (honest gossip lag); out-of-range → KEEP the violation so
                // it flows to the SAME PoolViolationDetected Alert the drain
                // pools use. By the book — same K-of-N pipeline. See
                // AXIOM_DESIGN_NablaJudoon.md §10.
                let outcome = if matches!(pool, PoolKind::Deed | PoolKind::DevDeed)
                    && matches!(
                        outcome,
                        crate::node::ReconcileOutcome::StructuralViolation { .. }
                            | crate::node::ReconcileOutcome::InvariantViolation { .. }
                            | crate::node::ReconcileOutcome::MagnitudeViolation { .. }
                    )
                {
                    let (window_sum, n_samples, local_total) = match pool {
                        PoolKind::Deed => (
                            deed_pool.rate_window_sum(),
                            deed_pool.rate_window_samples(),
                            deed_pool.total_credited(),
                        ),
                        _ => (
                            dev_deed_pool.rate_window_sum(),
                            dev_deed_pool.rate_window_samples(),
                            dev_deed_pool.total_credited(),
                        ),
                    };
                    if crate::judoon::increase_pool_should_alert(
                        window_sum, n_samples, n_validators, local_total, *total_claims,
                    ) {
                        outcome // out-of-range → emit Alert via existing path
                    } else {
                        crate::node::ReconcileOutcome::NoOp // gossip lag / sample-starved
                    }
                } else {
                    outcome
                };
                let accused = *sender_node_id;
                match outcome {
                    crate::node::ReconcileOutcome::Updated => GossipAction::Forward(msg.clone()),
                    crate::node::ReconcileOutcome::NoOp => GossipAction::Duplicate,
                    crate::node::ReconcileOutcome::StructuralViolation { proof, peer_balance, peer_claims } => {
                        // Layer 1 — single-observer probation route, NOT Alert.
                        // The binary picks up `PoolStructuralViolation`,
                        // enters the offender into probation, and drops
                        // the message from relay. No mesh-wide consensus
                        // wait; the proof is self-evident from the
                        // peer's signed PoolSync. See §2.5 +
                        // AXIOM_DESIGN_NablaJudoon.md.
                        log::warn!(
                            "[JUDOON/STRUCTURAL] {:?}: {:?} peer_balance={} peer_claims={} accused={}",
                            pool, proof, peer_balance, peer_claims, hex::encode(&accused[..8]),
                        );
                        let mut evidence = Vec::new();
                        match ciborium::into_writer(msg, &mut evidence) {
                            Ok(_) => GossipAction::PoolStructuralViolation { evidence, accused, proof },
                            Err(e) => {
                                log::error!("[POOL-RECONCILE] structural evidence serialize failed: {e}; dropping");
                                GossipAction::Duplicate
                            }
                        }
                    }
                    crate::node::ReconcileOutcome::InvariantViolation { peer_balance, local_balance } => {
                        // Now only reachable from the unreachable belt-
                        // and-suspenders branch in `set_balance`
                        // (peer_balance < self.balance somehow not
                        // strict-decrease), or DEED's beyond-tolerance draw.
                        // The higher-balance direction returns `NoOp` in
                        // AirdropPool AND (since 2026-09-26) DevTreasuryPool,
                        // per Mac's review §2.6 — before that DevTreasury fired
                        // this line on every claim burst, accusing lagging peers.
                        log::warn!(
                            "[POOL-RECONCILE-INVARIANT] {:?}: unreachable set_balance failure peer_balance={} local={} accused={}",
                            pool, peer_balance, local_balance, hex::encode(&accused[..8]),
                        );
                        let mut evidence = Vec::new();
                        match ciborium::into_writer(msg, &mut evidence) {
                            Ok(_) => GossipAction::PoolViolationDetected { evidence, accused },
                            Err(e) => {
                                log::error!("[POOL-RECONCILE] evidence serialize failed: {e}; dropping alert");
                                GossipAction::Duplicate
                            }
                        }
                    }
                    crate::node::ReconcileOutcome::MagnitudeViolation { peer_balance, peer_claims, local_balance, local_claims } => {
                        log::warn!(
                            "[POOL-RECONCILE-MAGNITUDE] {:?}: peer balance={} claims={} but our local balance={} claims={} (drop > claim delta × claim_amount) accused={}",
                            pool, peer_balance, peer_claims, local_balance, local_claims, hex::encode(&accused[..8]),
                        );
                        let mut evidence = Vec::new();
                        match ciborium::into_writer(msg, &mut evidence) {
                            Ok(_) => GossipAction::PoolViolationDetected { evidence, accused },
                            Err(e) => {
                                log::error!("[POOL-RECONCILE] evidence serialize failed: {e}; dropping alert");
                                GossipAction::Duplicate
                            }
                        }
                    }
                }
            }

            GossipMessage::Alert { .. } => {
                // Layer 4 alerts are handled at the binary level
                // (NablaNode::handle_alert), where the TCP source is
                // known and can be verified against intermediate_emitter.
                // The gossip engine itself is a pass-through here — the
                // binary intercepts Alert messages before calling
                // engine.process. If we get here, it's an unexpected
                // path; return Duplicate to silently drop.
                log::warn!("[ALERT-IN-GOSSIP-ENGINE] Alert reached engine.process; \
                    expected to be intercepted at binary level. Dropping.");
                GossipAction::Duplicate
            }

            GossipMessage::OraclePoolSync {
                date,
                pools,
                reserve_left,
                claims_today,
                tick,
            } => {
                // Phase 8: reconcile oracle pool state (conservative merge).
                // §11.7: lowest pool balance wins, highest claims_today wins.
                let changed = reconcile_pool(
                    pool,
                    date,
                    pools,
                    *reserve_left,
                    *claims_today,
                    *tick,
                );
                if changed {
                    GossipAction::Forward(msg.clone())
                } else {
                    GossipAction::Duplicate
                }
            }

            // KI#156 (deleted 2026-09-21): the ChequeClaim gossip consumer is gone
            // with its variant — a dead pre-redeem claim-race hint (see types.rs).

            GossipMessage::Recall {
                txid, sender_pk, recall_tick, committed, attestation,
            } => {
                // YPX-025 A2 / KI#205 residual 1 — a recall marker is applied from
                // gossip ONLY on VERIFIED evidence, never a peer's bare word (which
                // was the mesh-wide griefing hole: a forged Recall made query-txid
                // serve REDEEMED / blocked a legit redeem). Two-phase, single-node
                // (blessed-reserver residual, ruled 2026-09-19):
                //   RESERVATION (committed=false): require the reserver's
                //     RecallAttestation, binding THIS txid, verified against its NBC
                //     key (validation::verify_recall_attestation — the ONE Core-owned
                //     verify, reused; RULE 1). Forged/absent → drop, don't apply.
                //   COMMIT (committed=true): carries no attestation; apply ONLY where
                //     a verified reservation marker already exists for this txid (the
                //     reservation was verified above). A forged commit with no prior
                //     reservation → drop. WAL replay bypasses this engine and restores
                //     terminals directly, so it is unaffected.
                let evidence_ok = if *committed {
                    smt.is_txid_recall_pending(txid) || smt.is_txid_recalled(txid)
                } else {
                    matches!(attestation, Some(att)
                        if att.txid == *txid
                        && axiom_core_logic::validation::verify_recall_attestation(att).is_ok())
                };
                if !evidence_ok {
                    return GossipAction::Duplicate; // unverifiable → drop, never apply/forward
                }
                let updated = smt.apply_remote_recall(txid, sender_pk, *recall_tick, *committed);
                if updated {
                    GossipAction::Forward(msg.clone())
                } else {
                    GossipAction::Duplicate
                }
            }

            GossipMessage::Hibernation { client_pk, until } => {
                let updated = smt.apply_remote_hibernation(client_pk, *until, current_tick);
                if updated {
                    GossipAction::Forward(msg.clone())
                } else {
                    GossipAction::Duplicate
                }
            }

            GossipMessage::JfpSecret { .. } => {
                // YP §8.4.3 — vote-secret propagation. The secret store lives
                // in the binary's node state (not the SMT), so application
                // happens in the binary's Forward arm; the engine only dedups
                // (the two-generation `seen` set above) and keeps it flooding.
                // Nothing here touches the SMT — that was the whole point of
                // retiring the synthetic StateUpdate carrier (KI#46).
                GossipAction::Forward(msg.clone())
            }
            GossipMessage::FobTranche { .. } => {
                // FOB epoch tranche (AXIOM_DESIGN_BoundedPools.md §4). Same
                // shape as JfpSecret: the per-validator FOB registry + the
                // `verified_nbcs`/OODS materials the §5 committee verify needs
                // live in the BINARY's node state, not the SMT or this engine.
                // So the engine only dedups (the `seen` set above) and keeps it
                // flooding; the binary's dispatch layer verifies the movers,
                // audits each entry (`fob::audit_tranche_entry`), and
                // reconciles (`fob::fob_reconcile`) — or JUDOON-quarantines.
                // Nothing here touches the SMT.
                GossipAction::Forward(msg.clone())
            }

            GossipMessage::ChequeClaimAnnounce {
                cheque_id, client_pk, k_tier, wallet_address, claim_sig, claim_tick,
            } => {
                // YPX-022 §2.1.2a item 3 (KI#205) — a flooded claim is applied
                // ONLY after THIS node re-runs the same authentication the
                // originating node ran (`verify_cheque_claim`: claimant sig over
                // Core's one builder, address↔key binding, and equality with the
                // head THIS node holds for the claimant's bucket). A peer's bare
                // word never writes the delivery terminal (RULE 3 shape 5) —
                // otherwise any node could block every recall on the mesh with
                // forged claims. Forged → drop (not forwarded), counted on
                // /status `claims_unauthenticated`.
                let req = axiom_core_logic::wire_client::RegisterChequeClaimRequest {
                    cheque_id: *cheque_id,
                    client_pk: client_pk.clone(),
                    k_tier: *k_tier,
                    wallet_address: wallet_address.clone(),
                    claim_sig: claim_sig.clone(),
                };
                let head_pk = smt.head_client_pk_for_claimant(client_pk, *k_tier);
                if let Err(reason) = crate::registration::verify_cheque_claim(&req, head_pk.as_ref()) {
                    crate::registration::note_claim_unauthenticated(reason, cheque_id, "gossip");
                    return GossipAction::Duplicate; // unverifiable → drop, never apply/forward
                }
                // Store under the ORIGINATING node's claim tick so the mesh
                // converges on one value (like `Hibernation`); first-wins on a
                // conflicting key, as on the local path.
                let claim = crate::smt::ChequeClaim::from_request(&req, *claim_tick);
                match smt.register_cheque_claim(*cheque_id, claim, current_tick) {
                    Ok(true) => GossipAction::Forward(msg.clone()),
                    // Already held (idempotent) or a different key claimed first
                    // (CONFLICT — first-wins, the earlier claim stands).
                    Ok(false) | Err(_) => GossipAction::Duplicate,
                }
            }

            GossipMessage::ForkBan { claim } => {
                // ForkSettlement §2.3 [R25] — ATRAXI A1 adoption. The claim
                // passes the ONE chokepoint (`verify_fork_claim`, inside
                // `adopt_fork_claim` → `apply_fork_verdict`) BEFORE anything is
                // banned or recorded. Unverifiable → nothing banned, nothing
                // recorded, `atraxi_evidence_refused` counted, NOT forwarded
                // (a packaged forgery gets no amplification from this node).
                // Verified and ≥1 key newly banned → forward (every hop
                // re-verifies). Verified but every key already banned → the
                // verdict already left this node once; stop here.
                //
                // Unlike `SeqForkBan` (a tombstone since §9o [R56]; before that
                // drop-only, KI#46 follow-up: its evidence carries no parent
                // binding), a `ForkClaim`'s legs carry the
                // k-signed preimage, so "same parent" is PROVEN, not inferred.
                //
                // The verdict also queues the claim on the drain (WAL `Ban` +
                // the binary's fan-out); peers dedup that byte-identical second
                // copy by message hash.
                match crate::ban::adopt_fork_claim(smt, bans, claim, now_secs) {
                    Ok(newly) if !newly.is_empty() => GossipAction::Forward(msg.clone()),
                    Ok(_) => GossipAction::Duplicate,
                    Err(_) => GossipAction::Duplicate,
                }
            }
        }
    }

    /// Apply a state update from gossip.
    /// Detects conflicts (potential double-spend via gossip).
    /// YPX-009: Verifies client signature before accepting state mutation.
    ///
    /// DESIGN: perfect Nabla sync is NOT required and MUST NOT be added here —
    /// safety lives in the replicated majority, not any one node's freshness.
    /// Full rationale + reviewer rule: `node.rs::apply_remote_entry` doc comment
    /// and YPX-020 §3 ("Why absolute Nabla sync is NOT required"). Do not add
    /// mesh-wide head queries / convergence proofs to chase stale individuals.
    #[allow(clippy::too_many_arguments)]
    fn apply_state_update(
        &self,
        smt: &mut SparseMerkleTree,
        bans: &mut BanTable,
        wallet_id: &WalletId,
        new_state: &StateId,
        // The parent this advance consumed (the register's old_state) —
        // UNSIGNED; `verify_seq_proof_leg` checks it against the k-signed
        // preimage. All-zero = unknown (replay reconstruction). (It also fed
        // check-3's `previous_states` comparison until W2, §9o [R56].)
        old_state: &StateId,
        tx_hash: &TxHash,
        tick: &u64,
        is_genesis_claim: bool,
        wallet_seq: &u64,
        client_pk: &[u8; 32],
        client_sig: &[u8],
        amount: &u64,
        fee_breakdown: &[axiom_core_logic::types::FeeShare],
        seq_proof: &Option<SeqProof>,
        original_msg: &GossipMessage,
        now_secs: u64,
        is_witness: &dyn Fn(&[u8; 32]) -> bool,
    ) -> GossipAction {
        if bans.is_banned(wallet_id) {
            // Already banned — ignore updates for this wallet
            return GossipAction::Duplicate;
        }

        // YPX-009 ENFORCED (KI#46 zero-pk flip, 2026-07-30): every StateUpdate
        // must carry wallet authorship — zero pk is REJECTED, not exempted.
        // The exemption was the machine-path's ride (closed when the machine
        // builder gained signing) and the cover for three node-internal
        // producers, all retired: the JFP-secret synthetic carrier (now the
        // dedicated `GossipMessage::JfpSecret` variant), the fact-confirm
        // re-advertisement (now carries the stored entry's sig), and the
        // CLARA roll-forward flood (deleted — the wallet's own signed
        // register follows in the same heal call). Legacy zero-pk entries
        // re-offered by AE were already wedged (their heads could never
        // verify); this makes the drop uniform and loud.
        if *client_pk == [0u8; 32] {
            log::warn!(
                "[FLOOD-REJECT] zero-pk wallet={:02x}{:02x}.. tx_hash={:02x}{:02x}.. — \
                 unauthored StateUpdate dropped (YPX-009 enforced)",
                wallet_id[0], wallet_id[1], tx_hash[0], tx_hash[1],
            );
            return GossipAction::Duplicate;
        }
        // KI#226 — the row must be the SIGNING KEY's own: `wallet_id` is a
        // bucket derived from `client_pk` (either state class), never a free
        // name. Before this, A's leg re-signed by A over W's id replaced W's
        // head on every node through one injected flood (S8b). Counted,
        // dropped, never forwarded.
        if !crate::registration::bucket_derives_from_key(wallet_id, client_pk) {
            crate::registration::note_wallet_id_key_mismatch(wallet_id, client_pk, tx_hash, "flood");
            return GossipAction::Duplicate;
        }
        if !verify_client_state_sig(client_pk, client_sig, wallet_id, new_state, tx_hash) {
            log::warn!(
                "Gossip: invalid client sig for wallet {:02x}{:02x}... — dropping",
                wallet_id[0], wallet_id[1]
            );
            return GossipAction::Duplicate;
        }

        // Build the candidate entry from the StateUpdate. `status` and
        // `group_members` are NOT carried by StateUpdate gossip — inherit
        // them from the local entry so a flood update can never demote a
        // §32 freeze or drop group allocations. The §5.2 merge rule
        // (`NablaEntry::superseded_by`) then decides adoption; routing the
        // flood path and anti-entropy through one total order makes the
        // merge a convergent semilattice join.
        // WI3 hole-1 (KI#34 §5.4): is `wallet_seq` k-attested for THIS txid?
        // A bare seq is forgeable, and `wallet_seq` is the PRIMARY merge key
        // (`superseded_by` rule 2), so a seq-ADVANCE may win the merge only if
        // a carried k=3 proof verifies. Equal/lower seq doesn't need a proof —
        // it can't win on seq, only via the tick tiebreaker at equal seq.
        //
        // KI#224 (owner ruling 2026-10-02, "gate ALL paths") — valid sigs from
        // carried keys are not a witness round: the proof attests only if EVERY
        // key is in THIS node's R42 directory (`ban::
        // seq_proof_is_directory_witnessed`, the door's 5b⁗ predicate). A
        // non-directory proof is treated exactly as CARRIED-BUT-FAILED: no
        // seq-advance, no first-sight above seq 0, no txid-completed mark.
        // Nothing is remembered as refused — once the key is admitted, the
        // next head-AE round re-offers the head and it is adopted. The leg is
        // still recorded below (detect-only; `verify_fork_leg` stays ungated,
        // R58).
        let seq_verified = seq_proof
            .as_ref()
            .is_some_and(|p| crate::registration::verify_seq_proof(p, tx_hash, *wallet_seq));
        let seq_attested = seq_verified && match seq_proof.as_ref() {
            Some(p) if crate::ban::seq_proof_is_directory_witnessed(p, is_witness) => true,
            Some(p) => {
                let unknown = crate::ban::first_non_directory_witness(p, is_witness).unwrap_or_default();
                crate::registration::note_witness_not_in_directory(&unknown, wallet_id, tx_hash, "flood");
                false
            }
            None => false,
        };

        // ForkSettlement wave 2a (§2.2 carrier, [R‑MEDIUM-3]) — a carried
        // SeqProof's leg must reproduce its OWN k-signed `commitment_hash` and
        // this update's `tx_hash`, name this update's `client_pk` + seq, and —
        // when the message states a parent — consume exactly that parent (the
        // message's `old_state` is unsigned; the preimage is). A proof that
        // fails is a forged or corrupted leg: the WHOLE update is dropped
        // (counted, `leg_preimage_refused`), never adopted proofless, so a
        // node never stores or re-floods a leg it could not prove. Same ONE
        // verifier as the register door and the AE path (RULE 1). All-zero
        // `old_state` = "parent unknown" (replay/bootstrap reconstruction).
        if let Some(p) = seq_proof.as_ref() {
            let parent = (*old_state != [0u8; 32]).then_some(old_state);
            if let Err(reason) = crate::registration::verify_seq_proof_leg(
                p, tx_hash, client_pk, parent, Some(new_state), *wallet_seq,
            ) {
                crate::registration::note_leg_refused(reason, wallet_id, tx_hash, "flood");
                return GossipAction::Duplicate;
            }
        }
        // ForkSettlement §2.3 [R10] — the record-keyed fork detector on the
        // FLOOD path. Every carried SEND leg is recorded HERE, ABOVE every drop
        // below — the consumed-state drop, the byte-identical drop, the
        // unattested-advance reject, the `superseded_by` loser and the
        // first-sight reject — so a lower-seq loser or a leg whose parent this
        // node already saw consumed is still evidence, and BEFORE any
        // `put_with_proof` here [R24]. Detection is keyed on the RECORDS
        // (`(pk, consumed)` → txids), never on the head / `previous_state`:
        // the proofless ping-pong head swap and the late leg after an advance
        // both meet the held record. On a verified fork the candidate is
        // neither adopted nor forwarded — the claim floods instead (`ForkBan`,
        // via the node's drain). Since W7b a Redeem leg is recorded too — in
        // the separate redeem ledger, on the shared fork index (spec R52c).
        // (check-3, the `previous_states` seq-fork ban that sat below, was
        // retired 2026-09-30 — §9o [R56], W2.)
        if let Some(p) = seq_proof.as_ref() {
            let leg = crate::types::ForkLeg {
                new_state: *new_state,
                tx_hash: *tx_hash,
                client_sig: client_sig.to_vec(),
                seq_proof: p.clone(),
            };
            let key = leg.key();
            if let crate::ban::LegRecordOutcome::ForkBanned { .. } =
                crate::ban::record_leg_and_detect(smt, bans, leg, now_secs, "flood")
            {
                return GossipAction::Duplicate;
            }
            // Fork Settlement W7c prerequisite (plan §7, §9k) — the HELD-HEAD
            // LEG MAPPING (kept by §9o [R56] when check-3's ban was retired).
            // If the HELD head's leg is not in this node's records (a head
            // installed without the hook), the candidate alone sits under its
            // key and the record detector cannot see the pair. Record the held
            // head's leg through the ONE hook when it names the SAME
            // `(pk, consumed)` key with a different txid: a self-proving pair
            // is then an A1 `Fork` verdict under that key (WAL'd, flooded as
            // `ForkBan`), and the key holds both legs — which is what
            // `origin_vouch` reads now that clause 4 (ban table) is removed
            // (ruling 3). A pair the leg verifier does not accept as one parent
            // is not a fork in the records and bans nobody (until W2 it fell
            // through to check-3's legacy `SeqFork` ban).
            let held_leg = smt.get(wallet_id).zip(smt.seq_proof(wallet_id)).and_then(|(h, p)| {
                let l = crate::types::ForkLeg {
                    new_state: h.current_state,
                    tx_hash: h.tx_hash,
                    client_sig: h.client_sig.clone(),
                    seq_proof: p.clone(),
                };
                (l.key() == key && l.tx_hash != *tx_hash).then_some(l)
            });
            if let Some(l) = held_leg {
                if let crate::ban::LegRecordOutcome::ForkBanned { .. } =
                    crate::ban::record_leg_and_detect(smt, bans, l, now_secs, "flood-check3")
                {
                    return GossipAction::Duplicate;
                }
            }
        }

        // THREAT §5.4 consume-once on the FLOOD path (mirror of the AE-path gate
        // at node.rs `apply_remote_entry`). The seq gate above only blocks a
        // seq-ADVANCE; an EQUAL-seq candidate falls through to the `superseded_by`
        // tick tiebreaker (rule 3), so a forged higher-tick re-advertisement of a
        // CONSUMED state — seq stamped equal to the current head, no proof needed —
        // would otherwise win the merge and roll the head back to the spent state
        // (the KI#34 revival, reproduced live by `examples/ki34_wi1_recover`).
        // Check against THIS node's own monotonic consumed-set (a remote peer can't
        // forge it away; it's re-armed on a wiped node via the WI1 StatePull
        // bootstrap merge). An honest head is never consumed, so honest traffic is
        // never false-rejected; only a revival of a spent state is dropped.
        // Deterministic from (new_state, consumed-set) → every node decides
        // identically, mesh stays convergent.
        if smt.is_state_consumed(new_state) {
            return GossipAction::Duplicate;
        }

        match smt.get(wallet_id) {
            Some(existing) => {
                let candidate = NablaEntry {
                    wallet_id: *wallet_id,
                    current_state: *new_state,
                    tx_hash: *tx_hash,
                    tick: *tick,
                    wallet_seq: *wallet_seq, // WI3: k-attested gossip seq
                    group_members: existing.group_members.clone(),
                    status: existing.status,
                    client_pk: *client_pk,
                    client_sig: client_sig.to_vec(),
                    // §32.3 — the sender lineage is authenticated ONLY via the
                    // k-attested SeqProof (verify_seq_proof folds sender_state
                    // into the recomputed commitment). When attested, adopt the
                    // carried lineage; otherwise inherit the local entry's (an
                    // unattested candidate can only win via the equal-seq tick
                    // tiebreaker, where the lineage should already match) — a
                    // forged flood cannot strip taint by omitting it.
                    received_from: if seq_attested {
                        seq_proof.as_ref().and_then(|p| p.sender_state)
                    } else {
                        existing.received_from
                    },
                };
                if existing == &candidate {
                    // Byte-identical — already applied via another path.
                    return GossipAction::Duplicate;
                }
                // ── check-3 (KI#46 same-seq fork BAN) — RETIRED 2026-09-30, W2 ──
                // HISTORY (RULE 0 §4; Fork Settlement §9o [R56], KI#235). A branch
                // here banned W (`bans.ban_seq_fork`), flipped the held head to
                // `Banned` and flooded `SeqForkBan` when the candidate had the
                // SAME `wallet_seq`, a different `current_state`, both sides
                // attested + authored, and the carried `old_state` equal to
                // `previous_states[W]`. WRONG READING it rested on: that
                // `previous_states[W]` is "this node's AUTHORITATIVE parent of the
                // held head (exact)". RIGHT READING: it is the head this node's
                // last put OVERWROTE (`smt.rs` `put_inner`, every head change,
                // same-seq included); after a same-seq jump P→H (an honest redeem
                // chain P→X→H learned by AE, or ρ2's flood beating ρ1's) it is P,
                // not H's leg parent X, so the honest late ρ1 flood (P→X)
                // satisfied it and the wallet was BANNED mesh-wide
                // (`fork_detection_mesh::fork_retire_proof_b_*` / `_b2_*`). The
                // leg parent is the k-signed preimage's `consumed_state_id`
                // (`ForkLeg::consumed`), which the record detector above keys on.
                // The one shape only check-3 caught — a genuine redeem fork whose
                // sibling legs never meet at one node — is now carried by R48
                // record-AE (W1) to every node, where the ONE verdict path bans on
                // `Fork` evidence (`fork_retire_proof_c_*`). No new way to be
                // banned exists; a PROVEN self-fork keeps the permanent ban
                // (YPX-025 rule 4). Persisted `SeqFork` bans still load locally
                // (`BanTable::ban_seq_fork`, replay only) and never propagate.
                // Reject an unproven seq-ADVANCE before it can win the merge: a
                // forged high seq with no valid k=3 proof must not roll the head
                // forward. The decision is deterministic from (candidate, proof)
                // — every node that received this message rejects/adopts
                // identically, so the mesh stays convergent.
                if candidate.wallet_seq > existing.wallet_seq && !seq_attested {
                    // KI#38 diagnosis: same gate as the AE path — name why the
                    // flood couldn't advance this head (proof absent vs failed).
                    log::info!(
                        "[FLOOD-REJECT] seq-unattested wallet={:02x}{:02x} held_seq={} incoming_seq={} proof={} tx_hash={:02x}{:02x}..",
                        wallet_id[0], wallet_id[1],
                        existing.wallet_seq, candidate.wallet_seq,
                        if seq_proof.is_some() { "CARRIED-BUT-FAILED" } else { "ABSENT" },
                        tx_hash[0], tx_hash[1],
                    );
                    return GossipAction::Duplicate;
                }
                // KI#77: both sides' attestation state. Ours is whether we
                // retain a proof for the head we hold; theirs is `seq_attested`,
                // already computed above from the carried proof. The flood and
                // AE paths MUST pass the same thing or the mesh diverges (KI#46).
                let self_attested = smt.seq_proof(wallet_id).is_some();
                if existing.superseded_by(&candidate, self_attested, seq_attested) {
                    // The candidate wins the merge — adopt it and keep it
                    // flooding. Every node that holds an older entry adopts
                    // and re-forwards the winner, so it reaches the whole
                    // mesh; anti-entropy repairs any flood gap by leaf hash.
                    // §5.2.4 (KI#123): the disposition is declared, not
                    // remembered — a verified proof is installed atomically
                    // with the head (so the AE path can re-attach it when
                    // serving this head to a node that missed the flood); an
                    // unattested equal-seq tiebreaker adopt declares
                    // MergeWinner, and the KI#38 lock-step leaves the correct
                    // proof-absence (KI#77 rules that adoption legitimate).
                    let disposition = if seq_attested {
                        crate::smt::PutProof::Attested(seq_proof.clone().unwrap())
                    } else {
                        crate::smt::PutProof::ProoflessByDesign(
                            crate::smt::ProoflessKind::MergeWinner,
                        )
                    };
                    smt.put_with_proof(&candidate, disposition);
                    if seq_attested {
                        // YPX-022 B2: mesh-consistent completion mark — see the
                        // first-sight branch below for the rationale.
                        if *tx_hash != [0u8; 32] {
                            smt.mark_txid_completed(tx_hash, *tick);
                            // YPX-022 §5 REDEEMED parity (same B2 class): a
                            // k-attested redeem-finalize (receiver-pays signal =
                            // non-empty fee_breakdown, EXCLUDING genesis funds —
                            // they carry claim fees but are the SEND side of the
                            // claim's self-redeem) marks REDEEMED on THIS node
                            // too — else a gossip-only node would accept a
                            // recall of a redeemed txid AND serve a stale
                            // NOT_REDEEMED attestation. seq_attested-gated so a
                            // forged update cannot poison the terminal (strand a
                            // recall / block a legit redeem). `record_txid`
                            // feeds the YPX-014 txid service the SAME event —
                            // the service answers "redeemed?", so it is fed
                            // ONLY here and at 8b'' (put() no longer pollutes).
                            if !fee_breakdown.is_empty() && !is_genesis_claim {
                                smt.mark_txid_redeemed(tx_hash);
                                smt.record_txid(tx_hash, wallet_id, *tick);
                            }
                        }
                    }
                    apply_fee_record_from_gossip(
                        smt, tx_hash, wallet_id, *amount, fee_breakdown, *tick,
                    );
                    GossipAction::Forward(original_msg.clone())
                } else {
                    // The candidate lost the merge (older, or otherwise
                    // dominated) — drop it. A stale loser needs no
                    // propagation; only the winning entry must flood.
                    GossipAction::Duplicate
                }
            }
            None => {
                // New wallet we haven't seen. A first-sight entry that claims a
                // non-zero seq must carry a valid proof — else an attacker could
                // pre-seed a forged high-seq head for a wallet nobody's observed
                // yet and block the real entry. Zero-seq (legacy / heal /
                // genesis) is accepted as before.
                if *wallet_seq > 0 && !seq_attested {
                    return GossipAction::Duplicate;
                }
                let entry = NablaEntry {
                    wallet_id: *wallet_id,
                    current_state: *new_state,
                    tx_hash: *tx_hash,
                    tick: *tick,
                    wallet_seq: *wallet_seq, // WI3: k-attested gossip seq
                    group_members: None,
                    status: WalletStatus::Normal,
                    client_pk: *client_pk,
                    client_sig: client_sig.to_vec(),
                    // §32.3 — first-sight entry: adopt the lineage only from an
                    // attested SeqProof (the >0-seq guard above already required
                    // attestation; a zero-seq legacy entry carries no proof and
                    // is a non-redeem, so None).
                    received_from: if seq_attested {
                        seq_proof.as_ref().and_then(|p| p.sender_state)
                    } else {
                        None
                    },
                };
                // §5.2.4 (KI#123): first-sight adopt — a verified proof is
                // installed atomically with the head; a zero-seq legacy entry
                // carries none (the >0-seq guard above already required
                // attestation) and declares MergeWinner.
                let disposition = if seq_attested {
                    crate::smt::PutProof::Attested(seq_proof.clone().unwrap())
                } else {
                    crate::smt::PutProof::ProoflessByDesign(
                        crate::smt::ProoflessKind::MergeWinner,
                    )
                };
                smt.put_with_proof(&entry, disposition);
                if seq_attested {
                    // YPX-022 B2: a k-attested completion applied via gossip/AE marks the
                    // txid completed on THIS node too, so `completed_txids` is mesh-consistent
                    // — a RECALL is refused at ANY node, not only the one that directly handled
                    // the register. `seq_attested` ⟺ ≥ k distinct sigs (verify_seq_proof) AND every key a directory witness (KI#224), so a
                    // sub-quorum partial (never seq_attested; also rejected at the seq-advance
                    // guard above) is NEVER marked → genuine partials stay recallable.
                    if *tx_hash != [0u8; 32] {
                        smt.mark_txid_completed(tx_hash, *tick);
                        // YPX-022 §5 REDEEMED parity — see the merge branch above.
                        if !fee_breakdown.is_empty() && !is_genesis_claim {
                            smt.mark_txid_redeemed(tx_hash);
                            smt.record_txid(tx_hash, wallet_id, *tick);
                        }
                    }
                }
                apply_fee_record_from_gossip(
                    smt, tx_hash, wallet_id, *amount, fee_breakdown, *tick,
                );
                GossipAction::Forward(original_msg.clone())
            }
        }
    }

    /// Apply a group wallet update from gossip (Phase 3).
    /// Same conflict logic as state_update, but preserves member allocations.
    #[allow(clippy::too_many_arguments)]
    fn apply_group_update(
        &self,
        smt: &mut SparseMerkleTree,
        bans: &mut BanTable,
        wallet_id: &WalletId,
        new_state: &StateId,
        tx_hash: &TxHash,
        members: &[GroupMemberState],
        tick: &u64,
        original_msg: &GossipMessage,
    ) -> GossipAction {
        if bans.is_banned(wallet_id) {
            return GossipAction::Duplicate;
        }

        // Verify checksum: sum(available) must be consistent
        // (Core validated the real rules, Nabla just checks structural integrity)
        let _sum_available: u64 = members.iter().map(|m| m.available).sum();

        match smt.get(wallet_id) {
            Some(existing) => {
                if existing.current_state == *new_state {
                    return GossipAction::Duplicate;
                }

                if *tick > existing.tick {
                    // Newer tick — accept with group members
                    let entry = NablaEntry {
                        wallet_id: *wallet_id,
                        current_state: *new_state,
                        tx_hash: *tx_hash,
                        tick: *tick,
                        // WI3: group-update gossip carries no k-receipt seq, and
                        // this path orders by tick — preserve existing seq so
                        // `superseded_by` falls through to the tick tiebreaker
                        // (group ordering unchanged). Group anti-rollback (its own
                        // GroupUpdate seq wire) is a separate follow-on if needed.
                        wallet_seq: existing.wallet_seq,
                        group_members: Some(members.to_vec()),
                        // Fork Settlement §9o [R57] (W3; KI#236 related) — the
                        // status is this node's LOCAL projection: INHERIT it.
                        // This used to write `Normal`, so an unauthenticated
                        // GroupUpdate with a newer tick DEMOTED a local hold
                        // (Frozen / Tainted / a Banned leaf) — the reverse of
                        // the adoption hole, same class.
                        status: existing.status,
                        client_pk: [0u8; 32],
                        client_sig: vec![0u8; 64],
                        // §32.3 — group-update gossip carries no receipt lineage;
                        // preserve the existing entry's taint lineage.
                        received_from: existing.received_from,
                    };
                    smt.put_with_proof(
                        &entry,
                        crate::smt::PutProof::ProoflessByDesign(
                            crate::smt::ProoflessKind::GroupWallet,
                        ),
                    );
                    GossipAction::Forward(original_msg.clone())
                } else if *tick == existing.tick && existing.current_state != *new_state {
                    log::warn!(
                        "Gossip group conflict: wallet {:?} has different state at tick {}",
                        &wallet_id[..4],
                        tick
                    );
                    GossipAction::Forward(original_msg.clone())
                } else {
                    GossipAction::Duplicate
                }
            }
            None => {
                // New group wallet
                let entry = NablaEntry {
                    wallet_id: *wallet_id,
                    current_state: *new_state,
                    tx_hash: *tx_hash,
                    tick: *tick,
                    wallet_seq: 0, // WI3: first-seen group wallet (group seq wire is a follow-on)
                    group_members: Some(members.to_vec()),
                    status: WalletStatus::Normal,
                    client_pk: [0u8; 32],
                    client_sig: vec![0u8; 64],
                    received_from: None, // §32.3 — new group wallet, no lineage yet
                };
                smt.put_with_proof(
                    &entry,
                    crate::smt::PutProof::ProoflessByDesign(
                        crate::smt::ProoflessKind::GroupWallet,
                    ),
                );
                GossipAction::Forward(original_msg.clone())
            }
        }
    }

    /// Hash a gossip message for deduplication.
    fn hash_message(&self, msg: &GossipMessage) -> Hash256 {
        let bytes = bincode::serialize(msg).unwrap_or_default();
        blake3::hash(&bytes).into()
    }

    /// Rotate the seen set if it's too large.
    /// Two-generation strategy: current → prev, start fresh.
    /// Messages in prev_seen are still checked for dedup.
    /// Max 50% dedup loss on rotation (vs 100% with clear-all).
    fn maybe_prune(&mut self) {
        if self.seen.len() > self.max_seen {
            log::debug!("Gossip seen set rotated: {} entries moved to prev, {} prev discarded",
                self.seen.len(), self.prev_seen.len());
            self.prev_seen = core::mem::take(&mut self.seen);
        }
    }

    /// Total messages tracked for dedup (current + previous generation).
    pub fn seen_count(&self) -> usize {
        self.seen.len() + self.prev_seen.len()
    }
}

impl Default for GossipEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::AirdropPool;

    fn make_state_update(wid: u8, state: u8, tick: u64) -> GossipMessage {
        // KI#46 zero-pk flip: every fixture update is wallet-authored (key
        // derived from wid, same scheme as `ds_attested`) — zero-pk is now
        // REJECTED at the top of apply_state_update, so an unauthored
        // fixture would test nothing but the reject path.
        use ed25519_dalek::{Signer, SigningKey};
        // KI#226: the row is the signing key's own — `wallet_id` = the pk.
        let wallet_id = ds_wid(wid);
        let mut new_state = [0u8; 32];
        new_state[0] = state;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = wid ^ state;
        let wallet_sk = SigningKey::from_bytes(&[wid.wrapping_add(0xC0); 32]);
        let client_pk = wallet_sk.verifying_key().to_bytes();
        let payload = client_state_sign_payload(&wallet_id, &new_state, &tx_hash);
        let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();

        GossipMessage::StateUpdate {
            old_state: [0u8; 32],
            wallet_seq: 0,
            seq_proof: None,
            wallet_id,
            new_state,
            tx_hash,
            tick,
            is_genesis_claim: false,
            client_pk,
            client_sig,
            amount: 0,
            fee_breakdown: Vec::new(),
        }
    }

    // ── double-spend FORK ban: helpers + tests (deploy gate) ──
    fn ds_mint_seq_proof(txid: &TxHash, wallet_seq: u64, n: usize) -> crate::types::SeqProof {
        use ed25519_dalek::{Signer, SigningKey};
        let state_hash = [0x5a_u8; 32];
        let commitment_hash = [0x7c_u8; 32];
        let (epoch, is_dev_class) = (7u64, false);
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            txid, &state_hash, wallet_seq, &commitment_hash, epoch, is_dev_class, None, None,
            None,
        );
        let sigs = (0..n).map(|i| {
            let sk = SigningKey::from_bytes(&[0x10 + i as u8; 32]);
            crate::types::SeqProofSig {
                validator_pk: sk.verifying_key().to_bytes(),
                receipt_commitment_sig: sk.sign(&commitment).to_bytes().to_vec(),
            }
        }).collect();
        crate::types::SeqProof { state_hash, commitment_hash, epoch, is_dev_class, oods_flag: None, confidence_index: None, sigs, sender_state: None, required_k: 3, preimage: crate::types::test_legs::opaque_redeem_leg() /* wave 2a: minted over an arbitrary txid — a Send leg could not reproduce it */, declared: crate::types::test_legs::no_declared() }
    }
    /// StateUpdate carrying a k=`n`-attested SeqProof for (wid, state, seq),
    /// AND a valid wallet authorship sig (non-zero client_pk + client_sig over
    /// the §32 wallet-state payload). The wallet signing key is derived
    /// deterministically from `wid`, so the held A' and the conflicting B' are
    /// signed by the SAME wallet — exactly the authorship the ban now requires.
    /// `parent` = the state this advance consumed (0 = parent unknown/none);
    /// checked against the preimage by `verify_seq_proof_leg`.
    fn ds_attested(wid: u8, state: u8, parent: u8, seq: u64, tick: u64, n: usize) -> GossipMessage {
        use ed25519_dalek::{Signer, SigningKey};
        let wallet_id = ds_wid(wid); // KI#226: the key's own row
        let mut new_state = [0u8; 32]; new_state[0] = state;
        let mut old_state = [0u8; 32]; if parent != 0 { old_state[0] = parent; }
        let mut tag = [0u8; 32]; tag[0] = wid ^ state; tag[1] = state;
        let tx_hash = crate::types::test_legs::cheque_txid(tag); // KI#241 F-2: a redeem leg's txid has an origin
        let mut proof = ds_mint_seq_proof(&tx_hash, seq, n);
        let wallet_sk = SigningKey::from_bytes(&[wid.wrapping_add(0xC0); 32]);
        let client_pk = wallet_sk.verifying_key().to_bytes();
        // W7a: the redeem leg is verified on the flood — bind it to this update.
        crate::types::test_legs::bind_redeem_leg(&mut proof, &tx_hash, client_pk, old_state, new_state, seq, 0x10);
        let payload = client_state_sign_payload(&wallet_id, &new_state, &tx_hash);
        let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();
        GossipMessage::StateUpdate {
            old_state,
            wallet_seq: seq, seq_proof: Some(proof),
            wallet_id, new_state, tx_hash, tick,
            is_genesis_claim: false,
            client_pk, client_sig, amount: 0, fee_breakdown: Vec::new(),
        }
    }
    fn ds_proc(engine: &mut GossipEngine, smt: &mut SparseMerkleTree, bans: &mut BanTable, msg: &GossipMessage) -> GossipAction {
        let mut pool = DailyPoolState::new();
        engine.process(msg, smt, bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all)
    }
    /// The fixture wallet id for `wid` — since KI#226 it MUST be the bucket of
    /// the fixture's signing key (`[wid + 0xC0; 32]`), i.e. its pk (k=3).
    fn ds_wid(wid: u8) -> WalletId {
        ed25519_dalek::SigningKey::from_bytes(&[wid.wrapping_add(0xC0); 32]).verifying_key().to_bytes()
    }

    // ── ForkSettlement wave 2a — the flood re-verifies the carried leg ──────

    /// A GENUINE send leg for the flood tests — built by the ONE test leg
    /// builder (`types::test_legs::genuine_send_leg`, RULE 1): the wallet's
    /// client sig is over `smt_bucket(pk, k)` (the bucket derived from the key,
    /// exactly as the door floods it), every hash derived. The former local
    /// `ds_send_leg` signed over `ds_wid` instead, so its legs could never
    /// become origin records.
    fn ds_genuine_leg(seed: u8, consumed: u8, seq: u64) -> crate::types::ForkLeg {
        crate::types::test_legs::genuine_send_leg(
            &crate::types::test_legs::wallet(seed), [consumed; 32], seq,
            "bob@axiom.internal/0123456789", 500, 3, 3,
        )
    }

    /// POSITIVE control — a flood whose leg reproduces its own proof is adopted,
    /// and the adopted head's retained proof still carries the leg (so this
    /// node can serve it over AE in turn).
    #[test]
    fn wave2a_flood_adopts_a_genuine_leg_and_retains_it() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        let leg = ds_genuine_leg(0x61, 0x30, 2);
        let msg = crate::types::test_legs::flood_of(&leg, [0x30; 32], 9);
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &msg), GossipAction::Forward(_)));
        let held = smt.seq_proof(&leg.bucket()).expect("attested head retains its proof");
        assert!(matches!(held.preimage, crate::types::LegPreimage::Send(_)), "leg retained");
    }

    /// A flooded SeqProof whose preimage does NOT reproduce its own
    /// commitment_hash (nonce edited after signing) is REJECTED — dropped,
    /// counted, never adopted. MUTATION: delete the leg check in
    /// `apply_state_update` → this test goes RED (the update is adopted).
    #[test]
    fn wave2a_flood_rejects_a_seqproof_whose_preimage_does_not_reproduce() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        let mut leg = ds_genuine_leg(0x62, 0x30, 2);
        if let crate::types::LegPreimage::Send(p) = &mut leg.seq_proof.preimage { p.nonce += 1; }
        let msg = crate::types::test_legs::flood_of(&leg, [0u8; 32], 9);
        let before = crate::registration::leg_preimage_refused_total();
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &msg), GossipAction::Duplicate),
            "a non-reproducing leg must be dropped");
        assert!(smt.get(&leg.bucket()).is_none(), "nothing adopted");
        assert!(crate::registration::leg_preimage_refused_total() > before, "counted");
        assert_eq!(smt.origin_len(), 0, "and never recorded");
    }

    /// [R‑MEDIUM-3] on the flood — the message's `old_state` (unsigned) names a
    /// different parent than the preimage (signed) consumed: dropped.
    #[test]
    fn wave2a_flood_rejects_a_parent_that_is_not_the_preimage_consumed_state() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        let leg = ds_genuine_leg(0x63, 0x30, 2);
        let msg = crate::types::test_legs::flood_of(&leg, [0x3F; 32], 9);
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &msg), GossipAction::Duplicate));
        assert!(smt.get(&leg.bucket()).is_none());
    }

    // ── ForkSettlement wave 3 S6 — the flood record hook + ForkBan adoption ──

    fn w3_leg(seed: u8, consumed: StateId, seq: u64, recv: &str, amount: u64, nonce: u64) -> crate::types::ForkLeg {
        crate::types::test_legs::genuine_send_leg(
            &crate::types::test_legs::wallet(seed), consumed, seq, recv, amount, nonce, 3)
    }
    fn w3_flood(leg: &crate::types::ForkLeg, parent: StateId, tick: u64) -> GossipMessage {
        crate::types::test_legs::flood_of(leg, parent, tick)
    }
    fn w3_pk(seed: u8) -> WalletId {
        crate::types::test_legs::wallet(seed).verifying_key().to_bytes()
    }

    /// Test 17 — the flood records ABOVE its drops. (i) CONSUMED drop: the
    /// [R31] pair (equal amount + nonce, two receivers ⇒ one new_state Z1,
    /// two txids); after tx_a and a dust advance Z1 → Z1′ this node holds Z1
    /// consumed, so tx_b's StateUpdate hits `is_state_consumed(new_state)` —
    /// recorded first, the claim opens. (ii) SUPERSEDE LOSER: an equal-seq,
    /// LOWER-tick second leg loses `superseded_by` — recorded first, claim.
    /// MUTATION: move the flood hook below the `is_state_consumed(new_state)`
    /// drop ⇒ (i) RED; below the `superseded_by` branch ⇒ (ii) RED.
    #[test]
    fn flood_loser_and_consumed_drop_legs_open_claim() {
        // (i) consumed drop.
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        let y = [0x40u8; 32];
        let tx_a = w3_leg(0xD1, y, 1, "p@axiom.internal/0123456789", 100, 7);
        let tx_b = w3_leg(0xD1, y, 1, "q@axiom.internal/0123456789", 100, 7);
        assert_eq!(tx_a.new_state, tx_b.new_state, "fixture: R31 one new_state");
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&tx_a, y, 10)), GossipAction::Forward(_)));
        let dust = w3_leg(0xD1, tx_a.new_state, 2, "r@axiom.internal/0123456789", 1, 8);
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&dust, tx_a.new_state, 11)), GossipAction::Forward(_)));
        assert!(smt.is_state_consumed(&tx_b.new_state), "fixture: Z1 consumed");
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&tx_b, y, 12)), GossipAction::Duplicate));
        assert!(bans.is_banned(&w3_pk(0xD1)), "(i) the consumed-drop leg opened the claim");
        assert_eq!(bans.take_pending_fork_floods().len(), 1, "queued for the ForkBan flood");

        // (ii) supersede loser.
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        let y = [0x41u8; 32];
        let tx_a = w3_leg(0xD2, y, 1, "p@axiom.internal/0123456789", 100, 1);
        let tx_b = w3_leg(0xD2, y, 1, "q@axiom.internal/0123456789", 90, 2);
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&tx_a, [0u8; 32], 50)), GossipAction::Forward(_)));
        let act = ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&tx_b, [0u8; 32], 40));
        assert!(matches!(act, GossipAction::Duplicate), "the candidate is neither adopted nor forwarded");
        assert!(bans.is_banned(&w3_pk(0xD2)), "(ii) the supersede loser opened the claim");
        assert_eq!(smt.get(&w3_pk(0xD2)).unwrap().status, WalletStatus::Banned, "head flipped Banned");
    }

    /// Test 19 — design pass-2 HIGH-1 seq 1, PROOFLESS PING-PONG. The node
    /// holds A's head on tx_a (attested). The attacker floods an UNATTESTED
    /// same-seq, higher-tick copy of tx_b — `superseded_by` (KI#77) lets it
    /// replace the attested head, so check-3 (retired 2026-09-30, §9o [R56])
    /// held no proof for the head and stayed silent. Then tx_b's attested copy arrives: the node
    /// still ends holding BOTH records under (A, Y) ⇒ claim ⇒ A banned.
    /// MUTATION: skip the flood hook (detection keyed on the head / check-3
    /// alone) ⇒ RED.
    #[test]
    fn regression_proofless_ping_pong() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        let y = [0x42u8; 32];
        let tx_a = w3_leg(0xD3, y, 1, "p@axiom.internal/0123456789", 100, 1);
        let tx_b = w3_leg(0xD3, y, 1, "q@axiom.internal/0123456789", 90, 2);
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&tx_a, y, 10)), GossipAction::Forward(_)));
        // The proofless copy of tx_b, higher tick: swaps the head.
        let mut proofless = w3_flood(&tx_b, y, 20);
        if let GossipMessage::StateUpdate { seq_proof, .. } = &mut proofless { *seq_proof = None; }
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &proofless), GossipAction::Forward(_)),
            "fixture: the proofless same-seq entry wins the merge (KI#77)");
        assert_eq!(smt.get(&w3_pk(0xD3)).unwrap().current_state, tx_b.new_state, "fixture: head swapped");
        assert!(smt.seq_proof(&w3_pk(0xD3)).is_none(), "fixture: no held proof — check-3 is blind");
        assert!(!bans.is_banned(&w3_pk(0xD3)));
        // tx_b's attested copy (a different message: carries the proof).
        let _ = ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&tx_b, y, 21));
        assert!(bans.is_banned(&w3_pk(0xD3)), "both records held under (A, Y) ⇒ the claim");
        assert_eq!(smt.legs_under(&(w3_pk(0xD3), y)).len(), 2);
    }

    /// Test 20 — design pass-2 seq 2 on the FLOOD, the LATE LEG after A
    /// advanced past the parent: tx_a Y → Z1, dust Z1 → Z1′ (seq 2), then
    /// tx_b Y → Z2 (seq 1) arrives — a lower-seq LOSER; check-3 (retired
    /// W2) was silent (`previous_state = Z1 ≠ Y`). The record under (A, Y) catches it.
    /// MUTATION: skip the flood hook ⇒ RED.
    #[test]
    fn regression_late_leg_after_advance() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        let y = [0x43u8; 32];
        let tx_a = w3_leg(0xD4, y, 1, "p@axiom.internal/0123456789", 100, 1);
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&tx_a, y, 10)), GossipAction::Forward(_)));
        let dust = w3_leg(0xD4, tx_a.new_state, 2, "r@axiom.internal/0123456789", 1, 3);
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&dust, tx_a.new_state, 11)), GossipAction::Forward(_)));
        let tx_b = w3_leg(0xD4, y, 1, "q@axiom.internal/0123456789", 100, 2);
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&tx_b, y, 12)), GossipAction::Duplicate));
        assert!(bans.is_banned(&w3_pk(0xD4)), "the late lower-seq leg opened the claim");
        assert_eq!(smt.get(&w3_pk(0xD4)).unwrap().current_state, dust.new_state, "the head is untouched");
    }

    /// Test 31 — KI#68 / #204: an honest retry re-floods the SAME txid; the
    /// record is write-once and no claim ever opens. MUTATION: detect the
    /// conflict by `new_state` / by a re-record instead of the txid
    /// (`record_verified_leg` without the Duplicate short-circuit) ⇒ RED.
    #[test]
    fn honest_retry_same_txid_never_claims() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        let y = [0x44u8; 32];
        let leg = w3_leg(0xD5, y, 1, "p@axiom.internal/0123456789", 100, 1);
        let _ = ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&leg, y, 10));
        // A re-flood at another tick (not deduped by hash) and a replay with an
        // unknown parent — the same transaction, seen again.
        let _ = ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&leg, y, 11));
        let _ = ds_proc(&mut e, &mut smt, &mut bans, &w3_flood(&leg, [0u8; 32], 12));
        assert!(!bans.is_banned(&w3_pk(0xD5)));
        assert_eq!(smt.origin_len(), 1);
        assert_eq!(bans.origin_fork_claims_detected(), 0);
        assert_eq!(bans.atraxi_evidence_refused(), 0);
    }

    fn w3_claim(seed: u8) -> crate::types::ForkClaim {
        let y = [0x45u8; 32];
        crate::types::ForkClaim {
            a: w3_leg(seed, y, 1, "p@axiom.internal/0123456789", 100, 1),
            b: w3_leg(seed, y, 1, "q@axiom.internal/0123456789", 100, 2),
        }
    }

    /// Test 22a — a genuine `ForkBan` claim is adopted ONLY after
    /// `verify_fork_claim`: the registrant is banned (head flipped), both legs
    /// are recorded, the adoption is counted, and it is FORWARDED. A second
    /// delivery (already banned) is not re-forwarded. MUTATION: return
    /// `Duplicate` on the adopt arm (no forward) ⇒ RED; skip the leg records
    /// ⇒ RED.
    #[test]
    fn fork_ban_adopted_after_verify_and_forwarded() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        let claim = w3_claim(0xD6);
        let msg = GossipMessage::ForkBan { claim: claim.clone() };
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &msg), GossipAction::Forward(_)));
        assert!(bans.is_banned(&w3_pk(0xD6)));
        assert!(matches!(bans.get(&w3_pk(0xD6)).unwrap().evidence, crate::types::BanEvidence::Fork(_)));
        assert_eq!(bans.origin_fork_claims_adopted(), 1);
        assert_eq!(smt.legs_under(&claim.a.key()).len(), 2, "both legs recorded [R28]");
        // Same claim again, fresh engine (not the dedup): verified, nothing new ⇒ not forwarded.
        let mut e2 = GossipEngine::new();
        assert!(matches!(ds_proc(&mut e2, &mut smt, &mut bans, &msg), GossipAction::Duplicate));
    }

    /// Test 22b — a FORGED `ForkBan` (the legs signed over W's bucket by A —
    /// the HIGH-3 framing; and a tampered leg) is refused at the ONE
    /// chokepoint: nothing banned, nothing recorded, counted
    /// `atraxi_evidence_refused`, NOT forwarded. MUTATION: the receiver skips
    /// `verify_fork_claim` (ban on the carried word) ⇒ RED; forward on Err ⇒ RED.
    #[test]
    fn forged_fork_ban_refused_counted_not_forwarded() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        // Tampered: leg b's nonce edited after signing.
        let mut claim = w3_claim(0xD7);
        if let crate::types::LegPreimage::Send(p) = &mut claim.b.seq_proof.preimage { p.nonce += 9; }
        let act = ds_proc(&mut e, &mut smt, &mut bans, &GossipMessage::ForkBan { claim });
        assert!(matches!(act, GossipAction::Duplicate), "never forwarded");
        assert!(!bans.is_banned(&w3_pk(0xD7)));
        assert_eq!(bans.atraxi_evidence_refused(), 1);
        assert_eq!(smt.origin_len(), 0, "an unverifiable claim records nothing");
        // Honest-legs-from-two-parents: both legs genuine, not a fork.
        let chain_a = w3_leg(0xD8, [0x46; 32], 1, "p@axiom.internal/0123456789", 100, 1);
        let chain_b = w3_leg(0xD8, chain_a.new_state, 2, "q@axiom.internal/0123456789", 100, 2);
        let act = ds_proc(&mut e, &mut smt, &mut bans,
            &GossipMessage::ForkBan { claim: crate::types::ForkClaim { a: chain_a, b: chain_b } });
        assert!(matches!(act, GossipAction::Duplicate));
        assert!(!bans.is_banned(&w3_pk(0xD8)), "an honest chain is not a fork");
        assert_eq!(bans.atraxi_evidence_refused(), 2);
        assert_eq!(bans.origin_fork_claims_adopted(), 0);
    }

    fn claim_announce(req: &axiom_core_logic::wire_client::RegisterChequeClaimRequest, claim_tick: u64) -> GossipMessage {
        GossipMessage::ChequeClaimAnnounce {
            cheque_id: req.cheque_id,
            client_pk: req.client_pk.clone(),
            k_tier: req.k_tier,
            wallet_address: req.wallet_address.clone(),
            claim_sig: req.claim_sig.clone(),
            claim_tick,
        }
    }

    /// YPX-022 §2.1.2a item 3 (KI#205) — a gossiped claim is RE-VERIFIED by the
    /// receiving node: a forged one (bad signature) is dropped and stores
    /// nothing; a valid one is stored under the originating tick and forwarded.
    /// Goes red if the `verify_cheque_claim` call is removed from the
    /// `ChequeClaimAnnounce` arm (the forged claim would then be stored and
    /// forwarded) or if the arm stops calling `register_cheque_claim`.
    #[test]
    fn gossiped_claim_is_reverified_forged_dropped_valid_stored() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let cheque = [0xD1u8; 32];
        let (req, _) = crate::registration::signed_claim_request(0x61, "alice@example.com", cheque, 3);

        // Forged: same fields, signature flipped.
        let mut forged = req.clone();
        forged.claim_sig[0] ^= 0x80;
        let before = crate::registration::claims_unauthenticated_total();
        let action = ds_proc(&mut engine, &mut smt, &mut bans, &claim_announce(&forged, 777));
        assert!(matches!(action, GossipAction::Duplicate), "a forged claim must be DROPPED, got {action:?}");
        assert!(smt.query_cheque_claim(&cheque).is_none(), "a forged claim must store NOTHING");
        assert!(crate::registration::claims_unauthenticated_total() > before, "RULE 3 §2: counted");

        // Valid: stored under the ORIGINATING tick and forwarded.
        let action = ds_proc(&mut engine, &mut smt, &mut bans, &claim_announce(&req, 777));
        assert!(matches!(action, GossipAction::Forward(_)), "a valid claim must be applied+forwarded, got {action:?}");
        let stored = smt.query_cheque_claim(&cheque).expect("valid claim stored");
        assert_eq!(stored.claim_tick, 777, "mesh converges on the originating node's claim tick");
        assert_eq!(stored.client_pk, req.client_pk);
        assert!(smt.has_live_claim(&cheque, 800));

        // A DIFFERENT key claiming the same cheque later loses (first-wins) and is not re-flooded.
        let (rival, _) = crate::registration::signed_claim_request(0x62, "bob@example.com", cheque, 3);
        let action = ds_proc(&mut engine, &mut smt, &mut bans, &claim_announce(&rival, 778));
        assert!(matches!(action, GossipAction::Duplicate));
        assert_eq!(smt.query_cheque_claim(&cheque).unwrap().client_pk, req.client_pk, "first claim stands");
    }

    /// §2.1.2a item 1 (ii) over gossip — when this node holds a head for the
    /// claimant's bucket registered under a DIFFERENT key, the flooded claim is
    /// refused even with a valid signature and binding.
    #[test]
    fn gossiped_claim_refused_when_local_head_key_differs() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let cheque = [0xD2u8; 32];
        let (req, _) = crate::registration::signed_claim_request(0x63, "alice@example.com", cheque, 3);
        let pk: [u8; 32] = req.client_pk.as_slice().try_into().unwrap();
        // Plant a head at the claimant's bucket (k=3: bucket == pk) under another key.
        let mut entry = crate::types::NablaEntry {
            received_from: None,
            wallet_seq: 1,
            wallet_id: pk,
            current_state: [0x10; 32],
            tx_hash: [0x11; 32],
            tick: 1,
            group_members: None,
            status: crate::types::WalletStatus::Normal,
            client_pk: [0x99; 32],
            client_sig: vec![1u8; 64],
        };
        smt.put(&entry);
        let action = ds_proc(&mut engine, &mut smt, &mut bans, &claim_announce(&req, 10));
        assert!(matches!(action, GossipAction::Duplicate), "head key differs → refused, got {action:?}");
        assert!(smt.query_cheque_claim(&cheque).is_none());
        // Same key on the head → accepted.
        entry.client_pk = pk;
        smt.put(&entry);
        let mut engine2 = GossipEngine::new();
        let action = ds_proc(&mut engine2, &mut smt, &mut bans, &claim_announce(&req, 10));
        assert!(matches!(action, GossipAction::Forward(_)), "head key equal → accepted, got {action:?}");
    }

    /// Authored StateUpdate whose k=`n` SeqProof carries `sender_state` (§32.3),
    /// folded into the receipt_commitment exactly as Core CL5 does — so the k
    /// sigs attest it and `verify_seq_proof` recompute matches.
    fn ds_attested_sender(wid: u8, state: u8, seq: u64, tick: u64, n: usize, sender_state: [u8; 32]) -> GossipMessage {
        use ed25519_dalek::{Signer, SigningKey};
        let wallet_id = ds_wid(wid); // KI#226: the signing key's own row
        let mut new_state = [0u8; 32]; new_state[0] = state;
        let mut tag = [0u8; 32]; tag[0] = wid ^ state; tag[1] = state;
        let tx_hash = crate::types::test_legs::cheque_txid(tag); // KI#241 F-2: a redeem leg's txid has an origin
        let (state_hash, commitment_hash, epoch, is_dev_class) = ([0x5au8; 32], [0x7cu8; 32], 7u64, false);
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            &tx_hash, &state_hash, seq, &commitment_hash, epoch, is_dev_class, None, None, Some(&sender_state));
        let sigs = (0..n).map(|i| {
            let sk = SigningKey::from_bytes(&[0x10 + i as u8; 32]);
            crate::types::SeqProofSig { validator_pk: sk.verifying_key().to_bytes(), receipt_commitment_sig: sk.sign(&commitment).to_bytes().to_vec() }
        }).collect();
        let mut proof = crate::types::SeqProof { state_hash, commitment_hash, epoch, is_dev_class, oods_flag: None, confidence_index: None, sigs, sender_state: Some(sender_state), required_k: 3, preimage: crate::types::test_legs::opaque_redeem_leg() /* wave 2a: minted over an arbitrary txid — a Send leg could not reproduce it */, declared: crate::types::test_legs::no_declared() };
        let wallet_sk = SigningKey::from_bytes(&[wid.wrapping_add(0xC0); 32]);
        let client_pk = wallet_sk.verifying_key().to_bytes();
        // W7a: the redeem leg is verified on the flood — bind it to this update.
        crate::types::test_legs::bind_redeem_leg(&mut proof, &tx_hash, client_pk, [0u8; 32], new_state, seq, 0x10);
        let payload = client_state_sign_payload(&wallet_id, &new_state, &tx_hash);
        let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();
        GossipMessage::StateUpdate {
            old_state: [0u8; 32], wallet_seq: seq, seq_proof: Some(proof),
            wallet_id, new_state, tx_hash, tick, is_genesis_claim: false,
            client_pk, client_sig, amount: 0, fee_breakdown: Vec::new(),
        }
    }

    /// §32.3 WIRE PROOF (deployed apply path): `NablaEntry.received_from` is set
    /// from a k-ATTESTED `SeqProof.sender_state` over the real gossip apply —
    /// NOT set directly (the g1/g2 unit tests do that). This closes the gap the
    /// live forced-fork check targeted: the deployed `apply_state_update` wiring
    /// authenticates the lineage (via `verify_seq_proof`) before adopting it,
    /// and a forged/absent sender_state does NOT populate it.
    #[test]
    fn received_from_set_from_attested_seqproof_sender_state_over_wire() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let sender_state = { let mut s = [0u8; 32]; s[0] = 0x0B; s }; // S's forked state

        // Receiver R (wid 0x0C) advances to 0x07, its k=3 SeqProof carrying
        // sender_state = 0x0B. Apply over the REAL gossip engine.
        let r = ds_attested_sender(0x0C, 0x07, 0, 1, 3, sender_state);
        let act = ds_proc(&mut engine, &mut smt, &mut bans, &r);
        assert!(matches!(act, GossipAction::Forward(_)), "attested first-sight update adopts + forwards");

        // WIRE WIRING: received_from adopted from the attested SeqProof, and its
        // tx_hash is the receiver's own txid (NOT the sender state) — proving the
        // edge is `received_from`, sourced over the wire, not a tx_hash coincidence.
        let e = smt.get(&ds_wid(0x0C)).expect("R registered");
        assert_eq!(e.received_from, Some(sender_state),
            "§32.3: received_from must be set from the k-attested SeqProof.sender_state");
        assert_ne!(e.tx_hash, sender_state, "tx_hash is R's own redeem txid, not the sender state");
    }

    #[test]
    fn jfp_secret_forwards_without_touching_smt() {
        // KI#46 zero-pk flip: the dedicated JfpSecret variant must flood
        // (Forward) WITHOUT planting anything in the SMT — the retired
        // synthetic StateUpdate carrier wrote a junk zero-pk entry into
        // every receiving node's tree. Application (secret storage) is
        // binary-side; the engine only dedups + forwards.
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        let root_before = smt.root_hash();
        let msg = GossipMessage::JfpSecret {
            dwp_wallet_id: ds_wid(0xD7),
            secret: [0x5E; 32],
        };
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &msg), GossipAction::Forward(_)),
            "first sight must flood");
        assert_eq!(smt.root_hash(), root_before, "JfpSecret must never touch the SMT");
        assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &msg), GossipAction::Duplicate),
            "replay must dedup");
    }

    #[test]
    fn dsfork_two_k3_successors_same_seq_same_parent_BANS() {
        // KI#46 check-3 shape: the node must have WITNESSED the parent get
        // consumed (previous_states[W] = X) — a fork is two children of X.
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        // Base: wallet at X (seq 4).
        ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAA, 0x0F, 0, 4, 9, 3));
        // Held: A' at seq 5 consuming X (put records previous_states[W] = X).
        ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAA, 0x01, 0x0F, 5, 10, 3));
        assert!(smt.seq_proof(&ds_wid(0xAA)).is_some(), "held entry must retain its seq proof");
        assert_eq!(smt.previous_state(&ds_wid(0xAA)).map(|s| s[0]), Some(0x0F),
            "adopting A' must record X as the authoritative parent");
        // Incoming: B' ALSO consuming X at the SAME seq 5 = double-SPEND.
        // Fork Settlement W7b: `ds_attested` carries GENUINE redeem legs, so
        // A' and B' are two k-witnessed, wallet-signed REDEEM legs from X —
        // the record-keyed detector (the Redeem arm, spec R52c) now catches
        // the fork FIRST, above check-3: a verified `ForkClaim` bans the key
        // and the update is dropped (`Duplicate`; the claim floods as
        // `ForkBan` via the node's drain). Before W7b redeem legs were never
        // recorded and check-3 (`BanDetected`) was the only detector here;
        // both are gone since W2 (§9o [R56]) — the record detector is THE
        // detector for this shape.
        let action = ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAA, 0x02, 0x0F, 5, 11, 3));
        assert!(matches!(action, GossipAction::Duplicate), "the fork leg is dropped, not adopted");
        assert!(bans.is_banned(&ds_wid(0xAA)), "double-spender must be banned");
        match &bans.get(&ds_wid(0xAA)).expect("ban entry").evidence {
            crate::types::BanEvidence::Fork(c) => {
                assert_eq!(crate::ban::verify_fork_claim(c), Ok(()), "the evidence is a verified redeem-fork claim");
                assert_eq!(c.a.kind(), axiom_core_logic::types::LegKind::Redeem);
            }
            other => panic!("expected a record-keyed Fork verdict, got {other:?}"),
        }
        // The SMT entry must flip to Banned so the §4.6 read path (process_query
        // reports entry.status, not the BanTable) surfaces BANNED to a downstream
        // verify_cheque — otherwise the redeem gap stays open.
        assert_eq!(smt.get(&ds_wid(0xAA)).map(|e| e.status), Some(WalletStatus::Banned),
            "banned wallet's SMT entry must report Banned for the §4.6 redeem gate");
    }

    /// The HELD-HEAD LEG MAPPING (Fork Settlement W7c prerequisite; kept by
    /// §9o [R56] when check-3's ban was retired, W2). The HELD head A'
    /// (X → 0x01) was installed WITHOUT the record hook (a head this node holds
    /// but never recorded — the shape only check-3 used to catch). B' (X → 0x02,
    /// same seq, same parent) floods in: the flood hook records B' alone under
    /// (W, X), then records the held head's leg through the ONE hook — so the
    /// ban is an A1 `Fork` verdict under the key and the key holds BOTH legs
    /// (what `origin_vouch` reads, clause 4 gone).
    /// (Renamed 2026-09-30 from `w7c_check3_fork_lands_in_the_fork_index`.)
    /// MUTATIONS: (run 2026-09-28, pre-W2) delete the `held_leg` block ⇒
    /// check-3's legacy `SeqFork` ban fired instead, ONE leg ⇒ RED; (run
    /// 2026-09-30, W2) delete the `held_leg` block ⇒ nobody is banned (check-3
    /// is gone) and B' is ADOPTED ⇒ RED at "the fork leg is dropped, not
    /// adopted".
    #[test]
    fn held_head_leg_mapped_into_fork_index() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAE, 0x0F, 0, 4, 9, 3));
        let GossipMessage::StateUpdate { wallet_id, new_state, tx_hash, tick, wallet_seq, client_pk, client_sig, seq_proof, .. } =
            ds_attested(0xAE, 0x01, 0x0F, 5, 10, 3) else { unreachable!() };
        let held = NablaEntry {
            wallet_id, current_state: new_state, tx_hash, tick, wallet_seq,
            group_members: None, status: WalletStatus::Normal, client_pk, client_sig,
            received_from: None,
        };
        let proof = seq_proof.unwrap();
        smt.put_with_proof(&held, crate::smt::PutProof::Attested(proof.clone()));
        let mut x = [0u8; 32]; x[0] = 0x0F;
        assert_eq!(smt.previous_state(&wallet_id), Some(x), "fixture: X is the held head's parent");
        assert!(smt.legs_under(&(client_pk, x)).is_empty(), "fixture: the held head's leg is NOT recorded");
        let action = ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAE, 0x02, 0x0F, 5, 11, 3));
        assert!(matches!(action, GossipAction::Duplicate), "the fork leg is dropped, not adopted");
        assert!(matches!(&bans.get(&wallet_id).expect("banned").evidence, crate::types::BanEvidence::Fork(_)),
            "the ban is an A1 Fork verdict, not a legacy SeqFork");
        assert_eq!(smt.legs_under(&(client_pk, x)).len(), 2, "both legs under the fork key");
        assert!(bans.take_pending_fork_floods().len() == 1, "the claim floods as ForkBan");
    }

    /// KI#46 regression (found live 2026-07-29, run 1785338039): a claim's
    /// self-redeem is a SAME-SEQ state advance (Core keeps wallet_seq on
    /// receive) whose parent is the HELD head — a chain continuation, never
    /// a fork. The seq-only predicate banned wallet A for exactly this.
    #[test]
    fn dsfork_same_seq_chain_continuation_redeem_NO_ban() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        // Claim: seq 1 -> state 0x01 (parent: none/genesis).
        ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAB, 0x01, 0, 1, 10, 3));
        // Self-redeem: seq STAYS 1, state 0x01 -> 0x02 (parent = held head).
        let _ = ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAB, 0x02, 0x01, 1, 11, 3));
        assert!(!bans.is_banned(&ds_wid(0xAB)), "honest redeem must NOT be banned");
    }

    /// KI#46: an unknown parent (all-zero old_state, e.g. replay
    /// reconstruction) can never be ban evidence — a node that cannot
    /// prove the fork defers to nodes that can.
    #[test]
    fn dsfork_unknown_parent_NO_ban() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAC, 0x0F, 0, 4, 9, 3));
        ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAC, 0x01, 0x0F, 5, 10, 3));
        let _ = ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAC, 0x02, 0, 5, 11, 3));
        assert!(!bans.is_banned(&ds_wid(0xAC)));
    }

    #[test]
    fn dsfork_normal_sequential_advance_NO_ban() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xBB, 0x01, 0, 5, 10, 3));
        // A legitimate next tx: different STATE but a HIGHER seq (6) — not a conflict.
        let _ = ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xBB, 0x02, 0x01, 6, 11, 3));
        assert!(!bans.is_banned(&ds_wid(0xBB)), "honest sequential advance must NOT be banned");
    }

    #[test]
    fn dsfork_one_sided_unproven_NO_ban() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xCC, 0x01, 0, 5, 10, 3));
        // Conflicting state at same seq but UNPROVEN (no seq_proof) — can't prove
        // it's k=3-witnessed, so it must NOT trigger a ban (avoids framing).
        // AUTHORED (KI#46 flip: zero-pk is rejected before the seq gate, which
        // would make this test vacuously pass) — signed with the wallet's own
        // key so the message reaches the dsfork predicate and fails ONLY on
        // the missing proof.
        use ed25519_dalek::{Signer as _, SigningKey};
        let wallet_id = ds_wid(0xCC); // KI#226: the signing key's own row
        let mut new_state = [0u8; 32]; new_state[0] = 0x02;
        let mut tx_hash = [0u8; 32]; tx_hash[0] = 0xCC ^ 0x02;
        let wallet_sk = SigningKey::from_bytes(&[0xCCu8.wrapping_add(0xC0); 32]);
        let client_pk = wallet_sk.verifying_key().to_bytes();
        let payload = client_state_sign_payload(&wallet_id, &new_state, &tx_hash);
        let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();
        let unproven = GossipMessage::StateUpdate {
            old_state: [0u8; 32],
            wallet_seq: 5, seq_proof: None, wallet_id, new_state, tx_hash, tick: 11,
            is_genesis_claim: false,
            client_pk, client_sig, amount: 0, fee_breakdown: Vec::new(),
        };
        let _ = ds_proc(&mut e, &mut smt, &mut bans, &unproven);
        assert!(!bans.is_banned(&ds_wid(0xCC)), "unproven (framing-risk) conflict must NOT be banned");
    }

    #[test]
    fn dsfork_forged_zeropk_unauthored_NO_ban() {
        // FRAMING ATTACK: an attacker mints two valid-looking k=3 SeqProofs for a
        // VICTIM's wallet_id (verify_seq_proof checks only sig count, not the
        // approved-validator set), but CANNOT forge the wallet's authorship sig, so
        // sends zero-pk/unauthored StateUpdates. KI#46 zero-pk flip: forged
        // unauthored evidence is now rejected at the TOP of apply_state_update
        // (YPX-009 enforced) — even EARLIER than the dsfork authorship gate it
        // originally exercised. Assert the REJECT: neither message is adopted,
        // nothing enters the SMT, and the victim is never banned.
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        let held = {
            let mut wallet_id = [0u8; 32]; wallet_id[0] = 0xEE;
            let mut new_state = [0u8; 32]; new_state[0] = 0x01;
            let mut tx_hash = [0u8; 32]; tx_hash[0] = 0xEE ^ 0x01; tx_hash[1] = 0x01;
            GossipMessage::StateUpdate {
                old_state: [0u8; 32],
                wallet_seq: 5, seq_proof: Some(ds_mint_seq_proof(&tx_hash, 5, 3)),
                wallet_id, new_state, tx_hash, tick: 10,
            is_genesis_claim: false,
                client_pk: [0u8; 32], client_sig: vec![0u8; 64], amount: 0, fee_breakdown: Vec::new(),
            }
        };
        let action = ds_proc(&mut e, &mut smt, &mut bans, &held);
        assert!(matches!(action, GossipAction::Duplicate), "zero-pk update must be REJECTED (not adopted, not forwarded)");
        assert!(smt.get(&ds_wid(0xEE)).is_none(), "zero-pk update must never enter the SMT");
        // Forged conflicting B' at the SAME seq, also k=3-attested, also zero-pk.
        let forged = {
            let mut wallet_id = [0u8; 32]; wallet_id[0] = 0xEE;
            let mut new_state = [0u8; 32]; new_state[0] = 0x02;
            let mut tx_hash = [0u8; 32]; tx_hash[0] = 0xEE ^ 0x02; tx_hash[1] = 0x02;
            GossipMessage::StateUpdate {
                old_state: [0u8; 32],
                wallet_seq: 5, seq_proof: Some(ds_mint_seq_proof(&tx_hash, 5, 3)),
                wallet_id, new_state, tx_hash, tick: 11,
            is_genesis_claim: false,
                client_pk: [0u8; 32], client_sig: vec![0u8; 64], amount: 0, fee_breakdown: Vec::new(),
            }
        };
        let action = ds_proc(&mut e, &mut smt, &mut bans, &forged);
        assert!(matches!(action, GossipAction::Duplicate), "forged zero-pk conflict must be REJECTED");
        assert!(!bans.is_banned(&ds_wid(0xEE)), "victim must NOT be framed by forged zero-pk evidence");
    }

    // `dsfork_subquorum_evidence_rejected_by_verifier` DELETED 2026-09-30 with
    // `BanTable::verify_seq_conflict` (§9o [R56], W2): the verifier's last
    // production caller (the `SeqForkBan` arm's telemetry verify) is gone.

    #[test]
    fn gossip_new_wallet_accepted() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg = make_state_update(0xAA, 0x01, 1);
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        assert!(matches!(action, GossipAction::Forward(_)));
        assert_eq!(smt.len(), 1);
    }

    #[test]
    fn gossip_duplicate_ignored() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg = make_state_update(0xAA, 0x01, 1);
        engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        // Same message again
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);
        assert!(matches!(action, GossipAction::Duplicate));
    }

    #[test]
    fn gossip_newer_tick_updates() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg1 = make_state_update(0xAA, 0x01, 1);
        engine.process(&msg1, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        let msg2 = make_state_update(0xAA, 0x02, 2);
        let action = engine.process(&msg2, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        assert!(matches!(action, GossipAction::Forward(_)));
        let wid = ds_wid(0xAA);
        assert_eq!(smt.get(&wid).unwrap().current_state[0], 0x02);
    }

    #[test]
    fn gossip_older_tick_ignored() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg1 = make_state_update(0xAA, 0x01, 5);
        engine.process(&msg1, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        let msg2 = make_state_update(0xAA, 0x02, 3); // older tick
        let action = engine.process(&msg2, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        assert!(matches!(action, GossipAction::Duplicate));
        let wid = ds_wid(0xAA);
        assert_eq!(smt.get(&wid).unwrap().current_state[0], 0x01); // unchanged
    }

    #[test]
    fn gossip_banned_wallet_ignored() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let wid = ds_wid(0xAA);
        bans.ban(
            wid,
            ConflictProof {
                old_state: [0; 32],
                new_state: [1; 32],
                tx_hash: [2; 32],
                k3_signatures: vec![
                    WitnessSig { validator_pk: [1; 32], signature: vec![1; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [2; 32], signature: vec![2; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [3; 32], signature: vec![3; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                ],
                tick: 0,
                required_k: 3,
            },
            ConflictProof {
                old_state: [0; 32],
                new_state: [3; 32],
                tx_hash: [4; 32],
                k3_signatures: vec![
                    WitnessSig { validator_pk: [1; 32], signature: vec![1; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [2; 32], signature: vec![2; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [3; 32], signature: vec![3; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                ],
                tick: 0,
                required_k: 3,
            },
        );

        let msg = make_state_update(0xAA, 0x01, 1);
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        assert!(matches!(action, GossipAction::Duplicate));
        assert_eq!(smt.len(), 0); // not inserted
    }

    /// KI#222 — the `BanAlert` receiver is RETIRED. This replaces
    /// `gossip_ban_alert_verified`, which asserted the forgeable path WORKED
    /// (under `NoopSigner`: ban + forward).
    ///
    /// Feeds the exact attack through `process` with a REAL Ed25519 signer: a pair
    /// forged from ONE genuine receipt (`ban::ki222_forged_pair_from_one_receipt`)
    /// that the old verifier ACCEPTS (asserted below as the precondition, so this
    /// test cannot pass vacuously on evidence the old arm would have refused
    /// anyway). The victim is held in the SMT with a distinct `client_pk`, so the
    /// old §10.4 pair-ban would ALSO have fired — both must stay unbanned.
    #[test]
    fn ki222_banalert_receiver_retired_no_ban_no_forward() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();
        let real = crate::crypto::Ed25519Signer::from_seed(&[0x01; 32]);

        // The victim: a registered wallet with a real owner key.
        let wid = ds_wid(0xAA);
        let consumed = [0x10; 32];
        // `make_state_update` is wallet-authored: the entry carries a real,
        // non-zero `client_pk` (= `wid` since KI#226).
        let msg = make_state_update(0xAA, 0x01, 1);
        engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);
        let victim_pk = smt.get(&wid).expect("victim registered").client_pk;
        // KI#226: a head's `client_pk` is now always its own row's key
        // (`wallet_id` derives from it), so the victim's pk IS `wid`; the
        // asserts below still cover both names.
        assert!(victim_pk != [0u8; 32], "fixture: a wallet-authored head");

        let (ev1, ev2) = crate::ban::ki222_forged_pair_from_one_receipt(&wid, &consumed);
        // Precondition: this is evidence the OLD arm would have acted on.
        assert!(BanTable::verify_conflict(&wid, &ev1, &ev2, &real),
            "precondition: the forged pair must pass the old verifier, or this test proves nothing");

        let msg = GossipMessage::BanAlert { wallet_id: wid, evidence_1: ev1.clone(), evidence_2: ev2.clone() };
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        assert!(matches!(action, GossipAction::Duplicate),
            "KI#222: a BanAlert must be DROPPED — not forwarded; got {}",
            match &action { GossipAction::Forward(_) => "Forward", _ => "other" });
        assert!(bans.is_empty(), "KI#222: the retired receiver must ban NOTHING (BanTable len {})", bans.len());
        assert!(!bans.is_banned(&wid), "KI#222: victim wallet must not be banned by a forged pair");
        assert!(!bans.is_banned(&victim_pk), "KI#222: victim client_pk must not be pair-banned");
        assert_eq!(bans.refused_malformed(), 0, "the drop happens before ban(), not inside it");
        assert_eq!(smt.get(&wid).unwrap().status, WalletStatus::Normal, "victim SMT entry untouched");
        assert_eq!(engine.ki222_banalert_dropped(), 1, "the drop must be COUNTED (/status)");

        // A second, distinct alert is counted too (dedup is by message hash).
        let (ev3, ev4) = crate::ban::ki222_forged_pair_from_one_receipt(&wid, &[0x11; 32]);
        let msg2 = GossipMessage::BanAlert { wallet_id: wid, evidence_1: ev3, evidence_2: ev4 };
        let action2 = engine.process(&msg2, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);
        assert!(matches!(action2, GossipAction::Duplicate));
        assert!(bans.is_empty());
        assert_eq!(engine.ki222_banalert_dropped(), 2);
    }

    /// Fork Settlement §9o [R56] (W2) — `SeqForkBan` is a TOMBSTONE: a
    /// well-formed one (two k=3-attested, same-seq heads of the victim — the
    /// exact shape the retired check-3 emitted) is DROPPED: not forwarded, no
    /// ban, the victim's head untouched, and the drop COUNTED on /status
    /// (`seqforkban_dropped`, RULE 3 §2). Emission is covered by
    /// `fork_detection_mesh::fork_retire_proof_{a,b,b2,c}_*` (0 `SeqForkBan`
    /// envelopes on the whole mesh).
    /// MUTATION (run 2026-09-30): return `GossipAction::Forward(msg.clone())`
    /// from the `SeqForkBan` arm ⇒ RED at "must not be forwarded".
    #[test]
    fn seqforkban_dropped_counted_never_forwarded() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        let wid = ds_wid(0xAF);
        ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAF, 0x01, 0, 5, 10, 3));
        let head = smt.get(&wid).expect("fixture: the victim holds a head").clone();
        let (txa, txb) = ([0xA1u8; 32], [0xB2u8; 32]);
        let evidence = crate::types::SeqConflictProof {
            wallet_seq: 5,
            state_a: [0x01; 32], tx_a: txa, proof_a: ds_mint_seq_proof(&txa, 5, 3),
            state_b: [0x02; 32], tx_b: txb, proof_b: ds_mint_seq_proof(&txb, 5, 3),
        };
        let msg = GossipMessage::SeqForkBan { wallet_id: wid, evidence: evidence.clone() };
        let action = ds_proc(&mut e, &mut smt, &mut bans, &msg);
        assert!(matches!(action, GossipAction::Duplicate),
            "R56: a SeqForkBan must not be forwarded; got {}",
            match &action { GossipAction::Forward(_) => "Forward", _ => "other" });
        assert!(bans.is_empty(), "R56: a SeqForkBan bans nothing");
        assert_eq!(smt.get(&wid), Some(&head), "R56: the victim's head is untouched");
        assert_eq!(e.seqforkban_dropped(), 1, "R56: the drop is COUNTED (/status)");
        // A second, distinct one is counted too (dedup is by message hash).
        let mut ev2 = evidence;
        ev2.tx_b = [0xB3; 32];
        ev2.proof_b = ds_mint_seq_proof(&ev2.tx_b, 5, 3);
        let action2 = ds_proc(&mut e, &mut smt, &mut bans, &GossipMessage::SeqForkBan { wallet_id: wid, evidence: ev2 });
        assert!(matches!(action2, GossipAction::Duplicate));
        assert_eq!(e.seqforkban_dropped(), 2);
        assert!(bans.is_empty());
    }

    // ── Group Wallet Gossip Tests (Phase 3) ──

    fn make_group_update(wid: u8, state: u8, tick: u64) -> GossipMessage {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = wid;
        let mut new_state = [0u8; 32];
        new_state[0] = state;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = wid ^ state;

        GossipMessage::GroupUpdate {
            wallet_id,
            new_state,
            tx_hash,
            members: vec![
                GroupMemberState { member_pk: [0x10; 32], share_bps: 5000, available: 500 },
                GroupMemberState { member_pk: [0x20; 32], share_bps: 3000, available: 300 },
                GroupMemberState { member_pk: [0x30; 32], share_bps: 2000, available: 200 },
            ],
            tick,
        }
    }

    #[test]
    fn gossip_group_update_new_wallet() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg = make_group_update(0xBB, 0x01, 1);
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        assert!(matches!(action, GossipAction::Forward(_)));
        let wid = { let mut w = [0u8; 32]; w[0] = 0xBB; w } /* group wallet: zero-pk carve-out, not key-derived */;
        let entry = smt.get(&wid).unwrap();
        assert!(entry.group_members.is_some());
        assert_eq!(entry.group_members.as_ref().unwrap().len(), 3);
        assert_eq!(entry.group_members.as_ref().unwrap()[0].available, 500);
    }

    #[test]
    fn gossip_group_update_newer_tick() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg1 = make_group_update(0xBB, 0x01, 1);
        engine.process(&msg1, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        // Newer tick with updated members
        let msg2_members = vec![
            GroupMemberState { member_pk: [0x10; 32], share_bps: 5000, available: 800 },
            GroupMemberState { member_pk: [0x20; 32], share_bps: 3000, available: 480 },
            GroupMemberState { member_pk: [0x30; 32], share_bps: 2000, available: 320 },
        ];
        let wid = { let mut w = [0u8; 32]; w[0] = 0xBB; w } /* group wallet: zero-pk carve-out, not key-derived */;
        let msg2 = GossipMessage::GroupUpdate {
            wallet_id: wid,
            new_state: { let mut s = [0u8; 32]; s[0] = 0x02; s },
            tx_hash: [0xBB ^ 0x02; 32],
            members: msg2_members.clone(),
            tick: 5,
        };

        let action = engine.process(&msg2, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);
        assert!(matches!(action, GossipAction::Forward(_)));

        let entry = smt.get(&wid).unwrap();
        let members = entry.group_members.as_ref().unwrap();
        assert_eq!(members[0].available, 800);
        assert_eq!(members[1].available, 480);
    }

    /// Fork Settlement §9o [R57] (W3; KI#236 related) — an unauthenticated
    /// GroupUpdate with a newer tick advances the head but must NOT demote
    /// this node's local hold: the status is INHERITED. For each hold
    /// (Frozen / Tainted / Banned-leaf) the head moves, the status stays.
    /// MUTATION (run 2026-09-30): write `status: WalletStatus::Normal` in
    /// `apply_group_update` (the pre-W3 code) ⇒ RED ("demoted").
    #[test]
    fn group_update_cannot_demote_status() {
        for (i, hold) in [WalletStatus::Frozen, WalletStatus::Tainted, WalletStatus::Banned].into_iter().enumerate() {
            let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
            let w = 0xD0 + i as u8;
            let wid = { let mut x = [0u8; 32]; x[0] = w; x } /* group wallet: zero-pk carve-out */;
            assert!(matches!(ds_proc(&mut e, &mut smt, &mut bans, &make_group_update(w, 0x01, 1)), GossipAction::Forward(_)));
            let mut held = smt.get(&wid).unwrap().clone();
            held.status = hold;
            smt.put_with_proof(&held, crate::smt::PutProof::SameHeadStatusChange);
            let action = ds_proc(&mut e, &mut smt, &mut bans, &make_group_update(w, 0x02, 5));
            assert!(matches!(action, GossipAction::Forward(_)), "{hold:?}: the newer group head is applied");
            let after = smt.get(&wid).unwrap();
            assert_eq!(after.current_state[0], 0x02, "{hold:?}: head advanced");
            assert_eq!(after.status, hold, "{hold:?}: local hold DEMOTED by an unauthenticated GroupUpdate");
        }
    }

    #[test]
    fn gossip_group_update_older_tick_ignored() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg1 = make_group_update(0xCC, 0x01, 10);
        engine.process(&msg1, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        let msg2 = make_group_update(0xCC, 0x02, 5); // older tick
        let action = engine.process(&msg2, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        assert!(matches!(action, GossipAction::Duplicate));
        let wid = { let mut w = [0u8; 32]; w[0] = 0xCC; w } /* group wallet: zero-pk carve-out, not key-derived */;
        assert_eq!(smt.get(&wid).unwrap().current_state[0], 0x01); // unchanged
    }

    #[test]
    fn gossip_group_banned_wallet_ignored() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let wid = { let mut w = [0u8; 32]; w[0] = 0xDD; w }; // group wallet: zero-pk carve-out
        bans.ban(wid,
            ConflictProof { old_state: [0; 32], new_state: [1; 32], tx_hash: [2; 32], k3_signatures: vec![WitnessSig { validator_pk: [1; 32], signature: vec![1; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 }, WitnessSig { validator_pk: [2; 32], signature: vec![2; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 }, WitnessSig { validator_pk: [3; 32], signature: vec![3; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 }], tick: 0, required_k: 3 },
            ConflictProof { old_state: [0; 32], new_state: [3; 32], tx_hash: [4; 32], k3_signatures: vec![WitnessSig { validator_pk: [1; 32], signature: vec![1; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 }, WitnessSig { validator_pk: [2; 32], signature: vec![2; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 }, WitnessSig { validator_pk: [3; 32], signature: vec![3; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 }], tick: 0, required_k: 3 },
        );

        let msg = make_group_update(0xDD, 0x01, 1);
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        assert!(matches!(action, GossipAction::Duplicate));
        assert_eq!(smt.len(), 0);
    }

    // ── Oracle Pool Sync Tests (Phase 8) ──

    fn make_oracle_sync(date: &str, platform0_remaining: u64, reserve: u64, claims: u64, tick: u64) -> GossipMessage {
        use crate::oracle::DailyPoolState;
        let defaults = DailyPoolState::new();
        let mut pools = defaults.pools;
        // Override platform 0 to specific value; others stay at weighted allocation
        pools[0] = platform0_remaining;
        GossipMessage::OraclePoolSync {
            date: String::from(date),
            pools,
            reserve_left: reserve,
            claims_today: claims,
            tick,
        }
    }

    #[test]
    fn gossip_oracle_sync_updates_pool() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();
        pool.date = String::from("2027-03-15");

        // Remote has lower pool balance (more claims happened)
        let msg = make_oracle_sync("2027-03-15", 1_000, 93_960_000, 5, 200);
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        assert!(matches!(action, GossipAction::Forward(_)));
        assert_eq!(pool.pools[0], 1_000); // took lower value
        assert_eq!(pool.claims_today, 5);
    }

    #[test]
    fn gossip_oracle_sync_no_change_not_forwarded() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();
        pool.date = String::from("2027-03-15");
        pool.pools[0] = 500; // already very low
        pool.claims_today = 100;
        pool.last_tick = 100; // already ahead of remote tick

        // Remote has higher pool balance AND a higher reserve — our state is more
        // conservative. The reserve is derived from the register (KI#164), never
        // typed: a literal here went stale when the Market sub-pool moved.
        let msg = make_oracle_sync("2027-03-15", 2_000,
            crate::constants::TOTAL_RESERVE_AXC + 1, 10, 50);
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        assert!(matches!(action, GossipAction::Duplicate)); // no change, not forwarded
    }

    #[test]
    fn gossip_oracle_sync_deduplicates() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();
        pool.date = String::from("2027-03-15");

        let msg = make_oracle_sync("2027-03-15", 1_000, 93_960_000, 5, 200);

        // First: forwarded
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);
        assert!(matches!(action, GossipAction::Forward(_)));

        // Second: exact duplicate hash → deduplicated before reconciliation
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);
        assert!(matches!(action, GossipAction::Duplicate));
    }

    // ── YPX-009: Client Signature Verification Tests ──

    #[test]
    fn client_sig_valid_accepted() {
        use ed25519_dalek::{SigningKey, Signer as DalekSigner};
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key().to_bytes();

        let wallet_id = [0xAA; 32];
        let new_state = [0xBB; 32];
        let tx_hash = [0xCC; 32];
        let tick = 100u64;

        let _ = tick; // tick is node-stamped, no longer part of the payload (KI#46)
        let payload = super::client_state_sign_payload(&wallet_id, &new_state, &tx_hash);
        let sig = sk.sign(&payload);

        assert!(super::verify_client_state_sig(
            &pk, &sig.to_bytes(), &wallet_id, &new_state, &tx_hash
        ));
    }

    #[test]
    fn client_sig_invalid_rejected() {
        let pk = [0x01; 32]; // not a valid Ed25519 key
        let bad_sig = vec![0u8; 64];
        let wallet_id = [0xAA; 32];
        let new_state = [0xBB; 32];
        let tx_hash = [0xCC; 32];

        assert!(!super::verify_client_state_sig(
            &pk, &bad_sig, &wallet_id, &new_state, &tx_hash
        ));
    }

    #[test]
    fn client_sig_wrong_payload_rejected() {
        use ed25519_dalek::{SigningKey, Signer as DalekSigner};
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key().to_bytes();

        let wallet_id = [0xAA; 32];
        let new_state = [0xBB; 32];
        let tx_hash = [0xCC; 32];

        // Sign for tx_hash A
        let payload = super::client_state_sign_payload(&wallet_id, &new_state, &tx_hash);
        let sig = sk.sign(&payload);

        // Verify against a different tx_hash — should fail
        let other_tx = [0xDD; 32];
        assert!(!super::verify_client_state_sig(
            &pk, &sig.to_bytes(), &wallet_id, &new_state, &other_tx
        ));
    }

    #[test]
    fn gossip_state_update_with_valid_client_sig() {
        use ed25519_dalek::{SigningKey, Signer as DalekSigner};
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key().to_bytes();

        let wallet_id = pk; // KI#226: the key's own row
        let mut new_state = [0u8; 32];
        new_state[0] = 0x01;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = 0xEE ^ 0x01;
        let tick = 5u64;

        let payload = super::client_state_sign_payload(&wallet_id, &new_state, &tx_hash);
        let sig = sk.sign(&payload);

        let msg = GossipMessage::StateUpdate {
                      old_state: [0u8; 32],
                      wallet_seq: 0,
            seq_proof: None,
            wallet_id, new_state, tx_hash, tick,
            is_genesis_claim: false,
            client_pk: pk,
            client_sig: sig.to_bytes().to_vec(),
            amount: 0,
            fee_breakdown: Vec::new(),
        };

        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);
        assert!(matches!(action, GossipAction::Forward(_)));
        assert_eq!(smt.len(), 1);
    }

    #[test]
    fn gossip_flood_rejects_unproven_seq_advance() {
        // WI3 hole-1 (KI#34 §5.4): the flood path (`apply_state_update`) must not
        // let a forged high `wallet_seq` win the merge — a seq-ADVANCE requires a
        // valid carried k=3 proof. (The flood path now ALSO has a consume-once gate
        // for the equal-seq case — see `gossip_flood_rejects_consumed_state_revival`
        // — but the proof gate is what blocks a seq-ADVANCE specifically.)
        use ed25519_dalek::{Signer, SigningKey};
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();
        let wid = SigningKey::from_bytes(&[0x77u8; 32]).verifying_key().to_bytes(); // KI#226: the signing key's own row

        let mint = |txid: &[u8; 32], seq: u64, n: usize| -> crate::types::SeqProof {
            let (state_hash, commitment_hash, epoch, dev) = ([0x5au8; 32], [0x7cu8; 32], 7u64, false);
            let c = axiom_core_logic::compute::compute_receipt_commitment(
                txid, &state_hash, seq, &commitment_hash, epoch, dev, None, None,
                None,
            );
            let sigs = (0..n)
                .map(|i| {
                    let sk = SigningKey::from_bytes(&[0x40 + i as u8; 32]);
                    crate::types::SeqProofSig {
                        validator_pk: sk.verifying_key().to_bytes(),
                        receipt_commitment_sig: sk.sign(&c).to_bytes().to_vec(),
                    }
                })
                .collect();
            crate::types::SeqProof { state_hash, commitment_hash, epoch, is_dev_class: dev, oods_flag: None, confidence_index: None, sigs, sender_state: None, required_k: 3, preimage: crate::types::test_legs::opaque_redeem_leg() /* wave 2a: minted over an arbitrary txid — a Send leg could not reproduce it */, declared: crate::types::test_legs::no_declared() }
        };
        // KI#46 flip: fixtures must be wallet-authored (zero-pk is rejected
        // before the seq gate this test exercises).
        let wallet_sk = SigningKey::from_bytes(&[0x77u8; 32]);
        let client_pk = wallet_sk.verifying_key().to_bytes();
        let msg = |state: u8, tx: [u8; 32], tick: u64, seq: u64, proof: Option<crate::types::SeqProof>| {
            let new_state = [state; 32];
            // W7a: bind a carried proof's redeem leg to this update (forged /
            // sub-quorum slots stay invalid — see `bind_redeem_leg`).
            let proof = proof.map(|mut p| {
                crate::types::test_legs::bind_redeem_leg(&mut p, &tx, client_pk, [0u8; 32], new_state, seq, 0x40);
                p
            });
            let payload = client_state_sign_payload(&wid, &new_state, &tx);
            let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();
            GossipMessage::StateUpdate {
                wallet_id: wid, new_state, tx_hash: tx, tick,
                old_state: [0u8; 32],
            is_genesis_claim: false,
                wallet_seq: seq, client_pk, client_sig,
                amount: 0, fee_breakdown: Vec::new(), seq_proof: proof,
            }
        };
        macro_rules! go {
            ($m:expr) => {
                engine.process(&$m, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0),
                    &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(),
                    &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all)
            };
        }

        // Honest head Y at seq=5 WITH a valid proof → adopted.
        let txid_y = crate::types::test_legs::cheque_txid([0xA1u8; 32]); // KI#241 F-2
        assert!(matches!(go!(msg(0x22, txid_y, 10, 5, Some(mint(&txid_y, 5, 3)))), GossipAction::Forward(_)));
        assert_eq!(smt.get(&wid).unwrap().wallet_seq, 5);

        // Forged seq=99 advance, no proof → dropped, head unchanged.
        assert!(matches!(go!(msg(0x33, [0xB2u8; 32], 99, 99, None)), GossipAction::Duplicate));
        assert_eq!(smt.get(&wid).unwrap().current_state[0], 0x22, "flood head must not roll forward");

        // Honest advance Z at seq=6 WITH a valid proof → adopted + proof retained.
        let txid_z = crate::types::test_legs::cheque_txid([0xD4u8; 32]); // KI#241 F-2
        assert!(matches!(go!(msg(0x55, txid_z, 11, 6, Some(mint(&txid_z, 6, 3)))), GossipAction::Forward(_)));
        assert_eq!(smt.get(&wid).unwrap().wallet_seq, 6);
        assert!(smt.seq_proof(&wid).is_some());
    }

    #[test]
    fn gossip_flood_rejects_consumed_state_revival() {
        // THREAT §5.4 (KI#34) — the EQUAL-seq rollback the seq gate alone misses.
        // The seq-advance gate only blocks a seq going UP without a proof; a
        // candidate stamped at the SAME seq as the current head falls through to the
        // `superseded_by` tick tiebreaker, so a forged HIGHER-tick re-advertisement
        // of an already-consumed state would roll the flood-path head back to the
        // spent state with NO proof required. This is the KI#34 revival reproduced
        // live by `examples/ki34_wi1_recover` (it FAILED here before the consume-once
        // gate was mirrored from the AE path onto the flood path). The fix: drop any
        // candidate whose `new_state` is in this node's monotonic consumed-set.
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();
        let wid = SigningKey::from_bytes(&[0x78u8; 32]).verifying_key().to_bytes(); // KI#226: the signing key's own row
        let (x, y) = ([0xA0u8; 32], [0xA1u8; 32]);
        // KI#46 flip: fixtures must be wallet-authored (zero-pk is rejected
        // before the consume-once gate this test exercises).
        use ed25519_dalek::{Signer as _, SigningKey};
        let wallet_sk = SigningKey::from_bytes(&[0x78u8; 32]);
        let client_pk = wallet_sk.verifying_key().to_bytes();
        let msg = |state: [u8; 32], tx: [u8; 32], tick: u64| {
            let payload = client_state_sign_payload(&wid, &state, &tx);
            let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();
            GossipMessage::StateUpdate {
                wallet_id: wid, new_state: state, tx_hash: tx, tick,
                old_state: [0u8; 32],
                is_genesis_claim: false,
                wallet_seq: 0, client_pk, client_sig,
                amount: 0, fee_breakdown: Vec::new(), seq_proof: None,
            }
        };
        macro_rules! go {
            ($m:expr) => {
                engine.process(&$m, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0),
                    &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(),
                    &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all)
            };
        }

        // Advance X → Y on the tick path (equal seq 0): X becomes consumed.
        assert!(matches!(go!(msg(x, [0xB0u8; 32], 1)), GossipAction::Forward(_)));
        assert!(matches!(go!(msg(y, [0xB1u8; 32], 2)), GossipAction::Forward(_)));
        assert_eq!(smt.get(&wid).unwrap().current_state, y);
        assert!(smt.is_state_consumed(&x), "X must be consumed after X→Y");

        // Forged higher-tick (9999) re-advertisement of consumed X at equal seq,
        // no proof → MUST be rejected; head stays Y. Pre-fix this won the tick
        // tiebreaker and rolled the head back to the spent state.
        assert!(matches!(go!(msg(x, [0xBFu8; 32], 9999)), GossipAction::Duplicate));
        assert_eq!(
            smt.get(&wid).unwrap().current_state, y,
            "§5.4: flood path must not revive a consumed state via the tick tiebreaker"
        );
    }

    #[test]
    fn gossip_state_update_with_invalid_client_sig_dropped() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        // Non-zero pk but bad sig — should be dropped
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = 0xFF;
        let mut new_state = [0u8; 32];
        new_state[0] = 0x01;

        // Use a valid Ed25519 pk but wrong sig
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[99u8; 32]);
        let pk = sk.verifying_key().to_bytes();

        let msg = GossipMessage::StateUpdate {
                      old_state: [0u8; 32],
                      wallet_seq: 0,
            seq_proof: None,
            wallet_id, new_state,
            tx_hash: [0xDD; 32],
            tick: 5,
            is_genesis_claim: false,
            client_pk: pk,
            client_sig: vec![0xBA; 64], // invalid sig
            amount: 0,
            fee_breakdown: Vec::new(),
        };

        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);
        assert!(matches!(action, GossipAction::Duplicate)); // dropped silently
        assert_eq!(smt.len(), 0); // not inserted
    }

    #[test]
    fn gossip_state_update_zero_pk_rejected() {
        // KI#46 zero-pk flip (YPX-009 ENFORCED): an unauthored StateUpdate is
        // REJECTED — the pre-flip behavior ("legacy pre-YPX-009 accepted
        // without sig check") is gone; every producer signs now.
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg = match make_state_update(0xDD, 0x01, 5) {
            GossipMessage::StateUpdate { wallet_id, new_state, tx_hash, tick, is_genesis_claim, wallet_seq, old_state, amount, fee_breakdown, seq_proof, .. } =>
                GossipMessage::StateUpdate {
                    wallet_id, new_state, tx_hash, tick, is_genesis_claim, wallet_seq, old_state,
                    client_pk: [0u8; 32], client_sig: vec![],
                    amount, fee_breakdown, seq_proof,
                },
            _ => unreachable!(),
        };
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);

        assert!(matches!(action, GossipAction::Duplicate), "zero-pk must be rejected (not forwarded)");
        assert_eq!(smt.len(), 0, "zero-pk must never enter the SMT");
    }

    #[test]
    fn client_sig_payload_covers_all_fields() {
        // Changing any single field should produce a different payload
        let w = [0xAA; 32];
        let s = [0xBB; 32];
        let t = [0xCC; 32];

        let baseline = super::client_state_sign_payload(&w, &s, &t);

        let mut w2 = w;
        w2[0] = 0x00;
        assert_ne!(baseline, super::client_state_sign_payload(&w2, &s, &t));

        let mut s2 = s;
        s2[0] = 0x00;
        assert_ne!(baseline, super::client_state_sign_payload(&w, &s2, &t));

        let mut t2 = t;
        t2[0] = 0x00;
        assert_ne!(baseline, super::client_state_sign_payload(&w, &s, &t2));
    }

    /// KI#46: the payload is MIRRORED in axiom-sdk (the client signs, this
    /// crate verifies). Pin the exact bytes so the two implementations can
    /// never drift silently — the SDK carries the identical vector test
    /// (`client_state_payload_pinned_vector`). If this assert ever needs a
    /// new constant, change BOTH crates in the same commit.
    #[test]
    fn client_state_payload_pinned_vector() {
        let payload = super::client_state_sign_payload(&[0x11; 32], &[0x22; 32], &[0x33; 32]);
        assert_eq!(
            hex::encode(payload),
            "671ddff46c3f61b16a08bb378fc22546066759306747f5cae69fde9afa5dc55e",
        );
    }

    // ── YPX-009: Pulse Proof Gossip Tests ──

    #[test]
    fn pulse_proof_sign_verify_roundtrip() {
        use ed25519_dalek::{SigningKey, Signer};
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vpk: [u8; 32] = sk.verifying_key().to_bytes();
        let epoch = 5u64;
        let acc = [0xAA; 32];
        let audit = [0xBB; 32];

        let payload = super::pulse_proof_sign_payload(&vpk, epoch, &acc, &audit, None);
        let sig = sk.sign(&payload);

        assert!(super::verify_pulse_proof_sig(&vpk, sig.to_bytes().as_ref(), &payload));
        println!("  ✓ Pulse proof sign/verify roundtrip");
    }

    #[test]
    fn pulse_proof_reject_bad_sig() {
        let vpk = [1u8; 32]; // not a valid key for this sig
        let payload = super::pulse_proof_sign_payload(&vpk, 1, &[0; 32], &[0; 32], None);
        let bad_sig = [0u8; 64];
        assert!(!super::verify_pulse_proof_sig(&vpk, &bad_sig, &payload));
        println!("  ✓ Invalid pulse proof signature rejected");
    }

    #[test]
    fn pulse_proof_domain_separation() {
        let vpk = [1u8; 32];
        let epoch = 1u64;
        let acc1 = [0xAA; 32];
        let acc2 = [0xBB; 32];
        let audit = [0xCC; 32];

        let p1 = super::pulse_proof_sign_payload(&vpk, epoch, &acc1, &audit, None);
        let p2 = super::pulse_proof_sign_payload(&vpk, epoch, &acc2, &audit, None);
        assert_ne!(p1, p2, "different accumulators must produce different payloads");

        let p3 = super::pulse_proof_sign_payload(&vpk, epoch + 1, &acc1, &audit, None);
        assert_ne!(p1, p3, "different epochs must produce different payloads");
        println!("  ✓ Pulse proof domain separation verified");
    }

    #[test]
    fn pulse_proof_gossip_forwarding() {
        use ed25519_dalek::{SigningKey, Signer as _};
        use crate::types::GossipMessage;

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vpk: [u8; 32] = sk.verifying_key().to_bytes();
        let epoch = 3u64;
        let acc = [0xDD; 32];
        let audit = [0xEE; 32];

        let payload = super::pulse_proof_sign_payload(&vpk, epoch, &acc, &audit, None);
        let sig = sk.sign(&payload);

        let msg = GossipMessage::PulseProof {
            validator_pk: vpk,
            epoch,
            full_accumulator: acc,
            entry_count: 100,
            sample_size: 5,
            audit_hash: audit,
            argon2id_per_sec: 2000,
            signature: sig.to_bytes().to_vec(),
            tick: 2160,
        };

        let mut engine = super::GossipEngine::new();
        let mut pool = crate::oracle::DailyPoolState::default();
        let action = engine.process(&msg, &mut crate::smt::SparseMerkleTree::new(),
                                     &mut crate::ban::BanTable::new(), &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);
        match action {
            super::GossipAction::Forward(_) => println!("  ✓ Valid PulseProof forwarded"),
            _ => panic!("expected Forward for valid PulseProof"),
        }
    }

    /// §7 the one new PoolSync arm — Bounded-Fee reconcile: HOLD an increase
    /// whose authorising statement we have not judged (§4.1, never accuse),
    /// ADOPT when the epoch's verified credit matches, and QUARANTINE only a
    /// disprovable (epoch-judged, amount-mismatched) increase.
    #[test]
    fn bounded_fee_poolsync_arm_holds_adopts_and_violates() {
        use crate::types::{GossipMessage, PoolKind};
        let vid = [0x9au8; 32];
        let et = crate::constants::fob_epoch_span_secs(false); // KI#165: the same projected span the arm divides by
        let tick = et; // epoch = 1
        let epoch = tick / et;
        let amt = 3_000_000_000u64;
        let mk = |bal: u64| GossipMessage::PoolSync {
            pool: PoolKind::BoundedFee(vid, false),
            balance: bal,
            total_claims: bal,
            // KI#191 — BoundedFee is a two-state tranche pool judged by its own
            // arm, not by the drain-pool conservation identity; these carry no
            // meaning for it.
            paid_out: 0,
            topped_up: 0,
            tick,
            sender_node_id: [1u8; 32],
            sender_sig: vec![],
        };
        let run = |msg: &GossipMessage,
                   fob_pools: &mut std::collections::HashMap<([u8; 32], bool), crate::fob::FobPool>,
                   fob_credits: &std::collections::HashMap<
            u64,
            std::collections::HashMap<([u8; 32], bool), u64>,
        >| {
            let mut engine = super::GossipEngine::new();
            let mut pool = crate::oracle::DailyPoolState::default();
            engine.process(
                msg,
                &mut crate::smt::SparseMerkleTree::new(),
                &mut crate::ban::BanTable::new(),
                &mut pool,
                &mut AirdropPool::new(0),
                &mut crate::node::DevTreasuryPool::new(0),
                &mut AirdropPool::new(0),
                &mut AirdropPool::new(0),
                &mut crate::node::DeedPool::new(),
                &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0),
                fob_pools,
                fob_credits,
                tick, 0,
                1, &crate::types::test_legs::dir_admits_all,
            )
        };

        // (1) increase, epoch NOT judged (no credit) → HOLD (Duplicate/NoOp),
        //     pool untouched — a stale auditor must NEVER accuse (§4.1).
        let mut pools = std::collections::HashMap::new();
        let none = std::collections::HashMap::new();
        let a = run(&mk(amt), &mut pools, &none);
        assert!(matches!(a, super::GossipAction::Duplicate), "unjudged increase must HOLD, got {a:?}");
        assert_eq!(pools.get(&(vid, false)).map(|p| p.balance()).unwrap_or(0), 0);

        // (2) verified credit matches the advertised balance → ADOPT.
        let mut credits: std::collections::HashMap<u64, std::collections::HashMap<([u8; 32], bool), u64>> =
            std::collections::HashMap::new();
        credits.entry(epoch).or_default().insert((vid, false), amt);
        let mut pools = std::collections::HashMap::new();
        let a = run(&mk(amt), &mut pools, &credits);
        assert!(matches!(a, super::GossipAction::Forward(_)), "matching credit must adopt, got {a:?}");
        assert_eq!(pools.get(&(vid, false)).unwrap().balance(), amt, "adopted the tranche amount");

        // (3) epoch judged but amount MISMATCHES the credit → StructuralViolation.
        let mut pools = std::collections::HashMap::new();
        let a = run(&mk(amt + 1), &mut pools, &credits);
        assert!(
            matches!(
                a,
                super::GossipAction::PoolStructuralViolation {
                    proof: crate::judoon::ProofKind::BoundedFeeConservation,
                    ..
                }
            ),
            "amount mismatch must be a Bounded-Fee structural violation, got {a:?}"
        );
        assert_eq!(pools.get(&(vid, false)).map(|p| p.balance()).unwrap_or(0), 0, "violation is not applied");
    }

    #[test]
    fn pulse_proof_empty_audit_dropped() {
        use ed25519_dalek::{SigningKey, Signer as _};
        use crate::types::GossipMessage;

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vpk: [u8; 32] = sk.verifying_key().to_bytes();
        let payload = super::pulse_proof_sign_payload(&vpk, 1, &[0; 32], &[0; 32], None);
        let sig = sk.sign(&payload);

        let msg = GossipMessage::PulseProof {
            validator_pk: vpk,
            epoch: 1,
            full_accumulator: [0; 32],
            entry_count: 0, // empty audit
            sample_size: 0,
            audit_hash: [0; 32],
            argon2id_per_sec: 2000,
            signature: sig.to_bytes().to_vec(),
            tick: 5,
        };

        let mut engine = super::GossipEngine::new();
        let mut pool = crate::oracle::DailyPoolState::default();
        let action = engine.process(&msg, &mut crate::smt::SparseMerkleTree::new(),
                                     &mut crate::ban::BanTable::new(), &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);
        match action {
            super::GossipAction::Duplicate => println!("  ✓ Empty audit PulseProof dropped"),
            _ => panic!("expected Duplicate (drop) for empty audit PulseProof"),
        }
    }

    #[test]
    fn pulse_proof_zero_throughput_dropped() {
        use ed25519_dalek::{SigningKey, Signer as _};
        use crate::types::GossipMessage;

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vpk: [u8; 32] = sk.verifying_key().to_bytes();
        let acc = [0xAA; 32];
        let audit = [0xBB; 32];

        let payload = super::pulse_proof_sign_payload(&vpk, 1, &acc, &audit, None);
        let sig = sk.sign(&payload);

        // Zero throughput = benchmark never ran (protocol violation)
        let msg = GossipMessage::PulseProof {
            validator_pk: vpk,
            epoch: 1,
            full_accumulator: acc,
            entry_count: 100,
            sample_size: 5,
            audit_hash: audit,
            argon2id_per_sec: 0, // invalid — no benchmark
            signature: sig.to_bytes().to_vec(),
            tick: 5,
        };

        let mut engine = super::GossipEngine::new();
        let mut pool = crate::oracle::DailyPoolState::default();
        let action = engine.process(&msg, &mut crate::smt::SparseMerkleTree::new(),
                                     &mut crate::ban::BanTable::new(), &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut AirdropPool::new(0), &mut AirdropPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0), &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all);
        match action {
            super::GossipAction::Duplicate => {
                println!("  ✓ Zero-throughput PulseProof rejected");
            }
            _ => panic!("expected Duplicate (drop) for zero-throughput PulseProof"),
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // YP §19.6 — gossip-driven txid_records propagation
    // ───────────────────────────────────────────────────────────────────

    use axiom_core_logic::types::FeeShare;

    /// Build a StateUpdate carrying a non-empty fee_breakdown that fits
    /// the per-validator + aggregate caps (3 × 30 bps × 1_000_000 =
    /// 9000 atoms total, on a 1M-atom TX).
    fn vid_byte(b: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = b;
        v
    }

    fn make_fee_state_update(wid: u8, state: u8, tick: u64, amount: u64) -> GossipMessage {
        let wallet_id = ds_wid(wid); // KI#226: the signing key's own row
        let mut new_state = [0u8; 32];
        new_state[0] = state;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = wid ^ state ^ 0x80;
        let cap = (amount * 30) / 10_000;
        let fee_breakdown = vec![
            FeeShare { validator_id: vid_byte(0x11), amount: cap },
            FeeShare { validator_id: vid_byte(0x22), amount: cap },
            FeeShare { validator_id: vid_byte(0x33), amount: cap },
        ];
        // KI#46 flip: fixture is wallet-authored (zero-pk rejected upstream
        // of the fee-record logic this helper exercises).
        use ed25519_dalek::{Signer as _, SigningKey};
        let wallet_sk = SigningKey::from_bytes(&[wid.wrapping_add(0xC0); 32]);
        let client_pk = wallet_sk.verifying_key().to_bytes();
        let payload = client_state_sign_payload(&wallet_id, &new_state, &tx_hash);
        let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();
        GossipMessage::StateUpdate {
            old_state: [0u8; 32],
            wallet_seq: 0,
            seq_proof: None,
            wallet_id, new_state, tx_hash, tick,
            is_genesis_claim: false,
            client_pk, client_sig,
            amount, fee_breakdown,
        }
    }

    #[test]
    fn gossip_state_update_with_fees_records_in_hashmap_mode() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::with_txid_mode(crate::bloom::TxidServiceMode::Hashmap);
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg = make_fee_state_update(0xAA, 0x01, 5, 1_000_000);
        let action = engine.process(
            &msg, &mut smt, &mut bans, &mut pool,
            &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0),
            &mut AirdropPool::new(0), &mut AirdropPool::new(0),
            &mut crate::node::DeedPool::new(),
            &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0),
            &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all,
        );
        assert!(matches!(action, GossipAction::Forward(_)));
        // The hashmap node must now hold the per-tx record, and each
        // slot's validator should appear in the validator_earnings index.
        assert_eq!(smt.tx_records_len(), 1);
        let cap = (1_000_000_u64 * 30) / 10_000;
        for b in [0x11u8, 0x22, 0x33] {
            assert_eq!(smt.validator_earnings(&vid_byte(b), 0).0, cap,
                "validator {:02x} earnings must match the gossiped slot", b);
        }
    }

    /// YPX-022 §5 REDEEMED parity (same class as the B2 completed fix): a
    /// k-attested StateUpdate carrying the receiver-pays signal (non-empty
    /// fee_breakdown = redeem-finalize, the registration.rs 8b'' predicate)
    /// must mark the txid REDEEMED on the receiving node too — else a
    /// gossip-only node accepts a recall of an already-redeemed txid.
    /// An UNATTESTED update with fees must NOT mark it (a forged update
    /// could otherwise poison the terminal and strand a legitimate recall).
    #[test]
    fn gossip_attested_redeem_finalize_marks_txid_redeemed() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());

        // Attested redeem-finalize: seq proof + in-cap fee_breakdown.
        let amount = 1_000_000u64;
        let cap = (amount * 30) / 10_000;
        let wallet_id = ds_wid(0xD7); // KI#226: the signing key's own row
        let mut new_state = [0u8; 32]; new_state[0] = 0x01;
        let mut tag = [0u8; 32]; tag[0] = 0xD7 ^ 0x01;
        let tx_hash = crate::types::test_legs::cheque_txid(tag); // KI#241 F-2: a redeem leg's txid has an origin
        let mut proof = ds_mint_seq_proof(&tx_hash, 5, 3);
        let wallet_sk = SigningKey::from_bytes(&[0xD7u8.wrapping_add(0xC0); 32]);
        let client_pk = wallet_sk.verifying_key().to_bytes();
        // W7a: an attested redeem-finalize carries a GENUINE redeem leg.
        crate::types::test_legs::bind_redeem_leg(&mut proof, &tx_hash, client_pk, [0u8; 32], new_state, 5, 0x10);
        let payload = client_state_sign_payload(&wallet_id, &new_state, &tx_hash);
        let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();
        let attested_redeem = GossipMessage::StateUpdate {
            old_state: [0u8; 32],
            wallet_seq: 5, seq_proof: Some(proof),
            wallet_id, new_state, tx_hash, tick: 10,
            is_genesis_claim: false,
            client_pk, client_sig, amount,
            fee_breakdown: vec![
                FeeShare { validator_id: vid_byte(0x11), amount: cap },
                FeeShare { validator_id: vid_byte(0x22), amount: cap },
                FeeShare { validator_id: vid_byte(0x33), amount: cap },
            ],
        };
        let action = ds_proc(&mut e, &mut smt, &mut bans, &attested_redeem);
        assert!(matches!(action, GossipAction::Forward(_)));
        assert!(smt.is_txid_completed(&tx_hash), "B2: attested advance marks completed");
        assert!(smt.is_txid_redeemed(&tx_hash),
            "attested redeem-finalize gossip must mark REDEEMED — a gossip-only \
             node must refuse a recall of a redeemed txid");

        // Unattested update with fees: fee record may apply, terminal must NOT.
        let unattested = make_fee_state_update(0xD8, 0x01, 11, amount);
        let tx_unatt = {
            let mut t = [0u8; 32]; t[0] = 0xD8 ^ 0x01 ^ 0x80; t
        };
        let action = ds_proc(&mut e, &mut smt, &mut bans, &unattested);
        assert!(matches!(action, GossipAction::Forward(_)));
        assert!(!smt.is_txid_redeemed(&tx_unatt),
            "an UNATTESTED update must never poison the REDEEMED terminal");
    }

    #[test]
    fn gossip_state_update_no_op_on_bloom_mode() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::with_txid_mode(crate::bloom::TxidServiceMode::Bloom);
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg = make_fee_state_update(0xAA, 0x01, 5, 1_000_000);
        let action = engine.process(
            &msg, &mut smt, &mut bans, &mut pool,
            &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0),
            &mut AirdropPool::new(0), &mut AirdropPool::new(0),
            &mut crate::node::DeedPool::new(),
            &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0),
            &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all,
        );
        assert!(matches!(action, GossipAction::Forward(_)));
        // Bloom-mode node still forwards the state update (the rest of
        // the gossip applies) but DOES NOT persist the per-tx record.
        assert_eq!(smt.tx_records_len(), 0);
    }

    #[test]
    fn gossip_over_cap_fee_breakdown_is_dropped() {
        // Per-validator slot exceeds MAX_VALIDATOR_FEE_BPS — the gossip-side
        // cap check (validate_fee_breakdown in apply_fee_record_from_gossip)
        // drops the record without affecting the state update.
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::with_txid_mode(crate::bloom::TxidServiceMode::Hashmap);
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        // 50 bps per validator > 30 bps cap → reject the record.
        // KI#46 flip: authored fixture — the update must survive the
        // authorship gate to reach the fee-cap check under test.
        use ed25519_dalek::{Signer as _, SigningKey};
        let amount = 1_000_000_u64;
        let over_cap = (amount * 50) / 10_000;
        let (new_state, tx_hash) = ([0x01; 32], [0x77; 32]);
        let wallet_sk = SigningKey::from_bytes(&[0x79u8; 32]);
        let client_pk = wallet_sk.verifying_key().to_bytes();
        let wallet_id = client_pk; // KI#226: the signing key's own row
        let payload = client_state_sign_payload(&wallet_id, &new_state, &tx_hash);
        let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();
        let msg = GossipMessage::StateUpdate {
                      old_state: [0u8; 32],
                      wallet_seq: 0,
            seq_proof: None,
            wallet_id, new_state,
            tx_hash, tick: 5,
            is_genesis_claim: false,
            client_pk, client_sig,
            amount,
            fee_breakdown: vec![
                FeeShare { validator_id: vid_byte(0x11), amount: over_cap },
            ],
        };
        let action = engine.process(
            &msg, &mut smt, &mut bans, &mut pool,
            &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0),
            &mut AirdropPool::new(0), &mut AirdropPool::new(0),
            &mut crate::node::DeedPool::new(),
            &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0),
            &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all,
        );
        // State update still propagates — only the record is dropped.
        assert!(matches!(action, GossipAction::Forward(_)));
        assert_eq!(smt.tx_records_len(), 0,
            "over-cap fee_breakdown gossip must NOT land in txid_records");
    }

    #[test]
    fn gossip_duplicate_tx_hash_deduplicates_record() {
        // Same tx_hash gossiped twice (race condition between origin's
        // direct gossip and a re-broadcast from another peer) — record_tx_meta
        // dedups on tx_hash so totals don't double.
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::with_txid_mode(crate::bloom::TxidServiceMode::Hashmap);
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg1 = make_fee_state_update(0xAA, 0x01, 5, 1_000_000);
        // Build a second message with the SAME tx_hash but later tick so
        // it wins the state merge (otherwise apply_state_update returns
        // Duplicate before reaching record_tx_meta).
        let mut msg2 = make_fee_state_update(0xAA, 0x02, 6, 1_000_000);
        if let GossipMessage::StateUpdate { tx_hash, .. } = &mut msg2 {
            // Force same tx_hash as msg1.
            *tx_hash = if let GossipMessage::StateUpdate { tx_hash, .. } = &msg1 {
                *tx_hash
            } else { unreachable!() };
        }

        engine.process(
            &msg1, &mut smt, &mut bans, &mut pool,
            &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0),
            &mut AirdropPool::new(0), &mut AirdropPool::new(0),
            &mut crate::node::DeedPool::new(),
            &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0),
            &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all,
        );
        engine.process(
            &msg2, &mut smt, &mut bans, &mut pool,
            &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0),
            &mut AirdropPool::new(0), &mut AirdropPool::new(0),
            &mut crate::node::DeedPool::new(),
            &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0),
            &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all,
        );

        assert_eq!(smt.tx_records_len(), 1,
            "duplicate tx_hash gossip must produce exactly one record");
        let cap = (1_000_000_u64 * 30) / 10_000;
        assert_eq!(smt.validator_earnings(&vid_byte(0x11), 0).0, cap,
            "validator earnings must not double-count on duplicate tx_hash");
    }

    #[test]
    fn gossip_losing_merge_does_not_record_fees() {
        // Pre-load an entry at tick=10. Gossip an older (tick=5) StateUpdate
        // with fee_breakdown for the SAME wallet — it loses the superseded_by
        // merge, so the fee record must NOT be written.
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::with_txid_mode(crate::bloom::TxidServiceMode::Hashmap);
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        // Pre-populate with a newer AUTHORED entry (no fee record). The pk
        // must be non-zero: since the 2026-08-01 legitimacy rank (rule 1b in
        // `superseded_by`) an unauthored non-group entry loses to ANY
        // authored incoming regardless of tick — a zero-pk fixture here
        // would make the stale update win for the wrong reason.
        let wallet_id = ds_wid(0xAA); // KI#226: the signing key's own row
        smt.put(&NablaEntry {
                     received_from: None,
                     wallet_seq: 0,
            wallet_id,
            current_state: [0x05; 32],
            tx_hash: [0x99; 32],
            tick: 10,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: [0xC0; 32],
            client_sig: vec![0u8; 64],
        });

        // Now gossip a stale (tick=5) update WITH fees — it should lose
        // the merge and the record must not land.
        let stale = make_fee_state_update(0xAA, 0x01, 5, 1_000_000);
        let action = engine.process(
            &stale, &mut smt, &mut bans, &mut pool,
            &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0),
            &mut AirdropPool::new(0), &mut AirdropPool::new(0),
            &mut crate::node::DeedPool::new(),
            &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0),
            &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), 0, 0, 1, &crate::types::test_legs::dir_admits_all,
        );
        assert!(matches!(action, GossipAction::Duplicate),
            "stale state update must lose the superseded_by merge");
        assert_eq!(smt.tx_records_len(), 0,
            "losing merge must NOT persist the fee record");
    }

    // ───────────────────────────────────────────────────────────────────────
    // KI#34 check-3 — HAL-revival fork-ban (endorsement model) A/B/C harness.
    //
    // Threat: a wiped/colluding subset re-witnesses an ALREADY-CONSUMED state
    // X (spent to reach head Y) into a fresh head X', double-realizing X's
    // value. HAL is the only path that relaxes the dead-overlap gate, and it
    // rests on the lossy consume-once bloom — which a wipe can clear. The
    // defence is the ENDORSEMENT model: every honest holder that retained the
    // EXACT consumed state (`previous_state`, not the bloom) detects the fork
    // against its OWN view, freezes locally, and forwards so peers re-detect.
    //
    // These three scenarios are the deterministic gossip-level gate. The full
    // running-validator soak (scenarios A/B/C against live Lambda+Nabla) is the
    // separate HARD-RULE merge gate; this proves the detection core in-tree.
    // ───────────────────────────────────────────────────────────────────────

    /// KI#226: a fixture wallet's id is its signing key's own row
    /// (`make_state_update` signs with `[b + 0xC0; 32]`).
    fn wid(b: u8) -> WalletId {
        ds_wid(b)
    }
    fn st(b: u8) -> StateId {
        let mut s = [0u8; 32];
        s[0] = b;
        s
    }

    /// The pre-B2 `HalAdvance` witness field — content is irrelevant (the arm
    /// is a tombstone since §9q and verifies nothing); kept so the tombstone
    /// tests send the exact shape a pre-B2 build emits.
    fn k3_sigs(n: usize) -> Vec<WitnessSig> {
        (0..n)
            .map(|i| WitnessSig {
                validator_pk: [i as u8 + 1; 32],
                signature: vec![i as u8 + 1; 64],
                execution_proof: vec![],
                proof_type: 0,
                receipt_commitment_sig: vec![],
                validator_id: [0u8; 32],
                slot_amount: 0,
            })
            .collect()
    }

    fn make_hal_advance(
        w: u8,
        old: u8,
        new: u8,
        tick: u64,
        n_sigs: usize,
    ) -> GossipMessage {
        // A pre-B2 `HalAdvance`, wallet-authored (same wid-derived key scheme
        // as ds_attested) — the shape the retired E3 arm judged.
        use ed25519_dalek::{Signer as _, SigningKey};
        let wallet_id = wid(w);
        let new_state = st(new);
        let tx_hash = st(w ^ new ^ 0x5A);
        let wallet_sk = SigningKey::from_bytes(&[w.wrapping_add(0xC0); 32]);
        let client_pk = wallet_sk.verifying_key().to_bytes();
        let payload = client_state_sign_payload(&wallet_id, &new_state, &tx_hash);
        let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();
        GossipMessage::HalAdvance {
            wallet_id,
            old_state: st(old),
            new_state,
            tx_hash,
            tick,
            client_pk,
            client_sig,
            k3_signatures: k3_sigs(n_sigs),
            amount: 0,
            fee_breakdown: Vec::new(),
            required_k: 3,
        }
    }

    /// One independent mesh participant: its own engine + SMT + bans + pool, so
    /// detection is exercised exactly as it runs per-node (no shared dedup/state).
    struct Node {
        engine: GossipEngine,
        smt: SparseMerkleTree,
        bans: BanTable,
        pool: DailyPoolState,
    }
    impl Node {
        fn new() -> Self {
            Node {
                engine: GossipEngine::new(),
                smt: SparseMerkleTree::new(),
                bans: BanTable::new(),
                pool: DailyPoolState::new(),
            }
        }
        fn feed(&mut self, msg: &GossipMessage, tick: u64) -> GossipAction {
            self.engine.process(
                msg, &mut self.smt, &mut self.bans, &mut self.pool,
                &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0),
            &mut AirdropPool::new(0), &mut AirdropPool::new(0),
                &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &mut crate::emission::EmissionPools::new_from_registers(0),
                &mut std::collections::HashMap::new(), &std::collections::HashMap::new(), tick, 0, 1, &crate::types::test_legs::dir_admits_all,
            )
        }
        /// Drive this node to head Y via X: genesis X, then advance X→Y. After
        /// this `previous_state(W) == X` (the overwritten head the retired E3
        /// arm keyed on — the predicate the tombstone tests put in place, so a
        /// re-added E3 would fire on them) and the head is Y.
        fn anchor_x_then_y(&mut self, w: u8, x: u8, y: u8) {
            self.feed(&make_state_update(w, x, 1), 1);
            self.feed(&make_state_update(w, y, 2), 2);
            assert_eq!(self.smt.previous_state(&wid(w)), Some(st(x)),
                "setup: node must retain X as the consumed previous_state");
            assert_eq!(self.smt.get(&wid(w)).unwrap().current_state, st(y),
                "setup: node head must be Y");
        }
        fn head(&self, w: u8) -> Option<StateId> {
            self.smt.get(&wid(w)).map(|e| e.current_state)
        }
        fn status(&self, w: u8) -> Option<WalletStatus> {
            self.smt.get(&wid(w)).map(|e| e.status)
        }
        fn frozen(&self, w: u8) -> bool {
            self.status(w) == Some(WalletStatus::Frozen)
        }
    }

    // ── KI#34 check-3 / YPX-025 E3 → A1 (Fork Settlement §9q, design B2) ────
    //
    // The E3 arm froze W when a `HalAdvance` from X met a node whose
    // `previous_states[W] == X`. It is RETIRED: a HAL re-anchor floods as a
    // plain `StateUpdate` with its SeqProof (`registration.rs` step 10), so a
    // revival is the A1 fork every other double spend is — two wallet-signed,
    // k-witnessed legs under one `(pk, consumed)` key → `apply_fork_verdict`
    // (a permanent ban on evidence, never a local freeze). `HalAdvance` is a
    // dropped, counted tombstone. The tests below are the pre-B2 KI#34
    // scenarios rewritten to that expectation; each says what changed and why.

    /// X→Y (the spend) and X→X′ (the HAL re-anchor, a self-send) — genuine
    /// legs from the ONE builder, both from the wallet's opening state X.
    fn b2_legs(seed: u8) -> (crate::types::ForkLeg, crate::types::ForkLeg, StateId) {
        let sk = crate::types::test_legs::wallet(seed);
        let x = crate::types::test_legs::opening(&sk);
        let spend = w3_leg(seed, x, 1, "q@axiom.internal/0123456789", 20, 2);
        let hal = w3_leg(seed, x, 1, "self@axiom.internal/0123456789", 1, 3);
        assert_ne!(spend.tx_hash, hal.tx_hash, "fixture: two txids");
        (spend, hal, x)
    }

    fn fork_evidence_names(n: &Node, pk: &WalletId, legs: &[&crate::types::ForkLeg]) -> bool {
        match n.bans.get(pk).map(|b| &b.evidence) {
            Some(BanEvidence::Fork(c)) => {
                crate::ban::verify_fork_claim(c).is_ok()
                    && legs.iter().any(|l| l.tx_hash == c.a.tx_hash)
                    && legs.iter().any(|l| l.tx_hash == c.b.tx_hash)
            }
            _ => false,
        }
    }

    /// KI#233 — a forged revival must freeze / ban NOBODY, in BOTH shapes a
    /// third party can send:
    /// (1) the pre-B2 `HalAdvance` carrier, three attacker-made "witness" keys
    ///     and the attacker's own key as the wallet half — now a tombstone:
    ///     dropped + counted, never frozen (was: dropped by the KI#233
    ///     wallet-signature gate; the assertion "not frozen" is unchanged);
    /// (2) the B2 carrier — the HAL leg re-witnessed by junk keys and signed by
    ///     the attacker over W's bucket (`StateUpdate`): refused at the KI#226
    ///     key/bucket gate before any record, so no claim can name W.
    /// MUTATION (run 2026-09-30): make the tombstone arm call
    /// `TardisNode::freeze_wallet` ⇒ RED at (1) "FORGED FREEZE".
    #[test]
    fn hal_forged_freeze_with_self_made_keys() {
        use ed25519_dalek::{Signer as _, SigningKey};
        const W: u8 = 0xB7;
        let mut honest = Node::new();
        honest.anchor_x_then_y(W, 0x01 /*X*/, 0x02 /*Y*/);
        let tick = 0u64;
        let payload = crate::crypto::receipt_sign_payload(&wid(W), &st(0x01), tick);
        let forged: Vec<WitnessSig> = (0..3u8)
            .map(|i| {
                let sk = SigningKey::from_bytes(&[0xE0 + i; 32]); // attacker-made, no VBC
                WitnessSig {
                    validator_pk: sk.verifying_key().to_bytes(),
                    signature: sk.sign(&payload).to_bytes().to_vec(),
                    execution_proof: vec![],
                    proof_type: 0,
                    receipt_commitment_sig: vec![],
                    validator_id: [0u8; 32],
                    slot_amount: 0,
                }
            })
            .collect();
        let mut msg = make_hal_advance(W, 0x01, 0x03, tick, 0);
        let attacker = SigningKey::from_bytes(&[0xEE; 32]);
        if let GossipMessage::HalAdvance { k3_signatures, client_pk, client_sig, wallet_id, new_state, tx_hash, .. } = &mut msg {
            *k3_signatures = forged;
            *client_pk = attacker.verifying_key().to_bytes();
            *client_sig = attacker
                .sign(&client_state_sign_payload(wallet_id, new_state, tx_hash))
                .to_bytes().to_vec();
        }
        let action = honest.feed(&msg, tick);
        assert!(!honest.frozen(W),
            "FORGED FREEZE: an honest holder froze W on three self-made, non-validator keys");
        assert!(matches!(action, GossipAction::Duplicate), "(1) a HalAdvance is never forwarded");
        assert_eq!(honest.engine.haladvance_dropped(), 1, "(1) the drop is COUNTED (/status)");
        assert_eq!(honest.head(W), Some(st(0x02)), "(1) head untouched");

        // (2) the B2 carrier, forged by a third party.
        let seed = 0xB6u8;
        let (spend, hal, x) = b2_legs(seed);
        let victim = w3_pk(seed);
        let mut n = Node::new();
        n.feed(&w3_flood(&spend, x, 5), 5);
        let junk: Vec<SigningKey> = (0..3u8).map(crate::types::test_legs::junk_witness).collect();
        let mut forged_leg = crate::types::test_legs::rewitness(&hal, &junk);
        forged_leg.client_sig = crate::types::test_legs::client_sig_over(&attacker, &victim, &hal.new_state, &hal.tx_hash);
        let mut forged_flood = w3_flood(&forged_leg, x, 9);
        if let GossipMessage::StateUpdate { client_pk, .. } = &mut forged_flood {
            *client_pk = attacker.verifying_key().to_bytes();
        }
        let action = n.feed(&forged_flood, 9);
        assert!(matches!(action, GossipAction::Duplicate), "(2) a forged HAL leg is dropped");
        assert!(!n.bans.is_banned(&victim), "(2) FORGED BAN: a third party banned W");
        assert_eq!(n.smt.get(&victim).map(|e| e.status), Some(WalletStatus::Normal), "(2) W stays Normal");
        assert_eq!(n.smt.get(&victim).map(|e| e.current_state), Some(spend.new_state), "(2) head untouched");
    }

    /// KI#233 positive control, re-stated for B2. Pre-B2 this asserted that a
    /// WALLET-SIGNED `HalAdvance` revival (k3 sigs over tick 0) still FROZE the
    /// holder. That freeze is the E3 arm, retired: the message is now dropped +
    /// counted and nobody is frozen — CHANGED assertion (`frozen` → `!frozen`,
    /// + the drop counter). What replaces it is `ki34_scenario_a_*` below: the
    /// SAME revival on the B2 carrier is BANNED on evidence. (The test also
    /// records why the old arm was a ghost live: its door stamped `tick =
    /// current_tick`, never the tick 0 Lambda signs — `fork_detection_mesh::
    /// b2_a2_*` records the §9q probe that measured it.)
    /// MUTATION (run 2026-09-30): forward the tombstone (`Forward(msg.clone())`)
    /// ⇒ RED at "never forwarded".
    #[test]
    fn hal_advance_wallet_signed_revival_is_dropped_counted_never_frozen() {
        use ed25519_dalek::{Signer as _, SigningKey};
        const W: u8 = 0xB8;
        let mut honest = Node::new();
        honest.anchor_x_then_y(W, 0x01, 0x02);
        let tick = 0u64;
        let payload = crate::crypto::receipt_sign_payload(&wid(W), &st(0x01), tick);
        let sigs: Vec<WitnessSig> = (0..3u8)
            .map(|i| {
                let sk = SigningKey::from_bytes(&[0xD0 + i; 32]);
                WitnessSig {
                    validator_pk: sk.verifying_key().to_bytes(),
                    signature: sk.sign(&payload).to_bytes().to_vec(),
                    execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![],
                    validator_id: [0u8; 32], slot_amount: 0,
                }
            })
            .collect();
        let mut msg = make_hal_advance(W, 0x01, 0x03, tick, 0); // wallet half signed by W's own key
        if let GossipMessage::HalAdvance { k3_signatures, .. } = &mut msg {
            *k3_signatures = sigs;
        }
        let action = honest.feed(&msg, tick);
        assert!(matches!(action, GossipAction::Duplicate), "a HalAdvance is never forwarded");
        assert!(!honest.frozen(W), "E3 is retired: nothing freezes on a HalAdvance");
        assert_eq!(honest.head(W), Some(st(0x02)), "nothing adopted from a HalAdvance");
        assert_eq!(honest.engine.haladvance_dropped(), 1, "the drop is COUNTED");
    }

    // ── Scenario A ──────────────────────────────────────────────────────────
    // Honest holder recorded X→Y. The wallet re-anchors the consumed X into
    // X′ at a node that never saw Y and the HAL leg floods here. CHANGED
    // assertions (B2): the holder BANS W on a verified `Fork` claim naming
    // both legs (was: FREEZE on its `previous_state` view); the head is NOT
    // adopted (unchanged — Y stays, now reported `Banned`, never `Frozen`);
    // the flood answers `Duplicate` (was `Forward`: a freeze had to be
    // re-detected by each peer from the forwarded message; a verdict travels
    // as `ForkBan` with its evidence instead — `take_pending_fork_floods`).
    // MUTATION (run 2026-09-30): skip the flood record hook in
    // `apply_state_update` ⇒ RED at "must BAN" (nothing judges the fork).
    #[test]
    fn ki34_scenario_a_honest_holder_detects_respend() {
        let seed = 0xA1u8;
        let (spend, hal, x) = b2_legs(seed);
        let w = w3_pk(seed);
        let mut honest = Node::new();
        honest.feed(&w3_flood(&spend, x, 5), 5);
        let action = honest.feed(&w3_flood(&hal, x, 4), 9);
        assert!(honest.bans.is_banned(&w), "A: the holder of X→Y must BAN on the revival leg");
        assert!(fork_evidence_names(&honest, &w, &[&spend, &hal]), "A: banned on a verified Fork claim of the two legs");
        assert!(matches!(action, GossipAction::Duplicate), "A: the fork leg is not forwarded (the claim floods as ForkBan)");
        assert_eq!(honest.bans.take_pending_fork_floods().len(), 1, "A: exactly one claim queued for the ForkBan flood");
        assert_eq!(honest.smt.get(&w).map(|e| e.current_state), Some(spend.new_state),
            "A: the forked head X′ must NOT be adopted — head stays Y");
        assert_eq!(honest.smt.get(&w).map(|e| e.status), Some(WalletStatus::Banned), "A: §4.6 reads Banned, not Frozen");
    }

    // Negative control for A: an UNDER-witnessed (< k=3) revival is not
    // evidence. CHANGED: it now rides the flood path, where the leg verifier
    // refuses it (`WitnessSigsBelowQuorum`, counted `origin_leg_unrecordable`)
    // — nothing recorded, nobody banned or frozen (was: dropped by the E3
    // arm's k3 count). Head untouched: an unattested equal-seq candidate with
    // a LOWER tick loses the ordinary merge (the merge decides adoption, never
    // a judgment on the leg).
    // MUTATION (run 2026-09-30): count the leg as recordable with 2 sigs
    // (`verify_fork_leg` quorum check skipped) ⇒ RED at "must NOT ban".
    #[test]
    fn ki34_scenario_a_underwitnessed_revival_does_not_freeze() {
        let seed = 0xA2u8;
        let (spend, hal, x) = b2_legs(seed);
        let w = w3_pk(seed);
        let two: Vec<ed25519_dalek::SigningKey> = (0..2u8).map(crate::types::test_legs::validator).collect();
        let under = crate::types::test_legs::rewitness(&hal, &two);
        let mut honest = Node::new();
        honest.feed(&w3_flood(&spend, x, 5), 5);
        let before = honest.bans.origin_leg_unrecordable();
        let _ = honest.feed(&w3_flood(&under, x, 4), 9);
        assert!(!honest.bans.is_banned(&w), "A-neg: must NOT ban on an under-witnessed leg");
        assert_eq!(honest.smt.get(&w).map(|e| e.status), Some(WalletStatus::Normal), "A-neg: must NOT freeze");
        assert_eq!(honest.bans.origin_leg_unrecordable(), before + 1, "A-neg: the refusal is COUNTED");
        assert_eq!(honest.smt.get(&w).map(|e| e.current_state), Some(spend.new_state), "A-neg: head untouched");
    }

    // ── Scenario B ──────────────────────────────────────────────────────────
    // No false positive on a node that lacks the spend, and the verdict still
    // reaches it. A node that never saw X→Y ("wiped") receives the HAL leg: one
    // leg is not evidence — it adopts X′ and bans nobody (unchanged: "must NOT
    // false-freeze"). The holder of X→Y bans on arrival (CHANGED: ban on Fork
    // evidence, was freeze). CHANGED: the wiped node then learns the verdict
    // from the holder's `ForkBan` — the claim carries both legs, so it bans on
    // the SAME evidence (was: it stayed unfrozen until a forwarded HalAdvance
    // met a node that retained `previous_state`; it never could itself).
    // MUTATION (run 2026-09-30): make the `ForkBan` arm drop every claim ⇒ RED
    // at "the wiped node bans on the carried evidence".
    #[test]
    fn ki34_scenario_b_endorsement_floor_and_no_false_positive() {
        let seed = 0xB1u8;
        let (spend, hal, x) = b2_legs(seed);
        let w = w3_pk(seed);
        let mut honest = Node::new();
        honest.feed(&w3_flood(&spend, x, 5), 5);
        let mut wiped = Node::new();
        let w_action = wiped.feed(&w3_flood(&hal, x, 4), 9);
        assert!(matches!(w_action, GossipAction::Forward(_)), "B: the wiped node applies the lone leg");
        assert!(!wiped.bans.is_banned(&w), "B: one leg is not evidence — no false ban");
        assert_eq!(wiped.smt.get(&w).map(|e| e.status), Some(WalletStatus::Normal), "B: no false freeze");

        let _ = honest.feed(&w3_flood(&hal, x, 4), 9);
        assert!(fork_evidence_names(&honest, &w, &[&spend, &hal]), "B: the holder bans on Fork evidence");
        let claims = honest.bans.take_pending_fork_floods();
        assert_eq!(claims.len(), 1);
        let _ = wiped.feed(&GossipMessage::ForkBan { claim: claims[0].clone() }, 10);
        assert!(fork_evidence_names(&wiped, &w, &[&spend, &hal]), "B: the wiped node bans on the carried evidence");
    }

    // ── Scenario C ──────────────────────────────────────────────────────────
    // Partition isolation + heal-time detection. While the re-anchor's node is
    // cut off, the honest holder never sees the HAL leg: head Y, Normal
    // (unchanged). On heal the HAL leg's flood reaches the holder: CHANGED —
    // it BANS on Fork evidence and answers `Duplicate` (was: freeze +
    // `Forward`); the forked head is never adopted (unchanged).
    // MUTATION (run 2026-09-30): the same flood-hook skip as A ⇒ RED at "on
    // heal the holder bans".
    #[test]
    fn ki34_scenario_c_partition_isolation_then_heal_detection() {
        let seed = 0xC1u8;
        let (spend, hal, x) = b2_legs(seed);
        let w = w3_pk(seed);
        let mut honest = Node::new();
        honest.feed(&w3_flood(&spend, x, 5), 5);
        let mut colluder = Node::new();
        let revival = w3_flood(&hal, x, 4);
        colluder.feed(&revival, 9);
        assert_eq!(colluder.smt.get(&w).map(|e| e.current_state), Some(hal.new_state), "C: the isolated node holds X′");

        assert_eq!(honest.smt.get(&w).map(|e| e.current_state), Some(spend.new_state),
            "C: partitioned — honest head must remain Y, no value crosses");
        assert_eq!(honest.smt.get(&w).map(|e| e.status), Some(WalletStatus::Normal),
            "C: partitioned — the honest holder is not holding W yet");

        let action = honest.feed(&revival, 9);
        assert!(fork_evidence_names(&honest, &w, &[&spend, &hal]), "C: on heal the holder bans on Fork evidence");
        assert!(matches!(action, GossipAction::Duplicate), "C: the fork leg is not forwarded");
        assert_eq!(honest.smt.get(&w).map(|e| e.current_state), Some(spend.new_state),
            "C: the forked head X′ must never be adopted, even at heal");
    }


    // ── ForkSettlement §9r-E4 — `TaintAlert` / `MergeResolved` are tombstones ──
    //
    // (Was ghost-audit G2: the arm re-derived taint from the local SMT and wrote
    // `Tainted`, which the door refused. Retired 2026-10-02 — see the arm.)

    fn taint_alert(victim: u8, source: u8) -> GossipMessage {
        GossipMessage::TaintAlert {
            wallet_id: wid(victim),
            tainted_source: wid(source),
            detected_at_tick: 100,
        }
    }

    /// The OLD arm's exact live predicate holds (source S `Banned` — the status
    /// `apply_fork_verdict` writes in production — and V's `received_from` IS
    /// S's head), so under the pre-E4 arm V would be `Tainted`, blocked and the
    /// alert forwarded. Now: V stays `Normal`, unblocked, nothing forwarded,
    /// the drop is counted.
    /// MUTATION (run 2026-10-02): make the tombstone write `Tainted` on
    /// `wallet_id` (the old `taint_wallet`) and return `Forward` ⇒ RED at
    /// "V tainted by a peer's word".
    #[test]
    fn taintalert_dropped_counted_never_taints_never_forwards() {
        let mut n = Node::new();
        n.feed(&make_state_update(0x0A, 0x0B, 1), 1); // S, head 0x0B
        n.feed(&make_state_update(0x0C, 0x07, 1), 1); // V
        let mut v = n.smt.get(&wid(0x0C)).unwrap().clone();
        v.received_from = Some(st(0x0B));
        n.smt.put(&v);
        let mut src = n.smt.get(&wid(0x0A)).unwrap().clone();
        src.status = WalletStatus::Banned;
        n.smt.put_with_proof(&src, crate::smt::PutProof::SameHeadStatusChange);
        // Non-vacuity: the OLD predicate is satisfied, read from the SMT.
        assert_eq!(n.status(0x0A), Some(WalletStatus::Banned), "fixture: S Banned");
        assert_eq!(n.smt.get(&wid(0x0C)).unwrap().received_from,
            Some(n.smt.get(&wid(0x0A)).unwrap().current_state), "fixture: V downstream of S's head");

        let action = n.feed(&taint_alert(0x0C, 0x0A), 2);
        assert_eq!(n.status(0x0C), Some(WalletStatus::Normal), "V tainted by a peer's word");
        assert!(!crate::tardis::TardisNode::is_wallet_blocked(&n.smt, &wid(0x0C)), "V blocked");
        assert!(matches!(action, GossipAction::Duplicate), "a tombstone is never forwarded");
        assert_eq!(n.engine.taintalert_dropped(), 1, "the drop is COUNTED");
        // A second, unconfirmable one: same outcome (no branch on content).
        assert!(matches!(n.feed(&taint_alert(0x0D, 0x0E), 3), GossipAction::Duplicate));
        assert_eq!(n.engine.taintalert_dropped(), 2);
    }

    /// D-E4-1 — `MergeResolved` (whose only emitter, the 75 s quarantine
    /// expiry, is deleted) is dropped and counted, never forwarded.
    /// MUTATION (run 2026-10-02): return `Forward(msg.clone())` from the arm
    /// (the pre-E4 behaviour) ⇒ RED.
    #[test]
    fn mergeresolved_dropped_counted_never_forwards() {
        let mut n = Node::new();
        let msg = GossipMessage::MergeResolved {
            forked_wallets: vec![wid(0x0A)],
            restored_wallets: vec![wid(0x0C)],
            resolved_at_tick: 5,
        };
        assert!(matches!(n.feed(&msg, 1), GossipAction::Duplicate), "never forwarded");
        assert_eq!(n.engine.mergeresolved_dropped(), 1, "the drop is COUNTED");
    }


    /// G15 — H3 data-availability messages must be DROPPED, never relayed.
    ///
    /// `types.rs` documented a SCAR penalty "same enforcement as JFP" gated on
    /// `CHALLENGE_WINDOW_TICKS`. That constant does not exist, neither variant
    /// is ever constructed, there is no timer and no SCAR path. Yet both arms
    /// forwarded — and the response arm's only gate was `sig.len() == 64` under
    /// a comment promising "full verification by peers", which every peer also
    /// skipped. A protocol with no emitter that still fans out mesh-wide is
    /// pure amplification surface.
    #[test]
    fn g15_h3_messages_are_dropped_not_forwarded() {
        let mut n = Node::new();

        let challenge = GossipMessage::DataWithholdChallenge {
            challenged_validator_pk: [0xAA; 32],
            withheld_txid: [0xBB; 32],
            challenger_pk: [0xCC; 32],
            challenger_sig: vec![0u8; 64],
            challenge_tick: 10,
        };
        assert!(matches!(n.feed(&challenge, 10), GossipAction::Duplicate),
            "G15: an unbuilt-protocol challenge must not be relayed");

        // The response arm's old gate: a 64-byte sig and a non-zero txid was
        // ALL it took to get fanned out mesh-wide.
        let response = GossipMessage::DataWithholdResponse {
            withheld_txid: [0xBB; 32],
            validator_pk: [0xAA; 32],
            receipt_data: vec![0xFF; 128],
            validator_sig: vec![0u8; 64],
            response_tick: 11,
        };
        assert!(matches!(n.feed(&response, 11), GossipAction::Duplicate),
            "G15: an unbuilt-protocol response must not be relayed — this shape \
             passed the old `sig.len() == 64` gate and was forwarded");

        assert_eq!(n.engine.h3_unbuilt_dropped(), 2,
            "both drops must be COUNTED — if H3 traffic ever appears we need to \
             see it, not silently relay it");
    }

    // ── Gossip/AE flood load-shedding (B + A + E) — DELETED 2026-09-30 (§9q) ─
    // Seven tests (`load_shed_verify_budget_*`, `load_shed_precheck_*`,
    // `load_shed_offlock_verified_*`, `load_shed_verify_hal_k3_predicate`)
    // drove the off-lock `HalPrecheck` handoff and the per-peer verify budget
    // that existed ONLY for the E3 `HalAdvance` conflict verify. The arm is a
    // tombstone now (dropped unverified, O(1) — `hal_advance_*` above), so the
    // machinery and its tests went with it; the HAL leg pays the ordinary
    // flood-path leg verification (ForkSettlement §9b R36).

    // ── KI#203 — the gossip-latency instrument must be able to say "I am stale" ──

    /// THE DEFECT, reproduced: a restart re-flood fills the ring with entries
    /// carrying their ORIGINAL ticks; a handful of fresh, instant messages then
    /// cannot move the lifetime p99. The WINDOWED view judges only what was
    /// observed since `since_tick`, and the lifetime view now carries the
    /// observation span so a reader can see it is looking at history.
    #[test]
    fn ki203_window_excludes_restart_era_samples_lifetime_view_says_how_old_it_is() {
        let mut stats = GossipLatencyStats::new();
        let restart = 1_000_000u64;
        // 900 re-flooded StateUpdates, each ~4 days old when observed at restart.
        for i in 0..900u64 {
            stats.observe(&make_state_update((i % 250) as u8, 1, restart - 340_000 - i), restart);
        }
        // An hour later: 24 fresh updates, each applied the tick it was made.
        let seeded = restart + 3_600;
        for i in 0..24u64 {
            stats.observe(&make_state_update((i % 250) as u8, 2, seeded + i), seeded + i);
        }
        let now = seeded + 30;

        let lifetime = stats.snapshot(now, None);
        assert_eq!(lifetime.since_tick, None);
        assert_eq!(lifetime.state_update.count, 924);
        assert!(lifetime.state_update.p99_ticks >= 340_000,
            "the lifetime ring still reports the re-flood as latency: {:?}", lifetime.state_update);
        // …but it can now be SEEN to be stale: its evidence reaches back to the restart.
        assert_eq!(lifetime.state_update.oldest_observed_tick, restart);
        assert_eq!(lifetime.state_update.newest_observed_tick, seeded + 23);

        let windowed = stats.snapshot(now, Some(seeded));
        assert_eq!(windowed.since_tick, Some(seeded), "the applied window is ECHOED");
        assert_eq!(windowed.current_tick, now);
        assert_eq!(windowed.state_update.count, 24, "only what was observed in the window");
        assert_eq!(windowed.state_update.p99_ticks, 0);
        assert_eq!(windowed.state_update.max_ticks, 0);
        assert_eq!(windowed.state_update.oldest_observed_tick, seeded);
    }

    /// The window must not HIDE a real problem: a slow message observed INSIDE
    /// the window is still reported. (Filtering on the message's own tick
    /// instead of `observed_at` would drop exactly the sample that matters.)
    #[test]
    fn ki203_window_still_reports_a_slow_message_observed_inside_it() {
        let mut stats = GossipLatencyStats::new();
        let t0 = 5_000u64;
        stats.observe(&make_state_update(1, 1, t0 + 10), t0 + 10);      // instant
        stats.observe(&make_state_update(2, 1, t0 - 400), t0 + 20);     // 420 ticks late, seen in-window
        let w = stats.snapshot(t0 + 30, Some(t0));
        assert_eq!(w.state_update.count, 2);
        assert_eq!(w.state_update.max_ticks, 420);
    }

    /// An empty window is `count == 0`, never a fabricated healthy percentile
    /// a consumer could mistake for "measured, and fine".
    #[test]
    fn ki203_empty_window_is_count_zero() {
        let mut stats = GossipLatencyStats::new();
        stats.observe(&make_state_update(1, 1, 90), 100);
        let w = stats.snapshot(500, Some(400));
        assert_eq!(w.state_update.count, 0);
        assert_eq!(w.state_update.oldest_observed_tick, 0);
        // The echo is what a consumer reads to know the zero is a WINDOWED zero.
        assert_eq!(w.since_tick, Some(400));
    }

    /// Consumers read JSON, not the struct (RULE 6 §4): the freshness fields
    /// and the echo must survive serialization, and `None` must be `null`.
    #[test]
    fn ki203_echo_and_freshness_reach_the_wire() {
        let mut stats = GossipLatencyStats::new();
        stats.observe(&make_state_update(1, 1, 100), 101);
        let v: serde_json::Value =
            serde_json::to_value(stats.snapshot(200, Some(50))).unwrap();
        assert_eq!(v["since_tick"], 50);
        assert_eq!(v["current_tick"], 200);
        assert_eq!(v["state_update"]["oldest_observed_tick"], 101);
        assert_eq!(v["state_update"]["newest_observed_tick"], 101);
        let whole: serde_json::Value = serde_json::to_value(stats.snapshot(200, None)).unwrap();
        assert!(whole["since_tick"].is_null(), "whole-ring answers echo null, not 0");
    }

    /// A window the caller asked for is never silently dropped.
    #[test]
    fn ki203_parse_latency_window() {
        assert_eq!(parse_latency_window(None, 1_000), Ok(None));
        assert_eq!(parse_latency_window(Some("foo=1"), 1_000), Ok(None));
        assert_eq!(parse_latency_window(Some("since_tick=700"), 1_000), Ok(Some(700)));
        assert_eq!(parse_latency_window(Some("x=1&window_ticks=60"), 1_000), Ok(Some(940)));
        assert_eq!(parse_latency_window(Some("window_ticks=5000"), 1_000), Ok(Some(0)),
            "a window longer than the node's life is the whole life, not an underflow");
        assert!(parse_latency_window(Some("since_tick=abc"), 1_000).is_err());
        assert!(parse_latency_window(Some("since_tick="), 1_000).is_err());
        assert!(parse_latency_window(Some("since_tick=1&window_ticks=2"), 1_000).is_err());
        // A parameter that merely STARTS with the name is a different parameter.
        assert_eq!(parse_latency_window(Some("since_tickle=9"), 1_000), Ok(None));
    }

    // ── KI#191 residual (RULED 2026-09-25) — ONE RULE FOR EVERY POOL ──────

    /// Build a PoolSync for `pool` at tick `tick`. The sender signature is not
    /// checked by `process` (SEC-03: verified at the binary layer), so a
    /// placeholder is enough to drive the reconcile + dispatch.
    fn ki191_pool_sync(pool: PoolKind, balance: u64, tick: u64) -> GossipMessage {
        GossipMessage::PoolSync {
            pool,
            balance,
            total_claims: 0,
            paid_out: 0,
            topped_up: 0,
            tick,
            sender_node_id: [0xE1u8; 32],
            sender_sig: vec![],
        }
    }

    /// Run one PoolSync through `process` with a fresh engine and the given
    /// emission pools + deed, returning the action.
    fn ki191_run(
        msg: &GossipMessage,
        emission: &mut crate::emission::EmissionPools,
        deed: &mut crate::node::DeedPool,
    ) -> GossipAction {
        let mut engine = GossipEngine::new();
        let mut pool = crate::oracle::DailyPoolState::default();
        engine.process(
            msg,
            &mut crate::smt::SparseMerkleTree::new(),
            &mut crate::ban::BanTable::new(),
            &mut pool,
            &mut AirdropPool::new(0),
            &mut crate::node::DevTreasuryPool::new(0),
            &mut AirdropPool::new(0),
            &mut AirdropPool::new(0),
            deed,
            &mut crate::node::DevDeedPool::new(),
            emission,
            &mut std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            0, 0,
            1, &crate::types::test_legs::dir_admits_all,
        )
    }

    /// NablaJudoon §2.5 ruling: an emission-pool PoolSync carrying a
    /// DISPROVABLE structural violation produces the SAME `GossipAction` an
    /// Airdrop one does — `PoolStructuralViolation`, same proof kind, same
    /// accused — so the binary routes it to `enter_probation_on_structural_
    /// violation` like any pool. Until 2026-09-25 the emission kinds were
    /// hard-coded to `NoOp` in `process` and this returned `Duplicate`.
    ///
    /// MUTATION: re-add `PoolKind::EmissionValidators | EmissionNabla =>
    /// ReconcileOutcome::NoOp` in `process` → THIS test goes red (the
    /// emission action reads `Duplicate`).
    #[test]
    fn ki191_emission_structural_violation_escalates_like_airdrop() {
        // Airdrop reference: `AirdropPool::new(0)` has a 0 genesis opening, so
        // any positive balance exceeds it — BalanceExceedsInitial.
        let airdrop = ki191_pool_sync(PoolKind::Airdrop, 1, 0);
        let a = ki191_run(
            &airdrop,
            &mut crate::emission::EmissionPools::new_from_registers(0),
            &mut crate::node::DeedPool::new(),
        );
        let (airdrop_proof, airdrop_accused) = match a {
            GossipAction::PoolStructuralViolation { proof, accused, .. } => (proof, accused),
            other => panic!("airdrop reference must escalate, got {other:?}"),
        };

        // Emission: a balance ABOVE the group's whole epoch need is not a
        // roll-order difference (`EmissionPools::reconcile` tolerates only
        // `peer_balance <= need`), so it reaches the same conservation
        // identity and exceeds the 0 opening — disprovable from the peer's
        // own snapshot.
        let need_v = axiom_core_logic::emission::validator_epoch_need(crate::emission::epoch_secs());
        for kind in [PoolKind::EmissionValidators, PoolKind::EmissionNabla] {
            let need_n = axiom_core_logic::emission::nabla_epoch_need(crate::emission::epoch_secs());
            let over = if matches!(kind, PoolKind::EmissionValidators) { need_v } else { need_n } + 1;
            let msg = ki191_pool_sync(kind, over, 0);
            let action = ki191_run(
                &msg,
                &mut crate::emission::EmissionPools::new_from_registers(0),
                &mut crate::node::DeedPool::new(),
            );
            match action {
                GossipAction::PoolStructuralViolation { proof, accused, .. } => {
                    // Same ACTION (the escalation path), same accused. The proof
                    // kind is whichever Layer-1 trigger fires first for the
                    // pool's constants (`judoon::structural_violation` order) —
                    // both are structural; the ruling is about the route.
                    assert!(
                        matches!(proof, crate::judoon::ProofKind::BalanceExceedsInitial
                            | crate::judoon::ProofKind::IntraSnapshotInconsistent),
                        "{kind:?}: a Layer-1 structural proof, got {proof:?} (airdrop: {airdrop_proof:?})"
                    );
                    assert_eq!(accused, airdrop_accused, "{kind:?}: the PoolSync sender is the accused");
                }
                other => panic!("{kind:?}: an emission structural violation must escalate exactly like \
                                 the airdrop pool (NablaJudoon §2.5, RULED 2026-09-25), got {other:?}"),
            }
        }
    }

    /// The other half of the ruling: a CONSISTENT emission advertisement is
    /// not a violation. Two honest shapes: (a) a same-epoch advertisement of
    /// a balance within the group's need; (b) KI#191's live-gate shape — the
    /// PEER ROLLED FIRST and advertises the epoch boundary before this node's
    /// own tick does, with this node's DEED both empty and full. All three
    /// must NOT produce `PoolStructuralViolation`.
    #[test]
    fn ki191_honest_emission_advertisement_is_not_a_violation() {
        let t = crate::emission::epoch_secs();
        let need_v = axiom_core_logic::emission::validator_epoch_need(t);

        // (a) same epoch, within need.
        let a = ki191_run(
            &ki191_pool_sync(PoolKind::EmissionValidators, need_v / 2, 0),
            &mut crate::emission::EmissionPools::new_from_registers(0),
            &mut crate::node::DeedPool::new(),
        );
        assert!(!matches!(a, GossipAction::PoolStructuralViolation { .. }),
            "a within-need advertisement is consistent, got {a:?}");

        // (b) peer rolled first: a full DEED peer drew `need_v` at epoch t.
        let mut peer = crate::emission::EmissionPools::new_from_registers(0);
        let mut peer_deed = crate::node::DeedPool::new();
        peer_deed.credit(10_000_000_000_000_000, 1);
        let roll = peer.maybe_roll(t, &mut peer_deed).expect("peer rolled");
        let boundary = ki191_pool_sync(PoolKind::EmissionValidators, roll.draw_v, t);

        // (b1) this node's DEED is EMPTY — it rolls by the same rule and draws 0.
        let mut mine = crate::emission::EmissionPools::new_from_registers(0);
        let b1 = ki191_run(&boundary, &mut mine, &mut crate::node::DeedPool::new());
        assert!(!matches!(b1, GossipAction::PoolStructuralViolation { .. }),
            "peer-rolled-first with an empty local DEED must not be a violation, got {b1:?}");
        assert_eq!(mine.epoch, roll.epoch, "this node rolled to the peer's epoch by the same rule");

        // (b2) this node's DEED is FULL — it draws the same need first.
        let mut mine = crate::emission::EmissionPools::new_from_registers(0);
        let mut my_deed = crate::node::DeedPool::new();
        my_deed.credit(10_000_000_000_000_000, 1);
        let b2 = ki191_run(&boundary, &mut mine, &mut my_deed);
        assert!(!matches!(b2, GossipAction::PoolStructuralViolation { .. }),
            "peer-rolled-first with a full local DEED must not be a violation, got {b2:?}");
        assert_eq!(mine.validators.balance(), roll.draw_v, "both drew the same need");
    }
}
