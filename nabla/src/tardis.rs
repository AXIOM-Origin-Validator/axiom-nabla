// AXIOM Nabla — TARDIS (Tick Authority)
// Reference: AXIOM_GUIDE_Nabla.md Section 5
//
// Phase 2 Tasks:
//   10. TARDIS node slots (UP, D1, D2, P, E)
//   11. Tick processing (receive, verify, forward)
//   12. Downstream approval
//   13. Bottom-up verification (merkle subtree proof audit)
//   14. Questionable alert cascade + self-healing disconnect
//   15. Seed triangle bootstrap
//   16. Maturity window enforcement
//
// Design:
//   TARDIS is built into Nabla — no separate binary.
//   TARDIS carries TICKS ONLY. All data flows through gossip mesh.
//   If upstream is lost, node degrades to SCARRED-only (cannot issue CLEAN).
//   Gossip still flows through mesh peers — node remains informed.

use std::collections::{HashMap, HashSet, VecDeque};
use crate::constants::{
    CHILD_ROTATION_INTERVAL_TICKS, CHILD_ROTATION_JITTER_TICKS, D_RESERVATION_TICKS,
    MATURITY_TICKS_MAX, MATURITY_TICKS_MIN, PARENT_ROTATION_INTERVAL_TICKS,
    PARENT_ROTATION_JITTER_TICKS, PARENTLESS_TIMEOUT_TICKS, REBALANCE_COOLDOWN_TICKS,
    TICK_INTERVAL_SECS,
};

/// Consecutive ticks without verifiable grandpa-sig before a node detaches
/// from its upstream and re-seeks. 10 ticks ≈ 50s at TICK_INTERVAL_SECS=5,
/// matching REBALANCE_COOLDOWN_TICKS so the threshold composes with the
/// existing anti-thrash window. Short enough that broken chains don't
/// linger; long enough that transient rotation-drain windows don't trigger
/// false detaches.
pub const GRANDPA_MISS_DETACH_THRESHOLD: u32 = 10;

/// KI#37 (2026-07-08) — QuestionableAlert cascade hygiene. An alert whose
/// `tick` is more than this many seconds behind the local tick is dropped
/// without action. Legitimate cascade propagation across the mesh is
/// seconds (tree depth × per-hop latency); the storm this bounds carried a
/// single alert that was still circulating 900+ seconds after minting.
/// 12 ticks ≈ 60 s at TICK_INTERVAL_SECS=5 — generous for propagation,
/// far below storm age. (TARDIS ticks are the Nabla-layer time base;
/// this is not a protocol time-gate.)
pub const ALERT_MAX_AGE_SECS: u64 = 12 * TICK_INTERVAL_SECS;

/// KI#37 — bound on the alert seen-set (FIFO eviction). 1024 distinct
/// alerts is ~2 orders of magnitude above what a healthy 10-node mesh
/// mints in ALERT_MAX_AGE_SECS; at 32 bytes/key the memory cost is
/// negligible. The freshness bound above makes eviction-replay harmless:
/// by the time a key is evicted the alert is stale anyway.
pub const ALERT_SEEN_CAP: usize = 1024;

/// KI#37 — per-reporter alert rate limit: max DISTINCT alerts accepted
/// from one reporter per `ALERT_RATE_WINDOW_SECS`. An honest node flags
/// an upstream at most on a real audit failure — sporadic, far below
/// this. A reporter minting alerts faster is either malfunctioning or
/// malicious; its excess is dropped (never cascaded). 6 per 60 s is
/// generous headroom over honest cadence while capping a spammer to a
/// trickle. Also bounds the `alert_rate` map (one entry per reporter).
pub const ALERT_MAX_PER_REPORTER_PER_WINDOW: u32 = 6;
pub const ALERT_RATE_WINDOW_SECS: u64 = 12 * TICK_INTERVAL_SECS;

/// Consecutive ticks where the node believes it has an upstream but has
/// received NO ticks from that upstream. Catches the "phantom child" case:
/// child has has_upstream=true but parent's d1/d2 doesn't include child
/// (stale state) → parent never forwards ticks down → grandpa-tick rule
/// never fires (it needs ticks to arrive). Without this rule, a phantom
/// child sits attached forever to a parent that doesn't acknowledge them.
///
/// 20 ticks (~100s) — was 5 ticks initially but caused mass cascading
/// detaches across the mesh during stress (silent-parent firing on many
/// nodes simultaneously when load slowed tick forwarding). 20 ticks
/// matches GRANDPA_MISS_DETACH_THRESHOLD × 2 — long enough to ride out
/// transient slowdowns, short enough that true phantom children clear
/// before the metric matters.
pub const SILENT_PARENT_THRESHOLD: u32 = 20;

/// Consecutive ticks where a node holding a downstream child slot (d1 or d2)
/// has received NO approval-up from that child. Catches the symmetric
/// "stale parent slot" case: parent's d1/d2 points at a child that has
/// detached (moved to a new parent) but the parent never got the
/// TardisDetach (dropped message or busy handler). Without this cleanup
/// the parent keeps reporting dc=2 → counted as a writer → math impossible
/// reports like writers=7 on a 10-node mesh.
pub const STALE_CHILD_SLOT_THRESHOLD: u32 = 20;
use crate::crypto::{self, Signer};
use crate::smt::SparseMerkleTree;
use crate::types::*;

// ── Outbound messages for the network layer to send ──

/// Actions the caller (network layer) must take after TARDIS processing.
#[derive(Debug)]
pub enum TardisAction {
    /// Forward signed tick to these downstream peers.
    ForwardTick {
        tick: TickMessage,
        targets: Vec<PeerId>,
    },
    /// Send approval back to upstream.
    SendApproval {
        approval: TickApproval,
        target: PeerId,
    },
    /// Broadcast root hash comparison via gossip mesh.
    BroadcastRootHash {
        tick: u64,
        root_hash: Hash256,
        node_pk: PeerId,
    },
    /// Send audit challenge to upstream.
    SendAuditRequest {
        request: SubtreeAuditRequest,
        target: PeerId,
    },
    /// Send audit response to downstream requester.
    SendAuditResponse {
        response: SubtreeAuditResponse,
        target: PeerId,
    },
    /// Cascade questionable alert to all downstream.
    CascadeAlert {
        alert: QuestionableAlert,
        targets: Vec<PeerId>,
    },
    /// Detach from upstream — parent failed writer check.
    /// Caller must find a new parent via recovery (P1-P4).
    DetachUpstream {
        /// The non-writer parent to disconnect from.
        parent: PeerId,
        /// Reason for detachment.
        reason: DetachReason,
    },
    /// Nothing to do.
    None,
}

/// Why a node detaches from its upstream parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetachReason {
    /// Parent has <2 downstream approvals for WRITER_GRACE_TICKS consecutive ticks.
    ParentNotWriter,
    /// Parent failed to include verifiable grandpa-sig in tick payload for
    /// GRANDPA_MISS_DETACH_THRESHOLD consecutive ticks. Indicates the upstream
    /// chain is structurally broken — parent itself is in a degraded chain or
    /// is acting without anchoring to its own writer. Detach + reseek.
    GrandpaTickMissing,
    /// We have an upstream set locally but received no tick from it for
    /// SILENT_PARENT_THRESHOLD ticks — likely a "phantom child" pattern
    /// where parent's d1/d2 doesn't include us (stale d1/d2 state). Detach
    /// + reseek so we re-enter the orphan-recovery loop.
    SilentParent,
}

// ── TARDIS Node ──

/// TARDIS tree node — manages tick authority for this Nabla node.
///
/// Five connection slots per the Implementation Guide §5.2:
///   UP  — upstream parent (receives ticks from)
///   D1  — downstream child 1 (sends ticks to)
///   D2  — downstream child 2 (sends ticks to)
///   P   — pending node (seeking D slot)
///   E   — ephemeral (stateless, not stored)
pub struct TardisNode {
    /// This node's public key.
    my_pk: PeerId,

    // ── Tree Slots ──
    up: Option<PeerId>,
    d1: Option<PeerId>,
    d2: Option<PeerId>,
    pending: Option<PeerId>,

    // ── Tick State ──
    current_tick: u64,
    last_tick_time_ms: u64,

    // ── Upstream Health ──
    upstream_status: NodeStatus,
    /// Number of consecutive successful audits.
    audit_pass_count: u64,
    /// Number of ticks since last audit.
    ticks_since_audit: u64,

    // ── Network Size (for dynamic maturity) ──
    unique_nodes_seen: u64,
    mesh_peer_count: u64,

    // ── Recovery State (§2.2) ──
    /// Last known nodes with open D slots, from tick messages.
    /// Updated every tick via available_slots field.
    /// Used for instant reconnection when upstream dies.
    last_known_open_slots: Vec<(PeerId, u32)>,

    // ── Parentless Timeout ──
    /// Ticks since this node lost its parent while still having children.
    /// After PARENTLESS_TIMEOUT_TICKS, the node must detach its children
    /// so all three can recover independently. Prevents zombie subtrees.
    /// Reset to 0 when upstream is established or when node has no children.
    parentless_ticks: u64,

    // ── Rebalance Cooldown ──
    /// Ticks remaining before this node can volunteer for rebalancing again.
    /// Prevents churn: after detaching to rebalance, wait before volunteering again.
    rebalance_cooldown: u8,

    // ── Rotation State ──
    /// Approval misses for D1 child. Incremented each tick the child doesn't approve.
    /// Reset when child is replaced or after rotation drop.
    d1_misses: u32,
    /// Approval misses for D2 child. Same as d1_misses.
    d2_misses: u32,
    /// Ticks since last parent-side rotation check.
    ticks_since_parent_rotation: u32,
    /// Ticks this node has been with its current parent.
    ticks_with_current_parent: u32,
    /// Number of downstream approvals received in the previous tick round.
    /// Used in TickMessage.downstream_approvals so children can verify
    /// this node is a qualified writer (needs ≥ 2). Updated each round
    /// by record_child_approvals().
    prev_round_approval_count: u8,
    /// Total open D slots in this node's subtree (§2.2, §2.14.5).
    /// Aggregated bottom-up: my_open + d1_subtree + d2_subtree.
    /// Updated from children's TickApproval.subtree_open_d each round.
    subtree_d_available: u32,

    // ── D Slot Reservation (§2.3) ──
    /// When a D1 child goes offline (not voluntarily detached), the slot is
    /// reserved for D_RESERVATION_TICKS. The original child can reclaim it
    /// immediately; other nodes must wait until reservation expires.
    /// Stores (original_peer_id, tick_when_reserved).
    d1_reserved: Option<(PeerId, u64)>,
    /// Same as d1_reserved but for D2 slot.
    d2_reserved: Option<(PeerId, u64)>,

    // ── §32 Merge Protocol State ──
    /// Whether this node is currently in merge quarantine.
    merge_quarantine_active: bool,
    /// Tick when merge quarantine started (0 = not in quarantine).
    merge_quarantine_start_tick: u64,
    /// Root hashes received from other branches during gossip.
    /// Used for fork detection: if root_hash differs at same tick → possible fork.
    /// Maps tick → (sender_pk, root_hash).
    branch_root_hashes: HashMap<u64, Vec<(PeerId, Hash256)>>,
    /// WalletIds that triggered §32 quarantine (the actual forks).
    /// Populated during handle_fork_evidence(). Used by resolve_merge()
    /// to distinguish forked from tainted-innocent.
    merge_forked_wallets: Vec<WalletId>,

    /// Random per-process seed mixed into rotation jitter — prevents the
    /// synchronized-rotation cluster trap. Without this, every rolling
    /// restart re-syncs all writers' rotation timers (jitter was purely a
    /// function of `my_pk`, which is persistent), causing all writers to
    /// drain together ~CHILD_ROTATION_INTERVAL ticks later. With a fresh
    /// random `boot_seed` per process, restarts produce uncorrelated
    /// rotation schedules.
    boot_seed: u64,
    /// Counter incremented on every voluntary writer rotation. Mixed into
    /// rotation_jitter so that even if two nodes' first-rotation timings
    /// coincide, their second-rotation timings decohere naturally.
    pub rotations_completed: u32,
    /// Consecutive ticks where the inbound tick lacked a verifiable
    /// grandpa-sig (either `grandparent_pk` is None or `prev_sig` is empty).
    /// Reset to 0 on every grandpa-OK tick. When it reaches
    /// `GRANDPA_MISS_DETACH_THRESHOLD`, `process_tick` emits a
    /// `DetachUpstream { reason: GrandpaTickMissing }` action — the caller
    /// then removes the parent, sends `TardisDetach` up, and the orphan-
    /// recovery loop fires on the next tick to actively seek a new parent.
    pub grandpa_miss_count: u32,
    /// Consecutive ticks where we believe we have an upstream but received
    /// NO tick from it. Increments in `set_tick` (per-tick) when
    /// has_upstream; resets to 0 in `process_tick` (tick received).
    /// At `SILENT_PARENT_THRESHOLD`, `check_silent_parent` returns a
    /// `DetachUpstream { reason: SilentParent }` action. Catches the
    /// "phantom child" pattern where parent's d1/d2 doesn't include us
    /// (stale state) → parent never forwards ticks → we sit attached
    /// forever to a parent that doesn't acknowledge us.
    pub silent_parent_ticks: u32,

    /// Fix #1: Cumulative TARDIS tick-signature verify failures since
    /// boot. Incremented in `process_tick` whenever Core's
    /// `signer.verify` returns false. Exposed via dashboard /status
    /// for SLO tracking — a non-zero rate flags upstream signing-key
    /// drift, transport corruption, or replay of stale ticks. Per
    /// the 2026-05-24 session: 6 such failures observed across a
    /// 72h adversarial soak, with one recurring 65-min pattern on
    /// kappa from theta — that pattern is the primary thing this
    /// counter helps measure once Fix #1 lands.
    tick_sig_failures: u64,

    /// KI#37 — QuestionableAlert dedup (seen-set + FIFO eviction order).
    /// Key = BLAKE3(alert_sign_payload) — covers suspect, reporter, tick,
    /// evidence_hash, so one minted alert has exactly one key mesh-wide.
    /// Without this, a transient cycle in the thrashing tick tree
    /// circulates one alert forever (measured 2026-07-08: ~9.2k copies/s
    /// into a single node, ~24 MB/s across an idle 10-node mesh).
    seen_alerts: HashSet<[u8; 32]>,
    seen_alerts_order: VecDeque<[u8; 32]>,

    /// KI#37 — per-reporter alert accept-rate limiter. Dedup + sig-verify
    /// stop the accidental loop and the forgery; this bounds the RESIDUAL
    /// vector: a node holding a VALID NBC that turns malicious and mints a
    /// stream of DISTINCT fresh alerts (varying evidence_hash) — each
    /// passes dedup and would drive one cascade pass per alert. Cap the
    /// accepted rate per reporter per window; excess is dropped and the
    /// reporter is a candidate for the existing quarantine machinery
    /// (a node that "accuses" faster than any honest audit cadence is
    /// itself questionable). Map: reporter_pk → (window_start_tick, count).
    alert_rate: HashMap<PeerId, (u64, u32)>,
}

impl TardisNode {
    /// Create a new TARDIS node with no connections.
    pub fn new(my_pk: PeerId) -> Self {
        Self {
            my_pk,
            up: None,
            d1: None,
            d2: None,
            pending: None,
            current_tick: 0,
            last_tick_time_ms: 0,
            upstream_status: NodeStatus::Disconnected,
            audit_pass_count: 0,
            ticks_since_audit: 0,
            unique_nodes_seen: 1, // at minimum, we see ourselves
            mesh_peer_count: 0,
            last_known_open_slots: Vec::new(),
            parentless_ticks: 0,
            rebalance_cooldown: 0,
            d1_misses: 0,
            d2_misses: 0,
            ticks_since_parent_rotation: 0,
            ticks_with_current_parent: 0,
            prev_round_approval_count: 0,
            subtree_d_available: 0,
            d1_reserved: None,
            d2_reserved: None,
            merge_quarantine_active: false,
            merge_quarantine_start_tick: 0,
            branch_root_hashes: HashMap::new(),
            merge_forked_wallets: Vec::new(),
            boot_seed: rand::random(),
            rotations_completed: 0,
            grandpa_miss_count: 0,
            silent_parent_ticks: 0,
            tick_sig_failures: 0,
            seen_alerts: HashSet::new(),
            seen_alerts_order: VecDeque::new(),
            alert_rate: HashMap::new(),
        }
    }

    /// Create a node with initial connections (used for bootstrap).
    /// After bootstrap, this node is identical to any other — no special treatment.
    pub fn new_with_ring_links(my_pk: PeerId, upstream: PeerId, downstream: PeerId) -> Self {
        let mut node = Self::new(my_pk);
        node.up = Some(upstream);
        node.d1 = Some(downstream);
        node.upstream_status = NodeStatus::Connected;
        node
    }

    // ── Tick Processing (§5.3) ──

    /// Process an incoming tick from upstream.
    ///
    /// Returns actions for the network layer:
    ///   - Forward signed tick to downstream (D1, D2, P)
    ///   - Send approval back to upstream
    ///   - Broadcast root hash via gossip
    ///
    /// The caller provides `now_ms` for testability (no system clock dependency).
    pub fn process_tick(
        &mut self,
        tick: &TickMessage,
        smt: &SparseMerkleTree,
        now_ms: u64,
        signer: &dyn Signer,
    ) -> Result<Vec<TardisAction>, NablaError> {
        // 1. Verify sender is our upstream
        match &self.up {
            Some(up_pk) if *up_pk == tick.upstream_pk => {}
            Some(_) => {
                // Demoted from warn → debug: when the env binds to a
                // non-loopback interface (e.g. 0.0.0.0 for cross-machine
                // wallet dev), every internet scanner that probes our
                // open Nabla TCP port produces one of these per tick
                // interval — at >10k/min, it floods logs and the
                // dashboard. Real upstream-confusion still surfaces at
                // higher levels (TARDIS rebuild path, peer-audit). Drop
                // this one to debug.
                log::debug!(
                    "Tick from unknown sender {:?}, expected upstream",
                    &tick.upstream_pk[..4]
                );
                return Ok(vec![TardisAction::None]);
            }
            None => return Err(NablaError::NoUpstream),
        }

        // 2. Combined bounds check (rewritten 2026-05-28 per the AXIOM
        //    wall-clock principle — see KI#18). Two bounds, only ONE of them
        //    uses wall clock (and only on the + side).
        //
        // ┌── tick-time lower bound (NEVER wall clock) ──┐
        //  self.current_tick  ≤  tick.number  ≤  now_secs + TICK_INTERVAL_SECS
        //                                       └── wall-clock upper bound, +5s ──┘
        //
        // Lower bound (tick.number < self.current_tick → REJECT): replay
        //   defense, derived purely from the receiver's accumulated tick
        //   state. Equality is accepted so the very first tick on a fresh
        //   node (current_tick=0) passes cleanly.
        //
        // Upper bound (tick.number > now_secs + 5 → REJECT): catches
        //   "future tick" claims by a sender whose wall clock has drifted
        //   forward. Wall clock is the right tool here BECAUSE the goal
        //   is to discipline absolute time — a node whose clock drifts
        //   forward gets every tick rejected by its children and
        //   self-ejects from the writer set. NO `-` (past-side) bound:
        //   stale ticks are not a timing violation; the tick-time lower
        //   bound above handles replay defense.
        //
        // Per the architectural rule: wall clock is permitted exactly
        // twice in AXIOM — (a) tick generation at the TARDIS root, (b)
        // this single forward-only verification. No `sleep` / timer /
        // schedule may derive from wall clock outside these two places.
        let now_secs = now_ms / 1000;
        let future_drift = tick.number as i64 - now_secs as i64;
        if future_drift > TICK_INTERVAL_SECS as i64 {
            // Sender's clock claims more than +5s into the future — reject.
            return Err(NablaError::TickTimingViolation {
                drift_ms: future_drift * 1000,
            });
        }
        if tick.number < self.current_tick {
            // Backward step in tick-time. Replay or out-of-order delivery.
            return Err(NablaError::NonSequentialTick {
                expected: self.current_tick,
                got: tick.number,
            });
        }

        // 3b. Duplicate-tick dedup (2026-05-28).
        // `tick.number == self.current_tick` is the same tick re-received via
        // a different gossip path. Treat as no-op: do NOT increment the
        // per-tick counters (rebalance_cooldown, ticks_since_parent_rotation,
        // ticks_with_current_parent, ticks_since_audit) because each
        // increment models ONE elapsed tick, not one received message.
        // Without this guard a node with N gossip peers re-incrementing each
        // tick produces `ticks_with_current_parent` values like 28876 in
        // ~1 minute, blowing past CHILD_ROTATION_INTERVAL_TICKS and
        // triggering the writer-rotate path immediately (observed in the
        // 2026-05-28 10-node smoke). The guard is fresh-node-safe because
        // `current_tick == 0` and the very first tick has `tick.number > 0`
        // (TARDIS ticks are wall-clock-seconds).
        if tick.number == self.current_tick && self.current_tick != 0 {
            return Ok(Vec::new());
        }

        // 4. Signature verification — MOVED to the caller (KI#18 fix,
        // 2026-05-28). Pre-fix this code passed `tick.upstream_pk` (the
        // BLAKE3(sphincs_pk) NodeId — a 32-byte HASH, not a curve point)
        // to `Ed25519Signer::verify`; verify always failed and the rest of
        // TARDIS silently swallowed every parent tick. The verification
        // key for a given node_id lives in its NBC (`subject_pubkey_ed25519`,
        // accessor `cc::nbc_ed25519_pk`), which `nabla_node.rs::recv_loop`
        // already has in scope via `verified_nbcs[tick.upstream_pk]`. The
        // recv_loop tier extracts the NBC's Ed25519 PK and verifies the
        // signature BEFORE process_tick runs — by the time we reach here,
        // the tick is already crypto-authenticated.
        //
        // `signer: &dyn Signer` stays on the function signature since
        // it's used below to sign the forwarded tick + approvals.

        // 4b. Writer check — REMOVED (v0.9.1).
        // All branches were no-ops (always returned false, never incremented streak).
        // Writer check on leaves is always destructive: drops parent dc with no benefit.
        // Genuinely broken parents are caught by stale tick detection (step 4)
        // and signature verification (step 4a). See §2.11.4.

        // 5. Accept tick
        self.current_tick = tick.number;
        self.last_tick_time_ms = now_ms;
        self.ticks_since_audit += 1;
        // Reset silent-parent counter — we DID receive a tick from upstream.
        self.silent_parent_ticks = 0;
        // Tick counters — only incremented here (process_tick is the canonical tick event).
        // set_tick() does NOT increment these to avoid double-counting in binary mode
        // where nodes call both set_tick() (tick_loop) and process_tick() (received tick).
        self.rebalance_cooldown = self.rebalance_cooldown.saturating_sub(1);
        self.ticks_since_parent_rotation = self.ticks_since_parent_rotation.saturating_add(1);
        self.ticks_with_current_parent = self.ticks_with_current_parent.saturating_add(1);

        // 5b. Store available slot info from tick (§2.2).
        // Every tick carries known open D slots. If parent dies, we already
        // know where to reconnect — no discovery delay.
        if !tick.available_slots.is_empty() {
            self.last_known_open_slots = tick.available_slots.clone();
        }

        let mut actions = Vec::new();

        // 5c. Grandpa-tick writer-integrity check.
        //
        // Three conditions, all evaluated against THIS tick:
        //   (i)  `grandparent_pk` present + `prev_sig` non-empty —
        //        structural signal that parent claims to be in a chain.
        //   (ii) `downstream_approvals >= 2` — parent's own attestation
        //        that it is a current writer. This is the cryptographically
        //        anchored check: the entire TickMessage is Ed25519-signed
        //        by parent (verified at `nabla_node.rs::recv_loop` against
        //        parent's NBC), so parent CANNOT lie about its own dc
        //        without invalidating the tick signature. When parent's
        //        chain breaks (e.g. parent loses children) the very next
        //        honestly-signed tick reflects the new `downstream_approvals`
        //        value, and we react to it within one tick.
        //   (iii) (deferred) cryptographic verification of `prev_sig`
        //        against `grandparent_pk`'s NBC-bound Ed25519 PK requires
        //        the grandparent's signed tick payload, which isn't
        //        currently carried in the wire. Adding it is a future
        //        extension; for the heal-storm bug we're solving today,
        //        (i)+(ii) is sufficient because (ii) catches the "phantom
        //        writer" pattern (parent thinks it's a writer but isn't).
        //
        // All three conditions MUST be true for grandpa_ok. On miss for
        // 10 consecutive ticks, emit DetachUpstream → orphan recovery.
        let parent_is_writer = tick.downstream_approvals >= 2;
        let chain_present = tick.grandparent_pk.is_some() && !tick.prev_sig.is_empty();
        let grandpa_ok = parent_is_writer && chain_present;
        if grandpa_ok {
            self.grandpa_miss_count = 0;
        } else {
            self.grandpa_miss_count = self.grandpa_miss_count.saturating_add(1);
            if self.grandpa_miss_count >= GRANDPA_MISS_DETACH_THRESHOLD {
                // Stage: detach. Caller acts on this by removing the parent
                // peer locally + sending TardisDetach up; orphan recovery
                // fires next tick via needs_parent().
                if let Some(parent) = self.up {
                    actions.push(TardisAction::DetachUpstream {
                        parent,
                        reason: DetachReason::GrandpaTickMissing,
                    });
                }
                self.grandpa_miss_count = 0; // reset; orphan recovery owns next steps
            }
        }

        // 6. Build signed tick to forward (we re-sign with our key).
        // grandparent_pk = our upstream's PK — that's the grandparent from
        // D1/D2's perspective, used by them to verify our forwarded prev_sig
        // and drive the grandpa-tick writer-integrity rule.
        // YPX-021 §6 OODS-tardis: fold THIS node's Core-produced draw into the
        // accumulator before relaying the tick down, so a fully-cascaded tick's
        // accumulator estimates the tree's size. Reuses the stateless Core
        // primitive (the value is Core-bound + deterministic). NOTE: the epoch
        // seed here is a per-epoch-stable placeholder derived from the tick
        // number — the §5.1 canonical committed-artifact (SMT-root) seed is the
        // hardening follow-up before this gates any decision.
        const OODS_EPOCH_TICKS: u64 = crate::constants::OODS_EPOCH_TICKS; // ~1h at 5s ticks (placeholder)
        let oods_tardis = {
            let seed = axiom_core_logic::oods_verify::oods_epoch_seed(
                tick.number / OODS_EPOCH_TICKS,
                &[],
            );
            let mine = axiom_core_logic::oods_verify::oods_produce(&self.my_pk, &seed);
            let mut acc = tick.oods_tardis.clone();
            if acc.is_empty() {
                acc = mine;
            } else {
                axiom_core_logic::oods_verify::oods_fold(&mut acc, &mine);
            }
            acc
        };
        let mut forward_tick = TickMessage {
            number: tick.number,
            upstream_pk: self.my_pk,
            payload: tick.payload.clone(),
            signature: vec![], // filled below
            prev_sig: tick.signature.clone(), // chain proof: parent's signature
            grandparent_pk: self.up, // our upstream = D1/D2's grandparent
            timestamp_ms: now_ms,
            available_slots: tick.available_slots.clone(),
            downstream_approvals: self.prev_round_approval_count, // OWN approval count, not parent's
            subtree_d_available: self.subtree_d_available, // aggregated from children's approvals
            oods_tardis,
            // TARDIS lineage (§7.6 Phase 2): our downstream set, bound into our commitment
            // so our grandchildren can verify strict-parent (their parent ∈ our children).
            child_pks: self.children(),
            // The grandparent's (= our upstream's) commitment fields, so our children can
            // recompute it and verify prev_sig (= our upstream's signature) against the
            // upstream's NBC key. `tick` is what WE received from our upstream; prev_sig
            // above is `tick.signature`, so these are exactly its commitment's pre-image.
            gp_commitment: Some(GpCommitment {
                number: tick.number,
                timestamp_ms: tick.timestamp_ms,
                payload: tick.payload.clone(),
                downstream_approvals: tick.downstream_approvals,
                prev_sig: tick.prev_sig.clone(),
                child_pks: tick.child_pks.clone(),
                oods_hash: crypto::oods_tardis_hash(&tick.oods_tardis),
            }),
        };
        forward_tick.signature = signer.sign(&crypto::tick_commitment(&forward_tick));

        // 7. Forward to downstream (TARDIS tree only)
        let mut targets = Vec::new();
        if let Some(d1) = &self.d1 {
            targets.push(*d1);
        }
        if let Some(d2) = &self.d2 {
            targets.push(*d2);
        }
        if let Some(p) = &self.pending {
            targets.push(*p);
        }
        if !targets.is_empty() {
            actions.push(TardisAction::ForwardTick {
                tick: forward_tick,
                targets,
            });
        }

        // 8. Send approval back to upstream
        let mut approval = TickApproval {
            tick_number: tick.number,
            approver_pk: self.my_pk,
            signature: vec![], // filled below
            subtree_open_d: self.subtree_d_available,
        };
        approval.signature = signer.sign(&crypto::approval_sign_payload(&approval));
        if let Some(up_pk) = &self.up {
            actions.push(TardisAction::SendApproval {
                approval,
                target: *up_pk,
            });
        }

        // 9. Broadcast root hash via gossip mesh for partition detection
        actions.push(TardisAction::BroadcastRootHash {
            tick: tick.number,
            root_hash: smt.root_hash(),
            node_pk: self.my_pk,
        });

        Ok(actions)
    }

    // ── Downstream Approval (§5.4) ──

    /// Receive an approval from a downstream node.
    /// Stores it as evidence that the tick was legitimate.
    ///
    /// **KI#20 (2026-05-28):** signature verification was lifted out of
    /// this function and into `nabla_node.rs::recv_loop` because
    /// `approval.approver_pk` is a `PeerId = BLAKE3(sphincs_pk)` (a
    /// 32-byte HASH, not a curve point), so the previous
    /// `signer.verify(&approval.approver_pk, …)` call failed 100% of
    /// the time, generating ~51K `Approval signature verification
    /// failed` warnings per node in a 3-min idle window. Same fix
    /// pattern as c7ebe4eb KI#18 and KI#19 (audit-response sig). The
    /// caller now verifies the sig against the NBC-bound Ed25519 PK
    /// via `verified_nbcs[approver_pk].subject_pubkey_ed25519` BEFORE
    /// invoking this function.
    ///
    /// `signer` is retained in the signature for binary-compat with
    /// the test suite (NoopSigner) but is no longer consulted.
    pub fn receive_approval(&mut self, approval: &TickApproval, _signer: &dyn Signer) -> bool {
        // Verify the approval is for our current tick
        if approval.tick_number != self.current_tick {
            // DEBUG, not WARN: stale approvals are a normal artefact of
            // mesh-propagation lag — every late approval at every node
            // generates one. The downstream behaviour (rejection + return
            // false) is the actionable signal; the log line at WARN was
            // operational noise during sustained load (2026-05-30 soak).
            log::debug!(
                "Stale approval: tick {} (current {})",
                approval.tick_number,
                self.current_tick
            );
            return false;
        }

        // Verify it's from one of our downstream nodes
        let is_downstream = self
            .d1
            .map(|d| d == approval.approver_pk)
            .unwrap_or(false)
            || self
                .d2
                .map(|d| d == approval.approver_pk)
                .unwrap_or(false)
            || self
                .pending
                .map(|p| p == approval.approver_pk)
                .unwrap_or(false);

        if !is_downstream {
            log::warn!(
                "Approval from unknown node {:?}",
                &approval.approver_pk[..4]
            );
            return false;
        }

        true
    }

    // ── Bottom-Up Verification (§5.5) ──

    /// Generate a random subtree audit challenge for our upstream.
    /// Called periodically (e.g., every few ticks).
    pub fn generate_audit_request(&self) -> Option<TardisAction> {
        let up_pk = self.up?;

        // Pick a random prefix — one byte = audit 1/256th of keyspace
        // Use tick + our pk as entropy source (deterministic but unpredictable to upstream)
        let prefix_byte =
            blake3::hash(&[&self.current_tick.to_le_bytes()[..], &self.my_pk[..]].concat());
        let prefix = vec![prefix_byte.as_bytes()[0]];

        let request = SubtreeAuditRequest {
            prefix,
            prefix_bits: 8,
            request_tick: self.current_tick,
            requester_pk: self.my_pk,
        };

        Some(TardisAction::SendAuditRequest {
            request,
            target: up_pk,
        })
    }

    /// Handle an audit request from a downstream node.
    /// Returns the subtree proof for the requested prefix.
    pub fn handle_audit_request(
        &self,
        request: &SubtreeAuditRequest,
        smt: &SparseMerkleTree,
        signer: &dyn Signer,
    ) -> TardisAction {
        let subtree_hash = smt.subtree_hash_at(request.prefix_bits);
        let root_hash = smt.root_hash();

        let mut response = SubtreeAuditResponse {
            prefix: request.prefix.clone(),
            prefix_bits: request.prefix_bits,
            subtree_hash,
            root_hash,
            response_tick: self.current_tick,
            responder_pk: self.my_pk,
            signature: vec![], // filled below
        };
        response.signature = signer.sign(&crypto::audit_response_sign_payload(&response));

        TardisAction::SendAuditResponse {
            response,
            target: request.requester_pk,
        }
    }

    /// Verify an audit response from upstream.
    ///
    /// **KI#19 (2026-05-28):** signature verification was lifted out of
    /// this function and into `nabla_node.rs::recv_loop` because
    /// `response.responder_pk` is a `PeerId = BLAKE3(sphincs_pk)` (a
    /// 32-byte HASH, not a curve point), so the previous
    /// `signer.verify(&response.responder_pk, …)` call failed 100% of
    /// the time and cascaded a QUESTIONABLE alert per audit response
    /// (>190,000:1 amplification observed). The caller now verifies
    /// the sig against the NBC-bound Ed25519 PK via
    /// `verified_nbcs[responder_pk].subject_pubkey_ed25519` BEFORE
    /// invoking this function. By the time we reach this code path the
    /// responder is authenticated.
    ///
    /// Remaining check here: SMT root mismatch ⇒ flag upstream as
    /// questionable.
    pub fn verify_audit_response(
        &mut self,
        response: &SubtreeAuditResponse,
        our_smt: &SparseMerkleTree,
        signer: &dyn Signer,
    ) -> Result<TardisAction, NablaError> {
        // Compare upstream's root hash against what we expect.
        let our_root = our_smt.root_hash();

        if response.root_hash != our_root {
            log::warn!(
                "Audit: root mismatch. Upstream: {:?}, ours: {:?}",
                &response.root_hash[..4],
                &our_root[..4]
            );

            return Ok(self.flag_questionable(response.responder_pk, signer));
        }

        // Audit passed
        self.audit_pass_count += 1;
        self.ticks_since_audit = 0;
        log::debug!(
            "Audit passed (count: {}), root: {:?}",
            self.audit_pass_count,
            &our_root[..4]
        );

        Ok(TardisAction::None)
    }

    // ── Questionable Cascade (§5.5) ──

    /// KI#37 — canonical dedup key for a QuestionableAlert. The sign
    /// payload covers (suspect, reporter, tick, evidence_hash): every
    /// re-forwarded copy of one minted alert hashes identically.
    fn alert_seen_key(alert: &QuestionableAlert) -> [u8; 32] {
        *blake3::hash(&crypto::alert_sign_payload(alert)).as_bytes()
    }

    /// KI#37 — record an alert as seen. Returns `true` if it was NEW,
    /// `false` if already seen (caller must drop it). Bounded FIFO.
    fn record_alert_seen(&mut self, key: [u8; 32]) -> bool {
        if !self.seen_alerts.insert(key) {
            return false;
        }
        self.seen_alerts_order.push_back(key);
        if self.seen_alerts_order.len() > ALERT_SEEN_CAP {
            if let Some(oldest) = self.seen_alerts_order.pop_front() {
                self.seen_alerts.remove(&oldest);
            }
        }
        true
    }

    /// KI#37 — per-reporter accept-rate check. Returns `true` if this
    /// reporter is within budget for the current window (accept), `false`
    /// if it has exceeded `ALERT_MAX_PER_REPORTER_PER_WINDOW` (drop).
    /// Only called for alerts that already passed dedup, so it counts
    /// DISTINCT alerts — exactly the malicious-valid-node vector.
    fn alert_rate_ok(&mut self, reporter: PeerId) -> bool {
        let entry = self.alert_rate.entry(reporter).or_insert((self.current_tick, 0));
        if self.current_tick.saturating_sub(entry.0) >= ALERT_RATE_WINDOW_SECS {
            *entry = (self.current_tick, 0);
        }
        entry.1 += 1;
        entry.1 <= ALERT_MAX_PER_REPORTER_PER_WINDOW
    }

    /// Flag upstream as questionable and cascade alert to downstream.
    fn flag_questionable(&mut self, suspect: PeerId, signer: &dyn Signer) -> TardisAction {
        log::warn!(
            "Flagging upstream {:?} as QUESTIONABLE at tick {}",
            &suspect[..4],
            self.current_tick
        );

        // 1. Mark upstream status
        self.upstream_status = NodeStatus::Questionable;

        // 2. Build alert
        let evidence_hash = blake3::hash(
            &[
                &self.current_tick.to_le_bytes()[..],
                &suspect[..],
                &self.my_pk[..],
            ]
            .concat(),
        );

        let mut alert = QuestionableAlert {
            suspect_pk: suspect,
            reporter_pk: self.my_pk,
            tick: self.current_tick,
            evidence_hash: *evidence_hash.as_bytes(),
            signature: vec![], // filled below
        };
        alert.signature = signer.sign(&crypto::alert_sign_payload(&alert));

        // KI#37 — record our own minted alert as seen, so the cascade
        // looping back through a transient tree cycle is dropped instead
        // of re-triggering detach + re-forward.
        let _ = self.record_alert_seen(Self::alert_seen_key(&alert));

        // 3. Disconnect from upstream
        self.up = None;
        self.upstream_status = NodeStatus::Disconnected;
        self.audit_pass_count = 0;

        // 4. Cascade alert to all downstream
        let mut targets = Vec::new();
        if let Some(d1) = &self.d1 {
            targets.push(*d1);
        }
        if let Some(d2) = &self.d2 {
            targets.push(*d2);
        }
        if let Some(p) = &self.pending {
            targets.push(*p);
        }
        // KI#37 — never forward to self (a stale slot can transiently hold
        // our own pk during thrash; observed as a node flooding itself).
        targets.retain(|t| t != &self.my_pk);

        if targets.is_empty() {
            TardisAction::None
        } else {
            TardisAction::CascadeAlert { alert, targets }
        }
    }

    /// §7.6: emit a QuestionableAlert against `suspect` for a LINEAGE VIOLATION —
    /// the suspect forwarded a tick whose lineage failed cryptographic verification.
    /// Rate-limited (`alert_rate_ok`) + deduped (`record_alert_seen`) — the KI#37 storm
    /// hygiene. Unlike `flag_questionable`, this does NOT detach or set upstream_status:
    /// it is a pure accusation into the quarantine-consensus channel (the suspect need
    /// not be our upstream). Returns the cascade action, or `None` if rate-limited /
    /// dedup-suppressed / no downstream to cascade to. The CALLER must only invoke this
    /// after verifying the suspect's OWN tick signature (anti-framing — see nabla_node).
    pub fn flag_lineage_violation(&mut self, suspect: PeerId, signer: &dyn Signer) -> TardisAction {
        if !self.alert_rate_ok(self.my_pk) {
            return TardisAction::None;
        }
        let evidence_hash = blake3::hash(
            &[
                &self.current_tick.to_le_bytes()[..],
                &suspect[..],
                &self.my_pk[..],
            ]
            .concat(),
        );
        let mut alert = QuestionableAlert {
            suspect_pk: suspect,
            reporter_pk: self.my_pk,
            tick: self.current_tick,
            evidence_hash: *evidence_hash.as_bytes(),
            signature: vec![],
        };
        alert.signature = signer.sign(&crypto::alert_sign_payload(&alert));
        if !self.record_alert_seen(Self::alert_seen_key(&alert)) {
            return TardisAction::None; // already emitted this accusation
        }
        let mut targets = Vec::new();
        if let Some(d1) = &self.d1 {
            targets.push(*d1);
        }
        if let Some(d2) = &self.d2 {
            targets.push(*d2);
        }
        if let Some(p) = &self.pending {
            targets.push(*p);
        }
        targets.retain(|t| t != &self.my_pk && t != &suspect);
        if targets.is_empty() {
            TardisAction::None
        } else {
            TardisAction::CascadeAlert { alert, targets }
        }
    }

    /// Handle a questionable alert from upstream (cascade received).
    pub fn handle_questionable_alert(&mut self, alert: &QuestionableAlert, signer: &dyn Signer) -> TardisAction {
        // ── KI#37 cascade hygiene (2026-07-08) ──
        // Pre-fix this method re-forwarded EVERY received alert to the
        // node's current d1/d2/pending with no dedup and no age bound.
        // The tick tree thrashes under CPU pressure, transient cycles
        // form, and one alert then circulates forever — measured as a
        // single 180-byte frame at ~9.2k copies/s into one node,
        // ~24 MB/s across an IDLE 10-node mesh, which starves ticks,
        // mints more alerts, and sustains itself. Two gates close it:
        //
        // (1) Freshness: an alert older than ALERT_MAX_AGE_SECS is dead —
        //     legitimate cascade propagation completes in seconds.
        if alert.tick.saturating_add(ALERT_MAX_AGE_SECS) < self.current_tick {
            log::debug!(
                "Dropping stale QUESTIONABLE alert (tick {} vs current {})",
                alert.tick,
                self.current_tick
            );
            return TardisAction::None;
        }
        // (2) Dedup: each distinct alert is acted on ONCE per node. This
        //     bounds any cascade to one delivery per node per alert, so
        //     even a cyclic tree cannot amplify.
        if !self.record_alert_seen(Self::alert_seen_key(alert)) {
            return TardisAction::None;
        }
        // (3) Per-reporter rate limit: a VALID-NBC node that turns
        //     malicious can still mint DISTINCT fresh alerts that each
        //     pass dedup. Cap the accepted rate per reporter — excess is
        //     dropped, and a reporter over budget is itself a quarantine
        //     candidate (accuses faster than any honest audit cadence).
        if !self.alert_rate_ok(alert.reporter_pk) {
            log::warn!(
                "Rate-limiting QUESTIONABLE alerts from reporter {:?} (>{} per window) — dropping",
                &alert.reporter_pk[..4],
                ALERT_MAX_PER_REPORTER_PER_WINDOW
            );
            return TardisAction::None;
        }

        // DEBUG, not WARN: every node along the cascade path receives and
        // re-forwards the same alert, so a single originating event produces
        // ~30-40 entries per node per cascade (>99% of nabla.log volume
        // measured 2026-05-30). The ORIGINATING WARN in flag_questionable()
        // is the one to grep for during incident triage; this cascade-side
        // line is operational noise at WARN.
        log::debug!(
            "Received QUESTIONABLE alert for {:?} from {:?} at tick {}",
            &alert.suspect_pk[..4],
            &alert.reporter_pk[..4],
            alert.tick
        );

        // If the suspect is our upstream, disconnect
        if self.up.map(|u| u == alert.suspect_pk).unwrap_or(false) {
            return self.flag_questionable(alert.suspect_pk, signer);
        }

        // Otherwise just cascade the alert downward
        let mut targets = Vec::new();
        if let Some(d1) = &self.d1 {
            targets.push(*d1);
        }
        if let Some(d2) = &self.d2 {
            targets.push(*d2);
        }
        if let Some(p) = &self.pending {
            targets.push(*p);
        }
        // KI#37 — never forward to self (see flag_questionable).
        targets.retain(|t| t != &self.my_pk);

        if targets.is_empty() {
            TardisAction::None
        } else {
            TardisAction::CascadeAlert {
                alert: alert.clone(),
                targets,
            }
        }
    }

    // ── Maturity Window (§5.6) ──

    /// Check if a registration is mature (can achieve CLEAN status).
    pub fn check_maturity(&self, registration_tick: u64) -> ChequeStatus {
        // No tick authority → cannot issue CLEAN
        if self.upstream_status == NodeStatus::Disconnected {
            return ChequeStatus::Scarred;
        }

        let maturity = self.dynamic_maturity_ticks();
        // current_tick and registration_tick are tick VALUES (unix seconds); maturity is a
        // tick COUNT → project it through the SINGLE shared `ticks_to_secs` helper (the same
        // projection the recall window and hibernation use — no inline `* TICK_INTERVAL_SECS`).
        if self.current_tick >= registration_tick + axiom_core_logic::types::ticks_to_secs(maturity) {
            ChequeStatus::Clean
        } else {
            ChequeStatus::Scarred
        }
    }

    /// Dynamic maturity window — adapts to network size (§5.6).
    ///
    /// Formula: clamp(ceil(log(seen) / log(peers)) + 2, MIN, MAX)
    ///
    /// The +2 safety margin ensures maturity always exceeds actual gossip time.
    pub fn dynamic_maturity_ticks(&self) -> u64 {
        let seen = self.unique_nodes_seen.max(1) as f64;
        let peers = self.mesh_peer_count.max(2) as f64;

        let ticks = (seen.ln() / peers.ln()).ceil() as u64 + 2;
        ticks.clamp(MATURITY_TICKS_MIN, MATURITY_TICKS_MAX)
    }

    // ── Slot Management ──

    /// Set upstream connection.
    pub fn set_upstream(&mut self, peer: PeerId) {
        // Cycle prevention: never set a downstream child as our upstream
        if self.d1.as_ref() == Some(&peer) || self.d2.as_ref() == Some(&peer) {
            log::warn!("Cycle prevented: attempted to set downstream {:?} as upstream", &peer[..4]);
            return;
        }
        if peer == self.my_pk {
            log::warn!("Cycle prevented: attempted to set self as upstream");
            return;
        }
        self.up = Some(peer);
        self.upstream_status = NodeStatus::Connected;
        self.audit_pass_count = 0;
        self.ticks_since_audit = 0;
        self.ticks_with_current_parent = 0;
        log::info!("Upstream set to {:?}", &peer[..4]);
    }

    /// Add a downstream child. Returns false if both D slots are full.
    pub fn add_downstream(&mut self, peer: PeerId) -> bool {
        // Cycle prevention: never add our own upstream as a downstream child
        if self.up.as_ref() == Some(&peer) {
            return false;
        }
        // Don't add ourselves
        if peer == self.my_pk {
            return false;
        }
        // Don't add if already a downstream
        if self.d1.as_ref() == Some(&peer) || self.d2.as_ref() == Some(&peer) {
            return false;
        }
        // §2.3: Check if peer is reclaiming a reserved slot (priority access).
        // The original child can always reclaim its slot, even during reservation.
        if self.d1.is_none() && self.d1_reserved.as_ref().is_some_and(|(p, _)| *p == peer) {
            self.d1 = Some(peer);
            self.d1_reserved = None; // clear reservation
            self.d1_misses = 0;
            return true;
        }
        if self.d2.is_none() && self.d2_reserved.as_ref().is_some_and(|(p, _)| *p == peer) {
            self.d2 = Some(peer);
            self.d2_reserved = None;
            self.d2_misses = 0;
            return true;
        }
        // Normal path: find an open AND unreserved slot
        if self.d1.is_none() && self.d1_reserved.is_none() {
            self.d1 = Some(peer);
            self.d1_misses = 0;
            true
        } else if self.d2.is_none() && self.d2_reserved.is_none() {
            self.d2 = Some(peer);
            self.d2_misses = 0;
            true
        } else {
            false
        }
    }

    /// Set pending node (waiting for a D slot).
    pub fn set_pending(&mut self, peer: PeerId) {
        self.pending = Some(peer);
    }

    /// Remove a peer from all slots.
    pub fn remove_peer(&mut self, peer: &PeerId) {
        if self.up.as_ref() == Some(peer) {
            self.up = None;
            self.upstream_status = NodeStatus::Disconnected;
        }
        if self.d1.as_ref() == Some(peer) {
            self.d1 = None;
            self.d1_misses = 0;
        }
        if self.d2.as_ref() == Some(peer) {
            self.d2 = None;
            self.d2_misses = 0;
        }
        if self.pending.as_ref() == Some(peer) {
            self.pending = None;
        }
    }

    /// Remove a D child but reserve the slot for D_RESERVATION_TICKS (§2.3).
    /// Used when child goes offline (death/disconnect) — NOT for voluntary
    /// detach (rotation, rebalance). The original child can reclaim the slot
    /// immediately; other nodes must wait until reservation expires.
    pub fn remove_peer_reserved(&mut self, peer: &PeerId, current_tick: u64) {
        if self.d1.as_ref() == Some(peer) {
            self.d1_reserved = Some((*peer, current_tick));
            self.d1 = None;
            self.d1_misses = 0;
        }
        if self.d2.as_ref() == Some(peer) {
            self.d2_reserved = Some((*peer, current_tick));
            self.d2 = None;
            self.d2_misses = 0;
        }
        // UP and P don't get reservations
        if self.up.as_ref() == Some(peer) {
            self.up = None;
            self.upstream_status = NodeStatus::Disconnected;
        }
        if self.pending.as_ref() == Some(peer) {
            self.pending = None;
        }
    }

    /// Expire old D slot reservations. Call once per tick.
    /// Returns list of expired reservation peer IDs (for logging).
    pub fn check_reservations(&mut self, current_tick: u64) -> Vec<PeerId> {
        let mut expired = Vec::new();
        if let Some((peer, reserved_tick)) = self.d1_reserved {
            if current_tick.saturating_sub(reserved_tick) >= D_RESERVATION_TICKS {
                self.d1_reserved = None;
                expired.push(peer);
            }
        }
        if let Some((peer, reserved_tick)) = self.d2_reserved {
            if current_tick.saturating_sub(reserved_tick) >= D_RESERVATION_TICKS {
                self.d2_reserved = None;
                expired.push(peer);
            }
        }
        expired
    }

    /// Check if a peer has a valid reservation on one of our D slots.
    pub fn has_reservation_for(&self, peer: &PeerId) -> bool {
        self.d1_reserved.as_ref().is_some_and(|(p, _)| p == peer)
            || self.d2_reserved.as_ref().is_some_and(|(p, _)| p == peer)
    }

    /// Promote pending node to an open D slot (if available).
    pub fn promote_pending(&mut self) -> bool {
        if let Some(p) = self.pending.take() {
            self.add_downstream(p)
        } else {
            false
        }
    }

    /// Update network size observations (called when gossip reveals new peers).
    pub fn update_network_size(&mut self, unique_nodes_seen: u64, mesh_peer_count: u64) {
        self.unique_nodes_seen = unique_nodes_seen.max(1);
        self.mesh_peer_count = mesh_peer_count;
    }

    // ── Seed Bootstrap (§5.7) ──

    /// Create seed triangle: 3 nodes forming circular tick flow.
    ///
    /// S1: UP:S3  D1:S2  D2:(open)
    /// S2: UP:S1  D1:S3  D2:(open)
    /// S3: UP:S2  D1:S1  D2:(open)
    pub fn bootstrap_genesis_ring(pks: [PeerId; 3]) -> [TardisNode; 3] {
        [
            TardisNode::new_with_ring_links(pks[0], pks[2], pks[1]), // S1: UP=S3, D1=S2
            TardisNode::new_with_ring_links(pks[1], pks[0], pks[2]), // S2: UP=S1, D1=S3
            TardisNode::new_with_ring_links(pks[2], pks[1], pks[0]), // S3: UP=S2, D1=S1
        ]
    }

    // ── Getters ──

    pub fn current_tick(&self) -> u64 {
        self.current_tick
    }
    /// Fix #1: cumulative TARDIS tick-signature verify failures since
    /// boot. Read by the dashboard /status path. A non-zero rate
    /// flags upstream signing-key drift, transport corruption, or
    /// replay of stale ticks. See `process_tick` for the increment
    /// site and the structured `[TICK-SIG-FAIL]` log lines.
    pub fn tick_sig_failures(&self) -> u64 {
        self.tick_sig_failures
    }
    pub fn upstream_status(&self) -> NodeStatus {
        self.upstream_status
    }
    pub fn has_upstream(&self) -> bool {
        self.up.is_some() && self.upstream_status == NodeStatus::Connected
    }
    pub fn upstream(&self) -> Option<&PeerId> {
        self.up.as_ref()
    }
    pub fn downstream_count(&self) -> usize {
        self.d1.is_some() as usize + self.d2.is_some() as usize
    }
    pub fn my_pk(&self) -> &PeerId {
        &self.my_pk
    }
    pub fn is_leaf(&self) -> bool {
        self.d1.is_none() && self.d2.is_none()
    }
    pub fn prev_round_approval_count(&self) -> u8 {
        self.prev_round_approval_count
    }
    pub fn subtree_d_available(&self) -> u32 {
        self.subtree_d_available
    }
    pub fn has_d_open(&self) -> bool {
        // A slot is open only if empty AND not reserved (§2.3).
        // Reserved slots are held for the original child to reclaim.
        let d1_open = self.d1.is_none() && self.d1_reserved.is_none();
        let d2_open = self.d2.is_none() && self.d2_reserved.is_none();
        d1_open || d2_open
    }

    /// Number of truly open D slots (empty and unreserved).
    pub fn open_d_count(&self) -> u8 {
        let d1 = if self.d1.is_none() && self.d1_reserved.is_none() { 1 } else { 0 };
        let d2 = if self.d2.is_none() && self.d2_reserved.is_none() { 1 } else { 0 };
        d1 + d2
    }
    pub fn d1(&self) -> Option<&PeerId> {
        self.d1.as_ref()
    }
    pub fn d2(&self) -> Option<&PeerId> {
        self.d2.as_ref()
    }
    pub fn pending(&self) -> Option<&PeerId> {
        self.pending.as_ref()
    }
    pub fn audit_pass_count(&self) -> u64 {
        self.audit_pass_count
    }

    /// Downstream approval count from the previous round.
    pub fn downstream_approval_count(&self) -> u8 {
        self.prev_round_approval_count
    }

    /// Last known open slots (piggybacked from tick messages).
    pub fn available_slots(&self) -> Vec<(PeerId, u32)> {
        self.last_known_open_slots.clone()
    }

    /// List of downstream children (D1, D2, and pending).
    pub fn children(&self) -> Vec<PeerId> {
        let mut kids = Vec::with_capacity(3);
        if let Some(d1) = &self.d1 { kids.push(*d1); }
        if let Some(d2) = &self.d2 { kids.push(*d2); }
        if let Some(p) = &self.pending { kids.push(*p); }
        kids
    }
    pub fn ticks_with_parent(&self) -> u32 {
        self.ticks_with_current_parent
    }

    /// Current rebalance cooldown value. Returns 0 if not gated;
    /// `REBALANCE_COOLDOWN_TICKS + 1 = 11` immediately after a rotation
    /// fires, decrementing 1/tick. Exposed for KI#18 rotation diagnostics.
    pub fn rebalance_cooldown(&self) -> u8 {
        self.rebalance_cooldown
    }

    /// Set tick directly (used by tick originators — tree roots and cycle entry points).
    /// These nodes generate their own tick from NTP rather than receiving from upstream.
    /// NOTE: Rotation counters (ticks_since_parent_rotation, ticks_with_current_parent)
    /// are incremented ONLY in process_tick() — the canonical "received a tick" event.
    /// Incrementing here too would double-count for nodes that both call set_tick()
    /// and receive ticks via process_tick().
    pub fn set_tick(&mut self, tick: u64, now_ms: u64) {
        self.current_tick = tick;
        self.last_tick_time_ms = now_ms;
        // Tick down rebalance cooldown
        self.rebalance_cooldown = self.rebalance_cooldown.saturating_sub(1);
    }

    /// Per-tick silent-parent check, called once per tick from the
    /// tick_loop AFTER message processing (so any received tick has
    /// already reset the counter via process_tick).
    ///
    /// Logic:
    ///   - If I have no upstream: reset counter (orphan-recovery owns this)
    ///   - Else: increment counter. If >= SILENT_PARENT_THRESHOLD, emit
    ///     DetachUpstream { reason: SilentParent } and reset.
    ///
    /// Catches the phantom-child pattern where I think I have a parent
    /// (has_upstream=true) but parent's d1/d2 doesn't include me (stale
    /// state) so parent never forwards ticks down. Without this rule
    /// I'd sit attached forever, never reseeking.
    pub fn check_silent_parent(&mut self) -> Option<TardisAction> {
        let Some(parent) = self.up else {
            self.silent_parent_ticks = 0;
            return None;
        };
        self.silent_parent_ticks = self.silent_parent_ticks.saturating_add(1);
        if self.silent_parent_ticks >= SILENT_PARENT_THRESHOLD {
            self.silent_parent_ticks = 0;
            return Some(TardisAction::DetachUpstream {
                parent,
                reason: DetachReason::SilentParent,
            });
        }
        None
    }

    /// Whether this node should trigger an audit this tick.
    /// Audits once every 5 ticks (25 seconds) — sufficient coverage.
    pub fn should_audit(&self) -> bool {
        self.up.is_some() && self.ticks_since_audit >= 5
    }

    /// Record a successful audit pass (§9, GAP-07).
    /// Called by the sim when root hashes match, avoiding the borrow conflict
    /// that would occur from calling verify_audit_response with the same SimNode's SMT.
    /// Equivalent to the pass path of verify_audit_response().
    pub fn record_audit_pass(&mut self) {
        self.audit_pass_count += 1;
        self.ticks_since_audit = 0;
    }

    // ── Recovery (§2.2) ──

    /// Returns true if this node has no upstream and needs to find a parent.
    /// This applies to ALL nodes equally — genesis, seed, or regular.
    /// A node that has lost its parent must find a new one to get approval.
    pub fn needs_parent(&self) -> bool {
        !self.has_upstream()
    }

    /// Returns the last known open D slots received from tick messages (§2.2).
    /// These are candidates for instant reconnection when upstream dies.
    /// The caller (network layer) should try these first before mesh discovery.
    pub fn recovery_candidates(&self) -> &[(PeerId, u32)] {
        &self.last_known_open_slots
    }

    // ── Recovery Placement Strategy (§2.6 — protocol-level) ──
    //
    // When an orphan is placed, the protocol decides WHERE it goes:
    //
    //   1. Orphans WITH children prefer dc=1 parents (attaching creates a writer)
    //   2. Orphans WITHOUT children accept any open slot
    //   3. If pass-1 (strict) finds nothing, pass-2 (relaxed) accepts any slot
    //
    // This two-pass strategy is a PROTOCOL DECISION about tree topology
    // optimization. It lives here, not in the simulator, because:
    //   - It determines writer distribution (protocol concern)
    //   - Production nodes make this same decision locally
    //   - The sim must match production behavior (§2.6 rule)

    /// Does this orphan prefer a dc=1 parent? Returns true if orphan has children,
    /// meaning placing it under a dc=1 parent would create a new writer (dc=1→dc=2).
    /// Orphans without children don't benefit from this preference.
    pub fn recovery_prefers_writer_parent(&self) -> bool {
        // ALL orphans prefer dc=1 parents — landing there creates a writer.
        // Landing at dc=0 creates a dc=1 "half-writer" which wastes capacity.
        // The two-pass system (strict→relaxed) ensures we fall back to dc=0
        // when no dc=1 is available, so this never causes recovery failure.
        true
    }

    /// Check if a candidate parent is acceptable given the current recovery pass.
    ///
    /// Protocol rule: on strict pass (prefer_writer=true), only accept candidates
    /// with exactly 1 child (dc=1) — attaching here creates a writer.
    /// On relaxed pass (prefer_writer=false), accept any node with an open slot.
    ///
    /// This is a static protocol method — no instance state needed.
    pub fn recovery_candidate_acceptable(candidate_dc: usize, prefer_writer: bool) -> bool {
        !prefer_writer || candidate_dc == 1
    }

    /// Update the known open slots (called by network layer when receiving
    /// slot availability info via gossip or tick messages).
    pub fn update_known_slots(&mut self, slots: Vec<(PeerId, u32)>) {
        self.last_known_open_slots = slots;
    }

    // ── Sender → Writer Routing (§1.2.1, §2.16) ──

    /// Check if this node is a qualified WRITER (dc=2, has 2 downstream approvals).
    /// Writers can record transactions. Readers redirect to writers.
    pub fn is_self_writer(&self) -> bool {
        // Writer = has 2 downstream children (structural property of the TARDIS tree).
        // prev_round_approval_count tracks liveness (child responsiveness) and is used
        // for downstream rotation decisions, but does NOT gate writer status.
        // A dc=2 node IS a writer by topology — approval jitter in TCP mode should not
        // cause writer status to flicker, which blocks Nabla registration.
        self.downstream_count() >= 2
    }

    /// Returns the upstream parent PeerId if this node is a READER and needs
    /// to redirect a transaction sender to a writer. Walk upstream until finding
    /// a writer (dc=2 node). Maximum one extra hop in a healthy tree.
    ///
    /// Returns:
    ///   - None → this node IS a writer (handle locally)
    ///   - Some(parent_pk) → redirect sender to this parent
    ///
    /// In production, the parent is the most likely writer (it has us + sibling
    /// as children → dc=2). If parent is also a reader (dc=1), the transaction
    /// follows the chain up. The caller tracks hop count to prevent loops.
    pub fn find_nearest_writer(&self) -> Option<PeerId> {
        if self.is_self_writer() {
            return None; // We ARE a writer — handle locally
        }
        // Redirect to upstream parent (most likely a writer)
        self.up
    }

    // ── Rebalancing (§2.2 extension) ──
    //
    // After kill/restore cycles, the tree degrades into long chains
    // (dc=1→dc=1→dc=1→dc=0) where almost no node has 2 children.
    // Write% collapses because writers need dc=2.
    //
    // Fix: a leaf under a non-writer parent voluntarily detaches and
    // re-enters orphan recovery, which places it at a dc=1 parent
    // (making that parent dc=2 = writer). Net: +1 writer per move.
    //
    // Decision uses ONLY local state:
    //   - Am I a leaf? (dc=0)
    //   - Is my parent in the open_slots list? (parent has open D slot → not a writer)
    //   - Is there at least one OTHER node with open slots? (somewhere to go)
    //   - Am I off cooldown? (prevent churn)

    /// Protocol-level decision: should this node voluntarily detach for rebalancing?
    /// Uses only local state + topology knowledge from tick piggyback.
    pub fn wants_rebalance(&self) -> bool {
        // §2.15.3: DISABLED in steady-state networks.
        //
        // Rebalance (move leaf from dc=2 parent to dc=1 parent) is zero-sum:
        //   old parent: dc=2 → dc=1 (−1 writer)
        //   target:     dc=1 → dc=2 (+1 writer)
        //   Net writer change: 0
        //
        // Writer density is controlled entirely by recovery placement
        // (recovery_prefers_writer_parent → strict mode prefers dc=1).
        // Rotation creates transient orphans → recovery places them at dc=1
        // nodes → writer count self-corrects without rebalance.
        //
        // Rebalance is only useful during network GROWTH when new nodes
        // join at structurally imbalanced positions. This will be re-enabled
        // with growth-detection logic when node joining is implemented.
        false
    }

    /// Mark cooldown after voluntary rebalance detach.
    /// Prevents the node from immediately volunteering again.
    pub fn set_rebalance_cooldown(&mut self) {
        // +1 because process_tick decrements cooldown in the same tick cycle
        // that rebalance runs, making effective cooldown = TICKS - 1 without it.
        self.rebalance_cooldown = REBALANCE_COOLDOWN_TICKS + 1;
    }

    // ── Rotation — Tree Anti-Ossification ──
    //
    // Two complementary mechanisms prevent the tree from ossifying:
    //
    // 1. PARENT ROTATION: Every PARENT_ROTATION_INTERVAL ticks, a parent with
    //    2 children drops the one with more approval misses. This forces the
    //    dropped child to find a new parent via orphan recovery, distributing
    //    nodes across the tree over time.
    //
    // 2. CHILD ROTATION: Every CHILD_ROTATION_INTERVAL ticks, a node voluntarily
    //    detaches from its parent and re-enters orphan recovery. This prevents
    //    long-lived parent-child relationships from calcifying the topology.
    //
    // Both use only local state — no global knowledge required.

    /// Record whether each child approved this tick. Called by network layer
    /// after tick processing completes. Tracks cumulative misses per child.
    pub fn record_child_approvals(&mut self, d1_approved: bool, d2_approved: bool) {
        self.record_child_approvals_with_subtree(d1_approved, d2_approved, 0, 0);
    }

    /// Extended version that also receives subtree_open_d from each child's approval.
    pub fn record_child_approvals_with_subtree(
        &mut self,
        d1_approved: bool,
        d2_approved: bool,
        d1_subtree_open_d: u32,
        d2_subtree_open_d: u32,
    ) {
        // Track approval count for downstream_approvals in tick messages (§2.11)
        let mut count: u8 = 0;
        if self.d1.is_some() && d1_approved { count += 1; }
        if self.d2.is_some() && d2_approved { count += 1; }
        self.prev_round_approval_count = count;

        // Aggregate subtree availability (§2.14.5)
        let my_open = if self.has_d_open() { 2u32.saturating_sub(self.downstream_count() as u32) } else { 0 };
        self.subtree_d_available = my_open + d1_subtree_open_d + d2_subtree_open_d;

        // Track misses for rotation decisions
        if self.d1.is_some() && !d1_approved {
            self.d1_misses = self.d1_misses.saturating_add(1);
        }
        if self.d2.is_some() && !d2_approved {
            self.d2_misses = self.d2_misses.saturating_add(1);
        }
    }

    /// Parent-side rotation: should this node drop its slowest child?
    /// Returns Some(child_pk) to drop, or None.
    ///
    /// Conditions (all local):
    ///   - Must have 2 children (dc=2, a writer)
    ///   - PARENT_ROTATION_INTERVAL + per-node jitter ticks have elapsed
    ///   - At least one child has missed approvals
    ///
    /// Ghost-child escape hatch (beta10 fix): if the node has exactly ONE
    /// child and that child has missed approvals for `GHOST_CHILD_MISS_THRESHOLD`
    /// consecutive ticks, drop it immediately — no interval gating. Without
    /// this a parent with {d1=ghost, d2=None} would forward ticks to the
    /// ghost forever because the main rotation path requires both slots to
    /// be filled. Discovered in the 2026-04-13 soak: 3 parents were spamming
    /// 6,500+ rejected ticks at 3 ghost children over ~3 hours.
    pub fn wants_drop_slow_child(&mut self) -> Option<PeerId> {
        // Ghost-child escape hatch: single-child node with a non-responsive child.
        // 2026-05-28: bumped from 10 to 100 ticks (~8min @5s ticks) alongside
        // `WRITER_GRACE_TICKS` for the same reason — KI#18 made TARDIS load-
        // bearing, and 10 ticks was too aggressive against transient drift.
        const GHOST_CHILD_MISS_THRESHOLD: u32 = 100; // ~8min of misses
        if self.d1.is_some() && self.d2.is_none() && self.d1_misses >= GHOST_CHILD_MISS_THRESHOLD {
            let dropped = self.d1;
            self.d1 = None;
            self.d1_misses = 0;
            return dropped;
        }
        if self.d2.is_some() && self.d1.is_none() && self.d2_misses >= GHOST_CHILD_MISS_THRESHOLD {
            let dropped = self.d2;
            self.d2 = None;
            self.d2_misses = 0;
            return dropped;
        }

        // Stale-child slot cleanup (dc=2 case) — symmetric to the child-side
        // silent-parent detection. Drop a specific slot immediately when its
        // misses exceed STALE_CHILD_SLOT_THRESHOLD (=20 ticks ≈ 100s),
        // without waiting for PARENT_ROTATION_INTERVAL.
        //
        // Without this, when a child detaches via silent-parent but the
        // parent never receives the TardisDetach (dropped message or busy
        // handler), the parent keeps the stale slot and over-reports dc=2 →
        // shows up as a phantom writer → math-impossible reports like
        // writers=7 on a 10-node mesh. The fields d1_misses/d2_misses
        // already increment on every record_child_approvals call when the
        // child didn't approve — we just need to act on them faster than
        // the rotation interval.
        if self.d1.is_some() && self.d1_misses >= STALE_CHILD_SLOT_THRESHOLD {
            let dropped = self.d1;
            self.d1 = None;
            self.d1_misses = 0;
            return dropped;
        }
        if self.d2.is_some() && self.d2_misses >= STALE_CHILD_SLOT_THRESHOLD {
            let dropped = self.d2;
            self.d2 = None;
            self.d2_misses = 0;
            return dropped;
        }

        // Only writers with 2 children participate in interval-based rotation
        if self.d1.is_none() || self.d2.is_none() { return None; }

        // Check interval + per-node jitter (prevents synchronized mass-drop)
        let jitter = self.rotation_jitter(PARENT_ROTATION_JITTER_TICKS);
        if self.ticks_since_parent_rotation < PARENT_ROTATION_INTERVAL_TICKS + jitter { return None; }

        // Reset rotation timer
        self.ticks_since_parent_rotation = 0;

        // Only drop if there's a meaningful difference in performance.
        // If both children are perfect (0 misses), don't drop anyone.
        if self.d1_misses == 0 && self.d2_misses == 0 { return None; }

        // Drop the child with more misses
        if self.d1_misses >= self.d2_misses {
            let dropped = self.d1;
            self.d1_misses = 0;
            dropped
        } else {
            let dropped = self.d2;
            self.d2_misses = 0;
            dropped
        }
    }

    /// Writer-side rotation: every CHILD_ROTATION_INTERVAL + jitter ticks, a writer
    /// voluntarily disassembles — releases children, detaches from parent.
    /// All become orphans and scatter. Released children land on dc=1 nodes,
    /// turning them into writers. This is how leaves stop being permanent leaves.
    ///
    /// Only writers (dc=2) rotate. Leaves rotating is a no-op — they'd just
    /// reattach as a leaf somewhere else. Nothing structural changes.
    ///
    /// Jitter is derived from the node's own PK — deterministic, unique per node,
    /// prevents the entire network from rotating on the same tick.
    ///
    /// Conditions (all local):
    ///   - Must be a writer (dc=2)
    ///   - Must have a parent
    ///   - CHILD_ROTATION_INTERVAL + per-node jitter ticks with current parent
    ///   - Must be off rebalance cooldown (prevent stacking)
    pub fn wants_rotate(&self) -> bool {
        if self.downstream_count() < 2 { return false; } // writers only
        if self.up.is_none() { return false; }
        if self.rebalance_cooldown > 0 { return false; }
        let jitter = self.rotation_jitter(CHILD_ROTATION_JITTER_TICKS);
        self.ticks_with_current_parent >= CHILD_ROTATION_INTERVAL_TICKS + jitter
    }

    /// Per-node, per-process, per-cycle jitter for rotation timing.
    ///
    /// Three sources mixed:
    ///   - my_pk: stable across restarts (keeps node identity in the mix)
    ///   - boot_seed: random per process — desynchronizes restarts
    ///   - rotations_completed: changes each cycle — decoheres across time
    ///
    /// Without boot_seed, every rolling restart re-syncs all writers to
    /// the same rotation schedule. Without rotations_completed, even
    /// if two writers happen to coincide on cycle N, they coincide
    /// forever. With all three, sync is broken in both dimensions.
    ///
    /// Returns 0..max_jitter.
    fn rotation_jitter(&self, max_jitter: u32) -> u32 {
        if max_jitter == 0 { return 0; }
        let mut seed: u64 = self.boot_seed;
        for (i, &b) in self.my_pk.iter().take(8).enumerate() {
            seed ^= (b as u64) << (i * 8);
        }
        // Golden-ratio multiplier for good spread per cycle
        seed ^= (self.rotations_completed as u64).wrapping_mul(0x9e3779b97f4a7c15);
        (seed % max_jitter as u64) as u32
    }

    /// Get children to release before rotation. Returns list of child PKs.
    /// Called by network layer before executing the detach.
    pub fn children_to_release(&self) -> Vec<PeerId> {
        let mut children = Vec::new();
        if let Some(d1) = self.d1 { children.push(d1); }
        if let Some(d2) = self.d2 { children.push(d2); }
        children
    }

    // ── Tick Validation (YPX-003 §1-2) ──

    /// Validate a parent's tick against this node's local time.
    ///
    /// Per YPX-003 §1-2, a child validates:
    ///   - Parent tick is NOT in the future (parent_tick <= my_time)
    ///   - Parent tick is recent (age <= TICK_INTERVAL_SECS)
    ///
    /// This is the same validation as process_tick() but usable standalone
    /// for approval decisions without requiring the full tick message.
    ///
    /// Returns true if the parent's tick is acceptable.
    pub fn validate_parent_tick(&self, parent_tick: u64, my_time: u64) -> bool {
        if parent_tick > my_time {
            return false; // future tick — impossible or malicious
        }
        let age = my_time.saturating_sub(parent_tick);
        age <= TICK_INTERVAL_SECS
    }

    /// Full tick validation including writer proof.
    ///
    /// Checks both time validity AND that the parent is a qualified WRITER
    /// (has >= 2 downstream approvals). A tick from a non-writer parent is
    /// rejected — the child must find a new parent that can produce
    /// legitimate ticks.
    ///
    /// No exemptions — a seed is the same as every other Nabla.
    ///
    /// Returns `TickValidation` indicating accept, reject-time, or reject-writer.
    pub fn validate_parent_tick_full(
        &self,
        parent_tick: u64,
        my_time: u64,
        parent_downstream_approvals: u8,
    ) -> TickValidation {
        // Time check first
        if parent_tick > my_time {
            return TickValidation::RejectFuture;
        }
        let age = my_time.saturating_sub(parent_tick);
        if age > TICK_INTERVAL_SECS {
            return TickValidation::RejectStale;
        }

        // Writer check: parent must have >= 2 approvals to produce legitimate ticks.
        // No exemptions — seeds earn approvals like everyone else.
        if !Self::is_writer(parent_downstream_approvals as usize) {
            return TickValidation::RejectNotWriter;
        }

        TickValidation::Accept
    }

    // ── Writer Status (YPX-003 §1.5) ──

    /// Returns true if this node qualifies as a WRITER.
    ///
    /// Per YPX-003 §1.5: LEGITIMATE tick authority = D1 AND D2 approval.
    /// A WRITER has received approval from at least 2 downstream nodes,
    /// meaning it can record transactions. A READER (leaf) can only serve
    /// enquiries using its parent's approved tick as freshness proof.
    ///
    /// `downstream_approvals` is the count of downstream nodes that have
    /// approved this node's tick in the current round.
    pub fn is_writer(downstream_approvals: usize) -> bool {
        downstream_approvals >= 2
    }

    // ── Parentless Timeout ──

    /// Called every tick by the network layer. Tracks how long this node
    /// has been parentless while still having children.
    ///
    /// Returns `ParentlessAction` telling the caller what to do:
    ///   - `Ok` — node has a parent, or has no children. Counter reset.
    ///   - `Searching` — parentless with children, still within timeout.
    ///   - `DetachChildren` — timeout expired. Caller MUST detach both
    ///     children so all three nodes can recover independently.
    pub fn check_parentless_timeout(&mut self) -> ParentlessAction {
        if self.has_upstream() {
            // Has parent — all good
            self.parentless_ticks = 0;
            return ParentlessAction::Ok;
        }

        if self.downstream_count() == 0 {
            // No parent AND no children — pure orphan, normal recovery handles it
            self.parentless_ticks = 0;
            return ParentlessAction::Ok;
        }

        // Has children but NO parent — zombie subtree
        self.parentless_ticks += 1;

        if self.parentless_ticks >= PARENTLESS_TIMEOUT_TICKS {
            self.parentless_ticks = 0;
            ParentlessAction::DetachChildren
        } else {
            ParentlessAction::Searching(self.parentless_ticks)
        }
    }

    /// Force-detach both downstream children. Returns their PeerIds
    /// so the caller can clear their upstream pointers too.
    /// After this, the node and both ex-children are fully homeless.
    pub fn detach_children(&mut self) -> Vec<PeerId> {
        let mut detached = Vec::new();
        if let Some(d) = self.d1.take() {
            detached.push(d);
        }
        if let Some(d) = self.d2.take() {
            detached.push(d);
        }
        detached
    }

    /// Returns the current parentless tick counter (for dashboard/debug).
    pub fn parentless_ticks(&self) -> u64 {
        self.parentless_ticks
    }

    // ── Leaf Migration ──

    /// Determines if this node should voluntarily migrate to fill an
    /// open D slot elsewhere in the tree.
    ///
    /// A leaf node (no children, has parent) is a READER only. If it sees
    /// an available D slot on another node, it can detach from its current
    /// parent and reattach there. This helps the tree stay balanced and
    /// maximizes the number of WRITER nodes.
    ///
    /// Returns true if this node is eligible to migrate:
    ///   - Must be a leaf (0 children)
    ///   - Must have a parent (not already orphaned)
    ///   - Must not be the only child of its parent (don't orphan parent's writer status)
    ///
    /// The `parent_child_count` parameter is the number of children the
    /// current parent has. Prevents migrating if it would leave the parent
    /// with only 1 child (degrading parent from writer to reader).
    pub fn should_migrate(&self, parent_child_count: usize) -> bool {
        // Must be a leaf with a parent
        if self.downstream_count() > 0 { return false; }
        if !self.has_upstream() { return false; }

        // Don't migrate if parent would lose writer status
        // Parent has 2 children → removing one leaves 1 → still a reader, acceptable
        // Parent has 1 child → removing leaves 0 → parent becomes leaf, BAD
        parent_child_count >= 2
    }

    /// Detach from current upstream. Returns the old parent's PeerId
    /// so the caller can also clean up the parent's D slot.
    pub fn detach_upstream(&mut self) -> Option<PeerId> {
        let parent = self.up.take();
        self.upstream_status = NodeStatus::Disconnected;
        parent
    }

    // ═══════════════════════════════════════════════════════════════════
    // §32 Merge Protocol
    // ═══════════════════════════════════════════════════════════════════

    /// Record a root hash from another branch (received via TickHash gossip).
    /// Returns true if a fork is detected (same tick, different root hash).
    pub fn record_branch_root_hash(&mut self, tick: u64, sender_pk: PeerId, root_hash: Hash256) -> bool {
        let entries = self.branch_root_hashes.entry(tick).or_default();
        // Check for conflict: same tick, different root hash from a different sender
        let fork_detected = entries.iter().any(|(_, rh)| *rh != root_hash);
        entries.push((sender_pk, root_hash));
        // Prune old entries (keep last 20 ticks)
        if self.branch_root_hashes.len() > 20 {
            let cutoff = tick.saturating_sub(20);
            self.branch_root_hashes.retain(|t, _| *t > cutoff);
        }
        fork_detected
    }

    /// Enter merge quarantine. Called when fork is detected.
    /// Phase 1 (PAUSE): immediately freeze conflicted wallets.
    pub fn enter_merge_quarantine(&mut self, forked_wallet: Option<WalletId>) {
        if !self.merge_quarantine_active {
            self.merge_quarantine_active = true;
            self.merge_quarantine_start_tick = self.current_tick;
            log::warn!("∇ §32 MERGE QUARANTINE entered at tick {}", self.current_tick);
        }
        if let Some(wid) = forked_wallet {
            if !self.merge_forked_wallets.contains(&wid) {
                self.merge_forked_wallets.push(wid);
            }
        }
    }

    /// Return the list of wallets that triggered quarantine (confirmed forks).
    pub fn forked_wallets(&self) -> &[WalletId] {
        &self.merge_forked_wallets
    }

    /// Clear the forked wallets list (called after resolve_merge).
    pub fn clear_forked_wallets(&mut self) {
        self.merge_forked_wallets.clear();
    }

    /// Check if merge quarantine is active.
    pub fn is_in_quarantine(&self) -> bool {
        self.merge_quarantine_active
    }

    /// Check quarantine duration and resolve if expired.
    /// Returns true if quarantine just expired (Phase 3: RESOLVE).
    pub fn check_quarantine_expiry(&mut self) -> bool {
        if !self.merge_quarantine_active {
            return false;
        }
        let elapsed = self.current_tick.saturating_sub(self.merge_quarantine_start_tick);
        if elapsed >= crate::constants::MERGE_QUARANTINE_TICKS {
            self.merge_quarantine_active = false;
            log::info!("∇ §32 MERGE QUARANTINE expired at tick {} (duration: {} ticks)",
                self.current_tick, elapsed);
            true
        } else {
            false
        }
    }

    /// Phase 2 (SCAN): Detect conflicted wallets between two SMTs.
    /// Compares local SMT against a remote state snapshot.
    /// Returns list of wallet_ids with conflicting state_ids.
    pub fn detect_forked_wallets(
        local_smt: &SparseMerkleTree,
        remote_entries: &[(WalletId, StateId)],
    ) -> Vec<WalletId> {
        let mut forked = Vec::new();
        for (wid, remote_state) in remote_entries {
            if let Some(local_entry) = local_smt.get(wid) {
                if local_entry.current_state != *remote_state {
                    forked.push(*wid);
                }
            }
            // Wallets only in one partition are unaffected (§32.8, Invariant 5)
        }
        forked
    }

    /// Phase 2 (SCAN): Propagate taint downstream through state-ID graph.
    /// Given a set of forked wallet_ids, find all wallets whose state references
    /// a tainted state_id (recursive and exhaustive per §32.8, Invariant 3).
    pub fn propagate_taint(
        smt: &SparseMerkleTree,
        forked_wallets: &[WalletId],
    ) -> Vec<WalletId> {
        use std::collections::HashSet;

        let mut tainted_wids: HashSet<WalletId> = HashSet::new();
        let mut tainted_states: HashSet<StateId> = HashSet::new();

        // Seed: forked wallets' current_state values are tainted
        for wid in forked_wallets {
            if let Some(entry) = smt.get(wid) {
                tainted_states.insert(entry.current_state);
            }
        }

        // BFS: expand taint until convergence (§32.3 recursive and exhaustive)
        loop {
            let mut new_tainted = Vec::new();
            for entry in smt.entries().values() {
                if forked_wallets.contains(&entry.wallet_id) {
                    continue; // Skip the forked wallets themselves
                }
                if tainted_wids.contains(&entry.wallet_id) {
                    continue; // Already tainted
                }
                if tainted_states.contains(&entry.tx_hash) {
                    new_tainted.push(entry.clone());
                }
            }
            if new_tainted.is_empty() {
                break;
            }
            for entry in &new_tainted {
                tainted_wids.insert(entry.wallet_id);
                tainted_states.insert(entry.current_state);
            }
        }

        tainted_wids.into_iter().collect()
    }

    /// Phase 3 (RESOLVE): Forked wallets → BANNED. Tainted (innocent) → Normal.
    ///
    /// Forked wallets committed the double-spend → permanent ban.
    /// Tainted wallets received from forked source → restored to Normal.
    /// Their FACT links from tainted inputs remain scarred (no nabla_confirmation).
    ///
    /// NOTE(review): Tainted wallets are spared. Their scarred FACT links track
    /// the tainted lineage. Revisit if collusion becomes a concern.
    ///
    /// Returns the list of wallets that were banned (forked only).
    pub fn resolve_merge(
        smt: &mut SparseMerkleTree,
        forked_wallets: &[WalletId],
        tainted_wallets: &[WalletId],
    ) -> Vec<WalletId> {
        let mut banned = Vec::new();
        // Forked wallets → BANNED (they double-spent)
        for wid in forked_wallets {
            if let Some(entry) = smt.get(wid) {
                let mut updated = entry.clone();
                updated.status = WalletStatus::Banned;
                smt.put(&updated);
                banned.push(*wid);
            }
        }
        // Tainted wallets → restored to Normal (innocent downstream)
        for wid in tainted_wallets {
            if let Some(entry) = smt.get(wid) {
                let mut updated = entry.clone();
                updated.status = WalletStatus::Normal;
                smt.put(&updated);
                log::info!("§32 RESUME: tainted wallet {:02x}{:02x}... restored to Normal",
                    wid[0], wid[1]);
            }
        }
        banned
    }

    /// Freeze a specific wallet (Phase 1: immediate freeze on fork detection).
    pub fn freeze_wallet(smt: &mut SparseMerkleTree, wallet_id: &WalletId) -> bool {
        if let Some(entry) = smt.get(wallet_id) {
            if entry.status == WalletStatus::Normal {
                let mut updated = entry.clone();
                updated.status = WalletStatus::Frozen;
                smt.put(&updated);
                return true;
            }
        }
        false
    }

    /// Check if a wallet is frozen or banned (no transactions allowed).
    pub fn is_wallet_blocked(smt: &SparseMerkleTree, wallet_id: &WalletId) -> bool {
        smt.get(wallet_id).is_some_and(|e| {
            matches!(e.status, WalletStatus::Frozen | WalletStatus::Tainted | WalletStatus::Banned)
        })
    }
}

/// Result of `check_parentless_timeout()`.
#[derive(Debug, Clone, PartialEq)]
pub enum ParentlessAction {
    /// Node has a parent or has no children. No action needed.
    Ok,
    /// Node is parentless with children, still searching. Contains tick count.
    Searching(u64),
    /// Timeout expired. Caller MUST detach children immediately.
    DetachChildren,
}

/// Result of `validate_parent_tick_full()`.
#[derive(Debug, Clone, PartialEq)]
pub enum TickValidation {
    /// Tick is valid — time ok, parent is a qualified writer.
    Accept,
    /// Tick is in the future — impossible or malicious.
    RejectFuture,
    /// Tick is too old (age > TICK_INTERVAL_SECS).
    RejectStale,
    /// Parent is not a writer (< 2 downstream approvals).
    /// Child should detach and find a writer parent.
    RejectNotWriter,
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::NoopSigner;
    use crate::smt::SparseMerkleTree;
    use crate::types::NablaEntry;

    fn pk(b: u8) -> PeerId {
        [b; 32]
    }

    fn make_tick(number: u64, from: PeerId, ts: u64) -> TickMessage {
        TickMessage {
            number,
            upstream_pk: from,
            payload: number.to_le_bytes().to_vec(),
            signature: vec![0xFF; 64],
            prev_sig: vec![],
            grandparent_pk: None,
            timestamp_ms: ts,
            available_slots: vec![],
            downstream_approvals: 2, // default to writer for existing tests
            subtree_d_available: 0,
            oods_tardis: Vec::new(),
            child_pks: Vec::new(),
            gp_commitment: None,

        }
    }

    fn make_entry(id: u8, state: u8, tick: u64) -> NablaEntry {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = id;
        let mut current_state = [0u8; 32];
        current_state[0] = state;
        NablaEntry {
            wallet_seq: 0,
            wallet_id,
            current_state,
            tx_hash: [0u8; 32],
            tick,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        }
    }

    // ── Seed Bootstrap ──

    #[test]
    fn seed_triangle_topology() {
        let seeds = TardisNode::bootstrap_genesis_ring([pk(1), pk(2), pk(3)]);

        // S1: UP=S3, D1=S2
        assert_eq!(seeds[0].up, Some(pk(3)));
        assert_eq!(seeds[0].d1, Some(pk(2)));
        assert_eq!(seeds[0].d2, None);
        assert_eq!(seeds[0].upstream_status, NodeStatus::Connected);

        // S2: UP=S1, D1=S3
        assert_eq!(seeds[1].up, Some(pk(1)));
        assert_eq!(seeds[1].d1, Some(pk(3)));

        // S3: UP=S2, D1=S1
        assert_eq!(seeds[2].up, Some(pk(2)));
        assert_eq!(seeds[2].d1, Some(pk(1)));
    }

    // ── Tick Processing ──

    #[test]
    fn process_valid_tick() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));

        let smt = SparseMerkleTree::new();
        // tick.number = unix seconds, now_ms = same moment in ms
        let t = 1740000005; // unix seconds
        let tick = make_tick(t, pk(0xBB), t * 1000);

        let actions = node.process_tick(&tick, &smt, t * 1000, &NoopSigner).unwrap();

        assert_eq!(node.current_tick(), t);
        // Should have: ForwardTick + SendApproval + BroadcastRootHash
        assert!(actions.len() >= 2);
        assert!(actions
            .iter()
            .any(|a| matches!(a, TardisAction::ForwardTick { .. })));
        assert!(actions
            .iter()
            .any(|a| matches!(a, TardisAction::SendApproval { .. })));
        assert!(actions
            .iter()
            .any(|a| matches!(a, TardisAction::BroadcastRootHash { .. })));
    }

    #[test]
    fn reject_backward_tick() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));

        let smt = SparseMerkleTree::new();
        let t1 = 1740000005_u64;

        // First tick at t1
        let tick1 = make_tick(t1, pk(0xBB), t1 * 1000);
        assert!(node.process_tick(&tick1, &smt, t1 * 1000, &NoopSigner).is_ok());

        // Try to go backward — should fail
        let tick_back = make_tick(t1 - 5, pk(0xBB), (t1 - 5) * 1000);
        let result = node.process_tick(&tick_back, &smt, (t1 - 5) * 1000, &NoopSigner);
        assert!(matches!(result, Err(NablaError::NonSequentialTick { .. })));
    }

    #[test]
    fn reject_tick_from_wrong_sender() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));

        let smt = SparseMerkleTree::new();
        let t = 1740000005_u64;
        let tick = make_tick(t, pk(0xFF), t * 1000); // wrong sender

        let actions = node.process_tick(&tick, &smt, t * 1000, &NoopSigner).unwrap();
        // Should ignore silently (return None action)
        assert!(actions
            .iter()
            .all(|a| matches!(a, TardisAction::None)));
        assert_eq!(node.current_tick(), 0); // tick not accepted
    }

    #[test]
    fn reject_tick_more_than_5s_in_future() {
        // 2026-05-28: rewritten for the forward-only +5s rule. Pre-change
        // this rejected any future tick at all; post-change we only reject
        // ticks more than TICK_INTERVAL_SECS into the future. A tick at
        // `now + 3` is within tolerance and must pass.
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));

        let smt = SparseMerkleTree::new();
        let now = 1740000010_u64;

        // Tick within +5s — must ACCEPT (clock-drift tolerance).
        let near_future_tick = make_tick(now + 3, pk(0xBB), (now + 3) * 1000);
        assert!(node.process_tick(&near_future_tick, &smt, now * 1000, &NoopSigner).is_ok());

        // Tick more than +5s into the future — REJECT (sender's clock drift
        // exceeds the discipline window).
        let mut node2 = TardisNode::new(pk(0xAA));
        node2.set_upstream(pk(0xBB));
        let far_future_tick = make_tick(now + 10, pk(0xBB), (now + 10) * 1000);
        let result = node2.process_tick(&far_future_tick, &smt, now * 1000, &NoopSigner);
        assert!(matches!(result, Err(NablaError::TickTimingViolation { .. })));
    }

    #[test]
    fn accept_stale_tick_when_not_below_current_tick() {
        // 2026-05-28: stale ticks are no longer a timing violation. The
        // architecture rule (KI#18 fix) limits wall-clock comparisons to
        // the + side only — replay defense lives in the tick-time lower
        // bound (`tick.number < self.current_tick`). A node that has no
        // accumulated tick state yet (current_tick=0) MUST accept any
        // tick that is not in the future, even ones that look "old"
        // relative to wall clock.
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));

        let smt = SparseMerkleTree::new();
        let now = 1740000010_u64;

        // Tick is 10 seconds old. Pre-change this would have been rejected
        // as "stale" — post-change it must ACCEPT because the receiver has
        // no prior current_tick to compare against (current_tick=0).
        let stale_tick = make_tick(now - 10, pk(0xBB), (now - 10) * 1000);
        let result = node.process_tick(&stale_tick, &smt, now * 1000, &NoopSigner);
        assert!(result.is_ok(),
            "stale tick must be accepted on fresh node (no current_tick to fall below)");
    }

    #[test]
    fn accept_tick_within_time_buffer() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));

        let smt = SparseMerkleTree::new();
        let t = 1740000005_u64;

        // Tick created at t, downstream receives 3s later — within 0-5s window
        let tick = make_tick(t, pk(0xBB), t * 1000);
        assert!(node.process_tick(&tick, &smt, (t + 3) * 1000, &NoopSigner).is_ok());
        assert_eq!(node.current_tick(), t);
    }

    #[test]
    fn no_upstream_returns_error() {
        let mut node = TardisNode::new(pk(0xAA));
        // No upstream set

        let smt = SparseMerkleTree::new();
        let t = 1740000005_u64;
        let tick = make_tick(t, pk(0xBB), t * 1000);

        let result = node.process_tick(&tick, &smt, t * 1000, &NoopSigner);
        assert!(matches!(result, Err(NablaError::NoUpstream)));
    }

    // ── Downstream Approval ──

    #[test]
    fn receive_valid_approval() {
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        let approval = TickApproval {
            tick_number: 1740000050,
            approver_pk: pk(0xCC),
            signature: vec![],
            subtree_open_d: 0,
        };

        assert!(node.receive_approval(&approval, &NoopSigner));
    }

    #[test]
    fn reject_stale_approval() {
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        let approval = TickApproval {
            tick_number: 1740000045, // old tick
            approver_pk: pk(0xCC),
            signature: vec![],
            subtree_open_d: 0,
        };

        assert!(!node.receive_approval(&approval, &NoopSigner));
    }

    #[test]
    fn reject_approval_from_unknown() {
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        let approval = TickApproval {
            tick_number: 1740000050,
            approver_pk: pk(0xFF), // not our downstream
            signature: vec![],
            subtree_open_d: 0,
        };

        assert!(!node.receive_approval(&approval, &NoopSigner));
    }

    // ── Maturity Window ──

    #[test]
    fn maturity_requires_upstream() {
        let node = TardisNode::new(pk(0xAA));
        // No upstream → always SCARRED
        assert_eq!(node.check_maturity(0), ChequeStatus::Scarred);
    }

    #[test]
    fn maturity_before_window() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        let reg_time = 1740000000_u64;
        node.current_tick = reg_time + 10; // only 10s later, need 5 ticks × 5s = 25s

        assert_eq!(node.check_maturity(reg_time), ChequeStatus::Scarred);
    }

    #[test]
    fn maturity_after_window() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        let reg_time = 1740000000_u64;
        node.current_tick = reg_time + 50; // 50s later, well past 5 × 5 = 25s

        assert_eq!(node.check_maturity(reg_time), ChequeStatus::Clean);
    }

    #[test]
    fn dynamic_maturity_small_network() {
        let mut node = TardisNode::new(pk(0xAA));
        node.update_network_size(100, 10);
        // ceil(ln(100)/ln(10)) + 2 = ceil(2.0) + 2 = 4 → clamped to 5 (MIN)
        assert_eq!(node.dynamic_maturity_ticks(), MATURITY_TICKS_MIN);
    }

    #[test]
    fn dynamic_maturity_large_network() {
        let mut node = TardisNode::new(pk(0xAA));
        node.update_network_size(50_000, 13);
        // ceil(ln(50000)/ln(13)) + 2 = ceil(10.82/2.565) + 2 = ceil(4.22) + 2 = 7
        let m = node.dynamic_maturity_ticks();
        assert!((6..=MATURITY_TICKS_MAX).contains(&m), "maturity = {m}");
    }

    #[test]
    fn dynamic_maturity_capped() {
        let mut node = TardisNode::new(pk(0xAA));
        node.update_network_size(1_000_000, 5);
        // Very large network with few peers → high ticks, but capped
        assert_eq!(node.dynamic_maturity_ticks(), MATURITY_TICKS_MAX);
    }

    // ── Audit ──

    #[test]
    fn audit_request_generation() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.current_tick = 1740000050;
        node.ticks_since_audit = 5;

        assert!(node.should_audit());

        let action = node.generate_audit_request();
        assert!(action.is_some());
        match action.unwrap() {
            TardisAction::SendAuditRequest { request, target } => {
                assert_eq!(target, pk(0xBB));
                assert_eq!(request.prefix_bits, 8);
                assert_eq!(request.request_tick, 1740000050);
            }
            _ => panic!("Expected SendAuditRequest"),
        }
    }

    #[test]
    fn audit_no_upstream_skips() {
        let node = TardisNode::new(pk(0xAA));
        // No upstream → should_audit false
        assert!(!node.should_audit());
        assert!(node.generate_audit_request().is_none());
    }

    #[test]
    fn audit_pass_same_root() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.current_tick = 1740000050;

        let mut smt = SparseMerkleTree::new();
        smt.put(&make_entry(1, 1, 5));
        smt.put(&make_entry(2, 2, 6));

        // Upstream responds with matching root
        let response = SubtreeAuditResponse {
            prefix: vec![0xA3],
            prefix_bits: 8,
            subtree_hash: [0; 32], // doesn't matter for root comparison
            root_hash: smt.root_hash(),
            response_tick: 10,
            responder_pk: pk(0xBB),
            signature: vec![],
        };

        let action = node.verify_audit_response(&response, &smt, &NoopSigner).unwrap();
        assert!(matches!(action, TardisAction::None));
        assert_eq!(node.audit_pass_count(), 1);
    }

    #[test]
    fn audit_fail_different_root() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC)); // need downstream for cascade
        node.current_tick = 1740000050;

        let smt = SparseMerkleTree::new();

        // Upstream responds with DIFFERENT root → questionable
        let response = SubtreeAuditResponse {
            prefix: vec![0xA3],
            prefix_bits: 8,
            subtree_hash: [0; 32],
            root_hash: [0xFF; 32], // doesn't match empty tree
            response_tick: 10,
            responder_pk: pk(0xBB),
            signature: vec![],
        };

        let action = node.verify_audit_response(&response, &smt, &NoopSigner).unwrap();
        assert!(matches!(action, TardisAction::CascadeAlert { .. }));
        assert_eq!(node.upstream_status(), NodeStatus::Disconnected);
        assert_eq!(node.upstream(), None);
    }

    // ── Questionable Cascade ──

    #[test]
    fn questionable_cascades_to_downstream() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.add_downstream(pk(0xDD));
        node.current_tick = 1740000050;

        let alert = QuestionableAlert {
            suspect_pk: pk(0xBB), // our upstream
            reporter_pk: pk(0xAA),
            tick: 1740000048, // fresh (within ALERT_MAX_AGE_SECS of current)
            evidence_hash: [0; 32],
            signature: vec![],
        };

        let action = node.handle_questionable_alert(&alert, &NoopSigner);
        match action {
            TardisAction::CascadeAlert { targets, .. } => {
                assert_eq!(targets.len(), 2); // D1 + D2
                assert!(targets.contains(&pk(0xCC)));
                assert!(targets.contains(&pk(0xDD)));
            }
            _ => panic!("Expected CascadeAlert"),
        }

        // Upstream should be disconnected
        assert_eq!(node.upstream_status(), NodeStatus::Disconnected);
        assert_eq!(node.upstream(), None);
    }

    #[test]
    fn questionable_irrelevant_suspect_still_cascades() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        // Alert about some OTHER node (not our upstream)
        let alert = QuestionableAlert {
            suspect_pk: pk(0xFF),
            reporter_pk: pk(0xEE),
            tick: 1740000048, // fresh (within ALERT_MAX_AGE_SECS of current)
            evidence_hash: [0; 32],
            signature: vec![],
        };

        let action = node.handle_questionable_alert(&alert, &NoopSigner);
        // Should cascade but NOT disconnect our upstream
        assert!(matches!(action, TardisAction::CascadeAlert { .. }));
        assert_eq!(node.upstream_status(), NodeStatus::Connected);
    }

    // ── KI#37 — alert cascade hygiene ──

    #[test]
    fn ki37_duplicate_alert_dropped() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        let alert = QuestionableAlert {
            suspect_pk: pk(0xFF),
            reporter_pk: pk(0xEE),
            tick: 1740000048,
            evidence_hash: [7; 32],
            signature: vec![],
        };

        // First delivery cascades…
        assert!(matches!(
            node.handle_questionable_alert(&alert, &NoopSigner),
            TardisAction::CascadeAlert { .. }
        ));
        // …every subsequent copy of the SAME alert is a no-op. This is
        // the gate that kills the infinite re-broadcast loop.
        assert!(matches!(
            node.handle_questionable_alert(&alert, &NoopSigner),
            TardisAction::None
        ));
        assert!(matches!(
            node.handle_questionable_alert(&alert, &NoopSigner),
            TardisAction::None
        ));
    }

    #[test]
    fn ki37_duplicate_upstream_alert_detaches_once() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        let alert = QuestionableAlert {
            suspect_pk: pk(0xBB), // our upstream → flag_questionable path
            reporter_pk: pk(0xEE),
            tick: 1740000048,
            evidence_hash: [8; 32],
            signature: vec![],
        };

        assert!(matches!(
            node.handle_questionable_alert(&alert, &NoopSigner),
            TardisAction::CascadeAlert { .. }
        ));
        // Re-attach; a re-delivered copy must NOT re-mint a fresh alert
        // (each dup used to trigger detach + a NEW signed alert — a
        // second amplifier on top of the cascade loop).
        node.set_upstream(pk(0xBB));
        assert!(matches!(
            node.handle_questionable_alert(&alert, &NoopSigner),
            TardisAction::None
        ));
        assert_eq!(node.upstream_status(), NodeStatus::Connected);
    }

    // §7.6 fork-ban evidence: a lineage violation emits a QuestionableAlert naming the
    // suspect (the forwarder of the bad-lineage tick), cascaded to downstream, and it is
    // deduped so a repeat within the same tick does not re-mint a fresh accusation.
    #[test]
    fn lineage_violation_accuses_suspect_and_dedups() {
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000100;
        let suspect = pk(0xBB);

        match node.flag_lineage_violation(suspect, &NoopSigner) {
            TardisAction::CascadeAlert { alert, targets } => {
                assert_eq!(alert.suspect_pk, suspect);
                assert_eq!(alert.reporter_pk, pk(0xAA));
                assert!(targets.contains(&pk(0xCC)), "cascades to downstream");
                assert!(!targets.contains(&suspect), "never back to the accused");
                assert!(!targets.contains(&pk(0xAA)), "never to self");
            }
            other => panic!("expected CascadeAlert, got {other:?}"),
        }
        // Same suspect, same tick → deduped (no second accusation).
        assert!(matches!(
            node.flag_lineage_violation(suspect, &NoopSigner),
            TardisAction::None
        ));
    }

    #[test]
    fn ki37_stale_alert_dropped() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        // Older than ALERT_MAX_AGE_SECS → dropped without action, even
        // when the suspect is our upstream.
        let alert = QuestionableAlert {
            suspect_pk: pk(0xBB),
            reporter_pk: pk(0xEE),
            tick: 1740000050 - ALERT_MAX_AGE_SECS - 1,
            evidence_hash: [9; 32],
            signature: vec![],
        };

        assert!(matches!(
            node.handle_questionable_alert(&alert, &NoopSigner),
            TardisAction::None
        ));
        assert_eq!(node.upstream_status(), NodeStatus::Connected);
    }

    #[test]
    fn ki37_never_forwards_to_self() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        // set_pending has no self-guard — this is the real path by which
        // a node ended up flooding ITSELF (observed 2026-07-08: 1.2 GB
        // self-inflow on one node).
        node.set_pending(pk(0xAA));
        node.current_tick = 1740000050;

        let alert = QuestionableAlert {
            suspect_pk: pk(0xFF),
            reporter_pk: pk(0xEE),
            tick: 1740000048,
            evidence_hash: [10; 32],
            signature: vec![],
        };

        // Only forward slot is self → filtered → no cascade at all.
        assert!(matches!(
            node.handle_questionable_alert(&alert, &NoopSigner),
            TardisAction::None
        ));
    }

    #[test]
    fn ki37_own_minted_alert_loopback_dropped() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        // Suspect == upstream → node mints its OWN alert (flag_questionable).
        let incoming = QuestionableAlert {
            suspect_pk: pk(0xBB),
            reporter_pk: pk(0xEE),
            tick: 1740000048,
            evidence_hash: [11; 32],
            signature: vec![],
        };
        let minted = match node.handle_questionable_alert(&incoming, &NoopSigner) {
            TardisAction::CascadeAlert { alert, .. } => alert,
            other => panic!("Expected CascadeAlert, got {:?}", other),
        };
        assert_eq!(minted.reporter_pk, pk(0xAA)); // it IS our own mint

        // The minted alert looping back through a tree cycle must be
        // dropped — it was recorded as seen at mint time.
        assert!(matches!(
            node.handle_questionable_alert(&minted, &NoopSigner),
            TardisAction::None
        ));
    }

    #[test]
    fn ki37_per_reporter_rate_limited() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        // One malicious reporter mints DISTINCT fresh alerts (each passes
        // dedup). Accept up to the budget, then drop the rest.
        let mut cascaded = 0;
        let mut dropped = 0;
        for i in 0..(ALERT_MAX_PER_REPORTER_PER_WINDOW + 5) {
            let mut evidence = [0u8; 32];
            evidence[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let alert = QuestionableAlert {
                suspect_pk: pk(0xFF),
                reporter_pk: pk(0xEE), // SAME reporter every time
                tick: 1740000048,
                evidence_hash: evidence,
                signature: vec![],
            };
            match node.handle_questionable_alert(&alert, &NoopSigner) {
                TardisAction::CascadeAlert { .. } => cascaded += 1,
                TardisAction::None => dropped += 1,
                _ => {}
            }
        }
        assert_eq!(cascaded, ALERT_MAX_PER_REPORTER_PER_WINDOW as i32);
        assert_eq!(dropped, 5);

        // A DIFFERENT reporter is unaffected (honest nodes flagging the
        // same bad suspect must still get through).
        let mut evidence = [0u8; 32];
        evidence[0] = 0xAB;
        let other = QuestionableAlert {
            suspect_pk: pk(0xFF),
            reporter_pk: pk(0xDD), // different reporter
            tick: 1740000048,
            evidence_hash: evidence,
            signature: vec![],
        };
        assert!(matches!(
            node.handle_questionable_alert(&other, &NoopSigner),
            TardisAction::CascadeAlert { .. }
        ));
    }

    #[test]
    fn ki37_seen_set_bounded() {
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        for i in 0..(ALERT_SEEN_CAP + 100) {
            let mut evidence = [0u8; 32];
            evidence[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let alert = QuestionableAlert {
                suspect_pk: pk(0xFF),
                reporter_pk: pk(0xEE),
                tick: 1740000048,
                evidence_hash: evidence,
                signature: vec![],
            };
            node.handle_questionable_alert(&alert, &NoopSigner);
        }
        assert!(node.seen_alerts.len() <= ALERT_SEEN_CAP);
        assert_eq!(node.seen_alerts.len(), node.seen_alerts_order.len());
    }

    // ── Slot Management ──

    #[test]
    fn slot_management() {
        let mut node = TardisNode::new(pk(0xAA));

        // Add two downstream
        assert!(node.add_downstream(pk(0x01)));
        assert!(node.add_downstream(pk(0x02)));
        assert!(!node.add_downstream(pk(0x03))); // full
        assert_eq!(node.downstream_count(), 2);

        // Set pending and promote
        node.set_pending(pk(0x03));
        node.remove_peer(&pk(0x01)); // free D1
        assert_eq!(node.downstream_count(), 1);

        assert!(node.promote_pending());
        assert_eq!(node.downstream_count(), 2);
    }

    #[test]
    fn leaf_node_detection() {
        let mut node = TardisNode::new(pk(0xAA));
        assert!(node.is_leaf());

        node.add_downstream(pk(0x01));
        assert!(!node.is_leaf());
    }

    // ── Multi-tick sequence ──

    #[test]
    fn process_tick_sequence() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));

        let smt = SparseMerkleTree::new();
        let base = 1740000000_u64;

        // Process 10 ticks, each 5 seconds apart (unix time)
        for i in 1..=10u64 {
            let tick_time = base + (i * TICK_INTERVAL_SECS);
            let now_ms = tick_time * 1000;
            let tick = make_tick(tick_time, pk(0xBB), now_ms);
            let result = node.process_tick(&tick, &smt, now_ms, &NoopSigner);
            assert!(result.is_ok(), "Tick {i} failed: {:?}", result.err());
        }

        assert_eq!(node.current_tick(), base + 10 * TICK_INTERVAL_SECS);
    }

    #[test]
    fn should_audit_frequency() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));

        // Ticks 0-4: should NOT audit
        for _ in 0..4 {
            node.ticks_since_audit += 1;
        }
        assert!(!node.should_audit()); // 4 ticks, need 5

        node.ticks_since_audit += 1;
        assert!(node.should_audit()); // 5 ticks, time to audit

        // After audit passes, counter resets
        node.audit_pass_count += 1;
        node.ticks_since_audit = 0;
        assert!(!node.should_audit());
    }

    // ── Recovery ──

    #[test]
    fn needs_parent_when_no_upstream() {
        let node = TardisNode::new(pk(0xAA));
        assert!(node.needs_parent());
    }

    #[test]
    fn needs_parent_when_upstream_set() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        assert!(!node.needs_parent());
    }

    #[test]
    fn needs_parent_after_upstream_removed() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        assert!(!node.needs_parent());

        // Parent dies — peer removed
        node.remove_peer(&pk(0xBB));
        assert!(node.needs_parent());
    }

    #[test]
    fn needs_parent_seed_same_as_regular() {
        // Seeds are not special — if they lose upstream, they need recovery too
        let mut node = TardisNode::new_with_ring_links(pk(0xAA), pk(0xBB), pk(0xCC));
        assert!(!node.needs_parent());

        node.remove_peer(&pk(0xBB)); // upstream dies
        assert!(node.needs_parent());
    }

    #[test]
    fn recovery_candidates_from_tick() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));

        let smt = SparseMerkleTree::new();
        let tick_time = 1740000005_u64;
        let now_ms = tick_time * 1000;

        // Tick carries available slot info
        let tick = TickMessage {
            number: tick_time,
            upstream_pk: pk(0xBB),
            payload: tick_time.to_le_bytes().to_vec(),
            signature: vec![0xFF; 64],
            prev_sig: vec![],
            grandparent_pk: None,
            timestamp_ms: now_ms,
            available_slots: vec![(pk(0xCC), 5), (pk(0xDD), 8)],
            downstream_approvals: 2,
            subtree_d_available: 0,
            oods_tardis: Vec::new(),
            child_pks: Vec::new(),
            gp_commitment: None,
        };

        node.process_tick(&tick, &smt, now_ms, &NoopSigner).unwrap();

        // Recovery candidates should contain the slot info
        let candidates = node.recovery_candidates();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].0, pk(0xCC));
        assert_eq!(candidates[1].0, pk(0xDD));
    }

    // ── Tick Validation ──

    #[test]
    fn validate_parent_tick_valid() {
        let node = TardisNode::new(pk(0xAA));
        // Parent tick=100, my time=103 → age=3, within 5s window
        assert!(node.validate_parent_tick(100, 103));
    }

    #[test]
    fn validate_parent_tick_same_time() {
        let node = TardisNode::new(pk(0xAA));
        // Parent tick=100, my time=100 → age=0, valid
        assert!(node.validate_parent_tick(100, 100));
    }

    #[test]
    fn validate_parent_tick_exactly_5s() {
        let node = TardisNode::new(pk(0xAA));
        // Parent tick=100, my time=105 → age=5, exactly at boundary
        assert!(node.validate_parent_tick(100, 105));
    }

    #[test]
    fn validate_parent_tick_too_old() {
        let node = TardisNode::new(pk(0xAA));
        // Parent tick=100, my time=106 → age=6, stale
        assert!(!node.validate_parent_tick(100, 106));
    }

    #[test]
    fn validate_parent_tick_future() {
        let node = TardisNode::new(pk(0xAA));
        // Parent tick=110, my time=100 → future tick
        assert!(!node.validate_parent_tick(110, 100));
    }

    // ── Writer Status ──

    #[test]
    fn writer_requires_two_approvals() {
        assert!(!TardisNode::is_writer(0));
        assert!(!TardisNode::is_writer(1));
        assert!(TardisNode::is_writer(2));
        assert!(TardisNode::is_writer(3));
    }

    // ── Full Tick Validation (time + writer) ──

    #[test]
    fn full_validation_accept_writer_parent() {
        let node = TardisNode::new(pk(0xAA));
        // Time ok, parent has 2 approvals
        assert_eq!(
            node.validate_parent_tick_full(100, 103, 2),
            TickValidation::Accept
        );
    }

    #[test]
    fn full_validation_reject_non_writer_parent() {
        let node = TardisNode::new(pk(0xAA));
        // Time ok, but parent has only 1 approval → not a writer
        assert_eq!(
            node.validate_parent_tick_full(100, 103, 1),
            TickValidation::RejectNotWriter
        );
    }

    #[test]
    fn full_validation_reject_zero_approvals() {
        let node = TardisNode::new(pk(0xAA));
        // Parent has 0 approvals → definitely not a writer
        assert_eq!(
            node.validate_parent_tick_full(100, 103, 0),
            TickValidation::RejectNotWriter
        );
    }

    #[test]
    fn full_validation_no_seed_exemption() {
        let node = TardisNode::new(pk(0xAA));
        // No exemptions — 0 approvals = not a writer, period.
        // A seed is the same as every other Nabla.
        assert_eq!(
            node.validate_parent_tick_full(100, 103, 0),
            TickValidation::RejectNotWriter
        );
    }

    #[test]
    fn full_validation_time_reject_overrides_writer() {
        let node = TardisNode::new(pk(0xAA));
        // Future tick — rejected before writer check
        assert_eq!(
            node.validate_parent_tick_full(110, 100, 2),
            TickValidation::RejectFuture
        );
        // Stale tick — rejected before writer check
        assert_eq!(
            node.validate_parent_tick_full(100, 106, 2),
            TickValidation::RejectStale
        );
    }

    // ── Parentless Timeout ──

    #[test]
    fn parentless_ok_when_has_upstream() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        assert_eq!(node.check_parentless_timeout(), ParentlessAction::Ok);
    }

    #[test]
    fn parentless_ok_when_no_children() {
        // Pure orphan — normal recovery, not parentless timeout
        let mut node = TardisNode::new(pk(0xAA));
        assert_eq!(node.check_parentless_timeout(), ParentlessAction::Ok);
    }

    #[test]
    fn parentless_searching_increments() {
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC));
        node.add_downstream(pk(0xDD));
        // No upstream, has children → zombie subtree

        assert_eq!(node.check_parentless_timeout(), ParentlessAction::Searching(1));
        assert_eq!(node.check_parentless_timeout(), ParentlessAction::Searching(2));
        assert_eq!(node.check_parentless_timeout(), ParentlessAction::Searching(3));
        assert_eq!(node.check_parentless_timeout(), ParentlessAction::Searching(4));
    }

    #[test]
    fn parentless_detach_at_timeout() {
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC));
        node.add_downstream(pk(0xDD));

        // Tick 4 times (searching)
        for _ in 0..4 {
            assert!(matches!(node.check_parentless_timeout(), ParentlessAction::Searching(_)));
        }
        // Tick 5 → detach
        assert_eq!(node.check_parentless_timeout(), ParentlessAction::DetachChildren);
        // Counter reset after detach
        assert_eq!(node.parentless_ticks(), 0);
    }

    #[test]
    fn parentless_resets_when_parent_found() {
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC));

        // Accumulate some ticks
        assert_eq!(node.check_parentless_timeout(), ParentlessAction::Searching(1));
        assert_eq!(node.check_parentless_timeout(), ParentlessAction::Searching(2));

        // Found parent!
        node.set_upstream(pk(0xBB));
        assert_eq!(node.check_parentless_timeout(), ParentlessAction::Ok);
        assert_eq!(node.parentless_ticks(), 0);
    }

    #[test]
    fn detach_children_returns_both() {
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC));
        node.add_downstream(pk(0xDD));
        assert_eq!(node.downstream_count(), 2);

        let detached = node.detach_children();
        assert_eq!(detached.len(), 2);
        assert!(detached.contains(&pk(0xCC)));
        assert!(detached.contains(&pk(0xDD)));
        assert_eq!(node.downstream_count(), 0);
    }

    #[test]
    fn detach_children_one_child() {
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC));
        let detached = node.detach_children();
        assert_eq!(detached.len(), 1);
        assert_eq!(detached[0], pk(0xCC));
    }

    #[test]
    fn ghost_child_is_dropped_from_single_child_node() {
        // Regression: a node with {d1=ghost, d2=None} previously forwarded
        // ticks to the ghost forever because wants_drop_slow_child requires
        // both d-slots filled. Discovered in the 2026-04-13 soak.
        //
        // 2026-05-28: threshold bumped from 10 to 100 ticks alongside
        // WRITER_GRACE_TICKS. Test follows.
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC));
        assert_eq!(node.downstream_count(), 1);

        // 100 consecutive missed approvals (no d2 present)
        for _ in 0..100 {
            node.record_child_approvals(false, false);
        }

        let dropped = node.wants_drop_slow_child();
        assert_eq!(dropped, Some(pk(0xCC)));
        assert_eq!(node.downstream_count(), 0);
    }

    #[test]
    fn ghost_child_threshold_not_reached_keeps_child() {
        // 2026-05-29: STALE_CHILD_SLOT_THRESHOLD=20 lowered the
        // ghost-cleanup escape hatch from 100 to 20 misses (task #99).
        // Under the new threshold, child is still kept.
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC));
        for _ in 0..19 {
            node.record_child_approvals(false, false);
        }
        assert_eq!(node.wants_drop_slow_child(), None);
        assert_eq!(node.downstream_count(), 1);
    }

    // ── Leaf Migration ──

    #[test]
    fn leaf_should_migrate_when_parent_has_two_children() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        // Node is a leaf (0 children), parent has 2 children → safe to leave
        assert!(node.should_migrate(2));
    }

    #[test]
    fn leaf_should_not_migrate_when_parent_has_one_child() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        // Node is a leaf, parent has only 1 child (us) → leaving would orphan parent
        assert!(!node.should_migrate(1));
    }

    #[test]
    fn non_leaf_should_not_migrate() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        // Node has children → not a leaf → don't migrate
        assert!(!node.should_migrate(2));
    }

    #[test]
    fn orphan_should_not_migrate() {
        let node = TardisNode::new(pk(0xAA));
        // No parent → can't migrate, needs normal recovery
        assert!(!node.should_migrate(2));
    }

    #[test]
    fn detach_upstream_returns_parent() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        assert!(node.has_upstream());

        let parent = node.detach_upstream();
        assert_eq!(parent, Some(pk(0xBB)));
        assert!(!node.has_upstream());
        assert!(node.needs_parent());
    }

    // ═══════════════════════════════════════════════════════════════
    // Recovery Placement Strategy Tests (§2.6 protocol-level)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn orphan_with_children_prefers_writer_parent() {
        // An orphan that has downstream children should prefer
        // dc=1 parents (attaching creates a new writer).
        let mut node = TardisNode::new(pk(0xAA));
        node.add_downstream(pk(0xCC)); // has 1 child
        assert!(node.recovery_prefers_writer_parent());
    }

    #[test]
    fn orphan_leaf_also_prefers_writer_parent() {
        // ALL orphans prefer dc=1 parents — even leaves.
        // Landing at dc=1 → creates writer (+1). Landing at dc=0 → creates dc=1 waste (+0).
        // Two-pass recovery (strict→relaxed) falls back to dc=0 when no dc=1 available.
        let node = TardisNode::new(pk(0xAA));
        assert!(node.recovery_prefers_writer_parent());
    }

    #[test]
    fn recovery_candidate_strict_only_dc1() {
        // Strict mode (prefer_writer=true): only dc=1 parents acceptable
        assert!(TardisNode::recovery_candidate_acceptable(1, true));
        assert!(!TardisNode::recovery_candidate_acceptable(0, true));
        assert!(!TardisNode::recovery_candidate_acceptable(2, true));
    }

    #[test]
    fn recovery_candidate_relaxed_any_open() {
        // Relaxed mode (prefer_writer=false): any dc is acceptable
        assert!(TardisNode::recovery_candidate_acceptable(0, false));
        assert!(TardisNode::recovery_candidate_acceptable(1, false));
        // dc=2 would mean no open slot — but the method only checks
        // preference, not open status (caller checks has_d_open())
        assert!(TardisNode::recovery_candidate_acceptable(2, false));
    }

    // ── D Slot Reservation (§2.3) ──

    #[test]
    fn reservation_blocks_slot_for_others() {
        let mut node = TardisNode::new(pk(0xAA));
        let c1 = pk(0xBB);
        let c2 = pk(0xCC);
        node.add_downstream(c1); // D1
        node.add_downstream(c2); // D2
        assert!(!node.has_d_open()); // both full

        // Child c1 dies — reserve D1
        node.remove_peer_reserved(&c1, 100);
        assert!(node.d1.is_none()); // slot cleared
        assert!(!node.has_d_open()); // D1 reserved, D2 occupied — no open slots

        // Stranger can't take the reserved slot
        let other = pk(0xDD);
        assert!(!node.add_downstream(other)); // D1 reserved, D2 full
    }

    #[test]
    fn reservation_allows_original_peer_reclaim() {
        let mut node = TardisNode::new(pk(0xAA));
        let c1 = pk(0xBB);
        let c2 = pk(0xCC);
        node.add_downstream(c1); // D1
        node.add_downstream(c2); // D2
        node.remove_peer_reserved(&c1, 100);
        assert!(!node.has_d_open()); // reserved

        // Original child reclaims
        assert!(node.add_downstream(c1)); // should succeed
        assert_eq!(node.d1, Some(c1));
        assert!(node.d1_reserved.is_none()); // reservation cleared
    }

    #[test]
    fn reservation_expires_after_timeout() {
        let mut node = TardisNode::new(pk(0xAA));
        let c1 = pk(0xBB);
        let c2 = pk(0xCC);
        node.add_downstream(c1);
        node.add_downstream(c2);
        node.remove_peer_reserved(&c1, 100);

        // Before expiry
        node.check_reservations(105);
        assert!(!node.has_d_open()); // still reserved (only 5 ticks)

        // At expiry boundary (D_RESERVATION_TICKS = 10)
        node.check_reservations(110);
        assert!(node.has_d_open()); // expired! D1 now truly open

        // New node can take it
        let other = pk(0xDD);
        assert!(node.add_downstream(other));
        assert_eq!(node.d1, Some(other));
    }

    #[test]
    fn reservation_open_d_count() {
        let mut node = TardisNode::new(pk(0xAA));
        assert_eq!(node.open_d_count(), 2); // both empty

        let c1 = pk(0xBB);
        node.add_downstream(c1);
        assert_eq!(node.open_d_count(), 1); // D1 filled, D2 open

        // Reserve D1 (child offline)
        node.remove_peer_reserved(&c1, 100);
        // D1 empty but reserved, D2 still open
        assert_eq!(node.open_d_count(), 1); // only D2 counts as open
    }

    // ── Recursive Taint Propagation (§32.3) ──

    /// Helper: create a NablaEntry with explicit tx_hash for taint chain testing.
    fn make_chain_entry(id: u8, state: u8, tx_hash_byte: u8, tick: u64) -> NablaEntry {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = id;
        let mut current_state = [0u8; 32];
        current_state[0] = state;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = tx_hash_byte;
        NablaEntry {
            wallet_seq: 0,
            wallet_id,
            current_state,
            tx_hash,
            tick,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        }
    }

    #[test]
    fn test_recursive_taint_propagation() {
        // Chain: A → B → C → D
        // A.current_state = 0x0A
        // B.tx_hash = 0x0A (references A's state), B.current_state = 0x0B
        // C.tx_hash = 0x0B (references B's state), C.current_state = 0x0C
        // D.tx_hash = 0x0C (references C's state), D.current_state = 0x0D
        let a = make_chain_entry(1, 0x0A, 0x00, 100); // A: no tainted input
        let b = make_chain_entry(2, 0x0B, 0x0A, 101); // B: tx_hash = A's state
        let c = make_chain_entry(3, 0x0C, 0x0B, 102); // C: tx_hash = B's state
        let d = make_chain_entry(4, 0x0D, 0x0C, 103); // D: tx_hash = C's state

        // Also add an innocent wallet E that references nothing tainted
        let e = make_chain_entry(5, 0x0E, 0xFF, 104);

        let mut smt = SparseMerkleTree::new();
        smt.put(&a);
        smt.put(&b);
        smt.put(&c);
        smt.put(&d);
        smt.put(&e);

        // Mark A as forked
        let forked = vec![a.wallet_id];
        let tainted = TardisNode::propagate_taint(&smt, &forked);

        // B, C, D should all be tainted (recursive propagation)
        assert!(tainted.contains(&b.wallet_id), "B should be tainted (hop 1)");
        assert!(tainted.contains(&c.wallet_id), "C should be tainted (hop 2)");
        assert!(tainted.contains(&d.wallet_id), "D should be tainted (hop 3)");

        // A (forked) and E (innocent) should NOT be in the tainted list
        assert!(!tainted.contains(&a.wallet_id), "A is forked, not tainted");
        assert!(!tainted.contains(&e.wallet_id), "E is innocent");

        // Exactly 3 wallets tainted
        assert_eq!(tainted.len(), 3, "expected exactly B, C, D tainted");
    }

    #[test]
    fn test_propagate_taint_no_downstream() {
        // Single forked wallet with no downstream references
        let a = make_chain_entry(1, 0x0A, 0x00, 100);
        let b = make_chain_entry(2, 0x0B, 0xFF, 101); // unrelated

        let mut smt = SparseMerkleTree::new();
        smt.put(&a);
        smt.put(&b);

        let tainted = TardisNode::propagate_taint(&smt, &[a.wallet_id]);
        assert!(tainted.is_empty(), "no downstream should be tainted");
    }

    #[test]
    fn test_resolve_merge_forked_banned_tainted_restored() {
        // Forked wallet → BANNED, tainted wallet → Normal (restored)
        let mut forked = make_chain_entry(1, 0xAA, 0x00, 100);
        forked.status = WalletStatus::Frozen;
        let mut tainted = make_chain_entry(2, 0xBB, 0x00, 50);
        tainted.status = WalletStatus::Tainted;
        let normal = make_chain_entry(3, 0xCC, 0x00, 200);

        let mut smt = SparseMerkleTree::new();
        smt.put(&forked);
        smt.put(&tainted);
        smt.put(&normal);

        let banned = TardisNode::resolve_merge(
            &mut smt,
            &[forked.wallet_id],
            &[tainted.wallet_id],
        );

        // Only forked wallet should be banned
        assert_eq!(banned.len(), 1);
        assert_eq!(banned[0], forked.wallet_id);
        assert_eq!(smt.get(&forked.wallet_id).unwrap().status, WalletStatus::Banned);

        // Tainted wallet should be restored to Normal
        assert_eq!(smt.get(&tainted.wallet_id).unwrap().status, WalletStatus::Normal);

        // Unrelated wallet untouched
        assert_eq!(smt.get(&normal.wallet_id).unwrap().status, WalletStatus::Normal);
    }

    #[test]
    fn test_resolve_merge_multiple_tainted_all_restored() {
        let mut forked = make_chain_entry(1, 0xAA, 0x00, 100);
        forked.status = WalletStatus::Frozen;
        let mut t1 = make_chain_entry(2, 0xBB, 0x00, 50);
        t1.status = WalletStatus::Tainted;
        let mut t2 = make_chain_entry(3, 0xCC, 0x00, 30);
        t2.status = WalletStatus::Tainted;

        let mut smt = SparseMerkleTree::new();
        smt.put(&forked);
        smt.put(&t1);
        smt.put(&t2);

        let banned = TardisNode::resolve_merge(
            &mut smt,
            &[forked.wallet_id],
            &[t1.wallet_id, t2.wallet_id],
        );

        assert_eq!(banned.len(), 1);
        assert_eq!(smt.get(&t1.wallet_id).unwrap().status, WalletStatus::Normal);
        assert_eq!(smt.get(&t2.wallet_id).unwrap().status, WalletStatus::Normal);
    }
}
