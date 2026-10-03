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
    TICK_INTERVAL_SECS, AUDIT_CHALLENGE_PENDING_TICKS, AUDIT_INBOX_OTHER_CAP,
};

/// KI#71 — this node's ONE signed root advertisement for a tick label.
///
/// Built ONLY by [`TardisNode::advertise_root`], and used by EVERY path that
/// states "my root at tick T" — the per-tick `BroadcastRootHash` (process_tick
/// step 9), the binary's anti-entropy `TickHash` (tick-loop Step 9) and the §5.5
/// audit answer. Before 2026-10-01 the three sampled `smt.root_hash()` at three
/// different instants under one tick label, so an honest writer whose SMT moved
/// between them signed two different roots for the same tick and was convicted
/// of SELF-CONTRADICTION (detach + cascade) — YPX-003 §1.3.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAdvert {
    pub tick: u64,
    pub root_hash: Hash256,
    /// Signature over `crypto::tickhash_sign_payload(tick, root_hash, my_pk)`.
    pub signature: Vec<u8>,
}

/// Consecutive ticks without verifiable grandpa-sig before a node detaches
/// from its upstream and re-seeks. 10 ticks ≈ 50s at TICK_INTERVAL_SECS=5,
/// matching REBALANCE_COOLDOWN_TICKS so the threshold composes with the
/// existing anti-thrash window. Short enough that broken chains don't
/// linger; long enough that transient rotation-drain windows don't trigger
/// false detaches.
/// Re-exported from the tuning register (2026-08-01). Was hardcoded here; a
/// tick-denominated protocol value belongs in protocol_nabla.toml next to its
/// settle, where the two can be reviewed together.
pub use crate::constants::GRANDPA_MISS_DETACH_THRESHOLD;

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
        /// KI#71 — signed ONCE by `advertise_root`; the network layer sends it
        /// as-is and never re-signs a fresh sample.
        signature: Vec<u8>,
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

/// Why this node lost its upstream, counted. Observability only — no protocol
/// logic reads these.
///
/// **Two different questions, deliberately kept apart:**
///   * `via_*` — the CODE PATH that cleared `up`. Every path is counted,
///     including the ones that orphan a node without ever emitting a
///     `DetachReason` (a peer going away, an audit disconnect).
///   * `detach_*` — the protocol REASON carried by `TardisAction::DetachUpstream`.
///     Counted where the action is EMITTED, because the detach handler calls
///     `remove_peer()` and the reason is gone by the time `up` is cleared.
///
/// Modelled on `sim.rs::OrphanCause`, NOT copied from it: that enum predates the
/// grandpa rule and has no variant for `GrandpaTickMissing`, which is ~95% of
/// real detaches. Its `WriterCheck` variant is marked "disabled v0.9.1".
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OrphanCauseCounters {
    pub via_detach_upstream: u64,
    pub via_remove_peer: u64,
    pub via_remove_peer_reserved: u64,
    pub via_flag_questionable: u64,
    pub detach_grandpa_tick_missing: u64,
    pub detach_silent_parent: u64,
    /// `DetachReason::ParentNotWriter` is declared but NEVER emitted — verified
    /// 2026-08-06, zero occurrences in the live logs. Counted so that if it ever
    /// starts firing, it shows up instead of hiding inside another bucket.
    pub detach_parent_not_writer: u64,
    // ── BY INTENT (KI#71) ────────────────────────────────────────────────
    // The via_* buckets above name WHICH FUNCTION cleared `up`, not whether
    // the loss was chosen or forced. That made a rise in healthy §2.2
    // self-optimisation (103 of 114 clears in a 2h run) read as a doubled
    // fault. Intent is what an operator actually wants to know.
    /// Node chose to move (§2.2 rebalance, rotation). Healthy.
    pub intent_voluntary: u64,
    /// Node was forced off its parent. Counted at the sites that KNOW the
    /// intent: the DetachUpstream action (grandpa-tick / silent parent) and the
    /// audit flag.
    ///
    /// INCOMPLETE, deliberately: `remove_peer` serves both voluntary and forced
    /// paths, so a loss via `remove_peer` that is neither marked voluntary nor
    /// one of the above (e.g. a parent sending us TardisDetach) is counted in
    /// `via_remove_peer` but in NEITHER intent bucket. Better uncounted than
    /// miscounted — the whole reason these buckets exist is that counting by
    /// call site made healthy self-optimisation look like a fault. Read
    /// `intent_*` as a floor, not a partition of `via_*`.
    pub intent_forced: u64,
}

impl OrphanCauseCounters {
    /// `(label, count)` pairs, for /status and diagnostics.
    pub fn as_pairs(&self) -> [(&'static str, u64); 9] {
        [
            ("via_detach_upstream", self.via_detach_upstream),
            ("via_remove_peer", self.via_remove_peer),
            ("via_remove_peer_reserved", self.via_remove_peer_reserved),
            ("via_flag_questionable", self.via_flag_questionable),
            ("detach_grandpa_tick_missing", self.detach_grandpa_tick_missing),
            ("detach_silent_parent", self.detach_silent_parent),
            ("detach_parent_not_writer", self.detach_parent_not_writer),
            ("intent_voluntary", self.intent_voluntary),
            ("intent_forced", self.intent_forced),
        ]
    }
    pub fn total_cleared(&self) -> u64 {
        self.via_detach_upstream + self.via_remove_peer
            + self.via_remove_peer_reserved + self.via_flag_questionable
    }
}

// ── TARDIS Node ──

/// TARDIS tree node — manages tick authority for this Nabla node.
/// Where a registration received by this node must be handled (KI#69).
///
/// Three states that `Option<PeerId>` could not represent: `None` previously
/// meant both "I am the writer" and "I am an orphan", and callers acted on the
/// first reading in both cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterRouting {
    /// This node is write-qualified — handle the registration locally.
    IAmWriter,
    /// This node is a reader anchored in the mesh — redirect the sender here.
    RedirectTo(PeerId),
    /// This node is an orphan: not write-qualified AND no upstream to point at.
    ///
    /// It MUST refuse the registration. It has no authority to adjudicate and its
    /// SMT head may be arbitrarily stale — answering produces a false
    /// `StateMismatch` that a correct wallet records as a real divergence.
    NoWriterKnown,
}

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
    /// Prefix of the audit challenge we currently have in flight (KI#48
    /// follow-up), with the tick VALUE it was issued at (KI#71). A response is
    /// only evaluated if its prefix matches — without the pin, an upstream
    /// could answer a prefix of its own choosing and the challenge's
    /// unpredictability property is void. Not overwritten by a re-issue while
    /// younger than `AUDIT_CHALLENGE_PENDING_TICKS`: since KI#71 the upstream
    /// answers at its next advertisement instant (~1 tick later), and an
    /// overwrite would turn every delayed honest answer into `unmatched`.
    pending_audit_prefix: Option<(Vec<u8>, u64)>,
    /// KI#71 — this node's root advertisement for its current tick label
    /// (see [`RootAdvert`]). Sampled once per tick label.
    root_advert: Option<RootAdvert>,
    /// KI#71 — AuditRequests waiting for our NEXT advertisement instant, where
    /// they are answered in the same SMT borrow that samples the advertised
    /// root. `audit_inbox_other` counts the entries NOT from a current
    /// downstream in the 8-bit challenge shape (bounded by
    /// `AUDIT_INBOX_OTHER_CAP`); downstream entries are deduped, so at most 256
    /// per child, and are never shed.
    audit_inbox: Vec<SubtreeAuditRequest>,
    audit_inbox_other: usize,
    /// KI#71 counters (CLAUDE.md RULE 3 §2 — on /status via `audit_counters`).
    /// `audit_requests_shed`: non-downstream requests dropped at the cap.
    /// `audit_response_stale`: matched answers whose `response_tick` is OLDER
    /// than the challenge — COUNTED, never dropped (a drop would stop us
    /// evaluating a stale-answering equivocator). `audit_selfcontra_flags`:
    /// SELF-CONTRADICTION convictions minted by this node.
    audit_requests_shed: u64,
    audit_response_stale: u64,
    audit_selfcontra_flags: u64,
    /// G5 — per-node PRIVATE audit entropy. Never sent, never derived from
    /// anything the auditee can see. Without it the challenged prefix is a
    /// public function of (tick, requester_pk) and the auditee can pre-compute
    /// exactly which 1/256 of its database to keep honest.
    audit_seed: [u8; 32],
    /// G6 — audit responses refused because the sender is not our upstream,
    /// and responses that matched no pending challenge. Counted because a
    /// denial-of-audit is otherwise indistinguishable from a quiet network
    /// (CLAUDE.md RULE 3 §2).
    audit_responses_unauthorized: u64,
    audit_responses_unmatched: u64,

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
    /// The tick number for which this node last emitted an approval to its
    /// UPSTREAM. YPX-003 write-qualification condition 3 ("approved the
    /// upstream's tick this interval") is `== current_tick`. Distinct from
    /// `prev_round_approval_count`, which counts our CHILDREN approving US.
    last_approved_upstream_tick: u64,
    /// GUIDE §5.6a — our peers do not all observe the same source address for
    /// us. Demotes this node to READ (see `is_self_writer`). Not persisted:
    /// it is re-derived from live observations after any restart.
    address_disputed: bool,
    /// GUIDE §5.6a — how many distinct peers have reported our source address.
    /// Stored beside the flag so the two can never drift. 0 means the check has
    /// had NOTHING to evaluate — missing coverage, not a pass.
    address_report_count: usize,
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

    /// Orphan-cause counters (observability only).
    orphan_causes: OrphanCauseCounters,
    /// Self-contradiction flags SUPPRESSED because the answer matched our own
    /// root (see the exonerate-only guard). Counted so the guard is observable:
    /// a silent guard is indistinguishable from a dead one.
    audit_exonerated: u64,
    /// Alerts naming our upstream that carried no verified proof — ignored
    /// for detach purposes. Counted so "we never detached" is observable.
    alerts_unproven_ignored: u64,

    // ── §32 TickHash root advertisements (the §32 quarantine timer, SCAN and
    // `merge_forked_wallets` were retired 2026-10-02 — ForkSettlement §9r-E4) ──
    /// Root hashes received from other branches during gossip.
    /// Used for fork detection: if root_hash differs at same tick → possible fork.
    /// Maps tick → (sender_pk, root_hash).
    /// Advertisements received via TickHash gossip, keyed by tick.
    /// `(advertiser, root, signature)` — the SIGNATURE is retained so a
    /// self-contradiction is provable evidence (two signed statements) rather
    /// than this node's recollection. Without it, an accusation could not be
    /// verified by anyone it was cascaded to.
    branch_root_hashes: HashMap<u64, Vec<(PeerId, Hash256, Vec<u8>)>>,

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
            pending_audit_prefix: None,
            root_advert: None,
            audit_inbox: Vec::new(),
            audit_inbox_other: 0,
            audit_requests_shed: 0,
            audit_response_stale: 0,
            audit_selfcontra_flags: 0,
            audit_seed: {
                use rand::RngCore;
                let mut s = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut s);
                s
            },
            audit_responses_unauthorized: 0,
            audit_responses_unmatched: 0,
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
            last_approved_upstream_tick: 0,
            address_disputed: false,
            address_report_count: 0,
            subtree_d_available: 0,
            d1_reserved: None,
            d2_reserved: None,
            orphan_causes: OrphanCauseCounters::default(),
            audit_exonerated: 0,
            alerts_unproven_ignored: 0,
            branch_root_hashes: HashMap::new(),
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
            // KI#48 STORM FIX. `TICK_SLOT_PIGGYBACK_MAX` (8) is the documented
            // bound on slot hints riding a tick — and it was enforced ONLY in
            // `sim.rs:1759`. The node stored and forwarded the list VERBATIM, so
            // it grew without bound as ticks propagated. `recovery_candidates()`
            // returns this list, and orphan recovery sends ONE ATTACH REQUEST PER
            // ENTRY — which is the attach storm: measured 10,141 requests from a
            // single node in one tick, uniformly across all 10, growing ~10x per
            // 5 ticks until the process is OOM-killed. Fifth instance this
            // session of a bound that exists in the register and the simulator
            // and never ran in the product.
            self.last_known_open_slots = tick
                .available_slots
                .iter()
                .take(crate::constants::TICK_SLOT_PIGGYBACK_MAX)
                .cloned()
                .collect();
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
        //   (iii) cryptographic verification of `prev_sig` against
        //        `grandparent_pk`'s NBC-bound Ed25519 PK. ⚠ THIS IS BUILT
        //        AND ENFORCING — it is NOT deferred. An earlier version of
        //        this comment said the grandparent's signed payload "isn't
        //        currently carried in the wire"; that has been false since
        //        the §7.6 lineage work landed, and reading it as current
        //        cost a full investigation on 2026-08-06.
        //
        //        `TickMessage.gp_commitment` (types.rs) carries the
        //        grandparent's commitment fields; `tardis.rs` (build-tick,
        //        below) POPULATES it; and `nabla_node.rs` (recv, ~2255)
        //        reconstructs the commitment via
        //        `crypto::tick_commitment_fields` and checks THREE things:
        //        Ed25519 sig over that commitment, tick freshness
        //        (LINEAGE_FRESHNESS_TICKS), and strict-parent (our parent
        //        must appear in the grandparent's child set). Failure DROPS
        //        the tick and, if the sender's own signature is valid,
        //        accuses it into quarantine consensus. It runs under --dev.
        //
        //        Verified live 2026-08-06 (kappa, RUST_LOG=nabla_node=debug):
        //        [LINEAGE-OK] on real traffic, drift=0, LINEAGE-SKIP=0.
        //        `[LINEAGE-OK]` is debug + rate-limited (number % 120) so it
        //        is INVISIBLE at the production `info` level — silence is not
        //        evidence the check is dead. See the lineage counters on
        //        /status, which exist so this is observable without a restart.
        //
        // GRANDPA_OK BELOW IS A SEPARATE, WEAKER RULE — a PRESENCE check
        // (`grandparent_pk.is_some() && !prev_sig.is_empty()`) that decides
        // whether to DETACH. Do not confuse the two: (iii) rejects a FORGED
        // lineage; grandpa_ok reacts to an ABSENT one. On miss for
        // GRANDPA_MISS_DETACH_THRESHOLD consecutive ticks, emit
        // DetachUpstream → orphan recovery.
        let parent_is_writer = tick.downstream_approvals >= 2;
        let chain_present = tick.grandparent_pk.is_some() && !tick.prev_sig.is_empty();

        // ── KI#48: SETTLE GRACE ON A NEW PARENT ──────────────────────────────
        // `parent_is_writer` requires the parent to ALREADY hold two children.
        // But a parent gets its second child only by keeping the first — and the
        // first leaves after GRANDPA_MISS_DETACH_THRESHOLD ticks if the parent
        // has not become a writer yet. Circular: a dc=1 parent can never climb
        // to dc=2, so the mesh manufactures no writers and every attach is
        // undone. Measured live 2026-08-01: 2,478 successful attaches against
        // 2,147 GrandpaTickMissing detaches in one window, with orphan recovery
        // working underneath.
        //
        // Introduced by `e11cc84e` (2026-05-30), the day AFTER the §2.4.7 kick
        // test recorded 5 stable writers and 0 detach events. Nothing re-ran that
        // test afterwards.
        //
        // The grace gives a freshly-attached parent GRANDPA_SETTLE_TICKS to
        // acquire its second child before its children start counting misses.
        // This is NOT a fallback: nothing weaker is substituted and no failure is
        // swallowed. The check runs in full, just not before the parent has had a
        // fair chance to satisfy it. (`WRITER_SETTLE_TICKS` was meant to be this
        // guard and is dead code — declared, never consumed.)
        // ── ORIGIN CARVE-OUT (AXIOM Origin ruling, 2026-08-01) ──────────────
        // "If it does not have a parent, and it has two downstream, it SHOULD
        //  generate ticks — and actively seek a parent. This stops orphans."
        //
        // A node with no upstream is an ORIGIN, and TARDIS has no root — only an
        // origin (§1.1). Its ticks legitimately carry `grandparent_pk: None`,
        // because there is no grandparent to name. But `chain_present` demanded
        // `grandparent_pk.is_some()`, so EVERY child of an origin failed the
        // grandpa check and detached after GRANDPA_MISS_DETACH_THRESHOLD ticks.
        // The origin then dropped below dc=2, stopped qualifying as a writer,
        // and the subtree disintegrated — which is the orphan cascade: measured
        // `write:100% orph:10` (every node holding two downstream, producing
        // nothing that its children would accept).
        //
        // An origin's tick is legitimate when the origin itself is
        // write-qualified — it holds D1+D2 and carries their approvals. That is
        // the same evidence any other writer offers; the only thing it cannot
        // offer is a grandparent, and demanding one of a node that by
        // definition has none is the bug.
        //
        // This does NOT weaken the chain rule for non-origins: a parent that
        // CLAIMS an upstream must still present it (`chain_present`), and
        // nabla_node.rs separately ENFORCES the lineage signature whenever a
        // tick carries `grandparent_pk` + `gp_commitment`. A forged
        // "I am an origin" claim buys nothing — the sender still needs two
        // genuine downstream approvals, which are Ed25519-signed by the children.
        // DETACH ONLY IF THERE IS NO GRANDPA (AXIOM Origin, 2026-08-01).
        // The rule is named GrandpaTickMissing and that is ALL it should mean.
        // It previously required `parent_is_writer && chain_present`, so a child
        // also left a parent that simply had not become a writer YET — and since
        // a parent becomes a writer only by KEEPING two children, that is
        // circular and no dc=1 parent could ever climb to dc=2.
        //
        //   * parent claims an upstream  -> the chain must be present
        //     (`chain_present`). A parent WITH a grandpa is a valid link
        //     whatever its own downstream count; not-yet-a-writer is not a
        //     reason to leave.
        //   * parent is an ORIGIN (no upstream, so `grandparent_pk: None`) ->
        //     TARDIS has no root, only an origin (§1.1), and an origin cannot
        //     name a grandparent. Its legitimacy is its OWN two downstream
        //     approvals, which are Ed25519-signed by the children. So an origin
        //     with dc=2 may generate ticks, and its children stay attached while
        //     it actively seeks a parent.
        //
        // This is what stops the orphan cascade: previously EVERY child of an
        // origin detached after GRANDPA_MISS_DETACH_THRESHOLD, the origin fell
        // below dc=2, and its subtree disintegrated — measured `write:100%
        // orph:10`, every node holding two downstream and producing nothing its
        // children would accept.
        //
        // A forged "I am an origin" claim buys nothing: the sender still needs
        // two genuine downstream approvals it cannot fabricate.
        let is_origin_tick = tick.grandparent_pk.is_none();
        let settled = self.ticks_with_current_parent >= crate::constants::GRANDPA_SETTLE_TICKS;
        let grandpa_ok = !settled
            || if is_origin_tick { parent_is_writer } else { chain_present };
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
                    // Counted HERE, where the reason is known. The handler calls
                    // remove_peer(), so by the time `up` is cleared the reason
                    // is gone and only `via_remove_peer` would increment.
                    self.orphan_causes.detach_grandpa_tick_missing += 1;
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
            // Bounded forward — see the storm note above. Without the cap the
            // list accumulates on every hop and every tick.
            available_slots: tick
                .available_slots
                .iter()
                .take(crate::constants::TICK_SLOT_PIGGYBACK_MAX)
                .cloned()
                .collect(),
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
            // YPX-003 condition 3: record that we approved our upstream for THIS
            // tick. Write qualification reads it back in `is_self_writer`.
            self.last_approved_upstream_tick = tick.number;
        }

        // 9. Broadcast root hash via gossip mesh for partition detection.
        //    KI#71: through the ONE advertisement builder — the same SMT borrow
        //    answers every queued §5.5 audit request, so our audit answer for
        //    this tick can never contradict the root we advertise for it.
        let (advert, audit_responses) = self.advertise_root(smt, signer);
        actions.push(TardisAction::BroadcastRootHash {
            tick: advert.tick,
            root_hash: advert.root_hash,
            node_pk: self.my_pk,
            signature: advert.signature,
        });
        actions.extend(audit_responses);

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
    /// Called periodically (e.g., every few ticks). Records the challenged
    /// prefix so the response can be matched to it (unpredictability is only
    /// worth something if the answer is checked against the question).
    pub fn generate_audit_request(&mut self) -> Option<TardisAction> {
        let up_pk = self.up?;

        // §5.5 requires an UNPREDICTABLE prefix ("Pick random subtree prefix
        // (unpredictable)" — the spec pseudocode uses an RNG).
        //
        // RULE 0 marker (2026-08-07, ghost audit G5 — the old comment was
        // FALSE). This read:
        //     blake3(current_tick ‖ my_pk)[0]
        //     "deterministic but unpredictable to upstream"
        // Both inputs are PUBLIC to the upstream: it receives the tick it just
        // broadcast, and `my_pk` is the requester's peer id — carried in the
        // request itself as `requester_pk`. So the upstream could compute every
        // downstream's next prefix for every tick, keep exactly that 1/256 of
        // the keyspace honest, and tamper the rest undetected. The audit
        // verified a slice the auditee chose.
        //
        // Now derived from a per-node PRIVATE seed, so it stays deterministic
        // (replayable in tests via `set_audit_seed`) while being unpredictable
        // to everyone else. The seed never leaves the node.
        // KI#71: a challenge younger than AUDIT_CHALLENGE_PENDING_TICKS is still
        // owed an answer (the upstream answers at its NEXT advertisement
        // instant). Re-issuing now would overwrite the prefix and the delayed
        // honest answer would be dropped as `unmatched` — the audit would never
        // evaluate anything (RULE 3). Tick VALUEs are unix seconds (KI#47), so
        // the COUNT is projected through `ticks_to_secs`.
        if let Some((_, issued_at)) = &self.pending_audit_prefix {
            if self.current_tick.saturating_sub(*issued_at)
                < axiom_core_logic::types::ticks_to_secs(AUDIT_CHALLENGE_PENDING_TICKS)
            {
                return None;
            }
        }
        let prefix_byte = blake3::hash(
            &[&self.audit_seed[..], &self.current_tick.to_le_bytes()[..]].concat(),
        );
        let prefix = vec![prefix_byte.as_bytes()[0]];
        self.pending_audit_prefix = Some((prefix.clone(), self.current_tick));

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

    /// KI#71 — THE one builder for this node's root advertisement at its
    /// current tick label, and the ONLY production place a §5.5 audit answer is
    /// built. Samples `smt.root_hash()` once per tick label, signs
    /// `(tick, root, my_pk)`, caches it, and answers every queued AuditRequest
    /// in the SAME `&smt` borrow, so `response.root_hash` == the advertised
    /// root and `response.response_tick` == the advertised tick.
    ///
    /// A second call within the same tick label returns the cached advert and
    /// answers nothing — requests that arrived after the sample wait for the
    /// next tick's fresh sample (the SMT may have moved since).
    pub fn advertise_root(
        &mut self,
        smt: &SparseMerkleTree,
        signer: &dyn Signer,
    ) -> (RootAdvert, Vec<TardisAction>) {
        if let Some(adv) = &self.root_advert {
            if adv.tick == self.current_tick {
                return (adv.clone(), Vec::new());
            }
        }
        let root_hash = smt.root_hash();
        let advert = RootAdvert {
            tick: self.current_tick,
            root_hash,
            signature: signer.sign(&crypto::tickhash_sign_payload(
                self.current_tick,
                &root_hash,
                &self.my_pk,
            )),
        };
        self.root_advert = Some(advert.clone());
        let queued = std::mem::take(&mut self.audit_inbox);
        self.audit_inbox_other = 0;
        let responses = queued
            .iter()
            .map(|req| self.handle_audit_request(req, smt, signer))
            .collect();
        (advert, responses)
    }

    /// KI#71 — queue an AuditRequest for our next advertisement instant
    /// ([`Self::advertise_root`]). Returns false if it was shed at the cap.
    ///
    /// Bounding without a new denial-of-audit: a request from one of OUR
    /// downstream slots (D1/D2/P) in the 8-bit challenge shape that
    /// `generate_audit_request` emits is ALWAYS kept (deduped on
    /// (requester, prefix), so at most 256 per child — a spoofer cannot crowd
    /// out the honest prefix). Anything else is still answered, up to
    /// `AUDIT_INBOX_OTHER_CAP` per tick; overflow is counted, never silent.
    /// Wire intake is unchanged: before KI#71 every request was answered
    /// immediately and unbounded.
    pub fn queue_audit_request(&mut self, request: &SubtreeAuditRequest) -> bool {
        let dup = self.audit_inbox.iter().any(|q| {
            q.requester_pk == request.requester_pk
                && q.prefix == request.prefix
                && q.prefix_bits == request.prefix_bits
        });
        if dup {
            return true;
        }
        let from_downstream = [self.d1, self.d2, self.pending]
            .iter()
            .any(|s| *s == Some(request.requester_pk));
        let challenge_shape = request.prefix_bits == 8 && request.prefix.len() == 1;
        if !(from_downstream && challenge_shape) {
            if self.audit_inbox_other >= AUDIT_INBOX_OTHER_CAP {
                self.audit_requests_shed = self.audit_requests_shed.saturating_add(1);
                return false;
            }
            self.audit_inbox_other += 1;
        }
        self.audit_inbox.push(request.clone());
        true
    }

    /// Build the §5.5 answer to `request` from `smt` AT THIS INSTANT.
    ///
    /// Production never calls this directly — it goes through
    /// [`Self::queue_audit_request`] + [`Self::advertise_root`], which call it
    /// in the same SMT borrow that samples the advertised root (KI#71). The
    /// single-threaded sim (`sim.rs`) calls it directly: its SMT cannot move
    /// between the parent's advert and this answer within one sim step.
    pub fn handle_audit_request(
        &self,
        request: &SubtreeAuditRequest,
        smt: &SparseMerkleTree,
        signer: &dyn Signer,
    ) -> TardisAction {
        let (subtree_hash, siblings) = smt.subtree_proof(&request.prefix, request.prefix_bits);
        let root_hash = smt.root_hash();

        let mut response = SubtreeAuditResponse {
            prefix: request.prefix.clone(),
            prefix_bits: request.prefix_bits,
            subtree_hash,
            root_hash,
            response_tick: self.current_tick,
            responder_pk: self.my_pk,
            siblings,
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
        let our_root = our_smt.root_hash();

        // ── Responder authorization (§5.5: we audit our UPSTREAM) ──
        //
        // RULE 0 marker (2026-08-07, ghost audit G6). Nothing here checked WHO
        // answered. The binary verifies the signature (KI#19, NBC-anchored), so
        // the responder is AUTHENTICATED — but any node holding a valid NBC is
        // authenticated, and none of them but our upstream is authorized to
        // answer our challenge.
        //
        // Combined with the old `.take()` below that was a free, silent
        // denial-of-audit: `take()` ran BEFORE the prefix comparison, so ANY
        // response — even a junk prefix — consumed the pending challenge and
        // our upstream's real answer was then dropped as unsolicited. One peer
        // sending one response per tick disabled another node's upstream
        // auditing indefinitely, and the only trace was a `debug!` line.
        if Some(response.responder_pk) != self.up {
            self.audit_responses_unauthorized =
                self.audit_responses_unauthorized.saturating_add(1);
            log::warn!(
                "[AUDIT-RESP-NOT-UPSTREAM] responder={:02x}{:02x} is not our upstream                  — dropped WITHOUT consuming the pending challenge (§5.5)",
                response.responder_pk[0], response.responder_pk[1],
            );
            return Ok(TardisAction::None);
        }

        // ── Challenge/response binding (KI#48 follow-up) ──
        // Only evaluate a response to the prefix WE challenged. An unsolicited
        // or stale response is dropped, not flagged — crossed messages are
        // honest network noise; `ticks_since_audit` keeps growing so a fresh
        // challenge goes out next tick.
        //
        // Consume ONLY on a match. Taking first discards the challenge that a
        // late-but-correct answer still needs.
        match &self.pending_audit_prefix {
            Some((expected, challenge_tick)) if *expected == response.prefix => {
                // KI#71 (Fable): an answer for a tick OLDER than our challenge is
                // COUNTED and still evaluated — never dropped. A drop path here
                // would let an equivocator escape the self-contradiction check
                // simply by answering with a stale tick label.
                if response.response_tick < *challenge_tick {
                    self.audit_response_stale = self.audit_response_stale.saturating_add(1);
                    log::debug!(
                        "[AUDIT-RESP-STALE] response_tick={} < challenge_tick={} — counted, evaluated",
                        response.response_tick, challenge_tick
                    );
                }
                self.pending_audit_prefix = None;
            }
            _ => {
                self.audit_responses_unmatched =
                    self.audit_responses_unmatched.saturating_add(1);
                log::debug!(
                    "Audit: response prefix {:02x?} does not match a pending challenge — dropped",
                    &response.prefix
                );
                return Ok(TardisAction::None);
            }
        }

        // ── Proof verification (§5.5 step 4, the real one) ──
        // The response's subtree_hash + sibling path must fold back to the
        // root_hash the response itself claims. A response that fails this
        // is internally inconsistent — a provable lie about the upstream's
        // own database, whatever our own root looks like.
        if !SparseMerkleTree::verify_subtree_proof(
            &response.root_hash,
            &response.prefix,
            &response.subtree_hash,
            &response.siblings,
        ) {
            log::warn!(
                "Audit: subtree proof does NOT reconstruct to the claimed root {:?} (prefix {:02x?}, {} siblings)",
                &response.root_hash[..4],
                &response.prefix,
                response.siblings.len()
            );
            // The signed response is self-refuting: its own proof does not fold
            // to the root it claims. No advertisement needed.
            return Ok(self.flag_questionable(
                response.responder_pk,
                signer,
                Some(QuestionableEvidence {
                    audit_response: response.clone(),
                    advertised_root: None,
                    advertised_sig: Vec::new(),
                }),
            ));
        }

        // §5.5 (AXIOM_GUIDE_Nabla.md): the audit asks "is UP lying about its
        // OWN database?" — a SELF-consistency check. Beyond the proof above,
        // the upstream must not contradict itself: the root it answers with
        // must be the root it advertised via TickHash gossip for the same
        // tick.
        //
        // KI#48: the previous body compared the upstream's root against OUR
        // root and flagged QUESTIONABLE on mismatch. A freshly re-attached
        // orphan is divergent by definition, so its first audit (~5 ticks
        // after attach) always "failed", detaching it again — the orphan
        // oscillation. Divergence from our own root is AE's job to resolve,
        // never grounds to dismantle topology.
        // Facts gathered UP FRONT as owned values: `flag_questionable` needs
        // &mut self, so no borrow of `self.branch_root_hashes` may be held
        // across it.
        let advertised_for_tick: Option<Hash256> = self
            .branch_root_hashes
            .get(&response.response_tick)
            .and_then(|e| {
                e.iter()
                    .find(|(pk, _, _)| *pk == response.responder_pk)
                    .map(|(_, r, _)| *r)
            });
        let distinct_advertised = self
            .branch_root_hashes
            .get(&response.response_tick)
            .map(|e| {
                let mut v: Vec<Hash256> = e.iter().map(|(_, r, _)| *r).collect();
                v.sort_unstable();
                v.dedup();
                v.len()
            })
            .unwrap_or(0);
        // STALENESS TEST (2026-08-07): did the responder ALREADY advertise the
        // root it just answered with, at some other tick? If the answer matches
        // an advertisement at a LATER tick, the responder had simply moved on —
        // the "contradiction" is two snapshots of a moving target, not a lie.
        // Purely local; needs no wire change. This is what separates the 18
        // unexplained flags (advertised/answered/ours all different) into
        // staleness vs real divergence.
        let answered_seen_at: Option<u64> = self
            .branch_root_hashes
            .iter()
            .filter(|(_, v)| {
                v.iter()
                    .any(|(pk, r, _)| *pk == response.responder_pk && *r == response.root_hash)
            })
            .map(|(t, _)| *t)
            .max();
        // COVERAGE (2026-08-07): `answered_seen_at = none` is ambiguous on its
        // own — it means "we hold no record of that root", which is TRUE both
        // when the responder never advertised it (real divergence) and when the
        // advertisement simply never reached us or has aged out
        // (branch_root_hashes retains ~20 ticks). Without coverage, `none` was
        // being read as evidence of divergence when it may be evidence of our
        // own gap. Report what we actually hold about this responder so the
        // reader can tell the two apart:
        //   adv_count   — advertisements retained from THIS responder
        //   adv_after   — how many of those are at ticks LATER than the one
        //                 answered. If we hold several later roots from this
        //                 responder and the answer is none of them, "never
        //                 advertised" is well-evidenced. If adv_after == 0 we
        //                 simply cannot conclude.
        let (adv_count, adv_after) = {
            let mut count = 0usize;
            let mut after = 0usize;
            for (t, v) in self.branch_root_hashes.iter() {
                for (pk, _, _) in v.iter() {
                    if *pk == response.responder_pk {
                        count += 1;
                        if *t > response.response_tick {
                            after += 1;
                        }
                    }
                }
            }
            (count, after)
        };

        if let Some(advertised) = advertised_for_tick {
            if advertised != response.root_hash && response.root_hash == our_root {
                log::debug!(
                    "[SELFCONTRA-EXONERATED] tick={} responder={:?} advertised={:?} \
                     answered={:?} == our root — stale gossip, not a lie; staying attached",
                    response.response_tick,
                    &response.responder_pk[..4],
                    &advertised[..4],
                    &response.root_hash[..4]
                );
                self.audit_exonerated = self.audit_exonerated.saturating_add(1);
            } else if advertised != response.root_hash {
                log::warn!(
                    "Audit: upstream SELF-CONTRADICTION at tick {}: advertised root {:?} but audit answered {:?} \
                     | SELFCONTRA-DIAG proof_ok=true answered_eq_ours={} advertised_eq_ours={} \
                     distinct_advertised_roots={} answered_seen_at_tick={} adv_count={} adv_after={} \
                     our_tick={} responder={:?}",
                    response.response_tick,
                    &advertised[..4],
                    &response.root_hash[..4],
                    response.root_hash == our_root,
                    advertised == our_root,
                    distinct_advertised,
                    answered_seen_at.map(|t| t as i64).unwrap_or(-1),
                    adv_count,
                    adv_after,
                    self.current_tick,
                    &response.responder_pk[..4]
                );
                // Self-contradiction: two statements signed by the SUSPECT —
                // its audit answer and its own advertisement for the same tick.
                // We retain the advertisement signature precisely so this is
                // provable to a receiver rather than asserted.
                let advertised_sig = self
                    .branch_root_hashes
                    .get(&response.response_tick)
                    .and_then(|e| {
                        e.iter()
                            .find(|(pk, r, _)| {
                                *pk == response.responder_pk && *r == advertised
                            })
                            .map(|(_, _, sig)| sig.clone())
                    })
                    .unwrap_or_default();
                self.audit_selfcontra_flags = self.audit_selfcontra_flags.saturating_add(1);
                return Ok(self.flag_questionable(
                    response.responder_pk,
                    signer,
                    Some(QuestionableEvidence {
                        audit_response: response.clone(),
                        advertised_root: Some(advertised),
                        advertised_sig,
                    }),
                ));
            }
        }

        if response.root_hash != our_root {
            // Honest divergence (or we simply lag the upstream). Leave the
            // tree alone; anti-entropy converges the SMTs while attached —
            // detaching here is what PREVENTED convergence.
            log::debug!(
                "Audit: upstream root {:?} differs from ours {:?} — divergence noted, not flagged (AE will converge)",
                &response.root_hash[..4],
                &our_root[..4]
            );
        } else {
            self.audit_pass_count += 1;
            log::debug!(
                "Audit passed (count: {}), root: {:?}",
                self.audit_pass_count,
                &our_root[..4]
            );
        }
        self.ticks_since_audit = 0;

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
    /// `evidence` is the suspect's own signed statements proving the
    /// accusation. `None` means this node is re-minting on cascade and holds no
    /// proof — receivers MUST NOT detach on such an alert.
    fn flag_questionable(
        &mut self,
        suspect: PeerId,
        signer: &dyn Signer,
        evidence: Option<QuestionableEvidence>,
    ) -> TardisAction {
        log::warn!(
            "Flagging upstream {:?} as QUESTIONABLE at tick {}",
            &suspect[..4],
            self.current_tick
        );

        // 1. Mark upstream status
        self.upstream_status = NodeStatus::Questionable;

        // 2. Build alert
        // Commit to the PROOF when we have one. The old hash covered
        // (tick, suspect, reporter) — all already in the alert — so it proved
        // nothing; it was a dedup key named "evidence". With evidence attached,
        // the alert signature now covers the proof too.
        let evidence_hash = match &evidence {
            Some(ev) => crypto::evidence_commitment(ev),
            None => *blake3::hash(
                &[
                    &self.current_tick.to_le_bytes()[..],
                    &suspect[..],
                    &self.my_pk[..],
                ]
                .concat(),
            )
            .as_bytes(),
        };

        let mut alert = QuestionableAlert {
            suspect_pk: suspect,
            reporter_pk: self.my_pk,
            tick: self.current_tick,
            evidence_hash,
            signature: vec![], // filled below
            evidence,
        };
        alert.signature = signer.sign(&crypto::alert_sign_payload(&alert));

        // KI#37 — record our own minted alert as seen, so the cascade
        // looping back through a transient tree cycle is dropped instead
        // of re-triggering detach + re-forward.
        let _ = self.record_alert_seen(Self::alert_seen_key(&alert));

        // 3. Disconnect from upstream
        self.clear_upstream("flag_questionable");
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
            // Re-minted on cascade: this node did not audit the suspect itself,
            // so it holds no proof. `None` means "unproven" and a receiver MUST
            // NOT detach on it.
            evidence: None,
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

        // If the suspect is our upstream, disconnect — BUT ONLY ON PROOF.
        //
        // CONTRACT: `alert.evidence` is present only when the node layer has
        // VERIFIED it against the suspect's NBC-anchored key
        // (`crypto::verify_questionable_evidence`); it strips the field when the
        // proof fails or is absent. Same contract as `record_branch_root_hash`:
        // TardisNode holds no keys, so authentication happens at the edge and
        // this layer treats presence as proven.
        //
        // Previously this detached on the reporter's word alone, so one
        // accusation dismantled the suspect's whole subtree — and the
        // accusation itself could be generated from an unsigned TickHash. An
        // unproven alert still CASCADES (a warning is worth propagating to
        // nodes that can audit the suspect themselves); it just may not
        // dismantle topology.
        if self.up.map(|u| u == alert.suspect_pk).unwrap_or(false) {
            if alert.evidence.is_some() {
                return self.flag_questionable(alert.suspect_pk, signer, alert.evidence.clone());
            }
            self.alerts_unproven_ignored = self.alerts_unproven_ignored.saturating_add(1);
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

    /// Set upstream connection (a real D seat at `peer`).
    #[track_caller]
    pub fn set_upstream(&mut self, peer: PeerId) {
        self.attach_upstream(peer, NodeStatus::Connected);
    }

    /// YPX-003 §2.1 step 2 (KI#48, RULED 2026-09-25) — PARK in `peer`'s P
    /// slot. `up` becomes the host so its ticks are received and validated
    /// exactly like a D child's (`process_tick` checks only `up`), but the
    /// status is `Pending`, so `has_upstream()` / `needs_parent()` /
    /// `is_self_writer()` all read "still seeking". ONE builder with
    /// `set_upstream` (RULE 1): the status is the only difference.
    #[track_caller]
    pub fn set_upstream_pending(&mut self, peer: PeerId) {
        self.attach_upstream(peer, NodeStatus::Pending);
    }

    #[track_caller]
    fn attach_upstream(&mut self, peer: PeerId, status: NodeStatus) {
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
        self.upstream_status = status;
        self.audit_pass_count = 0;
        self.ticks_since_audit = 0;
        self.ticks_with_current_parent = 0;
        log::info!(
            "[TARDIS-UP-SET] up={:?} status={:?} caller={}",
            &peer[..4],
            status,
            std::panic::Location::caller()
        );
    }

    /// THE ONE "parked" predicate (YPX-003 §2.1 RULED 2026-09-25): this node
    /// sits in a host's P slot — a tick source, not a tree seat. The
    /// orphan-recovery loop (`needs_parent()`), the writer predicate
    /// (`is_self_writer()`) and the origin gate (`has_tick_source()`) all
    /// derive from `upstream_status`; nothing else may test `Pending`.
    pub fn is_parked(&self) -> bool {
        self.up.is_some() && self.upstream_status == NodeStatus::Pending
    }

    /// Does this node RECEIVE ticks from someone — a D parent OR a P host?
    /// Gates self-origination in the tick loop: a parked node must not
    /// generate its own tick on top of the host's (the two would collide in
    /// `process_tick`'s replay bound). Distinct from `has_upstream()`, which
    /// means "seated" and stays false while parked.
    pub fn has_tick_source(&self) -> bool {
        self.has_upstream() || self.is_parked()
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
    #[track_caller]
    pub fn remove_peer(&mut self, peer: &PeerId) {
        if self.up.as_ref() == Some(peer) {
            // KI#48: every clear of `up` must say why — the orphan
            // oscillation was invisible because this path had no log.
            self.clear_upstream("remove_peer");
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
    #[track_caller]
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
            self.clear_upstream("remove_peer_reserved");
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
            // Counted here, where the reason is known — see the grandpa site.
            self.orphan_causes.detach_silent_parent += 1;
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
    ///
    /// YPX-003 §2.1 (KI#48, RULED 2026-09-25): a PARKED node (`is_parked()`)
    /// also needs a parent — P is transitional, and this staying TRUE is what
    /// keeps it seeking a real D slot through `SlotAvailable` hints and the
    /// two-pass relax. The 08-01 grant set `Connected` here, `needs_parent()`
    /// went false, and a cold-started mesh parked every node and produced no
    /// writers. `has_upstream()` is `Connected`-only, so this needs no extra
    /// clause — but it is the reason that predicate must not widen.
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

    /// Check if this node is a qualified WRITER.
    /// Writers can record transactions. Readers redirect to writers.
    ///
    /// YPX-003 "Per-tick write qualification (NORMATIVE)" requires all three of:
    ///   1. downstream_count == 2
    ///   2. has_upstream == true
    ///   3. approved the upstream's tick this interval
    ///
    /// Condition 2 is enforced here (KI#69). It was previously absent, which let
    /// an ORPHAN qualify as a writer: the spec is explicit that "a writer without
    /// upstream is a candidate writer still searching; it does not yet have
    /// authority." An orphan that believes it is a writer adjudicates
    /// registrations against its own stale SMT head and tells a CORRECT wallet it
    /// has diverged — see KI#69 for the traced incident.
    ///
    /// Condition 3 is ENFORCED again as of 2026-08-18 (design decision), restoring full
    /// spec compliance. It had been switched off on 2026-08-05 on the grounds
    /// that "TCP approval jitter" made the role flicker and blocked Nabla
    /// registration. **That diagnosis is now believed wrong.** The jitter it was
    /// reacting to is far better explained by the address defect fixed in
    /// `a1aa1ad7`: nabla resolved its own `--advertise` name at boot and
    /// gossiped the resulting IP, so nodes held unroutable addresses for their
    /// peers and dropped approvals wholesale — `[APPROVAL-UNSENT] cannot resolve
    /// upstream … approval DROPPED`, which is exactly what flickering approval
    /// liveness looks like from the inside. Turning the condition off treated
    /// the symptom of a transport bug as a property of TCP.
    ///
    /// Note this reads OUR OWN emitted approval (`last_approved_upstream_tick`),
    /// not our children's — it cannot be starved by a peer, only by us failing
    /// to process a tick, which is the exact liveness the spec is asking about.
    ///
    /// ⚠ If writer flicker DOES reappear under load, do not simply switch this
    /// off again: capture which node stopped approving and why first. The whole
    /// point of the 2026-08-05 regression is that the off-switch hid the cause.
    ///
    /// `downstream_count() >= 2` is retained rather than the spec's `== 2`: the
    /// two are equivalent here because d1/d2 are two `Option<PeerId>` fields, so
    /// dc > 2 is unreachable by type, and `add_downstream` refuses a third child.
    pub fn is_self_writer(&self) -> bool {
        // YPX-003 §2.1 (KI#48, RULED 2026-09-25): P is NEVER a writer input.
        // A parked node fails condition 2 (`has_upstream()` is Connected-only,
        // so `is_parked()` ⇒ not a writer), and a host's P child is never in
        // `downstream_count()` (d1/d2 only) — so a mesh of parked nodes forms
        // writers only through real D attaches, which the 08-01 stall proved
        // necessary. Both halves are asserted by `p_slot_never_counts_toward_
        // writer`.
        // GUIDE §5.6a — DEMOTE, don't disconnect. When our peers do not all
        // observe the same source address for us, we serve as a READ node: still
        // gossiping, running AE, relaying ticks and propagating peers, but not
        // accepting client writes. Gating it HERE (not at the call sites) means
        // `writer_routing()` inherits it for free — one predicate, one owner
        // (RULE 1). Registrations then take the existing REDIRECT path, so a
        // client is handed to a node that can write rather than refused.
        !self.address_disputed
            && self.downstream_count() >= 2
            && self.has_upstream()
            && self.last_approved_upstream_tick == self.current_tick
    }

    /// `/status` slot label + writer flag — from the SAME predicate the register
    /// door routes on (`is_self_writer` → `writer_routing`). RULE 6 (2026-10-01): the
    /// status used `downstream_count() == 2` alone, so a node with two children whose
    /// upstream had not approved this tick (or whose address was disputed) read
    /// "Writer" while its door answered `reader_redirect` — the fork gate picked such
    /// "writers" as doors four times and never built its fork.
    pub fn writer_status(&self) -> (bool, String) {
        let w = self.is_self_writer();
        let label = if self.has_upstream() {
            if w { "Writer".to_string() } else { format!("D{}", self.downstream_count()) }
        } else if self.is_parked() {
            "Parked".to_string()
        } else {
            "Orphan".to_string()
        };
        (w, label)
    }

    /// GUIDE §5.6a — set by the node when peer address observations disagree.
    /// Separate from the operator's `reader_only` on purpose: an operator
    /// clearing their own flag must never clear a security demotion.
    pub fn set_address_disputed(&mut self, disputed: bool, report_count: usize) {
        self.address_disputed = disputed;
        self.address_report_count = report_count;
    }

    pub fn address_report_count(&self) -> usize {
        self.address_report_count
    }

    pub fn address_disputed(&self) -> bool {
        self.address_disputed
    }

    /// Where should a registration received by this node be handled? (KI#69)
    ///
    /// This replaces `find_nearest_writer() -> Option<PeerId>`, whose two-valued
    /// return could not distinguish three distinct states. `None` meant BOTH "I
    /// am the writer, handle locally" AND "I am an orphan with no parent" —
    /// because `self.up` is `None` for an orphan. Every caller read the second as
    /// the first and processed the registration locally.
    ///
    /// The three states are now explicit, and `NoWriterKnown` is NOT a licence to
    /// answer: a node that cannot locate a writer must not answer a question only
    /// a writer can answer.
    pub fn writer_routing(&self) -> WriterRouting {
        if self.is_self_writer() {
            WriterRouting::IAmWriter
        } else if let Some(parent) = self.up {
            // Reader with an anchor: redirect upward. In production the parent is
            // the most likely writer (it has us + sibling as children → dc=2). If
            // the parent is also a reader, the sender follows the chain up; the
            // caller tracks hop count to prevent loops.
            WriterRouting::RedirectTo(parent)
        } else {
            // Orphan. Structurally unable to know the current writer, and its own
            // SMT head may be arbitrarily stale.
            WriterRouting::NoWriterKnown
        }
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
    /// Convenience wrapper for callers with no subtree-D figures to report.
    ///
    /// ⚠ ghost audit G17: this was the ONLY caller of
    /// `record_child_approvals_with_subtree`, and it always passed `0, 0` — so
    /// the §2.14.5 subtree-D aggregation never aggregated anything and
    /// `subtree_open_d` had no production read site. A caller that HAS the
    /// children's reported figures (they ride on `TickApproval.subtree_open_d`)
    /// must call the extended form directly, or the aggregation stays dead.
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
    /// Ghost-child handling (beta10 fix, 2026-04-13 soak: 3 parents spamming
    /// 6,500+ rejected ticks at 3 ghost children over ~3 hours): a parent with
    /// {d1=ghost, d2=None} must not forward ticks to the ghost forever, because
    /// the main rotation path requires both slots to be filled.
    ///
    /// That case is handled by the STALE-CHILD SLOT rule below, which fires at
    /// 20 misses and does not require both slots. The separate 100-miss
    /// "ghost-child escape hatch" that used to sit above it was UNREACHABLE and
    /// has been deleted — see the note in the body (ghost audit G12).
    pub fn wants_drop_slow_child(&mut self) -> Option<PeerId> {
        // ── ghost audit G12: the ghost-child escape hatch is DELETED ──────
        //
        // It required `d1_misses >= GHOST_CHILD_MISS_THRESHOLD` (100, bumped
        // from 10 on 2026-05-28). But the stale-child slot rule immediately
        // below fires at `STALE_CHILD_SLOT_THRESHOLD` (20) and RESETS the miss
        // counter — and it covers the single-child case too, since it does not
        // require both slots filled. So misses could never reach 100: the
        // branch was unreachable and `reason=ghost` never appeared in any log.
        //
        // Deleted rather than re-thresholded: its purpose (drop a
        // non-responsive child on a single-child node) is fully served by the
        // stale-slot rule, five times faster. The two rules were added a month
        // apart to solve the same symptom; the later one silently superseded
        // the earlier. Behaviour is unchanged by this deletion — a dead branch
        // cannot have been doing anything. RULE 3: delete it, do not leave it
        // reading as an active escape hatch.

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
            log::info!("[TARDIS-DROP-CHILD] d1={:?} reason=stale-slot misses={}",
                dropped.as_ref().map(|p| &p[..4]), self.d1_misses);
            self.d1 = None;
            self.d1_misses = 0;
            return dropped;
        }
        if self.d2.is_some() && self.d2_misses >= STALE_CHILD_SLOT_THRESHOLD {
            let dropped = self.d2;
            log::info!("[TARDIS-DROP-CHILD] d2={:?} reason=stale-slot misses={}",
                dropped.as_ref().map(|p| &p[..4]), self.d2_misses);
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
            log::info!("[TARDIS-DROP-CHILD] d1={:?} reason=rotation misses={}",
                dropped.as_ref().map(|p| &p[..4]), self.d1_misses);
            self.d1_misses = 0;
            dropped
        } else {
            let dropped = self.d2;
            log::info!("[TARDIS-DROP-CHILD] d2={:?} reason=rotation misses={}",
                dropped.as_ref().map(|p| &p[..4]), self.d2_misses);
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
        // A PARKED node (YPX-003 §2.1, KI#48) relays its host's ticks to its
        // children, so its subtree is not a zombie: it counts as having a
        // parent HERE (tick liveness), while `needs_parent()` still says it
        // must keep seeking a D seat. `has_tick_source` is that distinction.
        if self.has_tick_source() {
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
    #[track_caller]
    pub fn detach_upstream(&mut self) -> Option<PeerId> {
        let parent = self.clear_upstream("detach_upstream");
        self.upstream_status = NodeStatus::Disconnected;
        parent
    }

    // ══════════════════════════════════════════════════════════════════
    //  CANONICAL upstream-clear funnel
    //
    //  ⚠ THIS IS THE ONE TO USE. Need to drop `up` for a new reason? Call
    //  `clear_upstream(via)`. Do NOT write `self.up = None` again.
    //
    //  There were FOUR copies of "log [TARDIS-UP-CLEAR] then self.up = None"
    //  (flag_questionable, remove_peer, remove_peer_reserved, detach_upstream)
    //  — four builders for one fact. They are now one. A fifth copy would go
    //  uncounted in `orphan_causes` and nothing would fail loudly.
    // ══════════════════════════════════════════════════════════════════

    /// Clear `up`, log why, and count the path. Returns the dropped parent.
    ///
    /// `via` appears verbatim in `[TARDIS-UP-CLEAR] ... via=<via>` — KI#48
    /// established that every clear must say why, because the orphan
    /// oscillation was invisible while one path had no log.
    fn clear_upstream(&mut self, via: &str) -> Option<PeerId> {
        let prev = self.up.take();
        if let Some(p) = &prev {
            log::info!(
                "[TARDIS-UP-CLEAR] up={:?} via={} caller={}",
                &p[..4],
                via,
                std::panic::Location::caller()
            );
            match via {
                // detach_upstream is only reached from the DetachUpstream action
                // (grandpa-tick missing / silent parent) — always FORCED.
                "detach_upstream" => {
                    self.orphan_causes.via_detach_upstream += 1;
                    self.orphan_causes.intent_forced += 1;
                }
                "remove_peer" => self.orphan_causes.via_remove_peer += 1,
                "remove_peer_reserved" => self.orphan_causes.via_remove_peer_reserved += 1,
                "flag_questionable" => {
                    self.orphan_causes.via_flag_questionable += 1;
                    self.orphan_causes.intent_forced += 1;
                }
                // A new caller that forgot to add a bucket. Loud, not silent.
                other => log::warn!("[TARDIS-UP-CLEAR] uncounted via={other} — add a bucket to OrphanCauseCounters"),
            }
        }
        prev
    }

    /// Orphan-cause counters for /status and diagnostics.
    pub fn orphan_causes(&self) -> &OrphanCauseCounters {
        &self.orphan_causes
    }

    /// Mark the NEXT upstream loss as VOLUNTARY (KI#71). Called by the §2.2
    /// rebalance path immediately before it drops its parent to move.
    ///
    /// Intent is counted at the SITE THAT DECIDES, because `clear_upstream`
    /// cannot tell a chosen move from a forced one — `remove_peer` serves both.
    /// Counting by call site is what made 103 healthy self-optimisation moves
    /// read as a doubled fault.
    pub fn note_voluntary_move(&mut self) {
        self.orphan_causes.intent_voluntary = self.orphan_causes.intent_voluntary.saturating_add(1);
    }

    /// Count of self-contradiction flags suppressed by the exonerate-only guard.
    /// Audit responses refused for coming from a node that is not our upstream.
    pub fn audit_responses_unauthorized(&self) -> u64 {
        self.audit_responses_unauthorized
    }

    /// Audit responses that matched no pending challenge.
    pub fn audit_responses_unmatched(&self) -> u64 {
        self.audit_responses_unmatched
    }

    /// Pin the private audit entropy. Tests only — production seeds from the
    /// OS RNG in `new()`, and the seed must never be settable from the wire.
    #[cfg(test)]
    pub fn set_audit_seed(&mut self, seed: [u8; 32]) {
        self.audit_seed = seed;
    }

    pub fn audit_exonerated(&self) -> u64 {
        self.audit_exonerated
    }

    /// The §5.5 audit counters, for /status (RULE 3 §2: a check that cannot be
    /// observed running reads the same as a dead one). `selfcontra_flags`
    /// isolates the SELF-CONTRADICTION conviction that `orphan_causes`
    /// `via_flag_questionable` mixes with the merkle-proof and cascade causes.
    pub fn audit_counters(&self) -> [(&'static str, u64); 6] {
        [
            ("responses_unauthorized", self.audit_responses_unauthorized),
            ("responses_unmatched", self.audit_responses_unmatched),
            ("response_stale", self.audit_response_stale),
            ("selfcontra_flags", self.audit_selfcontra_flags),
            ("requests_shed", self.audit_requests_shed),
            ("exonerated", self.audit_exonerated),
        ]
    }

    /// Alerts naming our upstream that were ignored for lack of proof.
    pub fn alerts_unproven_ignored(&self) -> u64 {
        self.alerts_unproven_ignored
    }

    // ═══════════════════════════════════════════════════════════════════
    // §32 Merge Protocol
    // ═══════════════════════════════════════════════════════════════════

    /// Record a root hash from another branch (received via TickHash gossip).
    /// Returns true if a fork is detected (same tick, different root hash).
    /// `signature` MUST already have been verified against the sender's
    /// NBC-anchored key by the caller — this only retains it as evidence.
    pub fn record_branch_root_hash(
        &mut self,
        tick: u64,
        sender_pk: PeerId,
        root_hash: Hash256,
        signature: Vec<u8>,
    ) -> bool {
        let entries = self.branch_root_hashes.entry(tick).or_default();
        // Check for conflict: same tick, different root hash from a different sender
        let fork_detected = entries.iter().any(|(_, rh, _)| *rh != root_hash);
        entries.push((sender_pk, root_hash, signature));
        // Prune old entries (keep last 20 ticks)
        if self.branch_root_hashes.len() > 20 {
            let cutoff = tick.saturating_sub(20);
            self.branch_root_hashes.retain(|t, _| *t > cutoff);
        }
        fork_detected
    }

    // ForkSettlement §9r-E4 (owner ruling 2026-10-01, built 2026-10-02) —
    // DELETED here: `enter_merge_quarantine`, `forked_wallets`,
    // `clear_forked_wallets`, `is_in_quarantine`, `check_quarantine_expiry`
    // (the 75 s §32 timer, D-E4-1), `detect_forked_wallets` (the §32 SCAN —
    // a ghost: its one caller compared the head with itself), `propagate_taint`,
    // `resolve_merge`, `freeze_wallet` and `taint_wallet`. Nothing in
    // production writes `Frozen` / `Tainted` any more (source gate
    // `fork_detection_mesh::e4_d_no_view_based_status_writer`). A fork is A1
    // (`ban::apply_fork_verdict`); a downstream hold is A5 (`provenance.rs`).
    // `is_wallet_blocked` stays: `Banned` (A1) blocks, and a restored LEGACY
    // `Frozen`/`Tainted` leaf keeps blocking with no exit — counted by
    // `status_unbacked_at_load`, required to be 0 by the pre-deploy gate
    // (D-E4-2: stop and ask the owner, never normalise at load).

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


// ── Tests ──

#[cfg(test)]
mod tests {

    /// GUIDE §5.6a — the demotion must be able to FIRE and to CLEAR.
    ///
    /// RULE 3 §4: a gate that has never been shown to fail is a ghost. The
    /// avoid-list version of this idea shipped earlier the same week and was
    /// dead on arrival because nothing could ever satisfy its condition, so this
    /// asserts the state machine in both directions rather than trusting it.
    #[test]
    fn address_dispute_demotes_to_read_and_restores() {
        // Build a genuinely write-qualified node: dc>=2, has upstream, and we
        // approved the upstream's tick this interval (YPX-003 condition 3).
        let mut t = TardisNode::new(pk(0xAA));
        t.add_downstream(pk(0xBB));
        t.add_downstream(pk(0xCC));
        t.up = Some(pk(0xDD));
        t.upstream_status = NodeStatus::Connected;  // has_upstream() requires this
        t.current_tick = 42;
        t.last_approved_upstream_tick = 42;

        // Baseline: write-qualified.
        assert!(t.is_self_writer(), "fixture must start write-qualified, else \
                                     this test cannot distinguish demotion from \
                                     a permanently-false predicate");
        assert!(!t.address_disputed());

        // Peers disagree about our source address ⇒ READ node.
        t.set_address_disputed(true, 3);
        assert!(!t.is_self_writer(), "disagreement MUST demote (§5.6a)");
        assert!(t.address_disputed());
        assert_eq!(t.address_report_count(), 3);
        // writer_routing() must inherit it — one predicate, no call-site checks.
        assert!(!matches!(t.writer_routing(), WriterRouting::IAmWriter),
                "writer_routing must inherit the demotion, not re-derive it");

        // Observers agree again ⇒ restored, no operator action needed.
        t.set_address_disputed(false, 4);
        assert!(t.is_self_writer(), "agreement MUST restore write qualification");
        assert_eq!(t.address_report_count(), 4);
    }

    /// RULE 6 (2026-10-01): `/status` must say "Writer" exactly when the door would
    /// accept a register. MUTATION: `writer_status` uses `downstream_count() == 2`
    /// (the old proxy) ⇒ RED at "stale upstream tick".
    #[test]
    fn status_writer_flag_follows_the_register_door_predicate() {
        let mut t = TardisNode::new(pk(0xAA));
        t.add_downstream(pk(0xBB));
        t.add_downstream(pk(0xCC));
        t.up = Some(pk(0xDD));
        t.upstream_status = NodeStatus::Connected;
        t.current_tick = 42;
        t.last_approved_upstream_tick = 42;
        assert_eq!(t.writer_status(), (true, "Writer".to_string()), "write-qualified");
        assert!(matches!(t.writer_routing(), WriterRouting::IAmWriter));
        // Two children, but this tick not yet approved upstream: the door redirects.
        t.current_tick = 43;
        assert!(!matches!(t.writer_routing(), WriterRouting::IAmWriter), "fixture: door redirects");
        assert_eq!(t.writer_status(), (false, "D2".to_string()), "stale upstream tick: NOT a writer");
        // Address disputed: demoted to read even with a fresh tick.
        t.last_approved_upstream_tick = 43;
        t.set_address_disputed(true, 2);
        assert!(!t.writer_status().0, "address disputed: NOT a writer");
    }

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
            received_from: None,
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
        let mut node = TardisNode::new(pk(0xAA));
        // No upstream → should_audit false
        assert!(!node.should_audit());
        assert!(node.generate_audit_request().is_none());
    }


    // ── G5 / G6: the audit must sample where the auditee cannot predict, and
    //            only our upstream may answer ────────────────────────────────

    /// G5 — the challenged prefix must NOT be a public function of the tick and
    /// the requester's pk. It was `blake3(tick ‖ my_pk)[0]`, and the upstream
    /// holds both: it receives the tick it broadcast, and `my_pk` rides in the
    /// request as `requester_pk`. So it could pre-compute every downstream's
    /// next prefix and keep exactly that 1/256 of its database honest.
    #[test]
    fn g5_audit_prefix_is_not_derivable_from_public_inputs() {
        let my_pk = pk(0xAA);
        let tick = 1740000050u64;

        let mut node = TardisNode::new(my_pk);
        node.set_upstream(pk(0xBB));
        node.current_tick = tick;
        let req = match node.generate_audit_request().unwrap() {
            TardisAction::SendAuditRequest { request, .. } => request,
            _ => panic!("expected an audit request"),
        };

        // What the auditee could compute from what it can see.
        let public_guess =
            blake3::hash(&[&tick.to_le_bytes()[..], &my_pk[..]].concat()).as_bytes()[0];
        assert_ne!(req.prefix[0], public_guess,
            "G5: the prefix is still the OLD public derivation — the upstream \
             can pre-compute the sampled slice and tamper everywhere else");

        // Two nodes, identical public inputs, different private seeds → the
        // prefix must differ. If it did not, the seed is not load-bearing.
        let mut a = TardisNode::new(my_pk);
        a.set_upstream(pk(0xBB)); a.current_tick = tick; a.set_audit_seed([0x11; 32]);
        let mut b = TardisNode::new(my_pk);
        b.set_upstream(pk(0xBB)); b.current_tick = tick; b.set_audit_seed([0x22; 32]);
        let pa = match a.generate_audit_request().unwrap() {
            TardisAction::SendAuditRequest { request, .. } => request.prefix,
            _ => unreachable!(),
        };
        let pb = match b.generate_audit_request().unwrap() {
            TardisAction::SendAuditRequest { request, .. } => request.prefix,
            _ => unreachable!(),
        };
        assert_ne!(pa, pb,
            "G5: identical public inputs must still give different prefixes — \
             the private seed decides the sample");
    }

    /// G6 — a response from anyone but our upstream must be dropped WITHOUT
    /// consuming the pending challenge.
    ///
    /// `.take()` used to run before the prefix comparison, so ANY response —
    /// even a junk prefix from an unrelated peer — consumed the challenge and
    /// the upstream's real answer was then dropped as unsolicited. One peer
    /// sending one packet per tick disabled another node's upstream auditing
    /// indefinitely, traced only by a `debug!` line.
    #[test]
    fn g6_stranger_cannot_cancel_our_pending_audit() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.current_tick = 1740000050;

        let mut smt = SparseMerkleTree::new();
        smt.put(&make_entry(1, 1, 5));
        smt.put(&make_entry(2, 2, 6));
        node.pending_audit_prefix = Some((vec![0xA3], 10));

        // A stranger (not our upstream) answers with a junk prefix.
        let (sh, sib) = smt.subtree_proof(&[0x77], 8);
        let stranger = SubtreeAuditResponse {
            prefix: vec![0x77], prefix_bits: 8, subtree_hash: sh,
            root_hash: smt.root_hash(), response_tick: 10,
            responder_pk: pk(0xEE), siblings: sib, signature: vec![],
        };
        let action = node.verify_audit_response(&stranger, &smt, &NoopSigner).unwrap();
        assert!(matches!(action, TardisAction::None));
        assert_eq!(node.audit_responses_unauthorized(), 1,
            "the refusal must be COUNTED — a denial-of-audit is otherwise \
             indistinguishable from a quiet network");
        assert_eq!(node.pending_audit_prefix, Some((vec![0xA3], 10)),
            "G6: the pending challenge MUST survive a stranger's response");

        // Our upstream's real answer still lands.
        let (sh2, sib2) = smt.subtree_proof(&[0xA3], 8);
        let real = SubtreeAuditResponse {
            prefix: vec![0xA3], prefix_bits: 8, subtree_hash: sh2,
            root_hash: smt.root_hash(), response_tick: 11,
            responder_pk: pk(0xBB), siblings: sib2, signature: vec![],
        };
        node.verify_audit_response(&real, &smt, &NoopSigner).unwrap();
        assert_eq!(node.audit_pass_count(), 1,
            "G6: the upstream's genuine answer must still be evaluated");
        assert_eq!(node.pending_audit_prefix, None, "matched — challenge consumed");
    }

    /// A wrong-prefix response from the REAL upstream must also not consume the
    /// challenge — a late or crossed answer is honest noise, and eating the
    /// challenge on it re-opens the same denial window.
    #[test]
    fn g6_upstream_wrong_prefix_does_not_consume_the_challenge() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.current_tick = 1740000050;
        let mut smt = SparseMerkleTree::new();
        smt.put(&make_entry(1, 1, 5));
        node.pending_audit_prefix = Some((vec![0xA3], 10));

        let (sh, sib) = smt.subtree_proof(&[0x01], 8);
        let stale = SubtreeAuditResponse {
            prefix: vec![0x01], prefix_bits: 8, subtree_hash: sh,
            root_hash: smt.root_hash(), response_tick: 9,
            responder_pk: pk(0xBB), siblings: sib, signature: vec![],
        };
        node.verify_audit_response(&stale, &smt, &NoopSigner).unwrap();
        assert_eq!(node.audit_responses_unmatched(), 1, "counted");
        assert_eq!(node.pending_audit_prefix, Some((vec![0xA3], 10)),
            "the challenge survives a stale answer from the right peer");
    }

    #[test]
    fn audit_pass_same_root() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.current_tick = 1740000050;

        let mut smt = SparseMerkleTree::new();
        smt.put(&make_entry(1, 1, 5));
        smt.put(&make_entry(2, 2, 6));

        // Upstream answers OUR challenge with a REAL proof from its tree
        // (same tree here — roots match).
        node.pending_audit_prefix = Some((vec![0xA3], 10));
        let (subtree_hash, siblings) = smt.subtree_proof(&[0xA3], 8);
        let response = SubtreeAuditResponse {
            prefix: vec![0xA3],
            prefix_bits: 8,
            subtree_hash,
            root_hash: smt.root_hash(),
            response_tick: 10,
            responder_pk: pk(0xBB),
            siblings,
            signature: vec![],
        };

        let action = node.verify_audit_response(&response, &smt, &NoopSigner).unwrap();
        assert!(matches!(action, TardisAction::None));
        assert_eq!(node.audit_pass_count(), 1);
    }

    #[test]
    fn audit_divergent_root_is_tolerated() {
        // KI#48: a root differing from OURS is honest divergence (AE's job),
        // not evidence of a lying upstream. Pre-fix this detached the parent,
        // which is exactly what re-orphaned every freshly attached node.
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        let smt = SparseMerkleTree::new();

        // Internally-consistent proof (0-level fold: subtree == root) for a
        // root that differs from ours.
        node.pending_audit_prefix = Some((vec![0xA3], 10));
        let response = SubtreeAuditResponse {
            prefix: vec![0xA3],
            prefix_bits: 8,
            subtree_hash: [0xFF; 32],
            root_hash: [0xFF; 32], // doesn't match empty tree
            response_tick: 10,
            responder_pk: pk(0xBB),
            siblings: vec![],
            signature: vec![],
        };

        let action = node.verify_audit_response(&response, &smt, &NoopSigner).unwrap();
        assert!(matches!(action, TardisAction::None));
        // Still attached — divergence must never dismantle topology.
        assert_eq!(node.upstream(), Some(&pk(0xBB)));
        assert_eq!(node.upstream_status(), NodeStatus::Connected);
        // No pass credit for a divergent answer.
        assert_eq!(node.audit_pass_count(), 0);
    }

    #[test]
    fn unauthenticated_advertisement_is_not_audit_evidence() {
        // A TickHash `node_pk` is a CLAIM. Before it was signed, any peer could
        // emit one naming somebody else's upstream with a bogus root; the §5.5
        // self-contradiction rule would then detach a healthy parent and cascade
        // an alert that detached its whole subtree — targeted topology grief
        // from one forged packet.
        //
        // The node layer now verifies the signature against the advertiser's
        // NBC-anchored key and records ONLY on success. This pins the contract
        // that the audit consumes: an advertisement that was never recorded
        // cannot convict anyone, so an unrecorded (forged/unverifiable) TickHash
        // leaves the upstream attached.
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        let smt = SparseMerkleTree::new();

        // NOTHING recorded for tick 10 — the forged advertisement was rejected
        // at the node layer and never reached branch_root_hashes.
        node.pending_audit_prefix = Some((vec![0xA3], 10));
        let response = SubtreeAuditResponse {
            prefix: vec![0xA3],
            prefix_bits: 8,
            subtree_hash: [0xFF; 32],
            root_hash: [0xFF; 32],
            response_tick: 10,
            responder_pk: pk(0xBB),
            siblings: vec![],
            signature: vec![],
        };

        let action = node.verify_audit_response(&response, &smt, &NoopSigner).unwrap();
        assert!(
            !matches!(action, TardisAction::CascadeAlert { .. }),
            "an unauthenticated advertisement must never produce an accusation"
        );
        assert_eq!(node.upstream(), Some(&pk(0xBB)), "must stay attached");
    }

    #[test]
    fn audit_fail_self_contradiction() {
        // §5.5: the flaggable lie is the upstream contradicting its OWN
        // TickHash advertisement for the same tick.
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC)); // need downstream for cascade
        node.current_tick = 1740000050;

        let smt = SparseMerkleTree::new();

        // Upstream advertised root [0xEE; 32] at tick 10 via TickHash gossip…
        node.record_branch_root_hash(10, pk(0xBB), [0xEE; 32], vec![]);

        // …but answers the audit for tick 10 with a (self-consistent) proof
        // for a DIFFERENT root.
        node.pending_audit_prefix = Some((vec![0xA3], 10));
        let response = SubtreeAuditResponse {
            prefix: vec![0xA3],
            prefix_bits: 8,
            subtree_hash: [0xFF; 32],
            root_hash: [0xFF; 32],
            response_tick: 10,
            responder_pk: pk(0xBB),
            siblings: vec![],
            signature: vec![],
        };

        let action = node.verify_audit_response(&response, &smt, &NoopSigner).unwrap();
        assert!(matches!(action, TardisAction::CascadeAlert { .. }));
        assert_eq!(node.upstream_status(), NodeStatus::Disconnected);
        assert_eq!(node.upstream(), None);
        // KI#71: the conviction is isolated on /status (RULE 3 §2).
        assert_eq!(node.audit_counters()[3], ("selfcontra_flags", 1));
    }

    #[test]
    fn audit_stale_advertisement_matching_our_root_is_exonerated() {
        // THE MISSING THIRD CASE. The suite pinned two corners —
        // audit_divergent_root_is_tolerated (no advertisement, divergent) and
        // audit_fail_self_contradiction (advertised != answered != ours) — but
        // NOTHING covered the convergent case, where the answer equals OUR
        // root. That gap is why the bug survived: 24/24 live flags had
        // answered == our_root and every one detached a healthy parent.
        //
        // Mechanism: `advertised` is captured from TickHash gossip earlier in
        // the tick; `answered` is read live when the audit arrives. A parent
        // that writes in between contradicts its own gossip WITHOUT lying.
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        // Our SMT is the empty tree, so our root is the empty-tree root.
        let smt = SparseMerkleTree::new();
        let our_root = smt.root_hash();

        // Upstream gossiped a STALE root for tick 10 …
        node.record_branch_root_hash(10, pk(0xBB), [0xEE; 32], vec![]);

        // … then answered the audit with its CURRENT root, which equals ours.
        // Internally consistent (0-level fold: subtree == root).
        node.pending_audit_prefix = Some((vec![0xA3], 10));
        let response = SubtreeAuditResponse {
            prefix: vec![0xA3],
            prefix_bits: 8,
            subtree_hash: our_root,
            root_hash: our_root,
            response_tick: 10,
            responder_pk: pk(0xBB),
            siblings: vec![],
            signature: vec![],
        };

        let action = node.verify_audit_response(&response, &smt, &NoopSigner).unwrap();

        // MUST NOT detach: the parent is serving exactly what we hold.
        assert!(
            !matches!(action, TardisAction::CascadeAlert { .. }),
            "a parent whose root equals ours must not be accused"
        );
        assert_eq!(node.upstream(), Some(&pk(0xBB)), "must stay attached");
        assert_eq!(node.upstream_status(), NodeStatus::Connected);
        assert_eq!(node.audit_exonerated(), 1, "the guard must be observable");
    }

    #[test]
    fn audit_fail_proof_does_not_reconstruct() {
        // KI#48 follow-up: a response whose subtree proof does not fold back
        // to its own claimed root is internally inconsistent — a provable
        // lie, flagged regardless of advertisements or our own root.
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        let mut smt = SparseMerkleTree::new();
        smt.put(&make_entry(1, 1, 5));

        node.pending_audit_prefix = Some((vec![0xA3], 10));
        let (subtree_hash, mut siblings) = smt.subtree_proof(&[0xA3], 8);
        if siblings.is_empty() {
            siblings.push([0xAB; 32]);
        } else {
            siblings[0] = [0xAB; 32]; // tamper one hash on the path
        }
        let response = SubtreeAuditResponse {
            prefix: vec![0xA3],
            prefix_bits: 8,
            subtree_hash,
            root_hash: smt.root_hash(),
            response_tick: 10,
            responder_pk: pk(0xBB),
            siblings,
            signature: vec![],
        };

        let action = node.verify_audit_response(&response, &smt, &NoopSigner).unwrap();
        assert!(matches!(action, TardisAction::CascadeAlert { .. }));
        assert_eq!(node.upstream(), None);
    }

    #[test]
    fn audit_unsolicited_response_dropped() {
        // A response with no pending challenge (or the wrong prefix) is
        // network noise: dropped, never flagged, upstream retained.
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.current_tick = 1740000050;

        let smt = SparseMerkleTree::new();
        let response = SubtreeAuditResponse {
            prefix: vec![0xA3],
            prefix_bits: 8,
            subtree_hash: [0xFF; 32],
            root_hash: [0xFF; 32],
            response_tick: 10,
            responder_pk: pk(0xBB),
            siblings: vec![],
            signature: vec![],
        };

        // No pending challenge at all…
        let action = node.verify_audit_response(&response, &smt, &NoopSigner).unwrap();
        assert!(matches!(action, TardisAction::None));
        assert_eq!(node.upstream(), Some(&pk(0xBB)));

        // …and a pending challenge for a DIFFERENT prefix.
        node.pending_audit_prefix = Some((vec![0x11], 10));
        let action = node.verify_audit_response(&response, &smt, &NoopSigner).unwrap();
        assert!(matches!(action, TardisAction::None));
        assert_eq!(node.upstream(), Some(&pk(0xBB)));
    }

    #[test]
    fn audit_full_cycle_request_to_verified_response() {
        // End-to-end over the real machinery: child challenges, parent
        // answers from its OWN (different) tree via handle_audit_request,
        // child verifies the proof and tolerates the divergence.
        let mut child = TardisNode::new(pk(0xAA));
        child.set_upstream(pk(0xBB));
        child.current_tick = 1740000050;
        child.ticks_since_audit = 5;

        let mut parent = TardisNode::new(pk(0xBB));
        parent.current_tick = 1740000050;

        let mut parent_smt = SparseMerkleTree::new();
        parent_smt.put(&make_entry(1, 1, 5));
        parent_smt.put(&make_entry(2, 2, 6));
        parent_smt.put(&make_entry(3, 3, 7));
        let child_smt = SparseMerkleTree::new(); // child diverges (empty)

        let Some(TardisAction::SendAuditRequest { request, target }) =
            child.generate_audit_request()
        else {
            panic!("expected SendAuditRequest");
        };
        assert_eq!(target, pk(0xBB));

        let TardisAction::SendAuditResponse { response, .. } =
            parent.handle_audit_request(&request, &parent_smt, &NoopSigner)
        else {
            panic!("expected SendAuditResponse");
        };

        // The parent's proof verifies against its own root…
        assert!(SparseMerkleTree::verify_subtree_proof(
            &response.root_hash,
            &response.prefix,
            &response.subtree_hash,
            &response.siblings,
        ));
        // …and the divergent child accepts without detaching.
        let action = child.verify_audit_response(&response, &child_smt, &NoopSigner).unwrap();
        assert!(matches!(action, TardisAction::None));
        assert_eq!(child.upstream(), Some(&pk(0xBB)));
    }

    // ── KI#71: answer at the advertisement instant ──

    /// The honest busy writer (KI#71, YPX-003 §1.3.5). The parent advertises
    /// its root for tick T, the child challenges, the parent's SMT moves
    /// (registrations / AE) BEFORE it answers, and the parent's tick-loop
    /// anti-entropy probe advertises again under the same label T. Before
    /// option A the answer and the second advertisement were fresh live
    /// samples, so the parent signed two different roots for T and the child
    /// convicted it of SELF-CONTRADICTION (detach + cascade).
    ///
    /// MUTATION: drop the same-tick cache check in `advertise_root` (sample
    /// fresh on every call) → the second advertisement / answer for T carries
    /// the mutated root, the child holds the first → flagged → RED.
    #[test]
    fn honest_writer_mutating_between_advert_and_challenge_never_flagged() {
        const T: u64 = 1_740_000_050;
        let mut child = TardisNode::new(pk(0xAA));
        child.set_upstream(pk(0xBB));
        child.add_downstream(pk(0xCC)); // a flag would cascade
        child.current_tick = T;
        child.ticks_since_audit = 5;
        let child_smt = SparseMerkleTree::new(); // divergent: no exoneration path

        let mut parent = TardisNode::new(pk(0xBB));
        parent.add_downstream(pk(0xAA));
        parent.current_tick = T;
        let mut parent_smt = SparseMerkleTree::new();
        parent_smt.put(&make_entry(1, 1, 5));

        // Tick T: the parent advertises (process_tick step 9); the child records it.
        let (adv_t, answered) = parent.advertise_root(&parent_smt, &NoopSigner);
        assert!(answered.is_empty());
        child.record_branch_root_hash(adv_t.tick, pk(0xBB), adv_t.root_hash, adv_t.signature.clone());

        // The child challenges; the parent queues it.
        let Some(TardisAction::SendAuditRequest { request, .. }) = child.generate_audit_request() else {
            panic!("expected SendAuditRequest");
        };
        assert!(parent.queue_audit_request(&request));

        // The parent is a busy writer: its SMT moves inside tick T.
        parent_smt.put(&make_entry(2, 2, 6));
        parent_smt.put(&make_entry(3, 3, 7));

        // Still tick T: the tick loop's AE probe advertises again — it MUST be
        // the cached (T, root) and must answer nothing yet.
        let (adv_t_again, answered) = parent.advertise_root(&parent_smt, &NoopSigner);
        assert_eq!(adv_t_again, adv_t, "one advertisement per tick label (RULE 1)");
        child.record_branch_root_hash(adv_t_again.tick, pk(0xBB), adv_t_again.root_hash, adv_t_again.signature.clone());
        assert!(answered.is_empty(), "a request queued after the sample waits for the next one");

        // Tick T+1: fresh sample; the queued request is answered from it.
        parent.current_tick = T + TICK_INTERVAL_SECS;
        child.current_tick = T + TICK_INTERVAL_SECS;
        let (adv_t1, answered) = parent.advertise_root(&parent_smt, &NoopSigner);
        child.record_branch_root_hash(adv_t1.tick, pk(0xBB), adv_t1.root_hash, adv_t1.signature.clone());
        assert_eq!(answered.len(), 1);
        let TardisAction::SendAuditResponse { response, target } = &answered[0] else {
            panic!("expected SendAuditResponse");
        };
        assert_eq!(*target, pk(0xAA));
        assert_eq!((response.response_tick, response.root_hash), (adv_t1.tick, adv_t1.root_hash),
            "the answer IS the advertisement: same tick, same root");

        let action = child.verify_audit_response(response, &child_smt, &NoopSigner).unwrap();
        assert!(matches!(action, TardisAction::None), "honest writer must not be flagged");
        assert_eq!(child.upstream(), Some(&pk(0xBB)));
        assert_eq!(child.audit_counters()[3], ("selfcontra_flags", 0));
        assert_eq!(child.orphan_causes().via_flag_questionable, 0);
    }

    /// KI#71 (Fable): the answer now arrives up to ~1 tick after the challenge.
    /// A re-issue on the next tick must NOT overwrite the pending prefix, or the
    /// delayed honest answer is `unmatched` and the audit evaluates nothing.
    ///
    /// MUTATION: delete the `AUDIT_CHALLENGE_PENDING_TICKS` guard in
    /// `generate_audit_request` → tick T+1 re-issues a NEW prefix, the T answer
    /// is unmatched → RED.
    #[test]
    fn delayed_answer_still_matches_pending_challenge() {
        const T: u64 = 1_740_000_050;
        let mut child = TardisNode::new(pk(0xAA));
        child.set_upstream(pk(0xBB));
        child.set_audit_seed([7; 32]);
        child.current_tick = T;
        child.ticks_since_audit = 5;
        let Some(TardisAction::SendAuditRequest { request, .. }) = child.generate_audit_request() else {
            panic!("expected SendAuditRequest");
        };

        // One tick later, the cadence still says "audit" (no answer yet).
        child.current_tick = T + TICK_INTERVAL_SECS;
        child.ticks_since_audit += 1;
        assert!(child.should_audit());
        assert!(child.generate_audit_request().is_none(),
            "a challenge younger than AUDIT_CHALLENGE_PENDING_TICKS is still owed an answer");

        // The delayed answer (built at the parent's next advertisement) matches.
        let mut parent_smt = SparseMerkleTree::new();
        parent_smt.put(&make_entry(1, 1, 5));
        let mut parent = TardisNode::new(pk(0xBB));
        parent.add_downstream(pk(0xAA));
        parent.current_tick = T + TICK_INTERVAL_SECS;
        assert!(parent.queue_audit_request(&request));
        let (_, answered) = parent.advertise_root(&parent_smt, &NoopSigner);
        let TardisAction::SendAuditResponse { response, .. } = &answered[0] else { panic!() };
        child.verify_audit_response(response, &SparseMerkleTree::new(), &NoopSigner).unwrap();
        assert_eq!(child.audit_responses_unmatched(), 0, "the delayed answer must match");
        assert_eq!(child.pending_audit_prefix, None, "matched — challenge consumed");

        // And once the window has passed, a fresh challenge IS issued.
        child.pending_audit_prefix = Some((vec![0x01], T));
        child.current_tick = T + axiom_core_logic::types::ticks_to_secs(AUDIT_CHALLENGE_PENDING_TICKS);
        assert!(child.generate_audit_request().is_some(), "an expired challenge is re-issued");
    }

    /// KI#71 (Fable): an answer for a tick OLDER than the challenge is counted
    /// and STILL evaluated — a stale label must not be an escape hatch for an
    /// equivocator.
    ///
    /// MUTATION: return early (drop) when `response_tick < challenge_tick` →
    /// no CascadeAlert → RED.
    #[test]
    fn stale_response_tick_is_counted_and_still_evaluated() {
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;
        node.record_branch_root_hash(10, pk(0xBB), [0xEE; 32], vec![]);
        node.pending_audit_prefix = Some((vec![0xA3], 15)); // challenged at 15
        let response = SubtreeAuditResponse {
            prefix: vec![0xA3], prefix_bits: 8,
            subtree_hash: [0xFF; 32], root_hash: [0xFF; 32],
            response_tick: 10, // answers with an OLDER label
            responder_pk: pk(0xBB), siblings: vec![], signature: vec![],
        };
        let action = node.verify_audit_response(&response, &SparseMerkleTree::new(), &NoopSigner).unwrap();
        assert!(matches!(action, TardisAction::CascadeAlert { .. }),
            "the contradiction at the stale label is still convicted");
        assert_eq!(node.audit_counters()[2], ("response_stale", 1));
    }

    /// KI#71 — the audit inbox is bounded WITHOUT a new denial-of-audit: a
    /// flood of junk requests is shed (and counted), but a downstream child's
    /// 8-bit challenge is always kept and answered.
    #[test]
    fn audit_inbox_never_sheds_a_downstream_challenge() {
        let mut parent = TardisNode::new(pk(0xBB));
        parent.add_downstream(pk(0xAA));
        parent.current_tick = 1740000050;
        for i in 0..(AUDIT_INBOX_OTHER_CAP as u32 + 10) {
            let junk = SubtreeAuditRequest {
                prefix: i.to_le_bytes().to_vec(), prefix_bits: 32,
                request_tick: 0, requester_pk: pk(0xEE),
            };
            parent.queue_audit_request(&junk);
        }
        assert_eq!(parent.audit_counters()[4], ("requests_shed", 10));
        // Even a spoofed flood under the CHILD's own pk cannot crowd it out:
        // the 8-bit shape is deduped, so all 256 prefixes fit.
        for b in 0..=255u8 {
            let req = SubtreeAuditRequest { prefix: vec![b], prefix_bits: 8, request_tick: 0, requester_pk: pk(0xAA) };
            assert!(parent.queue_audit_request(&req));
        }
        let (_, answered) = parent.advertise_root(&SparseMerkleTree::new(), &NoopSigner);
        assert_eq!(answered.len(), AUDIT_INBOX_OTHER_CAP + 256);
    }

    // ── Questionable Cascade ──

    #[test]
    fn proven_alert_still_detaches() {
        // The guard must not degrade into "never detach". An alert carrying
        // evidence — which the node layer only leaves present after verifying
        // it against the SUSPECT's NBC-anchored key — must still dismantle the
        // link, because at that point the suspect's own signatures prove the
        // claim.
        let mut node = TardisNode::new(pk(0xAA));
        node.set_upstream(pk(0xBB));
        node.add_downstream(pk(0xCC));
        node.current_tick = 1740000050;

        let alert = QuestionableAlert {
            suspect_pk: pk(0xBB),
            reporter_pk: pk(0xEE),
            tick: 1740000048,
            evidence_hash: [11; 32],
            signature: vec![],
            evidence: Some(QuestionableEvidence {
                audit_response: SubtreeAuditResponse {
                    prefix: vec![0xA3],
                    prefix_bits: 8,
                    subtree_hash: [0xFF; 32],
                    root_hash: [0xFF; 32],
                    response_tick: 10,
                    responder_pk: pk(0xBB),
                    siblings: vec![],
                    signature: vec![],
                },
                advertised_root: Some([0xEE; 32]),
                advertised_sig: vec![1, 2, 3],
            }),
        };

        let action = node.handle_questionable_alert(&alert, &NoopSigner);
        assert!(matches!(action, TardisAction::CascadeAlert { .. }));
        assert_eq!(node.upstream(), None, "a PROVEN accusation must detach");
        assert_eq!(node.upstream_status(), NodeStatus::Disconnected);
        assert_eq!(node.alerts_unproven_ignored(), 0, "this one was proven");
    }

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
                evidence: None,
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

        // CONTRACT CHANGE (2026-08-07): an alert naming our upstream that
        // carries NO VERIFIED PROOF must still CASCADE (the warning is worth
        // propagating to nodes that can audit the suspect themselves) but MUST
        // NOT dismantle topology. Previously this detached on the reporter's
        // word alone, so one accusation — itself derivable from an unsigned
        // TickHash — tore down the suspect's whole subtree.
        assert_eq!(node.upstream_status(), NodeStatus::Connected,
            "an unproven accusation must not disconnect us");
        assert_eq!(node.upstream(), Some(&pk(0xBB)), "must stay attached");
        assert_eq!(node.alerts_unproven_ignored(), 1, "and it must be counted");
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
                evidence: None,
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
                evidence: None,
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
                evidence: None,
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
                evidence: None,
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
                evidence: None,
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
                evidence: None,
            };
        let minted = match node.handle_questionable_alert(&incoming, &NoopSigner) {
            TardisAction::CascadeAlert { alert, .. } => alert,
            other => panic!("Expected CascadeAlert, got {:?}", other),
        };
        // CONTRACT CHANGE (2026-08-07): we no longer RE-MINT an accusation we
        // have not verified. With no proof attached we forward the ORIGINAL
        // alert unchanged, so the reporter stays the node that actually made
        // the claim (0xEE) rather than us laundering it under our own identity.
        // Re-minting an unverified claim is how one accusation acquired N
        // independent-looking reporters as it cascaded.
        assert_eq!(minted.reporter_pk, pk(0xEE), "unproven claims are forwarded, not re-minted");

        // KI#37 (unchanged, and the point of this test): the alert looping back
        // through a tree cycle must still be dropped by the seen-dedup, so one
        // minted alert produces at most one delivery per node mesh-wide.
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
                evidence: None,
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
                evidence: None,
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
                evidence: None,
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

    // ── Orphan-cause counters ──

    #[test]
    fn every_clear_path_is_counted() {
        // The funnel's value is that no path can orphan a node uncounted.
        let mut n = TardisNode::new(pk(0xAA));
        n.set_upstream(pk(0x01));
        n.detach_upstream();
        assert_eq!(n.orphan_causes().via_detach_upstream, 1);

        n.set_upstream(pk(0x02));
        n.remove_peer(&pk(0x02));
        assert_eq!(n.orphan_causes().via_remove_peer, 1);

        // total_cleared is the sum of the via_* buckets, so a new path that
        // forgets its bucket shows up as a gap between this and reality.
        assert_eq!(n.orphan_causes().total_cleared(), 2);
    }

    #[test]
    fn clearing_when_already_orphaned_counts_nothing() {
        // No upstream to lose => not an orphan event. Otherwise repeated
        // remove_peer calls would inflate the counters and make the mesh look
        // far churnier than it is.
        let mut n = TardisNode::new(pk(0xAA));
        n.detach_upstream();
        n.remove_peer(&pk(0x01));
        assert_eq!(n.orphan_causes().total_cleared(), 0);
    }

    #[test]
    fn silent_parent_detach_is_counted_by_reason() {
        // The reason must be counted where it is EMITTED: the node handler
        // calls remove_peer(), so counting at the clear site would file every
        // detach under via_remove_peer and lose the protocol reason entirely.
        let mut n = TardisNode::new(pk(0xAA));
        n.set_upstream(pk(0x01));
        let mut fired = 0;
        for _ in 0..(SILENT_PARENT_THRESHOLD as usize + 2) {
            if n.check_silent_parent().is_some() { fired += 1; }
        }
        assert!(fired >= 1, "silent-parent detach never fired");
        assert_eq!(n.orphan_causes().detach_silent_parent, fired);
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

    // ── Full Tick Validation (time + writer) — REMOVED 2026-08-01 ──
    //
    // `validate_parent_tick_full` and its `TickValidation` enum were deleted.
    // They were TEST-ONLY (no production caller ever existed) and encoded the
    // RETIRED pre-2026-05-28 tick bounds: a wall-clock past-side staleness check
    // and NO +5 s forward tolerance. YPX-003 §"Why there is no wall-clock
    // 'stale' check on the past side" records that design as WRONG — it caused
    // spurious rejections when `now_secs` lagged `tick.number`.
    //
    // Sitting beside the real implementation it read like a reference and
    // actively misled a reader into reporting the live code as broken. The live
    // bounds are in `process_tick`: reject when
    // `tick.number > now_secs + TICK_INTERVAL_SECS` (forward, wall clock, +side
    // only) and when `tick.number < self.current_tick` (backward, tick-time).
    //
    // The writer half of those tests is not lost: `is_writer` is covered
    // directly by `writer_qualification` above.

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

    // (§32.3 taint-propagation / resolve_merge tests deleted with the code —
    // ForkSettlement §9r-E4.)

    // ── YPX-003 §2.1 P slot (KI#48, RULED 2026-09-25) ───────────────────

    /// A PARKED node has a tick source but is NOT seated: `needs_parent()`
    /// stays TRUE (it keeps seeking a D slot — the one rule the 08-01 grant
    /// lacked), `has_upstream()` is false, `is_parked()` is the ONE predicate.
    ///
    /// MUTATION: make `needs_parent()` return false while `Pending` (e.g.
    /// `!self.has_tick_source()`) → THIS test goes red, and so does the
    /// cold-start sim gate (`nabla-sim --gate cold-start`): every node parks
    /// and stops seeking, no D attaches, no writers.
    #[test]
    fn p_slot_parked_node_needs_parent_and_is_not_seated() {
        let mut node = TardisNode::new(pk(0x10));
        assert!(!node.is_parked() && !node.has_tick_source());
        node.set_upstream_pending(pk(0xA0));
        assert_eq!(node.upstream(), Some(&pk(0xA0)), "the host is the tick source");
        assert_eq!(node.upstream_status(), NodeStatus::Pending);
        assert!(node.is_parked(), "ONE predicate: upstream_status == Pending");
        assert!(node.has_tick_source(), "parked ⇒ ticks are expected from the host");
        assert!(!node.has_upstream(), "parked is NOT seated");
        assert!(node.needs_parent(),
            "§2.1 step 2: a P node keeps seeking a D slot — needs_parent stays TRUE while parked");
    }

    /// Evidence (c) as a unit stand-in: a parked node RECEIVES AND VALIDATES
    /// its host's ticks exactly like a D child (`process_tick` checks only
    /// `up`), so its tick advances while parked; a tick from anyone else is
    /// ignored exactly as for a D child.
    #[test]
    fn p_slot_parked_node_receives_and_validates_host_ticks() {
        let mut node = TardisNode::new(pk(0x10));
        node.set_upstream_pending(pk(0xA0));
        let smt = SparseMerkleTree::new();
        let t0 = 1_740_000_000u64;
        for k in 0..3u64 {
            let t = t0 + k * TICK_INTERVAL_SECS;
            let tick = make_tick(t, pk(0xA0), t * 1000);
            node.process_tick(&tick, &smt, t * 1000, &NoopSigner)
                .unwrap_or_else(|e| panic!("host tick {} must be accepted while parked: {e:?}", k));
            assert_eq!(node.current_tick(), t, "tick advanced while parked");
            assert!(node.is_parked(), "receiving ticks does not seat the node");
        }
        // Not our host → ignored (TardisAction::None), tick unchanged.
        let stranger = make_tick(t0 + 10 * TICK_INTERVAL_SECS, pk(0xB0), (t0 + 10 * TICK_INTERVAL_SECS) * 1000);
        let acts = node.process_tick(&stranger, &smt, (t0 + 10 * TICK_INTERVAL_SECS) * 1000, &NoopSigner).unwrap();
        assert!(matches!(acts.as_slice(), [TardisAction::None]), "a non-host tick is ignored: {acts:?}");
        assert_eq!(node.current_tick(), t0 + 2 * TICK_INTERVAL_SECS);
    }

    /// (ii) P is NEVER a writer input, on either side of the link:
    ///   host — a P child is not in `downstream_count()` (d1/d2 only), so a
    ///          host with one D child and one P child is dc=1, not a writer;
    ///   child — a parked node fails `is_self_writer` condition 2 even with
    ///           two children and a fresh approval.
    /// MUTATION: count `pending` in `downstream_count()` → THIS test goes red.
    #[test]
    fn p_slot_never_counts_toward_writer() {
        // Host side.
        let mut host = TardisNode::new(pk(0xA0));
        host.set_upstream(pk(0x01));
        assert!(host.add_downstream(pk(0xD1)));
        host.set_pending(pk(0xF0));
        assert_eq!(host.downstream_count(), 1, "P is not a D slot");
        assert_eq!(host.children().len(), 2, "…but it IS a tick-forward target");
        let t = 1_740_000_000u64;
        host.current_tick = t;
        host.last_approved_upstream_tick = t;
        assert!(!host.is_self_writer(), "dc=1 + P must not read as a writer");
        assert!(host.add_downstream(pk(0xD2)));
        assert_eq!(host.downstream_count(), 2);
        assert_eq!(host.children().len(), 3);
        assert!(host.is_self_writer(), "two REAL D children make the writer");

        // Child side: parked with two children + fresh approval → not a writer.
        let mut parked = TardisNode::new(pk(0x10));
        parked.set_upstream_pending(pk(0xA0));
        assert!(parked.add_downstream(pk(0x21)));
        assert!(parked.add_downstream(pk(0x22)));
        parked.current_tick = t;
        parked.last_approved_upstream_tick = t;
        assert_eq!(parked.downstream_count(), 2);
        assert!(!parked.is_self_writer(), "a parked node is never a writer (condition 2)");
        // Seating it (the host promoted us, or a D slot elsewhere) makes it one.
        parked.set_upstream(pk(0xA0));
        assert!(!parked.is_parked() && parked.has_upstream());
        assert!(parked.is_self_writer());
    }

    /// (iii) leaving P: `detach_upstream` from a parked node returns the host
    /// (the caller sends it `TardisDetach`, whose `remove_peer` clears the
    /// host's `pending`), and seating elsewhere flips the status in place.
    #[test]
    fn p_slot_leaving_the_host_clears_both_sides() {
        let mut child = TardisNode::new(pk(0x10));
        child.set_upstream_pending(pk(0xA0));
        assert_eq!(child.detach_upstream(), Some(pk(0xA0)));
        assert!(!child.is_parked() && child.needs_parent() && !child.has_tick_source());
        assert_eq!(child.upstream_status(), NodeStatus::Disconnected);

        // Host side: the child's TardisDetach → remove_peer clears `pending`.
        let mut host = TardisNode::new(pk(0xA0));
        host.set_pending(pk(0x10));
        assert_eq!(host.pending(), Some(&pk(0x10)));
        host.remove_peer(&pk(0x10));
        assert!(host.pending().is_none(), "P slot free again");
        // …and the existing promotion still works for a child that stayed.
        host.set_pending(pk(0x11));
        assert!(host.promote_pending());
        assert_eq!(host.d1(), Some(&pk(0x11)));
    }

    /// A parked node relays its host's ticks to its children, so a parked
    /// subtree is not a zombie: the parentless timeout must not dismantle it.
    #[test]
    fn p_slot_parked_subtree_is_not_a_zombie() {
        let mut node = TardisNode::new(pk(0x10));
        node.set_upstream_pending(pk(0xA0));
        assert!(node.add_downstream(pk(0x21)));
        for _ in 0..(PARENTLESS_TIMEOUT_TICKS + 2) {
            assert!(matches!(node.check_parentless_timeout(), ParentlessAction::Ok));
        }
        // A true orphan with children still counts down.
        node.detach_upstream();
        assert!(matches!(node.check_parentless_timeout(), ParentlessAction::Searching(1)));
    }
}

/// Test-only fixtures. ForkSettlement §9r-E4: production has NO writer of
/// `Frozen` / `Tainted`; tests that model a RESTORED LEGACY leaf (snapshot from
/// a pre-E4 build) build one here, with the same `SameHeadStatusChange` put the
/// deleted writers used, so the fixture is the on-disk shape a node can load.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::smt::SparseMerkleTree;
    use crate::types::{WalletId, WalletStatus};

    pub(crate) fn legacy_status_leaf(smt: &mut SparseMerkleTree, wallet_id: &WalletId, status: WalletStatus) {
        let mut e = smt.get(wallet_id).expect("fixture: leaf exists").clone();
        e.status = status;
        smt.put_with_proof(&e, crate::smt::PutProof::SameHeadStatusChange);
    }
}
