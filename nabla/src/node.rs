// AXIOM Nabla — Node
// Reference: AXIOM_GUIDE_Nabla.md Sections 2-9
//
// NablaNode ties together all Phase 1 components:
//   SMT, WAL, Snapshots, Registration, Query, Gossip, Ban detection.
//
// Gossip forwarding is the caller's responsibility — register() returns
// the gossip message alongside the ack so the network layer can forward it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::ban::BanTable;
use crate::cc::{CcChain, CompanionCertificate, NBC, RunnerPool, deed_split};
use crate::constants::SNAPSHOT_INTERVAL_TICKS;
use crate::crypto::Signer;
use crate::gossip::{GossipAction, GossipEngine, GossipLatencyStats, GossipLatencySnapshot};
use crate::mesh::{GossipMesh, MeshAction};
use crate::monitor::{self, NodeStatusSnapshot};
use crate::oracle::DailyPoolState;
use crate::query;
use crate::registration;
use crate::smt::SparseMerkleTree;
use crate::snapshot::{NablaSnapshot, SnapshotManager};
use crate::tardis::{ParentlessAction, TardisAction, TardisNode};
use crate::types::*;
use crate::wal::{WalOp, WriteAheadLog};

/// Result of a successful registration.
pub struct RegisterResult {
    pub ack: RegistrationAck,
    pub gossip_msg: GossipMessage,
    /// YPX-020 HAL: hibernation deadline stamped on a re-anchor register
    /// (`None` otherwise). The node handler floods it via
    /// `GossipMessage::Hibernation` — single source, no recompute.
    pub hibernation_until: Option<u64>,
    /// YPX-022 §2.2.1 — recall reservations COMMITTED by this register
    /// (`(txid, reservation_tick)`; empty for ordinary registers). The node
    /// handler garbage-inserts each and floods the committed Recall gossip.
    pub committed_recalls: Vec<(crate::types::TxHash, u64)>,
}

/// Persistence metrics for dashboard display.
#[derive(Debug, Clone, Default)]
pub struct PersistenceStats {
    pub smt_entries: usize,
    pub smt_memory_bytes: u64,
    pub ban_count: usize,
    pub wal_file_bytes: u64,
    pub wal_ops_since_snapshot: u64,
    pub wal_last_snapshot_tick: u64,
    pub snapshot_count: usize,
    pub snapshot_latest_bytes: u64,
    pub snapshot_total_bytes: u64,
    pub last_snapshot_tick: u64,
    pub ticks_since_snapshot: u64,
    pub total_disk_bytes: u64,
    pub cc_ticks_helped: u64,
    pub cc_total_registrations: u64,
    pub cc_score: u64,
}

/// Action the caller (gossip dispatch) should take after a Nabla's
/// `handle_alert` call. Used by Phase B Layer 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertHandleAction {
    /// Drop the alert — duplicate, self-accused, or other no-action case.
    Drop,
    /// Forgery attempt (intermediate_emitter doesn't match the PROVEN TCP
    /// source). Drop the alert + bump the offending peer's ban-score.
    ///
    /// ⚠ Currently unreachable from the gossip path: no transport-proven
    /// identity exists, so `handle_alert` receives `None` and the comparison
    /// that would emit this cannot run. Ghost audit G4 / KI#72.
    DropAndBanScore { peer: NodeId },
    /// Alert recorded; threshold not yet met. Forward to peers.
    Forward,
    /// 3-of-N consensus reached. Forward AND act on the quarantine
    /// (caller drops any cached TCP connections to `accused`, etc.).
    ForwardAndQuarantineActive { accused: NodeId, until_tick: u64 },
}

/// Layer 4 quarantine state — per-Nabla bookkeeping for the
/// 3-of-N consensus that drives the Infected Nabla mechanism.
/// See `docs/AXIOM_DESIGN_NablaPoolCaps.md` §5.6.
///
/// Two collections:
///   - `pending` — alerts received but not yet at quorum. Each entry
///     records (origin, intermediate) pairs per accused. Swept after
///     10 ticks.
///   - `active` — current quarantines. Each entry maps accused → tick
///     after which the quarantine lifts. Swept on tick boundary.
///
/// `active` + `cooldown` ride the snapshot (`persisted_entries` /
/// `restore_entries`, GUIDE §5.6c "Persistence", KI#75) — until 2026-09-25
/// this comment read "WAL persistence is a follow-up" and a restart lifted
/// every quarantine. `pending` and `probation` remain in-memory (shorter
/// than any restart).
#[derive(Debug, Default, Clone)]
pub struct QuarantineState {
    /// Active quarantines: accused → expiry tick.
    /// Stays accused-keyed (NOT (accused, pool_kind)) — a quarantine
    /// is per-accused, mesh-wide. Conservative direction per Mac's
    /// review §3.5.1.
    active: std::collections::HashMap<NodeId, u64>,
    /// Quorums that WOULD have quarantined but were withheld because no
    /// transport-proven sender identity exists (ghost audit G4 / KI#72).
    /// Counted, not just logged: a silent withhold is indistinguishable from
    /// "no attack happened" (CLAUDE.md RULE 3 §2).
    withheld_activations: u64,
    /// Re-activation cooldown: accused → tick before which incoming
    /// alerts about this accused are silently dropped. Set when a
    /// quarantine first activates (= `until_tick + cooldown`) and
    /// cleared by `sweep` once `current_tick` passes it. Prevents the
    /// forwarded-Alert flood from immediately re-quarantining the
    /// same accused once the active TTL expires — which the
    /// 2026-05-26 attack-injection test showed happens because the
    /// pending-alerts bucket is removed on activation, so subsequent
    /// forwards rebuild a fresh bucket.
    /// Also accused-keyed for the same reason as `active`: a
    /// per-accused cooldown gates per-(accused, pool_kind) pending
    /// accumulation across pools (Mac's review §3.5.1).
    cooldown: std::collections::HashMap<NodeId, u64>,
    /// Pending alerts: (accused, pool_kind) → list of
    /// (origin, intermediate, recv_tick). Re-keyed from `accused` per
    /// `AXIOM_DESIGN_NablaJudoon.md` §3.5 so that alerts
    /// spanning multiple pools against one accused don't merge into
    /// one ill-defined consensus count. The 10-tick consensus window
    /// starts at the FIRST entry's recv_tick; the whole bucket is
    /// dropped once the window closes (if quorum not met).
    pending: std::collections::HashMap<(NodeId, crate::types::PoolKind), PendingAlerts>,
    /// Layer 1 probation: accused → entry. Per
    /// `AXIOM_DESIGN_NablaJudoon.md` §2.5, a peer entering
    /// probation has its gossip relay-suppressed for
    /// `PROBATION_COUNTDOWN_TICKS` ticks (typically 10 ≈ 50 s). A
    /// recovered sensible PoolSync clears probation; expiry without
    /// recovery escalates to quarantine via WAL/TTL/cooldown reuse
    /// (PROOF-SHAPED single-observer — does NOT route through Alert
    /// K-of-N consensus).
    probation: std::collections::HashMap<NodeId, ProbationEntry>,
}

/// Per-peer probation record. In-memory only; Nabla restart resets
/// to "no probation entries, treat next violation as new" — accepted
/// trade-off (Mac's review §8: probation is soft signal, structural
/// check still fires on next bad PoolSync).
#[derive(Debug, Clone, Copy)]
pub struct ProbationEntry {
    /// TARDIS tick when probation was entered.
    pub started_at_tick: u64,
    /// Countdown in ticks; expiry at `started_at_tick + countdown`.
    pub countdown_ticks: u64,
    /// Which structural impossibility initially triggered probation.
    /// Logged on escalation for operator dashboards.
    pub initial_proof: crate::judoon::ProofKind,
}

#[derive(Debug, Clone)]
struct PendingAlerts {
    /// Tick of the first alert in the rolling window. Window closes
    /// at `first_seen + ALERT_CONSENSUS_WINDOW_TICKS * TICK_INTERVAL_SECS`.
    first_seen_tick: u64,
    /// All (origin, intermediate) pairs observed in the window.
    entries: Vec<(NodeId, NodeId)>,
}

/// Outcome of recording an incoming alert. Drives the higher-level
/// caller's decisions about (a) whether to forward the alert further
/// and (b) whether the consensus threshold was just crossed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertRecordOutcome {
    /// Dedup hit — same (accused, origin) already in window. No action.
    Duplicate,
    /// Self-alert (origin == self.node_id) — rejected as nonsensical.
    SelfOrigin,
    /// Self-accused (accused == self.node_id) — recorded locally but
    /// do NOT propagate. We don't help propagate accusations against
    /// ourselves; if the mesh quarantines us, that's its decision.
    SelfAccused,
    /// Alert recorded, but threshold not yet met. Forward to peers.
    Recorded,
    /// Threshold crossed: 3 distinct origins AND 3 distinct intermediates
    /// within the 10-tick window. Quarantine activated for the accused;
    /// return the expiry tick.
    QuarantineActivated { accused: NodeId, until_tick: u64 },
}

impl QuarantineState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Is this peer currently quarantined? Quarantine lifts when
    /// `current_tick >= until_tick`. Called from the message-receive
    /// path: messages from quarantined senders are dropped.
    pub fn is_quarantined(&self, peer: &NodeId, current_tick: u64) -> bool {
        self.active
            .get(peer)
            .map(|&until| current_tick < until)
            .unwrap_or(false)
    }

    /// Sweep expired entries. Call every tick.
    pub fn sweep(&mut self, current_tick: u64) {
        // Drop expired active quarantines
        self.active.retain(|_, &mut until| current_tick < until);
        // Drop expired cooldowns. After this, the same accused is
        // again eligible for a fresh consensus to form.
        self.cooldown.retain(|_, &mut until| current_tick < until);
        // Drop stale pending buckets (10-tick window elapsed without quorum).
        // Key is (NodeId, PoolKind) post-§3.5 re-keying — predicate
        // ignores the key entirely; window is per-bucket.
        let window_secs = crate::constants::ALERT_CONSENSUS_WINDOW_TICKS
            * crate::constants::TICK_INTERVAL_SECS;
        self.pending.retain(|_, p| {
            current_tick.saturating_sub(p.first_seen_tick) < window_secs
        });
    }

    /// Record an incoming alert and check if it triggers quarantine.
    /// `self_node_id` is the receiver's own NodeId (for self-checks).
    /// `pool_kind` is decoded from `Alert.evidence` by the caller
    /// (`handle_alert` in the binary) — see §3.5. `threshold` is the
    /// `K` to use for the dual-uniqueness consensus check, derived
    /// from `alert_threshold_for(pool_kind, ..)` upstream.
    ///
    /// Caller is responsible for the early return on `threshold ==
    /// None` (skip dispatch entirely for non-critical pools).
    /// Quorums met but NOT acted on for want of a proven sender identity.
    pub fn withheld_activations(&self) -> u64 { self.withheld_activations }

    pub fn record_alert(
        &mut self,
        self_node_id: &NodeId,
        accused: NodeId,
        pool_kind: crate::types::PoolKind,
        origin: NodeId,
        intermediate: NodeId,
        current_tick: u64,
        threshold: usize,
        // `identity_verified`: did the TRANSPORT prove who sent this hop? When
        // false, `intermediate` is an attacker-chosen string and the
        // dual-uniqueness count over it means nothing — so quarantine is never
        // activated (ghost audit G4 / KI#72).
        identity_verified: bool,
    ) -> AlertRecordOutcome {
        // §5.6.4 step 2: reject self-origin (nonsensical).
        if &origin == self_node_id {
            return AlertRecordOutcome::SelfOrigin;
        }
        // §5.6.4 step 3: self-accused → record but do not propagate.
        if &accused == self_node_id {
            return AlertRecordOutcome::SelfAccused;
        }
        // Cooldown gate: if we recently quarantined this accused (active
        // TTL just elapsed but cooldown window still open) treat any
        // incoming alert as a duplicate. Keyed on accused (not on
        // (accused, pool_kind)) — a per-accused cooldown gates pending
        // accumulation across all pools, conservative direction
        // (Mac's review §3.5.1).
        if let Some(&until) = self.cooldown.get(&accused) {
            if current_tick < until {
                return AlertRecordOutcome::Duplicate;
            }
        }
        // §5.6.4 step 4: dedup on (accused, pool_kind, origin) within
        // window. Bucket re-keyed per §3.5.
        let bucket_key = (accused, pool_kind);
        let bucket = self.pending.entry(bucket_key).or_insert(PendingAlerts {
            first_seen_tick: current_tick,
            entries: Vec::new(),
        });
        if bucket.entries.iter().any(|(o, _)| o == &origin) {
            return AlertRecordOutcome::Duplicate;
        }
        bucket.entries.push((origin, intermediate));
        // §5.6.5 dual-uniqueness check: K distinct origins AND
        // K distinct intermediates. K is the dispatch-supplied
        // depletion-aware threshold (Mac's review: minimum 3, max 10).
        let distinct_origins: std::collections::HashSet<&NodeId> =
            bucket.entries.iter().map(|(o, _)| o).collect();
        let distinct_intermediates: std::collections::HashSet<&NodeId> =
            bucket.entries.iter().map(|(_, i)| i).collect();
        // §5.6.5 dual-uniqueness holds ONLY if `intermediate` is a proven
        // identity. Unproven, one attacker supplies all `threshold` "distinct"
        // intermediates from a single node, and the accused is dropped from
        // every honest peer's gossip fan-out. Fail closed: record and forward
        // (so detection stays observable), never activate.
        if !identity_verified
            && distinct_origins.len() >= threshold
            && distinct_intermediates.len() >= threshold
        {
            log::warn!(
                "[QUARANTINE-WITHHELD] accused={} met {}-of-N on origins AND                  intermediates, but no transport-proven sender identity exists                  (§5.6.4 step 1 unbuilt) — NOT activating. See KI#72.",
                hex::encode(&accused[..8]), threshold,
            );
            self.withheld_activations = self.withheld_activations.saturating_add(1);
            return AlertRecordOutcome::Recorded;
        }
        if identity_verified
            && distinct_origins.len() >= threshold
            && distinct_intermediates.len() >= threshold
        {
            let until_tick = current_tick
                + crate::constants::QUARANTINE_DURATION_TICKS
                    * crate::constants::TICK_INTERVAL_SECS;
            let cooldown_until = until_tick
                + crate::constants::QUARANTINE_REACTIVATION_COOLDOWN_TICKS
                    * crate::constants::TICK_INTERVAL_SECS;
            self.active.insert(accused, until_tick);
            self.cooldown.insert(accused, cooldown_until);
            self.pending.remove(&bucket_key);
            return AlertRecordOutcome::QuarantineActivated { accused, until_tick };
        }
        AlertRecordOutcome::Recorded
    }

    // ── Layer 1 probation API (single-observer route) ──

    /// Enter a peer into probation, or refresh the existing entry on a
    /// fresh violation. Per `AXIOM_DESIGN_NablaJudoon.md`
    /// §2.5: callers route here on detecting a structural violation
    /// (BalanceExceedsInitial / IntraSnapshotInconsistent /
    /// MagnitudeBlatant).
    pub fn enter_probation(
        &mut self,
        peer: NodeId,
        current_tick: u64,
        proof: crate::judoon::ProofKind,
    ) {
        // Refresh existing entry rather than re-anchoring start_tick —
        // a malicious peer emitting repeat violations shouldn't get
        // probation extended indefinitely. The escalation fires at
        // the original countdown expiry.
        self.probation.entry(peer).or_insert(ProbationEntry {
            started_at_tick: current_tick,
            countdown_ticks: crate::constants::PROBATION_COUNTDOWN_TICKS,
            initial_proof: proof,
        });
    }

    /// Clear a peer's probation. Called when a subsequent PoolSync
    /// from the same peer passes structural checks — they've recovered.
    pub fn clear_probation(&mut self, peer: &NodeId) -> Option<ProbationEntry> {
        self.probation.remove(peer)
    }

    /// Is this peer currently in probation? Used by the gossip relay
    /// layer to suppress forwarding their PoolSyncs.
    pub fn is_probated(&self, peer: &NodeId) -> bool {
        self.probation.contains_key(peer)
    }

    /// Sweep expired probation entries — escalate to quarantine via
    /// the proof-shaped path (reuses `active` + `cooldown` WAL/TTL
    /// bookkeeping but does NOT route through K-of-N). Per §2.5
    /// "the escalation is proof-shaped and single-observer."
    /// Returns the list of newly-escalated peers for the caller to
    /// log / surface on dashboards.
    pub fn sweep_probation(&mut self, current_tick: u64) -> Vec<(NodeId, ProbationEntry)> {
        let mut expired = Vec::new();
        let secs_per_tick = crate::constants::TICK_INTERVAL_SECS;
        self.probation.retain(|peer, entry| {
            let elapsed = current_tick.saturating_sub(entry.started_at_tick);
            let expiry = entry.countdown_ticks * secs_per_tick;
            if elapsed >= expiry {
                expired.push((*peer, *entry));
                false  // remove from probation map
            } else {
                true
            }
        });
        // Escalate each expired probation to quarantine, reusing the
        // §5.6 WAL/TTL/cooldown bookkeeping. NOT routed through Alert.
        for (peer, _entry) in &expired {
            let until_tick = current_tick
                + crate::constants::QUARANTINE_DURATION_TICKS * secs_per_tick;
            let cooldown_until = until_tick
                + crate::constants::QUARANTINE_REACTIVATION_COOLDOWN_TICKS * secs_per_tick;
            self.active.insert(*peer, until_tick);
            self.cooldown.insert(*peer, cooldown_until);
        }
        expired
    }

    /// Number of peers currently in probation (for /status telemetry).
    pub fn probation_count(&self) -> usize {
        self.probation.len()
    }

    /// Number of active quarantines (for /status telemetry).
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Iterate active quarantines as (accused, until_tick).
    pub fn active_iter(&self) -> impl Iterator<Item = (&NodeId, u64)> {
        self.active.iter().map(|(k, v)| (k, *v))
    }

    /// GUIDE §5.6c "Persistence" (KI#75) — the durable part of this state for
    /// the snapshot: the live quarantine set with its expiry ticks, and the
    /// re-activation cooldowns. Sorted so the snapshot bytes are
    /// deterministic. `pending` (10-tick consensus buckets) and Layer-1
    /// `probation` (a 10-tick countdown) are shorter than any restart and
    /// are deliberately not persisted.
    pub fn persisted_entries(&self) -> (Vec<(NodeId, u64)>, Vec<(NodeId, u64)>) {
        let mut active: Vec<(NodeId, u64)> = self.active.iter().map(|(k, v)| (*k, *v)).collect();
        let mut cooldown: Vec<(NodeId, u64)> = self.cooldown.iter().map(|(k, v)| (*k, *v)).collect();
        active.sort();
        cooldown.sort();
        (active, cooldown)
    }

    /// Restore what `persisted_entries` wrote. Entries already expired at
    /// `current_tick` are dropped on the way in (the same rule `sweep`
    /// applies) so a stale snapshot cannot resurrect a lifted quarantine.
    pub fn restore_entries(
        &mut self,
        active: Vec<(NodeId, u64)>,
        cooldown: Vec<(NodeId, u64)>,
        current_tick: u64,
    ) {
        for (peer, until) in active {
            if current_tick < until {
                self.active.insert(peer, until);
            }
        }
        for (peer, until) in cooldown {
            if current_tick < until {
                self.cooldown.insert(peer, until);
            }
        }
    }

    /// Test-only: activate a quarantine directly (the production path is
    /// `record_alert` reaching quorum). Lets persistence tests drive the state
    /// without building a three-origin alert storm.
    #[cfg(test)]
    pub fn activate_for_test(&mut self, accused: NodeId, until_tick: u64) {
        self.active.insert(accused, until_tick);
    }

    /// Number of pending-alert buckets (in-flight, pre-quorum).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Outcome of a `try_claim` call on a pool — distinguishes the three
/// refusal reasons so the caller (registration handler) can emit a
/// distinct error per case. Pre-fix this returned `bool` and the
/// caller silently registered the wallet "at balance=0", which under
/// Phase A per-Nabla cap saturation produced an AXC-issued-without-
/// pool-decrement gap (Session 13 soak: 16/50 wallets, see
/// `docs/AXIOM_REPORT_Soak_20260422.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// Claim accepted; balance decremented, counters incremented.
    Granted,
    /// Per-Nabla cycle cap reached on this node. Client can try a
    /// different Nabla now (their per-cycle counter is independent).
    RefusedPerNablaCap {
        /// Local (this Nabla's) reset moment, in TARDIS virtual_secs.
        cycle_resets_at_tick: u64,
    },
    /// Mesh-wide cycle cap reached. No Nabla in the mesh can grant
    /// until the next cycle — client must wait.
    RefusedMeshCap {
        /// Mesh-wide reset moment, in TARDIS virtual_secs.
        cycle_resets_at_tick: u64,
    },
    /// Pool balance below claim amount — pool is dry. Permanent
    /// (or until external refill, which never happens for Airdrop).
    RefusedExhausted,
}

impl ClaimOutcome {
    /// Convenience for assertion-style code that only cares about
    /// success vs any refusal. Production code should match on the
    /// full variant to dispatch the right error to the client.
    pub fn is_granted(self) -> bool {
        matches!(self, ClaimOutcome::Granted)
    }
}

/// Outcome of a `set_balance` write — Phase B Layer 4 signal channel.
///
/// `set_balance` returned `bool` in Phase A. Phase B promotes it to this
/// richer enum so the caller (reconcile / try_claim) has enough context
/// to emit a `GossipMessage::Alert` on invariant violation. The
/// detection happens here; the gossip emission happens in the layer
/// above, with access to current_tick, signer, and the offending
/// PoolSync evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetBalanceOutcome {
    /// Write applied; new balance committed.
    Applied,
    /// Write rejected — new value was not strictly less than current.
    /// Caller should emit a `GossipMessage::Alert` if this came from a
    /// peer-driven path (reconcile); for internal paths (try_claim),
    /// this should never happen and indicates a bug.
    RejectedNonStrictDecrease { current: u64, attempted: u64 },
}

/// Outcome of a `reconcile` call — Phase B propagation channel.
///
/// Phase A returned `bool` ("did local state advance?"). Phase B adds
/// variants for the specific failure modes that should trigger an
/// `Alert` emission: invariant violation (caught by set_balance) and
/// magnitude violation (D2 sanity gate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// Local state advanced (balance lowered and/or claims incremented).
    Updated,
    /// No advance — peer state was equal or staler. No action needed.
    NoOp,
    /// Layer 1 single-observer structural violation detected by
    /// `judoon::structural_violation`. Self-evident proof
    /// from the peer's coherent message snapshot — no consensus needed.
    /// Caller routes to probation (suppress relay, no Alert). See
    /// `AXIOM_DESIGN_NablaJudoon.md` §2.5.
    StructuralViolation {
        proof: crate::judoon::ProofKind,
        peer_balance: u64,
        peer_claims: u64,
    },
    /// Reserved for the unreachable `set_balance` belt-and-suspenders
    /// branch (peer_balance < self.balance but somehow not strict-
    /// decrease). NOT used for the higher-balance direction anymore —
    /// per Mac's review (§2.6), that route now returns `NoOp` because
    /// min-wins discards the message and the Alert was pure noise.
    InvariantViolation { peer_balance: u64, local_balance: u64 },
    /// Layer 2 magnitude violation: peer's balance drop exceeded what
    /// the claim-count delta can explain, even after applying the
    /// pool-state-aware D2 slack from
    /// `judoon::d2_slack_for_lifetime_pct`. Caller emits
    /// Alert, which feeds the K-curve.
    MagnitudeViolation { peer_balance: u64, peer_claims: u64, local_balance: u64, local_claims: u64 },
}

/// Persistence record for a pool's gossip-tracked state. Written to
/// `<data_dir>/<pool>.state` (CBOR) on every successful mutation so a
/// Nabla restart picks up where it left off instead of re-minting the
/// full pool from the initial constant.
///
/// `local_claims` is NOT persisted — it's a per-session counter for
/// the dashboard, not part of mesh-wide truth.
///
/// `claims_this_cycle`, `cycle_start_tick`, and
/// `mesh_claims_at_cycle_start` ARE persisted so a restart inside an
/// active cap cycle resumes the cap state correctly (otherwise an
/// attacker could restart-loop to bypass the per-Nabla cap).
///
/// **No backward-compat (CLAUDE.md §13):** existing dev-env `.state`
/// files written before this field set was added will fail to
/// deserialize on first Nabla restart with the new build. Migration:
/// delete `*.state` files before redeploy; mesh converges via gossip.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedPoolState {
    pub balance: u64,
    pub total_claims: u64,
    /// TARDIS tick when this state was last written. Operational
    /// timestamp for the persistence record — NOT the same as
    /// `cycle_start_tick`.
    pub tick: u64,
    /// Number of claims this Nabla has emitted in the current
    /// per-Nabla cap cycle. See docs/AXIOM_DESIGN_NablaPoolCaps.md §4.
    pub claims_this_cycle: u64,
    /// TARDIS tick at which the current per-Nabla cap cycle opened.
    /// Each Nabla's cycle starts independently (Scenario A) — drift
    /// across the mesh is a defense feature.
    pub cycle_start_tick: u64,
    /// KI#191 — Σminus in atoms. PERSISTED because it is mesh-wide truth, not a
    /// node-local counter: a restart must not reset the conservation terms, or
    /// the node's first PoolSync advertises a snapshot that cannot balance.
    /// ⚠ Adding these CHANGED THE PERSISTED SHAPE. Pool state written before
    /// this field must be WIPED at the rotation that ships it — an old file
    /// decodes with `paid_out = 0` against a drawn-down balance, and then every
    /// node accuses every peer. (Rotation #14 crashed alpha on exactly this
    /// class of change.)
    pub paid_out: u64,
    /// KI#191 — Σplus beyond the genesis opening (the accounted DEED inflow).
    pub topped_up: u64,
    /// Snapshot of `total_claims` taken when the current cap cycle
    /// opened. Used to enforce the mesh-wide cap:
    /// `total_claims - mesh_claims_at_cycle_start < MESH_CAP_PER_CYCLE`.
    /// See §5 for the binding-constraint analysis.
    pub mesh_claims_at_cycle_start: u64,
}

impl PersistedPoolState {
    /// Atomic CBOR write — tmp + rename so a torn write can't corrupt
    /// the persisted file. Best-effort directory creation.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("state.tmp");
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)
    }

    /// Load from `path`. Returns `None` if file doesn't exist (fresh
    /// node — caller falls back to the initial-balance constant).
    /// Returns `Err` only on actual IO / decode failure (corrupted
    /// file — bubbles up so the node fails loudly rather than
    /// silently re-minting).
    pub fn load(path: &Path) -> std::io::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        let state: Self = ciborium::from_reader(&bytes[..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Some(state))
    }
}

/// §17.11 Airdrop Pool — protocol-level counter for genesis claim funding.
/// New wallets claim 1 AXC from this pool at registration time.
///
/// **Balance is private** (was `pub` before the §5.5 invariant landed):
/// every mutation routes through `set_balance` which enforces strict
/// monotonic decrease. See docs/AXIOM_DESIGN_NablaPoolCaps.md §5.5.
///
/// Cap enforcement: every claim runs through the per-Nabla cap
/// (AIRDROP_CLAIMS_PER_CYCLE_PER_NABLA) and the mesh-wide cap
/// (AIRDROP_MESH_CAP_PER_CYCLE), both measured within the current
/// 8888-tick cycle. See §4 and §5 of the design doc.
#[derive(Debug, Clone)]
pub struct AirdropPool {
    /// Remaining balance available for claims (in atoms). Private —
    /// mutate only via `set_balance` so the §5.5 strict-decrease
    /// invariant fires on every write site.
    balance: u64,
    /// Network-wide claims (converges via gossip — max wins).
    pub total_claims: u64,
    /// Claims processed locally by THIS node only (not gossiped).
    pub local_claims: u64,
    /// Claims THIS Nabla has emitted in the current per-Nabla cap
    /// cycle. Reset to 0 on each cycle rollover.
    pub claims_this_cycle: u64,
    /// TARDIS tick at which the current per-Nabla cap cycle opened.
    pub cycle_start_tick: u64,
    /// Snapshot of `total_claims` (mesh-wide) when the current cap
    /// cycle opened. Used to compute mesh-wide claims this cycle.
    pub mesh_claims_at_cycle_start: u64,
    /// ── PER-POOL CLASS CONSTANTS (2026-09-02) ──────────────────────────
    /// This struct backs THREE pools — airdrop, Bootstrap and
    /// FoundationBootstrap — which is correct reuse: all three are drain-only
    /// with a fixed per-claim debit. But the two numbers JUDOON polices them
    /// with are properties of the POOL, not of the struct, and they were
    /// hardcoded to the airdrop's values in `impl DrainOnlyPool` and in
    /// `reconcile`. Every instance answered "I started with 600,000 AXC and
    /// each claim takes 1 AXC".
    ///
    /// Before this fix: an HONEST FoundationBootstrap PoolSync (2,500,000 AXC)
    /// was measured against the airdrop's 600,000 and tripped
    /// `BalanceExceedsInitial` — "no honest Nabla, however stale, can emit
    /// this" — so honest nodes accused each other. `MagnitudeBlatant` misfired
    /// the same way once a 500,000 AXC grant landed against a 1 AXC yardstick,
    /// and the conservation check went blind rather than loud.
    ///
    /// `AXIOM_DESIGN_NablaJudoon.md` §2.2 already specifies these as "a single
    /// PER-POOL class constant", and its pool table anticipated this case
    /// ("(Future) Founders / Early-adopter — same trait, same three layers").
    /// Storing them per instance IS that design; the trait and the shared
    /// PoolSync API are unchanged.
    initial_atoms: u64,
    claim_amount: u64,
    /// KI#191 — atoms ACTUALLY debited by claims, mesh-converged max-wins
    /// exactly like `total_claims`. Replaces `total_claims × claim_amount` in
    /// the Layer 1 conservation check: that product is right only while every
    /// claim costs the same, which is false for the emission pools (their
    /// per-claim grant is an epoch SHARE). YP §25.2.4 requires the pool be
    /// "conserved on every node (Σplus − Σminus)"; this is Σminus.
    paid_out: u64,
    /// KI#191 — accounted DEED inflow, mesh-converged max-wins. Σplus beyond
    /// the genesis opening: a two-way pool legitimately RISES (YP §25.2.4
    /// rule 4), which is why `balance > initial_atoms` alone is not a violation
    /// for it. Truthful only because the transfer verifies the debit equals the
    /// credit (KI#193, ValidatorEmission §4.3a) — a security check is only as
    /// good as the numbers it is handed. Always 0 for the airdrop pool.
    topped_up: u64,
    /// Cap-cycle class constants (2026-09-14): the airdrop's registers by
    /// default; the emission pools set their own (`with_caps`). Same two
    /// layers, same code — only the numbers differ.
    cycle_secs: u64,
    cap_per_nabla: u64,
    cap_mesh: u64,
}

impl AirdropPool {
    pub fn new(initial_balance: u64) -> Self {
        Self {
            balance: initial_balance,
            total_claims: 0,
            local_claims: 0,
            claims_this_cycle: 0,
            cycle_start_tick: 0,
            mesh_claims_at_cycle_start: 0,
            // Airdrop defaults — BYTE-IDENTICAL to the previous hardcoded
            // behaviour at all ~80 existing call sites (many are `new(0)`
            // fixtures that relied on initial_atoms() answering with the
            // airdrop constant, NOT with the balance passed here).
            // ⚠ KI#191 — a pool opened here with a balance OTHER than the
            // airdrop constant is born violating
            // `balance + paid_out == initial_atoms + topped_up`, because this
            // answers with the constant rather than the opening balance. That
            // is deliberate and NOT changed: the ~80 fixtures named above rely
            // on it. A pool with its own budget must declare it —
            // `with_class_constants(initial, claim)` — which every production
            // non-airdrop pool already does. The KI#30 simulation did not, and
            // its reconciles were all structural violations until it did.
            initial_atoms: crate::constants::AIRDROP_POOL_INITIAL_ATOMS,
            claim_amount: axiom_core_logic::types::GENESIS_CLAIM_AMOUNT,
            paid_out: 0,
            topped_up: 0,
            cycle_secs: crate::constants::AIRDROP_CYCLE_SECS,
            cap_per_nabla: crate::constants::AIRDROP_CLAIMS_PER_CYCLE_PER_NABLA,
            cap_mesh: crate::constants::AIRDROP_MESH_CAP_PER_CYCLE,
        }
    }

    /// The cap-cycle numbers for THIS pool (emission: the FOB epoch and the
    /// `emission_claims_*` registers). Airdrop/join pools keep the defaults.
    pub fn with_caps(mut self, cycle_secs: u64, cap_per_nabla: u64, cap_mesh: u64) -> Self {
        self.cycle_secs = cycle_secs.max(1);
        self.cap_per_nabla = cap_per_nabla;
        self.cap_mesh = cap_mesh;
        self
    }

    /// Epoch roll for an EMISSION pool (`AXIOM_DESIGN_ValidatorEmission.md`
    /// §4.3): the ONE legal way this pool's balance goes UP. Adds the top-up,
    /// re-anchors the JUDOON lattice and opens a fresh cap cycle at `tick`.
    /// Every node applies the same roll from the same inputs, so a peer's
    /// advertised balance never exceeds the need (see `reconcile`).
    ///
    /// The anchor is `initial_atoms = balance + total_claims × share`, NOT the
    /// bare balance: JUDOON's structural check reads the LIFETIME `total_claims`
    /// (PoolSync max-wins) against `initial_atoms` (`balance + claims × amount ≤
    /// initial`), so an anchor at the bare balance made every honest peer's
    /// advertisement inconsistent from the first roll after any claim —
    /// live gate #2, 2026-09-14: `IntraSnapshotInconsistent` on all 7 nodes,
    /// every peer into probation. With the claims folded in, a claim in this
    /// epoch moves balance and claims×share by the same amount and the lattice
    /// holds; the previous epochs' claims are the constant it is anchored on.
    /// KI#191 — Σminus: atoms actually paid out by claims.
    pub fn paid_out(&self) -> u64 { self.paid_out }
    /// KI#191 — Σplus beyond the genesis opening: the accounted DEED inflow.
    pub fn topped_up(&self) -> u64 { self.topped_up }

    pub fn roll_epoch(&mut self, tick: u64, top_up_atoms: u64, share_atoms: u64) {
        self.balance = self.balance.saturating_add(top_up_atoms);
        // KI#191 — record the inflow as Σplus. `initial_atoms` USED TO BE
        // RECOMPUTED HERE as `balance + total_claims × share_atoms`, i.e.
        // assigned exactly the value that makes Layer 1's conservation identity
        // true — which made the check VACUOUS at every roll and drifting
        // afterwards (`total_claims` is mesh-converged, `balance` is this
        // node's own view). `initial_atoms` is the GENESIS OPENING and never
        // changes; all growth is `topped_up`.
        self.topped_up = self.topped_up.saturating_add(top_up_atoms);
        self.claim_amount = share_atoms;
        self.cycle_start_tick = tick;
        self.claims_this_cycle = 0;
        self.mesh_claims_at_cycle_start = self.total_claims;
    }

    /// Declare this pool's OWN class constants — its initial budget and the
    /// atoms debited per claim. Required for any pool that is not the airdrop;
    /// see the field docs above for what goes wrong without it.
    ///
    /// `claim_amount` MUST equal the amount actually passed to
    /// `try_claim_amount` for this pool, or JUDOON's conservation check
    /// measures a different pool than the one draining. `initial_atoms` is the
    /// GENESIS OPENING (KI#191): the Layer-1 identity is
    /// `balance + paid_out == initial_atoms + topped_up`, so a RESTORED pool
    /// must pass `balance + paid_out − topped_up` here — never the bare
    /// balance (`emission.rs::from_persisted`, fixed 2026-09-24: it did, and
    /// no node could converge after a restart).
    pub fn with_class_constants(mut self, initial_atoms: u64, claim_amount: u64) -> Self {
        self.initial_atoms = initial_atoms;
        self.claim_amount = claim_amount;
        self
    }

    /// Read the current balance. Use this instead of a public field
    /// so the §5.5 strict-decrease invariant has a single mutation
    /// entry point (`set_balance`).
    pub fn balance(&self) -> u64 {
        self.balance
    }

    /// The ONLY way to mutate `balance` outside construction.
    /// Enforces strict monotonic decrease (docs/...PoolCaps §5.5):
    /// the new value MUST be strictly less than the current value.
    ///
    /// Equality is rejected too — a no-op write indicates a bug
    /// (stale re-application or a weakened reconcile gate), not a
    /// legitimate operation.
    ///
    /// Returns true if applied, false if rejected. A rejected write
    /// triggers a structured log; in debug builds it also panics so
    /// the bug is caught during development.
    fn set_balance(&mut self, new: u64) -> SetBalanceOutcome {
        if new >= self.balance {
            log::error!(
                "[POOL-INVARIANT] AirdropPool non-strict-decrease: \
                 current={} attempted={}; REJECTED",
                self.balance, new,
            );
            return SetBalanceOutcome::RejectedNonStrictDecrease {
                current: self.balance,
                attempted: new,
            };
        }
        self.balance = new;
        SetBalanceOutcome::Applied
    }

    /// Cap-cycle roll: at the start of a fresh cycle, reset the
    /// per-cycle counters. Called from `try_claim` at the top of
    /// every claim attempt.
    fn maybe_roll_cycle(&mut self, current_tick: u64) {
        // First claim ever for this Nabla → initialize cycle anchor.
        let cycle_secs = self.cycle_secs;
        if self.cycle_start_tick == 0
            || current_tick >= self.cycle_start_tick.saturating_add(cycle_secs)
        {
            self.cycle_start_tick = current_tick;
            self.claims_this_cycle = 0;
            self.mesh_claims_at_cycle_start = self.total_claims;
        }
    }

    /// Attempt to claim GENESIS_CLAIM_AMOUNT from the pool.
    /// Returns true if claimed, false if rejected for any reason
    /// (pool exhausted, per-Nabla cap reached, mesh-wide cap reached).
    ///
    /// `current_tick` is the Nabla's current TARDIS tick — used to
    /// detect cycle rollover.
    pub fn try_claim(&mut self, current_tick: u64) -> ClaimOutcome {
        self.try_claim_amount(current_tick, axiom_core_logic::types::GENESIS_CLAIM_AMOUNT)
    }

    /// Attempt to claim an ARBITRARY amount from the pool — the
    /// validator-join generalisation of `try_claim`
    /// (`AXIOM_DESIGN_ValidatorJoin.md` §4 step 3).
    ///
    /// `try_claim` is this function pinned to `GENESIS_CLAIM_AMOUNT`; the
    /// airdrop grants a fixed 1 AXC, but a join grants its TIER FLOOR, which
    /// differs by tier. Both go through the same two cap layers and the same
    /// invariant-checked `set_balance`, so a join can never decrement a pool
    /// by a path the airdrop's guarantees do not already cover.
    ///
    /// The caller supplies the amount, so the caller must have validated it.
    /// For joins that is Core: CL1 pins `tx.amount` to an exact tier floor and
    /// rejects anything else, and the amount is covered by the commitment
    /// hash. Nabla decides only whether the pool CAN fund it.
    ///
    /// A zero amount is refused. NOTE this guard is REDUNDANT defence, not the
    /// sole protection: `set_balance` rejects any non-strict-decrease, so a
    /// zero claim (new == current) is refused there too. Verified by mutation
    /// — removing the guard does not change the outcome. It is kept because it
    /// short-circuits before the cycle roll and cap checks, so a zero claim
    /// cannot consume a cap unit on its way to being refused, and because the
    /// intent is clearer stated than inferred.
    pub fn try_claim_amount(&mut self, current_tick: u64, claim_amount: u64) -> ClaimOutcome {
        if claim_amount == 0 {
            return ClaimOutcome::RefusedExhausted;
        }
        self.maybe_roll_cycle(current_tick);

        let cycle_resets_at_tick = self.cycle_start_tick + self.cycle_secs;

        // Layer 1 — per-Nabla cap
        if self.claims_this_cycle >= self.cap_per_nabla {
            log::debug!(
                "[POOL-CAP-PER-NABLA] AirdropPool: {} claims this cycle (cap {}), \
                 refusing further claims until cycle reset at tick {}",
                self.claims_this_cycle,
                self.cap_per_nabla,
                cycle_resets_at_tick,
            );
            return ClaimOutcome::RefusedPerNablaCap { cycle_resets_at_tick };
        }

        // Layer 2 — mesh-wide cap (measured against this Nabla's view
        // of total_claims, which converges via gossip max-wins).
        let mesh_claims_this_cycle = self.total_claims.saturating_sub(self.mesh_claims_at_cycle_start);
        if mesh_claims_this_cycle >= self.cap_mesh {
            log::debug!(
                "[POOL-CAP-MESH] AirdropPool: mesh has emitted {} claims this cycle (cap {}), \
                 refusing further claims",
                mesh_claims_this_cycle,
                self.cap_mesh,
            );
            return ClaimOutcome::RefusedMeshCap { cycle_resets_at_tick };
        }

        // Existing balance check
        if self.balance < claim_amount {
            return ClaimOutcome::RefusedExhausted;
        }

        // Apply decrement via the invariant-checked setter.
        let new_balance = self.balance - claim_amount;
        if !matches!(self.set_balance(new_balance), SetBalanceOutcome::Applied) {
            // set_balance log already fired. Should never happen
            // because new_balance < self.balance by construction.
            return ClaimOutcome::RefusedExhausted;
        }
        self.total_claims += 1;
        // KI#191 — Σminus in ATOMS, not in claim COUNT. `claim_amount` is this
        // claim's real debit (an epoch share for an emission pool, the fixed
        // constant for the airdrop), so this stays exact when the grant varies.
        self.paid_out = self.paid_out.saturating_add(claim_amount);
        self.local_claims += 1;
        self.claims_this_cycle += 1;
        ClaimOutcome::Granted
    }

    /// Serialise the persisted-state subset (no `local_claims` —
    /// that's node-local cosmetic, not part of mesh-wide truth).
    pub fn to_persisted(&self, tick: u64) -> PersistedPoolState {
        PersistedPoolState {
            balance: self.balance,
            total_claims: self.total_claims,
            paid_out: self.paid_out,
            topped_up: self.topped_up,
            tick,
            claims_this_cycle: self.claims_this_cycle,
            cycle_start_tick: self.cycle_start_tick,
            mesh_claims_at_cycle_start: self.mesh_claims_at_cycle_start,
        }
    }

    /// Restore a pool from a previously persisted state. `local_claims`
    /// resets to 0 — by definition no claims have been processed
    /// locally yet in this session.
    pub fn from_persisted(state: &PersistedPoolState) -> Self {
        Self {
            balance: state.balance,
            total_claims: state.total_claims,
            local_claims: 0,
            claims_this_cycle: state.claims_this_cycle,
            cycle_start_tick: state.cycle_start_tick,
            mesh_claims_at_cycle_start: state.mesh_claims_at_cycle_start,
            // Class constants are NOT persisted — they are properties of the
            // pool's identity, not of its drained state. A restored subsidy
            // pool re-declares them via `with_class_constants`.
            initial_atoms: crate::constants::AIRDROP_POOL_INITIAL_ATOMS,
            claim_amount: axiom_core_logic::types::GENESIS_CLAIM_AMOUNT,
            // KI#191 — RESTORED, not reset: these are mesh-wide truth.
            paid_out: state.paid_out,
            topped_up: state.topped_up,
            cycle_secs: crate::constants::AIRDROP_CYCLE_SECS,
            cap_per_nabla: crate::constants::AIRDROP_CLAIMS_PER_CYCLE_PER_NABLA,
            cap_mesh: crate::constants::AIRDROP_MESH_CAP_PER_CYCLE,
        }
    }

    /// Gossip reconciliation: three-layer defense per
    /// `AXIOM_DESIGN_NablaJudoon.md` §2.6.5.
    ///
    /// Canonical order (Mac's review must-fix):
    ///   1. Layer 1 `structural_violation()` first — catches provably-
    ///      impossible values in either direction. MUST come before
    ///      the higher-balance NoOp branch because two of its triggers
    ///      (`BalanceExceedsInitial`, high-direction
    ///      `IntraSnapshotInconsistent`) imply `peer_balance >
    ///      self.balance` and would otherwise be unreachable.
    ///   2. Higher-balance direction → NoOp (was T1 attack class /
    ///      `InvariantViolation`; min-wins already discards the
    ///      message, so the Alert was pure noise dominating the
    ///      original 338-flood).
    ///   3. Layer 2 cross-node D2 magnitude gate with floored slack
    ///      (`d2_slack_for_lifetime_pct`). The slack floor at
    ///      `CLAIM_AMOUNT` is load-bearing — preserves gossip-skew
    ///      tolerance at low pool.
    pub fn reconcile(&mut self, peer_balance: u64, peer_claims: u64, peer_paid_out: u64) -> ReconcileOutcome {
        // This pool's own per-claim debit, not the airdrop's (2026-09-02).
        let claim_amount = self.claim_amount;

        // ── Layer 1 ── single-observer structural violations.
        if let Some(proof) = crate::judoon::structural_violation(
            peer_balance, peer_claims, peer_paid_out, self,
        ) {
            // KI#191 (2026-09-16) — SAY WHICH POOL, AND SHOW THE ARITHMETIC.
            // This warning fired 194 times across one 30-minute soak and could
            // not be diagnosed from the log at all: it named no pool, and this
            // struct backs several (airdrop, dev treasury, bootstrap,
            // foundation bootstrap, emission) with different budgets and
            // per-claim debits. `initial_atoms` + `claim_amount` identify the
            // instance uniquely — there is no name field to print — and the
            // computed sum shows the inequality that actually fired, so a
            // reader can tell the documented variable-grant false positive
            // (AXIOM_DESIGN_NablaJudoon.md §2.2) from a real conservation
            // breach WITHOUT re-deriving it by hand.
            //
            // The tag also said AIRDROP while covering every pool this struct
            // backs — a stale label on a security-relevant warning (RULE 3
            // shape 7); the per-instance constants landed 2026-09-02 and the
            // tag was never updated with them.
            let claimed_value = peer_claims.saturating_mul(claim_amount);
            log::warn!(
                "[JUDOON/POOL-STRUCTURAL] {:?} pool(initial_atoms={} claim_amount={}) \
                 peer_balance={} peer_claims={} local_balance={} local_claims={} \
                 peer_balance+claims*claim_amount={} vs initial_atoms={}",
                proof, self.initial_atoms, claim_amount,
                peer_balance, peer_claims, self.balance, self.total_claims,
                peer_balance.saturating_add(claimed_value), self.initial_atoms,
            );
            return ReconcileOutcome::StructuralViolation {
                proof,
                peer_balance,
                peer_claims,
            };
        }

        // ── Higher-balance ── harmless once structurally consistent.
        // Min-wins discards it; no Alert (Mac's review §2.6).
        if peer_balance > self.balance {
            log::trace!(
                "[JUDOON/HIGHER-BALANCE-IGNORED] peer_balance={} local={}",
                peer_balance, self.balance,
            );
            return ReconcileOutcome::NoOp;
        }

        // ── Layer 2 ── cross-node D2 magnitude gate, FLOORED slack.
        if peer_balance < self.balance {
            let balance_drop = self.balance - peer_balance;
            let claim_increase = peer_claims.saturating_sub(self.total_claims);
            let expected_drop = claim_increase * claim_amount;
            let lifetime_pct = self.balance
                .saturating_mul(100)
                / crate::constants::AIRDROP_POOL_INITIAL_ATOMS.max(1);
            let slack = crate::judoon::d2_slack_for_lifetime_pct(
                lifetime_pct, claim_amount,
            );

            if balance_drop > expected_drop + slack {
                log::warn!(
                    "[AIRDROP-GOSSIP] Rejected: balance drop {} > expected {} + slack {} (claims {} → {}, lifetime {}%)",
                    balance_drop, expected_drop, slack, self.total_claims, peer_claims, lifetime_pct,
                );
                return ReconcileOutcome::MagnitudeViolation {
                    peer_balance, peer_claims,
                    local_balance: self.balance,
                    local_claims: self.total_claims,
                };
            }

            match self.set_balance(peer_balance) {
                SetBalanceOutcome::Applied => {
                    if peer_claims > self.total_claims {
                        self.total_claims = peer_claims;
                    }
                    // KI#191 — ADOPTING A BALANCE MEANS ADOPTING ITS Σminus.
                    // `balance` and `paid_out` are two halves of ONE conserved
                    // statement: taking the peer's lower balance while keeping
                    // our own smaller `paid_out` leaves THIS pool unable to
                    // balance, and it then gossips that incoherence onward —
                    // every downstream node reads a structural violation and
                    // the mesh stops converging. Measured while building this:
                    // the KI#30 simulation over-minted 50x, because each
                    // adopted balance arrived one claim ahead of the Σminus
                    // that explained it. Max-wins like the claim counter: a
                    // pool only ever pays out more.
                    if peer_paid_out > self.paid_out {
                        self.paid_out = peer_paid_out;
                    }
                    ReconcileOutcome::Updated
                }
                SetBalanceOutcome::RejectedNonStrictDecrease { .. } => {
                    // Should be unreachable: peer_balance < self.balance
                    // by the outer condition. Belt-and-suspenders only.
                    ReconcileOutcome::InvariantViolation {
                        peer_balance,
                        local_balance: self.balance,
                    }
                }
            }
        } else if peer_claims > self.total_claims && peer_balance == self.balance {
            // SEC-03: equal balance but a higher claim counter means claims
            // rose without the pool draining — impossible for real claims
            // (each drops balance by claim_amount). Accept only a bounded
            // skew so a single lying node can't ratchet `total_claims`
            // toward the mesh cap and induce mesh-wide RefusedMeshCap. A
            // jump beyond the bound is a MagnitudeViolation, routed to the
            // same K-of-N Alert pipeline as a drain-magnitude violation.
            let claims_jump = peer_claims - self.total_claims;
            if claims_jump > crate::constants::POOL_SYNC_MAX_CLAIMS_SKEW_PER_MERGE {
                log::warn!(
                    "[AIRDROP-GOSSIP] Rejected: equal-balance total_claims jump {} > max skew {} (claims {} → {})",
                    claims_jump,
                    crate::constants::POOL_SYNC_MAX_CLAIMS_SKEW_PER_MERGE,
                    self.total_claims, peer_claims,
                );
                return ReconcileOutcome::MagnitudeViolation {
                    peer_balance, peer_claims,
                    local_balance: self.balance,
                    local_claims: self.total_claims,
                };
            }
            self.total_claims = peer_claims;
            ReconcileOutcome::Updated
        } else {
            ReconcileOutcome::NoOp
        }
    }

    /// Dev-mode escape hatch — bypasses the §5.5 invariant for soak
    /// test setup that needs to INITIALIZE pool balance to specific
    /// values (e.g., simulating a refilled pool). Production code
    /// MUST NOT call this.
    #[cfg(feature = "dev-mode")]
    pub fn force_balance_dev_only(&mut self, balance: u64) {
        log::warn!(
            "[POOL-INVARIANT-BYPASS] AirdropPool::force_balance_dev_only called: \
             current={} new={}. Dev-mode only.",
            self.balance, balance,
        );
        self.balance = balance;
        // KI#191 — keep the pool CONSERVED. This helper sets a balance without
        // going through `try_claim`, so `paid_out` would otherwise stay behind
        // and the pool would advertise a snapshot that cannot balance — a
        // fixture that lies, which then reads as a structural violation in
        // every test built on it. Σminus is restated as whatever the budget no
        // longer holds, which is exactly what a real drain to this balance
        // would have recorded.
        self.paid_out = self.initial_atoms
            .saturating_add(self.topped_up)
            .saturating_sub(self.balance);
    }
}

/// Implementation of the `DrainOnlyPool` trait
/// (`docs/AXIOM_DESIGN_NablaJudoon.md` §2.2) for the
/// Airdrop monetary pool. Satisfies the fixed-claim-size precondition
/// trivially: `GENESIS_CLAIM_AMOUNT = 10^10` atoms is the single
/// per-claim debit constant (`node.rs::AirdropPool::try_claim`).
///
/// Conservation invariant verified at every honest state:
///   `balance + total_claims × GENESIS_CLAIM_AMOUNT == initial_atoms`
impl crate::judoon::DrainOnlyPool for AirdropPool {
    fn balance(&self) -> u64 { self.balance }
    // Per-instance since 2026-09-02: this struct backs three pools with three
    // different budgets and per-claim debits. Answering with the airdrop's
    // constants made JUDOON accuse honest subsidy-pool nodes.
    fn initial_atoms(&self) -> u64 { self.initial_atoms }
    fn total_claims(&self) -> u64 { self.total_claims }
    fn local_claims_this_cycle(&self) -> u64 { self.claims_this_cycle }
    fn mesh_claims_at_cycle_start(&self) -> u64 { self.mesh_claims_at_cycle_start }
    fn claim_amount(&self) -> u64 { self.claim_amount }
    fn paid_out(&self) -> u64 { self.paid_out }
    fn topped_up(&self) -> u64 { self.topped_up }
}

/// Dev-AXC treasury — sibling of `AirdropPool` for `@axiom.internal`
/// claims (`AXIOM_DESIGN_FactClassIsolation.md` §4). Fixed-lifetime
/// 1M dev-AXC, no minting authority — once drained, dev claims
/// hard-reject.
///
/// Symmetric to AirdropPool: private balance + set_balance invariant
/// + per-Nabla cap + mesh-wide cap. Cap values are more permissive
/// (9 / 10000) because abuse surface is the dev team's own keys, not
/// open internet. See PoolCaps design §3.
#[derive(Debug, Clone)]
pub struct DevTreasuryPool {
    /// Private — mutate only via `set_balance` (§5.5 invariant).
    balance: u64,
    pub total_claims: u64,
    pub local_claims: u64,
    pub claims_this_cycle: u64,
    pub cycle_start_tick: u64,
    pub mesh_claims_at_cycle_start: u64,
}

impl DevTreasuryPool {
    pub fn new(initial_balance: u64) -> Self {
        Self {
            balance: initial_balance,
            total_claims: 0,
            local_claims: 0,
            claims_this_cycle: 0,
            cycle_start_tick: 0,
            mesh_claims_at_cycle_start: 0,
        }
    }

    pub fn balance(&self) -> u64 {
        self.balance
    }

    fn set_balance(&mut self, new: u64) -> SetBalanceOutcome {
        if new >= self.balance {
            log::error!(
                "[POOL-INVARIANT] DevTreasuryPool non-strict-decrease: \
                 current={} attempted={}; REJECTED",
                self.balance, new,
            );
            return SetBalanceOutcome::RejectedNonStrictDecrease {
                current: self.balance,
                attempted: new,
            };
        }
        self.balance = new;
        SetBalanceOutcome::Applied
    }

    fn maybe_roll_cycle(&mut self, current_tick: u64) {
        let cycle_secs = crate::constants::DEV_TREASURY_CYCLE_SECS;
        if self.cycle_start_tick == 0
            || current_tick >= self.cycle_start_tick.saturating_add(cycle_secs)
        {
            self.cycle_start_tick = current_tick;
            self.claims_this_cycle = 0;
            self.mesh_claims_at_cycle_start = self.total_claims;
        }
    }

    /// Attempt to claim GENESIS_CLAIM_AMOUNT of dev-AXC. Returns the
    /// rich `ClaimOutcome` (Granted / RefusedPerNablaCap / RefusedMeshCap
    /// / RefusedExhausted) so the caller can hard-reject the registration
    /// with a refusal-specific error code — see `ClaimOutcome` docs.
    pub fn try_claim(&mut self, current_tick: u64) -> ClaimOutcome {
        self.maybe_roll_cycle(current_tick);

        let cycle_resets_at_tick =
            self.cycle_start_tick + crate::constants::DEV_TREASURY_CYCLE_SECS;

        // Layer 1 — per-Nabla cap
        if self.claims_this_cycle >= crate::constants::DEV_TREASURY_CLAIMS_PER_CYCLE_PER_NABLA {
            log::debug!(
                "[POOL-CAP-PER-NABLA] DevTreasuryPool: {} claims this cycle (cap {})",
                self.claims_this_cycle,
                crate::constants::DEV_TREASURY_CLAIMS_PER_CYCLE_PER_NABLA,
            );
            return ClaimOutcome::RefusedPerNablaCap { cycle_resets_at_tick };
        }

        // Layer 2 — mesh-wide cap
        let mesh_claims_this_cycle = self.total_claims.saturating_sub(self.mesh_claims_at_cycle_start);
        if mesh_claims_this_cycle >= crate::constants::DEV_TREASURY_MESH_CAP_PER_CYCLE {
            log::debug!(
                "[POOL-CAP-MESH] DevTreasuryPool: mesh has emitted {} claims this cycle (cap {})",
                mesh_claims_this_cycle,
                crate::constants::DEV_TREASURY_MESH_CAP_PER_CYCLE,
            );
            return ClaimOutcome::RefusedMeshCap { cycle_resets_at_tick };
        }

        let claim_amount = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;
        if self.balance < claim_amount {
            return ClaimOutcome::RefusedExhausted;
        }

        let new_balance = self.balance - claim_amount;
        if !matches!(self.set_balance(new_balance), SetBalanceOutcome::Applied) {
            return ClaimOutcome::RefusedExhausted;
        }
        self.total_claims += 1;
        self.local_claims += 1;
        self.claims_this_cycle += 1;
        ClaimOutcome::Granted
    }

    pub fn to_persisted(&self, tick: u64) -> PersistedPoolState {
        PersistedPoolState {
            balance: self.balance,
            total_claims: self.total_claims,
            // KI#191 — drain-only with a fixed grant; judged by its own
            // `reconcile`, not the two-way identity.
            paid_out: 0,
            topped_up: 0,
            tick,
            claims_this_cycle: self.claims_this_cycle,
            cycle_start_tick: self.cycle_start_tick,
            mesh_claims_at_cycle_start: self.mesh_claims_at_cycle_start,
        }
    }

    pub fn from_persisted(state: &PersistedPoolState) -> Self {
        Self {
            balance: state.balance,
            total_claims: state.total_claims,
            local_claims: 0,
            claims_this_cycle: state.claims_this_cycle,
            cycle_start_tick: state.cycle_start_tick,
            mesh_claims_at_cycle_start: state.mesh_claims_at_cycle_start,
        }
    }

    /// Gossip reconciliation — symmetric with `AirdropPool::reconcile`.
    /// Phase B: returns ReconcileOutcome (was bool).
    pub fn reconcile(&mut self, peer_balance: u64, peer_claims: u64) -> ReconcileOutcome {
        let claim_amount = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;

        if peer_balance < self.balance {
            let balance_drop = self.balance - peer_balance;
            let claim_increase = peer_claims.saturating_sub(self.total_claims);
            let expected_drop = claim_increase * claim_amount;

            if balance_drop > expected_drop + claim_amount {
                log::warn!("[DEV-TREASURY-GOSSIP] Rejected: balance drop {} > expected {} (claims {} → {})",
                    balance_drop, expected_drop, self.total_claims, peer_claims);
                return ReconcileOutcome::MagnitudeViolation {
                    peer_balance, peer_claims,
                    local_balance: self.balance,
                    local_claims: self.total_claims,
                };
            }

            match self.set_balance(peer_balance) {
                SetBalanceOutcome::Applied => {
                    if peer_claims > self.total_claims {
                        self.total_claims = peer_claims;
                    }
                    ReconcileOutcome::Updated
                }
                SetBalanceOutcome::RejectedNonStrictDecrease { .. } => {
                    ReconcileOutcome::InvariantViolation {
                        peer_balance,
                        local_balance: self.balance,
                    }
                }
            }
        } else if peer_balance > self.balance {
            // Higher-balance direction = the PEER is behind (fewer claims seen).
            // Min-wins discards it; no Alert — the ruling AirdropPool::reconcile
            // already follows (Mac's review §2.6). This pool kept the old
            // `InvariantViolation` until 2026-09-26 and accused the lagging peer
            // on every genesis-claim burst ([POOL-RECONCILE-INVARIANT] 44x on one
            // soak, 7x on the next — peer = local + exactly one claim each time).
            log::trace!(
                "[DEV-TREASURY-GOSSIP] higher-balance ignored peer_balance={} local={}",
                peer_balance, self.balance,
            );
            ReconcileOutcome::NoOp
        } else if peer_claims > self.total_claims && peer_balance == self.balance {
            // SEC-03: bound equal-balance claim-counter skew (see AirdropPool
            // ::reconcile for the rationale). Symmetric defense on the dev
            // treasury drain pool.
            let claims_jump = peer_claims - self.total_claims;
            if claims_jump > crate::constants::POOL_SYNC_MAX_CLAIMS_SKEW_PER_MERGE {
                log::warn!(
                    "[DEV-TREASURY-GOSSIP] Rejected: equal-balance total_claims jump {} > max skew {} (claims {} → {})",
                    claims_jump,
                    crate::constants::POOL_SYNC_MAX_CLAIMS_SKEW_PER_MERGE,
                    self.total_claims, peer_claims,
                );
                return ReconcileOutcome::MagnitudeViolation {
                    peer_balance, peer_claims,
                    local_balance: self.balance,
                    local_claims: self.total_claims,
                };
            }
            self.total_claims = peer_claims;
            ReconcileOutcome::Updated
        } else {
            ReconcileOutcome::NoOp
        }
    }

    #[cfg(feature = "dev-mode")]
    pub fn force_balance_dev_only(&mut self, balance: u64) {
        log::warn!(
            "[POOL-INVARIANT-BYPASS] DevTreasuryPool::force_balance_dev_only called: \
             current={} new={}. Dev-mode only.",
            self.balance, balance,
        );
        self.balance = balance;
    }
}

/// YP §20.8 / §20.11 — DEED fee pool.
///
/// Accumulator for the 10% slice of every validator fee that goes to
/// DEED (developer-equity / execution-deed). Credited at receiver's
/// /register time when the chain-verified fee_breakdown is non-empty;
/// drained later by DEED Group withdrawal flows (separate mechanism,
/// not yet wired — AXIOM Origin's directive 2026-06-02 "There is a pool for
/// DEED. Just like dev pool.").
///
/// Distinct from AirdropPool / DevTreasuryPool which model FINITE
/// supplies (strict-decrease invariant). DEED pool grows from fees
/// over time, so the invariant flips: credits only increase, withdraw
/// decreases. No need for §5.5 strict-decrease — there's no genesis
/// allocation to protect.
#[derive(Debug, Clone, Default)]
pub struct DeedPool {
    /// Current withdrawable balance in atoms (= total_credited − drawn_total).
    balance: u64,
    /// Contribution emission (2026-09-14): lifetime atoms DRAWN out of DEED into
    /// the emission pools by the deterministic epoch top-up. Every node computes
    /// the same draws from the same registers, so `reconcile` tolerates a peer
    /// whose balance is lower than ours by at most one epoch's top-up
    /// (`draw_tolerance`) — that peer rolled first, it did not lose coins.
    drawn_total: u64,
    draw_tolerance: u64,
    /// Lifetime total credited (audit trail; never decreases on credit
    /// rollback). Used to expose Σ-collected on dashboards.
    total_credited: u64,
    /// TARDIS tick of the last credit, for monitoring / liveness.
    pub last_credit_tick: u64,
    /// KI#28 rate detector — rolling window of locally-observed credits
    /// `(tick, atoms)`. IN-MEMORY ONLY (not persisted, not gossiped): it
    /// feeds `judoon::increase_pool_should_alert` to tolerate gossip lag
    /// on this monotonic-increase pool. See AXIOM_DESIGN_NablaJudoon §10.2.
    observed_credits: std::collections::VecDeque<(u64, u64)>,
}

impl DeedPool {
    pub fn new() -> Self { Self::default() }

    pub fn balance(&self) -> u64 { self.balance }
    pub fn total_credited(&self) -> u64 { self.total_credited }
    pub fn drawn_total(&self) -> u64 { self.drawn_total }

    /// Contribution emission top-up: move `amount` out of DEED (bounded by the
    /// balance). Returns what actually moved. `tolerance` is the largest
    /// single-epoch draw any honest node could apply this epoch, so a peer's
    /// lower balance within it is a roll-order difference, not a loss.
    pub fn draw(&mut self, amount: u64, tolerance: u64) -> u64 {
        let moved = amount.min(self.balance);
        self.balance -= moved;
        self.drawn_total = self.drawn_total.saturating_add(moved);
        self.draw_tolerance = tolerance;
        moved
    }

    /// Credit `amount` atoms to the pool. Called from registration.rs
    /// after the receipt_commitment chain verifies and Nabla has
    /// recorded the per-tx fee_breakdown. `tick` records when the
    /// credit landed.
    ///
    /// Uses checked_add — if the pool balance would overflow u64,
    /// we log and skip. At 100M AXC = 10^18 atoms total supply and
    /// 10% DEED share, overflow is purely theoretical, but the guard
    /// keeps the invariant correct.
    pub fn credit(&mut self, amount: u64, tick: u64) {
        let new_balance = match self.balance.checked_add(amount) {
            Some(b) => b,
            None => {
                log::error!(
                    "[deed_pool] credit overflow: balance={} + amount={}; SKIPPED",
                    self.balance, amount,
                );
                return;
            }
        };
        let new_total = self.total_credited.saturating_add(amount);
        self.balance = new_balance;
        self.total_credited = new_total;
        self.last_credit_tick = tick;
        self.observe_credit(amount, tick);
    }

    /// Push a locally-observed credit into the KI#28 rolling window and
    /// prune by age then by count. In-memory only; cheap (bounded by the
    /// pool credit rate, which tracks register throughput).
    fn observe_credit(&mut self, amount: u64, tick: u64) {
        self.observed_credits.push_back((tick, amount));
        let cutoff = tick.saturating_sub(crate::judoon::INCREASE_POOL_WINDOW_SECS);
        while self.observed_credits.front().is_some_and(|(t, _)| *t < cutoff) {
            self.observed_credits.pop_front();
        }
        while self.observed_credits.len() > crate::judoon::INCREASE_POOL_WINDOW_MAX_SAMPLES {
            self.observed_credits.pop_front();
        }
    }

    /// Sum of atoms credited locally within the current rolling window —
    /// the rate input to `judoon::increase_pool_should_alert`.
    pub fn rate_window_sum(&self) -> u64 {
        self.observed_credits.iter().map(|(_, a)| *a).sum()
    }

    /// Number of samples in the current rolling window — the statistical-
    /// safety gate input (detector self-disables below the minimum).
    pub fn rate_window_samples(&self) -> usize {
        self.observed_credits.len()
    }

    /// Atomic CBOR persistence — same shape as `PersistedPoolState` save/load,
    /// but the DEED pool fields are different so it gets its own struct.
    pub fn to_persisted(&self) -> PersistedDeedPoolState {
        PersistedDeedPoolState {
            balance: self.balance,
            total_credited: self.total_credited,
            last_credit_tick: self.last_credit_tick,
            drawn_total: self.drawn_total,
        }
    }

    pub fn from_persisted(state: &PersistedDeedPoolState) -> Self {
        Self {
            balance: state.balance,
            total_credited: state.total_credited,
            last_credit_tick: state.last_credit_tick,
            drawn_total: state.drawn_total,
            draw_tolerance: 0,
            // Rolling window is in-memory only — starts empty on restart.
            observed_credits: std::collections::VecDeque::new(),
        }
    }

    /// Gossip reconciliation — monotonic-INCREASE (the opposite of
    /// `AirdropPool::reconcile`, which is monotonic-decrease).
    /// DEED only grows during Phase 1: when a peer reports a higher
    /// balance + higher total_credited, we adopt them — the peer saw a
    /// register we missed. Lower-balance peers are rejected: we'd never
    /// voluntarily reduce DEED balance.
    ///
    /// Sanity gate: the balance increase MUST not exceed
    /// `peer_total_credited − local.total_credited` plus a small grace
    /// (one slot of slack for the off-by-one between mesh-wide and
    /// local credit counters during gossip propagation).
    pub fn reconcile(&mut self, peer_balance: u64, peer_total_credited: u64) -> ReconcileOutcome {
        if peer_balance < self.balance {
            // 2026-09-14: DEED now DECREASES by the emission top-up. A peer
            // that rolled its epoch before us reads lower by exactly its draw;
            // within one epoch's tolerance that is order, not loss (NoOp — our
            // own roll catches up). Beyond it, the old invariant stands.
            if self.balance - peer_balance <= self.draw_tolerance {
                return ReconcileOutcome::NoOp;
            }
            return ReconcileOutcome::InvariantViolation {
                peer_balance,
                local_balance: self.balance,
            };
        }
        if peer_balance == self.balance && peer_total_credited <= self.total_credited {
            return ReconcileOutcome::NoOp;
        }
        let balance_gain = peer_balance - self.balance;
        let credit_gain = peer_total_credited.saturating_sub(self.total_credited);
        // Phase-1 invariant: any balance growth must be backed by an
        // equal-or-larger growth in total_credited (DEED never decreases
        // except via a future drain which is out of scope for this PR).
        if balance_gain > credit_gain {
            log::warn!(
                "[deed-gossip] Rejected: balance_gain={} > credit_gain={} \
                 (local={}/{} → peer={}/{})",
                balance_gain, credit_gain,
                self.balance, self.total_credited,
                peer_balance, peer_total_credited,
            );
            return ReconcileOutcome::MagnitudeViolation {
                peer_balance,
                peer_claims: peer_total_credited,
                local_balance: self.balance,
                local_claims: self.total_credited,
            };
        }
        self.balance = peer_balance;
        self.total_credited = peer_total_credited;
        ReconcileOutcome::Updated
    }
}

/// On-disk persistence for `DeedPool`. Same atomic CBOR pattern as
/// `PersistedPoolState`; different field set so the two stay
/// independent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedDeedPoolState {
    pub balance: u64,
    pub total_credited: u64,
    pub last_credit_tick: u64,
    /// Emission draws out of DEED (2026-09-14). Absent on a pre-emission
    /// file = 0 — pre-mainnet, the rotation wipes data anyway.
    #[serde(default)]
    pub drawn_total: u64,
}

impl PersistedDeedPoolState {
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("state.tmp");
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load(path: &std::path::Path) -> std::io::Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let state: Self = ciborium::from_reader(bytes.as_slice())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Ok(Some(state))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Per-validator NET earnings on Nabla. Populated by process_registration
/// after compute_deed_split runs — each entry is the 90%-of-slot the
/// validator can actually claim at Step 9B withdrawal mint.
///
/// Separate from Lambda's `validator_earned` ledger, which is GROSS (raw
/// slot amount, DEED-tax-blind). Lambda's ledger stays informational;
/// Nabla's NET ledger is authoritative for the Step 9B withdrawal cap.
///
/// Idempotency inherits from the existing `record_tx_meta` + idempotent-
/// retry short-circuit in `process_registration`: a re-gossiped or
/// retried register never reaches the credit step a second time.
#[derive(Debug, Default, Clone)]
pub struct ValidatorNetLedger {
    by_validator: std::collections::BTreeMap<[u8; 32], NetEntry>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetEntry {
    pub balance: u64,
    pub total_credited: u64,
    pub last_credit_tick: u64,
}

impl ValidatorNetLedger {
    pub fn new() -> Self { Self::default() }

    /// Credit `amount` atoms to validator `vid`'s NET balance. Uses
    /// checked_add — overflow is purely theoretical at AXIOM scale
    /// (total supply 10^18 atoms) but the guard keeps the invariant
    /// correct under a buggy caller.
    pub fn credit(&mut self, vid: &[u8; 32], amount: u64, tick: u64) {
        let entry = self.by_validator.entry(*vid).or_default();
        entry.balance = entry.balance.checked_add(amount).unwrap_or_else(|| {
            log::error!(
                "[validator-net-ledger] credit overflow for vid={}; capping at u64::MAX",
                hex::encode(&vid[..8]),
            );
            u64::MAX
        });
        entry.total_credited = entry.total_credited.saturating_add(amount);
        entry.last_credit_tick = tick;
    }

    pub fn balance(&self, vid: &[u8; 32]) -> u64 {
        self.by_validator.get(vid).map(|e| e.balance).unwrap_or(0)
    }

    pub fn total_credited(&self, vid: &[u8; 32]) -> u64 {
        self.by_validator.get(vid).map(|e| e.total_credited).unwrap_or(0)
    }

    /// Number of validators with a non-default entry (some credits seen).
    pub fn len(&self) -> usize { self.by_validator.len() }
    pub fn is_empty(&self) -> bool { self.by_validator.is_empty() }

    pub fn to_persisted(&self) -> PersistedValidatorNetLedger {
        PersistedValidatorNetLedger {
            entries: self.by_validator.iter().map(|(k, v)| (*k, v.clone())).collect(),
        }
    }

    pub fn from_persisted(state: &PersistedValidatorNetLedger) -> Self {
        Self {
            by_validator: state.entries.iter().cloned().collect(),
        }
    }
}

/// On-disk persistence for `ValidatorNetLedger`. CBOR vec of (vid,
/// entry) pairs — BTreeMap iteration is sorted, so the on-disk shape
/// is deterministic across restarts.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedValidatorNetLedger {
    pub entries: Vec<([u8; 32], NetEntry)>,
}

// ═══════════════════════════════════════════════════════════════════════════
// DEV-CLASS POOLS — leak boundary enforcement
//
// `AXIOM_DESIGN_FactClassIsolation.md` mandates dev-AXC (the 1M pool
// allocated to `@axiom.internal` test wallets) NEVER leak into the
// public 100M AXC economy. Pre-this-PR, dev TXs credited the SAME
// `DeedPool` + `ValidatorNetLedger` as public TXs, and validators
// could withdraw via the Step 9B mint path → mint PUBLIC AXC backed
// by dev fees. Bug filed 2026-06-05.
//
// The fix uses NEWTYPES (not type aliases) so a credit-routing bug
// is a COMPILE ERROR, not a runtime drift. `DevDeedPool::credit`
// cannot be passed to a function expecting `DeedPool::credit` and
// vice versa. The validator-withdrawal mint gate
// (`lambda::validator_withdrawal`) reads which ledger the entry came
// from and gates mint type accordingly.
//
// Routing decision lives in `nabla::registration::process_registration`:
// `if receipt.is_dev_class { dev_*.credit } else { public.credit }`.
// Core CL3/CL5 attested `is_dev_class` and k=3 validators signed it
// via `receipt_commitment`, so a forged flag is structurally
// impossible to land here.
// ═══════════════════════════════════════════════════════════════════════════

/// Dev-class DEED pool — mirrors `DeedPool` but tracks the 10% DEED
/// slice from `@axiom.internal` TXs. NEVER touches `DeedPool`; the
/// withdrawal mint gate reads which pool an earnings entry came from
/// and mints dev-AXC vs public-AXC accordingly.
#[derive(Debug, Default, Clone)]
pub struct DevDeedPool(DeedPool);

impl DevDeedPool {
    pub fn new() -> Self { Self(DeedPool::new()) }
    pub fn balance(&self) -> u64 { self.0.balance() }
    pub fn total_credited(&self) -> u64 { self.0.total_credited() }
    pub fn last_credit_tick(&self) -> u64 { self.0.last_credit_tick }
    /// Credit DEV-AXC atoms to the dev DEED pool. Type-distinct from
    /// `DeedPool::credit` — passing a `DevDeedPool` where a `DeedPool`
    /// is expected (or vice versa) is a compile error.
    pub fn credit(&mut self, amount: u64, tick: u64) {
        self.0.credit(amount, tick);
    }
    pub fn to_persisted(&self) -> PersistedDeedPoolState { self.0.to_persisted() }
    pub fn from_persisted(state: &PersistedDeedPoolState) -> Self {
        Self(DeedPool::from_persisted(state))
    }
    pub fn reconcile(&mut self, peer_balance: u64, peer_total_credited: u64) -> ReconcileOutcome {
        self.0.reconcile(peer_balance, peer_total_credited)
    }
    /// KI#28 rate-detector inputs — delegate to the inner pool.
    pub fn rate_window_sum(&self) -> u64 { self.0.rate_window_sum() }
    pub fn rate_window_samples(&self) -> usize { self.0.rate_window_samples() }
}

/// Dev-class per-validator NET earnings ledger — mirrors
/// `ValidatorNetLedger` for `@axiom.internal` TXs. Validator
/// withdrawals from THIS ledger mint dev-AXC only.
#[derive(Debug, Default, Clone)]
pub struct ValidatorDevNetLedger(ValidatorNetLedger);

impl ValidatorDevNetLedger {
    pub fn new() -> Self { Self(ValidatorNetLedger::new()) }
    pub fn balance(&self, vid: &[u8; 32]) -> u64 { self.0.balance(vid) }
    pub fn total_credited(&self, vid: &[u8; 32]) -> u64 { self.0.total_credited(vid) }
    pub fn len(&self) -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
    /// Credit DEV-AXC atoms to a validator's dev NET balance.
    /// Type-distinct from `ValidatorNetLedger::credit`.
    pub fn credit(&mut self, vid: &[u8; 32], amount: u64, tick: u64) {
        self.0.credit(vid, amount, tick);
    }
    pub fn to_persisted(&self) -> PersistedValidatorNetLedger { self.0.to_persisted() }
    pub fn from_persisted(state: &PersistedValidatorNetLedger) -> Self {
        Self(ValidatorNetLedger::from_persisted(state))
    }
}

impl PersistedValidatorNetLedger {
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("state.tmp");
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load(path: &std::path::Path) -> std::io::Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let state: Self = ciborium::from_reader(bytes.as_slice())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Ok(Some(state))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}
/// §6b registration record (ValidatorJoin §6b.10 / KI#169 / KI#170).
/// ⚠ ForkSettlement wave 4a (R42, KI#223): the record is now the STAMPED
/// certificate + its supporting chain and NOTHING else — every former field
/// (`wallet_pk`, `tick`, `balance`, `validator_id`, `expires_at`) is read out
/// of the verified certificate/stamp. It lives in `vbc_directory`, where the
/// only way into a directory is `vbc_directory::admit`.
pub use crate::vbc_directory::VbcRegistrationRecord;

/// Load `vbc_registrations.cbor`. ForkSettlement wave 4a — a PERSISTED-SHAPE
/// change: the pre-4a file is `Vec<(vbc_hash, {wallet_pk, tick, balance,
/// validator_id, expires_at})>`, the new one `Vec<VbcRegistrationRecord>`
/// (stamped certificate + chain). A file that does not decode STRICTLY is
/// REFUSED LOUDLY: `error!`, counted on `/status vbc_registry_decode_refused`,
/// moved aside to `vbc_registrations.cbor.refused` (evidence kept, never read
/// again), and the node boots with an EMPTY directory — never `Err`, which on
/// a RETAIN rotation would crash-loop every node
/// ([[feedback_retain_rotation_needs_persisted_shape_check]]; rotation #14).
/// Nothing of value is lost: the old entries were unverified (KI#223) and a
/// pre-4a record carries no certificate to verify — validators re-register
/// with their bundle (R37 operational step), and AE refills verified entries.
pub(crate) fn load_vbc_directory_file(path: &std::path::Path, bytes: &[u8]) -> crate::vbc_directory::VbcDirectory {
    match ciborium::from_reader::<Vec<VbcRegistrationRecord>, _>(bytes) {
        Ok(list) => crate::vbc_directory::VbcDirectory::restore(list),
        Err(e) => {
            crate::vbc_directory::note_registry_decode_refused();
            let aside = path.with_extension("cbor.refused");
            let moved = std::fs::rename(path, &aside);
            log::error!(
                "[VBC-REGISTRY-REFUSED] {} does not decode under this build's directory shape \
                 (ForkSettlement wave 4a: stamped certificate + supporting chain) — {e}. NOT loaded: \
                 the witness directory starts EMPTY; validators must re-register with their bundle and \
                 AE refills verified entries. File moved aside to {} ({:?}). Counted: /status \
                 vbc_registry_decode_refused.",
                path.display(), aside.display(), moved.err(),
            );
            Default::default()
        }
    }
}


/// WAL `Ban` records this process refused at replay because they did not
/// decode under this build's `BannedEntry` shape, cumulative (ForkSettlement
/// §9b R36 — the arm used to skip them SILENTLY). RULE 6: a refused
/// irreversible verdict must be countable, not inferred. On `/status` as
/// `wal_ban_decode_refused`.
static WAL_BAN_DECODE_REFUSED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Read the refused-WAL-Ban counter (see [`WAL_BAN_DECODE_REFUSED`]).
pub fn wal_ban_decode_refused_total() -> u64 {
    WAL_BAN_DECODE_REFUSED.load(std::sync::atomic::Ordering::Relaxed)
}

/// AXIOM Nabla Node — citizen infrastructure for wallet state verification.
pub struct NablaNode {
    smt: SparseMerkleTree,
    wal: WriteAheadLog,
    snapshots: SnapshotManager,
    bans: BanTable,
    gossip: GossipEngine,
    /// YPX-002 P5 — per-variant gossip age instrumentation. Observed on
    /// every incoming gossip message in `handle_gossip`, exposed via
    /// `gossip_latency()` for admin HTTP + soak assertions.
    gossip_latency: GossipLatencyStats,
    tardis: Option<TardisNode>,
    mesh: Option<GossipMesh>,
    cc_chain: Option<CcChain>,
    runner_pool: RunnerPool,
    oracle_pool: DailyPoolState,
    /// §17.11 Airdrop Pool — protocol-level counter for genesis claim funding.
    /// New wallets claim 1 AXC from this pool via Nabla registration.
    /// Balance decreases monotonically. Gossip convergence takes minimum.
    airdrop_pool: AirdropPool,
    /// Tier-3 (Community) validator-join subsidy — 200,000 AXC, 400 slots
    /// x 500 (`AXIOM_DESIGN_ValidatorJoin.md` §2). Drain-only with the SAME
    /// semantics as the airdrop pool, so it reuses `AirdropPool` rather than
    /// cloning a near-identical struct: same strict-decrease `set_balance`
    /// invariant, same min-wins gossip convergence, same JUDOON K-curve.
    /// The PoolKind — not the Rust type — is what keeps the pools distinct
    /// on disk and on the wire.
    bootstrap_pool: AirdropPool,
    /// Tier-2 (Foundation) validator-join subsidy — 2,500,000 AXC, 5 slots
    /// x 500,000. Separate kind from `bootstrap_pool` so the two can never
    /// cross-credit, exactly as DevDeed is separate from Deed.
    foundation_bootstrap_pool: AirdropPool,
    /// Contribution emission (`AXIOM_DESIGN_ValidatorEmission.md`): the two
    /// per-group instances of the airdrop gear, rolled per FOB epoch.
    emission: crate::emission::EmissionPools,
    /// KI#191 residual (RULED 2026-09-25) — emission-pool PoolSyncs whose
    /// structural violation escalated to JUDOON probation
    /// (`GossipAction::PoolStructuralViolation`), same rule as every pool.
    /// On `/status` as `emission_structural_violations`; the first soak after
    /// the build must show 0. Cumulative since start, not persisted.
    emission_structural_violations: u64,
    /// YPX-002 §9.1.1a (RULED 2026-09-25) — this node's NBC issuer budget for
    /// the current FOB epoch; snapshotted LAST, restored on boot. The bin's
    /// issuance handler checks `at_cap` before signing and `record`s after.
    nbc_issuance_budget: crate::cc::NbcIssuanceBudget,
    /// FACT class isolation: dev-AXC equivalent of the Airdrop Pool.
    /// `@axiom.internal` claims deduct from here (fixed 1M dev-AXC,
    /// outside the 100M public cap).
    dev_treasury_pool: DevTreasuryPool,
    /// YP §20.8 / §20.11 — DEED fee accumulator. Receives the 10%
    /// slice of every validator fee on receiver's /register; drained
    /// by DEED Group withdrawal (future).
    pub deed_pool: DeedPool,
    /// Per-validator NET earnings — what each validator can claim at
    /// Step 9B withdrawal mint after the DEED tax. Populated by
    /// `process_registration` via `compute_deed_split`. Separate from
    /// Lambda's GROSS `validator_earned` ledger; see
    /// `docs/AXIOM_DESIGN_DeedDistribution.md` §7.
    pub validator_net_ledger: ValidatorNetLedger,

    /// Dev-class DEED pool — receives the 10% slice from
    /// `@axiom.internal` TXs. Type-distinct from `DeedPool` so any
    /// cross-credit (dev → public, public → dev) is a compile error.
    /// Withdrawal mint reads which pool an entry came from and gates
    /// mint type to dev-AXC. See
    /// `AXIOM_DESIGN_FactClassIsolation.md` + the leak-boundary
    /// commit 2026-06-05.
    pub dev_deed_pool: DevDeedPool,

    /// Dev-class per-validator NET ledger. Validator-withdrawal
    /// mint path reads this AND `validator_net_ledger` separately;
    /// dev-NET → dev-AXC mint; public-NET → public-AXC mint;
    /// never crosses. The type system enforces this — passing one
    /// where the other is expected won't compile.
    pub validator_dev_net_ledger: ValidatorDevNetLedger,

    /// FOB (Fixed Outflow Balance) per-validator Fee pools, keyed by
    /// `(validator_id, is_dev)` — the class rides in the KEY (§10.2a), so dev
    /// and real funds live in the same map, same codepath, differing only by
    /// this bit. Two-state (EMPTY/FULL), funded by a §4 tranche of the
    /// class-filtered convergent accumulator (`validator_earnings_by_class` →
    /// `fob::fob_net_earned`). Persisted to `fob_pools.cbor` — `tranched_total`
    /// is the durable debit-cursor and MUST survive restart or a re-tranche
    /// double-counts. See `docs/AXIOM_DESIGN_BoundedPools.md`.
    pub fob_pools: std::collections::HashMap<([u8; 32], bool), crate::fob::FobPool>,
    /// §10.0 — consume-once record of FOB claim registrations:
    /// claim-tx hash → (validator_id, is_dev, swept amount). Written at
    /// register (verify #1 + sweep), read at cheque-claim (verify #2) and by
    /// the double-claim refusal. Persisted to `fob_claims.cbor`.
    pub fob_claims: std::collections::HashMap<crate::types::TxHash, ([u8; 32], bool, u64)>,
    /// ForkSettlement §9r (F-6 path 11, owner ruling 2026-10-02) — REDEEM fee
    /// credits (validator slots + DEED slice) PARKED because the redeemed
    /// cheque is not `Ok` in THIS node's provenance: cheque txid → credit.
    /// Released (credited ONCE) by `release_held_fee_credits` when the cheque
    /// judges `Ok`; a cheque that stays held (burned) never releases.
    /// Persisted to `held_fee_credits.cbor` with the pools (a restart must not
    /// forget an honest validator's fee). `/status fee_credits_held`.
    pub held_fee_credits: std::collections::BTreeMap<crate::types::TxHash, crate::registration::FeeCredit>,
    /// Cumulative — redeem fee credits parked / released (`/status`).
    fee_credits_parked: u64,
    fee_credits_released: u64,
    /// §6b.4(4) — consume-once record of VBC registrations, PER PRESENTER:
    /// `vbc_hash` → (stake wallet pk, stamp tick, stamped balance). The owner,
    /// 2026-09-08: *"our protocol is async, so a timeout shouldn't render the
    /// registration fail — the harness should retry it."* So the OWNER
    /// re-presenting the same certificate gets the SAME stamp back (the stored
    /// tick + balance re-sign to identical bytes; Ed25519 is deterministic),
    /// and only a DIFFERENT presenter is refused `CONSUMED`. Node-local and
    /// persisted to `vbc_registrations.cbor` (the `fob_claims` pattern) —
    /// (ONE stamp per stake wallet — ValidatorJoin §6b.10). ~~mesh-wide
    /// propagation is NOT built (handoff §13)~~ — stale since KI#170 (the
    /// registry AE); since ForkSettlement wave 4a (R42/R50) it is the
    /// SELF-PROVING witness directory: only `vbc_directory::admit`-verified
    /// entries enter (by type), and AE pages by signed per-entry diff.
    pub vbc_registrations: crate::vbc_directory::VbcDirectory,
    /// KI#84 — the PLUS ledger: every committee-applied tranche keyed by
    /// `(epoch, validator_id, is_dev)` → amount. The MINUS ledger is
    /// `fob_claims`. A pool's state is DERIVED from these two replicated sets:
    /// `balance = Σplus − Σminus`, so a reset/behind node rebuilds it exactly by
    /// set-union AE (`fob_ae_*`) — no local-only cursor to diverge. Persisted to
    /// `fob_tranches.cbor`. NOT pruned: these two sets ARE the source of truth
    /// (like the §19.6 fee ledger); a snapshot bound is a follow-up.
    pub fob_applied_tranches:
        std::collections::HashMap<(u64, [u8; 32], bool), u64>,
    /// KI#84 conservation guard — count of ledger facts REFUSED because they
    /// broke `Σminus ≤ Σplus` (a claim withdrawing more than was ever tranched
    /// = an atom-creation attempt). Refused facts are never stored (a node must
    /// not store what it would reject). Runtime counter, /status observability.
    pub fob_conservation_rejects: u64,
    /// Verified FOB tranche credits per epoch (`epoch → {(validator_id, is_dev)
    /// → amount}`), populated when this node judges a `FobTranche` statement
    /// (§4/§5). The PoolSync BoundedFee arm consults these to authorise an
    /// increase (§7). Runtime-only — NOT persisted: statements re-gossip and
    /// re-judge on restart, and a stale credit is harmless (the arm only ever
    /// ADOPTS a matching increase). Bounded by pruning old epochs.
    pub fob_credits:
        std::collections::HashMap<u64, std::collections::HashMap<([u8; 32], bool), u64>>,
    /// Layer 4 Quarantine state (PoolCaps design §5.6). Tracks
    /// pending alerts (rolling 10-tick window) and active mesh-wide
    /// quarantines (50-tick TTL each). Swept once per tick.
    quarantine: QuarantineState,
    current_tick: u64,
    deed_collected: u64,
    /// YPX-011: Permanent FACT #0 payload (serialized GenesisFact)
    genesis_fact_payload: Option<Vec<u8>>,
    data_dir: PathBuf,
    /// CC restored from snapshot — picked up by init_cc() so penguin score survives restart.
    restored_cc: Option<CompanionCertificate>,
    /// KI#32: verified peer NBCs, kept in sync by nabla_node.rs (`set_peer_nbcs`)
    /// so `take_snapshot` persists them. Lets a restarting node restore a warm
    /// NBC cache instead of dropping PoolSync while Hello re-exchange repopulates.
    peer_nbcs: Vec<NBC>,
    /// Peer NBCs restored from the last snapshot — consumed once by nabla_node.rs
    /// on boot to seed `verified_nbcs` (mirrors `restored_cc`).
    restored_peer_nbcs: Vec<NBC>,
    last_snapshot_tick: u64,
    /// KI#43a — was the boot WAL replay CLEAN (reached EOF at an entry
    /// boundary, all checksums good)? A clean replay is the continuity proof
    /// that lets the exact consumed-state store treat this restart as NOT a
    /// recording gap. Torn tail / checksum stop ⇒ false ⇒ gap (fail-closed).
    wal_replay_clean: bool,
    start_time: std::time::SystemTime,
    /// Cryptographic signer — interface to Core.
    ///
    /// Stored as `Arc<dyn Signer>` (not `Box<dyn Signer>`) so the `/clara`
    /// HTTP handler — and any future hot-path that needs to sign without
    /// holding the global node lock — can `Arc::clone` the signer cheaply
    /// inside the lock and run `signer.sign(..)` *outside* the lock. The
    /// `Signer` trait already requires `Send + Sync`, so the Arc is safe
    /// to share across threads. Constructors still take `Box<dyn Signer>`
    /// for callsite ergonomics; the conversion happens internally via
    /// `Arc::from(box_signer)`. See audit pass #2 finding 3, beta6.
    signer: Arc<dyn Signer>,
    /// ForkSettlement §2.3 — verified A1 claims that banned ≥1 new key, already
    /// WAL-logged by `drain_fork_side_effects`, waiting for the binary to flood
    /// them to `mesh.forward_targets` (as `GossipMessage::ForkBan`, appended
    /// LAST). In-memory: a claim lost here is re-derived from the
    /// origin records at the next load [R28].
    pending_fork_floods: Vec<ForkClaim>,
    /// ForkSettlement [R18] — where the next AE page of fork bans starts when
    /// this node holds more than `ban::AE_FORK_BANS_MAX` (`ae_fork_bans_out`).
    /// In-memory; a restart just starts the rotation over.
    ae_fork_ban_cursor: usize,
    /// [R28] — claims the load-time detector re-derived from the persisted
    /// origin records that banned ≥1 key the node no longer held banned
    /// (cumulative since start). On `/status` (`origin_fork_bans_rederived_at_load`).
    origin_fork_bans_rederived_at_load: u64,
    /// Fork Settlement §9o [R57] (W3) — AE entries whose NON-`Normal` status was
    /// DISCARDED before the merge (`apply_remote_entry`): the leaf status is a
    /// LOCAL projection, never adopted from a peer (KI#236). Cumulative, not
    /// persisted. On `/status` (`ae_status_discarded`). Non-zero is expected
    /// wherever a peer holds a local hold this node does not (and is what a
    /// forged status push looks like).
    ae_status_discarded: u64,
    /// Fork Settlement §9o [R57] (W3) — leaves restored at `open` whose status
    /// this node cannot back: `Banned` with no BanTable entry, plus every
    /// `Frozen` / `Tainted` (held from before a restart — possibly adopted
    /// from a peer before W3). COUNTED ONLY, nothing is changed (a persisted
    /// hold is not re-judged at load). On `/status` (`status_unbacked_at_load`).
    status_unbacked_at_load: u64,
    /// The ONE Nabla ban file (`ban::NABLA_BAN_FILE`, the owner 2026-09-29): the
    /// ban-table size last written to it. `None` = not yet written (open writes
    /// it once, even empty, so a present file means "this node's list", an
    /// absent one "no Nabla here"). Bans are permanent and insert-only, so the
    /// file content changes iff the size does. A failed write leaves this
    /// unchanged, so the next drain retries.
    ban_file_len: Option<usize>,
    /// Ban-file writes that failed (RULE 3 §2). On `/status` as
    /// `ban_file_write_failed`. Cumulative, not persisted.
    ban_file_write_failed: u64,
    /// ForkSettlement §2.4 — txid attestations whose origin this node VOUCHED
    /// (`origin_vouch` returned `Some`), cumulative. Atomic because the
    /// attestation signer holds `&self` (`query_txid_core`). On `/status`.
    origin_attest_vouched: std::sync::atomic::AtomicU64,
    /// …and those it WITHHELD (`origin = None`, tick 0): no record, not yet
    /// listening, re-derivation queued, or the DERIVED provenance is not OK
    /// (contested, key forked, ancestry held or ungrounded). On `/status`.
    origin_attest_withheld: std::sync::atomic::AtomicU64,
    /// ForkSettlement §9p — the subset of `origin_attest_withheld` signed
    /// `OriginVouchStatus::Held`. On `/status`.
    origin_attest_held: std::sync::atomic::AtomicU64,
    /// Fork Settlement W7c/W7d — the derived provenance verdicts behind
    /// `origin_vouch` and `RegistrationAck.provenance`. In-memory only (plan
    /// C6): re-derived from the records at `open`, before listening.
    provenance: crate::provenance::Provenance,
    /// Fork Settlement §9o [R58] (W1) — the R48 RECORD TRIE: one leaf per
    /// GRADED record (every witness an R42 directory witness HERE —
    /// `ban::leg_is_directory_witnessed`). Fed by `drain_fork_side_effects`
    /// (every record created or upgraded), re-graded when the directory admits
    /// an entry (`on_directory_admitted`), rebuilt from the ledgers in `open`
    /// before listening. In-memory only.
    record_trie: crate::record_sync::RecordTrie,
    /// Records held but NOT graded here (a witness not in the directory) —
    /// not leaves, never shipped; re-checked on every directory admission.
    record_ungraded: std::collections::BTreeSet<(crate::smt::OriginKey, crate::smt::LegRef)>,
    /// Fork Settlement §9o [R59] (W1) — record-AE: R50 guard, descents (≤ 1 in
    /// flight per peer), the R51 walk, the global cap and the counters.
    record_ae: crate::record_sync::RecordAeSession,
}

/// What a node vouches for inside its txid attestation (ForkSettlement §2.4 /
/// §3.2). `origin = None, registered_at_secs = 0` is the honest "I do not
/// vouch" — Core's `fact::origin_settled_link` reads it as NOT settled — and
/// `status` (ForkSettlement §9p, SIGNED) says WHY: `Held` or `Unknown`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginVouch {
    pub origin: Option<axiom_core_logic::types::OriginRecord>,
    /// `max(record.first_seen_secs, node_boot_secs)` — wall-clock seconds of
    /// THIS node (the Core field is named `sender_registered_at_tick`; it
    /// carries seconds, plan A20). Nabla applies NO settle floor: Core does.
    pub registered_at_secs: u64,
    /// ForkSettlement §9p — `Vouched` iff `origin` is `Some` (Core's
    /// consistency rule `fact::txid_attestation_origin_consistent`), else
    /// `Held` / `Unknown`. Signed into the attestation by
    /// `NablaNode::sign_txid_attestation`.
    pub status: axiom_core_logic::types::OriginVouchStatus,
}

impl OriginVouch {
    /// "Not judgeable here / wait" — signed `Unknown`.
    pub const NONE: OriginVouch = OriginVouch {
        origin: None,
        registered_at_secs: 0,
        status: axiom_core_logic::types::OriginVouchStatus::Unknown,
    };
    /// "Descends from a fork or a held receive in my records" — signed `Held`.
    pub const HELD: OriginVouch = OriginVouch {
        origin: None,
        registered_at_secs: 0,
        status: axiom_core_logic::types::OriginVouchStatus::Held,
    };
}

/// A signed txid attestation's origin half — what `query_txid_core` ships.
#[derive(Debug, Clone)]
pub struct SignedTxidAttestation {
    pub vouch: OriginVouch,
    /// ForkSettlement §9h [R53] — the node's OWN OODS reading at signing time,
    /// SIGNED (the caller's reading, copied 1:1 into `QueryTxidResponse`).
    pub oods: OodsReading,
    /// The node's Ed25519 signature over `BLAKE3(txid_attest_payload(txid,
    /// status, nabla_secs, origin, registered_at_secs, oods_size,
    /// oods_healthy, vouch.status))` — Core's ONE builder.
    pub signature: Vec<u8>,
}

/// ForkSettlement §9h [R53] — a node's own OODS reading at one instant: its
/// live network-size estimate and whether that is HEALTHY against its own NBC
/// baseline (`validation::oods_healthy`: `size·3 ≥ baseline`, YPX-021; a
/// baseline-0 NBC reads healthy — R53a, deliberately not special-cased). The
/// binary measures it (`NablaNodeState::current_oods_reading`, from the SAME
/// estimate its `OodsReadingRequest` handler serves) and passes it in, as it
/// passes `now_secs` — the lib has no peer-id view of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OodsReading {
    pub size: u32,
    pub healthy: bool,
}

impl NablaNode {
    /// Create a new Nabla node, or recover from existing state.
    ///
    /// Recovery: load last snapshot → replay WAL entries after snapshot.
    pub fn open(data_dir: impl AsRef<Path>, signer: Box<dyn Signer>) -> Result<Self, NablaError> {
        Self::open_with_txid_mode(data_dir, signer, crate::bloom::TxidServiceMode::Bloom)
    }

    /// Open with explicit txid service mode (YPX-014).
    pub fn open_with_txid_mode(
        data_dir: impl AsRef<Path>,
        signer: Box<dyn Signer>,
        txid_mode: crate::bloom::TxidServiceMode,
    ) -> Result<Self, NablaError> {
        Self::open_with_options(data_dir, signer, txid_mode, false)
    }

    pub fn open_with_options(
        data_dir: impl AsRef<Path>,
        signer: Box<dyn Signer>,
        txid_mode: crate::bloom::TxidServiceMode,
        dev_mode: bool,
    ) -> Result<Self, NablaError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| NablaError::WalError(format!("create data dir: {e}")))?;

        let wal_path = data_dir.join("nabla.wal");
        let snap_dir = data_dir.join("snapshots");

        let mut smt = SparseMerkleTree::with_txid_mode(txid_mode);
        // KI#43a — hashmap nodes turn the exact-record event buffer on BEFORE
        // snapshot restore + WAL replay, so replayed head-advances re-derive
        // their consumed marks into the buffer. This is what lets a CLEAN
        // restart not count as a recording gap: the WAL is the continuity
        // proof, and the boot drain rebuilds the era file from it (duplicates
        // with already-persisted marks are harmless — membership semantics).
        // The snapshot's one-put-per-wallet restore produces no marks (no
        // prior head), which is correct: heads are not consumptions.
        if txid_mode == crate::bloom::TxidServiceMode::Hashmap {
            smt.enable_exact_recording();
        }
        let mut bans = if dev_mode { BanTable::new_dev() } else { BanTable::new() };
        let mut deed_collected = 0u64;
        let mut current_tick = 0u64;
        let mut last_snapshot_tick = 0u64;
        let mut restored_cc: Option<CompanionCertificate> = None;
        let mut restored_genesis_fact: Option<Vec<u8>> = None;
        let mut restored_peer_nbcs: Vec<NBC> = Vec::new();
        // GUIDE §5.6c "Persistence" (KI#75) — the JUDOON quarantine set.
        let mut restored_quarantine: (Vec<(NodeId, u64)>, Vec<(NodeId, u64)>) = (Vec::new(), Vec::new());
        let mut restored_nbc_issuance_budget = crate::cc::NbcIssuanceBudget::default();

        // 1. Load last snapshot
        let snapshots = SnapshotManager::new(&snap_dir)?;
        if let Some(snapshot) = snapshots.load_latest()? {
            log::info!(
                "Restoring from snapshot: tick={}, entries={}, bans={}",
                snapshot.tick, snapshot.entries.len(), snapshot.bans.len()
            );
            for entry in &snapshot.entries {
                // §5.2.4: snapshot restore into an empty SMT — the retained
                // proofs come back in bulk via `restore_seq_proofs` below
                // (KI#38), so each entry restores with None here.
                smt.put_with_proof(
                    entry,
                    crate::smt::PutProof::RestoredFromLocalState(None),
                );
            }
            // YP §19.6 — replay per-tx records into the hashmap-mode SMT.
            // `record_tx_meta` is a no-op on bloom-mode SMTs (defensive guard),
            // so loading a hashmap-mode snapshot into a bloom-mode boot just
            // skips the records (matches the snapshot author's storage tier).
            for (tx_hash, record) in &snapshot.tx_records {
                smt.record_tx_meta(*tx_hash, record.clone());
            }
            bans.load_from(snapshot.bans);
            deed_collected = snapshot.deed_collected;
            current_tick = snapshot.tick;
            last_snapshot_tick = snapshot.tick;
            restored_cc = snapshot.latest_cc;
            restored_genesis_fact = snapshot.genesis_fact_payload;
            restored_peer_nbcs = snapshot.peer_nbcs;
            // YPX-022 §5 — restore the exact txid terminals. A restart must
            // never forget a recall (or a redeem, or the completion base the
            // recall window reads).
            smt.restore_terminal_ledgers(
                snapshot.completed_txids,
                snapshot.redeemed_txids,
                snapshot.recalled_txids,
            );
            // KI#38 — restore retained seq proofs so the node can attest its
            // held heads over anti-entropy immediately after boot.
            smt.restore_seq_proofs(snapshot.seq_proofs);
            // ForkSettlement §2.4 Q5 [R27] — the origin ledger, VERBATIM
            // (`first_seen_secs` and `contested` are never recomputed). The
            // [R28] detector re-runs over it below.
            for (tx_hash, entry) in snapshot.origin_ledger {
                smt.restore_origin_entry(tx_hash, entry);
            }
            // Fork Settlement W7b (spec R52c) — the redeem ledger, VERBATIM
            // under the same [R27] rules, into its OWN map (never an origin).
            for (id, entry) in snapshot.redeem_ledger {
                smt.restore_redeem_entry(id, entry);
            }
            // YPX-022 §2.1.2a (KI#205) — restore the authenticated claims (the
            // delivery terminal `register_recall` reads). First-wins merge.
            smt.restore_cheque_claims(snapshot.cheque_claims);
            // GUIDE §5.6c "Persistence" (KI#75) — until this field a restart
            // silently lifted every JUDOON quarantine.
            restored_quarantine = (snapshot.quarantine_active, snapshot.quarantine_cooldown);
            // YPX-002 §9.1.1a — the issuer budget survives a restart.
            restored_nbc_issuance_budget = snapshot.nbc_issuance_budget;
        }

        // 2. Replay WAL after snapshot
        let (mut wal_ops, wal_replay_clean, marker_found) =
            WriteAheadLog::read_after_snapshot_reporting_marker(&wal_path, last_snapshot_tick)?;
        // KI#78 — the deep-scan recovery (G11) truncates at the clean prefix
        // and REWRITES the file, so a corrupted-then-recovered WAL reads
        // CLEAN here while entries are genuinely missing. The durable marker
        // `truncate_at` wrote is the surviving evidence; OR it in so
        // continuity reads NOT PROVEN on the boot after a truncation. The
        // marker is consumed only after the gap is durably recorded
        // (nabla_node::init_consumed_exact), so a crash mid-boot re-flags
        // rather than forgets.
        let wal_truncated = WriteAheadLog::truncation_marker_present(&wal_path);
        let wal_replay_clean = wal_replay_clean && !wal_truncated;
        if wal_truncated {
            log::warn!(
                "[KI#78] WAL truncation marker present — a corruption recovery \
                 truncated this WAL since the marker was last consumed; \
                 continuity NOT proven, restart counted as a recording gap"
            );
        }
        // KI#73 — fail closed when a snapshot was loaded but its WAL marker was
        // never reached (torn tail, checksum stop, or an undecodable record —
        // e.g. the first boot after the WalOp::Put format gained `seq_proof`).
        // Those ops PREDATE the snapshot, and replay is a raw `put` that does
        // not consult `superseded_by`, so replaying them would overwrite newer
        // snapshot heads with older ones — a silent, mesh-wide rollback.
        if last_snapshot_tick > 0 && !marker_found && !wal_ops.is_empty() {
            log::warn!(
                "WAL replay SKIPPED: snapshot tick {} loaded but its WAL marker was                  not reached ({} op(s) read). Those ops predate the snapshot;                  replaying them would roll heads BACKWARDS. State stands at the                  snapshot; anything committed after it is recovered from peers                  via anti-entropy.",
                last_snapshot_tick, wal_ops.len(),
            );
            wal_ops = Vec::new();
        }
        if !wal_ops.is_empty() {
            log::info!("Replaying {} WAL entries after tick {}", wal_ops.len(), last_snapshot_tick);
        }
        if !wal_replay_clean {
            // KI#43a: a torn WAL tail means the replay does NOT provably cover
            // everything up to the crash — the exact store must treat this
            // restart as a recording gap (fail-closed on completeness).
            log::warn!("WAL replay NOT clean (torn tail / checksum stop) — \
                        exact consumed-state record will count this restart as a gap");
        }
        for op in wal_ops {
            match op {
                WalOp::Put { key: _, value, seq_proof, .. } => {
                    if let Ok(entry) = bincode::deserialize::<NablaEntry>(&value) {
                        if entry.tick > current_tick {
                            current_tick = entry.tick;
                        }
                        // KI#73 / §5.2.4 — the persisted record's proof rides
                        // the SAME call as the head, so the put-then-set
                        // ordering this site used to own by comment is now
                        // structural: `put_with_proof` installs the proof
                        // AFTER the KI#38 lock-step delete, atomically.
                        //
                        // Before KI#73, replay restored the head and NOT the
                        // proof — and worse, deleted the one the snapshot had
                        // just restored. The node came back holding a head it
                        // could not attest, AE refused to serve it forever
                        // (`seq-unattested proof=ABSENT`), and its higher seq
                        // stopped it adopting anyone else's.
                        smt.put_with_proof(
                            &entry,
                            crate::smt::PutProof::RestoredFromLocalState(seq_proof),
                        );
                    }
                }
                WalOp::Ban { wallet_id, evidence } => {
                    // RULE 0 marker (R36, 2026-09-28) — this arm used to read
                    // `if let Ok(banned) = bincode::deserialize(..)` and SKIP an
                    // undecodable record with no log and no count. The wrong
                    // reading: "a Ban that does not decode is noise". The right
                    // one: it is an IRREVERSIBLE verdict this node once reached,
                    // now silently forgotten — exactly what a `BannedEntry`
                    // shape change (ForkSettlement wave 3, `BanEvidence`) does to
                    // every prior-shape record. Decode STRICTLY (trailing bytes
                    // are a refusal, not a mis-read), and make a refusal LOUD +
                    // COUNTED (`wal_ban_decode_refused_total`, RULE 6). A lost
                    // A1 fork ban is re-derived from the origin records at load
                    // [R28] only if both records survived.
                    match crate::ban::decode_banned_entry(&evidence) {
                        Ok(banned) => {
                            // Preserve the ban's ORIGIN on replay: re-ban
                            // through the entry point matching its evidence, so
                            // a post-restart node holds the same irreversible
                            // ban WITH its proof, identical to the
                            // snapshot-restore path (`load_from`).
                            match banned.evidence {
                                crate::types::BanEvidence::LegacyConflict(e1, e2) => {
                                    bans.ban(wallet_id, e1, e2);
                                }
                                crate::types::BanEvidence::SeqFork(sf) => {
                                    bans.ban_seq_fork(wallet_id, sf);
                                }
                                crate::types::BanEvidence::Fork(claim) => {
                                    bans.ban_fork(wallet_id, claim);
                                }
                            }
                        }
                        Err(e) => {
                            WAL_BAN_DECODE_REFUSED
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            log::error!(
                                "[WAL-BAN-REFUSED] wallet {} — a WAL Ban record does not \
                                 decode under this build's BannedEntry shape ({}). The ban \
                                 is NOT restored from this record (a persisted-shape change \
                                 such as ForkSettlement wave 3's BanEvidence, or corruption); \
                                 an A1 fork ban is re-derived from the origin records if both \
                                 survived [R28]. Counted: wal_ban_decode_refused.",
                                hex::encode(&wallet_id[..4]), e,
                            );
                        }
                    }
                }
                WalOp::Snapshot { tick, .. } => {
                    last_snapshot_tick = tick;
                }
                WalOp::CcUpdate { tick: _, cc_bytes } => {
                    if let Ok(cc) = bincode::deserialize::<CompanionCertificate>(&cc_bytes) {
                        restored_cc = Some(cc);
                    }
                }
                WalOp::RecordTx { tx_hash, record } => {
                    // YP §19.6 — replay per-tx record (hashmap mode only;
                    // record_tx_meta no-ops on bloom-mode SMTs).
                    if let Ok(rec) = bincode::deserialize::<crate::types::TxRecord>(&record) {
                        smt.record_tx_meta(tx_hash, rec);
                    }
                }
                // YPX-022 §5 — replay the exact txid terminals (crash window
                // between snapshots). All three are first-wins/monotonic, so
                // replay composes with the snapshot restore above.
                WalOp::TxCompleted { tx_hash, tick } => {
                    smt.mark_txid_completed(&tx_hash, tick);
                }
                WalOp::TxRedeemed { tx_hash } => {
                    smt.mark_txid_redeemed(&tx_hash);
                }
                WalOp::TxRecalled { tx_hash, sender_pk, recall_tick } => {
                    // TxRecalled is appended only for COMMITTED recalls
                    // (reservations are deliberately not durable — a lost
                    // reservation is a harmless idempotent retry, §2.2.1).
                    smt.apply_remote_recall(&tx_hash, &sender_pk, recall_tick, true);
                }
                WalOp::TxBurnResolved { target_tx_hash } => {
                    smt.mark_txid_burn_resolved(&target_tx_hash);
                }
                // ForkSettlement §2.4 [R19, R27] — a VERBATIM restore of the
                // persisted record (the last copy of the same leg wins — a
                // W1 record-AE upgrade re-logs it): NO `put()`, NO `contested` recompute (at
                // replay the parent's consumption is already in the bloom, so
                // `record_verified_leg` here would flip every honest record to
                // contested — R24), NO re-verify (own trusted state). KI#73's
                // "replay SKIPPED" above drops post-snapshot records — fail
                // closed; R48 record-AE (W1) refills them from peers.
                WalOp::OriginRecord { tx_hash, entry } => {
                    smt.restore_origin_entry(tx_hash, entry);
                }
                // Fork Settlement W7b — the redeem record, same rules.
                WalOp::RedeemRecord { id, entry } => {
                    smt.restore_redeem_entry(id, entry);
                }
            }
        }

        let mut wal = WriteAheadLog::open(&wal_path)?;
        // KI#81 — the audit reference is rebuilt from the FILE, always. The
        // snapshot's `wal_checksums` list described the PRE-compact file
        // (take_snapshot captures it before compact() renumbers from 0), so
        // restoring it here handed the audit a reference to a file that no
        // longer existed: the first audit_recent then manufactured
        // "corruption" on a file this very boot had read CLEAN, and the
        // recovery truncated GOOD records — once per restart-under-traffic,
        // on all ten nodes of the 2026-08-08 KI#79 roll. KI#74 fixed the
        // cursor half; this closes the list half. The snapshot field is no
        // longer read (written empty; see take_snapshot).
        wal.rebuild_checksums_from_file()?;

        // Restore pool state from disk if present (per-pool CBOR file).
        // Falls back to the initial-balance constant on a fresh node —
        // no file → caller is bootstrapping; first incoming PoolSync
        // gossip will reconcile to mesh state.
        let airdrop_initial = crate::constants::AIRDROP_POOL_INITIAL_ATOMS;
        let dev_treasury_initial = crate::constants::DEV_TREASURY_POOL_INITIAL_ATOMS;
        let airdrop_pool = match PersistedPoolState::load(
            &data_dir.join(crate::types::PoolKind::Airdrop.state_filename()),
        )
        .map_err(|e| NablaError::SerializationError(format!("airdrop pool restore: {e}")))?
        {
            Some(state) => {
                log::info!(
                    "[POOL-RESTORE] Airdrop: balance={} total_claims={} tick={}",
                    state.balance, state.total_claims, state.tick
                );
                AirdropPool::from_persisted(&state)
            }
            None => AirdropPool::new(airdrop_initial),
        };
        let dev_treasury_pool = match PersistedPoolState::load(
            &data_dir.join(crate::types::PoolKind::DevTreasury.state_filename()),
        )
        .map_err(|e| NablaError::SerializationError(format!("dev treasury pool restore: {e}")))?
        {
            Some(state) => {
                log::info!(
                    "[POOL-RESTORE] DevTreasury: balance={} total_claims={} tick={}",
                    state.balance, state.total_claims, state.tick
                );
                DevTreasuryPool::from_persisted(&state)
            }
            None => DevTreasuryPool::new(dev_treasury_initial),
        };
        // Validator-join subsidy pools. Same restore-or-initialise shape as
        // the airdrop pool: no file means this node is bootstrapping and the
        // first incoming PoolSync reconciles it to mesh state — it does NOT
        // mean the pool is full.
        let bootstrap_pool = match PersistedPoolState::load(
            &data_dir.join(crate::types::PoolKind::Bootstrap.state_filename()),
        )
        .map_err(|e| NablaError::SerializationError(format!("bootstrap pool restore: {e}")))?
        {
            Some(state) => {
                log::info!(
                    "[POOL-RESTORE] Bootstrap: balance={} total_claims={} tick={}",
                    state.balance, state.total_claims, state.tick
                );
                AirdropPool::from_persisted(&state)
                    .with_class_constants(crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS, axiom_core_logic::types::TIER3_CLAIM_ATOMS)
            }
            None => AirdropPool::new(crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS)
                .with_class_constants(crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS, axiom_core_logic::types::TIER3_CLAIM_ATOMS),
        };
        let emission = match crate::emission::PersistedEmissionState::load(
            &data_dir.join(crate::emission::PersistedEmissionState::FILENAME),
        )
        .map_err(|e| NablaError::SerializationError(format!("emission pools restore: {e}")))?
        {
            Some(s) => {
                log::info!("[POOL-RESTORE] Emission: epoch={} v={} n={} drawn={}/{}",
                    s.epoch, s.validators.balance, s.nabla.balance, s.drawn_v, s.drawn_n);
                crate::emission::EmissionPools::from_persisted(&s)
            }
            None => crate::emission::EmissionPools::new_from_registers(
                axiom_denomination::axc(axiom_core_logic::types::POOL_VALIDATOR_EMISSION_AXC),
            ),
        };
        let foundation_bootstrap_pool = match PersistedPoolState::load(
            &data_dir.join(crate::types::PoolKind::FoundationBootstrap.state_filename()),
        )
        .map_err(|e| NablaError::SerializationError(format!("foundation bootstrap pool restore: {e}")))?
        {
            Some(state) => {
                log::info!(
                    "[POOL-RESTORE] FoundationBootstrap: balance={} total_claims={} tick={}",
                    state.balance, state.total_claims, state.tick
                );
                AirdropPool::from_persisted(&state)
                    .with_class_constants(crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS, axiom_core_logic::types::TIER2_CLAIM_ATOMS)
            }
            None => AirdropPool::new(crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS)
                .with_class_constants(crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS, axiom_core_logic::types::TIER2_CLAIM_ATOMS),
        };
        // DEED pool starts at zero — there's no initial balance; it
        // ACCUMULATES over the 10-year collection window. On a fresh
        // node, first incoming PoolSync gossip reconciles to mesh state.
        let deed_pool = match PersistedDeedPoolState::load(
            &data_dir.join(crate::types::PoolKind::Deed.state_filename()),
        )
        .map_err(|e| NablaError::SerializationError(format!("deed pool restore: {e}")))?
        {
            Some(state) => {
                log::info!(
                    "[POOL-RESTORE] Deed: balance={} total_credited={} last_credit_tick={}",
                    state.balance, state.total_credited, state.last_credit_tick,
                );
                DeedPool::from_persisted(&state)
            }
            None => DeedPool::new(),
        };
        let validator_net_ledger = match PersistedValidatorNetLedger::load(
            &data_dir.join("validator_net_ledger.cbor"),
        )
        .map_err(|e| NablaError::SerializationError(format!("validator NET ledger restore: {e}")))?
        {
            Some(state) => {
                log::info!(
                    "[POOL-RESTORE] ValidatorNetLedger: validators={}",
                    state.entries.len(),
                );
                ValidatorNetLedger::from_persisted(&state)
            }
            None => ValidatorNetLedger::new(),
        };
        // Dev-class pools — restored from separate files. Distinct
        // filenames so they NEVER round-trip into the public pool
        // by accident, and the on-disk layout makes the leak
        // boundary explicit on the operator's filesystem.
        let dev_deed_pool = match PersistedDeedPoolState::load(
            &data_dir.join("dev_deed_pool.state"),
        )
        .map_err(|e| NablaError::SerializationError(format!("dev deed pool restore: {e}")))?
        {
            Some(state) => {
                log::info!(
                    "[POOL-RESTORE] DevDeed: balance={} total_credited={}",
                    state.balance, state.total_credited,
                );
                DevDeedPool::from_persisted(&state)
            }
            None => DevDeedPool::new(),
        };
        let validator_dev_net_ledger = match PersistedValidatorNetLedger::load(
            &data_dir.join("validator_dev_net_ledger.cbor"),
        )
        .map_err(|e| NablaError::SerializationError(format!("validator dev NET ledger restore: {e}")))?
        {
            Some(state) => {
                log::info!(
                    "[POOL-RESTORE] ValidatorDevNetLedger: validators={}",
                    state.entries.len(),
                );
                ValidatorDevNetLedger::from_persisted(&state)
            }
            None => ValidatorDevNetLedger::new(),
        };

        // FOB pools — the two-state Fee FOBs. `tranched_total` is the durable
        // debit-cursor against the convergent earnings, so a corrupted file
        // fails LOUDLY at boot (silently opening empty would re-tranche
        // already-moved value — a double-count).
        let fob_pools: std::collections::HashMap<([u8; 32], bool), crate::fob::FobPool> = {
            let path = data_dir.join("fob_pools.cbor");
            match std::fs::read(&path) {
                Ok(bytes) => {
                    // Serialized as a LIST of ((vid, is_dev), pool) — a tuple map
                    // key isn't a portable CBOR map key, so we round-trip a Vec.
                    let list: Vec<(([u8; 32], bool), crate::fob::FobPool)> =
                        ciborium::from_reader(&bytes[..]).map_err(|e| {
                            NablaError::SerializationError(format!("FOB pools restore: {e}"))
                        })?;
                    let map: std::collections::HashMap<([u8; 32], bool), crate::fob::FobPool> =
                        list.into_iter().collect();
                    log::info!("[POOL-RESTORE] FobPools: pools={}", map.len());
                    map
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Default::default(),
                Err(e) => {
                    return Err(NablaError::SerializationError(format!(
                        "FOB pools read: {e}"
                    )))
                }
            }
        };

        log::info!(
            "Nabla node ready: entries={}, bans={}, tick={}, root={:?}",
            smt.len(), bans.len(), current_tick, &smt.root_hash()[..4]
        );

        let mut node = Self {
            fob_pools,
            vbc_registrations: {
                let path = data_dir.join("vbc_registrations.cbor");
                match std::fs::read(&path) {
                    Ok(bytes) => load_vbc_directory_file(&path, &bytes),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Default::default(),
                    Err(e) => {
                        return Err(NablaError::SerializationError(format!("VBC registrations read: {e}")))
                    }
                }
            },
            fob_claims: {
                let path = data_dir.join("fob_claims.cbor");
                match std::fs::read(&path) {
                    Ok(bytes) => {
                        let list: Vec<(crate::types::TxHash, ([u8; 32], bool, u64))> =
                            ciborium::from_reader(&bytes[..]).map_err(|e| {
                                NablaError::SerializationError(format!("FOB claims restore: {e}"))
                            })?;
                        list.into_iter().collect()
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Default::default(),
                    Err(e) => {
                        return Err(NablaError::SerializationError(format!("FOB claims read: {e}")))
                    }
                }
            },
            held_fee_credits: {
                let path = data_dir.join("held_fee_credits.cbor");
                match std::fs::read(&path) {
                    Ok(bytes) => {
                        let list: Vec<(crate::types::TxHash, crate::registration::FeeCredit)> =
                            ciborium::from_reader(&bytes[..]).map_err(|e| {
                                NablaError::SerializationError(format!("held fee credits restore: {e}"))
                            })?;
                        list.into_iter().collect()
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Default::default(),
                    Err(e) => {
                        return Err(NablaError::SerializationError(format!("held fee credits read: {e}")))
                    }
                }
            },
            fee_credits_parked: 0,
            fee_credits_released: 0,
            fob_applied_tranches: {
                let path = data_dir.join("fob_tranches.cbor");
                match std::fs::read(&path) {
                    Ok(bytes) => {
                        let list: Vec<((u64, [u8; 32], bool), u64)> =
                            ciborium::from_reader(&bytes[..]).map_err(|e| {
                                NablaError::SerializationError(format!("FOB tranches restore: {e}"))
                            })?;
                        list.into_iter().collect()
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Default::default(),
                    Err(e) => {
                        return Err(NablaError::SerializationError(format!("FOB tranches read: {e}")))
                    }
                }
            },
            fob_conservation_rejects: 0,
            fob_credits: std::collections::HashMap::new(),
            smt, wal, snapshots, bans,
            gossip: GossipEngine::new(),
            gossip_latency: GossipLatencyStats::new(),
            tardis: None,
            mesh: None,
            cc_chain: None,
            runner_pool: RunnerPool::new(),
            oracle_pool: DailyPoolState::new(),
            airdrop_pool,
            dev_treasury_pool,
            bootstrap_pool,
            foundation_bootstrap_pool,
            emission,
            emission_structural_violations: 0,
            nbc_issuance_budget: restored_nbc_issuance_budget,
            deed_pool,
            validator_net_ledger,
            dev_deed_pool,
            validator_dev_net_ledger,
            quarantine: QuarantineState::new(),
            current_tick, deed_collected, data_dir, last_snapshot_tick,
            wal_replay_clean,
            genesis_fact_payload: restored_genesis_fact,
            start_time: std::time::SystemTime::now(),
            // Convert the constructor's `Box<dyn Signer>` to `Arc<dyn Signer>`
            // so the /clara handler can clone the signer cheaply and sign
            // outside the global node lock. `Arc::from(Box<T>)` is the std
            // conversion (one allocation, no copy).
            signer: Arc::from(signer),
            restored_cc,
            peer_nbcs: Vec::new(),
            restored_peer_nbcs,
            pending_fork_floods: Vec::new(),
            ae_fork_ban_cursor: 0,
            origin_fork_bans_rederived_at_load: 0,
            ae_status_discarded: 0,
            status_unbacked_at_load: 0,
            ban_file_len: None,
            ban_file_write_failed: 0,
            origin_attest_vouched: std::sync::atomic::AtomicU64::new(0),
            origin_attest_withheld: std::sync::atomic::AtomicU64::new(0),
            origin_attest_held: std::sync::atomic::AtomicU64::new(0),
            provenance: crate::provenance::Provenance::default(),
            record_trie: crate::record_sync::RecordTrie::new(),
            record_ungraded: std::collections::BTreeSet::new(),
            record_ae: crate::record_sync::RecordAeSession::default(),
        };
        // KI#84 — pools are DERIVED from the two ledgers, so the persisted
        // `fob_pools.cbor` cursor is superseded: rebuild every pool from
        // (fob_applied_tranches, fob_claims) on load. A node whose ledgers were
        // seeded by AE thus rebuilds the identical pool set.
        node.fob_rebuild_all_pools();
        // GUIDE §5.6c "Persistence" (KI#75) — re-arm the JUDOON quarantine set
        // from the snapshot. Expired entries are dropped on the way in (same
        // rule as `sweep`). The mesh does not exist yet at this point; the
        // mesh-side filter is re-armed in `init_mesh*` from this set.
        let (q_active, q_cooldown) = restored_quarantine;
        let restored_active = q_active.len();
        node.quarantine.restore_entries(q_active, q_cooldown, node.current_tick);
        if restored_active > 0 {
            log::info!(
                "[QUARANTINE-RESTORED] {} persisted quarantine(s) read, {} still active at tick {} \
                 (§5.6c persistence — a restart no longer lifts a quarantine)",
                restored_active, node.quarantine.active_count(), node.current_tick,
            );
        }
        // ForkSettlement §2.3 [R28] — two records under one key IS the claim, so
        // the detector re-runs over the persisted record index at LOAD: a ban
        // lost with a snapshot / an undecodable WAL `Ban` (R36) is re-derived,
        // and a restarted node holding both legs never vouches for either even
        // before AE reaches it. Runs after the WAL replay AND `WriteAheadLog::
        // open`, so the re-derived bans are WAL-logged by the drain.
        node.rederive_fork_bans_at_load();
        // Fork Settlement §9o [R57] (W3) — count (never change) restored leaf
        // statuses this node cannot back with its own evidence. AFTER the R28
        // re-derivation, so a ban it re-derived counts as backed.
        node.status_unbacked_at_load = node.count_status_unbacked();
        // Fork Settlement §9o [R58] (W1) — the record trie is in-memory: build
        // it from every restored record (graded ones become leaves) before
        // `recv_loop` can answer a record-AE ask.
        node.rebuild_record_trie();
        // Fork Settlement W7c (plan §2 "Persistence: none") — every restored
        // record was queued by its restore; derive them ALL now, unbudgeted,
        // before `recv_loop` is live (the binary's `boot_secs` is `None`
        // until then, so nothing is vouched meanwhile either).
        node.provenance_drain(None);
        node.drain_fork_side_effects();
        Ok(node)
    }

    /// [R28] — re-run the record-keyed fork detector over the SHARED index
    /// (send AND redeem records, W7b): for every `(pk, consumed)` key holding
    /// ≥ 2 legs, the two LOWEST legs form a `ForkClaim`, which goes through the
    /// ONE verdict path (`ban::apply_fork_verdict` — re-verified, never trusted
    /// because it is local). A contested-only key opens nothing (contested ≠
    /// claim, R23). Returns how many claims banned ≥1 new key.
    pub fn rederive_fork_bans_at_load(&mut self) -> u64 {
        let mut rederived = 0u64;
        for key in self.smt.origin_conflicting_keys() {
            let members = self.smt.legs_under(&key);
            let legs: Vec<ForkLeg> = members
                .iter()
                .take(2)
                .filter_map(|m| self.smt.leg_record(&key, m).map(|e| e.leg.clone()))
                .collect();
            let [a, b] = <[ForkLeg; 2]>::try_from(legs).expect(
                "origin_conflicting_keys yields keys with >= 2 indexed legs, each in a ledger",
            );
            let claim = ForkClaim { a, b };
            match crate::ban::apply_fork_verdict(&mut self.smt, &mut self.bans, &claim) {
                Ok(newly) if !newly.is_empty() => {
                    rederived += 1;
                    log::warn!(
                        "[FORK-REDERIVED-AT-LOAD] key pk={} consumed={} — {} leg(s) under one \
                         parent; re-banned {} key(s) from the persisted records [R28]",
                        hex::encode(&key.0[..4]), hex::encode(&key.1[..4]),
                        members.len(), newly.len(),
                    );
                }
                Ok(_) => {}
                Err(why) => log::error!(
                    "[FORK-REDERIVE-REFUSED] key pk={} consumed={} — two persisted records \
                     under one key do not verify as a claim ({}); counted \
                     atraxi_evidence_refused",
                    hex::encode(&key.0[..4]), hex::encode(&key.1[..4]), why,
                ),
            }
        }
        self.origin_fork_bans_rederived_at_load =
            self.origin_fork_bans_rederived_at_load.saturating_add(rederived);
        rederived
    }

    /// See the `origin_fork_bans_rederived_at_load` field.
    pub fn origin_fork_bans_rederived_at_load(&self) -> u64 {
        self.origin_fork_bans_rederived_at_load
    }

    /// Fork Settlement §9o [R57] — leaves whose status this node cannot back:
    /// `Banned` without a BanTable entry, plus every `Frozen` / `Tainted`.
    /// Pure count (read-only); `open` stores it as `status_unbacked_at_load`.
    fn count_status_unbacked(&self) -> u64 {
        let (mut banned_unbacked, mut frozen, mut tainted) = (0u64, 0u64, 0u64);
        for (wid, e) in self.smt.entries() {
            match e.status {
                WalletStatus::Normal => {}
                WalletStatus::Banned => {
                    if !self.bans.is_banned(wid) {
                        banned_unbacked += 1;
                    }
                }
                WalletStatus::Frozen => frozen += 1,
                WalletStatus::Tainted => tainted += 1,
            }
        }
        let total = banned_unbacked + frozen + tainted;
        if total > 0 {
            log::warn!(
                "[STATUS-UNBACKED-AT-LOAD] {total} restored leaf status(es) this node cannot \
                 back with its own evidence (Banned without a BanTable entry: {banned_unbacked}, \
                 Frozen: {frozen}, Tainted: {tainted}) — counted, NOT changed \
                 (ForkSettlement §9o [R57])"
            );
        }
        total
    }

    /// See the `ae_status_discarded` field.
    pub fn ae_status_discarded(&self) -> u64 {
        self.ae_status_discarded
    }

    /// See the `status_unbacked_at_load` field.
    pub fn status_unbacked_at_load(&self) -> u64 {
        self.status_unbacked_at_load
    }

    /// The ONE emission + WAL path for every A1 side effect (ForkSettlement
    /// §2.3): (1) every origin record created (or, W1, upgraded) since the
    /// last drain is appended as `WalOp::OriginRecord` [R19] and every redeem
    /// record as `WalOp::RedeemRecord` (W7b), and fed to the R48 record trie
    /// (a leaf iff graded, §9o [R58]); (2) every verified claim that banned ≥1
    /// new key has each of THOSE bans appended as `WalOp::Ban` and is queued
    /// for the binary's flood (`take_pending_fork_floods`); (3) rewrites the
    /// ONE Nabla ban file when the ban table grew (`write_ban_file_if_changed`).
    ///
    /// Called at the end of `open` (the R28 re-derivation), `register` (Ok AND
    /// Err paths — a refused leg is still recorded, R30), `handle_gossip` and
    /// `apply_remote_entry` (every return path).
    pub fn drain_fork_side_effects(&mut self) {
        // Fork Settlement W7c/W7d (M3) — derive every leg recorded since the
        // last drain, and cascade retroactively, under a visit budget. The
        // remainder drains on the next call (the binary's `fork_ban_fanout`
        // calls this after every handled message and once per tick); until the
        // queue is empty `origin_vouch` vouches NOTHING (fail closed).
        self.provenance_drain(Some(crate::provenance::CASCADE_BUDGET));
        self.release_held_fee_credits();
        for (tx_hash, entry) in self.smt.take_origin_wal_pending() {
            // W1 (§9o [R58]) — every record created or upgraded feeds the trie.
            self.record_trie_feed(entry.leg.key(), crate::smt::LegRef::Send(tx_hash), &entry.leg);
            if let Err(e) = self.wal.append(&WalOp::OriginRecord { tx_hash, entry }) {
                log::error!(
                    "[ORIGIN-WAL-FAILED] tx {} — origin record not WAL-logged ({}); it \
                     survives only until the next snapshot",
                    hex::encode(&tx_hash[..4]), e,
                );
            }
        }
        // Fork Settlement W7b — every redeem record created since the last
        // drain, as its own op (never an `OriginRecord`, R5).
        for (id, entry) in self.smt.take_redeem_wal_pending() {
            self.record_trie_feed(id.0, crate::smt::LegRef::Redeem(id.1), &entry.leg);
            if let Err(e) = self.wal.append(&WalOp::RedeemRecord { id, entry }) {
                log::error!(
                    "[REDEEM-WAL-FAILED] cheque {} — redeem record not WAL-logged ({}); it \
                     survives only until the next snapshot",
                    hex::encode(&id.1[..4]), e,
                );
            }
        }
        for claim in self.bans.take_pending_fork_floods() {
            for key in crate::ban::fork_ban_keys(&claim) {
                let Some(entry) = self.bans.get(&key) else { continue };
                // Only the bans THIS claim made (a key banned earlier on other
                // evidence was WAL-logged when that ban was made).
                if !matches!(&entry.evidence, BanEvidence::Fork(c) if c == &claim) {
                    continue;
                }
                let logged = bincode::serialize(entry)
                    .map_err(|e| NablaError::SerializationError(e.to_string()))
                    .and_then(|evidence| {
                        self.wal.append(&WalOp::Ban { wallet_id: key, evidence })
                    });
                if let Err(e) = logged {
                    log::error!(
                        "[FORK-BAN-WAL-FAILED] wallet {} — fork ban not WAL-logged ({}); \
                         it is re-derived from the origin records at the next load [R28]",
                        hex::encode(&key[..4]), e,
                    );
                }
            }
            self.pending_fork_floods.push(claim);
        }
        self.write_ban_file_if_changed();
    }

    /// Write the ONE Nabla ban file (`<data_dir>/nabla_bans.txt`,
    /// `BanTable::ban_file_contents`) when the ban table has grown since the
    /// last write — or has never been written (open). Every ban origin (the
    /// door, flood, AE, `ForkBan` adoption, E2 seq-fork, WAL/snapshot load)
    /// passes through a `drain_fork_side_effects` call, which ends here.
    /// Atomic: `<file>.tmp` + `rename(2)`, so a reader never sees a torn list.
    /// Local-disk I/O under the node lock only when the table changed (bans are
    /// rare and permanent), never network.
    fn write_ban_file_if_changed(&mut self) {
        let len = self.bans.len();
        if self.ban_file_len == Some(len) {
            return;
        }
        let path = self.data_dir.join(crate::ban::NABLA_BAN_FILE);
        let tmp = self.data_dir.join(format!("{}.tmp", crate::ban::NABLA_BAN_FILE));
        let written = std::fs::write(&tmp, self.bans.ban_file_contents())
            .and_then(|()| std::fs::rename(&tmp, &path));
        match written {
            Ok(()) => self.ban_file_len = Some(len),
            Err(e) => {
                self.ban_file_write_failed = self.ban_file_write_failed.saturating_add(1);
                log::error!(
                    "[BAN-FILE-WRITE-FAILED] {} — {} ban(s) not written ({}); retried on the \
                     next drain (counted ban_file_write_failed)",
                    path.display(), len, e,
                );
            }
        }
    }

    /// Drain the WAL-logged, verified claims for the binary to flood as
    /// `GossipMessage::ForkBan` — `recv_loop` after each handled message and
    /// `tick_loop` once per iteration (`fork_ban_fanout` in the binary).
    pub fn take_pending_fork_floods(&mut self) -> Vec<ForkClaim> {
        std::mem::take(&mut self.pending_fork_floods)
    }

    /// ForkSettlement §2.3 [R18] — the fork bans this node puts on the NEXT AE
    /// reconcile message it sends (`AeReconcile.fork_bans` /
    /// `AeEntries.fork_bans`): every distinct `ForkClaim` it holds as ban
    /// evidence, at most `ban::AE_FORK_BANS_MAX`; with more, a cursor rotates
    /// the page so every ban reaches the peer within ⌈bans / cap⌉ exchanges.
    pub fn ae_fork_bans_out(&mut self) -> Vec<ForkClaim> {
        let all = self.bans.fork_claims();
        let cap = crate::ban::AE_FORK_BANS_MAX;
        if all.len() <= cap {
            return all;
        }
        let start = self.ae_fork_ban_cursor % all.len();
        self.ae_fork_ban_cursor = (start + cap) % all.len();
        all.iter().cycle().skip(start).take(cap).cloned().collect()
    }

    /// ForkSettlement [R18] — the BRIEF-LOCK half of AE ban screening: for
    /// each carried claim, is every key it names already banned here? Those
    /// are skipped unverified (they could change nothing); the rest are
    /// verified OFF the lock by `ban::screen_ae_fork_bans`. The keys of an
    /// unverified claim are only used to decide what NOT to verify.
    pub fn ae_fork_bans_known(&self, claims: &[ForkClaim]) -> Vec<bool> {
        claims
            .iter()
            .take(crate::ban::AE_FORK_BANS_MAX)
            .map(|c| crate::ban::fork_ban_keys(c).iter().all(|k| self.bans.is_banned(k)))
            .collect()
    }

    /// ForkSettlement [R18] — adopt the fork bans an AE reconcile message
    /// carried, given the off-lock `screen` (`ban::adopt_ae_fork_bans`: the
    /// ONE chokepoint for verified claims, `atraxi_evidence_refused` for the
    /// rest), then WAL + queue the verdicts for the `ForkBan` fan-out. Called
    /// by the binary's `AeReconcile` / `AeEntries` arms AFTER the carried
    /// entries were applied. Returns the claims that banned ≥1 new key.
    pub fn adopt_ae_fork_bans(
        &mut self,
        claims: &[ForkClaim],
        screen: &[crate::ban::AeBanScreen],
        now_secs: u64,
    ) -> usize {
        let n = crate::ban::adopt_ae_fork_bans(&mut self.smt, &mut self.bans, claims, screen, now_secs);
        self.drain_fork_side_effects();
        n
    }

    /// ForkSettlement §9r (F-6 path 11, owner ruling 2026-10-02) — credit every
    /// parked redeem fee whose cheque THIS node now judges `Ok` (the same
    /// `judge_send` the origin vouch reads), exactly once (removed from the
    /// map as it is credited). Fail closed like the vouch: nothing releases
    /// while provenance work is queued. `Held` / `Wait` stay parked — a held
    /// cheque that is never cleared (burned) never credits its fees.
    pub fn release_held_fee_credits(&mut self) {
        if self.held_fee_credits.is_empty() || !self.provenance_idle() {
            return;
        }
        let ready: Vec<crate::types::TxHash> = self.held_fee_credits.keys()
            .filter(|t| matches!(
                self.provenance.judge_send(&self.smt, t),
                crate::provenance::Judgment::Ok { .. }
            ))
            .copied()
            .collect();
        if ready.is_empty() {
            return;
        }
        for t in ready {
            let Some(credit) = self.held_fee_credits.remove(&t) else { continue };
            crate::registration::apply_fee_credit(
                &credit, self.current_tick,
                Some(&mut self.deed_pool), Some(&mut self.validator_net_ledger),
                Some(&mut self.dev_deed_pool), Some(&mut self.validator_dev_net_ledger),
            );
            self.fee_credits_released += 1;
            log::info!(
                "[FEE-CREDIT-RELEASED] cheque={} deed={} slots={} — provenance Ok (§9r F-6 path 11)",
                hex::encode(&t[..8]), credit.deed_atoms, credit.slots.len(),
            );
        }
        if let Err(e) = self.persist_pool_states() {
            log::warn!("[POOL-PERSIST] save after fee-credit release failed: {e}");
        }
    }

    /// W7c/W7d — hand the SMT's queued legs to the provenance engine and drain
    /// up to `budget` visits (`None` = all: the load-time re-derivation). The
    /// R42 directory is the producer-admission witness test.
    pub fn provenance_drain(&mut self, budget: Option<usize>) {
        self.provenance.enqueue(self.smt.take_provenance_pending());
        let dir = &self.vbc_registrations;
        self.provenance.drain(&self.smt, &|pk| dir.is_witness(pk), budget);
    }

    /// W7c — nothing queued for derivation (the vouch's fail-closed gate).
    fn provenance_idle(&self) -> bool {
        self.provenance.dirty_len() == 0 && !self.smt.has_provenance_pending()
    }

    /// W7d — the register ack's `provenance` for `(pk, state)`: the
    /// registrant's new state, read after the register's drain. `Wait` while
    /// anything is queued (fail closed).
    pub fn provenance_view(&self, pk: &[u8; 32], state: &StateId) -> crate::types::ProvenanceView {
        if self.smt.has_provenance_pending() {
            return crate::types::ProvenanceView::Wait;
        }
        self.provenance.view(pk, state)
    }

    /// ForkSettlement §9r F-1(c) (KI#244) — this node's provenance verdict on
    /// the stake wallet's REGISTERED head at `bucket` (`provenance_view` of the
    /// SMT entry's `(client_pk, current_state)` — the same rule as the vouch,
    /// nothing copied: `Wait` while anything is queued). `None` when this node
    /// holds no entry (the §6c genesis DERIVED head, which cannot have received
    /// or sent). Read by `register_vbc_core` step 2c: a stamp — the one Nabla
    /// signature that turns stake into validator power — is signed only on `Ok`.
    pub fn stake_head_provenance(&self, bucket: &WalletId) -> Option<crate::types::ProvenanceView> {
        self.smt.get(bucket).map(|e| self.provenance_view(&e.client_pk, &e.current_state))
    }

    /// The provenance engine (tests / diagnostics).
    pub fn provenance(&self) -> &crate::provenance::Provenance {
        &self.provenance
    }

    /// What THIS node vouches for about `txid`'s origin (ForkSettlement §2.4,
    /// §3.2; Fork Settlement W7c M1, plan §2/§3) — "a registration I verified
    /// whose WHOLE ancestry my own records ground, with no fork and no held
    /// receive in it, while LISTENING". Returns no origin (signed `Held` or
    /// `Unknown` — ForkSettlement §9p, the mapping is on `origin_vouch_inner`)
    /// unless:
    /// 1. `boot_secs` is `Some` — the node is listening (R9; the binary stamps
    ///    it when `recv_loop` goes live and re-floors it after a tick-loop
    ///    stall, R13/R34);
    /// 2. the origin ledger holds a record for `txid`;
    /// 3. no provenance re-derivation is queued (fail closed, M3 — a late fork
    ///    with a large descendant set must not be vouched mid-cascade);
    /// 4. `provenance::Provenance::judge_send` is `Ok` — the record is not
    ///    contested (R16), its `(pk, consumed)` key holds ONE leg (not held —
    ///    the old clause 5, 3-way forks included), and its input state is
    ///    grounded here with no HELD / pending root, transitively to a
    ///    structural root (the opening state or a unique zero-consumed first
    ///    redeem — M2).
    ///
    /// ~~Clause 4 "registrant `client_pk` / bucket banned → NONE"~~ — REMOVED
    /// (W7c, §9k ruling 3, TLA+ c19 `NoFalseHold`). RULE 0 marker — the WRONG
    /// reading it encoded: "a banned wallet's money is all bad". It is not: M,
    /// paid by A from a state BEFORE A's fork, holds good money, and the
    /// clause made M's origin unsettleable forever once A was banned. The
    /// correct reading: the hold is scoped to what DESCENDS from the forked
    /// parent — carried by the `Fork(key)` root on the records, never by the
    /// ban table. (Every ban is a fork key in the index: A1 verdicts record
    /// both legs; the flood's held-head leg mapping records the held head's
    /// leg first — `gossip.rs`. Since §9o [R56] every live ban is an A1
    /// verdict; a legacy `SeqFork` ban only replays.)
    ///
    /// Then `origin = leg.origin_record()` (the preimage Core recomputes the
    /// txid from, [R11]) and `registered_at_secs = max(ancestry ready_at,
    /// first_seen_secs, boot_secs)` — the settle floor runs from the YOUNGEST
    /// ancestor this node saw (c17h), so an honest chain settles at its latest
    /// hop's floor, never before. Nabla applies NO floor — Core's
    /// `origin_settled_link` does (`SCAR_SETTLE_TICKS{,_DEV}`).
    /// Pure reads — safe under the node lock (nothing blocks).
    pub fn origin_vouch(&self, txid: &crate::types::TxHash, boot_secs: Option<u64>) -> OriginVouch {
        use std::sync::atomic::Ordering::Relaxed;
        let v = self.origin_vouch_inner(txid, boot_secs);
        if v.origin.is_some() {
            self.origin_attest_vouched.fetch_add(1, Relaxed);
        } else {
            self.origin_attest_withheld.fetch_add(1, Relaxed);
            if v.status == axiom_core_logic::types::OriginVouchStatus::Held {
                self.origin_attest_held.fetch_add(1, Relaxed);
            }
        }
        v
    }

    /// ForkSettlement §9p — the status mapping (the minimal honest one):
    /// * not listening / no record / re-derivation queued / no origin record /
    ///   `judge_send == Wait` (ungrounded input, contested-not-held) ⇒ `Unknown`
    ///   ([`OriginVouch::NONE`]);
    /// * the record's own `(pk, consumed)` key holds ≥ 2 legs ⇒ `Held`
    ///   ([`OriginVouch::HELD`]) — checked BEFORE the idle and contested gates:
    ///   a fork in the records is structural and permanent (the ledger is
    ///   insert-only; a fork root is unburnable), so no pending derivation and
    ///   no `contested` flag can make it vouchable. `judge_send` answers `Wait`
    ///   for a contested record before looking at its key — without this
    ///   clause a contested fork leg would be signed `Unknown` and its receivers
    ///   told to wait;
    /// * `judge_send == Held` (the input descends from a fork / held receive) ⇒
    ///   `Held`;
    /// * `judge_send == Ok` ⇒ `Vouched` with the origin.
    /// `Held` is liveness only for the receiver's SDK (stop waiting); it
    /// clears nothing — Core settles only on `Vouched` (`fact::
    /// origin_settle_ready_at`).
    fn origin_vouch_inner(&self, txid: &crate::types::TxHash, boot_secs: Option<u64>) -> OriginVouch {
        let Some(boot) = boot_secs else { return OriginVouch::NONE };
        let Some(entry) = self.smt.vouch_record(txid) else { return OriginVouch::NONE };
        if self.smt.legs_under(&entry.leg.key()).len() >= 2 {
            return OriginVouch::HELD;
        }
        if !self.provenance_idle() {
            return OriginVouch::NONE;
        }
        // `origin_record()` is `None` for a redeem leg — unreachable here: the
        // origin ledger holds send legs only (R5).
        let Some(origin) = entry.leg.origin_record() else {
            return OriginVouch::NONE;
        };
        match self.provenance.judge_send(&self.smt, txid) {
            crate::provenance::Judgment::Ok { ready_at } => OriginVouch {
                origin: Some(origin),
                registered_at_secs: ready_at.max(boot),
                status: axiom_core_logic::types::OriginVouchStatus::Vouched,
            },
            crate::provenance::Judgment::Held => OriginVouch::HELD,
            crate::provenance::Judgment::Wait => OriginVouch::NONE,
        }
    }

    /// The txid attestation's signed origin half — the ONE assembly the
    /// binary's `query_txid_core` ships: `origin_vouch`, then the node's
    /// signature over Core's ONE builder `txid_attest_payload(txid, status,
    /// nabla_secs, origin, registered_at_secs, oods, origin_status)` — the
    /// §9p `origin_status` is `vouch.status` (re-exported via
    /// `registration`, Pattern 1). `nabla_secs` is the node's `virtual_secs`
    /// — the SAME clock as `first_seen_secs` (Fable #7).
    ///
    /// `oods` (ForkSettlement §9h [R53], Core W7a): the node's own reading at
    /// signing time, bound into the signature. Core's `origin_settled_link`
    /// refuses to settle on an attestation whose `oods_healthy` is false — an
    /// eclipsed node's vouch is not a settlement, whatever its records say.
    pub fn sign_txid_attestation(
        &self,
        txid: &crate::types::TxHash,
        status: &str,
        nabla_secs: u64,
        boot_secs: Option<u64>,
        oods: OodsReading,
    ) -> SignedTxidAttestation {
        let vouch = self.origin_vouch(txid, boot_secs);
        let hash = blake3::Hash::from(crate::registration::txid_attest_payload(
            txid, status, nabla_secs, vouch.origin.as_ref(), vouch.registered_at_secs,
            oods.size, oods.healthy, vouch.status,
        ));
        let signature = self.signer.sign(hash.as_bytes());
        SignedTxidAttestation { vouch, oods, signature }
    }

    /// Every ForkSettlement wave-3 `/status` counter from the lib side — ONE
    /// builder for both status builders (RULE 1). `boot_secs` /
    /// `boot_refloors` live in the binary (the R13 clock), so the caller
    /// passes them (the lib builder has no listener: `None` / 0).
    pub fn origin_status(&self, boot_secs: Option<u64>, boot_refloors: u64) -> crate::monitor::OriginStatus {
        use std::sync::atomic::Ordering::Relaxed;
        crate::monitor::OriginStatus {
            origin_records: self.smt.origin_len() as u64,
            origin_records_contested: self.smt.origin_contested_len() as u64,
            origin_records_created: self.smt.origin_records_created(),
            redeem_records: self.smt.redeem_len() as u64,
            redeem_records_contested: self.smt.redeem_contested_len() as u64,
            redeem_records_created: self.smt.redeem_records_created(),
            redeem_leg_zero_consumed: self.bans.redeem_leg_zero_consumed(),
            producer_binding_refused: self.bans.producer_binding_refused(),
            wallet_id_key_mismatch: crate::registration::wallet_id_key_mismatch_total(),
            origin_leg_unrecordable: self.bans.origin_leg_unrecordable(),
            origin_fork_claims_detected: self.bans.origin_fork_claims_detected(),
            origin_fork_claims_adopted: self.bans.origin_fork_claims_adopted(),
            fork_claims_applied: self.bans.fork_claims_applied(),
            atraxi_evidence_refused: self.bans.atraxi_evidence_refused(),
            origin_fork_bans_rederived_at_load: self.origin_fork_bans_rederived_at_load,
            origin_attest_vouched: self.origin_attest_vouched.load(Relaxed),
            origin_attest_withheld: self.origin_attest_withheld.load(Relaxed),
            origin_attest_held: self.origin_attest_held.load(Relaxed),
            provenance_states_derived: self.provenance.states_derived(),
            provenance_held_states: self.provenance.held_states(),
            provenance_dirty_queue: self.provenance.dirty_len() as u64,
            fee_credits_held: self.held_fee_credits.len() as u64,
            fee_credits_parked: self.fee_credits_parked,
            fee_credits_released: self.fee_credits_released,
            origin_boot_secs: boot_secs.unwrap_or(0),
            origin_boot_refloors: boot_refloors,
            ban_refused_malformed: self.bans.refused_malformed(),
            wal_ban_decode_refused: wal_ban_decode_refused_total(),
            ban_file_write_failed: self.ban_file_write_failed,
            record_ae_asks_sent: self.record_ae.counters.asks_sent,
            record_ae_answers_sent: self.record_ae.counters.answers_sent,
            record_ae_refused: self.record_ae.counters.refused_total(),
            record_ae_refused_unknown_sender: self.record_ae.counters.refused_unknown_sender,
            record_ae_refused_bad_signature: self.record_ae.counters.refused_bad_signature,
            record_ae_refused_replayed_nonce: self.record_ae.counters.refused_replayed_nonce,
            record_ae_refused_over_budget: self.record_ae.counters.refused_over_budget,
            record_ae_refused_unsolicited: self.record_ae.counters.refused_unsolicited,
            record_ae_refused_oversize: self.record_ae.counters.refused_oversize,
            record_ae_refused_malformed: self.record_ae.counters.refused_malformed,
            record_ae_shed_global: self.record_ae.counters.shed_global,
            record_ae_descents_completed: self.record_ae.counters.descents_completed,
            record_ae_descents_aborted: self.record_ae.counters.descents_aborted,
            record_ae_descents_truncated: self.record_ae.counters.descents_truncated,
            record_ae_legs_received: self.record_ae.counters.legs_received,
            record_ae_legs_refused: self.record_ae.counters.legs_refused,
            record_ae_legs_recorded: self.record_ae.counters.legs_recorded,
            record_ae_legs_ungraded: self.record_ae.counters.legs_ungraded,
            record_ae_legs_unrequested: self.record_ae.counters.legs_unrequested,
            origin_records_upgraded: self.smt.origin_records_upgraded(),
            record_trie_leaves: self.record_trie.len() as u64,
            seqforkban_dropped: self.gossip.seqforkban_dropped(),
            haladvance_dropped: self.gossip.haladvance_dropped(),
            taintalert_dropped: self.gossip.taintalert_dropped(),
            mergeresolved_dropped: self.gossip.mergeresolved_dropped(),
            ae_status_discarded: self.ae_status_discarded,
            status_unbacked_at_load: self.status_unbacked_at_load,
        }
    }

    // ── Fork Settlement §9o [R58/R59] (W1) — R48 record-AE ──────────────────
    //
    // The lib half of record-AE (`record_sync`): the record trie's feed, the
    // descent transitions, the ask/answer handlers. The binary owns only the
    // transport glue (`handle_message` arms, the off-lock `prelock_record_ae`,
    // the tick-driven walk) and passes `me` (its NBC node id), the sender's
    // VERIFIED NBC key and `virtual_secs`. Every function here is pure CPU and
    // bounded (≤ 256 views / ≤ 64 legs per exchange) — safe under the node
    // mutex; leg VERIFICATION is not done here (off the lock, `record_sync::
    // prepare_answer`).

    /// Is `leg` GRADED here — every witness an R42 directory witness at THIS
    /// node (the ONE predicate, `ban::leg_is_directory_witnessed`)?
    pub fn leg_is_graded(&self, leg: &ForkLeg) -> bool {
        let dir = &self.vbc_registrations;
        crate::ban::leg_is_directory_witnessed(leg, &|pk| dir.is_witness(pk))
    }

    /// The record trie (read-only).
    pub fn record_trie(&self) -> &crate::record_sync::RecordTrie {
        &self.record_trie
    }

    /// The record-AE `/status` counters.
    pub fn record_ae_counters(&self) -> &crate::record_sync::RecordAeCounters {
        &self.record_ae.counters
    }

    /// One record created or upgraded: a leaf iff graded, else remembered as
    /// ungraded (re-graded on the next directory admission).
    fn record_trie_feed(&mut self, key: crate::smt::OriginKey, member: crate::smt::LegRef, leg: &ForkLeg) {
        if self.leg_is_graded(leg) {
            self.record_trie.insert(crate::record_sync::LeafKey::of(leg));
            self.record_ungraded.remove(&(key, member));
        } else {
            self.record_ungraded.insert((key, member));
        }
    }

    /// Rebuild the record trie from every held record (called by `open`
    /// before listening, after the directory and the ledgers are restored).
    pub fn rebuild_record_trie(&mut self) {
        let mut trie = crate::record_sync::RecordTrie::new();
        let mut ungraded = std::collections::BTreeSet::new();
        let dir = &self.vbc_registrations;
        for (key, member, e) in self.smt.records() {
            if crate::ban::leg_is_directory_witnessed(&e.leg, &|pk| dir.is_witness(pk)) {
                trie.insert(crate::record_sync::LeafKey::of(&e.leg));
            } else {
                ungraded.insert((key, member));
            }
        }
        self.record_trie = trie;
        self.record_ungraded = ungraded;
    }

    /// The ONE hook every directory admission calls (registration, AE adopt,
    /// test admit): W7c producers that waited on a witness are re-queued, and
    /// (W1) held ungraded records are re-graded into the record trie.
    fn on_directory_admitted(&mut self) {
        self.provenance.requeue_awaiting_directory();
        let dir = &self.vbc_registrations;
        let smt = &self.smt;
        let now_graded: Vec<_> = self
            .record_ungraded
            .iter()
            .filter_map(|(k, m)| {
                smt.leg_record(k, m)
                    .filter(|e| crate::ban::leg_is_directory_witnessed(&e.leg, &|pk| dir.is_witness(pk)))
                    .map(|e| ((*k, *m), crate::record_sync::LeafKey::of(&e.leg)))
            })
            .collect();
        for (id, leaf) in now_graded {
            self.record_trie.insert(leaf);
            self.record_ungraded.remove(&id);
        }
    }

    /// The held leg a leaf key names (it is a leaf ⇒ it is held).
    fn leg_by_leaf(&self, k: &crate::record_sync::LeafKey) -> Option<ForkLeg> {
        use crate::record_sync::{LeafKey, LEAF_KIND_REDEEM, LEAF_KIND_SEND};
        match k.kind {
            LEAF_KIND_SEND => self.smt.vouch_record(&k.txid).map(|e| &e.leg).filter(|l| LeafKey::of(l) == *k).cloned(),
            LEAF_KIND_REDEEM => self
                .smt
                .redeem_records_of_cheque(&k.txid)
                .into_iter()
                .map(|(_, e)| &e.leg)
                .find(|l| LeafKey::of(l) == *k)
                .cloned(),
            _ => None,
        }
    }

    /// R58 — the BOUNDED answer to an (authenticated, admitted) ask: views of
    /// ≤ `RECORD_AE_MAX_PREFIXES_PER_ASK` prefixes, or ≤
    /// `RECORD_AE_MAX_LEGS_PER_ANSWER` legs — only LEAVES (graded legs), never
    /// an ungraded record — and ≤ `RECORD_AE_MAX_ANSWER_BYTES` either way
    /// (≥ 1 item; the asker re-asks the rest).
    pub fn record_ae_answer(&self, ask: &crate::record_sync::Ask) -> crate::record_sync::Answer {
        use crate::constants::{RECORD_AE_MAX_ANSWER_BYTES, RECORD_AE_MAX_LEGS_PER_ANSWER, RECORD_AE_MAX_PREFIXES_PER_ASK};
        use crate::record_sync::{take_within_bytes, Answer, Ask};
        match ask {
            Ask::Nodes(prefixes) => {
                let n = prefixes.len().min(RECORD_AE_MAX_PREFIXES_PER_ASK);
                Answer::Nodes(take_within_bytes(self.record_trie.views(&prefixes[..n]), RECORD_AE_MAX_ANSWER_BYTES))
            }
            Ask::Legs(keys) => {
                let legs: Vec<ForkLeg> = keys
                    .iter()
                    .take(RECORD_AE_MAX_LEGS_PER_ANSWER)
                    .filter(|k| self.record_trie.contains(k))
                    .filter_map(|k| self.leg_by_leaf(k))
                    .collect();
                Answer::Legs(take_within_bytes(legs, RECORD_AE_MAX_ANSWER_BYTES))
            }
        }
    }

    /// R59 — the RESPONDER: refuse (counted, by kind) an ask that is over a
    /// bound or malformed → not signed by `from`'s verified NBC key
    /// (`sender_pk`, `None` = unknown sender) → a replayed nonce / over the
    /// per-`from` budget; shed (counted `record_ae_shed_global`) past the
    /// global answers-per-window cap; else the SIGNED, bounded answer. The
    /// caller addresses it to `peer_by_id(from)` ONLY.
    #[allow(clippy::too_many_arguments)]
    pub fn record_ae_handle_ask(
        &mut self,
        me: NodeId,
        from: &NodeId,
        nonce: u64,
        ask: &crate::record_sync::Ask,
        sig: &[u8],
        sender_pk: Option<[u8; 32]>,
        now_secs: u64,
    ) -> Option<crate::transport::WireMessage> {
        use crate::record_sync as rs;
        let auth = rs::check_ask(ask)
            .and_then(|()| {
                crate::vbc_directory::verify_ae_signature(sender_pk, rs::RECORD_AE_KIND_ASK, from, nonce, &rs::ask_body_hash(ask), sig)
            })
            .and_then(|()| self.record_ae.guard.admit_request(*from, nonce, now_secs));
        if let Err(r) = auth {
            self.record_ae.counters.refuse(r, from, "ask");
            return None;
        }
        if !self.record_ae.global_admit(now_secs) {
            self.record_ae.counters.shed_global += 1;
            log::warn!(
                "[RECORD-AE] global answer cap reached — ask from {} shed (liveness only; counted \
                 record_ae_shed_global)",
                hex::encode(&from[..8]),
            );
            return None;
        }
        let answer = self.record_ae_answer(ask);
        let payload = crate::crypto::ae_sign_payload(rs::RECORD_AE_KIND_ANSWER, &me, nonce, &rs::answer_body_hash(&answer));
        let sig = self.signer.sign(&payload);
        self.record_ae.counters.answers_sent += 1;
        Some(crate::transport::WireMessage::RecordAeAnswer { from: me, nonce, answer, sig })
    }

    /// R51 — one walk step (the binary calls it once per tick): sync the walk
    /// with `peers` (in place — never redrawn), ABORT (counted) every descent
    /// whose in-flight ask outlived the reply TTL or whose peer left, then
    /// start a descent with the next walked peer unless one is already in
    /// flight with it. Returns the ask to send (≤ 1 per tick).
    ///
    /// Fable 2026-10-01 F-5: `genesis` ⊆ `peers` are the peers whose VERIFIED
    /// NBC names a PINNED genesis Nabla key (the caller asks
    /// `cc::nbc_is_pinned_genesis`); they are walked first in every window,
    /// then one citizen (`record_sync::TieredWalk`). An ORDER only — nothing
    /// below this line reads it, and empty `genesis` is the old walk exactly.
    pub fn record_ae_tick(
        &mut self,
        me: NodeId,
        peers: &[NodeId],
        genesis: &[NodeId],
        now_secs: u64,
    ) -> Vec<(NodeId, crate::transport::WireMessage)> {
        let salt = self.record_ae.salt;
        let live: std::collections::HashSet<&NodeId> = peers.iter().collect();
        let first: Vec<NodeId> = genesis.iter().filter(|g| live.contains(g)).copied().collect();
        self.record_ae.walk.sync(&first, peers, &salt);
        let dead: Vec<NodeId> = self
            .record_ae
            .descents
            .iter()
            .filter(|(p, d)| d.expired(now_secs) || !live.contains(p))
            .map(|(p, _)| *p)
            .collect();
        for p in dead {
            self.record_ae.end(&p, crate::record_sync::DescentEnd::Aborted);
        }
        let mut out = Vec::new();
        if let Some(peer) = self.record_ae.walk.next() {
            if let Some(m) = self.record_ae_start(me, peer, now_secs) {
                out.push((peer, m));
            }
        }
        out
    }

    /// Start a descent with `peer` (none if one is already open — at most one
    /// in flight per peer). Returns the first, signed ask (the root).
    pub fn record_ae_start(&mut self, me: NodeId, peer: NodeId, now_secs: u64) -> Option<crate::transport::WireMessage> {
        if self.record_ae.has_descent(&peer) {
            return None;
        }
        self.record_ae.descent_seq += 1;
        let d = crate::record_sync::Descent::new(self.record_ae.descent_seq);
        self.record_ae.descents.insert(peer, d);
        self.record_ae_next_ask(me, peer, now_secs)
    }

    /// The descent's next ask, signed under a fresh nonce — or, when it has
    /// nothing left to ask, its end (completed / truncated, counted).
    fn record_ae_next_ask(&mut self, me: NodeId, peer: NodeId, now_secs: u64) -> Option<crate::transport::WireMessage> {
        use crate::record_sync as rs;
        let salt = self.record_ae.salt;
        let d = self.record_ae.descents.get_mut(&peer)?;
        match d.next_ask(&salt) {
            Some(ask) => {
                let nonce = self.record_ae.guard.issue(peer, now_secs);
                let payload = crate::crypto::ae_sign_payload(rs::RECORD_AE_KIND_ASK, &me, nonce, &rs::ask_body_hash(&ask));
                let sig = self.signer.sign(&payload);
                d.set_in_flight(nonce, ask.clone(), now_secs);
                self.record_ae.counters.asks_sent += 1;
                Some(crate::transport::WireMessage::RecordAeAsk { from: me, nonce, ask, sig })
            }
            None => {
                let how = if d.is_truncated() { rs::DescentEnd::Truncated } else { rs::DescentEnd::Completed };
                self.record_ae.end(&peer, how);
                None
            }
        }
    }

    /// R59 — the ASKER, under the lock and BRIEF: refuse (counted, by kind) an
    /// answer over a count bound → not signed by `from`'s verified NBC key →
    /// not the answer to a live nonce this node issued to `from` → not the
    /// in-flight ask of its descent with `from` (all `Unsolicited` — a spoofed
    /// or replayed answer). Accepting TAKES the in-flight ask. The caller then
    /// runs `record_sync::prepare_answer` OFF the lock and
    /// `record_ae_apply_answer` under it.
    pub fn record_ae_accept_answer(
        &mut self,
        from: &NodeId,
        nonce: u64,
        answer: &crate::record_sync::Answer,
        sig: &[u8],
        sender_pk: Option<[u8; 32]>,
        now_secs: u64,
    ) -> Option<crate::record_sync::AcceptedAnswer> {
        use crate::record_sync as rs;
        use crate::vbc_directory::AeRefusal;
        let accepted = rs::check_answer(answer)
            .and_then(|()| {
                crate::vbc_directory::verify_ae_signature(sender_pk, rs::RECORD_AE_KIND_ANSWER, from, nonce, &rs::answer_body_hash(answer), sig)
            })
            .and_then(|()| self.record_ae.guard.accept_reply(*from, nonce, now_secs))
            .and_then(|()| {
                self.record_ae
                    .descents
                    .get_mut(from)
                    .and_then(|d| d.take_in_flight(nonce))
                    .ok_or(AeRefusal::Unsolicited)
            });
        match accepted {
            Ok(asked) => Some(rs::AcceptedAnswer { from: *from, nonce, asked }),
            Err(r) => {
                self.record_ae.counters.refuse(r, from, "answer");
                None
            }
        }
    }

    /// The under-lock half of an accepted answer (after `record_sync::
    /// prepare_answer` ran off the lock): count what was refused, record /
    /// detect the verified legs (`record_ae_apply`), advance the descent —
    /// no progress ⇒ ABORTED — and return its next signed ask (or `None`: the
    /// descent ended, counted).
    pub fn record_ae_apply_answer(
        &mut self,
        me: NodeId,
        prepared: crate::record_sync::PreparedAnswer,
        now_secs: u64,
    ) -> Option<crate::transport::WireMessage> {
        use crate::record_sync::{DescentEnd, Prepared, PreparedAnswer};
        let PreparedAnswer { from, nonce: _, body, malformed } = prepared;
        if malformed > 0 {
            self.record_ae.counters.refused_malformed += malformed;
            log::warn!(
                "[RECORD-AE] {} malformed / wrong-kind item(s) in an answer from {} ignored \
                 (counted record_ae_refused_malformed)",
                malformed, hex::encode(&from[..8]),
            );
        }
        let salt = self.record_ae.salt;
        let progress = match body {
            Prepared::Nodes { asked, views } => {
                let trie = &self.record_trie;
                match self.record_ae.descents.get_mut(&from) {
                    Some(d) => d.on_nodes(&asked, &views, trie, &salt),
                    None => return None,
                }
            }
            Prepared::Legs { asked, received, verified, refused, unrequested } => {
                let c = &mut self.record_ae.counters;
                c.legs_received += received.len() as u64 + unrequested;
                c.legs_refused += refused;
                c.legs_unrequested += unrequested;
                if refused > 0 || unrequested > 0 {
                    log::warn!(
                        "[RECORD-AE] answer from {}: {} leg(s) failed verify_fork_leg, {} leg(s) \
                         were not asked (refused unverified) — counted record_ae_legs_{{refused,unrequested}}",
                        hex::encode(&from[..8]), refused, unrequested,
                    );
                }
                self.record_ae_apply(verified, now_secs);
                match self.record_ae.descents.get_mut(&from) {
                    Some(d) => d.on_legs(&asked, &received),
                    None => return None,
                }
            }
        };
        if !progress {
            self.record_ae.end(&from, DescentEnd::Aborted);
            return None;
        }
        self.record_ae_next_ask(me, from, now_secs)
    }

    /// R58 — apply legs ALREADY verified (off the lock): a GRADED leg goes the
    /// record path (`ban::record_verified_and_detect` — created with
    /// `first_seen_secs = now_secs`, the RECEIVER's clock, R16 `contested`
    /// judged HERE; or an in-place upgrade of a held ungraded copy); an
    /// UNGRADED leg (directory lag) is `ban::detect_only` — a claim if its key
    /// holds another txid, else nothing stored. Then the ONE drain (WAL, trie
    /// feed, verdict fan-out queue, provenance).
    pub fn record_ae_apply(&mut self, legs: Vec<crate::ban::VerifiedForkLeg>, now_secs: u64) {
        for v in legs {
            if self.leg_is_graded(v.leg()) {
                let dir = &self.vbc_registrations;
                let grade = |l: &ForkLeg| crate::ban::leg_is_directory_witnessed(l, &|pk| dir.is_witness(pk));
                let o = crate::ban::record_verified_and_detect(&mut self.smt, &mut self.bans, v, now_secs, "record-ae", Some(&grade));
                if matches!(
                    o,
                    crate::ban::LegRecordOutcome::Recorded { .. }
                        | crate::ban::LegRecordOutcome::ForkBanned { .. }
                        | crate::ban::LegRecordOutcome::ForkRefused(_)
                ) {
                    self.record_ae.counters.legs_recorded += 1;
                }
            } else {
                self.record_ae.counters.legs_ungraded += 1;
                crate::ban::detect_only(&mut self.smt, &mut self.bans, v, "record-ae-ungraded");
            }
        }
        self.drain_fork_side_effects();
    }

    /// KI#84 — recompute EVERY pool from the two fact ledgers (called on load
    /// and after a bulk AE adoption). Every `(vid, is_dev)` that appears in
    /// either ledger is rebuilt.
    pub fn fob_rebuild_all_pools(&mut self) {
        let mut keys: std::collections::HashSet<([u8; 32], bool)> =
            std::collections::HashSet::new();
        for (_, v, d) in self.fob_applied_tranches.keys() {
            keys.insert((*v, *d));
        }
        for (v, d, _) in self.fob_claims.values() {
            keys.insert((*v, *d));
        }
        for (v, d) in keys {
            self.fob_rebuild_pool(&v, d);
        }
    }

    /// Test-only: admit `pk` as an R42 directory witness without a stamped
    /// VBC (a nabla test cannot make Core accept a bundle — `vbc_directory`
    /// tests). Re-queues producers that waited on the directory, exactly as a
    /// real admission does.
    #[cfg(test)]
    pub(crate) fn admit_witness_for_test(&mut self, pk: [u8; 32]) {
        self.vbc_registrations.insert_witness_for_test(pk);
        self.on_directory_admitted();
    }

    /// Test-only: one leg through the ONE record hook (`ban::
    /// record_leg_and_detect`, as the door / flood / AE call it), then the
    /// production drain.
    #[cfg(test)]
    pub(crate) fn record_leg_for_test(&mut self, leg: ForkLeg, now_secs: u64) -> crate::ban::LegRecordOutcome {
        let o = crate::ban::record_leg_and_detect(&mut self.smt, &mut self.bans, leg, now_secs, "test");
        self.drain_fork_side_effects();
        o
    }

    /// Test-only: a synthetic leaf (no record behind it) — for trie-SHAPE
    /// tests at a scale where minting genuine legs would dominate the run
    /// (`record_ae_single_divergent_leg_under_10k_converged`). Never answers
    /// an `Ask::Legs` (no record), which the tests do not ask of it.
    #[cfg(test)]
    pub(crate) fn record_trie_insert_for_test(&mut self, k: crate::record_sync::LeafKey) {
        self.record_trie.insert(k);
    }

    /// Test-only: admit the witnesses every `test_legs` leg is signed by.
    #[cfg(test)]
    pub(crate) fn admit_test_validators(&mut self) {
        self.admit_test_validators_except(&[]);
    }

    /// Test-only: as `admit_test_validators`, but WITHOUT `withheld` — a node
    /// whose R42 directory has not yet learned those witnesses (KI#224 K-e:
    /// a fresh node before directory AE).
    #[cfg(test)]
    pub(crate) fn admit_test_validators_except(&mut self, withheld: &[[u8; 32]]) {
        for i in 0..5u8 {
            let pk = crate::types::test_legs::validator(i).verifying_key().to_bytes();
            if !withheld.contains(&pk) {
                self.admit_witness_for_test(pk);
            }
        }
    }

    /// Lightweight constructor for unit tests — creates a temp dir internally.
    #[cfg(test)]
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("nabla_test_{}", rand::random::<u64>()));
        NablaNode::open(&dir, Box::new(crate::crypto::NoopSigner)).unwrap()
    }

    /// Process a registration request.
    /// Returns ack + gossip message for the network layer to forward.
    ///
    /// `now_secs` is the binary's wall clock (`virtual_secs`) — stamped as the
    /// `first_seen_secs` of the origin record the door creates (ForkSettlement
    /// §2.4 [R13]); never `current_tick`.
    pub fn register(
        &mut self,
        reg: &Registration,
        deed_tx: &DeedTransaction,
        now_secs: u64,
    ) -> Result<RegisterResult, NablaError> {
        let result = registration::process_registration(
            &mut self.smt, &mut self.wal, &mut self.bans,
            reg, deed_tx, self.current_tick, now_secs, &mut self.deed_collected,
            self.signer.as_ref(),
            // KI#224 — door step 5b⁗ reads the LIVE directory.
            &|pk| self.vbc_registrations.is_witness(pk),
            Some(&mut self.airdrop_pool),
            Some(&mut self.dev_treasury_pool),
            Some(&mut self.bootstrap_pool),
            Some(&mut self.foundation_bootstrap_pool),
            Some(&mut self.deed_pool),
            Some(&mut self.validator_net_ledger),
            Some(&mut self.dev_deed_pool),
            Some(&mut self.validator_dev_net_ledger),
        );
        // ForkSettlement §2.3 — WAL + flood every origin record / fork verdict
        // the door made, on the Ok AND the Err path: a leg the door REFUSES is
        // still recorded [R30], and a detected fork returns `WalletBanned`.
        self.drain_fork_side_effects();
        let result = result?;
        // ForkSettlement §9r (F-6 path 11) — a redeem's fee credit is parked
        // until THIS node's provenance judges the redeemed cheque `Ok`; the
        // release runs now (an honest, already-judged cheque credits at once)
        // and after every later drain. First park per cheque wins (a retry
        // never reaches 8c — the 5d short-circuit).
        if let Some((cheque, credit)) = result.held_fee_credit {
            if let std::collections::btree_map::Entry::Vacant(v) = self.held_fee_credits.entry(cheque) {
                v.insert(credit);
                self.fee_credits_parked += 1;
            }
            self.release_held_fee_credits();
        }
        // Every register can mutate pool state:
        //   - Genesis claims → airdrop_pool or dev_treasury_pool
        //   - Fee-paying registers (receiver post-redeem) → deed_pool +
        //     validator_net_ledger (hashmap mode only)
        // Persist after every register so an originating node's local
        // disk never lags its in-memory state. The atomic CBOR write
        // (tmp + rename) is sub-millisecond and rebuilds the full pool
        // file on each call; bounded by per-node register rate, well
        // under any practical disk pressure. Mirrors the same
        // "persist-on-mutation" guarantee airdrop / dev_treasury get
        // from the existing post-claim save.
        if let Err(e) = self.persist_pool_states() {
            log::warn!("[POOL-PERSIST] save after register failed: {e}");
        }
        Ok(RegisterResult {
            ack: result.ack,
            gossip_msg: result.gossip_msg,
            hibernation_until: result.hibernation_until,
            committed_recalls: result.committed_recalls,
        })
    }

    /// Process a wallet query.
    pub fn query(&self, wallet_id: &WalletId) -> NablaResponse {
        // No NBC context at this layer — the binary owns it. A caller that has
        // one MUST use `query_with_issuer`, or the signature covers an empty
        // `nbc_issuer_pk` while the wire carries a real one (G18).
        query::process_query(&self.smt, wallet_id, self.current_tick,
                             self.signer.as_ref(), Vec::new())
    }

    /// Query, stamping the responding node's NBC issuer BEFORE the response is
    /// signed (YPX-002 §4.3 / §4.6).
    ///
    /// G18: the binary used to call `query()` and then assign
    /// `response.nbc_issuer_pk` afterwards. `response_sign_payload` hashes that
    /// field, so the signature covered an EMPTY issuer while the wire carried
    /// the real one — the signed bytes were never the shipped bytes. Signing
    /// once, after every covered field is final, makes that drift impossible.
    pub fn query_with_issuer(
        &self,
        wallet_id: &WalletId,
        nbc_issuer_pk: Vec<u8>,
    ) -> NablaResponse {
        query::process_query(&self.smt, wallet_id, self.current_tick,
                             self.signer.as_ref(), nbc_issuer_pk)
    }

    // ── Group Wallet (Phase 3) ──

    /// Process a group wallet registration.
    /// Returns ack + GroupUpdate gossip message.
    pub fn register_group(
        &mut self,
        greg: &GroupRegistration,
        deed_tx: &DeedTransaction,
    ) -> Result<RegisterResult, NablaError> {
        let result = registration::process_group_registration(
            &mut self.smt, &mut self.wal, &mut self.bans,
            greg, deed_tx, self.current_tick, &mut self.deed_collected,
            self.signer.as_ref(),
        )?;
        Ok(RegisterResult {
            ack: result.ack,
            gossip_msg: result.gossip_msg,
            hibernation_until: None, // group registers are not HAL re-anchors
            committed_recalls: Vec::new(), // nor recall commits
        })
    }

    /// Query a specific member's allocation within a group wallet.
    pub fn query_member(
        &self,
        wallet_id: &WalletId,
        member_pk: &[u8; 32],
    ) -> Result<MemberQueryResponse, NablaError> {
        query::query_member(&self.smt, wallet_id, member_pk, self.current_tick)
    }

    /// Check if a wallet is a group wallet.
    pub fn is_group_wallet(&self, wallet_id: &WalletId) -> bool {
        self.smt.get(wallet_id)
            .and_then(|e| e.group_members.as_ref())
            .is_some()
    }

    /// Process an incoming gossip message. Records per-variant age for
    /// the P5 latency stats *before* dispatching to the processor so
    /// every observed message (including duplicates we dedup away) is
    /// counted — the metric we care about is "how stale was this by
    /// the time it reached us", not "how stale was it when we first
    /// acted on it". Duplicates still reflect real-network arrival time.
    ///
    /// `now_secs` = the binary's wall clock (`virtual_secs`), stamped on any
    /// origin record the flood hook / `ForkBan` adoption creates
    /// (ForkSettlement §2.4 [R13]).
    pub fn handle_gossip(&mut self, msg: &GossipMessage, now_secs: u64) -> GossipAction {
        self.gossip_latency.observe(msg, self.current_tick);
        // ── RULE 0 §4 marker (KI#191 residual, RULED 2026-09-25) ──
        // WRONG READING (this site until 2026-09-25): the contribution emission
        // PoolSync was reconciled HERE, before `GossipEngine::process`, and its
        // `ReconcileOutcome` was consumed by a `log::debug!` + a persist flag
        // and NOTHING ELSE, while `process` hard-coded the emission kinds to
        // `NoOp` — justified as "the Layer-1 identity false-positives on these
        // pools by construction". That described the pre-09-16 identity and had
        // no living reason after `AirdropPool::reconcile` was corrected.
        // RIGHT READING: ONE RULE FOR EVERY POOL. The emission pools are
        // reconciled INSIDE `process` (`&mut self.emission` below), so their
        // `StructuralViolation` becomes `GossipAction::PoolStructuralViolation`
        // and reaches `enter_probation_on_structural_violation` exactly like
        // the airdrop pool. Only the epoch-roll observation stays here.
        // AUTHORITY: AXIOM_DESIGN_NablaJudoon.md §2.5 ruling block; KI#191.
        let emission_epoch_before = self.emission.epoch;
        // KI#28 rate detector needs the mesh-size estimate; fall back to 1
        // (self-disables anyway below the sample gate) when mesh is unset.
        let n_validators = self.mesh.as_ref()
            .map(|m| m.estimated_network_size())
            .unwrap_or(1);
        let action = self.gossip.process(
            msg, &mut self.smt, &mut self.bans, &mut self.oracle_pool,
            &mut self.airdrop_pool, &mut self.dev_treasury_pool,
            &mut self.bootstrap_pool, &mut self.foundation_bootstrap_pool,
            &mut self.deed_pool,
            &mut self.dev_deed_pool,
            &mut self.emission,
            &mut self.fob_pools, &self.fob_credits,
            self.current_tick, now_secs,
            n_validators,
            // KI#224 — the LIVE directory (a disjoint field borrow).
            &|pk| self.vbc_registrations.is_witness(pk),
        );
        // ForkSettlement §2.3 — WAL every origin record the flood hook made and
        // WAL + queue for flood every verdict (local detection or an adopted
        // `ForkBan`), whatever the action.
        self.drain_fork_side_effects();
        // A peer's advertisement can carry the epoch boundary here BEFORE
        // this node's own tick does (live gate 2026-09-14: 5 of 7 nodes) —
        // the same rule rolled, so it is logged and PERSISTED the same.
        let emission_rolled = self.emission.epoch != emission_epoch_before;
        if emission_rolled {
            log::info!("[EMISSION-ROLL] epoch={} share_v={} share_n={} pool_v={} pool_n={} deed={} (via PoolSync)",
                self.emission.epoch, self.emission.share_v, self.emission.share_n,
                self.emission.validators.balance(), self.emission.nabla.balance(), self.deed_pool.balance());
        }
        // KI#191 residual — count the escalation per pool class so "0 emission
        // probations" is MEASURABLE on /status (RULE 3 §2), not inferred from
        // the absence of a warn line.
        if let GossipMessage::PoolSync { pool, .. } = msg {
            if matches!(pool, crate::types::PoolKind::EmissionValidators | crate::types::PoolKind::EmissionNabla)
                && matches!(action, GossipAction::PoolStructuralViolation { .. })
            {
                self.emission_structural_violations = self.emission_structural_violations.saturating_add(1);
            }
        }
        // Persist on PoolSync that mutated state. Both pools rebuilt
        // identically from disk on next boot — we save both to keep
        // logic simple (writes are cheap; bounded by claim rate which
        // is very low).
        if matches!(msg, GossipMessage::PoolSync { .. })
            && (matches!(action, GossipAction::Forward(_)) || emission_rolled)
        {
            if let Err(e) = self.persist_pool_states() {
                log::warn!("[POOL-PERSIST] save after PoolSync reconcile failed: {e}");
            }
        }
        // YPX-022 §5 — a NEWLY-applied COMMITTED recall marker (Forward ⇔
        // apply_remote_recall accepted it) is made durable immediately: a crash
        // must never resurrect a recalled cheque on this node. Reservations
        // (`committed: false`) are deliberately NOT durable — a lost
        // reservation is a harmless idempotent retry (§2.2.1). Best-effort
        // like the pool persist.
        if let GossipMessage::Recall { txid, sender_pk, recall_tick, committed: true, .. } = msg {
            if matches!(action, GossipAction::Forward(_)) {
                if let Err(e) = self.wal.append(&WalOp::TxRecalled {
                    tx_hash: *txid,
                    sender_pk: sender_pk.clone(),
                    recall_tick: *recall_tick,
                }) {
                    log::warn!("[RECALL-PERSIST] WAL append after gossip recall failed: {e}");
                }
            }
        }
        action
    }

    /// Write both pools' state to disk. Called after any mutation
    /// (local claim or gossip reconcile). Best-effort: errors logged,
    /// not propagated — the in-memory state is authoritative for the
    /// running session; persistence is purely for restart recovery.
    /// §6b.4(4) — the registration record for a certificate, if any:
    /// (presenter pk, stamp tick, stamped balance).
    pub fn vbc_registration(&self, vbc_hash: &[u8; 32]) -> Option<([u8; 32], u64, u64)> {
        self.vbc_registrations.get(vbc_hash).map(|e| (e.wallet_pk(), e.stamp_tick(), e.stamp_balance()))
    }
    /// ValidatorJoin §6b.10 (KI#169) — ONE live stamp per stake wallet. Returns the
    /// `validator_id` of another, still-live certificate this wallet already
    /// stakes, if any. A renewal (same `validator_id`) is never a conflict.
    /// KI#223: every compared value comes from a VERIFIED entry — an unverified
    /// peer entry can no longer block a genuine registration.
    pub fn vbc_registration_conflict(&self, wallet_pk: &[u8; 32], validator_id: &[u8; 32], now_tick: u64) -> Option<[u8; 32]> {
        self.vbc_registrations.conflict(wallet_pk, validator_id, now_tick)
    }
    /// The witness directory (read-only view).
    pub fn vbc_directory(&self) -> &crate::vbc_directory::VbcDirectory {
        &self.vbc_registrations
    }
    /// ForkSettlement R37/R42 — is `pk` the ed25519 subject of a STAMPED VBC
    /// this node verified (`vbc_directory::admit`)? Membership never expires
    /// (legs are history).
    ///
    /// Read by the provenance engine's PRODUCER admission (W7c, plan §2 step
    /// 1 — `provenance_drain` passes the same directory query): a leg with a
    /// non-directory witness never grounds the state it produces (c12).
    pub fn is_directory_witness(&self, pk: &[u8; 32]) -> bool {
        self.vbc_registrations.is_witness(pk)
    }
    /// Adopt entries ALREADY verified off the node lock (`vbc_directory::admit`
    /// in the binary's pre-lock stage). Set-union: a held key is never
    /// overwritten. Persists once if anything was added. Returns the count.
    /// ⚠ KI#223: this used to take raw peer records and union them unverified.
    pub fn adopt_verified_directory_entries(&mut self, entries: Vec<crate::vbc_directory::VerifiedDirectoryEntry>) -> usize {
        let mut adopted = 0;
        for e in entries {
            if self.vbc_registrations.insert(e) {
                adopted += 1;
            }
        }
        if adopted > 0 {
            // W7c — a new witness may admit producers that waited on it; W1 —
            // and may grade held records into the record trie.
            self.on_directory_admitted();
            if let Err(e) = self.persist_pool_states() {
                log::warn!("[VBC-REGISTRY-AE] persist failed: {e}");
            }
        }
        adopted
    }

    /// §6b.4(4) — record a VERIFIED registration and persist it on the same
    /// cadence as the FOB ledgers. Returns `false` if its `vbc_hash` was
    /// already recorded (the caller decides: same presenter → re-issue, else
    /// `CONSUMED`).
    pub fn record_vbc_registration(&mut self, entry: crate::vbc_directory::VerifiedDirectoryEntry) -> bool {
        if !self.vbc_registrations.insert(entry) {
            return false;
        }
        self.on_directory_admitted(); // W7c producers + W1 record grades
        if let Err(e) = self.persist_pool_states() {
            log::warn!("[VBC-REGISTER] persist failed: {} — the record stays in memory for this session", e);
        }
        true
    }

    fn persist_pool_states(&self) -> std::io::Result<()> {
        let tick = self.current_tick;
        self.airdrop_pool
            .to_persisted(tick)
            .save(&self.data_dir.join(crate::types::PoolKind::Airdrop.state_filename()))?;
        self.dev_treasury_pool
            .to_persisted(tick)
            .save(&self.data_dir.join(crate::types::PoolKind::DevTreasury.state_filename()))?;
        self.bootstrap_pool
            .to_persisted(tick)
            .save(&self.data_dir.join(crate::types::PoolKind::Bootstrap.state_filename()))?;
        self.foundation_bootstrap_pool
            .to_persisted(tick)
            .save(&self.data_dir.join(crate::types::PoolKind::FoundationBootstrap.state_filename()))?;
        self.emission
            .to_persisted(tick)
            .save(&self.data_dir.join(crate::emission::PersistedEmissionState::FILENAME))?;
        self.deed_pool
            .to_persisted()
            .save(&self.data_dir.join(crate::types::PoolKind::Deed.state_filename()))?;
        self.validator_net_ledger
            .to_persisted()
            .save(&self.data_dir.join("validator_net_ledger.cbor"))?;
        // Dev-class pools — distinct on-disk slots so a restart
        // doesn't reset accumulated dev credits.
        self.dev_deed_pool
            .to_persisted()
            .save(&self.data_dir.join(crate::types::PoolKind::DevDeed.state_filename()))?;
        self.validator_dev_net_ledger
            .to_persisted()
            .save(&self.data_dir.join("validator_dev_net_ledger.cbor"))?;
        // FOB pools — `tranched_total` is the durable debit-cursor (double-count
        // guard). Serialize as a LIST of ((vid, is_dev), pool) — tuple map keys
        // aren't a portable CBOR map key; the load side collects it back.
        {
            let list: Vec<(([u8; 32], bool), crate::fob::FobPool)> =
                self.fob_pools.iter().map(|(k, v)| (*k, v.clone())).collect();
            let mut bytes = Vec::new();
            ciborium::into_writer(&list, &mut bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            std::fs::write(self.data_dir.join("fob_pools.cbor"), &bytes)?;
            // §10.0 claim records ride the same persistence cadence.
            let claims: Vec<(crate::types::TxHash, ([u8; 32], bool, u64))> =
                self.fob_claims.iter().map(|(k, v)| (*k, *v)).collect();
            let mut cbytes = Vec::new();
            ciborium::into_writer(&claims, &mut cbytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            std::fs::write(self.data_dir.join("fob_claims.cbor"), &cbytes)?;
            // §9r F-6 path 11 — parked redeem fee credits, same cadence.
            let held: Vec<(crate::types::TxHash, crate::registration::FeeCredit)> =
                self.held_fee_credits.iter().map(|(k, v)| (*k, v.clone())).collect();
            let mut hbytes = Vec::new();
            ciborium::into_writer(&held, &mut hbytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            std::fs::write(self.data_dir.join("held_fee_credits.cbor"), &hbytes)?;
            // §6b.4(4) — VBC registration consume-once records, same cadence.
            let vregs: Vec<VbcRegistrationRecord> = self.vbc_registrations.persisted_list();
            let mut vbytes = Vec::new();
            ciborium::into_writer(&vregs, &mut vbytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            std::fs::write(self.data_dir.join("vbc_registrations.cbor"), &vbytes)?;
            // KI#84 — the PLUS ledger (the MINUS ledger is fob_claims above).
            // fob_pools.cbor above is now DERIVED (observability only); these two
            // ledgers are the source of truth that AE converges.
            let tranches: Vec<((u64, [u8; 32], bool), u64)> =
                self.fob_applied_tranches.iter().map(|(k, v)| (*k, *v)).collect();
            let mut tbytes = Vec::new();
            ciborium::into_writer(&tranches, &mut tbytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            std::fs::write(self.data_dir.join("fob_tranches.cbor"), &tbytes)?;
        }
        Ok(())
    }

    /// KI#84 — the two replicated ledgers, for AE exchange. Sorted so a digest
    /// over them is order-independent. `(plus, minus)`.
    #[allow(clippy::type_complexity)]
    pub fn fob_ledgers(
        &self,
    ) -> (
        Vec<((u64, [u8; 32], bool), u64)>,
        Vec<(crate::types::TxHash, ([u8; 32], bool, u64))>,
    ) {
        let mut plus: Vec<((u64, [u8; 32], bool), u64)> =
            self.fob_applied_tranches.iter().map(|(k, v)| (*k, *v)).collect();
        plus.sort();
        let mut minus: Vec<(crate::types::TxHash, ([u8; 32], bool, u64))> =
            self.fob_claims.iter().map(|(k, v)| (*k, *v)).collect();
        minus.sort();
        (plus, minus)
    }

    /// KI#84 — a stable digest over both ledgers. Two nodes match IFF they hold
    /// the identical plus+minus sets (⇒ identical pools). Cheap AE probe.
    pub fn fob_ledger_digest(&self) -> [u8; 32] {
        let (plus, minus) = self.fob_ledgers();
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_FOB_LEDGER");
        h.update(&(plus.len() as u64).to_le_bytes());
        for ((e, v, d), a) in &plus {
            h.update(&e.to_le_bytes());
            h.update(v);
            h.update(&[*d as u8]);
            h.update(&a.to_le_bytes());
        }
        h.update(&(minus.len() as u64).to_le_bytes());
        for (tx, (v, d, a)) in &minus {
            h.update(tx);
            h.update(v);
            h.update(&[*d as u8]);
            h.update(&a.to_le_bytes());
        }
        *h.finalize().as_bytes()
    }

    /// KI#84 — adopt AE-pulled ledger facts (set-union, idempotent). Returns the
    /// count of NEW facts applied; rebuilds every touched pool.
    pub fn fob_adopt_ledgers(
        &mut self,
        plus: &[((u64, [u8; 32], bool), u64)],
        minus: &[(crate::types::TxHash, ([u8; 32], bool, u64))],
    ) -> usize {
        let mut applied = 0;
        for ((epoch, vid, is_dev), amount) in plus {
            if self.fob_apply_tranche_epoch(*epoch, *vid, *is_dev, *amount) {
                applied += 1;
            }
        }
        for (tx_hash, (vid, is_dev, amount)) in minus {
            if self.fob_record_claim(*tx_hash, *vid, *is_dev, *amount) {
                applied += 1;
            }
        }
        applied
    }

    /// The CONVERGENT net earnings available to tranche into `vid`'s FOB pool
    /// (§4/§10.1b): `fob::fob_net_earned` over this validator's replicated
    /// `validator_earnings` (post-DEED via Core's `compute_deed_split`) minus
    /// what has already moved into the pool (`tranched_total`). Every recording
    /// node derives the same number from the same replicated `txid_records`;
    /// a bloom node holds no records so this is 0 (and it never authors). This
    /// is the `balance_used` a mover PINS into a tranche statement.
    pub fn fob_available(&self, vid: &[u8; 32], is_dev: bool, until_tick: u64) -> u64 {
        // ONE codepath, class is a data bit: read the class-filtered earnings
        // (dev vs real), same lines for both (§10.2a invariant). `until_tick` is
        // the authored epoch's floor (a shared, settled watermark) so the 3
        // recorders read the identical prefix and their tranche payloads
        // converge (see validator_earnings_by_class).
        let (_gross, entries) = self.smt.validator_earnings_by_class(vid, is_dev, 0, until_tick);
        // ForkSettlement §9r (F-6 path 11, owner ruling 2026-10-02) — THE mint
        // gate for fee slots: a fee counts toward the FOB (and so toward a
        // `ValidatorWithdrawalMint`) only when the money it was paid from is
        // CLEAN in this node's provenance — `judge_send(entry.tx_hash) == Ok`.
        // A redeem's earnings are keyed by the CHEQUE txid (the redeem registers
        // under it), a genesis claim's by its own send txid, so one judgment
        // covers both. Held / waiting ⇒ excluded (credited in a later epoch when
        // it clears; never if it stays held). Fail closed while re-derivation is
        // queued (counts nothing). A cheque re-held AFTER its fee was tranched
        // lowers `net` below `tranched`, so the saturating subtraction claws it
        // back from future earnings.
        let entries: Vec<_> = if self.provenance_idle() {
            entries.into_iter()
                .filter(|e| matches!(
                    self.provenance.judge_send(&self.smt, &e.tx_hash),
                    crate::provenance::Judgment::Ok { .. }
                ))
                .collect()
        } else {
            Vec::new()
        };
        let net = crate::fob::fob_net_earned(
            vid,
            &entries,
            axiom_core_logic::genesis_integrity::GENESIS_NEWS_ANCHOR,
        );
        let tranched = self
            .fob_pools
            .get(&(*vid, is_dev))
            .map(|p| p.tranched_total())
            .unwrap_or(0);
        net.saturating_sub(tranched)
    }

    /// Adopt a PRE-VERIFIED tranche `amount` into `vid`'s FOB pool (empty →
    /// full, DEBIT via `tranched_total`; no mint). The caller (authoring or the
    /// `FobTranche` receive-judge) has already confirmed
    /// `amount == compute_fob_tranche(balance_used)`. Idempotent under
    /// refill-requires-empty — a repeat onto a full pool is a `NotEmpty`
    /// refusal, so re-applying the mover's own re-gossiped statement is safe.
    /// KI#84 — recompute ONE pool's state from the two replicated fact sets:
    /// `balance = Σplus − Σminus`, `tranched_total = Σplus`,
    /// `withdrawn_total = Σminus`. Idempotent + order-independent, so two nodes
    /// holding the same sets derive the identical pool regardless of the order
    /// facts arrived — that is the convergence guarantee. Called after any
    /// plus/minus fact is inserted (locally or via AE).
    /// KI#84 — the two per-pool ledger sums `(Σplus, Σminus)`. The conservation
    /// invariant is `Σminus ≤ Σplus` (you cannot withdraw more than was ever
    /// tranched); `balance = Σplus − Σminus`.
    fn fob_pool_sums(&self, vid: &[u8; 32], is_dev: bool) -> (u64, u64) {
        let plus: u64 = self
            .fob_applied_tranches
            .iter()
            .filter(|((_, v, d), _)| v == vid && *d == is_dev)
            .map(|(_, a)| *a)
            .sum();
        let minus: u64 = self
            .fob_claims
            .values()
            .filter(|(v, d, _)| v == vid && *d == is_dev)
            .map(|(_, _, a)| *a)
            .sum();
        (plus, minus)
    }

    fn fob_rebuild_pool(&mut self, vid: &[u8; 32], is_dev: bool) {
        let (plus, minus) = self.fob_pool_sums(vid, is_dev);
        self.fob_pools.insert(
            (*vid, is_dev),
            crate::fob::FobPool::from_ledgers(plus, minus),
        );
    }

    /// KI#84 — apply a committee PLUS fact `(epoch, vid, is_dev) → amount`.
    /// Insert-once (idempotent per key: a re-gossiped or AE-replayed tranche
    /// for an epoch already applied is a no-op), then rebuild the pool. Returns
    /// `true` iff the fact was NEW (so the caller can PoolSync it onward).
    pub fn fob_apply_tranche_epoch(
        &mut self,
        epoch: u64,
        vid: [u8; 32],
        is_dev: bool,
        amount: u64,
    ) -> bool {
        if amount == 0 {
            return false;
        }
        let key = (epoch, vid, is_dev);
        if self.fob_applied_tranches.contains_key(&key) {
            return false; // already applied — idempotent
        }
        self.fob_applied_tranches.insert(key, amount);
        self.fob_rebuild_pool(&vid, is_dev);
        true
    }

    /// §10.0 + KI#84 — record a claim as a MINUS fact (tx_hash → vid/class/
    /// amount) and rebuild the pool (`balance −= amount`). Idempotent on
    /// tx_hash: an AE-replayed or re-registered claim is a no-op. Returns
    /// `true` iff the claim was NEW.
    pub fn fob_record_claim(&mut self, tx_hash: crate::types::TxHash, vid: [u8; 32], is_dev: bool, amount: u64) -> bool {
        if self.fob_claims.contains_key(&tx_hash) {
            return false;
        }
        // CONSERVATION GUARD (defense in depth, design decision 2026-08-11): a MINUS fact
        // must never push `Σminus` past `Σplus` — withdrawing more than was ever
        // tranched is an atom-creation attempt. Refuse it: DO NOT STORE what we
        // would reject (mirrors the SMT write rule). This guards BOTH the local
        // register sweep AND every AE-synced claim from a peer, so a forged or
        // corrupt fact can never inflate a pool. Core CL2/CL5 is the outer
        // layer; this is the Nabla-write layer.
        let (plus, minus) = self.fob_pool_sums(&vid, is_dev);
        if minus.saturating_add(amount) > plus {
            self.fob_conservation_rejects = self.fob_conservation_rejects.saturating_add(1);
            log::warn!(
                "[FOB-CONSERVE] REFUSED claim vid={:02x}{:02x} class={} amount={} — \
                 would over-withdraw (Σminus {} + {} > Σplus {}); fact NOT stored",
                vid[0], vid[1], if is_dev { "dev" } else { "real" },
                amount, minus, amount, plus,
            );
            return false;
        }
        self.fob_claims.insert(tx_hash, (vid, is_dev, amount));
        self.fob_rebuild_pool(&vid, is_dev);
        true
    }

    /// KI#84 conservation guard — count of refused (over-withdrawing) ledger
    /// facts, for /status.
    pub fn fob_conservation_rejects(&self) -> u64 {
        self.fob_conservation_rejects
    }

    /// §10.0 — verify #2 lookup: is this txid a recorded FOB claim?
    pub fn fob_claim_record(&self, tx_hash: &crate::types::TxHash) -> Option<([u8; 32], bool, u64)> {
        self.fob_claims.get(tx_hash).copied()
    }

    /// This validator's current FOB pool balance (0 if none/empty).
    /// All FOB pools, for /status observability (dashboard §10.0 display):
    /// `(validator_id, is_dev, balance)`, sorted for stable output.
    pub fn fob_pools_snapshot(&self) -> Vec<([u8; 32], bool, u64)> {
        let mut v: Vec<([u8; 32], bool, u64)> = self
            .fob_pools
            .iter()
            .map(|((vid, is_dev), p)| (*vid, *is_dev, p.balance()))
            .collect();
        v.sort();
        v
    }

    pub fn fob_pool_balance(&self, vid: &[u8; 32], is_dev: bool) -> u64 {
        self.fob_pools
            .get(&(*vid, is_dev))
            .map(|p| p.balance())
            .unwrap_or(0)
    }

    /// Record the verified tranche credits from a judged `FobTranche` statement
    /// so the PoolSync BoundedFee arm can authorise the matching increases (§7).
    /// Prunes epochs older than `keep_epochs` back from `epoch` to bound memory
    /// (a credit is only ever needed around its own epoch's advertisements).
    pub fn fob_store_credits(&mut self, epoch: u64, credits: &[(([u8; 32], bool), u64)]) {
        let entry = self.fob_credits.entry(epoch).or_default();
        for (key, amount) in credits {
            entry.insert(*key, *amount);
        }
        const KEEP_EPOCHS: u64 = 4;
        let cutoff = epoch.saturating_sub(KEEP_EPOCHS);
        self.fob_credits.retain(|e, _| *e >= cutoff);
    }

    /// Public final-flush invoked from the signal handler in
    /// `bin/nabla_node.rs::main()` between tick_loop exit and process
    /// termination. Idempotent — every individual operation also runs
    /// periodically during normal operation; this version forces them
    /// synchronously one last time so a SIGTERM (with the env's
    /// ~10s SIGKILL backstop) leaves disk consistent. Errors are
    /// logged and counted; the caller still proceeds to exit because
    /// the alternative (hang) is worse.
    pub fn flush_for_shutdown(&mut self) {
        // Use eprintln! for shutdown messages — env_logger may buffer
        // through stderr's line-buffered path, and a fast post-loop
        // exit can swallow the messages otherwise. The SHUTDOWN-FLUSH
        // marker lets soak diagnostics confirm the handler actually
        // ran vs the process being killed before reaching the path.
        match self.persist_pool_states() {
            Ok(()) => eprintln!("[SHUTDOWN-FLUSH] pool states persisted (airdrop+dev_treasury)"),
            Err(e) => eprintln!("[SHUTDOWN-FLUSH] pool states FAILED: {e}"),
        }
        match self.take_snapshot() {
            Ok(()) => eprintln!("[SHUTDOWN-FLUSH] snapshot taken at tick={}", self.current_tick),
            Err(e) => eprintln!("[SHUTDOWN-FLUSH] snapshot FAILED: {e:?}"),
        }
        // WAL: append() already calls `self.file.flush()` after every
        // op, so user-space-buffer durability is already covered.
        // Power-loss-class durability (fsync-to-disk) is out of scope
        // for the signal-handler path — that's a separate hardening
        // around `OpenOptions::sync_all` on every write.
    }

    /// Return a snapshot of gossip latency stats (p50/p99/max per
    /// variant). Safe to call from an HTTP handler — clones the ring
    /// buffers and sorts a local copy to compute percentiles.
    ///
    /// `since_tick` restricts the snapshot to samples OBSERVED at or after that
    /// tick (KI#203) — see `GossipLatencyStats::snapshot`.
    pub fn gossip_latency(&self, since_tick: Option<u64>) -> GossipLatencySnapshot {
        self.gossip_latency.snapshot(self.current_tick, since_tick)
    }

    /// The node's current tick — the reference `parse_latency_window` resolves
    /// a relative `window_ticks` against.
    pub fn current_tick_for_latency(&self) -> u64 {
        self.current_tick
    }

    /// Advance tick (TARDIS delivers a new tick).
    pub fn advance_tick(&mut self, tick: u64) {
        self.current_tick = tick;
        if tick.saturating_sub(self.last_snapshot_tick) >= SNAPSHOT_INTERVAL_TICKS { // same clock-step-back guard as process_tick
            if let Err(e) = self.take_snapshot() {
                log::error!("Snapshot failed at tick {}: {}", tick, e);
            }
        }
    }

    /// KI#32: nabla_node.rs keeps the core's snapshot-able peer-NBC set in sync
    /// (called after each `verify_peer_nbc` insert / eviction) so `take_snapshot`
    /// persists the current `verified_nbcs` values.
    pub fn set_peer_nbcs(&mut self, nbcs: Vec<NBC>) {
        self.peer_nbcs = nbcs;
    }

    /// KI#32: consume the peer NBCs restored from the last snapshot. Called once
    /// by nabla_node.rs on boot to warm `verified_nbcs` (mirrors how `restored_cc`
    /// is taken by `init_cc`). Empty after the first call / when no snapshot.
    pub fn take_restored_peer_nbcs(&mut self) -> Vec<NBC> {
        std::mem::take(&mut self.restored_peer_nbcs)
    }

    /// Take a snapshot of current state.
    pub fn take_snapshot(&mut self) -> Result<(), NablaError> {
        // YPX-022 §5 — the exact txid terminals (the archive layer a
        // garbage-chain bloom Hit resolves through).
        let (completed_txids, redeemed_txids, recalled_txids) =
            self.smt.terminal_ledgers_snapshot();
        let (quarantine_active, quarantine_cooldown) = self.quarantine.persisted_entries();
        let snapshot = NablaSnapshot {
            tick: self.current_tick,
            root_hash: self.smt.root_hash(),
            entries: self.smt.entries().values().cloned().collect(),
            bans: self.bans.all(),
            deed_collected: self.deed_collected,
            latest_cc: self.cc_chain.as_ref().and_then(|c| c.latest().cloned()),
            // KI#81 — written EMPTY since 2026-08-08: this list described the
            // PRE-compact file (compact() below renumbers from 0), so it was
            // stale the moment the snapshot landed on disk, and boot no
            // longer reads it (the file is the only truth —
            // `rebuild_checksums_from_file`). Field retained so every
            // existing snapshot still decodes; remove it at the next
            // snapshot-format change.
            wal_checksums: Vec::new(),
            genesis_fact_payload: self.genesis_fact_payload.clone(),
            // YP §19.6 — per-tx records (hashmap-mode only; bloom-mode
            // SMT.iter_tx_records returns zero entries).
            tx_records: self.smt.iter_tx_records()
                .map(|(h, r)| (*h, r.clone()))
                .collect(),
            // KI#32: persist the verified peer NBCs (kept current via
            // `set_peer_nbcs`) so a restart restores a warm NBC cache.
            peer_nbcs: self.peer_nbcs.clone(),
            completed_txids,
            redeemed_txids,
            recalled_txids,
            // KI#38 — persist retained seq proofs so a restart doesn't strand
            // every head as `proof=ABSENT` until each wallet re-registers.
            seq_proofs: self.smt.seq_proofs_snapshot(),
            // YPX-022 §2.1.2a (KI#205) — the delivery terminal must survive a
            // restart, or a recall of a delivered cheque is granted after boot.
            cheque_claims: self.smt.cheque_claims_snapshot(),
            // GUIDE §5.6c "Persistence" (KI#75) — the JUDOON quarantine set +
            // cooldowns, so a restart no longer lifts a quarantine.
            quarantine_active,
            quarantine_cooldown,
            // YPX-002 §9.1.1a — the NBC issuer budget.
            nbc_issuance_budget: self.nbc_issuance_budget,
            // ForkSettlement §2.4 Q5 — the origin ledger (LAST).
            origin_ledger: self.smt.origin_ledger_snapshot(),
            redeem_ledger: self.smt.redeem_ledger_snapshot(),
        };
        self.snapshots.write(&snapshot)?;
        self.wal.append(&WalOp::Snapshot {
            tick: self.current_tick,
            root: self.smt.root_hash(),
        })?;
        self.wal.compact()?;
        self.snapshots.prune(3)?;
        self.last_snapshot_tick = self.current_tick;
        log::info!("Snapshot: tick={}, entries={}, bans={}",
            self.current_tick, self.smt.len(), self.bans.len());
        Ok(())
    }

    // ── TARDIS Integration (Phase 2) ──

    /// Initialize TARDIS with this node's public key.
    /// Must be called before processing ticks.
    pub fn init_tardis(&mut self, my_pk: PeerId) {
        let mut tardis = TardisNode::new(my_pk);
        // Sync TARDIS tick with node's recovered tick
        // (advance_tick is used for Phase 1 compatibility)
        tardis.update_network_size(1, 0);
        self.tardis = Some(tardis);
    }

    /// Initialize TARDIS as a seed node in the bootstrap triangle.
    pub fn init_tardis_ring_node(&mut self, my_pk: PeerId, upstream: PeerId, downstream: PeerId) {
        self.tardis = Some(TardisNode::new_with_ring_links(my_pk, upstream, downstream));
    }

    /// Process an incoming tick from TARDIS upstream.
    /// Updates node tick and triggers snapshot if needed.
    pub fn process_tick(
        &mut self,
        tick: &TickMessage,
        now_ms: u64,
    ) -> Result<Vec<TardisAction>, NablaError> {
        let tardis = self.tardis.as_mut().ok_or(NablaError::NoUpstream)?;
        let actions = tardis.process_tick(tick, &self.smt, now_ms, self.signer.as_ref())?;

        // Sync node's tick counter with TARDIS
        self.current_tick = tardis.current_tick();

        // Trigger snapshot if needed. `saturating_sub`: a persisted snapshot can
        // carry a tick LATER than the tick we now hold (a clock that stepped
        // back between runs; the binary sim's virtual clock runs ahead of
        // wall-clock, so every consecutive sim run over a kept data dir hits
        // it). Found 2026-09-25 by the KI#48 cold-start gate: 9 of 10 nodes
        // died on this line with "attempt to subtract with overflow" and the
        // tree read as a stall. A node must never be killed by its own
        // arithmetic; it simply waits until the tick catches up.
        if self.current_tick.saturating_sub(self.last_snapshot_tick) >= SNAPSHOT_INTERVAL_TICKS {
            if let Err(e) = self.take_snapshot() {
                log::error!("Snapshot failed at tick {}: {}", self.current_tick, e);
            }
        }

        Ok(actions)
    }

    /// Receive a tick approval from a downstream node.
    /// Returns true if the approval was accepted.
    pub fn receive_approval(&mut self, approval: &TickApproval) -> bool {
        let tardis = match self.tardis.as_mut() {
            Some(t) => t,
            None => return false,
        };
        tardis.receive_approval(approval, self.signer.as_ref())
    }

    /// Check cheque maturity via TARDIS tick authority.
    pub fn check_maturity(&self, registration_tick: u64) -> ChequeStatus {
        match &self.tardis {
            Some(tardis) => tardis.check_maturity(registration_tick),
            None => ChequeStatus::Scarred, // no TARDIS = no CLEAN
        }
    }

    /// Queue an audit request from a downstream node (KI#71). It is answered at
    /// our NEXT root-advertisement instant by [`Self::advertise_root`] — never
    /// live, because a live answer samples the SMT at a different instant from
    /// the root we advertised for the same tick (the honest-writer
    /// SELF-CONTRADICTION false positive, YPX-003 §1.3.5).
    pub fn queue_audit_request(&mut self, request: &SubtreeAuditRequest) -> bool {
        match self.tardis.as_mut() {
            Some(t) => t.queue_audit_request(request),
            None => false,
        }
    }

    /// KI#71 — this node's ONE signed root advertisement for its current tick
    /// label + the §5.5 answers to every queued audit request, from the same
    /// SMT borrow. See `TardisNode::advertise_root`.
    pub fn advertise_root(&mut self) -> Option<(crate::tardis::RootAdvert, Vec<TardisAction>)> {
        let tardis = self.tardis.as_mut()?;
        Some(tardis.advertise_root(&self.smt, self.signer.as_ref()))
    }

    /// Verify an audit response from upstream.
    pub fn verify_audit_response(
        &mut self,
        response: &SubtreeAuditResponse,
    ) -> Result<TardisAction, NablaError> {
        let tardis = self.tardis.as_mut().ok_or(NablaError::NoUpstream)?;
        tardis.verify_audit_response(response, &self.smt, self.signer.as_ref())
    }

    /// Handle a questionable alert (cascade from above).
    pub fn handle_questionable_alert(&mut self, alert: &QuestionableAlert) -> Option<TardisAction> {
        let tardis = self.tardis.as_mut()?;
        Some(tardis.handle_questionable_alert(alert, self.signer.as_ref()))
    }

    /// §7.6 fork-ban evidence: accuse `suspect` of a lineage violation (forwarded a
    /// tick whose lineage failed verification) into the quarantine-consensus channel.
    /// Rate-limited + deduped inside `flag_lineage_violation`. The caller must have
    /// verified `suspect`'s own tick signature first (anti-framing).
    pub fn flag_lineage_violation(&mut self, suspect: NodeId) -> Option<TardisAction> {
        let tardis = self.tardis.as_mut()?;
        Some(tardis.flag_lineage_violation(suspect, self.signer.as_ref()))
    }

    /// Check if we should run an audit this tick, and generate request.
    pub fn maybe_audit(&mut self) -> Option<TardisAction> {
        let tardis = self.tardis.as_mut()?;
        if tardis.should_audit() {
            tardis.generate_audit_request()
        } else {
            None
        }
    }

    /// Get mutable reference to TARDIS node for slot management.
    pub fn tardis_mut(&mut self) -> Option<&mut TardisNode> {
        self.tardis.as_mut()
    }

    /// Get reference to TARDIS node.
    pub fn tardis(&self) -> Option<&TardisNode> {
        self.tardis.as_ref()
    }

    /// Check if this node needs to find a new TARDIS parent.
    /// Returns true if upstream is lost — applies to ALL nodes (including genesis/seed).
    pub fn tardis_needs_recovery(&self) -> bool {
        match &self.tardis {
            Some(tardis) => tardis.needs_parent(),
            None => false, // TARDIS not initialized
        }
    }

    /// Attempt TARDIS parent recovery using available knowledge.
    ///
    /// Recovery priority (same for ALL nodes — genesis, seed, or regular):
    ///   1. Last known open slots from tick messages (§2.2) — instant
    ///   2. Mesh topology hints via find_tardis_parent() — gossip knowledge
    ///   3. Mesh known_nodes with has_d_open — passive discovery
    ///
    /// Returns the NodeId of the candidate parent if found, or None.
    /// The caller (network layer) must connect and call set_upstream().
    pub fn tardis_recovery_candidate(&mut self) -> Option<NodeId> {
        let tardis = self.tardis.as_ref()?;
        if !tardis.needs_parent() {
            return None;
        }

        // Priority 1: Last known open slots from tick messages (§2.2).
        let candidates = tardis.recovery_candidates();
        if let Some((peer_id, _slot_idx)) = candidates.first() {
            return Some(*peer_id);
        }

        // Priority 2: Mesh topology hints (find_tardis_parent).
        if let Some(mesh) = self.mesh.as_mut() {
            let action = mesh.find_tardis_parent();
            if let MeshAction::AttemptTardisReconnect { target, .. } = action {
                return Some(target);
            }
        }

        // Priority 3: Mesh known_nodes with has_d_open.
        if let Some(mesh) = self.mesh.as_ref() {
            let known = mesh.known_nodes_snapshot();
            for peer_info in &known {
                if peer_info.has_d_open {
                    return Some(peer_info.node_id);
                }
            }
        }

        None // no candidate found — caller may use other discovery
    }

    /// Check parentless timeout. Called every tick by the network layer.
    ///
    /// A node with children but no parent is a zombie subtree — it can't
    /// participate in the approval chain. The protocol gives it
    /// PARENTLESS_TIMEOUT_TICKS to find a parent. If it fails, it must
    /// detach both children so all three recover independently.
    ///
    /// Returns (action, detached_children). If DetachChildren, the Vec
    /// contains the PeerIds of the ex-children whose upstream was cleared.
    /// The caller (network layer) must notify those children.
    pub fn tardis_check_parentless(&mut self) -> (ParentlessAction, Vec<NodeId>) {
        let tardis = match self.tardis.as_mut() {
            Some(t) => t,
            None => return (ParentlessAction::Ok, Vec::new()),
        };

        let action = tardis.check_parentless_timeout();
        if action == ParentlessAction::DetachChildren {
            let children = tardis.detach_children();
            (ParentlessAction::DetachChildren, children)
        } else {
            (action, Vec::new())
        }
    }

    /// Check if this node (a leaf) should migrate to fill an open D slot.
    ///
    /// Leaves (0 children, has parent) can voluntarily move to a different
    /// parent that has an open D slot, improving tree balance. A leaf only
    /// migrates if its current parent keeps 1+ children (don't degrade
    /// parent from writer to leaf).
    ///
    /// `parent_child_count`: number of children the current parent has.
    ///
    /// Returns true if eligible to migrate. The caller must find the
    /// target node (via topology hints / known slots) and execute the move.
    pub fn tardis_should_migrate(&self, parent_child_count: usize) -> bool {
        match &self.tardis {
            Some(tardis) => tardis.should_migrate(parent_child_count),
            None => false,
        }
    }

    /// Detach this node from its upstream parent. Returns the old parent's
    /// PeerId so the caller can clean up the parent's D slot.
    /// Used during leaf migration — the leaf voluntarily leaves.
    pub fn tardis_detach_upstream(&mut self) -> Option<NodeId> {
        self.tardis.as_mut()?.detach_upstream()
    }

    // ── Gossip Mesh (Phase 4) ──

    /// Initialize the gossip mesh with our identity.
    pub fn init_mesh(&mut self, node_id: NodeId, address: NablaAddress) {
        let mut mesh = GossipMesh::new(node_id, address);
        self.rearm_mesh_quarantine_filter(&mut mesh);
        self.mesh = Some(mesh);
    }

    /// Initialize mesh with bootstrap peers.
    pub fn init_mesh_with_bootstrap(
        &mut self,
        node_id: NodeId,
        address: NablaAddress,
        bootstrap: Vec<PeerInfo>,
    ) {
        let mut mesh = GossipMesh::new(node_id, address);
        mesh.add_bootstrap(bootstrap);
        self.rearm_mesh_quarantine_filter(&mut mesh);
        self.mesh = Some(mesh);
    }

    /// GUIDE §5.6c "Persistence" (KI#75) — a quarantine restored from the
    /// snapshot must also be in the mesh's fan-out filter, or the restore is
    /// a ghost: `is_peer_quarantined` would say yes while `forward_targets`
    /// kept gossiping to the peer. Called from both `init_mesh*` paths.
    fn rearm_mesh_quarantine_filter(&self, mesh: &mut GossipMesh) {
        for (peer, _until) in self.quarantine.active_iter() {
            mesh.set_quarantined_peer(*peer, true);
        }
    }

    /// Run periodic mesh maintenance (called once per tick).
    pub fn mesh_tick(&mut self) -> MeshAction {
        match self.mesh.as_mut() {
            Some(mesh) => mesh.periodic_peer_check(self.current_tick),
            None => MeshAction::None,
        }
    }

    /// Observe a node in gossip traffic.
    pub fn mesh_observe(&mut self, node_id: NodeId) {
        if let Some(mesh) = self.mesh.as_mut() {
            mesh.observe_node(node_id, self.current_tick);
        }
    }

    /// Get forward targets for a gossip message.
    pub fn mesh_forward_targets(&self, sender: &NodeId) -> Vec<NodeId> {
        match &self.mesh {
            Some(mesh) => mesh.forward_targets(sender),
            None => Vec::new(),
        }
    }

    /// Process a topology hint from gossip.
    pub fn mesh_apply_topology(&mut self, hint: &TopologyHint) {
        if let Some(mesh) = self.mesh.as_mut() {
            mesh.apply_topology_hint(hint);
        }
    }

    /// Find a TARDIS parent via mesh knowledge (self-healing).
    pub fn mesh_find_tardis_parent(&mut self) -> MeshAction {
        match self.mesh.as_mut() {
            Some(mesh) => mesh.find_tardis_parent(),
            None => MeshAction::None,
        }
    }

    /// Announce lost upstream to mesh peers.
    pub fn mesh_announce_lost_upstream(&self) -> MeshAction {
        match &self.mesh {
            Some(mesh) => mesh.announce_lost_upstream(),
            None => MeshAction::None,
        }
    }

    /// Get reference to mesh.
    pub fn mesh(&self) -> Option<&GossipMesh> {
        self.mesh.as_ref()
    }

    /// Get mutable reference to mesh.
    pub fn mesh_mut(&mut self) -> Option<&mut GossipMesh> {
        self.mesh.as_mut()
    }

    // ── Companion Certificate (Phase 5) ──

    /// Initialize the CC chain with an NBC.
    /// If a CC was restored from snapshot/WAL, it is picked up here so
    /// penguin score (ticks_helped, total_registrations) survives restart.
    pub fn init_cc(&mut self, nbc: NBC) {
        let mut chain = CcChain::new(nbc);
        if let Some(cc) = self.restored_cc.take() {
            chain.accept_cc(cc);
        }
        self.cc_chain = Some(chain);
    }

    /// Record a registration in the CC chain (called after each successful registration).
    pub fn cc_record_registration(&mut self) {
        if let Some(chain) = self.cc_chain.as_mut() {
            chain.record_registration();
        }
    }

    /// Produce and accept a new CC for the current tick.
    /// Called once per tick after all registrations for that tick are processed.
    /// Writes CC to WAL before accepting (crash-safe).
    pub fn cc_tick(&mut self) -> Option<CompanionCertificate> {
        let chain = self.cc_chain.as_mut()?;
        let cc = chain.produce_cc(self.current_tick, self.signer.as_ref());
        // WAL before state mutation
        if let Ok(bytes) = bincode::serialize(&cc) {
            let _ = self.wal.append(&WalOp::CcUpdate {
                tick: self.current_tick,
                cc_bytes: bytes,
            });
        }
        chain.accept_cc(cc.clone());
        Some(cc)
    }

    /// Get the latest CC.
    pub fn latest_cc(&self) -> Option<&CompanionCertificate> {
        self.cc_chain.as_ref()?.latest()
    }

    /// Add DEED fee to runner pool (with split).
    pub fn runner_pool_add_fee(&mut self, fee: u64) {
        self.runner_pool.add_deed_fee(fee, self.current_tick);
    }

    /// Get runner pool balance.
    pub fn runner_pool_balance(&self) -> u64 {
        self.runner_pool.balance
    }

    /// §17.11: Airdrop pool balance (genesis claim funding).
    pub fn airdrop_pool(&self) -> &AirdropPool {
        &self.airdrop_pool
    }

    /// FACT class isolation §6: Dev Treasury pool balance (dev-AXC
    /// genesis claim funding, 1M cap, OUTSIDE the 100M public cap).
    /// Read-only accessor for dashboards / observability.
    pub fn dev_treasury_pool(&self) -> &DevTreasuryPool {
        &self.dev_treasury_pool
    }

    /// §17.11: Attempt a genesis claim from the airdrop pool.
    /// Returns `ClaimOutcome` (Granted on success, or one of three
    /// distinct refusal reasons — see `ClaimOutcome`). Persists the
    /// new pool state on success so a restart picks up where we
    /// left off.
    pub fn try_airdrop_claim(&mut self) -> ClaimOutcome {
        let outcome = self.airdrop_pool.try_claim(self.current_tick);
        if matches!(outcome, ClaimOutcome::Granted) {
            if let Err(e) = self.persist_pool_states() {
                log::warn!("[POOL-PERSIST] save after airdrop claim failed: {e}");
            }
        }
        outcome
    }

    /// Contribution emission: the per-tick epoch roll (every node, every tick;
    /// idempotent per epoch) and the claim path used by the register handler.
    pub fn emission(&self) -> &crate::emission::EmissionPools {
        &self.emission
    }
    pub fn deed_pool(&self) -> &DeedPool {
        &self.deed_pool
    }
    pub fn emission_maybe_roll(&mut self) -> Option<crate::emission::EpochRoll> {
        let tick = self.current_tick;
        let roll = self.emission.maybe_roll(tick, &mut self.deed_pool);
        if roll.is_some() {
            if let Err(e) = self.persist_pool_states() {
                log::warn!("[POOL-PERSIST] save after emission roll failed: {e}");
            }
        }
        roll
    }
    pub fn emission_record_claim(&mut self, pool: u8, identity: [u8; 32], amount: u64) -> ClaimOutcome {
        let tick = self.current_tick;
        let out = self.emission.record_claim(pool, identity, amount, tick);
        if matches!(out, ClaimOutcome::Granted) {
            if let Err(e) = self.persist_pool_states() {
                log::warn!("[POOL-PERSIST] save after emission claim failed: {e}");
            }
        }
        out
    }

    /// Read-only accessors for the validator-join subsidy pools.
    pub fn bootstrap_pool(&self) -> &AirdropPool {
        &self.bootstrap_pool
    }
    pub fn foundation_bootstrap_pool(&self) -> &AirdropPool {
        &self.foundation_bootstrap_pool
    }

    /// Attempt a validator-join stake grant from the subsidy pool for `tier`
    /// (`AXIOM_DESIGN_ValidatorJoin.md` §4 step 3).
    ///
    /// Tier 2 (Foundation) draws 500,000 from `FoundationBootstrap`; tier 3
    /// (Community) draws 500 from `Bootstrap`. The pools are separate so the
    /// two tiers can never cross-credit — draining Community can never fund a
    /// Foundation seat, and vice versa.
    ///
    /// **Tier 1 is not grantable here and returns `RefusedExhausted`.** Genesis
    /// stakes are minted at the G1 ceremony and there is no pool behind them;
    /// an unknown tier takes the same path. Refusing rather than defaulting is
    /// deliberate — a fallback to the cheapest pool would let a malformed tier
    /// silently draw a Community grant.
    ///
    /// **Refusal is not a refusal to JOIN.** `RefusedExhausted` means the
    /// subsidy is gone; the candidate can still join by holding the floor
    /// itself (§4.1). Callers must not translate this into a join failure.
    ///
    /// Replay protection is NOT here: the join TX carries a txid and Nabla's
    /// existing consume-once index rejects a second presentation, exactly as
    /// it does for a genesis claim. Duplicating that check in the pool would
    /// be a second, drifting source of truth.
    pub fn try_validator_join_claim(&mut self, tier: u8) -> ClaimOutcome {
        let tick = self.current_tick;
        let outcome = match tier {
            2 => self.foundation_bootstrap_pool
                .try_claim_amount(tick, axiom_core_logic::types::TIER2_CLAIM_ATOMS),
            3 => self.bootstrap_pool
                .try_claim_amount(tick, axiom_core_logic::types::TIER3_CLAIM_ATOMS),
            other => {
                log::warn!(
                    "[JOIN-GRANT] refusing grant for tier {other} — only tiers 2 and 3 \
                     are pool-funded (tier 1 is ceremony-minted)"
                );
                ClaimOutcome::RefusedExhausted
            }
        };
        if matches!(outcome, ClaimOutcome::Granted) {
            log::info!(
                "[JOIN-GRANT] tier={} granted; bootstrap_balance={} foundation_balance={}",
                tier,
                self.bootstrap_pool.balance(),
                self.foundation_bootstrap_pool.balance(),
            );
            if let Err(e) = self.persist_pool_states() {
                log::warn!("[POOL-PERSIST] save after validator-join grant failed: {e}");
            }
        }
        outcome
    }

    /// Same as `try_airdrop_claim` but against the DevTreasury pool.
    /// Used by the `@axiom.internal` claim path.
    pub fn try_dev_treasury_claim(&mut self) -> ClaimOutcome {
        let outcome = self.dev_treasury_pool.try_claim(self.current_tick);
        if matches!(outcome, ClaimOutcome::Granted) {
            if let Err(e) = self.persist_pool_states() {
                log::warn!("[POOL-PERSIST] save after dev-treasury claim failed: {e}");
            }
        }
        outcome
    }

    /// Build a `PoolSync` gossip message for the given pool's current state,
    /// signed with this node's Ed25519 key. Phase B Layer 4 attribution
    /// path requires every PoolSync to be self-authenticating; receivers
    /// verify before reconcile so any reconcile-detected violation can be
    /// attributed unambiguously to the signer
    /// (`docs/AXIOM_DESIGN_NablaPoolCaps.md` §5.6.5).
    pub fn pool_sync_message(&self, pool: crate::types::PoolKind) -> crate::types::GossipMessage {
        // KI#191 — the snapshot carries its own conservation terms so a
        // receiver can judge the peer's COHERENT single message (JUDOON §2.5)
        // rather than mixing in its own numbers. Pools that do not track them
        // send 0/0 and are judged by their own `reconcile`, unchanged.
        let (balance, total_claims, paid_out, topped_up) = match pool {
            crate::types::PoolKind::Airdrop => {
                (self.airdrop_pool.balance(), self.airdrop_pool.total_claims, self.airdrop_pool.paid_out(), self.airdrop_pool.topped_up())
            }
            crate::types::PoolKind::DevTreasury => {
                (self.dev_treasury_pool.balance(), self.dev_treasury_pool.total_claims, 0u64, 0u64)
            }
            crate::types::PoolKind::Bootstrap => {
                (self.bootstrap_pool.balance(), self.bootstrap_pool.total_claims, self.bootstrap_pool.paid_out(), self.bootstrap_pool.topped_up())
            }
            crate::types::PoolKind::FoundationBootstrap => {
                (self.foundation_bootstrap_pool.balance(),
                 self.foundation_bootstrap_pool.total_claims,
                 self.foundation_bootstrap_pool.paid_out(),
                 self.foundation_bootstrap_pool.topped_up())
            }
            crate::types::PoolKind::EmissionValidators => {
                (self.emission.validators.balance(), self.emission.validators.total_claims, self.emission.validators.paid_out(), self.emission.validators.topped_up())
            }
            crate::types::PoolKind::EmissionNabla => {
                (self.emission.nabla.balance(), self.emission.nabla.total_claims, self.emission.nabla.paid_out(), self.emission.nabla.topped_up())
            }
            crate::types::PoolKind::Deed => {
                // `total_claims` on the wire carries `total_credited` for
                // the DEED pool — the same lifetime-counter role the
                // claims counter plays for airdrop/dev_treasury.
                (self.deed_pool.balance(), self.deed_pool.total_credited(), 0u64, 0u64)
            }
            crate::types::PoolKind::DevDeed => {
                // Dev-class DEED — same monotonic-increase wire shape as
                // the public DEED, but a distinct sign_tag (0x04) so the
                // gossip payload binds the class. A peer that receives
                // a DevDeed PoolSync with a Deed sign_tag fails the
                // signature verify and the alert layer flags it.
                (self.dev_deed_pool.balance(), self.dev_deed_pool.total_credited(), 0u64, 0u64)
            }
            crate::types::PoolKind::BoundedFee(vid, is_dev) => {
                // Per-validator FOB Fee pool, class in the key. `total_claims`
                // carries the lifetime `tranched_total` (Σ attested tranches) —
                // the monotonic conservation counter (§7 pt 3), same role
                // total_credited plays for DEED. Balance is 0/last-tranche
                // (two-state). A pool this node has never seen reads (0, 0).
                self.fob_pools
                    .get(&(vid, is_dev))
                    .map(|p| (p.balance(), p.tranched_total(), 0u64, 0u64))
                    .unwrap_or((0, 0, 0, 0))
            }
        };
        let tick = self.current_tick;
        let sender_node_id: NodeId = self
            .mesh
            .as_ref()
            .map(|m| *m.my_node_id())
            .unwrap_or([0u8; 32]);
        let payload = crate::crypto::pool_sync_sign_payload(
            pool.sign_tag(), balance, total_claims, paid_out, topped_up, tick,
            &sender_node_id, pool.bounded_fee_key(),
        );
        let sender_sig = self.signer.sign(&payload);
        crate::types::GossipMessage::PoolSync {
            pool,
            balance,
            total_claims,
            paid_out,
            topped_up,
            tick,
            sender_node_id,
            sender_sig,
        }
    }

    /// Dev-mode: set airdrop pool balance directly (for soak test).
    /// Bypasses the §5.5 invariant; production code MUST NOT use this.
    #[cfg(feature = "dev-mode")]
    pub fn set_airdrop_pool_balance(&mut self, balance: u64) {
        self.airdrop_pool.force_balance_dev_only(balance);
    }

    // ── Layer 4 Quarantine (PoolCaps design §5.6) ─────────────────────────

    /// Build a `GossipMessage::Alert` for the given pool-state violation.
    /// Called when reconcile returns InvariantViolation or
    /// MagnitudeViolation. The caller (gossip dispatch) emits the
    /// returned message to the mesh.
    pub fn build_pool_invariant_alert(
        &self,
        accused: NodeId,
        evidence: Vec<u8>,
    ) -> crate::types::GossipMessage {
        let self_id: NodeId = self
            .mesh
            .as_ref()
            .map(|m| *m.my_node_id())
            .unwrap_or([0u8; 32]);
        // KI#72: sign this hop. We are both origin and intermediate here, so
        // the signature proves the alert really came from us — the property
        // §5.6.5's dual-uniqueness count needs and never had.
        let payload = crate::crypto::pool_alert_sign_payload(
            crate::types::AlertType::PoolInvariantViolation as u8,
            &accused,
            &evidence,
            &self_id,
            &self_id,
            self.current_tick,
        );
        let intermediate_sig = self.signer.sign(&payload);
        crate::types::GossipMessage::Alert {
            alert_type: crate::types::AlertType::PoolInvariantViolation,
            accused,
            evidence,
            origin_emitter: self_id,
            intermediate_emitter: self_id,
            emitted_at_tick: self.current_tick,
            intermediate_sig,
        }
    }

    /// Handle an incoming `GossipMessage::Alert` from peer `sender_id`.
    /// `sender_id` is the NBC-verified TCP source (the caller validated
    /// it before calling us). Returns the action the caller should take:
    /// drop, forward, or also act on a triggered quarantine.
    /// `verified_sender` is the peer identity the TRANSPORT PROVED, or `None`
    /// when it cannot prove one.
    ///
    /// RULE 0 marker (2026-08-07, ghost audit G4). §5.6.4 step 1 is "verify
    /// alert.intermediate_emitter == P (**NBC-bound TCP identity**)", and the
    /// whole dual-uniqueness property in §5.6.5 rests on it: A1/A6/A7 are all
    /// defended by "intermediate = self, TCP-source-verified". That identity
    /// DOES NOT EXIST — `Envelope` carries only a `SocketAddr`, there is no NBC
    /// handshake, and `peer_id_from_addr` matches a peer's LISTEN address while
    /// an inbound connection presents an ephemeral source port.
    ///
    /// The caller used to pass `alert.intermediate_emitter` as the sender, so
    /// the step-1 check compared a field to ITSELF and `DropAndBanScore` was
    /// unreachable. A single attacker could then fabricate 3 distinct
    /// `(origin, intermediate)` pairs, satisfy dual-uniqueness alone, and have
    /// any honest node excluded from every gossip fan-out.
    ///
    /// Until a proven identity exists this takes `None` and FAILS CLOSED: the
    /// alert is still recorded and forwarded for observability, but it can
    /// never activate a quarantine. See KnownIssues KI#72.
    pub fn handle_alert(
        &mut self,
        alert: &crate::types::GossipMessage,
        verified_sender: Option<NodeId>,
    ) -> AlertHandleAction {
        let (accused, origin_emitter, intermediate_emitter, evidence) = match alert {
            crate::types::GossipMessage::Alert {
                accused,
                origin_emitter,
                intermediate_emitter,
                evidence,
                ..
            } => (*accused, *origin_emitter, *intermediate_emitter, evidence),
            _ => return AlertHandleAction::Drop,
        };

        // §5.6.4 step 1: verify intermediate_emitter == TCP source. Runs ONLY
        // when the transport proved a sender; with `None` there is nothing to
        // compare against and pretending otherwise is the ghost this replaced.
        let identity_verified = verified_sender.is_some();
        if let Some(sender_id) = verified_sender {
        if intermediate_emitter != sender_id {
            log::warn!(
                "[ALERT-INTERMEDIATE-MISMATCH] sender={} claimed_intermediate={} \
                 accused={} (forgery attempt — drop + ban-score++)",
                hex::encode(&sender_id[..8]),
                hex::encode(&intermediate_emitter[..8]),
                hex::encode(&accused[..8]),
            );
            return AlertHandleAction::DropAndBanScore { peer: sender_id };
        }
        }

        // §3.5: decode pool_kind from evidence (the signed PoolSync).
        // Evidence-pool binding (§3.5.2): the PoolSync's sender_node_id
        // must match the alert's accused — otherwise a forwarder could
        // substitute evidence from a different pool. §3.5.3: malformed
        // evidence → silent drop with WARN, no panic.
        let evidence_msg: crate::types::GossipMessage =
            match ciborium::de::from_reader(evidence.as_slice()) {
                Ok(m) => m,
                Err(e) => {
                    log::warn!(
                        "[ALERT-EVIDENCE-DECODE-FAILED] accused={} err={} — drop",
                        hex::encode(&accused[..8]), e,
                    );
                    return AlertHandleAction::Drop;
                }
            };
        let (evidence_pool, evidence_sender) = match &evidence_msg {
            crate::types::GossipMessage::PoolSync { pool, sender_node_id, .. } => {
                (*pool, *sender_node_id)
            }
            _ => {
                log::warn!(
                    "[ALERT-EVIDENCE-NOT-POOLSYNC] accused={} — drop",
                    hex::encode(&accused[..8]),
                );
                return AlertHandleAction::Drop;
            }
        };
        if evidence_sender != accused {
            log::warn!(
                "[ALERT-EVIDENCE-POOL-BINDING-FAILED] accused={} evidence_sender={} \
                 (forwarder substituted evidence — drop + ban-score++)",
                hex::encode(&accused[..8]),
                hex::encode(&evidence_sender[..8]),
            );
            return match verified_sender {
                Some(peer) => AlertHandleAction::DropAndBanScore { peer },
                None => AlertHandleAction::Drop,
            };
        }

        // §2.7 dispatch: alert_threshold_for returns Some(K) for
        // critical drain-only pools (Airdrop today), None for
        // non-critical and bidirectional pools. None → skip recording
        // entirely.
        let threshold = match crate::judoon::alert_threshold_for(
            evidence_pool,
            &self.airdrop_pool,
        ) {
            Some(k) => k,
            None => return AlertHandleAction::Drop,
        };

        let self_id: NodeId = self
            .mesh
            .as_ref()
            .map(|m| *m.my_node_id())
            .unwrap_or([0u8; 32]);

        let outcome = self.quarantine.record_alert(
            &self_id,
            accused,
            evidence_pool,
            origin_emitter,
            intermediate_emitter,
            self.current_tick,
            threshold,
            identity_verified,
        );

        match outcome {
            AlertRecordOutcome::Duplicate => AlertHandleAction::Drop,
            AlertRecordOutcome::SelfOrigin => {
                log::warn!(
                    "[ALERT-SELF-ORIGIN] from sender={} claimed origin=self — drop",
                    hex::encode(&intermediate_emitter[..8]),
                );
                // Ban-scoring needs a PROVEN peer; without one we would be
                // scoring whoever the packet named, which is attacker-chosen.
                match verified_sender {
                    Some(peer) => AlertHandleAction::DropAndBanScore { peer },
                    None => AlertHandleAction::Drop,
                }
            }
            AlertRecordOutcome::SelfAccused => {
                log::warn!(
                    "[ALERT-SELF-ACCUSED] mesh is forming a quarantine alert about us \
                     (accused=self). Recorded locally; not forwarding."
                );
                AlertHandleAction::Drop
            }
            AlertRecordOutcome::Recorded => AlertHandleAction::Forward,
            AlertRecordOutcome::QuarantineActivated { accused, until_tick } => {
                log::warn!(
                    "[ALERT-QUARANTINE-ACTIVATED] accused={} until_tick={} (3-of-N consensus reached)",
                    hex::encode(&accused[..8]),
                    until_tick,
                );
                AlertHandleAction::ForwardAndQuarantineActive { accused, until_tick }
            }
        }
    }

    /// Is this peer currently quarantined? Called from the
    /// message-receive path: messages from quarantined senders are
    /// dropped. Drop-not-disconnect avoids needing to tear down TCP
    /// sockets; the effect is the same (dead-air for the peer).
    /// Quorums withheld for want of a proven sender identity (G4 / KI#72).
    /// Non-zero means a 3-of-N alert pattern occurred that we refused to act
    /// on — either a real attack we correctly declined to amplify, or an
    /// honest detection we could not safely honour. Either way it must be
    /// visible (CLAUDE.md RULE 3 §2).
    pub fn quarantine_withheld_activations(&self) -> u64 {
        self.quarantine.withheld_activations()
    }

    pub fn is_peer_quarantined(&self, peer: &NodeId) -> bool {
        self.quarantine.is_quarantined(peer, self.current_tick)
    }

    /// Sweep expired quarantine + pending entries. Call once per tick.
    /// On expiry, also clear the mesh-side quarantine filter so the
    /// formerly-quarantined peer is re-included in gossip fan-out and
    /// can rejoin via existing anti-entropy / StatePull.
    pub fn quarantine_sweep(&mut self) {
        let current = self.current_tick;
        // Snapshot active quarantined peers BEFORE the sweep so we can
        // detect which ones the sweep is about to expire.
        let before: Vec<NodeId> = self
            .quarantine
            .active_iter()
            .map(|(id, _)| *id)
            .collect();
        self.quarantine.sweep(current);

        // Layer 1 probation sweep: any probation entry whose countdown
        // has elapsed without recovery escalates to quarantine via the
        // proof-shaped path (NOT K-of-N). Per §2.5 escalation semantics.
        let escalated = self.quarantine.sweep_probation(current);
        for (peer, entry) in &escalated {
            log::warn!(
                "[JUDOON/ZERO-ROOM-EXPIRED-TO-QUARANTINE] peer={} initial_proof={:?} \
                 elapsed_ticks={} — escalating via proof-shaped path",
                hex::encode(&peer[..8]),
                entry.initial_proof,
                current.saturating_sub(entry.started_at_tick),
            );
            if let Some(mesh) = self.mesh.as_mut() {
                mesh.set_quarantined_peer(*peer, true);
            }
        }

        // For every NodeId that was active before but isn't quarantined
        // anymore at `current`, clear its mesh-filter entry → eligible
        // for gossip again.
        if let Some(mesh) = self.mesh.as_mut() {
            for peer in &before {
                if !self.quarantine.is_quarantined(peer, current) {
                    mesh.set_quarantined_peer(*peer, false);
                    log::warn!(
                        "[QUARANTINE-EXPIRED] peer={} — re-included in mesh \
                         gossip fan-out; rejoin runs via existing anti-entropy",
                        hex::encode(&peer[..8]),
                    );
                }
            }
        }
    }

    /// Caller-friendly entry to Layer 1 probation. Called from the
    /// bin layer on `GossipAction::PoolStructuralViolation`. Logs the
    /// transition; the actual escalation happens in
    /// `quarantine_sweep()` once countdown expires.
    pub fn enter_probation_on_structural_violation(
        &mut self,
        accused: NodeId,
        proof: crate::judoon::ProofKind,
    ) {
        let current = self.current_tick;
        self.quarantine.enter_probation(accused, current, proof);
    }

    /// Caller-friendly exit from Layer 1 probation. The reconcile
    /// caller can invoke this when a peer's subsequent PoolSync
    /// passes structural checks — they've recovered before countdown
    /// expiry.
    pub fn clear_probation_on_recovery(&mut self, peer: &NodeId) {
        if let Some(entry) = self.quarantine.clear_probation(peer) {
            log::info!(
                "[JUDOON/ZERO-ROOM-CLEARED] peer={} initial_proof={:?} \
                 elapsed_ticks={} — recovered before countdown expiry",
                hex::encode(&peer[..8]),
                entry.initial_proof,
                self.current_tick.saturating_sub(entry.started_at_tick),
            );
        }
    }

    /// Is this peer currently in Layer 1 probation? Used by the
    /// gossip relay layer to suppress forwarding the peer's PoolSync
    /// during the countdown window.
    pub fn is_peer_probated(&self, peer: &NodeId) -> bool {
        self.quarantine.is_probated(peer)
    }

    /// Push the just-activated quarantine target into the mesh-side
    /// filter so gossip fan-outs immediately skip it. Called from the
    /// bin layer right after `handle_alert` returns
    /// `ForwardAndQuarantineActive`.
    pub fn activate_mesh_quarantine_filter(&mut self, peer: NodeId) {
        if let Some(mesh) = self.mesh.as_mut() {
            mesh.set_quarantined_peer(peer, true);
        }
    }

    /// Access the quarantine state (read-only) for /status telemetry.
    pub fn quarantine_state(&self) -> &QuarantineState {
        &self.quarantine
    }

    /// KI#191 residual — emission-pool structural violations that escalated
    /// to JUDOON probation on this node (cumulative). Read by the bin's
    /// `/status` builder.
    pub fn emission_structural_violations(&self) -> u64 {
        self.emission_structural_violations
    }

    /// YPX-002 §9.1.1a — the issuer's per-epoch budget (read: /status; write:
    /// the bin's `NbcIssuanceRequest` handler, `record` after a signature).
    pub fn nbc_issuance_budget(&self) -> crate::cc::NbcIssuanceBudget {
        self.nbc_issuance_budget
    }
    pub fn nbc_issuance_budget_mut(&mut self) -> &mut crate::cc::NbcIssuanceBudget {
        &mut self.nbc_issuance_budget
    }

    /// Test-only mutable access (persistence tests activate a quarantine
    /// without staging a three-origin alert quorum).
    #[cfg(test)]
    pub fn quarantine_state_mut(&mut self) -> &mut QuarantineState {
        &mut self.quarantine
    }

    // ── Monitoring (Phase 6) ──

    /// Collect a full status snapshot for the monitor.
    pub fn status_snapshot(&self) -> NodeStatusSnapshot {
        let (split_r, split_d) = deed_split(self.current_tick);
        let deed_split_str = format!("{}/{}", split_r, split_d);

        let node_id_hex = self.mesh.as_ref()
            .map(|m| monitor::hex_short(m.my_node_id()))
            .unwrap_or_else(|| "not-set".into());

        let tardis_slot = self.tardis.as_ref()
            .map(|t| format!("{:?}", t.upstream_status()))
            .unwrap_or_else(|| "N/A".into());

        // OODS (YPX-021): read-only size estimate over the node's learned mesh
        // view (Extrema Propagation, identity-bound draws). NOT a consensus gate.
        // Under a partition/eclipse the known set shrinks, so this drops — the
        // detection signal. Cheap: <=256 ids. NOTE: the production `nabla-node`
        // binary anchors this to the VERIFIED-NBC set (see bin/nabla_node.rs) so
        // only real bonded NBCs count; the lib path here uses the mesh view
        // (test/generic — no per-node NBC verification at this layer).
        let oods_estimate = self.mesh.as_ref().map(|m| {
            let self_id = *m.my_node_id();
            let peer_ids: Vec<[u8; 32]> =
                m.known_nodes_snapshot().iter().map(|p| p.node_id).collect();
            crate::oods::estimate_from_ids(&self_id, &peer_ids)
        }).unwrap_or(0.0);

        let (cc_tick, cc_ticks_helped, cc_total_regs, cc_score) = match self.latest_cc() {
            Some(cc) => (cc.tick, cc.ticks_helped, cc.total_registrations, cc.score),
            None => (0, 0, 0, 0),
        };

        let uptime = monitor::uptime_secs(self.start_time);
        let has_upstream = self.tardis.as_ref().map(|t| t.has_upstream()).unwrap_or(false);
        let downstream_count = self.tardis.as_ref().map(|t| t.downstream_count()).unwrap_or(0);
        let is_writer = downstream_count == 2;

        // TARDIS tree peer hex IDs
        let upstream_hex = self.tardis.as_ref()
            .and_then(|t| t.upstream().map(hex::encode))
            .unwrap_or_default();
        let d1_hex = self.tardis.as_ref()
            .and_then(|t| t.d1().map(hex::encode))
            .unwrap_or_default();
        let d2_hex = self.tardis.as_ref()
            .and_then(|t| t.d2().map(hex::encode))
            .unwrap_or_default();

        // Active mesh peers for graph
        let peer_list: Vec<monitor::PeerEntry> = self.mesh.as_ref()
            .map(|m| m.active_peers().iter().map(|p| {
                monitor::PeerEntry {
                    node_id_hex: hex::encode(p.node_id),
                    node_name: String::new(),
                    is_genesis: false, // can't determine from PeerInfo alone
                    txid_service: p.txid_service.clone(),
                }
            }).collect())
            .unwrap_or_default();

        // Penguin scoring — compute from available CC data
        let writes_approved = cc_ticks_helped; // ticks where we had 2 children approved
        let orphans_rescued = 0u64; // tracked by sim only for now
        let rotations_survived = 0u64; // tracked by sim only for now
        let contribution = monitor::penguin_contribution(
            cc_ticks_helped, writes_approved, cc_total_regs,
            orphans_rescued, rotations_survived,
        );
        // Simple uptime % estimate: if node has been up continuously, assume 100%
        let uptime_pct = if uptime > 86400 * 7 { 99.9 } else { 95.0 };
        let rel_mult = monitor::reliability_multiplier(uptime_pct);
        let penguin_score = (contribution as f64 * rel_mult) as u64;
        let (level_name, level_emoji) = monitor::penguin_level(penguin_score);
        let uptime_streak_days = uptime / 86400;

        let (addr_disputed, addr_reports) = self.tardis.as_ref()
            .map(|t| (t.address_disputed(), t.address_report_count()))
            .unwrap_or((false, 0));
        let mut status = NodeStatusSnapshot {
            built_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            address_disputed: addr_disputed,
            address_reports: addr_reports,
            // §5.6a-bis — see monitor::NodeStatusSnapshot. This snapshot
            // builder has no mesh handle in scope; the live value is
            // supplied by the nabla_node.rs builder.
            slot_hints_dropped_unobserved: 0,
            // §5.6a / NBC — this builder has no node handle in scope; the live
            // values come from the nabla_node.rs snapshot builder.
            address_observers: Vec::new(),
            address_unroutable: false,
            nbc_issued_at: 0,
            nbc_expires_at: 0,
            nbc_expires_in_secs: 0,
            nbc_chain_depth: 0,
            nbc_issuer: String::new(),
            version: format!("v{}", env!("CARGO_PKG_VERSION")),
            node_name: self.cc_chain.as_ref().map(|cc| cc.nbc().node_name.clone()).unwrap_or_default(),
            node_id_hex,
            uptime_secs: uptime,
            txid_service: self.smt.txid_mode().to_string(),
            txid_hashmap_len: self.smt.txid_hashmap_len() as u64,
            txid_hashmap_bytes: self.smt.txid_hashmap_bytes(),
            txid_bloom_count: self.smt.txid_bloom_count(),
            txid_bloom_bytes: self.smt.txid_bloom_bytes(),
            txid_bloom_fpr: self.smt.txid_bloom_fpr(),
            txid_bloom_fill_ratio: self.smt.txid_bloom_fill_ratio(),
            consumed_bloom_count: self.smt.consumed_bloom_count(),
            consumed_bloom_fpr: self.smt.consumed_bloom_fpr(),
            consumed_bloom_fill_ratio: self.smt.consumed_bloom_fill_ratio(),
            listen_addr: String::new(),
            wan_addr: None,
            current_tick: self.current_tick,
            tardis_active: self.tardis.is_some(),
            tardis_slot,
            has_upstream,
            downstream_count,
            is_writer,
            d1_approved: false,
            d2_approved: false,
            ticks_with_current_parent: self.tardis.as_ref().map(|t| t.ticks_with_parent()).unwrap_or(0),
            rebalance_cooldown: self.tardis.as_ref().map(|t| t.rebalance_cooldown()).unwrap_or(0),
            orphan_causes: self.tardis.as_ref()
                .map(|t| t.orphan_causes().as_pairs().iter()
                    .map(|(k, v)| (k.to_string(), *v)).collect())
                .unwrap_or_default(),
            lineage_ok: 0,
            lineage_reject: 0,
            lineage_skip: 0,
            audit_exonerated: self.tardis.as_ref().map(|t| t.audit_exonerated()).unwrap_or(0),
            tardis_audit: self.tardis.as_ref()
                .map(|t| t.audit_counters().iter().map(|(k, v)| (k.to_string(), *v)).collect())
                .unwrap_or_default(),
            tickhash_verified: 0,
            tickhash_unverified: 0,
            alert_proven: 0,
            alert_unproven: 0,
            quarantine_withheld: self.quarantine.withheld_activations(),
            // KI#63(c): the AE windows are counted by the bin's tick loop
            // (`nabla_node.rs`), which overrides this field in its own status.
            ae_stall_windows: 0,
            // KI#132 — non-zero means a Core gate leaked (see the field doc).
            stake_lock_observed_not_own_claim:
                crate::registration::stake_lock_observations(),
            audit_resp_unauthorized: self.tardis.as_ref().map(|t| t.audit_responses_unauthorized()).unwrap_or(0),
            audit_resp_unmatched: self.tardis.as_ref().map(|t| t.audit_responses_unmatched()).unwrap_or(0),
            poolsync_drop_unverified: 0,
            approvals_unverified: 0,
            alert_identity_proven: 0,
            alert_identity_unproven: 0,
            wal_deep_scan_corrupt: 0,
            h3_unbuilt_dropped: self.gossip.h3_unbuilt_dropped(),
            ki222_banalert_dropped: self.gossip.ki222_banalert_dropped(),
            root_hash_hex: monitor::hex_short(&self.smt.root_hash()),
            entry_count: self.smt.len(),
            ban_count: self.bans.len(),
            mesh_active: self.mesh.is_some(),
            mesh_peer_count: self.mesh.as_ref().map(|m| m.peer_count()).unwrap_or(0),
            mesh_target_peers: self.mesh.as_ref().map(|m| m.target_peer_count()).unwrap_or(0),
            mesh_known_nodes: self.mesh.as_ref().map(|m| m.known_node_count()).unwrap_or(0),
            estimated_network_size: self.mesh.as_ref().map(|m| m.estimated_network_size()).unwrap_or(0),
            oods_estimate,
            // OODS-tardis is retained on the binary's node state (it processes the
            // ticks); the lib NablaCore status doesn't hold it — the production
            // dashboard uses the binary's status_snapshot, which populates this.
            tardis_depth: 0,
            enquiry_peer_count: self.mesh.as_ref().map(|m| if m.has_enquiry_peer() { 1 } else { 0 }).unwrap_or(0),
            cc_active: self.cc_chain.is_some(),
            cc_tick,
            cc_ticks_helped,
            cc_total_registrations: cc_total_regs,
            cc_score,
            runner_pool_balance: self.runner_pool.balance,
            airdrop_pool_balance: self.airdrop_pool.balance(),
            airdrop_pool_claims: self.airdrop_pool.total_claims,
            airdrop_local_claims: self.airdrop_pool.local_claims,
            dev_pool_balance: self.dev_treasury_pool.balance(),
            dev_pool_claims: self.dev_treasury_pool.total_claims,
            dev_pool_local_claims: self.dev_treasury_pool.local_claims,
            bootstrap_pool_balance: self.bootstrap_pool.balance(),
            bootstrap_pool_claims: self.bootstrap_pool.total_claims,
            foundation_pool_balance: self.foundation_bootstrap_pool.balance(),
            foundation_pool_claims: self.foundation_bootstrap_pool.total_claims,
            deed_collected: self.deed_collected,
            deed_split: deed_split_str,
            deed_pool_balance: self.deed_pool.balance(),
            deed_pool_total_credited: self.deed_pool.total_credited(),
            dev_deed_pool_balance: self.dev_deed_pool.balance(),
            dev_deed_pool_total_credited: self.dev_deed_pool.total_credited(),
            // FOB tranche counters live on the binary NodeState (gossip/tick
            // layer), not the core; the core snapshot defaults them and the
            // binary's status_snapshot fills the real values.
            fob_pools: self.fob_pools_snapshot().iter()
                .map(|(vid, is_dev, bal)| format!(
                    "{}:{}:{}", hex::encode(&vid[..8]),
                    if *is_dev { "dev" } else { "real" }, bal,
                ))
                .collect(),
            fob_tranches_authored: 0,
            fob_tranches_applied: 0,
            fob_tranches_rejected: 0,
            fob_conservation_rejects: self.fob_conservation_rejects,
            emission_epoch: self.emission.epoch,
            emission_rolls: self.emission.rolls,
            emission_top_up_atoms: self.emission.top_up_atoms,
            emission_claims_ok: self.emission.claims_ok,
            emission_claims_refused: self.emission.claims_refused,
            emission_conservation_refusals: self.emission.conservation_refusals,
            gossip_seen_count: self.gossip.seen_count(),
            last_gossip_tick: self.current_tick,
            // 2026-04-15 fix `af79958` companion: TCP transport send
            // failure counters live in `nabla_node.rs::NablaNodeState`
            // (the TCP networking layer), not in this lib-level NablaNode.
            // Library callers (sim, tests) report 0/empty; only the bin
            // path populates the real counts.
            transport_send_failures_total: 0,
            transport_send_failures_per_peer: std::collections::HashMap::new(),
            // KI#37 storm breaker — lib callers (sim/tests) report clean.
            storm_shed_active: false,
            storm_dropped_total: 0,
            storm_trips_total: 0,
            // Fix #1: TARDIS tick-signature verify failures counter.
            // Sourced from the TardisNode; 0 when no upstream is set.
            tick_sig_failures: self.tardis.as_ref()
                .map(|t| t.tick_sig_failures())
                .unwrap_or(0),
            // KI#48 P slot — the parked predicate is lib-owned; the grant
            // counters live in the bin's requester path and are overridden there.
            tardis_parked: self.tardis.as_ref().map(|t| t.is_parked()).unwrap_or(false),
            tardis_parked_grants: 0,
            tardis_parked_to_seated: 0,
            // GUIDE §5.6c — probation is a BIN-level view (verified_nbcs +
            // the refusal counters live in NablaNodeState); the lib node has
            // no peer-NBC map or PoolSync receive path, so it reports the
            // neutral values and the bin's builder overrides all four.
            probationary_peers: 0,
            probation_refusals: 0,
            pool_synced_kinds: Vec::new(),
            pool_sync_gate_open: true,
            // Phase B Layer 4: quarantine telemetry.
            quarantine_active_count: self.quarantine.active_count(),
            quarantine_pending_count: self.quarantine.pending_count(),
            // KI#191 residual — emission-pool structural escalations.
            emission_structural_violations: self.emission_structural_violations,
            // YPX-002 §9.1.1a — the refusal/alarm counters are bin-owned; the
            // lib reports its budget count for the current epoch.
            nbc_issued_this_epoch: self.nbc_issuance_budget.count_in(
                crate::constants::nbc_issuance_epoch(self.current_tick)),
            nbc_issuance_refused_cap: 0,
            nbc_issuer_over_cap_seen: 0,
            penguin_score,
            penguin_level: level_name.into(),
            penguin_emoji: level_emoji.into(),
            uptime_streak_days,
            writes_approved,
            orphans_rescued,
            rotations_survived,
            reliability_multiplier: rel_mult,
            // Persistence metrics
            wal_file_bytes: self.wal.file_size_bytes(),
            wal_ops_since_snapshot: self.wal.ops_since_snapshot(),
            snapshot_count: self.snapshots.snapshot_count(),
            snapshot_total_bytes: self.snapshots.total_size_bytes(),
            last_snapshot_tick: self.last_snapshot_tick,
            total_disk_bytes: self.wal.file_size_bytes() + self.snapshots.total_size_bytes(),
            smt_memory_bytes: self.smt.len() as u64 * 200,
            upstream_hex,
            upstream_name: String::new(),
            d1_hex,
            d1_name: String::new(),
            d2_hex,
            d2_name: String::new(),
            peer_list,
            bootstrap_peers: Vec::new(),
            // KI#79 — the serve-gate is a BIN-level state machine
            // (NablaNodeState.anti_rollback_armed); the lib node has no
            // arming concept, so this snapshot reports armed to keep
            // diagnose() from flagging lib consumers. The deployed
            // /status comes from the bin's own builder, which reports
            // the real flag.
            anti_rollback_armed: true,
            unarmed_rounds: 0,
            unarmed_ticks: 0,
            // KI#65 — the lib node reads the real counters; the bin's own
            // builder does the same from its wrapped core.
            same_seq_marks_manufactured: self.smt.same_seq_mark_counters().0,
            same_seq_marks_cleared: self.smt.same_seq_mark_counters().1,
            same_seq_marks_active: self.smt.same_seq_mark_counters().2 as u64,
            // YPX-022 §2.1.2a (KI#205) — the lib node reads the real counters;
            // the bin's builder does the same from its wrapped core.
            claims_unauthenticated: crate::registration::claims_unauthenticated_total(),
            recalls_refused_claimed: self.smt.recalls_refused_claimed(),
            // ForkSettlement wave 2a — process-wide atomics, one source for
            // both status builders.
            leg_preimage_refused: crate::registration::leg_preimage_refused_total(),
            witness_not_in_directory_refused: crate::registration::witness_not_in_directory_refused_total(),
            declared_state_unanchored: crate::registration::declared_state_unanchored_total(),
            wal_checksum_missing_refused: crate::wal::wal_checksum_missing_refused_total(),
            snapshot_decode_refused: crate::snapshot::snapshot_decode_refused_total(),
            vbc_directory_refused: crate::vbc_directory::directory_refused_total(),
            vbc_stamp_refused_no_floor: crate::registration::vbc_stamp_refused_no_floor_total(),
            vbc_stamp_refused_held: crate::registration::vbc_stamp_refused_held_total(),
            vbc_stamp_refused_wait: crate::registration::vbc_stamp_refused_wait_total(),
            vbc_registry_decode_refused: crate::vbc_directory::registry_decode_refused_total(),
            vbc_directory_ae_refused: crate::vbc_directory::directory_ae_refused_total(),
            vbc_directory_entries: self.vbc_registrations.len() as u64,
            // ForkSettlement wave 3 — ONE builder for both status builders. The
            // lib node has no listener, so no boot floor (0 = not listening).
            origin: self.origin_status(None, 0),
            // ATRAXI lives on NablaNodeState (binary); the core snapshot cannot see it.
            atraxi_open_keys: 0,
            atraxi_claims_opened: 0,
            atraxi_held_refusals: 0,
            healthy: true,
            health_issues: Vec::new(),
        };

        monitor::diagnose(&mut status);
        status
    }

    // ── Persistence metrics (for dashboard) ──

    /// Collect persistence metrics for dashboard display.
    /// Involves filesystem stat calls — call on dashboard request only, not every tick.
    pub fn persistence_stats(&self) -> PersistenceStats {
        let smt_entries = self.smt.len();
        let wal_file_bytes = self.wal.file_size_bytes();
        let wal_ops = self.wal.ops_since_snapshot();
        let wal_snap_tick = self.wal.last_snapshot_tick;
        let snap_count = self.snapshots.snapshot_count();
        let snap_latest = self.snapshots.latest_size_bytes();
        let snap_total = self.snapshots.total_size_bytes();
        let ticks_since = self.current_tick.saturating_sub(self.last_snapshot_tick);

        let (cc_helped, cc_regs, cc_score) = self.cc_chain.as_ref()
            .and_then(|c| c.latest())
            .map(|cc| (cc.ticks_helped, cc.total_registrations, cc.score))
            .unwrap_or((0, 0, 0));

        PersistenceStats {
            smt_entries,
            smt_memory_bytes: smt_entries as u64 * 200,
            ban_count: self.bans.len(),
            wal_file_bytes,
            wal_ops_since_snapshot: wal_ops,
            wal_last_snapshot_tick: wal_snap_tick,
            snapshot_count: snap_count,
            snapshot_latest_bytes: snap_latest,
            snapshot_total_bytes: snap_total,
            last_snapshot_tick: self.last_snapshot_tick,
            ticks_since_snapshot: ticks_since,
            total_disk_bytes: wal_file_bytes + snap_total,
            cc_ticks_helped: cc_helped,
            cc_total_registrations: cc_regs,
            cc_score,
        }
    }

    // ── Getters ──
    pub fn current_tick(&self) -> u64 { self.current_tick }
    pub fn set_current_tick(&mut self, tick: u64) { self.current_tick = tick; }
    pub fn root_hash(&self) -> Hash256 { self.smt.root_hash() }
    pub fn entry_count(&self) -> usize { self.smt.len() }
    pub fn ban_count(&self) -> usize { self.bans.len() }
    pub fn deed_collected(&self) -> u64 { self.deed_collected }
    pub fn is_banned(&self, wallet_id: &WalletId) -> bool { self.bans.is_banned(wallet_id) }
    pub fn is_dev_mode(&self) -> bool { self.bans.is_dev_mode() }
    pub fn sign_bytes(&self, payload: &[u8]) -> Vec<u8> { self.signer.sign(payload) }
    pub fn signer_pk(&self) -> Vec<u8> { self.signer.public_key() }
    pub fn data_dir(&self) -> &Path { &self.data_dir }

    // ── Component accessors (for NablaNodeState wrapper) ──
    pub fn smt(&self) -> &SparseMerkleTree { &self.smt }

    /// KI#43a — see the field doc: clean boot WAL replay ⇒ restart is not a
    /// recording gap for the exact consumed-state store.
    pub fn wal_replay_clean(&self) -> bool { self.wal_replay_clean }
    pub fn smt_mut(&mut self) -> &mut SparseMerkleTree { &mut self.smt }

    /// Apply a wallet entry received from a peer via anti-entropy
    /// (`AeReconcile.push` / `AeEntries`). Verifies the client signature
    /// and applies the §5.2 merge rule — returns true if the local SMT
    /// advanced. Never adopts unsigned, banned, or non-superseding state, and
    /// NEVER a peer's `status` (§9o [R57]: normalised to `Normal` before the
    /// merge, counted `ae_status_discarded`).
    /// See `docs/AXIOM_DESIGN_NablaAntiEntropy.md` §5.4/§6.
    ///
    /// DESIGN — PERFECT SYNC IS NOT REQUIRED, AND MUST NOT BE ASSUMED OR ADDED
    /// (YPX-020 §3, "Why absolute Nabla sync is NOT required"). Safety is a
    /// property of the REPLICATED MAJORITY, never of any one node's freshness.
    /// A witnessed spend `X->Y` is mesh-flooded, so the majority holds `Y` and
    /// rejects a fraudulent re-anchor `X->X'` with the ordinary consume-once.
    /// A stale/offline node is noise: if it wrongly rejects -> liveness only
    /// (retry / snapshot re-sync); if it wrongly accepts -> it lands on the
    /// losing side of the `X'`-vs-`Y` fork -> ban (attacker-only). One node
    /// cannot flip a majority. Therefore: do NOT add per-node sync guarantees,
    /// mesh-wide head queries ("pull-on-completion"), or convergence proofs to
    /// make every node perfectly fresh — they buy zero safety the majority does
    /// not already provide, and cost bandwidth + sync. The future witness-backed
    /// gossip + the wait keep the MAJORITY uncorrupted; that is sufficient.
    ///
    /// `now_secs` = the binary's wall clock (`virtual_secs`), stamped on the
    /// origin record this path creates (ForkSettlement §2.4 [R13]).
    pub fn apply_remote_entry(
        &mut self,
        entry: &NablaEntry,
        seq_proof: Option<&crate::types::SeqProof>,
        now_secs: u64,
    ) -> bool {
        let adopted = self.apply_remote_entry_inner(entry, seq_proof, now_secs);
        // ForkSettlement §2.3 — WAL the record / verdict this entry produced on
        // EVERY return path (a refused entry can still carry a recorded leg).
        self.drain_fork_side_effects();
        adopted
    }

    fn apply_remote_entry_inner(
        &mut self,
        entry: &NablaEntry,
        seq_proof: Option<&crate::types::SeqProof>,
        now_secs: u64,
    ) -> bool {
        // Structurally empty — never adopt.
        if entry.current_state == [0u8; 32] || entry.tick == 0 {
            return false;
        }
        if self.bans.is_banned(&entry.wallet_id) {
            return false;
        }
        // YPX-009 ENFORCED (KI#46 zero-pk flip, 2026-07-30): authorship is
        // required on BOTH replication paths — the gossip flood
        // (`apply_state_update`) rejects zero-pk, so anti-entropy rejects it
        // identically (the two paths must decide the same or the mesh
        // diverges). A zero-pk entry re-offered by AE is legacy debris whose
        // head could never verify anyway — the drop is now uniform and
        // labeled instead of an exemption here and a wedge there.
        // GROUP carve-out: group-wallet entries are written by
        // `apply_group_update` with zero pk BY DESIGN — group authorship
        // rides the GroupUpdate wire (its own seq/authorship wire is a
        // recorded follow-on, see apply_group_update's WI3 note), not the
        // per-wallet YPX-009 state sig. Rejecting them here would wedge
        // group replication in a permanent AE re-offer loop.
        if entry.client_pk == [0u8; 32] && entry.group_members.is_none() {
            log::info!(
                "[AE-REJECT] client-sig wallet={:02x}{:02x} zero-pk (unauthored \
                 entry; YPX-009 enforced)",
                entry.wallet_id[0], entry.wallet_id[1],
            );
            return false;
        }
        // KI#226 — the row must be the SIGNING KEY's own (same rule as the
        // flood, `registration::bucket_derives_from_key`): an AE entry whose
        // `wallet_id` is not a bucket of its own `client_pk` is refused and
        // counted. The group carve-out (zero pk) above is unchanged — a group
        // entry has no key to derive from.
        if entry.client_pk != [0u8; 32]
            && !crate::registration::bucket_derives_from_key(&entry.wallet_id, &entry.client_pk)
        {
            crate::registration::note_wallet_id_key_mismatch(
                &entry.wallet_id, &entry.client_pk, &entry.tx_hash, "anti-entropy",
            );
            return false;
        }
        if entry.client_pk != [0u8; 32]
            && !crate::gossip::verify_client_state_sig(
            &entry.client_pk,
            &entry.client_sig,
            &entry.wallet_id,
            &entry.current_state,
            &entry.tx_hash,
        ) {
            // KI#46: name the gate — a silent drop here masked the dead-flood
            // diagnosis for weeks (rejects logged only at the later seq gate).
            log::info!(
                "[AE-REJECT] client-sig wallet={:02x}{:02x} sig_len={} (authorship \
                 verify failed)",
                entry.wallet_id[0], entry.wallet_id[1], entry.client_sig.len(),
            );
            return false;
        }
        // ForkSettlement wave 2a (§2.2 carrier) — the SAME leg check the flood
        // path runs (RULE 1: `registration::verify_seq_proof_leg`): a carried
        // proof whose leg does not reproduce its own k-signed commitment_hash
        // and this entry's tx_hash / client_pk / seq is refused (counted,
        // `leg_preimage_refused`). `NablaEntry` carries no parent, so there is
        // no [R‑MEDIUM-3] comparison on this path (`None`).
        if let Some(p) = seq_proof {
            if let Err(reason) = crate::registration::verify_seq_proof_leg(
                p, &entry.tx_hash, &entry.client_pk, None, Some(&entry.current_state), entry.wallet_seq,
            ) {
                crate::registration::note_leg_refused(
                    reason, &entry.wallet_id, &entry.tx_hash, "anti-entropy",
                );
                return false;
            }
        }
        // ForkSettlement §2.3 [R6, R10] — the record-keyed fork detector on the
        // AE path. The carried leg is recorded HERE, ABOVE the consumed-state
        // drop, the unattested-advance reject and the `superseded_by` loser
        // below (a leg is evidence even when this node refuses the head), and
        // BEFORE `put_with_proof` [R24]. Keyed on the records, never on the
        // head: a second leg under `(pk, consumed)` IS the claim — send or
        // redeem (W7b: redeem legs go to the separate redeem ledger on the
        // shared index). The group carve-out (zero pk) records nothing —
        // `verify_fork_leg` refuses it. `NablaEntry` carries no parent; the
        // parent is the preimage's.
        if let Some(p) = seq_proof {
            if entry.client_pk != [0u8; 32] {
                let leg = ForkLeg {
                    new_state: entry.current_state,
                    tx_hash: entry.tx_hash,
                    client_sig: entry.client_sig.clone(),
                    seq_proof: p.clone(),
                };
                if let crate::ban::LegRecordOutcome::ForkBanned { .. } =
                    crate::ban::record_leg_and_detect(
                        &mut self.smt, &mut self.bans, leg, now_secs, "anti-entropy",
                    )
                {
                    return false;
                }
            }
        }

        // THREAT §5.4 partial hardening (AXIOM_THREAT_CollusionWipeRevival.md):
        // never adopt an entry whose current_state was already advanced past
        // (consumed) on THIS node — A12 consume-once moved onto the anti-entropy
        // adoption path. The check is against the node's OWN monotonic
        // consumed-set, which a remote peer cannot forge around. A legitimate
        // entry's current_state is a fresh head, never consumed, so this never
        // false-rejects honest traffic; only a re-advertisement of a consumed
        // head is rejected. PARTIAL: catches an exact rollback to a literal
        // consumed state, NOT a fork to a brand-new state X' (that needs the
        // wire-level continuity/seq fix — see §6a/§9, Linux+soak). Also depends
        // on §5.2 (the consumed-set must be present; a wiped+AE-recovered node
        // has an empty set and this gate is blind there).
        if self.smt.is_state_consumed(&entry.current_state) {
            // KI#38 diagnosis: name the gate so an AE non-convergence can be
            // attributed from logs instead of guessed at. Rejecting a
            // consumed re-advertisement is CORRECT behavior — the log only
            // matters when a mesh sits at applied=0 forever.
            log::info!(
                "[AE-REJECT] consumed-state wallet={:02x}{:02x} seq={} state={:02x}{:02x}..",
                entry.wallet_id[0], entry.wallet_id[1],
                entry.wallet_seq,
                entry.current_state[0], entry.current_state[1],
            );
            return false;
        }
        // WI3 hole-1 (KI#34 §5.4): `wallet_seq` is the PRIMARY merge key, and a
        // bare seq replicated over anti-entropy is forgeable — a malicious peer
        // can inject a fork `X'` with a self-stamped high seq to win the merge.
        // Require the carried k=3 proof to verify before an entry can ADVANCE the
        // seq past what we hold (or set a non-zero seq on first sight). Same gate,
        // same deterministic decision as the flood path (`apply_state_update`).
        let held_seq = self.smt.get(&entry.wallet_id).map(|e| e.wallet_seq);
        let advances_seq = match held_seq {
            Some(h) => entry.wallet_seq > h,
            None => entry.wallet_seq > 0,
        };
        // KI#224 (owner ruling 2026-10-02, "gate ALL paths") — the SAME
        // directory predicate as door step 5b⁗ and the flood: a proof whose
        // witness keys do not ALL walk back to the root through THIS node's R42
        // directory does not attest (treated as CARRIED-BUT-FAILED). Not
        // remembered as refused: the next head-AE round re-offers the entry,
        // and it is adopted once `adopt_verified_directory_entries` admitted
        // the key.
        let seq_verified = seq_proof
            .is_some_and(|p| crate::registration::verify_seq_proof(p, &entry.tx_hash, entry.wallet_seq));
        let is_witness = |pk: &[u8; 32]| self.vbc_registrations.is_witness(pk);
        let seq_attested = seq_verified && match seq_proof {
            Some(p) if crate::ban::seq_proof_is_directory_witnessed(p, &is_witness) => true,
            Some(p) => {
                let unknown = crate::ban::first_non_directory_witness(p, &is_witness).unwrap_or_default();
                crate::registration::note_witness_not_in_directory(&unknown, &entry.wallet_id, &entry.tx_hash, "anti-entropy");
                false
            }
            None => false,
        };
        if advances_seq && !seq_attested {
            // KI#38 diagnosis: distinguish "no proof carried" (retention gap —
            // e.g. the origin node never retains its own proof) from "proof
            // carried but verify failed" (commitment/txid-domain mismatch).
            log::info!(
                "[AE-REJECT] seq-unattested wallet={:02x}{:02x} held_seq={:?} incoming_seq={} proof={} tx_hash={:02x}{:02x}..",
                entry.wallet_id[0], entry.wallet_id[1],
                held_seq, entry.wallet_seq,
                if seq_proof.is_some() { "CARRIED-BUT-FAILED" } else { "ABSENT" },
                entry.tx_hash[0], entry.tx_hash[1],
            );
            return false;
        }
        // Fork Settlement §9o [R57] (W3; KI#236) — the leaf `status` is a
        // LOCAL projection, NEVER adopted from a peer. It lies outside every
        // signature (`client_sig` covers wallet_id ‖ state ‖ tx only) and an AE
        // entry has no authenticated sender, so adopting it let ANY party that
        // can reach this node freeze or ban ANY wallet mesh-wide by re-sending
        // the victim's genuine head with `status = Banned` (rank rule 1 made it
        // win the merge). Normalise to `Normal` BEFORE `superseded_by`, on the
        // existing-head AND first-sight paths alike: rank rule 1 then protects
        // only THIS node's own holds (`Banned` = its own BanTable evidence,
        // `Frozen` = its own E3 judgment, `Tainted` = its own E6 derivation).
        // Bans travel only as self-proving evidence (ForkBan, AE `fork_bans`,
        // R48 records). Counted (`ae_status_discarded`, RULE 3 §2).
        let normalised;
        let entry = if entry.status != WalletStatus::Normal {
            self.ae_status_discarded = self.ae_status_discarded.saturating_add(1);
            if self.ae_status_discarded.is_power_of_two() {
                log::warn!(
                    "[STATUS-NOT-ADOPTED] wallet={:02x}{:02x} incoming status {:?} discarded — \
                     the leaf status is a local projection (ForkSettlement §9o [R57], KI#236); \
                     total discarded: {}",
                    entry.wallet_id[0], entry.wallet_id[1], entry.status, self.ae_status_discarded,
                );
            }
            normalised = NablaEntry { status: WalletStatus::Normal, ..entry.clone() };
            &normalised
        } else {
            entry
        };
        let superseding = match self.smt.get(&entry.wallet_id) {
            Some(existing) => {
                // KI#77 — same two flags the flood path passes, computed the
                // same way. `seq_attested` above is the VERIFIED result, not
                // merely "a proof was carried".
                let self_attested = self.smt.seq_proof(&entry.wallet_id).is_some();
                existing.superseded_by(entry, self_attested, seq_attested)
            }
            None => true,
        };
        if !superseding {
            // KI#38 diagnosis: the merge rule kept the local entry. Log the
            // comparison keys so a stuck tie (leaf digest differs but merge
            // can't pick a winner) is visible.
            if let Some(existing) = self.smt.get(&entry.wallet_id) {
                log::info!(
                    "[AE-REJECT] not-superseding wallet={:02x}{:02x} held(seq={} tick={} state={:02x}{:02x}) vs incoming(seq={} tick={} state={:02x}{:02x})",
                    entry.wallet_id[0], entry.wallet_id[1],
                    existing.wallet_seq, existing.tick,
                    existing.current_state[0], existing.current_state[1],
                    entry.wallet_seq, entry.tick,
                    entry.current_state[0], entry.current_state[1],
                );
            }
        }
        if superseding {
            // §5.2.4 (KI#123): the disposition is declared — a verified proof
            // is installed atomically with the head (so this node can in turn
            // re-attest the seq when it serves the head to another AE peer);
            // an unattested equal-seq winner declares MergeWinner and the
            // KI#38 lock-step leaves the correct proof-absence. Same branch
            // the flood path takes — the two paths MUST decide identically
            // (KI#46) and now retain identically too.
            let disposition = if seq_attested {
                crate::smt::PutProof::Attested(seq_proof.unwrap().clone())
            } else {
                crate::smt::PutProof::ProoflessByDesign(
                    crate::smt::ProoflessKind::MergeWinner,
                )
            };
            self.smt.put_with_proof(entry, disposition);
        }
        superseding
    }
    pub fn bans(&self) -> &BanTable { &self.bans }
    pub fn bans_mut(&mut self) -> &mut BanTable { &mut self.bans }
    pub fn gossip(&self) -> &GossipEngine { &self.gossip }
    pub fn gossip_mut(&mut self) -> &mut GossipEngine { &mut self.gossip }
    pub fn signer(&self) -> &dyn Signer { self.signer.as_ref() }
    /// Disjoint borrow of the SMT (mut) and the node signer — for a handler that
    /// marks the SMT and signs in one call (KI#59 `registration::ooo_confirm`).
    pub fn smt_mut_and_signer(&mut self) -> (&mut SparseMerkleTree, &dyn Signer) {
        (&mut self.smt, self.signer.as_ref())
    }
    /// Cheap `Arc::clone` of the signer — returns an owned handle that can
    /// be used to call `signer.sign(..)` without holding any reference to
    /// `self`. Used by the `/clara` HTTP handler to drop the global node
    /// lock before signing the attestation. See audit pass #2 finding 3
    /// (beta6).
    pub fn signer_arc(&self) -> Arc<dyn Signer> { Arc::clone(&self.signer) }
    pub fn cc_chain(&self) -> Option<&CcChain> { self.cc_chain.as_ref() }
    pub fn cc_chain_mut(&mut self) -> Option<&mut CcChain> { self.cc_chain.as_mut() }
    /// Update the NBC in the CC chain (for renewal). Preserves CC state.
    pub fn set_nbc(&mut self, nbc: NBC, _supporting: Vec<NBC>) {
        if let Some(chain) = self.cc_chain.as_mut() {
            chain.update_nbc(nbc);
        }
    }
    /// YPX-011: Store signed FACT #0 payload for permanent persistence.
    /// Called once during genesis ceremony. Persisted in snapshots.
    pub fn store_genesis_fact(&mut self, payload: Vec<u8>) {
        self.genesis_fact_payload = Some(payload);
    }

    /// YPX-011: Get FACT #0 payload (if stored).
    pub fn genesis_fact_payload(&self) -> Option<&[u8]> {
        self.genesis_fact_payload.as_deref()
    }

    pub fn wal(&self) -> &WriteAheadLog { &self.wal }
    pub fn wal_mut(&mut self) -> &mut WriteAheadLog { &mut self.wal }
    pub fn oracle_pool(&self) -> &DailyPoolState { &self.oracle_pool }
    pub fn oracle_pool_mut(&mut self) -> &mut DailyPoolState { &mut self.oracle_pool }
    pub fn runner_pool(&self) -> &RunnerPool { &self.runner_pool }
    pub fn runner_pool_mut(&mut self) -> &mut RunnerPool { &mut self.runner_pool }
    pub fn start_time(&self) -> std::time::SystemTime { self.start_time }

    // ── §32 Merge Protocol — RETIRED into ATRAXI A1 + A5 (ForkSettlement §9r-E4) ──
    //
    // RULE 0 §4 marker (2026-10-02). `handle_fork_evidence` (freeze the "forked"
    // wallet, `propagate_taint` downstream, emit `TaintAlert`) and
    // `check_merge_quarantine` (the 75 s expiry: restore `Tainted` → `Normal`,
    // flood `MergeResolved`) were DELETED. The wrong reading: "the §32 SCAN
    // freezes a fork it sees in gossip and the timer restores the innocent".
    // MEASURED before deletion: the SCAN's only caller ran on `Forward` of a
    // `StateUpdate`, AFTER the update had become the head, so it compared the
    // head with itself and never fired — a ghost. The correct reading (owner
    // ruling 2026-10-01): a fork is judged only by A1 self-proving evidence
    // (`ban::apply_fork_verdict`); a downstream hold only by A5, derived from
    // this node's own records (`provenance.rs`, the vouch); a view disagreement
    // does nothing. Legacy restored `Frozen`/`Tainted` leaves have no writer and
    // no exit; `status_unbacked_at_load` counts them and the pre-deploy gate
    // requires 0 (D-E4-2 — never normalised at load).

    /// Check if a wallet is blocked (frozen/tainted/banned).
    pub fn is_wallet_blocked(&self, wallet_id: &WalletId) -> bool {
        TardisNode::is_wallet_blocked(&self.smt, wallet_id)
    }

    /// Inject a test entry directly into SMT with WAL write (crash-safe).
    /// Dev/test only — bypasses registration validation.
    #[cfg(any(test, feature = "dev-status"))]
    pub fn inject_test_entry(&mut self, entry: &NablaEntry) {
        let value = bincode::serialize(entry).expect("serialize NablaEntry");
        let _ = self.wal.append(&WalOp::Put {
            key: entry.wallet_id,
            value,
            client_pk: entry.client_pk,
            client_sig: entry.client_sig.clone(),
            // Test injection bypasses registration, so there is no receipt to
            // derive an attestation from.
            seq_proof: None,
        });
        // §5.2.4 (KI#123): `SparseMerkleTree::put` is `#[cfg(test)]`-only, so
        // this `dev-status` (non-test) caller failed to compile from the KI#123
        // change until 2026-09-25 — the feature was unbuildable. Declare the
        // disposition the bare form stood for.
        self.smt.put_with_proof(entry, crate::smt::PutProof::RestoredFromLocalState(None));
    }

    /// Inject a test ban directly into the ban table with WAL write (crash-safe).
    /// Dev/test only — bypasses the two-k3-evidence gossip-merge path that is
    /// now the only production code path to a ban (YPX-002 §3.3 / §7.5).
    /// Exists so crash-recovery tests can seed a ban without simulating a
    /// full gossip merge.
    #[cfg(test)]
    pub fn inject_test_ban(
        &mut self,
        wallet_id: WalletId,
        evidence_1: crate::types::ConflictProof,
        evidence_2: crate::types::ConflictProof,
    ) {
        let banned = BannedEntry {
            wallet_id,
            evidence: crate::types::BanEvidence::LegacyConflict(evidence_1.clone(), evidence_2.clone()),
            status: crate::types::BanStatus::Active,
        };
        let bytes = bincode::serialize(&banned).expect("serialize BannedEntry");
        let _ = self.wal.append(&WalOp::Ban { wallet_id, evidence: bytes });
        self.bans.ban(wallet_id, evidence_1, evidence_2);
    }

    /// Inject a test seq-fork (double-spend) ban directly into the ban table with
    /// WAL write (crash-safe). Mirrors `inject_test_ban` but seeds the seq-fork
    /// evidence kind, so the WAL-replay-preserves-origin path can be tested.
    #[cfg(test)]
    pub fn inject_test_seq_fork_ban(
        &mut self,
        wallet_id: WalletId,
        evidence: crate::types::SeqConflictProof,
    ) {
        let banned = BannedEntry {
            wallet_id,
            evidence: crate::types::BanEvidence::SeqFork(evidence.clone()),
            status: crate::types::BanStatus::Active,
        };
        let bytes = bincode::serialize(&banned).expect("serialize BannedEntry");
        let _ = self.wal.append(&WalOp::Ban { wallet_id, evidence: bytes });
        self.bans.ban_seq_fork(wallet_id, evidence);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registration::DEED_PROTOCOL_WALLET_ID;

    /// KI#46 zero-pk flip: gossip/AE fixtures must be wallet-authored — an
    /// unauthored (zero-pk) update/entry is now rejected before the gate a
    /// test means to exercise. Deterministic key from `sk_byte`; sig over
    /// the YPX-009 wallet-state payload for (wallet_id, state, tx).
    fn test_author(
        sk_byte: u8,
        wallet_id: &[u8; 32],
        state: &[u8; 32],
        tx: &[u8; 32],
    ) -> ([u8; 32], Vec<u8>) {
        use ed25519_dalek::{Signer as _, SigningKey};
        let sk = SigningKey::from_bytes(&[sk_byte; 32]);
        let pk = sk.verifying_key().to_bytes();
        let payload = crate::gossip::client_state_sign_payload(wallet_id, state, tx);
        (pk, sk.sign(&payload).to_bytes().to_vec())
    }

    /// KI#226 — a fixture wallet id MUST be its signing key's own row: the pk
    /// of `test_author`'s key `[sk_byte; 32]` (k=3 bucket = pk).
    fn test_wid(sk_byte: u8) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[sk_byte; 32]).verifying_key().to_bytes()
    }

    fn make_valid_reg(wid: u8, old: u8, new: u8) -> (Registration, DeedTransaction) {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = wid;
        let mut old_state = [0u8; 32];
        old_state[0] = old;
        let mut new_state = [0u8; 32];
        new_state[0] = new;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = wid;
        tx_hash[1] = new;

        let reg = Registration {
            declared_balance: 0,
            declared_hibernation_until: 0,
            declared_wall_clock_lock: 0,
            declared_emission_claimed_epoch: 0,
            declared_stake_floor_until: 0,
            declared_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
            fob_claim: None,
            k_tier: 3,
            is_recall: false,
            wallet_id, old_state, new_state, tx_hash,
            receipt: K3Receipt {
                sender_state: None,
                oods_flag: None,
                confidence_index: None,
                consumed_state_id: old_state,
                produced_state_id: new_state,
                amount: 100,
                signatures: vec![
                    WitnessSig { validator_pk: [1; 32], signature: vec![1; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [2; 32], signature: vec![2; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [3; 32], signature: vec![3; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                ],
                program_digest: [0u8; 32],
                tick: 0,
                state_hash: [0u8; 32], new_wallet_seq: 0,
                commitment_hash: [0u8; 32], epoch: 0,
                fee_breakdown: vec![],
            is_dev_class: false,
            },
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
            is_genesis_claim: false,
            is_hal_reanchor: false,
            claimant_wallet_id: String::new(),
            is_dev_claim: false,
            burn_target_tx_id: None,
            // ForkSettlement wave 2a — zero-pk fixture: door 5b′ does not run (group
            // carve-out), and no WITNESS_V2 preimage reproduces this arbitrary tx_hash.
            preimage: crate::types::test_legs::opaque_redeem_leg(),
        };
        let deed = DeedTransaction {
            sender_wallet_id: wallet_id,
            receiver_wallet_id: DEED_PROTOCOL_WALLET_ID,
            amount: crate::constants::DEED_WRITE_FEE,
            signature: vec![0xFF; 64],
        };
        // §5.2.4 (KI#123): real witness rounds ALWAYS sign the receipt
        // commitment, and registration §8 now refuses a head it cannot derive
        // a retainable SeqProof from — the fixture matches production shape
        // (the KI#53 fixture lesson: never construct what the gate excludes).
        let mut reg = reg;
        attest_receipt_commitment(&mut reg);
        (reg, deed)
    }

    /// KI#224 — admit the witnesses these fixtures sign with into the node's
    /// R42 directory (the fixed-seed keys below and the `test_legs`
    /// validators); the door, flood and AE refuse a head whose
    /// witness keys are not directory members. Never a bypass in the node.
    fn admit_fixture_witnesses(n: &mut NablaNode) {
        use ed25519_dalek::SigningKey;
        n.admit_test_validators();
        // `[1..=5]`: `attest_receipt_commitment`; `[0x30..=0x34]`: the AE
        // tests' `mint` proofs.
        for b in (1..=5u8).chain(0x30..=0x34u8) {
            n.admit_witness_for_test(SigningKey::from_bytes(&[b; 32]).verifying_key().to_bytes());
        }
    }

    /// Sign the receipt_commitment with 3 real ed25519 keys — same helper
    /// shape as registration.rs's (§5.2.4).
    fn attest_receipt_commitment(reg: &mut Registration) {
        use ed25519_dalek::{Signer as _, SigningKey};
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            &reg.tx_hash,
            &reg.receipt.state_hash,
            reg.receipt.new_wallet_seq,
            &reg.receipt.commitment_hash,
            reg.receipt.epoch,
            reg.receipt.is_dev_class,
            reg.receipt.oods_flag.as_ref(),
            None,
            reg.receipt.sender_state.as_ref(),
        );
        for (i, ws) in reg.receipt.signatures.iter_mut().enumerate() {
            let sk = SigningKey::from_bytes(&[(i as u8) + 1; 32]);
            ws.validator_pk = sk.verifying_key().to_bytes();
            ws.receipt_commitment_sig = sk.sign(&commitment).to_bytes().to_vec();
        }
    }

    #[test]
    fn node_open_empty() {
        let dir = tempfile::tempdir().unwrap();
        let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert_eq!(node.entry_count(), 0);
        assert_eq!(node.ban_count(), 0);
        assert_eq!(node.deed_collected(), 0);
    }


    /// KI#73 — a head committed after the last snapshot must stay ATTESTABLE
    /// across a restart. Drives the REAL producer end-to-end: a real
    /// `register` (which retains the proof + appends the WAL), then a genuine
    /// reopen through `NablaNode::open`, which is snapshot-load + WAL replay.
    ///
    /// Before the fix, `WalOp::Put` carried no proof and replay's `smt.put`
    /// DELETED the snapshot-restored one (KI#38 lock-step, tx_hash changed).
    /// The node came back holding a head it could not serve over anti-entropy
    /// (`seq-unattested proof=ABSENT`) while its higher seq stopped it adopting
    /// anyone else's — the stable multi-root mesh of 2026-08-07.
    ///
    /// NOTE: an earlier version of this test re-implemented the replay loop
    /// inline and passed against the BUG — mutation-testing caught it. Anything
    /// here must go through `open`.
    #[test]
    fn ki73_registered_head_stays_attestable_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let wid;
        {
            let mut node =
                NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
            let (mut reg, deed) = make_valid_reg(0xE7, 0x00, 0x01);
            // `make_valid_reg` leaves `receipt_commitment_sig` EMPTY, and
            // `SeqProof::from_registration` returns None without at least one
            // 64-byte sig — so every test on that fixture silently skips the
            // KI#38 retention path this test exists to cover. Fill it in here
            // rather than mutating the shared fixture and changing what the
            // other tests mean.
            for (i, ws) in reg.receipt.signatures.iter_mut().enumerate() {
                ws.receipt_commitment_sig = vec![(i as u8) + 1; 64];
            }
            wid = crate::registration::smt_bucket(&reg.wallet_id, reg.k_tier);
            node.register(&reg, &deed, crate::types::test_legs::NOW_SECS).unwrap();

            // A SECOND register, so the WAL replays a head ON TOP of a prior
            // one with a different tx_hash. That is the real KI#73 shape and it
            // is what arms `put`'s KI#38 drop-branch — without a prior head the
            // branch never fires and a set-BEFORE-put ordering bug would slip
            // through green.
            let (mut reg2, deed2) = make_valid_reg(0xE7, 0x01, 0x02);
            for (i, ws) in reg2.receipt.signatures.iter_mut().enumerate() {
                ws.receipt_commitment_sig = vec![(i as u8) + 0x41; 64];
            }
            reg2.receipt.new_wallet_seq = 1;
            node.register(&reg2, &deed2, crate::types::test_legs::NOW_SECS).unwrap();

            assert!(
                node.smt().seq_proof(&wid).is_some(),
                "setup: the register path must retain the attestation (KI#38)"
            );
            // No snapshot is taken — the head lives only in the WAL, which is
            // exactly the window KI#73 stranded.
        }

        // Restart: snapshot-load + WAL replay, the real path.
        let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert_eq!(
            node.entry_count(), 1,
            "the head itself survives replay (it always did — that was the trap)"
        );
        assert!(
            node.smt().seq_proof(&wid).is_some(),
            "KI#73: the head came back UNATTESTABLE. Anti-entropy will reject \
             every push of it with `seq-unattested proof=ABSENT` forever, and \
             this node's higher seq stops it adopting any peer's head — \
             permanent single-node divergence that survives every restart."
        );
    }

    /// KI#78 — a WAL that was corrupted and then recovered by the deep scan
    /// must STILL count the next restart as a recording gap. G11's recovery
    /// rewrites the file clean, so without the durable truncation marker the
    /// next boot reads continuity PROVEN over a hole — an era with missing
    /// entries adjudicated as complete (§12.4.1's dangerous direction).
    ///
    /// Drives the REAL producers end-to-end: real `register` (WAL appends +
    /// in-memory checksums), real on-disk corruption, the real
    /// `audit_deep_and_recover`, and a genuine reopen through
    /// `NablaNode::open`. Mutation check performed during development:
    /// with the marker write removed from `truncate_at`, the first reopen
    /// assertion fails (continuity reads PROVEN over the hole).
    #[test]
    fn ki78_truncated_wal_counts_restart_as_gap() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut node =
                NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
            let (reg, deed) = make_valid_reg(0xD8, 0x00, 0x01);
            node.register(&reg, &deed, crate::types::test_legs::NOW_SECS).unwrap();

            // Corrupt a payload byte on disk while the node is live — the
            // in-memory checksums are the audit's reference, exactly the
            // hardware-corruption shape the deep scan exists for.
            let wal_path = dir.path().join("nabla.wal");
            let mut data = std::fs::read(&wal_path).unwrap();
            let pos = data.len() / 2;
            data[pos] ^= 0xFF;
            std::fs::write(&wal_path, &data).unwrap();

            let recovered = node.wal_mut().audit_deep_and_recover().unwrap();
            assert!(recovered.is_some(), "setup: the deep scan must have truncated");
        }

        // Restart 1: the file reads clean (G11 rewrote it) — the marker is
        // what must force continuity NOT proven.
        {
            let node =
                NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert!(
                !node.wal_replay_clean(),
                "KI#78: a truncated WAL read CLEAN on the next boot — the \
                 recording gap was erased and the era would be adjudicated \
                 as complete with entries missing"
            );
            // The bin clears the marker after the gap is durably recorded
            // (init_consumed_exact); mirror that consumption here.
            node.wal().clear_truncation_marker().unwrap();
        }

        // Restart 2: marker consumed, file clean — continuity is PROVEN
        // again. The marker must not over-flag forever (the 2026-07-29
        // continuity fix's whole point).
        {
            let node =
                NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert!(
                node.wal_replay_clean(),
                "KI#78: the consumed marker must not keep gapping every \
                 subsequent boot"
            );
        }
    }

    /// KI#81 — the REAL boot path: register → take_snapshot (which captures
    /// state and compacts/renumbers the WAL) → more registers → genuine
    /// reopen. The audit must stay clean: pre-fix, boot installed the
    /// snapshot's pre-compact checksum list and the first audit manufactured
    /// corruption on a file boot had just read CLEAN, then truncated GOOD
    /// records (all ten nodes of the 2026-08-08 roll, once per restart).
    #[test]
    fn ki81_restart_after_snapshot_keeps_audit_clean() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut node =
                NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
            let (reg, deed) = make_valid_reg(0x81, 0x00, 0x01);
            node.register(&reg, &deed, crate::types::test_legs::NOW_SECS).unwrap();
            node.take_snapshot().unwrap(); // captures + compacts (renumbers)
            let (reg2, deed2) = make_valid_reg(0x82, 0x00, 0x01);
            node.register(&reg2, &deed2, crate::types::test_legs::NOW_SECS).unwrap(); // post-compact traffic
        }

        // Genuine reopen, then post-boot traffic, then the audit.
        let mut node =
            NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
        assert!(node.wal_replay_clean(), "setup: the file itself is clean");
        let (reg3, deed3) = make_valid_reg(0x83, 0x00, 0x01);
        node.register(&reg3, &deed3, crate::types::test_legs::NOW_SECS).unwrap();

        for _ in 0..50 {
            assert_eq!(
                node.wal_mut().audit_recent().unwrap(),
                None,
                "KI#81: the audit manufactured corruption after a clean \
                 snapshot+restart — the boot reference does not match the \
                 compacted file, and the recovery would now destroy good records"
            );
        }
    }

    #[test]
    fn node_register_and_query() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory

        let (reg, deed) = make_valid_reg(0xAA, 0x00, 0x01);
        let result = node.register(&reg, &deed, crate::types::test_legs::NOW_SECS).unwrap();
        assert_eq!(result.ack.new_state[0], 0x01);

        let resp = node.query(&reg.wallet_id);
        assert_eq!(resp.current_state[0], 0x01);
        assert_eq!(node.entry_count(), 1);
        assert_eq!(node.deed_collected(), crate::constants::DEED_WRITE_FEE);
    }

    #[test]
    fn node_register_returns_gossip() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory

        let (reg, deed) = make_valid_reg(0xBB, 0x00, 0x01);
        let result = node.register(&reg, &deed, crate::types::test_legs::NOW_SECS).unwrap();

        match result.gossip_msg {
            GossipMessage::StateUpdate { wallet_id, new_state, .. } => {
                assert_eq!(wallet_id[0], 0xBB);
                assert_eq!(new_state[0], 0x01);
            }
            _ => panic!("Expected StateUpdate"),
        }
    }

    #[test]
    fn node_snapshot_and_recover() {
        let dir = tempfile::tempdir().unwrap();
        let root_before;
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
            node.advance_tick(100);
            for i in 0..5u8 {
                let (reg, deed) = make_valid_reg(i, 0x00, i + 1);
                node.register(&reg, &deed, crate::types::test_legs::NOW_SECS).unwrap();
            }
            assert_eq!(node.entry_count(), 5);
            node.take_snapshot().unwrap();
            root_before = node.root_hash();
        }
        {
            let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert_eq!(node.entry_count(), 5);
            assert_eq!(node.root_hash(), root_before);
        }
    }

    #[test]
    fn node_wal_recovery_after_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let root_final;
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
            node.advance_tick(100);
            for i in 0..5u8 {
                let (reg, deed) = make_valid_reg(i, 0x00, i + 1);
                node.register(&reg, &deed, crate::types::test_legs::NOW_SECS).unwrap();
            }
            node.take_snapshot().unwrap();
            // These 3 are only in WAL
            for i in 5..8u8 {
                let (reg, deed) = make_valid_reg(i, 0x00, i + 1);
                node.register(&reg, &deed, crate::types::test_legs::NOW_SECS).unwrap();
            }
            assert_eq!(node.entry_count(), 8);
            root_final = node.root_hash();
        }
        {
            let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert_eq!(node.entry_count(), 8);
            assert_eq!(node.root_hash(), root_final);
        }
    }

    /// YPX-022 §5 — the three exact txid terminals ride the snapshot: a
    /// restart must never forget a recall (or a redeem, or the completion
    /// base the recall window reads). Fails without the NablaSnapshot
    /// terminal fields + restore_terminal_ledgers.
    #[test]
    fn recall_terminals_survive_snapshot_restart() {
        let dir = tempfile::tempdir().unwrap();
        let completed = [0xC0u8; 32];
        let redeemed = [0xD0u8; 32];
        let recalled = [0xE0u8; 32];
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            node.advance_tick(100);
            node.smt_mut().mark_txid_completed(&completed, 40);
            node.smt_mut().mark_txid_redeemed(&redeemed);
            // Recall requires a completion base; mark then recall in-window.
            node.smt_mut().mark_txid_completed(&recalled, 40);
            node.smt_mut()
                .register_recall(recalled, vec![0xAA; 32], 40 + crate::smt::RECALL_INIT_WINDOW_LOW.to_secs() + 1, false)
                .expect("in-window recall of a completed txid");
            // §2.2.1 — flip the reservation to the Committed terminal (the
            // hibernation-entry commit); only the terminal blocks redeems.
            let committed_pairs = node.smt_mut().commit_recalls_for(&[0xAA; 32]);
            assert_eq!(committed_pairs.len(), 1, "exactly one reservation committed");
            node.take_snapshot().unwrap();
        }
        {
            let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert_eq!(node.smt().completion_tick(&completed), Some(40),
                "completion tick must survive restart (recall window depends on it)");
            assert!(node.smt().is_txid_redeemed(&redeemed),
                "REDEEMED terminal must survive restart");
            assert!(node.smt().is_txid_recalled(&recalled),
                "a restart must never resurrect a recalled cheque");
        }
    }

    /// YPX-022 §2.1.2a (KI#205) — the authenticated claim (the delivery
    /// terminal) rides the snapshot: after a restart `register_recall` must
    /// still refuse CLAIMED. Fails without `NablaSnapshot.cheque_claims` +
    /// `restore_cheque_claims` (the recall below would be GRANTED after boot).
    #[test]
    fn cheque_claims_survive_snapshot_restart() {
        let dir = tempfile::tempdir().unwrap();
        let cheque = [0xF0u8; 32];
        let (req, _) = crate::registration::signed_claim_request(0x71, "alice@example.com", cheque, 3);
        let (win_low, _) = axiom_core_logic::types::recall_init_window(false);
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            node.advance_tick(100);
            node.smt_mut().mark_txid_completed(&cheque, 40);
            let claim = crate::smt::ChequeClaim::from_request(&req, 50);
            assert_eq!(node.smt_mut().register_cheque_claim(cheque, claim, 50), Ok(true));
            node.take_snapshot().unwrap();
        }
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            let restored = node.smt().query_cheque_claim(&cheque).expect("claim must survive restart");
            assert_eq!(restored.claim_tick, 50);
            assert_eq!(restored.client_pk, req.client_pk);
            assert_eq!(restored.claim_sig, req.claim_sig, "claim_sig rides too — it is what Core binds");
            assert_eq!(
                node.smt_mut().register_recall(cheque, vec![0xAA; 32], 40 + win_low.to_secs() + 1, false),
                Err("CLAIMED".to_string()),
                "a restart must never forget a delivery"
            );
        }
    }

    /// GUIDE §5.6c "Persistence" (KI#75) — a restart no longer lifts a
    /// quarantine. Before this build `wal.rs`/`snapshot.rs` had zero
    /// quarantine mentions: the reopened node below answered
    /// `is_peer_quarantined == false` and `forward_targets` gossiped to the
    /// accused again. Fails without `NablaSnapshot.quarantine_active` +
    /// `restore_entries` + the `init_mesh` re-arm.
    #[test]
    fn quarantine_survives_snapshot_restart() {
        let dir = tempfile::tempdir().unwrap();
        let accused = nid(0xCC);
        let me = nid(0xA0);
        let until = 100 + crate::constants::QUARANTINE_DURATION_TICKS * crate::constants::TICK_INTERVAL_SECS;
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            node.advance_tick(100);
            node.quarantine_state_mut().activate_for_test(accused, until);
            assert!(node.is_peer_quarantined(&accused), "premise: active before the snapshot");
            node.take_snapshot().unwrap();
        }
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert!(node.is_peer_quarantined(&accused),
                "a restart must not lift an active quarantine");
            assert_eq!(node.quarantine_state().active_count(), 1);
            // The mesh created AFTER the restore carries the filter too — or
            // the restore would be a ghost (state says quarantined, fan-out
            // still gossips to the peer).
            node.init_mesh(me, NablaAddress::V4 { ip: [127, 0, 0, 1], port: 6225 });
            assert!(node.mesh().unwrap().is_peer_quarantined(&accused),
                "the mesh-side filter must be re-armed from the restored set");
            // And it still EXPIRES on the restored tick: the TTL rides too.
            node.advance_tick(until);
            node.quarantine_sweep();
            assert!(!node.is_peer_quarantined(&accused), "TTL still honoured after restore");
            assert!(!node.mesh().unwrap().is_peer_quarantined(&accused), "filter cleared on expiry");
        }
        // An entry already expired at boot is dropped on load (same rule as
        // `sweep`), so a stale snapshot cannot resurrect a lifted quarantine.
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            node.advance_tick(until + 1);
            node.quarantine_state_mut().activate_for_test(accused, until);
            node.take_snapshot().unwrap();
        }
        {
            let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert_eq!(node.quarantine_state().active_count(), 0,
                "an entry expired at boot must not be restored");
        }
    }

    /// YPX-022 §5 — crash window: terminals appended to the WAL replay on
    /// boot even when NO snapshot was taken after them. Drives the REAL
    /// producers: `handle_gossip(Recall)` appends TxRecalled; the register
    /// path appends TxCompleted (proven separately in registration.rs tests).
    #[test]
    fn recall_marker_survives_wal_only_crash() {
        let dir = tempfile::tempdir().unwrap();
        let txid = [0xE1u8; 32];
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            node.advance_tick(100);
            // YPX-025 A2 — the engine's commit gate requires a prior VERIFIED
            // reservation. Seed one via the smt method (which the engine calls after
            // its verify gate) so the committed gossip applies and appends TxRecalled.
            node.smt_mut().apply_remote_recall(&txid, &[0xAB; 32], 89, false);
            let action = node.handle_gossip(&GossipMessage::Recall {
                txid,
                sender_pk: vec![0xAB; 32],
                recall_tick: 90,
                committed: true,
                attestation: None,
            }, crate::types::test_legs::NOW_SECS);
            assert!(matches!(action, GossipAction::Forward(_)), "commit with a prior reservation must apply");
            assert!(node.smt().is_txid_recalled(&txid));
            // NO take_snapshot — simulate a crash; only the WAL survives.
        }
        {
            let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert!(node.smt().is_txid_recalled(&txid),
                "TxRecalled WAL op must replay — a crash must not resurrect a recalled cheque");
        }
    }

    #[test]
    fn node_gossip_integration() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();

        let wid = test_wid(0xCC); // KI#226: the signing key's own row
        let mut state = [0u8; 32];
        state[0] = 0x01;

        let (client_pk, client_sig) = test_author(0xCC, &wid, &state, &[0xDD; 32]);
        let msg = GossipMessage::StateUpdate {
                      old_state: [0u8; 32],
                      wallet_seq: 0,
            seq_proof: None,
            wallet_id: wid, new_state: state, tx_hash: [0xDD; 32], tick: 5,
            is_genesis_claim: false,
            client_pk, client_sig,
            amount: 0, fee_breakdown: Vec::new(),
        };

        let action = node.handle_gossip(&msg, crate::types::test_legs::NOW_SECS);
        assert!(matches!(action, GossipAction::Forward(_)));
        assert_eq!(node.entry_count(), 1);

        let resp = node.query(&wid);
        assert_eq!(resp.current_state[0], 0x01);
    }

    #[test]
    fn node_register_state_mismatch_no_ban() {
        // YPX-002 §3.3 regression guard: a conflicting /register call must
        // return StateMismatch and MUST NOT ban the wallet. Bans are issued
        // only by the gossip-merge path (§7.5) with two independent k=3
        // receipts as evidence. This test asserts both halves of that rule.
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory

        let (reg1, deed1) = make_valid_reg(0xAA, 0x00, 0x01);
        node.register(&reg1, &deed1, crate::types::test_legs::NOW_SECS).unwrap();

        let (reg2, deed2) = make_valid_reg(0xAA, 0x00, 0x02);
        let result = node.register(&reg2, &deed2, crate::types::test_legs::NOW_SECS);

        assert!(matches!(result, Err(NablaError::StateMismatch)),
            "register-path conflict must be StateMismatch, not a ban");
        assert!(!node.is_banned(&reg1.wallet_id),
            "register-path must NOT ban — that's gossip-merge's job (YPX-002 §3.3)");
        assert_eq!(node.ban_count(), 0);
    }

    // ── Group Wallet Integration Tests (Phase 3) ──

    fn make_valid_group_reg(wid: u8, old: u8, new: u8) -> (GroupRegistration, DeedTransaction) {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = wid;
        let mut old_state = [0u8; 32];
        old_state[0] = old;
        let mut new_state = [0u8; 32];
        new_state[0] = new;

        let greg = GroupRegistration {
            wallet_id,
            old_state,
            new_state,
            tx_hash: [wid ^ new; 32],
            receipt: K3Receipt {
                sender_state: None,
                oods_flag: None,
                confidence_index: None,
                consumed_state_id: old_state,
                produced_state_id: new_state,
                amount: 1000,
                signatures: vec![
                    WitnessSig { validator_pk: [1; 32], signature: vec![1; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [2; 32], signature: vec![2; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [3; 32], signature: vec![3; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                ],
                program_digest: [0u8; 32],
                tick: 0,
                state_hash: [0u8; 32],                 new_wallet_seq: 0,
                commitment_hash: [0u8; 32], epoch: 0,
                fee_breakdown: vec![],
            is_dev_class: false,
            },
            members: vec![
                GroupMemberState { member_pk: [0x10; 32], share_bps: 5000, available: 500 },
                GroupMemberState { member_pk: [0x20; 32], share_bps: 3000, available: 300 },
                GroupMemberState { member_pk: [0x30; 32], share_bps: 2000, available: 200 },
            ],
            balance: 1000,
            k_tier: 3,
        };

        let deed = DeedTransaction {
            sender_wallet_id: wallet_id,
            receiver_wallet_id: DEED_PROTOCOL_WALLET_ID,
            amount: crate::constants::DEED_WRITE_FEE,
            signature: vec![0xFF; 64],
        };

        (greg, deed)
    }

    #[test]
    fn node_register_group_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();

        let (greg, deed) = make_valid_group_reg(0xAA, 0x00, 0x01);
        let result = node.register_group(&greg, &deed).unwrap();
        assert_eq!(result.ack.new_state[0], 0x01);

        // Verify it's stored as a group wallet
        assert!(node.is_group_wallet(&greg.wallet_id));
        assert_eq!(node.entry_count(), 1);
    }

    #[test]
    fn apply_remote_entry_rejects_consumed_state_readvertise() {
        // THREAT §5.4 hardening (AXIOM_THREAT_CollusionWipeRevival.md): the
        // anti-entropy adoption path must not adopt an entry that re-advertises
        // an already-consumed state as the head — A12 consume-once checked
        // against the node's OWN consumed-set (a peer cannot forge it away).
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();

        let e = |state: u8, tick: u64, tx: u8| {
            let (client_pk, client_sig) =
                test_author(0x77, &test_wid(0x77), &[state; 32], &[tx; 32]);
            crate::types::NablaEntry {
                received_from: None,
                wallet_seq: 0,
                wallet_id: test_wid(0x77), // KI#226: the signing key's own row
                current_state: [state; 32],
                tx_hash: [tx; 32],
                tick,
                group_members: None,
                status: crate::types::WalletStatus::Normal,
                client_pk,
                client_sig,
            }
        };

        // Advance X → Y, so X becomes consumed on this node.
        assert!(node.apply_remote_entry(&e(0x11, 1, 1), None, crate::types::test_legs::NOW_SECS), "adopt X");
        assert!(node.apply_remote_entry(&e(0x22, 2, 2), None, crate::types::test_legs::NOW_SECS), "adopt Y (consumes X)");

        // A HIGHER-tick re-advertisement of the consumed state X must be
        // REJECTED. Pre-fix it won superseded_by on tick and rolled the head
        // back to X.
        assert!(
            !node.apply_remote_entry(&e(0x11, 999, 3), None, crate::types::test_legs::NOW_SECS),
            "§5.4: re-advertising consumed state X as head must be rejected"
        );

        // Control: a genuine forward step to a fresh state is still adopted.
        assert!(
            node.apply_remote_entry(&e(0x33, 4, 4), None, crate::types::test_legs::NOW_SECS),
            "a fresh forward state must still be adopted (no false-reject)"
        );
    }

    /// KI#236 probe (2026-09-30): a wallet entry's `status` is outside every
    /// signature (`client_sig` covers wallet_id‖state‖tx only), and AE entries are
    /// unauthenticated. A party that copies the victim's GENUINE signed head from
    /// gossip and re-sends it with `status = Banned` must NOT get the victim banned.
    /// FAILED until W3 (merge rank 1: non-Normal beats Normal; `#[ignore]`d);
    /// GREEN since ForkSettlement §9o [R57] (W3): the incoming status is
    /// normalised to `Normal` before the merge and counted.
    /// MUTATION (run 2026-09-30): delete the normalisation in
    /// `apply_remote_entry_inner` — or keep its count but adopt the status —
    /// ⇒ RED ("FORGED STATUS ADOPTED").
    #[test]
    fn ki236_forged_status_push_does_not_ban_an_honest_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        let (client_pk, client_sig) = test_author(0x78, &test_wid(0x78), &[0x21; 32], &[0x31; 32]);
        let honest = crate::types::NablaEntry {
            received_from: None, wallet_seq: 0, wallet_id: test_wid(0x78),
            current_state: [0x21; 32], tx_hash: [0x31; 32], tick: 1, group_members: None,
            status: crate::types::WalletStatus::Normal, client_pk, client_sig,
        };
        assert!(node.apply_remote_entry(&honest, None, crate::types::test_legs::NOW_SECS), "adopt the honest head");
        assert!(!node.is_wallet_blocked(&test_wid(0x78)), "fixture: honest wallet not blocked");
        // The attacker's push: the SAME genuine signed head, status flipped.
        let forged = crate::types::NablaEntry { status: crate::types::WalletStatus::Banned, ..honest.clone() };
        let _ = node.apply_remote_entry(&forged, None, crate::types::test_legs::NOW_SECS);
        assert!(!node.is_wallet_blocked(&test_wid(0x78)),
            "FORGED STATUS ADOPTED: an unsigned peer-pushed Banned blocked an honest wallet");
        assert_eq!(node.ae_status_discarded(), 1, "the discarded status is COUNTED (/status)");
    }

    /// An authored AE fixture entry for `sk_byte` at (state, tx, tick) with
    /// `status` — the shape a peer (or anyone) can send.
    fn r57_entry(sk_byte: u8, state: u8, tx: u8, tick: u64, status: WalletStatus) -> NablaEntry {
        let wid = test_wid(sk_byte);
        let (client_pk, client_sig) = test_author(sk_byte, &wid, &[state; 32], &[tx; 32]);
        NablaEntry {
            received_from: None, wallet_seq: 0, wallet_id: wid,
            current_state: [state; 32], tx_hash: [tx; 32], tick, group_members: None,
            status, client_pk, client_sig,
        }
    }

    /// Fork Settlement §9o [R57] (W3) — the table: an incoming non-`Normal`
    /// status (Banned / Frozen / Tainted) is NEVER adopted, on the EXISTING-head
    /// path (the victim's genuine head, status flipped, newer tick) AND on the
    /// FIRST-SIGHT path (a node that never held the wallet). The head itself is
    /// adopted where the merge says so — always as `Normal` — and every discard
    /// is counted (`ae_status_discarded`).
    /// MUTATION (run 2026-09-30): delete the normalisation in
    /// `apply_remote_entry_inner` ⇒ RED (first row: "existing / Banned").
    #[test]
    fn ae_forged_status_not_adopted() {
        let now = crate::types::test_legs::NOW_SECS;
        let statuses = [WalletStatus::Banned, WalletStatus::Frozen, WalletStatus::Tainted];
        let mut node = NablaNode::new();
        let mut expected = 0u64;
        for (i, st) in statuses.iter().enumerate() {
            // existing-head: honest Normal head, then a newer genuine head carrying `st`.
            let k = 0x60 + i as u8;
            // (states are per-wallet: the consumed set is node-wide.)
            assert!(node.apply_remote_entry(&r57_entry(k, k, 0x31, 1, WalletStatus::Normal), None, now));
            let pushed = r57_entry(k, k ^ 0x80, 0x32, 2, *st);
            assert!(node.apply_remote_entry(&pushed, None, now), "existing / {st:?}: the newer head merges");
            expected += 1;
            let held = node.smt().get(&test_wid(k)).expect("held");
            assert_eq!((held.current_state, held.status), ([k ^ 0x80; 32], WalletStatus::Normal),
                "existing / {st:?}: head adopted, status NOT adopted");
            assert!(!node.is_wallet_blocked(&test_wid(k)), "existing / {st:?}: wallet blocked by a peer's word");
            // first-sight: a wallet this node never held arrives carrying `st`.
            let f = 0x70 + i as u8;
            assert!(node.apply_remote_entry(&r57_entry(f, f, 0x33, 1, *st), None, now),
                "first-sight / {st:?}: the head is adopted");
            expected += 1;
            assert_eq!(node.smt().get(&test_wid(f)).map(|e| e.status), Some(WalletStatus::Normal),
                "first-sight / {st:?}: status NOT adopted");
            assert!(!node.is_wallet_blocked(&test_wid(f)), "first-sight / {st:?}: wallet blocked by a peer's word");
        }
        assert_eq!(node.ae_status_discarded(), expected, "every discard COUNTED");
        assert_eq!(node.origin_status(None, 0).ae_status_discarded, expected, "…and on /status");
        assert!(node.bans().is_empty(), "no BanTable entry from a status");
    }

    /// Fork Settlement §9o [R57] — normalising the INCOMING status must not
    /// weaken THIS node's own hold: rank rule 1 (`superseded_by`) keeps a local
    /// `Frozen` head against a peer's genuine newer `Normal` head, and against
    /// a forged push of the same head carrying `Banned` (normalised to `Normal`,
    /// so it neither demotes nor upgrades the hold).
    /// MUTATION (run 2026-09-30): make rank rule 1 return early only when
    /// `r_in > r_self` (drop the "never demoted" half) ⇒ RED at "a peer's
    /// Normal head must not replace a local hold".
    #[test]
    fn local_hold_not_demoted_by_peer() {
        let now = crate::types::test_legs::NOW_SECS;
        let mut node = NablaNode::new();
        let k = 0x7A;
        assert!(node.apply_remote_entry(&r57_entry(k, 0x41, 0x51, 1, WalletStatus::Normal), None, now));
        crate::tardis::test_support::legacy_status_leaf(node.smt_mut(), &test_wid(k), WalletStatus::Frozen); // fixture: a restored legacy hold (E4: no production writer)
        let newer = r57_entry(k, 0x42, 0x52, 5, WalletStatus::Normal);
        assert!(!node.apply_remote_entry(&newer, None, now), "a peer's Normal head must not replace a local hold");
        let held = node.smt().get(&test_wid(k)).expect("held");
        assert_eq!((held.current_state, held.status), ([0x41; 32], WalletStatus::Frozen),
            "local hold demoted by a peer");
        let forged = r57_entry(k, 0x42, 0x52, 6, WalletStatus::Banned);
        assert!(!node.apply_remote_entry(&forged, None, now));
        assert_eq!(node.smt().get(&test_wid(k)).map(|e| e.status), Some(WalletStatus::Frozen),
            "a forged Banned push neither demotes nor upgrades the local hold");
        assert!(!node.is_banned(&test_wid(k)));
    }

    /// Fork Settlement §9o [R57] — `status_unbacked_at_load` COUNTS (never
    /// changes) restored leaves whose status this node cannot back: a `Banned`
    /// leaf with no BanTable entry, a `Frozen` and a `Tainted` leaf → 3; a
    /// `Banned` leaf WITH its ban and a `Normal` leaf → not counted. The
    /// statuses survive the reopen unchanged.
    /// MUTATION (run 2026-09-30): count only `Banned` leaves (drop the
    /// Frozen/Tainted arms) ⇒ RED (1 ≠ 3).
    #[test]
    fn status_unbacked_at_load_counted() {
        let dir = tempfile::tempdir().unwrap();
        let cases = [
            (0x81u8, WalletStatus::Banned),  // unbacked
            (0x82, WalletStatus::Frozen),
            (0x83, WalletStatus::Tainted),
            (0x84, WalletStatus::Banned),    // backed (BanTable entry below)
            (0x85, WalletStatus::Normal),
        ];
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert_eq!(node.status_unbacked_at_load(), 0, "fixture: empty node");
            for (k, st) in cases {
                node.inject_test_entry(&r57_entry(k, k, k, 1, st));
            }
            let mk_proof = |seed: u8| crate::types::SeqProof {
                sender_state: None, oods_flag: None, confidence_index: None,
                state_hash: [seed; 32], commitment_hash: [seed ^ 0xFF; 32], epoch: 7,
                is_dev_class: false, sigs: Vec::new(), required_k: 3,
                preimage: crate::types::test_legs::opaque_redeem_leg(),
                declared: crate::types::test_legs::no_declared(),
            };
            node.inject_test_seq_fork_ban(test_wid(0x84), crate::types::SeqConflictProof {
                wallet_seq: 1, state_a: [1; 32], tx_a: [2; 32], proof_a: mk_proof(1),
                state_b: [3; 32], tx_b: [4; 32], proof_b: mk_proof(2),
            });
        }
        let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert!(node.is_banned(&test_wid(0x84)), "fixture: the backed ban replayed");
        assert_eq!(node.status_unbacked_at_load(), 3, "Banned-unbacked + Frozen + Tainted");
        assert_eq!(node.origin_status(None, 0).status_unbacked_at_load, 3, "…and on /status");
        for (k, st) in cases {
            assert_eq!(node.smt().get(&test_wid(k)).map(|e| e.status), Some(st), "count only — {k:#x} unchanged");
        }
    }

    #[test]
    fn apply_remote_entry_authored_replaces_unauthored_debris() {
        // AE-convergence fix (2026-08-01): a locally-held zero-pk non-group
        // entry (fact-confirm debris — an entry this node would itself REJECT
        // from a peer) must not block adoption of the authored head, even
        // when the debris carries a LATER tick (pre-fix it won the tick
        // tiebreak and the node wedged in a permanent AE re-offer loop).
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        let wid = test_wid(0x77); // KI#226: the signing key's own row

        // Seed the debris directly (as the pre-fix fact-confirm write did):
        // same state the network knows, different tx_hash, later tick, no
        // authorship.
        node.smt_mut().put(&crate::types::NablaEntry {
            received_from: None,
            wallet_seq: 1,
            wallet_id: wid,
            current_state: [0x11; 32],
            tx_hash: [0xBB; 32],
            tick: 200,
            group_members: None,
            status: crate::types::WalletStatus::Normal,
            client_pk: [0u8; 32],
            client_sig: vec![],
        });

        // The authored head arrives over AE: same seq/state, EARLIER tick.
        let (client_pk, client_sig) = test_author(0x77, &wid, &[0x11; 32], &[0xAA; 32]);
        let authored = crate::types::NablaEntry {
            received_from: None,
            wallet_seq: 1,
            wallet_id: wid,
            current_state: [0x11; 32],
            tx_hash: [0xAA; 32],
            tick: 100,
            group_members: None,
            status: crate::types::WalletStatus::Normal,
            client_pk,
            client_sig,
        };
        assert!(
            node.apply_remote_entry(&authored, None, crate::types::test_legs::NOW_SECS),
            "authored head must replace unauthored debris despite lower tick"
        );
        let held = node.smt().get(&wid).unwrap();
        assert_eq!(held.tx_hash, [0xAA; 32], "the authored entry is now held");
        assert_ne!(held.client_pk, [0u8; 32]);
    }

    /// ForkSettlement wave 2a — the AE path runs the SAME leg check as the
    /// flood (RULE 1, `registration::verify_seq_proof_leg`): an entry whose
    /// carried proof's preimage does not reproduce the proof's own
    /// commitment_hash is REFUSED even though its k sigs verify; the genuine
    /// leg (control) is adopted. MUTATION: delete the leg check in
    /// `apply_remote_entry` → the tampered case goes RED (adopted).
    #[test]
    fn wave2a_apply_remote_entry_rejects_a_non_reproducing_leg() {
        use ed25519_dalek::{Signer, SigningKey};
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
        let wid = test_wid(0x7B); // KI#226: the signing key's own row
        let author = SigningKey::from_bytes(&[0x7B; 32]);
        let client_pk = author.verifying_key().to_bytes();
        let leg_entry = |nonce_tamper: u64| {
            let mut preimage = axiom_core_logic::types::WitnessPreimage {
                consumed_state_id: [0x21; 32], client_pk, wallet_seq: 5,
                receiver_wallet_id: "bob@axiom.internal/0123456789".into(), amount: 700, nonce: 11,
            };
            let (state_hash, epoch) = ([0x5au8; 32], 1_790_000_011u64);
            let commitment_hash = preimage.commitment_hash();
            let tx_hash = preimage.txid(epoch);
            let c = axiom_core_logic::compute::compute_receipt_commitment(
                &tx_hash, &state_hash, 5, &commitment_hash, epoch, false, None, None, None);
            let sigs = (0..3).map(|i| {
                let sk = SigningKey::from_bytes(&[0x30 + i as u8; 32]);
                crate::types::SeqProofSig { validator_pk: sk.verifying_key().to_bytes(),
                    receipt_commitment_sig: sk.sign(&c).to_bytes().to_vec() }
            }).collect();
            preimage.nonce += nonce_tamper;
            let proof = crate::types::SeqProof {
                state_hash, commitment_hash, epoch, is_dev_class: false, oods_flag: None,
                confidence_index: None, sigs, sender_state: None, required_k: 3,
                preimage: crate::types::LegPreimage::Send(preimage),
                declared: crate::types::test_legs::no_declared(),
            };
            let payload = crate::gossip::client_state_sign_payload(&wid, &[0x22; 32], &tx_hash);
            let entry = crate::types::NablaEntry {
                received_from: None, wallet_seq: 5, wallet_id: wid, current_state: [0x22; 32],
                tx_hash, tick: 10, group_members: None, status: crate::types::WalletStatus::Normal,
                client_pk, client_sig: author.sign(&payload).to_bytes().to_vec(),
            };
            (entry, proof)
        };
        let (bad, bad_proof) = leg_entry(1);
        let before = crate::registration::leg_preimage_refused_total();
        assert!(!node.apply_remote_entry(&bad, Some(&bad_proof), crate::types::test_legs::NOW_SECS), "tampered leg must be refused");
        assert!(node.smt().get(&wid).is_none(), "nothing adopted");
        assert!(crate::registration::leg_preimage_refused_total() > before, "counted");
        let (good, good_proof) = leg_entry(0);
        assert!(node.apply_remote_entry(&good, Some(&good_proof), crate::types::test_legs::NOW_SECS), "genuine leg adopts (control)");
        assert_eq!(node.smt().seq_proof(&wid).map(|p| &p.preimage), Some(&good_proof.preimage),
            "the adopted head retains the verified leg");
    }

    #[test]
    fn apply_remote_entry_rejects_unproven_seq_advance() {
        // WI3 hole-1 (KI#34 §5.4): `wallet_seq` is the PRIMARY merge key, and a
        // bare seq on an anti-entropy entry is forgeable. An advance past the held
        // seq must carry a valid k=3 proof or be rejected — otherwise a malicious
        // peer rolls the head forward to a fork `X'` by self-stamping a high seq.
        use ed25519_dalek::{Signer, SigningKey};
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
        let wid = test_wid(0x7A); // KI#226: the signing key's own row

        let mint = |txid: &[u8; 32], seq: u64, n: usize| -> crate::types::SeqProof {
            let (state_hash, commitment_hash, epoch, dev) = ([0x5au8; 32], [0x7cu8; 32], 7u64, false);
            let c = axiom_core_logic::compute::compute_receipt_commitment(
                txid, &state_hash, seq, &commitment_hash, epoch, dev, None, None,
                None,
            );
            let sigs = (0..n)
                .map(|i| {
                    let sk = SigningKey::from_bytes(&[0x30 + i as u8; 32]);
                    crate::types::SeqProofSig {
                        validator_pk: sk.verifying_key().to_bytes(),
                        receipt_commitment_sig: sk.sign(&c).to_bytes().to_vec(),
                    }
                })
                .collect();
            crate::types::SeqProof { state_hash, commitment_hash, epoch, is_dev_class: dev, oods_flag: None, confidence_index: None, sigs, sender_state: None, required_k: 3, preimage: crate::types::test_legs::opaque_redeem_leg() /* wave 2a: minted over an arbitrary txid — a Send leg could not reproduce it */, declared: crate::types::test_legs::no_declared() }
        };
        let mk = |state: u8, tx: [u8; 32], tick: u64, seq: u64| {
            let (client_pk, client_sig) = test_author(0x7A, &wid, &[state; 32], &tx);
            crate::types::NablaEntry {
                received_from: None,
                wallet_seq: seq,
                wallet_id: wid,
                current_state: [state; 32],
                tx_hash: tx,
                tick,
                group_members: None,
                status: crate::types::WalletStatus::Normal,
                client_pk,
                client_sig,
            }
        };
        // W7a: bind each proof's redeem leg to the entry it rides with (the AE
        // leg check verifies redeem legs since W7a; forged slots stay forged).
        let bound = |e: &crate::types::NablaEntry, mut p: crate::types::SeqProof| {
            crate::types::test_legs::bind_redeem_leg(&mut p, &e.tx_hash, e.client_pk, [0u8; 32], e.current_state, e.wallet_seq, 0x30);
            p
        };

        // Honest head Y at seq=5 WITH a valid k=3 proof → adopted (advance 0→5).
        let txid_y = crate::types::test_legs::cheque_txid([0xA1u8; 32]); // KI#241 F-2
        assert!(
            node.apply_remote_entry(&mk(0x22, txid_y, 10, 5), Some(&bound(&mk(0x22, txid_y, 10, 5), mint(&txid_y, 5, 3))), crate::types::test_legs::NOW_SECS),
            "honest proven advance must adopt"
        );
        assert_eq!(node.smt().get(&wid).unwrap().wallet_seq, 5);

        // Attacker fork X' at a self-stamped seq=99 with NO proof → REJECTED.
        assert!(
            !node.apply_remote_entry(&mk(0x33, [0xB2u8; 32], 99, 99), None, crate::types::test_legs::NOW_SECS),
            "unproven seq-advance must be rejected (no rollback to a forged head)"
        );
        assert_eq!(node.smt().get(&wid).unwrap().current_state[0], 0x22, "head unchanged");

        // Same, but with a sub-quorum (k=2) forged proof → still rejected.
        let txid_c = crate::types::test_legs::cheque_txid([0xC3u8; 32]); // KI#241 F-2
        assert!(
            !node.apply_remote_entry(&mk(0x44, txid_c, 99, 99), Some(&bound(&mk(0x44, txid_c, 99, 99), mint(&txid_c, 99, 2))), crate::types::test_legs::NOW_SECS),
            "sub-quorum proof must not pass the gate"
        );
        assert_eq!(node.smt().get(&wid).unwrap().current_state[0], 0x22);

        // Control: an honest advance Z at seq=6 WITH a valid proof → adopted, and
        // the verified proof is retained so this node can re-attest on AE.
        let txid_z = crate::types::test_legs::cheque_txid([0xD4u8; 32]); // KI#241 F-2
        assert!(
            node.apply_remote_entry(&mk(0x55, txid_z, 11, 6), Some(&bound(&mk(0x55, txid_z, 11, 6), mint(&txid_z, 6, 3))), crate::types::test_legs::NOW_SECS),
            "honest proven advance must still adopt (no false-reject)"
        );
        assert_eq!(node.smt().get(&wid).unwrap().wallet_seq, 6);
        assert!(node.smt().seq_proof(&wid).is_some(), "verified proof retained for AE re-attest");
    }

    #[test]
    fn ki38_equal_seq_adopt_clears_stale_proof() {
        // KI#38 part 1 — proof↔entry lock-step. A node holds head Z@seq=6 WITH a
        // valid proof. An EQUAL-seq (6) tiebreaker candidate with a higher tick
        // and a DIFFERENT tx_hash wins superseded_by but carries NO proof. The
        // stale proof (bound to Z's tx_hash) must be CLEARED, else the node would
        // serve (new head, stale proof) over AE and every downstream verify would
        // fail `CARRIED-BUT-FAILED`, wedging the mesh at applied=0.
        use ed25519_dalek::{Signer, SigningKey};
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
        let wid = test_wid(0x7B); // KI#226: the signing key's own row

        let mint = |txid: &[u8; 32], seq: u64, n: usize| -> crate::types::SeqProof {
            let (state_hash, commitment_hash, epoch, dev) = ([0x5au8; 32], [0x7cu8; 32], 7u64, false);
            let c = axiom_core_logic::compute::compute_receipt_commitment(
                txid, &state_hash, seq, &commitment_hash, epoch, dev, None, None,
                None,
            );
            let sigs = (0..n).map(|i| {
                let sk = SigningKey::from_bytes(&[0x30 + i as u8; 32]);
                crate::types::SeqProofSig {
                    validator_pk: sk.verifying_key().to_bytes(),
                    receipt_commitment_sig: sk.sign(&c).to_bytes().to_vec(),
                }
            }).collect();
            crate::types::SeqProof { state_hash, commitment_hash, epoch, is_dev_class: dev, oods_flag: None, confidence_index: None, sigs, sender_state: None, required_k: 3, preimage: crate::types::test_legs::opaque_redeem_leg() /* wave 2a: minted over an arbitrary txid — a Send leg could not reproduce it */, declared: crate::types::test_legs::no_declared() }
        };
        let mk = |state: u8, tx: [u8; 32], tick: u64, seq: u64| {
            let (client_pk, client_sig) = test_author(0x7B, &wid, &[state; 32], &tx);
            crate::types::NablaEntry {
                received_from: None,
                wallet_seq: seq, wallet_id: wid, current_state: [state; 32], tx_hash: tx,
                tick, group_members: None, status: crate::types::WalletStatus::Normal,
                client_pk, client_sig,
            }
        };
        // W7a: bind each proof's redeem leg to the entry it rides with (the AE
        // leg check verifies redeem legs since W7a; forged slots stay forged).
        let bound = |e: &crate::types::NablaEntry, mut p: crate::types::SeqProof| {
            crate::types::test_legs::bind_redeem_leg(&mut p, &e.tx_hash, e.client_pk, [0u8; 32], e.current_state, e.wallet_seq, 0x30);
            p
        };

        // Adopt head Z@seq=6 with a valid proof → proof retained.
        let txid_z = crate::types::test_legs::cheque_txid([0xE1u8; 32]); // KI#241 F-2
        assert!(node.apply_remote_entry(&mk(0x22, txid_z, 10, 6), Some(&bound(&mk(0x22, txid_z, 10, 6), mint(&txid_z, 6, 3))), crate::types::test_legs::NOW_SECS));
        assert!(node.smt().seq_proof(&wid).is_some(), "valid proof retained");

        // Equal-seq (6) tiebreaker: higher tick, different tx_hash, NO proof → wins
        // merge, adopts the new head, and MUST clear the now-stale proof.
        let txid_w = [0xE2u8; 32];
        assert!(node.apply_remote_entry(&mk(0x33, txid_w, 20, 6), None, crate::types::test_legs::NOW_SECS), "equal-seq higher-tick adopt");
        assert_eq!(node.smt().get(&wid).unwrap().tx_hash, txid_w, "head replaced");
        assert!(
            node.smt().seq_proof(&wid).is_none(),
            "KI#38: stale proof (bound to the superseded head) must be cleared"
        );
    }

    #[test]
    fn ki34_wipe_recover_rejects_revival_rollback() {
        // KI#34 WI1 — the END-TO-END wipe → recover → reject-revival flow that the
        // whole work item exists for. The earlier hole-1 tests prove the seq gate;
        // this proves the consume-once net SURVIVES a node wipe and then refuses
        // the rollback HAL would otherwise revive.
        //
        // Story: a coalition wipes a Nabla's data dir. The node recovers its head
        // from the mesh (StatePull head adopt), then re-arms its consume-once memory
        // from honest peers (merge_consumed_bloom + merge_previous_states). A spent
        // wallet state X (consumed when the wallet advanced X→Y) must NOT be
        // adoptable again — even self-stamped at an absurd tick — because the
        // recovered node now KNOWS X is consumed.
        //
        // Node C is the load-bearing contrast: a node that recovers ONLY the head
        // (no WI1 re-arm) is blind to X being consumed and ADOPTS the rollback,
        // proving the WI1 merge is what closes the revival, not the head adopt.
        use crate::types::{NablaEntry, WalletStatus};
        let wid = test_wid(0x7C); // KI#226: the signing key's own row
        let x = [0xA0u8; 32]; // the spent state HAL would try to revive
        let y = [0xA1u8; 32]; // the live head after X→Y
        // KI#65: a tick-path advance at constant seq is a CHAIN advance, and
        // since the falsifiable-mark fix its permanence rests on the entry
        // carrying the real `fact_tx_hash(prev, new)` linkage (a same-seq
        // entry with an unprovable parent is only provisionally marked and
        // does NOT reach the eras this test transfers). Carry it like
        // production does; the forged revival keeps its junk hash.
        let entry = |state: [u8; 32], tick: u64, prev: Option<[u8; 32]>| {
            let tx_hash = match prev {
                Some(p) => crate::registration::fact_tx_hash(&p, &state),
                None => [tick as u8; 32],
            };
            let (client_pk, client_sig) = test_author(0x7C, &wid, &state, &tx_hash);
            NablaEntry {
                received_from: None,
                wallet_seq: 0, // tick-path advance (seq unchanged) — exercises the consume-once gate, not the seq gate
                wallet_id: wid,
                current_state: state,
                tx_hash,
                tick,
                group_members: None,
                status: WalletStatus::Normal,
                client_pk,
                client_sig,
            }
        };

        // ── Node A: honest, never wiped. Advances X→Y, so X is consumed. ──
        let dir_a = tempfile::tempdir().unwrap();
        let mut a = NablaNode::open(dir_a.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert!(a.apply_remote_entry(&entry(x, 1, None), None, crate::types::test_legs::NOW_SECS), "a adopts X");
        assert!(a.apply_remote_entry(&entry(y, 2, Some(x)), None, crate::types::test_legs::NOW_SECS), "a adopts Y (X consumed)");
        assert!(a.smt().is_state_consumed(&x), "a knows X is consumed");
        assert_eq!(a.smt().previous_state(&wid), Some(x), "a remembers prev=X");

        // ── Node B: WIPED, then recovers. Head Y + WI1 re-arm from A. ──
        let dir_b = tempfile::tempdir().unwrap();
        let mut b = NablaNode::open(dir_b.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert!(b.apply_remote_entry(&entry(y, 2, Some(x)), None, crate::types::test_legs::NOW_SECS), "b recovers head Y from the mesh");
        // WI1: re-arm consume-once memory from an honest peer's snapshots.
        // KI#42 step 4d: re-arm is era-shaped now — transfer every consumed era A
        // holds, which is exactly what the StatePull handler does (and what its
        // completeness gate requires before the node will serve).
        for id in a.smt().consumed_era_ids() {
            let bytes = a.smt().consumed_era_bytes(id).expect("era serializes");
            let era: crate::bloom_era::BloomEra =
                ciborium::from_reader(bytes.as_slice()).expect("era decodes");
            b.smt_mut().merge_consumed_era(era).expect("honest era adopted");
        }
        b.smt_mut().merge_previous_states(&a.smt().previous_states_snapshot(), 2);
        assert!(b.smt().is_state_consumed(&x), "WI1: b is re-armed — knows X consumed");
        assert_eq!(b.smt().previous_state(&wid), Some(x), "WI1: b recovered prev=X");

        // KI#34 core assertion: the recovered node REJECTS the revival rollback.
        assert!(
            !b.apply_remote_entry(&entry(x, 999, None), None, crate::types::test_legs::NOW_SECS),
            "KI#34: a WI1-recovered node must REJECT the HAL-style rollback to consumed X"
        );
        assert_eq!(b.smt().get(&wid).unwrap().current_state, y, "b head stays Y");

        // ── Node C: WIPED, recovers head ONLY (no WI1). Proves WI1 is load-bearing. ──
        let dir_c = tempfile::tempdir().unwrap();
        let mut c = NablaNode::open(dir_c.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert!(c.apply_remote_entry(&entry(y, 2, Some(x)), None, crate::types::test_legs::NOW_SECS), "c recovers head Y (no consume-once re-arm)");
        assert!(!c.smt().is_state_consumed(&x), "c is blind — never re-armed");
        assert!(
            c.apply_remote_entry(&entry(x, 999, None), None, crate::types::test_legs::NOW_SECS),
            "without WI1, c ADOPTS the rollback (the vulnerability WI1 closes)"
        );
        assert_eq!(
            c.smt().get(&wid).unwrap().current_state,
            x,
            "c rolled back to X — WI1 re-arm is what makes the difference"
        );
    }

    #[test]
    fn node_group_query_returns_members() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();

        let (greg, deed) = make_valid_group_reg(0xBB, 0x00, 0x01);
        node.register_group(&greg, &deed).unwrap();

        let resp = node.query(&greg.wallet_id);
        assert!(resp.group_members.is_some());
        let members = resp.group_members.unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].available, 500);
    }

    #[test]
    fn node_group_member_query() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();

        let (greg, deed) = make_valid_group_reg(0xCC, 0x00, 0x01);
        node.register_group(&greg, &deed).unwrap();

        // Query specific member
        let result = node.query_member(&greg.wallet_id, &[0x20; 32]).unwrap();
        assert_eq!(result.share_bps, 3000);
        assert_eq!(result.available, 300);
        assert_eq!(result.group_balance, 1000);
        assert!(result.checksum_valid);

        // Query non-existent member
        let err = node.query_member(&greg.wallet_id, &[0xFF; 32]);
        assert!(matches!(err, Err(NablaError::MemberNotFound)));
    }

    #[test]
    fn node_group_gossip_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();

        let mut wallet_id = [0u8; 32];
        wallet_id[0] = 0xDD;
        let msg = GossipMessage::GroupUpdate {
            wallet_id,
            new_state: [0x01; 32],
            tx_hash: [0; 32],
            members: vec![
                GroupMemberState { member_pk: [0x10; 32], share_bps: 6000, available: 600 },
                GroupMemberState { member_pk: [0x20; 32], share_bps: 4000, available: 400 },
            ],
            tick: 5,
        };

        let action = node.handle_gossip(&msg, crate::types::test_legs::NOW_SECS);
        assert!(matches!(action, crate::gossip::GossipAction::Forward(_)));
        assert!(node.is_group_wallet(&wallet_id));

        // Verify members are stored
        let resp = node.query_member(&wallet_id, &[0x10; 32]).unwrap();
        assert_eq!(resp.available, 600);
        assert_eq!(resp.share_bps, 6000);
    }

    #[test]
    fn node_personal_wallet_not_group() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory

        let (reg, deed) = make_valid_reg(0xEE, 0x00, 0x01);
        node.register(&reg, &deed, crate::types::test_legs::NOW_SECS).unwrap();

        assert!(!node.is_group_wallet(&reg.wallet_id));
        let err = node.query_member(&reg.wallet_id, &[0x10; 32]);
        assert!(matches!(err, Err(NablaError::NotGroupWallet)));
    }

    // ── Companion Certificate Integration Tests (Phase 5) ──

    #[test]
    fn node_init_cc() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        let nbc = make_test_nbc(0xAA);
        node.init_cc(nbc);

        assert!(node.latest_cc().is_none()); // no tick processed yet
    }

    #[test]
    fn node_cc_tick_produces_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
        let nbc = make_test_nbc(0xAA);
        node.init_cc(nbc);
        node.advance_tick(1);

        // Register some wallets
        let (reg, deed) = make_valid_reg(0x01, 0x00, 0x01);
        node.register(&reg, &deed, crate::types::test_legs::NOW_SECS).unwrap();
        node.cc_record_registration();

        let (reg2, deed2) = make_valid_reg(0x02, 0x00, 0x01);
        node.register(&reg2, &deed2, crate::types::test_legs::NOW_SECS).unwrap();
        node.cc_record_registration();

        // Produce CC for tick
        let cc = node.cc_tick().unwrap();
        assert_eq!(cc.tick, 1);
        assert_eq!(cc.registrations_this_tick, 2);
        assert_eq!(cc.ticks_helped, 1);
    }

    #[test]
    fn node_cc_chain_across_ticks() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        let nbc = make_test_nbc(0xAA);
        node.init_cc(nbc);

        for tick in 1..=5 {
            node.advance_tick(tick);
            node.cc_record_registration();
            node.cc_tick();
        }

        let cc = node.latest_cc().unwrap();
        assert_eq!(cc.tick, 5);
        assert_eq!(cc.ticks_helped, 5);
        assert_eq!(cc.total_registrations, 5);
    }

    #[test]
    fn node_runner_pool_integration() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();

        // Simulate DEED fees
        node.runner_pool_add_fee(10); // 30% = 3
        node.runner_pool_add_fee(10); // 30% = 3
        node.runner_pool_add_fee(10); // 30% = 3

        assert_eq!(node.runner_pool_balance(), 9);
    }

    // ── Monitoring Tests (Phase 6) ──

    #[test]
    fn node_status_snapshot_basic() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        node.advance_tick(5);

        let status = node.status_snapshot();
        assert_eq!(status.current_tick, 5);
        assert!(!status.tardis_active);
        assert!(!status.mesh_active);
        assert!(!status.cc_active);
        assert!(!status.healthy); // no tardis/mesh/cc = unhealthy
    }

    #[test]
    fn node_status_snapshot_fully_initialized() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        node.init_tardis(pk(0xAA));
        node.init_mesh_with_bootstrap(
            pk(0xAA),
            make_addr(0xAA),
            vec![make_peer_info(1), make_peer_info(2), make_peer_info(3),
                 make_peer_info(4), make_peer_info(5), make_peer_info(6),
                 make_peer_info(7), make_peer_info(8), make_peer_info(9)],
        );
        let nbc = make_test_nbc(0xAA);
        node.init_cc(nbc);
        node.advance_tick(1);
        node.cc_tick();

        // A "fully initialized" node in a real mesh has a PARENT. Attach one:
        // as of 2026-08-01 `diagnose()` reports a node with no upstream as an
        // ORPHAN (YPX-003 §1.1 — "the only state that's actually a problem";
        // it receives no ticks and its SMT diverges). Without this the fixture
        // described a node that is initialized but unattached, which is
        // precisely the state the new check exists to catch.
        node.tardis_mut().unwrap().set_upstream(pk(0xBB));

        let status = node.status_snapshot();
        assert!(status.tardis_active);
        assert!(status.mesh_active);
        assert!(status.cc_active);
        assert_eq!(status.mesh_peer_count, 9);
        assert!(status.has_upstream);
        assert!(status.healthy, "issues: {:?}", status.health_issues);
    }

    #[test]
    fn orphan_node_is_reported_unhealthy() {
        // The regression guard for the 2026-08-01 finding: a mesh with 8 of 10
        // nodes orphaned and three distinct SMT roots reported
        // `healthy: true, issues: []` on every node, because `diagnose()` had
        // no attachment check at all. It must never be silent about this again.
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        node.init_tardis(pk(0xAA));
        node.init_mesh_with_bootstrap(
            pk(0xAA),
            make_addr(0xAA),
            vec![make_peer_info(1), make_peer_info(2), make_peer_info(3)],
        );
        let nbc = make_test_nbc(0xAA);
        node.init_cc(nbc);
        node.advance_tick(1);
        node.cc_tick();
        // deliberately NO set_upstream

        let status = node.status_snapshot();
        assert!(status.tardis_active);
        assert!(!status.has_upstream);
        assert!(!status.healthy, "an orphan must never report healthy");
        assert!(
            status.health_issues.iter().any(|i| i.contains("ORPHAN")),
            "expected an ORPHAN issue, got {:?}",
            status.health_issues,
        );
    }

    // ── Gossip Mesh Integration Tests (Phase 4) ──

    fn make_addr(b: u8) -> NablaAddress {
        NablaAddress::V4 { ip: [10, 0, 0, b], port: 8080 + b as u16 }
    }

    fn make_peer_info(b: u8) -> PeerInfo {
        PeerInfo {
            node_id: pk(b),
            address: make_addr(b),
            last_seen: 0,
            tardis_up: None,
            has_d_open: false, open_slots: 0,
            messages_delivered: 0,
            connected_since: 0,
            txid_service: String::new(),
        }
    }

    #[test]
    fn node_init_mesh() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        node.init_mesh(pk(0xAA), make_addr(0xAA));

        assert!(node.mesh().is_some());
        assert_eq!(node.mesh().unwrap().peer_count(), 0);
    }

    #[test]
    fn node_init_mesh_with_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        node.init_mesh_with_bootstrap(
            pk(0xAA),
            make_addr(0xAA),
            vec![make_peer_info(1), make_peer_info(2), make_peer_info(3)],
        );

        assert_eq!(node.mesh().unwrap().peer_count(), 3);
    }

    #[test]
    fn node_mesh_forward_targets() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        node.init_mesh_with_bootstrap(
            pk(0xAA),
            make_addr(0xAA),
            vec![make_peer_info(1), make_peer_info(2), make_peer_info(3)],
        );

        // Forward to all except sender
        let targets = node.mesh_forward_targets(&pk(2));
        assert_eq!(targets.len(), 2);
        assert!(!targets.contains(&pk(2)));
    }

    #[test]
    fn node_mesh_topology_self_healing() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        node.init_mesh(pk(0xAA), make_addr(0xAA));

        // Another node advertises open slot
        // §5.6a-bis: the hint is identity-only, so the address must already be
        // known from an observation before the slot is dialable.
        node.mesh_mut().unwrap().merge_peer_info(crate::types::PeerInfo {
            node_id: pk(5), address: make_addr(5), last_seen: 1, tardis_up: None,
            has_d_open: false, open_slots: 0, messages_delivered: 0,
            connected_since: 1, txid_service: String::new(),
        });
        node.mesh_apply_topology(&TopologyHint::SlotAvailable {
            node_id: pk(5),
            open_slots: 1,
        });

        // We can find that slot for TARDIS reconnection
        let action = node.mesh_find_tardis_parent();
        assert!(matches!(action, MeshAction::AttemptTardisReconnect { .. }));
    }

    #[test]
    fn node_mesh_observe_gossip() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        node.init_mesh(pk(0xAA), make_addr(0xAA));

        node.mesh_observe(pk(1));
        node.mesh_observe(pk(2));
        node.mesh_observe(pk(3));

        assert_eq!(node.mesh().unwrap().unique_seen_count(), 3);
    }

    #[test]
    fn node_gossip_topology_hint_forwarded() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();

        let msg = GossipMessage::Topology(TopologyHint::NewNode {
            node_id: pk(0x50),
        });

        let action = node.handle_gossip(&msg, crate::types::test_legs::NOW_SECS);
        assert!(matches!(action, crate::gossip::GossipAction::Forward(_)));
    }

    #[test]
    fn node_gossip_approved_tick_forwarded() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();

        let msg = GossipMessage::ApprovedTick {
            tick_number: 42,
            approvals: vec![TickApproval {
                approver_pk: pk(0xBB),
                tick_number: 42,
                signature: vec![0xFF; 64],
                subtree_open_d: 0,
            }],
        };

        let action = node.handle_gossip(&msg, crate::types::test_legs::NOW_SECS);
        assert!(matches!(action, crate::gossip::GossipAction::Forward(_)));
    }

    // ── TARDIS Integration Tests ──

    fn pk(b: u8) -> [u8; 32] { [b; 32] }

    fn make_test_nbc(b: u8) -> crate::cc::NBC {
        crate::cc::sim_nbc([b; 32], 0)
    }

    #[test]
    fn node_tardis_init_and_tick() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        node.init_tardis(pk(0xAA));

        // Set upstream on TARDIS
        node.tardis_mut().unwrap().set_upstream(pk(0xBB));

        // Process a tick
        let tick = TickMessage {
            number: 1,
            upstream_pk: pk(0xBB),
            payload: 1u64.to_le_bytes().to_vec(),
            signature: vec![0xFF; 64],
            timestamp_ms: 5000,
            available_slots: vec![],
            downstream_approvals: 2,
            prev_sig: vec![], grandparent_pk: None, subtree_d_available: 0,
            oods_tardis: Vec::new(),
            child_pks: Vec::new(),
            gp_commitment: None,
        };

        let actions = node.process_tick(&tick, 5000).unwrap();
        assert_eq!(node.current_tick(), 1);
        // Should have BroadcastRootHash at minimum
        assert!(actions.iter().any(|a| matches!(a, TardisAction::BroadcastRootHash { .. })));
    }

    #[test]
    fn node_maturity_without_tardis() {
        let dir = tempfile::tempdir().unwrap();
        let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        // No TARDIS init → always Scarred
        assert_eq!(node.check_maturity(0), ChequeStatus::Scarred);
    }

    #[test]
    fn node_maturity_with_tardis() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        node.init_tardis(pk(0xAA));
        node.tardis_mut().unwrap().set_upstream(pk(0xBB));

        // Advance 10 ticks via TARDIS using Unix timestamps
        let base_secs: u64 = 1_740_000_000;
        for i in 1..=10u64 {
            let tick_secs = base_secs + (i * 5);
            let ts = tick_secs * 1000;
            let tick = TickMessage {
                number: tick_secs, upstream_pk: pk(0xBB),
                payload: tick_secs.to_le_bytes().to_vec(),
                signature: vec![0xFF; 64], timestamp_ms: ts,
                available_slots: vec![],
                downstream_approvals: 2,
                prev_sig: vec![], grandparent_pk: None, subtree_d_available: 0,
                oods_tardis: Vec::new(),
                child_pks: Vec::new(),
                gp_commitment: None,
            };
            node.process_tick(&tick, ts).unwrap();
        }

        // current_tick = base+50. Registered at base → 50s elapsed, maturity=25s → Clean
        assert_eq!(node.check_maturity(base_secs), ChequeStatus::Clean);
        // Registered at base+40 → only 10s elapsed, maturity=25s → Scarred
        assert_eq!(node.check_maturity(base_secs + 40), ChequeStatus::Scarred);
    }

    #[test]
    fn node_tardis_register_then_mature() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
        node.init_tardis(pk(0xAA));
        node.tardis_mut().unwrap().set_upstream(pk(0xBB));

        // Advance to tick 1 using Unix timestamps
        let base_secs: u64 = 1_740_000_000;
        let tick1_secs = base_secs + 5;
        let tick1 = TickMessage {
            number: tick1_secs, upstream_pk: pk(0xBB),
            payload: tick1_secs.to_le_bytes().to_vec(),
            signature: vec![0xFF; 64], timestamp_ms: tick1_secs * 1000,
            available_slots: vec![],
            downstream_approvals: 2,
            prev_sig: vec![], grandparent_pk: None, subtree_d_available: 0,
            oods_tardis: Vec::new(),
            child_pks: Vec::new(),
            gp_commitment: None,
        };
        node.process_tick(&tick1, tick1_secs * 1000).unwrap();

        // Register a wallet at tick 1
        let (reg, deed) = make_valid_reg(0xCC, 0x00, 0x01);
        node.register(&reg, &deed, crate::types::test_legs::NOW_SECS).unwrap();

        // Still not mature at tick 1
        assert_eq!(node.check_maturity(tick1_secs), ChequeStatus::Scarred);

        // Advance 6 more ticks (total 7), each 5s apart
        for i in 2..=7u64 {
            let tick_secs = base_secs + (i * 5);
            let ts = tick_secs * 1000;
            let tick = TickMessage {
                number: tick_secs, upstream_pk: pk(0xBB),
                payload: tick_secs.to_le_bytes().to_vec(),
                signature: vec![0xFF; 64], timestamp_ms: ts,
                available_slots: vec![],
                downstream_approvals: 2,
                prev_sig: vec![], grandparent_pk: None, subtree_d_available: 0,
                oods_tardis: Vec::new(),
                child_pks: Vec::new(),
                gp_commitment: None,
            };
            node.process_tick(&tick, ts).unwrap();
        }

        // Now mature: current_tick=base+35, reg_tick=base+5, elapsed=30s, maturity=25s → Clean
        assert_eq!(node.check_maturity(tick1_secs), ChequeStatus::Clean);
    }

    #[test]
    fn node_audit_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
        node.init_tardis(pk(0xAA));
        node.tardis_mut().unwrap().set_upstream(pk(0xBB));

        // Register some data so SMT has a non-empty root
        let (reg, deed) = make_valid_reg(0xDD, 0x00, 0x01);
        node.register(&reg, &deed, crate::types::test_legs::NOW_SECS).unwrap();

        // Simulate: upstream has same data, responds to OUR challenge with
        // a real proof from the same tree (roots match).
        let our_root = node.root_hash();
        let Some(TardisAction::SendAuditRequest { request, .. }) =
            node.tardis_mut().unwrap().generate_audit_request()
        else {
            panic!("expected SendAuditRequest");
        };
        let (subtree_hash, siblings) = node.smt().subtree_proof(&request.prefix, 8);
        let response = SubtreeAuditResponse {
            prefix: request.prefix.clone(),
            prefix_bits: 8,
            subtree_hash,
            root_hash: our_root,
            response_tick: 0,
            responder_pk: pk(0xBB),
            siblings,
            signature: vec![],
        };

        let action = node.verify_audit_response(&response).unwrap();
        assert!(matches!(action, TardisAction::None)); // audit passed
    }

    // ── Parentless Timeout (via NablaNode) ──

    #[test]
    fn node_tardis_parentless_ok_with_parent() {
        let mut node = NablaNode::new();
        node.init_tardis(pk(0xAA));
        node.tardis.as_mut().unwrap().set_upstream(pk(0xBB));
        node.tardis.as_mut().unwrap().add_downstream(pk(0xCC));
        let (action, detached) = node.tardis_check_parentless();
        assert_eq!(action, ParentlessAction::Ok);
        assert!(detached.is_empty());
    }

    #[test]
    fn node_tardis_parentless_detach_after_timeout() {
        let mut node = NablaNode::new();
        node.init_tardis(pk(0xAA));
        node.tardis.as_mut().unwrap().add_downstream(pk(0xCC));
        node.tardis.as_mut().unwrap().add_downstream(pk(0xDD));
        // No upstream set — zombie subtree

        // 4 ticks: still searching
        for _ in 0..4 {
            let (action, _) = node.tardis_check_parentless();
            assert!(matches!(action, ParentlessAction::Searching(_)));
        }

        // 5th tick: detach
        let (action, detached) = node.tardis_check_parentless();
        assert_eq!(action, ParentlessAction::DetachChildren);
        assert_eq!(detached.len(), 2);
        assert!(detached.contains(&pk(0xCC)));
        assert!(detached.contains(&pk(0xDD)));
    }

    // ── Leaf Migration (via NablaNode) ──

    #[test]
    fn node_tardis_leaf_should_migrate() {
        let mut node = NablaNode::new();
        node.init_tardis(pk(0xAA));
        node.tardis.as_mut().unwrap().set_upstream(pk(0xBB));
        // Leaf: 0 children, parent has 2 children → safe to leave
        assert!(node.tardis_should_migrate(2));
    }

    #[test]
    fn node_tardis_leaf_should_not_migrate_only_child() {
        let mut node = NablaNode::new();
        node.init_tardis(pk(0xAA));
        node.tardis.as_mut().unwrap().set_upstream(pk(0xBB));
        // Parent has only 1 child (us) → don't orphan parent
        assert!(!node.tardis_should_migrate(1));
    }

    #[test]
    fn node_tardis_detach_upstream() {
        let mut node = NablaNode::new();
        node.init_tardis(pk(0xAA));
        node.tardis.as_mut().unwrap().set_upstream(pk(0xBB));

        let old_parent = node.tardis_detach_upstream();
        assert_eq!(old_parent, Some(pk(0xBB)));
        assert!(node.tardis_needs_recovery());
    }

    // ── Full Persistence Tests — data path verification ──
    //
    // These tests prove that actual wallet entries (not just CC chain)
    // survive crash and recovery through both snapshot and WAL paths.

    /// Helper: create a NablaEntry with deterministic, verifiable fields.
    fn make_entry(idx: u8, tick: u64) -> NablaEntry {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = idx;
        wallet_id[31] = idx.wrapping_mul(7);  // secondary fingerprint

        let mut current_state = [0u8; 32];
        current_state[0] = idx.wrapping_add(0x10);
        current_state[1] = (tick & 0xFF) as u8;

        let mut tx_hash = [0u8; 32];
        tx_hash[0] = idx ^ 0xFF;
        tx_hash[1] = (tick >> 8) as u8;

        NablaEntry {
            received_from: None,
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
    fn persist_100_entries_snapshot_crash_recover() {
        // Inject 100 entries → snapshot → "crash" → reopen → verify every entry
        let dir = tempfile::tempdir().unwrap();
        let root_before;
        let mut wallet_ids: Vec<WalletId> = Vec::new();
        let mut states: Vec<StateId> = Vec::new();

        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            node.set_current_tick(1000);

            for i in 0..100u8 {
                let entry = make_entry(i, 1000);
                wallet_ids.push(entry.wallet_id);
                states.push(entry.current_state);
                node.inject_test_entry(&entry);
            }

            assert_eq!(node.entry_count(), 100);
            root_before = node.root_hash();

            // Take snapshot so data is on disk
            node.take_snapshot().unwrap();
        }
        // Node dropped — simulates crash

        // Reopen — should recover from snapshot
        {
            let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert_eq!(node.entry_count(), 100, "entry count must match after recovery");
            assert_eq!(node.root_hash(), root_before, "root hash must match after recovery");

            // Verify EVERY wallet has the correct state
            for i in 0..100u8 {
                let entry = node.smt().get(&wallet_ids[i as usize]);
                assert!(entry.is_some(), "wallet {} missing after recovery", i);
                let entry = entry.unwrap();
                assert_eq!(entry.current_state, states[i as usize],
                    "wallet {} state mismatch after recovery", i);
                assert_eq!(entry.tick, 1000, "wallet {} tick mismatch", i);
                assert_eq!(entry.wallet_id[31], i.wrapping_mul(7),
                    "wallet {} fingerprint mismatch", i);
            }
        }
    }

    #[test]
    fn persist_wal_only_entries_crash_recover() {
        // Snapshot 50 entries, then inject 50 MORE (WAL-only), crash, recover.
        // All 100 must survive — the WAL-only entries prove WAL replay works.
        let dir = tempfile::tempdir().unwrap();
        let root_final;
        let mut all_ids: Vec<WalletId> = Vec::new();
        let mut all_states: Vec<StateId> = Vec::new();

        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            node.set_current_tick(500);

            // Phase 1: 50 entries → snapshot (these are safe)
            for i in 0..50u8 {
                let entry = make_entry(i, 500);
                all_ids.push(entry.wallet_id);
                all_states.push(entry.current_state);
                node.inject_test_entry(&entry);
            }
            node.take_snapshot().unwrap();

            // Phase 2: 50 MORE entries — WAL only, no snapshot
            node.set_current_tick(600);
            for i in 50..100u8 {
                let entry = make_entry(i, 600);
                all_ids.push(entry.wallet_id);
                all_states.push(entry.current_state);
                node.inject_test_entry(&entry);
            }

            assert_eq!(node.entry_count(), 100);
            root_final = node.root_hash();
            // NO snapshot here — crash with WAL-only entries
        }

        // Reopen — must recover snapshot (50) + WAL replay (50)
        {
            let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert_eq!(node.entry_count(), 100, "all 100 entries must survive WAL replay");
            assert_eq!(node.root_hash(), root_final, "root hash must match including WAL entries");

            // Verify snapshot entries (tick=500)
            for i in 0..50u8 {
                let entry = node.smt().get(&all_ids[i as usize]).unwrap();
                assert_eq!(entry.tick, 500, "snapshot entry {} wrong tick", i);
                assert_eq!(entry.current_state, all_states[i as usize]);
            }

            // Verify WAL-only entries (tick=600) — the critical test
            for i in 50..100u8 {
                let entry = node.smt().get(&all_ids[i as usize]);
                assert!(entry.is_some(), "WAL-only entry {} missing after crash recovery", i);
                let entry = entry.unwrap();
                assert_eq!(entry.tick, 600, "WAL-only entry {} wrong tick", i);
                assert_eq!(entry.current_state, all_states[i as usize],
                    "WAL-only entry {} state mismatch", i);
            }
        }
    }

    #[test]
    fn persist_entry_update_survives_crash() {
        // Write entry, snapshot, UPDATE the entry (new state), crash, verify update survives.
        let dir = tempfile::tempdir().unwrap();
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = 0xAA;

        let updated_state;
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            node.set_current_tick(100);

            // Initial entry
            let entry_v1 = NablaEntry {
                               received_from: None,
                               wallet_seq: 0,
                wallet_id,
                current_state: [0x01; 32],
                tx_hash: [0xF1; 32],
                tick: 100,
                group_members: None,
                status: WalletStatus::Normal,
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            };
            node.inject_test_entry(&entry_v1);
            node.take_snapshot().unwrap();

            // Update same wallet (new state) — WAL only
            node.set_current_tick(200);
            let mut new_state = [0x02; 32];
            new_state[0] = 0xBE;
            new_state[1] = 0xEF;
            updated_state = new_state;
            let entry_v2 = NablaEntry {
                               received_from: None,
                               wallet_seq: 0,
                wallet_id,
                current_state: new_state,
                tx_hash: [0xF2; 32],
                tick: 200,
                group_members: None,
                status: WalletStatus::Normal,
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            };
            node.inject_test_entry(&entry_v2);

            // Verify in-memory: should be v2
            let live = node.smt().get(&wallet_id).unwrap();
            assert_eq!(live.current_state[0], 0xBE);
            assert_eq!(live.tick, 200);
            // NO snapshot — crash with WAL-only update
        }

        // Reopen — must replay WAL and get v2, not v1
        {
            let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert_eq!(node.entry_count(), 1, "should have 1 entry (updated, not duplicated)");
            let entry = node.smt().get(&wallet_id).unwrap();
            assert_eq!(entry.current_state, updated_state,
                "entry must have WAL-updated state, not snapshot state");
            assert_eq!(entry.tick, 200, "entry must have WAL-updated tick");
            assert_eq!(entry.tx_hash[0], 0xF2, "entry must have WAL-updated tx_hash");
        }
    }

    #[test]
    fn persist_cc_chain_with_smt_data_survives_crash() {
        // Full integration: entries + bans + CC chain, snapshot, more entries (WAL),
        // crash, verify everything recovers together.
        let dir = tempfile::tempdir().unwrap();
        let root_final;
        let ban_wid;

        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory
            let nbc = make_test_nbc(0xCC);
            node.init_cc(nbc);
            node.set_current_tick(100);

            // 20 wallet entries
            for i in 0..20u8 {
                let entry = make_entry(i, 100);
                node.inject_test_entry(&entry);
            }

            // Ban one wallet. YPX-002 §3.3 — /register no longer bans on
            // state mismatch; bans now come from the gossip-merge path
            // with two k=3 receipts as evidence. Use the test-only injector
            // to seed a ban with crash-safe WAL persistence so this test
            // can still verify that bans survive crash recovery alongside
            // SMT entries and the CC chain.
            let (reg1, deed1) = make_valid_reg(0xFA, 0x00, 0x01);
            node.register(&reg1, &deed1, crate::types::test_legs::NOW_SECS).unwrap();
            ban_wid = reg1.wallet_id;
            let evidence_1 = crate::types::ConflictProof {
                old_state: reg1.old_state,
                new_state: reg1.new_state,
                tx_hash: reg1.tx_hash,
                k3_signatures: vec![
                    WitnessSig { validator_pk: [1; 32], signature: vec![1; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [2; 32], signature: vec![2; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [3; 32], signature: vec![3; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                ],
                tick: 0,
                required_k: 3,
            };
            let evidence_2 = crate::types::ConflictProof {
                old_state: reg1.old_state,
                new_state: [0x02u8; 32],
                tx_hash: [0xFAu8; 32],
                k3_signatures: vec![
                    WitnessSig { validator_pk: [1; 32], signature: vec![1; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [2; 32], signature: vec![2; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [3; 32], signature: vec![3; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                ],
                tick: 0,
                required_k: 3,
            };
            node.inject_test_ban(ban_wid, evidence_1, evidence_2);
            let _ = deed1; // deed unused in this injection path

            // Produce CC ticks
            for tick in 101..=110 {
                node.set_current_tick(tick);
                node.cc_record_registration();
                node.cc_tick();
            }

            node.take_snapshot().unwrap();

            // More entries after snapshot (WAL only)
            node.set_current_tick(200);
            for i in 20..30u8 {
                let entry = make_entry(i, 200);
                node.inject_test_entry(&entry);
            }

            // More CC ticks after snapshot (WAL only)
            for tick in 201..=205 {
                node.set_current_tick(tick);
                node.cc_tick();
            }

            root_final = node.root_hash();
            // NO snapshot — crash
        }

        // Reopen — verify SMT + bans + CC all recovered
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            admit_fixture_witnesses(&mut node); // KI#224: the door/flood/AE read the directory

            // SMT: 20 (snapshot) + 10 (WAL) + 1 (reg before ban) = 31
            // But banned wallet may or may not be in SMT (depends on ban handling)
            // The registered wallet (0xFA) gets banned AND removed? Let's check:
            assert!(node.entry_count() >= 30,
                "at least 30 entries must survive: got {}", node.entry_count());
            assert_eq!(node.root_hash(), root_final, "root hash must match");

            // Ban survived
            assert!(node.is_banned(&ban_wid), "ban must survive crash recovery");

            // WAL-only entries survived
            for i in 20..30u8 {
                let wid = make_entry(i, 200).wallet_id;
                assert!(node.smt().get(&wid).is_some(),
                    "WAL-only entry {} missing", i);
            }

            // CC chain: restore it and verify score survived
            let nbc = make_test_nbc(0xCC);
            node.init_cc(nbc);  // picks up restored CC
            let cc = node.latest_cc();
            assert!(cc.is_some(), "CC must be restored from WAL");
            let cc = cc.unwrap();
            // 10 ticks in snapshot + 5 in WAL = 15
            assert_eq!(cc.ticks_helped, 15,
                "CC ticks_helped must include WAL-only ticks: got {}", cc.ticks_helped);
        }
    }

    /// Double-spend (seq-fork) ban survives a crash with its evidence intact.
    /// The ban is "no turning back": a WAL-persisted seq-fork ban must reopen as
    /// the SAME ban kind (seq_fork evidence present), not silently downgraded to
    /// an evidence-less ConflictProof ban.
    #[test]
    fn seq_fork_ban_survives_crash_with_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let ban_wid = { let mut w = [0u8; 32]; w[0] = 0xD5; w };
        let mk_proof = |seed: u8| crate::types::SeqProof {
            sender_state: None,
            oods_flag: None,
            confidence_index: None,
            state_hash: [seed; 32],
            commitment_hash: [seed ^ 0xFF; 32],
            epoch: 7,
            is_dev_class: false,
            sigs: Vec::new(),
            required_k: 3,
            preimage: crate::types::test_legs::opaque_redeem_leg(), // wave 2a — test proof, no WITNESS_V2 preimage
            declared: crate::types::test_legs::no_declared(),
        };
        let evidence = crate::types::SeqConflictProof {
            wallet_seq: 5,
            state_a: { let mut s = [0u8; 32]; s[0] = 0x01; s },
            tx_a: { let mut t = [0u8; 32]; t[0] = 0x0A; t },
            proof_a: mk_proof(0xA0),
            state_b: { let mut s = [0u8; 32]; s[0] = 0x02; s },
            tx_b: { let mut t = [0u8; 32]; t[0] = 0x0B; t },
            proof_b: mk_proof(0xB0),
        };
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            node.inject_test_seq_fork_ban(ban_wid, evidence.clone());
            assert!(node.is_banned(&ban_wid));
            // NO snapshot — crash, recover from WAL alone.
        }
        {
            let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert!(node.is_banned(&ban_wid), "seq-fork ban must survive crash recovery");
            let restored = node.bans().get(&ban_wid).expect("banned entry must exist after replay");
            assert_eq!(restored.evidence, crate::types::BanEvidence::SeqFork(evidence.clone()),
                "seq-fork evidence must survive WAL replay, not downgrade to a plain ban");
        }
    }

    // ── ForkSettlement wave 3 S4 — origin-ledger persistence + [R28] ────────
    //
    // The door / flood / AE hooks land in S5–S7, so these tests create records
    // through the ONE creation fn directly (`record_verified_leg`, from a
    // genuinely verified leg) and drain them to the WAL exactly as the hooks
    // will.

    fn w3_fork_legs(seed: u8) -> (crate::types::ForkLeg, crate::types::ForkLeg, [u8; 32]) {
        let sk = crate::types::test_legs::wallet(seed);
        let g = |recv: &str, nonce| crate::types::test_legs::genuine_send_leg(&sk, [0x59; 32], 5, recv, 400, nonce, 3);
        (g("p@axiom.internal/0123456789", 1), g("q@axiom.internal/0123456789", 2), sk.verifying_key().to_bytes())
    }

    fn w3_record(node: &mut NablaNode, leg: crate::types::ForkLeg, now: u64) -> crate::smt::OriginOutcome {
        let v = crate::ban::verify_fork_leg(leg).expect("genuine leg");
        node.smt_mut().record_verified_leg(v, now)
    }

    /// KI#228 — the ONE Nabla ban file (the owner 2026-09-29). `open` writes it
    /// (empty); a fork ban through the ONE verdict path lands in it on the
    /// next drain as the line ANTIE matches (the registrant's Ed25519 pk,
    /// lowercase hex), written atomically (no `.tmp` left); a reopen rewrites
    /// it from the PERSISTED bans (WAL replay) even after the file is deleted.
    /// Bans are permanent: there is no path that removes a line.
    /// MUTATION: drop the `write_ban_file_if_changed()` call in
    /// `drain_fork_side_effects` ⇒ red (the file is never created).
    #[test]
    fn fork_ban_lands_in_the_one_ban_file_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(crate::ban::NABLA_BAN_FILE);
        let (a, b, pk) = w3_fork_legs(0xC7);
        let line = hex::encode(pk);
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert_eq!(std::fs::read_to_string(&file).expect("open writes the file"), "",
                       "no bans yet = present and empty");
            w3_record(&mut node, a.clone(), 100);
            let held = match w3_record(&mut node, b.clone(), 101) {
                crate::smt::OriginOutcome::Conflict { held } => held,
                other => panic!("expected Conflict, got {other:?}"),
            };
            let claim = ForkClaim { a: held[0].leg.clone(), b: b.clone() };
            let (smt, bans) = (&mut node.smt, &mut node.bans);
            assert_eq!(crate::ban::apply_fork_verdict(smt, bans, &claim), Ok(vec![pk]));
            node.drain_fork_side_effects();
            let body = std::fs::read_to_string(&file).unwrap();
            assert!(body.lines().any(|l| l == line), "the fork-banned pk is listed: {body:?}");
            assert_eq!(body, node.bans().ban_file_contents(), "the file IS the table");
            assert!(!dir.path().join(format!("{}.tmp", crate::ban::NABLA_BAN_FILE)).exists(),
                    "atomic: the tmp was renamed over the file");
            assert_eq!(node.origin_status(None, 0).ban_file_write_failed, 0);
        }
        std::fs::remove_file(&file).unwrap();
        {
            let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert!(node.is_banned(&pk));
            let body = std::fs::read_to_string(&file).expect("reopen rewrites the file");
            assert!(body.lines().any(|l| l == line), "rewritten from the persisted ban: {body:?}");
        }
    }

    /// Test 23 (S4 half) — [R28]: two records under one key, the ban LOST
    /// (snapshot bans emptied, the WAL compacted by the snapshot holds no Ban),
    /// reopen → the detector re-derives the claim from the persisted records:
    /// the registrant is banned WITH the claim as evidence, the key is held,
    /// the claim is queued for the flood, the counter reads 1. A second reopen
    /// holds the ban from the WAL and re-derives nothing (no re-flood).
    /// MUTATION: skip `rederive_fork_bans_at_load` in `open` ⇒ red.
    #[test]
    fn restart_with_ban_removed_rederives_the_fork_ban() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, pk) = w3_fork_legs(0xC1);
        let key = a.key();
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert!(matches!(w3_record(&mut node, a.clone(), 100), crate::smt::OriginOutcome::Created { .. }));
            let held = match w3_record(&mut node, b.clone(), 101) {
                crate::smt::OriginOutcome::Conflict { held } => held,
                other => panic!("expected Conflict, got {other:?}"),
            };
            // What the door / flood / AE hook does (`ban::record_leg_and_detect`): the claim through the ONE verdict path.
            let claim = ForkClaim { a: held[0].leg.clone(), b: b.clone() };
            let (smt, bans) = (&mut node.smt, &mut node.bans);
            assert_eq!(crate::ban::apply_fork_verdict(smt, bans, &claim), Ok(vec![pk]));
            node.drain_fork_side_effects();
            assert_eq!(node.take_pending_fork_floods().len(), 1);
            node.take_snapshot().unwrap();
        }
        // Remove the ban from the persisted state: rewrite the snapshot without it.
        {
            let mgr = SnapshotManager::new(dir.path().join("snapshots")).unwrap();
            let mut snap = mgr.load_latest().unwrap().expect("snapshot");
            assert_eq!(snap.bans.len(), 1, "fixture: the ban was persisted");
            assert_eq!(snap.origin_ledger.len(), 2, "fixture: both records persisted");
            snap.bans.clear();
            mgr.write(&snap).unwrap();
        }
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert!(node.is_banned(&pk), "the lost ban is RE-DERIVED from the two records at load");
            assert!(matches!(node.bans().get(&pk).unwrap().evidence, BanEvidence::Fork(_)));
            assert!(node.smt().origin_key_is_held(&key), "the key is held: neither leg vouchable");
            assert_eq!(node.origin_fork_bans_rederived_at_load(), 1);
            assert_eq!(node.take_pending_fork_floods().len(), 1, "the re-derived claim is re-flooded");
        }
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert!(node.is_banned(&pk), "the re-derived ban was WAL-logged by the drain");
            assert_eq!(node.origin_fork_bans_rederived_at_load(), 0, "nothing new to re-derive");
            assert!(node.take_pending_fork_floods().is_empty(), "no re-flood of a held ban");
        }
    }

    /// R36 + R28 together — a WAL `Ban` record in the PRIOR `BannedEntry` shape
    /// (evidence_1 / evidence_2 / seq_fork / status) is REFUSED LOUDLY at
    /// replay (counted `wal_ban_decode_refused`), never silently skipped; the
    /// fork ban it carried is then re-derived from the two origin records.
    /// MUTATION: restore the silent `if let Ok(..)` skip (no counter bump) ⇒ red.
    #[test]
    fn wal_ban_in_prior_shape_is_refused_loudly_and_rederived_from_records() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, pk) = w3_fork_legs(0xC2);
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            w3_record(&mut node, a, 10);
            w3_record(&mut node, b, 11);
            node.drain_fork_side_effects();
            let cp = crate::types::ConflictProof::default();
            let prior = bincode::serialize(&(pk, &cp, &cp, &None::<crate::types::SeqConflictProof>, crate::types::BanStatus::Active)).unwrap();
            node.wal_mut().append(&WalOp::Ban { wallet_id: pk, evidence: prior }).unwrap();
            // Also a Ban for a wallet with NO records: refused and NOT re-derivable.
            let lone = [0xEE; 32];
            let prior2 = bincode::serialize(&(lone, &cp, &cp, &None::<crate::types::SeqConflictProof>, crate::types::BanStatus::Active)).unwrap();
            node.wal_mut().append(&WalOp::Ban { wallet_id: lone, evidence: prior2 }).unwrap();
        }
        let before = super::wal_ban_decode_refused_total();
        let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert!(super::wal_ban_decode_refused_total() >= before + 2, "both refusals COUNTED");
        assert!(node.is_banned(&pk), "re-derived from the surviving records [R28]");
        assert!(!node.is_banned(&[0xEE; 32]), "a refused ban with no records is gone — which is WHY it must be loud");
    }

    /// Test 24 — [R27] WAL replay of `OriginRecord` is a pure `or_insert`: the
    /// WAL holds (1) a Put of the parent head Y, (2) a Put advancing Y→Z (so Y
    /// IS consumed at replay time), (3) the record, persisted `contested:false`
    /// with `first_seen_secs = 777`. After reopen the record is still
    /// `contested:false` / 777 although a recompute would now say contested.
    /// MUTATION: replay through `record_verified_leg` (re-verify + recompute) ⇒ red.
    #[test]
    fn wal_replay_origin_record_is_pure_or_insert() {
        let dir = tempfile::tempdir().unwrap();
        let (a, _b, pk) = w3_fork_legs(0xC3);
        let tx = a.tx_hash;
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            assert_eq!(w3_record(&mut node, a.clone(), 777), crate::smt::OriginOutcome::Created { contested: false });
            let entry = |state: [u8; 32], seq: u64, tx_hash: [u8; 32]| NablaEntry {
                received_from: None, wallet_seq: seq, wallet_id: pk, current_state: state, tx_hash,
                tick: 1, group_members: None, status: WalletStatus::Normal, client_pk: pk, client_sig: vec![0u8; 64],
            };
            for e in [entry([0x59; 32], 4, [0x33; 32]), entry(a.new_state, 5, tx)] {
                node.wal_mut().append(&WalOp::Put {
                    key: pk, value: bincode::serialize(&e).unwrap(), client_pk: pk,
                    client_sig: e.client_sig.clone(), seq_proof: None,
                }).unwrap();
            }
            node.drain_fork_side_effects(); // the OriginRecord lands AFTER both Puts
        }
        let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert!(node.smt().is_state_consumed(&[0x59; 32]), "fixture: the parent is consumed at replay");
        let e = node.smt().vouch_record(&tx).expect("record replayed");
        assert!(!e.contested, "persisted contested:false stays false — never recomputed");
        assert_eq!(e.first_seen_secs, 777, "first_seen preserved");
        assert_eq!(node.smt().origin_len(), 1);
    }

    /// Test 25 (node half) — `take_snapshot` persists the ledger and `open`
    /// restores it verbatim (the WAL is compacted, so the snapshot is the only
    /// home). MUTATION: drop `origin_ledger` from `take_snapshot` (write an
    /// empty Vec) or drop the restore loop in `open` ⇒ red.
    #[test]
    fn origin_ledger_survives_snapshot_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (a, _b, _pk) = w3_fork_legs(0xC4);
        let tx = a.tx_hash;
        {
            let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            w3_record(&mut node, a, 555);
            node.drain_fork_side_effects();
            node.take_snapshot().unwrap();
        }
        let wal_ops = WriteAheadLog::read_all(dir.path().join("nabla.wal")).unwrap();
        assert!(!wal_ops.iter().any(|o| matches!(o, WalOp::OriginRecord { .. })),
            "fixture: the WAL was compacted — only the snapshot holds the record");
        let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        let e = node.smt().vouch_record(&tx).expect("restored from the snapshot");
        assert_eq!((e.first_seen_secs, e.contested), (555, false));
        assert!(node.smt().cheque_sender_registered(&tx));
    }

    /// YPX-009 §12.7: Corrupted WAL recovery test.
    ///
    /// Verifies the full recovery path:
    ///   1. Node writes entries + takes snapshot + writes more entries
    ///   2. WAL is corrupted (byte flip in post-snapshot region)
    ///   3. Node re-opens — recovers snapshot + pre-corruption WAL entries
    ///   4. Post-corruption entries are lost
    ///   5. Missing entries fed via handle_gossip (simulating peer re-sync)
    ///   6. Full state converges
    #[test]
    fn corrupted_wal_recovery_via_peer_resync() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        // ── Step 1: Build state with snapshot + post-snapshot entries ──
        let mut wallet_ids: Vec<WalletId> = Vec::new();
        {
            let mut node = NablaNode::open(data_dir, Box::new(crate::crypto::NoopSigner)).unwrap();

            // Insert 5 entries (pre-snapshot)
            for i in 0..5u8 {
                let wid = test_wid(0x40 + i); // KI#226: the key's own row
                let entry = NablaEntry {
                                received_from: None,
                                wallet_seq: 0,
                    wallet_id: wid,
                    current_state: [i + 10; 32],
                    tx_hash: [i + 20; 32],
                    tick: (i as u64) * 10,
                    group_members: None,
                    status: WalletStatus::Normal,
                    client_pk: [0u8; 32],
                    client_sig: vec![0u8; 64],
                };
                node.inject_test_entry(&entry);
                wallet_ids.push(wid);
            }

            // Force a snapshot at tick 40
            node.current_tick = 40;
            node.take_snapshot().unwrap();

            // Insert 5 more entries (post-snapshot — these are WAL-only)
            for i in 5..10u8 {
                let wid = test_wid(0x40 + i); // KI#226: the key's own row
                let entry = NablaEntry {
                                received_from: None,
                                wallet_seq: 0,
                    wallet_id: wid,
                    current_state: [i + 10; 32],
                    tx_hash: [i + 20; 32],
                    tick: (i as u64) * 10,
                    group_members: None,
                    status: WalletStatus::Normal,
                    client_pk: [0u8; 32],
                    client_sig: vec![0u8; 64],
                };
                node.inject_test_entry(&entry);
                wallet_ids.push(wid);
            }

            assert_eq!(node.entry_count(), 10, "should have 10 entries before corruption");
        }
        // node dropped — WAL flushed to disk

        // ── Step 2: Corrupt the WAL in the post-snapshot region ──
        let wal_path = data_dir.join("nabla.wal");
        {
            let data = std::fs::read(&wal_path).unwrap();
            assert!(data.len() > 100, "WAL should have substantial data");

            // Corrupt near the end (post-snapshot entries)
            let mut corrupted = data.clone();
            let pos = corrupted.len() - 40;
            corrupted[pos] ^= 0xFF;
            corrupted[pos + 1] ^= 0xFF;
            std::fs::write(&wal_path, &corrupted).unwrap();
        }

        // ── Step 3: Re-open node — should recover snapshot + partial WAL ──
        let mut node = NablaNode::open(data_dir, Box::new(crate::crypto::NoopSigner)).unwrap();

        // Snapshot had 5 entries. Some WAL entries may have survived corruption.
        // At minimum, the 5 snapshot entries should be present.
        assert!(node.entry_count() >= 5,
            "snapshot entries must survive: got {}", node.entry_count());
        assert!(node.entry_count() < 10,
            "corruption should lose some entries: got {}", node.entry_count());

        // Verify snapshot entries are intact
        for i in 0..5u8 {
            let resp = node.query(&wallet_ids[i as usize]);
            assert_eq!(resp.current_state[0], i + 10,
                "snapshot entry {} should be intact", i);
        }

        // ── Step 4: Identify missing entries ──
        let mut missing_wallet_ids = Vec::new();
        for i in 5..10u8 {
            let resp = node.query(&wallet_ids[i as usize]);
            if resp.current_state == [0u8; 32] {
                missing_wallet_ids.push(i);
            }
        }
        assert!(!missing_wallet_ids.is_empty(),
            "at least some post-snapshot entries should be lost");

        // ── Step 5: Re-sync missing entries via handle_gossip (simulating peer pull) ──
        for i in &missing_wallet_ids {
            let (client_pk, client_sig) = test_author(
                0x40 + *i, &wallet_ids[*i as usize], &[*i + 10; 32], &[*i + 20; 32],
            );
            let gossip_msg = GossipMessage::StateUpdate {
                                 old_state: [0u8; 32],
                                 wallet_seq: 0,
                seq_proof: None,
                wallet_id: wallet_ids[*i as usize],
                new_state: [*i + 10; 32],
                tx_hash: [*i + 20; 32],
                tick: (*i as u64) * 10,
            is_genesis_claim: false,
                client_pk,
                client_sig,
                amount: 0,
                fee_breakdown: Vec::new(),
            };
            let action = node.handle_gossip(&gossip_msg, crate::types::test_legs::NOW_SECS);
            assert!(matches!(action, crate::gossip::GossipAction::Forward(_)),
                "re-synced entry {} should be accepted (Forward)", i);
        }

        // ── Step 6: Verify full convergence ──
        assert_eq!(node.entry_count(), 10,
            "all 10 entries should be restored after re-sync");
        for i in 0..10u8 {
            let resp = node.query(&wallet_ids[i as usize]);
            assert_eq!(resp.current_state[0], i + 10,
                "entry {} state mismatch after recovery", i);
        }

        // WAL should now have new checksums for the re-synced entries
        assert!(node.wal().checksum_count() > 0,
            "WAL should have checksums after recovery");
    }

    // ── Pool persistence + restart recovery ────────────────────────────

    /// Round-trip a `PersistedPoolState` through CBOR on disk and
    /// verify all three fields survive byte-identically.
    #[test]
    fn persisted_pool_state_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_pool.state");
        let state = PersistedPoolState {
            balance: 5_999_990_000_000_000,
            total_claims: 13,
            // KI#191 — distinct values so the round trip actually proves these
            // survive; a restart that resets them advertises an unbalanced
            // snapshot on its first PoolSync.
            paid_out: 10_000_000_000,
            topped_up: 7,
            tick: 42_000,
            claims_this_cycle: 3,
            cycle_start_tick: 40_000,
            mesh_claims_at_cycle_start: 10,
        };
        state.save(&path).expect("save");
        let loaded = PersistedPoolState::load(&path)
            .expect("load IO ok")
            .expect("file present");
        assert_eq!(state, loaded);
    }

    // ── PoolCaps (Phase A) tests ────────────────────────────────────────
    //
    // Cover: per-Nabla cap firing, mesh-wide cap firing, cycle rollover,
    // §5.5 monotonic-decrease invariant. See docs/AXIOM_DESIGN_NablaPoolCaps.md.

    /// Per-Nabla cap fires at exactly N claims within a cycle.
    /// KI#30 — measure the supply-cap over-mint ("leak") caused by gossip
    /// under-counting. `total_claims` converges via **max-wins**, not sum
    /// (`node.rs::reconcile` + the mesh-cap check at `try_claim`), so concurrent
    /// genesis claims on different Nablas do NOT accumulate in the counter the
    /// mesh cap is measured against. The effective ceiling therefore becomes
    /// per-node-cap × N rather than the intended mesh aggregate.
    ///
    /// This test runs the REAL `AirdropPool::try_claim` + `reconcile` over an
    /// N-node mesh with a tunable gossip window and prints the over-mint. Run
    /// with `--nocapture` to see the numbers; it also asserts the structural
    /// relationship so it doubles as a regression guard.
    #[test]
    fn ki30_supply_cap_leak_measurement() {
        use crate::constants::{
            AIRDROP_MESH_CAP_PER_CYCLE, AIRDROP_CLAIMS_PER_CYCLE_PER_NABLA,
            AIRDROP_POOL_INITIAL_ATOMS,
        };
        let tick = 1_000_000u64;
        let per_node = AIRDROP_CLAIMS_PER_CYCLE_PER_NABLA;
        let mesh_cap = AIRDROP_MESH_CAP_PER_CYCLE;

        eprintln!("[KI30] per_node_cap={per_node} mesh_cap={mesh_cap}");

        // --- Direct probe: does the counter under-count concurrent claims? ---
        {
            let mut a = AirdropPool::new(AIRDROP_POOL_INITIAL_ATOMS);
            let mut b = AirdropPool::new(AIRDROP_POOL_INITIAL_ATOMS);
            for _ in 0..50 { assert!(a.try_claim(tick).is_granted()); }
            for _ in 0..50 { assert!(b.try_claim(tick).is_granted()); }
            // Gossip both directions (PoolSync reconcile).
            let _ = a.reconcile(b.balance(), b.total_claims, b.paid_out());
            let _ = b.reconcile(a.balance(), a.total_claims, a.paid_out());
            let true_claims = a.local_claims + b.local_claims; // 100
            eprintln!(
                "[KI30] probe: 2 nodes each granted 50 (true minted={true_claims}); \
                 after gossip each node believes total_claims={} — undercount={}",
                a.total_claims, true_claims - a.total_claims,
            );
            assert_eq!(true_claims, 100);
            assert_eq!(a.total_claims, 50, "max-wins counter undercounts concurrent claims");
        }

        // --- Realistic leak model: per-claim PoolSync propagation ---
        // CRITICAL: in production every GRANTED claim immediately broadcasts a
        // PoolSync (nabla_node.rs:~5976), so min-wins balance converges as
        // claims spread. The leak is therefore bounded by the claims IN FLIGHT
        // within one propagation window — NOT by N × per_node_cap. We model the
        // in-flight window `w` = claims granted mesh-wide before a claim is
        // globally visible (reconcile every `w` grants). w=1 = instant
        // propagation (the production path); larger w models slower gossip /
        // an adversarial burst. Pool sized to a known capacity.
        let claim_amount = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;
        let capacity = 1_000u64; // pool allows exactly 1000 claims
        let initial = capacity * claim_amount;
        let cycle = crate::constants::AIRDROP_CYCLE_SECS;

        let run = |n: usize, w: usize| -> u64 {
            // KI#191 — a pool with its own budget must DECLARE it, or its
            // `initial_atoms` answers with the airdrop constant and every
            // snapshot it gossips fails conservation by construction.
            // KI#191 — a pool with its own budget must DECLARE it. `new()`
            // answers `initial_atoms()` with the AIRDROP constant whatever
            // balance it is opened with (see its comment: ~80 fixtures depend on
            // that), so this 1,000-claim pool claimed a 600,000 AXC budget and
            // every snapshot it gossiped failed conservation by construction.
            let mut nodes: Vec<AirdropPool> = (0..n)
                .map(|_| AirdropPool::new(initial).with_class_constants(initial, claim_amount))
                .collect();
            let mut minted = 0u64;
            let mut since_gossip = 0usize;
            let mut t = tick;
            let mut idle = 0u64;
            loop {
                let mut any = false;
                for i in 0..n {
                    if nodes[i].try_claim(t).is_granted() {
                        minted += 1;
                        any = true;
                        since_gossip += 1;
                        if since_gossip >= w {
                            // KI#191 — the CONSERVATION TERMS must come from ONE node's
                            // own snapshot (`balance` and `paid_out` together), because
                            // a mixed pair is a state no node ever held and the identity
                            // correctly refuses it. The CLAIM COUNTER keeps its max-wins
                            // role: a real receiver hears every peer and takes the
                            // highest, and that counter is what drives the mesh cap —
                            // feeding it one node's count instead lets the cap never trip
                            // and the pool over-mints 50x (measured while building this).
                            let (min_bal, min_paid) = nodes.iter()
                                .min_by_key(|x| x.balance())
                                .map(|x| (x.balance(), x.paid_out()))
                                .unwrap();
                            let max_claims = nodes.iter().map(|x| x.total_claims).max().unwrap();
                            for node in nodes.iter_mut() { let _ = node.reconcile(min_bal, max_claims, min_paid); }
                            since_gossip = 0;
                        }
                    }
                }
                // converge + roll the cycle so the per-node cap doesn't cap the
                // drain before the balance does (we are measuring balance-level).
                // KI#191 — coherent (balance, paid_out); max-wins claim counter.
                let (min_bal, min_paid) = nodes.iter()
                    .min_by_key(|x| x.balance())
                    .map(|x| (x.balance(), x.paid_out()))
                    .unwrap();
                let max_claims = nodes.iter().map(|x| x.total_claims).max().unwrap();
                for node in nodes.iter_mut() { let _ = node.reconcile(min_bal, max_claims, min_paid); }
                if !any { idle += 1; if idle > 2 { break; } } else { idle = 0; }
                t += cycle;
            }
            minted
        };

        eprintln!("[KI30] pool capacity = {capacity} claims (per-claim PoolSync = in_flight_window w=1)");
        for &(n, w) in &[(10usize, 1usize), (50, 1), (200, 1), (10, 5), (50, 25), (200, 100)] {
            let minted = run(n, w);
            let over = minted.saturating_sub(capacity);
            eprintln!(
                "[KI30] nodes={n:>4} in_flight_window={w:>4} : minted={minted:>6} \
                 capacity={capacity} over-mint={over:>5} ({:.3}x)",
                minted as f64 / capacity as f64,
            );
        }

        // With per-claim propagation (w=1, the PRODUCTION path), the over-mint is
        // bounded by ~the in-flight window, NOT N×. The earlier "N× over-mint"
        // figure was an artifact of modelling ZERO gossip between claims — not
        // faithful to nabla_node.rs:~5976, which broadcasts on every grant. The
        // residual leak is (in-flight window × N)-bounded, material only under an
        // adversarial burst faster than gossip propagation (each claim = a k=3
        // round). Real env timing is the right place to put an exact number.
        let minted_w1 = run(50, 1);
        assert!(
            minted_w1 <= capacity + 50,
            "per-claim PoolSync (w=1) conserves to within ~N: minted={minted_w1} cap={capacity}",
        );
        // keep `per_node` / `mesh_cap` referenced (avoid unused warnings)
        let _ = (per_node, mesh_cap);
    }

    #[test]
    fn airdrop_per_nabla_cap_fires_at_limit() {
        let mut pool = AirdropPool::new(crate::constants::AIRDROP_POOL_INITIAL_ATOMS);
        let cap = crate::constants::AIRDROP_CLAIMS_PER_CYCLE_PER_NABLA;
        let tick = 1_000_000;
        // First N claims succeed
        for i in 0..cap {
            assert!(pool.try_claim(tick).is_granted(), "claim {} should succeed (under cap)", i);
        }
        // (N+1)th claim refused — cap reached
        assert!(matches!(
            pool.try_claim(tick),
            ClaimOutcome::RefusedPerNablaCap { .. }
        ), "claim N+1 must be refused by per-Nabla cap");
        assert_eq!(pool.claims_this_cycle, cap, "counter exactly at cap");
    }

    /// Cycle rollover resets the per-Nabla counter.
    #[test]
    fn airdrop_cap_resets_on_cycle_rollover() {
        let mut pool = AirdropPool::new(crate::constants::AIRDROP_POOL_INITIAL_ATOMS);
        let cap = crate::constants::AIRDROP_CLAIMS_PER_CYCLE_PER_NABLA;
        let cycle_secs = crate::constants::AIRDROP_CYCLE_SECS;
        let t0 = 1_000_000;
        // Saturate the cap
        for _ in 0..cap { let _ = pool.try_claim(t0); }
        assert!(!pool.try_claim(t0).is_granted(), "saturated");
        // Advance past cycle end → counter resets, next claim succeeds
        let t1 = t0 + cycle_secs;
        assert!(pool.try_claim(t1).is_granted(), "first claim of new cycle should succeed");
        assert_eq!(pool.claims_this_cycle, 1, "counter restarted at 1");
        assert_eq!(pool.cycle_start_tick, t1, "cycle anchor moved");
    }

    /// Mesh-wide cap fires when peer-gossiped claims push us past the
    /// per-cycle ceiling, even if our own per-Nabla cap isn't reached.
    #[test]
    fn airdrop_mesh_cap_fires_via_gossiped_total_claims() {
        let mut pool = AirdropPool::new(crate::constants::AIRDROP_POOL_INITIAL_ATOMS);
        let mesh_cap = crate::constants::AIRDROP_MESH_CAP_PER_CYCLE;
        let t0 = 1_000_000;
        // Roll cycle by performing one local claim
        assert!(pool.try_claim(t0).is_granted());
        assert_eq!(pool.mesh_claims_at_cycle_start, 0);
        // Simulate gossip: total_claims jumps to mesh_cap + snapshot
        // (we already did one local claim so total_claims = 1; gossip
        // brings it to mesh_cap from the snapshot of 0).
        pool.total_claims = mesh_cap;
        // Next try_claim sees mesh_claims_this_cycle = mesh_cap → refuse
        assert!(matches!(
            pool.try_claim(t0),
            ClaimOutcome::RefusedMeshCap { .. },
        ), "mesh-wide cap reached: must refuse further local claims");
    }

    /// SEC-03: an equal-balance reconcile that ratchets total_claims
    /// beyond the per-merge skew bound is rejected as a MagnitudeViolation
    /// and does NOT mutate the persisted counter — a single lying node
    /// can't poison the mesh cap to induce RefusedMeshCap.
    ///
    /// The pool is drained first (via the dev-only setter) so the Layer-1
    /// structural conservation gate — which already bounds total_claims to
    /// `(initial − balance)/claim_amount` — has slack; this test targets the
    /// residual equal-balance window the new bound closes.
    /// KI#191 — ADOPTING A PEER'S BALANCE MUST ADOPT ITS Σminus WITH IT.
    ///
    /// `balance` and `paid_out` are two halves of one conserved statement. A
    /// node that takes the peer's lower balance but keeps its own smaller
    /// `paid_out` can no longer balance, and the snapshot it gossips next is
    /// incoherent — every downstream node reads a structural violation and the
    /// mesh stops converging. That is not hypothetical: it is what this bug did
    /// to the KI#30 simulation while KI#191 was being built (50x over-mint,
    /// because each adopted balance arrived one claim ahead of the Σminus that
    /// explained it).
    ///
    /// MUTATION-TESTED: delete the `paid_out` adoption in
    /// `AirdropPool::reconcile` and this test fails on the identity assert,
    /// and `ki30_supply_cap_leak_measurement` fails alongside it.
    #[test]
    fn adopting_a_peer_balance_adopts_its_paid_out() {
        let initial = 1_000 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;
        let claim = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;
        let mk = || AirdropPool::new(initial).with_class_constants(initial, claim);

        // A peer three claims ahead: its snapshot is internally conserved.
        let mut peer = mk();
        for _ in 0..3 { assert!(peer.try_claim(1).is_granted()); }
        assert_eq!(peer.balance() + peer.paid_out(), initial, "fixture must be conserved");

        // A local node that has claimed nothing adopts it.
        let mut local = mk();
        let out = local.reconcile(peer.balance(), peer.total_claims, peer.paid_out());
        assert!(matches!(out, ReconcileOutcome::Updated), "min-wins must adopt, got {out:?}");

        assert_eq!(
            local.balance() + local.paid_out(), initial,
            "after adopting, THIS pool must still balance — otherwise the next \
             snapshot it gossips is incoherent and the mesh stops converging",
        );
        assert_eq!(local.paid_out(), peer.paid_out(), "Σminus is adopted, not inferred");

        // And Σminus never goes backwards: a stale peer cannot lower it.
        let mut stale = mk();
        assert!(stale.try_claim(1).is_granted());
        let before = local.paid_out();
        let _ = local.reconcile(stale.balance(), stale.total_claims, stale.paid_out());
        assert_eq!(local.paid_out(), before, "a pool only ever pays out MORE");
    }

    #[test]
    fn airdrop_reconcile_rejects_unbounded_equal_balance_claims_jump() {
        let mut pool = AirdropPool::new(crate::constants::AIRDROP_POOL_INITIAL_ATOMS);
        // Drain to half so conservation permits a large claim counter.
        pool.force_balance_dev_only(3_000_000_000_000_000);
        let balance = pool.balance();
        let claims_before = pool.total_claims; // 0
        let bound = crate::constants::POOL_SYNC_MAX_CLAIMS_SKEW_PER_MERGE;

        // Attacker reports the SAME balance but a claim counter jumping
        // past the per-merge bound (still within conservation slack).
        // KI#191 — same balance ⇒ same Σminus. An incoherent pair would trip the
        // Layer 1 conservation check first and this test would stop exercising
        // the magnitude bound it is named for.
        let outcome = pool.reconcile(balance, claims_before + bound + 1, pool.paid_out());
        assert!(
            matches!(outcome, ReconcileOutcome::MagnitudeViolation { .. }),
            "equal-balance claims jump past the bound must be a MagnitudeViolation, got {:?}",
            outcome,
        );
        assert_eq!(
            pool.total_claims, claims_before,
            "rejected reconcile must NOT mutate the counter",
        );
    }

    /// SEC-03: a within-bound equal-balance claim skew (normal gossip
    /// ordering) is still accepted so convergence isn't broken.
    #[test]
    fn airdrop_reconcile_accepts_within_bound_equal_balance_skew() {
        let mut pool = AirdropPool::new(crate::constants::AIRDROP_POOL_INITIAL_ATOMS);
        pool.force_balance_dev_only(3_000_000_000_000_000);
        let balance = pool.balance();
        let claims_before = pool.total_claims;
        // A small skew (a peer saw a few more claims we'll see drains for soon).
        let outcome = pool.reconcile(balance, claims_before + 1, pool.paid_out());
        assert!(
            matches!(outcome, ReconcileOutcome::Updated),
            "within-bound skew must converge, got {:?}", outcome,
        );
        assert_eq!(pool.total_claims, claims_before + 1);
    }

    /// §5.5 invariant: set_balance rejects an equal or higher value.
    /// Phase B promoted return from bool to SetBalanceOutcome.
    #[test]
    fn airdrop_balance_invariant_rejects_non_strict_decrease() {
        let mut pool = AirdropPool::new(1_000);
        assert_eq!(pool.balance(), 1_000);
        // Equal: rejected
        assert!(
            matches!(pool.set_balance(1_000),
                SetBalanceOutcome::RejectedNonStrictDecrease { .. }),
            "equal value must be rejected",
        );
        assert_eq!(pool.balance(), 1_000, "rejected write must not apply");
        // Higher: rejected
        assert!(
            matches!(pool.set_balance(2_000),
                SetBalanceOutcome::RejectedNonStrictDecrease { .. }),
            "higher value must be rejected",
        );
        assert_eq!(pool.balance(), 1_000);
        // Lower: accepted
        assert!(matches!(pool.set_balance(500), SetBalanceOutcome::Applied),
            "strict decrease must be accepted");
        assert_eq!(pool.balance(), 500);
    }

    /// A LAGGING peer (higher balance: it has not seen our latest claim) is not
    /// an invariant violation — same rule as the airdrop pool. Measured live
    /// 2026-09-26: peer = local + exactly one claim, accused every burst.
    #[test]
    fn dev_treasury_lagging_peer_is_noop_not_accused() {
        let claim = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;
        let mut pool = DevTreasuryPool::new(crate::constants::DEV_TREASURY_POOL_INITIAL_ATOMS);
        assert!(pool.try_claim(1_000_000).is_granted());
        let local = pool.balance();
        let claims = pool.total_claims;
        assert!(matches!(pool.reconcile(local + claim, claims - 1), ReconcileOutcome::NoOp),
                "a peer one claim behind must be ignored, not accused");
        assert_eq!(pool.balance(), local, "min-wins: our lower balance stands");
        // The lower direction is untouched: a real drain is still adopted.
        assert!(matches!(pool.reconcile(local - claim, claims + 1), ReconcileOutcome::Updated));
    }

    /// Dev pool symmetric per-Nabla cap.
    #[test]
    fn dev_treasury_per_nabla_cap_fires_at_limit() {
        let mut pool = DevTreasuryPool::new(crate::constants::DEV_TREASURY_POOL_INITIAL_ATOMS);
        let cap = crate::constants::DEV_TREASURY_CLAIMS_PER_CYCLE_PER_NABLA;
        let tick = 1_000_000;
        for i in 0..cap {
            assert!(pool.try_claim(tick).is_granted(), "claim {} should succeed", i);
        }
        assert!(matches!(
            pool.try_claim(tick),
            ClaimOutcome::RefusedPerNablaCap { .. },
        ), "claim N+1 must be refused");
    }

    // ── Validator-join grants (AXIOM_DESIGN_ValidatorJoin.md §4 step 3) ──

    /// A pool drains by EXACTLY its tier floor per grant, and stops when the
    /// declared slot count is spent — no 401st Community grant, no dust left.
    /// This is the runtime half of the arithmetic Core asserts statically.
    #[test]
    fn join_pool_grants_exactly_the_slot_count_then_refuses() {
        use axiom_core_logic::types::{COMMUNITY_SUBSIDISED_SLOTS, TIER3_CLAIM_AXC};
        let mut pool = AirdropPool::new(crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS);
        // The pool drains by what a claim PAYS, not by the stake floor. Those
        // were the same number until 2026-09-04; draining by the floor now
        // leaves 400 x 5 = 2,000 AXC of dust the pool can never grant.
        let floor = axiom_denomination::axc(TIER3_CLAIM_AXC);

        let mut granted = 0u64;
        // Cap layers are per-cycle, so advance the tick each round to isolate
        // the property under test (balance exhaustion, not rate limiting).
        for i in 0..COMMUNITY_SUBSIDISED_SLOTS {
            let tick = i * crate::constants::AIRDROP_CYCLE_SECS;
            match pool.try_claim_amount(tick, floor) {
                ClaimOutcome::Granted => granted += 1,
                other => panic!("grant {i} refused early: {other:?}"),
            }
        }
        assert_eq!(granted, COMMUNITY_SUBSIDISED_SLOTS, "all declared slots must be grantable");
        assert_eq!(pool.balance(), 0, "the pool must drain to exactly zero — no dust");

        // The slot after the last one is refused: the pool is the cap.
        let after = pool.try_claim_amount(
            COMMUNITY_SUBSIDISED_SLOTS * crate::constants::AIRDROP_CYCLE_SECS, floor);
        assert!(matches!(after, ClaimOutcome::RefusedExhausted),
            "grant {} must be refused, got {after:?}", COMMUNITY_SUBSIDISED_SLOTS + 1);
    }

    /// A zero-amount claim must be refused and must not move the balance.
    ///
    /// This asserts the BEHAVIOUR, not any one mechanism: the outcome is
    /// guaranteed twice over, by the explicit guard in `try_claim_amount` and
    /// independently by `set_balance`'s strict-decrease invariant. Mutation
    /// confirmed the test still passes with the explicit guard removed, so it
    /// must NOT be read as proof that the guard is load-bearing.
    #[test]
    fn join_pool_refuses_zero_amount() {
        let mut pool = AirdropPool::new(crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS);
        let before = pool.balance();
        assert!(matches!(pool.try_claim_amount(0, 0), ClaimOutcome::RefusedExhausted));
        assert_eq!(pool.balance(), before, "a refused claim must not move the balance");
    }

    /// A claim larger than the remaining balance is refused outright — the
    /// pool must never part-fund a grant, which would strand a candidate with
    /// less than its tier floor and no way to reach it.
    #[test]
    fn join_pool_never_part_funds_a_grant() {
        // A grant size, not a floor (the ruled Foundation claim) — any consistent
        // grant exercises the no-part-fund rule.
        let floor = axiom_core_logic::types::TIER2_CLAIM_ATOMS;
        // One floor short of two grants.
        let mut pool = AirdropPool::new(floor + floor / 2);
        assert!(matches!(pool.try_claim_amount(0, floor), ClaimOutcome::Granted));
        let remaining = pool.balance();
        assert!(remaining > 0 && remaining < floor, "setup: partial remainder");
        let second = pool.try_claim_amount(
            crate::constants::AIRDROP_CYCLE_SECS, floor);
        assert!(matches!(second, ClaimOutcome::RefusedExhausted),
            "a grant larger than the balance must be refused, got {second:?}");
        assert_eq!(pool.balance(), remaining, "a refused grant must not partially debit");
    }

    /// Persisted cycle fields round-trip through CBOR (a Nabla restart
    /// mid-cycle resumes its cap state correctly).
    #[test]
    fn airdrop_pool_cycle_state_persists_across_round_trip() {
        let mut pool = AirdropPool::new(crate::constants::AIRDROP_POOL_INITIAL_ATOMS);
        let tick = 5_555;
        pool.try_claim(tick);
        pool.try_claim(tick);
        pool.try_claim(tick);
        let persisted = pool.to_persisted(tick);
        assert_eq!(persisted.claims_this_cycle, 3);
        assert_eq!(persisted.cycle_start_tick, tick);
        let restored = AirdropPool::from_persisted(&persisted);
        assert_eq!(restored.claims_this_cycle, 3);
        assert_eq!(restored.cycle_start_tick, tick);
        assert_eq!(restored.balance(), persisted.balance);
    }

    /// `load()` on a non-existent file returns `Ok(None)`, signalling
    /// "fresh node, fall back to initial balance".
    #[test]
    fn persisted_pool_state_missing_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.state");
        assert!(PersistedPoolState::load(&path).unwrap().is_none());
    }

    /// `load()` on a corrupt file returns `Err`, NOT silently `Ok(None)` —
    /// caller fails loudly rather than re-minting the pool.
    #[test]
    fn persisted_pool_state_corrupt_file_is_loud_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.state");
        std::fs::write(&path, b"not valid cbor at all").unwrap();
        let result = PersistedPoolState::load(&path);
        assert!(
            result.is_err(),
            "corrupt CBOR must surface as IO error, not Ok(None)"
        );
    }

    /// After a successful airdrop claim, the persisted file on disk
    /// reflects the new balance/total_claims.
    #[test]
    fn try_airdrop_claim_persists_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        let initial_balance = node.airdrop_pool().balance;

        assert_eq!(node.try_airdrop_claim(), ClaimOutcome::Granted, "claim should succeed on fresh pool");

        let state_path = dir.path().join(PoolKind::Airdrop.state_filename());
        assert!(state_path.exists(), "airdrop pool state file must be written");

        let loaded = PersistedPoolState::load(&state_path).unwrap().unwrap();
        assert_eq!(loaded.balance, initial_balance - axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        assert_eq!(loaded.total_claims, 1);
    }

    /// Same for the DevTreasury pool — the dev-pool wrapper persists.
    #[test]
    fn try_dev_treasury_claim_persists_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        let initial_balance = node.dev_treasury_pool().balance;

        assert_eq!(node.try_dev_treasury_claim(), ClaimOutcome::Granted, "claim should succeed on fresh dev pool");

        let state_path = dir.path().join(PoolKind::DevTreasury.state_filename());
        assert!(state_path.exists(), "dev_treasury pool state file must be written");

        let loaded = PersistedPoolState::load(&state_path).unwrap().unwrap();
        assert_eq!(loaded.balance, initial_balance - axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        assert_eq!(loaded.total_claims, 1);
    }

    /// End-to-end restart test: claim, drop the node, reopen — pools
    /// recover from disk with the post-claim state, NOT the initial
    /// constants. This is the "balance is never recorded" regression
    /// gate from 2026-05-24.
    #[test]
    fn pools_recover_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let claim_amount = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;

        // Session 1: open, claim airdrop twice and dev once, drop.
        let (airdrop_initial, dev_initial) = {
            let mut node =
                NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            let airdrop_initial = node.airdrop_pool().balance;
            let dev_initial = node.dev_treasury_pool().balance;
            assert_eq!(node.try_airdrop_claim(), ClaimOutcome::Granted);
            assert_eq!(node.try_airdrop_claim(), ClaimOutcome::Granted);
            assert_eq!(node.try_dev_treasury_claim(), ClaimOutcome::Granted);
            // drop happens at end of scope
            (airdrop_initial, dev_initial)
        };

        // Session 2: reopen — pools must reflect prior session's deductions.
        let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert_eq!(
            node.airdrop_pool().balance,
            airdrop_initial - 2 * claim_amount,
            "airdrop balance must survive restart"
        );
        assert_eq!(
            node.airdrop_pool().total_claims, 2,
            "airdrop total_claims must survive restart"
        );
        assert_eq!(
            node.dev_treasury_pool().balance,
            dev_initial - claim_amount,
            "dev_treasury balance must survive restart"
        );
        assert_eq!(
            node.dev_treasury_pool().total_claims, 1,
            "dev_treasury total_claims must survive restart"
        );
        assert_eq!(
            node.airdrop_pool().local_claims, 0,
            "local_claims does not persist — resets per session"
        );
    }

    /// PoolSync gossip from a peer-with-smaller-balance updates the
    /// local pool AND persists the new state. This is the gossip-driven
    /// convergence path; it must also survive restart.
    #[test]
    fn pool_sync_gossip_persists_state() {
        let dir = tempfile::tempdir().unwrap();
        let claim_amount = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;

        let initial_balance = {
            let mut node =
                NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            let initial = node.airdrop_pool().balance;

            // Simulate gossip from a peer that processed 3 more claims.
            let msg = GossipMessage::PoolSync {
                pool: PoolKind::Airdrop,
                balance: initial - 3 * claim_amount,
                total_claims: 3,
                // KI#191 — a COHERENT peer snapshot: it drained exactly what its
                // three claims cost, so `balance + paid_out == initial`. An
                // incoherent pair would now be a structural violation and this
                // test would stop measuring the claim-skew behaviour it names.
                paid_out: 3 * claim_amount,
                topped_up: 0,
                tick: 100,
                sender_node_id: [0u8; 32],
                sender_sig: Vec::new(),
            };
            let _action = node.handle_gossip(&msg, crate::types::test_legs::NOW_SECS);
            assert_eq!(node.airdrop_pool().balance, initial - 3 * claim_amount);
            assert_eq!(node.airdrop_pool().total_claims, 3);
            initial
        };

        // Reopen — state must survive.
        let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert_eq!(node.airdrop_pool().balance, initial_balance - 3 * claim_amount);
        assert_eq!(node.airdrop_pool().total_claims, 3);
    }

    /// PoolSync gossip with HIGHER peer balance is REJECTED (stale or
    /// malicious peer). No state change, no persistence write needed.
    /// Confirms the monotonic-decrease rule is enforced on the
    /// unified handler regardless of pool type.
    #[test]
    fn pool_sync_rejects_higher_peer_balance() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();

        let claim_amount = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;
        // First, advance local pool one claim ahead.
        assert_eq!(node.try_airdrop_claim(), ClaimOutcome::Granted);
        let after_claim = node.airdrop_pool().balance();

        // Peer claims a HIGHER balance (impossible — pool is monotonic-down).
        let stale = GossipMessage::PoolSync {
            pool: PoolKind::Airdrop,
            balance: after_claim + claim_amount, // higher than ours
            total_claims: 0,
            // KI#191 — coherent: zero claims means zero paid out, and this
            // balance IS the pool's opening. The snapshot is internally sound;
            // what makes it wrong is that it is STALE relative to ours, which is
            // the higher-balance rule this test exercises, not conservation.
            paid_out: 0,
            topped_up: 0,
            tick: 100,
            sender_node_id: [0u8; 32],
            sender_sig: Vec::new(),
        };
        let action = node.handle_gossip(&stale, crate::types::test_legs::NOW_SECS);
        // A "higher peer balance" = the peer is behind. Min-wins drops it with
        // NO accusation (Mac's review §2.6). ~~Phase B promoted it to
        // PoolViolationDetected~~ — superseded; this assertion accepted BOTH
        // outcomes until 2026-09-26, which is why it never caught DevTreasury
        // still accusing lagging peers. The local balance must NOT change.
        assert!(
            matches!(action, GossipAction::Duplicate),
            "stale/higher-balance PoolSync must be IGNORED (Duplicate), never an accusation; got {:?}",
            action,
        );
        assert_eq!(
            node.airdrop_pool().balance(), after_claim,
            "local balance unchanged by rejected stale gossip"
        );
    }

    /// Symmetric to `pool_sync_rejects_higher_peer_balance` for the
    /// DevTreasury pool — confirms dev pool follows the same rule as
    /// airdrop.
    #[test]
    fn pool_sync_dev_treasury_rejects_higher_peer_balance() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();

        let claim_amount = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;
        assert_eq!(node.try_dev_treasury_claim(), ClaimOutcome::Granted);
        let after_claim = node.dev_treasury_pool().balance();

        let stale = GossipMessage::PoolSync {
            pool: PoolKind::DevTreasury,
            balance: after_claim + claim_amount,
            total_claims: 0,
            paid_out: 0,
            topped_up: 0,
            tick: 100,
            sender_node_id: [0u8; 32],
            sender_sig: Vec::new(),
        };
        let action = node.handle_gossip(&stale, crate::types::test_legs::NOW_SECS);
        // EXACTLY Duplicate. This assertion used to accept `PoolViolationDetected`
        // too — i.e. it passed whether or not the lagging peer was ACCUSED, so it
        // could not see that DevTreasury accused every lagging peer (live
        // 2026-09-26, [POOL-RECONCILE-INVARIANT]). A lagging peer is ignored.
        assert!(
            matches!(action, GossipAction::Duplicate),
            "stale dev-treasury PoolSync must be IGNORED (Duplicate), never an accusation; got {:?}",
            action,
        );
        assert_eq!(node.dev_treasury_pool().balance(), after_claim);
    }

    // ── Phase B Layer 4 Quarantine consensus tests ─────────────────────
    //
    // Each test maps to a scenario in §5.6.7 of the design doc.
    // The dual-uniqueness rule (3 distinct origins AND 3 distinct
    // intermediates within 10 ticks) is what makes the consensus
    // resistant to single-attacker forging.

    fn nid(b: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    /// A1: Single attacker M sends 3 alerts with fake origins {B,D,E},
    /// all routed through M. Each has intermediate=M.
    /// Expected: 3 distinct origins but only 1 unique intermediate →
    /// dual-uniqueness gate NOT satisfied → no quarantine.

    /// G4 — the attack the A1 test never modelled.
    ///
    /// `quarantine_a1_single_attacker_fake_origins_blocked` holds
    /// `intermediate = m` constant: it models an attacker that reports ITSELF
    /// honestly, which the spec guarantees only because §5.6.4 step 1 pins
    /// intermediate to an NBC-bound TCP identity. That identity was never
    /// built, so nothing stopped one attacker from writing three DIFFERENT
    /// intermediates — satisfying dual-uniqueness alone and getting any honest
    /// node dropped from every peer's gossip fan-out.
    #[test]
    fn g4_single_attacker_forging_intermediates_cannot_quarantine() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let accused = nid(0xCC);
        // ONE attacker, three fabricated (origin, intermediate) pairs.
        for (i, (o, m)) in [(0x01, 0xD1), (0x02, 0xD2), (0x03, 0xD3)].iter().enumerate() {
            q.record_alert(&me, accused, crate::types::PoolKind::Airdrop,
                nid(*o), nid(*m), 1000 + i as u64, 3, /* identity_verified */ false);
        }
        assert!(!q.is_quarantined(&accused, 1100),
            "G4: an unverified intermediate is attacker-chosen — one node must \
             NOT be able to satisfy dual-uniqueness and partition the accused");
        assert_eq!(q.withheld_activations(), 1,
            "the withheld quorum must be COUNTED — a silent withhold reads \
             identically to 'no attack happened'");
    }

    /// Positive control: the SAME pattern with a proven identity DOES
    /// quarantine. Without this, the test above passes against a
    /// `record_alert` that never quarantines anything.
    #[test]
    fn g4_positive_control_verified_identity_still_quarantines() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let accused = nid(0xCC);
        for (i, (o, m)) in [(0x01, 0xD1), (0x02, 0xD2), (0x03, 0xD3)].iter().enumerate() {
            q.record_alert(&me, accused, crate::types::PoolKind::Airdrop,
                nid(*o), nid(*m), 1000 + i as u64, 3, /* identity_verified */ true);
        }
        assert!(q.is_quarantined(&accused, 1100),
            "3 distinct origins AND 3 distinct PROVEN intermediates is the real \
             §5.6.5 quorum and must still activate");
        assert_eq!(q.withheld_activations(), 0, "nothing was withheld here");
    }

    #[test]
    fn quarantine_a1_single_attacker_fake_origins_blocked() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let accused = nid(0xCC);
        let m = nid(0xBB);
        // M emits 3 alerts with origins=B,D,E all coming via M
        let r1 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x01), m, 1000, 3, true);
        let r2 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x02), m, 1001, 3, true);
        let r3 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x03), m, 1002, 3, true);
        // All 3 should record (different origins) but not trigger quarantine
        assert!(matches!(r1, AlertRecordOutcome::Recorded), "got {:?}", r1);
        assert!(matches!(r2, AlertRecordOutcome::Recorded), "got {:?}", r2);
        assert!(matches!(r3, AlertRecordOutcome::Recorded), "got {:?}", r3);
        assert!(!q.is_quarantined(&accused, 1100),
            "A1: single intermediate must not trigger quarantine");
    }

    /// A2: Cascade — M's alert reaches receiver via 3 honest forwarders
    /// Q, R, S. All have same origin=M but different intermediates.
    /// Expected: dedup on (accused, origin) catches duplicates → only
    /// 1 origin recorded → no quarantine.
    #[test]
    fn quarantine_a2_cascade_single_origin_blocked() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let accused = nid(0xCC);
        let m = nid(0xBB); // original origin
        // 3 forwarders Q, R, S all forwarding M's alert
        let r1 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, m, nid(0xD1), 1000, 3, true); // via Q
        let r2 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, m, nid(0xD2), 1001, 3, true); // via R
        let r3 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, m, nid(0xD3), 1002, 3, true); // via S
        assert!(matches!(r1, AlertRecordOutcome::Recorded), "got {:?}", r1);
        // Subsequent forwards with same origin are dedup'd
        assert!(matches!(r2, AlertRecordOutcome::Duplicate), "got {:?}", r2);
        assert!(matches!(r3, AlertRecordOutcome::Duplicate), "got {:?}", r3);
        assert!(!q.is_quarantined(&accused, 1100),
            "A2: single-origin cascade must not trigger quarantine");
    }

    /// A3/A4: Replay — same (accused, origin) re-emitted later.
    /// Expected: dedup catches it.
    #[test]
    fn quarantine_a3_a4_replay_blocked() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let accused = nid(0xCC);
        let origin = nid(0xBB);
        let r1 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, origin, nid(0xD1), 1000, 3, true);
        let r2 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, origin, nid(0xD2), 1005, 3, true); // replay
        assert!(matches!(r1, AlertRecordOutcome::Recorded));
        assert!(matches!(r2, AlertRecordOutcome::Duplicate),
            "A3/A4: replay must dedup on (accused, origin)");
    }

    /// Layer 1 probation: enter, then sweep before countdown → still
    /// probated, no escalation. Sweep after countdown → escalated to
    /// quarantine via the proof-shaped path (active map populated).
    #[test]
    fn probation_countdown_expires_to_quarantine() {
        let mut q = QuarantineState::new();
        let peer = nid(0xAB);
        q.enter_probation(peer, 1000, crate::judoon::ProofKind::BalanceExceedsInitial);
        assert!(q.is_probated(&peer));

        // Sweep BEFORE countdown elapses → still probated, no quarantine.
        // PROBATION_COUNTDOWN_TICKS=10, TICK_INTERVAL_SECS=5 → 50s window.
        let escalated = q.sweep_probation(1000 + 25);  // 25s elapsed
        assert_eq!(escalated.len(), 0);
        assert!(q.is_probated(&peer));
        assert_eq!(q.active_count(), 0);

        // Sweep AFTER countdown → escalated to quarantine.
        let escalated = q.sweep_probation(1000 + 60);  // 60s elapsed, > 50s
        assert_eq!(escalated.len(), 1);
        assert_eq!(escalated[0].0, peer);
        assert!(!q.is_probated(&peer));         // removed from probation
        assert!(q.is_quarantined(&peer, 1000 + 60));  // moved to active
    }

    /// Layer 1 probation: clear_probation removes the entry. Used when
    /// a subsequent PoolSync passes structural checks (recovery path).
    #[test]
    fn probation_clear_on_recovery() {
        let mut q = QuarantineState::new();
        let peer = nid(0xCD);
        q.enter_probation(peer, 1000, crate::judoon::ProofKind::IntraSnapshotInconsistent);
        assert!(q.is_probated(&peer));

        let entry = q.clear_probation(&peer);
        assert!(entry.is_some());
        assert!(!q.is_probated(&peer));

        // Subsequent sweep with countdown expired produces no
        // escalation — entry was cleared, peer recovered.
        let escalated = q.sweep_probation(1000 + 100);
        assert_eq!(escalated.len(), 0);
    }

    /// Pending bucket re-keyed to (accused, pool_kind): alerts about
    /// the same accused across different pools accumulate
    /// independently. K=3 threshold met in Airdrop alone fires
    /// quarantine; DevTreasury entries in parallel don't dilute it.
    #[test]
    fn pending_bucket_separates_by_pool_kind() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let accused = nid(0xCC);
        // Three Airdrop alerts (distinct origins + intermediates) →
        // K=3 met → quarantine fires.
        let _ = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0xB1), nid(0xB1), 1000, 3, true);
        let _ = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0xB2), nid(0xB2), 1001, 3, true);
        let r = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0xB3), nid(0xB3), 1002, 3, true);
        assert!(matches!(r, AlertRecordOutcome::QuarantineActivated { .. }));
    }

    /// A8: 3+ colluding attackers — each real NBC, real intermediate.
    /// Expected: dual-uniqueness satisfied → quarantine fires.
    /// This is the documented residual risk (3-NBC compromise).
    #[test]
    fn quarantine_a8_three_distinct_attackers_succeed() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let accused = nid(0xCC);
        // 3 colluding attackers, each origin AND intermediate distinct
        let r1 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x01), nid(0x01), 1000, 3, true);
        let r2 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x02), nid(0x02), 1001, 3, true);
        let r3 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x03), nid(0x03), 1002, 3, true);
        assert!(matches!(r1, AlertRecordOutcome::Recorded));
        assert!(matches!(r2, AlertRecordOutcome::Recorded));
        match r3 {
            AlertRecordOutcome::QuarantineActivated { accused: a, until_tick } => {
                assert_eq!(a, accused);
                assert!(until_tick > 1002, "until_tick must be in future");
            }
            other => panic!("expected QuarantineActivated, got {:?}", other),
        }
        // Probe inside the active TTL — use a tick guaranteed to be
        // less than `current + QUARANTINE_DURATION_TICKS *
        // TICK_INTERVAL_SECS` regardless of constant tuning.
        assert!(q.is_quarantined(&accused, 1003),
            "A8: quarantine must be active immediately after threshold met");
    }

    /// Self-origin rejection: a Nabla cannot alert about itself as origin.
    #[test]
    fn quarantine_self_origin_rejected() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let accused = nid(0xCC);
        let r = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, me, me, 1000, 3, true);
        assert!(matches!(r, AlertRecordOutcome::SelfOrigin));
    }

    /// Self-accused: don't propagate accusations against ourselves.
    #[test]
    fn quarantine_self_accused_recorded_not_propagated() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let r = q.record_alert(&me, me, crate::types::PoolKind::Airdrop, nid(0xBB), nid(0xBB), 1000, 3, true);
        assert!(matches!(r, AlertRecordOutcome::SelfAccused));
    }

    /// Quarantine expires after the configured TTL.
    #[test]
    fn quarantine_expires_after_ttl() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let accused = nid(0xCC);
        // Trigger quarantine with 3 attackers
        q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x01), nid(0x01), 1000, 3, true);
        q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x02), nid(0x02), 1000, 3, true);
        q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x03), nid(0x03), 1000, 3, true);
        // Inside the active TTL: still quarantined
        assert!(q.is_quarantined(&accused, 1001),
            "quarantine active immediately after threshold met");
        // Quarantine TTL = QUARANTINE_DURATION_TICKS * TICK_INTERVAL_SECS
        let ttl_secs = crate::constants::QUARANTINE_DURATION_TICKS
            * crate::constants::TICK_INTERVAL_SECS;
        // Right at expiry tick: not quarantined anymore
        assert!(!q.is_quarantined(&accused, 1000 + ttl_secs),
            "quarantine expires when current_tick >= until_tick");
    }

    /// Pending alerts older than the 10-tick window are swept.
    #[test]
    fn quarantine_pending_swept_after_window() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let accused = nid(0xCC);
        // 2 alerts within window — not enough for quarantine
        q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x01), nid(0x01), 1000, 3, true);
        q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x02), nid(0x02), 1000, 3, true);
        assert_eq!(q.pending_count(), 1, "1 bucket for accused");
        // Sweep at well past the window — bucket should drop
        let window_secs = crate::constants::ALERT_CONSENSUS_WINDOW_TICKS
            * crate::constants::TICK_INTERVAL_SECS;
        q.sweep(1000 + window_secs + 1);
        assert_eq!(q.pending_count(), 0, "stale pending bucket swept");
    }

    // (ForkSettlement §9r-E4, 2026-10-02: the §32 ghost-audit G1 tests of
    // `handle_fork_evidence` / `check_merge_quarantine` — taint-and-restore by
    // the quarantine timer — were deleted WITH that machinery: a downstream hold
    // is ATRAXI A5 (`provenance.rs`), proven in `fork_detection_mesh::e4_*`.)

    /// KI#84 conservation guard: a claim (MINUS) that would withdraw more than
    /// was ever tranched (Σminus > Σplus) MUST be refused, NOT stored, and
    /// counted. Proves the guard can fire (RULE 3).
    #[test]
    fn fob_conservation_guard_refuses_over_withdrawal() {
        let mut node = NablaNode::new();
        let vid = [0x11u8; 32];
        // Tranche 100 into the pool (PLUS).
        assert!(node.fob_apply_tranche_epoch(1, vid, false, 100));
        assert_eq!(node.fob_pool_balance(&vid, false), 100);

        // A legit claim sweeping exactly 100 (MINUS) — accepted, pool → 0.
        assert!(node.fob_record_claim([0xA1; 32], vid, false, 100));
        assert_eq!(node.fob_pool_balance(&vid, false), 0);
        assert_eq!(node.fob_conservation_rejects(), 0);

        // A SECOND claim of 100 would make Σminus (200) > Σplus (100) — an
        // atom-creation attempt. REFUSED, not stored, counted.
        assert!(!node.fob_record_claim([0xB2; 32], vid, false, 100));
        assert_eq!(node.fob_conservation_rejects(), 1);
        assert!(node.fob_claim_record(&[0xB2; 32]).is_none(),
            "the over-withdrawing fact must NOT be stored");
        assert_eq!(node.fob_pool_balance(&vid, false), 0,
            "the pool is unchanged — no phantom atoms");

        // Same guard on the AE-sync path: a forged MINUS from a peer is ignored.
        let forged_minus = vec![([0xC3u8; 32], (vid, false, 500u64))];
        assert_eq!(node.fob_adopt_ledgers(&[], &forged_minus), 0,
            "AE must ignore the over-withdrawing forged fact");
        assert_eq!(node.fob_conservation_rejects(), 2);
    }
    // ── Per-pool JUDOON class constants (2026-09-02) ─────────────────────

    /// THE REGRESSION: an HONEST FoundationBootstrap PoolSync must not read as
    /// a structural violation.
    ///
    /// `AirdropPool` backs three pools. Before this fix its `DrainOnlyPool`
    /// impl answered with the airdrop's constants for all of them, so a node
    /// holding the true 2,500,000 AXC foundation budget gossiped a balance that
    /// every peer measured against the airdrop's 600,000 and judged
    /// `BalanceExceedsInitial` — a proof kind whose whole meaning is "no honest
    /// Nabla, however stale, can emit this". Honest nodes accusing each other,
    /// on a pool that is already gossiped today (`nabla_node.rs` fans out
    /// Bootstrap + FoundationBootstrap on every genesis-claim register).
    ///
    /// MUTATION-TESTED: restore either hardcoded constant in the trait impl and
    /// this goes red.
    #[test]
    fn honest_subsidy_pool_sync_is_not_a_structural_violation() {
        use crate::judoon::{structural_violation, DrainOnlyPool};

        let foundation = AirdropPool::new(crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS)
            .with_class_constants(
                crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS,
                axiom_core_logic::types::TIER2_CLAIM_ATOMS,
            );

        // The pool answers for ITSELF, not for the airdrop.
        assert_eq!(foundation.initial_atoms(),
            crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS);
        assert_eq!(foundation.claim_amount(), axiom_core_logic::types::TIER2_CLAIM_ATOMS);
        // Until 2026-09-13 the Foundation budget (2,525,000) EXCEEDED the airdrop's,
        // which is how borrowing the airdrop's constant produced a false accusation.
        // The ruled budget (5 x 6,060) is smaller — what matters is that the two
        // yardsticks DIFFER, so borrowing one for the other is always wrong.
        assert_ne!(foundation.initial_atoms(), crate::constants::AIRDROP_POOL_INITIAL_ATOMS,
            "the foundation pool must answer with its OWN budget, never the airdrop's");

        // A full, honest pool gossiped by a peer: no violation.
        let full = crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS;
        // KI#191 — a full pool has paid out nothing: full + 0 == full + 0.
        assert_eq!(structural_violation(full, 0, 0, &foundation), None,
            "an honest FULL foundation pool must not be a structural violation");

        // One honest grant: balance drops by the tier-2 floor, claims 0 -> 1.
        // ATOMS — subtracting the bare AXC constant left the balance barely
        // changed against claims=1, and the conservation check correctly
        // flagged IntraSnapshotInconsistent. The fixture was wrong, not the gate.
        let after_one = full - axiom_core_logic::types::TIER2_CLAIM_ATOMS;
        // KI#191 — Σminus is the ATOMS granted, so the identity closes exactly:
        // (full − TIER2) + TIER2 == full.
        assert_eq!(structural_violation(after_one, 1,
                   axiom_core_logic::types::TIER2_CLAIM_ATOMS, &foundation), None,
            "one honest Foundation grant must not read as MagnitudeBlatant");

        // And the check still BITES: more atoms than the pool ever held.
        assert!(structural_violation(full + 1, 0, 0, &foundation).is_some(),
            "the gate must still catch a genuinely impossible balance");
    }

    /// The airdrop pool's own answers are unchanged by the refactor — a fix
    /// that quietly moved the airdrop's yardstick would be worse than the bug.
    #[test]
    fn airdrop_pool_class_constants_are_unchanged() {
        use crate::judoon::DrainOnlyPool;
        let airdrop = AirdropPool::new(crate::constants::AIRDROP_POOL_INITIAL_ATOMS);
        assert_eq!(airdrop.initial_atoms(), crate::constants::AIRDROP_POOL_INITIAL_ATOMS);
        assert_eq!(airdrop.claim_amount(), axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        // `new(0)` fixtures (~80 call sites) keep the airdrop yardstick too.
        let fixture = AirdropPool::new(0);
        assert_eq!(fixture.initial_atoms(), crate::constants::AIRDROP_POOL_INITIAL_ATOMS);
    }

    /// PIN: the declared `claim_amount` must equal the amount the grant path
    /// actually debits. These are stated in two places — construction and
    /// `try_validator_join_claim` — and JUDOON's conservation law is only
    /// meaningful while they agree.
    #[test]
    fn subsidy_class_constants_match_the_amounts_actually_claimed() {
        use crate::judoon::DrainOnlyPool;
        let mut node = NablaNode::new();

        node.bootstrap_pool = AirdropPool::new(crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS)
            .with_class_constants(
                crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS,
                axiom_core_logic::types::TIER3_CLAIM_ATOMS,
            );
        let declared = node.bootstrap_pool.claim_amount();
        let before = node.bootstrap_pool.balance();
        assert!(matches!(node.try_validator_join_claim(3), ClaimOutcome::Granted));
        let debited = before - node.bootstrap_pool.balance();
        assert_eq!(debited, declared,
            "tier-3 grant debited {debited} but the pool declares {declared} per claim — \
             JUDOON would be policing a pool that is not the one draining");
    }
}

// The KI#169/KI#170 registry tests moved to `vbc_directory::tests` with the
// ForkSettlement wave-4a rewrite: the old `adopt_is_a_set_union_and_idempotent`
// pinned the UNVERIFIED union that was KI#223.

/// ForkSettlement wave 3 S5–S8 — the record hooks at the door / flood / AE,
/// `ForkBan` adoption, the attestation vouch. Real ed25519 keypairs, every
/// leg built by the ONE test builder `types::test_legs::genuine_send_leg`.
/// Each test names the mutation that must turn it RED.
#[cfg(test)]
pub(crate) mod wave3_hook_tests {
    use super::*;
    use crate::types::test_legs::{self, NOW_SECS};

    const RECV_P: &str = "p@axiom.internal/0123456789";
    const RECV_Q: &str = "q@axiom.internal/0123456789";
    const RECV_R: &str = "r@axiom.internal/0123456789";

    fn node() -> NablaNode {
        let mut n = NablaNode::new();
        n.admit_test_validators(); // KI#224: the door/flood/AE read the directory
        n
    }

    /// X → Y (seq 1), then the leg under test consumes Y.
    fn chain_leg(seed: u8, consumed: StateId, seq: u64, recv: &str, amount: u64, nonce: u64) -> ForkLeg {
        test_legs::genuine_send_leg(&test_legs::wallet(seed), consumed, seq, recv, amount, nonce, 3)
    }

    fn register_leg(node: &mut NablaNode, leg: &ForkLeg, now: u64) -> Result<RegisterResult, NablaError> {
        let (reg, deed) = test_legs::registration_of(leg);
        node.register(&reg, &deed, now)
    }

    fn pk_of(seed: u8) -> [u8; 32] {
        test_legs::wallet(seed).verifying_key().to_bytes()
    }

    /// Test 14 — [R24] AT THE DOOR (the S1–S4 worker could only test it at
    /// record level). The node holds A at Y (from X → Y); A registers Y → Z.
    /// The record is made BEFORE `put_with_proof` consumes Y, so it is born
    /// UNCONTESTED, `origin_vouch` vouches once listening, and readiness
    /// (`cheque_sender_registered`) answers true again after a register.
    /// MUTATION: move the 5b‴ hook below the `put_with_proof` in
    /// `process_registration` ⇒ the record sees its own consumption of Y
    /// ⇒ born contested ⇒ RED.
    #[test]
    fn door_honest_register_is_not_contested_r24() {
        let mut n = node();
        n.admit_test_validators(); // W7c: X→Y must PRODUCE Y (R42) for Y→Z to be grounded
        let x_to_y = chain_leg(0xA1, test_legs::opening(&test_legs::wallet(0xA1)), 1, RECV_P, 100, 1);
        register_leg(&mut n, &x_to_y, NOW_SECS).expect("X→Y registers");
        let y_to_z = chain_leg(0xA1, x_to_y.new_state, 2, RECV_Q, 100, 2);
        assert!(!n.smt().cheque_sender_registered(&y_to_z.tx_hash), "not yet registered");
        register_leg(&mut n, &y_to_z, NOW_SECS + 5).expect("Y→Z registers");
        assert!(n.smt().is_state_consumed(&x_to_y.new_state), "fixture: the register consumed Y");
        let rec = n.smt().vouch_record(&y_to_z.tx_hash).expect("the door recorded the leg");
        assert!(!rec.contested, "R24: an honest register is NOT born contested");
        assert_eq!(rec.first_seen_secs, NOW_SECS + 5, "first_seen = the now_secs the door was handed");
        assert!(n.smt().cheque_sender_registered(&y_to_z.tx_hash), "readiness true again after a register");
        let v = n.origin_vouch(&y_to_z.tx_hash, Some(NOW_SECS));
        assert_eq!(v.origin, y_to_z.origin_record(), "vouches the leg's own preimage");
        assert_eq!(v.registered_at_secs, NOW_SECS + 5);
        assert_eq!(n.origin_status(None, 0).origin_records, 2);
    }

    /// Test 15 — [R16/R30]: an A12-refused leg at a SIBLING-LESS node whose
    /// parent is consumed. This node never held any record under (A, Y); it
    /// holds only a "Y consumed" mark (another wallet's head advanced past Y
    /// here — the second-hand / merged-mark shape). A registers Y → Z: the door
    /// refuses it (A12 `DoubleSpendDetected`), yet RECORDS the leg — born
    /// CONTESTED — and the signer reports None for it forever.
    /// MUTATION: skip record creation on refused legs (hook after 6b) ⇒ no
    /// record ⇒ RED; drop the `is_state_consumed` term ⇒ uncontested ⇒ RED.
    #[test]
    fn door_a12_refused_siblingless_leg_is_contested_and_never_vouches() {
        let mut n = node();
        let y: StateId = [0x77; 32];
        // Another wallet's head at Y, then advanced: Y is in THIS node's consumed set.
        let mut other = test_legs::entry_of(&chain_leg(0xB9, [0x10; 32], 1, RECV_P, 1, 1), 5);
        other.current_state = y;
        n.smt_mut().put(&other);
        other.current_state = [0x78; 32];
        other.wallet_seq = 2;
        n.smt_mut().put(&other);
        assert!(n.smt().is_state_consumed(&y), "fixture: Y consumed, no record under (A, Y)");

        let leg = chain_leg(0xA2, y, 1, RECV_Q, 100, 1);
        let r = register_leg(&mut n, &leg, NOW_SECS);
        assert!(matches!(r, Err(NablaError::DoubleSpendDetected)), "A12 refuses: {:?}", r.as_ref().err());
        let rec = n.smt().vouch_record(&leg.tx_hash).expect("R30: the refused leg IS recorded");
        assert!(rec.contested, "R16: parent consumed, no sibling ⇒ born contested");
        assert_eq!(n.origin_vouch(&leg.tx_hash, Some(0)), OriginVouch::NONE, "never vouches");
        assert_eq!(n.origin_vouch(&leg.tx_hash, Some(NOW_SECS + 10_000)), OriginVouch::NONE);
        assert!(!n.is_banned(&pk_of(0xA2)), "contested ≠ claim: no ban (R23)");
    }

    /// Test 16 — the door holds (A, Y) = tx_a and head Z1; tx_b Y → Z2
    /// (a different receiver) is a StateMismatch at 6a — but the record hook
    /// runs FIRST: the claim opens, A is banned, `WalletBanned` is returned,
    /// the claim is WAL-logged + queued for the `ForkBan` flood, and neither
    /// leg vouches. MUTATION: place the hook after the 6a/6b refusals ⇒ tx_b is
    /// refused StateMismatch with nothing recorded ⇒ RED.
    #[test]
    fn door_refused_second_leg_opens_claim_and_bans_registrant() {
        let mut n = node();
        let y = test_legs::opening(&test_legs::wallet(0xA3)); // W7c: grounded, so NONE is the fork's doing
        let tx_a = chain_leg(0xA3, y, 1, RECV_P, 100, 1);
        let tx_b = chain_leg(0xA3, y, 1, RECV_Q, 100, 2);
        register_leg(&mut n, &tx_a, NOW_SECS).expect("tx_a registers");
        let r = register_leg(&mut n, &tx_b, NOW_SECS + 1);
        assert!(matches!(r, Err(NablaError::WalletBanned)), "got {:?}", r.as_ref().err());
        assert!(n.is_banned(&pk_of(0xA3)));
        assert!(matches!(n.bans().get(&pk_of(0xA3)).unwrap().evidence, BanEvidence::Fork(_)));
        let floods = n.take_pending_fork_floods();
        assert_eq!(floods.len(), 1, "the claim is queued for the ForkBan flood (Err path drained)");
        assert_eq!(n.bans().origin_fork_claims_detected(), 1);
        for tx in [&tx_a.tx_hash, &tx_b.tx_hash] {
            assert_eq!(n.origin_vouch(tx, Some(NOW_SECS)), OriginVouch::HELD, "§9p: a fork leg is signed HELD");
        }
        assert_eq!(n.smt().get(&pk_of(0xA3)).unwrap().status, WalletStatus::Banned, "head flipped");
    }

    /// Design pass-2 seq 2 AT THE DOOR — the late leg after A advanced past the
    /// parent: tx_a Y → Z1, then dust Z1 → Z1′ (seq 2); tx_b Y → Z2 (seq 1)
    /// reaches this node's door. The door refuses it (`seq_newer` false →
    /// StateMismatch) — and refusing used to be ALL it did. Now the leg is
    /// recorded first, meets tx_a's record under (A, Y), and A is banned.
    /// MUTATION: key the detector on the head (skip the hook when
    /// `reg.old_state != head`) ⇒ RED.
    #[test]
    fn regression_late_leg_after_advance_at_the_door() {
        let mut n = node();
        let y = test_legs::opening(&test_legs::wallet(0xA4));
        let tx_a = chain_leg(0xA4, y, 1, RECV_P, 100, 1);
        register_leg(&mut n, &tx_a, NOW_SECS).expect("tx_a");
        assert!(n.origin_vouch(&tx_a.tx_hash, Some(NOW_SECS)).origin.is_some(), "control: P's origin vouched before tx_b");
        let dust = chain_leg(0xA4, tx_a.new_state, 2, RECV_R, 1, 3);
        register_leg(&mut n, &dust, NOW_SECS + 1).expect("dust advance");
        let tx_b = chain_leg(0xA4, y, 1, RECV_Q, 100, 2);
        let r = register_leg(&mut n, &tx_b, NOW_SECS + 2);
        assert!(matches!(r, Err(NablaError::WalletBanned)), "got {:?}", r.as_ref().err());
        assert!(n.is_banned(&pk_of(0xA4)));
        assert_eq!(n.origin_vouch(&tx_a.tx_hash, Some(NOW_SECS)), OriginVouch::HELD, "P's origin revoked (signed HELD, §9p)");
    }

    /// Test 27 — HIGH-1 / [R5]: the receiver's redeem-finalize register is
    /// keyed on the CHEQUE txid and carries a `LegPreimage::Redeem(..)` leg
    /// (verified at the door since W7a); it creates
    /// NO record — neither for the cheque's txid (the sender's origin) nor
    /// anything else — so P's own redeem can never make a node vouch for A.
    /// MUTATION: `cheque_sender_registered` answering from the SMT heads'
    /// `tx_hash` (the pre-R5 `put`-fed membership) ⇒ RED.
    #[test]
    fn redeem_finalize_register_creates_no_sender_record() {
        let mut n = node();
        let cheque = chain_leg(0xA5, [0x35; 32], 1, RECV_P, 100, 1); // A's send — NOT registered here
        let p_sk = test_legs::wallet(0xA6);
        let p_leg = test_legs::genuine_send_leg(&p_sk, [0x36; 32], 1, RECV_Q, 100, 1, 3);
        // W7a: a GENUINE redeem leg (the door verifies it since W7a).
        let (reg, deed) = test_legs::redeem_registration(&p_sk, &p_leg, &test_legs::origin_of(&cheque));
        n.register(&reg, &deed, NOW_SECS).expect("the receiver's register is accepted");
        assert_eq!(n.smt().origin_len(), 0, "a Redeem leg records nothing");
        assert!(!n.smt().cheque_sender_registered(&cheque.tx_hash), "the cheque's origin is NOT vouchable here");
        assert_eq!(n.origin_vouch(&cheque.tx_hash, Some(0)), OriginVouch::NONE);
        assert_eq!(n.bans().origin_leg_unrecordable(), 0, "a Redeem leg is expected, not counted");
    }

    /// Fork Settlement W7a/W7b (spec R52c) — the door's REDEEM arm. A genuine
    /// redeem leg (the preimage recomputes, through Core's ONE verifier
    /// `redeem_preimage_matches`, to the k-signed commitment and names this
    /// register's cheque txid / wallet / states) is accepted; each TAMPERED
    /// copy — a balance the k never signed, a produced state other than the
    /// register's, another wallet as receiver, another consumed state — is
    /// refused `LegUnverifiable` with its reason, and nothing is stored.
    /// MUTATION: the `Redeem` arm returns `Ok(())` without checking (the
    /// pre-W7a unverified accept) ⇒ every tamper is accepted ⇒ RED.
    ///
    /// KI#241 F-2 (Fable review 2026-10-01, test 2) — the FORGED-PREIMAGE
    /// negative: a leg whose carried cheque origin claims another amount (its
    /// txid no longer reproduces the k-bound cheque txid), or the right
    /// preimage under another epoch, or a `Redeem`-kind origin, is refused
    /// `ChequeOriginMismatch` at the door and nothing is stored.
    /// MUTATION (run 2026-10-01): delete the `cheque_origin_matches` check in
    /// `registration::verify_redeem_leg_preimage` ⇒ the forged origins are
    /// accepted ⇒ RED.
    #[test]
    fn redeem_leg_is_verified_at_the_door_and_a_tampered_one_refused() {
        use crate::registration::LegRefusal as R;
        let p_sk = test_legs::wallet(0xB6);
        let p_leg = test_legs::genuine_send_leg(&p_sk, [0x46; 32], 1, RECV_Q, 100, 1, 3);
        let origin = test_legs::stray_origin_amount([0x47; 32], 100);
        let (reg, deed) = test_legs::redeem_registration(&p_sk, &p_leg, &origin);
        assert_eq!(crate::registration::verify_registered_leg(&reg), Ok(()), "the genuine redeem leg reproduces");
        let tamper = |f: &dyn Fn(&mut axiom_core_logic::types::RedeemPreimage)| {
            let mut t = reg.clone();
            let crate::types::LegPreimage::Redeem { redeem: p, .. } = &mut t.preimage else { unreachable!() };
            f(p);
            t
        };
        let forge = |f: &dyn Fn(&mut axiom_core_logic::types::OriginRecord)| {
            let mut t = reg.clone();
            let crate::types::LegPreimage::Redeem { cheque, .. } = &mut t.preimage else { unreachable!() };
            f(cheque);
            t
        };
        for (what, t) in [
            ("a forged cheque amount (+1)", forge(&|c| c.preimage.amount += 1)),
            ("a forged cheque amount (x1000)", forge(&|c| c.preimage.amount *= 1_000)),
            ("the right preimage under another epoch", forge(&|c| c.epoch += 1)),
            ("a Redeem-kind origin", forge(&|c| c.kind = axiom_core_logic::types::LegKind::Redeem)),
        ] {
            assert_eq!(crate::registration::verify_registered_leg(&t), Err(R::ChequeOriginMismatch), "{what}");
            let mut n = node();
            assert!(matches!(n.register(&t, &deed, NOW_SECS), Err(NablaError::LegUnverifiable(R::ChequeOriginMismatch))),
                "the door refuses a redeem leg carrying {what}");
            assert!(n.smt().get(&t.wallet_id).is_none(), "nothing stored for {what}");
        }
        for (what, t, want) in [
            ("balance the k never signed", tamper(&|p| p.new_balance += 1), R::RedeemPreimageMismatch),
            ("another produced state", tamper(&|p| p.new_state_id = [0x99; 32]), R::NewStateMismatch),
            ("another receiver", tamper(&|p| p.receiver_pk = [0x98; 32]), R::ClientPkMismatch),
            ("another consumed state", tamper(&|p| p.consumed_state_id = [0x97; 32]), R::ConsumedStateMismatch),
            ("another cheque", tamper(&|p| p.cheque_txid = [0x96; 32]), R::TxidMismatch),
        ] {
            assert_eq!(crate::registration::verify_registered_leg(&t), Err(want), "{what}");
            let mut n = node();
            assert!(matches!(n.register(&t, &deed, NOW_SECS), Err(NablaError::LegUnverifiable(r)) if r == want),
                "the door refuses a redeem leg with {what}");
            assert!(n.smt().get(&t.wallet_id).is_none(), "nothing stored for {what}");
        }
        let mut n = node();
        n.register(&reg, &deed, NOW_SECS).expect("the genuine redeem register is accepted");
        assert_eq!(n.smt().origin_len(), 0, "a verified redeem leg still creates NO origin record (R33)");
    }

    /// ForkSettlement §9h [R53] — an attestation signed by an UNHEALTHY node
    /// (its OODS reading below its NBC baseline) carries `oods_healthy = false`
    /// under the node's signature, and Core's `origin_settled_link` REFUSES to
    /// settle on it at the very time it accepts the healthy node's.
    /// MUTATION: `sign_txid_attestation` signing `healthy: true` regardless of
    /// the reading ⇒ the unhealthy attestation settles ⇒ RED.
    #[test]
    fn an_unhealthy_nodes_attestation_does_not_settle_under_core() {
        let dir = tempfile::tempdir().unwrap();
        let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::Ed25519Signer::from_seed(&[0x4F; 32]))).unwrap();
        n.admit_test_validators(); // KI#224: the door/flood/AE read the directory
        let leg = chain_leg(0xAE, test_legs::opening(&test_legs::wallet(0xAE)), 1, RECV_P, 100, 1);
        assert!(n.apply_remote_entry(&test_legs::entry_of(&leg, 9), Some(&leg.seq_proof), NOW_SECS));
        let txid = leg.tx_hash;
        let floor = axiom_core_logic::validation::SCAR_SETTLE_TICKS.to_secs();
        let at = NOW_SECS + floor;
        let healthy = attestation_with_oods(&n, &txid, at, Some(NOW_SECS - 1_000), HEALTHY);
        assert!(axiom_core_logic::fact::origin_settled_link(&healthy, &txid, false), "control: a healthy node's vouch settles");
        let eclipsed = OodsReading { size: 1, healthy: false };
        let unhealthy = attestation_with_oods(&n, &txid, at, Some(NOW_SECS - 1_000), eclipsed);
        assert!(!unhealthy.oods_healthy && unhealthy.oods_size == 1, "the reading rides the attestation");
        assert!(signature_verifies(&unhealthy), "the unhealthy verdict is SIGNED — a relay cannot flip it");
        assert!(unhealthy.origin.is_some(), "the node still vouches its record — the health gate is Core's");
        assert!(!axiom_core_logic::fact::origin_settled_link(&unhealthy, &txid, false),
            "Core refuses to settle on an unhealthy node's vouch");
    }

    /// Test 18 — the AE path records ABOVE the consumed-state drop. The
    /// [R31] fork: equal amount + nonce to two receivers ⇒ ONE new_state Z1,
    /// two txids. The node registers tx_a (Y → Z1) and a dust advance
    /// (Z1 → Z1′), so Z1 is CONSUMED here; tx_b arrives by AE with
    /// current_state Z1 → the consumed drop refuses the head — but the leg is
    /// recorded first and the claim opens. MUTATION: move the AE hook below
    /// the `is_state_consumed(current_state)` drop ⇒ RED.
    #[test]
    fn ae_leg_opens_claim_above_consumed_drop() {
        let mut n = node();
        let y: StateId = [0x37; 32];
        let tx_a = chain_leg(0xA7, y, 1, RECV_P, 100, 7);
        let tx_b = chain_leg(0xA7, y, 1, RECV_Q, 100, 7);
        assert_eq!(tx_a.new_state, tx_b.new_state, "fixture: R31 same new_state");
        assert_ne!(tx_a.tx_hash, tx_b.tx_hash);
        register_leg(&mut n, &tx_a, NOW_SECS).expect("tx_a");
        register_leg(&mut n, &chain_leg(0xA7, tx_a.new_state, 2, RECV_R, 1, 8), NOW_SECS + 1).expect("dust");
        assert!(n.smt().is_state_consumed(&tx_b.new_state), "fixture: Z1 consumed here");
        let adopted = n.apply_remote_entry(&test_legs::entry_of(&tx_b, 9), Some(&tx_b.seq_proof), NOW_SECS + 2);
        assert!(!adopted);
        assert!(n.is_banned(&pk_of(0xA7)), "the AE-carried leg opened the claim");
        assert_eq!(n.take_pending_fork_floods().len(), 1, "drained on the AE path");
    }

    /// Test 21 — a 3-way fork: all three legs under (A, Y) held; ONE
    /// `BannedEntry` pair (ban_fork is write-once); `origin_vouch` returns
    /// None for EVERY leg, including the third, which no ban evidence names.
    /// MUTATION: vouch keyed on "txid named in the ban evidence" (drop the
    /// pk-ban and key-held clauses) ⇒ the third leg vouches ⇒ RED.
    #[test]
    fn three_way_fork_no_leg_vouchable() {
        let mut n = node();
        let y = test_legs::opening(&test_legs::wallet(0xA8));
        let legs: Vec<ForkLeg> = [RECV_P, RECV_Q, RECV_R].iter().enumerate()
            .map(|(i, r)| chain_leg(0xA8, y, 1, r, 100, i as u64 + 1))
            .collect();
        // All three recorded (e.g. restored / adopted before any verdict).
        for l in &legs {
            let v = crate::ban::verify_fork_leg(l.clone()).unwrap();
            n.smt_mut().record_verified_leg(v, NOW_SECS);
        }
        let claim = ForkClaim { a: legs[0].clone(), b: legs[1].clone() };
        let act = n.handle_gossip(&GossipMessage::ForkBan { claim }, NOW_SECS);
        assert!(matches!(act, GossipAction::Forward(_)));
        match &n.bans().get(&pk_of(0xA8)).unwrap().evidence {
            BanEvidence::Fork(c) => assert!(c.a.tx_hash != legs[2].tx_hash && c.b.tx_hash != legs[2].tx_hash,
                "the third leg is named in no ban evidence"),
            other => panic!("{other:?}"),
        }
        for l in &legs {
            assert_eq!(n.origin_vouch(&l.tx_hash, Some(NOW_SECS)), OriginVouch::HELD, "§9p: every leg signed HELD");
        }
    }

    /// Test 28 — each `origin_vouch` condition, dropped in turn, must be the
    /// one that says None: not listening; no record; contested; key held with
    /// NO ban (two records, no verdict yet). And (W7c, §9k ruling 3) a BANNED
    /// registrant whose key is NOT forked here still vouches — the ban table
    /// is no longer read (clause 4 removed; `w7c_tests::
    /// pre_fork_payment_vouched_after_ban` is the scenario).
    /// MUTATION: delete any single condition ⇒ its case goes RED (contested:
    /// `judge_send`'s contested arm — the key-held arm no longer covers it,
    /// since a contested sibling-less key holds ONE leg); restore clause 4 ⇒
    /// the banned case goes RED.
    #[test]
    fn origin_vouch_none_when_contested_held_or_not_listening() {
        let y = test_legs::opening(&test_legs::wallet(0xA9));
        let leg = chain_leg(0xA9, y, 1, RECV_P, 100, 1);
        let rec = |n: &mut NablaNode, l: &ForkLeg| {
            let v = crate::ban::verify_fork_leg(l.clone()).unwrap();
            let o = n.smt_mut().record_verified_leg(v, NOW_SECS);
            n.drain_fork_side_effects();
            o
        };
        // Positive control.
        let mut n = node();
        rec(&mut n, &leg);
        assert!(n.origin_vouch(&leg.tx_hash, Some(NOW_SECS)).origin.is_some(), "control vouches");
        // 1. not listening.
        assert_eq!(n.origin_vouch(&leg.tx_hash, None), OriginVouch::NONE, "not listening");
        // 2. no record.
        assert_eq!(n.origin_vouch(&[0xEE; 32], Some(NOW_SECS)), OriginVouch::NONE, "no record");
        // Ruling 3: the registrant banned (any evidence), key NOT forked here ⇒ STILL vouched.
        n.bans_mut().ban_fork(pk_of(0xA9), ForkClaim { a: leg.clone(), b: leg.clone() });
        assert!(n.origin_vouch(&leg.tx_hash, Some(NOW_SECS)).origin.is_some(),
            "a ban alone withholds nothing — only a fork in the records does (ruling 3)");
        // 5. key held, nobody banned.
        let mut n = node();
        rec(&mut n, &leg);
        rec(&mut n, &chain_leg(0xA9, y, 1, RECV_Q, 100, 2));
        assert_eq!(n.origin_vouch(&leg.tx_hash, Some(NOW_SECS)), OriginVouch::HELD, "key held ⇒ signed HELD (§9p)");
        // 3. contested.
        let mut n = node();
        let mut other = test_legs::entry_of(&chain_leg(0xBA, [0x11; 32], 1, RECV_P, 1, 1), 5);
        other.current_state = y;
        n.smt_mut().put(&other);
        other.current_state = [0x3A; 32];
        other.wallet_seq = 2;
        n.smt_mut().put(&other);
        rec(&mut n, &leg);
        assert!(n.smt().vouch_record(&leg.tx_hash).unwrap().contested);
        assert_eq!(n.origin_vouch(&leg.tx_hash, Some(NOW_SECS)), OriginVouch::NONE, "contested ⇒ signed Unknown");
        // §9p: contested AND fork-held (a second leg under the SAME key) ⇒ signed
        // HELD — `judge_send` answers Wait for a contested record before it
        // looks at the key, so only the structural clause in
        // `origin_vouch_inner` says Held here.
        rec(&mut n, &chain_leg(0xA9, y, 1, RECV_Q, 100, 2));
        assert_eq!(n.provenance().judge_send(n.smt(), &leg.tx_hash), crate::provenance::Judgment::Wait,
            "fixture: judge_send alone says Wait (contested first)");
        assert_eq!(n.origin_vouch(&leg.tx_hash, Some(NOW_SECS)), OriginVouch::HELD,
            "contested + fork-held ⇒ signed HELD (§9p)");
        // Counters: every call on this node was counted one way or the other;
        // the Held ones are the §9p subset of the withheld.
        let st = n.origin_status(None, 0);
        assert_eq!(st.origin_attest_vouched + st.origin_attest_withheld, 2);
        assert_eq!(st.origin_attest_held, 1, "the one HELD answer is counted");
    }

    /// ForkSettlement §9p (KI#221 residual 1) — the SIGNED origin status, end
    /// to end through `sign_txid_attestation` (the ONE assembly
    /// `query_txid_core` ships) and Core:
    /// * a GROUNDED origin (opening-state send) signs `Vouched` with its
    ///   origin, and Core settles it at the floor;
    /// * an UNGROUNDED origin (a send from a parent this node never saw
    ///   produced) signs `Unknown`, no origin — Core: consistent, never settles;
    /// * a HELD key (a second leg under the same `(pk, consumed)`) signs
    ///   `Held`, no origin — Core: consistent, never settles, and the status is
    ///   under the signature (relabelled `Unknown` it no longer verifies);
    /// * not listening / no record sign `Unknown`.
    /// MUTATIONS (run): `origin_vouch_inner` maps `Judgment::Held` to
    /// `OriginVouch::NONE` AND drops the structural fork clause ⇒ the held
    /// case signs `Unknown` ⇒ RED; `sign_txid_attestation` signs
    /// `OriginVouchStatus::Unknown` regardless ⇒ the `Vouched` attestation is
    /// malformed / the Held one relabels ⇒ RED.
    #[test]
    fn s9p_signed_origin_status_vouched_held_unknown() {
        use axiom_core_logic::types::OriginVouchStatus as S;
        let dir = tempfile::tempdir().unwrap();
        let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::Ed25519Signer::from_seed(&[0x5A; 32]))).unwrap();
        n.admit_test_validators();
        let floor = axiom_core_logic::validation::SCAR_SETTLE_TICKS.to_secs();
        let boot = Some(NOW_SECS - 1_000);
        let core_ok = |a: &axiom_core_logic::types::NablaTxidAttestation| {
            signature_verifies(a) && axiom_core_logic::fact::txid_attestation_origin_consistent(a)
        };

        // Grounded ⇒ Vouched.
        let y = test_legs::opening(&test_legs::wallet(0xC1));
        let good = chain_leg(0xC1, y, 1, RECV_P, 100, 1);
        register_leg(&mut n, &good, NOW_SECS).expect("grounded send registers");
        let a = attestation(&n, &good.tx_hash, NOW_SECS + floor, boot);
        assert_eq!(a.origin_status, S::Vouched, "a grounded origin signs Vouched");
        assert!(a.origin.is_some() && core_ok(&a));
        assert!(axiom_core_logic::fact::origin_settled_link(&a, &good.tx_hash, false), "Core settles it at the floor");

        // Ungrounded ⇒ Unknown.
        let orphan = chain_leg(0xC2, [0x36; 32], 1, RECV_P, 100, 1);
        let v = crate::ban::verify_fork_leg(orphan.clone()).unwrap();
        n.smt_mut().record_verified_leg(v, NOW_SECS);
        n.drain_fork_side_effects();
        assert_eq!(n.provenance().judge_send(n.smt(), &orphan.tx_hash), crate::provenance::Judgment::Wait,
            "fixture: the input is ungrounded here");
        let u = attestation(&n, &orphan.tx_hash, NOW_SECS + 10 * floor, boot);
        assert_eq!((u.origin_status, u.origin.is_none(), u.sender_registered_at_tick), (S::Unknown, true, 0),
            "an ungrounded origin signs Unknown");
        assert!(core_ok(&u));
        assert!(!axiom_core_logic::fact::origin_settled_link(&u, &orphan.tx_hash, false));

        // Held key ⇒ Held.
        let twin = chain_leg(0xC1, y, 1, RECV_Q, 100, 2);
        let _ = register_leg(&mut n, &twin, NOW_SECS + 1);
        assert!(n.smt().origin_key_is_held(&good.key()), "fixture: the key holds two legs");
        for t in [&good.tx_hash, &twin.tx_hash] {
            let h = attestation(&n, t, NOW_SECS + 10 * floor, boot);
            assert_eq!((h.origin_status, h.origin.is_none()), (S::Held, true), "a fork leg signs Held");
            assert!(core_ok(&h), "a Held attestation is well-formed and genuinely signed");
            assert!(!axiom_core_logic::fact::origin_settled_link(&h, t, false), "Held never settles");
            let mut relabelled = h.clone();
            relabelled.origin_status = S::Unknown;
            assert!(!signature_verifies(&relabelled), "the status is under the signature");
        }

        // Not listening / no record ⇒ Unknown.
        assert_eq!(attestation(&n, &good.tx_hash, NOW_SECS, None).origin_status, S::Unknown, "not listening");
        assert_eq!(attestation(&n, &[0xEE; 32], NOW_SECS, boot).origin_status, S::Unknown, "no record");
    }

    /// Test 28b — [R9]: `registered_at_secs = max(first_seen_secs, boot)`.
    /// A node that recorded the leg at T and (re)booted at T + 500 vouches
    /// `registered_at = T + 500` — one extra settle after a restart. And the
    /// boot floor after a RESTART: the record's `first_seen` survives the
    /// snapshot, the new process's boot floor dominates it.
    /// MUTATION: `registered_at = first_seen` (drop the boot term) ⇒ RED.
    #[test]
    fn origin_vouch_registered_at_is_max_first_seen_boot_and_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let leg = chain_leg(0xAC, test_legs::opening(&test_legs::wallet(0xAC)), 1, RECV_P, 100, 1);
        {
            let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            n.admit_test_validators(); // KI#224: the door/flood/AE read the directory
            assert!(n.apply_remote_entry(&test_legs::entry_of(&leg, 9), Some(&leg.seq_proof), NOW_SECS));
            assert_eq!(n.origin_vouch(&leg.tx_hash, Some(NOW_SECS - 100)).registered_at_secs, NOW_SECS,
                "first_seen dominates an earlier boot");
            assert_eq!(n.origin_vouch(&leg.tx_hash, Some(NOW_SECS + 500)).registered_at_secs, NOW_SECS + 500,
                "boot dominates an earlier first_seen");
            n.take_snapshot().unwrap();
        }
        let n = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert_eq!(n.smt().vouch_record(&leg.tx_hash).unwrap().first_seen_secs, NOW_SECS, "first_seen preserved");
        let reboot = NOW_SECS + 3_600;
        assert_eq!(n.origin_vouch(&leg.tx_hash, Some(reboot)).registered_at_secs, reboot,
            "after a restart the node's boot floor restarts the settle");
    }

    /// Core's view of a signed attestation (the fields `origin_settled_link`
    /// and the payload verifier read).
    /// Also driven by `fork_detection_mesh` (the multi-node gate) — ONE
    /// assembly of Core's view, RULE 1.
    pub(crate) fn attestation(n: &NablaNode, txid: &TxHash, nabla_secs: u64, boot: Option<u64>) -> axiom_core_logic::types::NablaTxidAttestation {
        attestation_with_oods(n, txid, nabla_secs, boot, HEALTHY)
    }

    /// A healthy node's reading (baseline met) — the default for tests that are
    /// not about R53.
    pub(crate) const HEALTHY: OodsReading = OodsReading { size: 10, healthy: true };

    /// [`attestation`] signed with an explicit OODS reading (§9h [R53]).
    pub(crate) fn attestation_with_oods(n: &NablaNode, txid: &TxHash, nabla_secs: u64, boot: Option<u64>, oods: OodsReading) -> axiom_core_logic::types::NablaTxidAttestation {
        let signed = n.sign_txid_attestation(txid, "NOT_REDEEMED", nabla_secs, boot, oods);
        axiom_core_logic::types::NablaTxidAttestation {
            txid: *txid,
            status: "NOT_REDEEMED".into(),
            registered_by: vec![],
            nabla_node_pk: n.signer_pk().try_into().unwrap(),
            nabla_signature: signed.signature,
            nabla_tick: nabla_secs,
            origin: signed.vouch.origin,
            sender_registered_at_tick: signed.vouch.registered_at_secs,
            oods_size: signed.oods.size,
            oods_healthy: signed.oods.healthy,
            origin_status: signed.vouch.status,
            txid_service: "bloom".into(),
            nbc_issuer_pk: vec![],
            nbc_signature: vec![],
            nbc_commitment: vec![],
        }
    }

    /// The attestation's signature verifies over Core's ONE payload builder
    /// (what `fact.rs` / `modes.rs` check before trusting the origin half).
    pub(crate) fn signature_verifies(att: &axiom_core_logic::types::NablaTxidAttestation) -> bool {
        use ed25519_dalek::Verifier;
        let hash = blake3::Hash::from(crate::registration::txid_attest_payload(
            &att.txid, &att.status, att.nabla_tick, att.origin.as_ref(), att.sender_registered_at_tick,
            att.oods_size, att.oods_healthy, att.origin_status,
        ));
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&att.nabla_node_pk).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&att.nabla_signature).unwrap();
        vk.verify(hash.as_bytes(), &sig).is_ok()
    }

    /// Test 29 — END TO END against Core: the attestation this node signs
    /// (`sign_txid_attestation`, the ONE assembly `query_txid_core` ships)
    /// carries a preimage that recomputes to the txid, verifies under the
    /// node key, and is one Core's `fact::origin_settled_link` ACCEPTS at
    /// `registered_at + floor` and REJECTS one second before — for the real
    /// and the dev twin. With the node rebooted after first_seen the floor
    /// runs from the BOOT. A banned registrant ⇒ None/0 ⇒ Core rejects.
    /// MUTATION: `registered_at = first_seen` without boot ⇒ the rebooted case
    /// is accepted early ⇒ RED; sign `origin = None` ⇒ RED.
    #[test]
    fn vouched_attestation_settles_under_core_predicate() {
        let dir = tempfile::tempdir().unwrap();
        let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::Ed25519Signer::from_seed(&[0x4E; 32]))).unwrap();
        n.admit_test_validators(); // KI#224: the door/flood/AE read the directory
        let leg = chain_leg(0xAD, test_legs::opening(&test_legs::wallet(0xAD)), 1, RECV_P, 100, 1);
        assert!(n.apply_remote_entry(&test_legs::entry_of(&leg, 9), Some(&leg.seq_proof), NOW_SECS));
        let txid = leg.tx_hash;
        for is_dev in [false, true] {
            let floor = axiom_core_logic::types::dev_or_real(
                is_dev,
                axiom_core_logic::validation::SCAR_SETTLE_TICKS_DEV,
                axiom_core_logic::validation::SCAR_SETTLE_TICKS,
            ).to_secs();
            // Listening since before first_seen: the floor runs from first_seen.
            let settled = attestation(&n, &txid, NOW_SECS + floor, Some(NOW_SECS - 1_000));
            assert!(signature_verifies(&settled), "the node's signature covers origin + registered_at");
            let o = settled.origin.as_ref().expect("vouched");
            assert_eq!(o.preimage.txid(o.epoch), txid, "the carried preimage recomputes to the txid");
            assert_eq!(settled.sender_registered_at_tick, NOW_SECS);
            assert!(axiom_core_logic::fact::origin_settled_link(&settled, &txid, is_dev),
                "Core ACCEPTS at registered_at + floor (dev={is_dev})");
            let early = attestation(&n, &txid, NOW_SECS + floor - 1, Some(NOW_SECS - 1_000));
            assert!(signature_verifies(&early));
            assert!(!axiom_core_logic::fact::origin_settled_link(&early, &txid, is_dev),
                "Core REJECTS one second before (dev={is_dev})");
            // Rebooted AFTER first_seen: the floor runs from the boot.
            let boot = NOW_SECS + 7;
            let rebooted_early = attestation(&n, &txid, boot + floor - 1, Some(boot));
            assert!(!axiom_core_logic::fact::origin_settled_link(&rebooted_early, &txid, is_dev),
                "one second before boot + floor is NOT settled");
            let rebooted = attestation(&n, &txid, boot + floor, Some(boot));
            assert!(axiom_core_logic::fact::origin_settled_link(&rebooted, &txid, is_dev));
        }
        // A second leg under the key (a fork in the records) ⇒ the node says
        // nothing ⇒ Core rejects. (W7c: a ban ALONE no longer withholds —
        // clause 4 removed, ruling 3; the fork key does.)
        let other = chain_leg(0xAD, test_legs::opening(&test_legs::wallet(0xAD)), 1, RECV_Q, 100, 2);
        assert!(!n.apply_remote_entry(&test_legs::entry_of(&other, 10), Some(&other.seq_proof), NOW_SECS + 1));
        assert!(n.is_banned(&pk_of(0xAD)), "fixture: the fork was detected");
        let banned = attestation(&n, &txid, NOW_SECS + 1_000_000, Some(NOW_SECS));
        assert_eq!((banned.origin.as_ref(), banned.sender_registered_at_tick), (None, 0));
        assert!(signature_verifies(&banned), "the honest 'none' is still signed");
        assert!(!axiom_core_logic::fact::origin_settled_link(&banned, &txid, false));
    }

    /// R36 — the measured cost of `verify_fork_leg` (≥3 witness Ed25519 +
    /// 1 client sig + two hash recomputes) per leg. A MEASUREMENT, not a
    /// check: run explicitly with `-- --ignored --nocapture`.
    #[test]
    #[ignore = "R36 measurement — run with --ignored --nocapture"]
    fn verify_fork_leg_cost_measured() {
        let leg = chain_leg(0xAE, [0x3E; 32], 1, RECV_P, 100, 1);
        let n = 500u32;
        let t0 = std::time::Instant::now();
        for _ in 0..n {
            std::hint::black_box(crate::ban::verify_fork_leg(std::hint::black_box(leg.clone())).is_ok());
        }
        let per = t0.elapsed() / n;
        eprintln!("[R36] verify_fork_leg: {:.1} µs/leg over {n} legs (k=3)", per.as_secs_f64() * 1e6);
    }

    /// ForkSettlement [R18] — the AE page bound: each claim once (a claim
    /// bans pk + bucket keys but is carried once), at most
    /// `AE_FORK_BANS_MAX` per message, and with more bans than the cap the
    /// cursor pages through ALL of them. Built on `ban_fork` (the replay
    /// insert — no verification needed to test paging).
    /// MUTATION (measured 2026-09-28): drop the cursor advance ⇒ the 33rd
    /// claim never leaves the node ⇒ RED; drop the `take(cap)` ⇒ RED.
    #[test]
    fn r18_ae_fork_bans_out_pages_every_ban_under_the_cap() {
        let cap = crate::ban::AE_FORK_BANS_MAX;
        let mut n = node();
        let mut all = Vec::new();
        for i in 0..=cap as u8 {
            let seed = 0x40u8.wrapping_add(i);
            let y = test_legs::opening(&test_legs::wallet(seed));
            let claim = ForkClaim {
                a: chain_leg(seed, y, 1, RECV_P, 100, 1),
                b: chain_leg(seed, y, 1, RECV_Q, 250, 2),
            };
            for key in crate::ban::fork_ban_keys(&claim) {
                n.bans_mut().ban_fork(key, claim.clone());
            }
            all.push(claim);
            if all.len() == cap {
                let page = n.ae_fork_bans_out();
                assert_eq!(page.len(), cap, "at the cap: every claim, each ONCE");
            }
        }
        assert_eq!(all.len(), cap + 1);
        let (p1, p2) = (n.ae_fork_bans_out(), n.ae_fork_bans_out());
        assert!(p1.len() == cap && p2.len() == cap, "each page is capped");
        for c in &all {
            assert!(p1.contains(c) || p2.contains(c), "two pages carry every ban");
        }
    }
}

/// Fork Settlement W7b (spec R52c/R52d, §9g) + KI#226 — node-level tests with
/// REAL keys through the door (`NablaNode::register`), the WAL and the
/// snapshot. Each names the mutation that must turn it red (RULE 6 §3a).
#[cfg(test)]
mod w7b_tests {
    use super::*;
    use crate::types::test_legs::{self, NOW_SECS};

    fn register(node: &mut NablaNode, leg: &ForkLeg, now: u64) -> Result<RegisterResult, NablaError> {
        let (reg, deed) = test_legs::registration_of(leg);
        let r = node.register(&reg, &deed, now);
        node.drain_fork_side_effects();
        r
    }

    /// A receiver R redeems TWO cheques from ONE state R0 (two validator sets)
    /// → the second redeem register meets the first's REDEEM record under the
    /// SHARED `(R, R0)` key → a verified `ForkClaim` (the Redeem arm) bans R
    /// and the door refuses. Both legs live in the redeem ledger, NONE in the
    /// origin ledger (R5).
    /// MUTATION (run 2026-09-28): in `SparseMerkleTree::record_verified_leg`
    /// return `Duplicate` for every `LegKind::Redeem` (redeem legs never
    /// recorded — the pre-W7b behaviour) ⇒ THIS test red (second register Ok,
    /// R unbanned); S9 (`fork_detection_mesh`) red with it.
    #[test]
    fn redeem_fork_at_the_door_bans_the_receiver_via_the_redeem_arm() {
        let mut n = NablaNode::new();
        n.admit_test_validators(); // KI#224: the door/flood/AE read the directory
        let r = test_legs::wallet(0xB1);
        let r_pk = r.verifying_key().to_bytes();
        let r0: StateId = [0xB0; 32];
        let rho1 = test_legs::genuine_redeem_leg(&r, r0, &crate::types::test_legs::stray_origin([0xB2; 32]), 1_000, 3, 3);
        let rho2 = test_legs::genuine_redeem_leg(&r, r0, &crate::types::test_legs::stray_origin([0xB3; 32]), 2_000, 3, 3);
        register(&mut n, &rho1, NOW_SECS).expect("the first redeem registers");
        assert_eq!(n.smt().redeem_len(), 1, "the redeem leg is RECORDED (W7b)");
        assert_eq!(n.smt().origin_len(), 0, "never as an origin (R5)");
        let Err(err) = register(&mut n, &rho2, NOW_SECS + 1) else { panic!("a second redeem from R0 is a fork") };
        assert!(matches!(err, NablaError::WalletBanned), "got {err:?}");
        assert!(n.is_banned(&r_pk));
        match &n.bans().get(&r_pk).expect("ban").evidence {
            BanEvidence::Fork(c) => {
                assert_eq!(crate::ban::verify_fork_claim(c), Ok(()));
                assert_eq!((c.a.kind(), c.b.kind()),
                    (axiom_core_logic::types::LegKind::Redeem, axiom_core_logic::types::LegKind::Redeem));
                let mut txs = [c.a.tx_hash, c.b.tx_hash];
                txs.sort();
                let mut want = [rho1.tx_hash, rho2.tx_hash];
                want.sort();
                assert_eq!(txs, want);
            }
            other => panic!("expected a Fork verdict, got {other:?}"),
        }
        assert_eq!(n.smt().legs_under(&(r_pk, r0)).len(), 2, "both legs under the shared key");
        assert_eq!(n.smt().redeem_records_of_cheque(&rho2.tx_hash).len(), 1);
        assert_eq!(n.smt().origin_len(), 0, "still no origin record");
        assert_eq!(n.take_pending_fork_floods().len(), 1, "the claim is queued for ForkBan");
        assert_eq!(n.origin_status(None, 0).redeem_records, 2);
    }

    /// T3 — a redeem record is NEVER vouched as an origin. R redeems cheque t
    /// (A's send t) at a node that never saw A's send: the redeem record
    /// exists, yet `cheque_sender_registered(t)` is false and `origin_vouch(t)`
    /// is NONE. When A's send t then registers, the vouch is A's OWN preimage.
    /// MUTATION (run 2026-09-28): route `LegKind::Redeem` into `origin_ledger`
    /// in `record_verified_leg` (the R5 regression) ⇒ THIS test red (t reads
    /// registered from R's redeem).
    #[test]
    fn redeem_record_is_never_vouched_as_an_origin() {
        let mut n = NablaNode::new();
        n.admit_test_validators(); // KI#224: the door/flood/AE read the directory
        let a = test_legs::wallet(0xB4);
        let r = test_legs::wallet(0xB5);
        let t = test_legs::genuine_send_leg(&a, test_legs::opening(&a), 1, "r@axiom.internal/0123456789", 300, 1, 3);
        let rho = test_legs::genuine_redeem_leg(&r, [0xB7; 32], &crate::types::test_legs::origin_of(&t), 300, 1, 3);
        register(&mut n, &rho, NOW_SECS).expect("R's redeem registers");
        let key = (r.verifying_key().to_bytes(), [0xB7; 32]);
        assert!(n.smt().redeem_record(&key, &t.tx_hash).is_some(), "the redeem record exists");
        assert!(!n.smt().cheque_sender_registered(&t.tx_hash), "R's redeem is NOT the sender's registration");
        assert!(n.smt().vouch_record(&t.tx_hash).is_none());
        assert_eq!(n.origin_vouch(&t.tx_hash, Some(NOW_SECS)), OriginVouch::NONE,
            "a redeem record never vouches the cheque's origin");
        register(&mut n, &t, NOW_SECS + 1).expect("A's send registers");
        let v = n.origin_vouch(&t.tx_hash, Some(NOW_SECS));
        assert_eq!(v.origin, t.origin_record(), "the vouch is A's own send leg");
    }

    /// Persistence — a redeem record survives a CRASH (WAL `RedeemRecord`
    /// replay only) and a SNAPSHOT restart, verbatim, in the redeem ledger.
    /// MUTATION (run 2026-09-28): skip the `WalOp::RedeemRecord` append in
    /// `drain_fork_side_effects` ⇒ THIS test red at the crash reopen; write an
    /// empty `redeem_ledger` in `take_snapshot` ⇒ red at the snapshot reopen.
    #[test]
    fn redeem_records_survive_snapshot_and_wal_restart() {
        let dir = tempfile::tempdir().unwrap();
        let r = test_legs::wallet(0xBA);
        let rho = test_legs::genuine_redeem_leg(&r, [0xBB; 32], &crate::types::test_legs::stray_origin([0xBC; 32]), 70, 2, 3);
        let id = (rho.key(), rho.tx_hash);
        {
            let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            n.admit_test_validators(); // KI#224: the door/flood/AE read the directory
            register(&mut n, &rho, 4_242).expect("registers");
        } // crash: no snapshot
        let persisted = {
            let n = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            let e = n.smt().redeem_record(&id.0, &id.1).expect("WAL replay restored the redeem record").clone();
            assert_eq!(e.first_seen_secs, 4_242, "verbatim");
            assert_eq!(n.smt().origin_len(), 0);
            e
        };
        {
            let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            n.admit_test_validators(); // KI#224: the door/flood/AE read the directory
            n.take_snapshot().unwrap();
        }
        let wal_ops = WriteAheadLog::read_all(dir.path().join("nabla.wal")).unwrap();
        assert!(!wal_ops.iter().any(|o| matches!(o, WalOp::RedeemRecord { .. })),
            "fixture: compacted — the snapshot is now the only home");
        let n = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert_eq!(n.smt().redeem_record(&id.0, &id.1), Some(&persisted), "snapshot restore is verbatim");
    }

    /// [R28] over REDEEM records — two redeem records under one key, the ban
    /// LOST (snapshot bans cleared): reopen re-derives the redeem-fork ban from
    /// the persisted redeem ledger (shared index).
    /// MUTATION (run 2026-09-28): make `rederive_fork_bans_at_load` skip keys
    /// whose lowest member is a `LegRef::Redeem` ⇒ THIS test red.
    #[test]
    fn restart_with_ban_removed_rederives_a_redeem_fork_ban() {
        let dir = tempfile::tempdir().unwrap();
        let r = test_legs::wallet(0xBD);
        let r_pk = r.verifying_key().to_bytes();
        let r0: StateId = [0xBE; 32];
        let rho1 = test_legs::genuine_redeem_leg(&r, r0, &crate::types::test_legs::stray_origin([0xC1; 32]), 10, 1, 3);
        let rho2 = test_legs::genuine_redeem_leg(&r, r0, &crate::types::test_legs::stray_origin([0xC2; 32]), 20, 1, 3);
        {
            let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            n.admit_test_validators(); // KI#224: the door/flood/AE read the directory
            register(&mut n, &rho1, 10).unwrap();
            assert!(register(&mut n, &rho2, 11).is_err());
            assert!(n.is_banned(&r_pk));
            n.take_snapshot().unwrap();
        }
        {
            let mgr = SnapshotManager::new(dir.path().join("snapshots")).unwrap();
            let mut snap = mgr.load_latest().unwrap().expect("snapshot");
            assert_eq!(snap.redeem_ledger.len(), 2, "fixture: both redeem records persisted");
            assert!(snap.origin_ledger.is_empty());
            assert!(!snap.bans.is_empty(), "fixture: the ban was persisted");
            snap.bans.clear();
            mgr.write(&snap).unwrap();
        }
        let n = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert!(n.is_banned(&r_pk), "the lost redeem-fork ban is RE-DERIVED from the redeem records");
        assert_eq!(n.origin_fork_bans_rederived_at_load(), 1);
        assert!(n.smt().origin_key_is_held(&(r_pk, r0)));
    }

    /// KI#226 at the DOOR — A's genuine leg, re-signed by A over W's id, is
    /// REFUSED (counted) and nothing is stored under W; the SAME leg under A's
    /// own id registers (the honest register is unaffected).
    /// MUTATION (run 2026-09-28): delete step 0b in `process_registration`
    /// (bucket from `reg.wallet_id` again) ⇒ THIS test red (W's head is A's).
    #[test]
    fn ki226_door_refuses_a_wallet_id_the_signing_key_does_not_own() {
        let mut n = NablaNode::new();
        n.admit_test_validators(); // KI#224: the door/flood/AE read the directory
        let a = test_legs::wallet(0xC3);
        let w = test_legs::wallet(0xC4).verifying_key().to_bytes();
        let leg = test_legs::genuine_send_leg(&a, [0xC5; 32], 1, "p@axiom.internal/0123456789", 10, 1, 3);
        let (mut reg, deed) = test_legs::registration_of(&leg);
        reg.wallet_id = w;
        test_legs::resign_registration(&mut reg, &a);
        let before = crate::registration::wallet_id_key_mismatch_total();
        let Err(err) = n.register(&reg, &deed, NOW_SECS) else { panic!("W's id, A's key must be refused") };
        assert!(matches!(err, NablaError::InvalidReceipt), "got {err:?}");
        assert!(crate::registration::wallet_id_key_mismatch_total() > before, "COUNTED");
        assert!(n.smt().get(&w).is_none(), "nothing stored under W");
        assert_eq!(n.smt().origin_len(), 0, "refused before any record");
        register(&mut n, &leg, NOW_SECS).expect("the honest register under A's own id");
        assert_eq!(n.smt().get(&a.verifying_key().to_bytes()).map(|e| e.tx_hash), Some(leg.tx_hash));
    }

    /// KI#226 on ANTI-ENTROPY — an entry naming W, authored by A (A's sig over
    /// W's id) is refused and counted; W's held head is untouched.
    /// MUTATION (run 2026-09-28): delete the `bucket_derives_from_key` gate in
    /// `apply_remote_entry_inner` ⇒ THIS test red (W's head replaced).
    #[test]
    fn ki226_anti_entropy_refuses_a_wallet_id_the_signing_key_does_not_own() {
        let mut n = NablaNode::new();
        n.admit_test_validators(); // KI#224: the door/flood/AE read the directory
        let a = test_legs::wallet(0xC6);
        let wk = test_legs::wallet(0xC7);
        let w = wk.verifying_key().to_bytes();
        let honest = test_legs::genuine_send_leg(&wk, [0xC8; 32], 1, "p@axiom.internal/0123456789", 10, 1, 3);
        register(&mut n, &honest, NOW_SECS).expect("W's honest leg");
        let fa = test_legs::genuine_send_leg(&a, [0xC9; 32], 2, "q@axiom.internal/0123456789", 10, 2, 3);
        let mut e = test_legs::entry_of(&fa, n.current_tick + 50);
        e.wallet_id = w;
        e.client_sig = test_legs::client_sig_over(&a, &w, &fa.new_state, &fa.tx_hash);
        let before = crate::registration::wallet_id_key_mismatch_total();
        assert!(!n.apply_remote_entry(&e, Some(&fa.seq_proof), NOW_SECS), "refused");
        assert!(crate::registration::wallet_id_key_mismatch_total() > before, "COUNTED");
        let head = n.smt().get(&w).expect("W's head");
        assert_eq!((head.client_pk, head.tx_hash), (w, honest.tx_hash), "W's head untouched");
    }
}

/// Fork Settlement §9o [R58/R59] (W1) — R48 record-AE, node level, with REAL
/// node keys (`Ed25519Signer`; a node's id IS its key here, so the "verified
/// NBC key" of `from` is `from` itself) and GENUINE k-witnessed,
/// wallet-signed legs (`types::test_legs`). Every exchange runs the SAME lib
/// calls the binary makes (`record_ae_start` / `record_ae_handle_ask` /
/// `record_ae_accept_answer` / `record_sync::prepare_answer` /
/// `record_ae_apply_answer`) — `descend` is the transport. Each test names the
/// mutation that turns it RED (RULE 6 §3a); each was run on 2026-09-30.
#[cfg(test)]
pub(crate) mod record_ae_tests {
    use super::*;
    use crate::record_sync::{self as rs, Answer, Ask, LeafKey};
    use crate::transport::WireMessage;
    use crate::types::test_legs::{self, NOW_SECS};
    use ed25519_dalek::{Signer as _, SigningKey};

    const RECV: &str = "p@axiom.internal/0123456789";

    pub(crate) struct Peer {
        dir: tempfile::TempDir,
        seed: [u8; 32],
        pub(crate) n: NablaNode,
        pub(crate) id: NodeId,
    }

    pub(crate) fn peer(seed: u8, admit: bool) -> Peer {
        let dir = tempfile::tempdir().unwrap();
        let seed = [seed; 32];
        let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::Ed25519Signer::from_seed(&seed))).unwrap();
        if admit {
            n.admit_test_validators();
        }
        let id = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        Peer { dir, seed, n, id }
    }

    /// Crash + reopen from the node's own dir (WAL / snapshot), then re-admit
    /// the test witnesses (a test admission is not persisted).
    fn reopen(p: &mut Peer) {
        let dir = p.dir.path().to_path_buf();
        p.n = NablaNode::open(&dir, Box::new(crate::crypto::Ed25519Signer::from_seed(&p.seed))).unwrap();
        p.n.admit_test_validators();
    }

    fn key_of(p: &Peer) -> SigningKey {
        SigningKey::from_bytes(&p.seed)
    }

    /// Sign an answer as `signer` claiming `from` (a genuine or a spoofed one).
    fn signed_answer(signer: &SigningKey, from: NodeId, nonce: u64, answer: Answer) -> WireMessage {
        let payload = crate::crypto::ae_sign_payload(rs::RECORD_AE_KIND_ANSWER, &from, nonce, &rs::answer_body_hash(&answer));
        WireMessage::RecordAeAnswer { from, nonce, answer, sig: signer.sign(&payload).to_bytes().to_vec() }
    }

    fn signed_ask(signer: &SigningKey, from: NodeId, nonce: u64, ask: Ask) -> (Ask, Vec<u8>) {
        let payload = crate::crypto::ae_sign_payload(rs::RECORD_AE_KIND_ASK, &from, nonce, &rs::ask_body_hash(&ask));
        (ask, signer.sign(&payload).to_bytes().to_vec())
    }

    /// Deliver one answer message to the asker the way the binary does
    /// (accept under the lock → prepare off it → apply under it).
    pub(crate) fn deliver_answer(a: &mut NablaNode, a_id: NodeId, msg: WireMessage, from_pk: [u8; 32], now: u64) -> Option<WireMessage> {
        let WireMessage::RecordAeAnswer { from, nonce, answer, sig } = msg else { panic!("not an answer") };
        let acc = a.record_ae_accept_answer(&from, nonce, &answer, &sig, Some(from_pk), now)?;
        a.record_ae_apply_answer(a_id, rs::prepare_answer(acc, answer), now)
    }

    /// What one descent cost the asker.
    #[derive(Debug, Clone, Copy, Default)]
    pub(crate) struct DescentRun {
        pub(crate) asks: u32,
        /// Trie prefixes asked over all `Ask::Nodes`.
        pub(crate) prefixes: usize,
    }

    /// ONE full descent of `a` against `b` over the lib API. `a`'s id / `b`'s
    /// id are their verified NBC keys.
    pub(crate) fn descend_nodes(a: &mut NablaNode, a_id: NodeId, b: &mut NablaNode, b_id: NodeId, now: u64) -> DescentRun {
        let mut run = DescentRun::default();
        let mut msg = a.record_ae_start(a_id, b_id, now);
        while let Some(WireMessage::RecordAeAsk { from, nonce, ask, sig }) = msg {
            run.asks += 1;
            if let Ask::Nodes(p) = &ask {
                run.prefixes += p.len();
            }
            let Some(answer) = b.record_ae_handle_ask(b_id, &from, nonce, &ask, &sig, Some(a_id), now) else { break };
            msg = deliver_answer(a, a_id, answer, b_id, now);
        }
        run
    }

    fn descend(a: &mut Peer, b: &mut Peer, now: u64) -> u32 {
        descend_nodes(&mut a.n, a.id, &mut b.n, b.id, now).asks
    }

    fn send(seed: u8, consumed: u8, nonce: u64) -> ForkLeg {
        test_legs::genuine_send_leg(&test_legs::wallet(seed), [consumed; 32], 1, RECV, 100, nonce, 3)
    }

    fn junk_keys() -> Vec<SigningKey> {
        (0..3).map(test_legs::junk_witness).collect()
    }

    /// Mark `state` consumed at `n` (a head at `state`, then a successor).
    fn consume(n: &mut NablaNode, pk: [u8; 32], state: StateId) {
        for (st, seq) in [(state, 4u64), ([0x77; 32], 5)] {
            let e = NablaEntry {
                received_from: None, wallet_seq: seq, wallet_id: pk, current_state: st, tx_hash: [seq as u8; 32],
                tick: 1, group_members: None, status: WalletStatus::Normal, client_pk: pk, client_sig: vec![0u8; 64],
            };
            n.smt_mut().put(&e);
        }
        assert!(n.smt().is_state_consumed(&state), "fixture: consumed");
    }

    /// R58 — two nodes holding ONE leg set agree on the root whatever the
    /// insert order, the `first_seen_secs`, the `contested` flag and the
    /// WITNESS SUBSET (both graded) each copy carries.
    /// MUTATION (run): fold the first witness pk into `LeafKey::of`'s fork key
    /// (`h.update(&leg.seq_proof.sigs[0].validator_pk)`) ⇒ RED (the rewitnessed
    /// copy files under another leaf). The shape-vs-history mutation is the
    /// unit twin's (`record_sync::tests::record_trie_root_is_a_function_of_
    /// the_leaf_set`).
    #[test]
    fn record_trie_root_independent_of_insert_order_and_metadata() {
        let legs: Vec<ForkLeg> = (0..40u8).map(|i| send(0x30 + i % 5, 0x80 + i, i as u64)).collect();
        let mut a = peer(0x01, true);
        let mut b = peer(0x02, true);
        for l in &legs {
            a.n.record_leg_for_test(l.clone(), 100);
        }
        let alt: Vec<SigningKey> = (1..4).map(test_legs::validator).collect();
        consume(&mut b.n, legs[0].client_pk(), legs[0].consumed());
        for l in legs.iter().rev() {
            b.n.record_leg_for_test(test_legs::rewitness(l, &alt), 900);
        }
        let (ra, rb) = (a.n.smt().vouch_record(&legs[0].tx_hash).unwrap(), b.n.smt().vouch_record(&legs[0].tx_hash).unwrap());
        assert_ne!(ra.first_seen_secs, rb.first_seen_secs, "fixture: first_seen differs");
        assert_ne!(ra.contested, rb.contested, "fixture: contested differs");
        assert_ne!(ra.leg.seq_proof.sigs, rb.leg.seq_proof.sigs, "fixture: witness subsets differ");
        assert_eq!(a.n.record_trie().len(), 40);
        assert_eq!(a.n.record_trie().root(), b.n.record_trie().root(), "one leaf set ⇒ one root");
    }

    /// Converged sets cost ONE round trip: the root views hash equal.
    /// MUTATION (run): `RecordTrie::subtree_hash` answers `EMPTY_HASH` for a
    /// node it holds (`Located::Node(n) => EMPTY_HASH`) ⇒ RED (the descent
    /// walks the whole trie). Dropping ONE of the two comparisons in
    /// `Descent::on_nodes` alone does NOT turn it red — the view-level skip
    /// and the per-child compare each suffice for a converged pair (run).
    #[test]
    fn record_ae_converged_sets_one_round_trip() {
        let mut a = peer(0x03, true);
        let mut b = peer(0x04, true);
        for i in 0..50u8 {
            let l = send(0x40 + i % 7, i, i as u64);
            a.n.record_leg_for_test(l.clone(), 100);
            b.n.record_leg_for_test(l, 200);
        }
        assert!(a.n.record_trie().depth() >= 2, "fixture: an internal root");
        assert_eq!(descend(&mut a, &mut b, NOW_SECS), 1, "one ask/answer");
        let c = a.n.record_ae_counters();
        assert_eq!((c.descents_completed, c.asks_sent, c.legs_received), (1, 1, 0));
        assert_eq!(b.n.record_ae_counters().answers_sent, 1);
    }

    /// One divergent leg under 10 000 converged leaves is found in at most
    /// `depth + 1` asks (every level once, then one `Ask::Legs`), walking ONE
    /// prefix per level, and recorded.
    /// MUTATION (run): in `Descent::on_nodes` push EVERY non-empty child of an
    /// internal view (drop `&& *ch != local.subtree_hash(&cp)`) ⇒ RED (the
    /// ask COUNT survives it — levels are batched — the prefix count does not).
    #[test]
    fn record_ae_single_divergent_leg_under_10k_converged() {
        let mut a = peer(0x05, true);
        let mut b = peer(0x06, true);
        for i in 0..10_000u32 {
            let h = *blake3::hash(&i.to_le_bytes()).as_bytes();
            let k = LeafKey { fork_key: h, txid: *blake3::hash(&h).as_bytes(), kind: (i % 2) as u8 };
            a.n.record_trie_insert_for_test(k);
            b.n.record_trie_insert_for_test(k);
        }
        let leg = send(0x50, 0x51, 1);
        b.n.record_leg_for_test(leg.clone(), 100);
        let depth = b.n.record_trie().depth() as u32;
        let run = descend_nodes(&mut a.n, a.id, &mut b.n, b.id, NOW_SECS);
        eprintln!("[R58] 10k converged + 1: depth {depth}, asks {}, prefixes {}", run.asks, run.prefixes);
        assert!(run.asks <= depth + 1, "asks {} > depth {depth} + 1", run.asks);
        assert!(run.prefixes <= depth as usize, "one prefix per level: {} > {depth}", run.prefixes);
        assert!(a.n.smt().vouch_record(&leg.tx_hash).is_some(), "the divergent leg was fetched and recorded");
        assert_eq!(a.n.record_trie().root(), b.n.record_trie().root(), "converged");
        assert_eq!(a.n.record_ae_counters().descents_completed, 1);
    }

    /// The KI#235 C shape in miniature: R forks P → X (ρ1, held only by A) and
    /// P → Y (ρ2, held only by B). One descent brings ρ2 to A: A bans R on a
    /// VERIFIED redeem/redeem `Fork` claim, holds both legs under (R, P), and
    /// queues the verdict for the `ForkBan` fan-out.
    /// MUTATION (run): feed only SEND legs into the trie (`record_trie_feed`
    /// skips `LegRef::Redeem`) ⇒ RED.
    #[test]
    fn record_ae_sibling_redeem_leg_meets_and_bans_with_evidence() {
        let sk = test_legs::wallet(0x60);
        let pk = sk.verifying_key().to_bytes();
        let p = [0x61; 32];
        let rho1 = test_legs::genuine_redeem_leg(&sk, p, &crate::types::test_legs::stray_origin([0xC1; 32]), 2_000, 1, 3);
        let rho2 = test_legs::genuine_redeem_leg(&sk, p, &crate::types::test_legs::stray_origin([0xC2; 32]), 3_000, 1, 3);
        let mut a = peer(0x07, true);
        let mut b = peer(0x08, true);
        a.n.record_leg_for_test(rho1.clone(), 100);
        b.n.record_leg_for_test(rho2.clone(), 100);
        assert!(!a.n.is_banned(&pk) && !b.n.is_banned(&pk));
        descend(&mut a, &mut b, NOW_SECS);
        assert!(a.n.is_banned(&pk), "A banned R");
        match &a.n.bans().get(&pk).unwrap().evidence {
            BanEvidence::Fork(c) => {
                crate::ban::verify_fork_claim(c).expect("the claim verifies");
                let mut t = [c.a.tx_hash, c.b.tx_hash];
                t.sort();
                assert_eq!(t, [rho1.tx_hash, rho2.tx_hash]);
            }
            other => panic!("banned on {other:?}"),
        }
        assert_eq!(a.n.smt().legs_under(&(pk, p)).len(), 2);
        assert!(!a.n.take_pending_fork_floods().is_empty(), "verdict queued for the ForkBan fan-out");
        assert_eq!(a.n.record_ae_counters().legs_recorded, 1);
    }

    /// An UNGRADED record (a witness outside the directory) is not a leaf and
    /// is never shipped — neither found by a descent nor served to a direct
    /// `Ask::Legs` for its key.
    /// MUTATION (run): insert every record into the trie (drop the grade test
    /// in `record_trie_feed`) ⇒ RED.
    #[test]
    fn record_ae_ungraded_leg_not_a_leaf_not_shipped() {
        let junk = test_legs::rewitness(&send(0x62, 0x63, 1), &junk_keys());
        let mut a = peer(0x09, true);
        let mut b = peer(0x0A, true);
        assert!(matches!(b.n.record_leg_for_test(junk.clone(), 100), crate::ban::LegRecordOutcome::Recorded { .. }),
            "fixture: a junk-witnessed leg still VERIFIES and is recorded (door/flood/AE)");
        assert!(!b.n.leg_is_graded(&junk));
        assert_eq!(b.n.record_trie().len(), 0, "not a leaf");
        assert_eq!(descend(&mut a, &mut b, NOW_SECS), 1, "empty trie ⇒ one ask");
        assert!(a.n.smt().vouch_record(&junk.tx_hash).is_none(), "never shipped");
        let ans = b.n.record_ae_answer(&Ask::Legs(vec![LeafKey::of(&junk)]));
        assert_eq!(ans, Answer::Legs(Vec::new()), "a direct ask gets nothing");
    }

    /// DIRECTORY LAG at the receiver: A's directory admits no test witness, so
    /// every fetched leg is UNGRADED there — detect-only. The sibling of A's
    /// own leg opens a claim and bans on evidence; an unrelated leg is stored
    /// NOWHERE (no record, no leaf).
    /// MUTATIONS (run): route ungraded legs through the record path in
    /// `record_ae_apply` ⇒ RED ("stored nothing else"); make `detect_only`
    /// return `NotStored` unconditionally ⇒ RED (no ban).
    #[test]
    fn record_ae_directory_lag_detect_only_bans_fork_stores_nothing_else() {
        let y = [0x64; 32];
        let a_leg = send(0x65, 0x64, 1);
        let b_leg = test_legs::genuine_send_leg(&test_legs::wallet(0x65), y, 1, "q@axiom.internal/0123456789", 250, 2, 3);
        let c_leg = send(0x66, 0x67, 1);
        let pk = a_leg.client_pk();
        let mut a = peer(0x0B, false);
        let mut b = peer(0x0C, true);
        a.n.record_leg_for_test(a_leg.clone(), 100);
        b.n.record_leg_for_test(b_leg.clone(), 100);
        b.n.record_leg_for_test(c_leg.clone(), 100);
        assert_eq!((a.n.record_trie().len(), b.n.record_trie().len()), (0, 2), "fixture: A grades nothing");
        descend(&mut a, &mut b, NOW_SECS);
        assert!(a.n.is_banned(&pk), "the fork is detected — detection is not gated on the directory (R37)");
        match &a.n.bans().get(&pk).unwrap().evidence {
            BanEvidence::Fork(c) => crate::ban::verify_fork_claim(c).expect("verifies"),
            other => panic!("banned on {other:?}"),
        }
        assert!(a.n.smt().vouch_record(&c_leg.tx_hash).is_none(), "the unrelated ungraded leg is NOT stored");
        assert!(a.n.smt().vouch_record(&b_leg.tx_hash).is_none(), "the sibling itself is not stored either");
        assert_eq!(a.n.smt().origin_len(), 1, "only A's own record");
        assert_eq!(a.n.record_trie().len(), 0);
        let c = a.n.record_ae_counters();
        assert_eq!((c.legs_ungraded, c.legs_recorded), (2, 0));
    }

    /// A held JUNK-witnessed (ungraded) copy is UPGRADED in place by the
    /// graded copy record-AE brings: same leg, graded witnesses, first_seen
    /// and contested KEPT, now a leaf; the upgrade is WAL-logged and survives
    /// a restart (the last copy wins at replay).
    /// MUTATIONS (run): `try_upgrade` returns `None` ⇒ RED; make
    /// `restore_last_copy_wins` keep the held copy ⇒ RED at the reopen.
    #[test]
    fn record_ae_junk_copy_upgraded_keeps_first_seen() {
        let leg = send(0x68, 0x69, 1);
        let junk = test_legs::rewitness(&leg, &junk_keys());
        let mut a = peer(0x0D, true);
        let mut b = peer(0x0E, true);
        consume(&mut a.n, leg.client_pk(), leg.consumed());
        a.n.record_leg_for_test(junk.clone(), 100);
        b.n.record_leg_for_test(leg.clone(), 900);
        let before = a.n.smt().vouch_record(&leg.tx_hash).unwrap().clone();
        assert!(before.contested && before.leg == junk, "fixture: a contested junk copy");
        assert_eq!(a.n.record_trie().len(), 0);
        descend(&mut a, &mut b, 5_000);
        let after = a.n.smt().vouch_record(&leg.tx_hash).unwrap().clone();
        assert_eq!(after.leg, leg, "the graded copy replaced the junk one");
        assert_eq!((after.first_seen_secs, after.contested), (100, true), "first_seen + contested KEPT");
        assert_eq!(a.n.smt().origin_records_upgraded(), 1);
        assert!(a.n.record_trie().contains(&LeafKey::of(&leg)), "now a leaf");
        assert_eq!(a.n.record_trie().root(), b.n.record_trie().root());
        reopen(&mut a);
        let replayed = a.n.smt().vouch_record(&leg.tx_hash).unwrap();
        assert_eq!(replayed, &after, "WAL replay: the last copy (the upgrade) wins");
        assert!(a.n.record_trie().contains(&LeafKey::of(&leg)));
    }

    /// R59 — a spoofed answer (signed by another key), a replayed one, one to
    /// a nonce never issued, unrequested legs inside a genuine answer, and a
    /// spoofed / unknown-sender ask are all REFUSED, COUNTED by kind, and
    /// change nothing.
    /// MUTATIONS (run): drop `verify_ae_signature` in
    /// `record_ae_accept_answer` ⇒ RED at (a) (spoof accepted); accept ANY
    /// answer while an ask is in flight (drop `accept_reply` AND the nonce
    /// match of `take_in_flight`; each alone still refuses a replay by design —
    /// the guard consumed the nonce, the descent moved to a new one) ⇒ RED at
    /// the replay count.
    #[test]
    fn record_ae_spoofed_or_unsolicited_answer_refused_counted() {
        let l1 = send(0x6A, 0x6B, 1);
        let l2 = send(0x6C, 0x6D, 1);
        let mut a = peer(0x0F, true);
        let mut b = peer(0x10, true);
        let intruder = SigningKey::from_bytes(&[0x99; 32]);
        b.n.record_leg_for_test(l1.clone(), 100);
        b.n.record_leg_for_test(l2.clone(), 100);
        // (a) spoofed: B's genuine answer re-signed by the intruder as `from = B`.
        let Some(WireMessage::RecordAeAsk { from, nonce, ask, sig }) = a.n.record_ae_start(a.id, b.id, NOW_SECS) else { panic!() };
        let genuine = b.n.record_ae_handle_ask(b.id, &from, nonce, &ask, &sig, Some(a.id), NOW_SECS).unwrap();
        let WireMessage::RecordAeAnswer { answer, .. } = genuine.clone() else { panic!() };
        let spoof = signed_answer(&intruder, b.id, nonce, answer);
        assert!(deliver_answer(&mut a.n, a.id, spoof, b.id, NOW_SECS).is_none());
        assert_eq!(a.n.record_ae_counters().refused_bad_signature, 1);
        // (b) the genuine answer is accepted (its ask was still in flight) …
        let next = deliver_answer(&mut a.n, a.id, genuine.clone(), b.id, NOW_SECS);
        assert!(next.is_some(), "genuine answer accepted, the descent goes on");
        // … and a REPLAY of it is unsolicited.
        assert!(deliver_answer(&mut a.n, a.id, genuine, b.id, NOW_SECS).is_none());
        assert_eq!(a.n.record_ae_counters().refused_unsolicited, 1);
        // (c) an answer to a nonce A never issued (B-signed, genuine body).
        let stray = signed_answer(&key_of(&b), b.id, 0xDEAD_BEEF, Answer::Legs(vec![l1.clone()]));
        assert!(deliver_answer(&mut a.n, a.id, stray, b.id, NOW_SECS).is_none());
        assert_eq!(a.n.record_ae_counters().refused_unsolicited, 2);
        // (d) unrequested legs inside a genuine answer to a real ask.
        let Some(WireMessage::RecordAeAsk { nonce, ask, .. }) = next else { panic!("expected the legs ask") };
        let Ask::Legs(asked) = &ask else { panic!("expected Ask::Legs, got {ask:?}") };
        assert_eq!(asked.len(), 2);
        let only = [l1.clone()].into_iter().filter(|l| asked.contains(&LeafKey::of(l))).collect::<Vec<_>>();
        let extra = send(0x6E, 0x6F, 1);
        let mut carried = only.clone();
        carried.push(extra.clone());
        let msg = signed_answer(&key_of(&b), b.id, nonce, Answer::Legs(carried));
        deliver_answer(&mut a.n, a.id, msg, b.id, NOW_SECS);
        let c = a.n.record_ae_counters();
        assert_eq!(c.legs_unrequested, 1, "the extra leg is refused unverified");
        assert!(a.n.smt().vouch_record(&extra.tx_hash).is_none(), "and never recorded");
        assert!(a.n.smt().vouch_record(&l1.tx_hash).is_some(), "the asked one is");
        // (e) spoofed ask / unknown sender at the responder.
        let (ask, sig) = signed_ask(&intruder, a.id, 7, Ask::Nodes(vec![rs::Prefix::root()]));
        assert!(b.n.record_ae_handle_ask(b.id, &a.id, 7, &ask, &sig, Some(a.id), NOW_SECS).is_none());
        let (ask, sig) = signed_ask(&key_of(&a), a.id, 8, Ask::Nodes(vec![rs::Prefix::root()]));
        assert!(b.n.record_ae_handle_ask(b.id, &a.id, 8, &ask, &sig, None, NOW_SECS).is_none());
        let cb = b.n.record_ae_counters();
        assert_eq!((cb.refused_bad_signature, cb.refused_unknown_sender), (1, 1));
        assert_eq!(a.n.origin_status(None, 0).record_ae_refused, 3, "on /status, all kinds");
    }

    /// R59 — past `RECORD_AE_ANSWERS_PER_WINDOW` answers in one window the
    /// responder SHEDS authenticated asks (counted), and answers again in the
    /// next window. Many askers, each within its own per-`from` budget.
    /// MUTATION (run): `RecordAeSession::global_admit` always `true` ⇒ RED.
    #[test]
    fn record_ae_global_cap_sheds_counted() {
        let mut b = peer(0x11, true);
        let cap = crate::constants::RECORD_AE_ANSWERS_PER_WINDOW;
        let per = crate::constants::RECORD_AE_ASKS_PER_FROM_PER_WINDOW as u64;
        let askers: Vec<SigningKey> = (0..(cap / per + 2)).map(|i| SigningKey::from_bytes(&[(0xA0 + i) as u8; 32])).collect();
        let (mut answered, mut shed_seen) = (0u64, false);
        let mut nonce = 0u64;
        'outer: for k in &askers {
            let id = k.verifying_key().to_bytes();
            for _ in 0..per {
                nonce += 1;
                let (ask, sig) = signed_ask(k, id, nonce, Ask::Nodes(vec![rs::Prefix::root()]));
                match b.n.record_ae_handle_ask(b.id, &id, nonce, &ask, &sig, Some(id), NOW_SECS) {
                    Some(_) => answered += 1,
                    None => {
                        shed_seen = true;
                        break 'outer;
                    }
                }
            }
        }
        assert!(shed_seen, "the cap must shed");
        assert_eq!(answered, cap, "exactly the cap answered");
        let c = b.n.record_ae_counters();
        assert_eq!((c.shed_global, c.refused_total()), (1, 0), "shed is counted, and is not a refusal");
        let k = &askers[askers.len() - 1];
        let id = k.verifying_key().to_bytes();
        let (ask, sig) = signed_ask(k, id, 999_999, Ask::Nodes(vec![rs::Prefix::root()]));
        let later = NOW_SECS + crate::constants::RECORD_AE_WINDOW_SECS;
        assert!(b.n.record_ae_handle_ask(b.id, &id, 999_999, &ask, &sig, Some(id), later).is_some(), "next window answers");
    }

    /// Answers are BOUNDED (≤ `RECORD_AE_MAX_LEGS_PER_ANSWER` legs — an
    /// oversize answer is refused, counted) and a truncated answer RESUMES:
    /// the asker re-asks exactly what did not come, and converges.
    /// MUTATION (run): `Descent::on_legs` does not re-queue missing keys ⇒ RED.
    #[test]
    fn record_ae_answer_bounded_truncation_resumes() {
        let max = crate::constants::RECORD_AE_MAX_LEGS_PER_ANSWER;
        let legs: Vec<ForkLeg> = (0..(max as u32 + 36)).map(|i| send(0x70 + (i % 9) as u8, (i % 251) as u8, i as u64 + 1)).collect();
        let mut a = peer(0x12, true);
        let mut b = peer(0x13, true);
        for l in &legs {
            b.n.record_leg_for_test(l.clone(), 100);
        }
        let mut msg = a.n.record_ae_start(a.id, b.id, NOW_SECS);
        let mut truncated_once = false;
        while let Some(WireMessage::RecordAeAsk { from, nonce, ask, sig }) = msg {
            let ans = b.n.record_ae_handle_ask(b.id, &from, nonce, &ask, &sig, Some(a.id), NOW_SECS).unwrap();
            let WireMessage::RecordAeAnswer { answer, .. } = &ans else { panic!() };
            let ans = match answer {
                Answer::Legs(l) => {
                    assert!(l.len() <= max, "answer bounded: {} legs", l.len());
                    if !truncated_once && l.len() > 10 {
                        truncated_once = true;
                        signed_answer(&key_of(&b), b.id, nonce, Answer::Legs(l[..10].to_vec()))
                    } else {
                        ans
                    }
                }
                Answer::Nodes(_) => ans,
            };
            msg = deliver_answer(&mut a.n, a.id, ans, b.id, NOW_SECS);
        }
        assert!(truncated_once, "fixture: one answer was cut short");
        for l in &legs {
            assert!(a.n.smt().vouch_record(&l.tx_hash).is_some(), "leg {} missing after resume", hex::encode(&l.tx_hash[..4]));
        }
        assert_eq!(a.n.record_trie().root(), b.n.record_trie().root());
        // An oversize answer (max + 1 legs, genuinely signed) is refused.
        let Some(WireMessage::RecordAeAsk { nonce, .. }) = a.n.record_ae_start(a.id, b.id, NOW_SECS) else { panic!() };
        let over = signed_answer(&key_of(&b), b.id, nonce, Answer::Legs(legs[..max + 1].to_vec()));
        assert!(deliver_answer(&mut a.n, a.id, over, b.id, NOW_SECS).is_none());
        assert_eq!(a.n.record_ae_counters().refused_oversize, 1);
    }

    /// A record learned by record-AE is born at the RECEIVER's clock (R13/R16
    /// judged here) — never the responder's `first_seen_secs`.
    /// MUTATION (run): `record_ae_apply` passes `0` instead of `now_secs` to
    /// `record_verified_and_detect` ⇒ RED.
    #[test]
    fn record_ae_first_seen_is_receiver_clock() {
        let leg = send(0x7A, 0x7B, 1);
        let mut a = peer(0x14, true);
        let mut b = peer(0x15, true);
        b.n.record_leg_for_test(leg.clone(), 1_000);
        descend(&mut a, &mut b, 5_000);
        assert_eq!(b.n.smt().vouch_record(&leg.tx_hash).unwrap().first_seen_secs, 1_000);
        assert_eq!(a.n.smt().vouch_record(&leg.tx_hash).unwrap().first_seen_secs, 5_000, "receiver clock");
    }

    /// The trie is in-memory: `open` rebuilds it from the ledgers (graded
    /// records only) and it equals the live one, root and leaves; an ungraded
    /// record stays out.
    /// MUTATION (run): drop the `rebuild_record_trie()` call in `open` ⇒ RED.
    #[test]
    fn record_ae_trie_rebuilt_at_load_equals_live() {
        let mut a = peer(0x16, true);
        let sk = test_legs::wallet(0x7C);
        for i in 0..6u8 {
            a.n.record_leg_for_test(send(0x7D + i, 0x90 + i, 1), 100);
        }
        a.n.record_leg_for_test(test_legs::genuine_redeem_leg(&sk, [0x7E; 32], &crate::types::test_legs::stray_origin([0xC7; 32]), 10, 1, 3), 100);
        let junk = test_legs::rewitness(&send(0x7F, 0x9F, 1), &junk_keys());
        a.n.record_leg_for_test(junk.clone(), 100);
        assert_eq!(a.n.record_trie().len(), 7, "fixture: 6 sends + 1 redeem graded, the junk copy not");
        a.n.take_snapshot().unwrap();
        a.n.record_leg_for_test(send(0x6F, 0x6E, 9), 100); // one more, WAL-only after the snapshot
        let (root, leaves) = (a.n.record_trie().root(), a.n.record_trie().len());
        assert_eq!(leaves, 8);
        reopen(&mut a);
        assert_eq!((a.n.record_trie().root(), a.n.record_trie().len()), (root, leaves), "rebuilt == live");
        assert!(!a.n.record_trie().contains(&LeafKey::of(&junk)), "the ungraded record stays out");
    }

    /// R36 cost of the off-lock stage — MEASUREMENT: `prepare_answer` on a
    /// full answer (64 genuine legs). Run with `--ignored --nocapture`.
    #[test]
    #[ignore = "measurement — run with --ignored --nocapture"]
    fn record_ae_verify_cost_measured() {
        let max = crate::constants::RECORD_AE_MAX_LEGS_PER_ANSWER;
        let legs: Vec<ForkLeg> = (0..max as u64).map(|i| send(0x20 + (i % 7) as u8, i as u8, i + 1)).collect();
        let asked: Vec<LeafKey> = legs.iter().map(LeafKey::of).collect();
        let rounds = 10u32;
        let t0 = std::time::Instant::now();
        for _ in 0..rounds {
            let acc = rs::AcceptedAnswer { from: [0; 32], nonce: 1, asked: Ask::Legs(asked.clone()) };
            let p = rs::prepare_answer(acc, Answer::Legs(legs.clone()));
            std::hint::black_box(&p);
        }
        let per_answer = t0.elapsed() / rounds;
        eprintln!(
            "[R58] prepare_answer: {:.2} ms per full answer ({max} legs) = {:.1} µs/leg (off the node lock)",
            per_answer.as_secs_f64() * 1e3,
            per_answer.as_secs_f64() * 1e6 / max as f64,
        );
    }

    // ── Fable review 2026-10-01 F-5 — the genesis-first walk (an ORDER only) ──

    /// Drive `ticks` walk steps; every step advances the clock past the reply
    /// TTL so the previous descent expires (aborted) and no tick is skipped
    /// for an in-flight peer. Returns the peer each tick asked (`None` = the
    /// tick emitted nothing).
    fn walk_ticks(n: &mut NablaNode, clock: &mut u64, peers: &[NodeId], genesis: &[NodeId], ticks: usize) -> Vec<Option<NodeId>> {
        let me = [0xAA; 32];
        (0..ticks)
            .map(|_| {
                *clock += crate::constants::RECORD_AE_REPLY_TTL_SECS + 1;
                let out = n.record_ae_tick(me, peers, genesis, *clock);
                assert!(out.len() <= 1, "at most one ask per tick");
                out.first().map(|(p, _)| *p)
            })
            .collect()
    }

    fn ids(tag: u8, count: usize) -> Vec<NodeId> {
        (0..count).map(|i| *blake3::hash(&[tag, i as u8]).as_bytes()).collect()
    }

    /// F-5 ordering — 2 connected genesis peers among 200 Sybil citizens:
    /// EVERY window of 3 consecutive ticks asks both genesis peers (before:
    /// once per ~202 ticks each), citizens are round-robined behind them, and
    /// every tick asks someone.
    /// MUTATION (run 2026-10-01): `record_ae_tick` syncs the walk with `&[]`
    /// for `first` (the ordering removed) ⇒ RED here; the zero-genesis test
    /// below stays GREEN.
    #[test]
    fn f5_genesis_peers_walked_every_window_despite_sybils() {
        let mut n = NablaNode::new();
        let genesis = ids(0x67, 2);
        let mut peers = ids(0xC1, 200);
        peers.extend(&genesis);
        let asked = walk_ticks(&mut n, &mut NOW_SECS.clone(), &peers, &genesis, 60);
        assert!(asked.iter().all(Option::is_some), "no skipped tick: {asked:?}");
        let asked: Vec<NodeId> = asked.into_iter().flatten().collect();
        for (w, window) in asked.chunks(3).enumerate() {
            for g in &genesis {
                assert!(window.contains(g), "window {w}: genesis peer {} not walked", hex::encode(&g[..4]));
            }
        }
        let citizens: std::collections::HashSet<NodeId> =
            asked.iter().filter(|p| !genesis.contains(p)).copied().collect();
        assert_eq!(citizens.len(), 20, "one DISTINCT citizen per window (round-robin, 20 windows)");
    }

    /// F-5 condition (b) — ZERO genesis peers connected (none online, or
    /// pinned ones listed but not connected): the walk is EXACTLY the old R51
    /// `Walk` over the same peers and salt — same order, same churn handling,
    /// one ask every tick (no wait, no failure, no skipped tick).
    #[test]
    fn f5_zero_genesis_connected_is_exactly_the_old_walk() {
        let mut n = NablaNode::new();
        let salt = n.record_ae.salt;
        let peers = ids(0xC2, 7);
        let offline_genesis = ids(0x67, 3); // pinned, not connected
        let mut old = rs::Walk::default();
        let mut want = Vec::new();
        let mut clock = NOW_SECS;
        for (i, gen) in [&[][..], &offline_genesis[..]].iter().enumerate() {
            let got = walk_ticks(&mut n, &mut clock, &peers, gen, 11);
            assert!(got.iter().all(Option::is_some), "pass {i}: a tick asked nobody: {got:?}");
            for _ in 0..11 {
                old.sync(&peers, &salt);
                want.push(old.next());
            }
            assert_eq!(got, want[want.len() - 11..], "pass {i}: the walk differs from the old R51 walk");
        }
        // Churn: one peer leaves — both walks delete it in place identically.
        let fewer = &peers[1..];
        let got = walk_ticks(&mut n, &mut clock, fewer, &[], 9);
        let want: Vec<_> = (0..9).map(|_| { old.sync(fewer, &salt); old.next() }).collect();
        assert_eq!(got, want, "churn handled exactly as the old walk");
    }

    /// F-5 condition (c) — "is genesis" confers ZERO trust: no lib module
    /// that judges (verdict, ban, vouch, grade, answer acceptance) names the
    /// predicate or the pinned array; in the binary its only (non-comment)
    /// readers are the walk partition and the pre-existing emission
    /// ineligibility. `record_ae_tick` receives an id list and hands it ONLY
    /// to `TieredWalk::sync` (the walk) — asserted on its source.
    #[test]
    fn f5_genesis_predicate_confers_no_trust() {
        let pred = concat!("nbc_is_", "pinned_genesis");
        let pinned = concat!("NABLA_GENESIS_", "VALIDATOR_PKS");
        let code = |src: &str| -> Vec<String> {
            src.lines().filter(|l| !l.trim_start().starts_with("//")).map(str::to_owned).collect()
        };
        for (name, src) in [
            ("ban.rs", include_str!("ban.rs")),
            ("provenance.rs", include_str!("provenance.rs")),
            ("smt.rs", include_str!("smt.rs")),
            ("gossip.rs", include_str!("gossip.rs")),
            ("registration.rs", include_str!("registration.rs")),
            ("atraxi.rs", include_str!("atraxi.rs")),
            ("record_sync.rs", include_str!("record_sync.rs")),
            ("vbc_directory.rs", include_str!("vbc_directory.rs")),
            ("node.rs", include_str!("node.rs")),
        ] {
            let hits: Vec<_> = code(src).into_iter().filter(|l| l.contains(pred) || l.contains(pinned)).collect();
            assert!(hits.is_empty(), "{name} reads 'is genesis' on a judging path: {hits:?}");
        }
        let bin: Vec<_> = code(include_str!("bin/nabla_node.rs")).into_iter().filter(|l| l.contains(pred)).collect();
        assert_eq!(bin.len(), 2, "bin readers: the walk partition + emission ineligibility only: {bin:?}");
        assert!(bin.iter().any(|l| l.contains("verified_nbcs")), "the walk partition reads the VERIFIED NBC");
        let node = include_str!("node.rs");
        let body = &node[node.find("pub fn record_ae_tick(").unwrap()..];
        let body = &body[..body.find("\n    }\n").unwrap()];
        assert_eq!(body.matches("genesis").count(), 2, "`genesis` reaches only the walk partition: {body}");
        assert!(body.contains("walk.sync(&first, peers"));
    }
}
