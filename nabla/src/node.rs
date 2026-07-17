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
    /// Forgery attempt (intermediate_emitter doesn't match TCP source).
    /// Drop the alert + bump the offending peer's ban-score.
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
/// All in-memory for Phase B. WAL persistence is a follow-up.
#[derive(Debug, Default, Clone)]
pub struct QuarantineState {
    /// Active quarantines: accused → expiry tick.
    /// Stays accused-keyed (NOT (accused, pool_kind)) — a quarantine
    /// is per-accused, mesh-wide. Conservative direction per Mac's
    /// review §3.5.1.
    active: std::collections::HashMap<NodeId, u64>,
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
    pub fn record_alert(
        &mut self,
        self_node_id: &NodeId,
        accused: NodeId,
        pool_kind: crate::types::PoolKind,
        origin: NodeId,
        intermediate: NodeId,
        current_tick: u64,
        threshold: usize,
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
        if distinct_origins.len() >= threshold && distinct_intermediates.len() >= threshold {
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
        }
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
        let cycle_secs = crate::constants::AIRDROP_CYCLE_SECS;
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
        self.maybe_roll_cycle(current_tick);

        let cycle_resets_at_tick =
            self.cycle_start_tick + crate::constants::AIRDROP_CYCLE_SECS;

        // Layer 1 — per-Nabla cap
        if self.claims_this_cycle >= crate::constants::AIRDROP_CLAIMS_PER_CYCLE_PER_NABLA {
            log::debug!(
                "[POOL-CAP-PER-NABLA] AirdropPool: {} claims this cycle (cap {}), \
                 refusing further claims until cycle reset at tick {}",
                self.claims_this_cycle,
                crate::constants::AIRDROP_CLAIMS_PER_CYCLE_PER_NABLA,
                cycle_resets_at_tick,
            );
            return ClaimOutcome::RefusedPerNablaCap { cycle_resets_at_tick };
        }

        // Layer 2 — mesh-wide cap (measured against this Nabla's view
        // of total_claims, which converges via gossip max-wins).
        let mesh_claims_this_cycle = self.total_claims.saturating_sub(self.mesh_claims_at_cycle_start);
        if mesh_claims_this_cycle >= crate::constants::AIRDROP_MESH_CAP_PER_CYCLE {
            log::debug!(
                "[POOL-CAP-MESH] AirdropPool: mesh has emitted {} claims this cycle (cap {}), \
                 refusing further claims",
                mesh_claims_this_cycle,
                crate::constants::AIRDROP_MESH_CAP_PER_CYCLE,
            );
            return ClaimOutcome::RefusedMeshCap { cycle_resets_at_tick };
        }

        // Existing balance check
        let claim_amount = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;
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
    pub fn reconcile(&mut self, peer_balance: u64, peer_claims: u64) -> ReconcileOutcome {
        let claim_amount = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;

        // ── Layer 1 ── single-observer structural violations.
        if let Some(proof) = crate::judoon::structural_violation(
            peer_balance, peer_claims, self,
        ) {
            log::warn!(
                "[JUDOON/AIRDROP-STRUCTURAL] {:?} peer_balance={} peer_claims={} local_balance={} local_claims={}",
                proof, peer_balance, peer_claims, self.balance, self.total_claims,
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
    fn initial_atoms(&self) -> u64 { crate::constants::AIRDROP_POOL_INITIAL_ATOMS }
    fn total_claims(&self) -> u64 { self.total_claims }
    fn local_claims_this_cycle(&self) -> u64 { self.claims_this_cycle }
    fn mesh_claims_at_cycle_start(&self) -> u64 { self.mesh_claims_at_cycle_start }
    fn claim_amount(&self) -> u64 { axiom_core_logic::types::GENESIS_CLAIM_AMOUNT }
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
            ReconcileOutcome::InvariantViolation {
                peer_balance,
                local_balance: self.balance,
            }
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
    /// Current withdrawable balance in atoms.
    balance: u64,
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
        }
    }

    pub fn from_persisted(state: &PersistedDeedPoolState) -> Self {
        Self {
            balance: state.balance,
            total_credited: state.total_credited,
            last_credit_tick: state.last_credit_tick,
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
        let mut bans = if dev_mode { BanTable::new_dev() } else { BanTable::new() };
        let mut deed_collected = 0u64;
        let mut current_tick = 0u64;
        let mut last_snapshot_tick = 0u64;
        let mut restored_cc: Option<CompanionCertificate> = None;
        let mut restored_wal_checksums: Vec<(u64, [u8; 32])> = Vec::new();
        let mut restored_genesis_fact: Option<Vec<u8>> = None;
        let mut restored_peer_nbcs: Vec<NBC> = Vec::new();

        // 1. Load last snapshot
        let snapshots = SnapshotManager::new(&snap_dir)?;
        if let Some(snapshot) = snapshots.load_latest()? {
            log::info!(
                "Restoring from snapshot: tick={}, entries={}, bans={}",
                snapshot.tick, snapshot.entries.len(), snapshot.bans.len()
            );
            for entry in &snapshot.entries {
                smt.put(entry);
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
            restored_wal_checksums = snapshot.wal_checksums;
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
        }

        // 2. Replay WAL after snapshot
        let wal_ops = WriteAheadLog::read_after_snapshot(&wal_path, last_snapshot_tick)?;
        if !wal_ops.is_empty() {
            log::info!("Replaying {} WAL entries after tick {}", wal_ops.len(), last_snapshot_tick);
        }
        for op in wal_ops {
            match op {
                WalOp::Put { key: _, value, .. } => {
                    if let Ok(entry) = bincode::deserialize::<NablaEntry>(&value) {
                        if entry.tick > current_tick {
                            current_tick = entry.tick;
                        }
                        smt.put(&entry);
                    }
                }
                WalOp::Ban { wallet_id, evidence } => {
                    if let Ok(banned) = bincode::deserialize::<BannedEntry>(&evidence) {
                        // Preserve the ban's ORIGIN on replay. A seq-fork
                        // (double-spend) ban carries its evidence in `seq_fork`,
                        // not the ConflictProof pair — re-banning via the plain
                        // `ban()` path would forget that forensic evidence (the
                        // wallet would stay banned, but the "why" is lost). Restore
                        // the matching ban kind so a post-restart node holds the
                        // same irreversible ban WITH its proof, identical to the
                        // snapshot-restore path (load_from).
                        if let Some(seq_fork) = banned.seq_fork {
                            bans.ban_seq_fork(wallet_id, seq_fork);
                        } else {
                            bans.ban(wallet_id, banned.evidence_1, banned.evidence_2);
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
            }
        }

        let mut wal = WriteAheadLog::open(&wal_path)?;
        // YPX-009 §12: Restore WAL checksums from snapshot for fast audit recovery.
        if !restored_wal_checksums.is_empty() {
            wal.restore_checksums(restored_wal_checksums);
        } else {
            // No snapshot checksums — load from WAL file itself.
            let _ = wal.load_checksums();
        }

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

        log::info!(
            "Nabla node ready: entries={}, bans={}, tick={}, root={:?}",
            smt.len(), bans.len(), current_tick, &smt.root_hash()[..4]
        );

        Ok(Self {
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
            deed_pool,
            validator_net_ledger,
            dev_deed_pool,
            validator_dev_net_ledger,
            quarantine: QuarantineState::new(),
            current_tick, deed_collected, data_dir, last_snapshot_tick,
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
        })
    }

    /// Lightweight constructor for unit tests — creates a temp dir internally.
    #[cfg(test)]
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("nabla_test_{}", rand::random::<u64>()));
        NablaNode::open(&dir, Box::new(crate::crypto::NoopSigner)).unwrap()
    }

    /// Process a registration request.
    /// Returns ack + gossip message for the network layer to forward.
    pub fn register(
        &mut self,
        reg: &Registration,
        deed_tx: &DeedTransaction,
    ) -> Result<RegisterResult, NablaError> {
        let quarantined: Vec<WalletId> = self.tardis.as_ref()
            .filter(|t| t.is_in_quarantine())
            .map(|t| t.forked_wallets().to_vec())
            .unwrap_or_default();
        let result = registration::process_registration(
            &mut self.smt, &mut self.wal, &mut self.bans,
            reg, deed_tx, self.current_tick, &mut self.deed_collected,
            self.signer.as_ref(),
            Some(&mut self.airdrop_pool),
            Some(&mut self.dev_treasury_pool),
            Some(&mut self.deed_pool),
            Some(&mut self.validator_net_ledger),
            Some(&mut self.dev_deed_pool),
            Some(&mut self.validator_dev_net_ledger),
            &quarantined,
        )?;
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
        query::process_query(&self.smt, wallet_id, self.current_tick, self.signer.as_ref())
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
    pub fn handle_gossip(&mut self, msg: &GossipMessage) -> GossipAction {
        self.gossip_latency.observe(msg, self.current_tick);
        // KI#28 rate detector needs the mesh-size estimate; fall back to 1
        // (self-disables anyway below the sample gate) when mesh is unset.
        let n_validators = self.mesh.as_ref()
            .map(|m| m.estimated_network_size())
            .unwrap_or(1);
        let action = self.gossip.process(
            msg, &mut self.smt, &mut self.bans, &mut self.oracle_pool,
            &mut self.airdrop_pool, &mut self.dev_treasury_pool,
            &mut self.deed_pool,
            &mut self.dev_deed_pool,
            self.signer.as_ref(), self.current_tick,
            n_validators,
        );
        // Persist on PoolSync that mutated state. Both pools rebuilt
        // identically from disk on next boot — we save both to keep
        // logic simple (writes are cheap; bounded by claim rate which
        // is very low).
        if matches!(msg, GossipMessage::PoolSync { .. })
            && matches!(action, GossipAction::Forward(_))
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
        if let GossipMessage::Recall { txid, sender_pk, recall_tick, committed: true } = msg {
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
    fn persist_pool_states(&self) -> std::io::Result<()> {
        let tick = self.current_tick;
        self.airdrop_pool
            .to_persisted(tick)
            .save(&self.data_dir.join(crate::types::PoolKind::Airdrop.state_filename()))?;
        self.dev_treasury_pool
            .to_persisted(tick)
            .save(&self.data_dir.join(crate::types::PoolKind::DevTreasury.state_filename()))?;
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
        Ok(())
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
    pub fn gossip_latency(&self) -> GossipLatencySnapshot {
        self.gossip_latency.snapshot()
    }

    /// Advance tick (TARDIS delivers a new tick).
    pub fn advance_tick(&mut self, tick: u64) {
        self.current_tick = tick;
        if tick - self.last_snapshot_tick >= SNAPSHOT_INTERVAL_TICKS {
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
        let snapshot = NablaSnapshot {
            tick: self.current_tick,
            root_hash: self.smt.root_hash(),
            entries: self.smt.entries().values().cloned().collect(),
            bans: self.bans.all(),
            deed_collected: self.deed_collected,
            latest_cc: self.cc_chain.as_ref().and_then(|c| c.latest().cloned()),
            wal_checksums: self.wal.checksums_snapshot(),
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

        // Trigger snapshot if needed
        if self.current_tick - self.last_snapshot_tick >= SNAPSHOT_INTERVAL_TICKS {
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

    /// Handle an audit request from a downstream node.
    pub fn handle_audit_request(&self, request: &SubtreeAuditRequest) -> Option<TardisAction> {
        let tardis = self.tardis.as_ref()?;
        Some(tardis.handle_audit_request(request, &self.smt, self.signer.as_ref()))
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
    pub fn maybe_audit(&self) -> Option<TardisAction> {
        let tardis = self.tardis.as_ref()?;
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
        self.mesh = Some(GossipMesh::new(node_id, address));
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
        self.mesh = Some(mesh);
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
        let (balance, total_claims) = match pool {
            crate::types::PoolKind::Airdrop => {
                (self.airdrop_pool.balance(), self.airdrop_pool.total_claims)
            }
            crate::types::PoolKind::DevTreasury => {
                (self.dev_treasury_pool.balance(), self.dev_treasury_pool.total_claims)
            }
            crate::types::PoolKind::Deed => {
                // `total_claims` on the wire carries `total_credited` for
                // the DEED pool — the same lifetime-counter role the
                // claims counter plays for airdrop/dev_treasury.
                (self.deed_pool.balance(), self.deed_pool.total_credited())
            }
            crate::types::PoolKind::DevDeed => {
                // Dev-class DEED — same monotonic-increase wire shape as
                // the public DEED, but a distinct sign_tag (0x04) so the
                // gossip payload binds the class. A peer that receives
                // a DevDeed PoolSync with a Deed sign_tag fails the
                // signature verify and the alert layer flags it.
                (self.dev_deed_pool.balance(), self.dev_deed_pool.total_credited())
            }
        };
        let tick = self.current_tick;
        let sender_node_id: NodeId = self
            .mesh
            .as_ref()
            .map(|m| *m.my_node_id())
            .unwrap_or([0u8; 32]);
        let payload = crate::crypto::pool_sync_sign_payload(
            pool.sign_tag(), balance, total_claims, tick, &sender_node_id,
        );
        let sender_sig = self.signer.sign(&payload);
        crate::types::GossipMessage::PoolSync {
            pool,
            balance,
            total_claims,
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
        crate::types::GossipMessage::Alert {
            alert_type: crate::types::AlertType::PoolInvariantViolation,
            accused,
            evidence,
            origin_emitter: self_id,
            intermediate_emitter: self_id,
            emitted_at_tick: self.current_tick,
        }
    }

    /// Handle an incoming `GossipMessage::Alert` from peer `sender_id`.
    /// `sender_id` is the NBC-verified TCP source (the caller validated
    /// it before calling us). Returns the action the caller should take:
    /// drop, forward, or also act on a triggered quarantine.
    pub fn handle_alert(
        &mut self,
        alert: &crate::types::GossipMessage,
        sender_id: NodeId,
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

        // §5.6.4 step 1: verify intermediate_emitter == TCP source.
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
            return AlertHandleAction::DropAndBanScore { peer: sender_id };
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
        );

        match outcome {
            AlertRecordOutcome::Duplicate => AlertHandleAction::Drop,
            AlertRecordOutcome::SelfOrigin => {
                log::warn!(
                    "[ALERT-SELF-ORIGIN] from sender={} claimed origin=self — drop",
                    hex::encode(&sender_id[..8]),
                );
                AlertHandleAction::DropAndBanScore { peer: sender_id }
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

        let mut status = NodeStatusSnapshot {
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
            deed_collected: self.deed_collected,
            deed_split: deed_split_str,
            deed_pool_balance: self.deed_pool.balance(),
            deed_pool_total_credited: self.deed_pool.total_credited(),
            dev_deed_pool_balance: self.dev_deed_pool.balance(),
            dev_deed_pool_total_credited: self.dev_deed_pool.total_credited(),
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
            // Phase B Layer 4: quarantine telemetry.
            quarantine_active_count: self.quarantine.active_count(),
            quarantine_pending_count: self.quarantine.pending_count(),
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
    pub fn smt_mut(&mut self) -> &mut SparseMerkleTree { &mut self.smt }

    /// Apply a wallet entry received from a peer via anti-entropy
    /// (`AeReconcile.push` / `AeEntries`). Verifies the client signature
    /// and applies the §5.2 merge rule — returns true if the local SMT
    /// advanced. Never adopts unsigned, banned, or non-superseding state.
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
    pub fn apply_remote_entry(
        &mut self,
        entry: &NablaEntry,
        seq_proof: Option<&crate::types::SeqProof>,
    ) -> bool {
        // Structurally empty — never adopt.
        if entry.current_state == [0u8; 32] || entry.tick == 0 {
            return false;
        }
        if self.bans.is_banned(&entry.wallet_id) {
            return false;
        }
        // Verify the client signature when one is present. A zero client_pk
        // is the legacy / pre-YPX-009 path: the gossip flood
        // (`apply_state_update`) admits those entries unverified, so
        // anti-entropy must too — it only replicates what gossip already
        // accepted into the mesh. Being stricter than the flood path would
        // wedge every zero-pk wallet permanently divergent. Tightening this
        // belongs at the gossip layer (YPX-009 enforcement), where both
        // paths would then reject consistently.
        if entry.client_pk != [0u8; 32]
            && !crate::gossip::verify_client_state_sig(
                &entry.client_pk,
                &entry.client_sig,
                &entry.wallet_id,
                &entry.current_state,
                &entry.tx_hash,
                entry.tick,
            )
        {
            return false;
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
        let seq_attested = seq_proof
            .is_some_and(|p| crate::registration::verify_seq_proof(p, &entry.tx_hash, entry.wallet_seq));
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
        let superseding = match self.smt.get(&entry.wallet_id) {
            Some(existing) => existing.superseded_by(entry),
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
            // `put` structurally drops any proof bound to the superseded head's
            // tx_hash (KI#38 lock-step); we re-establish one only when this adopt
            // carried a verified proof for the NEW head.
            self.smt.put(entry);
            if seq_attested {
                // Retain the verified proof so this node can in turn re-attest the
                // seq when it serves the head to another AE peer.
                self.smt.set_seq_proof(entry.wallet_id, seq_proof.unwrap().clone());
            }
        }
        superseding
    }
    pub fn bans(&self) -> &BanTable { &self.bans }
    pub fn bans_mut(&mut self) -> &mut BanTable { &mut self.bans }
    pub fn gossip(&self) -> &GossipEngine { &self.gossip }
    pub fn gossip_mut(&mut self) -> &mut GossipEngine { &mut self.gossip }
    pub fn signer(&self) -> &dyn Signer { self.signer.as_ref() }
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

    // ── S6: Ban Challenge Protocol ──

    /// Challenge a ban. Resolves borrow conflict between bans_mut() and signer().
    pub fn challenge_ban(
        &mut self,
        wallet_id: &WalletId,
        evidence: ChallengeEvidence,
        current_tick: u64,
    ) -> Result<(), NablaError> {
        self.bans.challenge(wallet_id, evidence, current_tick, self.signer.as_ref())
    }

    // ── §32 Merge Protocol ──

    /// Process fork evidence: freeze the forked wallet and propagate taint.
    /// Returns gossip messages to flood (TaintAlert for downstream wallets).
    pub fn handle_fork_evidence(
        &mut self,
        wallet_id: &WalletId,
        detected_at_tick: u64,
    ) -> Vec<GossipMessage> {
        let mut gossip = Vec::new();
        // Phase 1: FREEZE the forked wallet immediately
        TardisNode::freeze_wallet(&mut self.smt, wallet_id);
        // Enter quarantine, recording which wallet triggered it
        if let Some(tardis) = self.tardis.as_mut() {
            tardis.enter_merge_quarantine(Some(*wallet_id));
        }
        // Phase 2: Find tainted downstream wallets
        let tainted = TardisNode::propagate_taint(&self.smt, &[*wallet_id]);
        for tainted_wid in &tainted {
            if tainted_wid != wallet_id {
                TardisNode::freeze_wallet(&mut self.smt, tainted_wid);
                gossip.push(GossipMessage::TaintAlert {
                    wallet_id: *tainted_wid,
                    tainted_source: *wallet_id,
                    detected_at_tick,
                });
            }
        }
        gossip
    }

    /// Process a taint alert: freeze the tainted wallet.
    pub fn handle_taint_alert(&mut self, wallet_id: &WalletId) {
        TardisNode::freeze_wallet(&mut self.smt, wallet_id);
    }

    /// Check and resolve merge quarantine if expired (Phase 3: RESUME).
    ///
    /// Forked wallets (double-spend source) → BANNED permanently.
    /// Tainted wallets (innocent downstream) → restored to Normal.
    /// Their FACT links from tainted inputs remain scarred (no nabla_confirmation).
    ///
    /// NOTE(review): This policy spares innocent downstream wallets. If a downstream
    /// wallet colluded with the forker, they keep ill-gotten gains. The mitigation is
    /// that scarred FACT links remain unresolved — the downstream must burn or heal them.
    /// Revisit once production data shows whether collusion is a real concern.
    ///
    /// Returns (banned_wallets, restored_wallets).
    pub fn check_merge_quarantine(&mut self) -> (Vec<WalletId>, Vec<WalletId>) {
        let expired = self.tardis.as_mut()
            .is_some_and(|t| t.check_quarantine_expiry());
        if !expired {
            return (Vec::new(), Vec::new());
        }
        // Log which wallets triggered quarantine (diagnostic only)
        if let Some(tardis) = self.tardis.as_ref() {
            let forked = tardis.forked_wallets();
            if !forked.is_empty() {
                for wid in forked {
                    log::info!("§32 RESUME: fork trigger was {:02x}{:02x}...", wid[0], wid[1]);
                }
            }
        }
        // Split: Frozen = forked source (→ BANNED), Tainted = downstream victim (→ Normal)
        let forked: Vec<WalletId> = self.smt.entries().values()
            .filter(|e| matches!(e.status, WalletStatus::Frozen))
            .map(|e| e.wallet_id)
            .collect();
        let tainted: Vec<WalletId> = self.smt.entries().values()
            .filter(|e| matches!(e.status, WalletStatus::Tainted))
            .map(|e| e.wallet_id)
            .collect();
        let banned = TardisNode::resolve_merge(&mut self.smt, &forked, &tainted);
        let restored = tainted; // All tainted wallets were restored to Normal
        // Clear quarantine state
        if let Some(tardis) = self.tardis.as_mut() {
            tardis.clear_forked_wallets();
        }
        (banned, restored)
    }

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
        });
        self.smt.put(entry);
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
            evidence_1: evidence_1.clone(),
            evidence_2: evidence_2.clone(),
            seq_fork: None,
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
            evidence_1: crate::types::ConflictProof::default(),
            evidence_2: crate::types::ConflictProof::default(),
            seq_fork: Some(evidence.clone()),
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
            is_recall: false,
            wallet_id, old_state, new_state, tx_hash,
            receipt: K3Receipt {
                oods_flag: None,
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
            partial_bridge: None,
            claimant_wallet_id: String::new(),
            is_dev_claim: false,
            burn_target_tx_id: None,
        };
        let deed = DeedTransaction {
            sender_wallet_id: wallet_id,
            receiver_wallet_id: DEED_PROTOCOL_WALLET_ID,
            amount: crate::constants::DEED_WRITE_FEE,
            signature: vec![0xFF; 64],
        };
        (reg, deed)
    }

    #[test]
    fn node_open_empty() {
        let dir = tempfile::tempdir().unwrap();
        let node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert_eq!(node.entry_count(), 0);
        assert_eq!(node.ban_count(), 0);
        assert_eq!(node.deed_collected(), 0);
    }

    #[test]
    fn node_register_and_query() {
        let dir = tempfile::tempdir().unwrap();
        let mut node = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();

        let (reg, deed) = make_valid_reg(0xAA, 0x00, 0x01);
        let result = node.register(&reg, &deed).unwrap();
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

        let (reg, deed) = make_valid_reg(0xBB, 0x00, 0x01);
        let result = node.register(&reg, &deed).unwrap();

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
            node.advance_tick(100);
            for i in 0..5u8 {
                let (reg, deed) = make_valid_reg(i, 0x00, i + 1);
                node.register(&reg, &deed).unwrap();
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
            node.advance_tick(100);
            for i in 0..5u8 {
                let (reg, deed) = make_valid_reg(i, 0x00, i + 1);
                node.register(&reg, &deed).unwrap();
            }
            node.take_snapshot().unwrap();
            // These 3 are only in WAL
            for i in 5..8u8 {
                let (reg, deed) = make_valid_reg(i, 0x00, i + 1);
                node.register(&reg, &deed).unwrap();
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
                .register_recall(recalled, vec![0xAA; 32], 40 + crate::smt::RECALL_INIT_WINDOW_LOW.to_secs() + 1)
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
            let action = node.handle_gossip(&GossipMessage::Recall {
                txid,
                sender_pk: vec![0xAB; 32],
                recall_tick: 90,
                committed: true,
            });
            assert!(matches!(action, GossipAction::Forward(_)), "fresh recall must apply");
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

        let mut wid = [0u8; 32];
        wid[0] = 0xCC;
        let mut state = [0u8; 32];
        state[0] = 0x01;

        let msg = GossipMessage::StateUpdate {
                      wallet_seq: 0,
            seq_proof: None,
            wallet_id: wid, new_state: state, tx_hash: [0xDD; 32], tick: 5,
            is_genesis_claim: false,
            client_pk: [0u8; 32], client_sig: vec![0u8; 64],
            amount: 0, fee_breakdown: Vec::new(),
        };

        let action = node.handle_gossip(&msg);
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

        let (reg1, deed1) = make_valid_reg(0xAA, 0x00, 0x01);
        node.register(&reg1, &deed1).unwrap();

        let (reg2, deed2) = make_valid_reg(0xAA, 0x00, 0x02);
        let result = node.register(&reg2, &deed2);

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
                oods_flag: None,
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

        let e = |state: u8, tick: u64, tx: u8| crate::types::NablaEntry {
                                                   wallet_seq: 0,
            wallet_id: [0x77; 32],
            current_state: [state; 32],
            tx_hash: [tx; 32],
            tick,
            group_members: None,
            status: crate::types::WalletStatus::Normal,
            client_pk: [0u8; 32], // zero pk → sig check skipped (legacy gossip path)
            client_sig: vec![],
        };

        // Advance X → Y, so X becomes consumed on this node.
        assert!(node.apply_remote_entry(&e(0x11, 1, 1), None), "adopt X");
        assert!(node.apply_remote_entry(&e(0x22, 2, 2), None), "adopt Y (consumes X)");

        // A HIGHER-tick re-advertisement of the consumed state X must be
        // REJECTED. Pre-fix it won superseded_by on tick and rolled the head
        // back to X.
        assert!(
            !node.apply_remote_entry(&e(0x11, 999, 3), None),
            "§5.4: re-advertising consumed state X as head must be rejected"
        );

        // Control: a genuine forward step to a fresh state is still adopted.
        assert!(
            node.apply_remote_entry(&e(0x33, 4, 4), None),
            "a fresh forward state must still be adopted (no false-reject)"
        );
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
        let wid = [0x77u8; 32];

        let mint = |txid: &[u8; 32], seq: u64, n: usize| -> crate::types::SeqProof {
            let (state_hash, commitment_hash, epoch, dev) = ([0x5au8; 32], [0x7cu8; 32], 7u64, false);
            let c = axiom_core_logic::compute::compute_receipt_commitment(
                txid, &state_hash, seq, &commitment_hash, epoch, dev, None,
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
            crate::types::SeqProof { state_hash, commitment_hash, epoch, is_dev_class: dev, oods_flag: None, sigs }
        };
        let mk = |state: u8, tx: [u8; 32], tick: u64, seq: u64| crate::types::NablaEntry {
            wallet_seq: seq,
            wallet_id: wid,
            current_state: [state; 32],
            tx_hash: tx,
            tick,
            group_members: None,
            status: crate::types::WalletStatus::Normal,
            client_pk: [0u8; 32], // zero pk → client-sig check skipped
            client_sig: vec![],
        };

        // Honest head Y at seq=5 WITH a valid k=3 proof → adopted (advance 0→5).
        let txid_y = [0xA1u8; 32];
        assert!(
            node.apply_remote_entry(&mk(0x22, txid_y, 10, 5), Some(&mint(&txid_y, 5, 3))),
            "honest proven advance must adopt"
        );
        assert_eq!(node.smt().get(&wid).unwrap().wallet_seq, 5);

        // Attacker fork X' at a self-stamped seq=99 with NO proof → REJECTED.
        assert!(
            !node.apply_remote_entry(&mk(0x33, [0xB2u8; 32], 99, 99), None),
            "unproven seq-advance must be rejected (no rollback to a forged head)"
        );
        assert_eq!(node.smt().get(&wid).unwrap().current_state[0], 0x22, "head unchanged");

        // Same, but with a sub-quorum (k=2) forged proof → still rejected.
        assert!(
            !node.apply_remote_entry(&mk(0x44, [0xC3u8; 32], 99, 99), Some(&mint(&[0xC3u8; 32], 99, 2))),
            "sub-quorum proof must not pass the gate"
        );
        assert_eq!(node.smt().get(&wid).unwrap().current_state[0], 0x22);

        // Control: an honest advance Z at seq=6 WITH a valid proof → adopted, and
        // the verified proof is retained so this node can re-attest on AE.
        let txid_z = [0xD4u8; 32];
        assert!(
            node.apply_remote_entry(&mk(0x55, txid_z, 11, 6), Some(&mint(&txid_z, 6, 3))),
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
        let wid = [0x88u8; 32];

        let mint = |txid: &[u8; 32], seq: u64, n: usize| -> crate::types::SeqProof {
            let (state_hash, commitment_hash, epoch, dev) = ([0x5au8; 32], [0x7cu8; 32], 7u64, false);
            let c = axiom_core_logic::compute::compute_receipt_commitment(
                txid, &state_hash, seq, &commitment_hash, epoch, dev, None,
            );
            let sigs = (0..n).map(|i| {
                let sk = SigningKey::from_bytes(&[0x30 + i as u8; 32]);
                crate::types::SeqProofSig {
                    validator_pk: sk.verifying_key().to_bytes(),
                    receipt_commitment_sig: sk.sign(&c).to_bytes().to_vec(),
                }
            }).collect();
            crate::types::SeqProof { state_hash, commitment_hash, epoch, is_dev_class: dev, oods_flag: None, sigs }
        };
        let mk = |state: u8, tx: [u8; 32], tick: u64, seq: u64| crate::types::NablaEntry {
            wallet_seq: seq, wallet_id: wid, current_state: [state; 32], tx_hash: tx,
            tick, group_members: None, status: crate::types::WalletStatus::Normal,
            client_pk: [0u8; 32], client_sig: vec![],
        };

        // Adopt head Z@seq=6 with a valid proof → proof retained.
        let txid_z = [0xE1u8; 32];
        assert!(node.apply_remote_entry(&mk(0x22, txid_z, 10, 6), Some(&mint(&txid_z, 6, 3))));
        assert!(node.smt().seq_proof(&wid).is_some(), "valid proof retained");

        // Equal-seq (6) tiebreaker: higher tick, different tx_hash, NO proof → wins
        // merge, adopts the new head, and MUST clear the now-stale proof.
        let txid_w = [0xE2u8; 32];
        assert!(node.apply_remote_entry(&mk(0x33, txid_w, 20, 6), None), "equal-seq higher-tick adopt");
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
        let wid = [0x99u8; 32];
        let x = [0xA0u8; 32]; // the spent state HAL would try to revive
        let y = [0xA1u8; 32]; // the live head after X→Y
        let entry = |state: [u8; 32], tick: u64| NablaEntry {
            wallet_seq: 0, // tick-path advance (seq unchanged) — exercises the consume-once gate, not the seq gate
            wallet_id: wid,
            current_state: state,
            tx_hash: [tick as u8; 32],
            tick,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: [0u8; 32], // zero pk → client-sig check skipped (soak's zero-pk path)
            client_sig: vec![],
        };

        // ── Node A: honest, never wiped. Advances X→Y, so X is consumed. ──
        let dir_a = tempfile::tempdir().unwrap();
        let mut a = NablaNode::open(dir_a.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert!(a.apply_remote_entry(&entry(x, 1), None), "a adopts X");
        assert!(a.apply_remote_entry(&entry(y, 2), None), "a adopts Y (X consumed)");
        assert!(a.smt().is_state_consumed(&x), "a knows X is consumed");
        assert_eq!(a.smt().previous_state(&wid), Some(x), "a remembers prev=X");

        // ── Node B: WIPED, then recovers. Head Y + WI1 re-arm from A. ──
        let dir_b = tempfile::tempdir().unwrap();
        let mut b = NablaNode::open(dir_b.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert!(b.apply_remote_entry(&entry(y, 2), None), "b recovers head Y from the mesh");
        // WI1: re-arm consume-once memory from an honest peer's snapshots.
        b.smt_mut().merge_consumed_bloom(&a.smt().consumed_bloom_bytes()).unwrap();
        b.smt_mut().merge_previous_states(&a.smt().previous_states_snapshot());
        assert!(b.smt().is_state_consumed(&x), "WI1: b is re-armed — knows X consumed");
        assert_eq!(b.smt().previous_state(&wid), Some(x), "WI1: b recovered prev=X");

        // KI#34 core assertion: the recovered node REJECTS the revival rollback.
        assert!(
            !b.apply_remote_entry(&entry(x, 999), None),
            "KI#34: a WI1-recovered node must REJECT the HAL-style rollback to consumed X"
        );
        assert_eq!(b.smt().get(&wid).unwrap().current_state, y, "b head stays Y");

        // ── Node C: WIPED, recovers head ONLY (no WI1). Proves WI1 is load-bearing. ──
        let dir_c = tempfile::tempdir().unwrap();
        let mut c = NablaNode::open(dir_c.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        assert!(c.apply_remote_entry(&entry(y, 2), None), "c recovers head Y (no consume-once re-arm)");
        assert!(!c.smt().is_state_consumed(&x), "c is blind — never re-armed");
        assert!(
            c.apply_remote_entry(&entry(x, 999), None),
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

        let action = node.handle_gossip(&msg);
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

        let (reg, deed) = make_valid_reg(0xEE, 0x00, 0x01);
        node.register(&reg, &deed).unwrap();

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
        let nbc = make_test_nbc(0xAA);
        node.init_cc(nbc);
        node.advance_tick(1);

        // Register some wallets
        let (reg, deed) = make_valid_reg(0x01, 0x00, 0x01);
        node.register(&reg, &deed).unwrap();
        node.cc_record_registration();

        let (reg2, deed2) = make_valid_reg(0x02, 0x00, 0x01);
        node.register(&reg2, &deed2).unwrap();
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

        let status = node.status_snapshot();
        assert!(status.tardis_active);
        assert!(status.mesh_active);
        assert!(status.cc_active);
        assert_eq!(status.mesh_peer_count, 9);
        assert!(status.healthy);
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
        node.mesh_apply_topology(&TopologyHint::SlotAvailable {
            node_id: pk(5),
            address: make_addr(5),
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
            address: make_addr(0x50),
        });

        let action = node.handle_gossip(&msg);
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

        let action = node.handle_gossip(&msg);
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
        node.register(&reg, &deed).unwrap();

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
        node.init_tardis(pk(0xAA));
        node.tardis_mut().unwrap().set_upstream(pk(0xBB));

        // Register some data so SMT has a non-empty root
        let (reg, deed) = make_valid_reg(0xDD, 0x00, 0x01);
        node.register(&reg, &deed).unwrap();

        // Simulate: upstream has same data, responds with matching root
        let our_root = node.root_hash();
        let response = SubtreeAuditResponse {
            prefix: vec![0xA3],
            prefix_bits: 8,
            subtree_hash: [0; 32],
            root_hash: our_root,
            response_tick: 0,
            responder_pk: pk(0xBB),
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
            node.register(&reg1, &deed1).unwrap();
            ban_wid = reg1.wallet_id;
            let evidence_1 = crate::types::ConflictProof {
                old_state: reg1.old_state,
                new_state: reg1.new_state,
                tx_hash: reg1.tx_hash,
                k3_signatures: Vec::new(),
                tick: 0,
            };
            let evidence_2 = crate::types::ConflictProof {
                old_state: reg1.old_state,
                new_state: [0x02u8; 32],
                tx_hash: [0xFAu8; 32],
                k3_signatures: Vec::new(),
                tick: 0,
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
            oods_flag: None,
            state_hash: [seed; 32],
            commitment_hash: [seed ^ 0xFF; 32],
            epoch: 7,
            is_dev_class: false,
            sigs: Vec::new(),
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
            assert_eq!(restored.seq_fork.as_ref(), Some(&evidence),
                "seq-fork evidence must survive WAL replay, not downgrade to a plain ban");
        }
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
                let mut wid = [0u8; 32];
                wid[0] = i;
                let entry = NablaEntry {
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
                let mut wid = [0u8; 32];
                wid[0] = i;
                let entry = NablaEntry {
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
            let gossip_msg = GossipMessage::StateUpdate {
                                 wallet_seq: 0,
                seq_proof: None,
                wallet_id: wallet_ids[*i as usize],
                new_state: [*i + 10; 32],
                tx_hash: [*i + 20; 32],
                tick: (*i as u64) * 10,
            is_genesis_claim: false,
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
                amount: 0,
                fee_breakdown: Vec::new(),
            };
            let action = node.handle_gossip(&gossip_msg);
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
            let _ = a.reconcile(b.balance(), b.total_claims);
            let _ = b.reconcile(a.balance(), a.total_claims);
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
            let mut nodes: Vec<AirdropPool> = (0..n).map(|_| AirdropPool::new(initial)).collect();
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
                            let min_bal = nodes.iter().map(|x| x.balance()).min().unwrap();
                            let max_claims = nodes.iter().map(|x| x.total_claims).max().unwrap();
                            for node in nodes.iter_mut() { let _ = node.reconcile(min_bal, max_claims); }
                            since_gossip = 0;
                        }
                    }
                }
                // converge + roll the cycle so the per-node cap doesn't cap the
                // drain before the balance does (we are measuring balance-level).
                let min_bal = nodes.iter().map(|x| x.balance()).min().unwrap();
                let max_claims = nodes.iter().map(|x| x.total_claims).max().unwrap();
                for node in nodes.iter_mut() { let _ = node.reconcile(min_bal, max_claims); }
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
        let outcome = pool.reconcile(balance, claims_before + bound + 1);
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
        let outcome = pool.reconcile(balance, claims_before + 1);
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
                tick: 100,
                sender_node_id: [0u8; 32],
                sender_sig: Vec::new(),
            };
            let _action = node.handle_gossip(&msg);
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
            tick: 100,
            sender_node_id: [0u8; 32],
            sender_sig: Vec::new(),
        };
        let action = node.handle_gossip(&stale);
        // Phase B: a "higher peer balance" gossip is now treated as a
        // direction-violation (InvariantViolation), promoted to
        // PoolViolationDetected so the binary can build + broadcast a
        // Layer 4 Alert against the sender. Either way, the local
        // balance must NOT change.
        assert!(
            matches!(action,
                GossipAction::Duplicate
                | GossipAction::PoolViolationDetected { .. }),
            "stale/higher-balance PoolSync must be dropped (Duplicate or PoolViolationDetected); got {:?}",
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
            tick: 100,
            sender_node_id: [0u8; 32],
            sender_sig: Vec::new(),
        };
        let action = node.handle_gossip(&stale);
        assert!(
            matches!(action,
                GossipAction::Duplicate
                | GossipAction::PoolViolationDetected { .. }),
            "stale dev-treasury PoolSync must be dropped (Duplicate or PoolViolationDetected); got {:?}",
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
    #[test]
    fn quarantine_a1_single_attacker_fake_origins_blocked() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let accused = nid(0xCC);
        let m = nid(0xBB);
        // M emits 3 alerts with origins=B,D,E all coming via M
        let r1 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x01), m, 1000, 3);
        let r2 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x02), m, 1001, 3);
        let r3 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x03), m, 1002, 3);
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
        let r1 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, m, nid(0xD1), 1000, 3); // via Q
        let r2 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, m, nid(0xD2), 1001, 3); // via R
        let r3 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, m, nid(0xD3), 1002, 3); // via S
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
        let r1 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, origin, nid(0xD1), 1000, 3);
        let r2 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, origin, nid(0xD2), 1005, 3); // replay
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
        let _ = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0xB1), nid(0xB1), 1000, 3);
        let _ = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0xB2), nid(0xB2), 1001, 3);
        let r = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0xB3), nid(0xB3), 1002, 3);
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
        let r1 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x01), nid(0x01), 1000, 3);
        let r2 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x02), nid(0x02), 1001, 3);
        let r3 = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x03), nid(0x03), 1002, 3);
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
        let r = q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, me, me, 1000, 3);
        assert!(matches!(r, AlertRecordOutcome::SelfOrigin));
    }

    /// Self-accused: don't propagate accusations against ourselves.
    #[test]
    fn quarantine_self_accused_recorded_not_propagated() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let r = q.record_alert(&me, me, crate::types::PoolKind::Airdrop, nid(0xBB), nid(0xBB), 1000, 3);
        assert!(matches!(r, AlertRecordOutcome::SelfAccused));
    }

    /// Quarantine expires after the configured TTL.
    #[test]
    fn quarantine_expires_after_ttl() {
        let mut q = QuarantineState::new();
        let me = nid(0xA0);
        let accused = nid(0xCC);
        // Trigger quarantine with 3 attackers
        q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x01), nid(0x01), 1000, 3);
        q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x02), nid(0x02), 1000, 3);
        q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x03), nid(0x03), 1000, 3);
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
        q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x01), nid(0x01), 1000, 3);
        q.record_alert(&me, accused, crate::types::PoolKind::Airdrop, nid(0x02), nid(0x02), 1000, 3);
        assert_eq!(q.pending_count(), 1, "1 bucket for accused");
        // Sweep at well past the window — bucket should drop
        let window_secs = crate::constants::ALERT_CONSENSUS_WINDOW_TICKS
            * crate::constants::TICK_INTERVAL_SECS;
        q.sweep(1000 + window_secs + 1);
        assert_eq!(q.pending_count(), 0, "stale pending bucket swept");
    }
}
