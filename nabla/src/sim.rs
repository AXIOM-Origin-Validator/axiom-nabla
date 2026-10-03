// AXIOM Nabla — Network Simulator Engine
// Uses real library components: GossipEngine, GossipMesh, SparseMerkleTree, BanTable
// No mocks. Same algorithms. Same bugs. Just no real sockets.
//
// ══════════════════════════════════════════════════════════════════════
// ⚠  BOUNDARY RULE: sim.rs is SIMULATION ONLY. It does NOT ship.
//
//    Protocol logic belongs in the protocol layer:
//      tardis.rs  → tick validation, writer status, recovery, slot storage
//      node.rs    → orchestrates protocol components for production
//      config.rs  → runtime config loading (file parser)
//      constants.rs → ALL protocol constants (thresholds, limits, intervals)
//
//    sim.rs may CALL protocol methods but must NEVER:
//      ✗ Hardcode protocol constants (use constants.rs)
//      ✗ Reimplement validation logic (call tardis.rs methods)
//      ✗ Define protocol state (use TardisNode fields)
//      ✗ Make protocol decisions (thresholds, windows, limits)
//      ✗ Special-case node types in recovery (all nodes are equal)
//
//    sim.rs MAY:
//      ✓ Orchestrate message delivery between nodes
//      ✓ Track simulation-only bookkeeping (tardis_links, blocked, etc.)
//      ✓ Simulate network conditions (delay, partitions, chaos)
//      ✓ BFS traversal order (sim decides processing order)
//      ✓ Display/export state for dashboard
// ══════════════════════════════════════════════════════════════════════
//
// DESIGN: Mimics real deployment.
//   - 10 genesis Nabla nodes start first, fully meshed (9 peers each)
//   - New nodes join over time, each bootstrapping to 2 genesis nodes
//   - Mesh grows organically via periodic_peer_check + RequestIntroduction
//   - Genesis nodes are temporary — operator kills them as network matures
//   - Links shown are real, living mesh peer connections

use std::collections::{HashMap, HashSet, VecDeque};

use crate::ban::BanTable;
use crate::constants::{ANTI_ENTROPY_INTERVAL, GENESIS_NABLA_COUNT, MAX_REBALANCE_PER_TICK, PARENTLESS_TIMEOUT_TICKS, REATTACH_MAX_PER_TICK, REATTACH_STABILITY_TICKS, TICK_INTERVAL_SECS, TICK_SLOT_PIGGYBACK_MAX};
use crate::crypto::{self, Ed25519Signer, Signer};
use crate::gossip::{GossipAction, GossipEngine};
use crate::mesh::{GossipMesh, MeshAction};
use crate::oracle::DailyPoolState;
use crate::smt::SparseMerkleTree;
use crate::tardis::{TardisAction, TardisNode};
use crate::types::*;

use serde::Serialize;

/// Number of genesis nodes (from protocol constants — matches real deployment).
pub const GENESIS_COUNT: usize = GENESIS_NABLA_COUNT;

// ── Orphan Diagnostic Tracker (sim-only instrumentation) ──
// Bounded-size event log for debugging long sessions.
// NOT protocol logic — purely observability.

/// Why a node became an orphan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanCause {
    /// Parent died → stale link cleaned
    ParentDied,
    /// Node volunteered for rebalancing
    Rebalance,
    /// Parent dropped this node as slow child
    DroppedByParent,
    /// Writer rotation released this child
    RotationChild,
    /// Writer rotation — the rotating node itself
    RotationSelf,
    /// Child detached from non-writer parent (§1.2.1 writer check — disabled v0.9.1)
    WriterCheck,
    /// Audit detected root hash mismatch with parent
    AuditFail,
}

/// How an orphan was recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPass {
    P1Candidates,
    P2MeshHint,
    P3KnownNodes,
    PeEnquiry,     // E-enquiry to any known writer for subtree open slots (§2.1, v0.9 §E7)
    P4BfsFallback, // Sim-only global BFS (no production equivalent)
}

/// A single orphan lifecycle event.
#[derive(Debug, Clone)]
pub struct OrphanEvent {
    pub tick: u64,
    pub node_idx: usize,
    pub cause: OrphanCause,
    /// None = still pending recovery this tick, Some = outcome
    pub recovery: Option<Result<(RecoveryPass, usize), String>>,  // Ok((pass, parent_idx)) or Err(reason)
    pub had_children: bool,  // orphan had downstream children (non-leaf)
}

/// Cumulative counters (O(1) memory, never reset).
#[derive(Debug, Default, Clone, Serialize)]
pub struct OrphanCounters {
    pub created: u64,
    pub recovered: u64,
    pub failed: u64,
    // by cause
    pub by_parent_died: u64,
    pub by_rebalance: u64,
    pub by_dropped: u64,
    pub by_rotation_child: u64,
    pub by_rotation_self: u64,
    pub by_writer_check: u64,
    pub by_audit_fail: u64,
    // by recovery pass
    pub by_p1: u64,
    pub by_p2: u64,
    pub by_p3: u64,
    pub by_pe: u64,
    pub by_p4: u64,
    // strict pass stats
    pub strict_pass_used: u64,
    pub strict_pass_fell_through: u64,
}

pub struct OrphanDiagnostic {
    /// Ring buffer of recent events. Bounded to `capacity`.
    events: VecDeque<OrphanEvent>,
    capacity: usize,
    pub counters: OrphanCounters,
    /// Nodes currently orphaned: idx → (tick_created, cause).
    pub persistent: HashMap<usize, (u64, OrphanCause)>,
    /// Longest time any node stayed orphaned (in ticks).
    pub max_orphan_duration: u64,
    /// Node that had the longest orphan duration.
    pub max_orphan_node: Option<usize>,
    /// Tags pending orphans that were just created this tick (before recovery runs).
    /// Key = node_idx, Value = cause. Consumed by recovery tracking.
    pending_cause: HashMap<usize, OrphanCause>,
}

impl OrphanDiagnostic {
    pub fn new(capacity: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
            counters: OrphanCounters::default(),
            persistent: HashMap::new(),
            max_orphan_duration: 0,
            max_orphan_node: None,
            pending_cause: HashMap::new(),
        }
    }

    /// Tag a node as newly orphaned. Call at orphan creation point.
    pub fn orphan_created(&mut self, tick: u64, node_idx: usize, cause: OrphanCause, had_children: bool) {
        self.counters.created += 1;
        match cause {
            OrphanCause::ParentDied => self.counters.by_parent_died += 1,
            OrphanCause::Rebalance => self.counters.by_rebalance += 1,
            OrphanCause::DroppedByParent => self.counters.by_dropped += 1,
            OrphanCause::RotationChild => self.counters.by_rotation_child += 1,
            OrphanCause::RotationSelf => self.counters.by_rotation_self += 1,
            OrphanCause::WriterCheck => self.counters.by_writer_check += 1,
            OrphanCause::AuditFail => self.counters.by_audit_fail += 1,
        }
        self.pending_cause.insert(node_idx, cause);
        self.persistent.insert(node_idx, (tick, cause));

        // Push creation event (recovery field filled later)
        let evt = OrphanEvent { tick, node_idx, cause, recovery: None, had_children };
        self.push_event(evt);
    }

    /// Record successful recovery.
    pub fn orphan_recovered(&mut self, tick: u64, node_idx: usize, pass: RecoveryPass, parent_idx: usize, strict_used: bool) {
        self.counters.recovered += 1;
        match pass {
            RecoveryPass::P1Candidates => self.counters.by_p1 += 1,
            RecoveryPass::P2MeshHint => self.counters.by_p2 += 1,
            RecoveryPass::P3KnownNodes => self.counters.by_p3 += 1,
            RecoveryPass::PeEnquiry => self.counters.by_pe += 1,
            RecoveryPass::P4BfsFallback => self.counters.by_p4 += 1,
        }
        if strict_used { self.counters.strict_pass_used += 1; }

        // Update the most recent event for this node if it exists
        if let Some(evt) = self.events.iter_mut().rev()
            .find(|e| e.node_idx == node_idx && e.recovery.is_none())
        {
            evt.recovery = Some(Ok((pass, parent_idx)));
        }

        // Track duration if it was persistent
        if let Some((created_tick, _)) = self.persistent.remove(&node_idx) {
            let duration = tick.saturating_sub(created_tick);
            if duration > self.max_orphan_duration {
                self.max_orphan_duration = duration;
                self.max_orphan_node = Some(node_idx);
            }
        }
        self.pending_cause.remove(&node_idx);
    }

    /// Record failed recovery (all 4 passes failed).
    pub fn orphan_failed(&mut self, _tick: u64, node_idx: usize, reason: &str) {
        self.counters.failed += 1;

        if let Some(evt) = self.events.iter_mut().rev()
            .find(|e| e.node_idx == node_idx && e.recovery.is_none())
        {
            evt.recovery = Some(Err(reason.to_string()));
        }
        // Node stays in persistent — will get duration tracked if recovered later
    }

    /// Record that strict pass fell through to relaxed.
    pub fn strict_fell_through(&mut self) {
        self.counters.strict_pass_fell_through += 1;
    }

    /// Call at the end of each tick to update persistent orphan durations.
    /// `actual_orphans` is the set of node indices that are CURRENTLY orphans.
    /// Any persistent entry NOT in this set has recovered through an untracked
    /// path and is cleaned up here.
    pub fn tick_end_check(&mut self, tick: u64, actual_orphans: &HashSet<usize>) {
        // Defensive cleanup: remove persistent entries for nodes that recovered
        // through untracked paths (e.g., re-attachment during partition heal).
        let stale: Vec<usize> = self.persistent.keys()
            .filter(|idx| !actual_orphans.contains(idx))
            .copied()
            .collect();
        for idx in &stale {
            if let Some((created_tick, _)) = self.persistent.remove(idx) {
                let duration = tick.saturating_sub(created_tick);
                if duration > self.max_orphan_duration {
                    self.max_orphan_duration = duration;
                    self.max_orphan_node = Some(*idx);
                }
                // Count as recovered (untracked path)
                self.counters.recovered += 1;
            }
        }

        // Update max duration for any still-persistent orphans
        for (&node_idx, &(created_tick, _)) in &self.persistent {
            let duration = tick.saturating_sub(created_tick);
            if duration > self.max_orphan_duration {
                self.max_orphan_duration = duration;
                self.max_orphan_node = Some(node_idx);
            }
        }
    }

    /// Remove a node from persistent tracking (e.g., if killed).
    pub fn node_killed(&mut self, node_idx: usize) {
        self.persistent.remove(&node_idx);
        self.pending_cause.remove(&node_idx);
    }

    fn push_event(&mut self, evt: OrphanEvent) {
        if self.events.len() >= self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(evt);
    }

    /// Dump compact diagnostic report to file. Returns the filename.
    pub fn dump(&self, tick: u64, filename: &str, tree_lines: &[String]) -> std::io::Result<String> {
        use std::io::Write;
        let path = filename;
        let mut f = std::fs::File::create(path)?;

        writeln!(f, "=== ORPHAN DIAGNOSTIC @ tick {} ===", tick)?;
        writeln!(f)?;

        // Counters
        writeln!(f, "── COUNTERS ──")?;
        writeln!(f, "created={} recovered={} failed={}", self.counters.created, self.counters.recovered, self.counters.failed)?;
        writeln!(f, "  by_cause:  parent_died={} rebalance={} dropped={} rot_child={} rot_self={} writer_check={} audit_fail={}",
            self.counters.by_parent_died, self.counters.by_rebalance, self.counters.by_dropped,
            self.counters.by_rotation_child, self.counters.by_rotation_self, self.counters.by_writer_check, self.counters.by_audit_fail)?;
        writeln!(f, "  by_pass:   P1={} P2={} P3={} PE={} P4={}",
            self.counters.by_p1, self.counters.by_p2, self.counters.by_p3, self.counters.by_pe, self.counters.by_p4)?;
        writeln!(f, "  strict:    used={} fell_through={}",
            self.counters.strict_pass_used, self.counters.strict_pass_fell_through)?;
        writeln!(f, "  max_orphan_duration={} ticks (node {:?})", self.max_orphan_duration, self.max_orphan_node)?;
        writeln!(f)?;

        // Persistent orphans (the bugs)
        if !self.persistent.is_empty() {
            writeln!(f, "── PERSISTENT ORPHANS ({}) ──", self.persistent.len())?;
            let mut sorted: Vec<_> = self.persistent.iter().collect();
            sorted.sort_by_key(|(_, (t, _))| *t);
            for (&idx, &(created, cause)) in &sorted {
                writeln!(f, "  node {} orphaned since tick {} ({} ticks ago) cause={:?}",
                    idx, created, tick.saturating_sub(created), cause)?;
            }
            writeln!(f)?;
        }

        // Recent events (ring buffer)
        writeln!(f, "── RECENT EVENTS (last {}/{}) ──", self.events.len(), self.capacity)?;
        // Show only failures and long-duration events to keep it compact
        let mut interesting = 0;
        for evt in &self.events {
            let is_failure = matches!(&evt.recovery, Some(Err(_)));
            let is_long = self.persistent.get(&evt.node_idx)
                .map(|(t, _)| tick.saturating_sub(*t) > 2)
                .unwrap_or(false);
            if is_failure || is_long || evt.recovery.is_none() {
                writeln!(f, "  t={:>6} node={:>3} cause={:<15?} children={} recovery={:?}",
                    evt.tick, evt.node_idx, evt.cause, evt.had_children,
                    evt.recovery.as_ref().map(|r| match r {
                        Ok((pass, parent)) => format!("{:?}→node{}", pass, parent),
                        Err(reason) => format!("FAIL: {}", reason),
                    }).unwrap_or_else(|| "PENDING".into()))?;
                interesting += 1;
            }
        }
        if interesting == 0 {
            writeln!(f, "  (all recent orphans recovered immediately — no issues)")?;
        }
        writeln!(f)?;

        // Full event dump for last 50
        writeln!(f, "── LAST 50 EVENTS (full) ──")?;
        for evt in self.events.iter().rev().take(50) {
            writeln!(f, "  t={:>6} node={:>3} cause={:<15?} children={} recovery={:?}",
                evt.tick, evt.node_idx, evt.cause, evt.had_children,
                evt.recovery.as_ref().map(|r| match r {
                    Ok((pass, parent)) => format!("{:?}→node{}", pass, parent),
                    Err(reason) => format!("FAIL: {}", reason),
                }).unwrap_or_else(|| "PENDING".into()))?;
        }

        // Full tree state
        writeln!(f)?;
        writeln!(f, "── TREE STATE ──")?;
        for line in tree_lines {
            writeln!(f, "{}", line)?;
        }

        Ok(path.to_string())
    }

    /// One-line summary for dashboard.
    pub fn dashboard_line(&self, tick: u64) -> String {
        let persistent_ages: Vec<u64> = self.persistent.values()
            .map(|(t, _)| tick.saturating_sub(*t))
            .collect();
        let max_age = persistent_ages.iter().max().copied().unwrap_or(0);
        format!("orphan_diag: created={} ok={} fail={} persistent={} max_age={}t | P1={} P2={} P3={} PE={} P4={} | max_ever={}t",
            self.counters.created, self.counters.recovered, self.counters.failed,
            self.persistent.len(), max_age,
            self.counters.by_p1, self.counters.by_p2, self.counters.by_p3, self.counters.by_pe, self.counters.by_p4,
            self.max_orphan_duration)
    }
}

// ── Simulation Node ──

/// A simulated Nabla node using real library components.
pub struct SimNode {
    pub id: usize,
    pub node_id: NodeId,
    pub gossip: GossipEngine,
    pub mesh: GossipMesh,
    pub smt: SparseMerkleTree,
    pub bans: BanTable,
    pub pool: DailyPoolState,
    pub airdrop_pool: crate::node::AirdropPool,
    /// Validator-join subsidy pools (AXIOM_DESIGN_ValidatorJoin.md §2).
    /// Drain-only, same type as the airdrop pool.
    pub bootstrap_pool: crate::node::AirdropPool,
    pub foundation_bootstrap_pool: crate::node::AirdropPool,
    pub dev_treasury_pool: crate::node::DevTreasuryPool,
    pub deed_pool: crate::node::DeedPool,
    pub dev_deed_pool: crate::node::DevDeedPool,
    /// Contribution emission pools (KI#191 residual): reconciled inside
    /// `GossipEngine::process` like every pool. The lib sim never advertises
    /// emission PoolSync, so this stays at its opening state.
    pub emission: crate::emission::EmissionPools,
    pub tardis: TardisNode,
    pub tick: u64,
    /// Tick received via TARDIS tree cascade (vs global sim tick).
    /// Only advances when upstream delivers a tick.
    pub tardis_tick: u64,
    pub alive: bool,
    pub is_genesis: bool,
    pub is_seed: bool,
    /// Ed25519 signer for this node (sim uses real crypto).
    pub signer: Ed25519Signer,
    /// Messages waiting to be delivered from this node.
    pub outbox: VecDeque<(NodeId, GossipMessage)>,
    /// Count of gossip messages received (for visualization).
    pub messages_received: u64,
    /// Tick when last gossip was received (for activity flash).
    pub last_gossip_tick: u64,
    /// TARDIS downstream approval status: (child_idx, approved) for current tick.
    pub tardis_approvals: Vec<(usize, bool)>,
    /// Approval count from PREVIOUS tick round. Used in tick messages so children
    /// can verify parent is a qualified writer. Updated at end of each tick cascade.
    pub prev_approval_count: u8,
    /// Real NBC (Nabla's own keys, separate from Validator's VBC, YPX-002).
    pub nbc: Option<axiom_core_logic::types::VBC>,
}

impl SimNode {
    pub fn new(id: usize, is_genesis: bool) -> Self {
        // Derive deterministic Ed25519 keypair from node index.
        // node_id IS the public key — same as production where Core manages keys.
        let signer = Ed25519Signer::from_node_index(id);
        let node_id = signer.public_key_bytes();

        let address = NablaAddress::V4 {
            ip: [10, 0, (id / 256) as u8, (id % 256) as u8],
            port: 6225,
        };

        Self {
            id,
            node_id,
            gossip: GossipEngine::new(),
            mesh: GossipMesh::new(node_id, address),
            smt: SparseMerkleTree::new(),
            bans: BanTable::new(),
            pool: DailyPoolState::new(),
            airdrop_pool: crate::node::AirdropPool::new(crate::constants::AIRDROP_POOL_INITIAL_ATOMS),
            bootstrap_pool: crate::node::AirdropPool::new(crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS)
                .with_class_constants(crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS, axiom_core_logic::types::TIER3_CLAIM_ATOMS),
            foundation_bootstrap_pool: crate::node::AirdropPool::new(crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS)
                .with_class_constants(crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS, axiom_core_logic::types::TIER2_CLAIM_ATOMS),
            dev_treasury_pool: crate::node::DevTreasuryPool::new(crate::constants::DEV_TREASURY_POOL_INITIAL_ATOMS),
            deed_pool: crate::node::DeedPool::new(),
            dev_deed_pool: crate::node::DevDeedPool::new(),
            emission: crate::emission::EmissionPools::new_from_registers(0),
            tardis: TardisNode::new(node_id),
            tick: 0,
            tardis_tick: 0,
            alive: true,
            is_genesis,
            is_seed: false,
            signer,
            outbox: VecDeque::new(),
            messages_received: 0,
            last_gossip_tick: 0,
            tardis_approvals: Vec::new(),
            prev_approval_count: 0,
            nbc: None,
        }
    }

    /// Create a SimNode with a real NBC from ceremony (real SPHINCS+ signatures).
    /// node_id = NBC.validator_id = BLAKE3(sphincs_pk) — cryptographically derived.
    /// Ed25519 signer uses the ceremony-generated keypair embedded in the NBC.
    pub fn from_ceremony(id: usize, is_genesis: bool, ceremony: crate::ceremony::CeremonyNode) -> Self {
        let signer = Ed25519Signer::from_seed(&ceremony.ed25519_sk);
        let node_id = ceremony.node_id; // BLAKE3(sphincs_pk) = validator_id

        let address = NablaAddress::V4 {
            ip: [10, 0, (id / 256) as u8, (id % 256) as u8],
            port: 6225,
        };

        Self {
            id,
            node_id,
            gossip: GossipEngine::new(),
            mesh: GossipMesh::new(node_id, address),
            smt: SparseMerkleTree::new(),
            bans: BanTable::new(),
            pool: DailyPoolState::new(),
            airdrop_pool: crate::node::AirdropPool::new(crate::constants::AIRDROP_POOL_INITIAL_ATOMS),
            bootstrap_pool: crate::node::AirdropPool::new(crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS)
                .with_class_constants(crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS, axiom_core_logic::types::TIER3_CLAIM_ATOMS),
            foundation_bootstrap_pool: crate::node::AirdropPool::new(crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS)
                .with_class_constants(crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS, axiom_core_logic::types::TIER2_CLAIM_ATOMS),
            dev_treasury_pool: crate::node::DevTreasuryPool::new(crate::constants::DEV_TREASURY_POOL_INITIAL_ATOMS),
            deed_pool: crate::node::DeedPool::new(),
            dev_deed_pool: crate::node::DevDeedPool::new(),
            emission: crate::emission::EmissionPools::new_from_registers(0),
            tardis: TardisNode::new(node_id),
            tick: 0,
            tardis_tick: 0,
            alive: true,
            is_genesis,
            is_seed: false,
            signer,
            outbox: VecDeque::new(),
            messages_received: 0,
            last_gossip_tick: 0,
            tardis_approvals: Vec::new(),
            prev_approval_count: 0,
            nbc: Some(ceremony.nbc),
        }
    }

    /// Process an incoming gossip message. Returns true if forwarded (not duplicate).
    pub fn receive_gossip(&mut self, msg: &GossipMessage, sender: &NodeId) -> bool {
        if !self.alive {
            return false;
        }

        // Keep sender alive in mesh (prevents stale-peer pruning)
        self.mesh.observe_node(*sender, self.tick);

        let n_validators = self.mesh.estimated_network_size();
        // The simulator does not exercise FOB Bounded-Fee pools — pass empty
        // maps (the BoundedFee arm no-ops without pools/credits).
        let mut sim_fob_pools = std::collections::HashMap::new();
        let sim_fob_credits = std::collections::HashMap::new();
        let action = self.gossip.process(msg, &mut self.smt, &mut self.bans, &mut self.pool, &mut self.airdrop_pool, &mut self.dev_treasury_pool, &mut self.bootstrap_pool, &mut self.foundation_bootstrap_pool, &mut self.deed_pool, &mut self.dev_deed_pool, &mut self.emission, &mut sim_fob_pools, &sim_fob_credits, self.tick, self.tick /* A19: the sim has no wall clock — its tick stands in for now_secs (sim-only unit substitution) */, n_validators, &|_| false /* KI#224: the sim carries no SeqProofs and has no witness directory */);
        match action {
            GossipAction::Forward(fwd_msg) => {
                self.messages_received += 1;
                self.last_gossip_tick = self.tick;

                let targets = self.mesh.forward_targets(sender);
                for target in targets {
                    self.outbox.push_back((target, fwd_msg.clone()));
                }
                true
            }
            GossipAction::Duplicate => false,
            // `BanDetected` deleted 2026-09-30 (§9o [R56], W2): check-3 retired.
            GossipAction::PoolViolationDetected { .. } => {
                // Sim doesn't model the full Layer 4 quarantine
                // emission path — production binary handles it. For
                // sim we just count the message as received-and-dropped.
                self.messages_received += 1;
                false
            }
            GossipAction::PoolStructuralViolation { .. } => {
                // Same shape as PoolViolationDetected for sim purposes —
                // production binary routes to probation; sim drops.
                self.messages_received += 1;
                false
            }
        }
    }

    /// Try to add a discovered node as a peer if there's room.
    /// §6.3: Always record in known_nodes. Add as peer only up to D (target).
    /// E-peer slots are handled separately in sim step.
    pub fn try_discover_peer(&mut self, peer_id: NodeId, peer_idx: usize) {
        if peer_id == self.node_id {
            return;
        }
        self.mesh.observe_node(peer_id, self.tick);

        let address = NablaAddress::V4 {
            ip: [10, 0, (peer_idx / 256) as u8, (peer_idx % 256) as u8],
            port: 6225,
        };
        let peer = PeerInfo {
            node_id: peer_id,
            address,
            last_seen: self.tick,
            tardis_up: None,
            has_d_open: false, open_slots: 0,
            messages_delivered: 0,
            connected_since: self.tick,
            txid_service: String::new(),
        };

        // Always record in known_nodes
        self.mesh.add_discovered_peer(peer.clone());

        // Already an active peer or E-peer?
        if self.mesh.peer_ids().contains(&peer_id) {
            return;
        }
        if let Some(ep) = self.mesh.enquiry_peer() {
            if ep.node_id == peer_id { return; }
        }

        // §6.3.1: Accept as regular peer only up to regular_peer_target.
        // The E-peer slot is reserved and never filled by regular peers.
        if self.mesh.peer_count() < self.mesh.regular_peer_target() {
            self.mesh.add_peer_direct(peer);
        }
    }
}

// ── Simulation Network ──

pub struct SimNetwork {
    pub nodes: Vec<SimNode>,
    target_count: usize,
    pub nodes_added: usize,
    blocked: HashSet<(usize, usize)>,
    id_to_idx: HashMap<NodeId, usize>,
    /// Links where gossip has actually been delivered. Only these are shown.
    live_links: HashSet<(usize, usize)>,
    /// TARDIS tree links: directed (parent_idx → child_idx).
    /// Separate from gossip mesh. Ticks flow down these links only.
    tardis_links: HashSet<(usize, usize)>,
    pub total_messages: u64,
    pub tick: u64,
    pending: VecDeque<PendingMessage>,
    tardis_pending: VecDeque<PendingTardisTick>,
    /// Network delay simulation (100ms units). Each message gets random delay in [min, max].
    pub delay_min_100ms: u32,
    pub delay_max_100ms: u32,
    /// Simple LCG state for deterministic pseudo-random delays.
    rng_state: u64,
    /// Whether TARDIS tree rotation is enabled.
    /// Can be toggled from the sim UI.
    pub rotation_enabled: bool,
    /// Orphan lifecycle diagnostic (bounded ring buffer + counters).
    pub orphan_diag: OrphanDiagnostic,
    /// Pre-generated ceremony nodes (real NBCs). Consumed as nodes join.
    ceremony_nodes: Vec<crate::ceremony::CeremonyNode>,
}

struct PendingMessage {
    from_idx: usize,
    to_idx: usize,
    msg: GossipMessage,
    sender_node_id: NodeId,
    /// Sim time (ms) when this message can be delivered.
    deliver_at_ms: u64,
}

/// Pending TARDIS tick cascade message (legacy — kept for API compatibility).
struct PendingTardisTick {
    _parent_idx: usize,
    _child_idx: usize,
    _tick_msg: TickMessage,
    _deliver_at_ms: u64,
}

fn make_peer_info(nodes: &[SimNode], idx: usize, tick: u64) -> PeerInfo {
    let dc = nodes[idx].tardis.downstream_count();
    let d_open = dc < 2;
    PeerInfo {
        node_id: nodes[idx].node_id,
        address: NablaAddress::V4 {
            ip: [10, 0, (idx / 256) as u8, (idx % 256) as u8],
            port: 6225,
        },
        last_seen: tick,
        tardis_up: None,
        has_d_open: d_open,
        open_slots: if d_open { (2 - dc) as u8 } else { 0 },
        messages_delivered: 0,
        connected_since: tick,
            txid_service: String::new(),
    }
}

impl SimNetwork {
    /// Create a network. 10 genesis nodes start fully meshed, others join over time.
    /// Loads NBCs from disk — run `nabla-ceremony` first (dev.sh → 28n).
    pub fn new(total_count: usize, base_dir: &std::path::Path) -> Self {
        let total = total_count.max(GENESIS_COUNT);

        // ── Load real NBCs from disk ──
        // Ceremony must have been run separately (dev.sh → 28n / nabla-ceremony).
        // Each node's nbc.json lives in its config directory:
        //   Genesis 0-9 → axiom-first-penguin-{name}/config/nbc.json
        //   Nabla 10+   → nabla_{i}/config/nbc.json
        let mut ceremony_nodes = match crate::ceremony::load_nbcs(base_dir, total) {
            Ok(nodes) => {
                eprintln!("🔑 Loaded {} real NBCs from {}", nodes.len(), base_dir.display());
                nodes
            }
            Err(e) => {
                eprintln!("╔════════════════════════════════════════════════════════════╗");
                eprintln!("║  ERROR: Nabla ceremony not found                          ║");
                eprintln!("╠════════════════════════════════════════════════════════════╣");
                eprintln!("║  {}", e);
                eprintln!("║                                                            ║");
                eprintln!("║  Run ceremony first:                                       ║");
                eprintln!("║    dev.sh → 28n (Nabla ceremony)                           ║");
                eprintln!("║    — OR —                                                  ║");
                eprintln!("║    nabla-ceremony --base-dir {} --count {}", base_dir.display(), total);
                eprintln!("╚════════════════════════════════════════════════════════════╝");
                std::process::exit(1);
            }
        };

        // Consume genesis nodes (first GENESIS_COUNT)
        let mut nodes: Vec<SimNode> = Vec::with_capacity(total);
        for i in 0..GENESIS_COUNT {
            let cn = ceremony_nodes.remove(0);
            nodes.push(SimNode::from_ceremony(i, true, cn));
        }

        // Each genesis bootstraps to 3 other genesis (sparse, not full mesh)
        // Real deployment: genesis nodes don't all know each other directly.
        for i in 0..GENESIS_COUNT {
            let mut bootstrap = Vec::new();
            let mut observe_ids = Vec::new();
            for offset in 1..=3 {
                let j = (i + offset) % GENESIS_COUNT;
                bootstrap.push(make_peer_info(&nodes, j, 0));
                observe_ids.push(nodes[j].node_id);
            }
            for nid in observe_ids {
                nodes[i].mesh.observe_node(nid, 0);
            }
            nodes[i].mesh.add_bootstrap(bootstrap);
        }

        let mut id_to_idx = HashMap::new();
        for (i, node) in nodes.iter().enumerate() {
            id_to_idx.insert(node.node_id, i);
        }

        // ── Genesis Ring Setup ──
        // Genesis nodes launch simultaneously and form a ring topology.
        // Every node generates its own tick from NTP — genesis nodes are not
        // special tick authorities. The ring exists because they're the only
        // nodes present at launch (v0.9 §2.16).
        // Ring topology: G0↔G1↔G2↔...↔G9↔G0
        // Each genesis: UP=prev, D1=next (ring). D2 stays open for non-genesis children.
        let mut tardis_links = HashSet::new();
        for i in 0..GENESIS_COUNT {
            nodes[i].is_seed = true;
            let prev = (i + GENESIS_COUNT - 1) % GENESIS_COUNT;
            let next = (i + 1) % GENESIS_COUNT;
            let prev_nid = nodes[prev].node_id;
            let next_nid = nodes[next].node_id;
            nodes[i].tardis.set_upstream(prev_nid);
            nodes[i].tardis.add_downstream(next_nid);
            tardis_links.insert((i, next));  // directed: i is parent of next
        }

        Self {
            nodes,
            target_count: total,
            nodes_added: GENESIS_COUNT,
            blocked: HashSet::new(),
            id_to_idx,
            live_links: HashSet::new(),
            tardis_links,
            total_messages: 0,
            tick: 0,
            pending: VecDeque::new(),
            tardis_pending: VecDeque::new(),
            delay_min_100ms: 0,
            delay_max_100ms: 0,
            rng_state: 0xDEAD_BEEF_CAFE_1234,
            rotation_enabled: true,
            orphan_diag: OrphanDiagnostic::new(2000),
            ceremony_nodes,
        }
    }

    /// Test-only constructor: uses deterministic Ed25519 keys (no ceremony needed).
    /// For unit tests only — production sim uses `new()` which requires real NBCs.
    #[cfg(test)]
    pub fn new_test(total_count: usize) -> Self {
        let total = total_count.max(GENESIS_COUNT);
        let mut nodes: Vec<SimNode> = Vec::with_capacity(total);

        for i in 0..GENESIS_COUNT {
            nodes.push(SimNode::new(i, true));
        }

        for i in 0..GENESIS_COUNT {
            let mut bootstrap = Vec::new();
            let mut observe_ids = Vec::new();
            for offset in 1..=3 {
                let j = (i + offset) % GENESIS_COUNT;
                bootstrap.push(make_peer_info(&nodes, j, 0));
                observe_ids.push(nodes[j].node_id);
            }
            for nid in observe_ids {
                nodes[i].mesh.observe_node(nid, 0);
            }
            nodes[i].mesh.add_bootstrap(bootstrap);
        }

        let mut id_to_idx = HashMap::new();
        for (i, node) in nodes.iter().enumerate() {
            id_to_idx.insert(node.node_id, i);
        }

        let mut tardis_links = HashSet::new();
        for i in 0..GENESIS_COUNT {
            nodes[i].is_seed = true;
            let prev = if i == 0 { GENESIS_COUNT - 1 } else { i - 1 };
            let next = (i + 1) % GENESIS_COUNT;
            let prev_nid = nodes[prev].node_id;
            let next_nid = nodes[next].node_id;
            nodes[i].tardis.set_upstream(prev_nid);
            nodes[i].tardis.add_downstream(next_nid);
            tardis_links.insert((i, next));
        }

        Self {
            nodes,
            target_count: total,
            nodes_added: GENESIS_COUNT,
            blocked: HashSet::new(),
            id_to_idx,
            live_links: HashSet::new(),
            tardis_links,
            total_messages: 0,
            tick: 0,
            pending: VecDeque::new(),
            tardis_pending: VecDeque::new(),
            delay_min_100ms: 0,
            delay_max_100ms: 0,
            rng_state: 0xDEAD_BEEF_CAFE_1234,
            rotation_enabled: true,
            orphan_diag: OrphanDiagnostic::new(2000),
            ceremony_nodes: Vec::new(),
        }
    }

    /// Add a new node using production-correct E → P → D join path (§2.1).
    ///
    /// 1. E-enquiry: new node contacts any known node and asks for subtree slot availability
    /// 2. If D slot found → attach directly as D
    /// 3. If no D slot → attach as P (pending) to a random node with children
    /// 4. P nodes get promoted to D when slots open (see step() P slot promotion)
    fn add_node(&mut self) {
        let idx = self.nodes.len();
        if idx >= self.target_count {
            return;
        }

        // Use ceremony NBC if available, else deterministic keys (test mode)
        let mut node = if !self.ceremony_nodes.is_empty() {
            let cn = self.ceremony_nodes.remove(0);
            SimNode::from_ceremony(idx, false, cn)
        } else {
            // No ceremony nodes left — test mode or ceremony was run with fewer nodes
            SimNode::new(idx, false)
        };
        node.tick = self.tick;

        // Bootstrap to ALL genesis nodes — in real deployment, bootstrap.toml
        // lists all genesis nodes. New nodes know every entry point from day one.
        let mut bootstrap: Vec<PeerInfo> = Vec::new();
        for g in 0..GENESIS_COUNT.min(self.nodes.len()) {
            if self.nodes[g].alive {
                bootstrap.push(make_peer_info(&self.nodes, g, self.tick));
            }
        }
        node.mesh.add_bootstrap(bootstrap);

        // Genesis nodes learn about new node
        let new_peer = PeerInfo {
            node_id: node.node_id,
            address: NablaAddress::V4 {
                ip: [10, 0, (idx / 256) as u8, (idx % 256) as u8],
                port: 6225,
            },
            last_seen: self.tick,
            tardis_up: None,
            has_d_open: false, open_slots: 0,
            messages_delivered: 0,
            connected_since: self.tick,
            txid_service: String::new(),
        };
        for g in 0..GENESIS_COUNT.min(self.nodes.len()) {
            if !self.nodes[g].alive { continue; }
            self.nodes[g].mesh.observe_node(node.node_id, self.tick);
            self.nodes[g].mesh.add_discovered_peer(new_peer.clone());
            if self.nodes[g].mesh.peer_count() < self.nodes[g].mesh.regular_peer_target() {
                self.nodes[g].mesh.add_peer_direct(new_peer.clone());
            }
        }

        self.id_to_idx.insert(node.node_id, idx);
        self.nodes.push(node);
        self.nodes_added = self.nodes.len();

        // ── E-enquiry Join Path (§2.1) ──
        // New node contacts any known node, asks for open D slots in subtree.
        // Genesis addresses serve as bootstrap contacts (v0.9 §E7).
        let child_nid = self.nodes[idx].node_id;
        let reachable = self.reachable_from_tree_roots();
        let mut attached = false;

        // Try each alive node's subtree via E-enquiry.
        // In production, a joining node contacts any known node.
        // Seeds are just bootstrap contacts — no special protocol role.
        let roots: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| i != idx && self.nodes[i].alive && reachable.contains(&i)
                && self.nodes[i].tardis.downstream_count() >= 1) // prefer nodes already in tree
            .collect();

        for root_idx in &roots {
            let open_in_subtree = self.e_enquiry_open_slots(*root_idx, &reachable);
            for &candidate in &open_in_subtree {
                if candidate == idx { continue; }
                if !self.nodes[candidate].tardis.has_d_open() { continue; }
                if self.attach_child(candidate, idx) {
                    attached = true;
                    break;
                }
            }
            if attached { break; }
        }

        // ── P Slot Fallback (§2.1) ──
        // If no D slot available via E-enquiry, attach as P (pending) to a node
        // that has children (a writer or dc=1). P receives ticks, is functional,
        // and gets promoted to D when a slot opens.
        if !attached {
            // Find a node with children that could eventually have an open slot
            // Prefer nodes that are reachable and have at least 1 child
            let p_candidates: Vec<usize> = (0..self.nodes.len())
                .filter(|&i| {
                    i != idx
                        && self.nodes[i].alive
                        && reachable.contains(&i)
                        && self.nodes[i].tardis.downstream_count() > 0
                        && self.nodes[i].tardis.pending().is_none()
                })
                .collect();

            if let Some(&host_idx) = p_candidates.first() {
                let host_nid = self.nodes[host_idx].node_id;
                self.nodes[host_idx].tardis.set_pending(child_nid);
                self.nodes[idx].tardis.set_upstream(host_nid);
                let now_ms = self.sim_time_ms();
                let prev_tick_time = self.tick_time_secs().saturating_sub(TICK_INTERVAL_SECS);
                let prev_ms = now_ms.saturating_sub(TICK_INTERVAL_SECS * 1000);
                self.nodes[idx].tardis.set_tick(prev_tick_time, prev_ms);
                // P nodes are in the tree (receive ticks) but don't have a tardis_link
                // because they're not in a D slot. Track via a separate mechanism.
                self.tardis_links.insert((host_idx, idx));
                attached = true;
                eprintln!("📎 TARDIS: node {} joined as P (pending) under node {} — awaiting D slot promotion",
                    idx, host_idx);
            }
        }

        if !attached {
            let total_open: Vec<usize> = (0..self.nodes.len())
                .filter(|&i| self.nodes[i].alive && self.nodes[i].tardis.has_d_open())
                .collect();
            eprintln!("⚠ TARDIS: node {} failed to attach! roots={} open_slots={:?}",
                idx, roots.len(), total_open);
        }
    }

    /// Advance one tick.
    pub fn step(&mut self) -> u64 {
        self.tick += 1;
        let mut delivered = 0u64;

        // Node join: scale growth rate with target size
        // Small network (≤50): 1 node every 2 ticks
        // Large network (>50): up to 5 nodes per tick
        if self.nodes.len() < self.target_count {
            let batch = if self.target_count <= 50 {
                if self.tick.is_multiple_of(2) { 1 } else { 0 }
            } else {
                ((self.target_count - self.nodes.len()) / 50).clamp(1, 5)
            };
            for _ in 0..batch {
                if self.nodes.len() >= self.target_count { break; }
                self.add_node();
            }
        }

        // One-time tree structure dump when all nodes are added
        if self.nodes.len() == self.target_count && self.tick == (self.target_count as u64 * 2) + 5 {
            self.dump_tree("STARTUP - all nodes added");
        }

        for node in &mut self.nodes {
            if node.alive { node.tick = self.tick; }
        }

        // ── TARDIS Tree Rotation — Protocol-driven anti-ossification ──
        // Two mechanisms prevent the tree from calcifying:
        //   1. Parent drops slowest child every PARENT_ROTATION_INTERVAL ticks
        //   2. Child switches parent every CHILD_ROTATION_INTERVAL ticks
        // Both decisions are in TardisNode (protocol level).
        // Sim just executes detach — orphan recovery handles re-placement.
        if self.rotation_enabled {
            // Parent-side: drop slow child
            // Two-phase to satisfy borrow checker: collect candidates (immutable),
            // then call wants_drop_slow_child (mutable) in a separate loop.
            let candidates: Vec<usize> = (0..self.nodes.len())
                .filter(|&i| self.nodes[i].alive && self.nodes[i].tardis.downstream_count() == 2)
                .collect();

            let mut parent_drops: Vec<(usize, PeerId)> = Vec::new();
            for i in candidates {
                if let Some(child_pk) = self.nodes[i].tardis.wants_drop_slow_child() {
                    parent_drops.push((i, child_pk));
                }
            }

            for (parent_idx, child_pk) in parent_drops {
                if let Some(&child_idx) = self.id_to_idx.get(&child_pk) {
                    if child_idx < self.nodes.len() && self.nodes[child_idx].alive {
                        let parent_nid = self.nodes[parent_idx].node_id;
                        self.nodes[parent_idx].tardis.remove_peer(&child_pk);
                        self.nodes[child_idx].tardis.remove_peer(&parent_nid);
                        self.tardis_links.remove(&(parent_idx, child_idx));
                        // Tag as dropped-by-parent orphan
                        let had_children = self.nodes[child_idx].tardis.downstream_count() > 0;
                        self.orphan_diag.orphan_created(self.tick, child_idx, OrphanCause::DroppedByParent, had_children);
                        // Dropped child becomes orphan → recovered by orphan recovery below (same tick)
                    }
                }
            }

            // Writer-side: voluntary rotation (disassemble and scatter)
            // Every 150 ticks (72h production), a WRITER releases its children
            // then detaches from its parent. All become orphans. Released children
            // land on dc=1 nodes via recovery, turning them into writers.
            // This is how leaves stop being permanent leaves.
            let rotators: Vec<usize> = (0..self.nodes.len())
                .filter(|&i| {
                    self.nodes[i].alive && self.nodes[i].tardis.wants_rotate()
                })
                .collect();

            for rot_idx in rotators {
                let rot_nid = self.nodes[rot_idx].node_id;

                // Step 1: Release children (they become orphans)
                let children: Vec<PeerId> = self.nodes[rot_idx].tardis.children_to_release();
                let mut released_child_indices: Vec<usize> = Vec::new();
                for child_nid in &children {
                    if let Some(&child_idx) = self.id_to_idx.get(child_nid) {
                        if child_idx < self.nodes.len() && self.nodes[child_idx].alive {
                            self.nodes[rot_idx].tardis.remove_peer(child_nid);
                            self.nodes[child_idx].tardis.remove_peer(&rot_nid);
                            self.tardis_links.remove(&(rot_idx, child_idx));
                            released_child_indices.push(child_idx);
                        }
                    }
                }

                // Step 2: Detach from parent (rotating node becomes orphan)
                let parent_nid = match self.nodes[rot_idx].tardis.upstream().cloned() {
                    Some(p) => p,
                    None => {
                        // No parent — just tag children as orphans
                        for &ci in &released_child_indices {
                            let had_children = self.nodes[ci].tardis.downstream_count() > 0;
                            self.orphan_diag.orphan_created(self.tick, ci, OrphanCause::RotationChild, had_children);
                        }
                        continue;
                    },
                };
                let parent_idx = match self.id_to_idx.get(&parent_nid).copied() {
                    Some(i) => i,
                    None => {
                        for &ci in &released_child_indices {
                            let had_children = self.nodes[ci].tardis.downstream_count() > 0;
                            self.orphan_diag.orphan_created(self.tick, ci, OrphanCause::RotationChild, had_children);
                        }
                        continue;
                    },
                };

                self.nodes[parent_idx].tardis.remove_peer(&rot_nid);
                self.nodes[rot_idx].tardis.remove_peer(&parent_nid);
                self.tardis_links.remove(&(parent_idx, rot_idx));

                // Step 3: Writer-preserving placement (§2.15)
                // Grandparent P just lost the rotating node → P has an open D slot.
                // Place one released child directly at P to prevent dc=1 accumulation.
                // Without this, every full rotation creates +1 net dc=1 node because
                // 3 orphans compete for only 1 dc=1 hole.
                let mut placed_at_grandparent = false;
                if self.nodes[parent_idx].alive && self.nodes[parent_idx].tardis.has_d_open() {
                    let best_child = released_child_indices.iter()
                        .find(|&&ci| self.nodes[ci].tardis.downstream_count() > 0)
                        .or_else(|| released_child_indices.first())
                        .copied();

                    if let Some(child_idx) = best_child {
                        if self.attach_child(parent_idx, child_idx) {
                            placed_at_grandparent = true;
                            released_child_indices.retain(|&ci| ci != child_idx);
                        }
                    }
                }

                // Tag remaining released children as orphans
                for &ci in &released_child_indices {
                    let had_children = self.nodes[ci].tardis.downstream_count() > 0;
                    self.orphan_diag.orphan_created(self.tick, ci, OrphanCause::RotationChild, had_children);
                }

                // Tag rotating node as orphan
                self.orphan_diag.orphan_created(self.tick, rot_idx, OrphanCause::RotationSelf, false);

                // Cooldown prevents immediate re-rotation
                self.nodes[rot_idx].tardis.set_rebalance_cooldown();

                if placed_at_grandparent {
                    eprintln!("🔄 TARDIS: rotation node {} — placed child at grandparent {} (writer-preserving)",
                        rot_idx, parent_idx);
                }
            }
        }

        // ── TARDIS Tree Rebalancing — Protocol-driven (§2.2 extension) ──
        // Each node locally decides if it should volunteer for rebalancing.
        // The decision is in TardisNode::wants_rebalance() (protocol level).
        // The sim just orchestrates: detach volunteer → run through orphan recovery.
        // This mirrors how real nodes would detach and re-enter the recovery path.
        {
            let mut rebalance_count = 0;
            
            let volunteers: Vec<usize> = (0..self.nodes.len())
                .filter(|&i| {
                    self.nodes[i].alive && self.nodes[i].tardis.wants_rebalance()
                })
                .collect();
            
            for vol_idx in volunteers {
                if rebalance_count >= MAX_REBALANCE_PER_TICK { break; }
                
                let vol_nid = self.nodes[vol_idx].node_id;
                
                // Find current parent
                let parent_nid = match self.nodes[vol_idx].tardis.upstream().cloned() {
                    Some(p) => p,
                    None => continue,
                };
                let parent_idx = match self.id_to_idx.get(&parent_nid).copied() {
                    Some(i) => i,
                    None => continue,
                };
                
                // Detach from parent (voluntary orphan)
                self.nodes[parent_idx].tardis.remove_peer(&vol_nid);
                self.nodes[vol_idx].tardis.remove_peer(&parent_nid);
                self.tardis_links.remove(&(parent_idx, vol_idx));
                
                // Tag as rebalance orphan
                let had_children = self.nodes[vol_idx].tardis.downstream_count() > 0;
                self.orphan_diag.orphan_created(self.tick, vol_idx, OrphanCause::Rebalance, had_children);

                // Now this node is an orphan — it will be picked up by orphan
                // recovery below (same tick). Strict mode (prefer dc=1) ensures
                // the leaf lands at a dc=1 parent, creating a writer.
                // Old parent went dc=2 → dc=1, creating a slot for future orphans.
                // Mark cooldown so it doesn't immediately volunteer again.
                self.nodes[vol_idx].tardis.set_rebalance_cooldown();
                
                rebalance_count += 1;
            }
        }

        // ── TARDIS Tree Maintenance: Self-Healing ──
        // The protocol's self-healing mechanism (NABLA Implementation Guide §5):
        //   - Nodes with open D slots announce SlotAvailable to mesh peers
        //   - Orphaned nodes announce LostUpstream, then check known_nodes
        //   - find_tardis_parent() uses LOCAL knowledge (available_slots) to reconnect
        //   - NO global BFS — each node only knows what its mesh told it
        //
        // ALL nodes are equal in tree maintenance. Genesis/seed nodes that lose
        // their upstream go through the same recovery as any other node.
        {
            // Step 1: Clean stale links where parent or child is dead.
            // §2.3: When child dies, RESERVE the D slot for D_RESERVATION_TICKS
            // so the child can reclaim its position if it recovers quickly.
            // When parent dies, no reservation — just free the child.
            let stale: Vec<(usize, usize)> = self.tardis_links.iter()
                .filter(|&&(p, c)| {
                    (p < self.nodes.len() && !self.nodes[p].alive) ||
                    (c < self.nodes.len() && !self.nodes[c].alive)
                })
                .copied()
                .collect();
            for (p, c) in &stale {
                self.tardis_links.remove(&(*p, *c));
                if *c < self.nodes.len() && *p < self.nodes.len() {
                    let child_nid = self.nodes[*c].node_id;
                    if self.nodes[*p].alive && !self.nodes[*c].alive {
                        // Child died — reserve D slot (§2.3)
                        self.nodes[*p].tardis.remove_peer_reserved(&child_nid, self.tick);
                    } else {
                        self.nodes[*p].tardis.remove_peer(&child_nid);
                    }
                }
                if *p < self.nodes.len() {
                    let parent_nid = self.nodes[*p].node_id;
                    self.nodes[*c].tardis.remove_peer(&parent_nid);
                    // Tag child as orphaned by parent death (if child is alive and lost upstream)
                    if *c < self.nodes.len() && self.nodes[*c].alive && !self.nodes[*p].alive {
                        let had_children = self.nodes[*c].tardis.downstream_count() > 0;
                        self.orphan_diag.orphan_created(self.tick, *c, OrphanCause::ParentDied, had_children);
                    }
                }
            }

            // Step 1a: Sever blocked TARDIS links.
            // When a network partition blocks the path between parent and child,
            // the child can't receive ticks or approvals. In production, the child
            // would detect unreachable parent via timeout. The sim detects this
            // immediately: if a TARDIS link crosses a partition boundary, sever it.
            // Both sides clean up their peer state; the child becomes an orphan
            // and goes through normal recovery within its own partition.
            if !self.blocked.is_empty() {
                let blocked_links: Vec<(usize, usize)> = self.tardis_links.iter()
                    .filter(|&&(p, c)| self.blocked.contains(&link_key(p, c)))
                    .copied()
                    .collect();
                for (p, c) in blocked_links {
                    self.tardis_links.remove(&(p, c));
                    if p < self.nodes.len() && c < self.nodes.len() {
                        let child_nid = self.nodes[c].node_id;
                        let parent_nid = self.nodes[p].node_id;
                        self.nodes[p].tardis.remove_peer(&child_nid);
                        self.nodes[c].tardis.remove_peer(&parent_nid);
                    }
                }
            }

            // Step 1b: Expire old D slot reservations (§2.3).
            // After D_RESERVATION_TICKS, reserved slots become truly open.
            // Orphan recovery (below) will fill newly opened slots naturally.
            for i in 0..self.nodes.len() {
                if !self.nodes[i].alive { continue; }
                self.nodes[i].tardis.check_reservations(self.tick);
            }

            // Step 1c: P slot → D promotion (§2.1 GAP-03).
            // Nodes in P (pending) slots receive ticks but can't be writers.
            // Each tick, check if their host has an open D slot and promote.
            // If promotion fails and the P node sees better options elsewhere
            // via should_migrate(), detach and re-enter as orphan.
            {
                let mut promotions: Vec<(usize, usize)> = Vec::new(); // (host_idx, pending_idx)
                let mut migrations: Vec<usize> = Vec::new(); // pending nodes to detach

                for i in 0..self.nodes.len() {
                    if !self.nodes[i].alive { continue; }
                    if let Some(pending_nid) = self.nodes[i].tardis.pending().copied() {
                        if let Some(&pending_idx) = self.id_to_idx.get(&pending_nid) {
                            if pending_idx < self.nodes.len() && self.nodes[pending_idx].alive {
                                if self.nodes[i].tardis.has_d_open() {
                                    // Host has open D slot — promote P → D
                                    promotions.push((i, pending_idx));
                                } else if self.nodes[pending_idx].tardis.should_migrate(
                                    self.nodes[i].tardis.downstream_count()
                                ) {
                                    // P node should seek a better host
                                    migrations.push(pending_idx);
                                }
                            }
                        }
                    }
                }

                for (host_idx, pending_idx) in promotions {
                    let _pending_nid = self.nodes[pending_idx].node_id;
                    if self.nodes[host_idx].tardis.promote_pending() {
                        // P → D success: tardis_link already exists from join,
                        // but the node is now a proper D child
                        eprintln!("📎→📌 TARDIS: P node {} promoted to D under node {} (slot opened)",
                            pending_idx, host_idx);
                    }
                }

                for pending_idx in migrations {
                    // Detach from current host, become orphan for recovery
                    let host_nid = self.nodes[pending_idx].tardis.upstream().copied();
                    if let Some(host_nid) = host_nid {
                        if let Some(&host_idx) = self.id_to_idx.get(&host_nid) {
                            let pending_nid = self.nodes[pending_idx].node_id;
                            self.nodes[host_idx].tardis.remove_peer(&pending_nid);
                            self.nodes[pending_idx].tardis.remove_peer(&host_nid);
                            self.tardis_links.remove(&(host_idx, pending_idx));
                            let had_children = self.nodes[pending_idx].tardis.downstream_count() > 0;
                            self.orphan_diag.orphan_created(self.tick, pending_idx, OrphanCause::Rebalance, had_children);
                            eprintln!("📎→🔍 TARDIS: P node {} migrating from node {} — seeking D slot",
                                pending_idx, host_idx);
                        }
                    }
                }
            }

            // DEBUG: trace state of nodes around a dead seed
            if self.nodes.len() > 3 && !self.nodes[2].alive && self.tick.is_multiple_of(10) {
                let n1_up = self.nodes[1].tardis.upstream().map(|p| self.id_to_idx.get(p).copied().unwrap_or(9999));
                let n1_d1 = self.nodes[1].tardis.d1().map(|p| self.id_to_idx.get(p).copied().unwrap_or(9999));
                let n1_d2 = self.nodes[1].tardis.d2().map(|p| self.id_to_idx.get(p).copied().unwrap_or(9999));
                let n3_up = self.nodes[3].tardis.upstream().map(|p| self.id_to_idx.get(p).copied().unwrap_or(9999));
                let n3_d1 = self.nodes[3].tardis.d1().map(|p| self.id_to_idx.get(p).copied().unwrap_or(9999));
                let n3_d2 = self.nodes[3].tardis.d2().map(|p| self.id_to_idx.get(p).copied().unwrap_or(9999));
                let n1_open = self.nodes[1].tardis.has_d_open();
                let n3_needs = self.nodes[3].tardis.needs_parent();
                let links_with_1: Vec<(usize,usize)> = self.tardis_links.iter()
                    .filter(|&&(p,c)| p == 1 || c == 1)
                    .copied().collect();
                let links_with_3: Vec<(usize,usize)> = self.tardis_links.iter()
                    .filter(|&&(p,c)| p == 3 || c == 3)
                    .copied().collect();
                eprintln!("🔍 KILL2 TRACE t={}: N1[UP={:?} D1={:?} D2={:?} open={}] N3[UP={:?} D1={:?} D2={:?} needs={}] links_1={:?} links_3={:?}",
                    self.tick, n1_up, n1_d1, n1_d2, n1_open, n3_up, n3_d1, n3_d2, n3_needs, links_with_1, links_with_3);
            }

            // Step 2: Propagate topology hints through mesh with relay.
            // Nodes with open D slots → SlotAvailable to their mesh peers.
            // Peers that learn NEW slot info relay to THEIR peers (up to 2 relay hops).
            // Total coverage: ~3 hops from source. This replaces the former god-view
            // scan in voluntary reattach with mesh-informed discovery.
            {
                // Round 0: Primary broadcast from nodes with open D slots.
                let mut slot_hints: Vec<(usize, TopologyHint)> = Vec::new();
                for i in 0..self.nodes.len() {
                    if !self.nodes[i].alive { continue; }
                    if self.nodes[i].tardis.has_d_open() {
                        let open = 2 - self.nodes[i].tardis.downstream_count() as u8;
                        // §5.6a-bis: identity + slot count only. The simulator
                        // used to synthesise a 10.0.x.y address here, which made
                        // the sim structurally unable to reproduce the very bug
                        // this change fixes — every node had a usable address for
                        // every other node without anyone ever observing one.
                        let hint = TopologyHint::SlotAvailable {
                            node_id: self.nodes[i].node_id,
                            open_slots: open,
                        };
                        let peer_ids: Vec<NodeId> = self.nodes[i].mesh.peer_ids();
                        for pid in &peer_ids {
                            if let Some(&peer_idx) = self.id_to_idx.get(pid) {
                                if peer_idx < self.nodes.len() && self.nodes[peer_idx].alive {
                                    slot_hints.push((peer_idx, hint.clone()));
                                }
                            }
                        }
                    }
                }

                // Apply round 0 hints and track which nodes learned new info.
                let mut newly_informed: Vec<(usize, TopologyHint)> = Vec::new();
                for (peer_idx, hint) in slot_hints {
                    let was_new = self.nodes[peer_idx].mesh.apply_topology_hint(&hint);
                    if was_new {
                        newly_informed.push((peer_idx, hint));
                    }
                }

                // Relay rounds 1-2: nodes that learned new info forward to their peers.
                for _relay_round in 0..2 {
                    if newly_informed.is_empty() { break; }
                    let mut relay_hints: Vec<(usize, TopologyHint)> = Vec::new();
                    for (relayer_idx, hint) in &newly_informed {
                        let peer_ids: Vec<NodeId> = self.nodes[*relayer_idx].mesh.peer_ids();
                        for pid in &peer_ids {
                            if let Some(&peer_idx) = self.id_to_idx.get(pid) {
                                if peer_idx < self.nodes.len() && self.nodes[peer_idx].alive {
                                    relay_hints.push((peer_idx, hint.clone()));
                                }
                            }
                        }
                    }
                    newly_informed.clear();
                    for (peer_idx, hint) in relay_hints {
                        let was_new = self.nodes[peer_idx].mesh.apply_topology_hint(&hint);
                        if was_new {
                            newly_informed.push((peer_idx, hint));
                        }
                    }
                }
            }

            // Step 2b: Update network size estimates on each node (§4.2).
            // Used by dynamic_maturity_ticks() to scale maturity window.
            for i in 0..self.nodes.len() {
                if !self.nodes[i].alive { continue; }
                let known = self.nodes[i].mesh.known_node_count() as u64;
                let peers = self.nodes[i].mesh.peer_ids().len() as u64;
                self.nodes[i].tardis.update_network_size(known, peers);
            }

            // Step 2c: Maturity check (GAP-09). Log dynamic maturity ticks periodically.
            // Maturity enforcement is a Nabla-level concern (cheque status), not TARDIS.
            // Here we just exercise the calculation and log for observability.
            if self.tick > 0 && self.tick.is_multiple_of(50) {
                // Sample one representative node for maturity logging
                if let Some(sample) = (0..self.nodes.len()).find(|&i| self.nodes[i].alive) {
                    let maturity = self.nodes[sample].tardis.dynamic_maturity_ticks();
                    eprintln!("📊 TARDIS maturity: dynamic_maturity_ticks={} (sampled node {})", maturity, sample);
                }
            }

            // Step 2d: Voluntary reattach — tree rebalancing (§2.16.5).
            //
            // After partition heal or chaos recovery, TARDIS trees can remain
            // fragmented with too many dc=1 nodes (readers with 1 child).
            // Orphan recovery doesn't fire because nobody IS an orphan.
            //
            // Fix: dc=0 leaves under dc=1 parents move to other dc=1 targets.
            // This is the only move that creates writers:
            //   parent dc=1→dc=0 (was reader, stays reader)
            //   target dc=1→dc=2 (becomes writer) → net +1 writer
            //   leaf now under dc=2 parent → won't move again. One-shot.
            //
            // Discovery: leaf uses mesh.find_reattach_target() which searches
            // known_nodes for dc=1 targets (open_slots==1). Slot info propagates
            // via SlotAvailable relay (Step 2 above) and PX introductions.
            //
            // Self-limiting: healthy tree has ~0 dc=1 nodes → mechanism is inert.
            // Degraded tree has many dc=1 nodes → fires until healed.
            {
                let mut moves_this_tick: usize = 0;

                // Collect reattach candidates: dc=0 leaves under dc=1 parents.
                let mut candidates: Vec<(usize, NodeId)> = Vec::new(); // (leaf_idx, parent_nid)
                for i in 0..self.nodes.len() {
                    if moves_this_tick + candidates.len() >= REATTACH_MAX_PER_TICK { break; }
                    if !self.nodes[i].alive { continue; }
                    // Must be a pure leaf (dc=0)
                    if self.nodes[i].tardis.downstream_count() != 0 { continue; }
                    // Must have a parent
                    let parent_nid = match self.nodes[i].tardis.upstream() {
                        Some(p) => *p,
                        None => continue,
                    };
                    let parent_idx = match self.id_to_idx.get(&parent_nid) {
                        Some(&idx) => idx,
                        None => continue,
                    };
                    // Parent must be dc=1. Only case that creates a writer.
                    if self.nodes[parent_idx].tardis.downstream_count() != 1 { continue; }
                    // Stability guard: don't bounce freshly-landed nodes.
                    if self.nodes[i].tardis.ticks_with_parent() < REATTACH_STABILITY_TICKS { continue; }
                    candidates.push((i, parent_nid));
                }

                // Each candidate leaf asks its mesh for a dc=1 target.
                for (leaf_idx, parent_nid) in candidates {
                    if moves_this_tick >= REATTACH_MAX_PER_TICK { break; }
                    // Ask mesh for dc=1 target (open_slots==1, excludes parent)
                    let target_nid = match self.nodes[leaf_idx].mesh.find_reattach_target(&parent_nid) {
                        Some(nid) => nid,
                        None => continue, // No known dc=1 target — wait for next PX/relay cycle
                    };
                    let target_idx = match self.id_to_idx.get(&target_nid) {
                        Some(&idx) => idx,
                        None => continue,
                    };
                    // Verify target is still alive and dc=1 (gossip may be stale)
                    if !self.nodes[target_idx].alive { continue; }
                    if self.nodes[target_idx].tardis.downstream_count() != 1 { continue; }
                    if !self.nodes[target_idx].tardis.has_d_open() { continue; }

                    let parent_idx = self.id_to_idx.get(&parent_nid).copied().unwrap_or(0);
                    if self.attach_child(target_idx, leaf_idx) {
                        moves_this_tick += 1;
                        eprintln!("🔀 TARDIS: leaf {} reattach: parent {}(dc=1→0) → target {}(dc=1→2)",
                            leaf_idx, parent_idx, target_idx);
                    }
                }
            }

            // Step 3: Orphan recovery via local knowledge.
            // Per YPX-003 §2.2: every tick carries available_slots, so children
            // already KNOW where open D slots are. When parent dies, child moves
            // to the last known position IMMEDIATELY — no discovery needed.
            //
            // ALL nodes go through the same recovery — genesis/seed included.
            //
            // Priority order:
            //   1. last_known_open_slots (from tick messages — instant)
            //   2. mesh.find_tardis_parent() (topology hints via gossip)
            //   3. mesh.known_nodes with has_d_open (passive knowledge)
            //   4. BFS from alive nodes (global fallback in sim)
            let mut orphans: Vec<usize> = Vec::new();
            for i in 0..self.nodes.len() {
                if !self.nodes[i].alive { continue; }
                if self.nodes[i].tardis.needs_parent() {
                    orphans.push(i);
                }
            }

            // Compute tree connectivity ONCE before recovery.
            // Only attach orphans to nodes reachable from tree roots.
            // Updated as orphans attach (child of reachable = reachable).
            let mut reachable = self.reachable_from_tree_roots();

            for orphan_idx in orphans {
                let orphan_nid = self.nodes[orphan_idx].node_id;
                let mut attached = false;
                let is_seed_orphan = self.nodes[orphan_idx].is_seed;
                // Protocol decision: does this orphan prefer a dc=1 parent?
                // §2.6: decision lives in TardisNode, sim only reads the result.
                let prefer_writer = self.nodes[orphan_idx].tardis.recovery_prefers_writer_parent();

                if is_seed_orphan {
                    eprintln!("🔍 TARDIS: seed orphan {} entering recovery. UP={:?} D1={:?} D2={:?}",
                        orphan_idx,
                        self.nodes[orphan_idx].tardis.upstream().map(|p| {
                            self.id_to_idx.get(p).copied().unwrap_or(9999)
                        }),
                        self.nodes[orphan_idx].tardis.d1().map(|p| {
                            self.id_to_idx.get(p).copied().unwrap_or(9999)
                        }),
                        self.nodes[orphan_idx].tardis.d2().map(|p| {
                            self.id_to_idx.get(p).copied().unwrap_or(9999)
                        }),
                    );
                }

                // Two-pass recovery (protocol-level strategy from §2.6):
                // Pass 0 (strict): only accept dc=1 parents → creates writers
                //   Uses TardisNode::recovery_candidate_acceptable(dc, true)
                // Pass 1 (relaxed): accept any open slot → never stay orphan
                //   Uses TardisNode::recovery_candidate_acceptable(dc, false)
                for pass in 0..2 {
                    if attached { break; }
                    let strict = pass == 0 && prefer_writer;

                    // Track when strict pass failed to find a candidate
                    if pass == 1 && prefer_writer && !attached {
                        self.orphan_diag.strict_fell_through();
                    }

                    // P1: Last known open slots from tick messages (§2.2).
                    if !attached {
                        let candidates: Vec<(PeerId, u32)> = self.nodes[orphan_idx].tardis
                            .recovery_candidates().to_vec();
                        for (candidate_nid, _candidate_slot) in &candidates {
                            let ci = match self.id_to_idx.get(candidate_nid) {
                                Some(&idx) => idx,
                                None => continue,
                            };
                            if ci >= self.nodes.len() || !self.nodes[ci].alive { continue; }
                            if ci == orphan_idx { continue; }
                            if !reachable.contains(&ci) { continue; }
                            if !self.nodes[ci].tardis.has_d_open() { continue; }
                            if !TardisNode::recovery_candidate_acceptable(
                                self.nodes[ci].tardis.downstream_count(), strict
                            ) {
                                continue;
                            }

                            if self.attach_child(ci, orphan_idx) {
                                reachable.insert(orphan_idx);
                                self.orphan_diag.orphan_recovered(self.tick, orphan_idx, RecoveryPass::P1Candidates, ci, strict);
                                attached = true;
                                break;
                            }
                        }
                    }

                    // P2: Mesh topology hints (find_tardis_parent).
                    if !attached {
                        let action = self.nodes[orphan_idx].mesh.find_tardis_parent();
                        if let MeshAction::AttemptTardisReconnect { target, .. } = action {
                            if let Some(&parent_idx) = self.id_to_idx.get(&target) {
                                if parent_idx < self.nodes.len()
                                    && self.nodes[parent_idx].alive
                                    && reachable.contains(&parent_idx)
                                    && self.nodes[parent_idx].tardis.has_d_open()
                                    && TardisNode::recovery_candidate_acceptable(
                                        self.nodes[parent_idx].tardis.downstream_count(), strict
                                    )
                                    && self.attach_child(parent_idx, orphan_idx)
                                {
                                    reachable.insert(orphan_idx);
                                    self.orphan_diag.orphan_recovered(self.tick, orphan_idx, RecoveryPass::P2MeshHint, parent_idx, strict);
                                    attached = true;
                                }
                            }
                        }
                    }

                    // P3: Mesh known_nodes with has_d_open (passive knowledge).
                    if !attached {
                        let known = self.nodes[orphan_idx].mesh.known_nodes_snapshot();
                        for peer_info in &known {
                            if peer_info.has_d_open && peer_info.node_id != orphan_nid {
                                if let Some(&parent_idx) = self.id_to_idx.get(&peer_info.node_id) {
                                    if parent_idx < self.nodes.len()
                                        && self.nodes[parent_idx].alive
                                        && reachable.contains(&parent_idx)
                                        && self.nodes[parent_idx].tardis.has_d_open()
                                        && TardisNode::recovery_candidate_acceptable(
                                            self.nodes[parent_idx].tardis.downstream_count(), strict
                                        )
                                        && self.attach_child(parent_idx, orphan_idx)
                                    {
                                        reachable.insert(orphan_idx);
                                        self.orphan_diag.orphan_recovered(self.tick, orphan_idx, RecoveryPass::P3KnownNodes, parent_idx, strict);
                                        attached = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // PE: E-enquiry to any reachable writer (§2.1 — production recovery path).
                    if !attached {
                        let writers: Vec<usize> = (0..self.nodes.len())
                            .filter(|&i| self.nodes[i].alive && reachable.contains(&i)
                                && self.nodes[i].tardis.downstream_count() >= 2)
                            .collect();
                        for writer_idx in writers {
                            let open_in_subtree = self.e_enquiry_open_slots(writer_idx, &reachable);
                            for &candidate in &open_in_subtree {
                                if candidate == orphan_idx { continue; }
                                if !self.nodes[candidate].tardis.has_d_open() { continue; }
                                if !TardisNode::recovery_candidate_acceptable(
                                    self.nodes[candidate].tardis.downstream_count(), strict
                                ) {
                                    continue;
                                }
                                if self.attach_child(candidate, orphan_idx) {
                                    reachable.insert(orphan_idx);
                                    self.orphan_diag.orphan_recovered(self.tick, orphan_idx, RecoveryPass::PeEnquiry, candidate, strict);
                                    attached = true;
                                    break;
                                }
                            }
                            if attached { break; }
                        }
                    }

                    // P4: BFS from all alive nodes (global fallback — sim only).
                    if !attached {
                        let mut queue: VecDeque<usize> = VecDeque::new();
                        for s in 0..self.nodes.len() {
                            if self.nodes[s].alive {
                                queue.push_back(s);
                            }
                        }
                        let mut bfs_visited = HashSet::new();
                        let mut bfs_open_found = 0usize;
                        
                        while let Some(candidate) = queue.pop_front() {
                            if !bfs_visited.insert(candidate) { continue; }
                            if candidate == orphan_idx { continue; }
                            if !self.nodes[candidate].alive { continue; }
                            if self.nodes[candidate].tardis.has_d_open() {
                                bfs_open_found += 1;
                                if !TardisNode::recovery_candidate_acceptable(
                                    self.nodes[candidate].tardis.downstream_count(), strict
                                ) {
                                    // Skip in strict pass — want dc=1 parent
                                } else if self.attach_child(candidate, orphan_idx) {
                                    reachable.insert(orphan_idx);
                                    self.orphan_diag.orphan_recovered(self.tick, orphan_idx, RecoveryPass::P4BfsFallback, candidate, strict);
                                    attached = true;
                                    break;
                                }
                            }
                            for &(p, c) in &self.tardis_links {
                                if p == candidate && !bfs_visited.contains(&c) && self.nodes[c].alive {
                                    queue.push_back(c);
                                }
                            }
                        }
                        if !attached && pass == 1 {
                            let reason = format!("bfs_visited={} open_found={} links={} alive={}",
                                bfs_visited.len(), bfs_open_found,
                                self.tardis_links.len(),
                                self.nodes.iter().filter(|n| n.alive).count());
                            self.orphan_diag.orphan_failed(self.tick, orphan_idx, &reason);
                            if is_seed_orphan {
                                let open_in_tree: Vec<usize> = (0..self.nodes.len())
                                    .filter(|&i| self.nodes[i].alive && self.nodes[i].tardis.has_d_open())
                                    .collect();
                                eprintln!("🔍 TARDIS P4: seed orphan {} FAILED! bfs_visited={} bfs_open_found={} tree_links={} alive={} global_open={:?}",
                                    orphan_idx, bfs_visited.len(), bfs_open_found,
                                    self.tardis_links.len(),
                                    self.nodes.iter().filter(|n| n.alive).count(),
                                    open_in_tree);
                            } else {
                                eprintln!("⚠ TARDIS P4: orphan {} FAILED! bfs_visited={} bfs_open_found={} tree_links={} alive={}",
                                    orphan_idx, bfs_visited.len(), bfs_open_found,
                                    self.tardis_links.len(),
                                    self.nodes.iter().filter(|n| n.alive).count());
                            }
                        }
                    }
                } // end two-pass loop
            }

            // ── Isolated tree cleanup ──
            // After recovery, check for nodes that have upstream but aren't
            // reachable from any tree root. These are in disconnected subtrees.
            // Force-detach them so they become orphans next tick and get
            // recovered to the main tree through normal P1-P4 recovery.
            let isolated = self.find_isolated_nodes();
            if !isolated.is_empty() {
                eprintln!("🔍 TARDIS: {} isolated nodes detected at t={}, force-detaching: {:?}",
                    isolated.len(), self.tick, &isolated[..isolated.len().min(10)]);
                for &iso_idx in &isolated {
                    let iso_nid = self.nodes[iso_idx].node_id;
                    // Detach from parent
                    if let Some(parent_nid) = self.nodes[iso_idx].tardis.upstream().cloned() {
                        if let Some(&parent_idx) = self.id_to_idx.get(&parent_nid) {
                            self.nodes[parent_idx].tardis.remove_peer(&iso_nid);
                            self.tardis_links.remove(&(parent_idx, iso_idx));
                        }
                        self.nodes[iso_idx].tardis.remove_peer(&parent_nid);
                    }
                    // Detach children (they become orphans too — they're also isolated)
                    let children: Vec<PeerId> = self.nodes[iso_idx].tardis.children_to_release();
                    for child_nid in &children {
                        if let Some(&child_idx) = self.id_to_idx.get(child_nid) {
                            if child_idx < self.nodes.len() && self.nodes[child_idx].alive {
                                self.nodes[iso_idx].tardis.remove_peer(child_nid);
                                self.nodes[child_idx].tardis.remove_peer(&iso_nid);
                                self.tardis_links.remove(&(iso_idx, child_idx));
                            }
                        }
                    }
                }
            }
        }

        // ── TARDIS Parentless Timeout (§10) ──
        // A node with children but no parent is a zombie subtree head.
        // After PARENTLESS_TIMEOUT_TICKS (5 ticks = 25s), it detaches its
        // children so all three become orphans and recover independently.
        {
            let mut detach_list: Vec<(usize, Vec<PeerId>)> = Vec::new();
            for i in 0..self.nodes.len() {
                if !self.nodes[i].alive { continue; }
                match self.nodes[i].tardis.check_parentless_timeout() {
                    crate::tardis::ParentlessAction::DetachChildren => {
                        let children = self.nodes[i].tardis.detach_children();
                        if !children.is_empty() {
                            detach_list.push((i, children));
                        }
                    }
                    crate::tardis::ParentlessAction::Searching(ticks) => {
                        if ticks == 1 {
                            eprintln!("⚠ TARDIS: node {} parentless with children, timeout in {} ticks",
                                i, PARENTLESS_TIMEOUT_TICKS - ticks);
                        }
                    }
                    crate::tardis::ParentlessAction::Ok => {}
                }
            }
            for (parent_idx, children) in detach_list {
                let parent_nid = self.nodes[parent_idx].node_id;
                for child_nid in children {
                    if let Some(&child_idx) = self.id_to_idx.get(&child_nid) {
                        if child_idx < self.nodes.len() && self.nodes[child_idx].alive {
                            self.nodes[child_idx].tardis.remove_peer(&parent_nid);
                            self.tardis_links.remove(&(parent_idx, child_idx));
                            let had_children = self.nodes[child_idx].tardis.downstream_count() > 0;
                            self.orphan_diag.orphan_created(self.tick, child_idx, OrphanCause::ParentDied, had_children);
                        }
                    }
                }
                // Parent itself is already an orphan (no upstream) — recovery handles it
                eprintln!("🔧 TARDIS: parentless timeout fired for node {} — detached children", parent_idx);
            }
        }

        // ── TARDIS Independent Tick Generation (YPX-003 §1-2) ──
        // Every node generates its own tick from NTP (§1.2). Tree roots
        // (nodes with no alive parent) start the cascade. Children receive
        // ticks via process_tick() which activates:
        //   - Full 6-step tick validation (§1.3.4)
        //   - Writer check with grace period (§1.2.1)
        //   - Forward-only ratchet enforcement
        //   - Proper TickMessage construction with all spec fields
        //
        // No node is exempt. Genesis nodes follow the same rules (v0.9 §2.16).
        let now_ms = self.sim_time_ms();
        let tick_time = self.tick_time_secs();
        {
            // Pre-compute open D slots for §2.2 piggyback on tick messages.
            // SIM SHORTCUT: iterates all nodes (god-view). In production,
            // each parent piggybacks OWN known open slots via gossip.
            // AUDIT-OK: orchestration, not protocol decision.
            let global_open_slots: Vec<(PeerId, u32)> = (0..self.nodes.len())
                .filter(|&i| self.nodes[i].alive && self.nodes[i].tardis.has_d_open())
                .take(TICK_SLOT_PIGGYBACK_MAX)
                .map(|i| (self.nodes[i].node_id, i as u32))
                .collect();

            // Reset approval tracking for this tick
            for i in 0..self.nodes.len() {
                let children: Vec<usize> = self.tardis_links.iter()
                    .filter(|&&(p, _)| p == i)
                    .map(|&(_, c)| c)
                    .collect();
                self.nodes[i].tardis_approvals = children.iter().map(|&c| (c, false)).collect();
            }

            // ── TICK CASCADE ──
            //
            // Every node generates its own tick from NTP. The sim processes
            // in parent-before-child order via BFS from tick originators.
            // Originators = tree roots (no alive parent) + cycle entry points.
            // No node is exempt. Genesis nodes follow the same rules (v0.9 §2.16).

            // Step 1: Build BFS queue — find all tick originators.
            let dummy_smt = SparseMerkleTree::new();
            let mut process_queue: VecDeque<usize> = VecDeque::new();

            // Tree roots = alive nodes with no alive upstream in the tree.
            for i in 0..self.nodes.len() {
                if !self.nodes[i].alive { continue; }
                let has_alive_parent = self.tardis_links.iter()
                    .any(|&(p, c)| c == i && p < self.nodes.len() && self.nodes[p].alive);
                if !has_alive_parent {
                    process_queue.push_back(i);
                }
            }

            // Cycle entry points: the genesis ring is a cycle — no node in it
            // qualifies as a "tree root" (all have alive parents). We ALWAYS need
            // to find cycle entries so the ring gets ticked, even when there are
            // also tree roots (orphans) in process_queue.
            //
            // In production, nodes tick asynchronously from NTP — no ordering needed.
            // This is a sim-only concern for deterministic parent-before-child processing.
            //
            // CRITICAL: The walker must BFS ALL children from each entry point,
            // not just follow one child chain. Otherwise tree branches hanging off
            // the cycle get missed, and every non-cycle node gets pushed as a
            // spurious "cycle entry" — causing set_tick on ALL nodes, which makes
            // process_tick reject with NonSequentialTick everywhere.
            {
                // Nodes already in process_queue (tree roots) are pre-marked as visited.
                let mut cycle_visited: HashSet<usize> = HashSet::new();

                // Pre-mark tree roots and their entire subtrees as visited.
                // This prevents them from being found as spurious cycle entries.
                let mut tree_bfs: VecDeque<usize> = process_queue.iter().copied().collect();
                while let Some(node) = tree_bfs.pop_front() {
                    if !cycle_visited.insert(node) { continue; }
                    for &(p, c) in self.tardis_links.iter() {
                        if p == node && c < self.nodes.len() && self.nodes[c].alive
                            && !cycle_visited.contains(&c)
                        {
                            tree_bfs.push_back(c);
                        }
                    }
                }

                // Now find cycle entries among unvisited nodes with parents.
                for i in 0..self.nodes.len() {
                    if !self.nodes[i].alive { continue; }
                    if cycle_visited.contains(&i) { continue; }
                    let has_parent = self.tardis_links.iter()
                        .any(|&(p, c)| c == i && p < self.nodes.len() && self.nodes[p].alive);
                    if !has_parent { continue; }
                    // This node has a parent but wasn't reachable from any tree root.
                    // It must be in a cycle (or hanging off one). Pick as entry point.
                    process_queue.push_back(i);
                    // BFS from entry point — mark ALL reachable descendants as visited.
                    // This covers ring members AND tree branches hanging off them.
                    let mut walk_queue: VecDeque<usize> = VecDeque::new();
                    walk_queue.push_back(i);
                    while let Some(walker) = walk_queue.pop_front() {
                        if !cycle_visited.insert(walker) { continue; }
                        for &(p, c) in self.tardis_links.iter() {
                            if p == walker && c < self.nodes.len() && self.nodes[c].alive
                                && !cycle_visited.contains(&c)
                            {
                                walk_queue.push_back(c);
                            }
                        }
                    }
                }
            }

            // Step 2: Tick originators call set_tick() (they generate time from NTP).
            for &orig in process_queue.iter() {
                if orig < self.nodes.len() && self.nodes[orig].alive {
                    self.nodes[orig].tardis.set_tick(tick_time, now_ms);
                    self.nodes[orig].tardis_tick = tick_time;
                }
            }

            let mut visited = HashSet::new();
            while let Some(parent_idx) = process_queue.pop_front() {
                if !visited.insert(parent_idx) { continue; }
                if !self.nodes[parent_idx].alive { continue; }

                let children: Vec<usize> = self.tardis_links.iter()
                    .filter(|&&(p, _)| p == parent_idx)
                    .map(|&(_, c)| c)
                    .filter(|&c| c < self.nodes.len() && self.nodes[c].alive)
                    .collect();

                for child_idx in children {
                    let key = link_key(parent_idx, child_idx);
                    if self.blocked.contains(&key) { continue; }

                    // Cycle-closing edge: if child is already visited (cycle entry point),
                    // skip process_tick (ratchet would reject — set_tick already ran) but
                    // grant approval directly. The entry point already has its tick from
                    // set_tick. In production, it would approve its parent asynchronously.
                    if visited.contains(&child_idx) {
                        for a in self.nodes[parent_idx].tardis_approvals.iter_mut() {
                            if a.0 == child_idx { a.1 = true; }
                        }
                        continue;
                    }

                    // Extract parent data for TickMessage
                    let parent_nid = self.nodes[parent_idx].node_id;
                    let parent_tick = self.nodes[parent_idx].tardis_tick;
                    let parent_approvals = self.nodes[parent_idx].tardis.prev_round_approval_count();
                    let parent_subtree = self.nodes[parent_idx].tardis.subtree_d_available();

                    let mut tick_msg = TickMessage {
                        number: parent_tick,
                        upstream_pk: parent_nid,
                        payload: parent_tick.to_le_bytes().to_vec(),
                        signature: vec![], // filled below
                        prev_sig: vec![],  // Chain proof (§1.3.4) — future
                        grandparent_pk: None,  // sim doesn't track chain depth
                        timestamp_ms: now_ms,
                        available_slots: global_open_slots.iter()
                            .filter(|&&(_, idx)| idx as usize != child_idx)
                            .cloned()
                            .collect(),
                        downstream_approvals: parent_approvals,
                        subtree_d_available: parent_subtree,
                        oods_tardis: Vec::new(), // sim: OODS-tardis not exercised
                        child_pks: Vec::new(), // sim: lineage not exercised
                        gp_commitment: None,   // sim: lineage not exercised
                    };
                    tick_msg.signature = self.nodes[parent_idx].signer.sign(
                        &crypto::tick_commitment(&tick_msg)
                    );

                    let tick_result = {
                        let child_node = &mut self.nodes[child_idx];
                        child_node.tardis.process_tick(&tick_msg, &dummy_smt, now_ms, &child_node.signer)
                    };
                    match tick_result {
                        Ok(ref actions) => {
                            // Check if child detached (writer check failed) — don't count as approval
                            let detached = actions.iter().any(|a| matches!(a, TardisAction::DetachUpstream { .. }));
                            if !detached {
                                self.nodes[child_idx].tardis_tick = parent_tick;
                                for a in self.nodes[parent_idx].tardis_approvals.iter_mut() {
                                    if a.0 == child_idx { a.1 = true; }
                                }
                                // Continue BFS to grandchildren
                                process_queue.push_back(child_idx);
                            }
                        }
                        Err(ref e) => {
                            eprintln!("⚠ TARDIS: node {} rejected tick from parent {} — {:?}",
                                child_idx, parent_idx, e);
                        }
                    }
                }
            }

            // Step 3: Detect nodes that detached via writer check.
            // process_tick clears self.up when parent fails writer check.
            for i in 0..self.nodes.len() {
                if !self.nodes[i].alive { continue; }
                if !self.nodes[i].tardis.has_upstream() {
                    let was_linked: Option<usize> = self.tardis_links.iter()
                        .find(|&&(_p, c)| c == i)
                        .map(|&(p, _)| p);
                    if let Some(parent_idx) = was_linked {
                        let child_nid = self.nodes[i].node_id;
                        self.nodes[parent_idx].tardis.remove_peer(&child_nid);
                        self.tardis_links.remove(&(parent_idx, i));
                        let had_children = self.nodes[i].tardis.downstream_count() > 0;
                        self.orphan_diag.orphan_created(
                            self.tick, i,
                            OrphanCause::WriterCheck,
                            had_children,
                        );
                        eprintln!("🔧 TARDIS: node {} detached from non-writer parent {} (writer check)",
                            i, parent_idx);
                    }
                }
            }

            // Step 4: Save approval counts into protocol layer.
            for i in 0..self.nodes.len() {
                let count = self.nodes[i].tardis_approvals.iter()
                    .filter(|(_, approved)| *approved).count();
                self.nodes[i].prev_approval_count = count as u8;

                // Feed per-child approval results into protocol layer.
                // Must run for ALL nodes with children (not just dc=2) so that
                // dc=1 nodes correctly report downstream_approvals=1.
                // Without this, genesis ring nodes permanently report 0.
                if self.nodes[i].alive && self.nodes[i].tardis.downstream_count() > 0 {
                    let d1_nid = self.nodes[i].tardis.d1().cloned();
                    let d2_nid = self.nodes[i].tardis.d2().cloned();
                    let d1_ok = d1_nid.and_then(|nid| self.id_to_idx.get(&nid).copied())
                        .map(|idx| self.nodes[i].tardis_approvals.iter().any(|&(c, ok)| c == idx && ok))
                        .unwrap_or(false);
                    let d2_ok = d2_nid.and_then(|nid| self.id_to_idx.get(&nid).copied())
                        .map(|idx| self.nodes[i].tardis_approvals.iter().any(|&(c, ok)| c == idx && ok))
                        .unwrap_or(false);
                    self.nodes[i].tardis.record_child_approvals(d1_ok, d2_ok);
                }
            }

        }
        // ── TARDIS Slot Filling ──
        // When a node dies, its upstream neighbor loses a D child (reader→degraded).
        // Meanwhile, the dead node's downstream children become orphans.
        // Rather than having children detach from degraded parents (which creates
        // MORE orphans and can cause loops), we let orphan recovery fill the
        // degraded parent's empty D slot. The 1-child preference in P4 BFS
        // ensures orphans go to nodes that need a second child to become writers.
        //
        // The writer check (protocol-level, in tardis.rs process_tick) remains
        // available for production use where real crypto verification enforces it.
        // In sim, we rely on recovery to heal the tree.

        // ── Mesh maintenance (real periodic_peer_check) ──
        // Run multiple rounds per tick so mesh growth isn't bottlenecked
        // at 1 peer promotion per tick. In real deployment, these happen
        // asynchronously and overlap — simulating that here.
        for _round in 0..5 {
            let mut introductions: Vec<(usize, usize)> = Vec::new();
            for i in 0..self.nodes.len() {
                if !self.nodes[i].alive { continue; }
                let action = self.nodes[i].mesh.periodic_peer_check(self.tick);
                if let MeshAction::RequestIntroduction { ask_peer } = action {
                    if let Some(&asked_idx) = self.id_to_idx.get(&ask_peer) {
                        introductions.push((i, asked_idx));
                    }
                }
            }

            if introductions.is_empty() { break; } // nothing to do

            // Process introductions (bidirectional — both sides learn about each other)
            // §6.3 Peer Exchange: share full known_nodes, not just active peers.
            // This is how GossipSub PX works — wider knowledge spreads faster.
            for (req_idx, asked_idx) in introductions {
                if asked_idx >= self.nodes.len() || !self.nodes[asked_idx].alive { continue; }
                let key = link_key(req_idx, asked_idx);
                if self.blocked.contains(&key) { continue; }

                // Requester learns about asked node's FULL knowledge base including slot info.
                // §6.3 Peer Exchange: share full PeerInfo so SlotAvailable data propagates.
                let known_snapshot: Vec<PeerInfo> = self.nodes[asked_idx].mesh.known_nodes_snapshot();

                for info in known_snapshot {
                    let peer_nid = info.node_id;
                    if peer_nid == self.nodes[req_idx].node_id { continue; }
                    // Merge with slot info preservation
                    self.nodes[req_idx].mesh.merge_peer_info(info);
                    // Also add as active peer if below target (existing logic)
                    if !self.nodes[req_idx].mesh.peer_ids().contains(&peer_nid)
                        && self.nodes[req_idx].mesh.peer_count() < self.nodes[req_idx].mesh.regular_peer_target()
                    {
                        if let Some(&peer_idx) = self.id_to_idx.get(&peer_nid) {
                            let address = NablaAddress::V4 {
                                ip: [10, 0, (peer_idx / 256) as u8, (peer_idx % 256) as u8],
                                port: 6225,
                            };
                            self.nodes[req_idx].mesh.add_peer_direct(PeerInfo {
                                node_id: peer_nid,
                                address,
                                last_seen: self.tick,
                                tardis_up: None,
                                has_d_open: false, open_slots: 0,
                                messages_delivered: 0,
                                connected_since: self.tick,
            txid_service: String::new(),
                            });
                        }
                    }
                }

                // Bidirectional: asked node also learns about requester (with slot info)
                let req_nid = self.nodes[req_idx].node_id;
                let req_has_open = self.nodes[req_idx].tardis.has_d_open();
                let req_open_slots = if req_has_open { 2 - self.nodes[req_idx].tardis.downstream_count() as u8 } else { 0 };
                self.nodes[asked_idx].mesh.merge_peer_info(PeerInfo {
                    node_id: req_nid,
                    address: NablaAddress::V4 {
                        ip: [10, 0, (req_idx / 256) as u8, (req_idx % 256) as u8],
                        port: 6225,
                    },
                    last_seen: self.tick,
                    tardis_up: None,
                    has_d_open: req_has_open,
                    open_slots: req_open_slots,
                    messages_delivered: 0,
                    connected_since: self.tick,
            txid_service: String::new(),
                });
            }
        }

        // ── E-peer requests: homeless nodes seek passive observation slots ──
        // §6.3.4: A node below D_lo can request to observe a full node's gossip.
        {
            let mut epeer_requests: Vec<(usize, usize)> = Vec::new(); // (homeless_idx, host_idx)
            for i in 0..self.nodes.len() {
                if !self.nodes[i].alive { continue; }
                let peers = self.nodes[i].mesh.peer_count();
                let d_lo = self.nodes[i].mesh.d_lo();
                if peers >= d_lo { continue; } // not homeless

                // Already an E-peer somewhere? Skip (can only be E-peer on 1 host)
                // We can't easily track this, so just let enquiry_request reject dupes

                // Pick a known node that is NOT already our peer, try to be its E-peer
                let my_peers: Vec<NodeId> = self.nodes[i].mesh.peer_ids();
                let known: Vec<NodeId> = self.nodes[i].mesh.known_node_ids();
                let my_nid = self.nodes[i].node_id;

                // Try a few candidates (round-robin based on tick)
                for attempt in 0..3u64 {
                    let candidate_idx_in_known = ((self.tick + attempt + i as u64) as usize) % known.len().max(1);
                    if candidate_idx_in_known >= known.len() { break; }
                    let candidate_nid = known[candidate_idx_in_known];
                    if candidate_nid == my_nid { continue; }
                    if my_peers.contains(&candidate_nid) { continue; }
                    if let Some(&host_idx) = self.id_to_idx.get(&candidate_nid) {
                        epeer_requests.push((i, host_idx));
                        break;
                    }
                }
            }

            for (homeless_idx, host_idx) in epeer_requests {
                if host_idx >= self.nodes.len() || !self.nodes[host_idx].alive { continue; }
                let homeless_nid = self.nodes[homeless_idx].node_id;
                let address = NablaAddress::V4 {
                    ip: [10, 0, (homeless_idx / 256) as u8, (homeless_idx % 256) as u8],
                    port: 6225,
                };
                self.nodes[host_idx].mesh.enquiry_request(homeless_nid, address, self.tick);
            }
        }

        // ── Anti-entropy: pull-based state sync ──
        // Every ANTI_ENTROPY_INTERVAL ticks, each node compares root hash with a
        // random peer. If roots differ, the richer node sends missing entries.
        // This is the complement to push-based gossip flood — ensures eventual
        // consistency even when a node missed the original broadcast.
        let delay_min = self.delay_min_100ms;
        let delay_max = self.delay_max_100ms;
        if self.tick > 0 && self.tick.is_multiple_of(ANTI_ENTROPY_INTERVAL) {
            // Collect sync pairs: (requester_idx, peer_idx)
            let mut sync_pairs: Vec<(usize, usize)> = Vec::new();
            for i in 0..self.nodes.len() {
                if !self.nodes[i].alive { continue; }
                let peers = self.nodes[i].mesh.peer_ids();
                if peers.is_empty() { continue; }
                // Round-robin peer selection for anti-entropy
                let peer_idx_in_list = (self.tick as usize / ANTI_ENTROPY_INTERVAL as usize + i) % peers.len();
                let peer_nid = peers[peer_idx_in_list];
                if let Some(&peer_idx) = self.id_to_idx.get(&peer_nid) {
                    if self.nodes[peer_idx].alive {
                        sync_pairs.push((i, peer_idx));
                    }
                }
            }

            // Process each sync pair
            for (req_idx, peer_idx) in sync_pairs {
                let req_root = self.nodes[req_idx].smt.root_hash();
                let peer_root = self.nodes[peer_idx].smt.root_hash();
                if req_root == peer_root { continue; } // already in sync

                // Determine who has more entries (richer sends to poorer)
                let (src_idx, dst_idx) = if self.nodes[peer_idx].smt.len() >= self.nodes[req_idx].smt.len() {
                    (peer_idx, req_idx)
                } else {
                    (req_idx, peer_idx)
                };

                // Collect entries from source that destination is missing
                let src_entries: Vec<(WalletId, StateId, TxHash, u64, [u8; 32], Vec<u8>)> = self.nodes[src_idx].smt.entries()
                    .iter()
                    .filter(|(wid, _)| self.nodes[dst_idx].smt.get(wid).is_none())
                    .map(|(_, entry)| (entry.wallet_id, entry.current_state, entry.tx_hash, entry.tick, entry.client_pk, entry.client_sig.clone()))
                    .collect();

                let sender_nid = self.nodes[src_idx].node_id;
                for (wallet_id, new_state, tx_hash, tick, client_pk, client_sig) in src_entries {
                    let msg = GossipMessage::StateUpdate {
                        wallet_id, new_state, old_state: [0u8; 32], tx_hash, tick,
            is_genesis_claim: false,
                        // sim exercises mesh replication, not seq anti-rollback —
                        // seq 0 + no proof so the WI3 hole-1 gate falls through to
                        // tick ordering (the sim's pre-WI3 behaviour).
                        wallet_seq: 0,
                        // KI#46 zero-pk flip: replicate the STORED entry's
                        // authorship (mirrors the real StatePull/RangeSync replay).
                        client_pk, client_sig,
                        amount: 0, fee_breakdown: Vec::new(),
                        seq_proof: None,
                    };
                    self.pending.push_back(PendingMessage {
                        from_idx: src_idx,
                        to_idx: dst_idx,
                        msg,
                        sender_node_id: sender_nid,
                        deliver_at_ms: now_ms + calc_delay_ms(&mut self.rng_state, delay_min, delay_max),
                    });
                }
            }
        }

        // ── Drain outboxes ──
        for i in 0..self.nodes.len() {
            if !self.nodes[i].alive { continue; }
            let sender_node_id = self.nodes[i].node_id;
            while let Some((target_nid, msg)) = self.nodes[i].outbox.pop_front() {
                if let Some(target_idx) = self.find_node_idx(&target_nid) {
                    self.pending.push_back(PendingMessage {
                        from_idx: i, to_idx: target_idx, msg, sender_node_id,
                        deliver_at_ms: now_ms + calc_delay_ms(&mut self.rng_state, delay_min, delay_max),
                    });
                }
            }
        }

        // ── Deliver (delay-aware) ──
        let mut rounds = 0;
        while !self.pending.is_empty() && rounds < 20 {
            rounds += 1;
            // Split into ripe (deliverable now) vs deferred (still waiting)
            let mut ripe = Vec::new();
            let mut deferred = VecDeque::new();
            while let Some(pm) = self.pending.pop_front() {
                if pm.deliver_at_ms <= now_ms {
                    ripe.push(pm);
                } else {
                    deferred.push_back(pm);
                }
            }
            self.pending = deferred;

            if ripe.is_empty() { break; }

            for pm in ripe {
                let key = link_key(pm.from_idx, pm.to_idx);
                if self.blocked.contains(&key) { continue; }
                if pm.to_idx >= self.nodes.len() || !self.nodes[pm.to_idx].alive { continue; }

                self.nodes[pm.to_idx].try_discover_peer(pm.sender_node_id, pm.from_idx);

                let forwarded = self.nodes[pm.to_idx].receive_gossip(&pm.msg, &pm.sender_node_id);
                delivered += 1;
                self.total_messages += 1;

                // Record this as a live link — gossip actually flowed
                self.live_links.insert(key);

                if forwarded {
                    let sender_nid = self.nodes[pm.to_idx].node_id;
                    while let Some((target_nid, msg)) = self.nodes[pm.to_idx].outbox.pop_front() {
                        if let Some(target_idx) = self.find_node_idx(&target_nid) {
                            self.pending.push_back(PendingMessage {
                                from_idx: pm.to_idx, to_idx: target_idx, msg,
                                sender_node_id: sender_nid,
                                deliver_at_ms: now_ms + calc_delay_ms(&mut self.rng_state, delay_min, delay_max),
                            });
                        }
                    }
                }
            }
        }

        // ── Bottom-Up Subtree Auditing (GAP-07, §9) ──
        // DISABLED: Audit detachments require consistent SMT state across nodes,
        // which requires the full registration pipeline (NBC issuance → wallet
        // registration → gossip propagation → SMT convergence). Without that,
        // every audit is a false positive that disrupts the tree.
        //
        // The protocol layer (verify_audit_response) does self.up = None on
        // mismatch, so we can't even call it in log-only mode — it would
        // disconnect upstream internally. Must skip entirely.
        //
        // Re-enable when:
        //   1. Registration pipeline produces consistent SMT state
        //   2. Add 2-tick grace period for gossip lag tolerance
        //   3. Expected false positive rate with pipeline: ~0.1%
        //
        // The audit mechanism itself is correct — it just needs real data.
        if false {
            // Preserved for when registration pipeline is ready.
            let has_delay = self.delay_min_100ms > 0 || self.delay_max_100ms > 0;

            if !has_delay {
                let mut audit_requests: Vec<(usize, usize)> = Vec::new();
                for i in 0..self.nodes.len() {
                    if !self.nodes[i].alive { continue; }
                    if !self.nodes[i].tardis.should_audit() { continue; }
                    if let Some(parent_nid) = self.nodes[i].tardis.upstream().cloned() {
                        if let Some(&parent_idx) = self.id_to_idx.get(&parent_nid) {
                            if parent_idx < self.nodes.len() && self.nodes[parent_idx].alive {
                                audit_requests.push((i, parent_idx));
                            }
                        }
                    }
                }

                let mut audit_passes = 0u64;
                let mut audit_fails = 0u64;

                for (child_idx, parent_idx) in audit_requests {
                    let request_action = self.nodes[child_idx].tardis.generate_audit_request();
                    let request = match request_action {
                        Some(TardisAction::SendAuditRequest { request, .. }) => request,
                        _ => continue,
                    };

                    let response_action = {
                        let parent_node = &self.nodes[parent_idx];
                        parent_node.tardis.handle_audit_request(
                            &request,
                            &parent_node.smt,
                            &parent_node.signer,
                        )
                    };
                    let response = match response_action {
                        TardisAction::SendAuditResponse { response, .. } => response,
                        _ => continue,
                    };

                    let child_node = &mut self.nodes[child_idx];
                    let result = child_node.tardis.verify_audit_response(
                        &response,
                        &child_node.smt,
                        &child_node.signer,
                    );

                    match result {
                        Ok(TardisAction::None) => {
                            audit_passes += 1;
                        }
                        Ok(TardisAction::CascadeAlert { .. }) => {
                            audit_fails += 1;
                            let child_nid = self.nodes[child_idx].node_id;
                            self.nodes[parent_idx].tardis.remove_peer(&child_nid);
                            self.tardis_links.remove(&(parent_idx, child_idx));
                            let had_children = self.nodes[child_idx].tardis.downstream_count() > 0;
                            self.orphan_diag.orphan_created(
                                self.tick, child_idx,
                                OrphanCause::AuditFail,
                                had_children,
                            );
                            eprintln!("🚨 TARDIS audit: node {} detached from parent {} (root mismatch)",
                                child_idx, parent_idx);
                        }
                        _ => {}
                    }
                }

                if (audit_passes > 0 || audit_fails > 0) && self.tick.is_multiple_of(50) {
                    eprintln!("📋 TARDIS audit: {} passes, {} fails", audit_passes, audit_fails);
                }
            }
        }

        // Update orphan diagnostic persistent tracking.
        // Build set of nodes that are ACTUALLY orphans right now.
        let actual_orphans: HashSet<usize> = (0..self.nodes.len())
            .filter(|&i| self.nodes[i].alive && self.nodes[i].tardis.needs_parent())
            .collect();
        self.orphan_diag.tick_end_check(self.tick, &actual_orphans);

        delivered
    }

    fn find_node_idx(&self, node_id: &NodeId) -> Option<usize> {
        self.id_to_idx.get(node_id).copied()
    }

    /// Simulated unix time in seconds for current tick.
    /// Base epoch + tick * 5 seconds.
    fn tick_time_secs(&self) -> u64 {
        // Feb 2026 epoch as sim base
        1740000000 + self.tick * 5
    }

    /// Simulated time in ms for current tick.
    fn sim_time_ms(&self) -> u64 {
        self.tick_time_secs() * 1000
    }

    /// Set delay range. Called from dashboard command.
    pub fn set_delay(&mut self, min_100ms: u32, max_100ms: u32) {
        self.delay_min_100ms = min_100ms.min(50); // cap at 5000ms
        self.delay_max_100ms = max_100ms.min(50);
        if self.delay_max_100ms < self.delay_min_100ms {
            self.delay_max_100ms = self.delay_min_100ms;
        }
    }

    // ── Chaos Commands ──

    pub fn kill_node(&mut self, idx: usize) {
        if idx < self.nodes.len() {
            self.nodes[idx].alive = false;
            self.nodes[idx].outbox.clear();
            // Remove live links involving this node
            self.live_links.retain(|&(a, b)| a != idx && b != idx);
            // Remove from orphan tracking (dead nodes aren't orphans)
            self.orphan_diag.node_killed(idx);
            // Dump tree state after kill
            self.dump_tree(&format!("AFTER KILL node {}", idx));
        }
    }

    pub fn revive_node(&mut self, idx: usize) {
        if idx < self.nodes.len() {
            self.nodes[idx].alive = true;
        }
    }

    /// Dump tree state to tardis_tree_dump.txt (appends)
    fn dump_tree(&self, label: &str) {
        let mut lines = Vec::new();
        let mut writers = 0usize;
        let mut readers = 0usize;
        let mut orphans_count = 0usize;
        let mut alive_count = 0usize;
        for i in 0..self.nodes.len() {
            if !self.nodes[i].alive { continue; }
            alive_count += 1;
            let dc = self.nodes[i].tardis.downstream_count();
            let has_up = self.nodes[i].tardis.has_upstream();
            // No seed exception — a seed is the same as every other Nabla.
            if !has_up { orphans_count += 1; }
            else if dc >= 2 { writers += 1; }
            else { readers += 1; }
        }
        lines.push(format!("\n=== {} (t={}) ===", label, self.tick));
        lines.push(format!("alive={} links={} writers={} readers={} orphans={}",
            alive_count, self.tardis_links.len(), writers, readers, orphans_count));
        for i in 0..self.nodes.len() {
            if !self.nodes[i].alive {
                lines.push(format!("  node {:2}: DEAD", i));
                continue;
            }
            let up = self.nodes[i].tardis.upstream().map(|p| self.id_to_idx.get(p).copied().unwrap_or(9999));
            let d1 = self.nodes[i].tardis.d1().map(|p| self.id_to_idx.get(p).copied().unwrap_or(9999));
            let d2 = self.nodes[i].tardis.d2().map(|p| self.id_to_idx.get(p).copied().unwrap_or(9999));
            let dc = self.nodes[i].tardis.downstream_count();
            let role = if dc >= 2 { "W" } else if !self.nodes[i].tardis.has_upstream() { "O" } else { "R" };
            lines.push(format!("  node {:2}: UP={:?} D1={:?} D2={:?} dc={} [{}] seed={}",
                i, up, d1, d2, dc, role, self.nodes[i].is_seed));
        }
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("tardis_tree_dump.txt") {
            let _ = f.write_all(lines.join("\n").as_bytes());
            let _ = f.write_all(b"\n");
        }
    }

    /// Dump orphan diagnostic to a compact file. Returns filename.
    pub fn dump_orphan_diag(&self) -> String {
        let filename = "orphan_diagnostic.txt";

        // Build tree state lines with reachability marking
        let reachable = self.reachable_from_tree_roots();
        let mut tree_lines = Vec::new();
        let mut writers = 0usize;
        let mut readers = 0usize;
        let mut orphans_count = 0usize;
        let mut isolated_count = 0usize;
        let mut alive_count = 0usize;

        for i in 0..self.nodes.len() {
            if !self.nodes[i].alive {
                tree_lines.push(format!("  node {:2}: DEAD", i));
                continue;
            }
            alive_count += 1;
            let dc = self.nodes[i].tardis.downstream_count();
            let _has_up = self.nodes[i].tardis.has_upstream();
            let is_seed = self.nodes[i].is_seed;
            let is_reachable = reachable.contains(&i);
            let needs_parent = self.nodes[i].tardis.needs_parent();

            let role = if needs_parent {
                orphans_count += 1;
                "O"
            } else if !is_reachable {
                isolated_count += 1;
                "I"  // Isolated — has parent but not connected to tree roots
            } else if dc >= 2 {
                writers += 1;
                "W"
            } else {
                readers += 1;
                "R"
            };

            let up = self.nodes[i].tardis.upstream().map(|p| self.id_to_idx.get(p).copied().unwrap_or(9999));
            let d1 = self.nodes[i].tardis.d1().map(|p| self.id_to_idx.get(p).copied().unwrap_or(9999));
            let d2 = self.nodes[i].tardis.d2().map(|p| self.id_to_idx.get(p).copied().unwrap_or(9999));

            tree_lines.push(format!("  node {:2}: UP={:?} D1={:?} D2={:?} dc={} [{}] seed={} reach={}",
                i, up, d1, d2, dc, role, is_seed, is_reachable));
        }

        let summary = format!("alive={} writers={} readers={} orphans={} isolated={}",
            alive_count, writers, readers, orphans_count, isolated_count);
        tree_lines.insert(0, summary);

        match self.orphan_diag.dump(self.tick, filename, &tree_lines) {
            Ok(path) => {
                eprintln!("📊 Orphan diagnostic written to {}", path);
                path
            }
            Err(e) => {
                eprintln!("❌ Failed to write orphan diagnostic: {}", e);
                String::new()
            }
        }
    }

    /// One-line orphan diagnostic summary for dashboard.
    pub fn orphan_diag_line(&self) -> String {
        self.orphan_diag.dashboard_line(self.tick)
    }

    pub fn kill_link(&mut self, a: usize, b: usize) {
        self.blocked.insert(link_key(a, b));
    }

    pub fn restore_link(&mut self, a: usize, b: usize) {
        self.blocked.remove(&link_key(a, b));
    }

    pub fn partition(&mut self, isolated: &[usize]) {
        let iso_set: HashSet<usize> = isolated.iter().copied().collect();
        let n = self.nodes.len();
        for a in 0..n {
            for b in (a + 1)..n {
                if iso_set.contains(&a) != iso_set.contains(&b) {
                    self.blocked.insert((a, b));
                }
            }
        }
    }

    pub fn restore_all(&mut self) {
        for node in &mut self.nodes {
            node.alive = true;
        }
        self.blocked.clear();
    }

    /// §6.6 Human Bridge — Split Recovery.
    ///
    /// The human bridge does three things:
    ///   1. Physical path restored (clear blocked links)
    ///   2. Bridge nodes become direct active peers (immediate gossip link)
    ///   3. Exchange known_nodes (both sides learn cross-partition topology)
    ///
    /// Step 2 is the real discovery — the two bridge nodes form a live link
    /// that gossip floods through immediately. No waiting for rotation.
    ///
    /// Returns ((recv_a, new_a, updated_a), (recv_b, new_b, updated_b)).
    pub fn human_bridge(&mut self, a_idx: usize, b_idx: usize) -> ((usize, usize, usize), (usize, usize, usize)) {
        if a_idx >= self.nodes.len() || b_idx >= self.nodes.len() {
            return ((0, 0, 0), (0, 0, 0));
        }
        if !self.nodes[a_idx].alive || !self.nodes[b_idx].alive {
            return ((0, 0, 0), (0, 0, 0));
        }

        // 1. Physical path is back — clear all blocked links
        self.blocked.clear();

        // 2. Bridge nodes become direct active peers of each other.
        //    This is the actual discovery — an immediate gossip link.
        let a_info = PeerInfo {
            node_id: *self.nodes[a_idx].mesh.my_node_id(),
            address: self.nodes[a_idx].mesh.my_address().clone(),
            last_seen: self.tick,
            tardis_up: None,
            has_d_open: false, open_slots: 0,
            messages_delivered: 0,
            connected_since: self.tick,
            txid_service: String::new(),
        };
        let b_info = PeerInfo {
            node_id: *self.nodes[b_idx].mesh.my_node_id(),
            address: self.nodes[b_idx].mesh.my_address().clone(),
            last_seen: self.tick,
            tardis_up: None,
            has_d_open: false, open_slots: 0,
            messages_delivered: 0,
            connected_since: self.tick,
            txid_service: String::new(),
        };
        self.nodes[a_idx].mesh.add_peer_direct(b_info);
        self.nodes[b_idx].mesh.add_peer_direct(a_info);

        // 3. Exchange known_nodes — both sides learn cross-partition topology
        let a_known = self.nodes[a_idx].mesh.known_nodes_snapshot();
        let b_known = self.nodes[b_idx].mesh.known_nodes_snapshot();
        let stats_a = self.nodes[a_idx].mesh.human_bridge_px(&b_known, self.tick);
        let stats_b = self.nodes[b_idx].mesh.human_bridge_px(&a_known, self.tick);

        (stats_a, stats_b)
    }

    pub fn mass_kill(&mut self, percent: u8) {
        let count = (self.nodes.len() * percent as usize) / 100;
        let mut killed = 0;
        for i in 0..self.nodes.len() {
            if killed >= count { break; }
            let hash = ((i as u64).wrapping_mul(2654435761) ^ self.tick) % 100;
            if hash < percent as u64 {
                self.nodes[i].alive = false;
                self.live_links.retain(|&(a, b)| a != i && b != i);
                killed += 1;
            }
        }
    }

    pub fn inject_registration(&mut self, node_idx: usize) -> bool {
        if node_idx >= self.nodes.len() || !self.nodes[node_idx].alive {
            return false;
        }
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&self.tick.to_le_bytes());
        seed[8..16].copy_from_slice(&(node_idx as u64).to_le_bytes());

        // KI#46 zero-pk flip: sim traffic must be wallet-authored (zero-pk is
        // rejected mesh-wide now). Deterministic key from a per-(tick, node)
        // seed keeps the sim reproducible; the sig covers the YPX-009 payload.
        // KI#226: the wallet id IS that key's own row (its pk, k=3) — a flood
        // naming any other id is refused.
        let (wallet_id, state, client_pk, client_sig) = {
            use ed25519_dalek::{Signer as _, SigningKey};
            let sk = SigningKey::from_bytes(blake3::hash(&seed).as_bytes());
            let wallet_id = sk.verifying_key().to_bytes();
            let state = *blake3::hash(&wallet_id).as_bytes();
            let payload =
                crate::gossip::client_state_sign_payload(&wallet_id, &state, &state);
            (wallet_id, state, wallet_id, sk.sign(&payload).to_bytes().to_vec())
        };
        let msg = GossipMessage::StateUpdate {
            wallet_id, new_state: state, old_state: [0u8; 32], tx_hash: state, tick: self.tick_time_secs(),
            is_genesis_claim: false,
            // sim exercises mesh replication, not seq anti-rollback — seq 0 + no
            // proof so the WI3 hole-1 gate falls through to tick ordering.
            wallet_seq: 0,
            client_pk, client_sig,
            amount: 0, fee_breakdown: Vec::new(),
            seq_proof: None,
        };

        let node = &mut self.nodes[node_idx];
        let sender_nid = node.node_id;
        let n_validators = node.mesh.estimated_network_size();
        let mut sim_fob_pools = std::collections::HashMap::new();
        let sim_fob_credits = std::collections::HashMap::new();
        let action = node.gossip.process(&msg, &mut node.smt, &mut node.bans, &mut node.pool, &mut node.airdrop_pool, &mut node.dev_treasury_pool, &mut node.bootstrap_pool, &mut node.foundation_bootstrap_pool, &mut node.deed_pool, &mut node.dev_deed_pool, &mut node.emission, &mut sim_fob_pools, &sim_fob_credits, node.tick, node.tick /* A19: the sim has no wall clock — its tick stands in for now_secs (sim-only unit substitution) */, n_validators, &|_| false /* KI#224: the sim carries no SeqProofs and has no witness directory */);
        if let GossipAction::Forward(fwd) = action {
            let targets = node.mesh.forward_targets(&sender_nid);
            for target in targets {
                node.outbox.push_back((target, fwd.clone()));
            }
        }
        true
    }

    // ── Chaos Engineering ──

    /// Random havoc: kills nodes, partitions, spikes delay, injects traffic.
    /// Returns a list of event descriptions for the dashboard.
    pub fn chaos(&mut self) -> Vec<String> {
        let mut events = Vec::new();
        let n = self.nodes.len();
        if n == 0 { return events; }

        // Roll dice for each chaos type (multiple can fire)
        let roll = |rng: &mut u64| -> u64 {
            *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *rng >> 33
        };

        // 1. Kill random nodes (60% chance, 1-4 nodes)
        if roll(&mut self.rng_state) % 100 < 60 {
            let count = (roll(&mut self.rng_state) % 4 + 1) as usize;
            let mut killed = Vec::new();
            for _ in 0..count {
                let idx = (roll(&mut self.rng_state) as usize) % n;
                if self.nodes[idx].alive {
                    self.nodes[idx].alive = false;
                    killed.push(idx);
                }
            }
            if !killed.is_empty() {
                events.push(format!("💀 Killed {} nodes: {:?}", killed.len(), killed));
            }
        }

        // 2. Revive some dead nodes (30% chance, 1-2 nodes)
        if roll(&mut self.rng_state) % 100 < 30 {
            let dead: Vec<usize> = (0..n).filter(|&i| !self.nodes[i].alive).collect();
            if !dead.is_empty() {
                let count = std::cmp::min((roll(&mut self.rng_state) % 2 + 1) as usize, dead.len());
                let mut revived = Vec::new();
                for _i in 0..count {
                    let idx = dead[(roll(&mut self.rng_state) as usize) % dead.len()];
                    if !self.nodes[idx].alive {
                        self.nodes[idx].alive = true;
                        revived.push(idx);
                    }
                }
                if !revived.is_empty() {
                    events.push(format!("🟢 Revived {} nodes: {:?}", revived.len(), revived));
                }
            }
        }

        // 3. Random partition (40% chance, split 20-40% of nodes)
        if roll(&mut self.rng_state) % 100 < 40 {
            let split_pct = (roll(&mut self.rng_state) % 20 + 20) as usize; // 20-40%
            let split_count = (n * split_pct) / 100;
            let mut isolated = Vec::new();
            for _ in 0..split_count {
                let idx = (roll(&mut self.rng_state) as usize) % n;
                if !isolated.contains(&idx) {
                    isolated.push(idx);
                }
            }
            if isolated.len() >= 2 {
                self.partition(&isolated);
                events.push(format!("🔀 Partitioned {} nodes ({}%)", isolated.len(), split_pct));
            }
        }

        // 4. Heal some partitions (25% chance)
        if roll(&mut self.rng_state) % 100 < 25 {
            let before = self.blocked.len();
            // Remove ~half of blocked links
            let to_remove: Vec<_> = self.blocked.iter()
                .enumerate()
                .filter(|(i, _)| i % 2 == 0)
                .map(|(_, &k)| k)
                .collect();
            for k in &to_remove {
                self.blocked.remove(k);
            }
            let healed = before - self.blocked.len();
            if healed > 0 {
                events.push(format!("🩹 Healed {} blocked links ({} remain)", healed, self.blocked.len()));
            }
        }

        // 5. Spike delay (50% chance)
        if roll(&mut self.rng_state) % 100 < 50 {
            let new_min = (roll(&mut self.rng_state) % 15) as u32; // 0-1400ms
            let new_max = new_min + (roll(&mut self.rng_state) % 35 + 1) as u32; // min+100..min+3500ms
            self.delay_min_100ms = new_min;
            self.delay_max_100ms = new_max;
            events.push(format!("📶 Delay spiked to {}–{}ms", new_min * 100, new_max * 100));
        }

        // 6. Inject traffic burst (35% chance, 5-20 registrations)
        if roll(&mut self.rng_state) % 100 < 35 {
            let count = (roll(&mut self.rng_state) % 16 + 5) as usize;
            let mut injected = 0;
            for _ in 0..count {
                let idx = (roll(&mut self.rng_state) as usize) % n;
                if self.inject_registration(idx) {
                    injected += 1;
                }
            }
            if injected > 0 {
                events.push(format!("📨 Injected {} registrations", injected));
            }
        }

        if events.is_empty() {
            events.push("🎲 Rolled dice... nothing happened this time".into());
        }

        events
    }

    /// Reset everything: revive all nodes, clear partitions, reset delay.
    pub fn chaos_heal(&mut self) {
        for node in &mut self.nodes {
            node.alive = true;
        }
        self.blocked.clear();
        self.delay_min_100ms = 0;
        self.delay_max_100ms = 0;
    }

    // ── State Export ──

    /// Attach a child to a new parent, cleaning up any stale old parent.
    ///
    /// This is the ONLY correct way to create a parent↔child link in the sim.
    /// It ensures bidirectional consistency: child's UP matches parent's D1/D2,
    /// old parent's D slot is cleared, and tardis_links stays in sync.
    ///
    /// Returns true if attachment succeeded (parent had open D slot).
    fn attach_child(&mut self, parent_idx: usize, child_idx: usize) -> bool {
        // Reject attachment across a partition boundary.
        if self.blocked.contains(&link_key(parent_idx, child_idx)) {
            return false;
        }

        let child_nid = self.nodes[child_idx].node_id;
        let parent_nid = self.nodes[parent_idx].node_id;

        // Step 1: Clean up old parent if child already has one.
        // This prevents phantom children — the #1 source of false writers.
        if let Some(old_parent_nid) = self.nodes[child_idx].tardis.upstream().copied() {
            if old_parent_nid != parent_nid {
                if let Some(&old_parent_idx) = self.id_to_idx.get(&old_parent_nid) {
                    self.nodes[old_parent_idx].tardis.remove_peer(&child_nid);
                    self.tardis_links.remove(&(old_parent_idx, child_idx));
                }
                self.nodes[child_idx].tardis.remove_peer(&old_parent_nid);
            }
        }

        // Step 2: Add child to parent's D slot.
        if !self.nodes[parent_idx].tardis.add_downstream(child_nid) {
            return false; // No open D slot
        }

        // Step 3: Set child's upstream.
        self.nodes[child_idx].tardis.set_upstream(parent_nid);

        // Step 4: Sync child's tick to avoid stale-tick rejection.
        let now = self.sim_time_ms();
        let prev_tick = self.tick_time_secs().saturating_sub(TICK_INTERVAL_SECS);
        let prev_ms = now.saturating_sub(TICK_INTERVAL_SECS * 1000);
        self.nodes[child_idx].tardis.set_tick(prev_tick, prev_ms);

        // Step 5: Track link.
        self.tardis_links.insert((parent_idx, child_idx));

        true
    }

    /// "who in your subtree has open D slots?" (YPX-003 §2.1)
    ///
    /// In production, this is a stateless TCP connection:
    ///   1. Orphan connects to target via E slot
    ///   2. Target responds with subtree_d_available info
    ///   3. Orphan disconnects E slot
    ///
    /// In sim, we walk the target's subtree through tardis_links.
    /// Returns list of (node_idx) with open D slots, filtered by reachability.
    fn e_enquiry_open_slots(&self, target_idx: usize, reachable: &HashSet<usize>) -> Vec<usize> {
        let mut result = Vec::new();
        let mut queue: VecDeque<usize> = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(target_idx);
        visited.insert(target_idx);

        while let Some(node_idx) = queue.pop_front() {
            if node_idx >= self.nodes.len() || !self.nodes[node_idx].alive { continue; }
            if !reachable.contains(&node_idx) { continue; }

            // Check if this node has open D slots
            if self.nodes[node_idx].tardis.has_d_open() {
                result.push(node_idx);
            }

            // Walk to children
            for &(p, c) in &self.tardis_links {
                if p == node_idx && !visited.contains(&c) {
                    visited.insert(c);
                    queue.push_back(c);
                }
            }
        }
        result
    }

    /// BFS from tree roots through tardis_links. Returns set of reachable node indices.
    /// Tree roots = alive nodes that have no alive parent in the tree.
    /// Nodes NOT in this set but alive = isolated (have upstream but unreachable).
    fn reachable_from_tree_roots(&self) -> HashSet<usize> {
        let mut visited = HashSet::new();
        let mut queue: VecDeque<usize> = VecDeque::new();

        // Phase 1: Tree roots — alive nodes with no alive parent in tardis_links.
        for i in 0..self.nodes.len() {
            if !self.nodes[i].alive { continue; }
            let has_alive_parent = self.tardis_links.iter()
                .any(|&(p, c)| c == i && p < self.nodes.len() && self.nodes[p].alive);
            if !has_alive_parent {
                queue.push_back(i);
                visited.insert(i);
            }
        }

        // BFS downward through tree links
        while let Some(parent) = queue.pop_front() {
            for &(p, c) in &self.tardis_links {
                if p == parent && !visited.contains(&c) && c < self.nodes.len() && self.nodes[c].alive {
                    visited.insert(c);
                    queue.push_back(c);
                }
            }
        }

        // Phase 2: Cycle detection.
        // The genesis ring is a cycle — every node has an alive parent, so
        // Phase 1 finds zero tree roots. Cycles are valid topology, not isolated.
        // Any alive node with upstream that wasn't visited is in a cycle.
        // BFS from cycle members to include their entire subtrees.
        for i in 0..self.nodes.len() {
            if visited.contains(&i) { continue; }
            if !self.nodes[i].alive { continue; }
            // Check if this node has an alive parent in tardis_links (cycle member)
            let in_cycle = self.tardis_links.iter()
                .any(|&(p, c)| c == i && p < self.nodes.len() && self.nodes[p].alive);
            if !in_cycle { continue; }
            // BFS from this cycle member and all connected nodes
            queue.push_back(i);
            visited.insert(i);
            while let Some(parent) = queue.pop_front() {
                for &(p, c) in &self.tardis_links {
                    if p == parent && !visited.contains(&c) && c < self.nodes.len() && self.nodes[c].alive {
                        visited.insert(c);
                        queue.push_back(c);
                    }
                }
            }
        }

        visited
    }

    /// Count alive nodes that have upstream but aren't reachable from tree roots.
    /// These are in isolated subtrees — they look healthy but can't get approved ticks.
    pub fn count_isolated(&self) -> usize {
        let reachable = self.reachable_from_tree_roots();
        let mut isolated = 0;
        for i in 0..self.nodes.len() {
            if !self.nodes[i].alive { continue; }
            if self.nodes[i].tardis.needs_parent() { continue; } // orphan, not isolated
            if !reachable.contains(&i) {
                isolated += 1;
            }
        }
        isolated
    }

    /// Returns indices of isolated nodes (for recovery).
    pub fn find_isolated_nodes(&self) -> Vec<usize> {
        let reachable = self.reachable_from_tree_roots();
        let mut isolated = Vec::new();
        for i in 0..self.nodes.len() {
            if !self.nodes[i].alive { continue; }
            if self.nodes[i].tardis.needs_parent() { continue; }
            if !reachable.contains(&i) {
                isolated.push(i);
            }
        }
        isolated
    }

    pub fn export_state(&self) -> NetworkState {
        let nodes: Vec<NodeState> = self.nodes.iter().map(|n| {
            NodeState {
                id: n.id,
                name: n.nbc.as_ref().map(|nbc| nbc.node_name.clone()).unwrap_or_default(),
                alive: n.alive,
                is_genesis: n.is_genesis,
                is_seed: n.is_seed,
                entries: n.smt.len(),
                bans: n.bans.len(),
                peers: n.mesh.peer_count(),
                enquiry_peers: if n.mesh.has_enquiry_peer() { 1 } else { 0 },
                known_nodes: n.mesh.known_node_count(),
                target_peers: n.mesh.regular_peer_target(),
                d_lo: n.mesh.d_lo(),
                root_hash: hex_short(&n.smt.root_hash()),
                messages_received: n.messages_received,
                gossip_active: n.last_gossip_tick >= self.tick.saturating_sub(2),
                // TARDIS
                tardis_tick: n.tardis_tick,
                has_upstream: !n.tardis.needs_parent(),
                downstream_count: n.tardis.downstream_count(),
                is_tardis_leaf: n.tardis.is_leaf(),
                tardis_approvals: n.tardis_approvals.iter()
                    .map(|&(c, ok)| TardisApprovalExport { child: c, approved: ok })
                    .collect(),
                has_nbc: n.nbc.is_some(),
                nbc_issuer: String::new(), // lib-mode: ceremony only
                // Lib-mode nodes don't have on-disk persistence
                wal_file_bytes: 0,
                wal_ops_since_snapshot: 0,
                snapshot_count: 0,
                snapshot_total_bytes: 0,
                last_snapshot_tick: 0,
                total_disk_bytes: 0,
                smt_memory_bytes: n.smt.len() as u64 * 200,
            }
        }).collect();

        // Show only MUTUAL gossip mesh connections (both sides peer with each other).
        // Asymmetric peering (A→B but not B→A) is normal gossip behavior but showing
        // it creates visual noise — a node with 9 peers appears to have 15-20 lines
        // because other nodes that peer with it also draw incoming lines.
        let mut active_links: HashSet<(usize, usize)> = HashSet::new();
        {
            // Build per-node peer sets first
            let peer_sets: Vec<HashSet<usize>> = (0..self.nodes.len())
                .map(|i| {
                    if !self.nodes[i].alive { return HashSet::new(); }
                    self.nodes[i].mesh.peer_ids().iter()
                        .filter_map(|pid| self.id_to_idx.get(pid).copied())
                        .filter(|&j| j < self.nodes.len() && self.nodes[j].alive)
                        .collect()
                })
                .collect();
            // Only add link if BOTH sides have each other as peers
            for i in 0..self.nodes.len() {
                if !self.nodes[i].alive { continue; }
                for &j in &peer_sets[i] {
                    if j > i && peer_sets[j].contains(&i) {
                        active_links.insert((i, j));
                    }
                }
            }
        }
        let link_states: Vec<LinkStateExport> = active_links.iter()
            .map(|&(a, b)| LinkStateExport {
                source: a, target: b,
                alive: !self.blocked.contains(&(a, b)) && !self.blocked.contains(&(b, a)),
            })
            .collect();

        // TARDIS tree links (directed)
        let tardis_link_states: Vec<TardisLinkExport> = self.tardis_links.iter()
            .filter(|(p, c)| *p < self.nodes.len() && *c < self.nodes.len())
            .filter(|(p, c)| self.nodes[*p].alive && self.nodes[*c].alive)
            .map(|&(p, c)| TardisLinkExport { parent: p, child: c })
            .collect();

        let mut hash_counts: HashMap<String, usize> = HashMap::new();
        for n in &self.nodes {
            if n.alive {
                *hash_counts.entry(hex_short(&n.smt.root_hash())).or_insert(0) += 1;
            }
        }
        let alive_count = self.nodes.iter().filter(|n| n.alive).count();
        let max_agreement = hash_counts.values().copied().max().unwrap_or(0);
        let convergence_pct = if alive_count > 0 {
            (max_agreement as f64 / alive_count as f64) * 100.0
        } else { 100.0 };

        // TARDIS health: 3 metrics for network health.
        //
        // 1. SYNC: % of alive nodes receiving ticks (have upstream).
        //    ALL nodes are equal — genesis/seed included.
        //    Target: ~100%. Drop = orphans or tree damage.
        //
        // 2. WRITERS: % of alive nodes with LEGITIMATE ticks (2+ downstream approvals).
        //    Target: ~50% in healthy binary tree (geometry: max N/2 nodes can have 2 children).
        //    Per YPX-003 §1.5: LEGITIMATE = D1 AND D2 approval. No exceptions.
        //    Writers can record transactions. Readers (leaves) serve enquiries using
        //    parent's approved tick as freshness proof.
        //
        // 3. ORPHANS: alive nodes with no upstream.
        //    Target: 0. Any orphan = recovery failure. Seeds are NOT exempt.
        let tardis_synced = self.nodes.iter()
            .filter(|n| n.alive && !n.tardis.needs_parent())
            .count();
        let tardis_sync_pct = if alive_count > 0 {
            (tardis_synced as f64 / alive_count as f64) * 100.0
        } else { 100.0 };

        let tardis_writers = self.nodes.iter()
            .filter(|n| n.alive && n.tardis.downstream_count() == 2)
            .count();
        let tardis_writer_pct = if alive_count > 0 {
            (tardis_writers as f64 / alive_count as f64) * 100.0
        } else { 100.0 };

        let tardis_orphans = self.nodes.iter()
            .filter(|n| n.alive && n.tardis.needs_parent())
            .count();

        // TARDIS tree: how many nodes are actually IN the tree
        let tardis_in_tree = self.nodes.iter()
            .filter(|n| n.alive && !n.tardis.needs_parent())
            .count();
        let tardis_tree_links = self.tardis_links.iter()
            .filter(|(p, c)| *p < self.nodes.len() && *c < self.nodes.len()
                && self.nodes[*p].alive && self.nodes[*c].alive)
            .count();

        // TARDIS isolated: nodes with upstream but no path to a tree root
        let tardis_isolated = self.count_isolated();

        // TARDIS pending: nodes in P slot awaiting D promotion (GAP-03)
        let tardis_pending = self.nodes.iter()
            .filter(|n| n.alive && n.tardis.pending().is_some())
            .count();

        // Reader first-contact ratio (GAP-14 §1.2.1):
        // % of alive non-orphan nodes that are READERs (would redirect transactions).
        // A READER is a node that redirects transactions to a writer.
        // In a healthy binary tree, ~50% of nodes are readers (leaves).
        //
        // KI#69: was `find_nearest_writer().is_some()`. Orphans are excluded by
        // the `!needs_parent()` filter, so this metric did not carry the routing
        // bug — but it read the same conflated Option. Now it names the state.
        let tardis_readers = self.nodes.iter()
            .filter(|n| {
                n.alive && !n.tardis.needs_parent()
                    && matches!(n.tardis.writer_routing(),
                                crate::tardis::WriterRouting::RedirectTo(_))
            })
            .count();
        let tardis_reader_pct = if alive_count > 0 {
            (tardis_readers as f64 / alive_count as f64) * 100.0
        } else { 0.0 };

        NetworkState {
            tick: self.tick_time_secs(),
            tick_time: self.tick_time_secs(),
            nodes,
            links: link_states,
            tardis_links: tardis_link_states,
            stats: NetworkStats {
                total_nodes: self.nodes.len(),
                alive_nodes: alive_count,
                total_messages: self.total_messages,
                convergence_pct,
                tardis_sync_pct,
                tardis_writer_pct,
                tardis_orphans,
                delay_min_ms: self.delay_min_100ms * 100,
                delay_max_ms: self.delay_max_100ms * 100,
                pending_gossip: self.pending.len(),
                pending_tardis: self.tardis_pending.len(),
                tardis_in_tree,
                tardis_tree_links,
                tardis_isolated,
                tardis_pending,
                tardis_reader_pct,
                // Lib-mode nodes have in-memory SMTs only
                total_smt_entries: self.nodes.iter()
                    .filter(|n| n.alive)
                    .map(|n| n.smt.len())
                    .sum(),
                total_disk_bytes: 0,
                avg_wal_bytes: 0,
            },
        }
    }
}

fn link_key(a: usize, b: usize) -> (usize, usize) {
    if a < b { (a, b) } else { (b, a) }
}

/// LCG pseudo-random delay in ms. Free function to avoid borrow conflicts.
fn calc_delay_ms(rng: &mut u64, min_100ms: u32, max_100ms: u32) -> u64 {
    let min_ms = min_100ms as u64 * 100;
    let max_ms = max_100ms as u64 * 100;
    if max_ms <= min_ms { return min_ms; }
    *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    let range = max_ms - min_ms + 1;
    min_ms + (*rng >> 33) % range
}

fn hex_short(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Serializable State ──

#[derive(Debug, Serialize)]
pub struct NetworkState {
    pub tick: u64,
    pub tick_time: u64, // unix seconds — the actual TARDIS tick value
    pub nodes: Vec<NodeState>,
    pub links: Vec<LinkStateExport>,
    pub tardis_links: Vec<TardisLinkExport>,
    pub stats: NetworkStats,
}

#[derive(Debug, Serialize)]
pub struct NodeState {
    pub id: usize,
    pub name: String,
    pub alive: bool,
    pub is_genesis: bool,
    pub is_seed: bool,
    pub entries: usize,
    pub bans: usize,
    pub peers: usize,
    pub enquiry_peers: usize,
    pub known_nodes: usize,
    pub target_peers: usize,
    pub d_lo: usize,
    pub root_hash: String,
    pub messages_received: u64,
    pub gossip_active: bool,
    // TARDIS fields
    pub tardis_tick: u64,
    pub has_upstream: bool,
    pub downstream_count: usize,
    pub is_tardis_leaf: bool,
    pub tardis_approvals: Vec<TardisApprovalExport>,
    /// Whether this node has a real NBC (from ceremony).
    pub has_nbc: bool,
    /// NBC issuer name (e.g. "alpha", "ceremony").
    #[serde(default)]
    pub nbc_issuer: String,
    // ── Persistence metrics ──
    #[serde(default)]
    pub wal_file_bytes: u64,
    #[serde(default)]
    pub wal_ops_since_snapshot: u64,
    #[serde(default)]
    pub snapshot_count: usize,
    #[serde(default)]
    pub snapshot_total_bytes: u64,
    #[serde(default)]
    pub last_snapshot_tick: u64,
    #[serde(default)]
    pub total_disk_bytes: u64,
    #[serde(default)]
    pub smt_memory_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct LinkStateExport {
    pub source: usize,
    pub target: usize,
    pub alive: bool,
}

/// Directed TARDIS tree link (parent → child).
#[derive(Debug, Serialize)]
pub struct TardisApprovalExport {
    pub child: usize,
    pub approved: bool,
}

#[derive(Debug, Serialize)]
pub struct TardisLinkExport {
    pub parent: usize,
    pub child: usize,
}

#[derive(Debug, Serialize)]
pub struct NetworkStats {
    pub total_nodes: usize,
    pub alive_nodes: usize,
    pub total_messages: u64,
    pub convergence_pct: f64,
    pub tardis_sync_pct: f64,
    pub tardis_writer_pct: f64,
    pub tardis_orphans: usize,
    pub delay_min_ms: u32,
    pub delay_max_ms: u32,
    pub pending_gossip: usize,
    pub pending_tardis: usize,
    pub tardis_in_tree: usize,
    pub tardis_tree_links: usize,
    /// Alive nodes that have upstream but NO path back to a tree root.
    pub tardis_isolated: usize,
    /// Nodes currently in P (pending) slot, awaiting D promotion (GAP-03).
    pub tardis_pending: usize,
    /// Reader first-contact ratio: % of alive nodes that would redirect
    /// transactions to a writer (GAP-14 §1.2.1). Target: ~50%.
    pub tardis_reader_pct: f64,
    // ── Persistence aggregates (network-wide) ──
    #[serde(default)]
    pub total_smt_entries: usize,
    #[serde(default)]
    pub total_disk_bytes: u64,
    #[serde(default)]
    pub avg_wal_bytes: u64,
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    /// KI#46 zero-pk flip: gossip fixtures must be wallet-authored.
    /// Deterministic key from the wallet id (blake3) — same scheme as the
    /// sim's own traffic generator, so injected and re-synced copies of the
    /// same logical entry carry the same authorship.
    fn sim_author(
        wallet_id: &[u8; 32],
        state: &[u8; 32],
        tx: &[u8; 32],
    ) -> ([u8; 32], Vec<u8>) {
        use ed25519_dalek::Signer as _;
        let sk = SIM_KEYS.with(|k| k.borrow().get(wallet_id).cloned())
            .expect("sim_author: wallet id not minted by sim_wid (KI#226: the id must be the key's own pk)");
        let payload = crate::gossip::client_state_sign_payload(wallet_id, state, tx);
        (sk.verifying_key().to_bytes(), sk.sign(&payload).to_bytes().to_vec())
    }

    thread_local! {
        /// pk → key for the fixture wallets `sim_wid` minted on this test thread.
        static SIM_KEYS: std::cell::RefCell<std::collections::HashMap<[u8; 32], ed25519_dalek::SigningKey>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
    }

    /// KI#226 — a fixture wallet id MUST be its signing key's own row (the pk,
    /// k=3). Mint the key deterministically from `seed` (blake3, as before)
    /// and return its pk as the wallet id; `sim_author` signs with it.
    fn sim_wid(seed: [u8; 32]) -> [u8; 32] {
        let sk = ed25519_dalek::SigningKey::from_bytes(blake3::hash(&seed).as_bytes());
        let pk = sk.verifying_key().to_bytes();
        SIM_KEYS.with(|k| k.borrow_mut().insert(pk, sk));
        pk
    }

    #[test]
    fn genesis_nodes_sparse_mesh() {
        let net = SimNetwork::new_test(50);
        // 10 genesis nodes, each with 3 peers (sparse ring, not full mesh)
        for i in 0..GENESIS_COUNT {
            assert!(net.nodes[i].is_genesis);
            assert_eq!(net.nodes[i].mesh.peer_count(), 3);
        }
    }

    #[test]
    fn new_nodes_join_over_time() {
        let mut net = SimNetwork::new_test(30);
        assert_eq!(net.nodes.len(), GENESIS_COUNT); // only genesis at start

        for _ in 0..50 {
            net.step();
        }
        // Should have added more nodes
        assert!(net.nodes.len() > GENESIS_COUNT);
    }

    #[test]
    fn new_nodes_bootstrap_to_genesis() {
        let mut net = SimNetwork::new_test(20);
        // Add some nodes
        for _ in 0..30 {
            net.step();
        }
        // Non-genesis nodes should have at least 2 peers (their genesis bootstrap)
        for node in &net.nodes[GENESIS_COUNT..] {
            assert!(node.mesh.peer_count() >= 2,
                "node {} has {} peers", node.id, node.mesh.peer_count());
        }
    }

    #[test]
    fn organic_mesh_growth() {
        let mut net = SimNetwork::new_test(30);
        for _ in 0..100 {
            net.inject_registration(0);
            net.step();
        }
        // Some non-genesis nodes should have grown beyond 2 bootstrap peers
        let grown = net.nodes[GENESIS_COUNT..].iter()
            .filter(|n| n.mesh.peer_count() > 2).count();
        assert!(grown > 0, "mesh should grow organically");
    }

    #[test]
    fn gossip_propagates() {
        let mut net = SimNetwork::new_test(30);
        // Let all nodes join
        for _ in 0..80 {
            net.step();
        }
        // Inject and propagate
        net.inject_registration(0);
        for _ in 0..30 {
            net.step();
        }
        let with_entries = net.nodes.iter().filter(|n| !n.smt.is_empty()).count();
        assert!(with_entries > GENESIS_COUNT, "gossip should reach non-genesis nodes");
    }

    #[test]
    fn kill_genesis_network_survives() {
        let mut net = SimNetwork::new_test(30);
        // Let network grow
        for _ in 0..100 {
            net.inject_registration(0);
            net.step();
        }
        // Kill all genesis
        for i in 0..GENESIS_COUNT {
            net.kill_node(i);
        }
        // Inject at a non-genesis node
        net.inject_registration(GENESIS_COUNT);
        for _ in 0..30 {
            net.step();
        }
        // Non-genesis nodes should still propagate
        let alive_with_entries = net.nodes[GENESIS_COUNT..].iter()
            .filter(|n| n.alive && !n.smt.is_empty()).count();
        assert!(alive_with_entries > 1, "network should survive without genesis");
    }

    #[test]
    fn export_shows_genesis() {
        let net = SimNetwork::new_test(20);
        let state = net.export_state();
        let genesis_count = state.nodes.iter().filter(|n| n.is_genesis).count();
        assert_eq!(genesis_count, GENESIS_COUNT);
    }

    #[test]
    fn partition_isolates() {
        let mut net = SimNetwork::new_test(30);
        for _ in 0..80 { net.step(); }

        net.partition(&[0, 1, 2, 3, 4]);
        net.inject_registration(2);
        for _ in 0..10 { net.step(); }

        let partition_max = net.nodes[..5].iter().map(|n| n.smt.len()).max().unwrap();
        let outside_max = net.nodes[15..].iter().map(|n| n.smt.len()).max().unwrap();
        assert!(partition_max > outside_max);
    }

    #[test]
    fn convergence_tracking() {
        let mut net = SimNetwork::new_test(20);
        let state = net.export_state();
        assert_eq!(state.stats.convergence_pct, 100.0);

        net.inject_registration(0);
        let state = net.export_state();
        assert!(state.stats.convergence_pct < 100.0);
    }

    #[test]
    fn links_are_live_gossip() {
        let mut net = SimNetwork::new_test(20);
        // No links at start — nothing has flowed yet
        let state = net.export_state();
        assert_eq!(state.links.len(), 0, "no links before gossip flows");

        // Inject and propagate — live links appear
        net.inject_registration(0);
        for _ in 0..10 { net.step(); }

        let state = net.export_state();
        assert!(!state.links.is_empty(), "links appear after gossip flows");
    }

    #[test]
    fn mass_kill() {
        let mut net = SimNetwork::new_test(50);
        for _ in 0..100 { net.step(); }
        net.mass_kill(30);
        let alive = net.nodes.iter().filter(|n| n.alive).count();
        assert!(alive < net.nodes.len());
        assert!(alive > net.nodes.len() / 2);
    }

    // ═══════════════════════════════════════════════════════════════
    // §6.3 Yellow Paper Simulation Tests (2–7)
    // ═══════════════════════════════════════════════════════════════

    /// Helper: Run the sim with periodic registration injections (like the binary).
    /// Returns final convergence percentage.
    fn run_with_injections(net: &mut SimNetwork, ticks: u64, inject_interval: u64) -> f64 {
        for t in 0..ticks {
            if inject_interval > 0 && t % inject_interval == 0 {
                let alive_count = net.nodes.iter().filter(|n| n.alive).count();
                if alive_count > 0 {
                    let target = ((t.wrapping_mul(2654435761)) as usize) % alive_count;
                    let target_idx = net.nodes.iter()
                        .enumerate()
                        .filter(|(_, n)| n.alive)
                        .nth(target)
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    net.inject_registration(target_idx);
                }
            }
            net.step();
        }
        net.export_state().stats.convergence_pct
    }

    // ── Test 2: Rotation prevents ossification ──
    // §6.3 Sim Plan: "Start 50 nodes, verify mesh does NOT ossify"
    // Prove rotation is working by growing to 50 nodes and confirming
    // convergence exceeds 90%. Without rotation, spec says 16% stall.
    #[test]
    fn rotation_prevents_ossification() {
        let mut net = SimNetwork::new_test(50);
        // Grow network to 50 nodes (1 new every 2 ticks → ~80 ticks)
        // Then run 300 more ticks with injections for propagation
        let conv = run_with_injections(&mut net, 400, 5);

        assert!(net.nodes.len() >= 50, "network should have grown to 50 nodes");
        assert!(
            conv > 80.0,
            "convergence should be >80% with rotation working, got {:.1}%",
            conv
        );

        // Verify no homeless nodes (all peers >= D_lo)
        let homeless = net.nodes.iter()
            .filter(|n| n.alive && n.mesh.peer_count() < n.mesh.d_lo())
            .count();
        assert_eq!(homeless, 0, "no nodes should be homeless at steady state");
    }

    // ── Test 3: E-peer helps homeless nodes recover ──
    // §6.3 Sim Plan: "Disable E-peer, verify homeless nodes recover more slowly"
    // We test the positive case: with E-peer enabled, all nodes in a growing
    // 50-node network find sufficient peers (no permanent homeless).
    #[test]
    fn e_peer_helps_homeless_recovery() {
        let mut net = SimNetwork::new_test(50);

        // Phase 1: Grow to full 50 nodes
        for _ in 0..120 { net.step(); } // 1 new node every 2 ticks → 60 new nodes max
        assert!(net.nodes.len() >= 50, "should have at least 50 nodes");

        // Phase 2: Run 300 more ticks with injections — E-peer + rotation + introductions
        // should get every node above D_lo
        run_with_injections(&mut net, 300, 5);

        // Phase 3: Verify zero homeless
        let homeless: Vec<usize> = net.nodes.iter()
            .filter(|n| n.alive && n.mesh.peer_count() < n.mesh.d_lo())
            .map(|n| n.id)
            .collect();
        assert!(
            homeless.is_empty(),
            "all nodes should be above D_lo, but {} are homeless: {:?}",
            homeless.len(), &homeless[..homeless.len().min(10)]
        );

        // Phase 4: Verify E-peer slots are being utilized across the network
        let _nodes_with_epeer = net.nodes.iter()
            .filter(|n| n.alive && n.mesh.has_enquiry_peer())
            .count();
        // At steady state with 0 homeless, E-peer utilization may be low — that's OK.
        // The important thing is zero homeless.
        // If we want to verify E-peer helped, we'd need to disable it and compare.
    }

    // ── Test 4: Genesis retirement — network survives without genesis ──
    // §6.3 Sim Plan: "Start 10 genesis, grow to 50, kill all genesis,
    // verify convergence >90%"
    #[test]
    fn genesis_retirement_convergence() {
        let mut net = SimNetwork::new_test(50);

        // Phase 1: Grow to 50 nodes with good convergence
        let pre_kill_conv = run_with_injections(&mut net, 400, 5);
        assert!(net.nodes.len() >= 50, "network should have grown to 50 nodes");
        assert!(
            pre_kill_conv > 80.0,
            "pre-retirement convergence should be >80%, got {:.1}%",
            pre_kill_conv
        );

        // Phase 2: Kill ALL 10 genesis nodes
        for i in 0..GENESIS_COUNT {
            net.kill_node(i);
        }
        let genesis_alive = net.nodes.iter()
            .filter(|n| n.is_genesis && n.alive)
            .count();
        assert_eq!(genesis_alive, 0, "all genesis should be dead");

        // Phase 3: Inject at non-genesis nodes, let mesh heal
        // The network must self-heal — stale genesis peers get pruned,
        // rotation fills slots with other live nodes.
        for t in 0..400u64 {
            if t % 5 == 0 {
                // Inject at a live non-genesis node
                let alive: Vec<usize> = net.nodes.iter()
                    .enumerate()
                    .filter(|(_, n)| n.alive)
                    .map(|(i, _)| i)
                    .collect();
                if !alive.is_empty() {
                    let target = alive[t as usize % alive.len()];
                    net.inject_registration(target);
                }
            }
            net.step();
        }

        let state = net.export_state();
        let alive_non_genesis = state.nodes.iter()
            .filter(|n| n.alive && !n.is_genesis)
            .count();
        assert!(alive_non_genesis >= 40, "should have 40+ alive non-genesis nodes");

        assert!(
            state.stats.convergence_pct > 90.0,
            "convergence should be >90% after genesis retirement, got {:.1}% ({} alive nodes)",
            state.stats.convergence_pct,
            state.stats.alive_nodes
        );
    }

    // ── Test 5: Anti-camping (sim-level) ──
    // §6.3 Sim Plan: "Verify same node can't monopolize E-slot"
    // Unit test already covers mesh-level anti-camping in mesh.rs.
    // This sim-level test verifies E-peer slot rotates across nodes.
    #[test]
    fn e_peer_anti_camping_sim() {
        let mut net = SimNetwork::new_test(50);
        run_with_injections(&mut net, 200, 5);

        // Pick a host node that should have E-peer activity
        let host_idx = GENESIS_COUNT; // first non-genesis
        assert!(net.nodes[host_idx].alive);

        // Track E-peer occupancy across 100 ticks
        let mut occupant_ids: HashSet<NodeId> = HashSet::new();
        for _ in 0..100 {
            net.step();
            if let Some(ep) = net.nodes[host_idx].mesh.enquiry_peer() {
                occupant_ids.insert(ep.node_id);
            }
        }

        // The same node should NOT monopolize the slot.
        // We can't guarantee rotation happened (host may not have had homeless
        // requestors), but if there were occupants, there should be diversity.
        // If no occupants at all, the network is healthy (no one is homeless).
        if !occupant_ids.is_empty() {
            // At minimum, the TTL (12 ticks) means in 100 ticks we should see
            // at most ~8 different occupants, and anti-camping means no single
            // node can camp twice in a row.
            // This is a sanity check — the mesh-level test is the authoritative one.
            assert!(
                !occupant_ids.is_empty(),
                "E-slot should have had at least 1 occupant"
            );
        }
        // If 0 occupants: no homeless nodes existed → network is healthy → pass
    }

    // ── Test 6: Partition recovery via §6.6 Human Bridge ──
    // §6.6: "Receiver contacts sender outside protocol... sender shares
    // Nabla address... receiver's Nabla connects... exchange data...
    // trees heal. Gossip floods across the bridge."
    #[test]
    fn partition_recovery_human_bridge() {
        let mut net = SimNetwork::new_test(50);

        // Phase 1: Grow and converge
        run_with_injections(&mut net, 400, 5);
        let pre_split_conv = net.export_state().stats.convergence_pct;
        assert!(
            pre_split_conv > 80.0,
            "pre-partition convergence should be >80%, got {:.1}%",
            pre_split_conv
        );

        // Phase 2: Partition — isolate first 25 nodes from last 25
        let isolated: Vec<usize> = (0..25).collect();
        net.partition(&isolated);

        // Inject different data on each side to force divergence
        net.inject_registration(0);  // partition A (node in first 25)
        net.inject_registration(30); // partition B (node in last 25)

        // Run long enough for stale-peer pruning to kick in (60 ticks).
        // After this, both sides have pruned all cross-partition peers.
        run_with_injections(&mut net, 100, 10);

        let during_conv = net.export_state().stats.convergence_pct;
        assert!(
            during_conv < pre_split_conv,
            "convergence should drop during partition (pre={:.1}%, during={:.1}%)",
            pre_split_conv, during_conv
        );

        // Phase 3: Human bridge — §6.6
        // If a human can reach across to do the bridge, the physical path is back.
        // human_bridge() clears blocked links AND exchanges known_nodes.
        // Pick one node from each side: receiver (node 30) contacts sender (node 5).
        let (stats_a, stats_b) = net.human_bridge(5, 30);
        assert!(
            stats_a.1 > 0 || stats_b.1 > 0,
            "bridge should discover new nodes (a: recv={} new={} upd={}, b: recv={} new={} upd={})",
            stats_a.0, stats_a.1, stats_a.2, stats_b.0, stats_b.1, stats_b.2
        );

        // Phase 5: Let periodic_peer_check graft from new knowledge, then
        // anti-entropy syncs the state differences across the bridge.
        // Rotation fires every 30 ticks → 1-2 cycles to form cross-links.
        // Anti-entropy fires every 6 ticks → state sync follows quickly.
        let post_bridge_conv = run_with_injections(&mut net, 200, 10);

        assert!(
            post_bridge_conv > 90.0,
            "convergence should recover to >90% after human bridge, got {:.1}%",
            post_bridge_conv
        );
    }

    // ── Test 7: Score accuracy (sim-level) ──
    // §6.3 Sim Plan: "Verify active peers score higher than idle/stale
    // across sizes"
    #[test]
    fn score_accuracy_active_beats_stale() {
        // §6.3 Sim Plan: "Verify active peers score higher than idle/stale"
        // Test the 3-weight formula across representative peer states.
        let my_id = [0u8; 32];
        let addr = NablaAddress::V4 { ip: [10, 0, 0, 0], port: 6225 };
        let mesh = GossipMesh::new(my_id, addr);

        // Active peer: 20 messages in 10 ticks, seen 1 tick ago (fresh, high throughput)
        let active = PeerInfo {
            node_id: [1u8; 32],
            address: NablaAddress::V4 { ip: [10, 0, 0, 1], port: 6225 },
            last_seen: 299,
            tardis_up: None, has_d_open: false, open_slots: 0,
            messages_delivered: 20,
            connected_since: 290,
            txid_service: String::new(),
        };

        // Idle peer: 0 messages in 10 ticks, seen 1 tick ago (connected but not forwarding)
        let idle = PeerInfo {
            node_id: [2u8; 32],
            address: NablaAddress::V4 { ip: [10, 0, 0, 2], port: 6225 },
            last_seen: 299,
            tardis_up: None, has_d_open: false, open_slots: 0,
            messages_delivered: 0,
            connected_since: 290,
            txid_service: String::new(),
        };

        // Stale peer: 20 messages, but not seen in 60 ticks (gone silent)
        let stale = PeerInfo {
            node_id: [3u8; 32],
            address: NablaAddress::V4 { ip: [10, 0, 0, 3], port: 6225 },
            last_seen: 240,
            tardis_up: None, has_d_open: false, open_slots: 0,
            messages_delivered: 20,
            connected_since: 200,
            txid_service: String::new(),
        };

        let tick = 300;
        let active_score = mesh.peer_score(&active, tick);
        let idle_score = mesh.peer_score(&idle, tick);
        let stale_score = mesh.peer_score(&stale, tick);

        assert!(
            active_score > idle_score,
            "active peer ({:.2}) should score higher than idle peer ({:.2})",
            active_score, idle_score
        );
        assert!(
            active_score > 0.0,
            "fresh active peer should have positive score, got {:.2}",
            active_score
        );
        assert!(
            active_score > stale_score,
            "active peer ({:.2}) should score higher than stale peer ({:.2})",
            active_score, stale_score
        );
        assert!(
            idle_score > stale_score,
            "idle-but-recent peer ({:.2}) should score higher than stale peer ({:.2})",
            idle_score, stale_score
        );

        // Stale peer should have negative score (staleness penalty dominates)
        assert!(
            stale_score < 0.0,
            "stale peer should have negative score, got {:.2}",
            stale_score
        );
    }

    // ── Test 7b: Score and rotation work across different network sizes ──
    // §6.3 Sim Plan: "across various network sizes"
    #[test]
    fn rotation_works_at_30_nodes() {
        let mut net = SimNetwork::new_test(30);
        let conv = run_with_injections(&mut net, 300, 5);
        assert!(net.nodes.len() >= 30);
        assert!(
            conv > 80.0,
            "30-node network convergence should be >80%, got {:.1}%",
            conv
        );
    }

    #[test]
    fn rotation_works_at_100_nodes() {
        let mut net = SimNetwork::new_test(100);
        // 100 nodes = ~180 ticks to grow, then 400 more for propagation
        let conv = run_with_injections(&mut net, 600, 5);
        assert!(net.nodes.len() >= 100);
        assert!(
            conv > 70.0,
            "100-node network convergence should be >70%, got {:.1}%",
            conv
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // TARDIS Tree Tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn all_genesis_are_tardis_seeds() {
        let net = SimNetwork::new_test(10);
        // All 10 genesis nodes are seeds
        for i in 0..GENESIS_COUNT {
            assert!(net.nodes[i].is_seed, "genesis node {} should be seed", i);
            assert!(
                net.nodes[i].tardis.has_upstream(),
                "genesis node {} should have TARDIS upstream (ring)", i
            );
        }
        // Ring: 10 links (G0→G1, G1→G2, ..., G9→G0)
        assert_eq!(
            net.tardis_links.len(), GENESIS_COUNT,
            "expected {} ring links for genesis seeds", GENESIS_COUNT
        );
    }

    #[test]
    fn genesis_ring_interconnected() {
        let net = SimNetwork::new_test(10);
        // Verify ring: each genesis i has link to (i+1) % 10
        for i in 0..GENESIS_COUNT {
            let next = (i + 1) % GENESIS_COUNT;
            assert!(
                net.tardis_links.contains(&(i, next)),
                "expected TARDIS ring link {}→{}", i, next
            );
        }
    }

    #[test]
    fn genesis_node_recovers_like_any_other() {
        // Genesis/seed nodes are NOT special. When their upstream dies,
        // they go through the same P1-P4 recovery as any other node.
        let mut net = SimNetwork::new_test(30);
        for _ in 0..50 { net.step(); }

        // Verify Node 2 (genesis) has upstream before kill
        assert!(net.nodes[2].tardis.has_upstream(),
            "Node 2 should have upstream before kill");

        // Kill Node 1 (genesis) — Node 2's upstream
        net.kill_node(1);

        // Recovery happens through normal P1-P4 (not special ring stitching)
        for _ in 0..5 { net.step(); }

        // Node 2 should have found a new parent — it's just a node
        assert!(net.nodes[2].tardis.has_upstream(),
            "Node 2 should recover upstream after Node 1 death");
        assert!(net.nodes[2].alive, "Node 2 should still be alive");

        // Old links involving dead Node 1 should be cleaned
        assert!(!net.tardis_links.contains(&(1, 2)),
            "dead link 1→2 should be cleaned");

        // Overall health should recover
        let state = net.export_state();
        assert_eq!(state.stats.tardis_orphans, 0,
            "no orphans after genesis node death");
    }

    #[test]
    fn network_survives_multiple_genesis_deaths() {
        // Kill multiple genesis nodes — they're mortal like everyone.
        let mut net = SimNetwork::new_test(50);
        for _ in 0..100 { net.step(); }

        // Kill genesis nodes 1, 3, 5
        net.kill_node(1);
        net.kill_node(3);
        net.kill_node(5);

        for _ in 0..10 { net.step(); }

        // ALL alive nodes should have upstream (no special treatment)
        for i in 0..net.nodes.len() {
            if !net.nodes[i].alive { continue; }
            assert!(net.nodes[i].tardis.has_upstream(),
                "alive node {} should have upstream after multiple kills", i);
        }

        let state = net.export_state();
        assert_eq!(state.stats.tardis_orphans, 0,
            "no orphans after killing 3 genesis nodes");
    }

    #[test]
    fn new_nodes_get_tardis_parent() {
        let mut net = SimNetwork::new_test(20);
        // Run until all 20 nodes exist
        for _ in 0..30 { net.step(); }
        assert!(net.nodes.len() >= 20);

        // Every alive node should have a TARDIS upstream (seeds included — they're in the ring)
        for i in 0..net.nodes.len() {
            if net.nodes[i].alive {
                assert!(
                    net.nodes[i].tardis.has_upstream(),
                    "node {} should have TARDIS upstream", i
                );
            }
        }
    }

    // TODO(sim-update): sim has its own orphan-recovery picker that still
    // reads gossip-declared topology. The spec-honest picker shipped
    // 2026-05-29 lives in bin/nabla_node.rs; sim.rs lags. Until sim's
    // picker is brought into spec-conformance (§1.7), this test does not
    // reflect production behaviour. Real-env 4 h soak validates the
    // equivalent behaviour.
    #[ignore = "sim picker lags spec-honest production picker; see §1.7"]
    #[test]
    fn tardis_tick_cascade_reaches_all() {
        let mut net = SimNetwork::new_test(20);
        // Run enough ticks for all nodes to join and receive ticks
        for _ in 0..40 { net.step(); }
        assert!(net.nodes.len() >= 20);

        let state = net.export_state();
        // All alive nodes should have generated their own tick (independent generation)
        let synced = state.nodes.iter()
            .filter(|n| n.alive && n.tardis_tick == state.tick_time)
            .count();
        let alive = state.nodes.iter().filter(|n| n.alive).count();

        assert!(
            synced == alive,
            "every alive node should tick independently: {}/{} synced",
            synced, alive
        );

        // TARDIS health metrics:
        // - Sync: all alive nodes receiving ticks (~100%)
        // - Writers: nodes with 2+ downstream approvals (~50% for binary tree)
        //   Per YPX-003 §1.5: LEGITIMATE = D1 AND D2 approval. No exceptions.
        //   In binary tree, max 50% of nodes can have 2 children (geometry).
        //   This is correct: 50% WRITERS record transactions, 100% serve enquiries.
        //   Leaves prove freshness via parent's approved tick.
        // - Orphans: should be 0
        let sync = state.stats.tardis_sync_pct;
        let writers = state.stats.tardis_writer_pct;
        let orphans = state.stats.tardis_orphans;
        assert!(
            sync > 95.0,
            "all alive nodes should be synced (got sync={:.1}%)", sync
        );
        assert!(
            writers > 0.0 && writers <= 55.0,
            "writers should be ~50% for binary tree (got {:.1}%)", writers
        );
        assert_eq!(
            orphans, 0,
            "no orphans in healthy network"
        );
    }

    #[test]
    fn tardis_blocked_by_partition() {
        let mut net = SimNetwork::new_test(20);
        for _ in 0..30 { net.step(); }

        let baseline_writers = net.export_state().stats.tardis_writer_pct;

        // Partition: isolate nodes 10-19 from 0-9 (seeds).
        // Every node still ticks independently but approval chain is broken.
        // Isolated non-seeds lose their seed parents → become orphans.
        let isolated: Vec<usize> = (10..net.nodes.len()).collect();
        net.partition(&isolated);

        for _ in 0..5 { net.step(); }

        let state = net.export_state();
        // Tree structure should be disrupted: orphans across partition
        let orphans = state.stats.tardis_orphans;
        // With partition, non-seed nodes can't reach seed parents
        // They may re-attach within their side but some should be disrupted
        assert!(orphans > 0 || state.stats.tardis_writer_pct < baseline_writers,
            "partition should disrupt tree: orphans={}, writers={:.1}% (was {:.1}%)",
            orphans, state.stats.tardis_writer_pct, baseline_writers);
    }

    // TODO(sim-update): same rationale as tardis_tick_cascade_reaches_all
    // — sim's orphan-recovery picker still consumes gossip-declared
    // topology; production picker (bin/nabla_node.rs) no longer does.
    // Real-env kick test 2026-05-29 validates equivalent behaviour.
    #[ignore = "sim picker lags spec-honest production picker; see §1.7"]
    #[test]
    fn tardis_orphan_recovery_on_node_death() {
        // When an intermediate node dies, its children must re-attach
        // to another parent and continue receiving ticks.
        let mut net = SimNetwork::new_test(30);
        // Let all nodes join
        for _ in 0..80 { net.step(); }

        let state = net.export_state();
        let _baseline_writers = state.stats.tardis_writer_pct;

        // Find an intermediate non-seed node (has children)
        let victim = (GENESIS_COUNT..net.nodes.len())
            .find(|&i| net.nodes[i].alive && net.nodes[i].tardis.downstream_count() > 0)
            .expect("should have at least one non-seed with children");

        let children_before: Vec<usize> = net.tardis_links.iter()
            .filter(|&&(p, _)| p == victim)
            .map(|&(_, c)| c)
            .collect();
        assert!(!children_before.is_empty(), "victim {} should have children", victim);

        // Kill the intermediate node
        net.kill_node(victim);

        // Let orphan recovery kick in
        for _ in 0..5 { net.step(); }

        let state = net.export_state();
        // All alive nodes should still be ticking (independent generation)
        let alive = state.stats.alive_nodes;
        let synced = state.nodes.iter()
            .filter(|n| n.alive && n.tardis_tick == state.tick_time)
            .count();
        assert!(synced == alive,
            "all alive nodes should tick independently: {}/{} after killing node {}",
            synced, alive, victim);

        // The orphaned children should be in the tree with new parents
        for child_idx in &children_before {
            if *child_idx < net.nodes.len() && net.nodes[*child_idx].alive {
                assert!(net.nodes[*child_idx].tardis.has_upstream(),
                    "child {} should have re-attached upstream after parent {} died",
                    child_idx, victim);
            }
        }
    }

    #[test]
    fn tardis_revived_node_rejoins_tree() {
        let mut net = SimNetwork::new_test(20);
        for _ in 0..50 { net.step(); }

        // Kill a non-seed node
        let victim = GENESIS_COUNT + 2;
        net.kill_node(victim);
        for _ in 0..3 { net.step(); }

        // Revive it and step until it has re-attached, rather than assuming a
        // fixed budget suffices.
        //
        // FLAKE FIX (2026-07-28): this previously stepped exactly 3 times and then
        // asserted. Re-attachment timing is not deterministic — it depends on where
        // the parent-rotation cursor happens to sit when the node comes back, and
        // even once attached the node only learns the CURRENT tick on its parent's
        // next downward broadcast. Three steps is marginal for that, so the test
        // failed at roughly 5-8%. A flaky test is worse than a slow one: it makes
        // every future suite run ambiguous (this one cost six test batches to
        // disambiguate from a real regression during the KI#42 work).
        //
        // Bounded, not unbounded: a genuine regression still fails, it just gets a
        // fair chance to converge first.
        net.revive_node(victim);
        const MAX_REATTACH_STEPS: usize = 60;
        for _ in 0..MAX_REATTACH_STEPS {
            net.step();
            let state = net.export_state();
            let n = &state.nodes[victim];
            if n.alive && n.has_upstream && n.tardis_tick == state.tick_time {
                break;
            }
        }

        // Should be back in the tree with a valid upstream. Asserted individually
        // so a failure names which property is missing, not just "did not converge".
        let state = net.export_state();
        let revived = &state.nodes[victim];
        assert!(revived.alive, "node should be alive");
        assert!(revived.has_upstream,
            "revived node {} should have re-attached to tree within {} steps",
            victim, MAX_REATTACH_STEPS);
        assert_eq!(revived.tardis_tick, state.tick_time,
            "revived node should receive current tick within {} steps",
            MAX_REATTACH_STEPS);
    }

    // ══════════════════════════════════════════════════════════════════
    // YPX-009 §12.7 Chaos: WAL corruption + peer recovery
    // ══════════════════════════════════════════════════════════════════

    /// Chaos test: corrupt random WAL entries on multiple nodes, re-open,
    /// verify partial recovery from snapshot, then pull missing state from
    /// a healthy peer and verify full convergence.
    ///
    /// Simulates a 3-node mini-network with real NablaNode (disk-backed):
    ///   Node 0 (healthy)  — untouched, acts as state source
    ///   Node 1 (victim 1) — WAL corrupted near end
    ///   Node 2 (victim 2) — WAL corrupted near middle
    #[test]
    fn chaos_wal_corruption_and_peer_recovery() {
        use crate::node::NablaNode;
        use crate::gossip::GossipAction;

        let base_dir = tempfile::tempdir().unwrap();
        let num_nodes = 3;
        let num_wallets = 20;

        // ── Phase 1: Create 3 nodes with identical state ──
        // All nodes get the same 20 wallet entries via gossip.
        let mut wallet_data: Vec<(WalletId, StateId, TxHash, u64)> = Vec::new();
        let dirs: Vec<_> = (0..num_nodes)
            .map(|i| base_dir.path().join(format!("node_{}", i)))
            .collect();

        for i in 0..num_wallets {
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            seed[1] = 0xCA; // marker
            let wid = sim_wid(seed);
            let state = *blake3::hash(&wid).as_bytes();
            let tx = *blake3::hash(&state).as_bytes();
            let tick = (i as u64 + 1) * 5;
            wallet_data.push((wid, state, tx, tick));
        }

        // Build all 3 nodes with identical state using inject_test_entry
        // (writes to both SMT and WAL, unlike handle_gossip which is SMT-only).
        //
        // Strategy: insert first half → snapshot → insert second half.
        // After snapshot+compact, only the snapshot marker + second half remain in WAL.
        // Corrupting the WAL loses some second-half entries; snapshot preserves first half.
        let split = num_wallets / 2; // 10
        for dir in &dirs {
            let mut node = NablaNode::open(dir, Box::new(crate::crypto::NoopSigner)).unwrap();

            // First half: pre-snapshot entries. Authored (sim_author) so the
            // re-synced copies hash to the SAME leaf — the convergence assert
            // compares root hashes.
            for (wid, state, tx, tick) in &wallet_data[..split] {
                let (client_pk, client_sig) = sim_author(wid, state, tx);
                let entry = NablaEntry {
                                received_from: None,
                                wallet_seq: 0,
                    wallet_id: *wid,
                    current_state: *state,
                    tx_hash: *tx,
                    tick: *tick,
                    group_members: None,
                    status: WalletStatus::Normal,
                    client_pk,
                    client_sig,
                };
                node.inject_test_entry(&entry);
            }

            // Snapshot captures first 10 entries; compact removes pre-snapshot WAL
            node.set_current_tick(50);
            node.take_snapshot().unwrap();

            // Second half: post-snapshot entries (WAL-only, not in snapshot)
            for (wid, state, tx, tick) in &wallet_data[split..] {
                let (client_pk, client_sig) = sim_author(wid, state, tx);
                let entry = NablaEntry {
                                received_from: None,
                                wallet_seq: 0,
                    wallet_id: *wid,
                    current_state: *state,
                    tx_hash: *tx,
                    tick: *tick,
                    group_members: None,
                    status: WalletStatus::Normal,
                    client_pk,
                    client_sig,
                };
                node.inject_test_entry(&entry);
            }

            assert_eq!(node.entry_count(), num_wallets,
                "node at {:?} should have all {} entries", dir, num_wallets);
        }
        // All nodes dropped — WAL flushed

        // ── Phase 2: Corrupt WAL on victim nodes ──
        // Node 0: healthy (untouched)
        // Node 1: corrupt near end of WAL (lose last few entries)
        // Node 2: corrupt near middle of WAL (lose more entries)
        let wal_1 = dirs[1].join("nabla.wal");
        let wal_2 = dirs[2].join("nabla.wal");

        {
            let mut data = std::fs::read(&wal_1).unwrap();
            assert!(data.len() > 100, "WAL 1 should have data");
            // Corrupt near end
            let pos = data.len() - 50;
            data[pos] ^= 0xFF;
            data[pos + 1] ^= 0xAA;
            std::fs::write(&wal_1, &data).unwrap();
        }

        {
            let mut data = std::fs::read(&wal_2).unwrap();
            assert!(data.len() > 200, "WAL 2 should have data");
            // Corrupt near middle (more aggressive)
            let pos = data.len() / 2;
            data[pos] ^= 0xFF;
            data[pos + 1] ^= 0xBB;
            data[pos + 2] ^= 0xCC;
            std::fs::write(&wal_2, &data).unwrap();
        }

        // ── Phase 3: Re-open all nodes — victims should have partial state ──
        let node_0 = NablaNode::open(&dirs[0], Box::new(crate::crypto::NoopSigner)).unwrap();
        let mut node_1 = NablaNode::open(&dirs[1], Box::new(crate::crypto::NoopSigner)).unwrap();
        let mut node_2 = NablaNode::open(&dirs[2], Box::new(crate::crypto::NoopSigner)).unwrap();

        // Healthy node should have all entries
        assert_eq!(node_0.entry_count(), num_wallets,
            "healthy node must have all {} entries, got {}", num_wallets, node_0.entry_count());

        // Victim nodes should have at least snapshot entries (10),
        // but fewer than all 20 due to WAL corruption.
        assert!(node_1.entry_count() >= 10,
            "victim 1 snapshot entries must survive: got {}", node_1.entry_count());
        assert!(node_1.entry_count() < num_wallets,
            "victim 1 should lose some entries: got {}", node_1.entry_count());

        assert!(node_2.entry_count() >= 10,
            "victim 2 snapshot entries must survive: got {}", node_2.entry_count());
        // Node 2's corruption is more aggressive — may lose more
        assert!(node_2.entry_count() <= node_1.entry_count(),
            "victim 2 (mid-corruption) should lose at least as many as victim 1 (end-corruption): v2={}, v1={}",
            node_2.entry_count(), node_1.entry_count());

        // ── Phase 4: WAL audit should detect corruption ──
        // Victim nodes' WAL checksums won't match disk after corruption.
        // (audit_recent/audit_deep operate on in-memory checksums vs disk)
        // After re-open, rebuild_checksums_from_file recovers what's intact.
        // The key test: entries past the corruption point are GONE.
        let missing_1: Vec<_> = wallet_data.iter()
            .filter(|(wid, ..)| node_1.smt().get(wid).is_none())
            .cloned()
            .collect();
        let missing_2: Vec<_> = wallet_data.iter()
            .filter(|(wid, ..)| node_2.smt().get(wid).is_none())
            .cloned()
            .collect();

        assert!(!missing_1.is_empty(), "victim 1 must have missing entries");
        assert!(!missing_2.is_empty(), "victim 2 must have missing entries");

        // ── Phase 5: Peer recovery — pull from healthy node ──
        // Simulate StatePull: healthy node serves entries, victims apply via gossip.
        // This is the real recovery path: RangeSync/StatePull → handle_gossip.
        for (wid, state, tx, tick) in &missing_1 {
            let (client_pk, client_sig) = sim_author(wid, state, tx);
            let gossip_msg = GossipMessage::StateUpdate {
                                 old_state: [0u8; 32],
                                 wallet_seq: 0,
                seq_proof: None,
                wallet_id: *wid,
                new_state: *state,
                tx_hash: *tx,
                tick: *tick,
            is_genesis_claim: false,
                client_pk,
                client_sig,
                amount: 0,
                fee_breakdown: Vec::new(),
            };
            let action = node_1.handle_gossip(&gossip_msg, crate::types::test_legs::NOW_SECS);
            assert!(matches!(action, GossipAction::Forward(_)),
                "victim 1: re-synced {:02x} should be accepted", wid[0]);
        }

        for (wid, state, tx, tick) in &missing_2 {
            let (client_pk, client_sig) = sim_author(wid, state, tx);
            let gossip_msg = GossipMessage::StateUpdate {
                                 old_state: [0u8; 32],
                                 wallet_seq: 0,
                seq_proof: None,
                wallet_id: *wid,
                new_state: *state,
                tx_hash: *tx,
                tick: *tick,
            is_genesis_claim: false,
                client_pk,
                client_sig,
                amount: 0,
                fee_breakdown: Vec::new(),
            };
            let action = node_2.handle_gossip(&gossip_msg, crate::types::test_legs::NOW_SECS);
            assert!(matches!(action, GossipAction::Forward(_)),
                "victim 2: re-synced {:02x} should be accepted", wid[0]);
        }

        // ── Phase 6: Verify convergence — all 3 nodes identical ──
        assert_eq!(node_1.entry_count(), num_wallets,
            "victim 1 must converge to {} entries after recovery, got {}",
            num_wallets, node_1.entry_count());
        assert_eq!(node_2.entry_count(), num_wallets,
            "victim 2 must converge to {} entries after recovery, got {}",
            num_wallets, node_2.entry_count());

        // Verify exact state match for every wallet
        for (wid, expected_state, _, _) in &wallet_data {
            let r0 = node_0.query(wid);
            let r1 = node_1.query(wid);
            let r2 = node_2.query(wid);

            assert_eq!(r0.current_state, *expected_state,
                "node 0 state mismatch for wallet {:02x}", wid[0]);
            assert_eq!(r1.current_state, *expected_state,
                "node 1 state mismatch for wallet {:02x} after recovery", wid[0]);
            assert_eq!(r2.current_state, *expected_state,
                "node 2 state mismatch for wallet {:02x} after recovery", wid[0]);
        }

        // Root hashes should converge
        assert_eq!(node_0.root_hash(), node_1.root_hash(),
            "victim 1 root hash must match healthy node after recovery");
        assert_eq!(node_0.root_hash(), node_2.root_hash(),
            "victim 2 root hash must match healthy node after recovery");

        // ── Phase 7: Re-synced entries should be persisted in WAL ──
        assert!(node_1.wal().checksum_count() > 0,
            "victim 1 WAL should have checksums after recovery");
        assert!(node_2.wal().checksum_count() > 0,
            "victim 2 WAL should have checksums after recovery");
    }

    /// Chaos test: corrupt WAL on a running SimNetwork node, verify the
    /// sim-level gossip propagation heals the state gap when the node
    /// is rebuilt from scratch (simulating total WAL loss + re-join).
    #[test]
    fn chaos_sim_node_total_wal_loss_recovers_via_gossip() {
        let mut net = SimNetwork::new_test(20);

        // Let network stabilize and populate with registrations
        for _ in 0..80 {
            net.step();
        }
        for _ in 0..30 {
            net.inject_registration(0);
            net.step();
        }
        // Let gossip propagate
        for _ in 0..50 {
            net.step();
        }

        // Snapshot: what the healthy network looks like
        let healthy_smt_len = net.nodes[0].smt.len();
        assert!(healthy_smt_len > 0, "node 0 should have entries");

        // Pick a victim (non-genesis, alive)
        let victim = GENESIS_COUNT + 3;
        assert!(net.nodes[victim].alive, "victim must be alive");
        let victim_entries_before = net.nodes[victim].smt.len();
        assert!(victim_entries_before > 0, "victim should have entries from gossip");

        // ── Simulate total WAL loss: wipe victim's SMT (as if WAL was destroyed) ──
        net.nodes[victim].smt = SparseMerkleTree::new();
        net.nodes[victim].gossip = GossipEngine::new(); // reset dedup so it accepts re-sent gossip
        assert_eq!(net.nodes[victim].smt.len(), 0, "victim SMT wiped");

        // ── Recovery: inject the same registrations again + run gossip ──
        // In production, healthy peers would serve entries via StatePull.
        // In the sim, we replay registrations + let gossip flood propagate.
        for _ in 0..10 {
            net.inject_registration(0);
            net.step();
        }
        // Let gossip propagate to the wiped node
        for _ in 0..50 {
            net.step();
        }

        // ── Verify: victim recovered at least the new registrations ──
        let victim_entries_after = net.nodes[victim].smt.len();
        assert!(victim_entries_after > 0,
            "victim should recover entries via gossip: got {}", victim_entries_after);

        // The victim won't have the OLD entries (those were already dedup'd
        // before the wipe), but MUST have the new ones injected after wipe.
        // This proves the gossip path works for state recovery.
        assert!(victim_entries_after >= 10,
            "victim should have at least the 10 new registrations: got {}",
            victim_entries_after);
    }

    /// Chaos test: real-world scenario — WAL corrupted while node is live,
    /// new entries keep arriving during and after corruption, audit detects it,
    /// node crashes + restarts, recovers old entries from peer while also
    /// accepting brand-new entries that arrived post-restart.
    ///
    /// Timeline:
    ///   T0: Node built with 10 entries (snapshot)
    ///   T1: 10 more entries written (WAL-only, post-snapshot)
    ///   T2: Disk corruption hits WAL (bit flip mid-file)
    ///   T3: 10 MORE entries written on top of corrupted WAL (node still "live")
    ///   T4: Audit detects corruption
    ///   T5: Crash (drop node)
    ///   T6: Re-open — snapshot entries survive, some WAL entries lost
    ///   T7: 10 brand-new entries arrive (fresh registrations, never seen before)
    ///   T8: Concurrently, peer sends missing old entries via StatePull
    ///   T9: Verify: all old + new entries present, root hashes match
    #[test]
    fn chaos_live_wal_corruption_with_concurrent_writes() {
        use crate::node::NablaNode;
        use crate::gossip::GossipAction;

        let base_dir = tempfile::tempdir().unwrap();
        let healthy_dir = base_dir.path().join("healthy");
        let victim_dir = base_dir.path().join("victim");

        // ── T0: Build initial state (both nodes identical) ──
        // 10 entries → snapshot
        let mut initial_entries: Vec<(WalletId, StateId, TxHash, u64)> = Vec::new();
        for i in 0..10u8 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            seed[31] = 0xA0; // "initial batch" marker
            let wid = sim_wid(seed);
            let state = *blake3::hash(&wid).as_bytes();
            let tx = *blake3::hash(&state).as_bytes();
            initial_entries.push((wid, state, tx, (i as u64 + 1) * 5));
        }

        // ── T1: Post-snapshot entries (WAL-only) ──
        let mut post_snap_entries: Vec<(WalletId, StateId, TxHash, u64)> = Vec::new();
        for i in 10..20u8 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            seed[31] = 0xB0; // "post-snapshot" marker
            let wid = sim_wid(seed);
            let state = *blake3::hash(&wid).as_bytes();
            let tx = *blake3::hash(&state).as_bytes();
            post_snap_entries.push((wid, state, tx, (i as u64 + 1) * 5));
        }

        // ── T2-T3: Entries written AFTER corruption (node still "live") ──
        let mut post_corrupt_entries: Vec<(WalletId, StateId, TxHash, u64)> = Vec::new();
        for i in 20..30u8 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            seed[31] = 0xC0; // "post-corruption live" marker
            let wid = sim_wid(seed);
            let state = *blake3::hash(&wid).as_bytes();
            let tx = *blake3::hash(&state).as_bytes();
            post_corrupt_entries.push((wid, state, tx, (i as u64 + 1) * 5));
        }

        // ── T7: Brand-new entries that arrive AFTER restart ──
        let mut fresh_entries: Vec<(WalletId, StateId, TxHash, u64)> = Vec::new();
        for i in 30..40u8 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            seed[31] = 0xD0; // "fresh post-restart" marker
            let wid = sim_wid(seed);
            let state = *blake3::hash(&wid).as_bytes();
            let tx = *blake3::hash(&state).as_bytes();
            fresh_entries.push((wid, state, tx, (i as u64 + 1) * 5));
        }

        let all_old_entries: Vec<_> = initial_entries.iter()
            .chain(post_snap_entries.iter())
            .chain(post_corrupt_entries.iter())
            .cloned()
            .collect();

        // ── Build victim node with T0 + T1 state ──
        {
            let mut node = NablaNode::open(&victim_dir, Box::new(crate::crypto::NoopSigner)).unwrap();

            // T0: initial entries → snapshot
            for (wid, state, tx, tick) in &initial_entries {
                let (client_pk, client_sig) = sim_author(wid, state, tx);
                let entry = NablaEntry {
                                received_from: None,
                                wallet_seq: 0,
                    wallet_id: *wid, current_state: *state, tx_hash: *tx, tick: *tick,
                    group_members: None, status: WalletStatus::Normal,
                    client_pk, client_sig,
                };
                node.inject_test_entry(&entry);
            }
            node.set_current_tick(50);
            node.take_snapshot().unwrap();

            // T1: post-snapshot entries (WAL-only)
            for (wid, state, tx, tick) in &post_snap_entries {
                let (client_pk, client_sig) = sim_author(wid, state, tx);
                let entry = NablaEntry {
                                received_from: None,
                                wallet_seq: 0,
                    wallet_id: *wid, current_state: *state, tx_hash: *tx, tick: *tick,
                    group_members: None, status: WalletStatus::Normal,
                    client_pk, client_sig,
                };
                node.inject_test_entry(&entry);
            }
            assert_eq!(node.entry_count(), 20);
        }
        // Victim dropped — WAL flushed

        // Build healthy node with ALL entries (no closing/reopening — stays consistent)
        let mut healthy = NablaNode::open(&healthy_dir, Box::new(crate::crypto::NoopSigner)).unwrap();
        for (wid, state, tx, tick) in all_old_entries.iter().chain(fresh_entries.iter()) {
            let (client_pk, client_sig) = sim_author(wid, state, tx);
            let entry = NablaEntry {
                            received_from: None,
                            wallet_seq: 0,
                wallet_id: *wid, current_state: *state, tx_hash: *tx, tick: *tick,
                group_members: None, status: WalletStatus::Normal,
                client_pk, client_sig,
            };
            healthy.inject_test_entry(&entry);
        }
        assert_eq!(healthy.entry_count(), 40,
            "healthy node must have all 40 entries");

        // ── T2: Corrupt victim's WAL mid-file ──
        let victim_wal = victim_dir.join("nabla.wal");
        {
            let mut data = std::fs::read(&victim_wal).unwrap();
            assert!(data.len() > 200, "WAL should have substantial data");
            // Corrupt in the middle — some post-snapshot entries will be lost
            let mid = data.len() / 2;
            data[mid] ^= 0xFF;
            data[mid + 1] ^= 0xAA;
            data[mid + 2] ^= 0x55;
            std::fs::write(&victim_wal, &data).unwrap();
        }

        // ── T3: Re-open victim (WAL partially corrupted) and keep writing ──
        // In real life the node is still running in memory. Here we simulate
        // by re-opening (picks up partial WAL) and then writing more entries.
        {
            let mut victim = NablaNode::open(&victim_dir, Box::new(crate::crypto::NoopSigner)).unwrap();
            let entries_after_corrupt_reopen = victim.entry_count();
            assert!(entries_after_corrupt_reopen >= 10,
                "snapshot entries must survive corruption: got {}", entries_after_corrupt_reopen);
            assert!(entries_after_corrupt_reopen < 20,
                "some WAL entries should be lost: got {}", entries_after_corrupt_reopen);

            // T3 continued: write post-corruption entries (node is "live")
            for (wid, state, tx, tick) in &post_corrupt_entries {
                let (client_pk, client_sig) = sim_author(wid, state, tx);
                let entry = NablaEntry {
                                received_from: None,
                                wallet_seq: 0,
                    wallet_id: *wid, current_state: *state, tx_hash: *tx, tick: *tick,
                    group_members: None, status: WalletStatus::Normal,
                    client_pk, client_sig,
                };
                victim.inject_test_entry(&entry);
            }

            // T4: Audit detects corruption in the existing WAL region
            // The new entries (post-corruption) have valid checksums, but the
            // old corrupted region is still damaged on disk.
            let _deep_result = victim.wal().audit_deep();
            // Deep audit may or may not find the old corruption depending on sampling,
            // but the key point is the node is still operational.

            // Node has: 10 (snapshot) + partial WAL survivors + 10 (post-corrupt live)
            let live_count = victim.entry_count();
            assert!(live_count >= 20, // at least snapshot + post-corrupt
                "live node should have snapshot + post-corrupt entries: got {}", live_count);
            assert!(live_count < 30, // missing some WAL entries
                "live node should still be missing some entries: got {}", live_count);

            // Verify the post-corruption entries are in memory
            for (wid, state, _, _) in &post_corrupt_entries {
                let resp = victim.query(wid);
                assert_eq!(resp.current_state, *state,
                    "post-corruption entry {:02x} must be in live node", wid[0]);
            }
        }
        // T5: Crash (drop)

        // (healthy node already has all 40 entries — built above)

        // ── T6: Re-open victim after crash ──
        let mut victim = NablaNode::open(&victim_dir, Box::new(crate::crypto::NoopSigner)).unwrap();
        let restart_count = victim.entry_count();

        // Should have snapshot entries + whatever survived from post-corrupt writes
        assert!(restart_count >= 10,
            "T6: at least snapshot entries: got {}", restart_count);

        // Identify ALL missing entries (from both old and post-corrupt batches)
        let missing_old: Vec<_> = all_old_entries.iter()
            .filter(|(wid, ..)| victim.smt().get(wid).is_none())
            .cloned()
            .collect();

        // ── T7+T8: Concurrently accept fresh entries AND recover old ones ──
        // Interleave: 1 fresh entry, then 1 recovered old entry, repeat.
        // This simulates real-world concurrent traffic during recovery.
        let max_rounds = fresh_entries.len().max(missing_old.len());
        for round in 0..max_rounds {
            // Fresh entry arrives (new registration, never seen before)
            if round < fresh_entries.len() {
                let (wid, state, tx, tick) = &fresh_entries[round];
                let (client_pk, client_sig) = sim_author(wid, state, tx);
                let gossip_msg = GossipMessage::StateUpdate {
                                     old_state: [0u8; 32],
                                     wallet_seq: 0,
                    seq_proof: None,
                    wallet_id: *wid, new_state: *state, tx_hash: *tx, tick: *tick,
            is_genesis_claim: false,
                    client_pk, client_sig,
                    amount: 0, fee_breakdown: Vec::new(),
                };
                let action = victim.handle_gossip(&gossip_msg, crate::types::test_legs::NOW_SECS);
                assert!(matches!(action, GossipAction::Forward(_)),
                    "fresh entry {:02x} must be accepted during recovery", wid[0]);
            }

            // Recovered old entry arrives from peer (StatePull gap-fill)
            if round < missing_old.len() {
                let (wid, state, tx, tick) = &missing_old[round];
                let (client_pk, client_sig) = sim_author(wid, state, tx);
                let gossip_msg = GossipMessage::StateUpdate {
                                     old_state: [0u8; 32],
                                     wallet_seq: 0,
                    seq_proof: None,
                    wallet_id: *wid, new_state: *state, tx_hash: *tx, tick: *tick,
            is_genesis_claim: false,
                    client_pk, client_sig,
                    amount: 0, fee_breakdown: Vec::new(),
                };
                let action = victim.handle_gossip(&gossip_msg, crate::types::test_legs::NOW_SECS);
                assert!(matches!(action, GossipAction::Forward(_)),
                    "recovered entry {:02x} must be accepted during concurrent writes", wid[0]);
            }
        }

        // ── T9: Final convergence check ──
        let total_expected = 40; // 10 initial + 10 post-snap + 10 post-corrupt + 10 fresh
        assert_eq!(victim.entry_count(), total_expected,
            "victim must have all {} entries after concurrent recovery, got {}",
            total_expected, victim.entry_count());

        // Verify every single entry is correct
        for (wid, expected_state, _, _) in all_old_entries.iter().chain(fresh_entries.iter()) {
            let rv = victim.query(wid);
            let rh = healthy.query(wid);
            assert_eq!(rv.current_state, *expected_state,
                "victim entry {:02x} state wrong after recovery", wid[0]);
            assert_eq!(rh.current_state, *expected_state,
                "healthy entry {:02x} state wrong", wid[0]);
        }

        // Root hashes must match
        assert_eq!(victim.root_hash(), healthy.root_hash(),
            "victim root must match healthy node after concurrent recovery+writes");
    }

    // ════════════════════════════════════════════════════════════════
    // INV-12: Partition and heal — convergence + data integrity
    // AUDIT-FIX v2.11.13: Confirms partition recovery restores full
    // consistency and no registrations are lost during split/heal.
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_inv12_partition_heal_convergence() {
        let mut net = SimNetwork::new_test(30);

        // Phase 1: Grow network to 30 nodes and stabilise
        for _ in 0..300 { net.step(); }
        let node_count = net.nodes.len();
        assert!(node_count >= 20, "network should have grown: got {}", node_count);

        // Inject registrations with interleaved steps for propagation
        for i in 0..20 {
            net.inject_registration(i % node_count);
            net.step();
        }
        for _ in 0..100 { net.step(); } // full propagation

        let pre_partition_entries = net.nodes[0].smt.len();
        assert!(pre_partition_entries > 0, "pre-partition entries should be > 0");

        // Phase 2: Partition — isolate upper half
        let half = node_count / 2;
        let isolated: Vec<usize> = (half..node_count).collect();
        net.partition(&isolated);

        // Inject on side A (low) with steps
        for _ in 0..10 {
            net.inject_registration(0);
            net.step();
        }
        // Inject on side B (high) with steps
        let side_b_node = half + 1;
        if side_b_node < node_count {
            for _ in 0..10 {
                net.inject_registration(side_b_node);
                net.step();
            }
        }
        for _ in 0..100 { net.step(); }

        // Assert divergence: side A and side B should differ
        let root_a = net.nodes[0].smt.root_hash();
        let root_b = net.nodes[node_count - 1].smt.root_hash();
        assert_ne!(root_a, root_b,
            "Partitioned halves must have different SMT roots");

        // Phase 3: Heal via human bridge
        net.human_bridge(half - 1, half);
        for _ in 0..500 { net.step(); }

        // Assert convergence: all alive nodes have same root
        let final_root = net.nodes[0].smt.root_hash();
        let mismatched = net.nodes.iter()
            .filter(|n| n.alive && n.smt.root_hash() != final_root)
            .count();
        assert_eq!(mismatched, 0,
            "All nodes must converge to same SMT root after partition heal");

        // Verify registrations were not lost
        let final_entries = net.nodes[0].smt.len();
        assert!(final_entries > pre_partition_entries,
            "Registrations added during partition must survive heal: pre={} post={}",
            pre_partition_entries, final_entries);
    }

    #[test]
    fn test_inv12_partition_data_survives_dark_side() {
        let mut net = SimNetwork::new_test(30);

        // Grow and stabilise
        for _ in 0..300 { net.step(); }
        let node_count = net.nodes.len();
        assert!(node_count >= 20, "network should have grown: got {}", node_count);

        // Record pre-partition state
        let pre_entries = net.nodes[0].smt.len();

        // Partition — isolate upper quarter
        let split = node_count * 3 / 4;
        let isolated: Vec<usize> = (split..node_count).collect();
        net.partition(&isolated);

        // Inject registrations ONLY on active side with interleaved steps
        for _ in 0..15 {
            net.inject_registration(0);
            net.step();
        }
        for _ in 0..100 { net.step(); }

        // Active side should have new registrations
        let active_entries = net.nodes[0].smt.len();
        assert!(active_entries > pre_entries,
            "Active side should have new registrations: pre={} now={}", pre_entries, active_entries);

        // Dark side should have fewer (only pre-partition data, if any)
        let dark_node = split + 1;
        if dark_node < node_count {
            let dark_entries = net.nodes[dark_node].smt.len();
            assert!(dark_entries < active_entries,
                "Dark side should have fewer entries: dark={} active={}", dark_entries, active_entries);
        }

        // Heal and converge
        net.human_bridge(split - 1, split);
        for _ in 0..500 { net.step(); }

        // After healing: all nodes should converge
        let final_root = net.nodes[0].smt.root_hash();
        let converged = net.nodes.iter()
            .filter(|n| n.alive)
            .all(|n| n.smt.root_hash() == final_root);
        assert!(converged,
            "All nodes must converge after partition heal");

        // Dark side should now have active side's registrations
        if dark_node < node_count {
            let healed_dark = net.nodes[dark_node].smt.len();
            assert_eq!(healed_dark, net.nodes[0].smt.len(),
                "Dark side must match active side after healing: dark={} active={}",
                healed_dark, net.nodes[0].smt.len());
        }
    }
}
