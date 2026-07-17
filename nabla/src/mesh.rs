// AXIOM Nabla — Gossip Mesh Network
// Reference: AXIOM_GUIDE_Nabla.md Section 6
//            YELLOWPAPER_6_3_MESH_ROTATION.md (anti-ossification)
//
// Phase 4 Tasks:
//   21. Mesh peer data structure (PeerInfo, known_nodes table)
//   22. Bootstrap peer list (bootstrap.toml — operator-configured contact points)
//   23. Peer discovery through gossip (learn new peers from messages)
//   24. Mesh peer connection management (D/D_lo/D_hi degree band)
//   25. Gossip message routing (flood fill through mesh, not tree)
//   26. Topology hints (LostUpstream, SlotAvailable, NewNode)
//   27. TARDIS self-healing via mesh peer knowledge
//   28. E enquiry for actual slot reconnection (real-time slot check)
//
// Design:
//   The gossip mesh is a SEPARATE overlay from the TARDIS tree.
//   Mesh carries ALL data. TARDIS carries ticks only.
//   If TARDIS branch breaks, data still flows through mesh.
//
//   Peer count adapts to network size:
//     D = 9 + max(0, ceil(log₁₀(seen_nodes)) - 1)
//   Degree band: D_lo = D-2, D_hi = D+3.
//   Bootstrap: D=9 (D_lo=7, D_hi=12). Production: D=12 (D_lo=10, D_hi=15).
//
//   §6.3 Anti-ossification:
//     - Score-based rotation every 30 ticks drops lowest peer
//     - Opportunistic grafting every 60 ticks replaces poor peers
//     - E-peer slot: passive observer for homeless nodes (1 per node, 5min TTL)
//     - Bootstrap peers NOT immune from pruning (§6.3.6)

use std::collections::{HashMap, HashSet};

use crate::constants::{
    MESH_PEER_BASE, MESH_PEER_MAX,
    MESH_D_LO_OFFSET, MESH_D_HI_OFFSET,
    ROTATION_INTERVAL, OPPORTUNISTIC_INTERVAL,
    OPPORTUNISTIC_GRAFT_COUNT, STALE_PEER_THRESHOLD,
    KNOWLEDGE_REFRESH_INTERVAL,
    E_PEER_TTL, E_PEER_MAX, PEER_W1, PEER_W2, PEER_W3,
    KNOWN_NODES_MAX,
    LATENCY_PRUNE_INTERVAL, RTT_EWMA_ALPHA, LATENCY_FLOOR_MS,
    LATENCY_OUTLIER_RATIO, LATENCY_KEEP_FASTEST, LATENCY_MIN_SAMPLES,
    LATENCY_PENALTY_ON_PRUNE, LATENCY_PENALTY_DECAY,
    LATENCY_PENALTY_GRAFT_BLOCK, LATENCY_PENALTY_MAX,
};
use crate::types::*;

/// Gossip mesh — manages peer connections and topology awareness.
///
/// Separate from GossipEngine (which handles message processing).
/// This module handles WHO we talk to; GossipEngine handles WHAT we do
/// with messages once received.
///
/// §6.3: Degree band [D_lo, D, D_hi] prevents mesh ossification.
/// Periodic rotation drops lowest-scored peers to create open slots.
/// Enquiry peers observe passively before joining as full peers.
pub struct GossipMesh {
    /// Our own node ID.
    my_node_id: NodeId,
    /// Our network address.
    my_address: NablaAddress,

    /// Active mesh peers (the nodes we gossip with).
    peers: Vec<PeerInfo>,
    /// Bootstrap peers — initial contact points from bootstrap.toml (NOT immune from pruning per §6.3.6).
    /// Retained for re-seeding when the node loses all peers and known_nodes.
    bootstrap: Vec<PeerInfo>,
    /// All known nodes (superset of peers — discovered via gossip).
    known_nodes: HashMap<NodeId, PeerInfo>,
    /// Unique node IDs seen in gossip recently (for network size estimate).
    unique_seen: HashSet<NodeId>,
    /// Tick when unique_seen was last pruned (hourly reset).
    last_seen_prune_tick: u64,

    // ── §6.3 Rotation state ──
    /// Tick of last rotation (drop lowest-scored peer).
    last_rotation_tick: u64,
    /// Tick of last opportunistic grafting check.
    last_opportunistic_tick: u64,
    /// Tick of last knowledge refresh (PX request while at full peers).
    last_knowledge_refresh_tick: u64,

    // ── §6.3.4 Enquiry Peer ──
    /// Current enquiry peer (passive observer, max 1).
    enquiry_peer: Option<EnquiryPeer>,
    /// Node ID of previous enquiry peer (anti-camping).
    last_enquiry_id: Option<NodeId>,

    /// Simple counter for round-robin peer selection (avoids always asking same peer).
    request_counter: u64,

    // ── YPX-009: Silicon Pulse state ──
    /// Per-validator pulse delivery tracking. Keyed by Ed25519 PK (not NodeId).
    pulse_state: HashMap<[u8; 32], crate::types::PeerPulseState>,
    /// Last epoch evaluated for pulse misses.
    last_pulse_epoch: u64,

    // ── §6.3.7 Latency-aware pruning ──
    /// Local EWMA round-trip latency (ms) per active peer. Local-only —
    /// NEVER gossiped, NEVER bound into a fact. Mirrors the `pulse_state`
    /// side-map pattern so `PeerInfo` (which IS gossiped) stays unchanged.
    /// Empty entry = unmeasured: such a peer is never pruned for latency.
    peer_rtt_ms: HashMap<NodeId, f32>,
    /// §6.3.7: node_id → decaying latency penalty. Bumps on a latency prune,
    /// decays every tick (LATENCY_PENALTY_DECAY). Grafting paths avoid a peer
    /// while its penalty is above LATENCY_PENALTY_GRAFT_BLOCK — a smooth, self-
    /// accumulating successor to a binary cooldown (no re-evaluation cliff).
    latency_penalty: HashMap<NodeId, f32>,

    // ── Topology awareness ──
    /// Nodes that have announced lost upstream (seeking TARDIS parent).
    orphaned_nodes: HashMap<NodeId, NablaAddress>,
    /// Nodes that have open D slots (can accept TARDIS children).
    available_slots: HashMap<NodeId, NablaAddress>,

    /// Phase B Layer 4: peers currently under mesh-wide quarantine.
    /// `forward_targets` and `active_peers` skip these. The set is
    /// driven by `NablaNode` — `set_quarantined_peer(true)` on
    /// QUARANTINE-ACTIVATED, `set_quarantined_peer(false)` when the
    /// quarantine TTL expires in `quarantine_sweep`.
    quarantined_peers: HashSet<NodeId>,
}

/// §6.3.4 — Enquiry peer: passive observer slot.
///
/// E-peers receive gossip (learn topology) but cannot forward.
/// They do NOT count toward D/D_lo/D_hi.
/// Max 1 per node, 5-minute TTL, anti-camping enforced.
#[derive(Debug, Clone)]
pub struct EnquiryPeer {
    pub node_id: NodeId,
    pub address: NablaAddress,
    /// Tick when this E-peer connected.
    pub connected_tick: u64,
}

/// Actions the network layer must take after mesh processing.
#[derive(Debug)]
pub enum MeshAction {
    /// Connect to a new peer.
    ConnectPeer(PeerInfo),
    /// Request peer introduction from an existing peer.
    RequestIntroduction { ask_peer: NodeId },
    /// Send a topology hint to all mesh peers.
    BroadcastTopology(TopologyHint),
    /// Attempt TARDIS reconnection to a node with open D slot.
    AttemptTardisReconnect { target: NodeId, address: NablaAddress },
    /// Nothing to do.
    None,
}

impl GossipMesh {
    /// Create a new mesh with bootstrap peers.
    pub fn new(my_node_id: NodeId, my_address: NablaAddress) -> Self {
        Self {
            my_node_id,
            my_address,
            peers: Vec::new(),
            bootstrap: Vec::new(),
            known_nodes: HashMap::new(),
            unique_seen: HashSet::new(),
            last_seen_prune_tick: 0,
            last_rotation_tick: 0,
            last_opportunistic_tick: 0,
            last_knowledge_refresh_tick: 0,
            enquiry_peer: None,
            last_enquiry_id: None,
            request_counter: 0,
            pulse_state: HashMap::new(),
            last_pulse_epoch: 0,
            peer_rtt_ms: HashMap::new(),
            latency_penalty: HashMap::new(),
            orphaned_nodes: HashMap::new(),
            available_slots: HashMap::new(),
            quarantined_peers: HashSet::new(),
        }
    }

    /// Mark / unmark a peer as quarantined. Sent here by `NablaNode`
    /// after the 3-of-N Layer 4 consensus activates a mesh-wide
    /// quarantine (true), and again when the quarantine TTL expires
    /// (false). `forward_targets()` skips quarantined peers, so the
    /// existing fan-out callsites stop gossiping to them for free.
    pub fn set_quarantined_peer(&mut self, peer_id: NodeId, quarantined: bool) {
        if quarantined {
            self.quarantined_peers.insert(peer_id);
        } else {
            self.quarantined_peers.remove(&peer_id);
        }
    }

    /// Is this peer currently in the mesh's quarantine-skip set?
    pub fn is_peer_quarantined(&self, peer_id: &NodeId) -> bool {
        self.quarantined_peers.contains(peer_id)
    }

    // ── Known Nodes Memory (capped at KNOWN_NODES_MAX=256) ──

    /// Insert or update a node in known_nodes, enforcing the capacity cap.
    /// When at capacity, evicts the entry with the oldest last_seen.
    /// During partitions, cross-partition entries naturally get evicted as
    /// same-side peers are observed more recently.
    #[allow(clippy::map_entry)]
    fn insert_known_node(&mut self, node_id: NodeId, peer: PeerInfo) {
        // Reject null peer_id — prevents ghost entries in the mesh table.
        // A zero node_id can arrive via unsigned TopologyHint gossip or
        // malformed Hello messages.
        if node_id == [0u8; 32] {
            return;
        }
        // Update existing — always allowed, no eviction needed
        if self.known_nodes.contains_key(&node_id) {
            self.known_nodes.insert(node_id, peer);
            return;
        }
        // At capacity — evict oldest last_seen (but never evict active peers)
        if self.known_nodes.len() >= KNOWN_NODES_MAX {
            let active_ids: HashSet<NodeId> = self.peers.iter().map(|p| p.node_id).collect();
            let oldest = self.known_nodes.iter()
                .filter(|(id, _)| !active_ids.contains(*id))
                .min_by_key(|(_, p)| p.last_seen)
                .map(|(id, _)| *id);
            if let Some(evict_id) = oldest {
                self.known_nodes.remove(&evict_id);
            } else {
                // All entries are active peers — can't evict. Skip insert.
                return;
            }
        }
        self.known_nodes.insert(node_id, peer);
    }

    // ── Task 22: Bootstrap Peer List ──

    /// Add bootstrap peers (initial contact points from bootstrap.toml).
    /// §6.3.6: Bootstrap peers are NOT immune from pruning or rotation.
    /// They are treated the same as any other peer. The bootstrap list is
    /// retained separately for re-seeding if the node becomes mesh-stranded.
    pub fn add_bootstrap(&mut self, peers: Vec<PeerInfo>) {
        for peer in peers {
            self.insert_known_node(peer.node_id, peer.clone());
            self.bootstrap.push(peer.clone());
            // Add as active peer — bootstrap peers may share node_id [0;32]
            // (address-only from bootstrap.toml), so deduplicate by address.
            let already = self.peers.iter().any(|p| p.address == peer.address);
            if !already {
                self.peers.push(peer);
            }
        }
    }

    // ── Task 21 & 24: Adaptive Peer Count ──

    /// Target peer count based on observed network size (§6.0).
    ///
    /// Formula: 9 + max(0, ceil(log₁₀(seen_nodes)) - 1)
    /// Clamped to [MESH_PEER_BASE, MESH_PEER_MAX].
    pub fn target_peer_count(&self) -> usize {
        let seen = self.unique_seen.len().max(1);
        let extra = (seen as f64).log10().ceil() as usize;
        let target = MESH_PEER_BASE + extra.saturating_sub(1);
        target.clamp(MESH_PEER_BASE, MESH_PEER_MAX)
    }

    // ── §6.3.1 Degree Band ──

    /// Max regular peers = D − E_PEER_MAX.
    /// The E-peer slot is ALWAYS reserved and never counted as a regular peer.
    pub fn regular_peer_target(&self) -> usize {
        self.target_peer_count().saturating_sub(E_PEER_MAX)
    }

    /// D_lo = regular_target - 2. Below this triggers panic-graft.
    pub fn d_lo(&self) -> usize {
        self.regular_peer_target().saturating_sub(MESH_D_LO_OFFSET)
    }

    /// D_hi = regular_target + 3. Above this triggers aggressive pruning.
    pub fn d_hi(&self) -> usize {
        (self.regular_peer_target() + MESH_D_HI_OFFSET).min(MESH_PEER_MAX)
    }

    // ── §6.3.2 Peer Scoring ──

    /// Compute peer score using §6.3.2 weighted formula:
    ///   score = (msg_rate × W1) − (staleness × W2) − (age × W3)
    /// Higher is better. New active peers score highest. Old peers decay naturally.
    pub fn peer_score(&self, peer: &PeerInfo, current_tick: u64) -> f64 {
        let age = current_tick.saturating_sub(peer.connected_since).max(1) as f64;
        let msg_rate = peer.messages_delivered as f64 / age;
        let staleness = current_tick.saturating_sub(peer.last_seen) as f64;
        let base = (msg_rate * PEER_W1) - (staleness * PEER_W2) - (age * PEER_W3);

        // YPX-009 §5: Pulse liveness bonus/penalty (W3 extension).
        // Peers with consistent pulse delivery get a bonus; missed pulses degrade score.
        if let Some(ps) = self.pulse_state.get(&peer.node_id) {
            let pulse_bonus = ps.total_pulses as f64 * 0.5;
            let miss_penalty = ps.consecutive_misses as f64 * 5.0;
            base + pulse_bonus - miss_penalty
        } else {
            base
        }
    }

    /// Get the index of the lowest-scored active peer.
    fn lowest_scored_peer_idx(&self, current_tick: u64) -> Option<usize> {
        if self.peers.is_empty() {
            return None;
        }
        let mut min_idx = 0;
        let mut min_score = self.peer_score(&self.peers[0], current_tick);
        for (i, peer) in self.peers.iter().enumerate().skip(1) {
            let s = self.peer_score(peer, current_tick);
            if s < min_score {
                min_score = s;
                min_idx = i;
            }
        }
        Some(min_idx)
    }

    /// Median score of all active peers (for opportunistic grafting trigger).
    fn median_peer_score(&self, current_tick: u64) -> f64 {
        if self.peers.is_empty() {
            return 0.0;
        }
        let mut scores: Vec<f64> = self.peers.iter()
            .map(|p| self.peer_score(p, current_tick))
            .collect();
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        scores[scores.len() / 2]
    }

    // ── §6.3.7 Latency-aware pruning ──

    /// Record a round-trip latency sample (ms) for a peer, EWMA-smoothed.
    /// Fed by the network layer on every observed request→response round-trip
    /// (passive) and by active pings to idle links. LOCAL-ONLY: this value
    /// never crosses the wire and never enters a fact — it ranks who we talk
    /// to, never whose money is valid. Negative samples are ignored.
    pub fn record_peer_rtt(&mut self, node_id: NodeId, sample_ms: f32) {
        if !(sample_ms >= 0.0) {
            return; // ignore NaN / negative
        }
        let prev = self.peer_rtt_ms.get(&node_id).copied();
        let new = match prev {
            Some(e) => (1.0 - RTT_EWMA_ALPHA) * e + RTT_EWMA_ALPHA * sample_ms,
            None => sample_ms,
        };
        self.peer_rtt_ms.insert(node_id, new);
        // Observability: one line the first time a peer's smoothed RTT is slow
        // (first sample OR an upward crossing) — proves measurement, no spam.
        if new > LATENCY_FLOOR_MS && prev.map_or(true, |p| p <= LATENCY_FLOOR_MS) {
            log::info!(
                "[latency] peer {:02x}{:02x}.. measured slow: {:.0}ms",
                node_id[0], node_id[1], new
            );
        }
    }

    /// Current smoothed RTT (ms) for a peer, if measured.
    pub fn peer_rtt(&self, node_id: &NodeId) -> Option<f32> {
        self.peer_rtt_ms.get(node_id).copied()
    }

    /// §6.3.7 — latency-aware prune decision (the converged design).
    ///
    /// Prune the SLOWEST link and graft a replacement, but ONLY when the slow
    /// link is both genuinely slow and a relative outlier — so a healthy mesh
    /// never churns and a uniformly-slow region never isolates itself:
    ///   - degree floor: never drop below `d_lo` (no isolation; swap-not-shed)
    ///   - keep the `LATENCY_KEEP_FASTEST` fastest links no matter what
    ///   - worst must exceed `LATENCY_FLOOR_MS` (a fast mesh has nothing to do)
    ///   - worst must exceed `median × LATENCY_OUTLIER_RATIO` (uniform-slow:
    ///     worst ≈ median ⇒ not an outlier ⇒ no prune, no churn)
    ///   - a graft candidate must exist (swap, never shed); accept-inbound
    ///     elsewhere guarantees the dropped peer re-homes (kick-with-hints).
    ///
    /// Returns `ConnectPeer` when it grafts a replacement, else `None`.
    /// Cadence + per-node jitter are applied by the caller (`periodic_peer_check`).
    fn latency_prune_step(&mut self, _current_tick: u64) -> Option<MeshAction> {
        let d_lo = self.d_lo();
        if self.peers.len() <= d_lo {
            return None; // degree floor — never prune toward isolation
        }

        // Collect (peer index, rtt) for peers we have actually measured.
        let mut measured: Vec<(usize, f32)> = self
            .peers
            .iter()
            .enumerate()
            .filter_map(|(i, p)| self.peer_rtt_ms.get(&p.node_id).map(|r| (i, *r)))
            .collect();
        if measured.len() < LATENCY_MIN_SAMPLES {
            return None; // not enough signal for a stable median
        }

        // Sort ascending by rtt: fastest first, slowest last.
        measured.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        let median = measured[measured.len() / 2].1;
        let (worst_idx, worst_rtt) = *measured.last().unwrap();

        // Protect the fastest links: the worst must not be one of them
        // (true whenever there are more measured peers than the keep band).
        if measured.len() <= LATENCY_KEEP_FASTEST {
            return None;
        }

        // Stability floor AND relative-outlier gate — both must hold.
        let is_slow = worst_rtt > LATENCY_FLOOR_MS;
        let is_outlier = worst_rtt > median * LATENCY_OUTLIER_RATIO;
        if !(is_slow && is_outlier) {
            return None;
        }

        // Swap, never shed: require a fresh candidate before dropping.
        let worst_id = self.peers[worst_idx].node_id;
        let candidate = match self.find_new_peer_candidate().cloned() {
            Some(c) => c,
            None => {
                log::info!(
                    "[latency-prune] outlier peer {:02x}{:02x}.. at {:.0}ms (median {:.0}ms) but no spare candidate — keeping (swap-not-shed)",
                    worst_id[0], worst_id[1], worst_rtt, median
                );
                return None;
            }
        };

        let dropped = self.peers.remove(worst_idx);
        self.peer_rtt_ms.remove(&dropped.node_id);
        // §6.3.7: bump the decaying penalty (capped) so grafting avoids it; a
        // chronic offender accumulates and stays avoided longer, a blip fades.
        let pen = self.latency_penalty.entry(dropped.node_id).or_insert(0.0);
        *pen = (*pen + LATENCY_PENALTY_ON_PRUNE).min(LATENCY_PENALTY_MAX);
        log::info!(
            "[latency-prune] dropped peer {:02x}{:02x}.. ({:.0}ms, median {:.0}ms) for faster neighbour {:02x}{:02x}..",
            dropped.node_id[0], dropped.node_id[1], worst_rtt, median,
            candidate.node_id[0], candidate.node_id[1]
        );
        self.peers.push(candidate.clone());
        Some(MeshAction::ConnectPeer(candidate))
    }

    // ── YPX-009: Silicon Pulse tracking ──

    /// Record a valid pulse proof from a validator (YPX-009 §5.2).
    /// Called after gossip engine verifies the Ed25519 signature.
    pub fn record_pulse_delivery(&mut self, validator_pk: &[u8; 32], epoch: u64) {
        use axiom_core_logic::types::PULSE_GRACE_CYCLES;
        let state = self.pulse_state.entry(*validator_pk).or_insert(crate::types::PeerPulseState {
            last_pulse_epoch: 0,
            consecutive_misses: 0,
            grace_remaining: PULSE_GRACE_CYCLES,
            total_pulses: 0,
        });
        if epoch > state.last_pulse_epoch {
            state.last_pulse_epoch = epoch;
            state.consecutive_misses = 0;
            state.total_pulses += 1;
        }
    }

    /// Evaluate pulse epoch — called at each epoch boundary (YPX-009 §7.2).
    /// Returns list of validator PKs that should be evicted (>= PULSE_MISS_EVICTION misses).
    pub fn evaluate_pulse_epoch(&mut self, current_epoch: u64) -> Vec<[u8; 32]> {
        use axiom_core_logic::types::{PULSE_MISS_EVICTION, PULSE_MISS_TOLERANCE};
        if current_epoch <= self.last_pulse_epoch {
            return vec![];
        }
        self.last_pulse_epoch = current_epoch;

        let mut evicted = vec![];
        for (pk, state) in self.pulse_state.iter_mut() {
            if state.grace_remaining > 0 {
                state.grace_remaining -= 1;
                continue;
            }
            if state.last_pulse_epoch < current_epoch {
                state.consecutive_misses += 1;
            }
            if state.consecutive_misses >= PULSE_MISS_EVICTION {
                evicted.push(*pk);
            } else if state.consecutive_misses >= PULSE_MISS_TOLERANCE {
                // Degraded — W3 penalty already computed from consecutive_misses
                log::debug!("YPX-009: Validator {:02x}{:02x}... degraded ({} misses)",
                    pk[0], pk[1], state.consecutive_misses);
            }
        }
        for pk in &evicted {
            self.pulse_state.remove(pk);
        }
        evicted
    }

    /// Get pulse state for a validator PK (for scoring).
    pub fn pulse_state_for(&self, validator_pk: &[u8; 32]) -> Option<&crate::types::PeerPulseState> {
        self.pulse_state.get(validator_pk)
    }

    // ── §6.3.3 Heartbeat + Rotation + Opportunistic Grafting ──

    /// Periodic peer check — called once per tick.
    ///
    /// Implements full §6.3 anti-ossification:
    ///   1. Prune stale peers (not seen in 60 ticks)
    ///   2. If peers > D_hi: prune lowest-scored to D_hi
    ///   3. If peers < D_lo: panic-graft (add multiple from known_nodes)
    ///   4. If peers < D: graft 1 per tick
    ///   5. Every 30 ticks: rotation — drop 1 lowest-scored if peers >= D
    ///   6. Every 60 ticks: opportunistic graft if median score < 0
    ///   7. Expire enquiry peer if TTL exceeded
    pub fn periodic_peer_check(&mut self, current_tick: u64) -> MeshAction {
        // Prune unique_seen every hour (720 ticks)
        if current_tick - self.last_seen_prune_tick >= 720 {
            self.unique_seen.clear();
            self.last_seen_prune_tick = current_tick;
        }

        // ── Step 1: Remove stale peers (not seen in STALE_PEER_THRESHOLD ticks) ──
        // §6.3.6: Bootstrap peers are NOT immune — same rules as everyone.
        let stale_threshold = current_tick.saturating_sub(STALE_PEER_THRESHOLD);
        self.peers.retain(|p| p.last_seen >= stale_threshold);

        // §6.3.7: drop RTT entries for peers no longer active (kept bounded to
        // the active peer set; a re-grafted peer is re-measured from scratch).
        let active_now: HashSet<NodeId> = self.peers.iter().map(|p| p.node_id).collect();
        self.peer_rtt_ms.retain(|id, _| active_now.contains(id));
        // §6.3.7: decay the latency penalties each tick, dropping negligible
        // entries so the map stays bounded.
        for v in self.latency_penalty.values_mut() {
            *v *= LATENCY_PENALTY_DECAY;
        }
        self.latency_penalty.retain(|_, v| *v > 0.05);

        // ── Step 1b: Prune stale entries from known_nodes ──
        // During partitions, cross-partition entries become stale and are removed.
        // This ensures bridge PX carries genuine discovery after sustained partition.
        // Active peers are protected from eviction (they're being seen).
        let active_ids: HashSet<NodeId> = self.peers.iter().map(|p| p.node_id).collect();
        self.known_nodes.retain(|id, p| {
            active_ids.contains(id) || p.last_seen >= stale_threshold
        });

        // ── Step 1c: Bootstrap fallback — re-seed when mesh-stranded ──
        // After sustained partition + stale pruning, a node can lose most of its
        // known_nodes. If below D_lo with no new candidates to graft, it's stuck
        // recycling the same depleted cluster. Re-inject bootstrap addresses
        // (from bootstrap.toml — operator-configured contact points)
        // as fresh known_nodes candidates.
        // Like DNS root hints — always available as last resort.
        let d_lo = self.d_lo();
        if self.peers.len() < d_lo && self.find_new_peer_candidate().is_none() {
            for bp in &self.bootstrap.clone() {
                if bp.node_id == self.my_node_id { continue; }
                let mut fresh = bp.clone();
                fresh.last_seen = current_tick; // mark fresh so it survives pruning
                fresh.connected_since = current_tick;
                self.insert_known_node(fresh.node_id, fresh);
            }
        }

        // ── Step 2: If peers > D_hi, prune lowest-scored to D_hi ──
        let d_hi = self.d_hi();
        while self.peers.len() > d_hi {
            if let Some(idx) = self.lowest_scored_peer_idx(current_tick) {
                self.peers.remove(idx);
            } else {
                break;
            }
        }

        // ── Step 3: If peers < D_lo, panic-graft (multiple at once) ──
        let target = self.regular_peer_target();
        if self.peers.len() < d_lo {
            // Graft up to regular_peer_target from known_nodes
            while self.peers.len() < target {
                if let Some(candidate) = self.find_new_peer_candidate() {
                    let peer = candidate.clone();
                    self.peers.push(peer);
                } else {
                    break;
                }
            }
            // If still below D_lo, need introductions
            if self.peers.len() < d_lo {
                if let Some(ask) = self.random_peer_id() {
                    return MeshAction::RequestIntroduction { ask_peer: ask };
                }
            }
        }

        // ── Step 4: If peers < D, graft 1 per tick ──
        if self.peers.len() < target {
            if let Some(candidate) = self.find_new_peer_candidate() {
                let peer = candidate.clone();
                self.peers.push(peer.clone());
                return MeshAction::ConnectPeer(peer);
            }
            // No known candidates — ask existing peer for introduction
            if let Some(ask) = self.random_peer_id() {
                return MeshAction::RequestIntroduction { ask_peer: ask };
            }
        }

        // ── Step 5: Rotation — every ROTATION_INTERVAL ticks ──
        // Drop 1 lowest-scored peer to create an open slot for newcomers.
        if current_tick > 0
            && current_tick - self.last_rotation_tick >= ROTATION_INTERVAL
            && self.peers.len() >= target
        {
            self.last_rotation_tick = current_tick;
            if let Some(idx) = self.lowest_scored_peer_idx(current_tick) {
                let removed = self.peers.remove(idx);
                self.peer_rtt_ms.remove(&removed.node_id);
                // Now peers < D, next tick will graft a new peer
            }
        }

        // ── Step 5b: §6.3.7 latency-aware prune — every LATENCY_PRUNE_INTERVAL ──
        // ticks, jittered per node so the mesh never rewires in lockstep. Swaps
        // the slowest link for a fresh one ONLY when it is a genuine outlier
        // (see latency_prune_step). Local RTT only — never a trust/money gate.
        if current_tick > 0
            && current_tick % LATENCY_PRUNE_INTERVAL
                == (self.my_node_id[0] as u64) % LATENCY_PRUNE_INTERVAL
        {
            if let Some(action) = self.latency_prune_step(current_tick) {
                return action;
            }
        }

        // ── Step 6: Opportunistic grafting — every OPPORTUNISTIC_INTERVAL ticks ──
        // If median peer score is negative, graft high-scoring known nodes.
        if current_tick > 0
            && current_tick - self.last_opportunistic_tick >= OPPORTUNISTIC_INTERVAL
        {
            self.last_opportunistic_tick = current_tick;
            if self.median_peer_score(current_tick) < 0.0 {
                let active_ids: HashSet<NodeId> = self.peers.iter().map(|p| p.node_id).collect();
                let my_id = self.my_node_id;
                // §6.3.7: opportunistic graft is latency-blind (it ranks by the
                // §6.3.2 message score), so it must ALSO skip latency-penalised
                // nodes — else a just-demoted slow node gets re-grafted here.
                let penalty = &self.latency_penalty;
                // Clone candidates to avoid holding refs into self.known_nodes
                let mut candidates: Vec<PeerInfo> = self.known_nodes.values()
                    .filter(|p| p.node_id != my_id && !active_ids.contains(&p.node_id)
                        && penalty.get(&p.node_id).copied().unwrap_or(0.0) <= LATENCY_PENALTY_GRAFT_BLOCK)
                    .cloned()
                    .collect();
                // Sort by score descending (inline formula to avoid &self borrow)
                let pulse_ref = &self.pulse_state;
                candidates.sort_by(|a, b| {
                    let score = |p: &PeerInfo| -> f64 {
                        let age = current_tick.saturating_sub(p.connected_since).max(1) as f64;
                        let base = (p.messages_delivered as f64 / age) * PEER_W1
                            - (current_tick.saturating_sub(p.last_seen) as f64 * PEER_W2)
                            - (age * PEER_W3);
                        if let Some(ps) = pulse_ref.get(&p.node_id) {
                            base + ps.total_pulses as f64 * 0.5 - ps.consecutive_misses as f64 * 5.0
                        } else {
                            base
                        }
                    };
                    score(b).partial_cmp(&score(a)).unwrap_or(std::cmp::Ordering::Equal)
                });
                let d_hi = self.d_hi();
                let graft_count = OPPORTUNISTIC_GRAFT_COUNT.min(candidates.len());
                for candidate in candidates.into_iter().take(graft_count) {
                    if self.peers.len() < d_hi {
                        self.peers.push(candidate);
                    }
                }
            }
        }

        // ── Step 7: Expire enquiry peer if TTL exceeded ──
        if let Some(ref epeer) = self.enquiry_peer {
            if current_tick.saturating_sub(epeer.connected_tick) >= E_PEER_TTL {
                self.enquiry_peer = None;
            }
        }

        // ── Step 8: Periodic knowledge refresh ──
        // Even at full peer count, request introductions every OPPORTUNISTIC_INTERVAL
        // to grow known_nodes for better rotation candidates.
        // Without this, nodes with only genesis peers never learn about other regulars.
        if current_tick > 0
            && self.peers.len() >= target
            && current_tick - self.last_knowledge_refresh_tick >= KNOWLEDGE_REFRESH_INTERVAL
        {
            self.last_knowledge_refresh_tick = current_tick;
            if let Some(ask) = self.random_peer_id() {
                return MeshAction::RequestIntroduction { ask_peer: ask };
            }
        }

        MeshAction::None
    }

    // ── §6.3.4 Enquiry Peer Management ──

    /// Request to become an enquiry peer on this node.
    /// Returns true if accepted, false if rejected.
    ///
    /// Rules:
    ///   - Max 1 E-peer per node
    ///   - 5-minute TTL
    ///   - Anti-camping: reject if same node_id as previous occupant
    pub fn enquiry_request(&mut self, node_id: NodeId, address: NablaAddress, current_tick: u64) -> bool {
        // Slot occupied?
        if self.enquiry_peer.is_some() {
            return false;
        }
        // Anti-camping: reject if same as last enquiry peer
        if self.last_enquiry_id == Some(node_id) {
            return false;
        }
        // Accept
        self.enquiry_peer = Some(EnquiryPeer {
            node_id,
            address,
            connected_tick: current_tick,
        });
        true
    }

    /// Disconnect the current enquiry peer (they found a home or timed out).
    pub fn enquiry_disconnect(&mut self) {
        if let Some(ref epeer) = self.enquiry_peer {
            self.last_enquiry_id = Some(epeer.node_id);
        }
        self.enquiry_peer = None;
    }

    /// Get current enquiry peer info (for read-only gossip forwarding).
    pub fn enquiry_peer(&self) -> Option<&EnquiryPeer> {
        self.enquiry_peer.as_ref()
    }

    /// Is this node currently hosting an enquiry peer?
    pub fn has_enquiry_peer(&self) -> bool {
        self.enquiry_peer.is_some()
    }

    /// Latency penalty for a node (0.0 if none recorded).
    fn latency_penalty_of(&self, node_id: &NodeId) -> f32 {
        self.latency_penalty.get(node_id).copied().unwrap_or(0.0)
    }

    /// Find a known node not yet in our active peer list.
    /// §6.3.7: prefer a candidate whose decaying latency penalty is below the
    /// graft-block threshold (so we don't re-graft a node we recently dropped
    /// for being slow); fall back to a penalised node only if it is the sole
    /// candidate (degree beats latency).
    fn find_new_peer_candidate(&self) -> Option<&PeerInfo> {
        let active_ids: HashSet<NodeId> = self.peers.iter().map(|p| p.node_id).collect();
        let eligible = |p: &&PeerInfo| {
            p.node_id != self.my_node_id && !active_ids.contains(&p.node_id)
        };
        self.known_nodes
            .values()
            .find(|p| eligible(p) && self.latency_penalty_of(&p.node_id) <= LATENCY_PENALTY_GRAFT_BLOCK)
            .or_else(|| self.known_nodes.values().find(eligible))
    }

    /// Get a peer's node ID for introduction requests (round-robin).
    fn random_peer_id(&mut self) -> Option<NodeId> {
        if self.peers.is_empty() {
            return None;
        }
        self.request_counter += 1;
        let idx = (self.request_counter as usize) % self.peers.len();
        Some(self.peers[idx].node_id)
    }

    // ── Task 23: Peer Discovery ──

    /// Learn about a node from a gossip message.
    /// Called whenever we see a node_id in any gossip traffic.
    /// Updates last_seen and increments messages_delivered for scoring (§6.3.2).
    pub fn observe_node(&mut self, node_id: NodeId, tick: u64) {
        self.unique_seen.insert(node_id);

        // Update last_seen if already known
        if let Some(existing) = self.known_nodes.get_mut(&node_id) {
            existing.last_seen = tick;
        }
        // Also update in active peers + count message delivery
        if let Some(peer) = self.peers.iter_mut().find(|p| p.node_id == node_id) {
            peer.last_seen = tick;
            peer.messages_delivered += 1;
        }
    }

    /// Add a newly discovered peer (from introduction or gossip).
    pub fn add_discovered_peer(&mut self, peer: PeerInfo) {
        if peer.node_id == self.my_node_id {
            return; // don't add ourselves
        }
        self.insert_known_node(peer.node_id, peer);
    }

    /// Merge peer info from PX introduction, preserving slot knowledge.
    /// Unlike add_discovered_peer which overwrites, this merges:
    /// - Positive slot info (has_d_open=true) always wins over unknown (false)
    /// - Newer last_seen wins
    /// - Updates available_slots map when slot info is present
    ///
    /// Used by PX introductions to propagate SlotAvailable knowledge.
    pub fn merge_peer_info(&mut self, peer: PeerInfo) {
        if peer.node_id == self.my_node_id {
            return;
        }
        if let Some(existing) = self.known_nodes.get_mut(&peer.node_id) {
            // Merge: newer last_seen wins
            if peer.last_seen > existing.last_seen {
                existing.last_seen = peer.last_seen;
            }
            // Positive slot info wins (has_d_open=true overrides false/unknown)
            if peer.has_d_open && !existing.has_d_open {
                existing.has_d_open = true;
                existing.open_slots = peer.open_slots;
                self.available_slots.insert(peer.node_id, peer.address);
            }
        } else {
            // New node — insert with full info
            if peer.has_d_open {
                self.available_slots.insert(peer.node_id, peer.address.clone());
            }
            self.insert_known_node(peer.node_id, peer);
        }
    }

    /// Add a peer directly to active list (if not already present).
    /// Insert-only: this is the path for SECOND-HAND information (attach
    /// referrals, IntroductionResponse peer exchange, sim wiring). A relayed
    /// PeerInfo carries whatever address the relayer had recorded — possibly
    /// stale — so it must never overwrite an entry we learned first-hand.
    /// First-hand self-announcements go through
    /// `upsert_peer_self_announced` instead.
    pub fn add_peer_direct(&mut self, peer: PeerInfo) {
        if peer.node_id == [0u8; 32] || peer.node_id == self.my_node_id {
            return;
        }
        if !self.peers.iter().any(|p| p.node_id == peer.node_id) {
            self.peers.push(peer);
        }
    }

    /// Insert or refresh an active peer from a FIRST-HAND self-announcement
    /// (Hello / TardisAttachRequest — a message the peer authored about
    /// itself). The announcement is authoritative for the peer's dial-back
    /// address (a node that rebinds or corrects a wildcard advertisement
    /// must become re-dialable) and its self-advertised txid mode — but NOT
    /// for this connection's lifetime counters or TARDIS topology fields.
    pub fn upsert_peer_self_announced(&mut self, peer: PeerInfo) {
        if peer.node_id == [0u8; 32] || peer.node_id == self.my_node_id {
            return;
        }
        if let Some(existing) = self.peers.iter_mut().find(|p| p.node_id == peer.node_id) {
            existing.address = peer.address;
            existing.last_seen = existing.last_seen.max(peer.last_seen);
            if !peer.txid_service.is_empty() {
                existing.txid_service = peer.txid_service;
            }
        } else {
            self.peers.push(peer);
        }
    }

    // ── §6.6 Human Bridge — Split Recovery PX ──

    /// One-shot peer exchange for split recovery (§6.6).
    ///
    /// When a receiver detects a root_hash mismatch (partition), the human
    /// bridge protocol connects receiver's Nabla to sender's Nabla. Both
    /// sides exchange their full known_nodes. The connection then closes.
    ///
    /// This injects cross-partition knowledge. The normal periodic_peer_check
    /// handles grafting from the new known_nodes within 1-2 rotation cycles.
    ///
    /// Returns (received, new_nodes, updated_nodes).
    pub fn human_bridge_px(&mut self, remote_known: &[PeerInfo], current_tick: u64) -> (usize, usize, usize) {
        let mut received = 0;
        let mut new_nodes = 0;
        let mut updated = 0;
        for peer in remote_known {
            if peer.node_id == self.my_node_id {
                continue;
            }
            received += 1;
            if self.known_nodes.contains_key(&peer.node_id) {
                updated += 1;
            } else {
                new_nodes += 1;
            }
            // Update or insert — remote info may be fresher
            let mut entry = peer.clone();
            entry.last_seen = current_tick; // mark as fresh — just learned about them
            entry.connected_since = current_tick;
            entry.messages_delivered = 0; // no local history yet
            self.insert_known_node(entry.node_id, entry);
            self.unique_seen.insert(peer.node_id);
        }
        (received, new_nodes, updated)
    }

    /// Export known_nodes for PX exchange (§6.6).
    /// Returns a snapshot of all known peers for sending to bridge partner.
    pub fn known_nodes_snapshot(&self) -> Vec<PeerInfo> {
        self.known_nodes.values().cloned().collect()
    }

    // ── Task 25: Gossip Message Routing ──

    /// Get list of peers for FULL gossip — mesh state, anti-entropy,
    /// pool sync, ban/quarantine, etc. E-peer is EXCLUDED: temporary
    /// observers (TTL 12 ticks) don't need the firehose; they only
    /// need discovery hints to find a parent. Use
    /// `discovery_hint_targets()` for `TopologyHint::*` broadcasts.
    pub fn forward_targets(&self, sender: &NodeId) -> Vec<NodeId> {
        self.peers
            .iter()
            .filter(|p| p.node_id != *sender && p.node_id != self.my_node_id
                && !self.quarantined_peers.contains(&p.node_id))
            .map(|p| p.node_id)
            .collect()
    }

    /// Get list of peers for discovery-hint gossip — `TopologyHint::*`
    /// (NewNode, SlotAvailable, LostUpstream). Includes mesh peers AND
    /// the current E-peer, since an observer needs parent-discovery
    /// info during its window. Per architectural rule: E-peer's data
    /// surface is ONLY discovery hints, never full mesh state.
    pub fn discovery_hint_targets(&self, sender: &NodeId) -> Vec<NodeId> {
        let mut targets = self.forward_targets(sender);
        if let Some(ref epeer) = self.enquiry_peer {
            if epeer.node_id != *sender && epeer.node_id != self.my_node_id
                && !self.quarantined_peers.contains(&epeer.node_id)
            {
                targets.push(epeer.node_id);
            }
        }
        targets
    }

    /// Get all active peer node IDs.
    pub fn peer_ids(&self) -> Vec<NodeId> {
        self.peers.iter().map(|p| p.node_id).collect()
    }

    // ── Task 26: Topology Hints ──

    /// Process a topology hint from gossip.
    /// Returns true if the hint contained NEW information worth relaying.
    pub fn apply_topology_hint(&mut self, hint: &TopologyHint) -> bool {
        match hint {
            TopologyHint::LostUpstream { node_id } => {
                // Record that this node needs a TARDIS parent
                if let Some(info) = self.known_nodes.get(node_id) {
                    self.orphaned_nodes.insert(*node_id, info.address.clone());
                }
                false // Don't relay LostUpstream (1-hop is sufficient)
            }
            TopologyHint::SlotAvailable { node_id, address, open_slots } => {
                // open_slots = 0 means "node is now full" (negative info).
                // Must propagate so peers stop preferring this node as a
                // dc=1 → writer-eligible candidate after its slots fill.
                let mut changed = false;
                if *open_slots > 0 {
                    let was_new = !self.available_slots.contains_key(node_id);
                    self.available_slots.insert(*node_id, address.clone());
                    changed = changed || was_new;
                } else if self.available_slots.remove(node_id).is_some() {
                    changed = true;
                }
                // Update known_nodes (long-term node directory)
                if let Some(info) = self.known_nodes.get_mut(node_id) {
                    if info.open_slots != *open_slots || info.has_d_open != (*open_slots > 0) {
                        info.has_d_open = *open_slots > 0;
                        info.open_slots = *open_slots;
                        changed = true;
                    }
                }
                // ALSO update active peers list — this is what the
                // prefer-dc=1 rebalance at nabla_node.rs:2778 reads.
                // Without this, prefer_writer pass sees stale data and
                // falls through to relaxed pass (= random pick).
                for peer in self.peers.iter_mut() {
                    if peer.node_id == *node_id {
                        if peer.open_slots != *open_slots || peer.has_d_open != (*open_slots > 0) {
                            peer.has_d_open = *open_slots > 0;
                            peer.open_slots = *open_slots;
                            changed = true;
                        }
                        break;
                    }
                }
                changed
            }
            TopologyHint::NewNode { node_id, address } => {
                // Add to known_nodes if not already there
                if !self.known_nodes.contains_key(node_id) {
                    self.insert_known_node(
                        *node_id,
                        PeerInfo {
                            node_id: *node_id,
                            address: address.clone(),
                            last_seen: 0,
                            tardis_up: None,
                            has_d_open: false, open_slots: 0,
                            messages_delivered: 0,
                            connected_since: 0,
            txid_service: String::new(),
                        },
                    );
                    true // New node — relay
                } else {
                    false
                }
            }
        }
    }

    /// Generate a LostUpstream hint (when our TARDIS upstream disconnects).
    pub fn announce_lost_upstream(&self) -> MeshAction {
        MeshAction::BroadcastTopology(TopologyHint::LostUpstream {
            node_id: self.my_node_id,
        })
    }

    /// Generate a SlotAvailable hint (when we have an open D slot).
    pub fn announce_slot_available(&self, open_slots: u8) -> MeshAction {
        MeshAction::BroadcastTopology(TopologyHint::SlotAvailable {
            node_id: self.my_node_id,
            address: self.my_address.clone(),
            open_slots,
        })
    }

    /// Generate a NewNode hint (when we first join the network).
    pub fn announce_new_node(&self) -> MeshAction {
        MeshAction::BroadcastTopology(TopologyHint::NewNode {
            node_id: self.my_node_id,
            address: self.my_address.clone(),
        })
    }

    // ── Task 27: TARDIS Self-Healing ──

    /// Find a candidate for TARDIS reconnection.
    ///
    /// When a node loses its TARDIS upstream, it uses mesh knowledge
    /// to find a node with an open D slot. The mesh provides discovery;
    /// actual reconnection uses the E → P → D path (Task 28).
    pub fn find_tardis_parent(&mut self) -> MeshAction {
        // Look for a node with an advertised open D slot
        if let Some((node_id, address)) = self.available_slots.iter().next() {
            let node_id = *node_id;
            let address = address.clone();
            // Remove from available — we're claiming it
            self.available_slots.remove(&node_id);
            return MeshAction::AttemptTardisReconnect {
                target: node_id,
                address,
            };
        }

        // No advertised slots — ask random peer if they have an open slot
        if let Some(ask) = self.random_peer_id() {
            return MeshAction::RequestIntroduction { ask_peer: ask };
        }

        MeshAction::None
    }

    /// Clear an orphan entry (node found a new parent).
    pub fn clear_orphan(&mut self, node_id: &NodeId) {
        self.orphaned_nodes.remove(node_id);
    }

    /// Find a dc=1 node (open_slots==1) for voluntary reattach.
    /// ONLY dc=1 targets — guarantees writer creation on attachment.
    /// dc=0 targets just shuffle the problem without creating writers.
    /// §2.16.5: mesh-informed tree rebalancing after partition/chaos.
    pub fn find_reattach_target(&self, exclude: &NodeId) -> Option<NodeId> {
        for (nid, info) in &self.known_nodes {
            if nid == exclude { continue; }
            if nid == &self.my_node_id { continue; }
            if info.has_d_open && info.open_slots == 1 {
                return Some(*nid);
            }
        }
        None
    }

    /// Clear a slot entry (slot was filled).
    pub fn clear_slot(&mut self, node_id: &NodeId) {
        self.available_slots.remove(node_id);
        if let Some(info) = self.known_nodes.get_mut(node_id) {
            info.has_d_open = false;
        }
    }

    // ── Task 28: E Enquiry ──
    // E enquiry is the real-time slot check for TARDIS reconnection.
    // The mesh provides discovery (find_tardis_parent).
    // The E enquiry is stateless — it's a direct TCP request to the
    // candidate node: "Do you have a D slot open? Can I connect?"
    // This is handled at the network layer, not the mesh layer.
    // The mesh returns AttemptTardisReconnect with the target address;
    // the network layer performs the E enquiry.

    // ── Getters ──

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn known_node_count(&self) -> usize {
        self.known_nodes.len()
    }

    /// All known node IDs (for Peer Exchange / introductions).
    /// Returns full knowledge base, not just active peers.
    pub fn known_node_ids(&self) -> Vec<NodeId> {
        self.known_nodes.keys().copied().collect()
    }

    pub fn unique_seen_count(&self) -> usize {
        self.unique_seen.len()
    }

    pub fn orphan_count(&self) -> usize {
        self.orphaned_nodes.len()
    }

    pub fn available_slot_count(&self) -> usize {
        self.available_slots.len()
    }

    pub fn my_node_id(&self) -> &NodeId {
        &self.my_node_id
    }

    pub fn my_address(&self) -> &NablaAddress {
        &self.my_address
    }

    /// Network size estimate (unique nodes seen recently).
    pub fn estimated_network_size(&self) -> usize {
        self.unique_seen.len().max(self.peers.len())
    }

    /// Look up a peer by node ID in active peers.
    pub fn peer_by_id(&self, node_id: &NodeId) -> Option<&PeerInfo> {
        self.peers.iter().find(|p| p.node_id == *node_id)
            .or_else(|| self.known_nodes.get(node_id))
    }

    /// Mutable peer lookup by node ID.
    pub fn peer_by_id_mut(&mut self, node_id: &NodeId) -> Option<&mut PeerInfo> {
        if let Some(p) = self.peers.iter_mut().find(|p| p.node_id == *node_id) {
            return Some(p);
        }
        self.known_nodes.get_mut(node_id)
    }

    /// Active mesh peers (snapshot for iteration).
    pub fn active_peers(&self) -> &[PeerInfo] {
        &self.peers
    }

    /// Record a peer we've heard from (add to known_nodes if new).
    pub fn note_peer(&mut self, node_id: NodeId, address: NablaAddress, tick: u64) {
        if node_id == self.my_node_id {
            return; // don't record ourselves
        }
        let peer = PeerInfo {
            node_id,
            address,
            last_seen: tick,
            tardis_up: None,
            has_d_open: false,
            open_slots: 0,
            messages_delivered: 0,
            connected_since: tick,
            txid_service: String::new(),
        };
        self.insert_known_node(node_id, peer);
    }

    /// Record a peer learned SECOND-HAND (attach referrals,
    /// IntroductionResponse peer exchange). Discovery-only: inserts unknown
    /// nodes but never overwrites an existing entry — the relayer's recorded
    /// address may be stale, and `note_peer` (first-hand) would clobber a
    /// good address we already hold.
    pub fn note_peer_referral(&mut self, node_id: NodeId, address: NablaAddress, tick: u64) {
        if node_id == self.my_node_id || self.known_nodes.contains_key(&node_id) {
            return;
        }
        self.note_peer(node_id, address, tick);
    }
}

// ── Nabla Address Encoding (§6.6) ──

/// Encode a Nabla address as a human-readable Base32 string.
/// IPv4: 10 chars, IPv6: 29 chars. Length determines type.
pub fn encode_nabla_address(addr: &NablaAddress) -> String {
    match addr {
        NablaAddress::V4 { ip, port } => {
            let mut bytes = Vec::with_capacity(6);
            bytes.extend_from_slice(ip);
            bytes.extend_from_slice(&port.to_be_bytes());
            base32_encode(&bytes)
        }
        NablaAddress::V6 { ip, port } => {
            let mut bytes = Vec::with_capacity(18);
            bytes.extend_from_slice(ip);
            bytes.extend_from_slice(&port.to_be_bytes());
            base32_encode(&bytes)
        }
    }
}

/// Decode a human-readable Base32 string back to a Nabla address.
pub fn decode_nabla_address(code: &str) -> Result<NablaAddress, NablaError> {
    let bytes = base32_decode(code)?;
    match bytes.len() {
        6 => {
            let ip: [u8; 4] = bytes[0..4].try_into().unwrap();
            let port = u16::from_be_bytes([bytes[4], bytes[5]]);
            Ok(NablaAddress::V4 { ip, port })
        }
        18 => {
            let ip: [u8; 16] = bytes[0..16].try_into().unwrap();
            let port = u16::from_be_bytes([bytes[16], bytes[17]]);
            Ok(NablaAddress::V6 { ip, port })
        }
        _ => Err(NablaError::SmtError("invalid nabla address length".into())),
    }
}

/// Simple Base32 encode (RFC 4648, no padding).
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        result.push(ALPHABET[idx] as char);
    }
    result
}

/// Simple Base32 decode (RFC 4648, no padding).
fn base32_decode(s: &str) -> Result<Vec<u8>, NablaError> {
    let mut result = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;

    for ch in s.chars() {
        let val = match ch {
            'A'..='Z' => ch as u64 - 'A' as u64,
            '2'..='7' => ch as u64 - '2' as u64 + 26,
            _ => return Err(NablaError::SmtError("invalid base32 character".into())),
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Ok(result)
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn node_id(b: u8) -> NodeId {
        [b; 32]
    }

    fn make_address(b: u8) -> NablaAddress {
        NablaAddress::V4 {
            ip: [10, 0, 0, b],
            port: 8080 + b as u16,
        }
    }

    fn make_peer(b: u8, tick: u64) -> PeerInfo {
        PeerInfo {
            node_id: node_id(b),
            address: make_address(b),
            last_seen: tick,
            tardis_up: None,
            has_d_open: false, open_slots: 0,
            messages_delivered: 0,
            connected_since: tick,
            txid_service: String::new(),
        }
    }

    // ── Bootstrap & Peer Count ──

    #[test]
    fn bootstrap_adds_peers() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        mesh.add_bootstrap(vec![make_peer(1, 0), make_peer(2, 0), make_peer(3, 0)]);

        assert_eq!(mesh.peer_count(), 3);
        assert_eq!(mesh.known_node_count(), 3);
    }

    #[test]
    fn self_announcement_refreshes_address_of_active_peer() {
        // A self-announcement (Hello) is authoritative for the dial-back
        // address: a peer that first advertised a wildcard bind and then
        // corrected it must become re-dialable. Lifetime counters stay.
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        let mut stale = make_peer(1, 5);
        stale.address = NablaAddress::V4 { ip: [0, 0, 0, 0], port: 7301 };
        stale.messages_delivered = 42;
        mesh.add_peer_direct(stale);

        let mut fresh = make_peer(1, 9);
        fresh.address = NablaAddress::V4 { ip: [172, 20, 0, 42], port: 7301 };
        fresh.txid_service = "hashmap".to_string();
        mesh.upsert_peer_self_announced(fresh);

        assert_eq!(mesh.peer_count(), 1);
        let p = mesh.active_peers().iter().find(|p| p.node_id == node_id(1)).unwrap();
        assert_eq!(p.address, NablaAddress::V4 { ip: [172, 20, 0, 42], port: 7301 });
        assert_eq!(p.last_seen, 9);
        assert_eq!(p.txid_service, "hashmap");
        assert_eq!(p.messages_delivered, 42, "lifetime counters must survive a refresh");
        assert_eq!(p.connected_since, 5, "connection start must survive a refresh");
    }

    #[test]
    fn referral_never_clobbers_first_hand_address() {
        // Second-hand info (attach referrals / IntroductionResponse) may
        // carry a stale address the relayer recorded long ago. It must not
        // overwrite what the node itself announced — in the active set OR
        // in known_nodes.
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        let good = NablaAddress::V4 { ip: [172, 20, 0, 42], port: 7301 };
        let stale = NablaAddress::V4 { ip: [0, 0, 0, 0], port: 7301 };

        let mut announced = make_peer(1, 5);
        announced.address = good.clone();
        mesh.note_peer(node_id(1), good.clone(), 5);
        mesh.upsert_peer_self_announced(announced);

        let mut relayed = make_peer(1, 9);
        relayed.address = stale.clone();
        mesh.note_peer_referral(node_id(1), stale.clone(), 9);
        mesh.add_peer_direct(relayed);

        let p = mesh.active_peers().iter().find(|p| p.node_id == node_id(1)).unwrap();
        assert_eq!(p.address, good, "active-set address must survive a referral");
        let k = mesh.known_nodes_snapshot().into_iter().find(|p| p.node_id == node_id(1)).unwrap();
        assert_eq!(k.address, good, "known_nodes address must survive a referral");

        // A referral for a genuinely unknown node still gets discovered.
        let mut unknown = make_peer(2, 9);
        unknown.address = stale.clone();
        mesh.note_peer_referral(node_id(2), stale.clone(), 9);
        mesh.add_peer_direct(unknown);
        assert!(mesh.known_nodes_snapshot().iter().any(|p| p.node_id == node_id(2)));
    }

    #[test]
    fn target_peer_count_small() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        // No nodes seen → 9
        assert_eq!(mesh.target_peer_count(), MESH_PEER_BASE);

        // 10 nodes seen → 9 + max(0, ceil(log10(10)) - 1) = 9 + 0 = 9
        for i in 1..=10u8 {
            mesh.unique_seen.insert(node_id(i));
        }
        assert_eq!(mesh.target_peer_count(), MESH_PEER_BASE);
    }

    #[test]
    fn target_peer_count_medium() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        // 100 nodes seen → 9 + max(0, ceil(log10(100)) - 1) = 9 + 1 = 10
        for i in 0..100u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_le_bytes());
            mesh.unique_seen.insert(id);
        }
        assert_eq!(mesh.target_peer_count(), 10);
    }

    #[test]
    fn target_peer_count_large() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        // 10000 nodes seen → 9 + max(0, ceil(log10(10000)) - 1) = 9 + 3 = 12
        for i in 0..10000u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_le_bytes());
            mesh.unique_seen.insert(id);
        }
        assert_eq!(mesh.target_peer_count(), 12);
    }

    #[test]
    fn target_peer_count_capped() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        // Simulate very large network — should cap at MESH_PEER_MAX
        for i in 0..1_000_000u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_le_bytes());
            mesh.unique_seen.insert(id);
        }
        assert!(mesh.target_peer_count() <= MESH_PEER_MAX);
    }

    // ── Peer Discovery ──

    #[test]
    fn observe_node_tracks_unique() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        mesh.observe_node(node_id(1), 1);
        mesh.observe_node(node_id(2), 1);
        mesh.observe_node(node_id(1), 2); // duplicate

        assert_eq!(mesh.unique_seen_count(), 2);
    }

    #[test]
    fn discover_peer_adds_to_known() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        mesh.add_discovered_peer(make_peer(5, 10));
        assert_eq!(mesh.known_node_count(), 1);

        // Can't add ourselves
        mesh.add_discovered_peer(PeerInfo {
            node_id: node_id(0),
            address: make_address(0),
            last_seen: 0,
            tardis_up: None,
            has_d_open: false, open_slots: 0,
            messages_delivered: 0,
            connected_since: 0,
            txid_service: String::new(),
        });
        assert_eq!(mesh.known_node_count(), 1);
    }

    // ── Peer Management ──

    #[test]
    fn periodic_check_adds_peer_from_known() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        // Add known nodes but don't make them active peers
        mesh.known_nodes.insert(node_id(1), make_peer(1, 10));
        mesh.known_nodes.insert(node_id(2), make_peer(2, 10));

        // We have 0 peers, below D_lo (6) → panic-graft adds all available
        let _action = mesh.periodic_peer_check(10);
        assert_eq!(mesh.peer_count(), 2, "panic-graft should add all known peers");
    }

    #[test]
    fn stale_peers_removed() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        // Add peers seen at tick 10
        mesh.peers.push(make_peer(1, 10));
        mesh.peers.push(make_peer(2, 10));
        assert_eq!(mesh.peer_count(), 2);

        // At tick 100 (90 ticks later > 60 threshold), they're stale
        mesh.periodic_peer_check(100);
        assert_eq!(mesh.peer_count(), 0);
    }

    #[test]
    fn bootstrap_peers_pruned_when_stale() {
        // §6.3.6: Bootstrap peers are NOT immune from stale pruning.
        // After pruning, bootstrap re-seeding (Step 1c) re-injects
        // the bootstrap peer with a fresh timestamp to prevent mesh-stranding.
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        mesh.add_bootstrap(vec![make_peer(1, 0)]);

        // At tick 1000 (1000 ticks since last_seen=0), bootstrap is stale.
        // Step 1c re-seeds it with last_seen=1000 (fresh), then Step 3 grafts it.
        mesh.periodic_peer_check(1000);
        // The peer was pruned (stale) then re-added fresh — verify it's now fresh
        assert_eq!(mesh.peer_count(), 1, "bootstrap re-seeded after stale pruning");
        assert!(mesh.peers[0].last_seen >= 1000, "re-seeded bootstrap should have fresh timestamp");
    }

    // ── §6.3.7 Latency-aware pruning ──

    /// Build a mesh whose ACTIVE peers are ids 1..=n at `tick`, with a single
    /// spare in known_nodes (id 200) available as a graft candidate.
    fn mesh_with_active(n: u8, tick: u64) -> GossipMesh {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        for b in 1..=n {
            mesh.peers.push(make_peer(b, tick));
        }
        // A fresh candidate to graft (not an active peer).
        mesh.known_nodes.insert(node_id(200), make_peer(200, tick));
        mesh
    }

    #[test]
    fn record_peer_rtt_ewma() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        mesh.record_peer_rtt(node_id(1), 100.0); // first sample = seed
        assert_eq!(mesh.peer_rtt(&node_id(1)), Some(100.0));
        mesh.record_peer_rtt(node_id(1), 200.0); // 0.8*100 + 0.2*200 = 120
        let r = mesh.peer_rtt(&node_id(1)).unwrap();
        assert!((r - 120.0).abs() < 0.001, "EWMA expected 120, got {r}");
        // NaN / negative ignored.
        mesh.record_peer_rtt(node_id(1), -5.0);
        assert!((mesh.peer_rtt(&node_id(1)).unwrap() - 120.0).abs() < 0.001);
    }

    #[test]
    fn latency_outlier_pruned_with_replacement() {
        // 8 fast peers (50ms) + 1 slow outlier (600ms). Outlier dropped, spare grafted.
        let mut mesh = mesh_with_active(9, 100);
        for b in 1..=8u8 {
            mesh.record_peer_rtt(node_id(b), 50.0);
        }
        mesh.record_peer_rtt(node_id(9), 600.0);
        let action = mesh.latency_prune_step(100);
        assert!(matches!(action, Some(MeshAction::ConnectPeer(_))), "should graft a replacement");
        assert!(!mesh.peer_ids().contains(&node_id(9)), "the 600ms outlier must be dropped");
        assert!(mesh.peer_ids().contains(&node_id(200)), "the fresh candidate must be grafted");
        assert_eq!(mesh.peer_count(), 9, "swap keeps degree constant");
        assert!(mesh.peer_rtt(&node_id(9)).is_none(), "dropped peer's RTT entry cleared");
    }

    #[test]
    fn latency_uniform_slow_does_not_prune() {
        // All 9 peers equally slow (550ms). Worst ≈ median ⇒ NOT an outlier ⇒
        // no prune, no self-isolation — the satellite-region case.
        let mut mesh = mesh_with_active(9, 100);
        for b in 1..=9u8 {
            mesh.record_peer_rtt(node_id(b), 550.0);
        }
        assert!(mesh.latency_prune_step(100).is_none(), "uniform-slow mesh must not churn");
        assert_eq!(mesh.peer_count(), 9);
    }

    #[test]
    fn latency_no_prune_below_floor() {
        // One peer is a relative outlier (200ms vs 20ms median = 10×) but still
        // under the 300ms floor → the mesh is fine, leave it alone.
        let mut mesh = mesh_with_active(9, 100);
        for b in 1..=8u8 {
            mesh.record_peer_rtt(node_id(b), 20.0);
        }
        mesh.record_peer_rtt(node_id(9), 200.0);
        assert!(mesh.latency_prune_step(100).is_none(), "below floor → no prune");
        assert!(mesh.peer_ids().contains(&node_id(9)));
    }

    #[test]
    fn latency_respects_degree_floor() {
        // At d_lo, never prune even a clear outlier (would risk isolation).
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        let d_lo = mesh.d_lo();
        for b in 1..=(d_lo as u8) {
            mesh.peers.push(make_peer(b, 100));
            mesh.record_peer_rtt(node_id(b), 50.0);
        }
        mesh.known_nodes.insert(node_id(200), make_peer(200, 100));
        // Make one a blatant outlier.
        mesh.record_peer_rtt(node_id(1), 999.0);
        assert_eq!(mesh.peer_count(), d_lo);
        assert!(mesh.latency_prune_step(100).is_none(), "at degree floor → never prune");
        assert_eq!(mesh.peer_count(), d_lo);
    }

    #[test]
    fn periodic_check_latency_swaps_slow_outlier() {
        // END-TO-END through periodic_peer_check (Step 5b) — the wiring the
        // live env could not exercise (10-node full mesh has no spare to graft).
        // A slow outlier WITH a spare candidate is swapped for a faster
        // neighbour under the real cadence + jitter.
        let tick = 100u64; // node_id[0]=0 → jitter phase 0 → 100 % 10 == 0 fires Step 5b
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        // 8 fresh active peers == regular target, so Steps 3/4 don't preempt.
        for b in 1..=8u8 {
            mesh.peers.push(make_peer(b, tick));
            mesh.unique_seen.insert(node_id(b));
        }
        // A fresh spare (known, not active) to graft into.
        mesh.known_nodes.insert(node_id(50), make_peer(50, tick));
        // Suppress rotation / opportunistic / knowledge-refresh so only the
        // latency step acts this tick.
        mesh.last_rotation_tick = tick;
        mesh.last_opportunistic_tick = tick;
        mesh.last_knowledge_refresh_tick = tick;
        // RTT: peers 1..=7 fast, peer 8 a clear slow outlier.
        for b in 1..=7u8 { mesh.record_peer_rtt(node_id(b), 5.0); }
        mesh.record_peer_rtt(node_id(8), 600.0);

        let action = mesh.periodic_peer_check(tick);

        assert!(matches!(action, MeshAction::ConnectPeer(_)),
            "Step 5b should graft a replacement, got {action:?}");
        assert!(!mesh.peer_ids().contains(&node_id(8)), "slow outlier (peer 8) must be pruned");
        assert!(mesh.peer_ids().contains(&node_id(50)), "spare candidate must be grafted");
        assert_eq!(mesh.peer_count(), 8, "swap keeps degree constant");
        assert!(mesh.peer_rtt(&node_id(8)).is_none(), "pruned peer's RTT entry cleared");
    }

    #[test]
    fn latency_penalty_bumps_on_prune_and_decays() {
        // A latency prune bumps the decaying penalty; periodic_peer_check decays
        // it each tick until it falls back below the graft-block threshold.
        let mut mesh = mesh_with_active(9, 100);
        for b in 1..=8u8 { mesh.record_peer_rtt(node_id(b), 50.0); }
        mesh.record_peer_rtt(node_id(9), 600.0);
        let _ = mesh.latency_prune_step(100);
        let p0 = mesh.latency_penalty_of(&node_id(9));
        assert!((p0 - LATENCY_PENALTY_ON_PRUNE).abs() < 0.001, "prune sets penalty ~1.0, got {p0}");
        assert!(p0 > LATENCY_PENALTY_GRAFT_BLOCK, "penalised node is above the graft block");

        // Decay runs once per periodic_peer_check. Keep peers fresh so the only
        // effect we observe is the penalty decaying.
        let mut tick = 100u64;
        for _ in 0..400 {
            tick += 1;
            for p in mesh.peers.iter_mut() { p.last_seen = tick; }
            let _ = mesh.periodic_peer_check(tick);
        }
        assert!(mesh.latency_penalty_of(&node_id(9)) <= LATENCY_PENALTY_GRAFT_BLOCK,
            "penalty must decay below the graft block over time (preference, not ban)");
    }

    #[test]
    fn latency_penalty_blocks_regraft_until_decayed() {
        // A penalised node is avoided as a graft candidate while a clean spare
        // exists, but is still grafted as a LAST resort (degree beats latency).
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        for b in 1..=8u8 { mesh.peers.push(make_peer(b, 100)); mesh.unique_seen.insert(node_id(b)); }
        mesh.known_nodes.insert(node_id(9), make_peer(9, 100));   // penalised spare
        mesh.known_nodes.insert(node_id(50), make_peer(50, 100)); // clean spare
        mesh.latency_penalty.insert(node_id(9), 1.0);

        assert_eq!(mesh.find_new_peer_candidate().map(|p| p.node_id), Some(node_id(50)),
            "must prefer the clean spare over the penalised node");

        mesh.known_nodes.remove(&node_id(50)); // now node 9 is the only spare
        assert_eq!(mesh.find_new_peer_candidate().map(|p| p.node_id), Some(node_id(9)),
            "penalised node grafted as last resort when it is the sole candidate");
    }

    #[test]
    fn latency_outlier_not_pruned_without_candidate() {
        // Swap-not-shed: a clear outlier stays if there is no replacement.
        let mut mesh = mesh_with_active(9, 100);
        mesh.known_nodes.clear(); // remove the spare candidate
        for b in 1..=8u8 {
            mesh.record_peer_rtt(node_id(b), 50.0);
        }
        mesh.record_peer_rtt(node_id(9), 600.0);
        assert!(mesh.latency_prune_step(100).is_none(), "no candidate → no shed");
        assert_eq!(mesh.peer_count(), 9, "degree preserved");
    }

    // ── Forward Targets ──

    #[test]
    fn forward_excludes_sender() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        mesh.peers.push(make_peer(1, 10));
        mesh.peers.push(make_peer(2, 10));
        mesh.peers.push(make_peer(3, 10));

        let targets = mesh.forward_targets(&node_id(2));
        assert_eq!(targets.len(), 2);
        assert!(!targets.contains(&node_id(2)));
        assert!(targets.contains(&node_id(1)));
        assert!(targets.contains(&node_id(3)));
    }

    // ── Topology Hints ──

    #[test]
    fn topology_lost_upstream() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        mesh.known_nodes.insert(node_id(5), make_peer(5, 10));

        mesh.apply_topology_hint(&TopologyHint::LostUpstream {
            node_id: node_id(5),
        });

        assert_eq!(mesh.orphan_count(), 1);
    }

    #[test]
    fn topology_slot_available() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        mesh.apply_topology_hint(&TopologyHint::SlotAvailable {
            node_id: node_id(7),
            address: make_address(7),
            open_slots: 1,
        });

        assert_eq!(mesh.available_slot_count(), 1);
    }

    #[test]
    fn topology_new_node_discovered() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        mesh.apply_topology_hint(&TopologyHint::NewNode {
            node_id: node_id(9),
            address: make_address(9),
        });

        assert_eq!(mesh.known_node_count(), 1);
    }

    // ── TARDIS Self-Healing ──

    #[test]
    fn find_tardis_parent_from_available() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        // Announce a slot
        mesh.apply_topology_hint(&TopologyHint::SlotAvailable {
            node_id: node_id(5),
            address: make_address(5),
            open_slots: 1,
        });

        let action = mesh.find_tardis_parent();
        match action {
            MeshAction::AttemptTardisReconnect { target, .. } => {
                assert_eq!(target, node_id(5));
            }
            _ => panic!("Expected AttemptTardisReconnect"),
        }

        // Slot consumed
        assert_eq!(mesh.available_slot_count(), 0);
    }

    #[test]
    fn find_tardis_parent_no_slots() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        mesh.peers.push(make_peer(1, 10));

        // No available slots — should request introduction
        let action = mesh.find_tardis_parent();
        assert!(matches!(action, MeshAction::RequestIntroduction { .. }));
    }

    // ── Announcements ──

    #[test]
    fn announce_lost_upstream() {
        let mesh = GossipMesh::new(node_id(0xAA), make_address(0xAA));
        let action = mesh.announce_lost_upstream();
        match action {
            MeshAction::BroadcastTopology(TopologyHint::LostUpstream { node_id: nid }) => {
                assert_eq!(nid, node_id(0xAA));
            }
            _ => panic!("Expected BroadcastTopology(LostUpstream)"),
        }
    }

    #[test]
    fn announce_slot_available() {
        let mesh = GossipMesh::new(node_id(0xBB), make_address(0xBB));
        let action = mesh.announce_slot_available(1);
        match action {
            MeshAction::BroadcastTopology(TopologyHint::SlotAvailable {
                node_id: nid,
                address,
                open_slots,
            }) => {
                assert_eq!(nid, node_id(0xBB));
                assert_eq!(address, make_address(0xBB));
                assert_eq!(open_slots, 1);
            }
            _ => panic!("Expected BroadcastTopology(SlotAvailable)"),
        }
    }

    // ── Address Encoding ──

    #[test]
    fn encode_decode_ipv4() {
        let addr = NablaAddress::V4 {
            ip: [192, 168, 1, 100],
            port: 9090,
        };
        let encoded = encode_nabla_address(&addr);
        let decoded = decode_nabla_address(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn encode_decode_ipv6() {
        let addr = NablaAddress::V6 {
            ip: [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x01,
            ],
            port: 8443,
        };
        let encoded = encode_nabla_address(&addr);
        let decoded = decode_nabla_address(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn ipv4_address_length() {
        let addr = NablaAddress::V4 {
            ip: [10, 0, 0, 1],
            port: 8080,
        };
        let encoded = encode_nabla_address(&addr);
        assert_eq!(encoded.len(), 10); // 6 bytes → 10 Base32 chars
    }

    #[test]
    fn ipv6_address_length() {
        let addr = NablaAddress::V6 {
            ip: [0u8; 16],
            port: 8080,
        };
        let encoded = encode_nabla_address(&addr);
        assert_eq!(encoded.len(), 29); // 18 bytes → 29 Base32 chars
    }

    // ── Network Size Estimate ──

    #[test]
    fn estimated_network_size() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        mesh.peers.push(make_peer(1, 10));
        mesh.peers.push(make_peer(2, 10));

        // No unique seen → estimate is peer count
        assert_eq!(mesh.estimated_network_size(), 2);

        // After observing more
        for i in 1..=50u8 {
            mesh.observe_node(node_id(i), 10);
        }
        assert_eq!(mesh.estimated_network_size(), 50);
    }

    // ── Unique Seen Pruning ──

    #[test]
    fn unique_seen_pruned_hourly() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        for i in 1..=20u8 {
            mesh.observe_node(node_id(i), 10);
        }
        assert_eq!(mesh.unique_seen_count(), 20);

        // After 720 ticks (1 hour), should prune
        mesh.periodic_peer_check(730);
        assert_eq!(mesh.unique_seen_count(), 0);
    }

    // ── §6.3.1 Degree Band ──

    #[test]
    fn degree_band_genesis() {
        let mesh = GossipMesh::new(node_id(0), make_address(0));
        // D=9 (base, no nodes seen), regular = 9 - 1(E-peer) = 8
        assert_eq!(mesh.target_peer_count(), 9);
        assert_eq!(mesh.regular_peer_target(), 8);
        assert_eq!(mesh.d_lo(), 6);  // 8 - 2
        assert_eq!(mesh.d_hi(), 11); // 8 + 3
    }

    #[test]
    fn degree_band_production() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        // 10000 nodes → D=12, regular = 12 - 1(E-peer) = 11
        for i in 0..10000u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_le_bytes());
            mesh.unique_seen.insert(id);
        }
        assert_eq!(mesh.target_peer_count(), 12);
        assert_eq!(mesh.regular_peer_target(), 11);
        assert_eq!(mesh.d_lo(), 9);  // 11 - 2
        assert_eq!(mesh.d_hi(), 14); // 11 + 3
    }

    // ── §6.3.2 Peer Scoring ──

    #[test]
    fn peer_score_active_higher() {
        let mesh = GossipMesh::new(node_id(0), make_address(0));

        let mut active_peer = make_peer(1, 100);
        active_peer.messages_delivered = 50;

        let mut idle_peer = make_peer(2, 50);
        idle_peer.messages_delivered = 5;

        let active_score = mesh.peer_score(&active_peer, 100);
        let idle_score = mesh.peer_score(&idle_peer, 100);

        // active: rate=50/1, age=1 → (50×10) - 0 - 0.1 ≈ 499.9
        // idle:   rate=5/50=0.1, stale=50, age=50 → 1 - 50 - 5 = −54
        assert!(active_score > idle_score,
            "active peer ({}) should score higher than idle peer ({})", active_score, idle_score);
    }

    #[test]
    fn peer_score_freshness_penalty() {
        let mesh = GossipMesh::new(node_id(0), make_address(0));

        let mut peer = make_peer(1, 0);
        peer.messages_delivered = 3;

        // At tick 100: rate=3/100=0.03, stale=100, age=100 → 0.3 - 100 - 10 ≈ −110
        let score = mesh.peer_score(&peer, 100);
        assert!(score < 0.0, "stale peer should have negative score: {}", score);
    }

    #[test]
    fn observe_node_increments_messages_delivered() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        mesh.peers.push(make_peer(1, 10));

        mesh.observe_node(node_id(1), 11);
        mesh.observe_node(node_id(1), 12);
        mesh.observe_node(node_id(1), 13);

        assert_eq!(mesh.peers[0].messages_delivered, 3);
    }

    // ── §6.3.3 Rotation ──

    #[test]
    fn rotation_drops_lowest_scored() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        // Add 9 peers (above regular_peer_target=8 for genesis)
        for i in 1..=9u8 {
            let mut peer = make_peer(i, 100);
            peer.messages_delivered = i as u64 * 10; // peer 1=10, peer 9=90
            mesh.peers.push(peer);
        }
        assert_eq!(mesh.peer_count(), 9);

        // Trigger rotation at tick 130 (> 30 ticks from last_rotation_tick=0)
        mesh.periodic_peer_check(130);

        // Peer 1 (lowest score=10) should be dropped
        assert_eq!(mesh.peer_count(), 8);
        assert!(!mesh.peer_ids().contains(&node_id(1)),
            "lowest-scored peer should be dropped by rotation");
    }

    #[test]
    fn rotation_interval_respected() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        // Fill to 9 (above regular target=8)
        for i in 1..=9u8 {
            let mut peer = make_peer(i, 50);
            peer.messages_delivered = 10;
            mesh.peers.push(peer);
        }

        // At tick 10 (< ROTATION_INTERVAL from 0), no rotation
        mesh.periodic_peer_check(10);
        assert_eq!(mesh.peer_count(), 9, "no rotation before interval");

        // At tick 31 (>= ROTATION_INTERVAL from 0), rotation happens
        mesh.periodic_peer_check(31);
        assert_eq!(mesh.peer_count(), 8, "rotation should drop 1 peer");
    }

    // ── §6.3 D_hi Pruning ──

    #[test]
    fn d_hi_prune_excess_peers() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        // Add 15 peers (D_hi=11 for regular_target=8)
        for i in 1..=15u8 {
            let mut peer = make_peer(i, 100);
            peer.messages_delivered = i as u64;
            mesh.peers.push(peer);
        }
        assert_eq!(mesh.peer_count(), 15);

        mesh.periodic_peer_check(100);

        // Should prune down to D_hi=11
        assert!(mesh.peer_count() <= mesh.d_hi(),
            "peers should be pruned to D_hi={}, got {}", mesh.d_hi(), mesh.peer_count());
    }

    // ── §6.3.4 Enquiry Peer ──

    #[test]
    fn enquiry_peer_accept() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        let accepted = mesh.enquiry_request(node_id(1), make_address(1), 100);
        assert!(accepted, "first enquiry should be accepted");
        assert!(mesh.has_enquiry_peer());
    }

    #[test]
    fn enquiry_peer_slot_full() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        mesh.enquiry_request(node_id(1), make_address(1), 100);
        let rejected = mesh.enquiry_request(node_id(2), make_address(2), 101);
        assert!(!rejected, "second enquiry should be rejected (slot full)");
    }

    #[test]
    fn enquiry_peer_anti_camping() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        // Node 1 connects and disconnects
        mesh.enquiry_request(node_id(1), make_address(1), 100);
        mesh.enquiry_disconnect();
        assert!(!mesh.has_enquiry_peer());

        // Node 1 tries again immediately → REJECTED (anti-camping)
        let rejected = mesh.enquiry_request(node_id(1), make_address(1), 101);
        assert!(!rejected, "same node should be rejected (anti-camping)");

        // Different node can use the slot
        let accepted = mesh.enquiry_request(node_id(2), make_address(2), 102);
        assert!(accepted, "different node should be accepted");

        // Node 2 disconnects → node 1 can try again (different node used slot in between)
        mesh.enquiry_disconnect();
        let accepted = mesh.enquiry_request(node_id(1), make_address(1), 103);
        assert!(accepted, "node 1 should be accepted after different node used slot");
    }

    #[test]
    fn enquiry_peer_ttl_expiry() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        mesh.enquiry_request(node_id(1), make_address(1), 100);
        assert!(mesh.has_enquiry_peer());

        // At tick 111 (11 ticks later), still alive
        mesh.periodic_peer_check(111);
        assert!(mesh.has_enquiry_peer(), "E-peer should survive before TTL");

        // At tick 112 (12 ticks = E_PEER_TTL), expired
        mesh.periodic_peer_check(112);
        assert!(!mesh.has_enquiry_peer(), "E-peer should expire at TTL");
    }

    #[test]
    fn enquiry_peer_excluded_from_full_gossip() {
        // E-peers are temporary observers (TTL 12 ticks). They get
        // *discovery hints* via discovery_hint_targets(), not the full
        // gossip firehose via forward_targets().
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        mesh.peers.push(make_peer(1, 10));
        mesh.enquiry_request(node_id(2), make_address(2), 10);

        let targets = mesh.forward_targets(&node_id(99));
        assert!(targets.contains(&node_id(1)), "regular peer should be in full-gossip targets");
        assert!(!targets.contains(&node_id(2)), "E-peer should NOT be in full-gossip targets");

        let hint_targets = mesh.discovery_hint_targets(&node_id(99));
        assert!(hint_targets.contains(&node_id(2)), "E-peer should receive discovery hints");
    }

    #[test]
    fn enquiry_peer_not_counted_in_degree() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        // Add 7 peers (below regular_peer_target=8)
        for i in 1..=7u8 {
            mesh.peers.push(make_peer(i, 100));
        }
        mesh.enquiry_request(node_id(20), make_address(20), 100);

        // peer_count should be 7, not 8 (E-peer doesn't count)
        assert_eq!(mesh.peer_count(), 7);
        // Should still want to add a peer (below regular target)
        assert!(mesh.peer_count() < mesh.regular_peer_target());
    }

    // ── §6.6 Human Bridge PX ──

    #[test]
    fn human_bridge_px_learns_new_nodes() {
        let mut mesh_a = GossipMesh::new(node_id(0), make_address(0));
        // A knows nodes 1-5
        for i in 1..=5u8 {
            mesh_a.add_discovered_peer(make_peer(i, 100));
        }
        assert_eq!(mesh_a.known_node_count(), 5);

        // Remote side knows nodes 6-10
        let remote_known: Vec<PeerInfo> = (6..=10u8)
            .map(|i| make_peer(i, 100))
            .collect();

        let (recv, new, upd) = mesh_a.human_bridge_px(&remote_known, 200);
        assert_eq!(recv, 5, "should receive 5 entries");
        assert_eq!(new, 5, "should learn 5 new nodes from remote");
        assert_eq!(upd, 0, "nothing to update");
        assert_eq!(mesh_a.known_node_count(), 10, "total known should be 10");
    }

    #[test]
    fn human_bridge_px_skips_self() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        let remote = vec![make_peer(0, 100), make_peer(1, 100)]; // includes our own ID
        let (recv, new, _upd) = mesh.human_bridge_px(&remote, 200);
        assert_eq!(recv, 1, "should skip own node_id, receive 1");
        assert_eq!(new, 1, "1 new node");
        assert_eq!(mesh.known_node_count(), 1);
    }

    #[test]
    fn human_bridge_px_deduplicates() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        mesh.add_discovered_peer(make_peer(1, 50));

        let remote = vec![make_peer(1, 100), make_peer(2, 100)];
        let (recv, new, upd) = mesh.human_bridge_px(&remote, 200);
        assert_eq!(recv, 2, "received 2 entries");
        assert_eq!(new, 1, "node 2 is new");
        assert_eq!(upd, 1, "node 1 already known, updated");
        assert_eq!(mesh.known_node_count(), 2);
    }

    #[test]
    fn human_bridge_snapshot_roundtrip() {
        let mut mesh_a = GossipMesh::new(node_id(0), make_address(0));
        let mut mesh_b = GossipMesh::new(node_id(10), make_address(10));

        // A knows 1-5, B knows 6-9
        for i in 1..=5u8 { mesh_a.add_discovered_peer(make_peer(i, 100)); }
        for i in 6..=9u8 { mesh_b.add_discovered_peer(make_peer(i, 100)); }

        // Exchange snapshots (bidirectional, like §6.6)
        let snap_a = mesh_a.known_nodes_snapshot();
        let snap_b = mesh_b.known_nodes_snapshot();

        let (_, a_new, _) = mesh_a.human_bridge_px(&snap_b, 200);
        let (_, b_new, _) = mesh_b.human_bridge_px(&snap_a, 200);

        assert_eq!(a_new, 4, "A should learn 4 nodes from B");
        assert_eq!(b_new, 5, "B should learn 5 nodes from A");
        assert_eq!(mesh_a.known_node_count(), 9); // 1-9, not self(0)
        assert_eq!(mesh_b.known_node_count(), 9); // 1-9, not self(10)
    }

    // ── Known Nodes Cap (KNOWN_NODES_MAX=256) ──

    #[test]
    fn known_nodes_capped_at_max() {
        use crate::constants::KNOWN_NODES_MAX;
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));

        // Fill to capacity
        for i in 1..=(KNOWN_NODES_MAX as u16) {
            let mut id = [0u8; 32];
            id[0] = (i >> 8) as u8;
            id[1] = (i & 0xFF) as u8;
            mesh.add_discovered_peer(PeerInfo {
                node_id: id,
                address: NablaAddress::V4 { ip: [10, 0, id[0], id[1]], port: 7001 },
                last_seen: i as u64,
                tardis_up: None,
                has_d_open: false, open_slots: 0,
                messages_delivered: 0,
                connected_since: i as u64,
            txid_service: String::new(),
            });
        }
        assert_eq!(mesh.known_node_count(), KNOWN_NODES_MAX);

        // Add one more — should evict oldest (last_seen=1)
        let new_peer = PeerInfo {
            node_id: [99; 32],
            address: NablaAddress::V4 { ip: [10, 0, 99, 99], port: 7001 },
            last_seen: 999,
            tardis_up: None,
            has_d_open: false, open_slots: 0,
            messages_delivered: 0,
            connected_since: 999,
            txid_service: String::new(),
        };
        mesh.add_discovered_peer(new_peer);

        assert_eq!(mesh.known_node_count(), KNOWN_NODES_MAX, "should not exceed cap");
        // The oldest entry (last_seen=1) should have been evicted
        let oldest_id = {
            let mut id = [0u8; 32];
            id[0] = 0;
            id[1] = 1;
            id
        };
        assert!(
            !mesh.known_nodes.contains_key(&oldest_id),
            "oldest entry should have been evicted"
        );
        // New entry should be present
        assert!(
            mesh.known_nodes.contains_key(&[99; 32]),
            "new entry should be present"
        );
    }

    // ── YPX-009: Silicon Pulse Pipeline Tests ──

    #[test]
    fn pulse_record_delivery() {
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        let vpk = node_id(1);

        mesh.record_pulse_delivery(&vpk, 1);
        let ps = mesh.pulse_state_for(&vpk).unwrap();
        assert_eq!(ps.last_pulse_epoch, 1);
        assert_eq!(ps.total_pulses, 1);
        assert_eq!(ps.consecutive_misses, 0);

        mesh.record_pulse_delivery(&vpk, 2);
        let ps = mesh.pulse_state_for(&vpk).unwrap();
        assert_eq!(ps.last_pulse_epoch, 2);
        assert_eq!(ps.total_pulses, 2);
    }

    #[test]
    fn pulse_epoch_miss_tracking() {
        use axiom_core_logic::types::PULSE_GRACE_CYCLES;
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        let vpk = node_id(1);

        // Record pulse at epoch 1
        mesh.record_pulse_delivery(&vpk, 1);

        // First PULSE_GRACE_CYCLES epochs are grace — no misses counted
        let grace = PULSE_GRACE_CYCLES as u64;
        for epoch in 2..=(1 + grace) {
            mesh.evaluate_pulse_epoch(epoch);
        }
        assert_eq!(mesh.pulse_state_for(&vpk).unwrap().consecutive_misses, 0,
            "should have 0 misses during grace period");

        // Now 3 more epochs without delivery → 3 consecutive misses
        for epoch in (2 + grace)..=(4 + grace) {
            let evicted = mesh.evaluate_pulse_epoch(epoch);
            assert!(evicted.is_empty(), "should not evict at {} misses", epoch - 1 - grace);
        }
        let ps = mesh.pulse_state_for(&vpk).unwrap();
        assert_eq!(ps.consecutive_misses, 3, "should have 3 consecutive misses after grace");
        println!("  ✓ Grace period ({} epochs) + 3 consecutive misses tracked correctly", grace);
    }

    #[test]
    fn pulse_epoch_eviction_at_threshold() {
        use axiom_core_logic::types::{PULSE_MISS_EVICTION, PULSE_GRACE_CYCLES};
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        let vpk = node_id(1);

        // Record initial pulse to create state
        mesh.record_pulse_delivery(&vpk, 1);

        // Must exhaust grace period + miss enough to trigger eviction
        let total_needed = PULSE_GRACE_CYCLES as u64 + PULSE_MISS_EVICTION as u64 + 5;
        let mut evicted = vec![];
        for epoch in 2..=(1 + total_needed) {
            evicted = mesh.evaluate_pulse_epoch(epoch);
            if !evicted.is_empty() { break; }
        }
        assert!(!evicted.is_empty(), "should evict after grace + {} misses", PULSE_MISS_EVICTION);
        assert_eq!(evicted[0], vpk);
        assert!(mesh.pulse_state_for(&vpk).is_none(), "evicted peer pulse state should be cleared");
        println!("  ✓ Eviction at {} consecutive misses (after {} grace epochs)", PULSE_MISS_EVICTION, PULSE_GRACE_CYCLES);
    }

    #[test]
    fn pulse_delivery_resets_misses() {
        use axiom_core_logic::types::PULSE_GRACE_CYCLES;
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        let vpk = node_id(1);
        let grace = PULSE_GRACE_CYCLES as u64;

        // Record pulse, exhaust grace, then miss 5 more epochs
        mesh.record_pulse_delivery(&vpk, 1);
        // Exhaust grace
        for epoch in 2..=(1 + grace) {
            mesh.evaluate_pulse_epoch(epoch);
        }
        // 5 real misses after grace
        for epoch in (2 + grace)..=(6 + grace) {
            mesh.evaluate_pulse_epoch(epoch);
        }
        assert_eq!(mesh.pulse_state_for(&vpk).unwrap().consecutive_misses, 5);

        // Deliver pulse → resets consecutive_misses
        mesh.record_pulse_delivery(&vpk, 7 + grace);
        assert_eq!(mesh.pulse_state_for(&vpk).unwrap().consecutive_misses, 0);
        assert_eq!(mesh.pulse_state_for(&vpk).unwrap().total_pulses, 2);
        println!("  ✓ Delivery resets consecutive miss counter (after {} grace epochs)", grace);
    }

    #[test]
    fn pulse_score_bonus_and_penalty() {
        use axiom_core_logic::types::PULSE_GRACE_CYCLES;
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        let grace = PULSE_GRACE_CYCLES as u64;

        let mut good_peer = make_peer(1, 100);
        good_peer.messages_delivered = 10;
        let mut bad_peer = make_peer(2, 100);
        bad_peer.messages_delivered = 10;

        // Good peer: delivers every epoch (many pulses, 0 misses)
        let total_epochs = grace + 10;
        for epoch in 1..=total_epochs {
            mesh.record_pulse_delivery(&node_id(1), epoch);
        }

        // Bad peer: delivers once at epoch 1, then goes silent through grace + real misses
        mesh.record_pulse_delivery(&node_id(2), 1);
        for epoch in 2..=total_epochs {
            mesh.evaluate_pulse_epoch(epoch);
        }

        let good_score = mesh.peer_score(&good_peer, 100);
        let bad_score = mesh.peer_score(&bad_peer, 100);
        let bad_misses = mesh.pulse_state_for(&node_id(2))
            .map(|ps| ps.consecutive_misses).unwrap_or(0);

        println!("  Pulse scoring (grace={} epochs):", grace);
        println!("    Good peer ({} pulses, 0 misses): score = {:.1}", total_epochs, good_score);
        println!("    Bad peer  (1 pulse,  {} misses): score = {:.1}", bad_misses, bad_score);
        assert!(good_score > bad_score,
            "good pulse peer ({:.1}) must outscore bad pulse peer ({:.1})", good_score, bad_score);
        println!("  ✓ Pulse liveness properly integrated into W3 scoring");
    }

    #[test]
    fn pulse_multi_validator_epoch_lifecycle() {
        use axiom_core_logic::types::{PULSE_MISS_TOLERANCE, PULSE_MISS_EVICTION, PULSE_GRACE_CYCLES};
        let mut mesh = GossipMesh::new(node_id(0), make_address(0));
        let n_validators = 5u8;
        let grace = PULSE_GRACE_CYCLES as u64;

        println!("\n  ╔══════════════════════════════════════════════════════════╗");
        println!("  ║  YPX-009 Silicon Pulse — Multi-Validator Lifecycle       ║");
        println!("  ╠══════════════════════════════════════════════════════════╣");

        // All validators deliver pulse at epoch 1
        for v in 1..=n_validators {
            mesh.record_pulse_delivery(&node_id(v), 1);
        }
        println!("  ║ Epoch 1: {} validators delivered pulse                   ║", n_validators);

        // Epochs 2..=(1+grace): V1-3 deliver, V4-5 silent (grace period)
        for epoch in 2..=(1 + grace) {
            for v in 1..=3 {
                mesh.record_pulse_delivery(&node_id(v), epoch);
            }
            mesh.evaluate_pulse_epoch(epoch);
        }
        println!("  ║ Epochs 2-{}: Grace period ({} epochs), V4-5 silent      ║",
            1 + grace, grace);

        // After grace: V4-5 start accumulating misses
        let post_grace_start = 2 + grace;
        for epoch in post_grace_start..=(post_grace_start + 2) {
            for v in 1..=3 {
                mesh.record_pulse_delivery(&node_id(v), epoch);
            }
            let evicted = mesh.evaluate_pulse_epoch(epoch);
            let silent_misses = mesh.pulse_state_for(&node_id(4))
                .map(|ps| ps.consecutive_misses).unwrap_or(0);
            println!("  ║ Epoch {}: V1-3 ok, V4-5 miss ({} consecutive), evicted: {} ║",
                epoch, silent_misses, evicted.len());
        }

        let ps4 = mesh.pulse_state_for(&node_id(4)).unwrap();
        assert!(ps4.consecutive_misses >= PULSE_MISS_TOLERANCE,
            "V4 misses ({}) should meet tolerance threshold ({})", ps4.consecutive_misses, PULSE_MISS_TOLERANCE);

        // Continue until eviction
        let mut eviction_epoch = 0u64;
        for epoch in (post_grace_start + 3)..=(post_grace_start + PULSE_MISS_EVICTION as u64 + 5) {
            for v in 1..=3 {
                mesh.record_pulse_delivery(&node_id(v), epoch);
            }
            let evicted = mesh.evaluate_pulse_epoch(epoch);
            if !evicted.is_empty() {
                eviction_epoch = epoch;
                println!("  ║ Epoch {}: V4/V5 EVICTED ({} >= {} threshold)          ║",
                    epoch, PULSE_MISS_EVICTION, PULSE_MISS_EVICTION);
                break;
            }
        }
        assert!(eviction_epoch > 0, "validators 4 & 5 should eventually be evicted");

        // Healthy validators still have clean records
        for v in 1u8..=3 {
            let ps = mesh.pulse_state_for(&node_id(v)).unwrap();
            assert_eq!(ps.consecutive_misses, 0);
            assert!(ps.total_pulses >= 4);
        }

        println!("  ║                                                          ║");
        println!("  ║ Summary:                                                 ║");
        println!("  ║   Grace period:       {} epochs                           ║", grace);
        println!("  ║   Miss tolerance:     {} (degraded scoring)               ║", PULSE_MISS_TOLERANCE);
        println!("  ║   Eviction threshold: {} consecutive misses            ║", PULSE_MISS_EVICTION);
        println!("  ║   Healthy validators: 3 (0 misses each)                  ║");
        println!("  ║   Evicted validators: 2 (at epoch {})                  ║", eviction_epoch);
        println!("  ╚══════════════════════════════════════════════════════════╝\n");
    }
}
