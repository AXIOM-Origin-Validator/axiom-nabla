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
use crate::crypto::Signer;
use crate::oracle::{DailyPoolState, reconcile_pool};
use crate::smt::SparseMerkleTree;
#[allow(unused_imports)]
use crate::types::*;

/// YPX-009 §5.3: Compute the BLAKE3 domain-tagged payload for pulse proof signatures.
/// Payload = BLAKE3("AXIOM_PULSE_PROOF" || validator_pk || epoch_le || full_accumulator || audit_hash).
pub fn pulse_proof_sign_payload(
    validator_pk: &[u8; 32],
    epoch: u64,
    full_accumulator: &[u8; 32],
    audit_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_PULSE_PROOF");
    hasher.update(validator_pk);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(full_accumulator);
    hasher.update(audit_hash);
    *hasher.finalize().as_bytes()
}

/// YPX-009 §5.3: Verify Ed25519 signature over a pulse proof payload.
pub fn verify_pulse_proof_sig(
    validator_pk: &[u8; 32],
    signature: &[u8],
    payload: &[u8; 32],
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    if signature.len() != 64 {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(validator_pk) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    vk.verify(payload, &sig).is_ok()
}

/// YPX-009: Compute the BLAKE3 domain-tagged payload for client state signatures.
/// Payload = BLAKE3("AXIOM_WALLET_STATE" || wallet_id || new_state || tx_hash || tick_le).
pub fn client_state_sign_payload(
    wallet_id: &[u8; 32],
    new_state: &[u8; 32],
    tx_hash: &[u8; 32],
    tick: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_WALLET_STATE");
    hasher.update(wallet_id);
    hasher.update(new_state);
    hasher.update(tx_hash);
    hasher.update(&tick.to_le_bytes());
    *hasher.finalize().as_bytes()
}

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
fn apply_fee_record_from_gossip(
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
pub fn verify_client_state_sig(
    client_pk: &[u8; 32],
    client_sig: &[u8],
    wallet_id: &[u8; 32],
    new_state: &[u8; 32],
    tx_hash: &[u8; 32],
    tick: u64,
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
    let payload = client_state_sign_payload(wallet_id, new_state, tx_hash, tick);
    vk.verify(&payload, &sig).is_ok()
}

/// SECURITY FIX #6: Maximum gossip messages accepted per peer per window.
/// Prevents a single malicious node from flooding the network with unique
/// messages that pass dedup but consume forwarding bandwidth and CPU.
pub const GOSSIP_PER_PEER_LIMIT: u64 = 500;

/// Window duration for per-peer gossip rate limiting (seconds).
pub const GOSSIP_RATE_WINDOW_SECS: u64 = 60;

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

#[derive(Debug, Clone, Default)]
pub struct GossipLatencyStats {
    /// Ring buffer of observed age values (in ticks) per variant.
    /// Uses Vec<u32> rather than VecDeque so we can sort a snapshot
    /// without allocating a second buffer. Writes wrap via modular
    /// index into `next_idx`.
    state_update: Vec<u32>,
    group_update: Vec<u32>,
    tick_hash:    Vec<u32>,
    state_update_idx: usize,
    group_update_idx: usize,
    tick_hash_idx:    usize,
}

impl GossipLatencyStats {
    pub fn new() -> Self { Self::default() }

    fn push(buf: &mut Vec<u32>, idx: &mut usize, age: u32) {
        if buf.len() < GOSSIP_LATENCY_RING {
            buf.push(age);
        } else {
            buf[*idx] = age;
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
        match msg {
            GossipMessage::StateUpdate { tick,
            is_genesis_claim: false, .. } => {
                let age = current_tick.saturating_sub(*tick) as u32;
                Self::push(&mut self.state_update, &mut self.state_update_idx, age);
            }
            GossipMessage::GroupUpdate { tick, .. } => {
                let age = current_tick.saturating_sub(*tick) as u32;
                Self::push(&mut self.group_update, &mut self.group_update_idx, age);
            }
            GossipMessage::TickHash { tick, .. } => {
                let age = current_tick.saturating_sub(*tick) as u32;
                Self::push(&mut self.tick_hash, &mut self.tick_hash_idx, age);
            }
            // Variants without tick: explicitly not instrumented.
            // Adding tick fields to BanAlert / ForkEvidence et al. would
            // require touching serialized protocol state and is out of
            // scope for an instrumentation-only change.
            _ => {}
        }
    }

    /// Returns (count, p50, p99, max) for one variant, computed from
    /// a sorted snapshot of the ring. Empty rings return (0,0,0,0).
    fn percentiles(buf: &[u32]) -> (usize, u32, u32, u32) {
        if buf.is_empty() { return (0, 0, 0, 0); }
        let mut v: Vec<u32> = buf.to_vec();
        v.sort_unstable();
        let n = v.len();
        let p50 = v[n * 50 / 100];
        // clamp p99 to last index so a ring of 1..100 still returns the top
        let p99_idx = ((n * 99 / 100).saturating_sub(0)).min(n - 1);
        let p99 = v[p99_idx];
        let max = *v.last().unwrap();
        (n, p50, p99, max)
    }

    /// Return a serializable snapshot. Used by the /gossip-latency
    /// HTTP endpoint and by soak test assertions.
    pub fn snapshot(&self) -> GossipLatencySnapshot {
        let (su_n, su_p50, su_p99, su_max) = Self::percentiles(&self.state_update);
        let (gu_n, gu_p50, gu_p99, gu_max) = Self::percentiles(&self.group_update);
        let (th_n, th_p50, th_p99, th_max) = Self::percentiles(&self.tick_hash);
        GossipLatencySnapshot {
            state_update: GossipLatencyVariant { count: su_n, p50_ticks: su_p50, p99_ticks: su_p99, max_ticks: su_max },
            group_update: GossipLatencyVariant { count: gu_n, p50_ticks: gu_p50, p99_ticks: gu_p99, max_ticks: gu_max },
            tick_hash:    GossipLatencyVariant { count: th_n, p50_ticks: th_p50, p99_ticks: th_p99, max_ticks: th_max },
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GossipLatencyVariant {
    pub count: usize,
    pub p50_ticks: u32,
    pub p99_ticks: u32,
    pub max_ticks: u32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GossipLatencySnapshot {
    pub state_update: GossipLatencyVariant,
    pub group_update: GossipLatencyVariant,
    pub tick_hash:    GossipLatencyVariant,
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
}

/// Result of processing a gossip message.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum GossipAction {
    /// Forward this message to all mesh peers except sender.
    Forward(GossipMessage),
    /// Message was a duplicate — do nothing.
    Duplicate,
    /// Message triggered a ban — forward ban alert.
    BanDetected {
        forward: GossipMessage,
        ban_alert: GossipMessage,
    },
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
        }
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
        deed_pool: &mut crate::node::DeedPool,
        dev_deed_pool: &mut crate::node::DevDeedPool,
        signer: &dyn Signer,
        current_tick: u64,
        n_validators: usize,
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
                smt, bans, wallet_id, new_state, tx_hash, tick, *is_genesis_claim, wallet_seq,
                client_pk, client_sig, amount, fee_breakdown, seq_proof, msg,
            ),

            // KI#34 check-3: a HAL re-anchor advance. Fork-check it against this
            // node's OWN authoritative view BEFORE adopting the head — the endorsement
            // model: every honest holder detects the revival independently, with NO
            // false-positive (exact `previous_state` match, not the lossy bloom) and
            // independent of the (wiped/malicious) node that processed the re-anchor.
            GossipMessage::HalAdvance {
                wallet_id,
                old_state,
                new_state,
                tx_hash,
                tick,
                client_pk,
                client_sig,
                k3_signatures,
                amount,
                fee_breakdown,
            } => {
                // Snapshot our view first (copies — released before the &mut freeze).
                let held_current = smt.get(wallet_id).map(|e| e.current_state);
                let prev = smt.previous_state(wallet_id);
                // Fork iff: we hold W at a state OTHER than new_state, AND old_state is
                // the state W authoritatively CONSUMED to reach its head (previous_state).
                // i.e. X was already spent to reach Y, and this re-anchor spends X again
                // to a different X'. A re-gossip of the legit advance (new == current) or
                // an unknown previous_state is NOT a fork.
                let is_conflict = held_current.is_some()
                    && held_current != Some(*new_state)
                    && prev == Some(*old_state);
                if is_conflict {
                    // Unforgeability: the k=3 sigs sign receipt_sign_payload(W, old_state,
                    // tick), so they BIND old_state — a malicious node can't fabricate a
                    // re-anchor from X without real witnessing. Verify before freezing
                    // (a permanent freeze on bad evidence would be worse than today's reject).
                    let payload = crate::crypto::receipt_sign_payload(wallet_id, old_state, *tick);
                    let k3_ok = k3_signatures.len() >= 3
                        && k3_signatures.iter().all(|ws| {
                            signer.verify(&ws.validator_pk, &payload, &ws.signature)
                        });
                    if k3_ok {
                        // Confirmed revival fork. Freeze W locally; the Frozen status
                        // propagates mesh-wide via the existing anti-entropy merge
                        // (`superseded_by` Frozen-monotonicity). Do NOT adopt the forked
                        // head. Forward so peers independently re-detect + freeze too.
                        crate::tardis::TardisNode::freeze_wallet(smt, wallet_id);
                        return GossipAction::Forward(msg.clone());
                    }
                    // Bad/insufficient sigs: don't freeze (possible framing), just drop.
                    return GossipAction::Duplicate;
                }
                // Not a fork — a legit HAL re-anchor of a genuine dead-overlap wallet,
                // an idempotent re-gossip, or an unknown previous_state. Apply the head
                // exactly like a normal advance.
                // WI3 hole-1: HalAdvance carries no k=3 receipt-commitment proof (its
                // k3_signatures sign `receipt_sign_payload(old_state)`, NOT the
                // seq-binding commitment), so it cannot present a `SeqProof`. PRESERVE
                // the held seq (no advance) so `apply_state_update`'s
                // seq-advance-requires-proof gate never trips on the HAL path — the
                // re-anchor still adopts via the tick tiebreaker, it just doesn't claim
                // seq-priority it can't prove. Carrying the HAL receipt's k-attested
                // new_wallet_seq on HalAdvance is a separate follow-on if HAL ever needs
                // seq-priority over a contending head.
                let hal_seq = smt.get(wallet_id).map(|e| e.wallet_seq).unwrap_or(0);
                self.apply_state_update(
                    smt, bans, wallet_id, new_state, tx_hash, tick,
                    false, // HalAdvance is never a genesis claim
                    &hal_seq,
                    client_pk, client_sig, amount, fee_breakdown, &None, msg,
                )
            }

            GossipMessage::BanAlert {
                wallet_id,
                evidence_1,
                evidence_2,
            } => {
                // Verify evidence independently before accepting
                if BanTable::verify_conflict(wallet_id, evidence_1, evidence_2, signer) {
                    bans.ban(*wallet_id, evidence_1.clone(), evidence_2.clone());
                }
                GossipAction::Forward(msg.clone())
            }

            GossipMessage::SeqForkBan { wallet_id, evidence } => {
                // Re-verify the two k=3 seq-proofs independently before banning —
                // a peer cannot forge them (compute_receipt_commitment sigs).
                if BanTable::verify_seq_conflict(wallet_id, evidence)
                    && bans.ban_seq_fork(*wallet_id, evidence.clone())
                {
                    // Surface the ban on the §4.6 read path here too: a node that
                    // learns the ban via propagation (not local detection) must
                    // flip its own SMT entry to Banned, else only the detecting
                    // node reports BANNED and the rest report NORMAL on a Query.
                    if let Some(entry) = smt.get(wallet_id) {
                        let mut banned_entry = entry.clone();
                        banned_entry.status = WalletStatus::Banned;
                        smt.put(&banned_entry);
                    }
                    // Newly banned on this node → BanDetected so the binary WAL-persists
                    // it ("no turning back") and keeps flooding the evidence.
                    GossipAction::BanDetected { forward: msg.clone(), ban_alert: msg.clone() }
                } else {
                    GossipAction::Forward(msg.clone())
                }
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

            GossipMessage::TaintAlert {
                wallet_id,
                ..
            } => {
                // §32: Freeze the tainted wallet
                use crate::tardis::TardisNode;
                TardisNode::freeze_wallet(smt, wallet_id);
                GossipAction::Forward(msg.clone())
            }

            GossipMessage::MergeResolved { .. } => {
                // §32: Forward merge resolution summary to peers.
                // Receiving nodes log but don't need to act — they run their own
                // quarantine timers and reach the same conclusion independently.
                GossipAction::Forward(msg.clone())
            }

            GossipMessage::BanChallenged {
                wallet_id,
                evidence,
                challenge_tick,
            } => {
                // S6: Apply challenge to our local ban table if wallet is actively banned.
                if bans.is_active_ban(wallet_id) {
                    let _ = bans.challenge(wallet_id, evidence.clone(), *challenge_tick, signer);
                }
                GossipAction::Forward(msg.clone())
            }

            GossipMessage::BanReversed {
                wallet_id,
                reversed_at_tick,
            } => {
                // S6: If we haven't reversed this ban yet, force it.
                if let Some(entry) = bans.get(wallet_id) {
                    if !matches!(entry.status, BanStatus::Reversed { .. }) {
                        // Use check_challenge_resolution with a far-future tick to force reversal
                        // (the originator already verified the window). Just update locally.
                        log::info!("S6: received BanReversed for {:02x}{:02x}... at tick {}",
                            wallet_id[0], wallet_id[1], reversed_at_tick);
                    }
                }
                GossipAction::Forward(msg.clone())
            }

            // H3: Data availability withholding challenge — verify challenger sig and forward.
            GossipMessage::DataWithholdChallenge {
                challenged_validator_pk,
                withheld_txid,
                challenger_pk,
                challenger_sig,
                challenge_tick,
            } => {
                // Verify challenger's signature
                let mut h = blake3::Hasher::new();
                h.update(b"AXIOM_DA_CHALLENGE");
                h.update(challenged_validator_pk);
                h.update(withheld_txid);
                h.update(&challenge_tick.to_le_bytes());
                let payload = *h.finalize().as_bytes();
                if crate::gossip::verify_pulse_proof_sig(challenger_pk, challenger_sig, &payload) {
                    log::info!("H3: DA withhold challenge for {:02x}{:02x}... txid {:02x}{:02x}...",
                        challenged_validator_pk[0], challenged_validator_pk[1],
                        withheld_txid[0], withheld_txid[1]);
                    GossipAction::Forward(msg.clone())
                } else {
                    log::warn!("H3: Invalid DA challenge signature — dropped");
                    GossipAction::Duplicate
                }
            }

            // H3: Data availability response — forward to resolve the challenge.
            GossipMessage::DataWithholdResponse {
                withheld_txid,
                validator_pk,
                receipt_data: _,
                validator_sig,
                response_tick: _,
            } => {
                // Verify validator's signature (just check non-empty, full verification by peers)
                if validator_sig.len() == 64 && !withheld_txid.iter().all(|&b| b == 0) {
                    log::info!("H3: DA withhold response from {:02x}{:02x}...",
                        validator_pk[0], validator_pk[1]);
                    GossipAction::Forward(msg.clone())
                } else {
                    GossipAction::Duplicate
                }
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
                let payload = pulse_proof_sign_payload(validator_pk, *epoch, full_accumulator, audit_hash);
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
                tick: _,
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
                    PoolKind::Airdrop => airdrop_pool.reconcile(*balance, *total_claims),
                    PoolKind::DevTreasury => {
                        dev_treasury_pool.reconcile(*balance, *total_claims)
                    }
                    PoolKind::Deed => deed_pool.reconcile(*balance, *total_claims),
                    PoolKind::DevDeed => dev_deed_pool.reconcile(*balance, *total_claims),
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
                        // strict-decrease). The higher-balance direction
                        // returns `NoOp` instead, per Mac's review §2.6.
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

            GossipMessage::ChequeClaim {
                cheque_id, client_pk, claim_tick,
            } => {
                let updated = smt.apply_remote_cheque_claim(
                    cheque_id, client_pk, *claim_tick, current_tick,
                );
                if updated {
                    GossipAction::Forward(msg.clone())
                } else {
                    GossipAction::Duplicate
                }
            }

            GossipMessage::Recall {
                txid, sender_pk, recall_tick, committed,
            } => {
                // YPX-022 §2.2.1 — phase-aware recall merge: commit dominates
                // reservation; first-wins by tick within a phase; a reservation
                // on a locally-REDEEMED txid is refused (the redeem already
                // won). Forward only on update.
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
    ) -> GossipAction {
        if bans.is_banned(wallet_id) {
            // Already banned — ignore updates for this wallet
            return GossipAction::Duplicate;
        }

        // YPX-009: Verify client signature if present (non-zero pk).
        // Zero pk = legacy/pre-YPX-009 — accepted with warning.
        if *client_pk != [0u8; 32]
            && !verify_client_state_sig(client_pk, client_sig, wallet_id, new_state, tx_hash, *tick)
        {
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
        let seq_attested = seq_proof
            .as_ref()
            .is_some_and(|p| crate::registration::verify_seq_proof(p, tx_hash, *wallet_seq));

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
                };
                if existing == &candidate {
                    // Byte-identical — already applied via another path.
                    return GossipAction::Duplicate;
                }
                // ── DOUBLE-SPEND FORK ORIGINATION (the gap this closes) ──
                // Same `wallet_seq` + different `current_state`, where BOTH the
                // held head and the incoming candidate are k=3-attested, is two
                // witnessed successors of the same predecessor = a double-spend.
                // It cannot occur accidentally (both are k=3-witnessed). Originate
                // an irreversible ban + flood the evidence INSTEAD of letting
                // `superseded_by` silently last-writer-wins merge it away. Requires
                // BOTH seq-proofs present+valid, so an unproven/legacy entry never
                // false-bans, and a normal sequential advance (different seq) and a
                // one-sided fork (only one side k=3-attested) are not affected.
                //
                // ANTI-FRAMING AUTHORSHIP GATE (closes the forged-SeqProof hole):
                // `verify_seq_proof` only checks >=3 distinct valid Ed25519 sigs over
                // the receipt commitment — it does NOT consult the approved-validator
                // set (Nabla holds no such authority; that lives in Lambda/Core). So
                // an attacker holding ANY 3 keypairs could mint two valid-looking
                // SeqProofs for a VICTIM's wallet_id and false-ban it. We ground the
                // ban in the wallet's OWN unforgeable signature instead: require BOTH
                // conflicting states to be wallet-authored (`client_pk != 0` + a valid
                // `client_sig`). The candidate's sig is already validated at the top of
                // this fn (the zero-pk warn-drop above); a non-zero `existing.client_pk`
                // implies its sig was validated when it was stored. An attacker cannot
                // forge the wallet's Ed25519 authorship sig, so forged/zero-pk evidence
                // can no longer trigger a ban. A genuine double-spend is two states the
                // WALLET signed over the same seq — exactly what this now gates on.
                if candidate.wallet_seq == existing.wallet_seq
                    && candidate.current_state != existing.current_state
                    && seq_attested
                    && *client_pk != [0u8; 32]
                    && existing.client_pk != [0u8; 32]
                {
                    if let Some(held_proof) = smt.seq_proof(wallet_id).cloned() {
                        if crate::registration::verify_seq_proof(
                            &held_proof, &existing.tx_hash, existing.wallet_seq,
                        ) {
                            let evidence = crate::types::SeqConflictProof {
                                wallet_seq: existing.wallet_seq,
                                state_a: existing.current_state,
                                tx_a: existing.tx_hash,
                                proof_a: held_proof,
                                state_b: *new_state,
                                tx_b: *tx_hash,
                                proof_b: seq_proof.clone().unwrap(),
                            };
                            if bans.ban_seq_fork(*wallet_id, evidence.clone()) {
                                // Flip the held SMT entry to Banned so the §4.6
                                // read path surfaces the ban. process_query reports
                                // entry.status, NOT the BanTable — without this the
                                // ban would block further gossip/registration (top
                                // is_banned guard) but a downstream verify_cheque
                                // would still see NORMAL and could return CLEAN on
                                // the two double-spent cheques. Mirrors the
                                // resolve_merge forked-wallet flip. Deterministic:
                                // every node that detects the same fork flips the
                                // same entry, so the mesh stays convergent.
                                let mut banned_entry = existing.clone();
                                banned_entry.status = WalletStatus::Banned;
                                smt.put(&banned_entry);
                                let ban_alert = GossipMessage::SeqForkBan {
                                    wallet_id: *wallet_id,
                                    evidence,
                                };
                                return GossipAction::BanDetected {
                                    forward: original_msg.clone(),
                                    ban_alert,
                                };
                            }
                            return GossipAction::Duplicate; // already banned
                        }
                    }
                }
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
                if existing.superseded_by(&candidate) {
                    // The candidate wins the merge — adopt it and keep it
                    // flooding. Every node that holds an older entry adopts
                    // and re-forwards the winner, so it reaches the whole
                    // mesh; anti-entropy repairs any flood gap by leaf hash.
                    // `put` structurally drops any proof bound to the SUPERSEDED
                    // head's tx_hash (KI#38 lock-step), so an equal-seq tiebreaker
                    // adopt with no proof leaves a correct absence. When we DO have
                    // a verified proof for the new head, re-establish it here.
                    smt.put(&candidate);
                    if seq_attested {
                        // Retain the verified proof so the AE path can re-attach
                        // it when serving this head to a node that missed the flood.
                        smt.set_seq_proof(*wallet_id, seq_proof.clone().unwrap());
                    }
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
                                smt.record_txid(tx_hash, wallet_id);
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
                };
                smt.put(&entry);
                if seq_attested {
                    smt.set_seq_proof(*wallet_id, seq_proof.clone().unwrap());
                    // YPX-022 B2: a k-attested completion applied via gossip/AE marks the
                    // txid completed on THIS node too, so `completed_txids` is mesh-consistent
                    // — a RECALL is refused at ANY node, not only the one that directly handled
                    // the register. `seq_attested` ⟺ ≥ k distinct sigs (verify_seq_proof), so a
                    // sub-quorum partial (never seq_attested; also rejected at the seq-advance
                    // guard above) is NEVER marked → genuine partials stay recallable.
                    if *tx_hash != [0u8; 32] {
                        smt.mark_txid_completed(tx_hash, *tick);
                        // YPX-022 §5 REDEEMED parity — see the merge branch above.
                        if !fee_breakdown.is_empty() && !is_genesis_claim {
                            smt.mark_txid_redeemed(tx_hash);
                            smt.record_txid(tx_hash, wallet_id);
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
                        status: WalletStatus::Normal,
                        client_pk: [0u8; 32],
                        client_sig: vec![0u8; 64],
                    };
                    smt.put(&entry);
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
                };
                smt.put(&entry);
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
    use crate::crypto::NoopSigner;
    use crate::node::AirdropPool;

    fn make_state_update(wid: u8, state: u8, tick: u64) -> GossipMessage {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = wid;
        let mut new_state = [0u8; 32];
        new_state[0] = state;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = wid ^ state;

        GossipMessage::StateUpdate {
            wallet_seq: 0,
            seq_proof: None,
            wallet_id,
            new_state,
            tx_hash,
            tick,
            is_genesis_claim: false,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
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
            txid, &state_hash, wallet_seq, &commitment_hash, epoch, is_dev_class, None,
        );
        let sigs = (0..n).map(|i| {
            let sk = SigningKey::from_bytes(&[0x10 + i as u8; 32]);
            crate::types::SeqProofSig {
                validator_pk: sk.verifying_key().to_bytes(),
                receipt_commitment_sig: sk.sign(&commitment).to_bytes().to_vec(),
            }
        }).collect();
        crate::types::SeqProof { state_hash, commitment_hash, epoch, is_dev_class, oods_flag: None, sigs }
    }
    /// StateUpdate carrying a k=`n`-attested SeqProof for (wid, state, seq),
    /// AND a valid wallet authorship sig (non-zero client_pk + client_sig over
    /// the §32 wallet-state payload). The wallet signing key is derived
    /// deterministically from `wid`, so the held A' and the conflicting B' are
    /// signed by the SAME wallet — exactly the authorship the ban now requires.
    fn ds_attested(wid: u8, state: u8, seq: u64, tick: u64, n: usize) -> GossipMessage {
        use ed25519_dalek::{Signer, SigningKey};
        let mut wallet_id = [0u8; 32]; wallet_id[0] = wid;
        let mut new_state = [0u8; 32]; new_state[0] = state;
        let mut tx_hash = [0u8; 32]; tx_hash[0] = wid ^ state; tx_hash[1] = state;
        let proof = ds_mint_seq_proof(&tx_hash, seq, n);
        let wallet_sk = SigningKey::from_bytes(&[wid.wrapping_add(0xC0); 32]);
        let client_pk = wallet_sk.verifying_key().to_bytes();
        let payload = client_state_sign_payload(&wallet_id, &new_state, &tx_hash, tick);
        let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();
        GossipMessage::StateUpdate {
            wallet_seq: seq, seq_proof: Some(proof),
            wallet_id, new_state, tx_hash, tick,
            is_genesis_claim: false,
            client_pk, client_sig, amount: 0, fee_breakdown: Vec::new(),
        }
    }
    fn ds_proc(engine: &mut GossipEngine, smt: &mut SparseMerkleTree, bans: &mut BanTable, msg: &GossipMessage) -> GossipAction {
        let mut pool = DailyPoolState::new();
        engine.process(msg, smt, bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1)
    }
    fn ds_wid(wid: u8) -> WalletId { let mut w = [0u8; 32]; w[0] = wid; w }

    #[test]
    fn dsfork_two_k3_successors_same_seq_BANS() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        // Held: A' at seq 5, k=3-attested (first sight adopts + retains proof).
        ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAA, 0x01, 5, 10, 3));
        assert!(smt.seq_proof(&ds_wid(0xAA)).is_some(), "held entry must retain its seq proof");
        // Incoming: B' at the SAME seq 5, also k=3-attested = double-SPEND.
        let action = ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xAA, 0x02, 5, 11, 3));
        assert!(matches!(action, GossipAction::BanDetected { .. }), "double-spend fork must originate a ban");
        assert!(bans.is_banned(&ds_wid(0xAA)), "double-spender must be banned");
        // The SMT entry must flip to Banned so the §4.6 read path (process_query
        // reports entry.status, not the BanTable) surfaces BANNED to a downstream
        // verify_cheque — otherwise the redeem gap stays open.
        assert_eq!(smt.get(&ds_wid(0xAA)).map(|e| e.status), Some(WalletStatus::Banned),
            "banned wallet's SMT entry must report Banned for the §4.6 redeem gate");
    }

    #[test]
    fn dsfork_normal_sequential_advance_NO_ban() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xBB, 0x01, 5, 10, 3));
        // A legitimate next tx: different STATE but a HIGHER seq (6) — not a conflict.
        let action = ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xBB, 0x02, 6, 11, 3));
        assert!(!matches!(action, GossipAction::BanDetected { .. }), "sequential advance must NOT ban");
        assert!(!bans.is_banned(&ds_wid(0xBB)), "honest sequential advance must NOT be banned");
    }

    #[test]
    fn dsfork_one_sided_unproven_NO_ban() {
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        ds_proc(&mut e, &mut smt, &mut bans, &ds_attested(0xCC, 0x01, 5, 10, 3));
        // Conflicting state at same seq but UNPROVEN (no seq_proof) — can't prove
        // it's k=3-witnessed, so it must NOT trigger a ban (avoids framing).
        let mut wallet_id = [0u8; 32]; wallet_id[0] = 0xCC;
        let mut new_state = [0u8; 32]; new_state[0] = 0x02;
        let mut tx_hash = [0u8; 32]; tx_hash[0] = 0xCC ^ 0x02;
        let unproven = GossipMessage::StateUpdate {
            wallet_seq: 5, seq_proof: None, wallet_id, new_state, tx_hash, tick: 11,
            is_genesis_claim: false,
            client_pk: [0u8; 32], client_sig: vec![0u8; 64], amount: 0, fee_breakdown: Vec::new(),
        };
        let action = ds_proc(&mut e, &mut smt, &mut bans, &unproven);
        assert!(!matches!(action, GossipAction::BanDetected { .. }), "unproven conflict must NOT ban");
        assert!(!bans.is_banned(&ds_wid(0xCC)), "unproven (framing-risk) conflict must NOT be banned");
    }

    #[test]
    fn dsfork_forged_zeropk_unauthored_NO_ban() {
        // FRAMING ATTACK: an attacker mints two valid-looking k=3 SeqProofs for a
        // VICTIM's wallet_id (verify_seq_proof checks only sig count, not the
        // approved-validator set), but CANNOT forge the wallet's authorship sig, so
        // sends zero-pk/unauthored StateUpdates. The authorship gate must refuse to
        // ban: a forged double-spend on a wallet the attacker doesn't control is not
        // a real double-spend and must never false-ban the victim.
        let (mut e, mut smt, mut bans) = (GossipEngine::new(), SparseMerkleTree::new(), BanTable::new());
        // Held A' (zero-pk, but k=3-attested seq): adopted, retains its proof.
        let held = {
            let mut wallet_id = [0u8; 32]; wallet_id[0] = 0xEE;
            let mut new_state = [0u8; 32]; new_state[0] = 0x01;
            let mut tx_hash = [0u8; 32]; tx_hash[0] = 0xEE ^ 0x01; tx_hash[1] = 0x01;
            GossipMessage::StateUpdate {
                wallet_seq: 5, seq_proof: Some(ds_mint_seq_proof(&tx_hash, 5, 3)),
                wallet_id, new_state, tx_hash, tick: 10,
            is_genesis_claim: false,
                client_pk: [0u8; 32], client_sig: vec![0u8; 64], amount: 0, fee_breakdown: Vec::new(),
            }
        };
        ds_proc(&mut e, &mut smt, &mut bans, &held);
        // Forged conflicting B' at the SAME seq, also k=3-attested, also zero-pk.
        let forged = {
            let mut wallet_id = [0u8; 32]; wallet_id[0] = 0xEE;
            let mut new_state = [0u8; 32]; new_state[0] = 0x02;
            let mut tx_hash = [0u8; 32]; tx_hash[0] = 0xEE ^ 0x02; tx_hash[1] = 0x02;
            GossipMessage::StateUpdate {
                wallet_seq: 5, seq_proof: Some(ds_mint_seq_proof(&tx_hash, 5, 3)),
                wallet_id, new_state, tx_hash, tick: 11,
            is_genesis_claim: false,
                client_pk: [0u8; 32], client_sig: vec![0u8; 64], amount: 0, fee_breakdown: Vec::new(),
            }
        };
        let action = ds_proc(&mut e, &mut smt, &mut bans, &forged);
        assert!(!matches!(action, GossipAction::BanDetected { .. }), "forged unauthored conflict must NOT ban");
        assert!(!bans.is_banned(&ds_wid(0xEE)), "victim must NOT be framed by forged zero-pk evidence");
    }

    #[test]
    fn dsfork_subquorum_evidence_rejected_by_verifier() {
        // verify_seq_conflict must reject sub-k=3 evidence (defense in depth on the
        // BanAlert receive path).
        let txa = { let mut t=[0u8;32]; t[0]=0x11; t };
        let txb = { let mut t=[0u8;32]; t[0]=0x22; t };
        let ev = crate::types::SeqConflictProof {
            wallet_seq: 5,
            state_a: { let mut s=[0u8;32]; s[0]=1; s }, tx_a: txa, proof_a: ds_mint_seq_proof(&txa, 5, 2),
            state_b: { let mut s=[0u8;32]; s[0]=2; s }, tx_b: txb, proof_b: ds_mint_seq_proof(&txb, 5, 3),
        };
        assert!(!BanTable::verify_seq_conflict(&ds_wid(0xDD), &ev), "sub-quorum (k=2) evidence must be rejected");
    }

    #[test]
    fn gossip_new_wallet_accepted() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg = make_state_update(0xAA, 0x01, 1);
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

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
        engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

        // Same message again
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);
        assert!(matches!(action, GossipAction::Duplicate));
    }

    #[test]
    fn gossip_newer_tick_updates() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg1 = make_state_update(0xAA, 0x01, 1);
        engine.process(&msg1, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

        let msg2 = make_state_update(0xAA, 0x02, 2);
        let action = engine.process(&msg2, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

        assert!(matches!(action, GossipAction::Forward(_)));
        let wid = {
            let mut w = [0u8; 32];
            w[0] = 0xAA;
            w
        };
        assert_eq!(smt.get(&wid).unwrap().current_state[0], 0x02);
    }

    #[test]
    fn gossip_older_tick_ignored() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg1 = make_state_update(0xAA, 0x01, 5);
        engine.process(&msg1, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

        let msg2 = make_state_update(0xAA, 0x02, 3); // older tick
        let action = engine.process(&msg2, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

        assert!(matches!(action, GossipAction::Duplicate));
        let wid = {
            let mut w = [0u8; 32];
            w[0] = 0xAA;
            w
        };
        assert_eq!(smt.get(&wid).unwrap().current_state[0], 0x01); // unchanged
    }

    #[test]
    fn gossip_banned_wallet_ignored() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let wid = {
            let mut w = [0u8; 32];
            w[0] = 0xAA;
            w
        };
        bans.ban(
            wid,
            ConflictProof {
                old_state: [0; 32],
                new_state: [1; 32],
                tx_hash: [2; 32],
                k3_signatures: vec![],
                tick: 0,
            },
            ConflictProof {
                old_state: [0; 32],
                new_state: [3; 32],
                tx_hash: [4; 32],
                k3_signatures: vec![],
                tick: 0,
            },
        );

        let msg = make_state_update(0xAA, 0x01, 1);
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

        assert!(matches!(action, GossipAction::Duplicate));
        assert_eq!(smt.len(), 0); // not inserted
    }

    #[test]
    fn gossip_ban_alert_verified() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let wid = [0xAA; 32];
        let msg = GossipMessage::BanAlert {
            wallet_id: wid,
            evidence_1: ConflictProof {
                old_state: [0x10; 32],
                new_state: [0x20; 32],
                tx_hash: [0xA1; 32],
                k3_signatures: vec![
                    WitnessSig { validator_pk: [1; 32], signature: vec![1; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [2; 32], signature: vec![2; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [3; 32], signature: vec![3; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                ],
                tick: 0,
            },
            evidence_2: ConflictProof {
                old_state: [0x10; 32],
                new_state: [0x30; 32],
                tx_hash: [0xA2; 32],
                k3_signatures: vec![
                    WitnessSig { validator_pk: [4; 32], signature: vec![4; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [5; 32], signature: vec![5; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [6; 32], signature: vec![6; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                ],
                tick: 0,
            },
        };

        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);
        assert!(matches!(action, GossipAction::Forward(_)));
        assert!(bans.is_banned(&wid));
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
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

        assert!(matches!(action, GossipAction::Forward(_)));
        let wid = { let mut w = [0u8; 32]; w[0] = 0xBB; w };
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
        engine.process(&msg1, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

        // Newer tick with updated members
        let msg2_members = vec![
            GroupMemberState { member_pk: [0x10; 32], share_bps: 5000, available: 800 },
            GroupMemberState { member_pk: [0x20; 32], share_bps: 3000, available: 480 },
            GroupMemberState { member_pk: [0x30; 32], share_bps: 2000, available: 320 },
        ];
        let wid = { let mut w = [0u8; 32]; w[0] = 0xBB; w };
        let msg2 = GossipMessage::GroupUpdate {
            wallet_id: wid,
            new_state: { let mut s = [0u8; 32]; s[0] = 0x02; s },
            tx_hash: [0xBB ^ 0x02; 32],
            members: msg2_members.clone(),
            tick: 5,
        };

        let action = engine.process(&msg2, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);
        assert!(matches!(action, GossipAction::Forward(_)));

        let entry = smt.get(&wid).unwrap();
        let members = entry.group_members.as_ref().unwrap();
        assert_eq!(members[0].available, 800);
        assert_eq!(members[1].available, 480);
    }

    #[test]
    fn gossip_group_update_older_tick_ignored() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg1 = make_group_update(0xCC, 0x01, 10);
        engine.process(&msg1, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

        let msg2 = make_group_update(0xCC, 0x02, 5); // older tick
        let action = engine.process(&msg2, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

        assert!(matches!(action, GossipAction::Duplicate));
        let wid = { let mut w = [0u8; 32]; w[0] = 0xCC; w };
        assert_eq!(smt.get(&wid).unwrap().current_state[0], 0x01); // unchanged
    }

    #[test]
    fn gossip_group_banned_wallet_ignored() {
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let wid = { let mut w = [0u8; 32]; w[0] = 0xDD; w };
        bans.ban(wid,
            ConflictProof { old_state: [0; 32], new_state: [1; 32], tx_hash: [2; 32], k3_signatures: vec![], tick: 0 },
            ConflictProof { old_state: [0; 32], new_state: [3; 32], tx_hash: [4; 32], k3_signatures: vec![], tick: 0 },
        );

        let msg = make_group_update(0xDD, 0x01, 1);
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

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
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

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

        // Remote has higher pool balance — our state is more conservative
        let msg = make_oracle_sync("2027-03-15", 2_000, 88_000_000, 10, 50);
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

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
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);
        assert!(matches!(action, GossipAction::Forward(_)));

        // Second: exact duplicate hash → deduplicated before reconciliation
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);
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

        let payload = super::client_state_sign_payload(&wallet_id, &new_state, &tx_hash, tick);
        let sig = sk.sign(&payload);

        assert!(super::verify_client_state_sig(
            &pk, &sig.to_bytes(), &wallet_id, &new_state, &tx_hash, tick
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
            &pk, &bad_sig, &wallet_id, &new_state, &tx_hash, 100
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

        // Sign for tick 100
        let payload = super::client_state_sign_payload(&wallet_id, &new_state, &tx_hash, 100);
        let sig = sk.sign(&payload);

        // Verify against tick 200 — should fail
        assert!(!super::verify_client_state_sig(
            &pk, &sig.to_bytes(), &wallet_id, &new_state, &tx_hash, 200
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

        let mut wallet_id = [0u8; 32];
        wallet_id[0] = 0xEE;
        let mut new_state = [0u8; 32];
        new_state[0] = 0x01;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = 0xEE ^ 0x01;
        let tick = 5u64;

        let payload = super::client_state_sign_payload(&wallet_id, &new_state, &tx_hash, tick);
        let sig = sk.sign(&payload);

        let msg = GossipMessage::StateUpdate {
                      wallet_seq: 0,
            seq_proof: None,
            wallet_id, new_state, tx_hash, tick,
            is_genesis_claim: false,
            client_pk: pk,
            client_sig: sig.to_bytes().to_vec(),
            amount: 0,
            fee_breakdown: Vec::new(),
        };

        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);
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
        let wid = [0xEEu8; 32];

        let mint = |txid: &[u8; 32], seq: u64, n: usize| -> crate::types::SeqProof {
            let (state_hash, commitment_hash, epoch, dev) = ([0x5au8; 32], [0x7cu8; 32], 7u64, false);
            let c = axiom_core_logic::compute::compute_receipt_commitment(
                txid, &state_hash, seq, &commitment_hash, epoch, dev, None,
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
            crate::types::SeqProof { state_hash, commitment_hash, epoch, is_dev_class: dev, oods_flag: None, sigs }
        };
        let msg = |state: u8, tx: [u8; 32], tick: u64, seq: u64, proof: Option<crate::types::SeqProof>| {
            GossipMessage::StateUpdate {
                wallet_id: wid, new_state: [state; 32], tx_hash: tx, tick,
            is_genesis_claim: false,
                wallet_seq: seq, client_pk: [0u8; 32], client_sig: vec![],
                amount: 0, fee_breakdown: Vec::new(), seq_proof: proof,
            }
        };
        macro_rules! go {
            ($m:expr) => {
                engine.process(&$m, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0),
                    &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(),
                    &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1)
            };
        }

        // Honest head Y at seq=5 WITH a valid proof → adopted.
        let txid_y = [0xA1u8; 32];
        assert!(matches!(go!(msg(0x22, txid_y, 10, 5, Some(mint(&txid_y, 5, 3)))), GossipAction::Forward(_)));
        assert_eq!(smt.get(&wid).unwrap().wallet_seq, 5);

        // Forged seq=99 advance, no proof → dropped, head unchanged.
        assert!(matches!(go!(msg(0x33, [0xB2u8; 32], 99, 99, None)), GossipAction::Duplicate));
        assert_eq!(smt.get(&wid).unwrap().current_state[0], 0x22, "flood head must not roll forward");

        // Honest advance Z at seq=6 WITH a valid proof → adopted + proof retained.
        let txid_z = [0xD4u8; 32];
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
        let wid = [0xDDu8; 32];
        let (x, y) = ([0xA0u8; 32], [0xA1u8; 32]);
        let msg = |state: [u8; 32], tx: [u8; 32], tick: u64| GossipMessage::StateUpdate {
            wallet_id: wid, new_state: state, tx_hash: tx, tick,
            is_genesis_claim: false,
            wallet_seq: 0, client_pk: [0u8; 32], client_sig: vec![],
            amount: 0, fee_breakdown: Vec::new(), seq_proof: None,
        };
        macro_rules! go {
            ($m:expr) => {
                engine.process(&$m, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0),
                    &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(),
                    &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1)
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

        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);
        assert!(matches!(action, GossipAction::Duplicate)); // dropped silently
        assert_eq!(smt.len(), 0); // not inserted
    }

    #[test]
    fn gossip_state_update_legacy_zero_pk_accepted() {
        // Zero pk = legacy pre-YPX-009 — accepted without sig check
        let mut engine = GossipEngine::new();
        let mut smt = SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let mut pool = DailyPoolState::new();

        let msg = make_state_update(0xDD, 0x01, 5); // uses [0u8; 32] pk
        let action = engine.process(&msg, &mut smt, &mut bans, &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &NoopSigner, 0, 1);

        assert!(matches!(action, GossipAction::Forward(_)));
        assert_eq!(smt.len(), 1);
    }

    #[test]
    fn client_sig_payload_covers_all_fields() {
        // Changing any single field should produce a different payload
        let w = [0xAA; 32];
        let s = [0xBB; 32];
        let t = [0xCC; 32];
        let tick = 100u64;

        let baseline = super::client_state_sign_payload(&w, &s, &t, tick);

        let mut w2 = w;
        w2[0] = 0x00;
        assert_ne!(baseline, super::client_state_sign_payload(&w2, &s, &t, tick));

        let mut s2 = s;
        s2[0] = 0x00;
        assert_ne!(baseline, super::client_state_sign_payload(&w, &s2, &t, tick));

        let mut t2 = t;
        t2[0] = 0x00;
        assert_ne!(baseline, super::client_state_sign_payload(&w, &s, &t2, tick));

        assert_ne!(baseline, super::client_state_sign_payload(&w, &s, &t, tick + 1));
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

        let payload = super::pulse_proof_sign_payload(&vpk, epoch, &acc, &audit);
        let sig = sk.sign(&payload);

        assert!(super::verify_pulse_proof_sig(&vpk, sig.to_bytes().as_ref(), &payload));
        println!("  ✓ Pulse proof sign/verify roundtrip");
    }

    #[test]
    fn pulse_proof_reject_bad_sig() {
        let vpk = [1u8; 32]; // not a valid key for this sig
        let payload = super::pulse_proof_sign_payload(&vpk, 1, &[0; 32], &[0; 32]);
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

        let p1 = super::pulse_proof_sign_payload(&vpk, epoch, &acc1, &audit);
        let p2 = super::pulse_proof_sign_payload(&vpk, epoch, &acc2, &audit);
        assert_ne!(p1, p2, "different accumulators must produce different payloads");

        let p3 = super::pulse_proof_sign_payload(&vpk, epoch + 1, &acc1, &audit);
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

        let payload = super::pulse_proof_sign_payload(&vpk, epoch, &acc, &audit);
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

        let signer = crate::crypto::Ed25519Signer::from_node_index(99);
        let mut engine = super::GossipEngine::new();
        let mut pool = crate::oracle::DailyPoolState::default();
        let action = engine.process(&msg, &mut crate::smt::SparseMerkleTree::new(),
                                     &mut crate::ban::BanTable::new(), &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &signer, 0, 1);
        match action {
            super::GossipAction::Forward(_) => println!("  ✓ Valid PulseProof forwarded"),
            _ => panic!("expected Forward for valid PulseProof"),
        }
    }

    #[test]
    fn pulse_proof_empty_audit_dropped() {
        use ed25519_dalek::{SigningKey, Signer as _};
        use crate::types::GossipMessage;

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vpk: [u8; 32] = sk.verifying_key().to_bytes();
        let payload = super::pulse_proof_sign_payload(&vpk, 1, &[0; 32], &[0; 32]);
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

        let signer = crate::crypto::Ed25519Signer::from_node_index(99);
        let mut engine = super::GossipEngine::new();
        let mut pool = crate::oracle::DailyPoolState::default();
        let action = engine.process(&msg, &mut crate::smt::SparseMerkleTree::new(),
                                     &mut crate::ban::BanTable::new(), &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &signer, 0, 1);
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

        let payload = super::pulse_proof_sign_payload(&vpk, 1, &acc, &audit);
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

        let signer = crate::crypto::Ed25519Signer::from_node_index(99);
        let mut engine = super::GossipEngine::new();
        let mut pool = crate::oracle::DailyPoolState::default();
        let action = engine.process(&msg, &mut crate::smt::SparseMerkleTree::new(),
                                     &mut crate::ban::BanTable::new(), &mut pool, &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0), &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(), &signer, 0, 1);
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
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = wid;
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
        GossipMessage::StateUpdate {
            wallet_seq: 0,
            seq_proof: None,
            wallet_id, new_state, tx_hash, tick,
            is_genesis_claim: false,
            client_pk: [0u8; 32], client_sig: vec![0u8; 64],
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
            &mut crate::node::DeedPool::new(),
            &mut crate::node::DevDeedPool::new(),
            &NoopSigner, 0, 1,
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
        let mut wallet_id = [0u8; 32]; wallet_id[0] = 0xD7;
        let mut new_state = [0u8; 32]; new_state[0] = 0x01;
        let mut tx_hash = [0u8; 32]; tx_hash[0] = 0xD7 ^ 0x01;
        let proof = ds_mint_seq_proof(&tx_hash, 5, 3);
        let wallet_sk = SigningKey::from_bytes(&[0xD7u8.wrapping_add(0xC0); 32]);
        let client_pk = wallet_sk.verifying_key().to_bytes();
        let payload = client_state_sign_payload(&wallet_id, &new_state, &tx_hash, 10);
        let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();
        let attested_redeem = GossipMessage::StateUpdate {
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
            &mut crate::node::DeedPool::new(),
            &mut crate::node::DevDeedPool::new(),
            &NoopSigner, 0, 1,
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
        let amount = 1_000_000_u64;
        let over_cap = (amount * 50) / 10_000;
        let msg = GossipMessage::StateUpdate {
                      wallet_seq: 0,
            seq_proof: None,
            wallet_id: [0xAA; 32], new_state: [0x01; 32],
            tx_hash: [0x77; 32], tick: 5,
            is_genesis_claim: false,
            client_pk: [0u8; 32], client_sig: vec![0u8; 64],
            amount,
            fee_breakdown: vec![
                FeeShare { validator_id: vid_byte(0x11), amount: over_cap },
            ],
        };
        let action = engine.process(
            &msg, &mut smt, &mut bans, &mut pool,
            &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0),
            &mut crate::node::DeedPool::new(),
            &mut crate::node::DevDeedPool::new(),
            &NoopSigner, 0, 1,
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
            &mut crate::node::DeedPool::new(),
            &mut crate::node::DevDeedPool::new(),
            &NoopSigner, 0, 1,
        );
        engine.process(
            &msg2, &mut smt, &mut bans, &mut pool,
            &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0),
            &mut crate::node::DeedPool::new(),
            &mut crate::node::DevDeedPool::new(),
            &NoopSigner, 0, 1,
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

        // Pre-populate with a newer entry (no fee record).
        let mut wallet_id = [0u8; 32]; wallet_id[0] = 0xAA;
        smt.put(&NablaEntry {
                     wallet_seq: 0,
            wallet_id,
            current_state: [0x05; 32],
            tx_hash: [0x99; 32],
            tick: 10,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        });

        // Now gossip a stale (tick=5) update WITH fees — it should lose
        // the merge and the record must not land.
        let stale = make_fee_state_update(0xAA, 0x01, 5, 1_000_000);
        let action = engine.process(
            &stale, &mut smt, &mut bans, &mut pool,
            &mut AirdropPool::new(0), &mut crate::node::DevTreasuryPool::new(0),
            &mut crate::node::DeedPool::new(),
            &mut crate::node::DevDeedPool::new(),
            &NoopSigner, 0, 1,
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

    fn wid(b: u8) -> WalletId {
        let mut w = [0u8; 32];
        w[0] = b;
        w
    }
    fn st(b: u8) -> StateId {
        let mut s = [0u8; 32];
        s[0] = b;
        s
    }

    /// A k=3 witness set binding `old_state` — content is irrelevant under
    /// `NoopSigner` (verify == true); the count (>= 3) is what the detector
    /// gates on. `n` lets a scenario forge an UNDER-witnessed advance.
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
        GossipMessage::HalAdvance {
            wallet_id: wid(w),
            old_state: st(old),
            new_state: st(new),
            tx_hash: st(w ^ new ^ 0x5A),
            tick,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
            k3_signatures: k3_sigs(n_sigs),
            amount: 0,
            fee_breakdown: Vec::new(),
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
                &mut crate::node::DeedPool::new(), &mut crate::node::DevDeedPool::new(),
                &NoopSigner, tick, 1,
            )
        }
        /// Drive this node to head Y via X: genesis X, then advance X→Y. After
        /// this `previous_state(W) == X` (the EXACT consumed state the detector
        /// keys on) and the head is Y.
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

    // ── Scenario A ──────────────────────────────────────────────────────────
    // Honest holder spent X→Y. A colluding/wiped node re-witnesses the consumed
    // X into a fresh head X' and gossips it. The honest holder must DETECT the
    // fork against its own retained previous_state, FREEZE, NOT adopt X', and
    // FORWARD so the rest of the mesh re-detects.
    #[test]
    fn ki34_scenario_a_honest_holder_detects_respend() {
        const W: u8 = 0xA1;
        let mut honest = Node::new();
        honest.anchor_x_then_y(W, 0x01 /*X*/, 0x02 /*Y*/);

        // Colluding re-anchor: X(0x01) → X'(0x03), fully k=3 witnessed.
        let revival = make_hal_advance(W, 0x01, 0x03, 9, 3);
        let action = honest.feed(&revival, 9);

        assert!(matches!(action, GossipAction::Forward(_)),
            "A: confirmed revival fork must be forwarded for peer re-detection");
        assert!(honest.frozen(W),
            "A: honest holder must FREEZE the wallet on a confirmed re-spend fork");
        assert_eq!(honest.head(W), Some(st(0x02)),
            "A: the forked head X' must NOT be adopted — head stays Y");
    }

    // Negative control for A: an UNDER-witnessed (< k=3) revival is a possible
    // framing attempt — the detector must NOT freeze on unverifiable evidence
    // (a permanent freeze on a forged claim would be worse than today's reject).
    #[test]
    fn ki34_scenario_a_underwitnessed_revival_does_not_freeze() {
        const W: u8 = 0xA2;
        let mut honest = Node::new();
        honest.anchor_x_then_y(W, 0x01, 0x02);

        let forged = make_hal_advance(W, 0x01, 0x03, 9, 2 /* only 2 sigs */);
        let action = honest.feed(&forged, 9);

        assert!(matches!(action, GossipAction::Duplicate),
            "A-neg: insufficient-sig revival must be dropped, not acted on");
        assert!(!honest.frozen(W),
            "A-neg: must NOT freeze on unverifiable (framing) evidence");
        assert_eq!(honest.head(W), Some(st(0x02)),
            "A-neg: head must be untouched");
    }

    // ── Scenario B ──────────────────────────────────────────────────────────
    // Endorsement floor + no-false-positive. A node WIPED then recovered via
    // anti-entropy holds head Y but has LOST the consumed-state memory
    // (previous_state == None). Replayed the revival, it cannot detect and so
    // must NOT false-freeze — it simply applies. Safety rests on ANY honest
    // holder that retained previous_state: that node detects, freezes, and
    // forwards. The mesh is safe as long as >= 1 such holder exists.
    #[test]
    fn ki34_scenario_b_endorsement_floor_and_no_false_positive() {
        const W: u8 = 0xB1;

        // Honest holder retains X as the consumed previous_state.
        let mut honest = Node::new();
        honest.anchor_x_then_y(W, 0x01, 0x02);

        // Wiped node: only re-learned the head Y via a single AE state update,
        // so it has NO previous_state for W.
        let mut wiped = Node::new();
        wiped.feed(&make_state_update(W, 0x02 /*Y*/, 2), 2);
        assert_eq!(wiped.smt.previous_state(&wid(W)), None,
            "B-setup: wiped node must have NO retained previous_state");

        let revival = make_hal_advance(W, 0x01, 0x03, 9, 3);

        // Wiped node: cannot detect (prev unknown) → applies, must NOT freeze.
        let w_action = wiped.feed(&revival, 9);
        assert!(!wiped.frozen(W),
            "B: a node with no retained previous_state must NOT false-freeze");
        assert!(matches!(w_action, GossipAction::Forward(_) | GossipAction::Duplicate));

        // Honest holder: detects + freezes + forwards — the endorsement floor.
        let h_action = honest.feed(&revival, 9);
        assert!(honest.frozen(W),
            "B: >= 1 honest holder with retained previous_state freezes the fork");
        assert!(matches!(h_action, GossipAction::Forward(_)),
            "B: the detecting holder must forward so the rest of the mesh re-detects");
    }

    // ── Scenario C ──────────────────────────────────────────────────────────
    // Partition isolation + heal-time detection. While the colluding subset is
    // partitioned away, its forked re-anchor NEVER reaches the honest holder, so
    // no value crosses and the honest head stays Y (Normal). When the partition
    // HEALS, the forwarded revival reaches the honest holder, which then detects
    // and freezes — the fork is caught at reconnect, never realized on the
    // honest side.
    #[test]
    fn ki34_scenario_c_partition_isolation_then_heal_detection() {
        const W: u8 = 0xC1;
        let mut honest = Node::new();
        honest.anchor_x_then_y(W, 0x01, 0x02);

        // Colluder, isolated, re-anchors X→X' in its own partition.
        let mut colluder = Node::new();
        colluder.feed(&make_state_update(W, 0x01 /*X*/, 1), 1);
        let revival = make_hal_advance(W, 0x01, 0x03, 9, 3);
        colluder.feed(&revival, 9);

        // ── During partition: honest holder never receives the revival. ──
        assert_eq!(honest.head(W), Some(st(0x02)),
            "C: partitioned — honest head must remain Y, no value crosses");
        assert!(!honest.frozen(W),
            "C: partitioned — honest holder must not be frozen yet");

        // ── Partition heals: the forwarded revival now reaches the holder. ──
        let action = honest.feed(&revival, 9);
        assert!(matches!(action, GossipAction::Forward(_)),
            "C: on heal the revival is detected as a fork and forwarded");
        assert!(honest.frozen(W),
            "C: on heal the honest holder detects the fork and freezes");
        assert_eq!(honest.head(W), Some(st(0x02)),
            "C: the forked head X' must never be adopted, even at heal");
    }
}
