// AXIOM Nabla — Core Types
// Reference: AXIOM_GUIDE_Nabla.md Sections 2-4, 7

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── 32-byte identifiers ──
//
// Wire-protocol identifiers (`WalletId`, `StateId`, `TxHash`) live in
// `axiom_core_logic::nabla_wire` per the UMP rule
// (`feedback_no_mirror_structs`). Re-exported here for back-compat so
// every existing `axiom_nabla::types::WalletId` reference keeps working.

pub use axiom_core_logic::nabla_wire::{StateId, TxHash, WalletId};

pub type Hash256 = [u8; 32];
pub type PeerId = [u8; 32];

// ── Cross-boundary wire types (Section 3) ──
//
// `Registration`, `DeedTransaction`, `K3Receipt`, and the k=3 witness
// signature live in UMP (`axiom_core_logic::nabla_wire`). Re-exported
// for back-compat — Nabla's k=3 sig is named `K3WitnessSig` in UMP to
// disambiguate from `axiom_core_logic::types::WitnessSig` (the full
// Lambda witness with Dilithium-65 + VBC bundle). Here we alias the
// UMP `K3WitnessSig` back to the local `WitnessSig` name that the
// rest of the axiom-nabla crate uses.

pub use axiom_core_logic::nabla_wire::{
    DeedTransaction, K3Receipt, K3WitnessSig as WitnessSig, PartialBridgeReceipt,
    Registration,
};

// ── Wallet Status (§32 Merge Protocol) ──

/// Which gossip-tracked pool a `PoolSync` message targets. Used as the
/// dispatch key in the unified PoolSync handler (replaces the old
/// AirdropPoolSync / DevTreasuryPoolSync split). Adding a new pool
/// (e.g. RunnerPool) is a single variant + handler arm.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PoolKind {
    /// §17.11 — 600,000 AXC public airdrop, claimed by non-`@axiom.internal` wallets.
    Airdrop,
    /// FACT class isolation §4 — 1,000,000 dev-AXC for `@axiom.internal` wallets.
    DevTreasury,
    /// DEED infrastructure-funding pool — 10% of every receiver-pays validator
    /// fee for the first 10 years (see `AXIOM_DESIGN_DeedDistribution.md`).
    /// Monotonic-INCREASE convergence (the opposite of Airdrop/DevTreasury):
    /// peers converge to the higher balance during Phase 1, freeze on the
    /// last seen balance after the cutoff.
    Deed,
    /// Dev-class DEED pool — same 10% slice mechanism, but credited from
    /// `@axiom.internal` TXs only. Type-distinct on-disk persistence
    /// (`dev_deed_pool.state`) and gossip discriminant so cross-credit
    /// is impossible. Observability only — NEVER convertible to public
    /// AXC (`AXIOM_DESIGN_FactClassIsolation.md`).
    DevDeed,
}

impl PoolKind {
    /// Wire-stable single-byte tag used in canonical signing payloads.
    /// MUST be stable across versions — discriminant order is NOT a
    /// substitute (serde would compile fine if you reorder, and the
    /// signature would silently break across the mesh).
    pub fn sign_tag(self) -> u8 {
        match self {
            PoolKind::Airdrop => 0x01,
            PoolKind::DevTreasury => 0x02,
            PoolKind::Deed => 0x03,
            PoolKind::DevDeed => 0x04,
        }
    }

    /// Filename slug for the on-disk persistence file (`<data_dir>/<slug>.state`).
    pub fn state_filename(&self) -> &'static str {
        match self {
            PoolKind::Airdrop => "airdrop_pool.state",
            PoolKind::DevTreasury => "dev_treasury_pool.state",
            PoolKind::Deed => "deed_pool.state",
            PoolKind::DevDeed => "dev_deed_pool.state",
        }
    }
}

/// Wallet status during normal operation and merge resolution.
/// NORMAL → FROZEN (on fork detection) → BANNED (permanent, after quarantine).
/// TAINTED = downstream wallet contaminated by forked inputs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum WalletStatus {
    /// Normal operation — transactions accepted.
    #[default]
    Normal,
    /// Frozen during merge quarantine — no transactions accepted.
    /// Contains the tick when freeze was triggered.
    Frozen,
    /// Contaminated by tainted inputs from a forked wallet.
    Tainted,
    /// Permanently banned — double-spend source or unresolvable taint.
    Banned,
}

/// JFP vote secret — unnamed, stored per DWP wallet ID.
/// See Yellow Paper §8.4.3. Propagated via Nabla gossip.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct JfpSecret {
    /// The vote secret (preimage component of vote hash)
    pub secret: [u8; 32],
    /// Which DWP case this belongs to
    pub dwp_wallet_id: WalletId,
}

// ── Per-tx record (YP §19.6 — receiver-pays-only fee ledger) ──

/// Per-transaction record stored on hashmap-mode Nabla nodes.
///
/// Populated alongside `txid_index` on the receiver's `/register` and via
/// `StateUpdate` gossip (the propagation mechanism that lets any hashmap
/// node serve fee-redemption queries — see Step 4). Light/bloom-mode nodes
/// pay no storage cost — this struct is hashmap-mode-only.
///
/// The fee ledger is **not** a separate balance counter. A validator's
/// total earnings is the SUM of slots where `fee_breakdown[i].validator_id`
/// matches that validator across all `TxRecord` entries — computed at query
/// time via the secondary `validator_earnings` index. This keeps the
/// hashmap-node storage model simple: per-tx records are immutable
/// once written; queries derive everything else.
///
/// AXIOM Origin's rule "fee registration can only happen when receiver registers
/// its balance, and only at that time" is satisfied structurally — Nabla's
/// registration handler is the only producer; gossip + WAL replay only
/// propagate what registration originally wrote.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxRecord {
    /// The receiver of the transaction (the wallet whose register produced
    /// this record). Joined back to NablaEntry by tx_hash → wallet_id.
    pub receiver_wallet_id: WalletId,
    /// Gross transaction amount in atoms — the cap-validation base.
    pub amount: u64,
    /// Receiver-pays slot allocation. Bound into receipt_commitment by
    /// Core CL5 + verified slot-by-slot by each Lambda before signing,
    /// so the bytes here match exactly what k validators agreed on.
    pub fee_breakdown: Vec<axiom_core_logic::types::FeeShare>,
    /// Tick at which this record was committed. Used by fee-redemption
    /// queries to slice "earnings since last withdrawal."
    pub tick: u64,
}

// ── Wallet State Entry (Section 2.2) ──

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NablaEntry {
    pub wallet_id: WalletId,
    pub current_state: StateId,
    pub tx_hash: TxHash,
    pub tick: u64,
    /// k-witnessed chain position (`receipt.new_wallet_seq`) — the anti-rollback
    /// merge key (KI#34 WI3, threat §5.4). Sourced from the k=3-attested receipt
    /// at register time, NOT client-set: a fork from an ancestor has a strictly
    /// LOWER seq than the honest head, so `superseded_by` orders by this BEFORE
    /// `tick` and the fork can never out-tick its way over the head. No
    /// `serde(default)` (CLAUDE.md §13 clean break) — an old-format entry without
    /// it does not deserialize, which is intended: the field changes the SMT leaf
    /// hash, so adopting it requires a coordinated all-Nabla restart + clean SMT.
    ///
    /// SECURITY: the seq is only as trustworthy as its k-attestation. A bare value
    /// gossiped over anti-entropy is forgeable; `apply_remote_entry` MUST verify
    /// the carried k=3 receipt proof before ordering on this (WI3 hole-1; the
    /// k-receipt-proof field + verify land in the next commit on this branch).
    pub wallet_seq: u64,
    /// Group wallet fields (None for personal wallets)
    pub group_members: Option<Vec<GroupMemberState>>,
    /// Wallet status for merge protocol (§32). Default: Normal.
    #[serde(default)]
    pub status: WalletStatus,
    /// Wallet owner's Ed25519 public key (YPX-009 client-signed state records).
    #[serde(default)]
    pub client_pk: [u8; 32],
    /// Ed25519 sig over BLAKE3("AXIOM_WALLET_STATE" || wallet_id || current_state || tx_hash || tick_le).
    #[serde(default)]
    pub client_sig: Vec<u8>,
}

impl NablaEntry {
    /// The anti-entropy merge order (design `AXIOM_DESIGN_NablaAntiEntropy.md`
    /// §5.2). Returns true iff `incoming` should replace `self` for the same
    /// wallet. Deterministic and total — gossip flooding and anti-entropy
    /// both adopt the maximum, so the merge is a semilattice join and the
    /// mesh converges regardless of message order or loss.
    ///
    /// Precondition: `self.wallet_id == incoming.wallet_id`, and `incoming`
    /// carries a verified client signature.
    pub fn superseded_by(&self, incoming: &NablaEntry) -> bool {
        // 1. Freeze monotonicity — a non-Normal wallet (§32 frozen / tainted
        //    / banned) is never demoted back to Normal.
        fn rank(s: WalletStatus) -> u8 {
            match s {
                WalletStatus::Normal => 0,
                WalletStatus::Frozen | WalletStatus::Tainted | WalletStatus::Banned => 1,
            }
        }
        let (r_self, r_in) = (rank(self.status), rank(incoming.status));
        if r_in != r_self {
            return r_in > r_self;
        }
        // 2. Higher k-witnessed wallet_seq wins (KI#34 WI3, threat §5.4). Chain
        //    position, not wall-clock: an ancestor-fork (rollback X→X') has a
        //    strictly LOWER seq than the honest head, so it can never supersede
        //    regardless of how late (high-tick) it was stamped — closing the §5.4
        //    rollback gap (test `rollback_fork_loses_by_kseq_despite_higher_tick`).
        //    tick is demoted
        //    to a tiebreaker below. The seq is trusted only after
        //    `apply_remote_entry` verifies its k=3 attestation (see the
        //    `NablaEntry.wallet_seq` SECURITY note — a bare seq is forgeable).
        if incoming.wallet_seq != self.wallet_seq {
            return incoming.wallet_seq > self.wallet_seq;
        }
        // 3. Equal seq → higher tick wins (tiebreaker only).
        if incoming.tick != self.tick {
            return incoming.tick > self.tick;
        }
        // 4. Equal tick → higher current_state (lexicographic).
        if incoming.current_state != self.current_state {
            return incoming.current_state.as_ref() > self.current_state.as_ref();
        }
        // 4. Equal tick & state → higher serialized form. A total-order
        //    closer; equal wallet+tick+state is byte-identical in practice,
        //    so this only decides on a genuine residual field conflict.
        match (bincode::serialize(incoming), bincode::serialize(self)) {
            (Ok(a), Ok(b)) => a > b,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GroupMemberState {
    pub member_pk: [u8; 32],
    pub share_bps: u16,
    pub available: u64,
}

// ── Seq Attestation (KI#34 WI3 hole-1) ──

/// One validator's Ed25519 attestation of a wallet's k-witnessed chain
/// position, extracted from `K3WitnessSig` (`validator_pk` +
/// `receipt_commitment_sig`). The sig is over
/// `compute_receipt_commitment(...)`, which folds in `new_wallet_seq` — the
/// same value `SeqProof::verifies_seq` reconstructs and checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SeqProofSig {
    pub validator_pk: [u8; 32],
    /// 64-byte Ed25519 signature over `compute_receipt_commitment`.
    pub receipt_commitment_sig: Vec<u8>,
}

/// KI#34 WI3 hole-1: the k=3 attestation that makes `NablaEntry.wallet_seq`
/// unforgeable on the gossip/anti-entropy wire. A bare `wallet_seq` is as
/// forgeable as `tick` — but `wallet_seq` is now the PRIMARY merge key
/// (`superseded_by` rule 2, before `tick`), so a self-stamped high seq would
/// otherwise win the merge over an honest head. This proof carries the same
/// material the `/register` path verifies (registration.rs §5b): the k
/// validators each signed `compute_receipt_commitment(txid, state_hash,
/// new_wallet_seq, commitment_hash, epoch, is_dev_class)`. Reconstructing the
/// commitment with the entry's OWN `tx_hash` + `wallet_seq` and verifying
/// ≥`MIN_FACT_WITNESSES` DISTINCT sigs proves the seq was k-witnessed for this
/// txid. (The seq binds to the entry's `current_state` transitively: the
/// `client_sig` binds `current_state ↔ tx_hash`, this proof binds
/// `tx_hash ↔ seq`.)
///
/// WHERE IT LIVES — not in `NablaEntry`. `smt.put` bincodes the whole entry
/// into the leaf hash, so folding the proof in would (a) diverge the leaf hash
/// between a node that received the proof and one that learned the head another
/// way → AE never converges, and (b) persist k sigs per wallet forever (KI#35
/// RAM growth). The proof therefore rides on the WIRE (`StateUpdate` gossip +
/// `AeReconcile`/`AeEntries`) and is held in a PARALLEL `SparseMerkleTree`
/// `seq_proofs` map (outside the leaf) so the AE path can re-attach it when
/// serving a pulled entry. Verified at adoption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SeqProof {
    pub state_hash: [u8; 32],
    pub commitment_hash: [u8; 32],
    pub epoch: u64,
    pub is_dev_class: bool,
    /// YPX-021 §8.2 — bound into receipt_commitment; carried so
    /// `verify_seq_proof`'s recompute matches what the k signed.
    pub oods_flag: Option<axiom_core_logic::types::OodsFlag>,
    pub sigs: Vec<SeqProofSig>,
}

impl SeqProof {
    /// Build a `SeqProof` from a `K3Receipt`. Returns `None` when the receipt
    /// carries no `receipt_commitment_sig`s (no-fee / heal / genesis / legacy
    /// paths) — those entries advertise `wallet_seq` but have no k-attestation
    /// to prove it, so the merge treats their seq as untrusted.
    pub fn from_receipt(txid_unused: &TxHash, receipt: &K3Receipt) -> Option<SeqProof> {
        let _ = txid_unused; // txid is the entry's tx_hash, supplied at verify time
        let sigs: Vec<SeqProofSig> = receipt
            .signatures
            .iter()
            .filter(|ws| ws.receipt_commitment_sig.len() == 64)
            .map(|ws| SeqProofSig {
                validator_pk: ws.validator_pk,
                receipt_commitment_sig: ws.receipt_commitment_sig.clone(),
            })
            .collect();
        if sigs.is_empty() {
            return None;
        }
        Some(SeqProof {
            state_hash: receipt.state_hash,
            commitment_hash: receipt.commitment_hash,
            epoch: receipt.epoch,
            is_dev_class: receipt.is_dev_class,
            oods_flag: receipt.oods_flag,
            sigs,
        })
    }
}

// NOTE: `SeqProof` is a pure DATA carrier — it holds no cryptographic logic.
// Verifying the seq attestation (recomputing `compute_receipt_commitment` and
// checking the k Ed25519 sigs) lives in `registration::verify_seq_proof`,
// alongside the EXISTING §5b receipt-commitment verify it mirrors. Core is the
// sole cryptographic authority (CLAUDE.md §1); the only nabla files permitted to
// touch core-logic crypto primitives directly are the hot-path handlers listed
// in `cc::tests::no_direct_core_crypto_in_production_code` (registration.rs is
// one of them). Do NOT add crypto here just to keep it next to the struct.

// ── Ban Status (Section 2.7, S6 Challenge Protocol) ──

/// Lifecycle of a ban: Active → Challenged → Reversed.
/// Active bans block all wallet operations. A successfully challenged ban
/// transitions to Reversed, which restores the wallet to Normal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BanStatus {
    /// Ban is active — wallet is blocked.
    Active,
    /// Ban has been challenged with valid evidence. Waiting for challenge window to expire.
    Challenged {
        challenge_tick: u64,
        evidence: ChallengeEvidence,
    },
    /// Ban was reversed after successful challenge. Wallet restored to Normal.
    Reversed { reversed_at_tick: u64 },
}

/// Evidence presented to challenge a ban.
/// Requires a valid scar recovery proof (k≥3 ML-DSA-65 signatures) plus
/// k≥3 Nabla node endorsement signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ChallengeEvidence {
    /// Original transaction ID that triggered the ban.
    pub original_tx_id: TxHash,
    /// k≥3 Nabla node endorsement signatures over the challenge commitment.
    /// Commitment = BLAKE3("AXIOM_BAN_CHALLENGE" || wallet_id || original_tx_id).
    pub nabla_signatures: Vec<ChallengeEndorsement>,
}

/// A single Nabla node's endorsement of a ban challenge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ChallengeEndorsement {
    pub node_id: NodeId,
    pub signature: Vec<u8>,
}

// ── Banned Entry (Section 2.7) ──

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BannedEntry {
    pub wallet_id: WalletId,
    /// /register-path conflict evidence (receipt_sign_payload sigs). Zeroed for
    /// gossip seq-fork bans, which carry their evidence in `seq_fork` instead.
    pub evidence_1: ConflictProof,
    pub evidence_2: ConflictProof,
    /// Gossip-path double-spend FORK evidence (two k=3 SeqProofs). `None` for the
    /// /register-path receipt-evidence bans above.
    #[serde(default)]
    pub seq_fork: Option<SeqConflictProof>,
    /// Ban lifecycle status. Default: Active.
    #[serde(default = "default_ban_status")]
    pub status: BanStatus,
}

fn default_ban_status() -> BanStatus {
    BanStatus::Active
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ConflictProof {
    pub old_state: StateId,
    pub new_state: StateId,
    pub tx_hash: TxHash,
    pub k3_signatures: Vec<WitnessSig>,
    /// Receipt tick — needed to reconstruct receipt_sign_payload for
    /// signature verification. Without this, verify_conflict builds a
    /// different payload than what validators actually signed.
    #[serde(default)]
    pub tick: u64,
}

/// Evidence of a double-SPEND detected on the GOSSIP path (not /register).
///
/// Two k=3-attested successors of the SAME predecessor: identical `wallet_seq`
/// (⟹ both consumed the same seq-(N-1) predecessor X), different `current_state`,
/// different `tx_hash`. Unlike [`ConflictProof`] — whose `k3_signatures` are over
/// `receipt_sign_payload` from the /register path — this carries the two
/// [`SeqProof`]s that the `StateUpdate` / anti-entropy wire ALREADY transports.
/// Each is re-verified with `registration::verify_seq_proof` (k=3 over
/// `compute_receipt_commitment`). Because both states are k=3-witnessed, this
/// conflict CANNOT occur accidentally — it is a deliberate double-spend, so the
/// detecting node bans the wallet irreversibly and floods this evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SeqConflictProof {
    pub wallet_seq: u64,
    pub state_a: StateId,
    pub tx_a: TxHash,
    pub proof_a: SeqProof,
    pub state_b: StateId,
    pub tx_b: TxHash,
    pub proof_b: SeqProof,
}

// ── Definitions of K3WitnessSig, Registration, K3Receipt, DeedTransaction
// moved to axiom_core_logic::nabla_wire; re-exported above per the UMP rule. ──

// ── Query Response (Section 4.2) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NablaResponse {
    pub wallet_id: WalletId,
    pub current_state: StateId,
    pub tx_hash: TxHash,
    /// WI3: k-witnessed chain position of the head — REQUIRED for merkle-proof
    /// verification, because the SMT leaf hash now folds in `wallet_seq`. A
    /// verifier reconstructs the `NablaEntry` from this response; without the
    /// matching seq the leaf hash differs and the proof fails. No serde(default).
    pub wallet_seq: u64,
    pub root_hash: Hash256,
    pub synced_to_tick: u64,
    pub group_members: Option<Vec<GroupMemberState>>,
    pub merkle_proof: Option<MerkleProof>,
    pub signature: Vec<u8>,
    /// Role attestation: 0 = reader, 1 = writer. Validators MUST reject writer responses.
    #[serde(default)]
    pub role: u8,
    /// Ed25519 signature over BLAKE3("AXIOM_NABLA_ROLE" || node_id || role || wallet_id || state_id || tick)
    #[serde(default)]
    pub role_signature: Vec<u8>,

    // ── YPX-002 §4.6 receiver verification fields ──
    //
    // These three fields are covered by `response_sign_payload` (and
    // therefore by the node's Ed25519 `signature`), so a client that
    // verifies the response signature can trust them to the same degree
    // as `current_state` and `root_hash`.
    //
    //   - `nbc_issuer_pk` : §4.3 cross-branch grouping key. Raw bytes of
    //     the SPHINCS+ pubkey from the responding node's NBC issuer set
    //     (first entry = immediate parent CA). Two nodes are cross-branch
    //     iff their `nbc_issuer_pk` differs. Absent (empty) on pre-§4.6
    //     nodes; receiver MUST treat empty as "branch unknown" and count
    //     the node as satisfying cross-branch only vacuously.
    //   - `registration_tick` : §4.6 step 7 maturity gate input.
    //     `current_tick - registration_tick >= MATURITY_TICKS_MIN` ⟹ CLEAN.
    //     0 when the wallet has no entry in this node's SMT.
    //   - `wallet_status` : §4.6 steps 3+5 BANNED check. Receiver MUST
    //     reject the cheque immediately if ANY queried node returns Banned.
    //
    // All three are `#[serde(default)]` so pre-§4.6 Nabla nodes still
    // round-trip without breaking the wire format.
    #[serde(default)]
    pub nbc_issuer_pk: Vec<u8>,
    #[serde(default)]
    pub registration_tick: u64,
    #[serde(default)]
    pub wallet_status: WalletStatus,
}

// ── Merkle Proof (Section 2.3) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub key: WalletId,
    pub siblings: Vec<Hash256>,
}

// ── Group Member Query Response (Phase 3, Section 8) ──

/// Response to a member-specific query on a group wallet.
/// Receivers can verify their allocation and the group checksum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberQueryResponse {
    pub wallet_id: WalletId,
    pub member_pk: [u8; 32],
    pub share_bps: u16,
    pub available: u64,
    pub group_balance: u64,
    pub total_members: usize,
    pub checksum_valid: bool,
    pub synced_to_tick: u64,
}

// ── Gossip Mesh Types (Phase 4, Section 6) ──

/// NodeId is a BLAKE3 hash of the node's public key.
pub type NodeId = [u8; 32];

/// Information about a mesh peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub address: NablaAddress,
    /// Tick of last contact.
    pub last_seen: u64,
    /// Topology hint: who is their TARDIS upstream.
    pub tardis_up: Option<NodeId>,
    /// Topology hint: do they have an open D slot?
    pub has_d_open: bool,
    /// How many D slots are open (0, 1, or 2). Self-reported via gossip.
    /// 1 open = has 1 child, 2 open = has 0 children.
    pub open_slots: u8,
    /// Count of gossip messages delivered through this peer (§6.3.2 scoring).
    pub messages_delivered: u64,
    /// Tick when this peer was added to our active peer list (§6.3.2 age penalty).
    pub connected_since: u64,
    /// YPX-014: Txid service mode advertised by this peer ("bloom" or "hashmap").
    #[serde(default)]
    pub txid_service: String,
}

/// Per-peer pulse delivery tracking (YPX-009 §5.2).
/// Tracks whether a validator peer is producing valid pulse proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPulseState {
    /// Last epoch for which this peer delivered a valid pulse proof.
    pub last_pulse_epoch: u64,
    /// Count of consecutive epochs without a pulse proof.
    pub consecutive_misses: u32,
    /// Grace cycles remaining (new peers get PULSE_GRACE_CYCLES before scoring).
    pub grace_remaining: u32,
    /// Total pulse proofs received from this peer.
    pub total_pulses: u64,
}

/// Stripped-down peer hint for external clients (PMC).
/// No mesh-internal fields (messages_delivered, connected_since, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NablaClientPeer {
    pub node_id: NodeId,
    pub address: NablaAddress,
    pub last_seen_tick: u64,
}

impl NablaClientPeer {
    pub fn from_peer_info(p: &PeerInfo, current_tick: u64) -> Self {
        Self {
            node_id: p.node_id,
            address: p.address.clone(),
            last_seen_tick: p.last_seen.min(current_tick),
        }
    }
}

/// Network address for a Nabla node.
/// Encoded as human-readable Base32 for split recovery (§6.6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NablaAddress {
    V4 { ip: [u8; 4], port: u16 },
    V6 { ip: [u8; 16], port: u16 },
}

/// Topology hints gossipped through the mesh (on change only, not every tick).
/// These enable TARDIS self-healing without central coordination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TopologyHint {
    /// "I lost my UP, need new parent"
    LostUpstream { node_id: NodeId },
    /// "I have an open D slot — open_slots tells how many (1 or 2)"
    SlotAvailable { node_id: NodeId, address: NablaAddress, open_slots: u8 },
    /// "New node joined the network"
    NewNode { node_id: NodeId, address: NablaAddress },
}

// ── Gossip Messages (Section 6.2 — Phase 1 subset) ──

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GossipMessage {
    /// Wallet state update (flood fill)
    StateUpdate {
        wallet_id: WalletId,
        new_state: StateId,
        tx_hash: TxHash,
        tick: u64,
        /// ONE txid domain (2026-07-07): true iff this advance is a GENESIS
        /// fund/claim register. Genesis registers carry a non-empty
        /// fee_breakdown (fees are collected at the claim) but are the SEND
        /// side of the claim's self-redeem — the k-attested REDEEMED parity
        /// mark must NOT fire for them or the genesis self-redeem reads its
        /// own txid as already-redeemed. No serde(default) (§13 clean break;
        /// whole mesh redeploys together).
        is_genesis_claim: bool,
        /// WI3 (KI#34 §5.4) — k-witnessed chain position, carried so the gossip
        /// flood path stamps `NablaEntry.wallet_seq` from the same k-attested
        /// source the register path uses. No `serde(default)` (§13 clean break;
        /// the field rotates the SMT leaf hash → coordinated redeploy). The
        /// flood-path seq is forgeable until verified against a carried k=3
        /// proof — same hole-1 follow-on as the anti-entropy path.
        wallet_seq: u64,
        /// Wallet owner's Ed25519 public key (YPX-009 client-signed state records).
        #[serde(default)]
        client_pk: [u8; 32],
        /// Ed25519 sig over BLAKE3("AXIOM_WALLET_STATE" || fields).
        #[serde(default)]
        client_sig: Vec<u8>,
        /// YP §19.6 — gross transaction amount in atoms. Carried so
        /// hashmap-mode nodes can reconstruct `TxRecord` from gossip
        /// alone (without round-tripping back to the originating
        /// validator). Empty (0) on heal / genesis / pre-step-4 paths.
        #[serde(default)]
        amount: u64,
        /// YP §19.6 — receiver-pays fee allocation that Core CL5 bound
        /// into receipt_commitment. Hashmap-mode nodes store this in
        /// `txid_records` for fee-redemption queries; bloom-mode nodes
        /// ignore it. Empty on no-fee paths (send / heal / genesis).
        #[serde(default)]
        fee_breakdown: Vec<axiom_core_logic::types::FeeShare>,
        /// WI3 hole-1 (KI#34 §5.4) — the k=3 attestation that makes
        /// `wallet_seq` unforgeable on the flood path. `apply_state_update`
        /// requires a valid proof before a seq-ADVANCE can win the merge; a
        /// self-stamped high seq with no proof is rejected. `None` on
        /// legacy / heal / genesis / no-fee paths (their seq is not trusted
        /// to win on seq). Rides on the message only — never persisted in the
        /// SMT leaf (see `SeqProof`).
        seq_proof: Option<SeqProof>,
    },
    /// Ban alert with evidence
    BanAlert {
        wallet_id: WalletId,
        evidence_1: ConflictProof,
        evidence_2: ConflictProof,
    },
    /// Double-spend FORK ban (gossip-path seq-conflict). Carries two k=3-attested
    /// successors of the same predecessor (see [`SeqConflictProof`]). Receivers
    /// re-verify both `SeqProof`s before applying the irreversible ban. This is
    /// the origination path the normal-send cross-node double-spend previously
    /// lacked (it silently last-writer-wins merged instead).
    SeqForkBan {
        wallet_id: WalletId,
        evidence: SeqConflictProof,
    },
    /// Root hash at tick boundary (partition detection)
    TickHash {
        tick: u64,
        root_hash: Hash256,
        node_pk: [u8; 32],
    },
    /// Group wallet state update (Phase 3)
    /// Carries full member allocations so all nodes track distribution.
    GroupUpdate {
        wallet_id: WalletId,
        new_state: StateId,
        tx_hash: TxHash,
        members: Vec<GroupMemberState>,
        tick: u64,
    },
    /// Approved tick relay — redundant path from TARDIS (Phase 4)
    /// Orphaned TARDIS nodes can see ticks but cannot produce them.
    ApprovedTick {
        tick_number: u64,
        approvals: Vec<TickApproval>,
    },
    /// Topology hint — on change only, not every tick (Phase 4)
    Topology(TopologyHint),
    /// Nabla ID announcement — gossipped during probation for duplicate detection.
    /// If any node sees the same nabla_id with a different wallet_id, the
    /// duplicate is rejected.
    NablaIdAnnounce {
        /// The joining node's Nabla_id (= NBC validator_id).
        nabla_id: NodeId,
        /// Operator's wallet bound to this Nabla node.
        wallet_id: WalletId,
        /// TARDIS tick when probation started (virtual time).
        announced_at: u64,
    },

    /// Cheque claim gossip — registered on 3 nodes during §4.6 verification.
    /// First-wins: lowest claim_tick is authoritative across all nodes.
    ChequeClaim {
        cheque_id: TxHash,
        client_pk: Vec<u8>,
        claim_tick: u64,
    },

    /// YPX-020 HAL hibernation. Broadcast by the node that processed a
    /// dead-overlap re-anchor register so the whole mesh learns the wallet is
    /// "out of work" until `until`. Required because the cheque-claim
    /// (`register_cheque_claim`) fans out to a ~3-node pick set that is NOT the
    /// re-anchor's writer — without this gossip those nodes wouldn't know the
    /// wallet is hibernating and would issue the claim proof. Keyed by the
    /// wallet's Ed25519 `client_pk` (the same key the claim carries).
    Hibernation {
        client_pk: Vec<u8>,
        until: u64,
    },

    /// §32 Merge Protocol: Taint propagation.
    /// Wallets that received from a forked/tainted wallet are themselves tainted.
    TaintAlert {
        wallet_id: WalletId,
        /// The tainted source wallet that contaminated this wallet.
        tainted_source: WalletId,
        /// Tick when taint was detected.
        detected_at_tick: u64,
    },

    /// §32 Merge Protocol: Quarantine resolved.
    /// Forked wallets banned, tainted wallets restored to Normal.
    /// NOTE(review): Tainted wallets are spared — revisit if collusion is observed.
    MergeResolved {
        /// Wallets permanently banned (fork source).
        forked_wallets: Vec<WalletId>,
        /// Wallets restored to Normal (innocent downstream).
        restored_wallets: Vec<WalletId>,
        /// Tick when merge was resolved.
        resolved_at_tick: u64,
    },

    /// S6: Ban challenge accepted — wallet's ban is under review.
    /// Gossipped so all nodes transition the ban to Challenged state.
    BanChallenged {
        wallet_id: WalletId,
        evidence: ChallengeEvidence,
        challenge_tick: u64,
    },

    /// S6: Ban reversed — challenged ban expired without counter-evidence.
    /// Gossipped so all nodes restore the wallet.
    BanReversed {
        wallet_id: WalletId,
        reversed_at_tick: u64,
    },

    /// H3: Data availability withholding challenge.
    /// A peer challenges a validator that accepted a TX but refuses to serve
    /// the receipt/cheque to the client or other validators. If the challenged
    /// validator doesn't respond with the withheld data within CHALLENGE_WINDOW_TICKS,
    /// they receive a SCAR (same enforcement as JFP).
    DataWithholdChallenge {
        /// The validator being challenged.
        challenged_validator_pk: [u8; 32],
        /// The TX ID of the withheld receipt/cheque.
        withheld_txid: [u8; 32],
        /// The challenger's PK (must be a registered Nabla node).
        challenger_pk: [u8; 32],
        /// Ed25519 signature by challenger over BLAKE3("AXIOM_DA_CHALLENGE" || challenged_pk || txid || tick).
        challenger_sig: Vec<u8>,
        /// Tick when challenge was issued.
        challenge_tick: u64,
    },

    /// H3: Data availability response — challenged validator provides the withheld data.
    /// If received within CHALLENGE_WINDOW_TICKS, the challenge is resolved.
    DataWithholdResponse {
        /// The original challenge txid.
        withheld_txid: [u8; 32],
        /// The challenged validator's PK.
        validator_pk: [u8; 32],
        /// The withheld receipt data (CBOR-encoded).
        receipt_data: Vec<u8>,
        /// Ed25519 signature by validator over the receipt data.
        validator_sig: Vec<u8>,
        /// Tick when response was sent.
        response_tick: u64,
    },

    /// YPX-009 Silicon Pulse: Validator's heartbeat proof.
    /// Gossipped after AVM passes audit (buffer full or time fallback).
    /// Nabla peers use this for mesh scoring (W3) and liveness tracking.
    PulseProof {
        /// Validator's Ed25519 public key (32 bytes).
        validator_pk: [u8; 32],
        /// Pulse epoch number.
        epoch: u64,
        /// Full accumulator hash over the audited TX buffer.
        full_accumulator: [u8; 32],
        /// Number of TX digests in the buffer at trigger time.
        entry_count: u32,
        /// Number of entries selected for re-execution audit (PULSE_SAMPLE_RATIO × entry_count).
        sample_size: u32,
        /// Hash of the audit response (proves Lambda responded correctly).
        audit_hash: [u8; 32],
        /// Measured Argon2id(48MB,t=1) throughput (iterations/sec).
        /// Reported for peer validation.
        argon2id_per_sec: u64,
        /// Ed25519 signature over BLAKE3("AXIOM_PULSE_PROOF" || validator_pk || epoch || full_accumulator || audit_hash).
        signature: Vec<u8>,
        /// TARDIS tick when proof was generated.
        tick: u64,
    },

    /// Unified pool state sync (replaces AirdropPoolSync + DevTreasuryPoolSync).
    /// Same monotonic-decrease semantics either way; receiver dispatches on
    /// `pool` to the matching in-memory pool's `reconcile()`.
    ///
    /// `tick` is the TARDIS tick at the producer when this state was written
    /// — recorded for future rate-limit / daily-cap rules (reconcile() may
    /// or may not consult it; payload always carries it for forward-compat).
    PoolSync {
        pool: PoolKind,
        /// Remaining atoms in this pool
        balance: u64,
        /// Network-wide total claims processed against this pool
        total_claims: u64,
        /// TARDIS tick when this state was produced
        tick: u64,
        /// Phase B Layer 4: the emitting Nabla's NodeId. Required for
        /// authentic attribution when reconcile detects a violation —
        /// `accused` in the resulting Alert is taken from this field
        /// only after `sender_sig` verifies. Carried on every PoolSync,
        /// not just attack scenarios, because honest gossip is the
        /// only place the receiver learns "this state came from N".
        sender_node_id: NodeId,
        /// Ed25519 signature over `pool_sync_sign_payload(...)` made
        /// with the sender's Nabla signing key. Bound to `sender_node_id`
        /// via the receiver's `verified_nbcs[sender_node_id]` lookup
        /// (Ed25519 pk inside the NBC). Verification failure = drop +
        /// ban-score++.
        sender_sig: Vec<u8>,
    },

    /// Oracle pool state sync (Phase 8, §11.7)
    /// Nabla nodes gossip daily pool counters so validators see consistent state.
    /// Reconciliation: highest claims_today wins, lowest pool balance wins.
    OraclePoolSync {
        /// Current UTC date string ("2027-03-15")
        date: String,
        /// Remaining AXC per platform today (11 platforms)
        pools: [u64; 11],
        /// Total reserve AXC remaining (never resets, only decreases)
        reserve_left: u64,
        /// Number of claims processed today (monotonically increasing within day)
        claims_today: u64,
        /// TARDIS tick when this state was produced
        tick: u64,
    },

    /// Layer 4 Quarantine Alert — emitted when a Nabla locally detects
    /// a pool-state invariant violation from a peer. Receivers verify
    /// the intermediate_emitter against the actual TCP source (NBC-bound
    /// identity), dedup on (accused, origin_emitter), and count toward
    /// the 3-of-N consensus that triggers a mesh-wide quarantine.
    ///
    /// See `docs/AXIOM_DESIGN_NablaPoolCaps.md` §5.6 for the full
    /// detection→consensus→quarantine→recovery design and the
    /// 9-scenario attack analysis (§5.6.7).
    Alert {
        alert_type: AlertType,
        /// The accused Nabla's id (NBC validator_id).
        accused: NodeId,
        /// Type-specific evidence blob. For PoolInvariantViolation,
        /// this is the CBOR-serialized offending PoolSync.
        evidence: Vec<u8>,
        /// Nabla that first detected the violation. Preserved across
        /// all hops; unverifiable on its own (see §5.6.5).
        origin_emitter: NodeId,
        /// Nabla forwarding this hop. Overwritten on each forward.
        /// Verified against TCP source at receive time.
        intermediate_emitter: NodeId,
        /// TARDIS tick at first emission. Used for 10-tick dedup window
        /// and the "10-tick rolling consensus" semantics.
        emitted_at_tick: u64,
    },

    /// KI#34 check-3: a HAL re-anchor advance (the overlap-relaxed re-activation
    /// path) gossiped with its proof, so the HONEST mesh can detect a revival fork
    /// independent of the (possibly wiped/malicious) processing node. Distinct from
    /// `StateUpdate` on purpose: the handler fork-checks `old_state` against the
    /// node's authoritative `previous_state[W]` BEFORE applying the head (a separate
    /// proof message would race the head-apply, which overwrites `previous_state`).
    /// Carries the same head/fee fields as `StateUpdate` so a non-fork HAL advance
    /// applies identically once the check clears.
    ///
    /// APPENDED AT THE ENUM END ON PURPOSE (KI#34): bincode encodes variants by
    /// positional discriminant, so a new variant must go last — an un-upgraded peer
    /// then still decodes every pre-existing variant correctly, and only HalAdvance
    /// (emitted solely by upgraded nodes, only for HAL re-anchors) is undecodable on
    /// the old binary. Inserting it mid-enum would shift every later discriminant and
    /// corrupt ChequeClaim/Hibernation/BanAlert across a mixed-version window.
    HalAdvance {
        wallet_id: WalletId,
        /// The state this re-anchor CONSUMED (`X` in `X→X'`).
        old_state: StateId,
        new_state: StateId,
        tx_hash: TxHash,
        tick: u64,
        #[serde(default)]
        client_pk: [u8; 32],
        #[serde(default)]
        client_sig: Vec<u8>,
        /// k=3 witness sigs binding `old_state → new_state` — make the conflicting
        /// branch unforgeable + bind `old_state` (the `client_sig` binds only
        /// `new_state`/`tx_hash`). Verified on receipt, never stored.
        k3_signatures: Vec<WitnessSig>,
        #[serde(default)]
        amount: u64,
        #[serde(default)]
        fee_breakdown: Vec<axiom_core_logic::types::FeeShare>,
    },
    /// YPX-022 §2.1 — a sender-initiated RECALL marker, gossiped mesh-wide so a
    /// redeem at any node refuses a recalled txid (first-wins, lowest-tick).
    /// §2.2.1 two-phase: `committed: false` = the RESERVATION flood (initiate;
    /// enables the mesh-wide `RETRACT_PENDING` notice AND the commit landing on
    /// any node); `committed: true` = the hibernation-entry COMMIT flood (the
    /// terminal — only this blocks redeems and enters the garbage chain).
    Recall {
        txid: crate::types::TxHash,
        sender_pk: Vec<u8>,
        recall_tick: u64,
        committed: bool,
    },
}

/// Discriminator for `GossipMessage::Alert` variants. Generic shape so
/// future alert classes can extend without a new wire-format variant.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AlertType {
    /// Pool-state invariant violation: direction (set_balance reject)
    /// or magnitude (D2 sanity-gate reject). Evidence is the CBOR
    /// PoolSync that triggered the violation.
    PoolInvariantViolation,
    // Future: WalAuditFailure, NbcExpired, etc.
}

// ── Group Registration (Phase 3, Section 8) ──

/// Registration for a group wallet — includes member allocation data.
/// All validation rules (share_bps sum, member_pk, checksums) are
/// enforced by Core, not Nabla. Nabla records the result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRegistration {
    pub wallet_id: WalletId,
    pub old_state: StateId,
    pub new_state: StateId,
    pub tx_hash: TxHash,
    pub receipt: K3Receipt,
    pub members: Vec<GroupMemberState>,
    /// Total balance of the group wallet (sum of available must equal this).
    pub balance: u64,
}

// ── TARDIS Types (Section 5) ──

/// Tick message flowing down the TARDIS tree.
/// Per YPX-003 §2.2, every tick carries slot availability information
/// so children always know where open D slots exist in the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickMessage {
    pub number: u64,
    pub upstream_pk: PeerId,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp_ms: u64,
    /// Chain proof: upstream's signature from the tick it received (§1.3.4).
    /// Allows verification that this tick descends from a tree root.
    /// Empty until Core integration provides real signatures.
    #[serde(default)]
    pub prev_sig: Vec<u8>,
    /// Sender's upstream PK — from receiver's POV, this is the GRANDPARENT.
    /// Receiver uses this to (a) look up the grandparent's NBC-bound Ed25519
    /// PK and verify `prev_sig`, and (b) drive the grandpa-tick writer-
    /// integrity rule. None if sender has no upstream (origin / orphan
    /// briefly during reattach) or for backward-compat with older ticks.
    #[serde(default)]
    pub grandparent_pk: Option<PeerId>,
    /// Slot availability piggybacked on tick (§2.2).
    /// List of (node_id, node_index) pairs with known open D slots.
    /// Children use this to instantly reconnect when their parent dies.
    #[serde(default)]
    pub available_slots: Vec<(PeerId, u32)>,
    /// Number of downstream approvals the sender had in the previous round.
    /// A child rejects ticks from parents with < 2 approvals (not a WRITER).
    /// This forces children to detach from degraded parents and find writers.
    /// No exemptions — all nodes follow the same rules (v0.9 §2.16.1).
    #[serde(default)]
    pub downstream_approvals: u8,
    /// Total open D slots in sender's subtree (§2.2, §2.14.5).
    /// Aggregated bottom-up from D1+D2 TickApproval.subtree_open_d.
    /// Used by E-enquiry to locate available parents without global knowledge.
    #[serde(default)]
    pub subtree_d_available: u32,
    // beacon field REMOVED (v0.9 §E6) — parent tick IS the liveness proof.
    // SeedBeacon struct also removed. No separate beacon mechanism needed.
    /// YPX-021 §6 OODS-tardis: the per-channel extrema accumulator riding the
    /// tick. Each node folds its own Core-produced draw in before forwarding
    /// (see `axiom_core_logic::oods_verify::{oods_produce, oods_fold}`); a
    /// fully-cascaded tick's accumulator estimates the tick-tree's size
    /// (`oods_estimate`) — a second, Core-bound OODS to cross-check the Nabla
    /// gossip estimate and flag partitions. Covered by `tick_sign_payload`, so
    /// each forwarder attests the value it propagates. `#[serde(default)]` for
    /// tolerance during a rolling restart (mixed old/new ticks briefly in
    /// flight); empty on a pre-OODS tick.
    #[serde(default)]
    pub oods_tardis: Vec<axiom_core_logic::oods_verify::OodsExtremum>,
    /// TARDIS lineage verification (AXIOM_YPX-003_TARDIS.md §7.6) Phase 2: this node's
    /// downstream child PKs, bound into `tick_commitment`. A child of THIS node appears
    /// here; its grandchildren verify strict-parent (`P ∈ gp_child_pks`) so a node cannot
    /// forge its place in the ring by borrowing a real tick without having been parented.
    #[serde(default)]
    pub child_pks: Vec<PeerId>,
    /// TARDIS lineage verification (§7.6) Phase 2: the GRANDPARENT's commitment fields, so
    /// the receiver recomputes the grandparent's `tick_commitment` and cryptographically
    /// verifies `prev_sig` (the grandparent's signature) against the grandparent's NBC key —
    /// proving this tick descends from a real, fresh, writer lineage that named this node's
    /// parent as a child. Set on the FORWARD path (from the tick this node received); `None`
    /// on a self-originated / bootstrap tick with no upstream lineage.
    #[serde(default)]
    pub gp_commitment: Option<GpCommitment>,
}

/// TARDIS lineage verification (YPX-003 §7.6): the grandparent's `tick_commitment`
/// preimage fields (everything except its `upstream_pk`, which equals the tick's
/// `grandparent_pk`). The receiver recomputes `tick_commitment_fields(...)` from these
/// and verifies `prev_sig` against the grandparent's NBC-bound Ed25519 key.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GpCommitment {
    pub number: u64,
    pub timestamp_ms: u64,
    pub payload: Vec<u8>,
    pub downstream_approvals: u8,
    /// The grandparent's OWN `prev_sig` (a field inside its commitment — no recursion).
    pub prev_sig: Vec<u8>,
    /// The grandparent's child set — for the strict-parent check.
    pub child_pks: Vec<PeerId>,
    /// `H(grandparent's oods_tardis)` — oods attested by hash, not re-carried.
    pub oods_hash: [u8; 32],
}

/// Downstream approval sent back to upstream after verifying a tick.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TickApproval {
    pub tick_number: u64,
    pub approver_pk: PeerId,
    pub signature: Vec<u8>,
    /// Open D slots in this approver's subtree, including self (§2.14.5).
    /// Aggregated: my_open + d1_subtree_open_d + d2_subtree_open_d.
    /// Flows bottom-up through approvals for E-enquiry support.
    #[serde(default)]
    pub subtree_open_d: u32,
}

/// Bottom-up audit: downstream challenges upstream's SMT consistency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubtreeAuditRequest {
    pub prefix: Vec<u8>,
    pub prefix_bits: usize,
    pub request_tick: u64,
    pub requester_pk: PeerId,
}

/// Upstream's response to a subtree audit challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubtreeAuditResponse {
    pub prefix: Vec<u8>,
    pub prefix_bits: usize,
    pub subtree_hash: Hash256,
    pub root_hash: Hash256,
    pub response_tick: u64,
    pub responder_pk: PeerId,
    pub signature: Vec<u8>,
}

/// Alert sent when a node flags its upstream as questionable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionableAlert {
    pub suspect_pk: PeerId,
    pub reporter_pk: PeerId,
    pub tick: u64,
    pub evidence_hash: Hash256,
    pub signature: Vec<u8>,
}

/// Nabla node trust status — tracks NBC verification state.
///
/// New nodes enter Probation (48 hours as LEAF). Genesis nodes skip.
/// Confirmed nodes have passed probation with no duplicate Nabla_id detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NbcTrustStatus {
    /// Genesis node — root of trust, no probation needed.
    Genesis,
    /// Confirmed — NBC verified, probation completed, no duplicate detected.
    Confirmed,
    /// Probation — first-time join, restricted to LEAF for NABLA_PROBATION_SECS.
    /// Contains the TARDIS tick (unix time) when probation started.
    /// Uses virtual time (TARDIS tick), NEVER SystemTime::now().
    Probation { since: u64 },
}

/// Status of a TARDIS connection to upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    /// Upstream is healthy — ticks flowing, audits pass.
    Connected,
    /// Upstream failed an audit — disconnecting, seeking new parent.
    Questionable,
    /// No upstream connection — operating in degraded mode.
    Disconnected,
}

/// Cheque maturity status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ChequeStatus {
    /// Maturity window passed, no conflicts detected.
    Clean,
    /// Not yet mature, or node lacks tick authority.
    /// Default for newly-built RegistrationAck before dispatch-layer overrides
    /// via `check_maturity()`.
    #[default]
    Scarred,
    /// Double-spend detected — wallet is BANNED.
    Rejected,
}

// ── Registration Acknowledgment ──

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistrationAck {
    pub wallet_id: WalletId,
    pub new_state: StateId,
    pub tick: u64,
    pub root_hash: Hash256,
    pub signature: Vec<u8>,
    /// Ed25519 public key of the Nabla node that signed this ACK (32 bytes).
    /// Allows clients to build a NablaConfirmation. Populated at dispatch layer.
    #[serde(default)]
    pub node_pk: Vec<u8>,
    /// NodeId = BLAKE3(sphincs_pk) = nbc.validator_id (32 bytes).
    /// Correct identifier for NablaConfirmation (node_pk is just the signing key).
    #[serde(default)]
    pub node_id: Vec<u8>,
    /// Peer hints for client-side peer discovery. Empty in business logic;
    /// populated at dispatch layer (nabla_node.rs).
    #[serde(default)]
    pub known_peers: Vec<NablaClientPeer>,
    /// NBC trust-anchor: SPHINCS+ root-authority pubkey that signed this
    /// node's NBC. Forwarded to the SDK and into `NablaConfirmation.nbc_issuer_pk`
    /// so Core's `verify_fact_link` can anchor `node_pk` to
    /// `NABLA_ROOT_AUTHORITY_PKS`. Populated at dispatch layer from
    /// `node.own_nbc_bytes`. KI#8 strengthening, 2026-05-15.
    #[serde(default)]
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature by `nbc_issuer_pk` over BLAKE3(nbc_commitment).
    /// See `verify_nbc_for_nabla_confirmation` in core/logic/src/validation.rs.
    #[serde(default)]
    pub nbc_signature: Vec<u8>,
    /// NBC canonical pre-image bytes. The Nabla node's Ed25519 pubkey
    /// (`node_pk` in this struct) MUST appear as a 32-byte window inside.
    /// Phase 5f binding fix pattern — see `verify_nbc_for_txid_attestation`.
    #[serde(default)]
    pub nbc_commitment: Vec<u8>,
    /// YPX-021 §8.2 — the writer's current signed OODS reading, folded into
    /// this register ACK the client already receives (no separate client→Nabla
    /// query — AXIOM Origin 2026-07-03). The SDK caches it and carries it into the
    /// NEXT send/redeem's Core inputs, where Core stamps `Receipt.oods_flag`.
    /// `None` when the node has no NBC loaded. Populated at the dispatch layer
    /// (nabla_node.rs) from `state.build_oods_attestation()`.
    #[serde(default)]
    pub oods_attestation: Option<axiom_core_logic::types::NablaOodsAttestation>,
    /// TARDIS depth (YPX-021 §6) — this witnessing node's depth in the tick tree,
    /// informational (NOT Core-verified, so it touches no commitment or CoreID).
    /// The `oods_estimate` off this node's latest TARDIS tick down-cascade
    /// accumulator = the count of verified writers in its lineage from the root,
    /// for the wallet to display next to the Nabla network size (OODS-gossip).
    /// 0 until the first tick. Not folded into `compute_oods_attestation_payload`,
    /// so a hostile Nabla could lie — a display reference, not a gate.
    #[serde(default)]
    pub tardis_depth: u32,
    /// Whether ZKP execution proofs were cryptographically verified (STARK).
    /// True = all non-empty proofs passed RISC Zero STARK verification.
    /// False = no proofs were present (bootstrap/legacy — will be rejected in future).
    #[serde(default)]
    pub zkp_verified: bool,
    /// Cheque maturity status at time of registration.
    /// Clean = maturity window passed, Scarred = not yet mature.
    #[serde(default = "default_cheque_status")]
    pub cheque_status: ChequeStatus,
    /// Server wire-protocol version. Incremented when the wire format
    /// adds new error codes / fields a client wallet needs to know
    /// about to render correct UI. SDK reads this on every ACK; if
    /// `min_client_protocol_version` (below) exceeds the SDK's baked
    /// `CLIENT_PROTOCOL_VERSION`, the wallet is too old and should
    /// surface an "Update required" prompt to the user.
    #[serde(default = "default_server_protocol_version")]
    pub server_protocol_version: u32,
    /// Minimum client protocol version this server still talks to.
    /// Older SDKs receiving an ACK with `min_client > their version`
    /// should refuse to continue and surface
    /// `ErrorCode::SdkVersionTooOld` so the user can update.
    #[serde(default = "default_min_client_protocol_version")]
    pub min_client_protocol_version: u32,
    /// FACT confirmation Ed25519 signature over:
    ///   BLAKE3("AXIOM_FACT_CONFIRM" || BLAKE3("AXIOM_TXHASH" || old_state || new_state) || new_state)
    /// Core verifies this to ensure the NablaConfirmation is authentic.
    /// Computed at registration time using the same state IDs stored in the SMT.
    #[serde(default)]
    pub fact_confirm_signature: Vec<u8>,
}

fn default_cheque_status() -> ChequeStatus {
    ChequeStatus::Scarred
}

/// Current server-side wire-protocol version. Bump when the wire format
/// adds new error codes / fields a client wallet needs to know about
/// (e.g. the Phase A pool-cap E_POOL_CAP_PER_NABLA / _MESH / _EXHAUSTED
/// codes added 2026-05-26 — version 2 first introduces those).
pub const SERVER_PROTOCOL_VERSION: u32 = 2;

/// Minimum client protocol version this server still talks to. Bump
/// when a wire-format change actually requires older clients to fail
/// rather than degrade silently. v1 clients did not know the
/// `E_POOL_CAP_*` reasons; they parsed the rejection string but
/// surfaced it as a generic error, which is acceptable degradation
/// — so for now keep min_client at 1 and only bump when a future
/// change is genuinely breaking.
pub const MIN_CLIENT_PROTOCOL_VERSION: u32 = 1;

fn default_server_protocol_version() -> u32 { 1 }
fn default_min_client_protocol_version() -> u32 { 1 }

// ── Errors ──

#[derive(Debug, Error)]
pub enum NablaError {
    #[error("invalid DEED payment")]
    InvalidDeedPayment,
    #[error("invalid DEED destination: expected protocol or implementation wallet")]
    InvalidDeedDestination,
    #[error("invalid k=3 receipt: signature verification failed")]
    InvalidReceipt,
    #[error("state mismatch: registration does not match receipt")]
    StateMismatch,
    #[error("wallet is BANNED")]
    WalletBanned,
    #[error("double-spend detected: conflicting state transition")]
    DoubleSpendDetected,
    /// YPX-022 §2.2.1 — an `is_recall` register arrived with no open recall
    /// reservation for this wallet: the receiver's redeem finalized during
    /// the reservation window and WON (first-wins), or nothing was reserved.
    /// The recall self-send fails closed — the payment stands.
    #[error("recall aborted: the cheque was redeemed while the recall was in progress — the payment stands (fail-closed, first-wins)")]
    RecallAborted,
    /// FACT class isolation: `is_dev_claim` flag disagrees with the
    /// `is_dev_wallet(claimant_wallet_id)` check, or `claimant_wallet_id`
    /// isn't pk-bound to the receipt's wallet pk. Refuse the claim —
    /// neither pool moves (`AXIOM_DESIGN_FactClassIsolation.md` §6).
    #[error("class-signal mismatch: claimant_wallet_id / is_dev_claim / pk_bind disagree")]
    ClassSignalMismatch,
    /// FACT class isolation: dev-class pool is drained. 1M dev-AXC
    /// is fixed; no minting authority means no replenishment. Public
    /// Airdrop pool can also reach this state.
    #[error("pool exhausted — no more claims available for this class")]
    PoolExhausted,
    /// Phase A per-Nabla cycle cap reached on the receiving Nabla.
    /// Client can retry the genesis-claim register on a DIFFERENT
    /// Nabla — every Nabla maintains its own independent cycle
    /// counter, so a sibling may still have headroom.
    /// `reset_tick` is when this Nabla's local counter rolls.
    #[error("per-Nabla cycle cap reached on this node — retry on a different Nabla (reset at tick {reset_tick})")]
    PoolCapPerNabla { reset_tick: u64 },
    /// Mesh-wide cycle cap reached. NO Nabla in the mesh can grant
    /// a claim until the cycle resets. Client must wait.
    /// `reset_tick` is the mesh-wide reset moment.
    #[error("mesh-wide cycle cap reached — retry after cycle reset at tick {reset_tick}")]
    PoolCapMesh { reset_tick: u64 },
    #[error("SMT error: {0}")]
    SmtError(String),
    #[error("WAL error: {0}")]
    WalError(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("snapshot error: {0}")]
    SnapshotError(String),
    // ── TARDIS errors (Phase 2) ──
    #[error("non-sequential tick: expected {expected}, got {got}")]
    NonSequentialTick { expected: u64, got: u64 },
    #[error("invalid tick signature from upstream")]
    InvalidTickSignature,
    #[error("tick timing violation: drift {drift_ms}ms exceeds buffer")]
    TickTimingViolation { drift_ms: i64 },
    #[error("no upstream connection — operating in degraded mode")]
    NoUpstream,
    #[error("upstream flagged questionable — audit failed")]
    UpstreamQuestionable,
    #[error("subtree audit failed: proof does not match root")]
    AuditFailed,
    // ── Group Wallet errors (Phase 3) ──
    #[error("group wallet checksum failed: sum(available) != balance")]
    GroupChecksumFailed,
    #[error("member not found in group wallet")]
    MemberNotFound,
    #[error("not a group wallet")]
    NotGroupWallet,
    // ── CC and Runner errors (Phase 5) ──
    #[error("CC chain integrity broken")]
    CcChainBroken,
    #[error("claim cooldown active (one per 24 hours)")]
    ClaimCooldownActive,
    #[error("insufficient pool balance")]
    InsufficientPoolBalance,
    /// SEC-05: the runner-pool payout path is disabled because the CC
    /// contribution score is self-reported and self-signed (no k-witnessed
    /// counts, no Core-mediated CC proof). Any economic split off `cc.score`
    /// fails closed until the attestation is wired. See SEC-05.
    #[error("CC payout disabled: contribution score is self-attested (SEC-05) — pending k-witnessed counts")]
    CcPayoutSelfAttested,
    // ── NBC verification errors (Phase 6) ──
    #[error("NBC missing: {0}")]
    NbcMissing(String),
    #[error("NBC expired: expires_at {expires_at} < current tick {current_tick}")]
    NbcExpired { expires_at: u64, current_tick: u64 },
    #[error("NBC identity mismatch: validator_id does not match BLAKE3(sphincs_pk)")]
    NbcIdentityMismatch,
    #[error("NBC malformed: {0}")]
    NbcMalformed(String),
    #[error("NBC signature invalid: SPHINCS+ verification failed")]
    NbcSignatureInvalid,
    #[error("NBC issuer not root: chain_depth=0 but issuer not in NABLA_ROOT_AUTHORITY_PKS")]
    NbcIssuerNotRoot,
    // ── ZKP verification errors ──
    #[error("invalid ZKP execution proof: {0}")]
    InvalidProof(String),
    // ── Ban challenge errors (S6) ──
    #[error("wallet is not banned")]
    WalletNotBanned,
    #[error("ban already challenged")]
    BanAlreadyChallenged,
    #[error("ban already reversed")]
    BanAlreadyReversed,
    #[error("insufficient challenge endorsements: need {need}, got {got}")]
    InsufficientEndorsements { need: usize, got: usize },
    #[error("invalid challenge endorsement signature")]
    InvalidEndorsementSignature,
    #[error("duplicate endorser node_id in challenge")]
    DuplicateEndorser,
    // ── NBC renewal errors ──
    #[error("NBC renewal rejected: {0}")]
    NbcRenewalRejected(String),
    // ── WAL audit errors (YPX-009 §12) ──
    #[error("WAL corruption detected at sequence {sequence}")]
    WalCorruption { sequence: u64 },
    #[error("WAL repair failed after {retries} attempts")]
    WalRepairFailed { retries: u32 },
}

// ── State Sync Types (YPX-009 §12.8) ──

/// StatePull mode: Bootstrap (full initial pull) or WalVerify (section hash comparison).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StatePullMode {
    /// Full initial state pull for new/recovering nodes.
    Bootstrap,
    /// Section hash comparison for WAL cross-verification.
    WalVerify,
}

/// A single state entry transferred during StatePull/RangeSync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatePullEntry {
    pub wallet_id: WalletId,
    pub new_state: StateId,
    pub tx_hash: TxHash,
    pub tick: u64,
    /// WI3: k-witnessed chain position, carried so a bootstrapping/recovering
    /// node rebuilds `NablaEntry.wallet_seq` (and re-arms its anti-rollback
    /// order — WI1) instead of coming back seq-blind. No serde(default).
    pub wallet_seq: u64,
    pub client_pk: [u8; 32],
    pub client_sig: Vec<u8>,
    /// WI3 hole-1: the k=3 attestation of `wallet_seq` (`None` on no-proof
    /// paths). A bootstrapping node replays each entry through the merge gate,
    /// which requires this proof before adopting a non-zero seq — so a wiped
    /// node recovers a VERIFIED seq, not a forgeable one.
    pub seq_proof: Option<SeqProof>,
}

/// Result of a WAL section hash comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalVerifyResult {
    /// Section hashes match — no divergence.
    Match,
    /// Section hashes differ — need RangeSync.
    Mismatch,
    /// Peer doesn't have entries in this range.
    Missing,
}

/// Result of a RangeSync section comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RangeSyncMatch {
    /// Section hashes match.
    Match,
    /// Section hashes differ — entries included in response.
    Mismatch,
    /// Peer doesn't have this section.
    Missing,
}

// ── Anti-entropy merge rule tests (AXIOM_DESIGN_NablaAntiEntropy.md §5.2) ──

#[cfg(test)]
mod merge_tests {
    use super::*;

    fn entry(tick: u64, state: u8, status: WalletStatus) -> NablaEntry {
        NablaEntry {
            wallet_seq: 0,
            wallet_id: [1u8; 32],
            current_state: [state; 32],
            tx_hash: [9u8; 32],
            tick,
            group_members: None,
            status,
            client_pk: [2u8; 32],
            client_sig: vec![0u8; 64],
        }
    }

    // ── WI3 hole-1: SeqProof ──

    /// Mint a `SeqProof` over `(txid, wallet_seq)` signed by `n` distinct real
    /// Ed25519 validators — the same commitment the register path verifies.
    fn mint_seq_proof(txid: &TxHash, wallet_seq: u64, n: usize) -> SeqProof {
        use ed25519_dalek::{Signer, SigningKey};
        let state_hash = [0x5a_u8; 32];
        let commitment_hash = [0x7c_u8; 32];
        let epoch = 7u64;
        let is_dev_class = false;
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            txid, &state_hash, wallet_seq, &commitment_hash, epoch, is_dev_class, None,
        );
        let sigs = (0..n)
            .map(|i| {
                let sk = SigningKey::from_bytes(&[0x10 + i as u8; 32]);
                SeqProofSig {
                    validator_pk: sk.verifying_key().to_bytes(),
                    receipt_commitment_sig: sk.sign(&commitment).to_bytes().to_vec(),
                }
            })
            .collect();
        SeqProof { state_hash, commitment_hash, epoch, is_dev_class, oods_flag: None, sigs }
    }

    #[test]
    fn seq_proof_verifies_genuine_k_attestation() {
        use crate::registration::verify_seq_proof;
        let txid = [0xab_u8; 32];
        let p = mint_seq_proof(&txid, 5, 3);
        // Verifies for the exact (txid, seq) the validators signed.
        assert!(verify_seq_proof(&p, &txid, 5), "genuine k=3 attestation must verify");
        // A different seq breaks the commitment → fails (a self-bumped seq can't
        // ride a real proof minted for another seq).
        assert!(!verify_seq_proof(&p, &txid, 6), "seq the validators did not sign must fail");
        // A different txid breaks the commitment too.
        assert!(!verify_seq_proof(&p, &[0xcd_u8; 32], 5), "wrong txid must fail");
    }

    #[test]
    fn seq_proof_rejects_subquorum_and_forgery() {
        use crate::registration::verify_seq_proof;
        let txid = [0xab_u8; 32];
        // Only 2 distinct validators — below MIN_FACT_WITNESSES (3).
        let p2 = mint_seq_proof(&txid, 5, 2);
        assert!(!verify_seq_proof(&p2, &txid, 5), "sub-quorum (k<3) must fail");
        // A self-stamped proof: random 64-byte garbage sigs, real-looking pks.
        let forged = SeqProof {
            oods_flag: None,
            state_hash: [0x5a; 32],
            commitment_hash: [0x7c; 32],
            epoch: 7,
            is_dev_class: false,
            sigs: (0..3)
                .map(|i| SeqProofSig {
                    validator_pk: [0x20 + i as u8; 32],
                    receipt_commitment_sig: vec![0u8; 64],
                })
                .collect(),
        };
        assert!(!verify_seq_proof(&forged, &txid, 5), "forged sigs must fail");
    }

    #[test]
    fn higher_tick_supersedes() {
        let a = entry(10, 1, WalletStatus::Normal);
        let b = entry(11, 1, WalletStatus::Normal);
        assert!(a.superseded_by(&b));
        assert!(!b.superseded_by(&a));
    }

    #[test]
    fn same_tick_higher_state_wins() {
        let a = entry(10, 1, WalletStatus::Normal);
        let b = entry(10, 2, WalletStatus::Normal);
        assert!(a.superseded_by(&b));
        assert!(!b.superseded_by(&a));
    }

    #[test]
    fn identical_entry_does_not_supersede() {
        let a = entry(10, 1, WalletStatus::Normal);
        let b = entry(10, 1, WalletStatus::Normal);
        assert!(!a.superseded_by(&b));
        assert!(!b.superseded_by(&a));
    }

    #[test]
    fn rollback_fork_loses_by_kseq_despite_higher_tick() {
        // THREAT: AXIOM_THREAT_CollusionWipeRevival.md §5.4 — CLOSED by WI3.
        //
        // The merge now orders by k-witnessed `wallet_seq` (chain position)
        // BEFORE `tick`. Scenario: an honest wallet spent X->Y (head Y is further
        // along the chain — seq 5, network tick 480) then went idle. An attacker
        // (colluding/wiped node) re-anchors a FORK off ancestor X (chain position
        // seq 3 — strictly LOWER) and stamps it with the *current*, later tick
        // 500. Pre-WI3 the later tick won (tick-max picked the fraud); with
        // seq-ordering the fork's lower seq loses regardless of when it was stamped.
        let mut honest_head = entry(480, 0x22, WalletStatus::Normal); // Y
        honest_head.wallet_seq = 5;
        let mut fraud_fork = entry(500, 0x99, WalletStatus::Normal); // X' (ancestor branch)
        fraud_fork.wallet_seq = 3;

        // The later-but-lower-seq fork does NOT supersede the honest head.
        assert!(
            !honest_head.superseded_by(&fraud_fork),
            "WI3: an ancestor-fork (lower k-seq) must NOT supersede the honest head, \
             even with a higher (later) tick."
        );
        // And the honest head DOES supersede the fork (higher k-seq wins).
        assert!(
            fraud_fork.superseded_by(&honest_head),
            "WI3: the honest head (higher k-seq) supersedes the lower-seq fork."
        );
    }

    #[test]
    fn equal_seq_falls_through_to_tick() {
        // When chain positions are equal (legacy / group / conf paths that
        // preserve the seq), the merge still orders by tick — the seq rule only
        // bites when the positions genuinely differ, so existing tick behaviour
        // is preserved for everything else.
        let a = entry(480, 0x22, WalletStatus::Normal); // seq 0
        let b = entry(500, 0x99, WalletStatus::Normal); // seq 0
        assert!(a.superseded_by(&b), "equal seq → higher tick wins");
    }

    #[test]
    fn freeze_dominates_normal_regardless_of_tick() {
        // A frozen entry at a LOWER tick still wins over a higher-tick
        // Normal — §32 freeze monotonicity: a fork-frozen wallet is
        // never demoted back to Normal by a later state update.
        let normal_new = entry(100, 5, WalletStatus::Normal);
        let frozen_old = entry(1, 1, WalletStatus::Frozen);
        assert!(normal_new.superseded_by(&frozen_old));
        assert!(!frozen_old.superseded_by(&normal_new));
    }

    #[test]
    fn merge_order_is_antisymmetric() {
        let samples = [
            entry(10, 1, WalletStatus::Normal),
            entry(10, 2, WalletStatus::Normal),
            entry(11, 1, WalletStatus::Normal),
            entry(5, 9, WalletStatus::Frozen),
        ];
        for a in &samples {
            for b in &samples {
                let (ab, ba) = (a.superseded_by(b), b.superseded_by(a));
                assert!(!(ab && ba), "merge order must be antisymmetric");
                if a == b {
                    assert!(!ab && !ba, "equal entries must not supersede");
                }
            }
        }
    }

    #[test]
    fn merge_max_is_order_independent() {
        // Folding the merge over any permutation yields the same winner —
        // the semilattice-join property that converges the mesh regardless
        // of gossip arrival order.
        let a = entry(10, 1, WalletStatus::Normal);
        let b = entry(12, 3, WalletStatus::Normal);
        let c = entry(7, 9, WalletStatus::Frozen); // freeze dominates
        let pick = |x: &NablaEntry, y: &NablaEntry| -> NablaEntry {
            if x.superseded_by(y) { y.clone() } else { x.clone() }
        };
        let w1 = pick(&pick(&a, &b), &c);
        let w2 = pick(&pick(&c, &a), &b);
        let w3 = pick(&pick(&b, &c), &a);
        assert_eq!(w1, w2);
        assert_eq!(w2, w3);
        assert_eq!(w1.status, WalletStatus::Frozen);
    }
}
