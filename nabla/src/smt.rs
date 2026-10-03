// AXIOM Nabla — Sparse Merkle Tree
// Reference: AXIOM_GUIDE_Nabla.md Section 2
//
// Phase 1 Tasks:
//   1. SMT implementation (insert, update, lookup, root_hash)
//   2. Path compression (empty subtree hashes, only store populated paths)
//
// Design:
//   - Key: wallet_id (256-bit), maps to tree path
//   - Value: NablaEntry (serialized)
//   - Root: BLAKE3 hash of tree root — this IS the root_hash for
//     partition detection and gossip comparison
//   - Empty subtrees: precomputed constant hashes at each depth
//   - Only populated paths are stored (path compression)
//   - In-memory operation; persistence via WAL + snapshots (separate modules)

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::bloom::{TxidBloomFilter, TxidServiceMode, DEFAULT_BLOOM_EXPECTED_ITEMS};
use crate::constants::SMT_EMPTY_LEAF_LABEL;
use crate::types::{
    ForkLeg, Hash256, MerkleProof, NablaEntry, OriginLedgerEntry, SeqProof, StateId, TxHash, TxRecord, WalletId,
};
#[cfg(test)]
use crate::types::WalletStatus;

// YPX-022 §2.1.2a item 2 (KI#205, RULED 2026-09-25): the fixed 17,280-tick
// claim expiry (`CHEQUE_CLAIM_EXPIRY_TICKS`) was DELETED here. It evicted the
// claim BEFORE the recall window opened at 18,000, so `register_recall` could
// never read it — one of the three reasons a payment settled twice. A claim now
// lives exactly as long as a recall is possible: see `claim_is_stale`.

/// YPX-010 §14 — longest claim chain kept per wallet.
///
/// Deliberately the SAME number as Core's `MAX_UNRESOLVED_SCARS`: a wallet
/// cannot legitimately hold more unresolved links than the scar cap, so a
/// longer chain could never be drained anyway. Two independent numbers here
/// would drift apart and the drift would be silent.
const MAX_CLAIM_CHAIN: usize = axiom_core_logic::validation::MAX_UNRESOLVED_SCARS;

/// YPX-010 §14 — one entry in a wallet's ordered claim chain.
///
/// The chain is a WORKLIST, not a reservation: it records the sequence of
/// cheques a wallet has claimed and whether each is backed by a registered
/// sender. It is re-derived on every touch (the client's next claim or
/// redeem), so an entry that was not ready becomes ready the moment its sender
/// registers, with no timer and no background scan.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClaimChainEntry {
    /// The claimed cheque (== the sender's txid).
    pub cheque_id: TxHash,
    /// Tick the claim first entered the chain — the ordering key.
    pub first_claim_tick: u64,
    /// Was the SENDER's transaction registered here, as of the last touch?
    /// Re-evaluated on every touch; never cached as final.
    pub sender_registered: bool,
}

/// Cheque claim registration state — YPX-022 §2.1.2a (KI#205): the
/// AUTHENTICATED claim is the delivery terminal `register_recall` reads.
/// Registered before every online redeem (Core CL5 requires the proof it
/// mints); flooded to the mesh (`GossipMessage::ChequeClaimAnnounce`) and
/// re-verified by every node that applies it (`registration::verify_cheque_claim`).
/// First-wins rule: the claim with the lowest tick is authoritative.
/// Serialize/Deserialize: rides `NablaSnapshot` (a restart must not forget a
/// delivery, or the sender's recall would be granted after the receiver had
/// the cheque).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChequeClaim {
    /// Ed25519 public key of the client who claimed this cheque.
    pub client_pk: Vec<u8>,
    /// The claimant's STATE-CLASS k (YPX-010 §14) — with `client_pk` it
    /// names the claimant's SMT bucket. Bound into `claim_sig`.
    pub k_tier: u8,
    /// The claimant's wallet address. Its class (`is_dev_wallet`) selects the
    /// recall window this claim must outlive. Bound into `claim_sig`.
    pub wallet_address: String,
    /// The claimant's Ed25519 signature over
    /// `crypto::cheque_claim_signing_payload(cheque_id, client_pk, k_tier,
    /// wallet_address)` — verified BEFORE storage; covered by the Nabla
    /// signature on the `ChequeClaimProof` so Core CL5 binds the same bytes.
    pub claim_sig: Vec<u8>,
    /// Virtual tick when the claim was registered.
    pub claim_tick: u64,
}

impl ChequeClaim {
    /// ONE constructor from the wire request (TCP path) or the flooded
    /// announce (gossip path rebuilds the same request type) — the fields
    /// are copied, never re-derived; `claim_tick` is the tick the claim was
    /// MADE (see `register_cheque_claim`).
    pub fn from_request(
        req: &axiom_core_logic::wire_client::RegisterChequeClaimRequest,
        claim_tick: u64,
    ) -> Self {
        ChequeClaim {
            client_pk: req.client_pk.clone(),
            k_tier: req.k_tier,
            wallet_address: req.wallet_address.clone(),
            claim_sig: req.claim_sig.clone(),
            claim_tick,
        }
    }
}

/// YPX-022 §2.2.1 — the recall's two phases. Initiate is a RESERVATION
/// (`C` stays live and redeemable; query-txid serves an unsigned
/// `RETRACT_PENDING` notice); the recall self-send's registration — the same
/// event that stamps the hibernation lock — is the COMMIT (point of no
/// return: terminal marker + garbage insert + committed gossip flood).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RecallPhase {
    /// Reserved at initiate. NOT yet blocking redeems; a redeem that
    /// finalizes first WINS and deletes the reservation.
    Reserved,
    /// Committed at hibernation-entry. The terminal — blocks redeems forever.
    Committed,
}

/// YPX-022 §2.1 — a sender-initiated RECALL marker (consume-once, first-wins).
/// Only the SENDER may recall their own send; keyed by the send's txid.
/// Serialize/Deserialize: rides `NablaSnapshot` (YPX-022 §5 — a restart must
/// never forget a recall).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecallMarker {
    /// Ed25519 public key of the SENDER who recalled this txid.
    pub sender_pk: Vec<u8>,
    /// Virtual tick when the recall was registered.
    pub recall_tick: u64,
    /// §2.2.1 — reservation vs terminal commit.
    pub phase: RecallPhase,
}

/// YPX-022 §2 — RECALL initiation window. A recall may be initiated only when the send
/// has aged into `[LOW, HIGH]` ticks: LOW is the receiver's protected redeem window
/// (recall opens only AFTER it, so the redeem outcome is settled); HIGH closes the
/// affordance. dev-mode uses a compressed window so smokes can exercise both bounds.
/// Single source: protocol_core.toml `[timing]` via core-logic (2026-07-07
/// consolidation — values unchanged; NEVER redeclare here).
pub use axiom_core_logic::types::{RECALL_INIT_WINDOW_LOW, RECALL_INIT_WINDOW_HIGH};

/// Depth of the sparse merkle tree (256-bit keys).
const TREE_DEPTH: usize = 256;

/// Precomputed empty subtree hashes for each depth level.
/// EMPTY_HASH[0] = BLAKE3("AXIOM_SMT_EMPTY_LEAF")
/// EMPTY_HASH[d] = BLAKE3(EMPTY_HASH[d-1] || EMPTY_HASH[d-1])
///
/// These represent "nothing here" at each level, enabling path compression.
fn compute_empty_hashes() -> Vec<Hash256> {
    let mut hashes = vec![[0u8; 32]; TREE_DEPTH + 1];
    // Empty-leaf domain is already distinct from real leaves (which carry
    // the SMT_LEAF_DOMAIN prefix), so an empty node can never collide with
    // a populated leaf — non-inclusion is unambiguous (SEC-16).
    hashes[0] = blake3::hash(SMT_EMPTY_LEAF_LABEL).into();
    for d in 1..=TREE_DEPTH {
        // Internal empties MUST use the same domain-separated combine as
        // hash_internal, or empty-subtree hashes won't match recomputed
        // internal hashes during proof verification.
        hashes[d] = hash_internal(&hashes[d - 1], &hashes[d - 1]);
    }
    hashes
}

/// We use OnceLock for lazy initialization of empty hashes.
/// Computed on first access, then cached for the process lifetime.
static EMPTY_HASHES: std::sync::OnceLock<Vec<Hash256>> = std::sync::OnceLock::new();

fn empty_hash(depth: usize) -> Hash256 {
    EMPTY_HASHES.get_or_init(compute_empty_hashes)[depth]
}

/// Get the bit at position `bit_index` in a 256-bit key.
/// bit_index 0 = MSB of byte 0.
#[inline]
fn get_bit(key: &[u8; 32], bit_index: usize) -> u8 {
    let byte_idx = bit_index / 8;
    let bit_idx = 7 - (bit_index % 8);
    (key[byte_idx] >> bit_idx) & 1
}

/// SEC-16: domain-separation prefixes so a leaf hash can never be confused
/// with an internal-node hash (second-preimage / node-type confusion). A
/// 1-byte tag is prepended to every hash input. Without it, an attacker
/// could craft a 64-byte leaf `value` equal to some `left || right` and make
/// a leaf hash collide with an internal node.
const SMT_LEAF_DOMAIN: u8 = 0x00;
const SMT_INTERNAL_DOMAIN: u8 = 0x01;

/// Load-shedding (see `docs/AXIOM_DESIGN_NablaAntiEntropy.md`
/// §"Gossip/AE flood load-shedding"): maximum `previous_states` entries merged
/// per `merge_previous_states` call, so an oversized StatePull payload cannot
/// hold the single global node lock for an unbounded loop. Honest mesh
/// snapshots are far below this; overflow re-applies harmlessly next StatePull.
pub const AE_MERGE_MAX_BATCH: usize = 4096;

/// Hash a leaf node: BLAKE3(0x00 || key || value).
fn hash_leaf(key: &[u8; 32], value: &[u8]) -> Hash256 {
    let mut input = Vec::with_capacity(1 + 32 + value.len());
    input.push(SMT_LEAF_DOMAIN);
    input.extend_from_slice(key);
    input.extend_from_slice(value);
    blake3::hash(&input).into()
}

/// Hash an internal node: BLAKE3(0x01 || left || right).
fn hash_internal(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut combined = [0u8; 65];
    combined[0] = SMT_INTERNAL_DOMAIN;
    combined[1..33].copy_from_slice(left);
    combined[33..].copy_from_slice(right);
    blake3::hash(&combined).into()
}

// ── Tree Node ──

#[derive(Debug, Clone)]
enum TreeNode {
    /// Leaf: actual wallet entry.
    Leaf {
        key: WalletId,
        _value: Vec<u8>, // serialized NablaEntry
        hash: Hash256,
    },
    /// Internal: hash of children. Children may be absent (empty subtree).
    Internal {
        left: Option<Box<TreeNode>>,
        right: Option<Box<TreeNode>>,
        hash: Hash256,
    },
}

impl TreeNode {
    fn hash(&self) -> Hash256 {
        match self {
            TreeNode::Leaf { hash, .. } => *hash,
            TreeNode::Internal { hash, .. } => *hash,
        }
    }
}

// ── Sparse Merkle Tree ──

/// Sparse Merkle Tree for wallet state storage.
///
/// Key: wallet_id (256-bit), maps to tree path.
/// Value: NablaEntry (serialized via bincode).
/// Root: BLAKE3 hash of tree root — this IS the root_hash for
///       partition detection and gossip comparison.
///
/// Only populated paths are stored. Empty subtrees are represented by
/// precomputed constant hashes at each depth level.
/// Consumed states expected per 90-day era, used to size each era's filter.
///
/// KI#42: this must NOT simply inherit `BloomChain::new_default` (1 M/era at the
/// filter's built-in 14.4 bits/item). Union across eras multiplies exposure —
/// `1-(1-p)^E` — and 14.4 bits/item yields ~0.099 % per era, which over ~40 eras
/// is **3.9 % aggregate**: the very problem the migration exists to remove, rebuilt
/// in a new shape. Over-provisioning by 4/3 buys ~19.2 bits per real item, taking
/// the per-era rate to ~0.012 % and the 40-era union to ~0.49 %.
///
/// OPEN: the base figure (1 M consumed states per 90 days) is a placeholder, not a
/// measured or agreed throughput. It is the same unanswered question KI#42 raises
/// about the original 10 M — nobody has written down the intended ops/day. Revisit
/// with a real estimate before mainnet; the constant is compile-time and identical
/// on every node, so it can be changed at a coordinated release boundary (and MUST
/// only change that way — divergent per-era sizing breaks merge mesh-wide).
/// Sourced from `nabla/protocol_nabla.toml` via build.rs — a TUNING REGISTER, not
/// a `const` to be edited in `.rs` (project rule: values are edited in the toml
/// before compile). The toml carries the full error-rate table and the
/// change-only-at-a-release-boundary warning.
const CONSUMED_ERA_EXPECTED_ITEMS: u64 =
    crate::constants::CONSUMED_ERA_REAL_ITEMS * 4 / 3;
/// Same, for the txid chain.
const TXID_ERA_EXPECTED_ITEMS: u64 = crate::constants::TXID_ERA_REAL_ITEMS * 4 / 3;

/// §5.2.4 (KI#123) — why a head legitimately carries no k=3 proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProoflessKind {
    /// Group wallets carry `wallet_seq: 0` and their own GroupUpdate seq
    /// wire; there is no per-head k=3 seq attestation (§5.2.1 exemption).
    GroupWallet,
    /// Adopted per the §5.2.3 merge with no verifiable proof carried — an
    /// equal-seq tick-tiebreak winner or a first-sight seq-0 entry. KI#77's
    /// one-directional ruling makes such adoption legitimate (blocking it
    /// froze legitimate progress live on 2026-08-07); the proof-absence
    /// afterwards is the TRUE retention state, not a loss. Note a seq
    /// ADVANCE without a proof never reaches `put` at all — both read paths
    /// reject it upstream (`[FLOOD-REJECT]`/`[AE-REJECT]` seq-unattested).
    MergeWinner,
}

/// §5.2.4 (KI#123, 2026-08-28) — the proof disposition every production head
/// write must declare. §5.2.3's rank 1c made attestedness a REQUIRED argument
/// because "a caller that silently assumed 'attested' IS this defect"; proof
/// RETENTION gets the same treatment. See [`SparseMerkleTree::put_with_proof`].
#[derive(Debug, Clone)]
pub enum PutProof {
    /// Caller holds the verified k=3 proof for the NEW head; installed
    /// atomically with it (no delete-then-forget window exists at all).
    Attested(SeqProof),
    /// This head class legitimately has no k-proof — see [`ProoflessKind`].
    ProoflessByDesign(ProoflessKind),
    /// Status/ban flip on the SAME head. Asserts `old.tx_hash == new.tx_hash`
    /// (fail closed — a "status flip" that changes the tx is a caller bug);
    /// the retained proof is kept by the KI#38 lock-step.
    SameHeadStatusChange,
    /// Boot-time replay of this node's own trusted state (snapshot / WAL),
    /// carrying whatever the persisted record carried.
    RestoredFromLocalState(Option<SeqProof>),
}

/// ForkSettlement §2.3 — the ATRAXI key of an origin record: `(registrant
/// client_pk, consumed state)`, both taken from the VERIFIED preimage. Not
/// `atraxi::AtraxiKey = (WalletId, state)` (binary-only, in-memory — plan A8).
pub type OriginKey = ([u8; 32], StateId);

/// Fork Settlement W7b (spec R52c) — one member of the SHARED `(pk, consumed)`
/// fork index: which ledger holds it and its txid (for a redeem, the CHEQUE
/// txid it registers under — unique under its key, since `(pk, consumed)` IS
/// the rest of a redeem record's identity). `Send < Redeem`, then by txid, so
/// "the lowest leg" is deterministic on every node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LegRef {
    /// A send leg — its record is in `origin_ledger[txid]`.
    Send(TxHash),
    /// A redeem leg of cheque `txid` — its record is in
    /// `redeem_ledger[(key, txid)]`, never in `origin_ledger` (R5).
    Redeem(TxHash),
}

/// Fork Settlement W7b — a redeem record's identity: its `(receiver_pk,
/// consumed)` key and the cheque txid it redeems. (The spec's
/// `HashMap<(receiver_pk, consumed), …>` holds ONE record per key, which
/// could not keep BOTH legs of the very redeem fork it exists to detect —
/// the cheque txid completes the identity.)
pub type RedeemRecordId = (OriginKey, TxHash);

/// What `SparseMerkleTree::record_verified_leg` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginOutcome {
    /// A new record was born; `contested` is its [R16] birth flag.
    Created { contested: bool },
    /// The txid was already recorded — write-once, nothing changed
    /// (`first_seen_secs` and `contested` are immutable). An honest retry
    /// (KI#68 / #204) reuses its txid and lands here, never in `Conflict`.
    Duplicate,
    /// The key already held ≥ 1 DIFFERENT leg (send or redeem — the shared
    /// index, W7b): the new record IS inserted too, and `held` returns the
    /// previously-held entries (ascending [`LegRef`]) so the caller can
    /// assemble the `ForkClaim` (both legs in hand) — [R10].
    Conflict { held: Vec<OriginLedgerEntry> },
    /// Fork Settlement §9o [R58] (record-AE only — `record_verified_leg_opt`
    /// with an `upgrade` grade): the held copy of this leg was UNGRADED and
    /// the new copy is GRADED with an equal `new_state` and `client_sig` (the
    /// same leg, a different witness subset). The leg was replaced IN PLACE;
    /// `first_seen_secs` and `contested` KEPT; re-queued for the WAL (replay:
    /// last copy wins) and for provenance.
    Upgraded,
}

pub struct SparseMerkleTree {
    root: Option<Box<TreeNode>>,
    /// Number of entries in the tree.
    count: usize,
    /// Index for O(1) existence checks and fast iteration.
    entries: HashMap<WalletId, NablaEntry>,
    /// Txid index: tracks which wallet registered each txid (HashMap mode only).
    /// Detects double-redeem: same txid registered by different wallet → conflict.
    /// Only populated when txid_mode == Hashmap. Bloom-only nodes keep this empty.
    txid_index: HashMap<TxHash, WalletId>,
    /// ForkSettlement §2.4 [R5, R10, R32] — the TXID RECORDS: every VERIFIED
    /// SEND leg this node has seen, keyed by its txid, holding the WHOLE leg +
    /// `first_seen_secs` + `contested`. Replaces `registered_txids:
    /// HashSet<TxHash>` (a membership bit fed by EVERY `put`, including the
    /// receiver's redeem-finalize head keyed on the CHEQUE txid — HIGH-1).
    ///
    /// Distinct from `txid_index` (REDEEMED-ness, fed only at redeem-finalize —
    /// "ONE txid domain, 2026-07-07") and from `txid_records` (the §19.6 fee
    /// ledger). Written ONLY by `record_verified_leg` (from a
    /// `ban::VerifiedForkLeg`) and `restore_origin_entry` (verbatim, [R27]).
    /// NOT gated on `txid_mode`: every node holds it (R22 fix 4). Write-once,
    /// never pruned (a pruned record IS the late-leg attack, §2.4 LOW-2) — the
    /// ONE exception (W1, §9o [R58]): record-AE's in-place UPGRADE of an
    /// ungraded copy to a graded copy of the SAME leg (`first_seen_secs` and
    /// `contested` kept).
    origin_ledger: HashMap<TxHash, OriginLedgerEntry>,
    /// The ATRAXI index of §2.3: `(registrant client_pk, consumed state)` →
    /// the legs recorded under it. ≥ 2 legs under one key IS a `ForkClaim`
    /// (both legs are in the ledgers). `BTreeSet` so "the lowest leg" is
    /// deterministic on every node. SHARED by send and redeem legs (W7b, spec
    /// R52c): a send and a redeem — or two redeems — from one parent meet here.
    origin_index: HashMap<OriginKey, BTreeSet<LegRef>>,
    /// Fork Settlement W7b (spec R52c, P6) — the REDEEM RECORDS: every
    /// verified REDEEM leg this node has seen (a zero-consumed one too since
    /// W7c — a root, kept out of `origin_index`, [R33]), keyed
    /// by `(key, cheque txid)`, holding the whole leg + `first_seen_secs` +
    /// `contested` (the same entry shape as an origin record). A SEPARATE map
    /// on purpose — it is NEVER read as an origin: `cheque_sender_registered`
    /// and `vouch_record` (→ `origin_vouch`) read `origin_ledger` only, so a
    /// receiver's redeem of cheque T can never make T look registered (R5 /
    /// HIGH-1). Its legs join the shared fork index. Written ONLY by
    /// `record_verified_leg` (a `Redeem` `VerifiedForkLeg`) and
    /// `restore_redeem_entry` (verbatim, [R27]). Write-once, never pruned.
    redeem_ledger: HashMap<RedeemRecordId, OriginLedgerEntry>,
    /// cheque txid → the `(receiver_pk, consumed)` keys it was redeemed from
    /// (spec R52c `redeem_by_cheque`) — the forward edge "send t → redeems of
    /// t" W7c's verdict cascade walks (`redeem_records_of_cheque`).
    redeem_by_cheque: HashMap<TxHash, Vec<OriginKey>>,
    /// Fork Settlement W7c (plan §2 "Base input", F8) — receiver pk → the
    /// cheques it redeemed from an all-ZERO consumed state (a fresh wallet's
    /// first receive). Those records live in `redeem_ledger` under
    /// `((pk, ZERO), cheque)` but are kept OUT of `origin_index`: a zero parent
    /// is no state, so it is nobody's fork sibling [R33]. They are grounding
    /// ROOTS for the provenance verdict — iff exactly one is held for the pk
    /// (a second one is the F8 reset shape: both then WAIT).
    zero_redeems: HashMap<[u8; 32], BTreeSet<TxHash>>,
    /// Fork Settlement W7c/W7d — legs whose provenance must be (re-)derived,
    /// queued by `record_verified_leg` (the new leg; on a `Conflict` EVERY leg
    /// under the key — M3) and by the two restores (load re-derivation). The
    /// ONE consumer is `NablaNode::drain_fork_side_effects` →
    /// `provenance::Provenance::drain`.
    provenance_pending: Vec<(OriginKey, LegRef)>,
    /// Redeem records created since the last drain, for `WalOp::RedeemRecord`.
    redeem_wal_pending: Vec<RedeemRecordId>,
    /// Redeem records created (cumulative, not persisted). On `/status` as
    /// `redeem_records_created`.
    redeem_records_created: u64,
    /// Txids recorded since the last drain, for the node to WAL-log as
    /// `WalOp::OriginRecord` [R19] — the `exact_pending` buffer pattern (the
    /// SMT owns no file handles). Restores never push here.
    origin_wal_pending: Vec<TxHash>,
    /// Records created by `record_verified_leg` (cumulative, not persisted).
    /// On `/status` as `origin_records_created`.
    origin_records_created: u64,
    /// Fork Settlement §9o [R58] — held ungraded copies replaced in place by a
    /// graded one (origin AND redeem records; cumulative, not persisted). On
    /// `/status` as `origin_records_upgraded`.
    origin_records_upgraded: u64,
    /// YPX-010 §14 — per-claimant ordered claim chain, keyed by the claimant's
    /// pk. Bounded by `MAX_CLAIM_CHAIN` (the scar cap): a wallet cannot hold
    /// more unresolved links than that, so a longer chain is meaningless.
    claim_chains: HashMap<Vec<u8>, Vec<ClaimChainEntry>>,
    /// Per-transaction record store (HashMap mode only) — YP §19.6 fee
    /// ledger. Populated by `record_tx_meta` from Nabla's `/register`
    /// handler (and by gossip-driven StateUpdate apply once Step 4 ships
    /// the wire extension). Lives outside the SMT root, same as
    /// `txid_index`, so updates don't churn the leaf hashes.
    /// Bloom-mode nodes leave this empty — light nodes pay no storage.
    txid_records: HashMap<TxHash, TxRecord>,
    /// Secondary index keyed by validator_id (HashMap mode only). Each
    /// entry is the list of (tx_hash, fee_amount, tick) tuples that
    /// allocated a slot to this validator. Rebuilt from `txid_records`
    /// on boot — never persisted directly (one source of truth).
    /// Enables O(1)-by-validator earnings queries; without it,
    /// `validator_earnings()` would have to walk the entire record set.
    validator_earnings: HashMap<[u8; 32], Vec<(TxHash, u64, u64)>>,
    /// Bloom filter: always populated regardless of mode (YPX-014).
    /// Every node maintains a bloom for baseline double-redeem detection.
    /// KI#42 step 4c — the txid membership filter is an ERA CHAIN, not a lifetime
    /// flat filter.
    ///
    /// It was `TxidBloomFilter::new(DEFAULT_BLOOM_EXPECTED_ITEMS)`: monotonic,
    /// never rotated, so its false-positive rate climbed for the life of the
    /// network toward the numbers §39.9 already condemned ("saturates at ~10 M
    /// txids and its compounding false-positive rate silently destroys user
    /// funds"). §39.9 replaced that shape with time-bucketed eras but the
    /// migration was only half-applied — a `BloomChain` was constructed at node
    /// level and never fed or read, while this flat filter stayed live. This is
    /// that migration finished: one chain, fed here, queried here, and syncable
    /// (`BloomChain::merge_era` + the StatePull era payload).
    ///
    /// Rotation is by TICK, never by entry count — nodes cross a tick together but
    /// cross a count at different moments, and divergent era sizes break merge
    /// mesh-wide. See `AXIOM_DESIGN_NablaAntiEntropy.md` §12.
    txid_chain: crate::bloom_chain::BloomChain,
    /// Consumed-state bloom (YPX-020 / HAL anti-rollback). Records every wallet
    /// state that has been ADVANCED PAST (consumed) — fed in `put()` from the
    /// prior head a write overwrites, so it replicates implicitly via the gossip
    /// flood exactly like `txid_bloom` (no wire change, no validator auth — Nabla
    /// stays dumb, boundary-respecting). MONOTONIC (insert-only): a forged
    /// head-rollback (A12) can move `current_state` back to an ancestor X, but it
    /// can NEVER un-consume X here. A HAL re-anchor of a consumed X is rejected
    /// against THIS record, not the rollback-able head.
    /// KI#42 step 4d — the consumed-state filter is an ERA CHAIN.
    ///
    /// This is the FAIL-CLOSED one: `is_state_consumed` is the A12 anti-rollback
    /// gate, so a false positive REFUSES a legitimate registration. It was a flat
    /// lifetime filter whose FPR climbed forever; it is now time-bucketed, so a
    /// frozen era's FPR is fixed and only the active era can fill.
    ///
    /// Two properties this chain must hold that the txid chain need not:
    ///   * **Completeness on sync.** A node holding 39 of 40 eras is silently blind
    ///     to whatever lived in the 40th and would pass a rollback. So a node arms
    ///     only when it holds every era in the peer's manifest — see the
    ///     `consumed_era_manifest` handling in nabla_node.rs. The txid chain may be
    ///     tiered (a hit there is adjudicable via archive lookup); this one may not.
    ///   * **Never expire an era.** Old consumed marks are exactly where this filter
    ///     is load-bearing: with an intact SMT head the head check already rejects a
    ///     rollback, so the bloom earns its keep precisely for the
    ///     wiped-or-rolled-back-head case.
    consumed_chain: crate::bloom_chain::BloomChain,
    /// KI#34 check-3: `wallet_id → previous_state` — the head this node's last
    /// write OVERWROTE. ⚠ Not the held head's leg parent after a same-seq jump
    /// (KI#235; see the RULE 0 marker in `put_inner`) — a node's VIEW, never ban
    /// evidence (the KI#46 seq-fork ban that read it was retired, §9o [R56]).
    /// Formerly documented as "AUTHORITATIVE" (the consumed `X`). The exact-match companion to the lossy
    /// `consumed_state_bloom` — fed at the SAME `put()` chokepoint from `old.current_state`,
    /// so it's coupled by construction and can't drift from `entries`. Lets an honest
    /// node tell a fork (incoming `X→X'` with `old_state == previous_state[W]` but
    /// `new_state != current_state` = a double-consume of `X`) from a harmless stale-view
    /// head-mismatch, with NO false-positive risk (unlike the bloom). 32B/wallet, local
    /// (per-node from its own puts), NOT gossiped — each honest holder detects on its own.
    ///
    /// ⚠ **LOAD-BEARING INVARIANT (KI#65): every write here MUST also insert
    /// into `consumed_chain`, and `Smt::put` is the ONLY place that writes
    /// either.** A new write path that sets a `previous_state` without the
    /// matching bloom insert silently breaks anti-rollback recovery.
    ///
    /// Why: `merge_previous_states` used to arm the A12 bloom from every mark it
    /// recovered from a peer. That was removed (KI#65) because it manufactured
    /// permanent false vetoes — a node inherited `is_state_consumed` for states
    /// it had never witnessed, and the bloom is monotonic, so the mistake was
    /// forever. Removing it is SAFE **only because of this invariant**: since
    /// both are written together here, anything a peer holds in
    /// `previous_states` is already inside the eras it serves, and the
    /// consumed-ERA transfer carries it. Verified: `consumed_era_ids()`
    /// enumerates the whole `BTreeMap` including the ACTIVE era, eras are never
    /// pruned, and the re-arm completeness gate refuses to arm while any
    /// advertised era is missing.
    ///
    /// The era path is also strictly STRONGER than the one that was removed:
    /// `merge_consumed_era` is gated on `MAX_ADOPTABLE_BIT_DENSITY` and a failed
    /// merge leaves the node DISARMED, whereas the old path inserted
    /// unconditionally with no density gate and no arm/disarm consequence — an
    /// ungated write into a fail-closed, monotonic filter.
    ///
    /// So: break this coupling and a recovering node goes blind to whatever the
    /// orphaned mark covered. Nothing enforces it mechanically — keep both
    /// writes at the `put` chokepoint.
    previous_states: HashMap<WalletId, StateId>,
    /// KI#34 WI3 hole-1: PARALLEL k=3 seq attestation per wallet, held OUTSIDE
    /// the leaf so it never touches the leaf hash (no AE divergence) — see
    /// `SeqProof`. Set at adoption (`set_seq_proof`) when a flood/AE message
    /// carried a valid proof; read by the AE path (`seq_proof`) to re-attach
    /// the attestation when serving a pulled entry, so a downstream node can
    /// verify the seq it adopts. Not gossiped on its own; rides the
    /// `StateUpdate` / `AeReconcile` / `AeEntries` wires alongside the entry.
    seq_proofs: HashMap<WalletId, SeqProof>,
    /// KI#43a — exact-record event buffer. When enabled, every insert into
    /// `consumed_chain` also pushes `(post-insert active era id, state)` here;
    /// the node drains it on its tick cadence into the on-disk
    /// `ConsumedExactStore`. Buffered (not written here) because the SMT is a
    /// pure data structure — it owns no file handles and stays `Clone`.
    /// Capturing the era id at insert time keeps exact-file placement
    /// byte-identical to bloom placement (the insert itself may rotate the
    /// era, so the caller could not re-derive it from the tick afterwards).
    /// Disabled (default) ⇒ zero-cost: no pushes, buffer stays empty.
    exact_recording: bool,
    exact_pending: Vec<(u64, StateId)>,
    /// KI#65 option (c) — the FALSIFIABLE same-seq mark (TLA+-verified:
    /// `docs/models/ki65_same_seq_mark`, 9/9 cases). A lateral same-seq head
    /// swap is NOT a consumption yet — it becomes one only when the wallet
    /// advances past that seq, at which point exactly one seq-N state was the
    /// real head and every other seq-N sibling was never consumed. So the
    /// swapped-away head is recorded HERE, per wallet at its stuck seq, and
    /// `is_state_consumed` consults this set alongside the permanent bloom
    /// (the fork-evidence window stays closed). On a seq-ADVANCING `put` for
    /// the wallet the whole set is DROPPED: the seq guard refuses seq-older
    /// heads from then on, so the marks are no longer load-bearing (model
    /// RESULTS.md, "c3 prov liveness").
    ///
    /// ⚠ OPTION (d) IS A REQUIREMENT, NOT A STOP-GAP (model case c6): these
    /// marks must NEVER leave the node — not via the consumed-ERA transfer
    /// (they are not in `consumed_chain`, so that is structural), not via
    /// `merge_previous_states`, not via StatePull. A cleared-then-inherited
    /// mark admits adopting a spent sibling (the launder trace, TLC
    /// counterexample in c6); node-local marks are launder-free (c7). Do not
    /// add a spread path.
    ///
    /// Deliberately NOT persisted: a restart clears the provisional set,
    /// which fails OPEN exactly like losing an unarmed bloom era — hygiene,
    /// while Core's consume-once/quorum gate holds fund safety (RULE 5). The
    /// KI#34 fork-ban evidence lives in `previous_states`, which is written
    /// on the same-seq swap as before and is unaffected.
    same_seq_provisional: HashMap<WalletId, (u64, HashSet<StateId>)>,
    /// Reverse index of every state in `same_seq_provisional`, so
    /// `is_state_consumed` stays O(1). Maintained by `put` only.
    same_seq_provisional_index: HashSet<StateId>,
    /// KI#65 observability (RULE 3 §2 — a rejection needs a counter): how
    /// many same-seq provisional marks this node has manufactured (cumulative)
    /// and how many were cleared by a seq advance (cumulative). On `/status`.
    same_seq_marks_manufactured: u64,
    same_seq_marks_cleared: u64,
    /// Txid service mode — controls whether txid_index HashMap is populated.
    txid_mode: TxidServiceMode,
    /// YPX-022 §2.1.2a — authenticated cheque claims by cheque_id (== the
    /// send's txid). The delivery terminal `register_recall` reads; first-wins
    /// between different client PKs. Entries live until the recall window
    /// closes on the send (`claim_is_stale`), then evict.
    cheque_claims: HashMap<[u8; 32], ChequeClaim>,
    /// RULE 3 §2 — recalls refused `CLAIMED` (cumulative; `/status`
    /// `recalls_refused_claimed`). Non-zero is the KI#205 double-settlement
    /// being STOPPED: a sender asked to recall a cheque its addressed receiver
    /// had already claimed.
    recalls_refused_claimed: u64,
    /// YPX-020 HAL hibernation: wallet_pk → tick until which the wallet is
    /// "out of work" after a dead-overlap re-anchor. Set by `process_registration`
    /// when `is_hal_reanchor` (= `register_tick + HIBERNATION_WINDOW`); checked in
    /// `register_cheque_claim` to refuse the self-redeem until the window elapses.
    /// Derivable from the gossiped register tick, so the mesh converges on one value.
    hibernations: HashMap<[u8; 32], u64>,
    /// YPX-022 §2.1 — txids with a k-witnessed COMPLETION registration (redeemable).
    /// Marked from `process_registration` on the completion path (mode-INDEPENDENT,
    /// unlike the Hashmap-gated fee ledger). The RECALL gate refuses a recall of a
    /// completed txid. A sub-quorum (k<3) round never registers (step 5/5b′), so
    /// its txid is NEVER marked here → genuine partials stay recallable. (The KI#5
    /// partial_bridge that once recorded such a txid via `record_txid` was RETIRED
    /// 2026-10-02.)
    /// Monotonic completion ledger. Maps txid → the tick it was completion-registered,
    /// so the RECALL initiation window `[18000, 50000]` (YPX-022 §2) can be checked
    /// against the send's age. Still insert-only (never removed) — the eligibility base.
    completed_txids: HashMap<TxHash, u64>,
    /// YPX-022 §2 (2026-07-07 repurpose) — the REDEEMED terminal, symmetric with
    /// `recalled_txids`. Set permanently at redeem-finalize (`process_registration`,
    /// receiver's register after redeem) so it survives past the transient §4.6
    /// cheque-claim eviction (17,280 ticks) into the recall window (18,000+). This is
    /// the clean "consumed by redeem" flag the RECALL gate reads — NOT the send-polluted
    /// `txid_bloom`. `live → {Redeemed | Recalled} → consumed`; first-wins between the two.
    redeemed_txids: HashSet<TxHash>,
    /// YPX-022 §2.1 — txids the sender has RECALLED (permanently non-redeemable).
    /// query-txid refuses to attest a recalled txid (option A) → CL5's txid-attestation
    /// prerequisite can never be obtained → the receiver's redeem dies. First-wins.
    recalled_txids: HashMap<TxHash, RecallMarker>,
    /// YPX-001 §1.5.1a — txids whose scarred origin transition was resolved
    /// by a k-witnessed BURN (`Registration.burn_target_tx_id`). query-txid
    /// attests these "BURNED" so downstream wallets can clear inherited
    /// scars via the standard client-carried attestation. Insert-only.
    burned_txids: HashSet<TxHash>,
    /// KI#59 — txids for which THIS node emitted an OUT-OF-ORDER confirmation
    /// (`OooConfirmRequest`). A SEPARATE marker from `origin_ledger`/the head:
    /// marking here does NOT advance any SMT head and does NOT block the later
    /// in-order head-registration of the same txid — it only records "this node
    /// saw+marked this link's (txid,new_state) out of order". Insert-only.
    ooo_attested_txids: HashSet<TxHash>,
}

impl SparseMerkleTree {
    /// Create an empty SMT with default bloom-only txid mode.
    pub fn new() -> Self {
        Self::with_txid_mode(TxidServiceMode::Bloom)
    }

    /// Create an empty SMT with a specific txid service mode.
    pub fn with_txid_mode(mode: TxidServiceMode) -> Self {
        Self {
            root: None,
            count: 0,
            entries: HashMap::new(),
            txid_index: HashMap::new(),
            origin_ledger: HashMap::new(),
            origin_index: HashMap::new(),
            origin_wal_pending: Vec::new(),
            origin_records_upgraded: 0,
            origin_records_created: 0,
            redeem_ledger: HashMap::new(),
            redeem_by_cheque: HashMap::new(),
            zero_redeems: HashMap::new(),
            provenance_pending: Vec::new(),
            redeem_wal_pending: Vec::new(),
            redeem_records_created: 0,
            claim_chains: HashMap::new(),
            txid_records: HashMap::new(),
            validator_earnings: HashMap::new(),
            txid_chain: crate::bloom_chain::BloomChain::new(
                0,
                crate::bloom_era::DEFAULT_ERA_DURATION_TICKS,
                TXID_ERA_EXPECTED_ITEMS,
            ),
            consumed_chain: crate::bloom_chain::BloomChain::new(
                0,
                crate::bloom_era::DEFAULT_ERA_DURATION_TICKS,
                CONSUMED_ERA_EXPECTED_ITEMS,
            ),
            previous_states: HashMap::new(),
            seq_proofs: HashMap::new(),
            cheque_claims: HashMap::new(),
            recalls_refused_claimed: 0,
            hibernations: HashMap::new(),
            completed_txids: HashMap::new(),
            redeemed_txids: HashSet::new(),
            recalled_txids: HashMap::new(),
            burned_txids: HashSet::new(),
            ooo_attested_txids: HashSet::new(),
            exact_recording: false,
            exact_pending: Vec::new(),
            same_seq_provisional: HashMap::new(),
            same_seq_provisional_index: HashSet::new(),
            same_seq_marks_manufactured: 0,
            same_seq_marks_cleared: 0,
            txid_mode: mode,
        }
    }

    /// KI#65 observability: (manufactured cumulative, cleared cumulative,
    /// currently-active provisional marks). Surfaced on `/status`.
    pub fn same_seq_mark_counters(&self) -> (u64, u64, usize) {
        (
            self.same_seq_marks_manufactured,
            self.same_seq_marks_cleared,
            self.same_seq_provisional_index.len(),
        )
    }

    /// KI#43a — enable exact consumed-state event buffering (hashmap/archive
    /// nodes; the node drains via [`Self::drain_exact_pending`]).
    pub fn enable_exact_recording(&mut self) {
        self.exact_recording = true;
    }

    /// KI#43a — drain buffered `(era_id, consumed state)` events for the
    /// on-disk exact store. Empty unless `enable_exact_recording` was called.
    pub fn drain_exact_pending(&mut self) -> Vec<(u64, StateId)> {
        std::mem::take(&mut self.exact_pending)
    }

    /// Current root hash. O(1) — just reads the root.
    /// For an empty tree, returns the precomputed empty hash at tree depth.
    pub fn root_hash(&self) -> Hash256 {
        match &self.root {
            Some(node) => node.hash(),
            None => empty_hash(TREE_DEPTH),
        }
    }

    /// Number of entries in the tree.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Lookup wallet by ID. O(log n) tree traversal, but O(1) via index.
    pub fn get(&self, wallet_id: &WalletId) -> Option<&NablaEntry> {
        self.entries.get(wallet_id)
    }

    /// Insert or update a wallet entry. Returns new root hash.
    ///
    /// This does NOT write to WAL — the caller (NablaNode) handles WAL
    /// writes before calling this, as per the guide's architecture:
    ///   "1. Write to WAL (crash recovery)"
    ///   "2. Walk tree path"
    ///
    /// §5.2.4 (KI#123) — PRODUCTION callers go through [`Self::put_with_proof`]
    /// so every head replacement DECLARES its proof disposition; this bare form
    /// survives only for the in-crate test corpus (identical to
    /// `put_with_proof(entry, PutProof::RestoredFromLocalState(None))`).
    #[cfg(test)]
    pub fn put(&mut self, entry: &NablaEntry) -> Hash256 {
        self.put_with_proof(entry, PutProof::RestoredFromLocalState(None))
    }

    /// §5.2.4 (KI#123, 2026-08-28) — insert or update a wallet entry WITH the
    /// caller's declared proof disposition. Returns new root hash.
    ///
    /// §5.2.1 rule 2 made the head-replace site OWN the proof-drop (a tx_hash
    /// change deletes the retained proof) but left the re-establish to
    /// CONVENTION — "the caller calls `set_seq_proof` right after". Fourteen
    /// production sites each had to remember; on 2026-08-25 at least one
    /// forgot, and four attested heads ended proof-less on every node at once
    /// (the KI#123 strand — a fresh node correctly refuses them over AE
    /// forever). Retention is now STRUCTURAL: "deleted and forgot" does not
    /// compile, because there is no production entry point without a
    /// [`PutProof`].
    pub fn put_with_proof(&mut self, entry: &NablaEntry, proof: PutProof) -> Hash256 {
        if let PutProof::SameHeadStatusChange = proof {
            // A "status flip" that changes the tx is a logic bug at the call
            // site (every such caller clones the held entry and mutates ONLY
            // `status`). Fail closed: debug builds stop dead; release builds
            // log loudly and continue — the write itself is still safe either
            // way, because `put_inner`'s KI#38 lock-step keeps the proof on a
            // same-tx write and drops it on a differing-tx write, so a stale
            // proof can never be retained even through a violated assert.
            if let Some(old) = self.entries.get(&entry.wallet_id) {
                debug_assert_eq!(
                    old.tx_hash, entry.tx_hash,
                    "PutProof::SameHeadStatusChange with a differing tx_hash — \
                     the caller is not doing a status flip (§5.2.4)"
                );
                if old.tx_hash != entry.tx_hash {
                    log::error!(
                        "[SMT] SameHeadStatusChange disposition violated: wallet={:02x}{:02x} \
                         held_tx={:02x}{:02x}.. new_tx={:02x}{:02x}.. — caller bug (§5.2.4); \
                         proof for the old head is dropped, not carried",
                        entry.wallet_id[0], entry.wallet_id[1],
                        old.tx_hash[0], old.tx_hash[1],
                        entry.tx_hash[0], entry.tx_hash[1],
                    );
                }
            }
        }
        let root = self.put_inner(entry);
        match proof {
            // Installed AFTER `put_inner` (which just dropped any proof bound
            // to the superseded tx_hash) and in the same call — the
            // delete-then-forget window §5.2.1 rule 2 left open no longer
            // exists at all.
            PutProof::Attested(p) => {
                self.seq_proofs.insert(entry.wallet_id, p);
            }
            // No proof exists for this head class; the KI#38 lock-step in
            // `put_inner` already produced the correct retention state
            // (kept on a same-tx write, dropped on a tx change).
            PutProof::ProoflessByDesign(_) => {}
            PutProof::SameHeadStatusChange => {}
            PutProof::RestoredFromLocalState(p) => {
                // Boot-time replay of this node's own trusted state. The
                // persisted record's proof (if any) is re-installed AFTER the
                // put — the KI#73 ordering, now structural instead of a
                // comment at the call site.
                if let Some(p) = p {
                    self.seq_proofs.insert(entry.wallet_id, p);
                }
            }
        }
        root
    }

    fn put_inner(&mut self, entry: &NablaEntry) -> Hash256 {
        let serialized =
            bincode::serialize(entry).expect("NablaEntry serialization cannot fail");
        let leaf_hash = hash_leaf(&entry.wallet_id, &serialized);

        let new_leaf = TreeNode::Leaf {
            key: entry.wallet_id,
            _value: serialized,
            hash: leaf_hash,
        };

        self.root = Some(Self::insert_at(
            self.root.take(),
            &entry.wallet_id,
            new_leaf,
            0,
        ));

        // Update index — capture the prior head so we can record the state this
        // write overwrites as CONSUMED (HAL anti-rollback, YPX-020). The bloom is
        // monotonic: once X is advanced past, no forged head-rollback can
        // un-consume it. Fed here so it replicates via the gossip flood like
        // `txid_bloom` — no wire change, no validator auth.
        // RULE 0 marker (ForkSettlement wave 3, 2026-09-28) — a send txid
        // used to be recorded as "registered" HERE (`registered_txids.insert`)
        // on the reading "`put` is the one place any entry enters the SMT, and
        // it is on the register, flood and AE paths, so recording here
        // replicates". WRONG for an origin record: `put` also sees the
        // RECEIVER's redeem-finalize head, keyed on the CHEQUE txid ("ONE txid
        // domain"), the snapshot head rebuild and WAL `Put` replay — so P's
        // own redeem minted the record for A's `tx_a`, and every node would
        // have vouched for a send A never registered there (HIGH-1). CORRECT:
        // a record comes ONLY from a VERIFIED SEND leg through
        // `record_verified_leg` (`ban::VerifiedForkLeg`, [R11] — structural), and
        // replication is carried by the LEG on the flood/AE paths, not by the
        // head. ForkSettlement §2.4 [R5, R11]. Do not re-add an insert here.
        let prev = self.entries.insert(entry.wallet_id, entry.clone());
        if let Some(old) = prev {
            // KI#65 FIXED (2026-08-09, TLA+-first: docs/models/ki65_same_seq_mark).
            // HISTORY OF A MISREADING (RULE 0 §4): this guard used to record a
            // PERMANENT consumption on ANY head change, including a lateral
            // swap between two candidates at the SAME wallet_seq — a failing
            // retry minted five candidates at wallet dad3's seq=18, a node
            // swapping between them condemned the loser into the monotonic
            // bloom forever, and a peer that inherited the mark refused the
            // head nine other nodes held as canonical. Nothing was consumed:
            // the wallet never advanced.
            //
            // A same-seq sibling swap is not a consumption YET — it becomes
            // one only when the wallet advances past that seq. So the same-seq
            // mark now goes to the FALSIFIABLE `same_seq_provisional` set
            // (consulted by `is_state_consumed`, so the double-spend evidence
            // window is unchanged — the ten tests that killed the naive
            // `wallet_seq >` gate in 2026-08-05 stay green), and the set is
            // dropped when a seq-ADVANCING put lands: from that moment the
            // seq guard refuses seq-older heads, so the marks are not
            // load-bearing (model case c3). The marks are NODE-LOCAL by
            // requirement (model case c6: spreading a clearable mark admits a
            // launder trace; c7: local-only is launder-free) — never add them
            // to an era transfer or merge path.
            if old.current_state != entry.current_state && old.current_state != [0u8; 32] {
                // Same-seq state change: TWO legitimate shapes share this
                // signature and MUST be told apart (the discriminator KI#65 §2
                // said this site lacked — it has one after all):
                //   * a CHAIN ADVANCE at constant seq — every redeem (Core's
                //     receive rule keeps wallet_seq unchanged; KI#46 ruling in
                //     gossip.rs) — a REAL consumption of the held head;
                //   * a LATERAL SIBLING swap — a retry re-produced this seq
                //     (KI#65) — NOT a consumption.
                // The linkage is computable because `tx_hash` is Core's
                // one-builder `fact_tx_hash(prev_state, new_state)` (KI#55):
                // an entry that chains from the held head recomputes exactly.
                // A same-seq entry that does NOT chain from the head (sibling,
                // or an out-of-order arrival whose ancestry this node cannot
                // prove) is marked PROVISIONALLY — under-marking fails open
                // (hygiene, RULE 5), over-marking is the KI#65 defect.
                let chains_from_old = entry.tx_hash != [0u8; 32]
                    && entry.tx_hash
                        == crate::registration::fact_tx_hash(
                            &old.current_state,
                            &entry.current_state,
                        );
                if entry.wallet_seq == old.wallet_seq && !chains_from_old {
                    // Lateral same-seq swap: PROVISIONAL mark, clearable.
                    let slot = self
                        .same_seq_provisional
                        .entry(entry.wallet_id)
                        .or_insert_with(|| (entry.wallet_seq, HashSet::new()));
                    debug_assert_eq!(
                        slot.0, entry.wallet_seq,
                        "stale provisional slot survived a seq advance"
                    );
                    if slot.1.insert(old.current_state) {
                        self.same_seq_provisional_index.insert(old.current_state);
                        self.same_seq_marks_manufactured += 1;
                    }
                } else {
                    // Seq-changing head replacement: a real consumption this
                    // node witnessed — permanent, era-carried, exact-mirrored.
                    self.consumed_chain.insert(entry.tick, &old.current_state);
                    // KI#43a: mirror the mark into the exact-record buffer, with
                    // the era the bloom insert just landed in (post-insert active
                    // era — the insert above may itself have rotated the chain).
                    if self.exact_recording {
                        self.exact_pending
                            .push((self.consumed_chain.active_era_id(), old.current_state));
                    }
                }
                // KI#34 check-3: the SAME consumed head, kept exact (not bloom).
                // ── RULE 0 §4 marker (2026-09-30, KI#235) — HISTORY ──
                // WRONG READING (until 2026-09-30): "kept exact so a fork-freeze can
                // be based on it without false-positive risk" / "the same-seq write
                // is exactly the fork-ban discriminator". RIGHT READING: this is the
                // head the put OVERWROTE, not the new head's leg parent; after a
                // same-seq jump (AE, flood reorder) the two differ, and the gossip.rs
                // check-3 ban fired on an HONEST late redeem flood
                // (`fork_detection_mesh::fork_retire_proof_b_*` / `_b2_*`, KI#235).
                // check-3 was RETIRED as a ban source 2026-09-30 (W2, Fork Settlement
                // §9o [R56]); no ban reads this map any more. Remaining readers: the
                // E3 HAL-revival arm (a local FREEZE, residual (4) of §9o) and the
                // R24 own-consumption test in `record_verified_leg`. The exact leg
                // parent is the recorded leg's `consumed` (origin index).
                self.previous_states.insert(entry.wallet_id, old.current_state);
            }
            // KI#65: a seq ADVANCE falsifies this wallet's provisional same-seq
            // marks — exactly one seq-N state was the real head (now recorded
            // permanently above, or by the node that witnessed the advance);
            // every other seq-N sibling was provably never consumed. Checked
            // OUTSIDE the head-change guard so a same-state seq bump clears too.
            if let Some(slot) = self.same_seq_provisional.get(&entry.wallet_id) {
                if entry.wallet_seq > slot.0 {
                    let (_, marks) = self.same_seq_provisional.remove(&entry.wallet_id).unwrap();
                    for m in &marks {
                        self.same_seq_provisional_index.remove(m);
                    }
                    self.same_seq_marks_cleared += marks.len() as u64;
                }
            }
            // KI#38 — proof↔entry lock-step, enforced STRUCTURALLY at the one
            // place a head is ever replaced. A `SeqProof` is bound to a specific
            // `tx_hash` (it's folded into `compute_receipt_commitment`), so the
            // instant `put` replaces the head with a DIFFERENT tx_hash, any
            // retained proof is stale — serving it fails downstream
            // `verify_seq_proof` (`CARRIED-BUT-FAILED`) and wedges anti-entropy
            // at applied=0. Drop it here (cheap 32-byte compare, NO crypto on the
            // hot path); a caller that actually holds a verified proof for the
            // NEW head re-establishes it with `set_seq_proof` right after. This
            // makes a stale proof structurally impossible across EVERY put site
            // (registration / flood / AE / HAL / recall),
            // replacing the per-site clears. A same-tx_hash put (e.g. a status/ban
            // flip) keeps the proof — same head, same binding.
            if old.tx_hash != entry.tx_hash {
                self.seq_proofs.remove(&entry.wallet_id);
            }
        }
        // YPX-014 txid service — deliberately NOT fed here (2026-07-07, ONE
        // txid domain). The service answers "was this txid REDEEMED?"; feeding
        // it every registration's tx_hash marked merely-SENT txids REDEEMED
        // the moment tx_hash became the protocol txid (pre-unification the
        // state-hash pollution was invisible to protocol-txid queries, which
        // is why the claim path carried the whole double-redeem defense).
        // The service is fed at redeem-finalize only: `record_txid` from
        // process_registration 8b'' + the k-attested gossip parity branch.
        // Count only increases for new entries
        self.count = self.entries.len();

        self.root_hash()
    }

    /// Look up which wallet registered a txid. For double-redeem detection.
    /// HashMap mode: returns exact wallet_id. Bloom mode: returns None (use may_contain_txid).
    pub fn get_wallet_by_txid(&self, txid: &TxHash) -> Option<WalletId> {
        self.txid_index.get(txid).copied()
    }

    /// HAL anti-rollback (YPX-020): has this wallet state been advanced past
    /// (consumed) at some point this node observed? Checked against the MONOTONIC
    /// consumed-state bloom, NOT the gossip-mutable head — so a forged rollback to
    /// X still reports X consumed. Bloom semantics: may false-positive (caller
    /// treats a positive as "reject the re-anchor of a spent state"), never
    /// false-negative. Used to gate a HAL re-anchor; normal registers are
    /// unaffected (their rollback is covered by Lambda S-ABR overlap).
    pub fn is_state_consumed(&self, state: &StateId) -> bool {
        // Union across EVERY era. A state consumed long ago must still read as
        // consumed after rotations, or a rollback to it would look fresh.
        //
        // KI#65: the falsifiable same-seq set is consulted TOO — while two
        // same-seq siblings coexist the swapped-away one must read consumed
        // (that window is the KI#34 double-spend evidence), but the mark
        // clears once the wallet advances instead of vetoing forever.
        matches!(self.consumed_chain.lookup(state), crate::bloom_chain::ChainLookup::Hit { .. })
            || self.same_seq_provisional_index.contains(state)
    }

    /// KI#34 check-3: the head this node's last write OVERWROTE for this wallet,
    /// or `None` if unknown (never advanced on this node / pre-feature genesis
    /// root). Exact-match (no bloom false positive) — but a VIEW: after a same-seq
    /// jump it is not the current head's leg parent (KI#235), so it is NOT ban
    /// evidence (§9o [R56]). It still feeds the E3 HAL arm's local freeze.
    pub fn previous_state(&self, wallet_id: &WalletId) -> Option<StateId> {
        self.previous_states.get(wallet_id).copied()
    }

    // ── WI1 (§5.2): carry the anti-rollback state in StatePull recovery ──
    //
    // A wiped-then-bootstrapped node receives only the head `Y` and comes back
    // DISARMED (empty consumed-bloom + previous_states) → blind to a forged
    // rollback. These export/merge the anti-rollback view so a recovering node
    // re-arms. Merge is UNION/insert-if-absent (monotonic): "consumed" is
    // append-only, so a state is consumed if ANY honest peer says so — an
    // attacker peer's empty/forged view can only fail to add, never subtract.

    /// Era ids we hold — the manifest a peer compares against to know whether we
    /// are COMPLETE. A fail-closed filter cannot be partially armed.
    pub fn consumed_era_ids(&self) -> Vec<u64> {
        self.consumed_chain.metadata().iter().map(|m| m.era_id).collect()
    }

    /// Serialize one consumed-state era for a StatePull response.
    pub fn consumed_era_bytes(&self, era_id: u64) -> Option<Vec<u8>> {
        let era = self.consumed_chain.era(era_id)?;
        let mut buf = Vec::new();
        ciborium::into_writer(era, &mut buf).ok()?;
        Some(buf)
    }

    /// UNION a peer's consumed-state era into ours. Monotonic — "consumed" is
    /// append-only, so a state is consumed if ANY honest peer says so, and an
    /// attacker's empty or partial view can only fail to add, never subtract.
    ///
    /// Refuses an implausibly dense era (`MAX_ADOPTABLE_BIT_DENSITY`). Union is
    /// permanent and this gate FAILS CLOSED, so adopting a poisoned era would make
    /// the node reject every legitimate registration forever — a peer cannot
    /// disarm us, but without this it could OVER-arm us.
    pub fn merge_consumed_era(
        &mut self,
        era: crate::bloom_era::BloomEra,
    ) -> Result<bool, String> {
        let density = era.filter.bit_density();
        if density > crate::bloom::MAX_ADOPTABLE_BIT_DENSITY {
            return Err(format!(
                "refusing consumed era {} at {:.1}% bit density (max {:.0}%) — \
                 a filter this saturated can only contribute false positives, \
                 and union is permanent",
                era.meta.era_id,
                density * 100.0,
                crate::bloom::MAX_ADOPTABLE_BIT_DENSITY * 100.0
            ));
        }
        self.consumed_chain.merge_era(era)
    }

    /// Snapshot the authoritative `previous_states` (wallet → consumed `X`) for
    /// a StatePull response.
    pub fn previous_states_snapshot(&self) -> Vec<(WalletId, StateId)> {
        self.previous_states.iter().map(|(w, s)| (*w, *s)).collect()
    }

    /// Merge a peer's `previous_states` (insert-if-absent). A recovering node
    /// has none, so it adopts the peer's; a partially-armed node fills gaps
    /// without clobbering a previous_state it already holds for a wallet.
    ///
    /// BOUNDED (load-shedding, see `docs/AXIOM_DESIGN_NablaAntiEntropy.md`
    /// §"Gossip/AE flood load-shedding"): processes at most
    /// `AE_MERGE_MAX_BATCH` entries per call so a malicious peer cannot tie up
    /// the single global node lock with an oversized `previous_states` array.
    /// The merge is idempotent insert-if-absent, so any overflow re-arrives and
    /// re-applies harmlessly on a subsequent StatePull. Returns the number of
    /// entries actually processed. Honest snapshots are far below the cap and
    /// never truncate.
    pub fn merge_previous_states(
        &mut self,
        entries: &[(WalletId, StateId)],
        current_tick: u64,
    ) -> usize {
        let take = entries.len().min(AE_MERGE_MAX_BATCH);
        if take < entries.len() {
            log::warn!(
                "[AE-MERGE-BOUND] previous_states batch of {} exceeds cap {} — \
                 processing first {}, overflow deferred to next StatePull",
                entries.len(), AE_MERGE_MAX_BATCH, take,
            );
        }
        for (w, s) in &entries[..take] {
            self.previous_states.entry(*w).or_insert(*s);
            // KI#65 — do NOT arm the A12 bloom from a mark we never witnessed.
            //
            // This used to `consumed_chain.insert(current_tick, s)` for every
            // recovered mark, so a node inherited `is_state_consumed` for
            // states it had never held. Combined with the same-seq false
            // positives `put` manufactures, that is what let ONE node veto the
            // head nine others held as canonical, permanently — the bloom is
            // monotonic, so an inherited mistake is forever. Live: gamma pulled
            // 21 and 27 marks across bootstrap re-arms and then refused `ea76`
            // 69 times.
            //
            // Rollback protection is NOT lost. It comes from the consumed-ERA
            // transfer, which is the authoritative path: KI#42 requires a node
            // to hold EVERY era in the peer's manifest before it arms, and the
            // WI1 §5.2 re-arm test proves a recovered node still knows X was
            // consumed. Anything a peer holds in `previous_states` it also
            // holds in its bloom (both are written together in `put`), so the
            // era transfer already carries it. This path was redundant
            // coverage that injected false positives.
            //
            // The exact-record mirror goes with it (KI#43a parity): the exact
            // file must not drift from the bloom, so recording an event for an
            // insert we no longer make would be exactly that drift.
            let _ = current_tick;
        }
        take
    }

    /// KI#34 WI3 hole-1: the k=3 seq attestation held for `wallet_id` (parallel
    /// to the leaf — see `SeqProof`). The AE path re-attaches this when serving
    /// a pulled entry so a downstream node can verify the seq it adopts.
    pub fn seq_proof(&self, wallet_id: &WalletId) -> Option<&SeqProof> {
        self.seq_proofs.get(wallet_id)
    }

    /// Store the verified k=3 seq attestation for `wallet_id`. §5.2.4
    /// (KI#123): production code has NO separate proof-install step any more
    /// — the proof rides [`Self::put_with_proof`] atomically with the head,
    /// so the put-then-set convention (whose "forgot the set" failure is
    /// KI#123) cannot be reintroduced. Test-only, for constructing retention
    /// scenarios directly.
    #[cfg(test)]
    pub fn set_seq_proof(&mut self, wallet_id: WalletId, proof: SeqProof) {
        self.seq_proofs.insert(wallet_id, proof);
    }

    /// KI#38 — the full retained seq-proof map, for snapshot persistence.
    /// Proofs were in-memory-only pre-fix, so every restart left the node
    /// unable to attest ANY held head over anti-entropy until each wallet
    /// re-registered — a whole-mesh restart re-stranded every head at once.
    pub fn seq_proofs_snapshot(&self) -> Vec<(WalletId, SeqProof)> {
        self.seq_proofs.iter().map(|(w, p)| (*w, p.clone())).collect()
    }

    /// KI#38 — restore retained seq proofs from a snapshot at boot. Each
    /// proof was verified before it was originally retained; the snapshot is
    /// this node's own trusted state, so no re-verification here (same trust
    /// basis as the restored entries themselves).
    pub fn restore_seq_proofs(&mut self, proofs: Vec<(WalletId, SeqProof)>) {
        for (w, p) in proofs {
            self.seq_proofs.insert(w, p);
        }
    }

    /// Record a txid → wallet mapping into the tiered txid bloom (YPX-014)
    /// and, in Hashmap mode, the txid index — WITHOUT touching the SMT
    /// state tree.
    ///
    /// `put()` records the txid of the entry it commits. The advance-on-proof
    /// path (KI #5) needs to additionally record the *intervening*
    /// sub-quorum partial's txid: that transition was never registered, so
    /// `put()` never saw it, yet the SMT is being advanced past it. Recording
    /// it here keeps double-redeem detection complete — a later replay of the
    /// same partial txid is still caught.
    ///
    /// Mirrors the txid-tracking block inside `put()` exactly; a zero txid
    /// is a no-op (matches `put()`'s `entry.tx_hash != [0u8; 32]` guard).
    pub fn record_txid(&mut self, txid: &TxHash, wallet_id: &WalletId, current_tick: u64) {
        if *txid == [0u8; 32] {
            return;
        }
        // Era chain: `insert` rotates internally when the tick crosses the active
        // era's end, so the caller only has to supply the tick it observed.
        self.txid_chain.insert(current_tick, txid);
        if self.txid_mode == TxidServiceMode::Hashmap {
            self.txid_index.insert(*txid, *wallet_id);
        }
    }

    /// YP §19.6 fee ledger — record the per-tx metadata (receiver, amount,
    /// fee_breakdown) keyed by tx_hash. Hashmap-mode only; bloom-mode nodes
    /// no-op so light nodes pay no storage cost.
    ///
    /// Called from `process_registration` after the SMT advance, and from
    /// `apply_state_update` once Step 4 extends the gossip wire so the
    /// records converge across the mesh via the existing flood path.
    /// Updates both `txid_records` and the secondary `validator_earnings`
    /// index in one shot so query-time reads are O(1) by validator.
    ///
    /// Zero-txid is a no-op (mirrors `record_txid`).
    pub fn record_tx_meta(&mut self, tx_hash: TxHash, record: TxRecord) {
        if tx_hash == [0u8; 32] {
            return;
        }
        if self.txid_mode != TxidServiceMode::Hashmap {
            return;
        }
        // Update secondary index first — if there's a collision (same
        // tx_hash gossiped twice), we want to avoid double-counting
        // earnings. The dedup key is tx_hash itself.
        if !self.txid_records.contains_key(&tx_hash) {
            for share in &record.fee_breakdown {
                self.validator_earnings
                    .entry(share.validator_id)
                    .or_default()
                    .push((tx_hash, share.amount, record.tick));
            }
            self.txid_records.insert(tx_hash, record);
        }
    }

    /// Look up the per-tx record for a given tx_hash. Hashmap-mode only —
    /// bloom-mode nodes never store records and return None.
    pub fn tx_record(&self, tx_hash: &TxHash) -> Option<&TxRecord> {
        self.txid_records.get(tx_hash)
    }

    /// Validator earnings since `since_tick` — the basis of the fee
    /// ledger query response. Returns `(total_amount, entries)` where
    /// each entry carries the full fee_breakdown (Step 8.3.A —
    /// required for §20.10 enforcement at withdrawal time). Hashmap-mode
    /// only; bloom-mode nodes return `(0, vec![])` — querying clients
    /// should ask a hashmap node for authoritative data.
    ///
    /// `since_tick = 0` returns all earnings ever recorded for this
    /// validator on this node.
    ///
    /// Order: by tick ascending then tx_hash lex — two honest hashmap
    /// nodes produce byte-identical entries vectors for the same query.
    /// Required for the Step 6 signed attestation payload.
    /// Every validator_id that has any recorded earnings (hashmap-mode only;
    /// bloom nodes return empty). The FOB authoring hook walks this to build a
    /// batched tranche statement covering each validator's Fee pool.
    pub fn validator_ids_with_earnings(&self) -> Vec<[u8; 32]> {
        // SORTED — the FOB authoring committee has no coordination (§3), so the
        // tranche `entries` VECTOR must be built in a deterministic order across
        // recorders or their statement payloads diverge (canonicalised again in
        // `fob::tranche_statement_payload`, but a deterministic wire order is
        // cleaner and keeps the two in step). HashMap key order is per-process.
        let mut ids: Vec<[u8; 32]> = self.validator_earnings.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Class-FILTERED validator earnings (FOB §10.2a). Same shape as
    /// `validator_earnings`, but keeps ONLY the entries whose tx is dev-class
    /// (`is_dev==true`) or public (`false`). The class is DERIVED — not stored —
    /// from the RECEIVER's `SeqProof.is_dev_class`, which already replicates and
    /// PERSISTS with the SMT state (so it survives the boot rebuild of
    /// `validator_earnings` from `txid_records`, and needs no `TxRecord` field).
    /// This is the ONE codepath the FOB accumulator reads, class as a data bit —
    /// dev and real run identical lines, differing only in this argument.
    pub fn validator_earnings_by_class(
        &self,
        validator_id: &[u8; 32],
        is_dev: bool,
        since_tick: u64,
        // SETTLED WATERMARK (exclusive upper bound). The FOB committee (§3) has
        // NO coordination and each recorder's accumulator differs on the RECENT,
        // not-yet-replicated tail — so a tranche read up to "now" would diverge
        // across recorders and never aggregate (found live 2026-08-10). Reading
        // only earnings with `tick < until_tick` — the AUTHORED EPOCH'S FLOOR
        // (`epoch * epoch_len`), a value every recorder authoring that epoch
        // computes identically — cuts at a shared, fully-settled point:
        // convergence comes from eventual-consistency (anything older than the
        // replication bound is on every recorder), NOT from traffic quiescing
        // (it never does). The moving in-flight tail is simply swept into a
        // later epoch once it settles.
        until_tick: u64,
    ) -> (u64, Vec<axiom_core_logic::wire_client::EarningsEntry>) {
        let Some(raw) = self.validator_earnings.get(validator_id) else {
            return (0, Vec::new());
        };
        let mut filtered: Vec<(TxHash, u64, u64)> = raw
            .iter()
            .filter(|(_, _, t)| *t >= since_tick && *t < until_tick)
            .filter(|(tx, _, _)| {
                // Class is DERIVED (never stored on the earnings record — design ruling:
                // "No there is not txrecord field") from the receiver's persisted
                // SeqProof.is_dev_class, the same bit modes.rs sources from the
                // sender (Rule R1 forces sender==receiver class). A missing proof
                // defaults to PUBLIC (is_dev=false): the dev fund fails closed, so
                // an un-replicated / absent proof can never inflate dev-AXC — it
                // only ever transiently mis-files an earning as public, which the
                // refill-requires-empty + skew tolerance re-judge corrects on
                // convergence (§10.2a).
                self.txid_records
                    .get(tx)
                    .map(|r| {
                        self.seq_proof(&r.receiver_wallet_id)
                            .map(|s| s.is_dev_class)
                            .unwrap_or(false)
                            == is_dev
                    })
                    .unwrap_or(false)
            })
            .copied()
            .collect();
        filtered.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));
        let total: u64 = filtered.iter().map(|(_, amt, _)| amt).sum();
        let entries = filtered
            .into_iter()
            .filter_map(|(tx_hash, amount, tick)| {
                let record = self.txid_records.get(&tx_hash)?;
                Some(axiom_core_logic::wire_client::EarningsEntry {
                    tx_hash,
                    amount,
                    tick,
                    full_fee_breakdown: record.fee_breakdown.clone(),
                })
            })
            .collect();
        (total, entries)
    }

    pub fn validator_earnings(
        &self,
        validator_id: &[u8; 32],
        since_tick: u64,
    ) -> (u64, Vec<axiom_core_logic::wire_client::EarningsEntry>) {
        let Some(raw_entries) = self.validator_earnings.get(validator_id) else {
            return (0, Vec::new());
        };
        let mut filtered: Vec<(TxHash, u64, u64)> = raw_entries
            .iter()
            .filter(|(_, _, t)| *t >= since_tick)
            .copied()
            .collect();
        filtered.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));
        let total: u64 = filtered.iter().map(|(_, amt, _)| amt).sum();
        // Hydrate the full fee_breakdown for each entry from txid_records.
        // A missing record at this stage shouldn't happen (writer-only path
        // populates both indices together), but skip gracefully if it does.
        let entries: Vec<axiom_core_logic::wire_client::EarningsEntry> = filtered
            .into_iter()
            .filter_map(|(tx_hash, amount, tick)| {
                let record = self.txid_records.get(&tx_hash)?;
                Some(axiom_core_logic::wire_client::EarningsEntry {
                    tx_hash,
                    amount,
                    tick,
                    full_fee_breakdown: record.fee_breakdown.clone(),
                })
            })
            .collect();
        (total, entries)
    }

    /// Number of per-tx records this node holds. Hashmap-mode only;
    /// bloom-mode returns 0. Used by dashboards and `validator_earnings`
    /// liveness checks.
    pub fn tx_records_len(&self) -> usize {
        self.txid_records.len()
    }

    /// Iterator over all per-tx records — for snapshot serialization.
    /// Hashmap-mode-only by construction; bloom-mode yields zero entries
    /// since the map stays empty. Order is HashMap-undefined, which is
    /// fine for snapshots (boot replay rebuilds the same end state
    /// regardless of insertion order — `record_tx_meta` is idempotent
    /// on duplicate tx_hash).
    pub fn iter_tx_records(&self) -> impl Iterator<Item = (&TxHash, &TxRecord)> {
        self.txid_records.iter()
    }

    /// KI#82 fee-ledger anti-entropy — the per-bucket digest vector:
    /// `(bucket_id, BLAKE3("AXIOM_TXID_AE_BUCKET" || bucket_id || sorted tx_hashes))`
    /// where `bucket_id = tick / bucket_ticks`. Two hashmap nodes hold the identical
    /// vector IFF they hold the identical `txid_records` SET — records are immutable
    /// and keyed by tx_hash, so the tx_hash set alone determines the records. Because
    /// the ledger is append-only, an old bucket's digest is FROZEN once its tick
    /// window passes, so only the recent bucket churns. Empty on bloom-mode nodes
    /// (they hold no records). See AXIOM_DESIGN_NablaAntiEntropy.md §13.
    pub fn txid_bucket_digests(&self, bucket_ticks: u64) -> Vec<(u64, Hash256)> {
        if bucket_ticks == 0 {
            return Vec::new();
        }
        let mut buckets: std::collections::HashMap<u64, Vec<TxHash>> =
            std::collections::HashMap::new();
        for (tx_hash, record) in &self.txid_records {
            buckets
                .entry(record.tick / bucket_ticks)
                .or_default()
                .push(*tx_hash);
        }
        let mut out: Vec<(u64, Hash256)> = Vec::with_capacity(buckets.len());
        for (bucket_id, mut hashes) in buckets {
            hashes.sort_unstable();
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_TXID_AE_BUCKET");
            h.update(&bucket_id.to_le_bytes());
            for tx in &hashes {
                h.update(tx);
            }
            out.push((bucket_id, *h.finalize().as_bytes()));
        }
        out.sort_unstable_by_key(|(b, _)| *b);
        out
    }

    /// KI#82 — every `(tx_hash, record)` whose bucket is in `bucket_ids`. The AE
    /// responder's push set for the buckets it found divergent (§13 step 2). A
    /// clone is fine: transfer fires only on an actual divergence, and adoption
    /// dedups on tx_hash so redundant records are a no-op.
    pub fn txid_records_in_buckets(
        &self,
        bucket_ids: &std::collections::HashSet<u64>,
        bucket_ticks: u64,
    ) -> Vec<(TxHash, TxRecord)> {
        if bucket_ticks == 0 {
            return Vec::new();
        }
        self.txid_records
            .iter()
            .filter(|(_, r)| bucket_ids.contains(&(r.tick / bucket_ticks)))
            .map(|(h, r)| (*h, r.clone()))
            .collect()
    }

    /// Bloom filter check: has this txid probably been seen? (YPX-014)
    /// Returns false = definitely not seen. Returns true = probably seen (~0.1% FPR).
    pub fn may_contain_txid(&self, txid: &TxHash) -> bool {
        // Union query across EVERY era, not just the active one: a txid recorded
        // before a rotation must still be found after it, or a replay would look
        // fresh the moment an era turned over.
        matches!(self.txid_chain.lookup(txid), crate::bloom_chain::ChainLookup::Hit { .. })
    }

    /// YPX-010 §14 — record a claim in the claimant's ordered chain and
    /// re-derive readiness for EVERY entry in it.
    ///
    /// Returns the whole chain, oldest first, so the caller learns in one
    /// answer which of its cheques are safe to redeem.
    ///
    /// **Re-derived on every touch, never cached.** An entry that was not ready
    /// becomes ready the moment its sender registers. That is why there is no
    /// timer and no background scan: the client's next claim or redeem IS the
    /// trigger, and until it touches the chain nobody needs the answer.
    ///
    /// **Bounded by the scar cap.** A wallet cannot legitimately hold more
    /// unresolved links than `MAX_CLAIM_CHAIN`, so a longer chain is
    /// meaningless; the oldest entry is dropped rather than letting the chain
    /// grow without limit. Using the SAME registered value as the scar cap
    /// keeps the two from drifting apart.
    ///
    /// This does NOT gate the claim — the caller has already claimed by the
    /// time this runs. It reports.
    pub fn record_claim_in_chain(
        &mut self,
        client_pk: &[u8],
        cheque_id: &TxHash,
        tick: u64,
    ) -> Vec<ClaimChainEntry> {
        // Compute readiness for the new entry BEFORE taking the &mut borrow.
        let ready_now = self.cheque_sender_registered(cheque_id);

        let chain = self.claim_chains.entry(client_pk.to_vec()).or_default();
        match chain.iter_mut().find(|e| &e.cheque_id == cheque_id) {
            Some(existing) => {
                // Idempotent re-claim: keep the original ordering key so a
                // re-touch cannot reshuffle the chain.
                existing.sender_registered = ready_now;
            }
            None => {
                chain.push(ClaimChainEntry {
                    cheque_id: *cheque_id,
                    first_claim_tick: tick,
                    sender_registered: ready_now,
                });
                chain.sort_by_key(|e| e.first_claim_tick);
                if chain.len() > MAX_CLAIM_CHAIN {
                    chain.remove(0);
                }
            }
        }
        let snapshot: Vec<TxHash> = chain.iter().map(|e| e.cheque_id).collect();

        // Re-derive readiness for the REST of the chain. This is the lazy
        // recheck: one touch refreshes every entry, so a client that comes back
        // after a long absence learns everything that changed while it was gone.
        let refreshed: Vec<bool> = snapshot
            .iter()
            .map(|id| self.cheque_sender_registered(id))
            .collect();
        let chain = self.claim_chains.get_mut(client_pk).expect("just inserted");
        for (e, r) in chain.iter_mut().zip(refreshed) {
            e.sender_registered = r;
        }
        chain.clone()
    }

    /// Read a claimant's chain without touching it (diagnostics / operators).
    pub fn claim_chain(&self, client_pk: &[u8]) -> Option<&Vec<ClaimChainEntry>> {
        self.claim_chains.get(client_pk)
    }

    /// YPX-010 §14 — is the SENDER's transaction for this cheque registered here?
    ///
    /// This is the readiness answer a receiver needs BEFORE redeeming.
    ///
    /// The receiver CAN register its own link either way — this test
    /// (`existing.current_state != reg.old_state`) looks only at the
    /// registering wallet's own bucket and never consults the sender. What the
    /// receiver cannot do is CLEAR the resulting scar: under YPX-001 §1.5.1a
    /// its redeem link inherits the sender's unresolved txid, and
    /// `fact.rs::verify_fact_chain` counts a link as resolved only when
    /// `nabla_confirmation.is_some() && inherited_unresolved() == 0` — a
    /// confirmed-but-tainted link stays scarred until the ORIGIN resolves.
    /// `heal()` re-registers the receiver's own tip and has no power over the
    /// origin, so the only self-service exit is a BURN, which discharges the
    /// taint by destroying the value.
    ///
    /// So the cure is not to repair afterwards but to not take the taint on.
    ///
    /// NOT YET OBSERVED LIVE: inspecting all 20 wallets of the 6h run
    /// s2r85774548 found 123 links and ZERO inherited scar txids. That run's
    /// 64 burn-escapes were KI#52 (own failed registration, wallet >1 link
    /// ahead of Nabla, heal can only re-register the tip) — a different bug.
    /// Do not cite them as evidence for this path.
    ///
    /// **Reports; never rejects.** Core deliberately allows scarred money —
    /// *"Core does NOT reject scarred money — that is the RECEIVER's
    /// decision."* A receiver that wants a cheque from a party it trusts may
    /// still take it. This only supplies the fact.
    ///
    /// **NOT the txid service.** An earlier version of this asked
    /// `txid_index` / `may_contain_txid`, which was simply the wrong question:
    /// that service is the REDEEMED domain, fed only at redeem-finalize
    /// ("ONE txid domain, 2026-07-07" — deliberately NOT populated by every
    /// registration). A plain send never enters it, so every unredeemed cheque
    /// answered "not registered" — a false negative on ALL of them, which is
    /// exactly what a live batch showed: 0 ready out of 10, and a fresh
    /// wallet's healthy send reported unbacked.
    ///
    /// **ForkSettlement wave 3 [R5] — the answer now comes from the ORIGIN
    /// LEDGER:** "does THIS node hold a verified SEND-leg record for this
    /// txid?" (`origin_ledger`). Two HIGH-1 cases therefore no longer answer
    /// true: the receiver's redeem-finalize head (keyed on the cheque txid) and
    /// a head rebuilt from a snapshot/WAL `Put` — neither is the sender's
    /// verified leg. Membership only: whether the record is VOUCHABLE
    /// (uncontested, registrant not banned, key not held) is the separate,
    /// stricter question `NablaNode::origin_vouch` answers (plan A9 — not
    /// folded in here).
    ///
    /// Writers of the ledger (wave 3 S5–S7, 2026-09-28): the door (after 5b′),
    /// the flood and the AE record hooks (`ban::record_leg_and_detect`) and
    /// the `ForkBan` adoption (`ban::adopt_fork_claim`) — so readiness is
    /// "true" again once the sender's register (or its flood / AE copy) has
    /// reached this node.
    pub fn cheque_sender_registered(&self, cheque_id: &TxHash) -> bool {
        self.origin_ledger.contains_key(cheque_id)
    }

    // ── ForkSettlement wave 3 — the origin ledger (§2.3, §2.4) ──────────────

    /// THE one creation point of a record (§2.4 [R11, R32]; W7b spec R52c):
    /// only a `ban::VerifiedForkLeg` can be recorded, so an unverified or
    /// zero-pk leg cannot become a record at compile time. A SEND leg goes to
    /// `origin_ledger`; a REDEEM leg to the SEPARATE `redeem_ledger` (never an
    /// origin, R5). Both join the shared `(pk, consumed)` index — EXCEPT a
    /// zero-consumed redeem (W7c, `ban.rs` [R33]): recorded as a grounding root
    /// (`zero_redeems`), never indexed, never a fork sibling. Every record
    /// created is queued for provenance derivation (W7c/W7d).
    ///
    /// Order — [R24] lives HERE so every caller inherits it:
    /// 1. leg already recorded → `Duplicate` (write-once; nothing changes).
    /// 2. `held_other` = the legs already under `(pk, consumed)`.
    /// 3. `contested = held_other.is_empty() && is_state_consumed(consumed)`
    ///    [R16], evaluated NOW — EXCEPT when this node's head for the leg's
    ///    bucket already IS this leg (`current_state == new_state`, `tx_hash
    ///    == txid`, previous state `consumed`): the consumption is the leg's
    ///    own (R24's sanctioned exclusion; the HalAdvance carrier, §9m B1). ⚠ [R24] every caller MUST invoke this BEFORE
    ///    its own `put_with_proof`: `put_inner` inserts the consumed head into
    ///    `consumed_chain` in the same write that installs the child, so a
    ///    record made after the put would see its OWN consumption as "consumed,
    ///    no sibling" and every honest register would be born contested.
    ///    [R23] the source is honest about its trust: `is_state_consumed` is
    ///    the era-bloom UNION (own seq-changing puts AND unauthenticated
    ///    `merge_consumed_era` bootstrap merges) plus the KI#65
    ///    `same_seq_provisional_index` (plan A21) — a false "consumed" can
    ///    only WITHHOLD this node's vouch (contested ≠ claim; no ban follows).
    /// 4. insert `{leg, first_seen_secs: now_secs, contested}`, index it, and
    ///    queue it for the WAL [R19] (`OriginRecord` / `RedeemRecord`).
    /// 5. `Conflict { held }` if another leg was under the key, else
    ///    `Created { contested }`.
    ///
    /// `now_secs` is the binary's `virtual_secs` (wall clock) [R13] — never a
    /// TARDIS tick, never `entry.tick`.
    ///
    /// Production callers: `ban::record_leg_and_detect` (the door / flood / AE
    /// record hooks) and `ban::adopt_fork_claim` (the `ForkBan` receiver).
    pub fn record_verified_leg(
        &mut self,
        leg: crate::ban::VerifiedForkLeg,
        now_secs: u64,
    ) -> OriginOutcome {
        self.record_verified_leg_opt(leg, now_secs, None)
    }

    /// [`Self::record_verified_leg`] with the record-AE flag (Fork Settlement
    /// §9o [R58]; ONE body — RULE 1): `upgrade` is the node's GRADE
    /// (`ban::leg_is_directory_witnessed` over its R42 directory). With it, a
    /// leg ALREADY recorded as an UNGRADED copy is replaced in place by a
    /// GRADED copy of the same `(key, txid, kind)` whose `new_state` and
    /// `client_sig` are equal — `first_seen_secs` and `contested` are KEPT
    /// (R27: never recomputed) — and the outcome is [`OriginOutcome::
    /// Upgraded`]. Every other held copy stays `Duplicate`. `None` = every
    /// non-record-AE path: write-once, exactly as before.
    pub fn record_verified_leg_opt(
        &mut self,
        leg: crate::ban::VerifiedForkLeg,
        now_secs: u64,
        upgrade: Option<&dyn Fn(&ForkLeg) -> bool>,
    ) -> OriginOutcome {
        let txid = leg.tx_hash();
        let key: OriginKey = (leg.client_pk(), leg.consumed());
        if let Some(graded) = upgrade {
            if let Some(o) = self.try_upgrade(&leg, key, graded) {
                return o;
            }
        }
        // W7c (plan §7 prerequisite, F8) — a ZERO-consumed redeem (a fresh
        // wallet's first receive) is RECORDED as a grounding root but joins
        // no fork index [R33]: a zero parent is nobody's sibling.
        if key.1 == [0u8; 32] && leg.kind() == axiom_core_logic::types::LegKind::Redeem {
            if self.redeem_ledger.contains_key(&(key, txid)) {
                return OriginOutcome::Duplicate;
            }
            let entry = OriginLedgerEntry { leg: leg.into_leg(), first_seen_secs: now_secs, contested: false };
            self.insert_zero_redeem(key, txid, entry);
            self.redeem_wal_pending.push((key, txid));
            self.redeem_records_created = self.redeem_records_created.saturating_add(1);
            return OriginOutcome::Created { contested: false };
        }
        let member = match leg.kind() {
            axiom_core_logic::types::LegKind::Send => {
                if self.origin_ledger.contains_key(&txid) {
                    return OriginOutcome::Duplicate;
                }
                LegRef::Send(txid)
            }
            axiom_core_logic::types::LegKind::Redeem => {
                if self.redeem_ledger.contains_key(&(key, txid)) {
                    return OriginOutcome::Duplicate;
                }
                LegRef::Redeem(txid)
            }
        };
        let held_other: Vec<LegRef> = self
            .origin_index
            .get(&key)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();
        // [R24] exclusion — "the head this very leg consumed" (design §9m, live
        // finding 2026-09-29, B1). A HAL re-anchor reaches non-door nodes as
        // `GossipMessage::HalAdvance`, which carries NO SeqProof: the head is
        // adopted (marking `consumed` consumed) with NO record, and the leg
        // arrives LATER by anti-entropy — a fourth head carrier R24 did not
        // list. Its own consumption then read "consumed, no sibling" and every
        // honest HAL record was born contested (immutable, R27) at every node
        // but the door. When this node's head for the leg's bucket IS this leg
        // (`current_state == new_state`, `tx_hash == txid`) and the head it
        // replaced WAS `consumed`, the consumption is this leg's own. A hidden
        // sibling leaves a different head or a different previous state, so
        // it still reads contested (R16 unchanged for the second-hand mark).
        let own_consumption = {
            let l = leg.leg();
            self.get(&l.bucket())
                .is_some_and(|h| h.current_state == l.new_state && h.tx_hash == txid)
                && self.previous_state(&l.bucket()) == Some(key.1)
        };
        let contested = held_other.is_empty() && self.is_state_consumed(&key.1) && !own_consumption;
        let entry = OriginLedgerEntry { leg: leg.into_leg(), first_seen_secs: now_secs, contested };
        match member {
            LegRef::Send(_) => {
                self.origin_ledger.insert(txid, entry);
                self.origin_wal_pending.push(txid);
                self.origin_records_created = self.origin_records_created.saturating_add(1);
            }
            LegRef::Redeem(_) => {
                self.redeem_ledger.insert((key, txid), entry);
                let keys = self.redeem_by_cheque.entry(txid).or_default();
                if !keys.contains(&key) {
                    keys.push(key);
                }
                self.redeem_wal_pending.push((key, txid));
                self.redeem_records_created = self.redeem_records_created.saturating_add(1);
            }
        }
        self.origin_index.entry(key).or_default().insert(member);
        // W7c/W7d — derive the new leg; on a second leg (a fork learned by
        // door, flood, AE or ForkBan) re-derive EVERY leg under the key, and so
        // everything descended from it (M3, retroactive — TLA+ c19).
        self.provenance_pending.push((key, member));
        for m in &held_other {
            self.provenance_pending.push((key, *m));
        }
        if held_other.is_empty() {
            OriginOutcome::Created { contested }
        } else {
            OriginOutcome::Conflict {
                held: held_other
                    .iter()
                    .filter_map(|m| self.leg_record(&key, m).cloned())
                    .collect(),
            }
        }
    }

    /// The upgrade arm of [`Self::record_verified_leg_opt`]: `Some(Upgraded)`
    /// if the held copy of this very leg is ungraded and `leg` is graded;
    /// `None` (fall through to the write-once path) otherwise.
    fn try_upgrade(
        &mut self,
        leg: &crate::ban::VerifiedForkLeg,
        key: OriginKey,
        graded: &dyn Fn(&ForkLeg) -> bool,
    ) -> Option<OriginOutcome> {
        let txid = leg.tx_hash();
        let member = match leg.kind() {
            axiom_core_logic::types::LegKind::Send => LegRef::Send(txid),
            axiom_core_logic::types::LegKind::Redeem => LegRef::Redeem(txid),
        };
        let new = leg.leg();
        let held = match member {
            LegRef::Send(t) => self.origin_ledger.get_mut(&t),
            LegRef::Redeem(t) => self.redeem_ledger.get_mut(&(key, t)),
        }?;
        let same_leg = held.leg.key() == key
            && held.leg.kind() == new.kind()
            && held.leg.new_state == new.new_state
            && held.leg.client_sig == new.client_sig;
        if !same_leg || graded(&held.leg) || !graded(new) {
            return None;
        }
        held.leg = new.clone();
        match member {
            LegRef::Send(t) => self.origin_wal_pending.push(t),
            LegRef::Redeem(t) => self.redeem_wal_pending.push((key, t)),
        }
        self.origin_records_upgraded = self.origin_records_upgraded.saturating_add(1);
        // The producer admission (R42) now sees the graded witnesses.
        self.provenance_pending.push((key, member));
        Some(OriginOutcome::Upgraded)
    }

    /// Every record held — origin and redeem ledgers, zero-consumed roots
    /// included — as `(key, member, entry)`. Read by `NablaNode`'s record-trie
    /// rebuild at `open` (Fork Settlement §9o [R58]).
    pub fn records(&self) -> impl Iterator<Item = (OriginKey, LegRef, &OriginLedgerEntry)> {
        self.origin_ledger
            .iter()
            .map(|(t, e)| (e.leg.key(), LegRef::Send(*t), e))
            .chain(self.redeem_ledger.iter().map(|((k, t), e)| (*k, LegRef::Redeem(*t), e)))
    }

    /// The record a shared-index member names, from whichever ledger holds it.
    pub fn leg_record(&self, key: &OriginKey, member: &LegRef) -> Option<&OriginLedgerEntry> {
        match member {
            LegRef::Send(t) => self.origin_ledger.get(t),
            LegRef::Redeem(t) => self.redeem_ledger.get(&(*key, *t)),
        }
    }

    /// Restore ONE persisted ORIGIN record verbatim — snapshot restore and WAL
    /// `OriginRecord` replay [R27]: an insert + index insert. It NEVER
    /// recomputes `contested` (R24: at replay the parent's consumption is
    /// already in the bloom, so a recompute would flip every honest record to
    /// contested) and NEVER re-verifies (the ledger is this node's own trusted
    /// state — the same basis as `restore_seq_proofs`). Never queues a WAL op.
    /// ~~pure `or_insert` — first copy wins~~ (until W1): since record-AE's
    /// in-place UPGRADE (§9o [R58]) re-logs an upgraded record, the LAST copy
    /// of the SAME leg (same key, kind, `new_state`, `client_sig`) wins —
    /// replay runs in WAL order after the snapshot, so the last copy is the
    /// newest. A persisted copy of a DIFFERENT leg under a held txid is
    /// refused (logged; the held one stays). WALs written before W1 hold no
    /// duplicates, so they restore exactly as before.
    /// Returns false (and logs an ERROR) for an entry whose leg carries no
    /// SEND preimage: a redeem leg is never an origin (R5, W7b) — impossible
    /// for a record this code wrote.
    pub fn restore_origin_entry(&mut self, txid: TxHash, entry: OriginLedgerEntry) -> bool {
        if entry.leg.send_preimage().is_none() {
            log::error!(
                "[ORIGIN-RESTORE-REFUSED] tx {} — persisted origin record has no send \
                 preimage; not restored (an origin record is only ever made from a \
                 verified Send leg — this is corruption or a foreign file)",
                hex::encode(&txid[..4]),
            );
            return false;
        }
        let key = entry.leg.key();
        if !Self::restore_last_copy_wins(self.origin_ledger.get_mut(&txid), &entry) {
            self.origin_ledger.insert(txid, entry);
        }
        self.origin_index.entry(key).or_default().insert(LegRef::Send(txid));
        // W7c — verdicts are NOT persisted (plan C6): every restored record is
        // re-derived at load, before the node listens.
        self.provenance_pending.push((key, LegRef::Send(txid)));
        true
    }

    /// Restore ONE persisted REDEEM record verbatim (W7b) — snapshot restore
    /// and WAL `RedeemRecord` replay, the same [R27] rules as
    /// `restore_origin_entry`. Refuses (false, ERROR) an entry that is not a
    /// redeem leg or whose leg does not match its persisted id.
    pub fn restore_redeem_entry(&mut self, id: RedeemRecordId, entry: OriginLedgerEntry) -> bool {
        let (key, cheque) = id;
        if entry.leg.redeem_preimage().is_none() || entry.leg.key() != key || entry.leg.tx_hash != cheque {
            log::error!(
                "[REDEEM-RESTORE-REFUSED] cheque {} — persisted redeem record is not the \
                 redeem leg its id names; not restored (corruption or a foreign file)",
                hex::encode(&cheque[..4]),
            );
            return false;
        }
        if key.1 == [0u8; 32] {
            // W7c — a zero-consumed redeem: a grounding root, never indexed.
            if !Self::restore_last_copy_wins(self.redeem_ledger.get_mut(&id), &entry) {
                self.insert_zero_redeem(key, cheque, entry);
            }
            return true;
        }
        if !Self::restore_last_copy_wins(self.redeem_ledger.get_mut(&id), &entry) {
            self.redeem_ledger.insert(id, entry);
        }
        let keys = self.redeem_by_cheque.entry(cheque).or_default();
        if !keys.contains(&key) {
            keys.push(key);
        }
        self.origin_index.entry(key).or_default().insert(LegRef::Redeem(cheque));
        self.provenance_pending.push((key, LegRef::Redeem(cheque)));
        true
    }

    /// The restore rule for an id already held (Fork Settlement §9o [R58]):
    /// `held = None` → `false` (the caller inserts). A copy of the SAME leg
    /// replaces the held one (last copy wins — an upgrade re-logged); a
    /// DIFFERENT leg under the id is refused with an ERROR (corruption or a
    /// foreign file). Returns `true` when the id was held (handled here).
    fn restore_last_copy_wins(held: Option<&mut OriginLedgerEntry>, entry: &OriginLedgerEntry) -> bool {
        let Some(held) = held else { return false };
        let same_leg = held.leg.key() == entry.leg.key()
            && held.leg.kind() == entry.leg.kind()
            && held.leg.tx_hash == entry.leg.tx_hash
            && held.leg.new_state == entry.leg.new_state
            && held.leg.client_sig == entry.leg.client_sig;
        if same_leg {
            *held = entry.clone();
        } else {
            log::error!(
                "[RECORD-RESTORE-REFUSED] tx {} — a persisted copy of a DIFFERENT leg under a \
                 held record id; the held record stays (corruption or a foreign file)",
                hex::encode(&entry.leg.tx_hash[..4]),
            );
        }
        true
    }

    /// W7c — the ONE insert of a zero-consumed redeem record (live record and
    /// restore): redeem ledger + `redeem_by_cheque` + `zero_redeems`, NOT the
    /// fork index. Queues every zero redeem of the pk for derivation — a
    /// second one flips the first from root to WAIT (F8).
    fn insert_zero_redeem(&mut self, key: OriginKey, cheque: TxHash, entry: OriginLedgerEntry) {
        self.redeem_ledger.insert((key, cheque), entry);
        let keys = self.redeem_by_cheque.entry(cheque).or_default();
        if !keys.contains(&key) {
            keys.push(key);
        }
        let set = self.zero_redeems.entry(key.0).or_default();
        set.insert(cheque);
        for c in set.iter() {
            self.provenance_pending.push((key, LegRef::Redeem(*c)));
        }
    }

    /// W7c — how many zero-consumed redeems are recorded for `pk` (the F8
    /// root rule: exactly one grounds).
    pub fn zero_redeem_count(&self, pk: &[u8; 32]) -> usize {
        self.zero_redeems.get(pk).map_or(0, |s| s.len())
    }

    /// W7c/W7d — drain the legs queued for provenance derivation. The ONE
    /// consumer is `NablaNode::drain_fork_side_effects`.
    pub fn take_provenance_pending(&mut self) -> Vec<(OriginKey, LegRef)> {
        std::mem::take(&mut self.provenance_pending)
    }

    /// W7c — is any leg queued for derivation (not yet handed to the engine)?
    pub fn has_provenance_pending(&self) -> bool {
        !self.provenance_pending.is_empty()
    }

    /// The ORIGIN record for `txid`, if held — `origin_ledger` ONLY, never a
    /// redeem record (R5, W7b). Vouchability is NOT decided here — see
    /// `NablaNode::origin_vouch`.
    ///
    /// Read by `NablaNode::origin_vouch` (the attestation signer).
    pub fn vouch_record(&self, txid: &TxHash) -> Option<&OriginLedgerEntry> {
        self.origin_ledger.get(txid)
    }

    /// The redeem record `(key, cheque)`, if held (W7b).
    ///
    /// Read by tests; the provenance engine reads records through
    /// `leg_record`. It decides nothing itself.
    pub fn redeem_record(&self, key: &OriginKey, cheque: &TxHash) -> Option<&OriginLedgerEntry> {
        self.redeem_ledger.get(&(*key, *cheque))
    }

    /// Every redeem record of cheque `cheque` — the forward edge "send t →
    /// redeems of t" (spec R52c `redeem_by_cheque`), sorted by key.
    ///
    /// Read by `provenance::Provenance` (W7c's cascade: a re-derived send
    /// re-queues the redeems of its cheque).
    pub fn redeem_records_of_cheque(&self, cheque: &TxHash) -> Vec<(OriginKey, &OriginLedgerEntry)> {
        let mut keys = self.redeem_by_cheque.get(cheque).cloned().unwrap_or_default();
        keys.sort();
        keys.into_iter()
            .filter_map(|k| self.redeem_ledger.get(&(k, *cheque)).map(|e| (k, e)))
            .collect()
    }

    /// Is the ATRAXI key HELD (§2.3 "derived, never stored apart")? True when
    /// the key carries ≥ 2 legs (a fork — send or redeem, the shared index;
    /// covers the 3-way fork even though `ban_fork` stores one pair) OR any
    /// record under it was born contested. A held key vouches for none of its
    /// records.
    ///
    /// Read by `NablaNode::origin_vouch` (ForkSettlement §2.4).
    pub fn origin_key_is_held(&self, key: &OriginKey) -> bool {
        match self.origin_index.get(key) {
            None => false,
            Some(set) => {
                set.len() > 1
                    || set
                        .iter()
                        .any(|m| self.leg_record(key, m).is_some_and(|e| e.contested))
            }
        }
    }

    /// Every key carrying ≥ 2 legs — the claims the records already prove
    /// [R28] (send and redeem records alike, W7b). Sorted, so the load-time
    /// re-derivation is deterministic.
    pub fn origin_conflicting_keys(&self) -> Vec<OriginKey> {
        let mut keys: Vec<OriginKey> = self
            .origin_index
            .iter()
            .filter(|(_, set)| set.len() >= 2)
            .map(|(k, _)| *k)
            .collect();
        keys.sort();
        keys
    }

    /// The legs recorded under `key`, ascending.
    pub fn legs_under(&self, key: &OriginKey) -> Vec<LegRef> {
        self.origin_index
            .get(key)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Drain the origin records created since the last drain, for the WAL
    /// [R19]. The ONE consumer is `NablaNode::drain_fork_side_effects`.
    pub fn take_origin_wal_pending(&mut self) -> Vec<(TxHash, OriginLedgerEntry)> {
        std::mem::take(&mut self.origin_wal_pending)
            .into_iter()
            .filter_map(|t| self.origin_ledger.get(&t).map(|e| (t, e.clone())))
            .collect()
    }

    /// Drain the redeem records created since the last drain, for
    /// `WalOp::RedeemRecord` (W7b). The ONE consumer is
    /// `NablaNode::drain_fork_side_effects`.
    pub fn take_redeem_wal_pending(&mut self) -> Vec<(RedeemRecordId, OriginLedgerEntry)> {
        std::mem::take(&mut self.redeem_wal_pending)
            .into_iter()
            .filter_map(|id| self.redeem_ledger.get(&id).map(|e| (id, e.clone())))
            .collect()
    }

    /// The whole origin ledger, for `NablaSnapshot.origin_ledger` (Q5).
    /// Sorted by txid so two snapshots of one ledger are byte-identical.
    pub fn origin_ledger_snapshot(&self) -> Vec<(TxHash, OriginLedgerEntry)> {
        let mut v: Vec<(TxHash, OriginLedgerEntry)> =
            self.origin_ledger.iter().map(|(t, e)| (*t, e.clone())).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// The whole redeem ledger, for `NablaSnapshot.redeem_ledger` (W7b).
    /// Sorted by id so two snapshots of one ledger are byte-identical.
    pub fn redeem_ledger_snapshot(&self) -> Vec<(RedeemRecordId, OriginLedgerEntry)> {
        let mut v: Vec<(RedeemRecordId, OriginLedgerEntry)> =
            self.redeem_ledger.iter().map(|(id, e)| (*id, e.clone())).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Ledger size (gauge). On `/status` as `origin_records`.
    pub fn origin_len(&self) -> usize {
        self.origin_ledger.len()
    }

    /// Records born contested (gauge). On `/status` as `origin_records_contested`.
    pub fn origin_contested_len(&self) -> usize {
        self.origin_ledger.values().filter(|e| e.contested).count()
    }

    /// Redeem ledger size (gauge). On `/status` as `redeem_records`.
    pub fn redeem_len(&self) -> usize {
        self.redeem_ledger.len()
    }

    /// Redeem records born contested (gauge). On `/status` as
    /// `redeem_records_contested`.
    pub fn redeem_contested_len(&self) -> usize {
        self.redeem_ledger.values().filter(|e| e.contested).count()
    }

    /// Redeem records created (cumulative). On `/status` as
    /// `redeem_records_created`.
    pub fn redeem_records_created(&self) -> u64 {
        self.redeem_records_created
    }

    /// Records created (cumulative). On `/status` as `origin_records_created`.
    pub fn origin_records_created(&self) -> u64 {
        self.origin_records_created
    }

    /// Ungraded copies upgraded in place by record-AE (cumulative, §9o [R58]).
    /// On `/status` as `origin_records_upgraded`.
    pub fn origin_records_upgraded(&self) -> u64 {
        self.origin_records_upgraded
    }


    /// Current txid service mode.
    pub fn txid_mode(&self) -> TxidServiceMode {
        self.txid_mode
    }

    /// Number of (txid → wallet_id) entries in the exact hashmap.
    /// Only populated when `txid_mode == Hashmap`; always 0 in bloom
    /// mode. Surfaced on `/status` so operators can see how the
    /// hashmap is growing under traffic and capacity-plan accordingly.
    pub fn txid_hashmap_len(&self) -> usize {
        self.txid_index.len()
    }

    /// Estimated resident bytes used by the exact hashmap. Conservative:
    /// each entry is `[u8; 32]` key + `[u8; 32]` value + ~1.5× hashbrown
    /// overhead → ~96 bytes/entry. Always 0 in bloom mode.
    pub fn txid_hashmap_bytes(&self) -> u64 {
        self.txid_index.len() as u64 * 96
    }

    /// Number of distinct txids inserted into the bloom filter since
    /// boot. ALWAYS populated — bloom rides alongside the hashmap in
    /// hashmap mode (acts as a fast negative-lookup pre-check), and is
    /// the only tier in bloom mode.
    pub fn txid_bloom_count(&self) -> u64 {
        self.txid_chain.metadata().iter().map(|m| m.entry_count).sum()
    }

    /// Physical bytes of the bloom filter. Fixed at boot from the
    /// `--bloom-size` flag (default sized for 10M txids ≈ 18 MB).
    pub fn txid_bloom_bytes(&self) -> u64 {
        // Sum across eras — total resident cost, which is what an operator budgets.
        self.txid_chain
            .metadata()
            .iter()
            .filter_map(|m| self.txid_chain.era(m.era_id))
            .map(|e| e.filter.size_bytes() as u64)
            .sum()
    }

    /// Current bloom-filter false-positive rate, computed from the
    /// observed load. Operators watch this — when it climbs past a few
    /// percent the bloom is saturated and `/query-txid` answers get
    /// noisy. Domain: `[0.0, 1.0]`.
    pub fn txid_bloom_fpr(&self) -> f64 {
        // Union across E eras multiplies exposure: 1-(1-p_i) over all eras. This is
        // the number that matters, not any single era's — it is what a lookup
        // actually faces.
        let mut clean = 1.0f64;
        for m in self.txid_chain.metadata() {
            if let Some(era) = self.txid_chain.era(m.era_id) {
                clean *= 1.0 - era.filter.estimated_fpr();
            }
        }
        1.0 - clean
    }

    /// KI#42 telemetry — the consumed-state bloom had NO exposed health signal at
    /// all, despite being the filter whose false positives fail CLOSED at the A12
    /// anti-rollback gate. Both are lifetime flat filters that never roll over, so
    /// these numbers only climb; treat a rising FPR as a countdown, not a blip.
    /// Fix plan: `AXIOM_DESIGN_NablaAntiEntropy.md` §12.
    pub fn consumed_bloom_count(&self) -> u64 {
        self.consumed_chain.metadata().iter().map(|m| m.entry_count).sum()
    }

    /// Estimated false-positive rate of the consumed-state bloom. A false positive
    /// here REJECTS A LEGITIMATE registration as a replay.
    pub fn consumed_bloom_fpr(&self) -> f64 {
        // Union exposure across eras — what a lookup actually faces.
        let mut clean = 1.0f64;
        for m in self.consumed_chain.metadata() {
            if let Some(era) = self.consumed_chain.era(m.era_id) {
                clean *= 1.0 - era.filter.estimated_fpr();
            }
        }
        1.0 - clean
    }

    /// Fill ratio of the ACTIVE era against per-era capacity. Post-migration this
    /// RESETS on rotation instead of climbing forever — frozen eras have fixed FPR,
    /// so only the active era can overflow. That reset is the fix.
    pub fn consumed_bloom_fill_ratio(&self) -> f64 {
        // Against PER-ERA capacity, not the old global constant — the number now
        // answers "how full is the era that can still overflow".
        let expected = self.consumed_chain.expected_items_per_era();
        if expected == 0 { return 0.0; }
        self.consumed_chain.active_era().filter.count() as f64 / expected as f64
    }

    /// Same ratio for the txid chain's active era.
    pub fn txid_bloom_fill_ratio(&self) -> f64 {
        let expected = self.txid_chain.expected_items_per_era();
        if expected == 0 { return 0.0; }
        // Per-era fill of the ACTIVE era: that is the one that can still overflow.
        // Frozen eras are immutable and their FPR is fixed, which is the whole point
        // of rotating — fill is no longer an unbounded lifetime number.
        self.txid_chain.active_era().filter.count() as f64 / expected as f64
    }

    /// Get a reference to the bloom filter (for persistence / export).
    /// The consumed-STATE chain, for callers that must ask "was this state
    /// advanced past?" (CLARA freshness). Read-only: only `put()` and the
    /// StatePull re-arm may write it.
    /// DEV-MODE ONLY (KI#43b live gate): stage a synthetic consumed-bloom
    /// FALSE POSITIVE — insert into the bloom WITHOUT recording an exact
    /// mark. This is precisely the divergence a real bloom FP creates and
    /// the only way to stage one on demand. Callers must gate on dev mode;
    /// `is_state_consumed` will now answer true for a state that was never
    /// consumed, which is the input the §12.4.4 barrier must refute.
    pub fn dev_inject_consumed_bloom_fp(&mut self, tick: u64, state: &StateId) {
        self.consumed_chain.insert(tick, state);
    }

    pub fn consumed_chain(&self) -> &crate::bloom_chain::BloomChain {
        &self.consumed_chain
    }

    pub fn txid_chain(&self) -> &crate::bloom_chain::BloomChain {
        &self.txid_chain
    }

    /// Mutable access for era sync (`merge_era` from a StatePull payload).
    pub fn txid_chain_mut(&mut self) -> &mut crate::bloom_chain::BloomChain {
        &mut self.txid_chain
    }

    /// Replace the bloom filter (for loading from disk on restart).


    /// Generate merkle proof for a wallet entry.
    /// Collects sibling hashes along the path from leaf to root.
    /// Used by bottom-up audit — verifier checks proof against known root.
    pub fn merkle_proof(&self, wallet_id: &WalletId) -> MerkleProof {
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        Self::collect_siblings(&self.root, wallet_id, 0, &mut siblings);
        MerkleProof {
            key: *wallet_id,
            siblings,
        }
    }

    /// Verify a merkle proof against a root hash.
    /// Used by downstream to audit upstream WITHOUT transferring raw data.
    ///
    /// SEC-16 / PRE-PROMOTION GUARD: this SMT is NOT yet a trust anchor.
    /// `verify_proof` has no production caller today — trust derives from
    /// k=3 Dilithium witness sigs, and the SMT root in
    /// `NablaConfirmation.root_hash` is NOT covered by the confirmation
    /// signature. Before ANY path is allowed to make a Core/Lambda trust
    /// decision off this proof, the SEC-16 items must be fully closed:
    /// (1) leaf/internal domain separation [DONE — SMT_LEAF/INTERNAL_DOMAIN],
    /// (2) proof-length bound [DONE — see below],
    /// (3) an explicit non-inclusion proof API distinct from inclusion.
    /// Do not wire this into a trust role until (3) lands.
    pub fn verify_proof(root: &Hash256, proof: &MerkleProof, entry: &NablaEntry) -> bool {
        // SEC-16: `proof.siblings` is untrusted input. The verify loop uses
        // the sibling index as a key bit position, so a vector longer than
        // the tree depth would index past the 32-byte key (OOB panic =
        // remote DoS). Reject before touching the key.
        if proof.siblings.len() > TREE_DEPTH {
            return false;
        }
        let serialized = match bincode::serialize(entry) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let mut hash = hash_leaf(&proof.key, &serialized);

        // Siblings are collected top-down (root→leaf).
        // Verification reconstructs bottom-up (leaf→root), so iterate in reverse.
        for (i, sibling) in proof.siblings.iter().enumerate().rev() {
            let bit = get_bit(&proof.key, i);
            hash = if bit == 0 {
                hash_internal(&hash, sibling)
            } else {
                hash_internal(sibling, &hash)
            };
        }

        hash == *root
    }

    /// Subtree proof for the §5.5 bottom-up audit (AXIOM_GUIDE_Nabla.md).
    ///
    /// Descends along `prefix` for at most `prefix_bits` levels and returns
    /// `(subtree_hash, siblings)`:
    /// - `subtree_hash` — hash of the node where descent stopped (the prefix
    ///   node, or the leaf/empty subtree encountered on the way — this tree
    ///   is path-compressed, so a leaf can sit above the target depth);
    /// - `siblings` — the off-path hashes root→down, one per level actually
    ///   descended (`siblings.len()` ≤ `prefix_bits`).
    ///
    /// Folding the pair back up along the prefix bits reproduces this tree's
    /// root (see [`Self::verify_subtree_proof`]) — that binding is what an
    /// auditing child checks against the root the upstream ADVERTISED. The
    /// pre-2026-08-01 `subtree_hash_at` ignored the prefix entirely and
    /// returned the root hash, making the challenge unanswerable-wrongly —
    /// a check that could not fail.
    pub fn subtree_proof(&self, prefix: &[u8], prefix_bits: usize) -> (Hash256, Vec<Hash256>) {
        let target = prefix_bits.min(TREE_DEPTH);
        let mut key = [0u8; 32];
        let n = prefix.len().min(32);
        key[..n].copy_from_slice(&prefix[..n]);

        let mut siblings = Vec::with_capacity(target);
        let mut node: &Option<Box<TreeNode>> = &self.root;
        let mut depth = 0usize;
        while depth < target {
            match node {
                None => {
                    // Empty subtree on the path — its hash is the canonical
                    // empty hash for this depth.
                    return (empty_hash(TREE_DEPTH - depth), siblings);
                }
                Some(n_ref) => match n_ref.as_ref() {
                    TreeNode::Leaf { .. } => break, // compressed leaf on the path
                    TreeNode::Internal { left, right, .. } => {
                        let bit = get_bit(&key, depth);
                        let (next, sib) = if bit == 0 { (left, right) } else { (right, left) };
                        siblings.push(
                            sib.as_ref()
                                .map(|s| s.hash())
                                .unwrap_or_else(|| empty_hash(TREE_DEPTH - depth - 1)),
                        );
                        node = next;
                        depth += 1;
                    }
                },
            }
        }
        let subtree_hash = match node {
            Some(nd) => nd.hash(),
            None => empty_hash(TREE_DEPTH - depth),
        };
        (subtree_hash, siblings)
    }

    /// Verify a [`Self::subtree_proof`] against a claimed root: fold
    /// `subtree_hash` upward along `prefix`, combining with `siblings`
    /// bottom-up. SEC-16 style: `siblings` is untrusted — its length is
    /// bounded before use.
    pub fn verify_subtree_proof(
        root: &Hash256,
        prefix: &[u8],
        subtree_hash: &Hash256,
        siblings: &[Hash256],
    ) -> bool {
        if siblings.len() > TREE_DEPTH || siblings.len() > prefix.len().saturating_mul(8) {
            return false;
        }
        let mut key = [0u8; 32];
        let n = prefix.len().min(32);
        key[..n].copy_from_slice(&prefix[..n]);

        let mut hash = *subtree_hash;
        for (i, sib) in siblings.iter().enumerate().rev() {
            hash = if get_bit(&key, i) == 0 {
                hash_internal(&hash, sib)
            } else {
                hash_internal(sib, &hash)
            };
        }
        hash == *root
    }

    /// Get all entries (for snapshot serialization).
    pub fn entries(&self) -> &HashMap<WalletId, NablaEntry> {
        &self.entries
    }

    /// `(wallet_id, leaf_hash)` for every entry — the anti-entropy digest
    /// (design `AXIOM_DESIGN_NablaAntiEntropy.md` §5.1). The leaf hash is
    /// `BLAKE3(wallet_id || bincode(entry))`, exactly what feeds the root,
    /// so two nodes whose leaf hashes match for a wallet hold a
    /// byte-identical `NablaEntry` for it.
    pub fn leaf_digest(&self) -> Vec<(WalletId, Hash256)> {
        self.entries
            .iter()
            .map(|(wid, entry)| (*wid, Self::entry_leaf_hash(wid, entry)))
            .collect()
    }

    /// Leaf hash for a single wallet, or `None` if the wallet is absent.
    pub fn leaf_hash(&self, wallet_id: &WalletId) -> Option<Hash256> {
        self.entries
            .get(wallet_id)
            .map(|entry| Self::entry_leaf_hash(wallet_id, entry))
    }

    /// `BLAKE3(wallet_id || bincode(entry))` — identical to the leaf hash
    /// `put()` commits into the tree.
    fn entry_leaf_hash(wallet_id: &WalletId, entry: &NablaEntry) -> Hash256 {
        let serialized =
            bincode::serialize(entry).expect("NablaEntry serialization cannot fail");
        hash_leaf(wallet_id, &serialized)
    }

    // ── Two-step cheque claim/confirm ──

    /// YPX-020 HAL: stamp the hibernation lock on a wallet at re-anchor register
    /// time. `until` = `register_tick + HIBERNATION_WINDOW` (Nabla's own tick) —
    /// stored as the completion deadline; the gate treats any non-zero as locked
    /// (binary), and `until` is the reference for the optional completion-window
    /// check at `HalComplete` register time.
    pub fn set_hibernation(&mut self, wallet_pk: [u8; 32], until: u64) {
        self.hibernations.insert(wallet_pk, until);
    }

    /// YPX-020 HAL: clear the hibernation flag — called on a `HalComplete`
    /// register (the wallet finished HAL). Canonical model: hibernation ends on
    /// COMPLETION, not by a clock.
    pub fn clear_hibernation(&mut self, wallet_pk: &[u8; 32]) -> bool {
        self.hibernations.remove(wallet_pk).is_some()
    }

    /// Tick until which `wallet_pk` is hibernating (0 = not hibernating).
    pub fn hibernation_until(&self, wallet_pk: &[u8; 32]) -> u64 {
        self.hibernations.get(wallet_pk).copied().unwrap_or(0)
    }

    /// Apply a hibernation received via gossip from a remote node (the wallet's
    /// re-anchor writer). Monotonic: only
    /// advances the lock (take the max `until`) so a stale/replayed gossip can't
    /// shorten it. Returns true if this changed local state (→ forward).
    ///
    /// ⚠ **UNAUTHENTICATED, AND DELIBERATELY INERT** (ghost audit G9, verified
    /// 2026-08-07). This accepts a bare `(client_pk, until)` from any peer: no
    /// signature, no reporter identity, and `until == 0` REMOVES the flag
    /// unconditionally, bypassing the monotonic rule above. `client_pk` is
    /// public, so anyone can name any wallet.
    ///
    /// That is safe today for one reason only: **this map gates nothing.** Its
    /// single read site is `registration.rs` §8a, an `else if` that CLEARS on a
    /// non-re-anchor register — it rejects no request. The map is not folded
    /// into `root_hash`, is not snapshotted, and is not served in any query
    /// response. YPX-020 §2b is explicit that "the authoritative 'out of work'
    /// lock is the wallet's own §15-anchored `hibernation_until` enforced at
    /// Core's SEND gate", and that the binary flag is "a clean-UX early-reject;
    /// the authoritative safety is Nabla + scar + fork-detection".
    ///
    /// **The moment anything REJECTS on this map, a forged packet becomes a
    /// remote send-lock on any wallet by public key.** Authenticate it first —
    /// carry the k=3 register attestation the way `SeqProof` does. The guard
    /// test `g9_forged_hibernation_cannot_block_a_register` fails if an
    /// enforcement read is added without that.
    ///
    /// The audit read this as an active attack; it is not, because the
    /// enforcement it would subvert was never wired. Recording the real reason
    /// so the next reader does not "fix" the inertness and arm the hole.
    pub fn apply_remote_hibernation(
        &mut self,
        client_pk: &[u8],
        until: u64,
        current_tick: u64,
    ) -> bool {
        if client_pk.len() != 32 {
            return false;
        }
        let pk: [u8; 32] = client_pk[..32].try_into().unwrap();
        // YPX-020 canonical model: `until == 0` is a HAL-completion CLEAR gossip —
        // remove the flag mesh-wide (the wallet finished HAL).
        if until == 0 {
            return self.hibernations.remove(&pk).is_some();
        }
        if self.hibernations.get(&pk).copied().unwrap_or(0) >= until {
            return false; // not newer
        }
        self.hibernations.insert(pk, until);
        true
    }

    /// Register a cheque claim (step 1).
    ///
    /// Returns Ok(()) on success (new claim or idempotent re-claim by same client).
    /// Errors:
    /// - "CONFLICT": a different client_pk already claimed this cheque_id
    ///
    /// YPX-020 §2: no hibernation gate here. The completion of a HAL session IS
    /// the claim+redeem of the distress cheque, so refusing a hibernating
    /// claimant would deadlock it. The authoritative "out of work" lock is the
    /// wallet's own §15-anchored `hibernation_until` enforced at Core's SEND gate
    /// (a hibernating wallet cannot SPEND); claiming/receiving is not spending.
    /// Core's CL5 clears that lock only on the SELF-redeem (the distress cheque),
    /// so an ordinary incoming-payment claim leaves the wallet send-locked. The
    /// anti-double-spend guarantee is the global SMT consume-once, independent of
    /// any claim-time gate (HAL A7). Clockless — the client self-times the window.
    ///
    /// YPX-022 §2.1.2a (KI#205): the caller has ALREADY authenticated `claim`
    /// (`registration::verify_cheque_claim`) — this is storage + first-wins
    /// only. `claim.claim_tick` is the tick the claim was MADE (the local tick
    /// on the TCP path; the originating node's tick on the gossip path, so the
    /// mesh converges on one value); `current_tick` is this node's clock, used
    /// only to evict a stale prior entry first.
    ///
    /// Returns `Ok(true)` when the claim was newly stored (the caller floods
    /// it), `Ok(false)` for an idempotent re-claim by the same key.
    pub fn register_cheque_claim(
        &mut self,
        cheque_id: [u8; 32],
        claim: ChequeClaim,
        current_tick: u64,
    ) -> Result<bool, String> {
        self.expire_claim_if_stale(&cheque_id, current_tick);

        if let Some(existing) = self.cheque_claims.get(&cheque_id) {
            if existing.client_pk != claim.client_pk {
                return Err("CONFLICT".to_string());
            }
            return Ok(false);
        }

        self.cheque_claims.insert(cheque_id, claim);
        Ok(true)
    }

    /// YPX-022 §2.1.2a item 2 — a claim's lifetime IS the recall window. It is
    /// stale once the send has aged past `recall_init_window_high` (`TOO_LATE`)
    /// — the same instant `register_recall` stops accepting a recall, so the
    /// claim blocks a recall for exactly as long as one is possible and never
    /// becomes a permanent record. The age base is the send's completion tick
    /// (`completed_txids`, Nabla's own monotonic ledger — the same base the
    /// recall window reads) and, only if this node never saw the completion,
    /// the claim's own tick. The window is account-keyed by the CLAIMANT's
    /// class (`is_dev_wallet(wallet_address)`; dev↔dev / real↔real are
    /// isolated, so it is the sender's class too).
    ///
    /// `now - base` is a difference of tick VALUES (unix seconds); the window is
    /// a tick COUNT — projected via `TickCount::to_secs`, never compared raw
    /// (KI#165 / KI#40; the `TickCount` type refuses the raw comparison).
    /// `>` mirrors `register_recall`'s `age_secs > win_high.to_secs()` exactly.
    fn claim_is_stale(&self, cheque_id: &[u8; 32], claim: &ChequeClaim, now: u64) -> bool {
        let base = self.completion_tick(cheque_id).unwrap_or(claim.claim_tick);
        let is_dev = axiom_core_logic::wallet_id::is_dev_wallet(&claim.wallet_address);
        let (_, win_high) = axiom_core_logic::types::recall_init_window(is_dev);
        now.saturating_sub(base) > win_high.to_secs()
    }

    fn expire_claim_if_stale(&mut self, cheque_id: &[u8; 32], current_tick: u64) {
        let stale = self
            .cheque_claims
            .get(cheque_id)
            .is_some_and(|c| self.claim_is_stale(cheque_id, c, current_tick));
        if stale {
            self.cheque_claims.remove(cheque_id);
        }
    }

    /// Query the current cheque claim entry for a cheque_id (as stored; the
    /// periodic `expire_stale_claims` sweep evicts stale ones).
    pub fn query_cheque_claim(&self, cheque_id: &[u8; 32]) -> Option<&ChequeClaim> {
        self.cheque_claims.get(cheque_id)
    }

    /// YPX-022 §2.1.2a — true iff an authenticated claim exists for `txid`
    /// and is still inside the recall window at `now` (`claim_is_stale`). THE
    /// delivery terminal `register_recall` and the recall-commit gate
    /// (`registration.rs` step 6b) read. Read-only: eviction happens on the
    /// next touch / sweep.
    pub fn has_live_claim(&self, txid: &TxHash, now: u64) -> bool {
        self.cheque_claims
            .get(txid)
            .is_some_and(|c| !self.claim_is_stale(txid, c, now))
    }

    /// Evict every claim whose send has aged past the recall window
    /// (`claim_is_stale`). Called from the node's periodic sweep.
    pub fn expire_stale_claims(&mut self, current_tick: u64) {
        let stale: Vec<[u8; 32]> = self
            .cheque_claims
            .iter()
            .filter(|(id, c)| self.claim_is_stale(id, c, current_tick))
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.cheque_claims.remove(&id);
        }
    }

    /// YPX-022 §2.1.2a item 1 (ii) — the `client_pk` registered on the head
    /// this node holds for the claimant's bucket, if any. The bucket is ONE
    /// derivation (`smt_bucket`, RULE 1); for an SDK register the SMT key IS
    /// the wallet's raw Ed25519 pk (`build_register_message` sets
    /// `wallet_id = wallet_pk`), so the claimant's `client_pk` is the key.
    /// `None` = un-anchored receiver on this node (layers (a)+(b) alone bind it).
    pub fn head_client_pk_for_claimant(&self, client_pk: &[u8], k_tier: u8) -> Option<[u8; 32]> {
        let pk: [u8; 32] = client_pk.try_into().ok()?;
        let bucket = crate::registration::smt_bucket(&pk, k_tier);
        self.get(&bucket).map(|e| e.client_pk)
    }

    /// YPX-022 §5 persistence — export the claim table for `NablaSnapshot`.
    pub fn cheque_claims_snapshot(&self) -> Vec<(TxHash, ChequeClaim)> {
        self.cheque_claims.iter().map(|(t, c)| (*t, c.clone())).collect()
    }

    /// YPX-022 §5 persistence — restore claims on boot. First-wins
    /// (`or_insert`) so a later merge never clobbers an earlier claim.
    pub fn restore_cheque_claims(&mut self, claims: Vec<(TxHash, ChequeClaim)>) {
        for (t, c) in claims {
            self.cheque_claims.entry(t).or_insert(c);
        }
    }

    /// RULE 3 §2 — recalls this node refused `CLAIMED` (cumulative).
    pub fn recalls_refused_claimed(&self) -> u64 {
        self.recalls_refused_claimed
    }

    // KI#156 (deleted 2026-09-21): the old unauthenticated `ChequeClaim` gossip
    // and its `apply_remote_cheque_claim` were removed as dead code. The LIVE
    // fan-out is `GossipMessage::ChequeClaimAnnounce` (2026-09-25, written
    // fresh with a live emitter on the TCP claim path): receivers re-verify
    // with `registration::verify_cheque_claim` and call `register_cheque_claim`.

    // ── YPX-022 RECALL ────────────────────────────────────────────────────

    /// Mark a txid as COMPLETION-registered (k-witnessed → redeemable). Called on
    /// the `process_registration` success path, mode-independent. Zero-txid no-op.
    pub fn mark_txid_completed(&mut self, txid: &TxHash, tick: u64) {
        if *txid == [0u8; 32] { return; }
        // Monotonic + first-wins on the tick: a re-mark (retry / gossip) keeps the
        // earliest completion tick, so the RECALL window is stable across the mesh.
        self.completed_txids.entry(*txid).or_insert(tick);
    }

    /// True iff the txid has a k-witnessed completion registration.
    pub fn is_txid_completed(&self, txid: &TxHash) -> bool {
        self.completed_txids.contains_key(txid)
    }

    /// The tick at which this txid was completion-registered (`None` if not completed).
    /// Used by the RECALL initiation-window check.
    pub fn completion_tick(&self, txid: &TxHash) -> Option<u64> {
        self.completed_txids.get(txid).copied()
    }

    /// YPX-022 §2 — mark a txid REDEEMED (the permanent consume-by-redeem terminal).
    /// Called at redeem-finalize (`process_registration`, receiver's register after
    /// redeem) so the flag outlives the transient §4.6 cheque-claim. Zero-txid no-op.
    pub fn mark_txid_redeemed(&mut self, txid: &TxHash) {
        if *txid == [0u8; 32] { return; }
        self.redeemed_txids.insert(*txid);
        // YPX-022 §2.2.1 — a redeem that finalizes while a recall RESERVATION
        // is open WINS: delete the reservation (the redeemed terminal IS the
        // abort record; the recall's commit register then refuses legibly).
        // A COMMITTED marker is the terminal and is never removed.
        if self.recalled_txids.get(txid).is_some_and(|m| m.phase == RecallPhase::Reserved) {
            self.recalled_txids.remove(txid);
        }
    }

    /// True iff the txid's cheque has been REDEEMED (receiver consumed it). The clean
    /// terminal signal the RECALL gate reads — never set by a plain send.
    pub fn is_txid_redeemed(&self, txid: &TxHash) -> bool {
        self.redeemed_txids.contains(txid)
    }

    /// True iff the txid's recall has COMMITTED (non-redeemable, terminal).
    /// A Reserved marker does NOT count — `C` stays redeemable until
    /// hibernation-entry (§2.2.1).
    /// YPX-001 §1.5.1a — mark a scarred origin txid resolved-by-burn.
    /// Insert-only, mode-independent (like the completion/redeem terminals).
    pub fn mark_txid_burn_resolved(&mut self, target: &TxHash) {
        self.burned_txids.insert(*target);
    }

    /// True if a k-witnessed burn named this txid as its target.
    pub fn is_txid_burn_resolved(&self, txid: &TxHash) -> bool {
        self.burned_txids.contains(txid)
    }

    /// KI#59 — record that this node emitted an OUT-OF-ORDER confirmation for
    /// `txid`. ⚠ Deliberately does NOT advance any head and does NOT touch
    /// `origin_ledger` (mirror `register_recall`, which also marks without a
    /// head advance): anti-rollback stays with the sequential head advance, and a
    /// later in-order head-registration of the same txid must still succeed. Idempotent.
    pub fn mark_ooo_attested(&mut self, txid: TxHash) {
        self.ooo_attested_txids.insert(txid);
    }

    /// KI#59 — true if this node has emitted an out-of-order confirmation for `txid`.
    pub fn is_txid_ooo_attested(&self, txid: &TxHash) -> bool {
        self.ooo_attested_txids.contains(txid)
    }

    pub fn is_txid_recalled(&self, txid: &TxHash) -> bool {
        self.recalled_txids.get(txid).is_some_and(|m| m.phase == RecallPhase::Committed)
    }

    /// True iff a recall RESERVATION is open on this txid (§2.2.1) — the
    /// unsigned `RETRACT_PENDING` in-flight notice query-txid serves.
    pub fn is_txid_recall_pending(&self, txid: &TxHash) -> bool {
        self.recalled_txids.get(txid).is_some_and(|m| m.phase == RecallPhase::Reserved)
    }

    /// §2.2.1 — true iff `sender_pk` holds an open recall reservation. The
    /// registration path refuses an `is_recall` register without one (the
    /// redeem won the reservation window, or nothing was ever reserved).
    pub fn has_reserved_recall(&self, sender_pk: &[u8]) -> bool {
        self.recalled_txids
            .values()
            .any(|m| m.phase == RecallPhase::Reserved && m.sender_pk == sender_pk)
    }

    /// YPX-022 §2.1.2a item 4 — the txids of every OPEN recall reservation
    /// held by `sender_pk` (a recall self-send commits all of them at once,
    /// `commit_recalls_for`). The commit gate (`registration.rs` 6b) refuses
    /// the register when any of them has a live claim: a claim arriving while
    /// a reservation is open beats it, exactly as a finalizing redeem does.
    pub fn reserved_recall_txids(&self, sender_pk: &[u8]) -> Vec<TxHash> {
        self.recalled_txids
            .iter()
            .filter(|(_, m)| m.phase == RecallPhase::Reserved && m.sender_pk == sender_pk)
            .map(|(t, _)| *t)
            .collect()
    }

    /// §2.2.1 COMMIT — flip every reservation held by `sender_pk` to the
    /// Committed terminal. Fires at the recall self-send's registration (the
    /// hibernation-entry event), under the same lock as the redeem-finalize
    /// marks, so exactly one of {redeem-wins-abort, commit} happens per
    /// reservation. Returns `(txid, reservation_tick)` pairs — the ORIGINAL
    /// reservation tick rides the WAL op and the committed gossip flood so
    /// every node converges on the same marker.
    pub fn commit_recalls_for(&mut self, sender_pk: &[u8]) -> Vec<(TxHash, u64)> {
        let mut committed = Vec::new();
        for (txid, m) in self.recalled_txids.iter_mut() {
            if m.phase == RecallPhase::Reserved && m.sender_pk == sender_pk {
                m.phase = RecallPhase::Committed;
                committed.push((*txid, m.recall_tick));
            }
        }
        committed
    }

    /// YPX-022 §5 persistence — export the three exact txid terminals
    /// (completed / redeemed / recalled) for `NablaSnapshot`. These are the
    /// archive layer a garbage-chain bloom `Hit` resolves through; a restart
    /// must never forget a recall.
    pub fn terminal_ledgers_snapshot(
        &self,
    ) -> (Vec<(TxHash, u64)>, Vec<TxHash>, Vec<(TxHash, RecallMarker)>) {
        (
            self.completed_txids.iter().map(|(t, k)| (*t, *k)).collect(),
            self.redeemed_txids.iter().copied().collect(),
            self.recalled_txids.iter().map(|(t, m)| (*t, m.clone())).collect(),
        )
    }

    /// YPX-022 §5 persistence — restore the terminals on boot (snapshot load).
    /// Merge-into with first-wins semantics (`or_insert`) so WAL replay after
    /// the snapshot composes without clobbering an earlier mark.
    pub fn restore_terminal_ledgers(
        &mut self,
        completed: Vec<(TxHash, u64)>,
        redeemed: Vec<TxHash>,
        recalled: Vec<(TxHash, RecallMarker)>,
    ) {
        for (t, tick) in completed {
            self.completed_txids.entry(t).or_insert(tick);
        }
        self.redeemed_txids.extend(redeemed);
        for (t, m) in recalled {
            self.recalled_txids.entry(t).or_insert(m);
        }
    }

    /// YPX-022 §2 (2026-07-07 repurpose) — record a sender RECALL of a
    /// COMPLETED-but-undelivered send (the "hash recalled" terminal, symmetric with
    /// the redeem's "consumed"). This SMT-level primitive enforces only the two
    /// invariants that live in Nabla's own monotonic ledger:
    ///   1. REQUIRE completed — `completed_txids` is the monotonic eligibility base
    ///      (a k-witnessed send is FOREVER completion-registered; never removed, or a
    ///      send could be un-completed and replayed). No completion ⇒ nothing to
    ///      recall (case 1: no hash), which also prevents minting a recall of a send
    ///      that never debited.
    ///   2. REFUSE redeemed — `is_txid_redeemed` reads the clean Redeemed terminal
    ///      (`mark_txid_redeemed`, set at redeem-finalize), NOT the send-polluted
    ///      `txid_bloom`/`get_wallet_by_txid` (both written by the sender's own send).
    ///      The receiver already consumed the cheque ⇒ first-wins, irreversible.
    ///   3. Consume-once, first-wins: same sender idempotent `Ok`; different sender
    ///      `"CONFLICT"`.
    /// Recall and redeem share the same txid `T`, so the two terminals resolve the
    /// first-wins race symmetrically: redeem's query-txid blocks on a recall marker;
    /// recall blocks on the Redeemed terminal. (`live → {Redeemed | Recalled} → consumed`.)
    pub fn register_recall(
        &mut self,
        txid: TxHash,
        sender_pk: Vec<u8>,
        tick: u64,
        // AXIOM_DESIGN_AccountKeyedDevTiming.md — the recall's class (is_dev_wallet(sender)),
        // selecting the account-keyed recall-init window. A real recall passes false.
        is_dev_class: bool,
    ) -> Result<(), String> {
        if txid == [0u8; 32] {
            return Err("ERROR".to_string());
        }
        if !self.is_txid_completed(&txid) {
            return Err("NOT_REGISTERED".to_string());
        }
        if self.is_txid_redeemed(&txid) {
            return Err("REDEEMED".to_string());
        }
        // YPX-022 §2.1.2a (KI#205, RULED 2026-09-25) — REFUSE CLAIMED. The
        // REDEEMED terminal above is written only by the receiver's post-redeem
        // register, which the receiver can withhold after its balance moved
        // (measured: sender recalled at 18,000, receiver kept the money, 498,500
        // atoms never issued). The authenticated CLAIM precedes every online
        // redeem and only the addressed receiver's key can make it, so it is
        // the delivery terminal: a claimed cheque was delivered; there is
        // nothing to recall. Live for exactly the recall window (`has_live_claim`).
        if self.has_live_claim(&txid, tick) {
            self.recalls_refused_claimed += 1;
            return Err("CLAIMED".to_string());
        }
        // WINDOW (YPX-022 §2): recall only when the send has aged into [LOW, HIGH]. The
        // completion tick is read from Nabla's own monotonic ledger (zero sender-trust).
        // `age` is a difference of two tick VALUES (unix-second stamps), i.e. an age in
        // SECONDS; the window constants are tick COUNTS, so they MUST be projected via
        // `.to_secs()` before the comparison. The `TickCount` type enforces this — a raw
        // `age < RECALL_INIT_WINDOW_LOW` no longer compiles. (Pre-fix it did compare a
        // seconds-age against a raw tick count and opened the window ~TICK_INTERVAL_SECS×
        // early; see `axiom_core_logic::types::TickCount`.)
        if let Some(completed_at) = self.completion_tick(&txid) {
            let age_secs = tick.saturating_sub(completed_at);
            // AXIOM_DESIGN_AccountKeyedDevTiming.md — the window is account-keyed:
            // a DEV-class recall uses the dev twins, a real one the real pair, chosen
            // at THIS one site via `recall_init_window`. `is_dev_class` is the caller's
            // `is_dev_wallet(sender)`; it can only ever RELAX a dev account's window,
            // never a real account's (a real recall passes is_dev_class=false).
            let (win_low, win_high) = axiom_core_logic::types::recall_init_window(is_dev_class);
            if age_secs < win_low.to_secs() {
                return Err("TOO_EARLY".to_string());
            }
            if age_secs > win_high.to_secs() {
                return Err("TOO_LATE".to_string());
            }
        }
        if let Some(existing) = self.recalled_txids.get(&txid) {
            if existing.sender_pk != sender_pk {
                return Err("CONFLICT".to_string());
            }
            // §2.2.1 — same sender: an open reservation is idempotent (a retry
            // after a died witness round re-serves the attestation); a
            // COMMITTED recall is terminal — nothing left to initiate.
            return match existing.phase {
                RecallPhase::Reserved => Ok(()),
                RecallPhase::Committed => Err("ALREADY_RECALLED".to_string()),
            };
        }
        // §2.2.1 — initiate is a RESERVATION, not the terminal. `C` stays live
        // and redeemable until the commit at hibernation-entry.
        self.recalled_txids.insert(
            txid,
            RecallMarker { sender_pk, recall_tick: tick, phase: RecallPhase::Reserved },
        );
        Ok(())
    }

    /// Apply a recall marker received via gossip (or WAL replay). First-wins:
    /// lowest tick wins within a phase; a COMMIT always dominates a
    /// reservation (§2.2.1). The originating node already gated the recall at
    /// initiation (completed + NotRedeemed three-state); this is a marker
    /// merge. A RESERVED marker for a txid this node knows is REDEEMED is
    /// refused — the redeem already won.
    pub fn apply_remote_recall(
        &mut self,
        txid: &TxHash,
        sender_pk: &[u8],
        recall_tick: u64,
        committed: bool,
    ) -> bool {
        if *txid == [0u8; 32] {
            return false;
        }
        let phase = if committed { RecallPhase::Committed } else { RecallPhase::Reserved };
        if phase == RecallPhase::Reserved && self.is_txid_redeemed(txid) {
            return false;
        }
        let insert = match self.recalled_txids.get(txid) {
            None => true,
            Some(existing) => match (existing.phase, phase) {
                // A commit upgrades a reservation regardless of tick.
                (RecallPhase::Reserved, RecallPhase::Committed) => true,
                // A reservation never demotes a commit.
                (RecallPhase::Committed, RecallPhase::Reserved) => false,
                // Same phase: first-wins by tick.
                _ => recall_tick < existing.recall_tick,
            },
        };
        if insert {
            self.recalled_txids.insert(*txid, RecallMarker {
                sender_pk: sender_pk.to_vec(),
                recall_tick,
                phase,
            });
        }
        insert
    }

    // ── Private helpers ──

    /// Recursively insert a leaf at the correct position.
    /// Path is determined by the bits of the wallet_id key.
    fn insert_at(
        node: Option<Box<TreeNode>>,
        key: &WalletId,
        new_leaf: TreeNode,
        depth: usize,
    ) -> Box<TreeNode> {
        match node {
            None => {
                // Empty position — place the leaf here
                Box::new(new_leaf)
            }
            Some(existing) => {
                match existing.as_ref() {
                    TreeNode::Leaf {
                        key: existing_key, ..
                    } => {
                        if *existing_key == *key {
                            // Same key — update in place
                            Box::new(new_leaf)
                        } else {
                            // Collision: two different keys at same position.
                            Self::split_leaves(*existing, new_leaf, key, depth)
                        }
                    }
                    TreeNode::Internal { .. } => {
                        // Destructure by moving out of the box
                        match *existing {
                            TreeNode::Internal {
                                mut left,
                                mut right,
                                ..
                            } => {
                                let bit = get_bit(key, depth);
                                if bit == 0 {
                                    left = Some(Self::insert_at(left, key, new_leaf, depth + 1));
                                } else {
                                    right = Some(Self::insert_at(right, key, new_leaf, depth + 1));
                                }
                                let left_hash = left
                                    .as_ref()
                                    .map(|n| n.hash())
                                    .unwrap_or_else(|| empty_hash(TREE_DEPTH - depth - 1));
                                let right_hash = right
                                    .as_ref()
                                    .map(|n| n.hash())
                                    .unwrap_or_else(|| empty_hash(TREE_DEPTH - depth - 1));
                                Box::new(TreeNode::Internal {
                                    left,
                                    right,
                                    hash: hash_internal(&left_hash, &right_hash),
                                })
                            }
                            _ => unreachable!(),
                        }
                    }
                }
            }
        }
    }

    /// Split two leaves that collide at the current depth.
    /// Creates internal nodes until their paths diverge.
    fn split_leaves(
        existing_leaf: TreeNode,
        new_leaf: TreeNode,
        new_key: &WalletId,
        depth: usize,
    ) -> Box<TreeNode> {
        let existing_key = match &existing_leaf {
            TreeNode::Leaf { key, .. } => *key,
            _ => unreachable!(),
        };

        if depth >= TREE_DEPTH {
            // Should never happen with proper 256-bit keys
            panic!("SMT depth exceeded: identical keys?");
        }

        let existing_bit = get_bit(&existing_key, depth);
        let new_bit = get_bit(new_key, depth);

        if existing_bit == new_bit {
            // Same direction — need to go deeper
            let child = Self::split_leaves(existing_leaf, new_leaf, new_key, depth + 1);
            let (left, right) = if existing_bit == 0 {
                (Some(child), None)
            } else {
                (None, Some(child))
            };
            let left_hash = left
                .as_ref()
                .map(|n| n.hash())
                .unwrap_or_else(|| empty_hash(TREE_DEPTH - depth - 1));
            let right_hash = right
                .as_ref()
                .map(|n| n.hash())
                .unwrap_or_else(|| empty_hash(TREE_DEPTH - depth - 1));
            Box::new(TreeNode::Internal {
                left,
                right,
                hash: hash_internal(&left_hash, &right_hash),
            })
        } else {
            // Paths diverge here — place each leaf on its side
            let (left, right) = if existing_bit == 0 {
                (
                    Some(Box::new(existing_leaf)),
                    Some(Box::new(new_leaf)),
                )
            } else {
                (
                    Some(Box::new(new_leaf)),
                    Some(Box::new(existing_leaf)),
                )
            };
            let left_hash = left.as_ref().map(|n| n.hash()).unwrap_or_else(|| empty_hash(TREE_DEPTH - depth - 1));
            let right_hash = right.as_ref().map(|n| n.hash()).unwrap_or_else(|| empty_hash(TREE_DEPTH - depth - 1));
            Box::new(TreeNode::Internal {
                left,
                right,
                hash: hash_internal(&left_hash, &right_hash),
            })
        }
    }

    /// Collect sibling hashes along the path from root to leaf.
    fn collect_siblings(
        node: &Option<Box<TreeNode>>,
        key: &WalletId,
        depth: usize,
        siblings: &mut Vec<Hash256>,
    ) {
        match node {
            None => {
                // No more nodes — fill remaining siblings with empty hashes
                // (the proof is for a non-existent entry, or we've reached bottom)
            }
            Some(n) => match n.as_ref() {
                TreeNode::Leaf { .. } => {
                    // Reached the leaf — done collecting
                }
                TreeNode::Internal { left, right, .. } => {
                    let bit = get_bit(key, depth);
                    if bit == 0 {
                        // Going left — sibling is right
                        let sibling_hash = right
                            .as_ref()
                            .map(|n| n.hash())
                            .unwrap_or_else(|| empty_hash(TREE_DEPTH - depth - 1));
                        siblings.push(sibling_hash);
                        Self::collect_siblings(left, key, depth + 1, siblings);
                    } else {
                        // Going right — sibling is left
                        let sibling_hash = left
                            .as_ref()
                            .map(|n| n.hash())
                            .unwrap_or_else(|| empty_hash(TREE_DEPTH - depth - 1));
                        siblings.push(sibling_hash);
                        Self::collect_siblings(right, key, depth + 1, siblings);
                    }
                }
            },
        }
    }

}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

// ── Remove the lazy_static macro call above — it was a mistake ──
// The OnceLock pattern is used instead. Remove the dead macro invocation.

// ── Tests ──

#[cfg(test)]
mod tests {
    /// KI#44: era identity is anchored at `GENESIS_NEWS_ANCHOR`, so raw synthetic
    /// ticks are PRE-genesis and never cross an era boundary. `tk(n)` puts a
    /// fixture tick on the real unix-scale grid.
    fn tk(offset: u64) -> u64 {
        axiom_core_logic::genesis_integrity::GENESIS_NEWS_ANCHOR + offset
    }

    use super::*;
    use crate::types::NablaEntry;

    /// YPX-022 §2 (2026-07-07 repurpose) — RECALL gate INVERTED: you recall a
    /// COMPLETED send whose cheque the receiver has NOT redeemed. Not-registered ⇒
    /// nothing to recall (case 1); already-redeemed ⇒ receiver won, irreversible.
    /// Consume-once is first-wins + sender-authored; gossip merges lowest-tick and
    /// vetoes a redeemed txid.
    #[test]
    /// AXIOM_DESIGN_AccountKeyedDevTiming.md — the recall-init window is chosen by
    /// the recall's CLASS, at runtime, on ONE binary. A DEV-class recall uses the
    /// short dev window; a real one the full window; the SAME node serves both.
    /// Mutation: hardcode `recall_init_window(false)` in register_recall — the dev
    /// arm then rejects TOO_EARLY at a dev-window age and this test goes red.
    #[test]
    fn recall_init_window_is_account_keyed() {
        use axiom_core_logic::types::recall_init_window;
        let (dev_low, _dev_high) = recall_init_window(true);
        let (real_low, _real_high) = recall_init_window(false);
        assert!(dev_low.to_secs() < real_low.to_secs(),
            "dev recall opens earlier than real (dev={} real={})", dev_low.to_secs(), real_low.to_secs());

        // At an age past the DEV low bound but before the REAL low bound, a dev-class
        // recall is IN window (Ok) and a real-class recall is TOO_EARLY — one binary,
        // both accounts, opposite verdicts from the same node.
        let age = dev_low.to_secs() + 1;
        assert!(age < real_low.to_secs(), "test needs a dev/real gap");
        let dev_tx: TxHash = [0xD1u8; 32];
        let real_tx: TxHash = [0xD2u8; 32];
        let mut smt = SparseMerkleTree::new();
        smt.mark_txid_completed(&dev_tx, 0);
        smt.mark_txid_completed(&real_tx, 0);
        assert!(smt.register_recall(dev_tx, vec![0xAA; 32], age, true).is_ok(),
            "a DEV-class recall is in-window at the dev age");
        assert_eq!(smt.register_recall(real_tx, vec![0xBB; 32], age, false),
            Err("TOO_EARLY".to_string()),
            "a REAL-class recall is TOO_EARLY at the same age — real timing, same node");
    }

    #[test]
    fn ooo_attested_marker_does_not_advance_the_head() {
        // KI#59 — the ooo marker is a SEPARATE set that must NOT touch the SMT
        // head/root (anti-rollback stays with the sequential head advance).
        let mut smt = SparseMerkleTree::new();
        let txid: TxHash = [0x5Au8; 32];
        let root_before = smt.root_hash();
        let count_before = smt.count;
        assert!(!smt.is_txid_ooo_attested(&txid));
        smt.mark_ooo_attested(txid);
        assert!(smt.is_txid_ooo_attested(&txid), "marker recorded");
        assert_eq!(smt.root_hash(), root_before, "the head/root must NOT move");
        assert_eq!(smt.count, count_before, "no entry added");
        // Idempotent.
        smt.mark_ooo_attested(txid);
        assert_eq!(smt.root_hash(), root_before);
    }

    #[test]
    fn recall_gate_completed_notredeemed_recallable() {
        let mut smt = SparseMerkleTree::new();
        let sender = vec![1u8; 32];
        let completed: TxHash = [0xC0u8; 32];

        // Case 1: a not-registered send has no hash — nothing to recall.
        assert_eq!(
            smt.register_recall(completed, sender.clone(), 100, false),
            Err("NOT_REGISTERED".to_string()),
            "an unregistered send cannot be recalled"
        );

        // A completed, NOT-yet-redeemed send IS recallable — inside the window (completion
        // at tick 0, recall in [LOW.to_secs(), HIGH.to_secs()]). `age` is a difference of
        // tick VALUES (seconds), so the window is the PROJECTED tick counts. base is an
        // in-window recall tick for both modes.
        let base = RECALL_INIT_WINDOW_LOW.to_secs() + 5;
        smt.mark_txid_completed(&completed, 0);
        assert!(smt.register_recall(completed, sender.clone(), base, false).is_ok());
        // §2.2.1 — initiate is a RESERVATION: pending, NOT the terminal.
        assert!(smt.is_txid_recall_pending(&completed));
        assert!(!smt.is_txid_recalled(&completed),
            "a reservation must not block redeems — C stays live until the commit");
        // Idempotent for the same sender while reserved.
        assert!(smt.register_recall(completed, sender.clone(), base + 1, false).is_ok());
        // A different sender cannot recall someone else's send.
        assert_eq!(
            smt.register_recall(completed, vec![2u8; 32], base + 2, false),
            Err("CONFLICT".to_string())
        );

        // WINDOW: too early (age < LOW.to_secs()) and too late (age > HIGH.to_secs()) are
        // both refused. The window is measured in tick-VALUE age (seconds), so the bounds
        // are the PROJECTED tick counts.
        let early: TxHash = [0x11u8; 32];
        smt.mark_txid_completed(&early, 1000);
        assert_eq!(smt.register_recall(early, sender.clone(), 1000 + RECALL_INIT_WINDOW_LOW.to_secs() - 1, false),
            Err("TOO_EARLY".to_string()), "recall before the window opens is refused");
        // Just AT the projected low bound is accepted.
        let at_low: TxHash = [0x12u8; 32];
        smt.mark_txid_completed(&at_low, 1000);
        assert!(smt.register_recall(at_low, sender.clone(), 1000 + RECALL_INIT_WINDOW_LOW.to_secs(), false).is_ok(),
            "recall exactly at the projected low bound is accepted");
        let late: TxHash = [0x22u8; 32];
        smt.mark_txid_completed(&late, 1000);
        assert_eq!(smt.register_recall(late, sender.clone(), 1000 + RECALL_INIT_WINDOW_HIGH.to_secs() + 1, false),
            Err("TOO_LATE".to_string()), "recall after the window closes is refused");

        // REGRESSION WITNESS (tick-count-vs-tick-value, 3rd recurrence): an age of exactly
        // RECALL_INIT_WINDOW_LOW *ticks* was ACCEPTED under the buggy raw-count gate (it
        // compared the seconds-age against the raw tick count). It must now be TOO_EARLY —
        // the true window opens at LOW.to_secs() = LOW * TICK_INTERVAL_SECS. This asserts
        // TICK_INTERVAL_SECS > 1 so the projection is meaningful; if it were ever 1 the
        // window would be a single tick and this witness would be vacuous.
        assert!(
            axiom_core_logic::types::TICK_INTERVAL_SECS > 1,
            "TICK_INTERVAL_SECS must exceed 1 for the recall-window projection to bind"
        );
        let raw_ticks_early: TxHash = [0x13u8; 32];
        smt.mark_txid_completed(&raw_ticks_early, 1000);
        assert_eq!(
            smt.register_recall(raw_ticks_early, sender.clone(), 1000 + RECALL_INIT_WINDOW_LOW.ticks(), false),
            Err("TOO_EARLY".to_string()),
            "an age of LOW *ticks* (accepted by the pre-fix raw-count gate) must now be \
             TOO_EARLY — the window opens at LOW.to_secs(), not LOW ticks"
        );

        // A REDEEMED send is irreversible — receiver won (checked before the window). The
        // clean Redeemed terminal (mark_txid_redeemed) — NOT the send-polluted txid_bloom.
        let redeemed: TxHash = [0x9au8; 32];
        smt.mark_txid_completed(&redeemed, 0);
        smt.mark_txid_redeemed(&redeemed);
        assert_eq!(
            smt.register_recall(redeemed, sender.clone(), base, false),
            Err("REDEEMED".to_string()),
            "a redeemed send is un-recallable — first-wins, receiver won"
        );

        // Gossip merge: lowest tick wins within a phase; commit dominates.
        let g: TxHash = [0x66u8; 32];
        assert!(smt.apply_remote_recall(&g, &sender, 50, false));
        assert!(!smt.apply_remote_recall(&g, &sender, 60, false), "higher tick loses");
        assert!(smt.apply_remote_recall(&g, &sender, 40, false), "lower tick wins");
        assert!(!smt.is_txid_recalled(&g), "a reservation does NOT block redeems (§2.2.1)");
        assert!(smt.is_txid_recall_pending(&g));
        assert!(smt.apply_remote_recall(&g, &sender, 99, true), "commit upgrades regardless of tick");
        assert!(smt.is_txid_recalled(&g), "committed marker IS the terminal");
        assert!(!smt.apply_remote_recall(&g, &sender, 10, false), "a reservation never demotes a commit");

        // Zero-txid is a no-op / error.
        assert_eq!(smt.register_recall([0u8; 32], sender.clone(), 1, false), Err("ERROR".to_string()));
    }

    /// YPX-020 §2: a hibernating wallet's cheque-claim is NOT refused at Nabla —
    /// completion IS the claim+redeem of the distress cheque, so a gate here would
    /// deadlock it. The "out of work" lock lives at Core's SEND gate (wallet-state
    /// hibernation), not the claim. Fails if a hibernation gate is re-added to
    /// `register_cheque_claim`. (The informational entry + gossip remain.)
    #[test]
    fn hibernating_wallet_can_still_claim_its_distress_cheque() {
        let mut tree = SparseMerkleTree::new();
        let wallet = [0x42u8; 32];
        let cheque = [0x01u8; 32];

        let until = 100u64.saturating_add(axiom_core_logic::types::HIBERNATION_WINDOW);
        tree.set_hibernation(wallet, until);
        assert_eq!(tree.hibernation_until(&wallet), until);

        // §2: the claim SUCCEEDS even while hibernating — no deadlock.
        let (req, _) = crate::registration::signed_claim_request(0x42, "alice@axiom.internal", cheque, 3);
        let claimed = tree.register_cheque_claim(cheque, ChequeClaim::from_request(&req, until - 1), until - 1);
        assert!(claimed.is_ok(),
            "a hibernating wallet must be able to claim (complete) — got {:?}", claimed);
    }

    // ── YPX-022 §2.1.2a (KI#205) — the authenticated claim as delivery terminal ──

    /// A real-class claim on a completed send. `signed_claim_request` builds a
    /// validly signed request (the SMT does not verify — the caller does).
    fn claimed_send(smt: &mut SparseMerkleTree, cheque: [u8; 32], completed_at: u64, email: &str) -> ChequeClaim {
        smt.mark_txid_completed(&cheque, completed_at);
        let (req, _) = crate::registration::signed_claim_request(0x51, email, cheque, 3);
        let claim = ChequeClaim::from_request(&req, completed_at + 10);
        assert_eq!(smt.register_cheque_claim(cheque, claim.clone(), completed_at + 10), Ok(true));
        claim
    }

    /// §2.1.2a item 2 — a claim is evicted at completion + `recall_init_window_high`
    /// (projected to seconds), NOT at the old 17,280. Goes red if `claim_is_stale`
    /// reverts to a fixed TTL, compares the tick-VALUE age to the raw tick COUNT,
    /// or bases the age on the claim tick when a completion tick exists.
    #[test]
    fn claim_lives_until_recall_window_high_not_17280() {
        let mut smt = SparseMerkleTree::new();
        let cheque = [0xA1u8; 32];
        let completed_at = 1_000_000u64;
        claimed_send(&mut smt, cheque, completed_at, "alice@example.com");
        let (_, win_high) = axiom_core_logic::types::recall_init_window(false);
        assert!(win_high.to_secs() > 17_280, "precondition: the real window outlives the old TTL");

        // Old TTL point: still live (this is exactly where the 09-19 hole opened).
        assert!(smt.has_live_claim(&cheque, completed_at + 17_280));
        smt.expire_stale_claims(completed_at + 17_280);
        assert!(smt.query_cheque_claim(&cheque).is_some(), "17,280 must NOT evict");

        // Raw tick-count point (the KI#165 unit bug): still live.
        assert!(smt.has_live_claim(&cheque, completed_at + win_high.ticks()));

        // Window edge: live AT high (a recall is still possible there), stale one past.
        assert!(smt.has_live_claim(&cheque, completed_at + win_high.to_secs()));
        assert!(!smt.has_live_claim(&cheque, completed_at + win_high.to_secs() + 1));
        smt.expire_stale_claims(completed_at + win_high.to_secs() + 1);
        assert!(smt.query_cheque_claim(&cheque).is_none(), "past the window the claim is evicted");
    }

    /// §2.1.2a — the window is account-keyed by the claimant's class: a DEV
    /// claim uses the dev window high. Goes red if `is_dev_wallet` is dropped
    /// from `claim_is_stale`.
    #[test]
    fn claim_lifetime_is_account_keyed() {
        let mut smt = SparseMerkleTree::new();
        let cheque = [0xA2u8; 32];
        let completed_at = 1_000_000u64;
        claimed_send(&mut smt, cheque, completed_at, "alice@axiom.internal");
        let (_, dev_high) = axiom_core_logic::types::recall_init_window(true);
        let (_, real_high) = axiom_core_logic::types::recall_init_window(false);
        assert_ne!(dev_high, real_high, "precondition: the dev twin differs");
        assert!(smt.has_live_claim(&cheque, completed_at + dev_high.to_secs()));
        assert!(!smt.has_live_claim(&cheque, completed_at + dev_high.to_secs() + 1));
        // Exactly one of the two windows is the longer; the dev claim obeys ITS OWN.
        let probe = completed_at + real_high.to_secs() + 1;
        assert_eq!(smt.has_live_claim(&cheque, probe), real_high.to_secs() < dev_high.to_secs());
    }

    /// §2.1.2a — with no completion tick on this node the claim's own tick is
    /// the base (the claim still expires). Goes red if `unwrap_or(claim_tick)`
    /// becomes a permanent record.
    #[test]
    fn claim_without_completion_base_ages_from_its_own_tick() {
        let mut smt = SparseMerkleTree::new();
        let cheque = [0xA3u8; 32];
        let (req, _) = crate::registration::signed_claim_request(0x52, "alice@example.com", cheque, 3);
        let claim = ChequeClaim::from_request(&req, 5_000);
        assert_eq!(smt.register_cheque_claim(cheque, claim, 5_000), Ok(true));
        let (_, win_high) = axiom_core_logic::types::recall_init_window(false);
        assert!(smt.has_live_claim(&cheque, 5_000 + win_high.to_secs()));
        assert!(!smt.has_live_claim(&cheque, 5_000 + win_high.to_secs() + 1));
    }

    /// §2.1.2a — `register_recall` refuses `CLAIMED` while an authenticated
    /// claim is live, and stops saying CLAIMED once it is evicted (then the
    /// window itself refuses). Goes red if the CLAIMED gate is removed from
    /// `register_recall` or placed after the window check.
    #[test]
    fn recall_is_refused_claimed_while_claim_is_live_and_not_after() {
        let mut smt = SparseMerkleTree::new();
        let cheque = [0xA4u8; 32];
        let completed_at = 1_000_000u64;
        let sender = vec![0xAAu8; 32];
        let (win_low, win_high) = axiom_core_logic::types::recall_init_window(false);

        // Control: an unclaimed completed send IS recallable in-window.
        let other = [0xA5u8; 32];
        smt.mark_txid_completed(&other, completed_at);
        assert_eq!(smt.register_recall(other, sender.clone(), completed_at + win_low.to_secs() + 1, false), Ok(()));

        claimed_send(&mut smt, cheque, completed_at, "alice@example.com");
        let before = smt.recalls_refused_claimed();
        assert_eq!(
            smt.register_recall(cheque, sender.clone(), completed_at + win_low.to_secs() + 1, false),
            Err("CLAIMED".to_string()),
            "a live claim is the delivery terminal — the recall must be refused CLAIMED"
        );
        assert_eq!(smt.recalls_refused_claimed(), before + 1, "RULE 3 §2: the refusal is counted");
        assert!(!smt.is_txid_recall_pending(&cheque), "nothing reserved");

        // Live at the window edge → still CLAIMED, not TOO_LATE.
        assert_eq!(
            smt.register_recall(cheque, sender.clone(), completed_at + win_high.to_secs(), false),
            Err("CLAIMED".to_string())
        );
        // Evicted one past the window → no longer CLAIMED (the window refuses).
        let r = smt.register_recall(cheque, sender, completed_at + win_high.to_secs() + 1, false);
        assert_ne!(r, Err("CLAIMED".to_string()), "an evicted claim must not be read");
        assert_eq!(r, Err("TOO_LATE".to_string()));
    }

    /// §2.1.2a item 4 helper — the open reservation's txids by sender, and
    /// only OPEN ones (a commit drops out).
    #[test]
    fn reserved_recall_txids_lists_open_reservations_only() {
        let mut smt = SparseMerkleTree::new();
        let sender = vec![0xABu8; 32];
        let (win_low, _) = axiom_core_logic::types::recall_init_window(false);
        let t1 = [0xB1u8; 32];
        let t2 = [0xB2u8; 32];
        smt.mark_txid_completed(&t1, 100);
        smt.mark_txid_completed(&t2, 100);
        let at = 100 + win_low.to_secs() + 1;
        smt.register_recall(t1, sender.clone(), at, false).unwrap();
        smt.register_recall(t2, sender.clone(), at, false).unwrap();
        let mut open = smt.reserved_recall_txids(&sender);
        open.sort();
        assert_eq!(open, vec![t1, t2]);
        assert!(smt.reserved_recall_txids(&[0xACu8; 32]).is_empty(), "another sender holds none");
        smt.commit_recalls_for(&sender);
        assert!(smt.reserved_recall_txids(&sender).is_empty(), "committed = no longer OPEN");
    }

    /// Claims round-trip the snapshot export/restore with first-wins.
    #[test]
    fn cheque_claims_snapshot_round_trip_is_first_wins() {
        let mut a = SparseMerkleTree::new();
        let cheque = [0xA6u8; 32];
        let claim = claimed_send(&mut a, cheque, 1_000, "alice@example.com");
        let exported = a.cheque_claims_snapshot();
        assert_eq!(exported, vec![(cheque, claim.clone())]);

        let mut b = SparseMerkleTree::new();
        let (req, _) = crate::registration::signed_claim_request(0x53, "bob@example.com", cheque, 3);
        let earlier = ChequeClaim::from_request(&req, 900);
        b.register_cheque_claim(cheque, earlier.clone(), 900).unwrap();
        b.restore_cheque_claims(exported);
        assert_eq!(b.query_cheque_claim(&cheque), Some(&earlier), "restore never clobbers an existing claim");
    }

    /// YPX-020 HAL: the informational hibernation entry must converge across the
    /// mesh via GOSSIP (a node that only HEARD the re-anchor, not processed it,
    /// still learns the wallet is hibernating — used for §15 awareness, not as a
    /// claim gate under §2). Monotonic apply + completion-clear. Fails if
    /// apply_remote_hibernation or the gossip path is removed.
    #[test]
    fn gossiped_hibernation_converges_on_a_remote_node() {
        let mut node_b = SparseMerkleTree::new();
        let wallet = [0x42u8; 32];
        let until = 200u64;

        assert_eq!(node_b.hibernation_until(&wallet), 0);

        // Gossip arrives at B (current_tick 100 < until 200).
        assert!(node_b.apply_remote_hibernation(&wallet, until, 100),
            "fresh in-window hibernation gossip must apply");
        assert_eq!(node_b.hibernation_until(&wallet), until);

        // Already-elapsed gossip is a no-op; a lower `until` can't shorten the
        // lock (monotonic).
        assert!(!node_b.apply_remote_hibernation(&wallet, 50, 100),
            "elapsed gossip must not apply");
        assert!(!node_b.apply_remote_hibernation(&wallet, until - 1, 100),
            "lower until must not shorten the lock");
        assert_eq!(node_b.hibernation_until(&wallet), until);

        // A completion CLEAR gossip (`until == 0`) removes the flag mesh-wide.
        assert!(node_b.apply_remote_hibernation(&wallet, 0, 300),
            "completion-clear gossip must apply on a remote node");
        assert_eq!(node_b.hibernation_until(&wallet), 0);
        // A redundant clear gossip is a no-op.
        assert!(!node_b.apply_remote_hibernation(&wallet, 0, 400),
            "clear gossip on an already-clear wallet must be a no-op");
    }

    /// KI#48 follow-up: every 1-byte prefix's subtree proof must fold back
    /// to the root, on empty, small, and spread-out trees — including
    /// prefixes whose subtree is empty and paths that stop at a compressed
    /// leaf above the target depth.
    #[test]
    fn subtree_proof_reconstructs_for_every_prefix() {
        let mut smt = SparseMerkleTree::new();
        for i in 0..32u8 {
            // id_byte varies the TOP bits, so entries scatter across prefixes
            smt.put(&make_entry(i.wrapping_mul(37), i));
        }
        let root = smt.root_hash();
        for p in 0..=255u8 {
            let (sh, sibs) = smt.subtree_proof(&[p], 8);
            assert!(
                SparseMerkleTree::verify_subtree_proof(&root, &[p], &sh, &sibs),
                "prefix {p:#04x}: proof did not reconstruct (siblings={})",
                sibs.len()
            );
        }
        // Empty tree: proof still verifies against the empty root.
        let empty = SparseMerkleTree::new();
        let (sh, sibs) = empty.subtree_proof(&[0xA3], 8);
        assert!(SparseMerkleTree::verify_subtree_proof(&empty.root_hash(), &[0xA3], &sh, &sibs));
    }

    #[test]
    fn subtree_proof_rejects_tampering() {
        let mut smt = SparseMerkleTree::new();
        for i in 0..8u8 {
            smt.put(&make_entry(i.wrapping_mul(41), i));
        }
        let root = smt.root_hash();
        let (sh, sibs) = smt.subtree_proof(&[0x5C], 8);
        assert!(SparseMerkleTree::verify_subtree_proof(&root, &[0x5C], &sh, &sibs));

        // Tampered subtree hash fails.
        let mut bad = sh;
        bad[0] ^= 1;
        assert!(!SparseMerkleTree::verify_subtree_proof(&root, &[0x5C], &bad, &sibs));
        // Tampered sibling fails (when the path has one).
        if !sibs.is_empty() {
            let mut bad_sibs = sibs.clone();
            bad_sibs[0][0] ^= 1;
            assert!(!SparseMerkleTree::verify_subtree_proof(&root, &[0x5C], &sh, &bad_sibs));
        }
        // Wrong root fails.
        assert!(!SparseMerkleTree::verify_subtree_proof(&[0xAB; 32], &[0x5C], &sh, &sibs));
        // SEC-16 bound: oversized sibling vector is rejected outright.
        let oversized = vec![[0u8; 32]; 9]; // > prefix.len()*8
        assert!(!SparseMerkleTree::verify_subtree_proof(&root, &[0x5C], &sh, &oversized));
    }

    fn make_entry(id_byte: u8, state_byte: u8) -> NablaEntry {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = id_byte;
        let mut state = [0u8; 32];
        state[0] = state_byte;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = id_byte ^ state_byte;
        NablaEntry {
            received_from: None,
            wallet_seq: 0,
            wallet_id,
            current_state: state,
            tx_hash,
            tick: 1,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        }
    }

    /// KI#43a parity: with recording enabled, every consumed-chain insert
    /// (organic put-advance AND recovered previous_states marks) produces
    /// exactly one buffered exact-record event, tagged with the bloom's
    /// post-insert active era — so exact-file placement can never drift from
    /// bloom placement. Disabled ⇒ buffer stays empty (zero-cost default).
    #[test]
    fn exact_recording_buffers_every_consumed_insert_with_bloom_era() {
        let mut smt = SparseMerkleTree::new();
        smt.enable_exact_recording();

        // Organic advance: X (0x11) -> Y (0x22) consumes X.
        let e1 = make_entry(1, 0x11);
        smt.put(&e1);
        let mut e2 = make_entry(1, 0x22);
        e2.wallet_seq = 1;
        smt.put(&e2);

        // KI#65: recovered marks no longer insert into the bloom, so they must
        // produce NO exact event either — that is exactly the parity this test
        // guards. Recording an event for an insert we do not make would BE the
        // drift.
        let m1 = ([9u8; 32], [0x33u8; 32]);
        let m2 = ([8u8; 32], [0x44u8; 32]);
        smt.merge_previous_states(&[m1, m2], 5);
        assert!(!smt.is_state_consumed(&[0x33u8; 32]),
            "KI#65: a mark recovered from a peer must NOT arm this node's A12 \
             bloom — an inherited false positive is permanent and vetoes the \
             canonical head");

        let drained = smt.drain_exact_pending();
        let era = smt.consumed_chain().active_era_id();
        let states: Vec<[u8; 32]> = drained.iter().map(|(_, s)| *s).collect();
        assert_eq!(drained.len(), 1, "one event per consumed insert — organic only");
        assert!(drained.iter().all(|(e, _)| *e == era),
            "events carry the bloom's active era");
        assert!(states.contains(&e1.current_state), "organic consumption recorded");
        assert!(!states.contains(&m1.1) && !states.contains(&m2.1),
            "KI#65: recovered marks must produce NO exact event, because they no \
             longer insert into the bloom — an event without a bloom mark is \
             exactly the drift this test guards");
        // Every buffered state is genuinely in the bloom.
        for s in &states {
            assert!(smt.is_state_consumed(s), "exact event without bloom mark");
        }
        // Drain empties; second drain is a no-op.
        assert!(smt.drain_exact_pending().is_empty());

        // Default-off: no buffering.
        let mut off = SparseMerkleTree::new();
        off.put(&make_entry(2, 0x55));
        let mut adv = make_entry(2, 0x66);
        adv.wallet_seq = 1;
        off.put(&adv);
        assert!(off.drain_exact_pending().is_empty(),
            "recording disabled must buffer nothing");
    }

    #[test]
    fn consumed_state_bloom_survives_head_rollback() {
        // YPX-020 A12 (the nastiest case): advancing X->Y records X as consumed;
        // a forged head-rollback back to X must NOT be able to un-consume X. The
        // HAL re-anchor gate checks this monotonic bloom, never the mutable head.
        let mut smt = SparseMerkleTree::new();
        let w = [0xAAu8; 32];
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let entry = |state: [u8; 32], tick: u64, txb: u8| NablaEntry {
                                                              received_from: None,
                                                              wallet_seq: 0,
            wallet_id: w,
            current_state: state,
            tx_hash: [txb; 32],
            tick,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        };
        smt.put(&entry(x, 1, 1));
        assert!(!smt.is_state_consumed(&x), "X is the live head — not consumed yet");
        smt.put(&entry(y, 2, 2)); // legitimate advance X -> Y consumes X
        assert!(smt.is_state_consumed(&x), "X consumed once advanced past");
        assert!(!smt.is_state_consumed(&y), "Y is the live head — not consumed");
        // forged A12 rollback: higher-tick gossip rolls the HEAD back to X
        smt.put(&entry(x, 999, 3));
        assert_eq!(smt.get(&w).unwrap().current_state, x, "head did roll back to X");
        assert!(
            smt.is_state_consumed(&x),
            "rollback must NOT un-consume X — monotonic bloom defeats A12"
        );
    }

    #[test]
    fn anti_rollback_state_recovered_via_statepull() {
        // THREAT: AXIOM_THREAT_CollusionWipeRevival.md §5.2 — CLOSED by WI1.
        //
        // A wiped node that bootstraps via StatePull receives the recovery
        // payload (consumed-bloom + previous_states) and UNION-merges it, so it
        // re-arms the anti-rollback view. It then KNOWS X was consumed and a
        // forged head-rollback to X is detected by `is_state_consumed`, not
        // admitted. This test asserts the SAFE behaviour (was the §5.2 gap).
        let w = [0xBBu8; 32];
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let entry = |state: [u8; 32], tick: u64, txb: u8| NablaEntry {
            received_from: None,
            wallet_seq: 0,
            wallet_id: w,
            current_state: state,
            tx_hash: [txb; 32],
            tick,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        };

        // (a) Live node processed X -> Y → knows X consumed. This is the
        //     StatePull SOURCE the recovering node bootstraps from.
        //     KI#65: X->Y is a same-seq CHAIN advance (tick/redeem path), so
        //     it must carry the real `fact_tx_hash(prev, new)` linkage — that
        //     is what marks it a permanent consumption vs a lateral sibling.
        let mut live = SparseMerkleTree::new();
        live.put(&entry(x, 1, 1));
        let mut ey = entry(y, 2, 2);
        ey.tx_hash = crate::registration::fact_tx_hash(&x, &y);
        live.put(&ey);
        assert!(live.is_state_consumed(&x), "live node that saw X->Y knows X consumed");

        // (b) Recovering node: head-syncs Y (prev == None → no consumed insert),
        //     so PRE-rearm it is blind — the §5.2 gap, still present for a beat.
        let mut recovered = SparseMerkleTree::new();
        recovered.put(&entry(y, 2, 2));
        assert!(!recovered.is_state_consumed(&x), "pre-rearm: blind (the §5.2 gap)");

        // WI1 re-arm: exactly what the StatePull handler does on bootstrap.
        // WI1 re-arm via ERAS now (KI#42 step 4d) — same guarantee, era-shaped:
        // transfer every era the live node holds, exactly as the StatePull handler
        // does, then merge the authoritative previous_states.
        for id in live.consumed_era_ids() {
            let bytes = live.consumed_era_bytes(id).expect("era must serialize");
            let era: crate::bloom_era::BloomEra =
                ciborium::from_reader(bytes.as_slice()).expect("era must decode");
            recovered.merge_consumed_era(era).expect("honest era must be adopted");
        }
        recovered.merge_previous_states(&live.previous_states_snapshot(), 2);

        // SAFE NOW: the recovered node KNOWS X was consumed, and its
        // authoritative previous_state[W] is restored to X → a forged rollback
        // to X is detected (is_state_consumed fires) rather than admitted.
        assert!(
            recovered.is_state_consumed(&x),
            "WI1 (§5.2): after StatePull re-arm, the recovered node knows X was consumed"
        );
        assert_eq!(
            recovered.previous_state(&w),
            Some(x),
            "WI1: authoritative previous_state[W] restored to X"
        );
    }

    #[test]
    fn merge_consumed_bloom_is_monotonic_union() {
        // An attacker peer's EMPTY bloom can never disarm a node — union only
        // adds. A node that already knows X consumed stays armed even after
        // merging a (forged) empty bloom.
        let x = [0x11u8; 32];
        let mut node = SparseMerkleTree::new();
        // KI#65: arm ORGANICALLY (a real advance past X). `merge_previous_states`
        // no longer arms the bloom — it must not, or a node inherits A12 vetoes
        // for states it never witnessed. This test is about the UNION being
        // monotonic, which is unchanged.
        let mut e1 = make_entry(0xBB, 0x11);
        e1.current_state = x;              // full 32-byte state, not just byte 0
        node.put(&e1);
        let mut e2 = make_entry(0xBB, 0x22);
        e2.current_state = [0x22u8; 32];
        e2.wallet_seq = 1;                 // a genuine advance consumes X
        node.put(&e2);
        assert!(node.is_state_consumed(&x));
        // attacker's EMPTY view, era-shaped: transfer every era of a blank node
        let empty = SparseMerkleTree::new();
        for id in empty.consumed_era_ids() {
            let bytes = empty.consumed_era_bytes(id).unwrap();
            let era: crate::bloom_era::BloomEra =
                ciborium::from_reader(bytes.as_slice()).unwrap();
            node.merge_consumed_era(era).unwrap();
        }
        assert!(node.is_state_consumed(&x), "union never subtracts a consumed mark");
    }

    // Load-shedding (C): merge_previous_states caps the per-call batch at
    // AE_MERGE_MAX_BATCH so an oversized StatePull payload can't tie up the
    // global node lock. Under the cap every entry is merged; over the cap only
    // the first AE_MERGE_MAX_BATCH are processed and the count is returned.
    #[test]
    fn merge_previous_states_is_batch_bounded() {
        // Under the cap: all entries processed.
        let small: Vec<(WalletId, StateId)> = (0..16u32)
            .map(|i| {
                let mut w = [0u8; 32]; w[..4].copy_from_slice(&i.to_le_bytes());
                let mut s = [0u8; 32]; s[0] = 0xA0 | (i as u8);
                (w, s)
            })
            .collect();
        let mut node = SparseMerkleTree::new();
        assert_eq!(node.merge_previous_states(&small, 1), 16, "under-cap: all merged");
        assert_eq!(node.previous_state(&small[0].0), Some(small[0].1));
        assert_eq!(node.previous_state(&small[15].0), Some(small[15].1));

        // Over the cap: only AE_MERGE_MAX_BATCH processed; the return value
        // reflects the bound and the overflow tail is NOT merged this call.
        let over = AE_MERGE_MAX_BATCH + 100;
        let big: Vec<(WalletId, StateId)> = (0..over as u32)
            .map(|i| {
                let mut w = [0u8; 32]; w[..4].copy_from_slice(&i.to_le_bytes());
                w[4] = 0x7E; // distinct namespace from `small`
                let mut s = [0u8; 32]; s[..4].copy_from_slice(&i.to_le_bytes()); s[4] = 0x7E;
                (w, s)
            })
            .collect();
        let mut node2 = SparseMerkleTree::new();
        assert_eq!(node2.merge_previous_states(&big, 1), AE_MERGE_MAX_BATCH,
            "over-cap: processes exactly AE_MERGE_MAX_BATCH");
        // First entry (within batch) merged; a tail entry (beyond batch) is not.
        assert_eq!(node2.previous_state(&big[0].0), Some(big[0].1));
        assert_eq!(node2.previous_state(&big[over - 1].0), None,
            "overflow tail deferred to next StatePull");
    }

    #[test]
    fn empty_tree_has_consistent_root() {
        let tree = SparseMerkleTree::new();
        let root = tree.root_hash();
        assert_eq!(root, empty_hash(TREE_DEPTH));
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());
    }

    #[test]
    fn ypx010_s14_chain_is_ordered_and_recheck_refreshes_everything() {
        // The claim chain is a WORKLIST, re-derived on every touch — not a
        // cached verdict. An entry that was not ready must become ready the
        // moment its sender registers, without any timer or background scan.
        let mut smt = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        let pk = vec![0xAA; 32];
        // Three senders' genuine legs; the cheque ids ARE their derived txids.
        let (la, lb, lc) = (origin_leg(0x11, 0x01), origin_leg(0x22, 0x02), origin_leg(0x33, 0x03));
        let (a, b, c): (TxHash, TxHash, TxHash) = (la.tx_hash, lb.tx_hash, lc.tx_hash);

        // Register through the REAL producer (wave 3): a VERIFIED send leg
        // recorded by `record_verified_leg`. A direct setter here is what let the
        // original three tests pass while the live answer was node-local.
        let reg = |smt: &mut SparseMerkleTree, leg: crate::types::ForkLeg, now: u64| {
            let v = crate::ban::verify_fork_leg(leg).expect("genuine leg verifies");
            assert!(matches!(smt.record_verified_leg(v, now), OriginOutcome::Created { contested: false }));
        };

        reg(&mut smt, la, 10);                     // only A's send is registered
        smt.record_claim_in_chain(&pk, &a, 10);
        smt.record_claim_in_chain(&pk, &b, 11);
        let chain = smt.record_claim_in_chain(&pk, &c, 12);

        assert_eq!(chain.len(), 3, "all three claims are in the chain");
        assert_eq!(chain[0].cheque_id, a, "oldest first — ordering is the point");
        assert_eq!(chain[2].cheque_id, c);
        assert!(chain[0].sender_registered, "A is backed");
        assert!(!chain[1].sender_registered, "B is NOT backed — do not redeem it");
        assert!(!chain[2].sender_registered, "C is NOT backed");

        // B's sender registers. NOTHING re-scans in the background...
        reg(&mut smt, lb, 20);
        let _ = lc;
        // ...until the client touches the chain again.
        let refreshed = smt.record_claim_in_chain(&pk, &c, 21);
        assert!(refreshed[1].sender_registered,
            "the touch must re-derive B, not serve a stale verdict");
        assert!(!refreshed[2].sender_registered, "C is still unbacked");
        assert_eq!(refreshed[0].first_claim_tick, 10,
            "a re-touch must NOT reshuffle the chain");
    }

    #[test]
    fn ypx010_s14_chain_is_bounded_by_the_scar_cap() {
        // A wallet cannot legitimately hold more unresolved links than the scar
        // cap, so a longer chain could never be drained. Bounded, and bounded
        // by the SAME registered number so the two cannot drift apart.
        let mut smt = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        let pk = vec![0xBB; 32];
        for i in 0..(MAX_CLAIM_CHAIN + 5) {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            id[1] = (i >> 8) as u8;
            smt.record_claim_in_chain(&pk, &id, 100 + i as u64);
        }
        let chain = smt.claim_chain(&pk).expect("chain exists");
        assert_eq!(chain.len(), MAX_CLAIM_CHAIN, "chain must be capped");
        assert_eq!(chain.len(), axiom_core_logic::validation::MAX_UNRESOLVED_SCARS,
            "and capped at the SAME value as the scar cap, not a second number");
    }

    #[test]
    fn ypx010_s14_readiness_answers_from_nablas_own_records() {
        // The claim asks Nabla a question Nabla can answer by itself: "have I
        // registered the send behind this cheque?" No client-supplied proof —
        // an earlier draft made the CLIENT send the sender's bucket and state,
        // which was both more complex and wrong (the receiver does not hold the
        // sender's chain).
        let mut smt = SparseMerkleTree::new();
        let leg = origin_leg(0xA1, 0x01);
        let known: TxHash = leg.tx_hash;
        let unknown: TxHash = origin_leg(0xB2, 0x02).tx_hash;

        assert!(!smt.cheque_sender_registered(&known),
            "nothing registered yet — NOT ready");

        // Drive the real producer (wave 3 [R5]): a VERIFIED send leg through
        // `record_verified_leg` — the one place a record is made.
        let v = crate::ban::verify_fork_leg(leg).unwrap();
        smt.record_verified_leg(v, 100);

        assert!(smt.cheque_sender_registered(&known),
            "a registered send must report ready");
        assert!(!smt.cheque_sender_registered(&unknown),
            "an unregistered send must report NOT ready");
    }

    /// Test 32 — `cheque_sender_registered` answers from the ORIGIN LEDGER and
    /// nowhere else: a head `put` carrying the same txid (the receiver's
    /// redeem-finalize head keyed on the cheque txid — HIGH-1 — or a snapshot /
    /// WAL `Put` rebuild) answers NOT registered. MUTATION: re-add the
    /// `registered_txids.insert` in `put_inner` (or answer from any head's
    /// tx_hash) ⇒ red.
    #[test]
    fn cheque_sender_registered_answers_from_origin_ledger() {
        let mut smt = SparseMerkleTree::new();
        let leg = origin_leg(0xC1, 0x01);
        let cheque = leg.tx_hash;
        // P's redeem-finalize head is keyed on the CHEQUE txid.
        let mut receiver_head = make_entry(0xC2, 0x05);
        receiver_head.tx_hash = cheque;
        smt.put(&receiver_head);
        smt.put_with_proof(&receiver_head, PutProof::RestoredFromLocalState(None));
        assert!(!smt.cheque_sender_registered(&cheque),
            "a head carrying the cheque txid is NOT the sender's verified leg (HIGH-1)");
        assert_eq!(smt.origin_len(), 0, "no put creates a record");
        smt.record_verified_leg(crate::ban::verify_fork_leg(leg).unwrap(), 7);
        assert!(smt.cheque_sender_registered(&cheque));
    }

    /// KI#65 FIX — the lateral same-seq mark is FALSIFIABLE: it holds while
    /// the siblings coexist (the KI#34 double-spend evidence window) and
    /// CLEARS when the wallet provably advances past that seq.
    ///
    /// Live case: wallet `dad3` sat at `seq=18` for its whole life (207 log
    /// samples, never a single `seq>18`) while a failing retry minted FIVE
    /// candidate states at that one sequence. A node swapping between two of
    /// them condemned the loser into the MONOTONIC bloom, and gamma then
    /// refused forever the state nine other nodes held as canonical. Nothing
    /// was consumed: the wallet never advanced. TLA+-verified semantics:
    /// `docs/models/ki65_same_seq_mark` (the old behaviour is case c1's
    /// BloomSound counterexample; this behaviour is cases c2/c3/c7).
    #[test]
    fn ki65_lateral_same_seq_mark_is_falsifiable_and_clears_on_advance() {
        let mut smt = SparseMerkleTree::new();

        let mut a = make_entry(0xD1, 0x01);
        a.wallet_seq = 18;
        a.current_state = [0xEAu8; 32];   // the live-case winner
        smt.put(&a);

        // Same wallet, SAME seq, a sibling candidate — a lateral move, not an
        // advance. The wallet is still at 18; it consumed nothing.
        let mut b = make_entry(0xD1, 0x02);
        b.wallet_seq = 18;
        b.current_state = [0xCEu8; 32];
        smt.put(&b);

        // WHILE the siblings coexist the swapped-away head must READ consumed
        // — this window is exactly the same-seq evidence KI#34 check-3 needs,
        // and why the naive `wallet_seq >` gate broke ten double-spend tests.
        assert!(
            smt.is_state_consumed(&[0xEAu8; 32]),
            "KI#65: the provisional mark must hold while same-seq siblings \
             coexist (the double-spend evidence window)"
        );
        let counters = smt.same_seq_mark_counters();
        assert_eq!(counters, (1, 0, 1), "one provisional mark manufactured + active");

        // The wallet ADVANCES (seq 19, consuming the current head CE): exactly
        // one seq-18 state was the real head; EA was provably never consumed.
        let mut c = make_entry(0xD1, 0x03);
        c.wallet_seq = 19;
        c.current_state = [0xADu8; 32];
        smt.put(&c);

        assert!(
            !smt.is_state_consumed(&[0xEAu8; 32]),
            "KI#65: the false mark must CLEAR once the wallet advances — the \
             seq guard covers seq-older heads from here, so a permanent veto \
             of the abandoned sibling protects nothing and (live case) vetoed \
             the canonical head forever"
        );
        assert!(
            smt.is_state_consumed(&[0xCEu8; 32]),
            "the advanced-through head IS a real consumption — permanent"
        );
        let counters = smt.same_seq_mark_counters();
        assert_eq!(counters, (1, 1, 0), "mark manufactured then cleared");
    }

    /// KI#65 discriminator — a same-seq CHAIN advance (every redeem: Core's
    /// receive rule keeps `wallet_seq` unchanged, KI#46 ruling) is a REAL
    /// consumption and must be marked PERMANENTLY (era-carried, wipe-proof —
    /// the KI#34 net), never provisionally. The linkage is the entry's
    /// `tx_hash == fact_tx_hash(prev, new)`; mutation check: swap the hash for
    /// junk and this test goes red (the mark degrades to provisional).
    #[test]
    fn ki65_same_seq_chain_advance_marks_permanently() {
        let mut smt = SparseMerkleTree::new();

        let r0 = [0x51u8; 32];
        let r1 = [0x52u8; 32];

        let mut a = make_entry(0xC4, 0x00);
        a.wallet_seq = 7;
        a.current_state = r0;
        smt.put(&a);

        // The redeem: same wallet, SAME seq, chained state — real tx_hash.
        let mut b = make_entry(0xC4, 0x01);
        b.wallet_seq = 7;
        b.current_state = r1;
        b.tx_hash = crate::registration::fact_tx_hash(&r0, &r1);
        smt.put(&b);

        assert!(smt.is_state_consumed(&r0), "redeem-consumed head reads consumed");
        let (made, _, active) = smt.same_seq_mark_counters();
        assert_eq!((made, active), (0, 0), "chain advance must NOT touch the provisional set");
        // The permanence that matters: the mark survives an era transfer to a
        // recovering node (provisional marks deliberately do not — option (d)).
        let mut recovered = SparseMerkleTree::new();
        for id in smt.consumed_era_ids() {
            let bytes = smt.consumed_era_bytes(id).expect("era serializes");
            let era: crate::bloom_era::BloomEra =
                ciborium::from_reader(bytes.as_slice()).expect("era decodes");
            recovered.merge_consumed_era(era).expect("honest era adopted");
        }
        assert!(
            recovered.is_state_consumed(&r0),
            "KI#34 net: a same-seq CHAIN consumption must be era-carried"
        );
    }

    /// KI#65 INVARIANT GUARD — every `previous_states` entry must ALSO answer
    /// `is_state_consumed` LOCALLY (permanent bloom for seq-advancing writes,
    /// falsifiable provisional set for same-seq writes).
    ///
    /// Removing the `merge_previous_states` bloom-arming is safe ONLY because
    /// both are written together at the `put` chokepoint: a peer's
    /// seq-advancing `previous_states` marks are already present in the eras
    /// it serves, so the consumed-ERA transfer carries them. Same-seq marks
    /// are DELIBERATELY absent from the eras (option (d), model case c6: a
    /// spread clearable mark admits a launder trace) — they are node-local
    /// and clear on advance. If a future change adds a `previous_state` write
    /// without the matching mark, a node holds fork evidence its own A12
    /// cannot see — and this test is the only thing that would notice.
    #[test]
    fn ki65_every_previous_state_is_also_locally_consumed() {
        let mut smt = SparseMerkleTree::new();

        // Drive several real advances through the only write path there is.
        for i in 0..6u8 {
            let mut a = make_entry(0xE0 + i, 0x01);
            a.wallet_seq = 1;
            a.current_state = [0x10 + i; 32];
            smt.put(&a);
            let mut b = make_entry(0xE0 + i, 0x02);
            b.wallet_seq = 2;                    // advance: consumes the first
            b.current_state = [0x20 + i; 32];
            smt.put(&b);
        }
        // And one LATERAL same-seq swap (KI#65): its previous_states write is
        // covered by the provisional set, not the bloom.
        let mut c = make_entry(0xF7, 0x01);
        c.wallet_seq = 5;
        c.current_state = [0xA1; 32];
        smt.put(&c);
        let mut d = make_entry(0xF7, 0x02);
        d.wallet_seq = 5;                        // same seq: lateral, provisional
        d.current_state = [0xA2; 32];
        smt.put(&d);

        let snapshot = smt.previous_states_snapshot();
        assert!(snapshot.len() >= 7, "control: advances + the lateral swap must have produced marks");

        for (wallet, state) in &snapshot {
            assert!(
                smt.is_state_consumed(state),
                "KI#65 INVARIANT BROKEN: previous_states holds {:02x}.. for wallet \
                 {:02x}.. but is_state_consumed does NOT see it. Both must be written \
                 together at the `put` chokepoint — a mark here that A12 cannot see \
                 is fork evidence the node itself is blind to.",
                state[0], wallet[0],
            );
        }
    }

    /// KI#65 — the SPREAD is closed: a false mark can no longer poison a peer.
    ///
    /// Replays the LIVE `dad3` sequence — the five candidate states the wallet
    /// actually minted at `seq=18` while a failing retry churned. The origin
    /// node still condemns losers locally (see the ignored test above — that
    /// half is unfixed), but `merge_previous_states` no longer arms a
    /// RECOVERING node's A12 bloom from marks it never witnessed.
    ///
    /// That is what turned a local false positive into a permanent mesh-wide
    /// veto: gamma pulled 21 and 27 marks across bootstrap re-arms and then
    /// refused `ea76` 69 times while nine nodes held it as canonical.
    #[test]
    fn ki65_recovered_marks_do_not_poison_a_peer() {
        let states: [[u8; 32]; 5] =
            [[0xEA; 32], [0xE8; 32], [0xCE; 32], [0xB5; 32], [0x25; 32]];

        let mut origin = SparseMerkleTree::new();
        for (i, st) in states.iter().enumerate() {
            let mut e = make_entry(0xDA, i as u8);
            e.wallet_seq = 18;          // the wallet NEVER advanced — 207 samples, all 18
            e.current_state = *st;
            origin.put(&e);
        }

        let mut recovering = SparseMerkleTree::new();
        recovering.merge_previous_states(&origin.previous_states_snapshot(), 1);

        for st in &states {
            assert!(!recovering.is_state_consumed(st),
                "a recovering node must NOT inherit an A12 veto for a state it \
                 never witnessed — the bloom is monotonic, so an inherited \
                 mistake is permanent, and this is what made gamma refuse the \
                 head nine other nodes held as canonical");
        }
    }

    /// KI#65 CONTROL — the real thing must still be recorded, or the fix has
    /// simply disabled A12. A genuine advance (seq moves) DOES consume.
    #[test]
    fn ki65_a_real_seq_advance_still_consumes_the_ancestor() {
        let mut smt = SparseMerkleTree::new();

        let mut a = make_entry(0xD2, 0x01);
        a.wallet_seq = 18;
        a.current_state = [0xA1u8; 32];
        smt.put(&a);

        let mut b = make_entry(0xD2, 0x02);
        b.wallet_seq = 19;                 // ADVANCE — a1 is now a true ancestor
        b.current_state = [0xB2u8; 32];
        smt.put(&b);

        assert!(
            smt.is_state_consumed(&[0xA1u8; 32]),
            "an ancestor reached through a seq-ADVANCING transition MUST still be \
             consumed — this is the A12 rollback defence and the fix must not \
             weaken it"
        );
    }

    #[test]
    fn ypx010_s14_readiness_replicates_with_the_entry_not_just_the_local_register() {
        // The regression the live gate caught. A node that never handled the
        // register — it only ADOPTED the entry over gossip/anti-entropy — must
        // give the same answer, because `put` is on that path too. If readiness
        // is ever moved back onto the local register path only, this fails.
        //
        // `apply_remote_entry` is the adopting caller; it reaches `put`, so
        // exercising `put` directly is exercising what replication does.
        //
        // RE-HOMED (ForkSettlement wave 3, [R5]): readiness replicates because
        // the flood / AE path carries the LEG (`SeqProof.preimage`) and the
        // adopting node records it through `record_verified_leg` — NOT because
        // of `put` (which no longer records anything). The path-level form
        // (flood / `apply_remote_entry` → record) is pinned by
        // `flood_loser_and_consumed_drop_legs_open_claim` / `ae_leg_opens_claim_above_consumed_drop`; this pins the SMT half: an adopter handed the verified
        // leg answers ready, one handed only the head does not.
        let leg = origin_leg(0xC3, 0x02);
        let tx: TxHash = leg.tx_hash;
        let mut head_only = SparseMerkleTree::new();
        let mut adopter = SparseMerkleTree::new();

        assert!(!adopter.cheque_sender_registered(&tx),
            "this node has registered nothing itself");

        let mut remote = make_entry(0xC3, 0x02);
        remote.tx_hash = tx;
        head_only.put(&remote);
        assert!(!head_only.cheque_sender_registered(&tx),
            "a bare head is not a record — `put` records nothing (R5)");

        adopter.put(&remote);
        adopter.record_verified_leg(crate::ban::verify_fork_leg(leg).unwrap(), 50);
        assert!(adopter.cheque_sender_registered(&tx),
            "a node that only ADOPTED the leg must still answer ready — \
             otherwise readiness is node-local and the receiver's pick-set \
             almost never includes the one node that knows");
    }

    #[test]
    fn ypx010_s14_empty_tx_hash_is_never_recorded_as_registered() {
        // Zero-tx_hash entries are debris (see the zero-pk / unauthored-head
        // work, KI#46/#48). Recording one would answer "ready" for a cheque id
        // of all zeros. Wave 3: through the real path — a leg claiming the
        // all-zero txid cannot verify (its preimage recomputes to a real txid),
        // so no record exists; and `put` records nothing at all.
        let mut smt = SparseMerkleTree::new();
        let mut e = make_entry(0xD4, 0x03);
        e.tx_hash = [0u8; 32];
        smt.put(&e);
        let mut zero = origin_leg(0xD4, 0x03);
        zero.tx_hash = [0u8; 32];
        assert!(crate::ban::verify_fork_leg(zero).is_err(),
            "a leg naming the all-zero txid is not a verified leg");
        assert!(!smt.cheque_sender_registered(&[0u8; 32]),
            "an all-zero tx_hash must never count as a registered send");
    }

    // ── ForkSettlement wave 3 S3 — the origin ledger (real keypairs) ────────

    /// A genuine send leg by wallet `seed` consuming `[consumed; 32]`, seq 5.
    fn origin_leg(seed: u8, consumed: u8) -> crate::types::ForkLeg {
        crate::types::test_legs::genuine_send_leg(
            &crate::types::test_legs::wallet(seed),
            [consumed; 32], 5, "p@axiom.internal/0123456789", 400, seed as u64, 3,
        )
    }
    fn verified(leg: crate::types::ForkLeg) -> crate::ban::VerifiedForkLeg {
        crate::ban::verify_fork_leg(leg).expect("genuine leg verifies")
    }

    /// Test 11 — write-once. A second record of the same txid (an honest retry,
    /// a re-flood) is `Duplicate` and changes NOTHING: `first_seen_secs` and
    /// `contested` are immutable, and no second WAL op is queued.
    /// MUTATION: `insert` instead of the early `Duplicate` return ⇒ red.
    #[test]
    fn origin_record_is_write_once() {
        let mut smt = SparseMerkleTree::new();
        let leg = origin_leg(0xE1, 0x01);
        let tx = leg.tx_hash;
        assert_eq!(smt.record_verified_leg(verified(leg.clone()), 100),
            OriginOutcome::Created { contested: false });
        // The parent becomes consumed afterwards — a recompute would flip it.
        let mut parent = make_entry(0xE9, 0x01);
        parent.current_state = [0x01; 32];
        smt.put(&parent);
        let mut child = parent.clone();
        child.wallet_seq = 1;
        child.current_state = [0x02; 32];
        smt.put(&child);
        assert!(smt.is_state_consumed(&[0x01; 32]));
        assert_eq!(smt.record_verified_leg(verified(leg), 999), OriginOutcome::Duplicate);
        let e = smt.vouch_record(&tx).unwrap();
        assert_eq!(e.first_seen_secs, 100, "first_seen is immutable");
        assert!(!e.contested, "contested is fixed at birth, never recomputed");
        assert_eq!(smt.take_origin_wal_pending().len(), 1, "one WAL op, not two");
        assert_eq!(smt.origin_records_created(), 1);
    }

    /// Test 12 + test 31 — a second, DIFFERENT txid under one `(pk, consumed)`
    /// key is `Conflict`: the new record IS inserted, `held` returns the prior
    /// leg (both legs in hand = the `ForkClaim`), and the key is HELD. An honest
    /// retry (same txid) never conflicts. MUTATION: skip the index lookup
    /// (treat every new txid as `Created`) ⇒ red.
    #[test]
    fn origin_second_txid_under_key_is_conflict_and_both_recorded() {
        let mut smt = SparseMerkleTree::new();
        let sk = crate::types::test_legs::wallet(0xE2);
        let g = |recv: &str, nonce| crate::types::test_legs::genuine_send_leg(&sk, [0x01; 32], 5, recv, 400, nonce, 3);
        let (a, b) = (g("p@axiom.internal/0123456789", 1), g("q@axiom.internal/0123456789", 2));
        let key = (sk.verifying_key().to_bytes(), [0x01u8; 32]);
        assert_eq!(smt.record_verified_leg(verified(a.clone()), 10), OriginOutcome::Created { contested: false });
        assert!(!smt.origin_key_is_held(&key), "one record = not held");
        // Honest retry of the SAME txid: Duplicate, never Conflict (test 31).
        assert_eq!(smt.record_verified_leg(verified(a.clone()), 11), OriginOutcome::Duplicate);
        assert!(smt.origin_conflicting_keys().is_empty());
        match smt.record_verified_leg(verified(b.clone()), 12) {
            OriginOutcome::Conflict { held } => {
                assert_eq!(held.len(), 1);
                assert_eq!(held[0].leg, a, "the held leg comes back — the claim's other half");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
        assert!(smt.cheque_sender_registered(&a.tx_hash) && smt.cheque_sender_registered(&b.tx_hash),
            "BOTH legs are recorded");
        assert!(smt.origin_key_is_held(&key));
        assert_eq!(smt.origin_conflicting_keys(), vec![key]);
        let mut both = vec![a.tx_hash, b.tx_hash];
        both.sort();
        assert_eq!(smt.legs_under(&key), both.iter().map(|t| LegRef::Send(*t)).collect::<Vec<_>>(), "ascending txids");
        // And the two held records form a claim the ONE verifier accepts.
        let claim = crate::types::ForkClaim { a, b };
        assert_eq!(crate::ban::verify_fork_claim(&claim), Ok(()));
    }

    /// Test 13 — [R16] a record is born CONTESTED when the parent is already
    /// consumed at this node and no sibling record is held (the node learned
    /// the consumption second-hand and cannot name the other leg). A contested
    /// record holds its key. MUTATION: drop the `is_state_consumed` term ⇒ red.
    /// Control: the same leg at a node where the parent is NOT consumed is
    /// born uncontested (the R24 shape — evaluated BEFORE any put).
    #[test]
    fn origin_record_born_contested_when_parent_consumed_and_no_sibling() {
        let leg = origin_leg(0xE3, 0x31);
        let key = leg.key();
        let mut fresh = SparseMerkleTree::new();
        assert_eq!(fresh.record_verified_leg(verified(leg.clone()), 1), OriginOutcome::Created { contested: false });
        assert!(!fresh.origin_key_is_held(&key));
        assert_eq!(fresh.origin_contested_len(), 0);

        let mut smt = SparseMerkleTree::new();
        let mut parent = make_entry(0xE3, 0x31);
        parent.current_state = [0x31; 32];
        smt.put(&parent);
        let mut child = parent.clone();
        child.wallet_seq = 1;
        child.current_state = [0x32; 32];
        smt.put(&child);
        assert!(smt.is_state_consumed(&[0x31; 32]), "fixture: parent consumed here");
        assert_eq!(smt.record_verified_leg(verified(leg), 2), OriginOutcome::Created { contested: true });
        assert!(smt.origin_key_is_held(&key), "a contested record holds its key");
        assert_eq!(smt.origin_contested_len(), 1);
    }

    /// Design §9m B1 — [R24]'s exclusion for a head adopted BEFORE its leg is
    /// recorded (the HalAdvance carrier): when this node's head for the leg's
    /// bucket IS the leg (`current_state == new_state`, `tx_hash == txid`,
    /// previous state == `consumed`), the parent's consumption is the leg's
    /// own ⇒ NOT contested. Control: the same consumed parent with a DIFFERENT
    /// head (a hidden sibling's child) stays contested — R16 unchanged.
    /// MUTATION (run 2026-09-29): drop `&& !own_consumption` ⇒ the first
    /// assert red.
    #[test]
    fn origin_record_not_contested_when_head_is_this_leg() {
        let leg = origin_leg(0xE6, 0x41);
        let bucket = leg.bucket();
        let head_at = |state: [u8; 32], tx: [u8; 32], seq: u64| {
            let mut e = make_entry(0, 0);
            e.wallet_id = bucket;
            e.current_state = state;
            e.tx_hash = tx;
            e.wallet_seq = seq;
            e
        };
        // Parent head, then THIS leg's head adopted without a record (HalAdvance).
        let mut smt = SparseMerkleTree::new();
        smt.put(&head_at([0x41; 32], [0x77; 32], 4));
        smt.put(&head_at(leg.new_state, leg.tx_hash, 4));
        assert!(smt.is_state_consumed(&[0x41; 32]), "fixture: parent consumed here");
        assert_eq!(smt.record_verified_leg(verified(leg.clone()), 2), OriginOutcome::Created { contested: false },
            "the consumption is this leg's own (head IS the leg)");
        // A hidden sibling's head: same consumed parent, another child.
        let mut other = SparseMerkleTree::new();
        other.put(&head_at([0x41; 32], [0x77; 32], 4));
        other.put(&head_at([0x42; 32], [0x78; 32], 4));
        assert_eq!(other.record_verified_leg(verified(leg), 2), OriginOutcome::Created { contested: true },
            "second-hand consumption by another child stays contested (R16)");
    }

    /// Test 26 (SMT half) — R11: no path but `record_verified_leg` makes a
    /// record. A zero-pk leg is refused by the verifier (so it cannot even be
    /// offered); `put`, snapshot-style restore puts and
    /// WAL-`Put`-style replay puts of heads carrying a real txid record
    /// nothing. MUTATION: re-add the `put_inner` insert ⇒ red.
    #[test]
    fn no_record_from_zero_pk_redeem_leg_snapshot_restore_or_wal_put_replay() {
        let mut zero = origin_leg(0xE4, 0x01);
        if let crate::types::LegPreimage::Send(p) = &mut zero.seq_proof.preimage { p.client_pk = [0u8; 32]; }
        assert_eq!(crate::ban::verify_fork_leg(zero).err(), Some(crate::ban::ForkLegRefusal::ZeroPk));

        let leg = origin_leg(0xE5, 0x01);
        let mut smt = SparseMerkleTree::new();
        let mut e = make_entry(0xE5, 0x07);
        e.tx_hash = leg.tx_hash;
        smt.put(&e);                                                        // door/flood/AE head write
        smt.put_with_proof(&e, PutProof::RestoredFromLocalState(None));     // snapshot restore
        smt.put_with_proof(&e, PutProof::RestoredFromLocalState(Some(leg.seq_proof.clone()))); // WAL Put replay
        assert_eq!(smt.origin_len(), 0, "no head write creates a record");
        assert!(smt.take_origin_wal_pending().is_empty());
        assert!(!smt.cheque_sender_registered(&leg.tx_hash));
    }

    /// [R27] restore is VERBATIM: it keeps the persisted `contested` and
    /// `first_seen_secs` (even where a recompute would differ) and never
    /// queues a WAL op. Since W1 (§9o [R58]) the LAST persisted copy of the
    /// SAME leg wins (record-AE re-logs an upgraded record); a different leg
    /// under a held txid never replaces it.
    /// MUTATION: route restore through `record_verified_leg` ⇒ red; drop the
    /// same-leg check in `restore_last_copy_wins` ⇒ red.
    #[test]
    fn restore_origin_entry_is_verbatim_or_insert() {
        let leg = origin_leg(0xE6, 0x41);
        let tx = leg.tx_hash;
        let mut smt = SparseMerkleTree::new();
        let mut parent = make_entry(0xE6, 0x41);
        parent.current_state = [0x41; 32];
        smt.put(&parent);
        let mut child = parent.clone();
        child.wallet_seq = 1;
        child.current_state = [0x42; 32];
        smt.put(&child);
        let persisted = OriginLedgerEntry { leg: leg.clone(), first_seen_secs: 1234, contested: false };
        assert!(smt.restore_origin_entry(tx, persisted.clone()));
        assert_eq!(smt.vouch_record(&tx), Some(&persisted), "verbatim — no recompute of contested");
        assert!(smt.take_origin_wal_pending().is_empty(), "a restore is not a new record");
        // W1 (§9o [R58]) — a later copy of the SAME leg wins (an upgrade is
        // re-logged; replay runs in WAL order). A copy of a DIFFERENT leg
        // under the held txid is refused.
        let mut foreign = persisted.clone();
        foreign.leg.client_sig = vec![0u8; 64];
        smt.restore_origin_entry(tx, foreign);
        assert_eq!(smt.vouch_record(&tx), Some(&persisted), "a different leg never replaces the held one");
        let later = OriginLedgerEntry { leg, first_seen_secs: 9, contested: true };
        smt.restore_origin_entry(tx, later.clone());
        assert_eq!(smt.vouch_record(&tx), Some(&later), "last copy of the same leg wins");
        assert!(smt.take_origin_wal_pending().is_empty(), "a restore is still not a new record");
        assert_eq!(smt.origin_ledger_snapshot(), vec![(tx, later)]);
    }

    #[test]
    fn insert_single_entry() {
        let mut tree = SparseMerkleTree::new();
        let entry = make_entry(0xAA, 0xBB);
        let root1 = tree.put(&entry);

        assert_ne!(root1, empty_hash(TREE_DEPTH));
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.get(&entry.wallet_id), Some(&entry));
    }

    #[test]
    fn insert_two_entries_different_root() {
        let mut tree = SparseMerkleTree::new();
        let e1 = make_entry(0x01, 0x10);
        let e2 = make_entry(0x02, 0x20);

        let root1 = tree.put(&e1);
        let root2 = tree.put(&e2);

        assert_ne!(root1, root2);
        assert_eq!(tree.len(), 2);
        assert_eq!(tree.get(&e1.wallet_id), Some(&e1));
        assert_eq!(tree.get(&e2.wallet_id), Some(&e2));
    }

    #[test]
    fn update_entry_changes_root() {
        let mut tree = SparseMerkleTree::new();
        let e1 = make_entry(0xAA, 0x01);
        let root1 = tree.put(&e1);

        let mut e1_updated = e1.clone();
        e1_updated.current_state[0] = 0x02;
        e1_updated.tick = 2;
        let root2 = tree.put(&e1_updated);

        assert_ne!(root1, root2);
        assert_eq!(tree.len(), 1); // same key, count unchanged
        assert_eq!(tree.get(&e1.wallet_id), Some(&e1_updated));
    }

    #[test]
    fn deterministic_roots() {
        // Two trees with same entries in same order produce same root.
        let entries: Vec<NablaEntry> = (0..10).map(|i| make_entry(i, i + 100)).collect();

        let mut tree1 = SparseMerkleTree::new();
        let mut tree2 = SparseMerkleTree::new();

        for e in &entries {
            tree1.put(e);
            tree2.put(e);
        }

        assert_eq!(tree1.root_hash(), tree2.root_hash());
    }

    #[test]
    fn merkle_proof_verifies() {
        let mut tree = SparseMerkleTree::new();
        let entries: Vec<NablaEntry> = (0..5).map(|i| make_entry(i, i + 50)).collect();

        for e in &entries {
            tree.put(e);
        }

        let root = tree.root_hash();

        // Verify proof for each entry
        for e in &entries {
            let proof = tree.merkle_proof(&e.wallet_id);
            assert!(
                SparseMerkleTree::verify_proof(&root, &proof, e),
                "Proof failed for wallet_id[0] = {}",
                e.wallet_id[0]
            );
        }
    }

    #[test]
    fn merkle_proof_rejects_wrong_entry() {
        let mut tree = SparseMerkleTree::new();
        let e1 = make_entry(0xAA, 0xBB);
        tree.put(&e1);

        let root = tree.root_hash();
        let proof = tree.merkle_proof(&e1.wallet_id);

        // Tamper with the entry
        let mut fake = e1.clone();
        fake.current_state[0] = 0xFF;
        assert!(!SparseMerkleTree::verify_proof(&root, &proof, &fake));
    }

    /// SEC-16: a proof with more siblings than the tree depth must be
    /// rejected without panicking (the verify loop uses the sibling index
    /// as a key-bit position; len > TREE_DEPTH would index past the key).
    #[test]
    fn verify_proof_rejects_over_long_proof_without_panic() {
        let mut tree = SparseMerkleTree::new();
        let e = make_entry(0xAA, 0xBB);
        tree.put(&e);
        let root = tree.root_hash();

        let mut proof = tree.merkle_proof(&e.wallet_id);
        // Forge an over-long sibling vector (TREE_DEPTH + 1 entries).
        proof.siblings = vec![[0u8; 32]; TREE_DEPTH + 1];
        assert!(
            !SparseMerkleTree::verify_proof(&root, &proof, &e),
            "over-long proof must be rejected, not panic",
        );
    }

    /// SEC-16: domain separation makes a leaf hash distinct from an
    /// internal-node hash over the same 64 bytes — no node-type confusion.
    #[test]
    fn leaf_and_internal_hashes_are_domain_separated() {
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];
        let internal = hash_internal(&left, &right);
        // A leaf whose key||value equals left||right hashes differently.
        let mut value = Vec::with_capacity(32);
        value.extend_from_slice(&right);
        let leaf = hash_leaf(&left, &value);
        assert_ne!(internal, leaf, "leaf and internal must not collide");
    }

    /// SEC-16: an empty (non-inclusion) node hash is distinct from every
    /// populated leaf hash, so inclusion can't be forged as non-inclusion.
    #[test]
    fn empty_leaf_distinct_from_populated_leaf() {
        let empty = empty_hash(0);
        let e = make_entry(0xAA, 0xBB);
        let serialized = bincode::serialize(&e).unwrap();
        let populated = hash_leaf(&e.wallet_id, &serialized);
        assert_ne!(empty, populated, "empty and populated leaf must differ");
    }

    #[test]
    fn many_entries_performance() {
        let mut tree = SparseMerkleTree::new();
        // Insert 1000 entries — should complete quickly
        for i in 0u16..1000 {
            let mut wid = [0u8; 32];
            wid[0] = (i >> 8) as u8;
            wid[1] = (i & 0xFF) as u8;
            let entry = NablaEntry {
                            received_from: None,
                            wallet_seq: 0,
                wallet_id: wid,
                current_state: wid,
                tx_hash: [0u8; 32],
                tick: i as u64,
                group_members: None,
                status: WalletStatus::Normal,
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            };
            tree.put(&entry);
        }
        assert_eq!(tree.len(), 1000);
        // Root hash should be deterministic
        let root = tree.root_hash();
        assert_ne!(root, empty_hash(TREE_DEPTH));
    }

    // ───────────────────────────────────────────────────────────────────
    // YP §19.6 fee ledger — TxRecord / record_tx_meta / validator_earnings
    // ───────────────────────────────────────────────────────────────────

    use axiom_core_logic::types::FeeShare;
    use crate::types::TxRecord;

    fn make_record(receiver_byte: u8, amount: u64, vid_byte: u8, fee: u64, tick: u64) -> TxRecord {
        let mut receiver = [0u8; 32];
        receiver[0] = receiver_byte;
        let mut vid = [0u8; 32];
        vid[0] = vid_byte;
        TxRecord {
            receiver_wallet_id: receiver,
            amount,
            fee_breakdown: vec![FeeShare { validator_id: vid, amount: fee }],
            tick,
        }
    }

    fn txhash(b: u8) -> TxHash {
        let mut h = [0u8; 32];
        h[0] = b;
        h
    }

    fn vid(b: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = b;
        v
    }

    #[test]
    fn record_tx_meta_no_op_on_bloom_mode() {
        let mut tree = SparseMerkleTree::with_txid_mode(TxidServiceMode::Bloom);
        let rec = make_record(0xAA, 1_000_000, 0x77, 3000, 5);
        tree.record_tx_meta(txhash(0x01), rec);
        assert_eq!(tree.tx_records_len(), 0);
        assert_eq!(tree.validator_earnings(&vid(0x77), 0).0, 0);
    }

    #[test]
    fn record_tx_meta_populates_both_stores_on_hashmap_mode() {
        let mut tree = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        let rec = make_record(0xAA, 1_000_000, 0x77, 3000, 5);
        tree.record_tx_meta(txhash(0x01), rec.clone());
        assert_eq!(tree.tx_records_len(), 1);
        assert_eq!(tree.tx_record(&txhash(0x01)), Some(&rec));
        let (total, entries) = tree.validator_earnings(&vid(0x77), 0);
        assert_eq!(total, 3000);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tx_hash, txhash(0x01));
        assert_eq!(entries[0].amount, 3000);
        assert_eq!(entries[0].tick, 5);
        // Step 8.3.A: full_fee_breakdown is populated from txid_records.
        assert_eq!(entries[0].full_fee_breakdown, rec.fee_breakdown);
    }

    /// The settled WATERMARK makes the tranche accumulator convergent across
    /// recorders (design decision 2026-08-10). Two recorders share the SAME settled
    /// earnings (tick < watermark) but have DIFFERENT in-flight tails
    /// (tick >= watermark); reading up to the watermark returns the IDENTICAL
    /// sum — the tail is excluded — so their tranche payloads converge no matter
    /// the replication lag. The positive control proves it: WITHOUT the
    /// watermark they diverge.
    #[test]
    fn watermark_excludes_in_flight_tail_so_recorders_converge() {
        let watermark = 100u64;
        let v = 0x77u8;
        let settle = |tree: &mut SparseMerkleTree| {
            tree.record_tx_meta(txhash(0x01), make_record(0xA1, 1_000_000, v, 3000, 10));
            tree.record_tx_meta(txhash(0x02), make_record(0xA2, 1_000_000, v, 5000, 50));
        };
        let mut r1 = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        let mut r2 = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        settle(&mut r1);
        settle(&mut r2);
        // DIFFERENT in-flight tails (tick >= watermark) — not yet replicated.
        r1.record_tx_meta(txhash(0x03), make_record(0xA3, 1_000_000, v, 7000, 105));
        r2.record_tx_meta(txhash(0x04), make_record(0xA4, 1_000_000, v, 9000, 130));

        let (t1, _) = r1.validator_earnings_by_class(&vid(v), false, 0, watermark);
        let (t2, _) = r2.validator_earnings_by_class(&vid(v), false, 0, watermark);
        assert_eq!(t1, t2, "same settled prefix -> same accumulator despite different tails");
        assert_eq!(t1, 3000 + 5000, "only settled earnings counted");

        // positive control: read to the horizon and they DIVERGE — the watermark
        // is what creates the convergence, not the data.
        let (all1, _) = r1.validator_earnings_by_class(&vid(v), false, 0, u64::MAX);
        let (all2, _) = r2.validator_earnings_by_class(&vid(v), false, 0, u64::MAX);
        assert_ne!(all1, all2, "without the watermark the in-flight tail desyncs recorders");
    }

    /// KI#82 — fee-ledger anti-entropy. Two recorders each hold a record the
    /// other lacks (the exact gap that left the accumulators diverged under
    /// load). One bucketed digest exchange in EACH direction (peer rotation)
    /// converges them to the UNION — identical set, identical digests, identical
    /// accumulator. See AXIOM_DESIGN_NablaAntiEntropy.md §13.
    #[test]
    fn txid_ae_bucketed_reconcile_converges_to_the_union() {
        let bt = 300u64;
        let v = 0x77u8;
        // shared prefix (buckets 0 and 1)
        let shared = |t: &mut SparseMerkleTree| {
            t.record_tx_meta(txhash(0x01), make_record(0xA1, 1_000_000, v, 3000, 10)); // bucket 0
            t.record_tx_meta(txhash(0x02), make_record(0xA2, 1_000_000, v, 5000, 350)); // bucket 1
        };
        let mut a = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        let mut b = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        shared(&mut a);
        shared(&mut b);
        a.record_tx_meta(txhash(0x03), make_record(0xA3, 1_000_000, v, 7000, 355)); // A-only, bucket 1
        b.record_tx_meta(txhash(0x04), make_record(0xA4, 1_000_000, v, 9000, 20)); // B-only, bucket 0

        // Order-independence of the digest: same set, different insertion order → same digest.
        {
            let mut c = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
            c.record_tx_meta(txhash(0x02), make_record(0xA2, 1_000_000, v, 5000, 350));
            c.record_tx_meta(txhash(0x01), make_record(0xA1, 1_000_000, v, 3000, 10));
            let mut d = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
            shared(&mut d);
            assert_eq!(c.txid_bucket_digests(bt), d.txid_bucket_digests(bt), "digest is order-independent");
        }

        // Divergence is visible per-bucket.
        let da: std::collections::HashMap<u64, [u8; 32]> = a.txid_bucket_digests(bt).into_iter().collect();
        let db: std::collections::HashMap<u64, [u8; 32]> = b.txid_bucket_digests(bt).into_iter().collect();
        assert_ne!(da.get(&0), db.get(&0), "bucket 0 differs (B has extra)");
        assert_ne!(da.get(&1), db.get(&1), "bucket 1 differs (A has extra)");

        // helper mirroring the handler: `to` advertises, `from` pushes its
        // divergent-bucket records, `to` adopts them.
        fn reconcile(from: &SparseMerkleTree, to: &mut SparseMerkleTree, bt: u64) {
            let to_map: std::collections::HashMap<u64, [u8; 32]> =
                to.txid_bucket_digests(bt).into_iter().collect();
            let divergent: std::collections::HashSet<u64> = from
                .txid_bucket_digests(bt)
                .into_iter()
                .filter(|(bk, d)| to_map.get(bk) != Some(d))
                .map(|(bk, _)| bk)
                .collect();
            for (h, r) in from.txid_records_in_buckets(&divergent, bt) {
                to.record_tx_meta(h, r);
            }
        }
        reconcile(&b, &mut a, bt); // A adopts what B has
        reconcile(&a, &mut b, bt); // B adopts what A has (reverse rotation)

        assert_eq!(a.tx_records_len(), 4);
        assert_eq!(b.tx_records_len(), 4);
        assert_eq!(a.txid_bucket_digests(bt), b.txid_bucket_digests(bt), "digests converge");
        assert_eq!(
            a.validator_earnings(&vid(v), 0).0,
            b.validator_earnings(&vid(v), 0).0,
            "accumulators converge — the KI#82 fix"
        );
    }

    #[test]
    fn record_tx_meta_zero_txhash_is_no_op() {
        let mut tree = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        let rec = make_record(0xAA, 1_000_000, 0x77, 3000, 5);
        tree.record_tx_meta([0u8; 32], rec);
        assert_eq!(tree.tx_records_len(), 0);
    }

    #[test]
    fn record_tx_meta_duplicate_tx_hash_does_not_double_count() {
        // Same tx_hash gossiped twice (legitimate retry or flood echo) must
        // not double-count earnings — the secondary index has to dedup
        // alongside the primary record store.
        let mut tree = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        let rec = make_record(0xAA, 1_000_000, 0x77, 3000, 5);
        tree.record_tx_meta(txhash(0x01), rec.clone());
        tree.record_tx_meta(txhash(0x01), rec);
        assert_eq!(tree.tx_records_len(), 1);
        assert_eq!(tree.validator_earnings(&vid(0x77), 0).0, 3000);
    }

    #[test]
    fn validator_earnings_filter_since_tick() {
        let mut tree = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        tree.record_tx_meta(txhash(0x01), make_record(0xAA, 1_000_000, 0x77, 100, 5));
        tree.record_tx_meta(txhash(0x02), make_record(0xAA, 1_000_000, 0x77, 200, 10));
        tree.record_tx_meta(txhash(0x03), make_record(0xAA, 1_000_000, 0x77, 300, 15));
        // since_tick = 10 includes ticks 10 and 15.
        let (total, entries) = tree.validator_earnings(&vid(0x77), 10);
        assert_eq!(total, 500);
        assert_eq!(entries.len(), 2);
        // Deterministic ordering — tick ascending.
        assert_eq!(entries[0].tick, 10);
        assert_eq!(entries[1].tick, 15);
    }

    #[test]
    fn validator_earnings_unknown_validator_returns_zero() {
        let mut tree = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        tree.record_tx_meta(txhash(0x01), make_record(0xAA, 1_000_000, 0x77, 3000, 5));
        let (total, entries) = tree.validator_earnings(&vid(0xFE), 0);
        assert_eq!(total, 0);
        assert!(entries.is_empty());
    }

    #[test]
    fn validator_earnings_multi_validator_breakdown() {
        // Two records, each with two slots (Lambda1 + Lambda2). Verify
        // each validator's index lists only its own slots.
        let mut tree = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        let two_slots = TxRecord {
            receiver_wallet_id: [0xAA; 32],
            amount: 1_000_000,
            fee_breakdown: vec![
                FeeShare { validator_id: vid(0x11), amount: 1500 },
                FeeShare { validator_id: vid(0x22), amount: 1500 },
            ],
            tick: 1,
        };
        tree.record_tx_meta(txhash(0x01), two_slots.clone());
        tree.record_tx_meta(txhash(0x02), two_slots);
        assert_eq!(tree.validator_earnings(&vid(0x11), 0).0, 3000);
        assert_eq!(tree.validator_earnings(&vid(0x22), 0).0, 3000);
        // Total across all records = 6000; per-validator sees half.
    }

    // ───────────────────────────────────────────────────────────────────
    // YP §19.6 Step 6 — earnings query end-to-end signing chain
    // ───────────────────────────────────────────────────────────────────

    #[test]
    fn earnings_query_signs_canonical_payload_and_verifies() {
        // Build an SMT with two fee records for the same validator, then
        // walk the exact Step 6 query path: compute attestation payload,
        // sign with an Ed25519 key, verify the signature. This is the
        // chain `query_validator_earnings_core` ships, less the NodeState
        // wrapper.
        use ed25519_dalek::{SigningKey, Signer, Verifier};

        let mut tree = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        tree.record_tx_meta(txhash(0x01), make_record(0xAA, 1_000_000, 0x77, 1500, 5));
        tree.record_tx_meta(txhash(0x02), make_record(0xAA, 1_000_000, 0x77, 1500, 10));

        let validator_id = vid(0x77);
        let (total, entries) = tree.validator_earnings(&validator_id, 0);
        assert_eq!(total, 3000);
        assert_eq!(entries.len(), 2);

        // Sign the canonical Step-6 attestation payload.
        let nabla_node_id = [0xCC; 32];
        let until_tick = 12;
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let vk = sk.verifying_key();
        let payload = axiom_core_logic::compute::compute_earnings_attestation_payload(
            &nabla_node_id, &validator_id, 0, until_tick, total, &entries, true, 0,
        );
        let sig = sk.sign(&payload);

        // Consumer-side verify mirrors what a validator's SDK will do
        // before trusting the response — recomputes the payload from the
        // claimed fields and verifies the Ed25519 sig with the node's pk.
        let recomputed = axiom_core_logic::compute::compute_earnings_attestation_payload(
            &nabla_node_id, &validator_id, 0, until_tick, total, &entries, true, 0,
        );
        assert!(vk.verify(&recomputed, &sig).is_ok(),
            "honest consumer must accept the signed payload");

        // A consumer fed a tampered total fails verification.
        let tampered = axiom_core_logic::compute::compute_earnings_attestation_payload(
            &nabla_node_id, &validator_id, 0, until_tick, total + 1, &entries, true, 0,
        );
        assert!(vk.verify(&tampered, &sig).is_err(),
            "tampered total must fail Ed25519 verify");
    }

    #[test]
    fn earnings_query_bloom_mode_returns_empty_non_authoritative() {
        // Bloom-mode nodes have no txid_records. validator_earnings returns
        // (0, empty) — matches what `query_validator_earnings_core` ships
        // with is_authoritative=false.
        let mut tree = SparseMerkleTree::with_txid_mode(TxidServiceMode::Bloom);
        tree.record_tx_meta(txhash(0x01), make_record(0xAA, 1_000_000, 0x77, 1500, 5));
        let (total, entries) = tree.validator_earnings(&vid(0x77), 0);
        assert_eq!(total, 0);
        assert!(entries.is_empty());
    }

    #[test]
    fn earnings_query_ordering_is_byte_stable() {
        // Two honest hashmap nodes that received the same records via
        // gossip produce identical entries vectors and therefore identical
        // attestation hashes. This is what makes k-of-N peer cross-check
        // feasible (Step 8's withdrawal flow).
        let mut a = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        let mut b = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        // Insert in DIFFERENT orders on each node.
        a.record_tx_meta(txhash(0x01), make_record(0xAA, 1_000_000, 0x77, 1500, 5));
        a.record_tx_meta(txhash(0x02), make_record(0xAA, 1_000_000, 0x77, 1500, 10));
        b.record_tx_meta(txhash(0x02), make_record(0xAA, 1_000_000, 0x77, 1500, 10));
        b.record_tx_meta(txhash(0x01), make_record(0xAA, 1_000_000, 0x77, 1500, 5));

        let (total_a, entries_a) = a.validator_earnings(&vid(0x77), 0);
        let (total_b, entries_b) = b.validator_earnings(&vid(0x77), 0);
        assert_eq!(total_a, total_b);
        assert_eq!(entries_a, entries_b,
            "two honest hashmap nodes must produce byte-identical entries");

        // Same hash on each side — Step 8's k-of-N cross-check can rely
        // on this invariant.
        let nid = [0xCC; 32];
        let h_a = axiom_core_logic::compute::compute_earnings_attestation_payload(
            &nid, &vid(0x77), 0, 12, total_a, &entries_a, true, 0,
        );
        let h_b = axiom_core_logic::compute::compute_earnings_attestation_payload(
            &nid, &vid(0x77), 0, 12, total_b, &entries_b, true, 0,
        );
        assert_eq!(h_a, h_b);
    }

    // ── KI#42: bloom saturation telemetry ──

    /// The consumed-state bloom must report its own fill, because its false
    /// positives fail CLOSED at the A12 anti-rollback gate — before this it had
    /// no exposed health signal at all and saturated invisibly.
    #[test]
    fn consumed_bloom_reports_fill_and_fpr() {
        let mut smt = SparseMerkleTree::new();
        assert_eq!(smt.consumed_bloom_count(), 0);
        assert_eq!(smt.consumed_bloom_fill_ratio(), 0.0);

        // Consume states through the real put() chokepoint, so the test exercises
        // the same path production does rather than poking the filter directly.
        for i in 1u8..=50 {
            // Same wallet advancing at constant seq (the tick/redeem path) —
            // each put() consumes the prior state. KI#65: the chain linkage is
            // what marks it a REAL consumption, so carry the real
            // `fact_tx_hash(prev, new)` exactly as production entries do.
            let mut e = make_entry(0xAA, i);
            if i > 1 {
                let mut prev = [0u8; 32];
                prev[0] = i - 1;
                e.tx_hash = crate::registration::fact_tx_hash(&prev, &e.current_state);
            }
            smt.put(&e);
        }

        assert!(smt.consumed_bloom_count() > 0, "put() must feed the consumed bloom");
        assert!(smt.consumed_bloom_fill_ratio() > 0.0);
        // Nowhere near the 10M design point, so the FPR must still be negligible.
        assert!(smt.consumed_bloom_fpr() < 0.001,
            "fpr {} unexpectedly high at trivial fill", smt.consumed_bloom_fpr());
    }

    /// Fill ratio is measured against the design capacity, so it is comparable
    /// across nodes and directly answers "how much runway is left".
    #[test]
    fn fill_ratio_is_relative_to_design_capacity() {
        let smt = SparseMerkleTree::new();
        // Empty filters are at 0% of capacity, not 0% of themselves.
        assert_eq!(smt.txid_bloom_fill_ratio(), 0.0);
        assert_eq!(smt.consumed_bloom_fill_ratio(), 0.0);
        // And capacity is the shared compile-time constant — the property that
        // makes `merge` work between nodes at all (identical dimensions).
        assert_eq!(crate::bloom::DEFAULT_BLOOM_EXPECTED_ITEMS, 10_000_000);
    }

    /// A peer must not be able to POISON us with a saturated filter. Union is
    /// permanent and `is_state_consumed` fails CLOSED, so adopting an over-dense
    /// bloom would make the node refuse every legitimate registration forever.
    /// The pre-existing comment ("an attacker peer's empty/forged view can't
    /// disarm us") covered only the opposite direction.
    #[test]
    fn merge_consumed_bloom_refuses_a_poisoned_filter() {
        let mut smt = SparseMerkleTree::new();

        // A hostile peer offers an all-ones filter of the correct dimensions.
        let mut evil = crate::bloom::TxidBloomFilter::new(
            smt.consumed_chain.expected_items_per_era());
        evil.set_all_bits_for_test();
        assert!(evil.bit_density() > 0.99);

        // Wrap it as an era, which is how it now arrives on the wire.
        let mut evil_era = crate::bloom_era::BloomEra::open(
            0, 0, crate::bloom_era::DEFAULT_ERA_DURATION_TICKS,
            smt.consumed_chain.expected_items_per_era());
        evil_era.filter = evil;
        let err = smt
            .merge_consumed_era(evil_era)
            .expect_err("a saturated era must be refused, not adopted");
        assert!(err.contains("density"), "error should name the cause: {err}");

        // And we are unpoisoned: an arbitrary state is still NOT consumed, so the
        // A12 gate still admits legitimate registrations.
        assert!(!smt.is_state_consumed(&[0x42u8; 32]),
            "refusing the merge must leave us usable");
    }

    /// The guard must not reject an HONEST filter. A peer at its design capacity
    /// sits near 50% density, well under the 80% ceiling.
    #[test]
    fn merge_consumed_bloom_accepts_an_honest_filter() {
        let mut smt = SparseMerkleTree::new();
        let mut peer = crate::bloom::TxidBloomFilter::new(
            smt.consumed_chain.expected_items_per_era());
        for i in 0u32..5_000 {
            let mut h = [0u8; 32];
            h[0..4].copy_from_slice(&i.to_le_bytes());
            peer.insert(&h);
        }
        assert!(peer.bit_density() < crate::bloom::MAX_ADOPTABLE_BIT_DENSITY);
        // KI#44: a peer's era must sit on the SAME GRID or merge_era correctly
        // refuses it (same id, different boundaries). Build it from the grid
        // helpers rather than raw 0..dur — that refusal is the mechanism working.
        let dur = crate::bloom_era::DEFAULT_ERA_DURATION_TICKS;
        let era_id = smt.consumed_chain.active_era_id();
        let start = crate::bloom_chain::era_start_tick(era_id, dur);
        let mut honest_era = crate::bloom_era::BloomEra::open(
            era_id, start, start + dur,
            smt.consumed_chain.expected_items_per_era());
        honest_era.filter = peer;
        smt.merge_consumed_era(honest_era)
            .expect("an honest era must be adopted");

        // And its knowledge transferred: a state the PEER saw is now consumed here.
        let mut known = [0u8; 32];
        known[0..4].copy_from_slice(&7u32.to_le_bytes());
        assert!(smt.is_state_consumed(&known), "peer knowledge must transfer");
    }

    // ── KI#42 step 4c: the txid filter is an era chain now ──

    /// The migration's whole point: a txid recorded long ago must still be found
    /// after the chain has rotated past its era. Under the old flat filter this was
    /// trivially true (nothing ever rotated) — which is exactly why the filter
    /// saturated forever. With eras it becomes a property that has to hold.
    #[test]
    fn recorded_txid_survives_era_rotation() {
        let mut smt = SparseMerkleTree::new();
        let wallet = [0xAAu8; 32];

        let mut old_txid = [0u8; 32];
        old_txid[0] = 0xA1;
        smt.record_txid(&old_txid, &wallet, tk(10));
        assert!(smt.may_contain_txid(&old_txid));

        // Advance far enough to roll the chain over several times. The default era
        // duration is 90 days of ticks, so jump well past it.
        let far = crate::bloom_era::DEFAULT_ERA_DURATION_TICKS * 3 + 500;
        let mut new_txid = [0u8; 32];
        new_txid[0] = 0xB2;
        smt.record_txid(&new_txid, &wallet, tk(far));

        assert!(smt.txid_chain().era_count() > 1, "expected rotation");
        assert!(smt.may_contain_txid(&old_txid),
            "a txid from a ROTATED era must still be found — otherwise a replay \
             looks fresh the moment an era turns over");
        assert!(smt.may_contain_txid(&new_txid));

        let mut never = [0u8; 32];
        never[0] = 0xC3;
        assert!(!smt.may_contain_txid(&never), "unseen txid must still miss");
    }

    /// Fill is now a PER-ERA number, not a lifetime one. That is the fix: the
    /// active era can overflow, but frozen eras have fixed FPR, so the metric
    /// stops being an unbounded countdown.
    #[test]
    fn txid_fill_ratio_tracks_the_active_era_not_all_time() {
        let mut smt = SparseMerkleTree::new();
        let wallet = [0xAAu8; 32];
        for i in 0u16..200 {
            let mut t = [0u8; 32];
            t[0..2].copy_from_slice(&i.to_le_bytes());
            smt.record_txid(&t, &wallet, tk(10));
        }
        let fill_before = smt.txid_bloom_fill_ratio();
        assert!(fill_before > 0.0);

        // Rotate: the new active era is empty, so fill DROPS — impossible under a
        // lifetime filter, and the whole point of rotating.
        let mut t = [0u8; 32];
        t[0] = 0xFF;
        smt.record_txid(&t, &wallet, tk(crate::bloom_era::DEFAULT_ERA_DURATION_TICKS + 1));
        assert!(smt.txid_bloom_fill_ratio() < fill_before,
            "active-era fill must reset on rotation");
        // Total count still reflects everything recorded, across eras.
        assert!(smt.txid_bloom_count() >= 200);
    }

    // ══════════════════════════════════════════════════════════════════
    // KI#42: the era migration under HASHMAP mode
    //
    // Review caught that nothing covered this. The pre-existing Hashmap tests all
    // exercise `record_tx_meta` (the fee ledger) — NOT `record_txid`, which is the
    // path the era migration actually changed. Two of the ten live nodes run
    // `--txid-mode hashmap`, so an untested divergence here would ship.
    // ══════════════════════════════════════════════════════════════════

    /// In Hashmap mode `record_txid` must feed BOTH stores: the era chain (fuzzy,
    /// rotates) and the exact index (authoritative, never rotates). If the
    /// migration had only fed the chain, hashmap nodes would silently lose their
    /// exactness advantage — the very thing they pay 5x memory for.
    #[test]
    fn hashmap_mode_record_txid_feeds_both_chain_and_exact_index() {
        let mut tree = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        let wallet = [0xAAu8; 32];
        let t = txhash(0x42);

        tree.record_txid(&t, &wallet, 10);

        assert!(tree.may_contain_txid(&t), "era chain must hold it");
        assert_eq!(tree.get_wallet_by_txid(&t), Some(wallet),
            "exact index must hold it too — hashmap mode's whole purpose");
    }

    /// Bloom mode must NOT populate the exact index — otherwise a light node pays
    /// the memory it explicitly opted out of.
    #[test]
    fn bloom_mode_record_txid_feeds_only_the_chain() {
        let mut tree = SparseMerkleTree::with_txid_mode(TxidServiceMode::Bloom);
        let wallet = [0xAAu8; 32];
        let t = txhash(0x43);

        tree.record_txid(&t, &wallet, 10);

        assert!(tree.may_contain_txid(&t), "chain holds it");
        assert_eq!(tree.get_wallet_by_txid(&t), None,
            "bloom-mode node must not build the exact index");
    }

    /// The two stores must still AGREE after the chain rotates. The exact index is
    /// flat and never rotates; the chain does. A txid recorded before a rotation
    /// must remain findable in both, or a hashmap node would answer "redeemed"
    /// exactly while its own bloom said "unseen" — a split-brain within one node.
    #[test]
    fn hashmap_exact_index_and_era_chain_agree_across_rotation() {
        let mut tree = SparseMerkleTree::with_txid_mode(TxidServiceMode::Hashmap);
        let wallet = [0xAAu8; 32];
        let old = txhash(0x51);
        tree.record_txid(&old, &wallet, tk(10));

        // Roll well past the era boundary and record another.
        let far = crate::bloom_era::DEFAULT_ERA_DURATION_TICKS * 2 + 100;
        let new = txhash(0x52);
        tree.record_txid(&new, &wallet, tk(far));
        assert!(tree.txid_chain().era_count() > 1, "expected rotation");

        for (label, t) in [("pre-rotation", old), ("post-rotation", new)] {
            assert!(tree.may_contain_txid(&t), "{label}: chain must still find it");
            assert_eq!(tree.get_wallet_by_txid(&t), Some(wallet),
                "{label}: exact index must still find it");
        }

        // And a txid never recorded misses in BOTH — no phantom agreement.
        let never = txhash(0x53);
        assert!(!tree.may_contain_txid(&never));
        assert_eq!(tree.get_wallet_by_txid(&never), None);
    }

    /// The consumed-state chain is mode-INDEPENDENT: a hashmap node gets no exact
    /// index for consumed states, so it relies on the same fuzzy chain as a bloom
    /// node. This is why the consumed chain needed the tighter per-era sizing —
    /// nobody can buy their way out of its false positives.
    #[test]
    fn consumed_chain_behaves_identically_in_both_modes() {
        for mode in [TxidServiceMode::Bloom, TxidServiceMode::Hashmap] {
            let mut tree = SparseMerkleTree::with_txid_mode(mode);
            // Same wallet advancing X -> Y; the second put consumes X.
            let e1 = make_entry(0xAA, 0x11);
            let e2 = make_entry(0xAA, 0x22);
            let x = e1.current_state;
            tree.put(&e1);
            tree.put(&e2);
            assert!(tree.is_state_consumed(&x),
                "{mode:?}: consumed marks must not depend on txid mode");
            assert!(!tree.is_state_consumed(&[0x99u8; 32]),
                "{mode:?}: unconsumed state must not read as consumed");
        }
    }

    /// KI#79 — the transfer invariant fix (b) rests on, as a red-bar test:
    /// a fully-allocated serialized bloom era (measured from the REAL chain,
    /// not recomputed from constants) must fit one StatePull section budget,
    /// and a worst-case StatePull response must fit one wire frame. Until
    /// 2026-08-08 both were false (5.41 MiB era vs 5 MiB budget vs 1 MiB
    /// wire) and era transfer had NEVER shipped — zero `[ERA-SYNC] adopted`
    /// in any node's log history. Anyone raising `*_ERA_REAL_ITEMS` without
    /// the caps lands here.
    #[test]
    fn ki79_era_fits_transfer_caps() {
        let smt = SparseMerkleTree::with_txid_mode(crate::bloom::TxidServiceMode::Hashmap);
        let consumed_len = smt
            .consumed_era_bytes(smt.consumed_chain().active_era_id())
            .map(|b| b.len())
            .expect("active consumed era must serialize");
        let txid_era = smt
            .txid_chain()
            .era(smt.txid_chain().active_era_id())
            .expect("active txid era exists");
        let mut buf = Vec::new();
        ciborium::into_writer(txid_era, &mut buf).expect("txid era must serialize");
        let worst_era = consumed_len.max(buf.len());

        assert!(
            worst_era <= crate::constants::STATE_PULL_MAX_BYTES,
            "a serialized era ({worst_era} B) exceeds STATE_PULL_MAX_BYTES \
             ({} B): era transfer will starve SILENTLY and lagging nodes can \
             never re-arm (KI#79). Raise the transfer caps in the same commit \
             as the era sizing, or build chunked transfer.",
            crate::constants::STATE_PULL_MAX_BYTES,
        );
        assert!(
            3 * crate::constants::STATE_PULL_MAX_BYTES + 2 * 1024 * 1024
                <= crate::transport::WIRE_MAX_MSG_BYTES,
            "worst-case StatePull response exceeds WIRE_MAX_MSG_BYTES (KI#79)",
        );
    }

    // ── §5.2.4 (KI#123) — structural proof retention ──

    fn p_entry(wallet_id: [u8; 32], state: u8, tx: u8, seq: u64, tick: u64) -> NablaEntry {
        NablaEntry {
            received_from: None,
            wallet_seq: seq,
            wallet_id,
            current_state: { let mut a = [0u8; 32]; a[0] = state; a },
            tx_hash: { let mut a = [0u8; 32]; a[0] = tx; a },
            tick,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: [9u8; 32],
            client_sig: vec![1u8; 64],
        }
    }

    fn p_proof(tag: u8) -> SeqProof {
        SeqProof {
            sender_state: None,
            state_hash: [tag; 32],
            commitment_hash: [tag; 32],
            epoch: 1,
            is_dev_class: false,
            oods_flag: None,
            confidence_index: None,
            sigs: vec![crate::types::SeqProofSig {
                validator_pk: [2u8; 32],
                receipt_commitment_sig: vec![2u8; 64],
            }],
            required_k: 3,
            preimage: crate::types::test_legs::opaque_redeem_leg(), // wave 2a — test proof, no WITNESS_V2 preimage
            declared: crate::types::test_legs::no_declared(),
        }
    }

    /// `Attested` installs the NEW head's proof atomically — even across a
    /// tx_hash change that just deleted the OLD head's proof. This is the
    /// window §5.2.1 rule 2's put-then-set convention left open (KI#123).
    #[test]
    fn s524_attested_installs_atomically_across_tx_change() {
        let wid = { let mut w = [0u8; 32]; w[0] = 0x51; w };
        let mut smt = SparseMerkleTree::new();
        smt.put_with_proof(&p_entry(wid, 0x0A, 0xA1, 5, tk(10)), PutProof::Attested(p_proof(0xA1)));
        assert!(smt.seq_proof(&wid).is_some());
        // Head advances with a DIFFERENT tx — old proof must go, new must be
        // present, in one call.
        smt.put_with_proof(&p_entry(wid, 0x0B, 0xB2, 6, tk(11)), PutProof::Attested(p_proof(0xB2)));
        let held = smt.seq_proof(&wid).expect("proof must survive the atomic swap");
        assert_eq!(held.state_hash, [0xB2; 32], "the NEW head's proof, not the old one");
    }

    /// `SameHeadStatusChange` (a §32 ban/taint/restore flip) keeps the
    /// retained proof — same head, same tx_hash, same binding.
    #[test]
    fn s524_status_flip_keeps_proof() {
        let wid = { let mut w = [0u8; 32]; w[0] = 0x52; w };
        let mut smt = SparseMerkleTree::new();
        let e = p_entry(wid, 0x0A, 0xA1, 5, tk(10));
        smt.put_with_proof(&e, PutProof::Attested(p_proof(0xA1)));
        let mut banned = e.clone();
        banned.status = WalletStatus::Banned;
        smt.put_with_proof(&banned, PutProof::SameHeadStatusChange);
        assert!(smt.seq_proof(&wid).is_some(), "a status flip must not strip the proof");
        assert_eq!(smt.get(&wid).unwrap().status, WalletStatus::Banned);
    }

    /// A `SameHeadStatusChange` whose tx_hash DIFFERS is a caller bug —
    /// fail closed (debug builds stop dead; §5.2.4).
    #[test]
    #[should_panic(expected = "SameHeadStatusChange")]
    fn s524_status_flip_with_tx_change_is_a_caller_bug() {
        let wid = { let mut w = [0u8; 32]; w[0] = 0x53; w };
        let mut smt = SparseMerkleTree::new();
        smt.put_with_proof(&p_entry(wid, 0x0A, 0xA1, 5, tk(10)), PutProof::Attested(p_proof(0xA1)));
        // Differing tx under a status-flip disposition: assert must fire.
        smt.put_with_proof(&p_entry(wid, 0x0B, 0xB2, 5, tk(11)), PutProof::SameHeadStatusChange);
    }

    /// THE KI#123 REPLAY — the 2026-08-25 stripping shape, at the predicate
    /// that now closes it. Held: an ATTESTED head (k=3 proof retained, the
    /// state a faithful-receipt redeem leaves). Candidate: the fact-confirm
    /// build — same wallet_seq (it copies the held seq by construction), a
    /// DIFFERING tx_hash, a fresher tick, and NO proof (unattested by
    /// construction).
    ///
    /// Rank 1c does not fire (it is one-directional: attested incoming only),
    /// so bare `superseded_by` falls to the equal-seq tick tiebreaker and the
    /// fresher candidate WINS — the counterfactual half below proves this
    /// test can fail, i.e. the predicate is load-bearing, not decorative.
    /// `fact_confirm_may_displace` must DECLINE it, and the proof must
    /// SURVIVE.
    #[test]
    fn ki123_fact_confirm_cannot_strip_attested_head() {
        let wid = { let mut w = [0u8; 32]; w[0] = 0x54; w };
        let mut smt = SparseMerkleTree::new();
        let held = p_entry(wid, 0x0A, 0xA1, 7, tk(100));
        smt.put_with_proof(&held, PutProof::Attested(p_proof(0xA1)));

        // The Aug-25 candidate shape: held seq, confirm's differing tx, fresh tick.
        let candidate = p_entry(wid, 0x0C, 0xC3, 7, tk(200));

        // Counterfactual: WITHOUT the KI#123 predicate, the merge adopts it —
        // proving the stripping path was real and this test bites.
        assert!(
            held.superseded_by(&candidate, true, false),
            "counterfactual broke: the tick tiebreaker no longer adopts the \
             candidate, so the predicate under test is untestable this way — \
             rewrite the fixture"
        );

        // The fix: DECLINED.
        assert!(
            !crate::types::fact_confirm_may_displace(&held, true, &candidate),
            "KI#123: a differing-tx unattested candidate must never displace \
             an attested head"
        );

        // And therefore the proof survives (nothing was written).
        assert!(smt.seq_proof(&wid).is_some(), "the attested head keeps its proof");
        assert_eq!(smt.get(&wid).unwrap().tx_hash[0], 0xA1, "head unchanged");
    }

    /// The fact-confirm site's INTENDED purpose stays alive: a candidate
    /// confirming the tx we already hold (same tx_hash, fresher tick) merges
    /// normally, and — via `SameHeadStatusChange` — the proof is KEPT.
    #[test]
    fn ki123_same_tx_confirm_still_merges_and_keeps_proof() {
        let wid = { let mut w = [0u8; 32]; w[0] = 0x55; w };
        let mut smt = SparseMerkleTree::new();
        let held = p_entry(wid, 0x0A, 0xA1, 7, tk(100));
        smt.put_with_proof(&held, PutProof::Attested(p_proof(0xA1)));

        // Same tx, fresher tick — a confirmation of the head we hold.
        let confirm = p_entry(wid, 0x0A, 0xA1, 7, tk(200));
        assert!(
            crate::types::fact_confirm_may_displace(&held, true, &confirm),
            "a same-tx confirm must still merge (the site's purpose)"
        );
        smt.put_with_proof(&confirm, PutProof::SameHeadStatusChange);
        assert!(smt.seq_proof(&wid).is_some(), "proof kept across the confirm");
        assert_eq!(smt.get(&wid).unwrap().tick, tk(200));
    }

    /// Against an UNATTESTED head, the ordinary merge still decides — the
    /// KI#77 one-directional ruling is untouched (nothing to strip).
    #[test]
    fn ki123_unattested_head_still_merges_by_tick() {
        let wid = { let mut w = [0u8; 32]; w[0] = 0x56; w };
        let held = p_entry(wid, 0x0A, 0xA1, 7, tk(100));
        let candidate = p_entry(wid, 0x0C, 0xC3, 7, tk(200));
        assert!(
            crate::types::fact_confirm_may_displace(&held, false, &candidate),
            "no proof to protect — the equal-seq tick tiebreaker decides as before"
        );
    }

    /// `RestoredFromLocalState` carries exactly what the persisted record
    /// carried — Some installs (the KI#73 replay path), None leaves absence.
    #[test]
    fn s524_restore_carries_persisted_proof() {
        let wid = { let mut w = [0u8; 32]; w[0] = 0x57; w };
        let mut smt = SparseMerkleTree::new();
        smt.put_with_proof(&p_entry(wid, 0x0A, 0xA1, 5, tk(10)), PutProof::RestoredFromLocalState(None));
        assert!(smt.seq_proof(&wid).is_none());
        smt.put_with_proof(
            &p_entry(wid, 0x0B, 0xB2, 6, tk(11)),
            PutProof::RestoredFromLocalState(Some(p_proof(0xB2))),
        );
        assert!(smt.seq_proof(&wid).is_some(), "WAL-replay proof rides the same call (KI#73)");
    }
}
