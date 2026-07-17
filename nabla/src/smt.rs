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

use std::collections::{HashMap, HashSet};

use crate::bloom::{TxidBloomFilter, TxidServiceMode, DEFAULT_BLOOM_EXPECTED_ITEMS};
use crate::constants::SMT_EMPTY_LEAF_LABEL;
use crate::types::{Hash256, MerkleProof, NablaEntry, SeqProof, StateId, TxHash, TxRecord, WalletId};
#[cfg(test)]
use crate::types::WalletStatus;

/// Tick-based expiry for cheque claim registrations.
/// 17,280 ticks at ~5s/tick = ~24 hours.
const CHEQUE_CLAIM_EXPIRY_TICKS: u64 = 17_280;

/// Cheque claim registration state.
/// Registered on 3 Nabla nodes during §4.6 cheque verification (before redeem).
/// First-wins rule: the claim with the lowest tick is authoritative.
#[derive(Debug, Clone)]
pub struct ChequeClaim {
    /// Ed25519 public key of the client who claimed this cheque.
    pub client_pk: Vec<u8>,
    /// Virtual tick when the claim was registered.
    pub claim_tick: u64,
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
    txid_bloom: TxidBloomFilter,
    /// Consumed-state bloom (YPX-020 / HAL anti-rollback). Records every wallet
    /// state that has been ADVANCED PAST (consumed) — fed in `put()` from the
    /// prior head a write overwrites, so it replicates implicitly via the gossip
    /// flood exactly like `txid_bloom` (no wire change, no validator auth — Nabla
    /// stays dumb, boundary-respecting). MONOTONIC (insert-only): a forged
    /// head-rollback (A12) can move `current_state` back to an ancestor X, but it
    /// can NEVER un-consume X here. A HAL re-anchor of a consumed X is rejected
    /// against THIS record, not the rollback-able head.
    consumed_state_bloom: TxidBloomFilter,
    /// KI#34 check-3: AUTHORITATIVE `wallet_id → previous_state` (the head a write
    /// overwrote = the consumed `X`). The exact-match companion to the lossy
    /// `consumed_state_bloom` — fed at the SAME `put()` chokepoint from `old.current_state`,
    /// so it's coupled by construction and can't drift from `entries`. Lets an honest
    /// node tell a fork (incoming `X→X'` with `old_state == previous_state[W]` but
    /// `new_state != current_state` = a double-consume of `X`) from a harmless stale-view
    /// head-mismatch, with NO false-positive risk (unlike the bloom). 32B/wallet, local
    /// (per-node from its own puts), NOT gossiped — each honest holder detects on its own.
    previous_states: HashMap<WalletId, StateId>,
    /// KI#34 WI3 hole-1: PARALLEL k=3 seq attestation per wallet, held OUTSIDE
    /// the leaf so it never touches the leaf hash (no AE divergence) — see
    /// `SeqProof`. Set at adoption (`set_seq_proof`) when a flood/AE message
    /// carried a valid proof; read by the AE path (`seq_proof`) to re-attach
    /// the attestation when serving a pulled entry, so a downstream node can
    /// verify the seq it adopts. Not gossiped on its own; rides the
    /// `StateUpdate` / `AeReconcile` / `AeEntries` wires alongside the entry.
    seq_proofs: HashMap<WalletId, SeqProof>,
    /// Txid service mode — controls whether txid_index HashMap is populated.
    txid_mode: TxidServiceMode,
    /// Two-step cheque claim/confirm state — tracks claimed cheques by cheque_id.
    /// Prevents double-redeem by rejecting concurrent claims from
    /// different client PKs. Entries expire after CHEQUE_CLAIM_EXPIRY_TICKS.
    cheque_claims: HashMap<[u8; 32], ChequeClaim>,
    /// YPX-020 HAL hibernation: wallet_pk → tick until which the wallet is
    /// "out of work" after a dead-overlap re-anchor. Set by `process_registration`
    /// when `is_hal_reanchor` (= `register_tick + HIBERNATION_WINDOW`); checked in
    /// `register_cheque_claim` to refuse the self-redeem until the window elapses.
    /// Derivable from the gossiped register tick, so the mesh converges on one value.
    hibernations: HashMap<[u8; 32], u64>,
    /// YPX-022 §2.1 — txids with a k-witnessed COMPLETION registration (redeemable).
    /// Marked from `process_registration` on the completion path (mode-INDEPENDENT,
    /// unlike the Hashmap-gated fee ledger). The RECALL gate refuses a recall of a
    /// completed txid. The KI#5 partial_bridge sub-quorum txid goes to `txid_index`
    /// via `record_txid` and is NEVER marked here → genuine partials stay recallable.
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
            txid_records: HashMap::new(),
            validator_earnings: HashMap::new(),
            txid_bloom: TxidBloomFilter::new(DEFAULT_BLOOM_EXPECTED_ITEMS),
            consumed_state_bloom: TxidBloomFilter::new(DEFAULT_BLOOM_EXPECTED_ITEMS),
            previous_states: HashMap::new(),
            seq_proofs: HashMap::new(),
            cheque_claims: HashMap::new(),
            hibernations: HashMap::new(),
            completed_txids: HashMap::new(),
            redeemed_txids: HashSet::new(),
            recalled_txids: HashMap::new(),
            burned_txids: HashSet::new(),
            txid_mode: mode,
        }
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
    pub fn put(&mut self, entry: &NablaEntry) -> Hash256 {
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
        let prev = self.entries.insert(entry.wallet_id, entry.clone());
        if let Some(old) = prev {
            if old.current_state != entry.current_state && old.current_state != [0u8; 32] {
                self.consumed_state_bloom.insert(&old.current_state);
                // KI#34 check-3: the SAME consumed head, kept exact (not bloom) so a
                // fork-freeze can be based on it without false-positive risk.
                self.previous_states.insert(entry.wallet_id, old.current_state);
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
            // (registration / flood / AE / advance-on-proof bridge / HAL / recall),
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
        self.consumed_state_bloom.may_contain(state)
    }

    /// KI#34 check-3: the AUTHORITATIVE state this wallet's current head was advanced
    /// FROM (the consumed `X`), or `None` if unknown (never advanced on this node /
    /// pre-feature genesis root). Exact-match — no false positive, so it is safe to
    /// base a fork-freeze on (unlike `is_state_consumed`'s bloom).
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

    /// Serialize the consumed-state bloom for inclusion in a StatePull response.
    pub fn consumed_bloom_bytes(&self) -> Vec<u8> {
        self.consumed_state_bloom.to_bytes()
    }

    /// UNION a peer's consumed-state bloom into the local one (OR the bit
    /// arrays). Re-arms a recovering node; never removes a consumed mark.
    pub fn merge_consumed_bloom(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Ok(());
        }
        let other = crate::bloom::TxidBloomFilter::from_bytes(bytes)?;
        self.consumed_state_bloom.merge(&other)
    }

    /// Snapshot the authoritative `previous_states` (wallet → consumed `X`) for
    /// a StatePull response.
    pub fn previous_states_snapshot(&self) -> Vec<(WalletId, StateId)> {
        self.previous_states.iter().map(|(w, s)| (*w, *s)).collect()
    }

    /// Merge a peer's `previous_states` (insert-if-absent). A recovering node
    /// has none, so it adopts the peer's; a partially-armed node fills gaps
    /// without clobbering a previous_state it already holds for a wallet.
    pub fn merge_previous_states(&mut self, entries: &[(WalletId, StateId)]) {
        for (w, s) in entries {
            self.previous_states.entry(*w).or_insert(*s);
            // A `previous_state[W]=X` means X was consumed → arm the bloom too,
            // so `is_state_consumed` fires for X on the recovered node.
            self.consumed_state_bloom.insert(s);
        }
    }

    /// KI#34 WI3 hole-1: the k=3 seq attestation held for `wallet_id` (parallel
    /// to the leaf — see `SeqProof`). The AE path re-attaches this when serving
    /// a pulled entry so a downstream node can verify the seq it adopts.
    pub fn seq_proof(&self, wallet_id: &WalletId) -> Option<&SeqProof> {
        self.seq_proofs.get(wallet_id)
    }

    /// Store the verified k=3 seq attestation for `wallet_id`. Called at
    /// adoption (flood / AE) AFTER the proof has been checked against the
    /// entry's `tx_hash` + `wallet_seq`, and at the ORIGIN's own registration
    /// commit (KI#38). Overwrites the prior proof — the SMT holds exactly one
    /// head per wallet, so it holds exactly one seq proof.
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
    pub fn record_txid(&mut self, txid: &TxHash, wallet_id: &WalletId) {
        if *txid == [0u8; 32] {
            return;
        }
        self.txid_bloom.insert(txid);
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

    /// Bloom filter check: has this txid probably been seen? (YPX-014)
    /// Returns false = definitely not seen. Returns true = probably seen (~0.1% FPR).
    pub fn may_contain_txid(&self, txid: &TxHash) -> bool {
        self.txid_bloom.may_contain(txid)
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
        self.txid_bloom.count()
    }

    /// Physical bytes of the bloom filter. Fixed at boot from the
    /// `--bloom-size` flag (default sized for 10M txids ≈ 18 MB).
    pub fn txid_bloom_bytes(&self) -> u64 {
        self.txid_bloom.size_bytes() as u64
    }

    /// Current bloom-filter false-positive rate, computed from the
    /// observed load. Operators watch this — when it climbs past a few
    /// percent the bloom is saturated and `/query-txid` answers get
    /// noisy. Domain: `[0.0, 1.0]`.
    pub fn txid_bloom_fpr(&self) -> f64 {
        self.txid_bloom.estimated_fpr()
    }

    /// Get a reference to the bloom filter (for persistence / export).
    pub fn txid_bloom(&self) -> &TxidBloomFilter {
        &self.txid_bloom
    }

    /// Replace the bloom filter (for loading from disk on restart).
    pub fn set_txid_bloom(&mut self, bloom: TxidBloomFilter) {
        self.txid_bloom = bloom;
    }

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

    /// Generate subtree proof at a given prefix.
    /// Returns the subtree hash and sibling path to root.
    pub fn subtree_hash_at(&self, prefix_bits: usize) -> Hash256 {
        // Navigate to the subtree root at the given prefix depth
        // For a full implementation this would walk the tree to the prefix
        // and return the hash at that node
        match &self.root {
            Some(node) => self.subtree_hash_recursive(node, prefix_bits, 0),
            None => empty_hash(TREE_DEPTH),
        }
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
    /// re-anchor writer). Mirrors `apply_remote_cheque_claim`. Monotonic: only
    /// advances the lock (take the max `until`) so a stale/replayed gossip can't
    /// shorten it. Returns true if this changed local state (→ forward).
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
    pub fn register_cheque_claim(
        &mut self,
        cheque_id: [u8; 32],
        client_pk: Vec<u8>,
        tick: u64,
    ) -> Result<(), String> {
        self.expire_claim_if_stale(&cheque_id, tick);

        if let Some(existing) = self.cheque_claims.get(&cheque_id) {
            if existing.client_pk != client_pk {
                return Err("CONFLICT".to_string());
            }
            return Ok(());
        }

        self.cheque_claims.insert(cheque_id, ChequeClaim {
            client_pk,
            claim_tick: tick,
        });
        Ok(())
    }

    fn expire_claim_if_stale(&mut self, cheque_id: &[u8; 32], current_tick: u64) {
        if let Some(entry) = self.cheque_claims.get(cheque_id) {
            if current_tick.saturating_sub(entry.claim_tick) >= CHEQUE_CLAIM_EXPIRY_TICKS {
                self.cheque_claims.remove(cheque_id);
            }
        }
    }

    /// Query the current cheque claim status for a cheque_id.
    pub fn query_cheque_claim(&self, cheque_id: &[u8; 32]) -> Option<&ChequeClaim> {
        self.cheque_claims.get(cheque_id)
    }

    /// Evict cheque claims older than 17,280 ticks.
    pub fn expire_stale_claims(&mut self, current_tick: u64) {
        self.cheque_claims.retain(|_cheque_id, entry| {
            current_tick.saturating_sub(entry.claim_tick) < CHEQUE_CLAIM_EXPIRY_TICKS
        });
    }

    /// Apply a cheque claim received via gossip from a remote node.
    /// First-wins: lowest tick is authoritative.
    pub fn apply_remote_cheque_claim(
        &mut self,
        cheque_id: &[u8; 32],
        client_pk: &[u8],
        claim_tick: u64,
        current_tick: u64,
    ) -> bool {
        if claim_tick + CHEQUE_CLAIM_EXPIRY_TICKS <= current_tick {
            return false;
        }

        self.expire_claim_if_stale(cheque_id, current_tick);

        if let Some(existing) = self.cheque_claims.get(cheque_id) {
            if claim_tick < existing.claim_tick {
                self.cheque_claims.insert(*cheque_id, ChequeClaim {
                    client_pk: client_pk.to_vec(),
                    claim_tick,
                });
                true
            } else {
                false
            }
        } else {
            self.cheque_claims.insert(*cheque_id, ChequeClaim {
                client_pk: client_pk.to_vec(),
                claim_tick,
            });
            true
        }
    }

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
            if age_secs < RECALL_INIT_WINDOW_LOW.to_secs() {
                return Err("TOO_EARLY".to_string());
            }
            if age_secs > RECALL_INIT_WINDOW_HIGH.to_secs() {
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

    fn subtree_hash_recursive(&self, node: &TreeNode, target_depth: usize, _current_depth: usize) -> Hash256 {
        if _current_depth == target_depth {
            return node.hash();
        }
        // For deeper traversal, return node hash at whatever depth we reach.
        // Full prefix-based traversal will be refined in Phase 4.
        node.hash()
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
    use super::*;
    use crate::types::NablaEntry;

    /// YPX-022 §2 (2026-07-07 repurpose) — RECALL gate INVERTED: you recall a
    /// COMPLETED send whose cheque the receiver has NOT redeemed. Not-registered ⇒
    /// nothing to recall (case 1); already-redeemed ⇒ receiver won, irreversible.
    /// Consume-once is first-wins + sender-authored; gossip merges lowest-tick and
    /// vetoes a redeemed txid.
    #[test]
    fn recall_gate_completed_notredeemed_recallable() {
        let mut smt = SparseMerkleTree::new();
        let sender = vec![1u8; 32];
        let completed: TxHash = [0xC0u8; 32];

        // Case 1: a not-registered send has no hash — nothing to recall.
        assert_eq!(
            smt.register_recall(completed, sender.clone(), 100),
            Err("NOT_REGISTERED".to_string()),
            "an unregistered send cannot be recalled"
        );

        // A completed, NOT-yet-redeemed send IS recallable — inside the window (completion
        // at tick 0, recall in [LOW.to_secs(), HIGH.to_secs()]). `age` is a difference of
        // tick VALUES (seconds), so the window is the PROJECTED tick counts. base is an
        // in-window recall tick for both modes.
        let base = RECALL_INIT_WINDOW_LOW.to_secs() + 5;
        smt.mark_txid_completed(&completed, 0);
        assert!(smt.register_recall(completed, sender.clone(), base).is_ok());
        // §2.2.1 — initiate is a RESERVATION: pending, NOT the terminal.
        assert!(smt.is_txid_recall_pending(&completed));
        assert!(!smt.is_txid_recalled(&completed),
            "a reservation must not block redeems — C stays live until the commit");
        // Idempotent for the same sender while reserved.
        assert!(smt.register_recall(completed, sender.clone(), base + 1).is_ok());
        // A different sender cannot recall someone else's send.
        assert_eq!(
            smt.register_recall(completed, vec![2u8; 32], base + 2),
            Err("CONFLICT".to_string())
        );

        // WINDOW: too early (age < LOW.to_secs()) and too late (age > HIGH.to_secs()) are
        // both refused. The window is measured in tick-VALUE age (seconds), so the bounds
        // are the PROJECTED tick counts.
        let early: TxHash = [0x11u8; 32];
        smt.mark_txid_completed(&early, 1000);
        assert_eq!(smt.register_recall(early, sender.clone(), 1000 + RECALL_INIT_WINDOW_LOW.to_secs() - 1),
            Err("TOO_EARLY".to_string()), "recall before the window opens is refused");
        // Just AT the projected low bound is accepted.
        let at_low: TxHash = [0x12u8; 32];
        smt.mark_txid_completed(&at_low, 1000);
        assert!(smt.register_recall(at_low, sender.clone(), 1000 + RECALL_INIT_WINDOW_LOW.to_secs()).is_ok(),
            "recall exactly at the projected low bound is accepted");
        let late: TxHash = [0x22u8; 32];
        smt.mark_txid_completed(&late, 1000);
        assert_eq!(smt.register_recall(late, sender.clone(), 1000 + RECALL_INIT_WINDOW_HIGH.to_secs() + 1),
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
            smt.register_recall(raw_ticks_early, sender.clone(), 1000 + RECALL_INIT_WINDOW_LOW.ticks()),
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
            smt.register_recall(redeemed, sender.clone(), base),
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
        assert_eq!(smt.register_recall([0u8; 32], sender.clone(), 1), Err("ERROR".to_string()));
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
        let claimed = tree.register_cheque_claim(cheque, wallet.to_vec(), until - 1);
        assert!(claimed.is_ok(),
            "a hibernating wallet must be able to claim (complete) — got {:?}", claimed);
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

    fn make_entry(id_byte: u8, state_byte: u8) -> NablaEntry {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = id_byte;
        let mut state = [0u8; 32];
        state[0] = state_byte;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = id_byte ^ state_byte;
        NablaEntry {
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
        let mut live = SparseMerkleTree::new();
        live.put(&entry(x, 1, 1));
        live.put(&entry(y, 2, 2));
        assert!(live.is_state_consumed(&x), "live node that saw X->Y knows X consumed");

        // (b) Recovering node: head-syncs Y (prev == None → no consumed insert),
        //     so PRE-rearm it is blind — the §5.2 gap, still present for a beat.
        let mut recovered = SparseMerkleTree::new();
        recovered.put(&entry(y, 2, 2));
        assert!(!recovered.is_state_consumed(&x), "pre-rearm: blind (the §5.2 gap)");

        // WI1 re-arm: exactly what the StatePull handler does on bootstrap.
        recovered
            .merge_consumed_bloom(&live.consumed_bloom_bytes())
            .unwrap();
        recovered.merge_previous_states(&live.previous_states_snapshot());

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
        node.merge_previous_states(&[([0xBBu8; 32], x)]); // learns X consumed
        assert!(node.is_state_consumed(&x));
        node.merge_consumed_bloom(&SparseMerkleTree::new().consumed_bloom_bytes())
            .unwrap(); // attacker's empty bloom
        assert!(node.is_state_consumed(&x), "union never subtracts a consumed mark");
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
}
