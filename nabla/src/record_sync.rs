//! Fork Settlement §9o [R58/R59] — R48 RECORD-AE (wave W1, 2026-09-30).
//!
//! Head anti-entropy (`AeReconcile` / `AeEntries`) carries HEADS. A fork leg
//! that is no longer a head anywhere — both branches continued at their own
//! doors, the floods lost — never rides it, so two sibling legs held by two
//! different nodes never meet and the record detector (`ban::
//! record_leg_and_detect`) never sees the pair (`fork_detection_mesh::
//! fork_retire_proof_c_*_rho1_loses_merge`, KI#235). Record-AE carries the
//! RECORDS: every node exchanges its verified legs with every peer (the R51
//! walk), so two legs under one `(pk, consumed)` key meet at the first
//! exchange with a holder of each, and the ONE verdict path bans on evidence.
//!
//! What lives here (pure — no I/O, no lock, no `NablaNode`):
//!
//! - [`LeafKey`] = `BLAKE3(tag ‖ pk ‖ consumed) ‖ txid ‖ kind` — clock-free,
//!   fixed per leg, so every node files one leg under one key (R48 replaced
//!   R43's `(bucket, …)` key, whose per-node day clamp gave one record two
//!   keys). Legs under one fork key share their first 64 nibbles, so fork
//!   siblings sit in one subtree.
//! - [`RecordTrie`] — an insert-only 16-ary radix trie over the leaf keys. A
//!   node is INTERNAL iff its subtree holds more than
//!   `RECORD_AE_BUCKET_SPLIT` leaves, else a BUCKET — so the shape (and every
//!   hash) is a pure function of the leaf SET, never of insert order. The leaf
//!   hash covers the KEY only: never the witness subset, `first_seen_secs` or
//!   `contested` (per-node metadata — two nodes holding one leg must agree).
//!   LEAVES ARE GRADED LEGS ONLY (every witness an R42 directory witness at
//!   THIS node — `ban::leg_is_directory_witnessed`); the owner (`NablaNode`)
//!   decides what is inserted.
//! - [`Descent`] — the RECEIVER's state machine: level by level, batched
//!   (`Ask::Nodes` ≤ `RECORD_AE_MAX_PREFIXES_PER_ASK` prefixes), then the legs
//!   it lacks (`Ask::Legs` ≤ `RECORD_AE_MAX_LEGS_PER_ANSWER`), against the
//!   responder's live trie. A level larger than the budget, or more wanted
//!   legs than the budget, is cut in a SALTED order (per boot, rotated per
//!   descent — txid prefixes are cheaply grindable, so a fixed order could be
//!   starved) and the descent ends TRUNCATED; the next descent resumes (a
//!   synced subtree hashes equal and drops out). An answer the responder cut
//!   short is re-asked (resume). An answer that delivers nothing asked is no
//!   progress: the descent ABORTS (a hostile responder cannot hold it open).
//! - [`Walk`] — the R51 per-boot walk over peers: inserted / deleted IN PLACE,
//!   never redrawn (a redraw lets Hello churn — attacker-triggerable — pick
//!   who is walked). [`TieredWalk`] (Fable 2026-10-01 F-5) walks the
//!   connected PINNED-genesis peers first in every window, then one citizen
//!   — an ORDER only, never trust.
//! - [`RecordAeSession`] — the per-node ledger: the R50 [`AeGuard`] (nonces
//!   issued / answered, per-`from` budget), the descents (at most ONE in
//!   flight per peer), the walk, the global answers-per-window cap, and the
//!   `/status` counters.
//! - the off-lock half of accepting an answer, [`prepare_answer`]: legs are
//!   checked against what was ASKED (an unrequested leg is refused unverified
//!   — counted) and verified with `ban::verify_fork_leg` WITHOUT the node
//!   lock; `NablaNode::record_ae_apply_answer` grades and records under it.
//!
//! RULE 5 / RULE 7: Nabla hygiene only. A hostile node answers nothing or
//! junk; junk is refused by `verify_fork_leg` (k-witnessed, wallet-signed) and
//! never recorded ungraded (R42). Core's settle rule holds regardless.
//! Residuals (§9o): synchrony — a verdict can be DELAYED (budgets, shedding,
//! eclipse), never wrong; a leg held only by colluders is never shown.
//! R49 (txid-keyed HAVE / negative cache) is deliberately NOT built — it is
//! the H-3 poisoning; a leg this node cannot grade (directory lag) is
//! re-fetched until its witnesses are admitted.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::ban::VerifiedForkLeg;
use crate::constants::{
    RECORD_AE_ANSWERS_PER_WINDOW, RECORD_AE_ASKS_PER_FROM_PER_WINDOW, RECORD_AE_BUCKET_SPLIT,
    RECORD_AE_MAX_LEGS_PER_ANSWER, RECORD_AE_MAX_PREFIXES_PER_ASK, RECORD_AE_REPLY_TTL_SECS,
    RECORD_AE_WINDOW_SECS,
};
use crate::types::{ForkLeg, NodeId, StateId, TxHash};
use crate::vbc_directory::{AeBudget, AeGuard, AeRefusal};

/// `LeafKey.kind` of a SEND leg.
pub const LEAF_KIND_SEND: u8 = 0;
/// `LeafKey.kind` of a REDEEM leg (send and redeem legs share the fork index).
pub const LEAF_KIND_REDEEM: u8 = 1;
/// Nibbles in a leaf key: 32 + 32 + 1 bytes.
pub const LEAF_KEY_NIBBLES: usize = 130;
/// The hash of an empty subtree.
pub const EMPTY_HASH: [u8; 32] = [0u8; 32];

/// R59 — the kind byte of a record-AE ASK inside `crypto::ae_sign_payload`
/// (1 / 2 are the directory's `DIRECTORY_AE_KIND_{HAVE,ENTRIES}`).
pub const RECORD_AE_KIND_ASK: u8 = 3;
/// R59 — the kind byte of a record-AE ANSWER.
pub const RECORD_AE_KIND_ANSWER: u8 = 4;

// ── Keys and prefixes ────────────────────────────────────────────────────────

/// One leaf of the record trie — see the module doc. Ordered by bytes
/// (`fork_key`, `txid`, `kind`), which IS the trie's nibble order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LeafKey {
    /// `BLAKE3("AXIOM_RECORD_AE_FORK_KEY" ‖ pk ‖ consumed)` — the leg's
    /// `(pk, consumed)` fork key, hashed (a domain tag added to R58's
    /// `BLAKE3(pk‖consumed)`: the value is local ordering, never signed).
    pub fork_key: [u8; 32],
    /// The leg's txid (a redeem's: the CHEQUE txid it registers under).
    pub txid: TxHash,
    /// [`LEAF_KIND_SEND`] / [`LEAF_KIND_REDEEM`].
    pub kind: u8,
}

impl LeafKey {
    /// The ONE builder of the hashed fork key.
    pub fn fork_key_of(pk: &[u8; 32], consumed: &StateId) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_RECORD_AE_FORK_KEY");
        h.update(pk);
        h.update(consumed);
        *h.finalize().as_bytes()
    }

    /// The ONE builder of a leg's leaf key (from the leg's preimage key — so
    /// call it on a VERIFIED leg when the answer matters; on an unverified
    /// one it only says what the leg CLAIMS to be).
    pub fn of(leg: &ForkLeg) -> LeafKey {
        let (pk, consumed) = leg.key();
        LeafKey {
            fork_key: Self::fork_key_of(&pk, &consumed),
            txid: leg.tx_hash,
            kind: match leg.kind() {
                axiom_core_logic::types::LegKind::Send => LEAF_KIND_SEND,
                axiom_core_logic::types::LegKind::Redeem => LEAF_KIND_REDEEM,
            },
        }
    }

    fn byte(&self, i: usize) -> u8 {
        if i < 32 {
            self.fork_key[i]
        } else if i < 64 {
            self.txid[i - 32]
        } else {
            self.kind
        }
    }

    /// Nibble `i` (high nibble of each byte first), `i < LEAF_KEY_NIBBLES`.
    pub fn nibble(&self, i: usize) -> u8 {
        let b = self.byte(i / 2);
        if i % 2 == 0 { b >> 4 } else { b & 0x0f }
    }

    pub fn has_prefix(&self, p: &Prefix) -> bool {
        p.0.iter().enumerate().all(|(i, n)| self.nibble(i) == *n)
    }

    /// The leaf hash — the KEY only (never witnesses, first_seen, contested).
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_RECORD_TRIE_LEAF");
        h.update(&self.fork_key);
        h.update(&self.txid);
        h.update(&[self.kind]);
        *h.finalize().as_bytes()
    }
}

/// A trie position: a nibble path from the root (each nibble < 16, at most
/// `LEAF_KEY_NIBBLES` long). Unverified on the wire — [`Prefix::is_valid`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Prefix(pub Vec<u8>);

impl Prefix {
    pub fn root() -> Prefix {
        Prefix(Vec::new())
    }
    pub fn child(&self, nibble: u8) -> Prefix {
        let mut v = self.0.clone();
        v.push(nibble);
        Prefix(v)
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn is_valid(&self) -> bool {
        self.0.len() <= LEAF_KEY_NIBBLES && self.0.iter().all(|n| *n < 16)
    }
}

// ── Node hashes (ONE builder each) ───────────────────────────────────────────

/// A bucket's hash over its SORTED keys; `EMPTY_HASH` for none.
pub fn bucket_hash(sorted_keys: &[LeafKey]) -> [u8; 32] {
    if sorted_keys.is_empty() {
        return EMPTY_HASH;
    }
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_RECORD_TRIE_BUCKET");
    for k in sorted_keys {
        h.update(&k.leaf_hash());
    }
    *h.finalize().as_bytes()
}

/// An internal node's hash over its 16 child hashes (`EMPTY_HASH` = no child).
pub fn internal_hash(children: &[[u8; 32]; 16]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_RECORD_TRIE_NODE");
    for c in children {
        h.update(c);
    }
    *h.finalize().as_bytes()
}

/// The canonical hash of a key SET at `depth` (the shape rule: bucket iff
/// ≤ split). Used where the local trie holds the keys in a shallower bucket.
fn canonical_hash(sorted_keys: &[LeafKey], depth: usize) -> [u8; 32] {
    if sorted_keys.len() <= RECORD_AE_BUCKET_SPLIT || depth >= LEAF_KEY_NIBBLES {
        return bucket_hash(sorted_keys);
    }
    let mut children = [EMPTY_HASH; 16];
    for (i, c) in children.iter_mut().enumerate() {
        let group: Vec<LeafKey> = sorted_keys.iter().copied().filter(|k| k.nibble(depth) == i as u8).collect();
        *c = canonical_hash(&group, depth + 1);
    }
    internal_hash(&children)
}

// ── The trie ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum TNode {
    Bucket { keys: Vec<LeafKey>, hash: [u8; 32] },
    Internal { children: Box<[Option<Box<TNode>>; 16]>, count: usize, hash: [u8; 32] },
}

impl TNode {
    fn empty() -> TNode {
        TNode::Bucket { keys: Vec::new(), hash: EMPTY_HASH }
    }

    fn hash(&self) -> [u8; 32] {
        match self {
            TNode::Bucket { hash, .. } | TNode::Internal { hash, .. } => *hash,
        }
    }

    fn count(&self) -> usize {
        match self {
            TNode::Bucket { keys, .. } => keys.len(),
            TNode::Internal { count, .. } => *count,
        }
    }

    /// Build the canonical node for `sorted_keys` at `depth`.
    fn build(sorted_keys: Vec<LeafKey>, depth: usize) -> TNode {
        if sorted_keys.len() <= RECORD_AE_BUCKET_SPLIT || depth >= LEAF_KEY_NIBBLES {
            let hash = bucket_hash(&sorted_keys);
            return TNode::Bucket { keys: sorted_keys, hash };
        }
        let count = sorted_keys.len();
        let mut groups: [Vec<LeafKey>; 16] = Default::default();
        for k in sorted_keys {
            groups[k.nibble(depth) as usize].push(k);
        }
        let mut children: Box<[Option<Box<TNode>>; 16]> = Box::default();
        for (i, g) in groups.into_iter().enumerate() {
            if !g.is_empty() {
                children[i] = Some(Box::new(TNode::build(g, depth + 1)));
            }
        }
        let hash = internal_hash(&child_hashes(&children));
        TNode::Internal { children, count, hash }
    }

    fn insert(&mut self, key: LeafKey, depth: usize) -> bool {
        match self {
            TNode::Bucket { keys, hash } => {
                let Err(pos) = keys.binary_search(&key) else { return false };
                keys.insert(pos, key);
                if keys.len() > RECORD_AE_BUCKET_SPLIT && depth < LEAF_KEY_NIBBLES {
                    *self = TNode::build(std::mem::take(keys), depth);
                } else {
                    *hash = bucket_hash(keys);
                }
                true
            }
            TNode::Internal { children, count, hash } => {
                let slot = &mut children[key.nibble(depth) as usize];
                let child = slot.get_or_insert_with(|| Box::new(TNode::empty()));
                if !child.insert(key, depth + 1) {
                    return false;
                }
                *count += 1;
                *hash = internal_hash(&child_hashes(children));
                true
            }
        }
    }

    fn depth(&self) -> usize {
        match self {
            TNode::Bucket { .. } => 1,
            TNode::Internal { children, .. } => {
                1 + children.iter().flatten().map(|c| c.depth()).max().unwrap_or(0)
            }
        }
    }
}

fn child_hashes(children: &[Option<Box<TNode>>; 16]) -> [[u8; 32]; 16] {
    let mut out = [EMPTY_HASH; 16];
    for (i, c) in children.iter().enumerate() {
        if let Some(c) = c {
            out[i] = c.hash();
        }
    }
    out
}

/// Where a prefix lands in a trie.
enum Located<'a> {
    /// A node sits exactly at the prefix.
    Node(&'a TNode),
    /// The prefix lies inside a shallower bucket: these are its keys under it.
    InBucket(Vec<LeafKey>),
    /// Nothing is stored under the prefix.
    Nothing,
}

/// The R48 record trie — see the module doc. Owned by `NablaNode`
/// (`record_trie`), fed ONLY with graded legs, rebuilt at `open`.
#[derive(Debug, Clone)]
pub struct RecordTrie {
    root: TNode,
}

impl Default for RecordTrie {
    fn default() -> Self {
        RecordTrie { root: TNode::empty() }
    }
}

impl RecordTrie {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a leaf; `false` if already present (insert-only, idempotent).
    pub fn insert(&mut self, key: LeafKey) -> bool {
        self.root.insert(key, 0)
    }

    /// The root hash (`EMPTY_HASH` for an empty trie).
    pub fn root(&self) -> [u8; 32] {
        self.root.hash()
    }

    /// Leaves held (`/status record_trie_leaves`).
    pub fn len(&self) -> usize {
        self.root.count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Node levels on the longest root-to-bucket path (the root counts 1).
    /// A descent to one divergent leaf asks at most `depth()` levels plus one
    /// `Ask::Legs`.
    pub fn depth(&self) -> usize {
        self.root.depth()
    }

    fn locate(&self, p: &Prefix) -> Located<'_> {
        let mut node = &self.root;
        let mut d = 0usize;
        loop {
            if d == p.len() {
                return Located::Node(node);
            }
            match node {
                TNode::Bucket { keys, .. } => {
                    return Located::InBucket(keys.iter().copied().filter(|k| k.has_prefix(p)).collect());
                }
                TNode::Internal { children, .. } => match &children[p.0[d] as usize] {
                    Some(c) => {
                        node = c;
                        d += 1;
                    }
                    None => return Located::Nothing,
                },
            }
        }
    }

    pub fn contains(&self, key: &LeafKey) -> bool {
        let mut node = &self.root;
        let mut d = 0usize;
        loop {
            match node {
                TNode::Bucket { keys, .. } => return keys.binary_search(key).is_ok(),
                TNode::Internal { children, .. } => match &children[key.nibble(d) as usize] {
                    Some(c) => {
                        node = c;
                        d += 1;
                    }
                    None => return false,
                },
            }
        }
    }

    /// The canonical hash of THIS node's leaves under `p` — equal to a peer's
    /// node hash at `p` iff both hold the same leaves there.
    pub fn subtree_hash(&self, p: &Prefix) -> [u8; 32] {
        match self.locate(p) {
            Located::Node(n) => n.hash(),
            Located::InBucket(keys) => canonical_hash(&keys, p.len()),
            Located::Nothing => EMPTY_HASH,
        }
    }

    /// The responder's view of each prefix (the body of `Answer::Nodes`).
    pub fn views(&self, prefixes: &[Prefix]) -> Vec<NodeView> {
        prefixes.iter().map(|p| self.view(p)).collect()
    }

    pub fn view(&self, p: &Prefix) -> NodeView {
        let body = match self.locate(p) {
            Located::Node(TNode::Bucket { keys, .. }) if keys.is_empty() => ViewBody::Empty,
            Located::Node(TNode::Bucket { keys, .. }) => ViewBody::Bucket(keys.clone()),
            Located::Node(TNode::Internal { children, .. }) => ViewBody::Internal(child_hashes(children).to_vec()),
            Located::InBucket(keys) if keys.is_empty() => ViewBody::Empty,
            Located::InBucket(keys) => ViewBody::Bucket(keys),
            Located::Nothing => ViewBody::Empty,
        };
        NodeView { prefix: p.clone(), body }
    }
}

// ── Wire types ───────────────────────────────────────────────────────────────

/// What a responder shows of one trie position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViewBody {
    /// Nothing stored under the prefix.
    Empty,
    /// An internal node: its 16 child hashes (`EMPTY_HASH` = no child).
    Internal(Vec<[u8; 32]>),
    /// A bucket (≤ `RECORD_AE_BUCKET_SPLIT` keys, sorted, all under the prefix).
    Bucket(Vec<LeafKey>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeView {
    pub prefix: Prefix,
    pub body: ViewBody,
}

impl NodeView {
    /// Structural validity (the asker checks it before using a view): a valid
    /// prefix; 16 children; a bucket's keys sorted, unique, under the prefix
    /// and within the split.
    pub fn is_well_formed(&self) -> bool {
        if !self.prefix.is_valid() {
            return false;
        }
        match &self.body {
            ViewBody::Empty => true,
            ViewBody::Internal(c) => c.len() == 16 && self.prefix.len() < LEAF_KEY_NIBBLES,
            ViewBody::Bucket(keys) => {
                !keys.is_empty()
                    && keys.len() <= RECORD_AE_BUCKET_SPLIT
                    && keys.windows(2).all(|w| w[0] < w[1])
                    && keys.iter().all(|k| k.has_prefix(&self.prefix))
            }
        }
    }

    /// The node hash this view commits to (well-formed views only).
    pub fn hash(&self) -> [u8; 32] {
        match &self.body {
            ViewBody::Empty => EMPTY_HASH,
            ViewBody::Internal(c) => {
                let mut a = [EMPTY_HASH; 16];
                for (i, h) in c.iter().take(16).enumerate() {
                    a[i] = *h;
                }
                internal_hash(&a)
            }
            ViewBody::Bucket(keys) => bucket_hash(keys),
        }
    }
}

/// `WireMessage::RecordAeAsk` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ask {
    /// "Show me these trie positions" (≤ `RECORD_AE_MAX_PREFIXES_PER_ASK`).
    Nodes(Vec<Prefix>),
    /// "Send me these legs" (≤ `RECORD_AE_MAX_LEGS_PER_ANSWER`).
    Legs(Vec<LeafKey>),
}

/// `WireMessage::RecordAeAnswer` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Answer {
    Nodes(Vec<NodeView>),
    Legs(Vec<ForkLeg>),
}

/// The digest an ask is signed over (R59: kind, from, nonce, body-hash).
pub fn ask_body_hash(ask: &Ask) -> [u8; 32] {
    *blake3::hash(&bincode::serialize(ask).unwrap_or_default()).as_bytes()
}

/// The digest an answer is signed over.
pub fn answer_body_hash(answer: &Answer) -> [u8; 32] {
    *blake3::hash(&bincode::serialize(answer).unwrap_or_default()).as_bytes()
}

/// Is an ask within its bounds and well-formed? `Err(Oversize)` over a
/// count bound, `Err(Malformed)` for an invalid prefix or an empty ask.
pub fn check_ask(ask: &Ask) -> Result<(), AeRefusal> {
    match ask {
        Ask::Nodes(p) if p.len() > RECORD_AE_MAX_PREFIXES_PER_ASK => Err(AeRefusal::Oversize),
        Ask::Legs(k) if k.len() > RECORD_AE_MAX_LEGS_PER_ANSWER => Err(AeRefusal::Oversize),
        Ask::Nodes(p) if p.is_empty() || !p.iter().all(Prefix::is_valid) => Err(AeRefusal::Malformed),
        Ask::Legs(k) if k.is_empty() => Err(AeRefusal::Malformed),
        _ => Ok(()),
    }
}

/// Is an answer within its count bounds?
pub fn check_answer(answer: &Answer) -> Result<(), AeRefusal> {
    match answer {
        Answer::Nodes(v) if v.len() > RECORD_AE_MAX_PREFIXES_PER_ASK => Err(AeRefusal::Oversize),
        Answer::Legs(l) if l.len() > RECORD_AE_MAX_LEGS_PER_ANSWER => Err(AeRefusal::Oversize),
        _ => Ok(()),
    }
}

/// Take items while the running serialized size stays within `max_bytes`,
/// always at least one (a page carries ≥ 1 item; the asker re-asks the rest).
pub fn take_within_bytes<T: Serialize>(items: Vec<T>, max_bytes: u64) -> Vec<T> {
    let mut used = 0u64;
    let mut out = Vec::new();
    for it in items {
        let sz = bincode::serialized_size(&it).unwrap_or(u64::MAX);
        if !out.is_empty() && used.saturating_add(sz) > max_bytes {
            break;
        }
        used = used.saturating_add(sz);
        out.push(it);
    }
    out
}

// ── Salted order ─────────────────────────────────────────────────────────────

fn salted_rank(salt: &[u8; 32], seq: u64, item: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_RECORD_AE_ORDER");
    h.update(salt);
    h.update(&seq.to_le_bytes());
    h.update(item);
    *h.finalize().as_bytes()
}

/// Keep at most `cap` items in the salted order; `true` if any were cut.
fn salted_cap<T, F: Fn(&T) -> Vec<u8>>(items: &mut Vec<T>, cap: usize, salt: &[u8; 32], seq: u64, bytes: F) -> bool {
    if items.len() <= cap {
        return false;
    }
    items.sort_by_cached_key(|it| salted_rank(salt, seq, &bytes(it)));
    items.truncate(cap);
    true
}

fn key_bytes(k: &LeafKey) -> Vec<u8> {
    let mut v = Vec::with_capacity(65);
    v.extend_from_slice(&k.fork_key);
    v.extend_from_slice(&k.txid);
    v.push(k.kind);
    v
}

// ── The receiver's descent ───────────────────────────────────────────────────

/// The ask a descent has in flight (one per peer).
#[derive(Debug, Clone)]
pub struct InFlight {
    pub nonce: u64,
    pub ask: Ask,
    pub sent_secs: u64,
}

/// How a descent ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescentEnd {
    /// Walked to the leaves with nothing cut.
    Completed,
    /// Walked to the end of its budget; something was left for the next one.
    Truncated,
    /// Timed out, no progress, or refused.
    Aborted,
}

/// The receiver-driven descent against ONE peer — see the module doc.
#[derive(Debug, Clone)]
pub struct Descent {
    seq: u64,
    /// This level's prefixes not yet answered.
    frontier: VecDeque<Prefix>,
    /// The next level's prefixes (capped at the level transition).
    next_level: Vec<Prefix>,
    /// Leaf keys to fetch.
    want: VecDeque<LeafKey>,
    wanted: HashSet<LeafKey>,
    in_flight: Option<InFlight>,
    truncated: bool,
    asks: u32,
}

impl Descent {
    /// A fresh descent from the root. `seq` rotates the salted order.
    pub fn new(seq: u64) -> Descent {
        let mut frontier = VecDeque::new();
        frontier.push_back(Prefix::root());
        Descent {
            seq,
            frontier,
            next_level: Vec::new(),
            want: VecDeque::new(),
            wanted: HashSet::new(),
            in_flight: None,
            truncated: false,
            asks: 0,
        }
    }

    /// Asks sent so far.
    pub fn asks(&self) -> u32 {
        self.asks
    }

    pub fn in_flight(&self) -> Option<&InFlight> {
        self.in_flight.as_ref()
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The next ask, or `None` when the descent is finished. Legs first (what
    /// the last level found), then the current level, then the next level
    /// (capped at `RECORD_AE_MAX_PREFIXES_PER_ASK` in the salted order —
    /// the per-level budget).
    pub fn next_ask(&mut self, salt: &[u8; 32]) -> Option<Ask> {
        if !self.want.is_empty() {
            let n = self.want.len().min(RECORD_AE_MAX_LEGS_PER_ANSWER);
            return Some(Ask::Legs(self.want.drain(..n).collect()));
        }
        if self.frontier.is_empty() && !self.next_level.is_empty() {
            let mut level = std::mem::take(&mut self.next_level);
            level.sort();
            level.dedup();
            if salted_cap(&mut level, RECORD_AE_MAX_PREFIXES_PER_ASK, salt, self.seq, |p| p.0.clone()) {
                self.truncated = true;
            }
            self.frontier = level.into();
        }
        if !self.frontier.is_empty() {
            let n = self.frontier.len().min(RECORD_AE_MAX_PREFIXES_PER_ASK);
            return Some(Ask::Nodes(self.frontier.drain(..n).collect()));
        }
        None
    }

    pub fn set_in_flight(&mut self, nonce: u64, ask: Ask, now_secs: u64) {
        self.asks += 1;
        self.in_flight = Some(InFlight { nonce, ask, sent_secs: now_secs });
    }

    /// Take the in-flight ask iff `nonce` answers it.
    pub fn take_in_flight(&mut self, nonce: u64) -> Option<Ask> {
        match &self.in_flight {
            Some(f) if f.nonce == nonce => self.in_flight.take().map(|f| f.ask),
            _ => None,
        }
    }

    /// Has the in-flight ask outlived the reply TTL?
    pub fn expired(&self, now_secs: u64) -> bool {
        self.in_flight
            .as_ref()
            .is_some_and(|f| now_secs.saturating_sub(f.sent_secs) > RECORD_AE_REPLY_TTL_SECS)
    }

    /// Process an `Answer::Nodes` to `asked` against the LOCAL trie. Returns
    /// whether anything asked was answered (no progress ⇒ the caller aborts).
    /// Views for prefixes not asked are ignored (the caller counted them);
    /// asked prefixes left unanswered (the responder's byte bound) are
    /// re-queued at the front — resume.
    pub fn on_nodes(&mut self, asked: &[Prefix], views: &[NodeView], local: &RecordTrie, salt: &[u8; 32]) -> bool {
        let mut answered: HashSet<&Prefix> = HashSet::new();
        let asked_set: HashSet<&Prefix> = asked.iter().collect();
        let mut found: Vec<LeafKey> = Vec::new();
        for v in views {
            if !asked_set.contains(&v.prefix) || !answered.insert(&v.prefix) {
                continue;
            }
            if v.hash() == local.subtree_hash(&v.prefix) {
                continue;
            }
            match &v.body {
                ViewBody::Empty => {}
                ViewBody::Internal(children) => {
                    for (i, ch) in children.iter().enumerate().take(16) {
                        let cp = v.prefix.child(i as u8);
                        if *ch != EMPTY_HASH && *ch != local.subtree_hash(&cp) {
                            self.next_level.push(cp);
                        }
                    }
                }
                ViewBody::Bucket(keys) => {
                    for k in keys {
                        if !local.contains(k) && !self.wanted.contains(k) {
                            found.push(*k);
                        }
                    }
                }
            }
        }
        let room = RECORD_AE_MAX_PREFIXES_PER_ASK.saturating_sub(self.wanted.len());
        if salted_cap(&mut found, room, salt, self.seq, key_bytes) {
            self.truncated = true;
        }
        for k in found {
            if self.wanted.insert(k) {
                self.want.push_back(k);
            }
        }
        for p in asked.iter().rev() {
            if !answered.contains(p) {
                self.frontier.push_front(p.clone());
            }
        }
        !answered.is_empty()
    }

    /// Process an `Answer::Legs` to `asked`: `received` = the asked keys the
    /// answer carried (whatever the verification then said). Asked keys not
    /// carried are re-queued (resume). Returns whether anything asked came.
    pub fn on_legs(&mut self, asked: &[LeafKey], received: &HashSet<LeafKey>) -> bool {
        let mut progress = false;
        for k in asked.iter().rev() {
            if received.contains(k) {
                progress = true;
            } else {
                self.want.push_front(*k);
            }
        }
        progress
    }

    /// Nothing left to ask and nothing in flight.
    pub fn is_done(&self) -> bool {
        self.in_flight.is_none() && self.want.is_empty() && self.frontier.is_empty() && self.next_level.is_empty()
    }
}

// ── The R51 walk ─────────────────────────────────────────────────────────────

/// The per-boot walk over peers — inserted/deleted IN PLACE, never redrawn.
#[derive(Debug, Clone, Default)]
pub struct Walk {
    order: Vec<NodeId>,
    cursor: usize,
}

impl Walk {
    /// Make the walk hold exactly `peers`: gone peers are deleted in place,
    /// new ones inserted at their salted position (no cap — churn is routine).
    pub fn sync(&mut self, peers: &[NodeId], salt: &[u8; 32]) {
        let live: HashSet<&NodeId> = peers.iter().collect();
        let mut i = 0;
        while i < self.order.len() {
            if live.contains(&self.order[i]) {
                i += 1;
            } else {
                self.order.remove(i);
                if i < self.cursor {
                    self.cursor -= 1;
                }
            }
        }
        let rank = |id: &NodeId| salted_rank(salt, 0, id);
        for p in peers {
            if self.order.contains(p) {
                continue;
            }
            let r = rank(p);
            let pos = self.order.partition_point(|q| rank(q) < r);
            self.order.insert(pos, *p);
            if pos < self.cursor {
                self.cursor += 1;
            }
        }
        if self.cursor >= self.order.len() {
            self.cursor = 0;
        }
    }

    /// The next peer in the walk (wrapping), `None` with no peers.
    pub fn next(&mut self) -> Option<NodeId> {
        if self.order.is_empty() {
            return None;
        }
        let id = self.order[self.cursor % self.order.len()];
        self.cursor = (self.cursor + 1) % self.order.len();
        Some(id)
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// Fable review 2026-10-01 F-5 (owner ruling: "as long as genesis node do not
/// need to be online.. then the design was right") — the R51 walk, made
/// non-dilutable by Sybil citizen peers. One WALK WINDOW = every connected
/// peer whose verified NBC names a PINNED genesis Nabla key (`first`, in its
/// own salted in-place order) once, then ONE citizen from the citizen
/// round-robin (`rest`). With `g` genesis peers connected, every genesis peer
/// is walked once per `g + 1` ticks whatever the number `d` of citizens
/// (before: once per `g + d` — `d` free citizen NBCs stretched the
/// pair-meeting time of the record-AE synchrony premise to `d` ticks).
///
/// The hard conditions (each a test):
/// - (a) the `first` set is chosen by the caller from the PINNED public keys
///   only (`cc::nbc_is_pinned_genesis` over `NABLA_GENESIS_VALIDATOR_PKS`) —
///   no config, no address, no node id list;
/// - (b) with ZERO genesis peers connected `next` is EXACTLY the old [`Walk`]
///   over `rest` — no wait, no failure, no skipped tick (genesis nodes need
///   not be online);
/// - (c) it is an ORDER only: nothing here (nor any caller) feeds "is
///   genesis" into a verdict, a ban, a vouch, a grade or an answer's
///   acceptance — an answer from a genesis peer runs the same
///   `record_ae_accept_answer` → `prepare_answer` → grade as any other.
#[derive(Debug, Clone, Default)]
pub struct TieredWalk {
    first: Walk,
    rest: Walk,
    /// `first` visits taken in the current window.
    taken: usize,
}

impl TieredWalk {
    /// Make the two walks hold exactly `first` / `rest` (each in place,
    /// [`Walk::sync`]). The caller partitions; a peer in both is walked as
    /// `first` only.
    pub fn sync(&mut self, first: &[NodeId], rest: &[NodeId], salt: &[u8; 32]) {
        let firsts: HashSet<&NodeId> = first.iter().collect();
        let rest: Vec<NodeId> = rest.iter().filter(|p| !firsts.contains(p)).copied().collect();
        self.first.sync(first, salt);
        self.rest.sync(&rest, salt);
    }

    /// The next peer: the window's remaining genesis peers, then one citizen.
    /// `first` empty ⇒ `rest.next()` and nothing else (condition b).
    pub fn next(&mut self) -> Option<NodeId> {
        if self.taken < self.first.len() {
            self.taken += 1;
            return self.first.next();
        }
        self.taken = 0;
        match self.rest.next() {
            Some(p) => Some(p),
            // No citizen: the window is genesis-only (still one per tick).
            None if !self.first.is_empty() => {
                self.taken = 1;
                self.first.next()
            }
            None => None,
        }
    }

    pub fn len(&self) -> usize {
        self.first.len() + self.rest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.first.is_empty() && self.rest.is_empty()
    }
}

// ── Session + counters ───────────────────────────────────────────────────────

/// `/status` counters of record-AE (RULE 3 §2: every refusal counted, "0"
/// distinguishable from "never ran"). Cumulative since start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordAeCounters {
    pub asks_sent: u64,
    pub answers_sent: u64,
    pub refused_unknown_sender: u64,
    pub refused_bad_signature: u64,
    pub refused_replayed_nonce: u64,
    pub refused_over_budget: u64,
    pub refused_unsolicited: u64,
    pub refused_oversize: u64,
    pub refused_malformed: u64,
    pub shed_global: u64,
    pub descents_completed: u64,
    pub descents_aborted: u64,
    pub descents_truncated: u64,
    pub legs_received: u64,
    pub legs_refused: u64,
    pub legs_recorded: u64,
    pub legs_ungraded: u64,
    pub legs_unrequested: u64,
}

impl RecordAeCounters {
    /// Count one refusal by kind and log it.
    pub fn refuse(&mut self, r: AeRefusal, from: &NodeId, what: &str) {
        let c = match r {
            AeRefusal::UnknownSender => &mut self.refused_unknown_sender,
            AeRefusal::BadSignature => &mut self.refused_bad_signature,
            AeRefusal::ReplayedNonce => &mut self.refused_replayed_nonce,
            AeRefusal::OverBudget => &mut self.refused_over_budget,
            AeRefusal::Unsolicited => &mut self.refused_unsolicited,
            AeRefusal::Oversize => &mut self.refused_oversize,
            AeRefusal::Malformed => &mut self.refused_malformed,
        };
        *c = c.saturating_add(1);
        log::warn!("[RECORD-AE] refused {} {:?} from {} (counted record_ae_refused)", what, r, hex::encode(&from[..8]));
    }

    /// Every refusal, all kinds (`/status record_ae_refused`).
    pub fn refused_total(&self) -> u64 {
        self.refused_unknown_sender
            + self.refused_bad_signature
            + self.refused_replayed_nonce
            + self.refused_over_budget
            + self.refused_unsolicited
            + self.refused_oversize
            + self.refused_malformed
    }
}

/// The R50 budget of the record-AE guard (registers in `protocol_nabla.toml`).
pub const RECORD_AE_BUDGET: AeBudget = AeBudget {
    requests_per_from_per_window: RECORD_AE_ASKS_PER_FROM_PER_WINDOW,
    window_secs: RECORD_AE_WINDOW_SECS,
    reply_ttl_secs: RECORD_AE_REPLY_TTL_SECS,
    seen_nonces_per_from: 256,
};

/// Per-node record-AE state. Owned by `NablaNode` (`record_ae`); every
/// transition runs under the node lock through `NablaNode::record_ae_*`
/// (pure CPU, bounded — nothing blocks).
#[derive(Debug)]
pub struct RecordAeSession {
    pub(crate) guard: AeGuard,
    pub(crate) descents: HashMap<NodeId, Descent>,
    pub(crate) walk: TieredWalk,
    /// Per-boot secret for the salted orders (child order, want cap, walk).
    pub(crate) salt: [u8; 32],
    pub(crate) descent_seq: u64,
    /// (window start, answers sent in it) — the global cap.
    global: (u64, u64),
    pub counters: RecordAeCounters,
}

impl Default for RecordAeSession {
    fn default() -> Self {
        RecordAeSession {
            guard: AeGuard::new(RECORD_AE_BUDGET),
            descents: HashMap::new(),
            walk: TieredWalk::default(),
            salt: rand::random(),
            descent_seq: 0,
            global: (0, 0),
            counters: RecordAeCounters::default(),
        }
    }
}

impl RecordAeSession {
    /// R59 global cap — may this node send one more answer now?
    pub fn global_admit(&mut self, now_secs: u64) -> bool {
        let (start, count) = &mut self.global;
        if now_secs.saturating_sub(*start) >= RECORD_AE_WINDOW_SECS {
            *start = now_secs;
            *count = 0;
        }
        if *count >= RECORD_AE_ANSWERS_PER_WINDOW {
            return false;
        }
        *count += 1;
        true
    }

    /// End a descent, counting how.
    pub fn end(&mut self, peer: &NodeId, how: DescentEnd) {
        if self.descents.remove(peer).is_none() {
            return;
        }
        let c = &mut self.counters;
        match how {
            DescentEnd::Completed => c.descents_completed += 1,
            DescentEnd::Truncated => c.descents_truncated += 1,
            DescentEnd::Aborted => c.descents_aborted += 1,
        }
    }

    /// Is a descent with `peer` open (at most one per peer)?
    pub fn has_descent(&self, peer: &NodeId) -> bool {
        self.descents.contains_key(peer)
    }
}

// ── Accepting an answer: authenticated under the lock, prepared off it ─────

/// An answer that passed authentication and matched the in-flight ask of
/// the descent with `from` (`NablaNode::record_ae_accept_answer`). The ask is
/// TAKEN out of the descent: the answer cannot be replayed.
#[derive(Debug, Clone)]
pub struct AcceptedAnswer {
    pub from: NodeId,
    pub nonce: u64,
    pub asked: Ask,
}

/// What `prepare_answer` produced OFF the node lock.
#[derive(Debug)]
pub enum Prepared {
    /// Views for asked prefixes, well-formed (the rest counted `malformed`).
    Nodes { asked: Vec<Prefix>, views: Vec<NodeView> },
    /// Asked legs, verified. `received` = the asked keys the answer carried
    /// (verified or not — the resume set); `refused` = asked legs that failed
    /// `verify_fork_leg`; `unrequested` = legs not asked, refused unverified.
    Legs { asked: Vec<LeafKey>, received: HashSet<LeafKey>, verified: Vec<VerifiedForkLeg>, refused: u64, unrequested: u64 },
}

#[derive(Debug)]
pub struct PreparedAnswer {
    pub from: NodeId,
    pub nonce: u64,
    pub body: Prepared,
    /// Views / legs that did not match the ask kind or were not well-formed.
    pub malformed: u64,
}

/// The OFF-LOCK half (the `prelock_ae_fork_bans` shape): check every item
/// against what was ASKED — a leg whose claimed key was not asked is
/// refused WITHOUT verification (counted `unrequested`) — and verify the
/// asked legs with `ban::verify_fork_leg` (≈178 µs each, §9b R36). Pure.
pub fn prepare_answer(accepted: AcceptedAnswer, answer: Answer) -> PreparedAnswer {
    let AcceptedAnswer { from, nonce, asked } = accepted;
    match (asked, answer) {
        (Ask::Nodes(asked), Answer::Nodes(views)) => {
            let total = views.len() as u64;
            let views: Vec<NodeView> = views.into_iter().filter(NodeView::is_well_formed).collect();
            let malformed = total - views.len() as u64;
            PreparedAnswer { from, nonce, body: Prepared::Nodes { asked, views }, malformed }
        }
        (Ask::Legs(asked), Answer::Legs(legs)) => {
            let asked_set: HashSet<LeafKey> = asked.iter().copied().collect();
            let mut received = HashSet::new();
            let mut verified = Vec::new();
            let (mut refused, mut unrequested) = (0u64, 0u64);
            for leg in legs {
                let k = LeafKey::of(&leg);
                if !asked_set.contains(&k) || !received.insert(k) {
                    unrequested += 1;
                    continue;
                }
                match crate::ban::verify_fork_leg(leg) {
                    Ok(v) if LeafKey::of(v.leg()) == k => verified.push(v),
                    _ => refused += 1,
                }
            }
            PreparedAnswer { from, nonce, body: Prepared::Legs { asked, received, verified, refused, unrequested }, malformed: 0 }
        }
        // An answer of the wrong kind answers nothing asked.
        (Ask::Nodes(asked), Answer::Legs(l)) => PreparedAnswer {
            from, nonce, body: Prepared::Nodes { asked, views: Vec::new() }, malformed: l.len().max(1) as u64,
        },
        (Ask::Legs(asked), Answer::Nodes(v)) => PreparedAnswer {
            from, nonce,
            body: Prepared::Legs { asked, received: HashSet::new(), verified: Vec::new(), refused: 0, unrequested: 0 },
            malformed: v.len().max(1) as u64,
        },
    }
}

// ── Tests (the pure trie / descent) ──────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: u32) -> LeafKey {
        let fk = LeafKey::fork_key_of(&[(i % 251) as u8; 32], &blake3::hash(&i.to_le_bytes()).into());
        LeafKey { fork_key: fk, txid: *blake3::hash(&(i ^ 0xdead).to_le_bytes()).as_bytes(), kind: (i % 2) as u8 }
    }

    /// R58 — the root is a pure function of the leaf SET: any insert order
    /// gives one root, re-inserting changes nothing, and the leaf hash covers
    /// the KEY only (the trie holds no per-node metadata at all — the
    /// node-level half of this property, "first_seen / contested / witness
    /// subset never reach the root", is `node::record_ae_tests::
    /// record_trie_root_independent_of_insert_order_and_metadata`).
    /// MUTATION (run 2026-09-30): make `TNode::insert` split only past
    /// `2 * SPLIT` while `TNode::build` keeps `<= SPLIT` (the shape then
    /// depends on history) ⇒ RED at "the live trie IS the canonical shape".
    /// (`>= SPLIT` in `insert` alone is NOT a mutation — `build` re-decides and
    /// yields the same bucket; run.)
    #[test]
    fn record_trie_root_is_a_function_of_the_leaf_set() {
        let keys: Vec<LeafKey> = (0..700).map(key).collect();
        let mut a = RecordTrie::new();
        for k in &keys {
            assert!(a.insert(*k));
        }
        let mut b = RecordTrie::new();
        for k in keys.iter().rev() {
            b.insert(*k);
        }
        let mut c = RecordTrie::new();
        for (i, k) in keys.iter().enumerate() {
            c.insert(keys[(i * 7919) % keys.len()]);
            c.insert(*k);
        }
        assert_eq!(a.root(), b.root());
        assert_eq!(a.root(), c.root());
        assert_eq!(a.len(), 700);
        assert!(!a.insert(keys[3]), "insert-only, idempotent");
        let mut all = keys.clone();
        all.sort();
        assert_eq!(a.root(), canonical_hash(&all, 0), "the live trie IS the canonical shape");
        assert!(a.depth() >= 2, "700 leaves split the root");
    }

    /// Where a local bucket is shallower than the prefix asked, the subtree
    /// hash is still the canonical one a peer with more leaves computes.
    #[test]
    fn subtree_hash_agrees_across_shapes() {
        let keys: Vec<LeafKey> = (0..200).map(key).collect();
        let mut big = RecordTrie::new();
        for k in &keys {
            big.insert(*k);
        }
        for i in 0..16u8 {
            let p = Prefix::root().child(i);
            let mut small = RecordTrie::new();
            for k in keys.iter().filter(|k| k.has_prefix(&p)) {
                small.insert(*k);
            }
            assert_eq!(small.subtree_hash(&p), big.subtree_hash(&p), "child {i}");
            assert_eq!(big.view(&p).hash(), big.subtree_hash(&p));
        }
    }
}
