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
// KI#173 — the Query reply and its parts are UMP types (moved unchanged; wire bytes identical).
pub use axiom_core_logic::nabla_wire::{GroupMemberState, MerkleProof, NablaResponse, WalletStatus};

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
    DeedTransaction, K3Receipt, K3WitnessSig as WitnessSig, LegPreimage, Registration,
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
    /// FOB (Fixed Outflow Balance) per-validator Fee pool, keyed by
    /// `(validator_id, is_dev)` (`AXIOM_DESIGN_BoundedPools.md` §7/§10.2a). A
    /// PER-VALIDATOR FAMILY reconciled through the same PoolSync machinery with
    /// one new arm (§7). The `is_dev` bit is the ONLY thing separating the dev
    /// fund from the real fund — same codepath, class as data (§10.2a). Two-state
    /// (EMPTY|FULL). Appended LAST to keep the singletons' `sign_tag`/serde
    /// stable. Persists via the single `fob_pools.cbor` list, NOT a `.state`.
    BoundedFee([u8; 32], bool),
    /// Tier-3 (Community) validator-join subsidy — 200,000 AXC, 400 slots at
    /// the 500 AXC floor (`AXIOM_DESIGN_ValidatorJoin.md` §2).
    ///
    /// DRAIN-ONLY, same convergence as `Airdrop` (monotonic decrease, max-claims
    /// wins) — NOT the monotonic-INCREASE shape `Deed`/`DevDeed` use. Exhaustion
    /// removes the subsidy, never permission: candidates then self-fund at the
    /// same floor.
    ///
    /// Appended after `BoundedFee` so every existing discriminant, `sign_tag`
    /// and serde position is untouched.
    Bootstrap,
    /// Tier-2 (Foundation) validator-join subsidy — 2,500,000 AXC, 5 slots at
    /// the 500,000 AXC floor. Same drain-only shape as `Bootstrap`; separate
    /// kind so the two cannot cross-credit, exactly as `DevDeed` is separate
    /// from `Deed`.
    FoundationBootstrap,
    /// Contribution emission (`AXIOM_DESIGN_ValidatorEmission.md`): the same
    /// airdrop-pool gear, ONE instance per group so each has its own PoolSync
    /// claim count. Rolled per FOB epoch (share recomputed, DEED top-up).
    EmissionValidators,
    EmissionNabla,
}

impl PoolKind {
    /// GUIDE §5.6c lever 5 — the pool kinds the KI#42 serve-gate waits on:
    /// every SINGLETON pool, i.e. every kind the periodic heartbeat
    /// (`POOL_SYNC_HEARTBEAT_TICKS`, nabla_node.rs tick loop) broadcasts
    /// unconditionally. `BoundedFee(validator, class)` is an open-ended
    /// per-validator family that is synced only when such a pool exists, so
    /// "one PoolSync for every kind" cannot include it without wedging a mesh
    /// that has no registered validator pool shut — it is deliberately NOT
    /// here. A node that has seen an authenticated PoolSync for each of these
    /// has a complete pool view; until then it answers `not_ready_syncing`.
    pub const SERVE_GATE_KINDS: [PoolKind; 8] = [
        PoolKind::Airdrop,
        PoolKind::DevTreasury,
        PoolKind::Deed,
        PoolKind::DevDeed,
        PoolKind::Bootstrap,
        PoolKind::FoundationBootstrap,
        PoolKind::EmissionValidators,
        PoolKind::EmissionNabla,
    ];

    /// Short stable name for `/status` (`pool_synced_kinds`).
    pub fn status_name(&self) -> &'static str {
        match self {
            PoolKind::Airdrop => "airdrop",
            PoolKind::DevTreasury => "dev_treasury",
            PoolKind::Deed => "deed",
            PoolKind::DevDeed => "dev_deed",
            PoolKind::BoundedFee(_, _) => "bounded_fee",
            PoolKind::Bootstrap => "bootstrap",
            PoolKind::FoundationBootstrap => "foundation_bootstrap",
            PoolKind::EmissionValidators => "emission_validators",
            PoolKind::EmissionNabla => "emission_nabla",
        }
    }

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
            // The byte tag alone does NOT distinguish per-validator BoundedFee
            // pools OR their class — the `(validator_id, is_dev)` is bound into
            // the PoolSync signing payload separately (`pool_sync_sign_payload`,
            // appended only for BoundedFee so singleton payloads stay identical).
            PoolKind::BoundedFee(_, _) => 0x05,
            // Appended after BoundedFee — existing tags 0x01..0x05 are untouched,
            // so no in-flight PoolSync signature is invalidated.
            PoolKind::Bootstrap => 0x06,
            PoolKind::FoundationBootstrap => 0x07,
            // Appended LAST (2026-09-14) — tags are signing-payload bytes.
            PoolKind::EmissionValidators => 0x08,
            PoolKind::EmissionNabla => 0x09,
        }
    }

    /// The `(validator_id, is_dev)` key for a BoundedFee pool; `None` for the
    /// singletons. Bound into the PoolSync signing payload so a sig for one
    /// validator's pool — or one CLASS — cannot be replayed onto another.
    pub fn bounded_fee_key(&self) -> Option<([u8; 32], bool)> {
        match self {
            PoolKind::BoundedFee(vid, is_dev) => Some((*vid, *is_dev)),
            _ => None,
        }
    }

    /// Filename slug for the on-disk persistence file (`<data_dir>/<slug>.state`).
    pub fn state_filename(&self) -> &'static str {
        match self {
            PoolKind::Airdrop => "airdrop_pool.state",
            PoolKind::DevTreasury => "dev_treasury_pool.state",
            PoolKind::Deed => "deed_pool.state",
            PoolKind::DevDeed => "dev_deed_pool.state",
            // BoundedFee is a per-validator FAMILY: the whole map persists to
            // one `fob_pools.cbor` (node.rs), NOT a per-pool `.state`. This slug
            // is never used to write an individual BoundedFee pool; it exists
            // only to keep the match exhaustive.
            PoolKind::BoundedFee(_, _) => "fob_pools.cbor",
            PoolKind::Bootstrap => "bootstrap_pool.state",
            PoolKind::FoundationBootstrap => "foundation_bootstrap_pool.state",
            PoolKind::EmissionValidators => "emission_validators_pool.state",
            PoolKind::EmissionNabla => "emission_nabla_pool.state",
        }
    }
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
    /// the carried k=3 receipt proof before ordering on this (WI3 hole-1 —
    /// CLOSED: `SeqProof`/`SeqProofSig` below carry the k-receipt attestation
    /// and gossip.rs verifies it, incl. the anti-framing authorship gate).
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

    /// YP §32.3 — the sender's `state_id` this wallet's funds derive from
    /// (`received_from:state_id`). Set at redeem registration from the
    /// k-attested `K3Receipt.sender_state` (Core CL5 folds it into
    /// `receipt_commitment`, so verifying the commitment authenticates it —
    /// NOT client-asserted; a forged value fails the commitment recompute).
    /// `None` for genesis / send / heal / recall. This is the edge §32.4
    /// merge-quarantine taint propagation walks: a wallet whose
    /// `received_from` is a tainted (forked) state is itself tainted.
    ///
    /// No `serde(default)` on the wire semantics but kept `#[serde(default)]`
    /// for decode tolerance — like `wallet_seq`, it changes the bincode SMT
    /// leaf hash, so adopting it requires a coordinated all-Nabla restart +
    /// clean SMT (CLAUDE.md §13).
    #[serde(default)]
    pub received_from: Option<StateId>,
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
    /// THE single definition of "this entry is authored".
    ///
    /// Authored = carries a client pubkey, OR is a group-wallet entry (zero pk
    /// BY DESIGN, members present). An unauthored non-group entry is one every
    /// node would REJECT from a peer, so it must never outrank an authored one
    /// (`superseded_by` rule 1b).
    ///
    /// Extracted so `superseded_by` has ONE definition of "authored" rather
    /// than an inline re-derivation. Do not re-derive this test at a call site.
    pub fn is_authored(&self) -> bool {
        self.client_pk != [0u8; 32] || self.group_members.is_some()
    }

    /// `self_attested` / `incoming_attested`: does a VERIFIED k=3 `SeqProof`
    /// exist for each side's head? Required arguments, not options — every
    /// caller must answer, because a caller that silently assumed "yes" is what
    /// KI#77 was (see rule 1c).
    pub fn superseded_by(
        &self,
        incoming: &NablaEntry,
        self_attested: bool,
        incoming_attested: bool,
    ) -> bool {
        // 1. Freeze monotonicity — a non-Normal wallet (§32 frozen / tainted
        //    / banned) is never demoted back to Normal.
        //    Fork Settlement §9o [R57] (W3, 2026-09-30; KI#236): this rule
        //    protects only THIS node's OWN holds. Every network caller
        //    (`NablaNode::apply_remote_entry`; the flood's `apply_state_update`
        //    and `apply_group_update`, which inherit `existing.status`)
        //    normalises the INCOMING status to `Normal` first, so `r_in` is 0
        //    for any peer's entry and a peer can never raise a status here.
        //    RULE 0 §4: until W3 the AE path passed the peer's status through,
        //    and this rule made an unsigned `Banned` beat a genuine `Normal`
        //    head — the KI#236 censorship hole. Do not call this with an
        //    un-normalised peer entry.
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
        // 1b. Authorship legitimacy (2026-08-01, AE-convergence fix). An
        //    unauthored NON-GROUP entry is one every node would REJECT from a
        //    peer (YPX-009 / KI#46), so it is structurally unreplicable —
        //    debris from a local write path, never network truth. It must
        //    never outrank an authored entry, whatever its seq/tick: letting
        //    it win rule 3's tick tiebreak (or rule 5's byte-compare) is what
        //    froze the live mesh at 7 distinct roots with 6-8k AE reconciles
        //    and 0 applied — the holder refused the authored head forever,
        //    and its own push was refused by everyone. Group-wallet entries
        //    (zero pk BY DESIGN, members present) rank as legitimate.
        let (l_self, l_in) = (u8::from(self.is_authored()), u8::from(incoming.is_authored()));
        if l_in != l_self {
            return l_in > l_self;
        }
        // 1c. Attestation legitimacy (KI#77, 2026-08-07). An entry whose seq we
        //    cannot attest is one every peer REJECTS (`[AE-REJECT]
        //    seq-unattested proof=ABSENT`), so it is structurally unreplicable
        //    — the EXACT shape rule 1b describes for authorship, on a different
        //    field. It must never outrank an attestable entry, whatever its seq.
        //
        //    Without this the holder refused every peer's attested head (rule 2:
        //    its own unprovable seq was higher) while every peer refused its
        //    push — permanent divergence that no restart, no gossip and no
        //    uptime clears, and on mainnet there is no `clean --data` to escape
        //    it. Exactly the 2026-08-01 rule-1b failure re-run on seq proofs;
        //    the six heads stranded by KI#73 are the live evidence.
        //
        //    Preferring PROVEN-lower over UNPROVABLE-higher is not a rollback of
        //    the seq rule, it is its premise: a bare `wallet_seq` is FORGEABLE
        //    (see the `wallet_seq` SECURITY note), which is why `SeqProof`
        //    exists. Trusting an unprovable seq over a proven one inverts the
        //    argument rule 2 rests on.
        //
        //    SAFETY: this cannot be used to roll a node back to a spent state.
        //    Both merge paths gate on A12 `is_state_consumed(new_state)` BEFORE
        //    reaching here (gossip.rs `apply_state_update`, node.rs
        //    `apply_remote_entry`), which is the defence against exactly that
        //    (the KI#34 revival). Residual, recorded not hidden: A12 is blind on
        //    a wiped node with an empty consumed-set (§5.2), and it is a
        //    fail-closed bloom (KI#43).
        //    ONE-DIRECTIONAL, deliberately. Only an UNATTESTED LOCAL head
        //    yielding to an ATTESTED incoming is fixed here. The reverse — an
        //    attested local blocking an unattested incoming — is NOT applied,
        //    and the first draft of this rule got that wrong: written
        //    symmetrically it froze `ki38_equal_seq_adopt_clears_stale_proof`,
        //    and in production it would freeze the head of any wallet whose
        //    updates legitimately carry no proof (an equal-seq tiebreaker, or a
        //    wallet whose `wallet_seq` does not advance — observed live on
        //    2026-08-07). Blocking legitimate progress would be a worse bug than
        //    the divergence this fixes. The asymmetry IS the fix: we are only
        //    ever giving up a head we cannot prove.
        if !self_attested && incoming_attested {
            return true;
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

/// §5.2.4 (KI#123, 2026-08-28) — may a locally-built FACT-CONFIRM candidate
/// (unattested BY CONSTRUCTION — it carries no seq proof) displace `existing`?
///
/// Rank 1c (`superseded_by`) is deliberately one-directional: it fires only
/// for `!self_attested && incoming_attested`, so an unattested candidate at
/// EQUAL seq against an ATTESTED head fell through to the tick tiebreaker and
/// won on freshness — whereupon `put`'s KI#38 lock-step (correctly) dropped
/// the proof bound to the displaced head's tx_hash, and the candidate had
/// nothing to re-establish. Every node ran the same deterministic path, so
/// the proof vanished MESH-WIDE at once (the 2026-08-25 strand: four attested
/// personal-wallet heads left proof-less on all ten nodes; a fresh node
/// correctly refused all four over AE forever, wedging at 630/635).
///
/// The rule: a candidate whose tx_hash EQUALS the held head's is a
/// confirmation of the head we hold — the site's intended purpose — and
/// merges normally. A DIFFERING-tx candidate against an ATTESTED head is
/// DECLINED outright: adopting it would strip a proof this node can never
/// recover, which is the "must not store what it would reject" rule (KI#46 /
/// KI#77) finishing its own thought. Against an UNattested head the ordinary
/// merge decides (nothing to strip; KI#77's one-directional ruling applies).
///
/// This is deliberately NOT folded into `superseded_by`: the flood/AE paths
/// compare two NETWORK entries where an unattested equal-seq winner is
/// legitimate (KI#77 — a symmetric block froze live progress on 2026-08-07).
/// Only the fact-confirm site BUILDS its unattested candidate locally, so
/// only it can promise the candidate is never network truth outranking us.
pub fn fact_confirm_may_displace(
    existing: &NablaEntry,
    self_attested: bool,
    candidate: &NablaEntry,
) -> bool {
    if candidate.tx_hash != existing.tx_hash && self_attested {
        return false;
    }
    existing.superseded_by(candidate, self_attested, false)
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
    /// P3.6 — the Core-computed CI, carried so `verify_seq_proof`'s
    /// `compute_receipt_commitment` recompute folds the same value the k signed.
    pub confidence_index: Option<axiom_core_logic::types::ConfidenceIndex>,
    /// §32.3 — the sender-lineage bound into `receipt_commitment`, carried so
    /// `verify_seq_proof`'s recompute matches what the k signed. This is how
    /// `received_from` is authenticated on the flood path: a peer verifying the
    /// SeqProof transitively verifies `sender_state` (the k sigs cover it).
    #[serde(default)]
    pub sender_state: Option<[u8; 32]>,
    pub sigs: Vec<SeqProofSig>,
    /// YP §17.3.1.4 v2.19.0 (KI#150) — the k of the round these sigs attest
    /// (the registration's tier); `verify_seq_proof` needs
    /// `max(required_k, 3)` distinct valid sigs. This IS the design's
    /// `k_tier` threshold selector (ForkSettlement §2.2 [R‑LOW]: unsigned —
    /// understating it can only lower the bar to the ≥3 floor), so no second
    /// `k_tier` field is carried.
    pub required_k: u8,
    /// ForkSettlement wave 2a (§2.2, [R10] carrier) — the leg this proof
    /// attests, copied from the verified `Registration::preimage` at the door.
    /// The SeqProof is the CARRIER: it already rides the StateUpdate flood,
    /// `StatePullEntry` / `RangeSyncResponse`, `AeReconcile` / `AeEntries`,
    /// `WalOp::Put` and `snapshot.seq_proofs`, so the leg reaches every node
    /// that learns the head. Every receiver re-runs
    /// `registration::verify_leg_preimage` (2 BLAKE3 for a `Send` leg) and
    /// REJECTS a proof whose preimage does not reproduce its own
    /// `commitment_hash` / the entry's `tx_hash` (counted,
    /// `leg_preimage_refused` on /status). Mandatory — no `Option`, no
    /// default (§13). LAST: bincode is positional, and a pre-wave-2a record
    /// (WAL `Put`, snapshot) therefore runs out of bytes here and fails to
    /// decode instead of mis-reading (see `snapshot.rs` persisted-shape test).
    pub preimage: LegPreimage,
    /// Fork Settlement W7b (spec R52d, §9g) — the declared produced state's
    /// balance and the k-signed seq (`DeclaredState`), carried so ANY node can
    /// check the producer binding (`ban::leg_is_state_bound`: a record is a
    /// PRODUCER of its state only if that state is k-bound) and — for a
    /// `Redeem` leg, whose preimage binds no seq — verify the witness quorum
    /// of a redeem leg carried inside a `ForkClaim` (no message around it).
    /// Mandatory, no default (§13). LAST (after `preimage`): a pre-W7b
    /// SeqProof (WAL `Put`, snapshot `seq_proofs` / `origin_ledger`) runs out
    /// of bytes and is refused loudly (`snapshot.rs`
    /// `persisted_shape_seq_proof_without_declared_is_refused_loudly`).
    pub declared: DeclaredState,
}

/// Fork Settlement W7b (spec R52d) — the two values of a leg's produced state
/// that its preimage does not carry for every kind:
///
/// * `balance` — the registrant's DECLARED post-transition balance
///   (`Registration::declared_balance`). For a genesis / stake CLAIM's send that
///   is the UNCHANGED balance (YP §17.11.2 step 3; KI#251 — Core credited at
///   the send until 2026-10-02, and a §9m arm here re-derived that credit). A SEND leg's produced state is only
///   wallet-signed (spec F7), so `ban::leg_is_state_bound` recomputes
///   `compute_produced_state_id(pk, balance, seq, consumed, nonce) ==
///   new_state` with every other input taken from the k-signed preimage.
/// * `wallet_seq` — the k-signed `receipt.new_wallet_seq` the door copied. A
///   REDEEM preimage binds no seq (Core keeps the seq on a receive), so this is
///   the only carried source of the seq the k witnesses signed; a wrong value
///   only fails the witness-sig recompute.
///
/// ⚠ DEVIATION from spec R52d, stated (2026-09-28, W7b): the spec carries the
/// full §15 tuple `{balance, hibernation_until, wall_clock_lock,
/// emission_claimed_epoch}` to ALSO recompute `compute_state_hash == state_hash`
/// (pinning the balance to a k-signed value). Not built: the only input left
/// unpinned by the produced-state recompute is the balance, and a fabricated
/// balance can "produce" only a state no validator ever witnessed — which no
/// k-witnessed leg can consume (§15 anchors every consumed state on its own
/// receipt), so it grounds no money (the goal test). Minimal carrier; the
/// full-tuple form was a hand-rolled `WalletState` mirror
/// (`check_mirror_structs.py`).
///
/// A CARRIER, never a hash preimage (Pattern 1). Built ONLY by
/// [`DeclaredState::of_registration`] (the register — the one producer of
/// every `SeqProof`); flood / AE / snapshot / WAL carry it verbatim.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DeclaredState {
    pub balance: u64,
    pub wallet_seq: u64,
}

impl DeclaredState {
    /// THE constructor — a pure field copy of what the register carried.
    pub fn of_registration(reg: &Registration) -> Self {
        DeclaredState {
            balance: reg.declared_balance,
            wallet_seq: reg.receipt.new_wallet_seq,
        }
    }
}

impl SeqProof {
    /// Build the `SeqProof` a register carries — the ONE producer of every
    /// `SeqProof` (door retention, 5b′/5b‴, the fee path, the KI#68 adopt).
    /// Returns `None` when the receipt carries no `receipt_commitment_sig`s
    /// (no-fee / heal / genesis / legacy paths) — those entries advertise
    /// `wallet_seq` but have no k-attestation to prove it, so the merge treats
    /// their seq as untrusted.
    ///
    /// The leg is the registration's carried `preimage` (ForkSettlement wave
    /// 2a) and `declared` its declared balance + k-signed seq (W7b, spec
    /// R52d) — retained with the head so both reach every node that learns
    /// it. The door verifies the leg at step 5b′ BEFORE any producer here runs
    /// on a committed head.
    pub fn from_registration(reg: &Registration) -> Option<SeqProof> {
        let receipt = &reg.receipt;
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
            confidence_index: receipt.confidence_index.clone(),
            sender_state: receipt.sender_state,
            sigs,
            required_k: reg.k_tier,
            preimage: reg.preimage.clone(),
            declared: DeclaredState::of_registration(reg),
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

// ── Ban Status (Section 2.7) ──

/// Ban lifecycle. A ban is **permanent and terminal** — there is exactly one
/// state (YPX-002 §7.3).
///
/// The `Challenged`/`Reversed` states and their challenge protocol (S6,
/// v2.10.27) were REMOVED 2026-07-28 (design decision). Their premise — "the ban
/// may have been caused by a network partition rather than genuine
/// double-spend" (AXIOM_GUIDE_Nabla.md §2.8) — no longer holds: both ban
/// entry points require the wallet's OWN key on BOTH conflicting branches
/// (`ban` takes two k=3-signed `ConflictProof`s; `ban_seq_fork` takes two
/// k=3-attested successors of one predecessor). [Superseded: KI#222 showed
/// `ban`'s pair forgeable and check-3's "one predecessor" was a node's view
/// (KI#235); both are replay-only now. The live entry point is `ban_fork` via
/// `ban::apply_fork_verdict`, which verifies a self-proving `ForkClaim`.] A partition yields scarred or
/// under-witnessed states, never two independently k=3-witnessed forks, and
/// anti-framing is regression-tested (a forged unauthored fork does not ban).
///
/// A ban is therefore a proof-carrying verdict, not an accusation: there is no
/// innocence evidence a banned wallet could present, so there was nothing for a
/// challenge to adjudicate. As built it was strictly harmful — endorsements
/// signed only `wallet_id ‖ ban_tick` (attesting nothing about the conflict),
/// no counter-evidence path existed despite the docs claiming one, and reversal
/// was an unconditional timeout — so 3 endorsements cleared a proven
/// double-spend in ~1h, at unpriced Sybil cost.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum BanStatus {
    /// Ban is active — wallet is blocked. Permanent; the only state.
    #[default]
    Active,
}

// ── Banned Entry (Section 2.7) ──

/// Persisted in `NablaSnapshot.bans` and in `WalOp::Ban.evidence` (bincode).
///
/// ForkSettlement wave 3 [R32] — `evidence` is ONE tagged [`BanEvidence`]
/// (was `evidence_1` / `evidence_2` / `seq_fork`, two of them zero-filled per
/// kind). A PERSISTED-SHAPE change: a prior-shape snapshot is refused loudly
/// (`snapshot_decode_refused`), a prior-shape WAL `Ban` record likewise
/// (`node::wal_ban_decode_refused_total`, R36) — see the persisted-shape tests
/// in `snapshot.rs` / `node.rs`. No `serde(default)` anywhere (§13).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BannedEntry {
    pub wallet_id: WalletId,
    /// What the ban rests on.
    pub evidence: BanEvidence,
    /// Ban lifecycle status. Always `Active` — bans are permanent (YPX-002 §7.3).
    pub status: BanStatus,
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
    /// YP §17.3.1.4 v2.19.0 (KI#150) — the k of the round the evidence
    /// carries; `ban::conflict_has_quorum` needs `max(required_k, 3)` sigs.
    /// LAST: bincode is positional.
    pub required_k: u8,
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

// ── ForkSettlement wave 3 — the self-proving fork evidence (§2.2, §2.4, §9b R32) ──
//
// Nabla-only (RULE 7): nothing here reaches a validator. RULE 5: all of it is
// Nabla HYGIENE — a hostile Nabla fails open. The Core enforcement that holds
// regardless is `fact::origin_settled_link` / `origin_settled_cl5` (txid
// recompute from the carried preimage + the settle floor) plus the signed
// `crypto::txid_attest_payload` (wave 2b-i).

/// ONE verified-able leg of a fork: what the k validators signed (inside
/// `seq_proof`) and what the wallet authored (`client_sig` over
/// `client_state_sign_payload(smt_bucket(pk, k), new_state, tx_hash)`).
///
/// SHAPE [R32] — `{new_state, tx_hash, client_sig, seq_proof}`, NOT the §2.2
/// list `{preimage, epoch, k_tier, new_state, tx_hash, seq_proof_sigs,
/// client_sig}`: the preimage (`seq_proof.preimage`), `epoch`, `k_tier`
/// (`seq_proof.required_k`) and the sigs already ride INSIDE `SeqProof`, so
/// carrying them again would be a second copy of one fact (RULE 1), and the
/// §2.2 list MEASURED 5/7 of Core `nabla_wire::Registration`'s fields — a
/// `check_mirror_structs.py` failure. The design-level names are the
/// accessors below (plain methods add nothing to the mirror surface).
///
/// Holds NO wallet id and NO bucket: the banned identity and the bucket the
/// client sig is checked over are DERIVED from the preimage's key [R7] — there
/// is no name in the message to forge.
///
/// A `ForkLeg` is UNVERIFIED data. Only `ban::verify_fork_leg` turns one into
/// a `ban::VerifiedForkLeg`, the only thing an origin record can be made from
/// [R11, structural].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ForkLeg {
    pub new_state: StateId,
    pub tx_hash: TxHash,
    /// 64-byte Ed25519 over `client_state_sign_payload(smt_bucket(pk, k),
    /// new_state, tx_hash)` — the KI#46 wallet authorship of THIS txid.
    pub client_sig: Vec<u8>,
    /// Carries the WITNESS_V2 leg (`preimage`), `epoch`, `required_k`
    /// (= `k_tier`), the receipt-commitment inputs and the k sigs.
    pub seq_proof: SeqProof,
}

impl ForkLeg {
    /// The WITNESS_V2 preimage of a SEND leg; `None` for a `Redeem` leg.
    pub fn send_preimage(&self) -> Option<&axiom_core_logic::types::WitnessPreimage> {
        self.seq_proof.preimage.send_preimage()
    }

    /// The `RedeemPreimage` of a REDEEM leg (Fork Settlement W7b, spec R52c);
    /// `None` for a send leg.
    pub fn redeem_preimage(&self) -> Option<&axiom_core_logic::types::RedeemPreimage> {
        self.seq_proof.preimage.redeem_preimage()
    }

    /// The cheque origin a REDEEM leg carries (KI#241 F-2 — verified against
    /// the k-bound `cheque_txid` on every path that records it); `None` for a
    /// send leg.
    pub fn cheque_origin(&self) -> Option<&axiom_core_logic::types::OriginRecord> {
        self.seq_proof.preimage.cheque_origin()
    }

    /// Which commitment builder the leg recomputes through.
    pub fn kind(&self) -> axiom_core_logic::types::LegKind {
        self.seq_proof.preimage.kind()
    }

    /// The registrant's key — from the (k-signed) preimage, never the message:
    /// the sender's `client_pk` of a send leg, the `receiver_pk` of a redeem
    /// leg (W7b — the redeem commitment binds it).
    pub fn client_pk(&self) -> [u8; 32] {
        match &self.seq_proof.preimage {
            LegPreimage::Send(p) => p.client_pk,
            LegPreimage::Redeem { redeem: r, .. } => r.receiver_pk,
        }
    }

    /// The parent this leg consumed — from the preimage (signed), never an
    /// unsigned message `old_state` [R‑MEDIUM-3]. For a redeem leg it is the
    /// receiver-DECLARED `consumed_state_id` (spec F8), k-bound by the redeem
    /// commitment ([R8], wave 2b-ii).
    pub fn consumed(&self) -> StateId {
        match &self.seq_proof.preimage {
            LegPreimage::Send(p) => p.consumed_state_id,
            LegPreimage::Redeem { redeem: r, .. } => r.consumed_state_id,
        }
    }

    /// The seq the k witnesses signed inside `receipt_commitment`: a send's
    /// `preimage.wallet_seq` (Core stamps `new_wallet_seq = tx.wallet_seq`), a
    /// redeem's carried `declared.wallet_seq` (W7b — a redeem preimage binds no
    /// seq; a wrong value only fails the witness-sig recompute).
    pub fn signed_seq(&self) -> u64 {
        match &self.seq_proof.preimage {
            LegPreimage::Send(p) => p.wallet_seq,
            LegPreimage::Redeem { .. } => self.seq_proof.declared.wallet_seq,
        }
    }

    /// The design's `k_tier` — `SeqProof.required_k` (unsigned; understating
    /// it only lowers the bar to the ≥3 floor, §2.2 [R‑LOW]).
    pub fn k_tier(&self) -> u8 {
        self.seq_proof.required_k
    }

    /// The SMT bucket the wallet's client sig is checked over, DERIVED from
    /// the key [R7] through the ONE builder (`smt_bucket`, re-exported by
    /// `registration`).
    pub fn bucket(&self) -> WalletId {
        crate::registration::smt_bucket(&self.client_pk(), self.k_tier())
    }

    /// The ATRAXI key of §2.3 — `(registrant client_pk, consumed state)`,
    /// SHARED by send and redeem legs (W7b, spec R52c: a send and a redeem
    /// from one parent are an A1 claim). NOT `atraxi::AtraxiKey = (WalletId,
    /// state)` (plan A8).
    pub fn key(&self) -> ([u8; 32], StateId) {
        (self.client_pk(), self.consumed())
    }

    /// The ONE conversion to Core's attestation payload
    /// (`axiom_core_logic::types::OriginRecord`, what a vouching node signs
    /// inside `NablaTxidAttestation`, §2.4 / §3.2 [R11]). `None` for a
    /// `Redeem` leg — a redeem is never an origin [R33, R5].
    ///
    /// Read by `NablaNode::origin_vouch` (the attestation signer).
    pub fn origin_record(&self) -> Option<axiom_core_logic::types::OriginRecord> {
        self.send_preimage().map(|p| axiom_core_logic::types::OriginRecord {
            preimage: p.clone(),
            epoch: self.seq_proof.epoch,
            kind: axiom_core_logic::types::LegKind::Send,
        })
    }
}

/// Two legs a verified claim says were authored by ONE key from ONE parent
/// with DIFFERENT txids — the double-spend itself (§2.2, [R31]). NO
/// `wallet_id` field [R7]: the banned identity is derived from the legs'
/// preimage key by `ban::fork_ban_keys`. Verified ONLY by
/// `ban::verify_fork_claim` (the one chokepoint for every carrier, [R25]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ForkClaim {
    pub a: ForkLeg,
    pub b: ForkLeg,
}

/// The node's TXID RECORD (§2.4) — and, since Fork Settlement W7b, the entry
/// shape of a REDEEM record too (`SparseMerkleTree::redeem_ledger`, a separate
/// map keyed `((pk, consumed), cheque_txid)`, WAL `RedeemRecord`, snapshot
/// `redeem_ledger` — never read as an origin, R5). The design's `OriginRecord {leg,
/// first_seen_secs, contested}`, RENAMED [R32]: Core's
/// `axiom_core_logic::types::OriginRecord` is the ATTESTATION payload (what a
/// node signs); this is what a node HOLDS. The map is
/// `SparseMerkleTree::origin_ledger` (`HashMap<TxHash, OriginLedgerEntry>`),
/// persisted in `NablaSnapshot.origin_ledger` and by `WalOp::OriginRecord`.
///
/// Write-once: created ONLY by `SparseMerkleTree::record_verified_leg` from a
/// `ban::VerifiedForkLeg`; restored ONLY verbatim (`restore_origin_entry` /
/// `restore_redeem_entry`, [R27]). Neither `first_seen_secs` nor `contested` is ever recomputed.
/// The one mutation (W1, §9o [R58]): record-AE may replace `leg` by a GRADED
/// copy of the same leg (other witnesses) when the held copy is ungraded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginLedgerEntry {
    /// The whole verified leg [R10] — so a second txid under the same
    /// `(pk, consumed)` key IS a `ForkClaim` with both legs in hand.
    pub leg: ForkLeg,
    /// THIS node's `virtual_secs` (wall-clock seconds sampled by the binary's
    /// tick loop) when the record was born — never `entry.tick`, never TARDIS
    /// [R13]. Plumbed explicitly by the caller.
    pub first_seen_secs: u64,
    /// [R16] fixed AT BIRTH [R24] and never recomputed [R27]: the parent was
    /// already consumed at this node and no sibling record was held — the
    /// node cannot name the other leg, so it never vouches for this key.
    pub contested: bool,
}

/// What a `BannedEntry` rests on. Replaces the old
/// `evidence_1` / `evidence_2` / `seq_fork` trio (three fields, two of them
/// zero-filled per kind) with one tagged value [R32].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BanEvidence {
    /// E1 `ConflictProof` pair — FORGEABLE (KI#222). No live producer: kept
    /// ONLY so a WAL `Ban` / snapshot written before the retirement replays
    /// faithfully (`BanTable::ban`). Unreachable after the §13 rotation wipe.
    LegacyConflict(ConflictProof, ConflictProof),
    /// LEGACY check-3 (`gossip.rs`, KI#46) seq-fork evidence. No live producer
    /// since 2026-09-30 (Fork Settlement §9o [R56], W2 — check-3 retired as a
    /// ban source, KI#235; redeem-leg forks are `Fork` claims since W7b). Kept
    /// ONLY so a persisted WAL `Ban` / snapshot replays faithfully
    /// (`BanTable::ban_seq_fork`); such a ban stays LOCAL — never propagated.
    SeqFork(SeqConflictProof),
    /// ATRAXI A1 — the self-proving `ForkClaim`, verified by
    /// `ban::verify_fork_claim` before anything is banned [R25].
    Fork(ForkClaim),
}

// ── Definitions of K3WitnessSig, Registration, K3Receipt, DeedTransaction
// moved to axiom_core_logic::nabla_wire; re-exported above per the UMP rule. ──

// ── Query Response (Section 4.2) ──


// ── Merkle Proof (Section 2.3) ──


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
///
/// `Name` is the form an operator-run node SHOULD advertise, and it must be
/// relayed onward **verbatim**. A discovery hint is a relay, not a judgement:
/// a node never resolves a peer's address on that peer's behalf, never
/// substitutes what it observed, and never drops a hint because *it* cannot
/// reach the address — reachability is a fact about the reader's own network,
/// not about the address. Resolution happens ONLY at dial time, locally, by
/// whoever is dialling (`transport::to_socket_addr`).
///
/// Why this variant exists (2026-08-18): addresses were IP-only, so a node
/// resolved its own `--advertise` DNS name at boot and gossiped the resulting
/// IP. On the control box `axiom-dev.mooo.com` legitimately resolves to the LAN
/// address `172.20.0.42` (no NAT loopback here, so co-located nodes must reach
/// each other that way) — and that private IP was then propagated mesh-wide.
/// The external node `iota`, correctly configured with public DNS and no VPN,
/// could not route to it: it flapped between Orphan and Writer and fell 379s
/// behind on ticks. The DDNS name was correct the whole time; the protocol
/// discarded it. With `Name`, every node resolves the same name in its own
/// context and each answer is right where it is used.
///
/// ⚠ `Name` is LAST on purpose — bincode encodes enum variants POSITIONALLY, so
/// a new variant may only be appended (see feedback_new_gossip_variants_go_last).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NablaAddress {
    V4 { ip: [u8; 4], port: u16 },
    V6 { ip: [u8; 16], port: u16 },
    /// DNS name + port, relayed verbatim and resolved only at dial time.
    Name { host: String, port: u16 },
}

/// Topology hints gossipped through the mesh (on change only, not every tick).
/// These enable TARDIS self-healing without central coordination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TopologyHint {
    /// "I lost my UP, need new parent"
    LostUpstream { node_id: NodeId },
    /// "I have an open D slot — open_slots tells how many (1 or 2)"
    ///
    /// ⚠ §5.6a-bis: IDENTITY ONLY — this hint carries NO address, deliberately.
    /// It is RELAYED, so the far end's `envelope.peer` is the RELAYER, not the
    /// subject: composition (`observed IP : declared port`) is impossible here,
    /// and the only alternatives were to keep relaying the subject's own claim
    /// or to let a relayer vouch for where a third party lives. Both hand a
    /// stranger the power to place a node it has never contacted.
    ///
    /// Correct reading: a recipient acts on this hint only for a node it ALREADY
    /// has a directly-observed address for (composed at `Hello` /
    /// `TardisAttachRequest`, or carried in a PX `PeerInfo` by a peer that
    /// observed it). No observed address ⇒ the slot is unusable and the hint is
    /// dropped — counted, not silent, so "never dropped" and "never ran" stay
    /// distinguishable (RULE 3 shape 2).
    ///
    /// Ruling: 2026-08-26 — option 1, identity-only, no trust delegation.
    SlotAvailable { node_id: NodeId, open_slots: u8 },
    /// "New node joined the network"
    ///
    /// ⚠ §5.6a-bis: IDENTITY ONLY — same reasoning as `SlotAvailable`. This is
    /// now a pure "someone joined" signal; it no longer seeds a dialable
    /// address, because the address it used to carry was the new node's own
    /// unverifiable claim, relayed onward by every hop.
    ///
    /// Discovery still closes, by a different route: the joiner dials its
    /// bootstrap/seed peers itself, THOSE peers compose its address from the
    /// connection, and the observed record spreads via PX `merge_peer_info`.
    /// Learning an address therefore always traces back to someone who actually
    /// talked to the node.
    NewNode { node_id: NodeId },
}

// ── Gossip Messages (Section 6.2 — Phase 1 subset) ──

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GossipMessage {
    /// Wallet state update (flood fill)
    StateUpdate {
        wallet_id: WalletId,
        new_state: StateId,
        tx_hash: TxHash,
        /// KI#46 dsfork check-3 alignment (design decision 2026-07-30): the state
        /// this advance CONSUMED (the register's `old_state`, i.e. the parent
        /// of `new_state`). The dsfork ban fires ONLY on a proven same-parent
        /// fork — `old_state == previous_states[W]` at the detecting node with
        /// a different `new_state` — never on a same-seq chain continuation
        /// (Core's receive rule keeps `wallet_seq` unchanged on redeem, so
        /// every redeem is a legitimate same-seq state advance; the seq-only
        /// predicate false-banned the first honest claim+redeem the moment
        /// authorship went live). ALL-ZERO = parent unknown (RangeSync/replay
        /// reconstruction) → never ban material, merge rule still governs.
        /// No serde(default) (§13 clean break; whole mesh redeploys together).
        old_state: StateId,
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
    /// TOMBSTONE — RETIRED under KI#222 (2026-09-28). MUST NEVER be emitted,
    /// and MUST NEVER be acted on: the receiver (`GossipEngine::process`)
    /// verifies nothing, bans nothing, forwards nothing — it counts the drop
    /// (`ki222_banalert_dropped` on /status) and returns.
    ///
    /// Why retired: the `ConflictProof` pair is FORGEABLE. Its k sigs are over
    /// `receipt_sign_payload(wallet_id, consumed_state, tick)`, which binds
    /// neither `new_state` nor `tx_hash`, so one genuine registration receipt's
    /// sigs "prove" any fabricated conflict — any Nabla peer could permanently
    /// ban any wallet mesh-wide. No honest node ever emitted it. The self-proving
    /// replacement is `ForkClaim` / the `ForkLeg` standard
    /// (`docs/AXIOM_DESIGN_ForkSettlement.md` Part A). (`SeqForkBan`, named here
    /// until 2026-09-30 as covering the gossip-path fork, is itself a tombstone
    /// now — §9o [R56].) Never revive this variant or copy its verifier.
    ///
    /// Why it is still here: `GossipMessage` is bincode-POSITIONAL (see the
    /// `HalAdvance` note below — new variants go LAST). Deleting a middle variant
    /// shifts every later discriminant and breaks the wire between any two nodes
    /// on different builds. Removing it therefore needs a COORDINATED roll of
    /// every node in the mesh at once — do not delete it in an ordinary change.
    BanAlert {
        wallet_id: WalletId,
        evidence_1: ConflictProof,
        evidence_2: ConflictProof,
    },
    /// TOMBSTONE — RETIRED 2026-09-30 (Fork Settlement §9o [R56], W2; KI#235).
    /// Was the flood of check-3's seq-fork ban. It is NEVER emitted by this
    /// build and MUST NEVER be acted on: the receiver (`GossipEngine::process`)
    /// verifies nothing, bans nothing, forwards nothing — it counts the drop
    /// (`seqforkban_dropped` on /status) and returns.
    ///
    /// RULE 0 §4 — the WRONG reading this doc used to state: "two k=3-attested
    /// successors of the same predecessor; receivers re-verify both `SeqProof`s
    /// before applying the irreversible ban". Receivers had stopped adopting it
    /// on 2026-07-30 (KI#46 follow-up — the evidence binds the SEQ, not the
    /// parent), and its emitter's "same predecessor" was `previous_states[W]`,
    /// the head the node's last put overwrote, which false-banned honest
    /// wallets (KI#235). Forks travel only as self-proving `ForkBan` claims.
    ///
    /// Kept because `GossipMessage` is bincode-POSITIONAL (see `BanAlert`).
    SeqForkBan {
        wallet_id: WalletId,
        evidence: SeqConflictProof,
    },
    /// Root hash at tick boundary (partition detection).
    ///
    /// AUTHENTICATED. `node_pk` is a CLAIM; `signature` is what makes it
    /// evidence. The §5.5 audit self-contradiction rule compares an upstream's
    /// signed audit answer against what that upstream advertised here — so an
    /// UNSIGNED advertisement meant a node could be detached, and its whole
    /// subtree alerted, on one forged packet naming it. That is the same
    /// targeted-topology-grief attack §5.5.1 point 8 closes on the alert path;
    /// it was open one layer down, on the input that GENERATES those alerts.
    ///
    /// Verified against the sender's NBC-anchored Ed25519 key on receive, the
    /// same identity↔key binding used by ticks and alerts. `signature` is LAST:
    /// bincode is positional.
    TickHash {
        tick: u64,
        root_hash: Hash256,
        node_pk: [u8; 32],
        signature: Vec<u8>,
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

    // KI#156 (deleted 2026-09-21): `ChequeClaim` gossip removed. It was the
    // pre-redeem claim-race fan-out (§4.6), whose ONLY emitter sat on the retired
    // HTTP path — the live TCP handler (`register_cheque_claim_core`) registers the
    // claim locally and never gossiped it, so this had no live producer. The
    // durable double-redeem defence is the WAL-backed `TxRedeemed` consume-once
    // terminal, not this hint. Deleting a mid-enum variant renumbers every variant
    // below it, so this rides a COORDINATED whole-mesh Nabla roll (CoreID-neutral).
    // See docs/AXIOM_REPORT_KnownIssues.md KI#156.
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

    /// ⚠ TOMBSTONE (ForkSettlement §9r-E4, 2026-10-02; YPX-025 E6 RETIRED).
    /// Was §32 taint propagation ("wallets that received from a forked wallet
    /// are themselves tainted" → `Tainted` → refused at the door). No node of
    /// this build emits it; the receive arm drops and counts it
    /// (`taintalert_dropped`), never taints, never forwards. A downstream hold
    /// is ATRAXI A5 (`provenance.rs`). Kept ONLY because bincode is positional.
    TaintAlert {
        wallet_id: WalletId,
        /// The tainted source wallet that contaminated this wallet.
        tainted_source: WalletId,
        /// Tick when taint was detected.
        detected_at_tick: u64,
    },

    /// ⚠ TOMBSTONE (ForkSettlement §9r-E4 / D-E4-1, 2026-10-02). Was the §32
    /// quarantine-expiry summary (forked wallets still held, tainted restored);
    /// its only emitter, the 75 s timer, is deleted. The receive arm drops and
    /// counts it (`mergeresolved_dropped`) — it used to FORWARD this
    /// unauthenticated summary. Kept ONLY because bincode is positional.
    MergeResolved {
        /// Fork-source wallets the SENDER still holds `Frozen` at expiry — a
        /// local hold, NOT a ban (field name kept: bincode-positional wire).
        forked_wallets: Vec<WalletId>,
        /// Wallets restored to Normal (innocent downstream).
        restored_wallets: Vec<WalletId>,
        /// Tick when merge was resolved.
        resolved_at_tick: u64,
    },

    /// H3: Data availability withholding challenge.
    ///
    /// ⚠ **UNBUILT — THIS IS NOT ENFORCEMENT** (ghost audit G15, verified
    /// 2026-08-07). The paragraph below describes the intended design. None of
    /// it exists:
    ///
    ///   * `CHALLENGE_WINDOW_TICKS` is **not a constant anywhere** — it occurs
    ///     only inside this comment and the `DataWithholdResponse` one;
    ///   * neither variant is ever **constructed** — no production emitter, and
    ///     no test builds one either;
    ///   * there is **no SCAR path** — nothing links a withhold to a scar;
    ///   * there is **no timer** to expire a challenge.
    ///
    /// The receive arms in `gossip.rs` now DROP both variants and count them
    /// (`h3_unbuilt_dropped`); they used to forward, which made a protocol with
    /// no emitter into free amplification surface. Kept in the enum rather than
    /// deleted because bincode is positional — removing them would shift every
    /// later discriminant and break the wire for all ten nodes.
    ///
    /// To build H3: add the constant, an emitter, a challenge timer, and the
    /// SCAR consequence — then re-enable forwarding in the same commit.
    ///
    /// INTENDED DESIGN (not implemented): A peer challenges a validator that
    /// accepted a TX but refuses to serve the receipt/cheque to the client or
    /// other validators. If the challenged validator doesn't respond with the
    /// withheld data within CHALLENGE_WINDOW_TICKS, they receive a SCAR (same
    /// enforcement as JFP).
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
    /// ⚠ UNBUILT — see `DataWithholdChallenge`. No such constant exists and
    /// nothing resolves anything; this arm's only gate was `sig.len() == 64`
    /// under a comment promising "full verification by peers", where every peer
    /// ran that same arm. Ghost audit G15.
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
        /// KI#191 — Σminus in ATOMS: what this pool has actually paid out.
        /// `total_claims` counts CLAIMS, which only converts to atoms while
        /// every claim costs the same; the emission pools' per-claim grant is
        /// an epoch share, so the count cannot express conservation for them.
        /// Carried so a receiver can check the peer's OWN coherent snapshot
        /// (JUDOON §2.5 skew-immunity) instead of mixing its own numbers in.
        paid_out: u64,
        /// KI#191 — Σplus beyond the genesis opening: the ACCOUNTED DEED inflow
        /// (YP §25.2.4 rule 4). 0 for a drain-only pool. Sent by the peer for
        /// the same reason as `paid_out`: the budget must come from the same
        /// snapshot as the balance, or the comparison is cross-node again —
        /// which is the skew that made honest nodes look guilty (soak_r22).
        topped_up: u64,
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
        ///
        /// **VERIFIED since 2026-08-07 (KI#72)** — by `intermediate_sig`
        /// below, not by the transport. It previously said "Verified against TCP
        /// source at receive time" and never was: the caller passed this field
        /// in as the "TCP source", so the check compared it to itself and one
        /// attacker could fabricate the whole dual-uniqueness quorum.
        intermediate_emitter: NodeId,
        /// TARDIS tick at first emission. Used for 10-tick dedup window
        /// and the "10-tick rolling consensus" semantics.
        emitted_at_tick: u64,
        /// KI#72 — the forwarding node's Ed25519 signature over
        /// `crypto::pool_alert_sign_payload(..)`, proving it really is
        /// `intermediate_emitter`.
        ///
        /// APPENDED LAST ON PURPOSE: bincode encodes struct fields positionally,
        /// so a new field must go at the end (same rule as the `HalAdvance`
        /// variant note below).
        ///
        /// This is the "short form" of §5.6.4 step 1: the NBC is NOT sent. The
        /// receiver looks the signer's Ed25519 key up in its own
        /// `verified_nbcs[intermediate_emitter]` — warm from the KI#32 snapshot
        /// — exactly as ticks (KI#18), audit responses (KI#19) and approvals
        /// (KI#20) already do. 64 bytes on the wire buys the proven identity the
        /// whole §5.6.5 dual-uniqueness argument depends on.
        intermediate_sig: Vec<u8>,
    },

    /// TOMBSTONE — RETIRED 2026-09-30 (Fork Settlement §9q, design B2; YPX-025
    /// E3 → A1; owner ruling "fix it with ATRAXI"). NEVER emitted by this build:
    /// a HAL re-anchor floods as a plain `StateUpdate` carrying its `SeqProof`
    /// (`registration.rs` step 10), so its leg meets the ONE record hook on every
    /// receiver and a revival is judged as an A1 fork on evidence. The receiver
    /// (`GossipEngine::process`) verifies nothing, adopts nothing, freezes
    /// nothing and forwards nothing — it counts the drop (`haladvance_dropped`
    /// on /status) and returns.
    ///
    /// RULE 0 §4 — the WRONG reading this doc used to state: "the handler
    /// fork-checks `old_state` against the node's AUTHORITATIVE
    /// `previous_state[W]`" and "the k3 sigs make the conflicting branch
    /// unforgeable". `previous_state[W]` is the head the node's last put
    /// overwrote (a view, KI#235); the k3 sigs were checked against keys carried
    /// in the message (KI#233) and over the door's `current_tick`, which Lambda
    /// never signs (tick 0) — so a genuine revival never verified and the arm
    /// never froze on a real fork (§9q probe). `k3_signatures` / `required_k`
    /// below are read by nothing.
    ///
    /// APPENDED AT THE ENUM END ON PURPOSE (KI#34): bincode encodes variants by
    /// positional discriminant, so a new variant must go last — an un-upgraded peer
    /// then still decodes every pre-existing variant correctly, and only HalAdvance
    /// (emitted solely by upgraded nodes, only for HAL re-anchors) is undecodable on
    /// the old binary. Inserting it mid-enum would shift every later discriminant and
    /// corrupt Hibernation/TaintAlert/BanAlert across a mixed-version window.
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
        /// ~~k=3 witness sigs … Verified on receipt~~ — read by nothing since
        /// §9q (tombstone); kept only for the positional wire shape.
        k3_signatures: Vec<WitnessSig>,
        #[serde(default)]
        amount: u64,
        #[serde(default)]
        fee_breakdown: Vec<axiom_core_logic::types::FeeShare>,
        /// ~~KI#150 — the re-anchor's k, judged by `verify_hal_k3`~~ — that
        /// verifier was deleted with the E3 arm (§9q). LAST in the variant:
        /// bincode is positional.
        required_k: u8,
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
        /// YPX-025 A2 / KI#205 residual 1 — the reserver's RecallAttestation, carried
        /// on the RESERVATION (`committed: false`) flood so every node verifies the
        /// recall against the reserver's NBC key (binds T) BEFORE applying the marker,
        /// instead of trusting a peer's bare word (the mesh-wide griefing hole). The
        /// COMMIT (`committed: true`) flood carries `None`: a commit applies only where
        /// a VERIFIED reservation marker already exists (see `GossipEngine::process`).
        /// LAST in the variant — bincode is positional; a pre-fix node cannot decode it,
        /// so every node rolls before any node sends it.
        #[serde(default)]
        attestation: Option<axiom_core_logic::types::RecallAttestation>,
    },

    /// JFP/DWP vote-secret propagation (YP §8.4.3). Dedicated variant —
    /// KI#46 zero-pk flip: secrets used to ride a SYNTHETIC zero-pk
    /// `StateUpdate` (blake3-derived fake wallet id, seq 0), which planted
    /// junk entries in every receiving SMT and never actually populated the
    /// receivers' secret stores (`JfpSecretsRequest` against a non-target
    /// node returned empty). This variant carries the secret honestly:
    /// receivers store it per DWP wallet (same 100-per-wallet cap as the
    /// registration handler) and re-forward; nothing touches the SMT.
    /// Secrets are unnamed by design — no authorship to verify (the vote
    /// TX carries the hash; the secret is its preimage component).
    ///
    /// APPENDED LAST deliberately: bincode discriminants are positional, so
    /// inserting mid-enum would renumber every following variant and, during
    /// the coordinated roll window, let a not-yet-rolled node MISDECODE this
    /// as the variant that used to hold the index (`TaintAlert` — which
    /// FREEZES a wallet). At the end, a stale node simply fails to decode an
    /// unknown discriminant and drops the message. Keep new variants last.
    JfpSecret {
        /// Which DWP case this belongs to.
        dwp_wallet_id: WalletId,
        /// The vote secret (preimage component of vote hash).
        secret: [u8; 32],
    },
    /// FOB (Fixed Outflow Balance / Bounded Pools) epoch tranche statement
    /// (`AXIOM_DESIGN_BoundedPools.md` §4, §8). The epoch's mover committee
    /// broadcasts ONE statement covering every pool it tranched; receivers
    /// verify the movers (§5 eligibility via each `att`, sortition rank, and
    /// the per-mover `statement_sig`), audit each entry
    /// (`fob::audit_tranche_entry`), and reconcile (`fob::fob_reconcile`) into
    /// their per-validator FOB registry — or JUDOON-quarantine on a structural
    /// violation.
    ///
    /// APPENDED LAST deliberately (see the same note on `JfpSecret`): bincode
    /// discriminants are positional, so this MUST stay the final variant. A
    /// not-yet-rolled node fails to decode the unknown discriminant and drops
    /// the message — safe; inserting mid-enum would renumber every following
    /// variant during the roll window. Keep new variants last.
    FobTranche {
        epoch_id: u64,
        /// Fund class (§10.2a) — dev vs real; every entry applies to
        /// `(pool_id, is_dev)`. Bound into the signed statement payload.
        is_dev: bool,
        entries: Vec<crate::fob::TrancheEntry>,
        movers: Vec<crate::fob::FobMoverSig>,
    },
    /// YPX-022 §2.1.2a item 3 (KI#205, RULED 2026-09-25) — an AUTHENTICATED
    /// cheque claim, flooded so every recorder holds the delivery terminal
    /// `register_recall` reads (the sender's recall can land on ANY node).
    /// Carries exactly the `RegisterChequeClaimRequest` fields plus the
    /// originating node's `claim_tick`; a receiver rebuilds the request, re-runs
    /// `registration::verify_cheque_claim` against ITS OWN SMT head (a peer's
    /// bare word is never applied — RULE 3 shape 5) and stores it first-wins.
    /// LIVE emitter: the TCP claim path (`register_cheque_claim_core` → OK,
    /// newly stored) in `nabla_node.rs`. KI#156 deleted the earlier, dead,
    /// unauthenticated `ChequeClaim` variant on 2026-09-21; this is written
    /// fresh, not resurrected.
    ///
    /// APPENDED LAST deliberately (see the note on `JfpSecret`): bincode
    /// discriminants are positional, so this MUST stay the final variant until
    /// the next one is appended after it.
    ChequeClaimAnnounce {
        cheque_id: crate::types::TxHash,
        client_pk: Vec<u8>,
        k_tier: u8,
        wallet_address: String,
        claim_sig: Vec<u8>,
        claim_tick: u64,
    },
    /// ForkSettlement §2.3 [R25, R32] — ATRAXI A1: a SELF-PROVING fork claim
    /// (two wallet-signed, k-witnessed SEND legs from one `(client_pk,
    /// consumed)` key with different txids). The ONE adoptable ban variant: a
    /// receiver runs `ban::adopt_fork_claim` (→ `verify_fork_claim`, the one
    /// chokepoint) BEFORE banning, and forwards only a claim that verified and
    /// banned ≥1 new key — re-verified at every hop; an unverifiable claim is
    /// dropped, counted `atraxi_evidence_refused`, and NOT forwarded (no
    /// amplification). Carries no wallet id: the banned identities are
    /// DERIVED from the preimage key [R7].
    ///
    /// Emitted by `NablaNode::drain_fork_side_effects` → the binary's fan-out
    /// (`recv_loop` after each handled message, `tick_loop` once per
    /// iteration). Since §9o [R56] (W2) it is the ONLY ban-carrying gossip
    /// variant: `SeqForkBan` (check-3's) is a dropped, counted tombstone.
    ///
    /// APPENDED LAST deliberately (see the note on `JfpSecret`): bincode
    /// encodes the variant as a positional index. Every node must be rolled
    /// before any node emits it (the §13 rotation wipe gives that).
    ForkBan {
        claim: ForkClaim,
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
    /// YP §17.3.1.4 v2.19.0 (KI#150) — the group wallet's tier; the receipt
    /// needs `max(k_tier, 3)` sigs. LAST: bincode is positional.
    pub k_tier: u8,
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
///
/// `siblings` (2026-08-01, KI#48 follow-up) is the merkle path root→down from
/// the challenged prefix node — folding `subtree_hash` up along the prefix
/// bits with these siblings MUST reproduce `root_hash`
/// (`SparseMerkleTree::verify_subtree_proof`). Without it the response was
/// unverifiable: `subtree_hash` was neither signed nor checkable, so the
/// audit could only compare roots. Bincode struct fields are positional —
/// this field stays LAST before `signature`; all nodes roll together
/// (pre-mainnet, no wire back-compat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubtreeAuditResponse {
    pub prefix: Vec<u8>,
    pub prefix_bits: usize,
    pub subtree_hash: Hash256,
    pub root_hash: Hash256,
    pub response_tick: u64,
    pub responder_pk: PeerId,
    pub siblings: Vec<Hash256>,
    pub signature: Vec<u8>,
}

/// Proof that a QuestionableAlert's accusation actually holds.
///
/// Every field here is signed BY THE SUSPECT, so a receiver can verify the
/// accusation itself instead of trusting the reporter. That is the whole point:
/// the alert's own `signature` proves only WHO accused, never that the
/// accusation is true.
///
/// ~425 bytes: the audit response is `prefix_bits = 8`, so `siblings` is ~8
/// hashes, not the 8KB the §5.5 sketch implies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionableEvidence {
    /// The suspect's own signed audit answer. Proves what it claimed.
    pub audit_response: SubtreeAuditResponse,
    /// The suspect's signed TickHash advertisement for the same tick, when the
    /// claim is SELF-CONTRADICTION. `None` when the claim is a failed merkle
    /// proof, which the audit response proves on its own.
    pub advertised_root: Option<Hash256>,
    /// Signature over `tickhash_sign_payload(tick, advertised_root, suspect)`.
    pub advertised_sig: Vec<u8>,
}

/// Alert sent when a node flags its upstream as questionable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionableAlert {
    pub suspect_pk: PeerId,
    pub reporter_pk: PeerId,
    pub tick: u64,
    /// Commitment to `evidence`. Historically this hashed (tick, suspect,
    /// reporter) — three values the alert already carried in clear — so it
    /// committed to NOTHING and was a dedup key wearing the name of proof.
    pub evidence_hash: Hash256,
    pub signature: Vec<u8>,
    /// The proof. `None` = unproven assertion; a receiver MUST NOT detach on
    /// it. LAST field: bincode is positional.
    pub evidence: Option<QuestionableEvidence>,
}

/// Nabla node trust status — DERIVED from the peer's NBC at read time
/// (GUIDE §5.6c, KI#75): `cc::PeerTrust::trust_status(now_tick)`.
///
/// ⚠ This enum carries NO local time. Until 2026-09-25 `Probation { since }`
/// stored the receiving node's own `virtual_secs` at join — a local "joined
/// at" clock that a re-join or restart could reset, and that nothing in
/// production ever read (KI#75). §5.6c judges probation from the signed
/// certificate's `issued_at` alone, so the status is a pure function of
/// (NBC, now) and there is nothing to store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NbcTrustStatus {
    /// Genesis certificate (`chain_depth == 0`) — exempt from probation.
    Genesis,
    /// Citizen certificate older than `nabla_probation_ticks` — full trust.
    Confirmed,
    /// Citizen certificate inside the probation window — the five §5.6c
    /// levers apply (never a writer, not in OODS, no emission, Alerts
    /// withheld, serve-gate).
    Probation,
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
    /// YPX-003 §2.1 step 2 (KI#48, RULED 2026-09-25) — PARKED in a host's P
    /// slot: `up` is the host and its ticks are received and validated exactly
    /// like a D child's, but this is NOT a tree seat. `has_upstream()` stays
    /// false, so `needs_parent()` stays TRUE (the node keeps seeking a real D
    /// slot) and `is_self_writer()` stays false. `TardisNode::is_parked` is the
    /// ONE predicate that reads this.
    Pending,
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
    ///   BLAKE3("AXIOM_FACT_CONFIRM" || BLAKE3("AXIOM_TXHASH" || old_state || new_state)
    ///          || new_state || committed_at_tick.to_le_bytes())
    ///   — built ONLY by Core's canonical `fact_confirm_payload`, re-exported
    ///     through `crate::registration`. Never assemble it here.
    /// Core verifies this to ensure the NablaConfirmation is authentic.
    /// Computed at registration time using the same state IDs stored in the SMT.
    #[serde(default)]
    pub fact_confirm_signature: Vec<u8>,
    /// Fork Settlement W7d (§9k rulings 1 + 3) — this node's DERIVED
    /// provenance of the registrant's NEW state (`provenance::Provenance::
    /// view`), set at the dispatch layer after the register's drain. UX only:
    /// a held state is ACCEPTED and MARKED, never refused (a refusal would
    /// strand the burn exit), and nothing is pushed to the wallet — the hold is
    /// discovered here, at the next Nabla interaction. Unsigned and
    /// Nabla-only: never a Core input, CoreID-neutral (RULE 5 — the money
    /// defence is Core's settled-vouch rule, not this field). LAST;
    /// mandatory — no `serde(default)` (§13). Encoded like the rest of the ack
    /// (CBOR map for the SDK): `"provenance": "Ok" | "Wait" | {"Held": [txid…]}`.
    pub provenance: ProvenanceView,
}

/// W7d — what the register ack reports about the registrant's new state.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProvenanceView {
    /// Grounded in this node's records with no hold — its sends are vouched
    /// once Core's settle floor has passed.
    Ok,
    /// Not judgeable yet (an ancestor unrecorded here, a pending receive, or
    /// re-derivation queued) — the existing "settling" UX. The default of an
    /// ack built below the dispatch layer (fail closed, never `Ok`).
    #[default]
    Wait,
    /// Descends from a fork: nothing sent from this state is ever vouched by
    /// this node. Lists the HELD receives (cheque txids) — burning EXACTLY one
    /// such cheque's amount (a send to `BURN_ADDRESS`) releases that receive
    /// (ruling 2). Empty = no cheque listed: the wallet itself forked
    /// (unburnable), or > 32 roots collapsed into `provenance::Root::Overflow
    /// { owed }` — a burn LEDGER each burn pays down (KI#241 F-9, 2026-10-01;
    /// was "unburnable" for both).
    Held(Vec<TxHash>),
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
    /// §5.2.2c KI#132 — the registrant's own k-signed receipt says the wallet is
    /// stake-locked and the deadline has not passed. ARMOUR ONLY: Nabla fails
    /// open, so this keeps an HONEST node's SMT clean; the enforcement is Core's
    /// attested-tick gate and the CL5 redeem gate.
    #[error("stake-locked wallet may not register state until its wall-clock deadline")]
    StakeLocked,
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
    /// KI#205 (YPX-022 §2.2 register-door half) — a redeem-finalize register
    /// arrived for a txid whose recall has already COMMITTED. The recall won by
    /// TARDIS stamp (it committed; this redeem's register is the late one — an
    /// on-time redeem would have aborted the reservation before commit, §2.2.1).
    /// The receiver's redeem link is NEVER confirmed: it stays a permanent scar
    /// (receiver-consent to spend, inherited taint §1.5.1a, exit by burn), so
    /// exactly one of {recall, redeem} settles CLEANLY. This closes the measured
    /// double-settle where a witnessed-but-unregistered redeem re-registered
    /// clean AFTER the recall completed. Symmetric with `mark_txid_redeemed`
    /// aborting an OPEN reservation (redeem wins the *reservation* race).
    #[error("redeem refused: this txid's recall has committed — the payment was reclaimed first; the link stays a scar (KI#205, first-wins)")]
    RedeemAfterRecallCommitted,
    /// ForkSettlement §2.3 [R17] / [R‑MEDIUM-3] — register door step 5b′: the
    /// registration's carried leg (`Registration::preimage`) does not reproduce
    /// what the k validators signed (commitment_hash / txid), disagrees with the
    /// message's unsigned `old_state` / `client_pk` / seq, or the receipt lacks
    /// ≥ max(k_tier, 3) distinct valid `receipt_commitment_sig`s. Nothing is
    /// stored. Wire code `E_NABLA_LEG_UNVERIFIABLE` (nabla_node.rs register
    /// Err arm); counted on /status as `leg_preimage_refused`.
    #[error("registration leg unverifiable ({0}) — the carried preimage/witness sigs do not reproduce the k-signed receipt (ForkSettlement R17)")]
    LegUnverifiable(crate::registration::LegRefusal),
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
    #[error("wallet is not banned")]
    WalletNotBanned,
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
    /// KI#224 (owner ruling 2026-10-02) — register door step 5b⁗: a witness
    /// key in the registration's k-signed receipt is not the subject of an
    /// R42 directory entry at THIS node (`ban::seq_proof_is_directory_witnessed`,
    /// ALL keys). Nothing is stored (the leg is still recorded, ungraded, at
    /// 5b‴ [R30]). RETRYABLE: a node whose directory is still filling (fresh /
    /// wiped, or a validator stamped elsewhere before R50 AE brought its
    /// entry) refuses an honest head here; another node — or this one after
    /// admission — accepts it. Wire `E_NABLA_WITNESS_NOT_IN_DIRECTORY|key=..`
    /// (the SDK walk treats it as "try the next Nabla"); counted on /status as
    /// `witness_not_in_directory_refused`.
    #[error("witness key {} is not in this node's R42 witness directory (KI#224) — retry on another Nabla", hex::encode(&.0[..4]))]
    WitnessNotInDirectory([u8; 32]),
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

    /// KI#77 — an UNATTESTABLE local head must yield to an ATTESTED remote one,
    /// even when the local seq is higher.
    ///
    /// The exact shape that stranded six heads after KI#73: the holder kept a
    /// head it could not prove, rule 2 gave it the win on raw seq, and every
    /// peer refused its push (`seq-unattested proof=ABSENT`). Permanent
    /// divergence with no route out but a data wipe — which mainnet lacks.
    #[test]
    fn ki77_unattestable_local_head_yields_to_attested_remote() {
        let mine = ki77_entry(0xAA, 22, 500);     // higher seq, NO proof
        let theirs = ki77_entry(0xBB, 21, 400);   // lower seq, ATTESTED

        assert!(mine.superseded_by(&theirs, false, true),
            "KI#77: a head we cannot attest must lose to one we can — a bare \
             wallet_seq is FORGEABLE, which is why SeqProof exists; trusting an \
             unprovable higher seq over a proven lower one inverts rule 2's premise");

        assert!(!mine.superseded_by(&theirs, true, true),
            "with both attested, rule 2 governs again and the higher seq wins");
    }

    /// ONE-DIRECTIONAL. An attested local head must NOT block an unattested
    /// incoming, or every wallet whose updates carry no proof freezes mesh-wide
    /// — a worse bug than the divergence being fixed.
    #[test]
    fn ki77_attested_local_does_not_block_unattested_progress() {
        let mine = ki77_entry(0xAA, 6, 100);
        let theirs = ki77_entry(0xBB, 7, 200);
        assert!(mine.superseded_by(&theirs, true, false),
            "KI#77 must not block advancement: a symmetric rule broke \
             ki38_equal_seq_adopt_clears_stale_proof and would freeze the head of \
             any wallet whose updates legitimately carry no proof");
    }

    fn ki77_entry(state: u8, seq: u64, tick: u64) -> NablaEntry {
        NablaEntry {
            received_from: None,
            wallet_seq: seq, wallet_id: [0x77; 32],
            current_state: [state; 32], tx_hash: [state ^ 0xFF; 32],
            tick, group_members: None, status: WalletStatus::Normal,
            client_pk: [9u8; 32], client_sig: vec![1u8; 64],
        }
    }

    fn entry(tick: u64, state: u8, status: WalletStatus) -> NablaEntry {
        NablaEntry {
            received_from: None,
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
            txid, &state_hash, wallet_seq, &commitment_hash, epoch, is_dev_class, None, None,
            None,
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
        SeqProof { state_hash, commitment_hash, epoch, is_dev_class, oods_flag: None, confidence_index: None, sigs, sender_state: None, required_k: 3, preimage: crate::types::test_legs::opaque_redeem_leg() /* wave 2a: minted over an arbitrary txid — a Send leg could not reproduce it */, declared: crate::types::test_legs::no_declared() }
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
            sender_state: None,
            oods_flag: None,
            confidence_index: None,
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
            required_k: 3,
            preimage: crate::types::test_legs::opaque_redeem_leg(), // wave 2a — test proof, no WITNESS_V2 preimage
            declared: crate::types::test_legs::no_declared(),
        };
        assert!(!verify_seq_proof(&forged, &txid, 5), "forged sigs must fail");
    }

    #[test]
    fn higher_tick_supersedes() {
        let a = entry(10, 1, WalletStatus::Normal);
        let b = entry(11, 1, WalletStatus::Normal);
        assert!(a.superseded_by(&b, true, true));
        assert!(!b.superseded_by(&a, true, true));
    }

    #[test]
    fn same_tick_higher_state_wins() {
        let a = entry(10, 1, WalletStatus::Normal);
        let b = entry(10, 2, WalletStatus::Normal);
        assert!(a.superseded_by(&b, true, true));
        assert!(!b.superseded_by(&a, true, true));
    }

    #[test]
    fn identical_entry_does_not_supersede() {
        let a = entry(10, 1, WalletStatus::Normal);
        let b = entry(10, 1, WalletStatus::Normal);
        assert!(!a.superseded_by(&b, true, true));
        assert!(!b.superseded_by(&a, true, true));
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
            !honest_head.superseded_by(&fraud_fork, true, true),
            "WI3: an ancestor-fork (lower k-seq) must NOT supersede the honest head, \
             even with a higher (later) tick."
        );
        // And the honest head DOES supersede the fork (higher k-seq wins).
        assert!(
            fraud_fork.superseded_by(&honest_head, true, true),
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
        assert!(a.superseded_by(&b, true, true), "equal seq → higher tick wins");
    }

    #[test]
    fn unauthored_debris_never_outranks_authored() {
        // AE-convergence fix (2026-08-01): a zero-pk NON-GROUP entry is one
        // every node rejects from a peer — structurally unreplicable debris.
        // It must lose to an authored entry whatever its tick or byte-order,
        // and never supersede one. (Pre-fix, a debris variant with tick+1
        // held one node hostage: it refused the authored head via the tick
        // tiebreak while its own push was refused mesh-wide — 7 frozen
        // distinct roots, 6-8k reconciles, 0 applied.)
        let mut debris = entry(500, 0x22, WalletStatus::Normal); // later tick
        debris.client_pk = [0u8; 32];
        debris.client_sig = vec![];
        let authored = entry(100, 0x22, WalletStatus::Normal); // earlier tick

        assert!(
            debris.superseded_by(&authored, true, true),
            "authored must replace unauthored debris despite lower tick"
        );
        assert!(
            !authored.superseded_by(&debris, true, true),
            "unauthored debris must never supersede an authored entry"
        );

        // Higher debris seq still loses — legitimacy ranks before seq.
        let mut high_seq_debris = debris.clone();
        high_seq_debris.wallet_seq = 7;
        assert!(high_seq_debris.superseded_by(&authored, true, true));
        assert!(!authored.superseded_by(&high_seq_debris, true, true));

        // Group-wallet entries carry zero pk BY DESIGN and rank as
        // legitimate: normal seq/tick ordering applies.
        let mut group_old = entry(100, 0x22, WalletStatus::Normal);
        group_old.client_pk = [0u8; 32];
        group_old.group_members = Some(vec![]);
        let mut group_new = group_old.clone();
        group_new.tick = 500;
        assert!(group_old.superseded_by(&group_new, true, true), "group entries keep tick ordering");
        assert!(!group_new.superseded_by(&group_old, true, true));

        // Freeze monotonicity still dominates legitimacy: an unauthored
        // FROZEN entry (ban path) is not demoted by an authored Normal.
        let mut frozen_debris = entry(1, 0x22, WalletStatus::Frozen);
        frozen_debris.client_pk = [0u8; 32];
        assert!(!frozen_debris.superseded_by(&authored, true, true));
    }

    #[test]
    fn freeze_dominates_normal_regardless_of_tick() {
        // A frozen entry at a LOWER tick still wins over a higher-tick
        // Normal — §32 freeze monotonicity: a fork-frozen wallet is
        // never demoted back to Normal by a later state update.
        let normal_new = entry(100, 5, WalletStatus::Normal);
        let frozen_old = entry(1, 1, WalletStatus::Frozen);
        assert!(normal_new.superseded_by(&frozen_old, true, true));
        assert!(!frozen_old.superseded_by(&normal_new, true, true));
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
                let (ab, ba) = (a.superseded_by(b, true, true), b.superseded_by(a, true, true));
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
            if x.superseded_by(y, true, true) { y.clone() } else { x.clone() }
        };
        let w1 = pick(&pick(&a, &b), &c);
        let w2 = pick(&pick(&c, &a), &b);
        let w3 = pick(&pick(&b, &c), &a);
        assert_eq!(w1, w2);
        assert_eq!(w2, w3);
        assert_eq!(w1.status, WalletStatus::Frozen);
    }

    /// The Nabla-side subsidy pool registers MUST equal the FACT #0 sub-pool
    /// declarations in Core. They are declared in two crates from two tuning
    /// sources, so nothing but this test stops them drifting — and a drift is
    /// not cosmetic: Nabla decides whether a grant can be funded from ITS
    /// balance, so a Nabla that starts richer than FACT #0 declares would hand
    /// out coins the genesis supply never contained.
    #[test]
    fn subsidy_pools_match_fact_zero_declarations() {
        use axiom_core_logic::genesis_integrity::{build_genesis_fact, SubPoolId};
        let fact = build_genesis_fact(1);
        let declared = |id: SubPoolId| -> u64 {
            fact.sub_pools.iter()
                .find(|p| p.pool_id == id)
                .unwrap_or_else(|| panic!("{id:?} must exist in FACT #0"))
                .initial_balance
        };
        // FACT #0 declares whole AXC; the Nabla constants are in atoms.
        assert_eq!(
            crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS,
            axiom_denomination::axc(declared(SubPoolId::Bootstrap)),
            "Bootstrap pool register disagrees with FACT #0",
        );
        assert_eq!(
            crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS,
            axiom_denomination::axc(declared(SubPoolId::FoundationBootstrap)),
            "FoundationBootstrap pool register disagrees with FACT #0",
        );
    }

    /// Appending PoolKind variants must not disturb any existing sign_tag —
    /// a moved tag would invalidate in-flight PoolSync signatures mesh-wide.
    #[test]
    fn appended_pool_kinds_do_not_move_existing_sign_tags() {
        assert_eq!(PoolKind::Airdrop.sign_tag(), 0x01);
        assert_eq!(PoolKind::DevTreasury.sign_tag(), 0x02);
        assert_eq!(PoolKind::Deed.sign_tag(), 0x03);
        assert_eq!(PoolKind::DevDeed.sign_tag(), 0x04);
        assert_eq!(PoolKind::BoundedFee([0u8; 32], false).sign_tag(), 0x05);
        // The new ones take fresh tags at the end.
        assert_eq!(PoolKind::Bootstrap.sign_tag(), 0x06);
        assert_eq!(PoolKind::FoundationBootstrap.sign_tag(), 0x07);
        // And every tag is distinct — a collision would let one pool's
        // PoolSync signature be replayed onto another pool.
        let tags = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let uniq: std::collections::BTreeSet<u8> = tags.iter().copied().collect();
        assert_eq!(uniq.len(), tags.len(), "sign_tag collision");
    }

    /// The two subsidy pools must persist to DISTINCT files, or a restart
    /// would load one pool's balance into the other and cross-credit tiers.
    #[test]
    fn subsidy_pools_persist_to_distinct_files() {
        let all = [
            PoolKind::Airdrop.state_filename(),
            PoolKind::DevTreasury.state_filename(),
            PoolKind::Deed.state_filename(),
            PoolKind::DevDeed.state_filename(),
            PoolKind::Bootstrap.state_filename(),
            PoolKind::FoundationBootstrap.state_filename(),
        ];
        let uniq: std::collections::BTreeSet<&str> = all.iter().copied().collect();
        assert_eq!(uniq.len(), all.len(), "two pools share a state file");
    }
}

/// ForkSettlement wave 3 — the ONE test builder of a GENUINE send leg (RULE 1:
/// every fork/origin test builds legs here; nothing pins a hash). Everything
/// is DERIVED with the production builders: the preimage's `commitment_hash`
/// and `txid` (`WitnessPreimage::{commitment_hash, txid}`), `new_state` via
/// Core's `compute_produced_state_id` (pk ‖ balance ‖ seq ‖ consumed ‖ nonce —
/// NOT the receiver, which is why an equal-amount, equal-nonce pair to two
/// receivers shares one `new_state` [R31]), max(k,3) REAL Ed25519 validator
/// sigs over `compute_receipt_commitment`, and the wallet's sig over
/// `client_state_sign_payload(smt_bucket(pk, k), new_state, tx_hash)`.
#[cfg(test)]
pub(crate) mod test_legs {
    use super::{ForkLeg, SeqProof, SeqProofSig, StateId, WalletId};
    use axiom_core_logic::types::WitnessPreimage;
    use ed25519_dalek::{Signer, SigningKey};

    /// KI#224 — a witness directory that holds EVERY key: the directory
    /// argument for unit tests of `registration::process_registration` /
    /// `GossipEngine::process` that are NOT about the directory and sign
    /// with ad-hoc keys. It is an explicit argument at each call, never a
    /// bypass inside the door; the KI#224 tests pass a real predicate, and
    /// `NablaNode` tests use the node's own directory
    /// (`admit_test_validators`).
    pub(crate) fn dir_admits_all(_: &[u8; 32]) -> bool {
        true
    }

    /// Fork Settlement W7a — a `Redeem` leg for a test PROOF whose leg is
    /// never run through `registration::verify_leg_preimage` (signature-only
    /// fixtures, persisted-shape / wire round-trips). Before W7a these sites
    /// used the unit `LegPreimage::Redeem` ("no preimage"); the variant now
    /// carries a `RedeemPreimage`, and this one reproduces NOTHING — any path
    /// that verifies the leg refuses it (`RedeemPreimageMismatch` or an
    /// earlier field check). Use [`redeem_leg_for`] where a verified redeem leg
    /// is meant.
    pub(crate) fn opaque_redeem_leg() -> super::LegPreimage {
        super::LegPreimage::Redeem {
            redeem: axiom_core_logic::types::RedeemPreimage {
                cheque_txid: [0xC4; 32],
                receiver_pk: [0xC5; 32],
                new_balance: 0,
                new_state_id: [0xC6; 32],
                consumed_state_id: [0xC7; 32],
            },
            cheque: stray_origin([0xC4; 32]),
        }
    }

    /// KI#241 F-2 — the cheque origin a receiver carries for send leg `send`
    /// (its `WitnessPreimage`, witnessed at [`EPOCH`], kind `Send`):
    /// `origin_txid(&origin_of(send)) == send.tx_hash`.
    pub fn origin_of(send: &ForkLeg) -> axiom_core_logic::types::OriginRecord {
        let preimage = send.send_preimage().expect("origin_of: a SEND leg").clone();
        let o = axiom_core_logic::types::OriginRecord {
            preimage,
            epoch: send.seq_proof.epoch,
            kind: axiom_core_logic::types::LegKind::Send,
        };
        assert_eq!(origin_txid(&o), send.tx_hash, "origin_of: the leg's own txid");
        o
    }

    /// KI#241 F-2 — the origin of a cheque from a sender that is NEVER recorded
    /// at the node under test (distinct per `tag`, gross `amount`). Its txid
    /// ([`origin_txid`]) is the cheque txid a redeem of it registers under.
    pub fn stray_origin_amount(tag: [u8; 32], amount: u64) -> axiom_core_logic::types::OriginRecord {
        axiom_core_logic::types::OriginRecord {
            preimage: WitnessPreimage {
                consumed_state_id: tag,
                client_pk: [0xEE; 32],
                wallet_seq: 1,
                receiver_wallet_id: "stray@axiom.internal/0123456789".to_string(),
                amount,
                nonce: 1,
            },
            epoch: EPOCH,
            kind: axiom_core_logic::types::LegKind::Send,
        }
    }

    /// [`stray_origin_amount`] at a fixed 1 000-atom amount (fixtures that
    /// only need a distinct, genuinely-bound cheque).
    pub fn stray_origin(tag: [u8; 32]) -> axiom_core_logic::types::OriginRecord {
        stray_origin_amount(tag, 1_000)
    }

    /// The cheque txid an origin reproduces (`preimage.txid(epoch)`).
    pub fn origin_txid(o: &axiom_core_logic::types::OriginRecord) -> [u8; 32] {
        o.preimage.txid(o.epoch)
    }

    std::thread_local! {
        /// Origins minted by [`cheque_txid`] in THIS test thread, by txid.
        static CHEQUES: std::cell::RefCell<std::collections::HashMap<[u8; 32], axiom_core_logic::types::OriginRecord>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
    }

    /// KI#241 F-2 — for SIGNATURE-ONLY fixtures that mint a proof over a txid
    /// and later [`bind_redeem_leg`] it: the txid of [`stray_origin`]`(tag)`,
    /// with the origin recorded so `bind_redeem_leg` can carry it. Use this
    /// wherever such a fixture used an arbitrary literal txid.
    pub fn cheque_txid(tag: [u8; 32]) -> [u8; 32] {
        let o = stray_origin(tag);
        let t = origin_txid(&o);
        CHEQUES.with(|c| c.borrow_mut().insert(t, o));
        t
    }

    /// Fork Settlement W7b — a `declared` for a SIGNATURE-ONLY fixture proof
    /// (never recorded as a producer; `bind_redeem_leg` resets it to the seq
    /// it binds).
    pub(crate) fn no_declared() -> super::DeclaredState {
        super::DeclaredState { balance: 0, wallet_seq: 0 }
    }

    /// Fork Settlement W7a — a GENUINE redeem leg: its preimage names the
    /// carrier's `(cheque_txid = tx_hash, receiver_pk = client_pk, consumed,
    /// new_state)`, and the returned `commitment_hash` is Core's ONE
    /// recompute of it — the value k witnesses sign for this redeem.
    ///
    /// KI#241 F-2: `cheque` is the cheque's origin; `cheque_txid` is ITS txid.
    pub(crate) fn redeem_leg_for(
        cheque: &axiom_core_logic::types::OriginRecord,
        receiver_pk: [u8; 32],
        consumed_state_id: StateId,
        new_state_id: StateId,
        new_balance: u64,
    ) -> (super::LegPreimage, [u8; 32]) {
        let p = axiom_core_logic::types::RedeemPreimage {
            cheque_txid: origin_txid(cheque), receiver_pk, new_balance, new_state_id, consumed_state_id,
        };
        let ch = p.commitment_hash();
        (super::LegPreimage::Redeem { redeem: p, cheque: cheque.clone() }, ch)
    }

    /// Balance before every test leg; `new_balance = START - amount`.
    pub const START_BALANCE: u64 = 1_000_000;
    /// Epoch every test leg is witnessed in.
    pub const EPOCH: u64 = 1_790_000_007;
    /// The wall-clock `now_secs` (the binary's `virtual_secs`, [R13]) tests
    /// pass to the record-creating paths. Deliberately NOT a tick value.
    pub const NOW_SECS: u64 = 1_790_000_100;

    /// Deterministic validator keys (real keypairs from fixed seeds).
    pub fn validator(i: u8) -> SigningKey {
        SigningKey::from_bytes(&[0x10u8.wrapping_add(i); 32])
    }

    /// A wallet key from a seed byte.
    pub fn wallet(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Fork Settlement W7c — the wallet's OPENING state (§6c, the ONE
    /// builder): a structural provenance root. A test leg that must be
    /// VOUCHED consumes this (or a state derived from it); an arbitrary
    /// consumed state is ungrounded, so its send is never vouched (M2).
    pub fn opening(sk: &SigningKey) -> StateId {
        axiom_core_logic::genesis::opening_state_id_for(
            &sk.verifying_key().to_bytes(),
            axiom_core_logic::wallet_id::K_DEFAULT,
            axiom_core_logic::wallet_id::PROOF_TYPE_DMAP,
        )
    }

    /// The wallet's client sig over an ARBITRARY bucket — the framing tool
    /// (sign over someone else's bucket) and the honest case alike.
    pub fn client_sig_over(sk: &SigningKey, bucket: &WalletId, new_state: &StateId, tx_hash: &[u8; 32]) -> Vec<u8> {
        let payload = crate::registration::client_state_sign_payload(bucket, new_state, tx_hash);
        sk.sign(&payload).to_bytes().to_vec()
    }

    /// A genuine, k-witnessed, wallet-signed send leg `consumed → new_state`.
    pub fn genuine_send_leg(
        sk: &SigningKey,
        consumed: StateId,
        seq: u64,
        receiver: &str,
        amount: u64,
        nonce: u64,
        k: u8,
    ) -> ForkLeg {
        send_leg_at(sk, consumed, seq, receiver, amount, nonce, k, START_BALANCE - amount, START_BALANCE - amount)
    }

    /// A GENESIS-CLAIM send leg as the SDK registers it: from the wallet's
    /// OPENING state at seq 1, producing the state Core's ONE post-tx balance
    /// rule (`compute_post_tx_balance`, genesis arm, over
    /// `genesis_opening_balance`) produces — DERIVED from Core, never typed
    /// here (RULE 1) — and declaring the wallet's balance, which is that same
    /// UNCHANGED balance (YP §17.11.2 step 3, KI#251). ⚠ Until 2026-10-02 this
    /// fixture hardcoded the CREDITED state (`amount`) with a separate
    /// declared balance (design §9m A1) — mirroring Core's send-side credit,
    /// which was the defect. If Core ever credits at the send again the leg's
    /// produced state stops matching the declared 0 and S11 goes red.
    pub fn genesis_claim_leg(sk: &SigningKey, receiver: &str, amount: u64, nonce: u64) -> ForkLeg {
        let pk = sk.verifying_key().to_bytes();
        let tx = axiom_core_logic::types::Transaction {
            kind: axiom_core_logic::types::TxKind::GenesisClaim,
            amount,
            ..Default::default()
        };
        let declared = axiom_core_logic::genesis::genesis_opening_balance(&pk);
        let produced = axiom_core_logic::validation::compute_post_tx_balance(&tx, declared)
            .expect("Core's claim balance rule");
        send_leg_at(sk, opening(sk), 1, receiver, amount, nonce, 3, produced, declared)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_leg_at(
        sk: &SigningKey,
        consumed: StateId,
        seq: u64,
        receiver: &str,
        amount: u64,
        nonce: u64,
        k: u8,
        produced_balance: u64,
        declared_balance: u64,
    ) -> ForkLeg {
        let client_pk = sk.verifying_key().to_bytes();
        let preimage = WitnessPreimage {
            consumed_state_id: consumed,
            client_pk,
            wallet_seq: seq,
            receiver_wallet_id: receiver.to_string(),
            amount,
            nonce,
        };
        let commitment_hash = preimage.commitment_hash();
        let tx_hash = preimage.txid(EPOCH);
        let new_state = axiom_core_logic::compute::compute_produced_state_id(
            &client_pk, produced_balance, seq, &consumed, nonce,
        );
        // Bound into the receipt commitment the k sign; nothing on the fork
        // path recomputes it, so a fixed value is faithful here.
        let state_hash = [0x5au8; 32];
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            &tx_hash, &state_hash, seq, &commitment_hash, EPOCH, false, None, None, None,
        );
        let n = (k as usize).max(3);
        let sigs = (0..n as u8)
            .map(|i| {
                let v = validator(i);
                SeqProofSig {
                    validator_pk: v.verifying_key().to_bytes(),
                    receipt_commitment_sig: v.sign(&commitment).to_bytes().to_vec(),
                }
            })
            .collect();
        let bucket = crate::registration::smt_bucket(&client_pk, k);
        ForkLeg {
            new_state,
            tx_hash,
            client_sig: client_sig_over(sk, &bucket, &new_state, &tx_hash),
            seq_proof: SeqProof {
                state_hash,
                commitment_hash,
                epoch: EPOCH,
                is_dev_class: false,
                oods_flag: None,
                confidence_index: None,
                sender_state: None,
                sigs,
                required_k: k,
                preimage: crate::types::LegPreimage::Send(preimage),
                // W7b R52d: the declared balance + seq (`genuine_send_leg`: the
                // ones `new_state` was produced from).
                declared: super::DeclaredState { balance: declared_balance, wallet_seq: seq },
            },
        }
    }

    /// Fork Settlement W7b — a GENUINE, k-witnessed, wallet-signed REDEEM leg:
    /// receiver `sk` redeems cheque `cheque_txid` from its state `consumed`
    /// (non-zero for a recordable leg), producing `new_state` at
    /// `new_balance`, at receiver seq `seq` (unchanged by a receive). The k
    /// sign `compute_receipt_commitment(cheque_txid, …, seq, redeem
    /// commitment, …)`; the wallet signs over `smt_bucket(pk, k)`.
    pub fn genuine_redeem_leg(
        sk: &SigningKey,
        consumed: StateId,
        cheque: &axiom_core_logic::types::OriginRecord,
        new_balance: u64,
        seq: u64,
        k: u8,
    ) -> ForkLeg {
        let cheque_txid = origin_txid(cheque);
        let client_pk = sk.verifying_key().to_bytes();
        let new_state = axiom_core_logic::validation::compute_redeem_state_id(
            &client_pk, new_balance, seq, &cheque_txid,
        );
        let (preimage, commitment_hash) =
            redeem_leg_for(cheque, client_pk, consumed, new_state, new_balance);
        let state_hash = [0x5bu8; 32];
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            &cheque_txid, &state_hash, seq, &commitment_hash, EPOCH, false, None, None, None,
        );
        let n = (k as usize).max(3);
        let sigs = (0..n as u8)
            .map(|i| {
                let v = validator(i);
                SeqProofSig {
                    validator_pk: v.verifying_key().to_bytes(),
                    receipt_commitment_sig: v.sign(&commitment).to_bytes().to_vec(),
                }
            })
            .collect();
        let bucket = crate::registration::smt_bucket(&client_pk, k);
        ForkLeg {
            new_state,
            tx_hash: cheque_txid,
            client_sig: client_sig_over(sk, &bucket, &new_state, &cheque_txid),
            seq_proof: SeqProof {
                state_hash,
                commitment_hash,
                epoch: EPOCH,
                is_dev_class: false,
                oods_flag: None,
                confidence_index: None,
                sender_state: None,
                sigs,
                required_k: k,
                preimage,
                declared: super::DeclaredState { balance: new_balance, wallet_seq: seq },
            },
        }
    }
    /// Fork Settlement §9o [R58] (W1) — the SAME leg (same preimage, txid,
    /// `new_state`, `client_sig`) witnessed by a DIFFERENT key set: every key
    /// signs the receipt commitment exactly as `registration::verify_seq_proof`
    /// recomputes it (the leg's own proof fields and signed seq), so the copy
    /// VERIFIES — keys outside a node's R42 directory make it an UNGRADED
    /// ("junk-witnessed") copy there.
    pub fn rewitness(leg: &ForkLeg, keys: &[SigningKey]) -> ForkLeg {
        let p = &leg.seq_proof;
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            &leg.tx_hash, &p.state_hash, leg.signed_seq(), &p.commitment_hash, p.epoch, p.is_dev_class,
            p.oods_flag.as_ref(), p.confidence_index.as_ref(), p.sender_state.as_ref(),
        );
        let mut out = leg.clone();
        out.seq_proof.sigs = keys
            .iter()
            .map(|k| SeqProofSig {
                validator_pk: k.verifying_key().to_bytes(),
                receipt_commitment_sig: k.sign(&commitment).to_bytes().to_vec(),
            })
            .collect();
        out
    }

    /// Keys that are NOT test validators — never in a test node's directory.
    pub fn junk_witness(i: u8) -> SigningKey {
        SigningKey::from_bytes(&[0xE0u8.wrapping_add(i); 32])
    }

    /// The REGISTER that carries `leg` — every field DERIVED from the leg (so
    /// the door's 5a′ client sig, 5b′ leg recompute and quorum checks pass on
    /// the leg's own bytes): `wallet_id` = the leg's bucket (= pk for k ≥ 3),
    /// `old_state` = the preimage's consumed state, the k sigs become the
    /// receipt's `receipt_commitment_sig`s, and the legacy step-5 `signature`
    /// is each SAME validator's genuine Ed25519 sig over
    /// `receipt_sign_payload(wallet_id, consumed, tick = 0)` — so the door
    /// passes with a REAL node signer (`Ed25519Signer`, the multi-node gate
    /// `fork_detection_mesh`), not only with `NoopSigner`.
    pub fn registration_of(leg: &ForkLeg) -> (super::Registration, super::DeedTransaction) {
        // Send or redeem (W7b): the consumed state, key and seq come from the
        // leg's own accessors; the amount is the send's (0 for a redeem — the
        // declared fee-cap amount of a receive), the balance the leg's declared.
        let (consumed, client_pk, seq) = (leg.consumed(), leg.client_pk(), leg.signed_seq());
        let amount = leg.send_preimage().map(|p| p.amount).unwrap_or(0);
        let wallet_id = leg.bucket();
        let step5 = crate::crypto::receipt_sign_payload(&wallet_id, &consumed, 0);
        let signatures = leg
            .seq_proof
            .sigs
            .iter()
            .enumerate()
            .map(|(i, s)| super::WitnessSig {
                validator_pk: s.validator_pk,
                signature: {
                    let v = validator(i as u8);
                    assert_eq!(v.verifying_key().to_bytes(), s.validator_pk,
                        "genuine_send_leg signs slot i with validator(i)");
                    v.sign(&step5).to_bytes().to_vec()
                },
                execution_proof: vec![],
                proof_type: 0,
                receipt_commitment_sig: s.receipt_commitment_sig.clone(),
                validator_id: [0u8; 32],
                slot_amount: 0,
            })
            .collect();
        let reg = super::Registration {
            declared_balance: leg.seq_proof.declared.balance,
            declared_hibernation_until: 0,
            declared_wall_clock_lock: 0,
            declared_emission_claimed_epoch: 0,
            declared_stake_floor_until: 0,
            declared_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
            fob_claim: None,
            k_tier: leg.k_tier(),
            is_recall: false,
            wallet_id,
            old_state: consumed,
            new_state: leg.new_state,
            tx_hash: leg.tx_hash,
            receipt: super::K3Receipt {
                sender_state: None,
                oods_flag: None,
                confidence_index: None,
                consumed_state_id: consumed,
                produced_state_id: leg.new_state,
                amount,
                signatures,
                program_digest: [0u8; 32],
                tick: 0,
                state_hash: leg.seq_proof.state_hash,
                new_wallet_seq: seq,
                commitment_hash: leg.seq_proof.commitment_hash,
                epoch: leg.seq_proof.epoch,
                fee_breakdown: vec![],
                is_dev_class: false,
            },
            client_pk,
            client_sig: leg.client_sig.clone(),
            is_genesis_claim: false,
            is_hal_reanchor: false,
            claimant_wallet_id: String::new(),
            is_dev_claim: false,
            burn_target_tx_id: None,
            preimage: leg.seq_proof.preimage.clone(),
        };
        let deed = super::DeedTransaction {
            sender_wallet_id: wallet_id,
            receiver_wallet_id: crate::registration::DEED_PROTOCOL_WALLET_ID,
            amount: crate::constants::DEED_WRITE_FEE,
            signature: vec![0xFF; 64],
        };
        (reg, deed)
    }

    /// The StateUpdate flood that carries `leg` — the shape the register door
    /// floods (`wallet_id` = the leg's bucket, the wallet's own client sig, the
    /// leg inside the `SeqProof`). `msg_parent` is the UNSIGNED message
    /// `old_state` (all-zero = "parent unknown", the replay shape).
    pub fn flood_of(leg: &ForkLeg, msg_parent: StateId, tick: u64) -> super::GossipMessage {
        super::GossipMessage::StateUpdate {
            wallet_id: leg.bucket(),
            new_state: leg.new_state,
            old_state: msg_parent,
            tx_hash: leg.tx_hash,
            tick,
            is_genesis_claim: false,
            wallet_seq: leg.signed_seq(),
            client_pk: leg.client_pk(),
            client_sig: leg.client_sig.clone(),
            amount: 0,
            fee_breakdown: Vec::new(),
            seq_proof: Some(leg.seq_proof.clone()),
        }
    }

    /// The AE form of `leg` (`NablaEntry` + its `SeqProof`, what
    /// `apply_remote_entry` receives from `AeReconcile` / `AeEntries`).
    pub fn entry_of(leg: &ForkLeg, tick: u64) -> super::NablaEntry {
        super::NablaEntry {
            wallet_id: leg.bucket(),
            current_state: leg.new_state,
            tx_hash: leg.tx_hash,
            tick,
            wallet_seq: leg.signed_seq(),
            group_members: None,
            status: super::WalletStatus::Normal,
            client_pk: leg.client_pk(),
            client_sig: leg.client_sig.clone(),
            received_from: None,
        }
    }

    /// Fork Settlement W7a — rebind a SIGNATURE-ONLY test proof (minted over an
    /// arbitrary txid, pre-W7a carried as the unit `Redeem` "no preimage") to a
    /// GENUINE redeem leg for its carrier (`tx_hash`, `client_pk`, `consumed`,
    /// `new_state`), so the flood / AE leg check (`verify_seq_proof_leg`) —
    /// which since W7a verifies redeem legs — passes on genuine bytes.
    /// `commitment_hash` becomes the leg's recompute and each slot is RE-SIGNED
    /// over the new receipt commitment ONLY if it was genuinely valid before
    /// and its key is one of `SigningKey::from_bytes([key_base + i; 32])`
    /// (i < 32) — a deliberately forged or foreign slot stays invalid, so a
    /// sub-quorum / forged fixture keeps its meaning.
    ///
    /// KI#241 F-2: a redeem leg carries its cheque's ORIGIN, and the door / flood
    /// / AE refuse it unless `origin.txid == tx_hash` — an arbitrary txid has no
    /// origin. So `tx_hash` MUST come from [`cheque_txid`]`(tag)`, which records
    /// the origin this looks up (panics otherwise, naming the fix).
    pub fn bind_redeem_leg(
        proof: &mut SeqProof,
        tx_hash: &[u8; 32],
        client_pk: [u8; 32],
        consumed: StateId,
        new_state: StateId,
        wallet_seq: u64,
        key_base: u8,
    ) {
        use ed25519_dalek::Verifier;
        let commit = |ch: &[u8; 32]| axiom_core_logic::compute::compute_receipt_commitment(
            tx_hash, &proof.state_hash, wallet_seq, ch, proof.epoch, proof.is_dev_class,
            proof.oods_flag.as_ref(), proof.confidence_index.as_ref(), proof.sender_state.as_ref(),
        );
        let old = commit(&proof.commitment_hash);
        let cheque = CHEQUES.with(|c| c.borrow().get(tx_hash).cloned()).unwrap_or_else(|| panic!(
            "bind_redeem_leg: tx_hash {} is not a `test_legs::cheque_txid(tag)` — a redeem leg needs its \
             cheque's origin (KI#241 F-2)", hex::encode(&tx_hash[..4])));
        let (leg, ch) = redeem_leg_for(&cheque, client_pk, consumed, new_state, 0);
        let new = commit(&ch);
        for s in proof.sigs.iter_mut() {
            let valid = ed25519_dalek::VerifyingKey::from_bytes(&s.validator_pk).ok()
                .zip(ed25519_dalek::Signature::from_slice(&s.receipt_commitment_sig).ok())
                .is_some_and(|(vk, sig)| vk.verify(&old, &sig).is_ok());
            let key = (0..32u8).map(|i| SigningKey::from_bytes(&[key_base.wrapping_add(i); 32]))
                .find(|k| k.verifying_key().to_bytes() == s.validator_pk);
            if let (true, Some(k)) = (valid, key) {
                s.receipt_commitment_sig = k.sign(&new).to_bytes().to_vec();
            }
        }
        proof.commitment_hash = ch;
        proof.preimage = leg;
        // W7b — the seq the k signed rides with a redeem leg (`ForkLeg::signed_seq`).
        proof.declared = super::DeclaredState { balance: 0, wallet_seq };
    }

    /// Fork Settlement W7a — a GENUINE redeem-finalize REGISTER: `leg`'s
    /// register re-keyed on `cheque_txid` (a redeem registers under the CHEQUE
    /// txid), carrying [`redeem_leg_for`]'s preimage (receiver = the wallet,
    /// consumed / produced = the register's own states, balance = its declared
    /// balance), the receipt's `commitment_hash` = Core's recompute of that
    /// preimage, and every sig re-made over those bytes — so the door's 5a′
    /// client sig, 5b′ redeem-leg check and quorum all pass on genuine bytes.
    pub fn redeem_registration(sk: &SigningKey, leg: &ForkLeg, cheque: &axiom_core_logic::types::OriginRecord) -> (super::Registration, super::DeedTransaction) {
        let (mut reg, deed) = registration_of(leg);
        reg.tx_hash = origin_txid(cheque);
        let (preimage, ch) = redeem_leg_for(cheque, reg.client_pk, reg.old_state, reg.new_state, reg.declared_balance);
        reg.preimage = preimage;
        reg.receipt.commitment_hash = ch;
        resign_registration(&mut reg, sk);
        (reg, deed)
    }

    /// Re-make `reg`'s k receipt-commitment sigs (the `validator(i)` keys) and
    /// the wallet's client sig over `reg`'s CURRENT bytes — after a deliberate
    /// edit (e.g. a redeem-finalize register keyed on the cheque txid), so the
    /// edit is the only thing that differs from a genuine register (the
    /// legacy step-5 sig too).
    pub fn resign_registration(reg: &mut super::Registration, sk: &SigningKey) {
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            &reg.tx_hash, &reg.receipt.state_hash, reg.receipt.new_wallet_seq,
            &reg.receipt.commitment_hash, reg.receipt.epoch, reg.receipt.is_dev_class,
            reg.receipt.oods_flag.as_ref(), None, reg.receipt.sender_state.as_ref(),
        );
        let step5 = crate::crypto::receipt_sign_payload(
            &reg.wallet_id, &reg.receipt.consumed_state_id, reg.receipt.tick,
        );
        for (i, ws) in reg.receipt.signatures.iter_mut().enumerate() {
            let v = validator(i as u8);
            ws.validator_pk = v.verifying_key().to_bytes();
            ws.receipt_commitment_sig = v.sign(&commitment).to_bytes().to_vec();
            ws.signature = v.sign(&step5).to_bytes().to_vec();
        }
        let bucket = crate::registration::smt_bucket(&reg.wallet_id, reg.k_tier);
        reg.client_sig = client_sig_over(sk, &bucket, &reg.new_state, &reg.tx_hash);
    }

}
