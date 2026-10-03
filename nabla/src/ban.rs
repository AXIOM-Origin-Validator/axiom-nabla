// AXIOM Nabla — Ban Detection (permanent bans; no challenge/reversal path)
// Reference: AXIOM_GUIDE_Nabla.md Sections 2.7, 6.4
//
// Phase 1 Task 9: Ban detection (conflict → BANNED, separate table)
//
// BANNED entries are stored in a separate flat table (not in SMT) because
// they need different access patterns (scan all bans, gossip evidence).
//
// BANS ARE PERMANENT (YPX-002 §7.3). The S6 Challenge Protocol
// (Active → Challenged → Reversed, v2.10.27) was REMOVED 2026-07-28 by explicit
// ruling. Rationale: a ban must be a proof-carrying verdict rather than an
// accusation — there is no innocence evidence to present and nothing to
// adjudicate.
//
// THE LIVE BAN ORIGIN (Fork Settlement §9o, 2026-09-30): ONE verdict path —
// `apply_fork_verdict` → `verify_fork_claim` — fed by self-proving `ForkClaim`
// evidence from the door, the flood, head-AE, AE `fork_bans` (R18) and R48
// record-AE. The wallet-leaf `status` (`Banned` / `Frozen` / `Tainted`) is a
// LOCAL projection of this table and of the node's own E3/E6 judgments, NEVER
// adopted from a peer (§9o [R57], KI#236): `Banned` in a leaf requires an entry
// here. `ban_seq_fork` (E2, check-3) and `ban` (E1) survive only to REPLAY
// persisted legacy entries; neither has a producer.
//
// RULE 0 marker (KI#222, 2026-09-28) — this header used to say "both ban entry
// points below require the wallet's OWN key on BOTH conflicting branches". That
// was TRUE only of the E2 seq-fork path (`ban_seq_fork`, fed by the gossip
// same-parent detection, which checks the wallet's `client_sig` on both legs —
// that detection, check-3, was itself retired 2026-09-30, §9o [R56], KI#235).
// The E1 path (`ban` + `verify_conflict`, fed by the `BanAlert` gossip receiver)
// checked NO wallet signature, and its k sigs were over a payload binding neither
// `new_state` nor `tx_hash` — one genuine receipt forged the pair. The `BanAlert`
// receiver is RETIRED (the variant is a bincode tombstone); `verify_conflict` is
// now `#[cfg(test)]`-only, kept solely so the forgery stays recorded by a test.
// `ban()` survives only for WAL replay of a pre-existing E1 entry (see its doc).
// ~~The live ban origin is E2 today~~ (superseded — see THE LIVE BAN ORIGIN
// above); the self-proving `ForkClaim` / `ForkLeg` standard is
// `docs/AXIOM_DESIGN_ForkSettlement.md` Part A. Its original premise (a ban "may have been caused by a network
// partition") does not hold: a partition yields scarred or under-witnessed
// states, never two independently k=3-witnessed forks. As built the protocol was
// also unsound — endorsements attested nothing about the conflict, no
// counter-evidence path existed, and reversal was an unconditional timeout, so
// 3 endorsements cleared a proven double-spend in ~1h at unpriced Sybil cost.
// Do NOT reintroduce a reversal path without a Core-verifiable innocence proof.

use std::collections::HashMap;

#[cfg(test)]
use crate::crypto::Signer;
use crate::types::{
    BanEvidence, BanStatus, BannedEntry, ConflictProof, ForkClaim, ForkLeg, NablaError, StateId,
    WalletId, WalletStatus,
};

/// File name of the ONE Nabla ban file, written in the node's data dir
/// (`<data_dir>/nabla_bans.txt`) by `NablaNode::drain_fork_side_effects`
/// whenever the table grows (and once at open). Format: `BanTable::ban_file_contents`.
/// A co-located ANTIE reads it by default (best-effort, RULE 7 part 2).
pub const NABLA_BAN_FILE: &str = "nabla_bans.txt";

/// Ban table — separate from SMT. Bans are permanent; there is no reversal path.
pub struct BanTable {
    bans: HashMap<WalletId, BannedEntry>,
    /// Dev-mode marker. Retained because callers branch on it for unrelated
    /// dev behaviour; it no longer gates any window.
    dev_mode: bool,
    /// P4.2 (ghost audit G3) — bans refused for malformed evidence.
    refused_malformed: u64,
    /// ForkSettlement §2.3 [R25] — `ForkClaim`s refused by the ONE
    /// `verify_fork_claim` chokepoint, whatever carried them (local detection,
    /// flood, AE, load). The design-named counter. Cumulative, not persisted.
    atraxi_evidence_refused: u64,
    /// `ForkClaim`s that banned at least one new key through
    /// `apply_fork_verdict`. Cumulative, not persisted.
    fork_claims_applied: u64,
    /// Verified claims that banned ≥1 new key, queued for the node to WAL +
    /// flood (`NablaNode::drain_fork_side_effects`). In-memory only: the ban
    /// itself is persisted through the WAL/snapshot, and a claim lost before
    /// the drain is re-derived from the origin records at the next load [R28].
    pending_fork_floods: Vec<ForkClaim>,
    /// Legs a path (door / flood / AE) had ALREADY accepted that
    /// `verify_fork_leg` then refused, so no record could be made — excluding
    /// the expected `ZeroPk` (the group carve-out). Non-zero means the record hook and the
    /// path's own gate disagree about a leg (RULE 3 §2). Cumulative, not
    /// persisted.
    origin_leg_unrecordable: u64,
    /// Fork Settlement W7c ([R33], plan §2 "Base input") — verified redeem
    /// legs that declared an all-zero consumed state, seen by the record hook
    /// (a fresh wallet's first receive, or a false declaration from a pk with
    /// history). Since W7c they ARE recorded — as grounding roots, in the
    /// redeem ledger, OUT of the fork index (`SparseMerkleTree::
    /// zero_redeem_count`; a second one for one pk grounds neither — F8).
    /// Before W7c they were dropped, which left every fresh wallet UNGROUNDED
    /// forever. Cumulative (duplicates included), not persisted.
    redeem_leg_zero_consumed: u64,
    /// Fork Settlement W7b (spec R52d) — records created whose declared
    /// produced state does NOT recompute to the k-signed `state_hash` /
    /// `new_state` (`leg_is_state_bound` false): detection legs, never
    /// producers. Cumulative, not persisted. On `/status` as
    /// `producer_binding_refused`.
    producer_binding_refused: u64,
    /// Local detections: a verified leg met a DIFFERENT txid under its
    /// `(pk, consumed)` key and the claim passed `verify_fork_claim`
    /// (`record_leg_and_detect`). Cumulative, not persisted.
    origin_fork_claims_detected: u64,
    /// Remote `GossipMessage::ForkBan` claims that passed `verify_fork_claim`
    /// (`adopt_fork_claim`). Cumulative, not persisted.
    origin_fork_claims_adopted: u64,
}

impl BanTable {
    pub fn new() -> Self {
        Self::with_mode(false)
    }

    pub fn new_dev() -> Self {
        Self::with_mode(true)
    }

    fn with_mode(dev_mode: bool) -> Self {
        Self {
            bans: HashMap::new(),
            dev_mode,
            refused_malformed: 0,
            atraxi_evidence_refused: 0,
            fork_claims_applied: 0,
            pending_fork_floods: Vec::new(),
            origin_leg_unrecordable: 0,
            redeem_leg_zero_consumed: 0,
            producer_binding_refused: 0,
            origin_fork_claims_detected: 0,
            origin_fork_claims_adopted: 0,
        }
    }

    pub fn is_dev_mode(&self) -> bool { self.dev_mode }

    /// A wallet is banned iff it has an entry. Bans are permanent — there is no
    /// status under which a present entry stops counting as banned.
    pub fn is_banned(&self, wallet_id: &WalletId) -> bool {
        self.bans.contains_key(wallet_id)
    }

    /// Check if a wallet has an active ban. Equivalent to `is_banned` now that
    /// `Active` is the only status; retained for call-site clarity.
    pub fn is_active_ban(&self, wallet_id: &WalletId) -> bool {
        matches!(
            self.bans.get(wallet_id).map(|e| &e.status),
            Some(BanStatus::Active)
        )
    }

    /// Get ban evidence for a wallet.
    pub fn get(&self, wallet_id: &WalletId) -> Option<&BannedEntry> {
        self.bans.get(wallet_id)
    }

    /// YP §17.3.1.4 v2.19.0 (KI#150): does the evidence carry the k it
    /// declares? `max(required_k, 3)` sigs. ONE predicate for both the
    /// structural check and `verify_conflict` (RULE 1 — one literal, one site).
    pub fn conflict_has_quorum(ev: &ConflictProof) -> bool {
        ev.k3_signatures.len() >= (ev.required_k as usize).max(3)
    }

    /// The structural half of `verify_conflict` — everything checkable without
    /// a `Signer`. Kept as ONE predicate so the ban gate and the gossip
    /// verifier cannot drift on what "a conflict" means (RULE 1).
    pub fn conflict_is_well_formed(ev1: &ConflictProof, ev2: &ConflictProof) -> bool {
        ev1.old_state == ev2.old_state
            && ev1.new_state != ev2.new_state
            && ev1.tx_hash != ev2.tx_hash
            && Self::conflict_has_quorum(ev1)
            && Self::conflict_has_quorum(ev2)
    }

    /// Bans refused because the evidence was not a proof-of-double-spend.
    /// Non-zero means something tried to issue an IRREVERSIBLE ban on evidence
    /// that could never verify — counted, not just logged (RULE 3 §2).
    pub fn refused_malformed(&self) -> u64 {
        self.refused_malformed
    }

    /// Ban a wallet on an E1 `ConflictProof` pair (structural check only).
    ///
    /// PARKED (KI#222, 2026-09-28) — ALLOW_UNREAD_CONST-style marker (RULE 3 §1):
    /// this entry point has NO live producer. Its only production feeder was the
    /// `BanAlert` gossip receiver, retired because the pair is forgeable (see the
    /// file header and KI#222). The single remaining production caller is WAL
    /// replay (`node.rs` `WalOp::Ban` with `seq_fork: None`) — kept so a replay
    /// stays faithful to what the WAL holds; production no longer WRITES such an
    /// entry (every live ban is an A1 `Fork` verdict WAL-logged by
    /// `NablaNode::drain_fork_side_effects`; the binary's former `BanDetected`
    /// WAL site went with check-3, §9o [R56]). Test injectors (`inject_test_ban`) also use it. Do NOT
    /// wire a new caller: a new ban origin must meet the self-proving `ForkLeg`
    /// standard (`docs/AXIOM_DESIGN_ForkSettlement.md` Part A), not this.
    ///
    /// Returns true if this is a new ban, false if already banned.
    pub fn ban(
        &mut self,
        wallet_id: WalletId,
        evidence_1: ConflictProof,
        evidence_2: ConflictProof,
    ) -> bool {
        if self.bans.contains_key(&wallet_id) {
            return false; // already banned
        }

        // ── P4.2 invariant (ghost audit G3) ────────────────────────────────
        // This assertion was CITED as the regression guard against the YPX-002
        // false-ban bug — `registration.rs` §6 says "See P4.2 invariant
        // assertion enforced at `bans.ban()` itself" — and it did not exist.
        // `ban()` banned on whatever it was handed. Meanwhile the group
        // registration path called it with `old_state: [0u8; 32]` and
        // `k3_signatures: vec![]`, so a group wallet was PERMANENTLY banned on
        // evidence that could never verify, for a condition YPX-002 §3.3 calls
        // normal during gossip propagation.
        //
        // A ban is irreversible (`BanStatus` has only `Active`), so it must
        // rest on the proof-of-double-spend YPX-002 §7.4/§7.5 defines: two
        // independently-valid k=3 registrations, same `old_state`, different
        // `new_state`. This is the STRUCTURAL half of `verify_conflict` — the
        // half checkable without a `Signer`. Signature verification stays at
        // the gossip receive path, which has one.
        if !Self::conflict_is_well_formed(&evidence_1, &evidence_2) {
            log::warn!(
                "[BAN-REFUSED-MALFORMED] wallet {} — evidence is not a                  proof-of-double-spend (old_state equal? {}; new_state differs? {};                  sigs {}/{}). YPX-002 §7.4 requires two valid k=3 registrations;                  refusing an irreversible ban on unverifiable evidence.",
                hex::encode(&wallet_id[..4]),
                evidence_1.old_state == evidence_2.old_state,
                evidence_1.new_state != evidence_2.new_state,
                evidence_1.k3_signatures.len(),
                evidence_2.k3_signatures.len(),
            );
            self.refused_malformed = self.refused_malformed.saturating_add(1);
            return false;
        }

        log::warn!(
            "BANNING wallet {:?}: double-spend detected",
            &wallet_id[..4]
        );

        self.bans.insert(
            wallet_id,
            BannedEntry {
                wallet_id,
                evidence: BanEvidence::LegacyConflict(evidence_1, evidence_2),
                status: BanStatus::Active,
            },
        );

        true
    }

    /// Restore a LEGACY check-3 ban (`BanEvidence::SeqFork`) — WAL / snapshot
    /// REPLAY ONLY (`node.rs` `WalOp::Ban`, and the `inject_test_seq_fork_ban`
    /// test injector). Returns true if this is a new ban.
    ///
    /// PARKED (Fork Settlement §9o [R56], W2, 2026-09-30) — ALLOW_UNREAD_CONST-
    /// style marker (RULE 3 §1): this entry point has NO live producer. Its only
    /// feeder was check-3 in `gossip::apply_state_update` (same seq ∧
    /// `old_state == previous_states[W]`), retired as a ban source because
    /// `previous_states[W]` is a node's VIEW, not evidence — it banned honest
    /// wallets (KI#235). A persisted `SeqFork` ban this node once reached still
    /// loads LOCALLY (a ban is permanent, YPX-002 §7.3) and is never
    /// propagated: `ae_fork_bans_out` / `ForkBan` carry only `Fork` claims and
    /// `SeqForkBan` is a dropped tombstone. Do NOT wire a new caller: a new ban
    /// must meet the self-proving `ForkLeg` standard (`apply_fork_verdict`).
    pub fn ban_seq_fork(
        &mut self,
        wallet_id: WalletId,
        evidence: crate::types::SeqConflictProof,
    ) -> bool {
        if self.bans.contains_key(&wallet_id) {
            return false; // already banned
        }
        log::warn!(
            "BANNING wallet {:?}: double-spend FORK detected (seq {})",
            &wallet_id[..4], evidence.wallet_seq
        );
        self.bans.insert(
            wallet_id,
            BannedEntry {
                wallet_id,
                evidence: BanEvidence::SeqFork(evidence),
                status: BanStatus::Active,
            },
        );
        true
    }

    /// Ban one key on a `ForkClaim` (ATRAXI A1, ForkSettlement §2.3). Write-once
    /// per key (as `ban_seq_fork`'s replay is): an already-banned key keeps its original
    /// evidence and this returns false.
    ///
    /// The caller MUST have verified the claim — the live callers are
    /// `apply_fork_verdict` (which runs `verify_fork_claim` every time) and the
    /// WAL replay of this node's OWN `Ban` record (trusted local state, the
    /// same basis `ban_seq_fork`'s replay rests on). Does NOT queue a flood:
    /// a replayed ban must not re-flood; `apply_fork_verdict` queues once per
    /// claim.
    pub fn ban_fork(&mut self, wallet_id: WalletId, claim: ForkClaim) -> bool {
        if self.bans.contains_key(&wallet_id) {
            return false;
        }
        log::warn!(
            "BANNING wallet {}: FORK — two wallet-signed, k-witnessed legs from one parent \
             (tx {} / tx {}) [ForkSettlement A1]",
            hex::encode(&wallet_id[..4]),
            hex::encode(&claim.a.tx_hash[..4]),
            hex::encode(&claim.b.tx_hash[..4]),
        );
        self.bans.insert(
            wallet_id,
            BannedEntry { wallet_id, evidence: BanEvidence::Fork(claim), status: BanStatus::Active },
        );
        true
    }

    /// `ForkClaim`s refused by `verify_fork_claim` inside `apply_fork_verdict`
    /// (RULE 3 §2 — "0 refused" must be distinguishable from "never ran").
    /// On `/status` as `atraxi_evidence_refused`.
    pub fn atraxi_evidence_refused(&self) -> u64 {
        self.atraxi_evidence_refused
    }

    /// Claims that banned ≥1 new key. On `/status` as `fork_claims_applied`.
    pub fn fork_claims_applied(&self) -> u64 {
        self.fork_claims_applied
    }

    /// See the `origin_leg_unrecordable` field. On `/status`.
    pub fn origin_leg_unrecordable(&self) -> u64 {
        self.origin_leg_unrecordable
    }

    /// See the `redeem_leg_zero_consumed` field. On `/status`.
    pub fn redeem_leg_zero_consumed(&self) -> u64 {
        self.redeem_leg_zero_consumed
    }

    /// See the `producer_binding_refused` field. On `/status`.
    pub fn producer_binding_refused(&self) -> u64 {
        self.producer_binding_refused
    }

    /// See the `origin_fork_claims_detected` field. On `/status`.
    pub fn origin_fork_claims_detected(&self) -> u64 {
        self.origin_fork_claims_detected
    }

    /// See the `origin_fork_claims_adopted` field. On `/status`.
    pub fn origin_fork_claims_adopted(&self) -> u64 {
        self.origin_fork_claims_adopted
    }

    /// Drain the verified claims queued for WAL + flood. The ONE consumer is
    /// `NablaNode::drain_fork_side_effects`.
    pub fn take_pending_fork_floods(&mut self) -> Vec<ForkClaim> {
        std::mem::take(&mut self.pending_fork_floods)
    }

    // `verify_seq_conflict` DELETED 2026-09-30 (Fork Settlement §9o [R56], W2).
    // It checked two DISTINCT k-attested states at one `wallet_seq` — NOT one
    // parent (Core keeps `wallet_seq` on receive, so any two honest receive-chain
    // states passed). Its last caller was the `SeqForkBan` arm's telemetry
    // verify; that arm now drops and counts without verifying (`seqforkban_dropped`).

    /// ⚠ FORGEABLE — KI#222. `#[cfg(test)]`-only since 2026-09-28; kept SOLELY so
    /// `ki222_verify_conflict_accepts_forged_pair_from_one_receipt` records the
    /// defect. NEVER wire it into production and NEVER copy it.
    ///
    /// What it checks: same `old_state`, different `new_state` / `tx_hash`,
    /// quorum, and k sigs over `receipt_sign_payload(wallet_id, old_state, tick)`.
    /// What that does NOT prove: that two transactions happened. The payload binds
    /// neither `new_state` nor `tx_hash`, so ONE genuine receipt's sigs satisfy
    /// both halves of any fabricated pair. Its only production caller was the
    /// retired `BanAlert` receiver (`gossip.rs`). The self-proving replacement is
    /// the `ForkLeg` standard (`docs/AXIOM_DESIGN_ForkSettlement.md` Part A).
    #[cfg(test)]
    pub fn verify_conflict(
        wallet_id: &WalletId,
        ev1: &ConflictProof,
        ev2: &ConflictProof,
        signer: &dyn Signer,
    ) -> bool {
        // Same old_state consumed
        if ev1.old_state != ev2.old_state {
            return false;
        }

        // Different new_state produced (otherwise it's the same TX, not a conflict)
        if ev1.new_state == ev2.new_state {
            return false;
        }

        // Both must carry the k they declare (KI#150 — same predicate as
        // conflict_is_well_formed).
        if !Self::conflict_has_quorum(ev1) || !Self::conflict_has_quorum(ev2) {
            return false;
        }

        // Different tx_hash (same TX can't produce different states)
        if ev1.tx_hash == ev2.tx_hash {
            return false;
        }

        // Verify all k=3 witness signatures via Core (Signer trait).
        // Payload: receipt_sign_payload(wallet_id, consumed, tick).
        //
        // RULE 0 marker (KI#222) — the WRONG reading that stood here: "(wallet_id,
        // consumed) is unique per TX because wallet state advances strictly
        // forward", so dropping produced_state and txid from the payload was
        // harmless. For a VERIFIER of a CONFLICT it is fatal: the whole claim is
        // that two DIFFERENT (new_state, tx_hash) consumed one state, and the sigs
        // attest neither — the same k sigs verify both halves. Correct reading:
        // these sigs prove only "some tx consumed old_state"; a fork proof must
        // bind each leg's outcome (`ForkLeg`, ForkSettlement Part A).
        let payload1 = crate::crypto::receipt_sign_payload(
            wallet_id, &ev1.old_state, ev1.tick,
        );
        for ws in &ev1.k3_signatures {
            if !signer.verify(&ws.validator_pk, &payload1, &ws.signature) {
                return false;
            }
        }

        let payload2 = crate::crypto::receipt_sign_payload(
            wallet_id, &ev2.old_state, ev2.tick,
        );
        for ws in &ev2.k3_signatures {
            if !signer.verify(&ws.validator_pk, &payload2, &ws.signature) {
                return false;
            }
        }

        true
    }

    /// Number of banned wallets.
    pub fn len(&self) -> usize {
        self.bans.len()
    }

    /// Whether ban table is empty.
    pub fn is_empty(&self) -> bool {
        self.bans.is_empty()
    }

    /// ForkSettlement §2.3 [R18] — every DISTINCT `ForkClaim` this table holds
    /// as ban evidence (one claim bans pk + bucket keys, so it appears once),
    /// ordered by `(a.tx_hash, b.tx_hash)` so a cursor over it is stable. The
    /// AE carrier's source (`NablaNode::ae_fork_bans_out`). Legacy
    /// `SeqFork` / `LegacyConflict` evidence is NOT carried: it is not
    /// adoptable (KI#46 / KI#222).
    pub fn fork_claims(&self) -> Vec<ForkClaim> {
        let mut by_pair: std::collections::BTreeMap<([u8; 32], [u8; 32]), ForkClaim> =
            std::collections::BTreeMap::new();
        for e in self.bans.values() {
            if let BanEvidence::Fork(c) = &e.evidence {
                by_pair.entry((c.a.tx_hash, c.b.tx_hash)).or_insert_with(|| c.clone());
            }
        }
        by_pair.into_values().collect()
    }

    /// THE one builder of the Nabla ban file (`NABLA_BAN_FILE`, the owner 2026-09-29:
    /// "Nabla ban list should only have ONE file"). Every key this table holds —
    /// every evidence kind (`Fork` pk + bucket keys, `SeqFork`, `LegacyConflict`)
    /// — as lowercase hex of the 32-byte key, one per line, sorted, each line
    /// `\n`-terminated. The keys are the SMT keys: the client's Ed25519 pk
    /// (identity / online-tier bucket) and, for an Ark-tier bucket,
    /// `smt_bucket(pk, k_tier)`. ANTIE's reader (`antie/src/gateway.rs`
    /// `nabla_ban_file_lists`) matches exactly these lines; the two are pinned
    /// together by one golden file, `nabla/tests/fixtures/nabla_bans.golden`
    /// (no shared non-Core crate carries the format). Validator-generated bans
    /// (§23.14 peer-audit bans, JFP freezes) are NOT in this file.
    pub fn ban_file_contents(&self) -> String {
        let mut keys: Vec<String> = self.bans.keys().map(hex::encode).collect();
        keys.sort();
        keys.into_iter().map(|k| k + "\n").collect()
    }

    /// All banned entries (for snapshot serialization and gossip).
    pub fn all(&self) -> Vec<BannedEntry> {
        self.bans.values().cloned().collect()
    }

    /// Load bans from snapshot.
    pub fn load_from(&mut self, bans: Vec<BannedEntry>) {
        for ban in bans {
            self.bans.insert(ban.wallet_id, ban);
        }
    }
}

/// Decode a persisted `BannedEntry` (the `WalOp::Ban.evidence` bytes)
/// STRICTLY: the same fixint little-endian encoding `bincode::serialize`
/// writes, but TRAILING BYTES ARE AN ERROR — a prior-shape record that happens
/// to decode a prefix is refused, never mis-read (the `snapshot.rs`
/// `decode_snapshot_bytes` rule; ForkSettlement §9b R36).
pub fn decode_banned_entry(bytes: &[u8]) -> Result<BannedEntry, NablaError> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| NablaError::SerializationError(format!("BannedEntry: {e}")))
}

/// KI#222 test fixture — the ONE builder of the forged E1 pair (RULE 1), used by
/// the `ban.rs` defect-record test and the `gossip.rs` retired-receiver test.
///
/// Models exactly the attack: k=3 REAL validator keypairs sign ONE genuine
/// registration receipt — `receipt_sign_payload(wallet_id, consumed, 0)`, the
/// payload Lambda signs with `tick = 0` on every send — and an attacker copies
/// those same signatures into two `ConflictProof`s with the same `old_state` and
/// two fabricated, different `new_state` / `tx_hash` values.
#[cfg(test)]
pub(crate) fn ki222_forged_pair_from_one_receipt(
    wallet_id: &WalletId,
    consumed: &crate::types::StateId,
) -> (ConflictProof, ConflictProof) {
    use crate::crypto::Ed25519Signer;
    let payload = crate::crypto::receipt_sign_payload(wallet_id, consumed, 0);
    let genuine_sigs: Vec<crate::types::WitnessSig> = (0..3u8)
        .map(|i| {
            let v = Ed25519Signer::from_seed(&[0x60 + i; 32]);
            crate::types::WitnessSig {
                validator_pk: v.public_key_bytes(),
                signature: v.sign(&payload),
                execution_proof: vec![],
                proof_type: 0,
                receipt_commitment_sig: vec![],
                validator_id: [0u8; 32],
                slot_amount: 0,
            }
        })
        .collect();
    let leg = |new: u8, tx: u8| ConflictProof {
        old_state: *consumed,
        new_state: [new; 32],
        tx_hash: [tx; 32],
        k3_signatures: genuine_sigs.clone(),
        tick: 0,
        required_k: 3,
    };
    (leg(0xB1, 0xC1), leg(0xB2, 0xC2))
}

impl Default for BanTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── ForkSettlement wave 3 — the ONE fork verifier (§2.2, §2.3 [R25], §9b R31/R32) ──
//
// Built ONLY from existing builders/verifiers (RULE 1, Pattern 1 — no new
// crypto): `registration::verify_seq_proof_leg` (preimage → commitment_hash +
// txid(epoch) recompute for a send; → Core's `redeem_preimage_matches` for a
// redeem), `registration::verify_seq_proof` (≥ max(k,3) distinct valid
// receipt-commitment sigs) and `gossip::verify_client_state_sig` (the wallet's
// KI#46 authorship sig) over `smt_bucket(pk, k)` — the bucket DERIVED from the
// key, never taken from the message [R7].
//
// Fork Settlement W7b (§9g, spec R52c) — the REDEEM ARM. A redeem leg carries
// its `RedeemPreimage` (W7a), whose `compute_redeem_commitment` binds
// `receiver_pk` and `consumed_state_id` ([R8]), so a redeem is a self-proving
// child of ONE parent exactly like a send: two legs (send or redeem, any mix)
// authored by one key from one parent with different txids ARE a fork. A
// receiver redeeming two cheques from one state on two validator sets is
// therefore banned by the same ONE chokepoint as a double send.
//
// RULE 5: Nabla hygiene — a hostile node skips all of it and fails open. The
// Core enforcement that holds regardless: `fact::origin_settled_link` /
// `origin_settled_cl5` recompute the txid from the vouched preimage and apply
// the settle floor, so an un-banned fork still cannot SETTLE a double copy.

/// Why a `ForkLeg` is not a verified leg. Every variant is a distinct check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkLegRefusal {
    /// ~~`NotASendLeg`~~ — retired by W7b (a redeem leg is verified by the
    /// Redeem arm). A `Redeem` leg whose `consumed_state_id` is all-zero: a
    /// zero parent is NO state, so the leg is no child of anything a sibling
    /// could share — it joins NO CLAIM ([R33]). Refused by `verify_fork_claim`
    /// only: since W7c `verify_fork_leg` ACCEPTS it, so it can be recorded as
    /// a grounding root (out of the fork index — `record_verified_leg`).
    ZeroConsumedRedeem,
    /// `preimage.client_pk` (send) / `receiver_pk` (redeem) is all-zero — an
    /// unauthored leg names no one.
    ZeroPk,
    /// The carried preimage does not reproduce the proof's `commitment_hash` /
    /// the leg's `tx_hash` / `new_state` (`registration::LegRefusal`).
    Leg(crate::registration::LegRefusal),
    /// Fewer than max(k_tier, 3) distinct valid witness sigs over the receipt
    /// commitment.
    WitnessSigsBelowQuorum,
    /// `client_sig` does not verify under the preimage's key over
    /// `smt_bucket(pk, k_tier)` — missing, forged, or signed over another
    /// wallet's bucket (the HIGH-3 framing attempt).
    ClientSigInvalid,
}

/// Why a `ForkClaim` is not a fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkClaimRefusal {
    LegA(ForkLegRefusal),
    LegB(ForkLegRefusal),
    /// The two legs were authored under different keys — two wallets, no fork.
    DifferentClientPk,
    /// Different consumed parents — e.g. the honest claim+redeem pair at one
    /// `wallet_seq` (the KI#46 false-ban shape). Not a fork.
    DifferentParent,
    /// One txid — the same transaction seen twice (an honest retry), not two.
    SameTxHash,
}

impl core::fmt::Display for ForkClaimRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A `ForkLeg` that passed `verify_fork_leg`. The field is PRIVATE and
/// `verify_fork_leg` is the ONLY constructor, so an unverified leg cannot
/// become a record (`SparseMerkleTree::record_verified_leg` accepts only
/// this type) — ForkSettlement §2.4 [R11] held at COMPILE time, not by review.
/// Send AND redeem legs (W7b): the record path dispatches on [`Self::kind`] —
/// a redeem leg lands in the SEPARATE redeem ledger, never the origin ledger
/// (R5).
/// Constructible off-lock: R48 record-AE (W1) verifies a batch before taking
/// the node lock (`record_sync::prepare_answer`) and records it under it
/// (`record_verified_and_detect` / `detect_only`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedForkLeg {
    leg: ForkLeg,
    client_pk: [u8; 32],
    consumed: StateId,
}

impl VerifiedForkLeg {
    pub fn leg(&self) -> &ForkLeg {
        &self.leg
    }
    pub fn into_leg(self) -> ForkLeg {
        self.leg
    }
    /// The registrant key (non-zero, from the verified preimage).
    pub fn client_pk(&self) -> [u8; 32] {
        self.client_pk
    }
    /// The parent the verified preimage consumed (all-zero only for a fresh
    /// wallet's first redeem — a W7c root, never a claim member).
    pub fn consumed(&self) -> StateId {
        self.consumed
    }
    /// The leg's txid — for a redeem, the CHEQUE txid it registers under.
    pub fn tx_hash(&self) -> crate::types::TxHash {
        self.leg.tx_hash
    }
    /// Send or redeem — which ledger the record belongs in.
    pub fn kind(&self) -> axiom_core_logic::types::LegKind {
        self.leg.kind()
    }
}

/// The per-leg checks, by reference (so `verify_fork_claim` clones nothing).
/// Returns the verified `(client_pk, consumed)`.
fn check_fork_leg(leg: &ForkLeg) -> Result<([u8; 32], StateId), ForkLegRefusal> {
    // 1. An authored leg — the key comes from the (k-signed) preimage: the
    //    sender's `client_pk` of a send, the `receiver_pk` of a redeem.
    let (pk, consumed) = leg.key();
    if pk == [0u8; 32] {
        return Err(ForkLegRefusal::ZeroPk);
    }
    // 2. (W7c) A zero-consumed redeem IS a verified leg — a grounding root.
    //    It joins no claim: `verify_fork_claim` refuses it ([R33]).
    // 3. The preimage reproduces what the k signed — send: commitment_hash +
    //    txid(epoch); redeem: the ONE Core recompute
    //    (`redeem_preimage_matches`), `cheque_txid == tx_hash`, `new_state_id
    //    == new_state`. `old_state = None` — the leg carries no unsigned
    //    parent; the parent IS the preimage's `consumed_state_id`.
    let seq = leg.signed_seq();
    crate::registration::verify_seq_proof_leg(
        &leg.seq_proof, &leg.tx_hash, &pk, None, Some(&leg.new_state), seq,
    )
    .map_err(ForkLegRefusal::Leg)?;
    // 4. ≥ max(required_k, 3) DISTINCT valid witness sigs over the receipt
    //    commitment at the signed seq (a send: the preimage's; a redeem: the
    //    carried `declared.wallet_seq` — `ForkLeg::signed_seq`).
    if !crate::registration::verify_seq_proof(&leg.seq_proof, &leg.tx_hash, seq) {
        return Err(ForkLegRefusal::WitnessSigsBelowQuorum);
    }
    // 5. The wallet authored THIS txid — over the bucket DERIVED from its own
    //    key [R7], never a message field: a claim signed over another wallet's
    //    bucket verifies nothing and bans no one.
    if !crate::gossip::verify_client_state_sig(
        &pk, &leg.client_sig, &leg.bucket(), &leg.new_state, &leg.tx_hash,
    ) {
        return Err(ForkLegRefusal::ClientSigInvalid);
    }
    Ok((pk, consumed))
}

/// THE leg verifier — the only way to obtain a [`VerifiedForkLeg`].
///
/// Production callers: `record_leg_and_detect` (the door / flood / AE record
/// hooks, ForkSettlement §2.3 [R10]), `adopt_fork_claim` (the `ForkBan`
/// receiver records the two legs of an adopted claim) and, since W1 (§9o
/// [R58]), `record_sync::prepare_answer` — record-AE legs verified OFF the
/// node lock, then recorded by `record_verified_and_detect` / `detect_only`.
///
/// Cost [R36, MEASURED 2026-09-28, `node::wave3_hook_tests::
/// verify_fork_leg_cost_measured`]: ~178 µs per k=3 leg at opt-level 3 (≥ 3
/// witness Ed25519 verifies + 1 client-sig verify + two hash recomputes), run
/// UNDER the node mutex on the door / flood / AE paths, each of which already
/// verified the same sigs itself — the off-lock / verify-once options are in
/// `AXIOM_DESIGN_ForkSettlement.md` §9b R36-COST (not built).
pub fn verify_fork_leg(leg: ForkLeg) -> Result<VerifiedForkLeg, ForkLegRefusal> {
    let (client_pk, consumed) = check_fork_leg(&leg)?;
    Ok(VerifiedForkLeg { leg, client_pk, consumed })
}

/// Fork Settlement W7b (spec R52d) — is `leg` a PRODUCER of its produced
/// state, i.e. is that state k-bound?
///
/// - **Redeem:** yes by construction — `new_state_id` is inside the redeem
///   commitment the k signed, which `verify_fork_leg` recomputed (spec F6).
/// - **Send:** the produced state is only WALLET-signed (`client_sig`; F7), so
///   recompute it: the carried `declared.wallet_seq` must be the preimage's,
///   and `compute_produced_state_id(pk, balance, seq, consumed, nonce)`
///   (Core's ONE builder — the formula `validation.rs` uses for a send) must
///   equal `new_state` for `balance` = `declared.balance`
///   (`registration::send_leg_produced_state_matches`; the §9m opening-state
///   genesis-credit arm was DELETED with KI#251 — Core's claim send binds the
///   unchanged balance, so a claim's declared 0 binds directly); every input but the balance is k-signed
///   (see `DeclaredState` for why the balance needs no further pin). A
///   mismatch leaves the record a DETECTION leg (it still opens claims) but
///   never a producer — counted `producer_binding_refused` at record creation.
///
/// Pure; call on a VERIFIED leg (an unverified one's answer means nothing).
/// ⚠ Not sufficient on its own for W7c: a producer ALSO needs witnesses that
/// pass the R42 directory (spec R52d, "record-grade producers only") — that
/// check is W7c's, at producer admission.
///
/// Read by `record_leg_and_detect` (the counter); W7c's verdict memo (R52f)
/// is its second consumer.
pub fn leg_is_state_bound(leg: &ForkLeg) -> bool {
    match &leg.seq_proof.preimage {
        crate::types::LegPreimage::Redeem { .. } => true,
        crate::types::LegPreimage::Send(p) => crate::registration::send_leg_produced_state_matches(
            p, &leg.seq_proof.declared, &leg.new_state,
        ),
    }
}

/// Fork Settlement W7c (R42, TLA+ c12) / §9o [R58] — is EVERY witness of
/// `leg` an R42 directory witness at THIS node (`is_witness` = the node's
/// `VbcDirectory::is_witness`)? The ONE predicate for both of its consumers:
///
/// - the provenance engine's PRODUCER admission (`provenance::Provenance::
///   derive` — a junk-witnessed send never grounds the state it produces);
/// - the record trie's GRADE (`NablaNode` — only a graded leg is a record-AE
///   leaf, is shipped, or upgrades a held ungraded copy).
///
/// ~~provenance.rs held its own copy of this test~~ — moved here 2026-09-30
/// (W1) so the two cannot drift (RULE 1). Pure; meaningful on a VERIFIED leg
/// (which carries ≥ 3 valid sigs). A leg with ANY non-directory sig — even
/// beside a directory quorum — is ungraded, exactly as provenance judged it.
pub fn leg_is_directory_witnessed(leg: &ForkLeg, is_witness: &dyn Fn(&[u8; 32]) -> bool) -> bool {
    seq_proof_is_directory_witnessed(&leg.seq_proof, is_witness)
}

/// KI#224 (owner ruling 2026-10-02: "the witness signs should be able to walk
/// back to the root") — the ONE directory predicate over a carried
/// `SeqProof`: is EVERY witness key in it the subject of an R42 directory
/// entry at THIS node (`VbcDirectory::is_witness` — admitted only after
/// `vbc::verify_vbc_bundle` walked the certificate to the genesis roots)?
/// ALL keys, never "≥ quorum of directory keys" (D-K224-3): one junk sig
/// beside a directory quorum is refused, exactly as the R58 grade judges.
///
/// Read by `leg_is_directory_witnessed` (provenance producer admission +
/// record-trie grade) and by the THREE head-intake paths — register door
/// step 5b⁗ (`registration::process_registration`), the flood
/// (`gossip::apply_state_update`) and head-AE (`NablaNode::
/// apply_remote_entry_inner`): a head whose proof fails it never advances a
/// seq, never first-sights above seq 0 and never marks a txid completed.
/// `verify_seq_proof` itself stays ungated — ban evidence
/// (`verify_fork_leg`) must not depend on the directory (R58).
pub fn seq_proof_is_directory_witnessed(
    p: &crate::types::SeqProof,
    is_witness: &dyn Fn(&[u8; 32]) -> bool,
) -> bool {
    first_non_directory_witness(p, is_witness).is_none()
}

/// KI#224 — the first witness key of `p` NOT in this node's directory
/// (`None` ⟺ every key is a directory witness). The predicate above is
/// defined by it (RULE 1: one scan); refusal logs name the key it returns.
pub fn first_non_directory_witness(
    p: &crate::types::SeqProof,
    is_witness: &dyn Fn(&[u8; 32]) -> bool,
) -> Option<[u8; 32]> {
    p.sigs.iter().map(|s| s.validator_pk).find(|pk| !is_witness(pk))
}

/// THE fork-claim verifier — the ONE chokepoint every carrier passes before
/// anything is banned [R25]. A claim is a fork iff both legs verify, they were
/// authored under ONE key, they consumed ONE parent, and their txids DIFFER.
///
/// **Redeem arm (W7b, spec R52c / §9g):** either leg may be a redeem —
/// `check_fork_leg` verifies it through the redeem builder (Core's
/// `redeem_preimage_matches`), its key is `(receiver_pk, consumed_state_id)`
/// from the k-signed preimage, and its "txid" is the CHEQUE txid it
/// registers under. Two redeems of two cheques from one receiver state (a
/// receiver forking its own chain on two sets), or a send and a redeem from
/// one state, are forks by the same three comparisons. A redeem of the SAME
/// cheque from one state seen twice is `SameTxHash` (an honest retry).
///
/// [R31] It does NOT require `a.new_state != b.new_state`: `new_state`
/// (`compute_produced_state_id`) hashes pk ‖ balance ‖ seq ‖ consumed ‖ nonce —
/// NOT the receiver — so the same amount + nonce sent to P and to Q yields ONE
/// `new_state` and two txids. Two wallet-signed, k-witnessed legs from one
/// parent with different txids ARE the double-spend, whatever state they
/// produce. (The E1 `conflict_is_well_formed` and the retired check-3 (W2,
/// §9o [R56]) carry/carried the `new_state` inequality — that blind spot is
/// theirs, not this one's.)
pub fn verify_fork_claim(c: &ForkClaim) -> Result<(), ForkClaimRefusal> {
    let (pk_a, parent_a) = check_fork_leg(&c.a).map_err(ForkClaimRefusal::LegA)?;
    let (pk_b, parent_b) = check_fork_leg(&c.b).map_err(ForkClaimRefusal::LegB)?;
    // [R33] a zero parent is no state: a zero-consumed redeem is nobody's
    // sibling (W7c records it as a root, out of the index — never a claim).
    if parent_a == [0u8; 32] {
        return Err(ForkClaimRefusal::LegA(ForkLegRefusal::ZeroConsumedRedeem));
    }
    if parent_b == [0u8; 32] {
        return Err(ForkClaimRefusal::LegB(ForkLegRefusal::ZeroConsumedRedeem));
    }
    if pk_a != pk_b {
        return Err(ForkClaimRefusal::DifferentClientPk);
    }
    if parent_a != parent_b {
        return Err(ForkClaimRefusal::DifferentParent);
    }
    if c.a.tx_hash == c.b.tx_hash {
        return Err(ForkClaimRefusal::SameTxHash);
    }
    Ok(())
}

/// The identities a claim bans: the registrant `client_pk` plus each DISTINCT
/// `smt_bucket(pk, leg.k_tier)` that differs from the pk (plan A7 — a k≥3
/// bucket IS the pk; only a non-default class hashes). Derived from the
/// preimage key — there is no name in the claim to forge [R7] (a redeem
/// leg's key is its k-bound `receiver_pk`, W7b). Call on a VERIFIED claim
/// only: the keys of an unverified claim name nobody the evidence proves.
pub fn fork_ban_keys(c: &ForkClaim) -> Vec<WalletId> {
    let pk = c.a.client_pk();
    let mut keys: Vec<WalletId> = vec![pk];
    for leg in [&c.a, &c.b] {
        let b = leg.bucket();
        if !keys.contains(&b) {
            keys.push(b);
        }
    }
    keys
}

/// THE adopt/ban path for EVERY A1 verdict, whatever carried the claim — local
/// detection at the door / flood / AE, load-time re-derivation [R28], a remote
/// `ForkBan` [R25]. Runs `verify_fork_claim` EVERY time, even for a claim
/// assembled locally from two already-verified records (one chokepoint, no
/// "trusted" shortcut).
///
/// - `Err` → `atraxi_evidence_refused` += 1, nothing banned.
/// - `Ok(keys)` → each key of `fork_ban_keys` not yet banned is banned
///   (`ban_fork`) and, when the SMT holds a head under it, that head is flipped
///   to `WalletStatus::Banned` on the SAME head (`PutProof::SameHeadStatusChange`
///   — so a §4.6 read reports the ban; the flip check-3 also did until W2).
///   This is the ONLY live writer of a `Banned` leaf (§9o [R57]: a peer's
///   status is never adopted). If any key was
///   new, the claim is queued ONCE for WAL + flood. Returns the newly banned
///   keys (empty = already banned everywhere it names).
pub fn apply_fork_verdict(
    smt: &mut crate::smt::SparseMerkleTree,
    bans: &mut BanTable,
    claim: &ForkClaim,
) -> Result<Vec<WalletId>, ForkClaimRefusal> {
    if let Err(why) = verify_fork_claim(claim) {
        bans.atraxi_evidence_refused = bans.atraxi_evidence_refused.saturating_add(1);
        log::warn!(
            "[ATRAXI-REFUSED] fork claim (tx {} / tx {}) refused: {} — nothing banned \
             (ForkSettlement R25; counted atraxi_evidence_refused)",
            hex::encode(&claim.a.tx_hash[..4]),
            hex::encode(&claim.b.tx_hash[..4]),
            why,
        );
        return Err(why);
    }
    let mut newly = Vec::new();
    for key in fork_ban_keys(claim) {
        if !bans.ban_fork(key, claim.clone()) {
            continue;
        }
        if let Some(mut head) = smt.get(&key).cloned() {
            if head.status != WalletStatus::Banned {
                head.status = WalletStatus::Banned;
                smt.put_with_proof(&head, crate::smt::PutProof::SameHeadStatusChange);
            }
        }
        newly.push(key);
    }
    if !newly.is_empty() {
        bans.fork_claims_applied = bans.fork_claims_applied.saturating_add(1);
        bans.pending_fork_floods.push(claim.clone());
    }
    Ok(newly)
}

/// What the record hook did with one carried leg (`record_leg_and_detect`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegRecordOutcome {
    /// `verify_fork_leg` refused the leg — nothing recorded. `ZeroPk` (the
    /// group carve-out) is expected; any other refusal is counted
    /// `origin_leg_unrecordable`.
    NotRecordable(ForkLegRefusal),
    /// A new record (R16 `contested` decided at birth) — in the origin ledger
    /// for a send leg, in the SEPARATE redeem ledger for a redeem leg (W7b).
    Recorded { contested: bool },
    /// The leg was already recorded (write-once; an honest retry).
    Duplicate,
    /// The leg's `(pk, consumed)` key already held a DIFFERENT leg (send or
    /// redeem — the SHARED index, W7b) and the claim `{held lowest leg, this
    /// leg}` passed `apply_fork_verdict`. `newly_banned` is empty when every
    /// key was already banned.
    ForkBanned { newly_banned: Vec<WalletId> },
    /// The key held another leg but the claim did NOT verify (counted
    /// `atraxi_evidence_refused` by `apply_fork_verdict`) — e.g. a send and a
    /// redeem under one key sharing ONE txid (`SameTxHash`). The caller
    /// continues its ordinary processing.
    ForkRefused(ForkClaimRefusal),
    /// Fork Settlement §9o [R58] (record-AE only) — a GRADED copy replaced a
    /// held UNGRADED copy of the same leg in place (`smt::OriginOutcome::
    /// Upgraded`), keeping `first_seen_secs` and `contested`.
    Upgraded,
    /// Fork Settlement §9o [R58] (`detect_only`) — an ungraded leg whose key
    /// held no other leg: nothing stored, nothing banned.
    NotStored,
}

/// THE record hook — ForkSettlement §2.3 [R10] / §2.4 [R11, R30], W7b spec
/// R52c. Every detection path calls this ONE function on every carried leg —
/// SEND and REDEEM — ABOVE its own drops and refusals and BEFORE its own
/// `put_with_proof` [R24]:
///
/// - the register door, right after 5b′ (`registration::process_registration`),
///   including legs the door then refuses (`StateMismatch` / A12 / `seq_newer`);
/// - the flood (`gossip::apply_state_update`), above the consumed-state drop,
///   the unattested-advance reject and the supersede loser (and above check-3
///   until its retirement, §9o [R56]);
/// - anti-entropy (`NablaNode::apply_remote_entry`), above the consumed-state
///   drop — and so the StatePull / RangeSync replays, which re-enter the
///   flood path with the head's `SeqProof`.
///
/// Detection is keyed on the RECORDS, never on the head or `previous_state`
/// [R10]: head swaps (proofless ping-pong) and a late leg below the current
/// head both still meet the held record under `(pk, consumed)`. The key is
/// SHARED by send and redeem legs (W7b): a redeem is recorded in the redeem
/// ledger — never read as an origin (R5) — but it sits in the same fork
/// index, so two children of one parent meet whatever their kinds.
///
/// `now_secs` is the binary's `virtual_secs` (wall clock) [R13] — never a
/// TARDIS tick, never `entry.tick`.
///
/// Since W1 (§9o [R58]) this is the two-step composition `verify_fork_leg` →
/// [`record_verified_and_detect`] (ONE body; the refusal counting lives here),
/// plus record-AE as a fourth carrier that calls the second step directly on
/// legs it verified off the lock.
pub fn record_leg_and_detect(
    smt: &mut crate::smt::SparseMerkleTree,
    bans: &mut BanTable,
    leg: ForkLeg,
    now_secs: u64,
    via: &str,
) -> LegRecordOutcome {
    let tx_hash = leg.tx_hash;
    match verify_fork_leg(leg) {
        Ok(verified) => record_verified_and_detect(smt, bans, verified, now_secs, via, None),
        Err(why) => {
            match why {
                ForkLegRefusal::ZeroPk => {}
                _ => {
                    bans.origin_leg_unrecordable = bans.origin_leg_unrecordable.saturating_add(1);
                    log::warn!(
                        "[ORIGIN-UNRECORDABLE] via={} tx {} — the path accepted this leg but \
                         verify_fork_leg refused it ({:?}); no record (counted \
                         origin_leg_unrecordable)",
                        via, hex::encode(&tx_hash[..4]), why,
                    );
                }
            }
            LegRecordOutcome::NotRecordable(why)
        }
    }
}

/// The second half of [`record_leg_and_detect`] — the ONE body that records
/// an ALREADY-verified leg and runs the detector (Fork Settlement §9o [R58],
/// W1 split): record-AE verifies a batch OFF the node lock
/// (`record_sync::prepare_answer`) and records it here under the lock, so a
/// leg is never verified twice and never verified under the lock.
///
/// `upgrade` (record-AE only; every other path passes `None`) is the node's
/// GRADE (`leg_is_directory_witnessed` over its directory): when set, a leg
/// already held as an UNGRADED copy is replaced in place by a GRADED one
/// (`LegRecordOutcome::Upgraded`, `smt::record_verified_leg_opt`).
pub fn record_verified_and_detect(
    smt: &mut crate::smt::SparseMerkleTree,
    bans: &mut BanTable,
    verified: VerifiedForkLeg,
    now_secs: u64,
    via: &str,
    upgrade: Option<&dyn Fn(&ForkLeg) -> bool>,
) -> LegRecordOutcome {
    let this_leg = verified.leg().clone();
    let zero_root = verified.kind() == axiom_core_logic::types::LegKind::Redeem && verified.consumed() == [0u8; 32];
    if zero_root {
        // W7c — recorded as a grounding root, out of the fork index.
        bans.redeem_leg_zero_consumed = bans.redeem_leg_zero_consumed.saturating_add(1);
    }
    let outcome = smt.record_verified_leg_opt(verified, now_secs, upgrade);
    if matches!(outcome, crate::smt::OriginOutcome::Created { .. } | crate::smt::OriginOutcome::Conflict { .. })
        && !leg_is_state_bound(&this_leg)
    {
        // R52d — a detection leg, never a producer (W7c reads the same predicate).
        bans.producer_binding_refused = bans.producer_binding_refused.saturating_add(1);
    }
    match outcome {
        crate::smt::OriginOutcome::Created { contested } => LegRecordOutcome::Recorded { contested },
        crate::smt::OriginOutcome::Duplicate => LegRecordOutcome::Duplicate,
        crate::smt::OriginOutcome::Upgraded => LegRecordOutcome::Upgraded,
        crate::smt::OriginOutcome::Conflict { held } => {
            // `held` comes from a BTreeSet walk → held[0] is the LOWEST other
            // leg, so every node assembles the same claim from the same pair.
            let Some(first) = held.into_iter().next() else {
                return LegRecordOutcome::Duplicate;
            };
            claim_verdict(smt, bans, first.leg, this_leg, via)
        }
    }
}

/// Fork Settlement §9o [R58] — DETECTION WITHOUT A RECORD, for a verified leg
/// this node cannot GRADE (a witness not yet in its R42 directory — directory
/// lag). Detection is never gated on the directory (R37): if the leg's
/// `(pk, consumed)` key already holds ANOTHER leg, the claim `{held lowest
/// other leg, this leg}` goes through the ONE verdict path
/// (`apply_fork_verdict` → `verify_fork_claim`) and bans on evidence (the
/// ban entry carries both legs). Otherwise NOTHING is stored — an ungraded
/// leg is never a record created by record-AE (junk replicates only with
/// staked witnesses, R42), and the next exchange re-fetches it once its
/// witnesses are admitted (R49 negative cache NOT built — H-3).
///
/// Production caller: `NablaNode::record_ae_apply` (ungraded legs).
pub fn detect_only(
    smt: &mut crate::smt::SparseMerkleTree,
    bans: &mut BanTable,
    verified: VerifiedForkLeg,
    via: &str,
) -> LegRecordOutcome {
    let key = (verified.client_pk(), verified.consumed());
    if key.1 == [0u8; 32] {
        return LegRecordOutcome::NotStored; // a zero parent is nobody's sibling [R33]
    }
    let this_leg = verified.into_leg();
    let other = smt
        .legs_under(&key)
        .into_iter()
        .filter_map(|m| smt.leg_record(&key, &m).map(|e| e.leg.clone()))
        .find(|l| !(l.tx_hash == this_leg.tx_hash && l.kind() == this_leg.kind()));
    match other {
        Some(first) => claim_verdict(smt, bans, first, this_leg, via),
        None => LegRecordOutcome::NotStored,
    }
}

/// The claim `{held, this}` through `apply_fork_verdict` — shared by the
/// record path and `detect_only`.
fn claim_verdict(
    smt: &mut crate::smt::SparseMerkleTree,
    bans: &mut BanTable,
    held: ForkLeg,
    this_leg: ForkLeg,
    via: &str,
) -> LegRecordOutcome {
    let claim = ForkClaim { a: held, b: this_leg };
    match apply_fork_verdict(smt, bans, &claim) {
        Ok(newly_banned) => {
            bans.origin_fork_claims_detected = bans.origin_fork_claims_detected.saturating_add(1);
            log::warn!(
                "[FORK-DETECTED] via={} two legs under one (pk, consumed) key: \
                 tx {} ({:?}) / tx {} ({:?}) — {} key(s) newly banned \
                 [ForkSettlement R10 / W7b]",
                via,
                hex::encode(&claim.a.tx_hash[..4]), claim.a.kind(),
                hex::encode(&claim.b.tx_hash[..4]), claim.b.kind(),
                newly_banned.len(),
            );
            LegRecordOutcome::ForkBanned { newly_banned }
        }
        Err(why) => LegRecordOutcome::ForkRefused(why),
    }
}

/// THE `ForkBan` receiver's adoption (ForkSettlement §2.3 [R25]): the carried
/// claim passes the ONE chokepoint (`apply_fork_verdict` → `verify_fork_claim`)
/// BEFORE anything is banned or recorded. `Err` = unverifiable: nothing banned,
/// nothing recorded, `atraxi_evidence_refused` counted by the verdict path, and
/// the caller must NOT forward (no amplification). `Ok` = verified: counted
/// `origin_fork_claims_adopted`, and both legs are recorded (they are verified
/// legs; recording them lets [R28] re-derive the claim after a restart even if
/// the ban record is lost). The legs are recorded with plain
/// `record_verified_leg` — the claim is already adjudicated, so no second local
/// verdict runs on them. A redeem leg lands in the redeem ledger (W7b).
pub fn adopt_fork_claim(
    smt: &mut crate::smt::SparseMerkleTree,
    bans: &mut BanTable,
    claim: &ForkClaim,
    now_secs: u64,
) -> Result<Vec<WalletId>, ForkClaimRefusal> {
    let newly = apply_fork_verdict(smt, bans, claim)?;
    bans.origin_fork_claims_adopted = bans.origin_fork_claims_adopted.saturating_add(1);
    for leg in [&claim.a, &claim.b] {
        if let Ok(v) = verify_fork_leg(leg.clone()) {
            let _ = smt.record_verified_leg(v, now_secs);
        }
    }
    Ok(newly)
}

/// ForkSettlement §2.3 [R18] — the most `ForkClaim`s ONE AE reconcile message
/// (`AeReconcile.fork_bans` / `AeEntries.fork_bans`) carries. Bans are rare; a
/// sender holding more rotates a cursor over them (`NablaNode::
/// ae_fork_bans_out`), so every ban reaches every AE peer within
/// ⌈bans / 32⌉ exchanges. A receiver refuses (and counts) anything past the
/// cap without verifying it. At ~178 µs per leg (§9b R36) a full page is
/// ≈ 11 ms of verification, and it runs OFF the node lock.
pub const AE_FORK_BANS_MAX: usize = 32;

/// ForkSettlement [R18] — what the OFF-LOCK screen decided for one AE-carried
/// claim (`screen_ae_fork_bans`), consumed under the lock by
/// `adopt_ae_fork_bans`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeBanScreen {
    /// Every key the claim names is already banned here — nothing it could
    /// change, so it was not verified (the steady state: every exchange
    /// carries every ban).
    Known,
    /// `verify_fork_claim` accepted it off the lock. Adoption re-verifies
    /// under the lock (the ONE chokepoint has no trusted shortcut) — that
    /// cost is paid only for a genuine, NEW ban.
    Verified,
    /// `verify_fork_claim` refused it off the lock, or it was past
    /// `AE_FORK_BANS_MAX`. Counted `atraxi_evidence_refused`; nothing banned.
    Refused,
}

/// ForkSettlement [R18] — the OFF-LOCK half of AE ban adoption (the
/// `prelock_directory_verify` shape; `prelock_hal_verify` retired §9q): `known[i]` is the
/// brief-lock answer "every key of claim i is already banned"
/// (`NablaNode::ae_fork_bans_known`); every other claim within the cap runs
/// `verify_fork_claim` here, WITHOUT the node lock. Pure.
pub fn screen_ae_fork_bans(claims: &[ForkClaim], known: &[bool]) -> Vec<AeBanScreen> {
    claims
        .iter()
        .enumerate()
        .map(|(i, c)| {
            if i >= AE_FORK_BANS_MAX {
                AeBanScreen::Refused
            } else if known.get(i).copied().unwrap_or(false) {
                AeBanScreen::Known
            } else if verify_fork_claim(c).is_ok() {
                AeBanScreen::Verified
            } else {
                AeBanScreen::Refused
            }
        })
        .collect()
}

/// ForkSettlement [R18] — the UNDER-LOCK half: adopt every `Verified` claim
/// through `adopt_fork_claim` (→ `apply_fork_verdict` → `verify_fork_claim`,
/// the ONE chokepoint, [R25]: ban + record both legs; the verdict queues the
/// claim for WAL + `ForkBan` flood), count every `Refused` one
/// `atraxi_evidence_refused`, skip `Known`. A `screen` that does not match
/// `claims` one-for-one adopts NOTHING and counts every claim refused (fail
/// closed — never adopt what was not screened). Returns the number of claims
/// that banned ≥1 new key.
pub fn adopt_ae_fork_bans(
    smt: &mut crate::smt::SparseMerkleTree,
    bans: &mut BanTable,
    claims: &[ForkClaim],
    screen: &[AeBanScreen],
    now_secs: u64,
) -> usize {
    let mut adopted = 0usize;
    for (i, claim) in claims.iter().enumerate() {
        let verdict = if screen.len() == claims.len() { screen[i] } else { AeBanScreen::Refused };
        match verdict {
            AeBanScreen::Known => {}
            AeBanScreen::Refused => {
                bans.atraxi_evidence_refused = bans.atraxi_evidence_refused.saturating_add(1);
                log::warn!(
                    "[ATRAXI-REFUSED] AE-carried fork claim (tx {} / tx {}) refused — nothing \
                     banned (ForkSettlement R18/R25; counted atraxi_evidence_refused)",
                    hex::encode(&claim.a.tx_hash[..4]),
                    hex::encode(&claim.b.tx_hash[..4]),
                );
            }
            AeBanScreen::Verified => {
                if let Ok(newly) = adopt_fork_claim(smt, bans, claim, now_secs) {
                    if !newly.is_empty() {
                        adopted += 1;
                    }
                }
            }
        }
    }
    adopted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WitnessSig;

    fn make_witness_sig(pk_byte: u8) -> WitnessSig {
        WitnessSig {
            validator_pk: [pk_byte; 32],
            signature: vec![pk_byte; 64],
            execution_proof: vec![],
            proof_type: 0,
            receipt_commitment_sig: vec![],
            validator_id: [0u8; 32],
            slot_amount: 0,
        }
    }

    fn make_conflict_proof(old: u8, new: u8, tx: u8) -> ConflictProof {
        ConflictProof {
            old_state: [old; 32],
            new_state: [new; 32],
            tx_hash: [tx; 32],
            k3_signatures: vec![
                make_witness_sig(0x01),
                make_witness_sig(0x02),
                make_witness_sig(0x03),
            ],
            tick: 0,
            required_k: 3,
        }
    }

    fn banned_table(wid: WalletId) -> BanTable {
        let mut table = BanTable::new();
        table.ban(wid, make_conflict_proof(0x10, 0x20, 0xA1), make_conflict_proof(0x10, 0x30, 0xA2));
        table
    }

    /// The ONE Nabla ban file's format (KI#228), pinned to the golden file
    /// ANTIE's reader test also reads (`antie/src/gateway.rs`
    /// `nabla_ban_file_golden_is_matched_by_antie`): two bans inserted out of
    /// order render as sorted lowercase hex lines.
    /// MUTATION: uppercase / unsorted / no trailing `\n` ⇒ red here; ANTIE's
    /// reader dropping a golden key ⇒ red there. (Every evidence kind renders
    /// through the same key loop; the fork kind is exercised end-to-end by
    /// `node.rs` `fork_ban_lands_in_the_one_ban_file_and_survives_reopen`.)
    #[test]
    fn ban_file_contents_match_the_golden_file_antie_reads() {
        let mut table = banned_table([0xAB; 32]);
        assert!(table.ban([0x01; 32], make_conflict_proof(0x11, 0x21, 0xB1), make_conflict_proof(0x11, 0x31, 0xB2)));
        assert_eq!(
            table.ban_file_contents(),
            include_str!("../tests/fixtures/nabla_bans.golden"),
        );
        assert_eq!(BanTable::new().ban_file_contents(), "", "no bans = empty file, not absent");
    }

    #[test]
    fn ban_new_wallet() {
        let mut table = BanTable::new();
        let wid = [0xAA; 32];
        let ev1 = make_conflict_proof(0x10, 0x20, 0xA1);
        let ev2 = make_conflict_proof(0x10, 0x30, 0xA2);

        assert!(!table.is_banned(&wid));
        assert!(table.ban(wid, ev1, ev2));
        assert!(table.is_banned(&wid));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn ban_status_defaults_to_active() {
        let mut table = BanTable::new();
        let wid = [0xAA; 32];
        table.ban(wid, make_conflict_proof(0x10, 0x20, 0xA1), make_conflict_proof(0x10, 0x30, 0xA2));
        assert!(table.is_active_ban(&wid));
        assert!(matches!(table.get(&wid).unwrap().status, BanStatus::Active));
    }

    #[test]
    fn double_ban_returns_false() {
        let mut table = BanTable::new();
        let wid = [0xBB; 32];
        let ev1 = make_conflict_proof(0x10, 0x20, 0xA1);
        let ev2 = make_conflict_proof(0x10, 0x30, 0xA2);

        assert!(table.ban(wid, ev1.clone(), ev2.clone()));
        assert!(!table.ban(wid, ev1, ev2)); // already banned
    }

    #[test]
    fn verify_conflict_valid() {
        let ev1 = make_conflict_proof(0x10, 0x20, 0xA1); // same old, different new
        let ev2 = make_conflict_proof(0x10, 0x30, 0xA2);
        assert!(BanTable::verify_conflict(&[0xAA; 32], &ev1, &ev2, &crate::crypto::NoopSigner));
    }

    #[test]
    fn verify_conflict_same_new_state() {
        let ev1 = make_conflict_proof(0x10, 0x20, 0xA1);
        let ev2 = make_conflict_proof(0x10, 0x20, 0xA2); // same new_state = not a conflict
        assert!(!BanTable::verify_conflict(&[0xAA; 32], &ev1, &ev2, &crate::crypto::NoopSigner));
    }

    #[test]
    fn verify_conflict_different_old_state() {
        let ev1 = make_conflict_proof(0x10, 0x20, 0xA1);
        let ev2 = make_conflict_proof(0x11, 0x30, 0xA2); // different old = not same-spend
        assert!(!BanTable::verify_conflict(&[0xAA; 32], &ev1, &ev2, &crate::crypto::NoopSigner));
    }

    #[test]
    fn verify_conflict_insufficient_sigs() {
        let mut ev1 = make_conflict_proof(0x10, 0x20, 0xA1);
        ev1.k3_signatures.truncate(2); // only 2 sigs
        let ev2 = make_conflict_proof(0x10, 0x30, 0xA2);
        assert!(!BanTable::verify_conflict(&[0xAA; 32], &ev1, &ev2, &crate::crypto::NoopSigner));
    }

    /// KI#222 — a test that RECORDS THE DEFECT (RULE 6 §2). Two `ConflictProof`s
    /// built from ONE genuine receipt's signatures (same `old_state`, fabricated
    /// different `new_state` / `tx_hash`) are ACCEPTED by `verify_conflict` under
    /// a REAL Ed25519 verifier — that is the forgery that let any Nabla peer ban
    /// any wallet mesh-wide through the (now retired) `BanAlert` receiver.
    ///
    /// If this assertion ever flips, `verify_conflict` changed: do NOT take that
    /// as licence to re-wire it — a conflict verifier must meet the `ForkLeg`
    /// standard (ForkSettlement Part A), and this function should be deleted.
    /// The guard that matters in production is
    /// `gossip::tests::ki222_banalert_receiver_retired_no_ban_no_forward`.
    #[test]
    fn ki222_verify_conflict_accepts_forged_pair_from_one_receipt() {
        let wid = [0xAA; 32];
        let consumed = [0x10; 32];
        let (ev1, ev2) = super::ki222_forged_pair_from_one_receipt(&wid, &consumed);
        // It IS one receipt: the two legs carry byte-identical signature sets.
        assert_eq!(ev1.k3_signatures, ev2.k3_signatures);
        assert_ne!(ev1.new_state, ev2.new_state);
        assert_ne!(ev1.tx_hash, ev2.tx_hash);
        // A real verifier (not NoopSigner) — the sigs are genuine Ed25519.
        let real = crate::crypto::Ed25519Signer::from_seed(&[0x01; 32]);
        assert!(
            BanTable::verify_conflict(&wid, &ev1, &ev2, &real),
            "KI#222 defect record: verify_conflict accepts a pair forged from ONE receipt"
        );
        // Control: the sigs really are checked — tamper one and it refuses. So the
        // acceptance above is the payload's fault, not a verifier that passes all.
        let mut bad = ev2.clone();
        bad.k3_signatures[0].signature[0] ^= 0xFF;
        assert!(!BanTable::verify_conflict(&wid, &ev1, &bad, &real));
    }

    // ── Permanence (S6 challenge protocol REMOVED 2026-07-28) ──

    /// A ban is permanent: once present it never stops counting as banned, and
    /// `BanStatus` has exactly one inhabitant. This is the regression guard for
    /// the removed Active → Challenged → Reversed path — if anyone reintroduces
    /// a reversal state, `BanStatus::Active` stops being exhaustive here and
    /// this test fails to compile.
    #[test]
    fn ban_is_permanent_and_status_has_one_state() {
        let wid = [0xAA; 32];
        let mut table = banned_table(wid);
        assert!(table.is_banned(&wid));
        assert!(table.is_active_ban(&wid));

        // Exhaustive match: adding a variant breaks compilation here.
        let entry = table.get(&wid).expect("ban entry");
        match entry.status {
            BanStatus::Active => {}
        }

        // Re-banning an already-banned wallet is a no-op, never a downgrade.
        let ev1 = make_conflict_proof(0x10, 0x20, 0xA1);
        let ev2 = make_conflict_proof(0x10, 0x30, 0xA2);
        assert!(!table.ban(wid, ev1, ev2), "already-banned wallet must not re-ban");
        assert!(table.is_banned(&wid), "must remain banned");
    }

    /// P4.2 (ghost audit G3) — `ban()` must REFUSE evidence that is not a
    /// proof-of-double-spend. The guard was cited by `registration.rs` §6 as the
    /// regression barrier against the YPX-002 false-ban bug and did not exist,
    /// so `ban()` banned on whatever it was handed — including the group path's
    /// zeroed `old_state` / empty `k3_signatures`.
    ///
    /// A ban is IRREVERSIBLE (`BanStatus` has only `Active`), so this fails
    /// closed.
    #[test]
    fn p42_ban_refuses_evidence_that_is_not_a_double_spend_proof() {
        fn sigs(n: usize) -> Vec<WitnessSig> {
            (0..n).map(|i| WitnessSig {
                validator_pk: [i as u8 + 1; 32], signature: vec![i as u8 + 1; 64],
                execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![],
                validator_id: [0u8; 32], slot_amount: 0,
            }).collect()
        }
        let wid = [0xC3u8; 32];
        let good1 = ConflictProof { old_state: [1; 32], new_state: [2; 32], tx_hash: [3; 32], k3_signatures: sigs(3), tick: 0, required_k: 3 };
        let good2 = ConflictProof { old_state: [1; 32], new_state: [9; 32], tx_hash: [8; 32], k3_signatures: sigs(3), tick: 0, required_k: 3 };

        // Each malformed shape must be refused, and must NOT ban.
        let cases: Vec<(&str, ConflictProof, ConflictProof)> = vec![
            ("no signatures (the group path's exact shape)",
             ConflictProof { k3_signatures: vec![], ..good1.clone() },
             ConflictProof { k3_signatures: vec![], ..good2.clone() }),
            ("zeroed old_state on one side (the group path's exact shape)",
             ConflictProof { old_state: [0; 32], ..good1.clone() }, good2.clone()),
            ("same new_state — that is the SAME tx, not a conflict",
             good1.clone(), ConflictProof { new_state: [2; 32], ..good2.clone() }),
            ("same tx_hash — one tx cannot produce two states",
             good1.clone(), ConflictProof { tx_hash: [3; 32], ..good2.clone() }),
            ("sub-quorum evidence (2 sigs)",
             ConflictProof { k3_signatures: sigs(2), ..good1.clone() },
             ConflictProof { k3_signatures: sigs(2), ..good2.clone() }),
        ];
        for (why, e1, e2) in cases {
            let mut bans = BanTable::new();
            assert!(!bans.ban(wid, e1, e2), "ban() must REFUSE: {why}");
            assert!(!bans.is_banned(&wid), "wallet must not be banned: {why}");
            assert_eq!(bans.refused_malformed(), 1, "the refusal must be counted: {why}");
        }

        // Positive control — a real proof-of-double-spend still bans. Without
        // this the test above passes against a `ban()` that never bans.
        let mut bans = BanTable::new();
        assert!(bans.ban(wid, good1, good2), "a genuine k=3 conflict must still ban");
        assert!(bans.is_banned(&wid));
        assert_eq!(bans.refused_malformed(), 0);
    }

    // ── ForkSettlement wave 3 S2 — the ONE fork verifier (real keypairs) ──────
    //
    // Every leg comes from `types::test_legs::genuine_send_leg` (RULE 1): the
    // preimage hashes, txid, new_state, k validator sigs and the wallet sig are
    // all DERIVED with the production builders — nothing pinned.

    use crate::types::test_legs::{self, client_sig_over, genuine_send_leg, validator, wallet};
    use crate::types::{ForkClaim, ForkLeg, NablaEntry};

    const Y: [u8; 32] = [0x59; 32];
    const P: &str = "p@axiom.internal/0123456789";
    const Q: &str = "q@axiom.internal/0123456789";

    /// Two genuine legs by wallet `seed` from ONE parent `Y` at seq 5 — the
    /// double-spend: same amount, different receivers, different nonces.
    fn fork_pair(seed: u8, k: u8) -> (ForkLeg, ForkLeg) {
        let sk = wallet(seed);
        (
            genuine_send_leg(&sk, Y, 5, P, 400, 1, k),
            genuine_send_leg(&sk, Y, 5, Q, 400, 2, k),
        )
    }

    fn head(wid: [u8; 32], tx: [u8; 32]) -> NablaEntry {
        NablaEntry {
            received_from: None,
            wallet_seq: 5,
            wallet_id: wid,
            current_state: [0x77; 32],
            tx_hash: tx,
            tick: 1,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: wid,
            client_sig: vec![0u8; 64],
        }
    }

    /// Test 1 — POSITIVE control. MUTATION: `verify_fork_claim` → always Err ⇒ red.
    #[test]
    fn fork_claim_accepts_genuine_same_parent_send_pair() {
        let (a, b) = fork_pair(0xA1, 3);
        assert_eq!(verify_fork_claim(&ForkClaim { a: a.clone(), b: b.clone() }), Ok(()));
        // Symmetric: the order of the legs does not matter.
        assert_eq!(verify_fork_claim(&ForkClaim { a: b, b: a }), Ok(()));
    }

    /// Test 2 — the honest claim+redeem shape (KI#46 false-ban regression):
    /// one key, one `wallet_seq`, but DIFFERENT parents (a redeem moved Y→Y′
    /// without advancing the seq, then the wallet sent from Y′). Same-seq is not
    /// same-parent. MUTATION: drop the consumed-equality check ⇒ red.
    #[test]
    fn fork_claim_rejects_different_parent() {
        let sk = wallet(0xA2);
        let a = genuine_send_leg(&sk, Y, 5, P, 400, 1, 3);
        let b = genuine_send_leg(&sk, [0x5A; 32], 5, Q, 400, 2, 3);
        assert_eq!(verify_fork_claim(&ForkClaim { a, b }), Err(ForkClaimRefusal::DifferentParent));
    }

    /// Test 3 — one txid twice is a retry, not a fork. MUTATION: drop the
    /// `tx_hash` inequality ⇒ red.
    #[test]
    fn fork_claim_rejects_same_tx_hash() {
        let (a, _) = fork_pair(0xA3, 3);
        assert_eq!(
            verify_fork_claim(&ForkClaim { a: a.clone(), b: a }),
            Err(ForkClaimRefusal::SameTxHash)
        );
    }

    /// Test 4 — [R31]. Equal amount + equal nonce to two receivers: ONE
    /// `new_state` (Core's `compute_produced_state_id` does not hash the
    /// receiver), TWO txids. That IS the double-spend and must verify.
    /// MUTATION: re-add `a.new_state != b.new_state` ⇒ red.
    #[test]
    fn fork_claim_accepts_same_new_state_different_txid() {
        let sk = wallet(0xA4);
        let a = genuine_send_leg(&sk, Y, 5, P, 400, 9, 3);
        let b = genuine_send_leg(&sk, Y, 5, Q, 400, 9, 3);
        assert_eq!(a.new_state, b.new_state, "the fixture must reproduce R31: one new_state");
        assert_ne!(a.tx_hash, b.tx_hash, "…and two txids");
        assert_eq!(verify_fork_claim(&ForkClaim { a: a.clone(), b: b.clone() }), Ok(()));
        // And it bans: through the one verdict path, the registrant is banned.
        let (mut smt, mut bans) = (crate::smt::SparseMerkleTree::new(), BanTable::new());
        let pk = sk.verifying_key().to_bytes();
        assert_eq!(apply_fork_verdict(&mut smt, &mut bans, &ForkClaim { a, b }), Ok(vec![pk]));
        assert!(bans.is_banned(&pk));
    }

    /// Test 5 — forged witness sigs. The leg's commitment sigs are replaced by
    /// sigs from the SAME validator keys over a DIFFERENT commitment (another
    /// leg's), and separately cut to 2 genuine sigs (sub-quorum).
    /// MUTATION: skip step 4 (`verify_seq_proof`) ⇒ red.
    #[test]
    fn fork_claim_rejects_forged_witness_sigs() {
        let (a, b) = fork_pair(0xA5, 3);
        let other = genuine_send_leg(&wallet(0x05), [0x11; 32], 1, P, 1, 1, 3);
        let mut forged = b.clone();
        forged.seq_proof.sigs = other.seq_proof.sigs.clone();
        assert_eq!(
            verify_fork_claim(&ForkClaim { a: a.clone(), b: forged }),
            Err(ForkClaimRefusal::LegB(ForkLegRefusal::WitnessSigsBelowQuorum))
        );
        let mut short = b;
        short.seq_proof.sigs.truncate(2);
        assert_eq!(
            verify_fork_claim(&ForkClaim { a, b: short }),
            Err(ForkClaimRefusal::LegB(ForkLegRefusal::WitnessSigsBelowQuorum))
        );
        // A k=5 leg carrying only 3 sigs is below ITS OWN quorum.
        let sk = wallet(0xB5);
        let mut k5 = genuine_send_leg(&sk, Y, 5, P, 400, 1, 5);
        k5.seq_proof.sigs.truncate(3);
        assert_eq!(verify_fork_leg(k5).err(), Some(ForkLegRefusal::WitnessSigsBelowQuorum));
        let _ = validator(0);
    }

    /// Test 6 — missing / forged client sig. MUTATION: skip step 5 ⇒ red.
    #[test]
    fn fork_claim_rejects_missing_or_forged_client_sig() {
        let (a, b) = fork_pair(0xA6, 3);
        let mut missing = b.clone();
        missing.client_sig = Vec::new();
        assert_eq!(
            verify_fork_claim(&ForkClaim { a: a.clone(), b: missing }),
            Err(ForkClaimRefusal::LegB(ForkLegRefusal::ClientSigInvalid))
        );
        // Signed by ANOTHER key over the right bucket/state/txid.
        let mut forged = b.clone();
        let pk = wallet(0xA6).verifying_key().to_bytes();
        forged.client_sig = client_sig_over(&wallet(0x66), &pk, &b.new_state, &b.tx_hash);
        assert_eq!(
            verify_fork_claim(&ForkClaim { a, b: forged }),
            Err(ForkClaimRefusal::LegB(ForkLegRefusal::ClientSigInvalid))
        );
    }

    /// Test 7 — the preimage edited after signing (nonce+1): it no longer
    /// reproduces the k-signed commitment. MUTATION: skip step 3
    /// (`verify_seq_proof_leg`) ⇒ red.
    #[test]
    fn fork_claim_rejects_tampered_preimage() {
        let (a, mut b) = fork_pair(0xA7, 3);
        if let crate::types::LegPreimage::Send(p) = &mut b.seq_proof.preimage {
            p.nonce += 1;
        }
        assert_eq!(
            verify_fork_claim(&ForkClaim { a, b }),
            Err(ForkClaimRefusal::LegB(ForkLegRefusal::Leg(
                crate::registration::LegRefusal::CommitmentHashMismatch
            )))
        );
    }

    /// Test 8 — the HIGH-3 framing attack. A forks two genuine legs of its own
    /// but signs each client payload over honest W's bucket, hoping to ban W.
    /// Refused, nothing banned, W untouched. CONTROL: the same legs signed over
    /// A's own (derived) bucket ban exactly `fork_ban_keys` = {A} (k=3 bucket IS
    /// the pk), and for Ark-class (k=0) legs {A, smt_bucket(A,0)}.
    /// MUTATION: skip step 5 (the derived-bucket client-sig check) ⇒ red (the
    /// framing claim verifies). No mutation can make W banned: the claim holds
    /// no name — the banned identity is derived from the preimage key.
    #[test]
    fn fork_claim_framing_a_signs_over_w_bucket_bans_nothing_but_a() {
        let sk_a = wallet(0xA8);
        let pk_a = sk_a.verifying_key().to_bytes();
        let w = wallet(0x88).verifying_key().to_bytes();
        let (mut a, mut b) = fork_pair(0xA8, 3);
        a.client_sig = client_sig_over(&sk_a, &w, &a.new_state, &a.tx_hash);
        b.client_sig = client_sig_over(&sk_a, &w, &b.new_state, &b.tx_hash);
        let framing = ForkClaim { a, b };
        let (mut smt, mut bans) = (crate::smt::SparseMerkleTree::new(), BanTable::new());
        smt.put(&head(w, [0x01; 32]));
        assert_eq!(
            apply_fork_verdict(&mut smt, &mut bans, &framing),
            Err(ForkClaimRefusal::LegA(ForkLegRefusal::ClientSigInvalid))
        );
        assert!(!bans.is_banned(&w), "W must never be banned by A's key");
        assert!(!bans.is_banned(&pk_a), "a refused claim bans no one");
        assert_eq!(bans.atraxi_evidence_refused(), 1, "the refusal is COUNTED");
        assert!(bans.take_pending_fork_floods().is_empty(), "a refused claim is never flooded");
        assert_eq!(smt.get(&w).unwrap().status, WalletStatus::Normal);

        // Control 1 — honest A-bucket signatures: bans exactly {A}.
        let (a, b) = fork_pair(0xA8, 3);
        let claim = ForkClaim { a, b };
        assert_eq!(fork_ban_keys(&claim), vec![pk_a]);
        assert_eq!(apply_fork_verdict(&mut smt, &mut bans, &claim), Ok(vec![pk_a]));
        assert!(!bans.is_banned(&w));

        // Control 2 — Ark-class legs hash the bucket: {A, bucket(A,0)}.
        let (a0, b0) = fork_pair(0xA9, 0);
        let pk9 = wallet(0xA9).verifying_key().to_bytes();
        let bucket0 = crate::registration::smt_bucket(&pk9, 0);
        assert_ne!(bucket0, pk9);
        let claim0 = ForkClaim { a: a0, b: b0 };
        assert_eq!(fork_ban_keys(&claim0), vec![pk9, bucket0]);
        let mut bans0 = BanTable::new();
        assert_eq!(
            apply_fork_verdict(&mut crate::smt::SparseMerkleTree::new(), &mut bans0, &claim0),
            Ok(vec![pk9, bucket0])
        );
    }

    /// Test 9 — one leg from A, one from B, same parent value: two wallets,
    /// no fork. MUTATION: drop the pk-equality check ⇒ red.
    #[test]
    fn fork_claim_rejects_legs_under_two_keys() {
        let a = genuine_send_leg(&wallet(0xAA), Y, 5, P, 400, 1, 3);
        let b = genuine_send_leg(&wallet(0xAB), Y, 5, Q, 400, 2, 3);
        assert_eq!(verify_fork_claim(&ForkClaim { a, b }), Err(ForkClaimRefusal::DifferentClientPk));
    }

    /// The record hook counts a leg the PATH accepted but `verify_fork_leg`
    /// refused (`origin_leg_unrecordable`, RULE 3 §2) — here a leg whose
    /// client sig is over another wallet's bucket — and does NOT count the
    /// expected refusal (a zero pk); a zero-consumed redeem is recorded as a
    /// root (W7c) and counted apart. MUTATION: drop the counter bump ⇒ RED;
    /// count every refusal (incl. ZeroPk) ⇒ RED.
    #[test]
    fn record_leg_and_detect_counts_unrecordable_but_not_redeem_or_zero_pk() {
        use crate::types::test_legs;
        let mut smt = crate::smt::SparseMerkleTree::new();
        let mut bans = BanTable::new();
        let sk = test_legs::wallet(0x91);
        let mut framed = test_legs::genuine_send_leg(&sk, [0x19; 32], 1, "p@axiom.internal/0123456789", 5, 1, 3);
        framed.client_sig = test_legs::client_sig_over(&sk, &[0x77; 32], &framed.new_state, &framed.tx_hash);
        assert_eq!(
            record_leg_and_detect(&mut smt, &mut bans, framed, 1, "test"),
            LegRecordOutcome::NotRecordable(ForkLegRefusal::ClientSigInvalid),
        );
        assert_eq!(bans.origin_leg_unrecordable(), 1);
        // W7c [R33] — a genuine redeem leg declaring NO parent (zero consumed)
        // is recorded as a grounding root OUT of the fork index, counted
        // apart, never as "unrecordable".
        let redeem = test_legs::genuine_redeem_leg(&sk, [0u8; 32], &crate::types::test_legs::stray_origin([0x1A; 32]), 5, 1, 3);
        assert_eq!(
            record_leg_and_detect(&mut smt, &mut bans, redeem, 1, "test"),
            LegRecordOutcome::Recorded { contested: false },
        );
        assert_eq!(bans.redeem_leg_zero_consumed(), 1);
        assert_eq!(smt.redeem_len(), 1, "a zero-consumed redeem is recorded (W7c root)");
        assert!(smt.legs_under(&(sk.verifying_key().to_bytes(), [0u8; 32])).is_empty(), "never indexed");
        let mut zero = test_legs::genuine_send_leg(&sk, [0x19; 32], 1, "r@axiom.internal/0123456789", 5, 3, 3);
        if let crate::types::LegPreimage::Send(p) = &mut zero.seq_proof.preimage { p.client_pk = [0u8; 32]; }
        assert_eq!(
            record_leg_and_detect(&mut smt, &mut bans, zero, 1, "test"),
            LegRecordOutcome::NotRecordable(ForkLegRefusal::ZeroPk),
        );
        assert_eq!(bans.origin_leg_unrecordable(), 1, "expected refusals are not counted");
        assert_eq!(smt.origin_len(), 0);
    }

    // ── Fork Settlement W7b — the Redeem arm (spec R52c) ──────────────────

    /// A receiver R redeeming TWO cheques from ONE state R0 (on two validator
    /// sets) is a fork: two wallet-signed, k-witnessed children of R0 with
    /// different (cheque) txids. The ONE verifier accepts it and the ban keys
    /// are R's own. Real keys throughout.
    /// MUTATION (run 2026-09-28): make `check_fork_leg` refuse every redeem leg
    /// (the pre-W7b `NotASendLeg` arm) ⇒ THIS test red (`LegA(..)`).
    #[test]
    fn fork_claim_redeem_arm_accepts_two_redeems_from_one_state() {
        let r = test_legs::wallet(0xA7);
        let r0: StateId = [0x70; 32];
        let a = test_legs::genuine_redeem_leg(&r, r0, &crate::types::test_legs::stray_origin([0x71; 32]), 500, 4, 3);
        let b = test_legs::genuine_redeem_leg(&r, r0, &crate::types::test_legs::stray_origin([0x72; 32]), 900, 4, 3);
        assert_eq!(verify_fork_claim(&ForkClaim { a: a.clone(), b: b.clone() }), Ok(()));
        assert_eq!(fork_ban_keys(&ForkClaim { a, b }), vec![r.verifying_key().to_bytes()]);
    }

    /// A send and a redeem from ONE state are a fork too (shared key).
    #[test]
    fn fork_claim_redeem_arm_accepts_send_and_redeem_from_one_state() {
        let r = test_legs::wallet(0xA8);
        let r0: StateId = [0x73; 32];
        let send = test_legs::genuine_send_leg(&r, r0, 4, "p@axiom.internal/0123456789", 10, 1, 3);
        let redeem = test_legs::genuine_redeem_leg(&r, r0, &crate::types::test_legs::stray_origin([0x74; 32]), 900, 4, 3);
        assert_eq!(verify_fork_claim(&ForkClaim { a: send, b: redeem }), Ok(()));
    }

    /// The honest receive chain is NOT a fork: R0 → R1 (redeem cheque 1) then
    /// R1 → R2 (redeem cheque 2) — different parents. And every redeem-leg
    /// binding refuses on its own: a tampered preimage, a sub-quorum, a
    /// client sig over another bucket, a wrong carried seq, a zero parent.
    #[test]
    fn fork_claim_redeem_arm_refusals() {
        let r = test_legs::wallet(0xA9);
        let r0: StateId = [0x75; 32];
        let a = test_legs::genuine_redeem_leg(&r, r0, &crate::types::test_legs::stray_origin([0x76; 32]), 500, 4, 3);
        let chained = test_legs::genuine_redeem_leg(&r, a.new_state, &crate::types::test_legs::stray_origin([0x77; 32]), 900, 4, 3);
        assert_eq!(verify_fork_claim(&ForkClaim { a: a.clone(), b: chained }),
            Err(ForkClaimRefusal::DifferentParent));
        // The same redeem seen twice is an honest retry.
        assert_eq!(verify_fork_claim(&ForkClaim { a: a.clone(), b: a.clone() }),
            Err(ForkClaimRefusal::SameTxHash));

        let mut tampered = a.clone();
        if let crate::types::LegPreimage::Redeem { redeem: p, .. } = &mut tampered.seq_proof.preimage { p.new_balance += 1; }
        assert!(matches!(verify_fork_leg(tampered).err(), Some(ForkLegRefusal::Leg(_))));

        let mut sub = a.clone();
        sub.seq_proof.sigs.truncate(2);
        assert_eq!(verify_fork_leg(sub).err(), Some(ForkLegRefusal::WitnessSigsBelowQuorum));

        let mut wrong_seq = a.clone();
        wrong_seq.seq_proof.declared.wallet_seq += 1;
        assert_eq!(verify_fork_leg(wrong_seq).err(), Some(ForkLegRefusal::WitnessSigsBelowQuorum),
            "the carried seq is only as good as the k-signed commitment it recomputes");

        let mut framed = a.clone();
        framed.client_sig = test_legs::client_sig_over(&r, &[0xEE; 32], &a.new_state, &a.tx_hash);
        assert_eq!(verify_fork_leg(framed).err(), Some(ForkLegRefusal::ClientSigInvalid));

        // W7c — a zero-consumed redeem is a VERIFIED leg (a grounding root)
        // but never a claim member [R33].
        let zero = test_legs::genuine_redeem_leg(&r, [0u8; 32], &crate::types::test_legs::stray_origin([0x78; 32]), 1, 4, 3);
        assert!(verify_fork_leg(zero.clone()).is_ok());
        let zero2 = test_legs::genuine_redeem_leg(&r, [0u8; 32], &crate::types::test_legs::stray_origin([0x79; 32]), 1, 4, 3);
        assert_eq!(verify_fork_claim(&ForkClaim { a: zero, b: zero2 }),
            Err(ForkClaimRefusal::LegA(ForkLegRefusal::ZeroConsumedRedeem)));
    }

    /// R52d — a genuine send leg is state-bound (its declared balance + seq
    /// reproduce `new_state`); a lying declared balance, or a `new_state` the
    /// preimage did not produce, is not. A redeem leg is bound by its
    /// commitment. MUTATION (run 2026-09-28): make
    /// `send_leg_produced_state_matches` return `true` ⇒ THIS test red.
    #[test]
    fn leg_is_state_bound_send_recomputes_redeem_by_commitment() {
        let sk = test_legs::wallet(0xAA);
        let good = test_legs::genuine_send_leg(&sk, [0x79; 32], 3, "p@axiom.internal/0123456789", 40, 9, 3);
        assert!(leg_is_state_bound(&good));
        let mut lying = good.clone();
        lying.seq_proof.declared.balance += 1;
        assert!(!leg_is_state_bound(&lying), "a declared balance that did not produce new_state");
        let mut bad_seq = good.clone();
        bad_seq.seq_proof.declared.wallet_seq += 1;
        assert!(!leg_is_state_bound(&bad_seq));
        let redeem = test_legs::genuine_redeem_leg(&sk, [0x7A; 32], &crate::types::test_legs::stray_origin([0x7B; 32]), 10, 3, 3);
        assert!(leg_is_state_bound(&redeem));
    }

    /// `ForkLeg::origin_record` is the ONE conversion to Core's attestation
    /// payload: Core binds it to the cheque by recomputing
    /// `preimage.txid(epoch)` — which must be this leg's txid. A redeem leg has
    /// no origin [R33].
    #[test]
    fn fork_leg_origin_record_recomputes_to_its_txid() {
        let (a, _) = fork_pair(0xB0, 3);
        let o = a.origin_record().expect("send leg has an origin");
        assert_eq!(o.preimage.txid(o.epoch), a.tx_hash);
        assert_eq!(o.kind, axiom_core_logic::types::LegKind::Send);
        let mut r = a;
        r.seq_proof.preimage = crate::types::test_legs::opaque_redeem_leg();
        assert!(r.origin_record().is_none());
    }

    /// A zero-pk leg is never a verified leg (an unauthored leg names no one).
    #[test]
    fn fork_leg_refuses_zero_pk() {
        let (mut a, _) = fork_pair(0xAD, 3);
        if let crate::types::LegPreimage::Send(p) = &mut a.seq_proof.preimage {
            p.client_pk = [0u8; 32];
        }
        assert_eq!(verify_fork_leg(a).err(), Some(ForkLegRefusal::ZeroPk));
    }

    /// The verdict path: verified → the registrant banned WITH the claim as
    /// evidence, its held head flipped to `Banned` on the SAME head (a §4.6
    /// read reports it), the claim queued ONCE for WAL + flood; a second
    /// verdict on the same key (the 3rd leg of a 3-way fork) bans nothing new
    /// and queues nothing — write-once, like `ban_seq_fork`.
    /// MUTATION (run 2026-09-28): drop the head flip ⇒ red.
    #[test]
    fn apply_fork_verdict_bans_flips_head_queues_once_and_is_write_once() {
        let sk = wallet(0xAE);
        let pk = sk.verifying_key().to_bytes();
        let a = genuine_send_leg(&sk, Y, 5, P, 400, 1, 3);
        let b = genuine_send_leg(&sk, Y, 5, Q, 400, 2, 3);
        let c = genuine_send_leg(&sk, Y, 5, "r@axiom.internal/0123456789", 400, 3, 3);
        let (mut smt, mut bans) = (crate::smt::SparseMerkleTree::new(), BanTable::new());
        smt.put(&head(pk, a.tx_hash));
        let ab = ForkClaim { a: a.clone(), b };
        assert_eq!(apply_fork_verdict(&mut smt, &mut bans, &ab), Ok(vec![pk]));
        assert_eq!(bans.get(&pk).unwrap().evidence, BanEvidence::Fork(ab.clone()));
        let held = smt.get(&pk).unwrap();
        assert_eq!(held.status, WalletStatus::Banned, "the held head is flipped");
        assert_eq!(held.tx_hash, a.tx_hash, "…on the SAME head");
        assert_eq!(bans.fork_claims_applied(), 1);
        assert_eq!(bans.take_pending_fork_floods(), vec![ab.clone()], "queued once");

        // 3-way fork: the (a, c) claim is genuine but its key is already banned.
        let ac = ForkClaim { a, b: c };
        assert_eq!(verify_fork_claim(&ac), Ok(()));
        assert_eq!(apply_fork_verdict(&mut smt, &mut bans, &ac), Ok(vec![]));
        assert_eq!(bans.get(&pk).unwrap().evidence, BanEvidence::Fork(ab), "evidence is write-once");
        assert!(bans.take_pending_fork_floods().is_empty(), "no re-flood for an already-banned key");
        assert_eq!(bans.fork_claims_applied(), 1);
        assert_eq!(bans.atraxi_evidence_refused(), 0);
    }

    /// R36 — the strict `BannedEntry` decoder: current shape decodes (each
    /// evidence kind), trailing bytes are refused. MUTATION:
    /// `.allow_trailing_bytes()` ⇒ red.
    #[test]
    fn decode_banned_entry_is_strict() {
        let (a, b) = fork_pair(0xAF, 3);
        let e = BannedEntry {
            wallet_id: [0xAF; 32],
            evidence: BanEvidence::Fork(ForkClaim { a, b }),
            status: BanStatus::Active,
        };
        let mut bytes = bincode::serialize(&e).unwrap();
        assert_eq!(decode_banned_entry(&bytes).unwrap(), e);
        bytes.extend_from_slice(&[0u8; 3]);
        assert!(decode_banned_entry(&bytes).is_err());
    }
}
