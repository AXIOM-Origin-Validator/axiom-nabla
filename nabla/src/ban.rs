// AXIOM Nabla — Ban Detection & Challenge Protocol
// Reference: AXIOM_GUIDE_Nabla.md Sections 2.7, 6.4
//
// Phase 1 Task 9: Ban detection (conflict → BANNED, separate table)
// S6: BANNED Challenge Protocol (Active → Challenged → Reversed)
//
// BANNED entries are stored in a separate flat table (not in SMT) because
// they need different access patterns (scan all bans, gossip evidence).
//
// S6 CHALLENGE PROTOCOL:
//   1. Wallet is banned (BanStatus::Active) with double-spend evidence.
//   2. Wallet owner presents ChallengeEvidence: k≥3 Nabla endorsements.
//   3. Ban transitions to BanStatus::Challenged (waiting CHALLENGE_WINDOW).
//   4. After CHALLENGE_WINDOW ticks with no counter-evidence: BanStatus::Reversed.
//   5. Reversed wallets are restored to Normal in the SMT.

use std::collections::{HashMap, HashSet};

use crate::crypto::Signer;
use crate::types::{
    BanStatus, BannedEntry, ChallengeEvidence, ConflictProof, NablaError, WalletId,
};

/// Challenge window: number of ticks a challenge must survive before reversal.
/// Production: 720 ticks ≈ 1 hour (at 5-second ticks).
/// Dev mode: 12 ticks ≈ 1 minute.
pub const CHALLENGE_WINDOW_TICKS: u64 = 720;
pub const CHALLENGE_WINDOW_TICKS_DEV: u64 = 12;

/// Minimum Nabla endorsements required for a challenge (k=3).
pub const MIN_CHALLENGE_ENDORSEMENTS: usize = 3;

/// Ban table — separate from SMT.
/// Supports lifecycle: Active → Challenged → Reversed.
pub struct BanTable {
    bans: HashMap<WalletId, BannedEntry>,
    challenge_window: u64,
}

impl BanTable {
    pub fn new() -> Self {
        Self {
            bans: HashMap::new(),
            challenge_window: CHALLENGE_WINDOW_TICKS,
        }
    }

    pub fn new_dev() -> Self {
        Self {
            bans: HashMap::new(),
            challenge_window: CHALLENGE_WINDOW_TICKS_DEV,
        }
    }

    /// Check if a wallet is actively banned (Active or Challenged, not Reversed).
    pub fn is_dev_mode(&self) -> bool { self.challenge_window == CHALLENGE_WINDOW_TICKS_DEV }

    pub fn is_banned(&self, wallet_id: &WalletId) -> bool {
        match self.bans.get(wallet_id) {
            Some(entry) => !matches!(entry.status, BanStatus::Reversed { .. }),
            None => false,
        }
    }

    /// Check if a wallet has an active (non-challenged, non-reversed) ban.
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

    /// Ban a wallet. Requires two conflicting proofs.
    ///
    /// Conflict means: same wallet, same old_state consumed by two different
    /// transactions producing different new_states. This is a double-spend.
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

        log::warn!(
            "BANNING wallet {:?}: double-spend detected",
            &wallet_id[..4]
        );

        self.bans.insert(
            wallet_id,
            BannedEntry {
                wallet_id,
                evidence_1,
                evidence_2,
                seq_fork: None,
                status: BanStatus::Active,
            },
        );

        true
    }

    /// Ban a wallet on GOSSIP-path double-spend FORK evidence (two k=3-attested
    /// successors of the same predecessor — `SeqConflictProof`). This is the
    /// origination path the normal-send cross-node double-spend previously lacked.
    /// Caller MUST have verified the evidence (`verify_seq_conflict`) first.
    /// Returns true if this is a new ban.
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
                evidence_1: ConflictProof::default(),
                evidence_2: ConflictProof::default(),
                seq_fork: Some(evidence),
                status: BanStatus::Active,
            },
        );
        true
    }

    /// Verify gossip-path seq-fork evidence: two DISTINCT k=3-attested states at
    /// the SAME `wallet_seq`. Same seq ⟹ both consumed the same predecessor; both
    /// k=3-witnessed ⟹ the conflict cannot be accidental. No Core `Signer` needed —
    /// `verify_seq_proof` checks the Ed25519 receipt-commitment sigs directly.
    pub fn verify_seq_conflict(
        wallet_id: &WalletId,
        ev: &crate::types::SeqConflictProof,
    ) -> bool {
        let _ = wallet_id; // identity is bound into each SeqProof's commitment
        if ev.state_a == ev.state_b || ev.tx_a == ev.tx_b {
            return false;
        }
        crate::registration::verify_seq_proof(&ev.proof_a, &ev.tx_a, ev.wallet_seq)
            && crate::registration::verify_seq_proof(&ev.proof_b, &ev.tx_b, ev.wallet_seq)
    }

    /// Challenge an existing ban with evidence.
    ///
    /// Requirements:
    ///   - Wallet must be in ban table with BanStatus::Active
    ///   - Challenge must have ≥ MIN_CHALLENGE_ENDORSEMENTS unique Nabla signatures
    ///   - All endorsement signatures must verify
    ///
    /// On success, transitions ban to BanStatus::Challenged.
    pub fn challenge(
        &mut self,
        wallet_id: &WalletId,
        evidence: ChallengeEvidence,
        current_tick: u64,
        signer: &dyn Signer,
    ) -> Result<(), NablaError> {
        let entry = self.bans.get(wallet_id).ok_or(NablaError::WalletNotBanned)?;

        match &entry.status {
            BanStatus::Active => {} // proceed
            BanStatus::Challenged { .. } => return Err(NablaError::BanAlreadyChallenged),
            BanStatus::Reversed { .. } => return Err(NablaError::BanAlreadyReversed),
        }

        // Verify k≥3 unique endorsements
        if evidence.nabla_signatures.len() < MIN_CHALLENGE_ENDORSEMENTS {
            return Err(NablaError::InsufficientEndorsements {
                need: MIN_CHALLENGE_ENDORSEMENTS,
                got: evidence.nabla_signatures.len(),
            });
        }

        // Check for duplicate endorser node_ids
        let mut seen_nodes = HashSet::new();
        for endorsement in &evidence.nabla_signatures {
            if !seen_nodes.insert(endorsement.node_id) {
                return Err(NablaError::DuplicateEndorser);
            }
        }

        // Verify each endorsement signature
        // Commitment = BLAKE3("AXIOM_BAN_CHALLENGE" || wallet_id || original_tx_id)
        let commitment = compute_challenge_commitment(wallet_id, &evidence.original_tx_id);
        for endorsement in &evidence.nabla_signatures {
            if !signer.verify(&endorsement.node_id, &commitment, &endorsement.signature) {
                return Err(NablaError::InvalidEndorsementSignature);
            }
        }

        // Transition to Challenged
        let entry = self.bans.get_mut(wallet_id).unwrap();
        entry.status = BanStatus::Challenged {
            challenge_tick: current_tick,
            evidence,
        };

        log::info!(
            "BAN CHALLENGED: wallet {:02x}{:02x}... at tick {}",
            wallet_id[0], wallet_id[1], current_tick
        );

        Ok(())
    }

    /// Check all challenged bans and reverse those whose window has expired.
    /// Returns list of wallet IDs that were reversed.
    pub fn check_challenge_resolution(&mut self, current_tick: u64) -> Vec<WalletId> {
        let mut reversed = Vec::new();
        for entry in self.bans.values_mut() {
            if let BanStatus::Challenged { challenge_tick, .. } = &entry.status {
                if current_tick >= challenge_tick + self.challenge_window {
                    entry.status = BanStatus::Reversed {
                        reversed_at_tick: current_tick,
                    };
                    reversed.push(entry.wallet_id);
                    log::info!(
                        "BAN REVERSED: wallet {:02x}{:02x}... at tick {}",
                        entry.wallet_id[0], entry.wallet_id[1], current_tick
                    );
                }
            }
        }
        reversed
    }

    /// Verify that two conflict proofs represent a genuine double-spend.
    ///
    /// Both proofs must:
    /// - Reference the same old_state (consumed the same state)
    /// - Produce different new_states (different transactions)
    /// - Have valid k=3 signatures (both transactions were really witnessed)
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

        // Both must have k=3 signatures
        if ev1.k3_signatures.len() < 3 || ev2.k3_signatures.len() < 3 {
            return false;
        }

        // Different tx_hash (same TX can't produce different states)
        if ev1.tx_hash == ev2.tx_hash {
            return false;
        }

        // Verify all k=3 witness signatures via Core (Signer trait).
        // Payload: receipt_sign_payload(wallet_id, consumed, tick) —
        // (wallet_id, consumed) is unique per TX because wallet state
        // advances strictly forward. produced_state and txid are dropped
        // from the payload to keep Lambda's sign payload and Nabla's
        // verify payload byte-identical without needing aggregate
        // total_fee knowledge.
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

impl Default for BanTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the challenge commitment: BLAKE3("AXIOM_BAN_CHALLENGE" || wallet_id || tx_id).
pub fn compute_challenge_commitment(wallet_id: &WalletId, original_tx_id: &[u8; 32]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_BAN_CHALLENGE");
    hasher.update(wallet_id);
    hasher.update(original_tx_id);
    hasher.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ChallengeEndorsement, WitnessSig};

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
        }
    }

    fn make_challenge_evidence(tx_byte: u8) -> ChallengeEvidence {
        ChallengeEvidence {
            original_tx_id: [tx_byte; 32],
            nabla_signatures: vec![
                ChallengeEndorsement { node_id: [0x10; 32], signature: vec![0x10; 64] },
                ChallengeEndorsement { node_id: [0x20; 32], signature: vec![0x20; 64] },
                ChallengeEndorsement { node_id: [0x30; 32], signature: vec![0x30; 64] },
            ],
        }
    }

    fn banned_table(wid: WalletId) -> BanTable {
        let mut table = BanTable::new();
        table.ban(wid, make_conflict_proof(0x10, 0x20, 0xA1), make_conflict_proof(0x10, 0x30, 0xA2));
        table
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

    // ── S6: Challenge Protocol Tests ──

    #[test]
    fn challenge_active_ban_accepted() {
        let wid = [0xAA; 32];
        let mut table = banned_table(wid);
        let evidence = make_challenge_evidence(0xA1);

        let result = table.challenge(&wid, evidence, 100, &crate::crypto::NoopSigner);
        assert!(result.is_ok());
        assert!(matches!(
            table.get(&wid).unwrap().status,
            BanStatus::Challenged { challenge_tick: 100, .. }
        ));
        // Still counts as banned (Challenged blocks wallet)
        assert!(table.is_banned(&wid));
        assert!(!table.is_active_ban(&wid));
    }

    #[test]
    fn challenge_not_banned_rejected() {
        let wid = [0xAA; 32];
        let mut table = BanTable::new();
        let evidence = make_challenge_evidence(0xA1);

        let result = table.challenge(&wid, evidence, 100, &crate::crypto::NoopSigner);
        assert!(matches!(result, Err(NablaError::WalletNotBanned)));
    }

    #[test]
    fn challenge_already_challenged_rejected() {
        let wid = [0xAA; 32];
        let mut table = banned_table(wid);
        let evidence = make_challenge_evidence(0xA1);
        table.challenge(&wid, evidence.clone(), 100, &crate::crypto::NoopSigner).unwrap();

        let result = table.challenge(&wid, evidence, 200, &crate::crypto::NoopSigner);
        assert!(matches!(result, Err(NablaError::BanAlreadyChallenged)));
    }

    #[test]
    fn challenge_insufficient_endorsements() {
        let wid = [0xAA; 32];
        let mut table = banned_table(wid);
        let mut evidence = make_challenge_evidence(0xA1);
        evidence.nabla_signatures.truncate(2); // only 2

        let result = table.challenge(&wid, evidence, 100, &crate::crypto::NoopSigner);
        assert!(matches!(result, Err(NablaError::InsufficientEndorsements { need: 3, got: 2 })));
    }

    #[test]
    fn challenge_duplicate_endorser_rejected() {
        let wid = [0xAA; 32];
        let mut table = banned_table(wid);
        let mut evidence = make_challenge_evidence(0xA1);
        evidence.nabla_signatures[1].node_id = evidence.nabla_signatures[0].node_id; // duplicate

        let result = table.challenge(&wid, evidence, 100, &crate::crypto::NoopSigner);
        assert!(matches!(result, Err(NablaError::DuplicateEndorser)));
    }

    #[test]
    fn challenge_resolution_before_window() {
        let wid = [0xAA; 32];
        let mut table = banned_table(wid);
        table.challenge(&wid, make_challenge_evidence(0xA1), 100, &crate::crypto::NoopSigner).unwrap();

        // Not enough ticks elapsed
        let reversed = table.check_challenge_resolution(100 + CHALLENGE_WINDOW_TICKS - 1);
        assert!(reversed.is_empty());
        assert!(table.is_banned(&wid)); // still banned
    }

    #[test]
    fn challenge_resolution_after_window() {
        let wid = [0xAA; 32];
        let mut table = banned_table(wid);
        table.challenge(&wid, make_challenge_evidence(0xA1), 100, &crate::crypto::NoopSigner).unwrap();

        // Enough ticks elapsed
        let reversed = table.check_challenge_resolution(100 + CHALLENGE_WINDOW_TICKS);
        assert_eq!(reversed.len(), 1);
        assert_eq!(reversed[0], wid);
        assert!(!table.is_banned(&wid)); // no longer banned
        assert!(matches!(
            table.get(&wid).unwrap().status,
            BanStatus::Reversed { .. }
        ));
    }

    #[test]
    fn reversed_ban_not_active() {
        let wid = [0xAA; 32];
        let mut table = banned_table(wid);
        table.challenge(&wid, make_challenge_evidence(0xA1), 100, &crate::crypto::NoopSigner).unwrap();
        table.check_challenge_resolution(100 + CHALLENGE_WINDOW_TICKS);

        assert!(!table.is_banned(&wid));
        assert!(!table.is_active_ban(&wid));
    }

    #[test]
    fn challenge_commitment_deterministic() {
        let wid = [0xAA; 32];
        let tx = [0xBB; 32];
        let c1 = compute_challenge_commitment(&wid, &tx);
        let c2 = compute_challenge_commitment(&wid, &tx);
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 32);

        // Different inputs → different commitment
        let c3 = compute_challenge_commitment(&[0xCC; 32], &tx);
        assert_ne!(c1, c3);
    }
}
