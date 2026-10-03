// AXIOM Nabla — Companion Certificate and Runner Reward
// Reference: AXIOM_GUIDE_Nabla.md Section 7
//
// Phase 5 Tasks:
//   36. NBC (Nabla Birth Certificate) issuance and storage
//   37. Companion Certificate struct and serialization
//   38. CC chain: Core produces new CC per tick (prev_cc + tick approval + receipts)
//   39. CC ZKP proof generation (verify prev CC, tick approval sigs, receipt sigs)
//   40. CC storage (only latest CC kept, previous discarded)
//   41. DEED fee split logic (30/70 for years 1-10, 100/0 after)
//   42. Nabla Runner Pool accumulator (on-chain, fed by DEED split)
//   43. Runner claim handler (submit CC to validator, verify proof, compute share)
//   44. One-claim-per-period enforcement (one NBC = one claim per 24 hours)
//   45. Score calculation (W1=1 uptime, W2=10 registrations — defined below as SCORE_W1/SCORE_W2)
//   46. Tests
//
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  ARCHITECTURAL RULE: Nabla NEVER does cryptography.                ║
// ║  NBC = VBC from Core (YPX-002: same VBC function, role = nabla).  ║
// ║  CC proofs are produced by Core.execute() — Nabla stores results. ║
// ║  Nabla manages the CC chain, stores CCs, tracks scores.           ║
// ╚══════════════════════════════════════════════════════════════════════╝

use serde::{Deserialize, Serialize};

use crate::constants::*;
use crate::crypto::{self, Signer};
use crate::types::*;

// Re-export VBC from Core — NBC IS a VBC (YPX-002 §2: "same VBC function
// from Core with role = nabla").
pub use axiom_core_logic::types::VBC;

// ════════════════════════════════════════════════════════════════════════
// Task 36: NBC (Nabla Birth Certificate)
// ════════════════════════════════════════════════════════════════════════

/// NBC = VBC. Same struct, same Core verification path.
///
/// YPX-002: "Nabla identity: NBC (Nabla Birth Certificate) using same VBC
/// function from Core with role = 'nabla'. Same trust chain, different
/// participant type."
///
/// - Generation: Core creates and signs the VBC (genesis or k=1 issuance)
/// - Verification: Core verifies VBC chain (same verify_vbc_bundle path)
/// - Storage: Nabla stores the VBC blob Core returns
/// - node_id in Nabla = validator_id in VBC = BLAKE3(sphincs_pk)
///
/// Nabla NEVER does any cryptographic operations on the NBC/VBC.
pub type NBC = VBC;

/// Extract node_id from an NBC (= VBC.validator_id).
/// Nabla's NodeId is the same as VBC's validator_id.
pub fn nbc_node_id(nbc: &NBC) -> NodeId {
    nbc.validator_id
}

/// GUIDE §5.6c (KI#75, ruled 2026-09-25) — THE join-probation predicate.
/// Every lever calls this (RULE 1): TARDIS attach refusal + upstream
/// candidate skip, the OODS baseline, the Nabla emission claim, the Alert
/// gate, and `/status`'s `probationary_peers`.
///
/// A certificate is probationary while it is a citizen NBC (`chain_depth !=
/// 0`; genesis is exempt) AND younger than `nabla_probation_ticks`. The
/// judgement uses ONLY the signed certificate's `issued_at` — verified on
/// every hop, so network-attested — never a local "joined at" clock: a
/// re-join, a peer hop or a restart cannot reset it, and expiry needs no
/// promotion message (each peer recomputes it per tick).
///
/// Units: `issued_at` and `now_tick` are tick VALUES (unix seconds, KI#47);
/// the register is a tick COUNT, projected once by
/// `nabla_probation_span_secs` (KI#40/#165 class).
pub fn is_probationary(nbc: &NBC, now_tick: u64) -> bool {
    nbc.chain_depth != 0 && now_tick < probation_ends_at(nbc)
}

/// The tick VALUE (unix seconds) at which `nbc` leaves probation:
/// `issued_at + projected window`. For a genesis certificate this is
/// still computed (the caller decides exemption via `is_probationary`);
/// reported to a joiner as `probation_until`.
pub fn probation_ends_at(nbc: &NBC) -> u64 {
    nbc.issued_at.saturating_add(nabla_probation_span_secs())
}

/// Peer trust record — the cached NBC of a peer that completed the join
/// protocol, plus the wallet it bound to.
///
/// Carries NO trust status field: since §5.6c the status is derived from
/// the certificate on read (`trust_status`). The old `status:
/// NbcTrustStatus::Probation { since }` was written from the local clock at
/// join and never read in production (KI#75).
#[derive(Debug, Clone)]
pub struct PeerTrust {
    pub nbc: NBC,
    pub wallet_id: Option<WalletId>,
}

impl PeerTrust {
    /// The peer's trust status at `now_tick`, derived from its NBC.
    pub fn trust_status(&self, now_tick: u64) -> NbcTrustStatus {
        if self.nbc.chain_depth == 0 {
            NbcTrustStatus::Genesis
        } else if is_probationary(&self.nbc, now_tick) {
            NbcTrustStatus::Probation
        } else {
            NbcTrustStatus::Confirmed
        }
    }
}

/// Build a placeholder VBC for simulation/testing.
///
/// NOT for production. In production, Core creates and signs NBCs.
/// This populates a VBC struct with minimal placeholder data so the
/// sim and tests can run without a real Core binary.
pub fn sim_nbc(node_id: NodeId, created_at: u64) -> NBC {
    VBC {
        version: 0x09,
        validator_id: node_id,
        subject_pubkey_sphincs: node_id.to_vec(),
        subject_pubkey_dilithium: vec![0u8; 1952],
        subject_pubkey_ed25519: node_id.to_vec(),
        pgp_fingerprint: vec![],
        node_name: String::new(),
        proof_cap: String::new(),
        issued_at: created_at,
        expires_at: created_at + NBC_EXPIRY_SECS,
        chain_depth: 0,
        issuer_set: vec![node_id.to_vec()],   // self-signed in sim
        signatures: vec![vec![]],              // empty sig — sim only
        max_tx: 0,                              // unlimited in sim
        founding_vbc_hash: [0u8; 32],
        network_size_baseline: 0, // sim — no baseline (genesis-style exempt)
        baseline_tick: 0,
        // §5.3 does not apply to NBCs — Nabla citizens have no genesis family.
        genesis_lineage: [0u8; 32],
        nabla_registration: None,
    }
}

// ════════════════════════════════════════════════════════════════════════
// NBC Verification (Phase 6 — Identity verification on connect)
// ════════════════════════════════════════════════════════════════════════

/// Verify structural integrity and SPHINCS+ signatures of an NBC.
///
/// **Dev/sim fallback** — when Core IPC is not available (no core_client).
/// In production, use `verify_nbc_via_core()` (CL7) which goes through Core
/// and produces zkVM-compatible outputs for the operator credit proof chain.
///
/// Checks performed:
///   a) Well-formed: all required fields present and valid lengths
///   b) Not expired: expires_at > current_tick
///   c) Identity match: validator_id == BLAKE3(subject_pubkey_sphincs)
///   d) Chain depth valid: issuer_set is non-empty
///   e) Ed25519 pubkey present (will be checked against tick signatures)
///   f) SPHINCS+ signature verification: each issuer's signature verified
///
/// Does NOT check root trust (issuer ∈ NABLA_ROOT_AUTHORITY_PKS) — use
/// verify_nbc_root_trust() for genesis NBCs.  For full chain-of-trust
/// verification on deep chains, use verify_nbc_chain().
pub fn verify_nbc(nbc: &NBC, current_tick: u64) -> Result<(), NablaError> {
    // (a) Well-formed: SPHINCS+ pubkey must be present and non-empty
    if nbc.subject_pubkey_sphincs.is_empty() {
        return Err(NablaError::NbcMalformed("missing SPHINCS+ public key".into()));
    }

    // (a) Well-formed: Ed25519 pubkey must be present and 32 bytes
    if nbc.subject_pubkey_ed25519.is_empty() {
        return Err(NablaError::NbcMalformed("missing Ed25519 public key".into()));
    }

    // (a) Well-formed: version must be 0x09 (v0.9)
    if nbc.version != 0x09 {
        return Err(NablaError::NbcMalformed(
            format!("unsupported version: 0x{:02x} (expected 0x09)", nbc.version),
        ));
    }

    // (b) Not expired
    if nbc.expires_at <= current_tick {
        return Err(NablaError::NbcExpired {
            expires_at: nbc.expires_at,
            current_tick,
        });
    }

    // (c) Identity match: validator_id == BLAKE3(sphincs_pk)
    // Use blake3 directly — this is a hash check, not crypto verification.
    let expected_id: [u8; 32] = blake3::hash(&nbc.subject_pubkey_sphincs).into();
    if nbc.validator_id != expected_id {
        return Err(NablaError::NbcIdentityMismatch);
    }

    // (d) Chain depth: issuer_set must be non-empty
    if nbc.issuer_set.is_empty() {
        return Err(NablaError::NbcMalformed("empty issuer_set".into()));
    }

    // (d) Signatures must match issuer count
    if nbc.signatures.len() != nbc.issuer_set.len() {
        return Err(NablaError::NbcMalformed(
            format!("signature count {} != issuer count {}", nbc.signatures.len(), nbc.issuer_set.len()),
        ));
    }

    // (e) node_name must not exceed 64 bytes UTF-8
    if nbc.node_name.len() > 64 {
        return Err(NablaError::NbcMalformed(
            format!("node_name exceeds 64 bytes: {} bytes", nbc.node_name.len()),
        ));
    }

    // SPHINCS+ single-hop signature verification.
    // Verifies each issuer's SPHINCS+ signature over the canonical VBC payload.
    // This catches forged/tampered NBCs without requiring Core IPC.
    let commitment = axiom_core_logic::compute::compute_vbc_signing_payload(nbc);
    for (issuer_pk, sig) in nbc.issuer_set.iter().zip(nbc.signatures.iter()) {
        axiom_core_logic::verify::verify_sphincs(issuer_pk, &commitment, sig)
            .map_err(|_| NablaError::NbcSignatureInvalid)?;
    }

    // NOTE: Full chain-of-trust for deep chains (chain_depth > 0) requires
    // verify_nbc_chain() which also checks root trust and supporting VBCs.

    Ok(())
}

/// Verify that a genesis NBC (chain_depth=0) was issued by a Nabla root authority.
///
/// Checks that every issuer in the NBC's issuer_set is in NABLA_ROOT_AUTHORITY_PKS.
/// This is separate from verify_nbc() because test-generated SPHINCS+ keys are NOT
/// in NABLA_ROOT_AUTHORITY_PKS — putting this check in verify_nbc() would break all
/// test helpers.
///
/// For non-genesis NBCs (chain_depth > 0), this check is skipped (root trust must
/// be established through the full chain via verify_nbc_chain()).
pub fn verify_nbc_root_trust(nbc: &NBC) -> Result<(), NablaError> {
    if nbc.chain_depth == 0 {
        for issuer_pk in &nbc.issuer_set {
            if !axiom_core_logic::nabla_genesis::is_nabla_root_authority(issuer_pk) {
                return Err(NablaError::NbcIssuerNotRoot);
            }
        }
    }
    Ok(())
}

/// Full NBC chain-of-trust verification.
///
/// Combines:
///   1. verify_nbc() — structural + SPHINCS+ single-hop
///   2. verify_nbc_root_trust() — genesis issuer ∈ NABLA_ROOT_AUTHORITY_PKS
///   3. For deep NBCs (chain_depth > 0): walk the issuer chain back to root,
///      verifying each issuer's NBC in the supporting chain.
///
/// Use this when the full supporting chain is available (e.g., at issuance
/// response time). For peer-to-peer verification without supporting chain,
/// use verify_nbc() + verify_nbc_root_trust() separately.
pub fn verify_nbc_chain(
    nbc: &NBC,
    supporting: &[NBC],
    current_tick: u64,
) -> Result<(), NablaError> {
    // Step 1: structural + SPHINCS+ single-hop on the target NBC
    verify_nbc(nbc, current_tick)?;

    // Step 2: root trust check (only meaningful for chain_depth=0)
    verify_nbc_root_trust(nbc)?;

    // Step 3: for chain_depth > 0, walk the issuer chain back to root.
    // verify_nbc() already checked the SPHINCS+ signature (issuer signed this NBC).
    // Now verify each issuer has a valid NBC that traces to a root authority.
    if nbc.chain_depth > 0 {
        for issuer_pk in &nbc.issuer_set {
            // Find the issuer's NBC in the supporting chain
            let issuer_nbc = supporting.iter()
                .find(|s| s.subject_pubkey_sphincs == *issuer_pk)
                .ok_or_else(|| NablaError::NbcMalformed(
                    "issuer NBC missing from supporting chain".into(),
                ))?;

            // Recursively verify the issuer's NBC
            verify_nbc_chain(issuer_nbc, supporting, current_tick)?;
        }
    }

    Ok(())
}

/// Does this (already VERIFIED) certificate name a PINNED genesis Nabla key
/// as its subject — `subject_pubkey_sphincs ∈
/// nabla_genesis::NABLA_GENESIS_VALIDATOR_PKS` (KI#97, the raw SPHINCS+ public
/// keys baked into Core)? THE one predicate (RULE 1): keyed by the pinned
/// PUBLIC KEYS only — no config, no address, no node-id list.
///
/// ⚠ Fable 2026-10-01 F-5: confers ZERO trust. Its readers are an ORDER (the
/// record-AE walk, `record_sync::TieredWalk`) and the emission ineligibility
/// of genesis nodes; no verdict, ban, vouch, grade or answer acceptance may
/// read it (`f5_genesis_predicate_confers_no_trust` greps the lib).
pub fn nbc_is_pinned_genesis(nbc: &NBC) -> bool {
    axiom_core_logic::nabla_genesis::NABLA_GENESIS_VALIDATOR_PKS
        .iter()
        .any(|k| k.as_slice() == nbc.subject_pubkey_sphincs.as_slice())
}

/// Extract the Ed25519 public key from an NBC, if present and valid (32 bytes).
///
/// Returns None if the Ed25519 key is missing or not exactly 32 bytes.
/// This key is bound into the NBC's SPHINCS+ signature and can be used
/// to verify tick signatures from this node.
pub fn nbc_ed25519_pk(nbc: &NBC) -> Option<[u8; 32]> {
    if nbc.subject_pubkey_ed25519.len() == 32 {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&nbc.subject_pubkey_ed25519);
        Some(pk)
    } else {
        None
    }
}

/// Full cryptographic NBC verification through Core IPC (CL7).
///
/// **Primary verification path** via AVM interpreter.
/// Executes CL7 NBC verification through the AVM interpreter directly.
/// Core runs verify_nbc_bundle() (k=1, NABLA_ROOT_AUTHORITY_PKS) which checks
/// SPHINCS+ chain-of-trust, expiry, Nabla root key binding.
///
/// Uses CL7 mode (NBC verification) instead of CL6 (VBC verification).
/// CL7 enforces k=1 issuer with NABLA_ROOT_AUTHORITY_PKS trust anchor.
///
/// Delegates to `verify_nbc_chain_via_core()` with empty supporting chain.
pub fn verify_nbc_via_core(
    avm: &axiom_dmap_vm::AvmInterpreter,
    nbc: &NBC,
    current_tick: u64,
) -> Result<(), NablaError> {
    verify_nbc_chain_via_core(avm, nbc, &[], current_tick)
}

/// Verify NBC with full chain-of-trust via AVM interpreter (CL7).
///
/// Unlike `verify_nbc_via_core()` which only handles root-signed NBCs,
/// this passes the full supporting chain for deep chain verification.
/// Core verifies the entire SPHINCS+ chain-of-trust from root to leaf.
pub fn verify_nbc_chain_via_core(
    avm: &axiom_dmap_vm::AvmInterpreter,
    nbc: &NBC,
    supporting: &[NBC],
    current_tick: u64,
) -> Result<(), NablaError> {
    use axiom_core_logic::types::{VBCProofBundle, Transaction, TxKind, PublicInputs};
    use axiom_core_logic::CoreLogicMode;

    let bundle = VBCProofBundle {
        target_vbc: nbc.clone(),
        supporting_vbcs: supporting.to_vec(),
        candidacy_pulse: None, renewal_work_receipt: None,
    };

    // CL7 only reads vbc_bundle and transaction.epoch — other fields are unused
    let inputs = PublicInputs {
        zkq_request: None,
        fact_certificates: Vec::new(),
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: None,
        fob_claim_attestation: None,
        claimant_vbc: None,
        receiver_witness: None,
        receiver_signing_key: None,
        recall_attestation: None,
        mode: CoreLogicMode::CL7,
        oods_attestation: None,
        // Nabla CL7 (VBC validation) doesn't process a TX; gate disabled by zero
        local_core_id: [0u8; 32],
        transaction: Transaction {
            consumed_state_id: [0u8; 32],
            client_pk: vec![],
            sender_wallet_id: String::new(),
            wallet_seq: 0,
            receiver_wallet_id: String::new(),
            receiver_address: None,
            amount: 0,
            reference: String::new(),
            nonce: 0,
            epoch: current_tick,
            client_sig: vec![],
            scar_passcode: None,
            burn_target_tx_id: None,
            required_k: 0,
            proof_type: 0,
            oracle_claim: None,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
            recall_target_tx_id: None,
        },
        prev_receipts: vec![],
        current_state: None,
        vbc_bundle: Some(bundle),
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_current_hibernation: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
        my_validator_pk: None,
        overlapped_signatures: vec![],
        group_member_index: None,
        sender_fact_chain: None,
        max_fact_links: None,
        receiver_fact_chain: None,
        my_dilithium_sk: None,
        my_dilithium_pk: None,
        my_validator_id: None,
        fact_witness_sigs: vec![],
        issuer_sphincs_sk: None,
        cl1_execution_proof: None,
        zkp_nonce: None,
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            nabla_stake_proof: None,
            frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None, txid_attestation: None,
            cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
    
    };

    let outputs = avm.execute(inputs)
        .map_err(|e| NablaError::NbcMalformed(format!("AVM CL7: {}", e)))?;

    match outputs.result {
        axiom_core_logic::ValidationResult::Accept => Ok(()),
        _ => {
            let reason = outputs.rejection_reason
                .map(|r| format!("{:?}", r))
                .unwrap_or_else(|| "unknown".into());
            Err(NablaError::NbcMalformed(format!("Core rejected NBC: {}", reason)))
        }
    }
}

/// Serialize an NBC to bytes for wire transmission.
pub fn serialize_nbc(nbc: &NBC) -> Vec<u8> {
    bincode::serialize(nbc).unwrap_or_default()
}

/// Deserialize an NBC from wire bytes.
pub fn deserialize_nbc(bytes: &[u8]) -> Result<NBC, NablaError> {
    if bytes.is_empty() {
        return Err(NablaError::NbcMissing("empty nbc_bytes".into()));
    }
    bincode::deserialize(bytes).map_err(|e| {
        NablaError::NbcMalformed(format!("deserialize failed: {}", e))
    })
}

// ════════════════════════════════════════════════════════════════════════
// NBC Peer-to-Peer Issuance (Phase 6 — peer issuance protocol)
// ════════════════════════════════════════════════════════════════════════
//
// Qualified Nabla nodes can issue NBCs to new nodes joining the network.
// Same crypto as ceremony: core-logic's sign_sphincs() directly.
// Core-logic IS Core.

/// Public keys for a new node requesting NBC issuance.
#[derive(Debug, Clone)]
pub struct NbcSubject {
    pub sphincs_pk: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub dilithium_pk: Vec<u8>,
    pub node_name: String,
    /// The node's ONE operator wallet (the owner, 2026-09-20: "Nabla binds one
    /// wallet and that is the operator wallet"). MUST be a REAL account — a dev
    /// account (`@axiom` / `@axiom.internal`) can never operate a Nabla node
    /// (`AXIOM_DESIGN_FactClassIsolation.md` preamble point 0). Empty = not
    /// declared (grandfathered genesis/renewal). `build_unsigned_nbc` rejects a
    /// dev operator. ⚠ FOLLOW-UP: bind this into the NBC signing preimage at the
    /// next genesis ceremony for a tamper-proof guarantee (today it is an
    /// issuance-time check, which matches the k=1 Nabla trust model).
    pub wallet_id: String,
}

/// Check if a node with the given NBC and SPHINCS+ SK is qualified to issue NBCs.
///
/// Requirements:
///   - Has a valid (non-expired) NBC
///   - Has SPHINCS+ secret key loaded
///   - NBC has been held long enough (maturity)
/// YPX-002 §9.1.1a (RULED 2026-09-25) — the issuer's per-epoch signing budget.
/// ONE (epoch, count) pair: the N+1-th certificate this node would SIGN inside
/// one FOB epoch is refused (`ISSUER_CAP_REACHED`); the next epoch starts a
/// fresh count. Persisted LAST in `NablaSnapshot` (no serde default) so a
/// restart cannot reset it. Genesis certificates are signed offline at the
/// ceremony, never through this path, so `chain_depth == 0` is exempt by
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct NbcIssuanceBudget {
    /// FOB epoch id (`constants::nbc_issuance_epoch`) the count belongs to.
    pub epoch: u64,
    /// Certificates signed in `epoch`.
    pub count: u64,
}

impl NbcIssuanceBudget {
    /// Would signing one more certificate in `epoch` exceed `cap`? A different
    /// epoch is a fresh budget (count reads as 0).
    pub fn at_cap(&self, epoch: u64, cap: u64) -> bool {
        let count = if self.epoch == epoch { self.count } else { 0 };
        count >= cap
    }

    /// Record one signed certificate in `epoch` (rolls the count when the
    /// epoch changed). Call AFTER a successful signature — a failed signing
    /// must not consume budget.
    pub fn record(&mut self, epoch: u64) {
        if self.epoch != epoch {
            self.epoch = epoch;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
    }

    /// Certificates signed in `epoch` so far (0 for any other epoch).
    pub fn count_in(&self, epoch: u64) -> u64 {
        if self.epoch == epoch { self.count } else { 0 }
    }
}

/// §9.1.1a peer side — count a VERIFIED citizen certificate against its issuer
/// for the epoch its own `issued_at` names. Returns `Some(seen)` when the
/// count is now ABOVE `cap` (the caller logs `[NBC-ISSUER-OVER-CAP]` and
/// counts it) — OBSERVABILITY ONLY, never a refusal: peers see certificates in
/// different orders and a compromised key can backdate `issued_at`, so
/// cross-node enforcement needs the evidence model (YPX-025) and is not ruled.
/// Genesis (`chain_depth == 0`) and a certificate with no issuer are skipped.
/// The map is keyed `(issuer node id, epoch)`; the caller owns pruning.
pub fn note_issuer_certificate(
    seen: &mut std::collections::HashMap<([u8; 32], u64), u64>,
    nbc: &NBC,
    cap: u64,
) -> Option<([u8; 32], u64, u64)> {
    if nbc.chain_depth == 0 {
        return None;
    }
    let issuer_pk = nbc.issuer_set.first()?;
    let issuer = axiom_core_logic::compute::compute_validator_id(issuer_pk);
    let epoch = crate::constants::nbc_issuance_epoch(nbc.issued_at);
    let n = seen.entry((issuer, epoch)).or_insert(0);
    *n = n.saturating_add(1);
    if *n > cap { Some((issuer, epoch, *n)) } else { None }
}

pub fn is_qualified_issuer(
    nbc: &NBC,
    sphincs_sk: Option<&[u8]>,
    maturity_secs: u64,
    current_time: u64,
) -> bool {
    // Must have SPHINCS+ SK loaded
    if sphincs_sk.is_none() {
        return false;
    }
    // NBC must not be expired
    if nbc.expires_at <= current_time {
        return false;
    }
    // Maturity: NBC must have been held long enough
    if current_time.saturating_sub(nbc.issued_at) < maturity_secs {
        return false;
    }
    true
}

/// Build an unsigned NBC for a subject. Shared by `issue_nbc()` and `issue_nbc_via_core()`.
///
/// Validates subject fields and constructs the NBC with all fields except signatures.
fn build_unsigned_nbc(
    subject: &NbcSubject,
    issuer_nbc: &NBC,
    current_time: u64,
    issuer_baseline: (u32, u64),
) -> Result<NBC, NablaError> {
    use axiom_core_logic::compute::compute_validator_id;

    // Validate subject fields
    if subject.sphincs_pk.is_empty() {
        return Err(NablaError::NbcMalformed("subject missing SPHINCS+ public key".into()));
    }
    if subject.ed25519_pk.len() != 32 {
        return Err(NablaError::NbcMalformed(
            format!("subject Ed25519 pk size: {} (expected 32)", subject.ed25519_pk.len()),
        ));
    }
    if subject.node_name.len() > 64 {
        return Err(NablaError::NbcMalformed(
            format!("subject node_name exceeds 64 bytes: {}", subject.node_name.len()),
        ));
    }
    // NO dev NBC (the owner, 2026-09-20; `AXIOM_DESIGN_FactClassIsolation.md`
    // preamble point 0). A Nabla node's operator wallet MUST be a REAL account.
    // Empty = not declared (grandfathered). A declared DEV operator is rejected
    // — the issuance-time half; the Core money gate already blocks a dev
    // operator's emission/withdrawal payouts.
    if !subject.wallet_id.is_empty()
        && axiom_core_logic::wallet_id::is_dev_wallet(&subject.wallet_id)
    {
        return Err(NablaError::NbcMalformed(
            "dev account (@axiom / @axiom.internal) cannot operate a Nabla node — the operator wallet must be a real account".into(),
        ));
    }

    let validator_id = compute_validator_id(&subject.sphincs_pk);
    Ok(VBC {
        version: 0x09,
        validator_id,
        subject_pubkey_sphincs: subject.sphincs_pk.clone(),
        subject_pubkey_dilithium: subject.dilithium_pk.clone(),
        subject_pubkey_ed25519: subject.ed25519_pk.clone(),
        pgp_fingerprint: vec![],
        node_name: subject.node_name.clone(),
        proof_cap: String::new(),
        issued_at: current_time,
        expires_at: current_time + NBC_EXPIRY_SECS,
        chain_depth: issuer_nbc.chain_depth.saturating_add(1),
        issuer_set: vec![issuer_nbc.subject_pubkey_sphincs.clone()], // k=1 for NBC
        signatures: vec![],
        max_tx: NBC_TX_BUDGET,
        founding_vbc_hash: issuer_nbc.founding_vbc_hash,
        // YPX-021 §7 — the subject is BORN WITH A BASELINE: the issuer
        // stamps its current PROVEN network-size view (and the tick it was
        // measured at) into the certificate. Bound into the issuer
        // signatures via compute_vbc_signing_payload_bytes (fixed 12-byte
        // suffix when non-zero). (0, _) = no baseline — genesis/dev-era
        // certs are exempt.
        network_size_baseline: issuer_baseline.0,
        baseline_tick: if issuer_baseline.0 == 0 { 0 } else { issuer_baseline.1 },
        // §5.3 does not apply to NBCs — Nabla citizens have no genesis family.
        genesis_lineage: [0u8; 32],
        nabla_registration: None,
    })
}

/// Issue a new NBC for a subject, signed by the issuer's SPHINCS+ key.
///
/// **DEV/TEST/CEREMONY ONLY** — calls `sign_sphincs()` directly, bypassing
/// the AVM trust boundary. Production runtime MUST use `issue_nbc_via_core()`
/// (CL8 via AVM). The nabla-node binary enforces this: release builds error
/// if AVM is unavailable. This function is retained for:
///   - Genesis ceremony (offline, not in the live node)
///   - Unit tests (no AVM needed)
///   - Debug builds during development
///
/// Returns (signed_nbc, supporting_chain) where supporting_chain contains
/// the issuer's NBC (and the issuer's own supporting VBCs if any).
pub fn issue_nbc(
    subject: &NbcSubject,
    issuer_nbc: &NBC,
    issuer_sphincs_sk: &[u8],
    issuer_supporting: &[NBC],
    current_time: u64,
    issuer_baseline: (u32, u64),
) -> Result<(NBC, Vec<NBC>), NablaError> {
    use axiom_core_logic::compute::{compute_vbc_signing_payload, sign_sphincs};
    use axiom_core_logic::verify::verify_sphincs;

    let mut nbc = build_unsigned_nbc(subject, issuer_nbc, current_time, issuer_baseline)?;

    // Compute signing payload (same as ceremony)
    let commitment = compute_vbc_signing_payload(&nbc);

    // Sign with issuer's SPHINCS+ SK
    let sig = sign_sphincs(issuer_sphincs_sk, &commitment)
        .map_err(|e| NablaError::NbcMalformed(format!("SPHINCS+ signing failed: {:?}", e)))?;

    // Verify immediately (fail-stop, same as ceremony)
    verify_sphincs(&issuer_nbc.subject_pubkey_sphincs, &commitment, &sig)
        .map_err(|e| NablaError::NbcMalformed(format!("SPHINCS+ verify-after-sign failed: {:?}", e)))?;

    nbc.signatures = vec![sig];

    // Build supporting chain: [issuer_nbc] ++ issuer's own supporting chain
    let mut supporting_chain = vec![issuer_nbc.clone()];
    supporting_chain.extend_from_slice(issuer_supporting);

    Ok((nbc, supporting_chain))
}

/// Issue NBC through AVM interpreter (CL8).
///
/// **Primary issuance path** via AVM interpreter.
/// Core signs the NBC internally — Nabla MUST NOT call sign_sphincs directly.
/// CL8 computes the signing payload, signs with SPHINCS+, verifies (fail-stop),
/// and returns the signature.
///
/// Returns (signed_nbc, supporting_chain).
pub fn issue_nbc_via_core(
    avm: &axiom_dmap_vm::AvmInterpreter,
    subject: &NbcSubject,
    issuer_nbc: &NBC,
    issuer_sphincs_sk: &[u8],
    issuer_supporting: &[NBC],
    current_time: u64,
    issuer_baseline: (u32, u64),
) -> Result<(NBC, Vec<NBC>), NablaError> {
    use axiom_core_logic::types::{VBCProofBundle, Transaction, TxKind, PublicInputs};
    use axiom_core_logic::CoreLogicMode;

    let mut nbc = build_unsigned_nbc(subject, issuer_nbc, current_time, issuer_baseline)?;

    // Send to Core CL8 for signing
    let bundle = VBCProofBundle {
        target_vbc: nbc.clone(),
        supporting_vbcs: vec![],
        candidacy_pulse: None, renewal_work_receipt: None,
    };
    let inputs = PublicInputs {
        zkq_request: None,
        fact_certificates: Vec::new(),
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: None,
        fob_claim_attestation: None,
        claimant_vbc: None,
        receiver_witness: None,
        receiver_signing_key: None,
        recall_attestation: None,
        mode: CoreLogicMode::CL8,
        oods_attestation: None,
        // Nabla CL8 (NBC issuance) doesn't process a TX; gate disabled by zero
        local_core_id: [0u8; 32],
        transaction: Transaction {
            consumed_state_id: [0u8; 32],
            client_pk: vec![],
            sender_wallet_id: String::new(),
            wallet_seq: 0,
            receiver_wallet_id: String::new(),
            receiver_address: None,
            amount: 0,
            reference: String::new(),
            nonce: 0,
            epoch: current_time,
            client_sig: vec![],
            scar_passcode: None,
            burn_target_tx_id: None,
            required_k: 0,
            proof_type: 0,
            oracle_claim: None,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
            recall_target_tx_id: None,
        },
        prev_receipts: vec![],
        current_state: None,
        vbc_bundle: Some(bundle),
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_current_hibernation: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
        my_validator_pk: None,
        overlapped_signatures: vec![],
        group_member_index: None,
        sender_fact_chain: None,
        max_fact_links: None,
        receiver_fact_chain: None,
        my_dilithium_sk: None,
        my_dilithium_pk: None,
        my_validator_id: None,
        fact_witness_sigs: vec![],
        issuer_sphincs_sk: Some(issuer_sphincs_sk.to_vec()),
        cl1_execution_proof: None,
        zkp_nonce: None,
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            nabla_stake_proof: None,
            frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None, txid_attestation: None,
            cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
    
    };

    let outputs = avm.execute(inputs)
        .map_err(|e| NablaError::NbcMalformed(format!("CL8 AVM: {}", e)))?;

    match outputs.result {
        axiom_core_logic::ValidationResult::Accept => {
            let sig = outputs.nbc_signature.ok_or_else(||
                NablaError::NbcMalformed("CL8: Core did not return signature".into()))?;
            nbc.signatures = vec![sig];

            // Build supporting chain (same as issue_nbc)
            let mut supporting_chain = vec![issuer_nbc.clone()];
            supporting_chain.extend_from_slice(issuer_supporting);
            Ok((nbc, supporting_chain))
        }
        _ => {
            let reason = outputs.rejection_reason
                .map(|r| format!("{:?}", r))
                .unwrap_or_else(|| "unknown".into());
            Err(NablaError::NbcMalformed(format!("CL8: Core rejected NBC signing: {}", reason)))
        }
    }
}

/// Renew an NBC: issue a new NBC for the same identity with extended expiry.
///
/// **DEV/TEST/CEREMONY ONLY** — delegates to `issue_nbc()` which calls
/// `sign_sphincs()` directly. Production runtime MUST use `renew_nbc_via_core()`.
///
/// Preserves `founding_vbc_hash` from the OLD NBC (not from the issuer).
/// This is critical: the renewed NBC represents the same lineage, not the issuer's.
///
/// Constraints:
/// - Only within NBC_RENEWAL_WINDOW_SECS (7 days) of expiry
/// - Already-expired NBCs cannot be renewed
/// - Issuer must be qualified (is_qualified_issuer + maturity check)
pub fn renew_nbc(
    old_nbc: &NBC,
    issuer_nbc: &NBC,
    issuer_sphincs_sk: &[u8],
    issuer_supporting: &[NBC],
    current_time: u64,
    issuer_baseline: (u32, u64),
) -> Result<(NBC, Vec<NBC>), NablaError> {
    use crate::constants::{NBC_RENEWAL_WINDOW_SECS, NBC_EXPIRY_SECS};

    // Reject if already expired
    if old_nbc.expires_at <= current_time {
        return Err(NablaError::NbcRenewalRejected("NBC already expired".into()));
    }
    // Issuer validates time-based window OR accepts TX-budget-triggered renewal.
    // TX-budget trigger: the issuer can't verify the requester's exact count,
    // but accepts renewal anytime the NBC hasn't expired — the self-enforcing
    // budget check at the requester side (check_nbc_renewal) prevents abuse,
    // and premature renewal is harmless (just resets the budget early).
    let renewal_start = old_nbc.expires_at.saturating_sub(NBC_RENEWAL_WINDOW_SECS);
    if current_time < renewal_start && old_nbc.max_tx == 0 {
        return Err(NablaError::NbcRenewalRejected(
            format!("too early: renewal window starts at {}", renewal_start),
        ));
    }

    // Build subject from old NBC's keys
    let subject = NbcSubject {
        sphincs_pk: old_nbc.subject_pubkey_sphincs.clone(),
        ed25519_pk: old_nbc.subject_pubkey_ed25519.clone(),
        dilithium_pk: old_nbc.subject_pubkey_dilithium.clone(),
        node_name: old_nbc.node_name.clone(),
        // Renewal carries the existing identity forward; the operator wallet was
        // validated at first issuance and the old NBC does not store it, so leave
        // it empty (grandfathered — the dev-operator reject fires at first issuance).
        wallet_id: String::new(),
    };

    // SEC-5 FIX: Use direct crypto path (dev/test fallback).
    // Production callers should use renew_nbc_via_core() instead.
    let (mut renewed, supporting) = issue_nbc(
        &subject, issuer_nbc, issuer_sphincs_sk, issuer_supporting, current_time, issuer_baseline,
    )?;

    // CRITICAL: Preserve founding_vbc_hash from OLD NBC, not issuer
    renewed.founding_vbc_hash = old_nbc.founding_vbc_hash;

    // Extend expiry from current_time
    renewed.expires_at = current_time + NBC_EXPIRY_SECS;

    Ok((renewed, supporting))
}

/// Renew an NBC through AVM interpreter (CL8).
///
/// Same as `renew_nbc()` but routes signing through Core.
/// **Primary renewal path** — Nabla MUST NOT call sign_sphincs directly.
pub fn renew_nbc_via_core(
    avm: &axiom_dmap_vm::AvmInterpreter,
    old_nbc: &NBC,
    issuer_nbc: &NBC,
    issuer_sphincs_sk: &[u8],
    issuer_supporting: &[NBC],
    current_time: u64,
    issuer_baseline: (u32, u64),
) -> Result<(NBC, Vec<NBC>), NablaError> {
    use crate::constants::{NBC_RENEWAL_WINDOW_SECS, NBC_EXPIRY_SECS};

    // Same validation as renew_nbc()
    if old_nbc.expires_at <= current_time {
        return Err(NablaError::NbcRenewalRejected("NBC already expired".into()));
    }
    let renewal_start = old_nbc.expires_at.saturating_sub(NBC_RENEWAL_WINDOW_SECS);
    if current_time < renewal_start && old_nbc.max_tx == 0 {
        return Err(NablaError::NbcRenewalRejected(
            format!("too early: renewal window starts at {}", renewal_start),
        ));
    }

    let subject = NbcSubject {
        sphincs_pk: old_nbc.subject_pubkey_sphincs.clone(),
        ed25519_pk: old_nbc.subject_pubkey_ed25519.clone(),
        dilithium_pk: old_nbc.subject_pubkey_dilithium.clone(),
        node_name: old_nbc.node_name.clone(),
        // Renewal carries the existing identity forward; the operator wallet was
        // validated at first issuance and the old NBC does not store it, so leave
        // it empty (grandfathered — the dev-operator reject fires at first issuance).
        wallet_id: String::new(),
    };

    // Route through Core (CL8) — same as issue_nbc_via_core
    let (mut renewed, supporting) = issue_nbc_via_core(
        avm, &subject, issuer_nbc, issuer_sphincs_sk, issuer_supporting, current_time, issuer_baseline,
    )?;

    // CRITICAL: Preserve founding_vbc_hash from OLD NBC, not issuer
    renewed.founding_vbc_hash = old_nbc.founding_vbc_hash;

    // Extend expiry from current_time
    renewed.expires_at = current_time + NBC_EXPIRY_SECS;

    Ok((renewed, supporting))
}

/// Generate SPHINCS+, Ed25519, and Dilithium keypairs for a new node.
/// Writes key files to `config_dir`. Returns the public keys as NbcSubject.
///
/// Same keygen as ceremony (nabla-ceremony). Key files:
///   nabla_sphincs.{pub,key}
///   nabla_ed25519.{pub,key}
///   nabla_dilithium.{pub,key}
pub fn generate_node_keys(config_dir: &std::path::Path, node_name: &str) -> Result<NbcSubject, NablaError> {
    use fips205::slh_dsa_sha2_128s;
    use fips205::traits::SerDes as SphincsSerDes;
    use fips204::ml_dsa_65;
    use fips204::traits::SerDes as DilSerDes;

    std::fs::create_dir_all(config_dir)
        .map_err(|e| NablaError::NbcMalformed(format!("create config dir: {}", e)))?;

    // Generate SPHINCS+ keypair
    let (sphincs_pk_obj, sphincs_sk_obj) = slh_dsa_sha2_128s::try_keygen()
        .map_err(|_| NablaError::NbcMalformed("SPHINCS+ keygen failed".into()))?;
    let sphincs_pk = sphincs_pk_obj.into_bytes().to_vec();
    let sphincs_sk = sphincs_sk_obj.into_bytes().to_vec();
    std::fs::write(config_dir.join("nabla_sphincs.pub"), &sphincs_pk)
        .map_err(|e| NablaError::NbcMalformed(format!("write sphincs pk: {}", e)))?;
    std::fs::write(config_dir.join("nabla_sphincs.key"), &sphincs_sk)
        .map_err(|e| NablaError::NbcMalformed(format!("write sphincs sk: {}", e)))?;

    // Generate Ed25519 keypair
    let mut ed25519_seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ed25519_seed);
    let ed25519_signing = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed);
    let ed25519_pk = ed25519_signing.verifying_key().as_bytes().to_vec();
    let ed25519_sk = ed25519_signing.to_bytes();
    std::fs::write(config_dir.join("nabla_ed25519.pub"), &ed25519_pk)
        .map_err(|e| NablaError::NbcMalformed(format!("write ed25519 pk: {}", e)))?;
    std::fs::write(config_dir.join("nabla_ed25519.key"), ed25519_sk)
        .map_err(|e| NablaError::NbcMalformed(format!("write ed25519 sk: {}", e)))?;

    // Generate Dilithium keypair
    let (dil_pk_obj, dil_sk_obj) = ml_dsa_65::try_keygen()
        .map_err(|_| NablaError::NbcMalformed("Dilithium keygen failed".into()))?;
    let dilithium_pk = dil_pk_obj.into_bytes().to_vec();
    let dilithium_sk = dil_sk_obj.into_bytes().to_vec();
    std::fs::write(config_dir.join("nabla_dilithium.pub"), &dilithium_pk)
        .map_err(|e| NablaError::NbcMalformed(format!("write dilithium pk: {}", e)))?;
    std::fs::write(config_dir.join("nabla_dilithium.key"), &dilithium_sk)
        .map_err(|e| NablaError::NbcMalformed(format!("write dilithium sk: {}", e)))?;

    Ok(NbcSubject {
        sphincs_pk,
        ed25519_pk,
        dilithium_pk,
        node_name: node_name.to_string(),
        // The node's ONE operator wallet is set by the caller from node config
        // BEFORE issuance (checked in `build_unsigned_nbc`). keygen itself does
        // not know it. Empty = not declared.
        wallet_id: String::new(),
    })
}

// ════════════════════════════════════════════════════════════════════════
// Task 37 & 38: Companion Certificate
// ════════════════════════════════════════════════════════════════════════

/// Companion Certificate — rolling score accumulator.
///
/// Core produces a new CC every tick, chaining to the previous one.
/// Records how much a Nabla node has helped the network.
///
/// CC chain: each CC contains hash of previous → immutable history.
/// Only the latest CC is stored; previous is discarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanionCertificate {
    /// NBC node_id (binds this CC to a specific node).
    pub node_id: NodeId,
    /// Current tick number.
    pub tick: u64,
    /// Registrations processed during this tick.
    pub registrations_this_tick: u32,
    /// Running total of all registrations processed.
    pub total_registrations: u64,
    /// Running total of ticks where this node was online and participating.
    pub ticks_helped: u64,
    /// Computed score (see compute_score).
    pub score: u64,
    /// Hash of the previous CC (depth 1 chain).
    pub prev_cc_hash: Hash256,
    /// ZKP proof covering all fields above.
    /// Produced by Core via Signer trait. Nabla never generates proofs.
    pub proof: Vec<u8>,
}

/// Input data for producing a new CC (sent to Core).
#[derive(Debug, Clone)]
pub struct CcTickInput {
    /// Previous CC (None for first tick after NBC creation).
    pub prev_cc: Option<CompanionCertificate>,
    /// Tick approval from TARDIS.
    pub tick_approval: TickApproval,
    /// Registration receipts processed during this tick.
    pub registration_count: u32,
}

// ════════════════════════════════════════════════════════════════════════
// Task 40: CC Storage (latest only)
// ════════════════════════════════════════════════════════════════════════

/// CC chain manager — stores the latest CC and tracks registration counts.
///
/// Only the latest CC is stored. Previous CCs are discarded.
/// This is the Nabla-side bookkeeping; Core handles all proofs.
pub struct CcChain {
    /// Our NBC (= VBC from Core).
    nbc: NBC,
    /// Latest CC (None until first tick).
    latest_cc: Option<CompanionCertificate>,
    /// Registrations accumulated during the current tick (not yet committed to CC).
    pending_registrations: u32,
}

impl CcChain {
    /// Create a new CC chain bound to an NBC.
    pub fn new(nbc: NBC) -> Self {
        Self {
            nbc,
            latest_cc: None,
            pending_registrations: 0,
        }
    }

    /// Record a registration processed during the current tick.
    pub fn record_registration(&mut self) {
        self.pending_registrations += 1;
    }

    /// Produce a new CC for the current tick.
    ///
    /// In production, this sends data to Core and Core returns the signed CC.
    /// Here we build the CC structure; the proof field is empty (deterministic mode).
    ///
    /// Returns the new CC. Caller should store it via `accept_cc()`.
    pub fn produce_cc(&self, tick: u64, signer: &dyn Signer) -> CompanionCertificate {
        let node_id = nbc_node_id(&self.nbc);
        let (prev_ticks_helped, prev_total_regs, prev_cc_hash) = match &self.latest_cc {
            Some(prev) => {
                let hash = hash_cc(prev);
                (prev.ticks_helped, prev.total_registrations, hash)
            }
            None => (0u64, 0u64, [0u8; 32]),
        };

        let total_registrations = prev_total_regs + self.pending_registrations as u64;
        let ticks_helped = prev_ticks_helped + 1;
        let score = compute_score(ticks_helped, total_registrations);

        let payload = crypto::cc_sign_payload(
            &node_id,
            tick,
            self.pending_registrations,
            total_registrations,
            ticks_helped,
            score,
            &prev_cc_hash,
        );

        CompanionCertificate {
            node_id,
            tick,
            registrations_this_tick: self.pending_registrations,
            total_registrations,
            ticks_helped,
            score,
            prev_cc_hash,
            proof: signer.sign(&payload), // Core produces proof; in sim, Ed25519 signature
        }
    }

    /// Accept a new CC (from Core), replacing the previous one.
    pub fn accept_cc(&mut self, cc: CompanionCertificate) {
        self.latest_cc = Some(cc);
        self.pending_registrations = 0;
    }

    /// Get the latest CC.
    pub fn latest(&self) -> Option<&CompanionCertificate> {
        self.latest_cc.as_ref()
    }

    /// Get the NBC.
    pub fn nbc(&self) -> &NBC {
        &self.nbc
    }

    /// Replace the NBC (for renewal). Preserves CC chain state.
    pub fn update_nbc(&mut self, nbc: NBC) {
        self.nbc = nbc;
    }

    /// Current pending registration count.
    pub fn pending_registrations(&self) -> u32 {
        self.pending_registrations
    }
}

/// Hash a CC for chaining (prev_cc_hash in next CC).
///
/// NOTE: This uses BLAKE3 for structural hashing (same as SMT internal hashing).
/// This is NOT cryptographic signing — it's a content hash for chain integrity.
/// If this needs to go through Core, CHECK WITH AXIOM ORIGIN FIRST.
fn hash_cc(cc: &CompanionCertificate) -> Hash256 {
    let bytes = bincode::serialize(cc).unwrap_or_default();
    blake3::hash(&bytes).into()
}

// ════════════════════════════════════════════════════════════════════════
// Task 39: CC Verification
// ════════════════════════════════════════════════════════════════════════

/// Verify CC chain integrity (structural checks only).
///
/// Core handles ZKP verification. Nabla checks structural properties:
/// - tick is sequential (no gaps in chain)
/// - prev_cc_hash matches previous CC
/// - total_registrations is monotonically increasing
/// - ticks_helped is monotonically increasing
/// - score matches compute_score()
pub fn verify_cc_chain(prev: &CompanionCertificate, curr: &CompanionCertificate) -> Result<(), NablaError> {
    // Same node
    if prev.node_id != curr.node_id {
        return Err(NablaError::CcChainBroken);
    }

    // Tick must advance
    if curr.tick <= prev.tick {
        return Err(NablaError::CcChainBroken);
    }

    // prev_cc_hash must match
    let expected_hash = hash_cc(prev);
    if curr.prev_cc_hash != expected_hash {
        return Err(NablaError::CcChainBroken);
    }

    // total_registrations must be monotonically increasing
    if curr.total_registrations < prev.total_registrations {
        return Err(NablaError::CcChainBroken);
    }

    // Increment must match registrations_this_tick
    let expected_total = prev.total_registrations + curr.registrations_this_tick as u64;
    if curr.total_registrations != expected_total {
        return Err(NablaError::CcChainBroken);
    }

    // ticks_helped must increase by exactly 1
    if curr.ticks_helped != prev.ticks_helped + 1 {
        return Err(NablaError::CcChainBroken);
    }

    // Score must match formula
    let expected_score = compute_score(curr.ticks_helped, curr.total_registrations);
    if curr.score != expected_score {
        return Err(NablaError::CcChainBroken);
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════
// Task 41: DEED Fee Split
// ════════════════════════════════════════════════════════════════════════

/// Compute the DEED fee split for a given tick.
///
/// Years 1-10: 30% → Nabla Runner Pool, 70% → DEED group wallet
/// Year 10+:  100% → Nabla Runner Pool, 0% → DEED group wallet
///
/// Returns (runner_pool_pct, deed_wallet_pct).
/// One flip. One date. Hardcoded. Immutable.
pub fn deed_split(current_tick: u64) -> (u8, u8) {
    if current_tick < DEED_TRANSITION_TICKS {
        (DEED_RUNNER_POOL_PCT, 100 - DEED_RUNNER_POOL_PCT) // (30, 70)
    } else {
        (DEED_RUNNER_POOL_FINAL_PCT, 0) // (100, 0)
    }
}

/// Compute DEED fee amounts for a given fee.
///
/// Returns (runner_pool_amount, deed_wallet_amount).
/// Rounding: runner pool gets the floor, DEED wallet gets the remainder.
pub fn deed_fee_amounts(fee: u64, current_tick: u64) -> (u64, u64) {
    let (runner_pct, _deed_pct) = deed_split(current_tick);
    let runner_amount = fee * runner_pct as u64 / 100;
    let deed_amount = fee - runner_amount;
    (runner_amount, deed_amount)
}

// ════════════════════════════════════════════════════════════════════════
// Task 42: Nabla Runner Pool Accumulator
// ════════════════════════════════════════════════════════════════════════

/// Runner Pool — accumulates the runner share of DEED fees.
///
/// This is the Nabla-side tracker. The actual pool is on-chain
/// (managed by validators). This tracks what we've accumulated
/// locally so the runner can submit a claim.
pub struct RunnerPool {
    /// Total accumulated in the pool (runner's share of DEED fees).
    pub balance: u64,
    /// Total DEED fees collected (both runner + project shares).
    pub total_collected: u64,
    /// Total paid out to runners via claims.
    pub total_claimed: u64,
}

impl RunnerPool {
    pub fn new() -> Self {
        Self {
            balance: 0,
            total_collected: 0,
            total_claimed: 0,
        }
    }

    /// Add a DEED fee, splitting according to current tick.
    pub fn add_deed_fee(&mut self, fee: u64, current_tick: u64) {
        let (runner_amount, _deed_amount) = deed_fee_amounts(fee, current_tick);
        self.balance += runner_amount;
        self.total_collected += fee;
    }

    /// Process a runner claim (reduces pool balance).
    pub fn process_claim(&mut self, amount: u64) -> Result<(), NablaError> {
        if amount > self.balance {
            return Err(NablaError::InsufficientPoolBalance);
        }
        self.balance -= amount;
        self.total_claimed += amount;
        Ok(())
    }
}

impl Default for RunnerPool {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════
// Task 43 & 44: Runner Claim Handler
// ════════════════════════════════════════════════════════════════════════

/// A runner's claim request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerClaim {
    /// The runner's NBC node_id.
    pub node_id: NodeId,
    /// The latest CC (with proof).
    pub cc: CompanionCertificate,
    /// Tick when the claim is submitted.
    pub claim_tick: u64,
}

/// Claim enforcement — tracks one-claim-per-period per NBC.
pub struct ClaimTracker {
    /// Map from node_id → tick of last claim.
    last_claims: std::collections::HashMap<NodeId, u64>,
}

impl ClaimTracker {
    pub fn new() -> Self {
        Self {
            last_claims: std::collections::HashMap::new(),
        }
    }

    /// Check if a node can claim (24-hour / RUNNER_CLAIM_TICKS cooldown).
    pub fn can_claim(&self, node_id: &NodeId, current_tick: u64) -> bool {
        match self.last_claims.get(node_id) {
            // KI#47: value-span vs tick COUNT — project. Pre-fix the "24h" runner
            // claim cooldown was really 4.8h.
            Some(&last_tick) => current_tick - last_tick >= RUNNER_CLAIM_TICKS.to_secs(),
            None => true, // never claimed before
        }
    }

    /// Record a successful claim.
    pub fn record_claim(&mut self, node_id: NodeId, tick: u64) {
        self.last_claims.insert(node_id, tick);
    }
}

impl Default for ClaimTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate a runner claim.
///
/// ⚠ **ALWAYS FAILS CLOSED — returns `Err(CcPayoutSelfAttested)` before any of
/// the checks below run** (SEC-05; see the load-bearing comment in the body).
/// The CC score is self-attested, so this function must not compute a payout
/// until CC attestation is k-witnessed and Core-mediated.
///
/// This rustdoc used to describe only the checks and "Returns the computed
/// claim amount", i.e. the UNREACHABLE code below the gate — inviting a reader
/// to treat the early return as a regression and delete it (ghost audit G21).
/// Removing that return requires the work listed in the body, in the same
/// change.
///
/// Checks (UNREACHABLE until the gate is lifted):
///   - CC node_id matches claim node_id
///   - Claim cooldown has passed (one per 24 hours)
///   - CC score is non-zero
///   - CC proof would be verified by Core (Signer trait)
///
/// Returns the computed claim amount — once the SEC-05 gate is lifted.
pub fn validate_runner_claim(
    claim: &RunnerClaim,
    pool: &RunnerPool,
    tracker: &ClaimTracker,
    total_network_score: u64,
    signer: &dyn Signer,
) -> Result<u64, NablaError> {
    // ── SEC-05 FAIL-CLOSED GATE (load-bearing) ──
    // The CC contribution score (`claim.cc.score`) is computed from local,
    // self-incremented counters (`ticks_helped`, `total_registrations`) and
    // the only "proof" is the node's OWN Ed25519 signature over its OWN
    // claims — no peer attestation, no k-of-N, no proof-of-service. A node
    // running patched code can set any score and Sybil cross-credit is
    // trivial. This function computes a pool payout proportional to that
    // score, so it MUST NOT run while the score is self-attested.
    //
    // It is harmless today only because no production path calls it
    // (`runner_pool_balance` is hardcoded 0; this has test-only callers).
    // This gate makes "wire the runner payout" structurally require "wire
    // the CC attestation" in the same change: to remove this early return
    // you must replace self-reported counts with k-witnessed registration
    // counts and make the CC proof Core-mediated (verify_cc_chain mandatory,
    // payout bound to a designated-payout-pk proving NBC ownership). Until
    // then, every call fails closed. See SEC-05 and
    // docs/AXIOM_DESIGN_RunnerPool.md.
    return Err(NablaError::CcPayoutSelfAttested);
    #[allow(unreachable_code)]
    {
    // CC must match claimant
    if claim.cc.node_id != claim.node_id {
        return Err(NablaError::CcChainBroken);
    }

    // Cooldown check
    if !tracker.can_claim(&claim.node_id, claim.claim_tick) {
        return Err(NablaError::ClaimCooldownActive);
    }

    // Must have non-zero score
    if claim.cc.score == 0 {
        return Err(NablaError::InsufficientPoolBalance);
    }

    // Verify CC proof via Core (Signer trait)
    let cc_payload = crypto::cc_sign_payload(
        &claim.cc.node_id,
        claim.cc.tick,
        claim.cc.registrations_this_tick,
        claim.cc.total_registrations,
        claim.cc.ticks_helped,
        claim.cc.score,
        &claim.cc.prev_cc_hash,
    );
    if !signer.verify(&claim.node_id, &cc_payload, &claim.cc.proof) {
        return Err(NablaError::CcChainBroken);
    }

    // Compute share: runner_score / total_scores × pool_balance.
    // SEC-05: `claim.cc.score` is self-attested — this split is only safe
    // once the score is k-witnessed and the CC proof is Core-mediated. The
    // fail-closed gate at the top of this function prevents reaching here on
    // any path today; do NOT remove that gate without wiring the attestation.
    if total_network_score == 0 {
        return Err(NablaError::InsufficientPoolBalance);
    }

    let share = (pool.balance as u128 * claim.cc.score as u128 / total_network_score as u128) as u64;
    if share == 0 {
        return Err(NablaError::InsufficientPoolBalance);
    }

    Ok(share)
    }
}

// ════════════════════════════════════════════════════════════════════════
// Task 45: Score Calculation
// ════════════════════════════════════════════════════════════════════════

/// Compute a runner's score from their CC stats.
///
/// Score = ticks_helped × W1 + total_registrations × W2
///
/// **Calibrated weights (v2.10.25):**
/// - W1 = 1 (uptime contributes, but doesn't dominate)
/// - W2 = 10 (registrations are 10× more valuable than just being online)
///
/// Sybil defense: a thousand empty nodes with zero registrations earn
/// nearly zero score. The registration count IS the Sybil defense.
///
/// **Calibration results:**
/// - At W1=1, W2=10: 1 honest node with 1 reg/tick beats 10 empty Sybils.
/// - 10 empty Sybils × 1000 ticks = combined score 10,000.
/// - 1 honest node: 1000 ticks + 1000 regs × 10 = 11,000 > 10,000.
/// - Even the weakest honest node (5 regs over 200 ticks) beats any empty Sybil.
/// - In a 50-node network, average honest score is >5× average Sybil score.
/// - Low-traffic nodes (1 reg per 10 ticks) still score 2× bare uptime.
///
/// Higher W2/W1 ratio = stronger Sybil resistance but higher bar for
/// low-traffic nodes. Current ratio (10:1) balances both concerns.
pub fn compute_score(ticks_helped: u64, total_registrations: u64) -> u64 {
    ticks_helped
        .saturating_mul(SCORE_W1)
        .saturating_add(total_registrations.saturating_mul(SCORE_W2))
}

// ════════════════════════════════════════════════════════════════════════
// Task 46: Tests
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// F-5 condition (a) — the predicate is keyed by the PINNED SPHINCS+
    /// PUBLIC KEYS only: all ten pinned keys are genesis; a certificate that
    /// carries a pinned NODE ID (`NABLA_GENESIS_VALIDATORS`, a digest) or a
    /// root-authority key as its subject is not; nothing else is consulted.
    #[test]
    fn f5_genesis_predicate_is_the_pinned_keys_only() {
        use axiom_core_logic::nabla_genesis as ng;
        for k in ng::NABLA_GENESIS_VALIDATOR_PKS {
            let mut c = sim_nbc([0x11; 32], 1_000_000);
            c.subject_pubkey_sphincs = k.to_vec();
            c.chain_depth = 1; // depth / name / address are not consulted
            assert!(nbc_is_pinned_genesis(&c));
        }
        let mut by_id = sim_nbc(ng::NABLA_GENESIS_VALIDATORS[0], 1_000_000);
        by_id.subject_pubkey_sphincs = ng::NABLA_GENESIS_VALIDATORS[0].to_vec();
        assert!(!nbc_is_pinned_genesis(&by_id), "a node id is not a pinned key");
        let mut root = sim_nbc([0x12; 32], 1_000_000);
        root.subject_pubkey_sphincs = ng::NABLA_ROOT_AUTHORITY_PKS[0].to_vec();
        assert!(!nbc_is_pinned_genesis(&root), "a root authority is not a genesis Nabla");
        assert!(!nbc_is_pinned_genesis(&sim_nbc([0x13; 32], 1_000_000)));
    }

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    // ── GUIDE §5.6c join probation — the ONE predicate ──────────────────────

    fn citizen_nbc(issued_at: u64) -> NBC {
        let mut nbc = sim_nbc(nid(0x5C), issued_at);
        nbc.chain_depth = 1;
        nbc
    }

    /// Genesis (`chain_depth == 0`) is exempt at ANY age — even at issue.
    #[test]
    fn probation_genesis_is_exempt() {
        let genesis = sim_nbc(nid(0x5C), 1_000_000);
        assert_eq!(genesis.chain_depth, 0);
        assert!(!is_probationary(&genesis, 1_000_000), "genesis at issue tick");
        assert!(!is_probationary(&genesis, 1_000_001), "genesis one second later");
    }

    /// The boundary: probationary one second before expiry, confirmed AT
    /// expiry (`issued_at + span <= now` → not probationary).
    #[test]
    fn probation_boundary_is_exact() {
        let issued = 1_000_000u64;
        let nbc = citizen_nbc(issued);
        let ends = probation_ends_at(&nbc);
        assert_eq!(ends, issued + nabla_probation_span_secs(),
            "expiry = issued_at + the PROJECTED window (tick count × interval)");
        assert!(is_probationary(&nbc, issued), "at issue");
        assert!(is_probationary(&nbc, ends - 1), "one second before expiry");
        assert!(!is_probationary(&nbc, ends), "at expiry");
        assert!(!is_probationary(&nbc, ends + 1), "after expiry");
    }

    /// The window is the tick COUNT register projected through the tick
    /// interval — a raw-count comparison (the KI#40/#165 class) would make
    /// the dev window 60 s instead of 300 s and go red here.
    #[test]
    fn probation_window_is_projected_not_raw_count() {
        let nbc = citizen_nbc(500);
        let raw_count_expiry = 500 + NABLA_PROBATION_TICKS;
        assert!(TICK_INTERVAL_SECS > 1, "premise: projection is observable");
        assert!(is_probationary(&nbc, raw_count_expiry),
            "still probationary where a raw-count comparison would have expired");
        assert!(!is_probationary(&nbc, 500 + NABLA_PROBATION_TICKS * TICK_INTERVAL_SECS));
    }

    /// A re-join cannot reset the clock: the predicate takes ONLY the
    /// certificate and the current tick — there is no `since` to restart.
    /// Asserted by calling it with the same cert at increasing `now` and
    /// showing the answer depends on the cert alone.
    #[test]
    fn probation_rejoin_does_not_reset() {
        let nbc = citizen_nbc(1_000_000);
        let ends = probation_ends_at(&nbc);
        // "join" at issue, "re-join" half way, "re-join" again at the end.
        assert!(is_probationary(&nbc, 1_000_000));
        assert!(is_probationary(&nbc, 1_000_000 + nabla_probation_span_secs() / 2));
        assert!(!is_probationary(&nbc, ends),
            "expiry is anchored to issued_at, not to any of the joins above");
        // And a NEWER certificate for the same node id is probationary again —
        // the certificate is the identity the window is bound to.
        let reissued = citizen_nbc(ends);
        assert!(is_probationary(&reissued, ends));
    }

    /// `PeerTrust::trust_status` is the same rule, named.
    #[test]
    fn peer_trust_status_is_derived_from_the_certificate() {
        let citizen = PeerTrust { nbc: citizen_nbc(1_000_000), wallet_id: None };
        assert_eq!(citizen.trust_status(1_000_000), NbcTrustStatus::Probation);
        assert_eq!(citizen.trust_status(probation_ends_at(&citizen.nbc)), NbcTrustStatus::Confirmed);
        let genesis = PeerTrust { nbc: sim_nbc(nid(0x5C), 1_000_000), wallet_id: None };
        assert_eq!(genesis.trust_status(1_000_000), NbcTrustStatus::Genesis);
    }

    /// Create a test NBC (= VBC) with deterministic fields.
    fn make_nbc(b: u8) -> NBC {
        sim_nbc(nid(b), 0)
    }

    // ── NBC Tests ──

    #[test]
    fn nbc_creation() {
        let nbc = make_nbc(0xAA);
        assert_eq!(nbc_node_id(&nbc), nid(0xAA));
        assert_eq!(nbc.issued_at, 0);
        assert_eq!(nbc.expires_at, NBC_EXPIRY_SECS);
    }

    /// The owner 2026-09-20: "Nabla binds one wallet and that is the operator
    /// wallet" — and it MUST be a real account. NO dev NBC.
    #[test]
    fn build_unsigned_nbc_rejects_dev_operator() {
        let issuer = make_nbc(0x01);
        let real = NbcSubject {
            sphincs_pk: vec![1u8; 32], ed25519_pk: vec![2u8; 32],
            dilithium_pk: vec![3u8; 32], node_name: "citizen".into(),
            wallet_id: "op@example.com".into(),           // REAL
        };
        assert!(build_unsigned_nbc(&real, &issuer, 0, (0, 0)).is_ok(),
                "a real operator wallet must be accepted");

        for dev in ["op@axiom", "op@axiom.internal", "SOAK@AXIOM"] {
            let mut s = real.clone();
            s.wallet_id = dev.into();
            assert!(build_unsigned_nbc(&s, &issuer, 0, (0, 0)).is_err(),
                    "dev operator {dev} must be rejected from an NBC");
        }

        let mut empty = real.clone();
        empty.wallet_id = String::new();                  // undeclared
        assert!(build_unsigned_nbc(&empty, &issuer, 0, (0, 0)).is_ok(),
                "an undeclared operator is grandfathered (checked at declaration)");
    }

    // ── CC Chain Tests ──

    #[test]
    fn cc_chain_first_tick() {
        let nbc = make_nbc(0xAA);
        let mut chain = CcChain::new(nbc);

        chain.record_registration();
        chain.record_registration();
        chain.record_registration();

        let cc = chain.produce_cc(1, &crate::crypto::NoopSigner);
        assert_eq!(cc.tick, 1);
        assert_eq!(cc.registrations_this_tick, 3);
        assert_eq!(cc.total_registrations, 3);
        assert_eq!(cc.ticks_helped, 1);
        assert_eq!(cc.prev_cc_hash, [0u8; 32]); // no previous CC
        assert_eq!(cc.score, compute_score(1, 3));
    }

    #[test]
    fn cc_chain_sequential_ticks() {
        let nbc = make_nbc(0xBB);
        let mut chain = CcChain::new(nbc);

        // Tick 1: 2 registrations
        chain.record_registration();
        chain.record_registration();
        let cc1 = chain.produce_cc(1, &crate::crypto::NoopSigner);
        chain.accept_cc(cc1.clone());

        // Tick 2: 5 registrations
        for _ in 0..5 {
            chain.record_registration();
        }
        let cc2 = chain.produce_cc(2, &crate::crypto::NoopSigner);
        chain.accept_cc(cc2.clone());

        assert_eq!(cc2.tick, 2);
        assert_eq!(cc2.registrations_this_tick, 5);
        assert_eq!(cc2.total_registrations, 7); // 2 + 5
        assert_eq!(cc2.ticks_helped, 2);
        assert_eq!(cc2.prev_cc_hash, hash_cc(&cc1));
    }

    #[test]
    fn cc_chain_zero_registrations_tick() {
        let nbc = make_nbc(0xCC);
        let mut chain = CcChain::new(nbc);

        // Tick 1: 0 registrations (node was online but idle)
        let cc1 = chain.produce_cc(1, &crate::crypto::NoopSigner);
        chain.accept_cc(cc1.clone());

        assert_eq!(cc1.registrations_this_tick, 0);
        assert_eq!(cc1.total_registrations, 0);
        assert_eq!(cc1.ticks_helped, 1);
    }

    #[test]
    fn cc_pending_reset_after_accept() {
        let nbc = make_nbc(0xDD);
        let mut chain = CcChain::new(nbc);

        chain.record_registration();
        chain.record_registration();
        assert_eq!(chain.pending_registrations(), 2);

        let cc = chain.produce_cc(1, &crate::crypto::NoopSigner);
        chain.accept_cc(cc);
        assert_eq!(chain.pending_registrations(), 0);
    }

    // ── CC Chain Integrity ──

    #[test]
    fn cc_chain_verify_valid() {
        let nbc = make_nbc(0xAA);
        let mut chain = CcChain::new(nbc);

        chain.record_registration();
        let cc1 = chain.produce_cc(1, &crate::crypto::NoopSigner);
        chain.accept_cc(cc1.clone());

        chain.record_registration();
        chain.record_registration();
        let cc2 = chain.produce_cc(2, &crate::crypto::NoopSigner);

        assert!(verify_cc_chain(&cc1, &cc2).is_ok());
    }

    #[test]
    fn cc_chain_verify_wrong_node() {
        let nbc_a = make_nbc(0xAA);
        let nbc_b = make_nbc(0xBB);
        let chain_a = CcChain::new(nbc_a);
        let chain_b = CcChain::new(nbc_b);

        let cc_a = chain_a.produce_cc(1, &crate::crypto::NoopSigner);
        let cc_b = chain_b.produce_cc(2, &crate::crypto::NoopSigner);

        assert!(matches!(verify_cc_chain(&cc_a, &cc_b), Err(NablaError::CcChainBroken)));
    }

    #[test]
    fn cc_chain_verify_wrong_hash() {
        let nbc = make_nbc(0xAA);
        let mut chain = CcChain::new(nbc);

        let cc1 = chain.produce_cc(1, &crate::crypto::NoopSigner);
        chain.accept_cc(cc1.clone());

        let mut cc2 = chain.produce_cc(2, &crate::crypto::NoopSigner);
        cc2.prev_cc_hash = [0xFF; 32]; // tampered

        assert!(matches!(verify_cc_chain(&cc1, &cc2), Err(NablaError::CcChainBroken)));
    }

    #[test]
    fn cc_chain_verify_tick_not_advancing() {
        let nbc = make_nbc(0xAA);
        let mut chain = CcChain::new(nbc);

        let cc1 = chain.produce_cc(5, &crate::crypto::NoopSigner);
        chain.accept_cc(cc1.clone());

        let mut cc2 = chain.produce_cc(6, &crate::crypto::NoopSigner);
        cc2.tick = 5; // same tick as prev

        assert!(matches!(verify_cc_chain(&cc1, &cc2), Err(NablaError::CcChainBroken)));
    }

    #[test]
    fn cc_chain_verify_inflated_registrations() {
        let nbc = make_nbc(0xAA);
        let mut chain = CcChain::new(nbc);

        let cc1 = chain.produce_cc(1, &crate::crypto::NoopSigner);
        chain.accept_cc(cc1.clone());

        let mut cc2 = chain.produce_cc(2, &crate::crypto::NoopSigner);
        cc2.total_registrations = 999; // inflated
        // Fix score to match the inflated registrations to isolate the check
        cc2.score = compute_score(cc2.ticks_helped, 999);

        assert!(matches!(verify_cc_chain(&cc1, &cc2), Err(NablaError::CcChainBroken)));
    }

    // ── Offline Gap Handling ──

    #[test]
    fn cc_offline_gap() {
        let nbc = make_nbc(0xAA);
        let mut chain = CcChain::new(nbc);

        // Online ticks 1-3
        for tick in 1..=3 {
            chain.record_registration();
            let cc = chain.produce_cc(tick, &crate::crypto::NoopSigner);
            chain.accept_cc(cc);
        }
        let cc_3 = chain.latest().unwrap().clone();
        assert_eq!(cc_3.ticks_helped, 3);

        // Offline ticks 4-100 (gap)
        // Come back at tick 101
        chain.record_registration();
        let cc_101 = chain.produce_cc(101, &crate::crypto::NoopSigner);
        chain.accept_cc(cc_101.clone());

        // ticks_helped only increased by 1 (not 98)
        assert_eq!(cc_101.ticks_helped, 4);
        assert_eq!(cc_101.tick, 101);
        // prev_cc_hash still chains to cc_3
        assert_eq!(cc_101.prev_cc_hash, hash_cc(&cc_3));
    }

    // ── DEED Fee Split ──

    #[test]
    fn deed_split_year_one() {
        let (runner, deed) = deed_split(1);
        assert_eq!(runner, 30);
        assert_eq!(deed, 70);
    }

    #[test]
    fn deed_split_year_nine() {
        // Just before transition
        let (runner, deed) = deed_split(DEED_TRANSITION_TICKS - 1);
        assert_eq!(runner, 30);
        assert_eq!(deed, 70);
    }

    #[test]
    fn deed_split_year_ten_plus_one() {
        let (runner, deed) = deed_split(DEED_TRANSITION_TICKS);
        assert_eq!(runner, 100);
        assert_eq!(deed, 0);
    }

    #[test]
    fn deed_split_far_future() {
        let (runner, deed) = deed_split(DEED_TRANSITION_TICKS * 10);
        assert_eq!(runner, 100);
        assert_eq!(deed, 0);
    }

    #[test]
    fn deed_fee_amounts_early() {
        let (runner, deed) = deed_fee_amounts(10, 1);
        assert_eq!(runner, 3); // 30% of 10
        assert_eq!(deed, 7);   // remainder
    }

    #[test]
    fn deed_fee_amounts_late() {
        let (runner, deed) = deed_fee_amounts(10, DEED_TRANSITION_TICKS);
        assert_eq!(runner, 10); // 100% of 10
        assert_eq!(deed, 0);
    }

    // ── Runner Pool ──

    #[test]
    fn runner_pool_accumulates() {
        let mut pool = RunnerPool::new();
        pool.add_deed_fee(10, 1); // 30% = 3
        pool.add_deed_fee(10, 1); // 30% = 3
        pool.add_deed_fee(10, 1); // 30% = 3

        assert_eq!(pool.balance, 9);
        assert_eq!(pool.total_collected, 30);
    }

    #[test]
    fn runner_pool_claim() {
        let mut pool = RunnerPool::new();
        pool.add_deed_fee(100, 1); // 30% = 30

        pool.process_claim(20).unwrap();
        assert_eq!(pool.balance, 10);
        assert_eq!(pool.total_claimed, 20);
    }

    #[test]
    fn runner_pool_claim_insufficient() {
        let mut pool = RunnerPool::new();
        pool.add_deed_fee(10, 1); // 30% = 3

        let result = pool.process_claim(100);
        assert!(matches!(result, Err(NablaError::InsufficientPoolBalance)));
    }

    // ── Claim Tracker ──

    #[test]
    fn claim_tracker_first_claim() {
        let tracker = ClaimTracker::new();
        assert!(tracker.can_claim(&nid(0xAA), 1));
    }

    #[test]
    fn claim_tracker_cooldown() {
        let mut tracker = ClaimTracker::new();
        tracker.record_claim(nid(0xAA), 100);

        // Too soon (need RUNNER_CLAIM_TICKS gap)
        assert!(!tracker.can_claim(&nid(0xAA), 100 + RUNNER_CLAIM_TICKS.to_secs() - 1));

        // Exactly at cooldown boundary
        assert!(tracker.can_claim(&nid(0xAA), 100 + RUNNER_CLAIM_TICKS.to_secs()));
    }

    #[test]
    fn claim_tracker_different_nodes() {
        let mut tracker = ClaimTracker::new();
        tracker.record_claim(nid(0xAA), 100);

        // Different node can still claim
        assert!(tracker.can_claim(&nid(0xBB), 100));
    }

    // ── Runner Claim Validation ──

    /// SEC-05: a fully-valid, well-formed runner claim STILL fails closed
    /// because the CC score is self-attested. This is the acceptance test
    /// for the fail-closed guardrail — the payout path refuses to run (and
    /// therefore cannot be drained by a patched node) until k-witnessed
    /// counts + Core-mediated CC proof are wired.
    #[test]
    fn validate_claim_fails_closed_while_cc_self_attested() {
        let nbc = make_nbc(0xAA);
        let node_id = nbc_node_id(&nbc);
        let mut chain = CcChain::new(nbc);

        for tick in 1..=10 {
            chain.record_registration();
            let cc = chain.produce_cc(tick, &crate::crypto::NoopSigner);
            chain.accept_cc(cc);
        }
        let latest = chain.latest().unwrap().clone();

        let mut pool = RunnerPool::new();
        for _ in 0..100 {
            pool.add_deed_fee(10, 1);
        }

        let tracker = ClaimTracker::new();
        let claim = RunnerClaim {
            node_id,
            cc: latest.clone(),
            claim_tick: 11,
        };

        // Everything about the claim is valid, yet the gate refuses it.
        assert!(matches!(
            validate_runner_claim(&claim, &pool, &tracker, latest.score * 2, &crate::crypto::NoopSigner),
            Err(NablaError::CcPayoutSelfAttested)
        ));
    }

    /// The fail-closed gate precedes every other check, so even a malformed
    /// claim (wrong node, cooldown) reports the gate rather than the inner
    /// reason. The inner checks remain in the code for the day the gate is
    /// removed alongside the attestation wiring.
    #[test]
    fn validate_claim_gate_precedes_inner_checks() {
        let nbc = make_nbc(0xAA);
        let node_id = nbc_node_id(&nbc);
        let chain = CcChain::new(nbc);
        let cc = chain.produce_cc(1, &crate::crypto::NoopSigner);

        let pool = RunnerPool::new();
        let tracker = ClaimTracker::new();

        // Wrong node: pre-gate this returned CcChainBroken; now gate fires.
        let wrong = RunnerClaim {
            node_id: [0xBB; 32],
            cc: cc.clone(),
            claim_tick: 2,
        };
        assert!(matches!(
            validate_runner_claim(&wrong, &pool, &tracker, 100, &crate::crypto::NoopSigner),
            Err(NablaError::CcPayoutSelfAttested)
        ));

        // Cooldown active: pre-gate this returned ClaimCooldownActive.
        let mut tracker2 = ClaimTracker::new();
        tracker2.record_claim(node_id, 1);
        let cooldown = RunnerClaim { node_id, cc, claim_tick: 2 };
        assert!(matches!(
            validate_runner_claim(&cooldown, &pool, &tracker2, 100, &crate::crypto::NoopSigner),
            Err(NablaError::CcPayoutSelfAttested)
        ));
    }

    // ── Score Calculation ──

    #[test]
    fn score_zero_registrations() {
        // Empty node — score is just uptime × W1
        let score = compute_score(1000, 0);
        assert_eq!(score, 1000 * SCORE_W1);
    }

    #[test]
    fn score_registrations_dominate() {
        // Node with many registrations should have much higher score
        let score_idle = compute_score(1000, 0);
        let score_busy = compute_score(1000, 1000);

        assert!(score_busy > score_idle * 5); // registrations dominate
    }

    #[test]
    fn score_sybil_resistance() {
        // 10 empty nodes vs 1 busy node
        let score_empty = compute_score(1000, 0) * 10; // 10 empty Sybil nodes
        let score_real = compute_score(1000, 1000);      // 1 real node with registrations

        assert!(score_real > score_empty); // single busy node beats 10 empty ones
    }

    // ── W1/W2 Calibration Tests (D3) ──

    #[test]
    fn calibration_1_honest_beats_10_empty_sybils() {
        // Core property: 1 honest node with moderate registrations beats
        // 10 empty Sybil nodes running the same uptime.
        // At W1=1, W2=10: honest=1000+1000*10=11000, sybil_total=10*1000=10000
        let honest = compute_score(1000, 1000);
        let sybil_total: u64 = (0..10).map(|_| compute_score(1000, 0)).sum();
        assert!(honest > sybil_total,
            "1 honest node (score={}) must beat 10 empty Sybils (total={})",
            honest, sybil_total);
    }

    #[test]
    fn calibration_low_traffic_still_viable() {
        // Low-traffic node (1 reg per 10 ticks) should still accumulate meaningful score.
        // Over 1000 ticks with 100 registrations: score = 1000 + 100*10 = 2000
        let score = compute_score(1000, 100);
        assert!(score > 1000, "Low-traffic node must score above bare uptime");
        // Should beat 1 empty Sybil with same uptime
        let sybil = compute_score(1000, 0);
        assert!(score >= sybil * 2, "Low-traffic honest node should significantly beat 1 empty Sybil");
    }

    #[test]
    fn calibration_50_node_network_scenario() {
        // Simulate a 50-node network: 40 honest (varying traffic), 10 Sybil (empty).
        // Honest nodes: 1-40 regs per tick × 200 ticks
        let honest_scores: Vec<u64> = (1..=40)
            .map(|i| compute_score(200, i * 5)) // 5-200 registrations over 200 ticks
            .collect();
        let sybil_scores: Vec<u64> = (0..10)
            .map(|_| compute_score(200, 0))
            .collect();

        let avg_honest: u64 = honest_scores.iter().sum::<u64>() / 40;
        let avg_sybil: u64 = sybil_scores.iter().sum::<u64>() / 10;

        // Average honest node should outscore average Sybil by at least 5x
        assert!(avg_honest > avg_sybil * 5,
            "avg honest={} must be >5x avg sybil={}",
            avg_honest, avg_sybil);

        // Even the weakest honest node should beat the strongest Sybil
        let min_honest = *honest_scores.iter().min().unwrap();
        let max_sybil = *sybil_scores.iter().max().unwrap();
        assert!(min_honest > max_sybil,
            "weakest honest={} must beat strongest sybil={}",
            min_honest, max_sybil);
    }

    #[test]
    fn calibration_overflow_safety() {
        // Score calculation must not overflow with large values
        let score = compute_score(u64::MAX / 2, u64::MAX / 20);
        assert!(score > 0, "saturating_mul should prevent overflow");
    }

    // ── Replay Prevention ──

    #[test]
    fn cc_replay_detection() {
        let nbc = make_nbc(0xAA);
        let mut chain = CcChain::new(nbc);

        chain.record_registration();
        let cc1 = chain.produce_cc(1, &crate::crypto::NoopSigner);
        chain.accept_cc(cc1.clone());

        chain.record_registration();
        let cc2 = chain.produce_cc(2, &crate::crypto::NoopSigner);
        chain.accept_cc(cc2.clone());

        chain.record_registration();
        let cc3 = chain.produce_cc(3, &crate::crypto::NoopSigner);

        // cc3 chains from cc2, not cc1
        assert!(verify_cc_chain(&cc2, &cc3).is_ok());
        // Trying to chain cc3 from cc1 fails (skipped cc2)
        assert!(verify_cc_chain(&cc1, &cc3).is_err());
    }

    // ── NBC Verification Tests ──

    /// Helper: generate 1 root authority SPHINCS+ keypair for NBC (k=1).
    /// Returns (public_keys, secret_keys) — Vec for API compatibility.
    fn make_root_keys() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes;
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("SPHINCS+ keygen");
        (vec![pk.into_bytes().to_vec()], vec![sk.into_bytes().to_vec()])
    }

    /// Helper: create a production-like NBC with real SPHINCS+ signature (k=1).
    fn make_real_nbc_signed(sphincs_pk: &[u8], ed25519_pk: &[u8], tick: u64,
                            root_pks: &[Vec<u8>], root_sks: &[Vec<u8>]) -> NBC {
        make_real_nbc_with_name(sphincs_pk, ed25519_pk, tick, root_pks, root_sks, "")
    }

    /// Helper: create NBC with a specific node_name (signed into payload).
    /// NBC uses k=1: 1 issuer, 1 signature.
    fn make_real_nbc_with_name(sphincs_pk: &[u8], ed25519_pk: &[u8], tick: u64,
                               root_pks: &[Vec<u8>], root_sks: &[Vec<u8>],
                               name: &str) -> NBC {
        let validator_id = axiom_core_logic::compute::compute_validator_id(sphincs_pk);
        let mut nbc = VBC {
            network_size_baseline: 0,
            baseline_tick: 0,
            version: 0x09,
            validator_id,
            subject_pubkey_sphincs: sphincs_pk.to_vec(),
            subject_pubkey_dilithium: vec![0u8; 1952],
            subject_pubkey_ed25519: ed25519_pk.to_vec(),
            pgp_fingerprint: vec![],
            node_name: name.to_string(),
            proof_cap: String::new(),
            issued_at: tick,
            expires_at: tick + NBC_EXPIRY_SECS,
            chain_depth: 0,
            issuer_set: vec![root_pks[0].clone()], // k=1: single issuer
            signatures: vec![],
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
            genesis_lineage: [0u8; 32],
            nabla_registration: None,
        };
        let payload = axiom_core_logic::compute::compute_vbc_signing_payload(&nbc);
        let sig = axiom_core_logic::compute::sign_sphincs(&root_sks[0], &payload).expect("sign");
        nbc.signatures = vec![sig]; // k=1: single signature
        nbc
    }

    /// Backward-compatible helper — creates NBC with real SPHINCS+ signature (k=1).
    fn make_real_nbc(sphincs_pk: &[u8], ed25519_pk: &[u8], tick: u64) -> NBC {
        let (root_pks, root_sks) = make_root_keys();
        make_real_nbc_signed(sphincs_pk, ed25519_pk, tick, &root_pks, &root_sks)
    }

    #[test]
    fn nbc_verify_valid() {
        let nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        assert!(verify_nbc(&nbc, 1000).is_ok());
    }

    #[test]
    fn nbc_verify_expired() {
        let nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        // expires_at = 1000 + NBC_EXPIRY_SECS, so tick past that should fail
        let result = verify_nbc(&nbc, 1000 + NBC_EXPIRY_SECS + 1);
        assert!(matches!(result, Err(NablaError::NbcExpired { .. })));
    }

    #[test]
    fn nbc_verify_identity_mismatch() {
        let mut nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        nbc.validator_id = [0xFF; 32]; // tampered
        let result = verify_nbc(&nbc, 1000);
        assert!(matches!(result, Err(NablaError::NbcIdentityMismatch)));
    }

    #[test]
    fn nbc_verify_empty_sphincs() {
        let mut nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        nbc.subject_pubkey_sphincs = vec![];
        let result = verify_nbc(&nbc, 1000);
        assert!(matches!(result, Err(NablaError::NbcMalformed(_))));
    }

    #[test]
    fn nbc_verify_empty_issuer_set() {
        let mut nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        nbc.issuer_set = vec![];
        nbc.signatures = vec![];
        let result = verify_nbc(&nbc, 1000);
        assert!(matches!(result, Err(NablaError::NbcMalformed(_))));
    }

    #[test]
    fn nbc_verify_sig_count_mismatch() {
        let mut nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        nbc.signatures = vec![vec![0u8; 16], vec![0u8; 16]]; // 2 sigs, 1 issuer
        let result = verify_nbc(&nbc, 1000);
        assert!(matches!(result, Err(NablaError::NbcMalformed(_))));
    }

    #[test]
    fn nbc_verify_wrong_version() {
        let mut nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        nbc.version = 0x01;
        let result = verify_nbc(&nbc, 1000);
        assert!(matches!(result, Err(NablaError::NbcMalformed(_))));
    }

    #[test]
    fn nbc_serialize_roundtrip() {
        let nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        let bytes = serialize_nbc(&nbc);
        let decoded = deserialize_nbc(&bytes).unwrap();
        assert_eq!(decoded.validator_id, nbc.validator_id);
        assert_eq!(decoded.subject_pubkey_ed25519, nbc.subject_pubkey_ed25519);
    }

    #[test]
    fn nbc_deserialize_empty() {
        let result = deserialize_nbc(&[]);
        assert!(matches!(result, Err(NablaError::NbcMissing(_))));
    }

    #[test]
    fn nbc_verify_name_too_long() {
        let mut nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        nbc.node_name = "A".repeat(65); // 65 bytes > 64 limit
        let result = verify_nbc(&nbc, 1000);
        assert!(matches!(result, Err(NablaError::NbcMalformed(_))));
    }

    #[test]
    fn nbc_verify_name_at_limit() {
        let (pks, sks) = make_root_keys();
        let name = "A".repeat(64); // exactly 64 bytes — OK
        let nbc = make_real_nbc_with_name(&[0xAA; 32], &[0xBB; 32], 1000, &pks, &sks, &name);
        assert!(verify_nbc(&nbc, 1000).is_ok());
    }

    #[test]
    fn nbc_verify_name_empty_ok() {
        let nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        assert!(nbc.node_name.is_empty());
        assert!(verify_nbc(&nbc, 1000).is_ok());
    }

    #[test]
    fn nbc_verify_name_cjk_ok() {
        let (pks, sks) = make_root_keys();
        let nbc = make_real_nbc_with_name(&[0xAA; 32], &[0xBB; 32], 1000, &pks, &sks, "皇帝企鵝");
        assert!(verify_nbc(&nbc, 1000).is_ok());
    }

    #[test]
    fn nbc_sim_nbc_passes_verify() {
        // sim_nbc uses node_id as sphincs_pk, so BLAKE3(node_id) != node_id
        // EXCEPT when node_id happens to be BLAKE3(node_id), which is ~never.
        // sim_nbc is a placeholder — it will NOT pass verify_nbc identity check.
        // This is by design: sim mode bypasses verification.
        let nbc = sim_nbc(nid(0xAA), 1000);
        let result = verify_nbc(&nbc, 1000);
        // sim_nbc has validator_id = node_id, sphincs_pk = node_id,
        // so validator_id != BLAKE3(sphincs_pk) → identity mismatch expected.
        assert!(matches!(result, Err(NablaError::NbcIdentityMismatch)));
    }

    // NOTE: verify_nbc() now includes SPHINCS+ signature verification.
    // SPHINCS+ tampered/wrong-issuer tests are below.
    // Full chain-of-trust for deep chains uses verify_nbc_chain().

    #[test]
    fn nbc_verify_sphincs_tampered_signature() {
        let nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        // Flip a bit in the signature
        let mut tampered = nbc.clone();
        tampered.signatures[0][0] ^= 0x01;
        let result = verify_nbc(&tampered, 1000);
        assert!(matches!(result, Err(NablaError::NbcSignatureInvalid)),
            "tampered SPHINCS+ signature must be rejected, got: {:?}", result);
    }

    #[test]
    fn nbc_verify_sphincs_wrong_issuer() {
        // Create NBC signed by one key, but replace issuer_set with a different key
        let (pks1, sks1) = make_root_keys();
        let (pks2, _sks2) = make_root_keys();
        let nbc = make_real_nbc_signed(&[0xAA; 32], &[0xBB; 32], 1000, &pks1, &sks1);
        // Swap issuer to a different key — signature won't match
        let mut wrong_issuer = nbc.clone();
        wrong_issuer.issuer_set = vec![pks2[0].clone()];
        let result = verify_nbc(&wrong_issuer, 1000);
        assert!(matches!(result, Err(NablaError::NbcSignatureInvalid)),
            "wrong issuer key must be rejected, got: {:?}", result);
    }

    #[test]
    fn nbc_verify_root_trust_genesis() {
        // Test-generated keys are NOT in NABLA_ROOT_AUTHORITY_PKS
        let nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        assert_eq!(nbc.chain_depth, 0, "make_real_nbc creates genesis NBC");
        let result = verify_nbc_root_trust(&nbc);
        assert!(matches!(result, Err(NablaError::NbcIssuerNotRoot)),
            "test key not in root authority set, got: {:?}", result);
    }

    #[test]
    fn nbc_verify_chain_peer_issued() {
        // Issue NBC from a test issuer — single-hop SPHINCS+ passes
        use axiom_nabla_ceremony::generate_node_nbc;

        let dir = tempfile::tempdir().unwrap();
        let root_keys_dir = dir.path().join("root-keys");
        let (root_pks, root_sks) = axiom_nabla_ceremony::generate_root_keys(&root_keys_dir);

        let issuer_config = dir.path().join("issuer").join("config");
        let issuer = generate_node_nbc("issuer", &issuer_config, &root_pks, &root_sks, 0, 1000, 1000 + NBC_EXPIRY_SECS);

        let new_config = dir.path().join("new_node").join("config");
        let subject = generate_node_keys(&new_config, "new-node").unwrap();
        let issuer_sk = std::fs::read(issuer_config.join("nabla_sphincs.key")).unwrap();

        let (nbc, supporting) = issue_nbc(&subject, &issuer.nbc, &issuer_sk, &[], 1500, (0, 0)).unwrap();
        // Single-hop SPHINCS+ verification should pass (issuer signed it)
        assert!(verify_nbc(&nbc, 1500).is_ok(), "peer-issued NBC must pass SPHINCS+ check");
        // Root trust should fail (test keys not in NABLA_ROOT_AUTHORITY_PKS)
        // chain_depth=1, so verify_nbc_root_trust skips the check
        assert_eq!(nbc.chain_depth, 1);
        assert!(verify_nbc_root_trust(&nbc).is_ok(),
            "chain_depth=1 NBC should skip root trust check");

        // Full chain verification: target NBC (chain_depth=1) + issuer NBC in supporting
        // verify_nbc_chain walks: target → issuer (chain_depth=0) → root trust.
        // This uses test keys NOT in NABLA_ROOT_AUTHORITY_PKS, so root trust check
        // will fail on the issuer's genesis NBC.
        let chain_result = verify_nbc_chain(&nbc, &supporting, 1500);
        assert!(chain_result.is_err(),
            "chain with test root keys should fail root trust on issuer");
    }

    #[test]
    fn nbc_ed25519_pk_extraction() {
        let ed25519_pk = [0xCC; 32];
        let nbc = make_real_nbc(&[0xAA; 32], &ed25519_pk, 1000);
        let extracted = nbc_ed25519_pk(&nbc);
        assert_eq!(extracted, Some(ed25519_pk));
    }

    #[test]
    fn nbc_ed25519_pk_wrong_size() {
        let mut nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        nbc.subject_pubkey_ed25519 = vec![0u8; 16]; // wrong size
        assert_eq!(nbc_ed25519_pk(&nbc), None);
    }

    // ── NBC Peer Issuance Tests ──

    #[test]
    fn test_issue_nbc_basic() {
        // Generate real keys for issuer (same pattern as ceremony)
        use axiom_nabla_ceremony::generate_node_nbc;

        let dir = tempfile::tempdir().unwrap();
        let root_keys_dir = dir.path().join("root-keys");
        let (root_pks, root_sks) = axiom_nabla_ceremony::generate_root_keys(&root_keys_dir);

        let issuer_config = dir.path().join("issuer").join("config");
        let issuer = generate_node_nbc("issuer", &issuer_config, &root_pks, &root_sks, 0, 1000, 1000 + NBC_EXPIRY_SECS);

        // Generate keys for new node
        let new_config = dir.path().join("new_node").join("config");
        let subject = generate_node_keys(&new_config, "new-node").unwrap();

        // Issuer's SPHINCS+ SK
        let issuer_sk = std::fs::read(issuer_config.join("nabla_sphincs.key")).unwrap();

        // Issue NBC
        let (nbc, supporting) = issue_nbc(
            &subject,
            &issuer.nbc,
            &issuer_sk,
            &[], // genesis issuer has no supporting chain
            1500,
            (0, 0),
        ).unwrap();

        // Verify result
        assert_eq!(nbc.chain_depth, 1); // issuer was depth 0, so new node is depth 1
        assert_eq!(nbc.node_name, "new-node");
        assert_eq!(nbc.issuer_set.len(), 1); // k=1 for NBC
        assert_eq!(nbc.issuer_set[0], issuer.nbc.subject_pubkey_sphincs);
        assert_eq!(nbc.signatures.len(), 1);
        assert_eq!(nbc.issued_at, 1500);
        assert_eq!(nbc.expires_at, 1500 + NBC_EXPIRY_SECS);
        assert_eq!(supporting.len(), 1); // just the issuer's NBC
        assert_eq!(supporting[0].validator_id, issuer.nbc.validator_id);

        // Verify structural integrity
        assert!(verify_nbc(&nbc, 1500).is_ok());
    }

    #[test]
    fn test_issue_nbc_chain_depth() {
        // Depth 0 (genesis) issues depth 1, depth 1 issues depth 2
        use axiom_nabla_ceremony::generate_node_nbc;

        let dir = tempfile::tempdir().unwrap();
        let root_keys_dir = dir.path().join("root-keys");
        let (root_pks, root_sks) = axiom_nabla_ceremony::generate_root_keys(&root_keys_dir);

        // Genesis issuer (depth 0)
        let genesis_config = dir.path().join("genesis").join("config");
        let genesis = generate_node_nbc("genesis", &genesis_config, &root_pks, &root_sks, 0, 1000, 1000 + NBC_EXPIRY_SECS);
        let genesis_sk = std::fs::read(genesis_config.join("nabla_sphincs.key")).unwrap();

        // First-gen node (depth 1)
        let node1_config = dir.path().join("node1").join("config");
        let subject1 = generate_node_keys(&node1_config, "node1").unwrap();
        let (nbc1, supporting1) = issue_nbc(&subject1, &genesis.nbc, &genesis_sk, &[], 1100, (0, 0)).unwrap();
        assert_eq!(nbc1.chain_depth, 1);
        let node1_sk = std::fs::read(node1_config.join("nabla_sphincs.key")).unwrap();

        // Second-gen node (depth 2)
        let node2_config = dir.path().join("node2").join("config");
        let subject2 = generate_node_keys(&node2_config, "node2").unwrap();
        let (nbc2, supporting2) = issue_nbc(&subject2, &nbc1, &node1_sk, &supporting1, 1200, (0, 0)).unwrap();
        assert_eq!(nbc2.chain_depth, 2);
        assert_eq!(supporting2.len(), 2); // [nbc1, genesis.nbc]
        assert_eq!(supporting2[0].validator_id, nbc1.validator_id);
        assert_eq!(supporting2[1].validator_id, genesis.nbc.validator_id);

        // Both should pass structural verification
        assert!(verify_nbc(&nbc1, 1100).is_ok());
        assert!(verify_nbc(&nbc2, 1200).is_ok());
    }

    #[test]
    fn test_qualified_issuer_maturity() {
        let nbc = sim_nbc(nid(0xAA), 1000);
        let sk = vec![0u8; 64]; // dummy SK — not actually signing

        // With 0 maturity (dev): qualified immediately
        assert!(is_qualified_issuer(&nbc, Some(&sk), 0, 1001));

        // With 48h maturity: not qualified until 48h after issuance
        assert!(!is_qualified_issuer(&nbc, Some(&sk), 48 * 3600, 1001));
        assert!(is_qualified_issuer(&nbc, Some(&sk), 48 * 3600, 1000 + 48 * 3600 + 1));

        // Without SK: never qualified
        assert!(!is_qualified_issuer(&nbc, None, 0, 1001));

        // Expired NBC: not qualified
        let expired_nbc = sim_nbc(nid(0xBB), 0);
        assert!(!is_qualified_issuer(&expired_nbc, Some(&sk), 0, NBC_EXPIRY_SECS + 1));
    }

    #[test]
    fn test_issue_nbc_unqualified_expired() {
        // Expired issuer → issue_nbc should still work (issue_nbc doesn't check qualification)
        // but is_qualified_issuer should reject
        let expired_nbc = sim_nbc(nid(0xCC), 0);
        let sk = vec![0u8; 64];
        assert!(!is_qualified_issuer(&expired_nbc, Some(&sk), 0, NBC_EXPIRY_SECS + 1));
    }

    #[test]
    fn test_generate_node_keys_creates_files() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        let subject = generate_node_keys(&config_dir, "test-keygen").unwrap();

        // All key files must exist
        assert!(config_dir.join("nabla_sphincs.pub").exists());
        assert!(config_dir.join("nabla_sphincs.key").exists());
        assert!(config_dir.join("nabla_ed25519.pub").exists());
        assert!(config_dir.join("nabla_ed25519.key").exists());
        assert!(config_dir.join("nabla_dilithium.pub").exists());
        assert!(config_dir.join("nabla_dilithium.key").exists());

        // Key sizes
        assert_eq!(subject.sphincs_pk.len(), 32);
        assert_eq!(subject.ed25519_pk.len(), 32);
        assert_eq!(subject.dilithium_pk.len(), 1952);
        assert_eq!(subject.node_name, "test-keygen");

        // SK file sizes
        assert_eq!(std::fs::read(config_dir.join("nabla_sphincs.key")).unwrap().len(), 64);
        assert_eq!(std::fs::read(config_dir.join("nabla_ed25519.key")).unwrap().len(), 32);
        assert_eq!(std::fs::read(config_dir.join("nabla_dilithium.key")).unwrap().len(), 4032);
    }

    #[test]
    fn nbc_verify_structural_and_sphincs_passes_valid() {
        // verify_nbc does structural + SPHINCS+ checks — valid NBC with real sigs passes
        let nbc = make_real_nbc(&[0xAA; 32], &[0xBB; 32], 1000);
        assert!(verify_nbc(&nbc, 1000).is_ok());
    }

    #[test]
    fn no_direct_core_crypto_in_production_code() {
        // Verify that nabla production code does NOT call axiom_core_logic::compute::
        // or ::verify:: directly. Only ceremony.rs and #[cfg(test)] blocks may use them.
        //
        // This is a compile-time-adjacent check: we grep the source files.
        // Walks src/ recursively (including src/bin/) to catch all .rs files.
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

        let forbidden = [
            "axiom_core_logic::compute::",
            "axiom_core_logic::verify::",
        ];

        // Files exempt from this rule.
        // cc.rs: NBC peer issuance uses core-logic sign_sphincs/verify_sphincs directly
        //        (same pattern as ceremony — core-logic IS Core).
        // clara.rs: CLARA registration (POST /clara) verifies cheque + heal-tx
        //        bundles cryptographically — compute_txid, compute_cheque_commitment,
        //        verify_ed25519, verify_pk_binding. HTTP-handler-synchronous: cannot
        //        afford a Core IPC round-trip for every request, and the canonical
        //        primitives live in core-logic. YPX-018 §2.4.
        // registration.rs: YP §19.6 fee_breakdown chain verify recomputes
        //        compute_receipt_commitment on every register to verify k Lambda
        //        Ed25519 sigs over the canonical hash. Same HTTP/TCP-handler-
        //        synchronous constraint as clara.rs — IPC round-trip per register
        //        would multiply latency. Canonical primitive lives in core-logic.
        // validator_pool.rs: YP §19.6 — SPHINCS+ verify on the
        //        RegisterValidatorPool path. Same hot-handler argument as
        //        clara/registration. Canonical primitives in core-logic.
        let exempt: [&str; 4] = ["cc.rs", "clara.rs", "registration.rs", "validator_pool.rs"];
        // TRIPWIRE: the crypto-boundary exemption set must NOT grow without
        // AXIOM Origin's explicit sign-off. Core is the sole cryptographic authority
        // (CLAUDE.md §1); each exempt file is a deliberate hot-path carve-out,
        // not a convenience hatch. If you need a synchronous core-logic crypto
        // primitive in new code, consolidate it into one of the files ALREADY
        // here (e.g. receipt-commitment verify → registration.rs), don't add a
        // 5th. See [[feedback_no_lazy_crypto_exemption]]. Bumping this number is
        // a red flag in review — it should never change silently.
        assert_eq!(
            exempt.len(),
            4,
            "crypto-boundary exemptions must not grow without AXIOM Origin's explicit sign-off \
             — consolidate into an existing exempt hot-path file instead of adding one",
        );

        fn walk_dir(dir: &std::path::Path, forbidden: &[&str], exempt: &[&str]) {
            for entry in std::fs::read_dir(dir).expect("read dir") {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_dir() {
                    walk_dir(&path, forbidden, exempt);
                    continue;
                }
                if path.extension().is_none_or(|ext| ext != "rs") { continue; }
                let filename = path.file_name().unwrap().to_str().unwrap();
                if exempt.contains(&filename) { continue; }

                let content = std::fs::read_to_string(&path).unwrap();

                // Strip #[cfg(test)] blocks (rough but effective)
                // Split on #[cfg(test)] and only check the part before it
                let production_code = content.split("#[cfg(test)]").next().unwrap_or(&content);

                for pattern in forbidden {
                    assert!(
                        !production_code.contains(pattern),
                        "BOUNDARY VIOLATION: {} contains '{}' in production code. \
                         Crypto must go through Core IPC (CL6), not direct calls. \
                         Only ceremony.rs and #[cfg(test)] blocks are exempt.",
                        path.display(), pattern,
                    );
                }
            }
        }

        walk_dir(&src_dir, &forbidden, &exempt);
    }

    // ── NBC Renewal Tests ──

    /// Helper: create a real issuer + old node NBCs using ceremony keygen.
    fn setup_renewal() -> (NBC, Vec<u8>, NBC, Vec<NBC>, tempfile::TempDir) {
        use axiom_nabla_ceremony::generate_node_nbc;

        let dir = tempfile::tempdir().unwrap();
        let root_keys_dir = dir.path().join("root-keys");
        let (root_pks, root_sks) = axiom_nabla_ceremony::generate_root_keys(&root_keys_dir);

        // Genesis issuer (depth 0)
        let issuer_config = dir.path().join("issuer").join("config");
        let issuer = generate_node_nbc("issuer", &issuer_config, &root_pks, &root_sks, 0, 1000, 1000 + NBC_EXPIRY_SECS);
        let issuer_sk = std::fs::read(issuer_config.join("nabla_sphincs.key")).unwrap();

        // Issue NBC for old node
        let old_config = dir.path().join("old_node").join("config");
        let subject = generate_node_keys(&old_config, "old-node").unwrap();
        let (old_nbc, _supporting) = issue_nbc(&subject, &issuer.nbc, &issuer_sk, &[], 1100, (0, 0)).unwrap();

        (old_nbc, issuer_sk, issuer.nbc, vec![], dir)
    }

    #[test]
    fn test_renew_preserves_founding_hash() {
        let (mut old_nbc, issuer_sk, issuer_nbc, issuer_sup, _dir) = setup_renewal();
        old_nbc.founding_vbc_hash = [0x42; 32];
        let current_time = old_nbc.expires_at - 3 * 86_400;

        let (renewed, _) = renew_nbc(
            &old_nbc, &issuer_nbc, &issuer_sk, &issuer_sup, current_time, (0, 0),
        ).unwrap();

        assert_eq!(renewed.founding_vbc_hash, [0x42; 32]);
        assert_eq!(renewed.validator_id, old_nbc.validator_id);
    }

    #[test]
    fn test_renew_extends_expiry() {
        let (old_nbc, issuer_sk, issuer_nbc, issuer_sup, _dir) = setup_renewal();
        let current_time = old_nbc.expires_at - 3 * 86_400;

        let (renewed, _) = renew_nbc(
            &old_nbc, &issuer_nbc, &issuer_sk, &issuer_sup, current_time, (0, 0),
        ).unwrap();

        assert_eq!(renewed.expires_at, current_time + NBC_EXPIRY_SECS);
        assert!(renewed.expires_at > old_nbc.expires_at);
    }

    #[test]
    fn test_renew_rejected_outside_window() {
        let (mut old_nbc, issuer_sk, issuer_nbc, issuer_sup, _dir) = setup_renewal();
        // max_tx=0 → time-only renewal (no TX-budget bypass)
        old_nbc.max_tx = 0;
        // Too early: 20 days before expiry
        let current_time = old_nbc.expires_at - 20 * 86_400;

        let result = renew_nbc(
            &old_nbc, &issuer_nbc, &issuer_sk, &issuer_sup, current_time, (0, 0),
        );
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("too early"));
    }

    #[test]
    fn test_renew_tx_budget_bypasses_time_window() {
        let (old_nbc, issuer_sk, issuer_nbc, issuer_sup, _dir) = setup_renewal();
        assert!(old_nbc.max_tx > 0, "NBC should have TX budget from build_unsigned_nbc");
        // 20 days before expiry — outside time window but max_tx > 0 allows it
        let current_time = old_nbc.expires_at - 20 * 86_400;

        let result = renew_nbc(
            &old_nbc, &issuer_nbc, &issuer_sk, &issuer_sup, current_time, (0, 0),
        );
        assert!(result.is_ok(), "TX-budget NBC should allow renewal outside time window");
    }

    #[test]
    fn test_renew_rejected_if_expired() {
        let (old_nbc, issuer_sk, issuer_nbc, issuer_sup, _dir) = setup_renewal();
        let current_time = old_nbc.expires_at + 100;

        let result = renew_nbc(
            &old_nbc, &issuer_nbc, &issuer_sk, &issuer_sup, current_time, (0, 0),
        );
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("expired"));
    }

    #[test]
    fn test_renew_accepted_in_window() {
        let (old_nbc, issuer_sk, issuer_nbc, issuer_sup, _dir) = setup_renewal();
        let current_time = old_nbc.expires_at - NBC_RENEWAL_WINDOW_SECS;

        let result = renew_nbc(
            &old_nbc, &issuer_nbc, &issuer_sk, &issuer_sup, current_time, (0, 0),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_renew_same_identity() {
        let (old_nbc, issuer_sk, issuer_nbc, issuer_sup, _dir) = setup_renewal();
        let current_time = old_nbc.expires_at - 3 * 86_400;

        let (renewed, _) = renew_nbc(
            &old_nbc, &issuer_nbc, &issuer_sk, &issuer_sup, current_time, (0, 0),
        ).unwrap();

        assert_eq!(renewed.validator_id, old_nbc.validator_id);
        assert_eq!(renewed.subject_pubkey_sphincs, old_nbc.subject_pubkey_sphincs);
        assert_eq!(renewed.subject_pubkey_ed25519, old_nbc.subject_pubkey_ed25519);
        assert_eq!(renewed.node_name, old_nbc.node_name);
    }

    // ── YPX-002 §9.1.1a — issuer self-cap + peer alarm (RULED 2026-09-25) ──

    /// The N+1-th certificate in one epoch is at cap; the N+1-th in the NEXT
    /// epoch is not (fresh budget). MUTATION: `count >= cap` → `count > cap`
    /// in `at_cap` lets the N+1-th through → this test goes red.
    #[test]
    fn nbc_issuance_budget_refuses_n_plus_one_in_epoch_not_in_next() {
        let cap = 3u64;
        let mut b = NbcIssuanceBudget::default();
        for i in 0..cap {
            assert!(!b.at_cap(7, cap), "certificate {} of {} is within budget", i + 1, cap);
            b.record(7);
        }
        assert_eq!(b.count_in(7), cap);
        assert!(b.at_cap(7, cap), "the N+1-th in the SAME epoch is refused");
        assert!(!b.at_cap(8, cap), "the N+1-th in the NEXT epoch is not");
        b.record(8);
        assert_eq!((b.epoch, b.count), (8, 1), "the count rolled with the epoch");
        assert_eq!(b.count_in(7), 0, "an old epoch reads as spent-nothing (it is gone)");
    }

    /// Peer alarm: fires ABOVE N, not AT N; genesis certificates are exempt;
    /// two issuers keep separate counts. MUTATION: `*n > cap` → `*n >= cap`
    /// → the "not at N" assertion goes red.
    #[test]
    fn nbc_issuer_over_cap_alarm_fires_above_n_not_at_n() {
        let cap = 2u64;
        let mk = |issuer: u8, issued_at: u64, depth: u8| {
            let mut nbc = sim_nbc(nid(0x5C), issued_at);
            nbc.chain_depth = depth;
            nbc.issuer_set = vec![vec![issuer; 32]];
            nbc
        };
        let span = crate::constants::fob_epoch_span_secs(false);
        let t = span * 5 + 1; // inside epoch 5
        let mut seen = std::collections::HashMap::new();
        assert!(note_issuer_certificate(&mut seen, &mk(0xA1, t, 1), cap).is_none(), "1 of N");
        assert!(note_issuer_certificate(&mut seen, &mk(0xA1, t + 1, 1), cap).is_none(), "AT N: no alarm");
        let fired = note_issuer_certificate(&mut seen, &mk(0xA1, t + 2, 1), cap);
        assert_eq!(fired.map(|(_, e, n)| (e, n)), Some((5, 3)), "ABOVE N: alarm names epoch + seen");
        // A different issuer is a different budget.
        assert!(note_issuer_certificate(&mut seen, &mk(0xB2, t, 1), cap).is_none());
        // The next epoch is a fresh count for the same issuer.
        assert!(note_issuer_certificate(&mut seen, &mk(0xA1, t + span, 1), cap).is_none());
        // Genesis (chain_depth 0) is exempt however many.
        for _ in 0..(cap + 2) {
            assert!(note_issuer_certificate(&mut seen, &mk(0xA1, t, 0), cap).is_none(), "genesis exempt");
        }
    }
}
