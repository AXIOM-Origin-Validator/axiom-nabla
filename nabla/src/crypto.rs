// AXIOM Nabla — Cryptographic Interface
//
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  ARCHITECTURAL RULE: Nabla NEVER does cryptography directly.       ║
// ║  All signing/verification goes through the Signer trait.           ║
// ║  Production: Core binary (IPC). Sim/Test: Ed25519Signer.          ║
// ╚══════════════════════════════════════════════════════════════════════╝
//
// In production, a Nabla node talks to its co-located Core binary:
//   - Core.in(payload)  → Core signs with its managed keys → signature
//   - Core.verify(pk, payload, sig) → true/false
//   - Nabla does not know which algorithm Core uses (Ed25519, Dilithium, SPHINCS+)
//
// The Signer trait abstracts this interface so that:
//   - Library code calls signer.sign() / signer.verify() at every point
//     where Core IPC previously existed (now uses Signer trait)
//   - Sim plugs in Ed25519Signer with real keypairs → catches payload bugs
//   - Production plugs in CoreIpcSigner → delegates to Core binary

use crate::types::*;

// ════════════════════════════════════════════════════════════════════════
// Signer Trait — Nabla's sole interface to cryptographic operations
// ════════════════════════════════════════════════════════════════════════

/// Cryptographic signer/verifier — Nabla's interface to Core.
///
/// Every place where Nabla needs to sign or verify goes through this trait.
/// Nabla never imports cryptographic primitives directly.
pub trait Signer: Send + Sync {
    /// Sign a payload with this node's private key.
    /// Returns the signature bytes (format is opaque to Nabla).
    fn sign(&self, payload: &[u8]) -> Vec<u8>;

    /// Verify a signature against a public key and payload.
    /// The public_key format matches what sign() was called with on the other end.
    fn verify(&self, public_key: &[u8], payload: &[u8], signature: &[u8]) -> bool;

    /// Return this node's public key bytes (for embedding in messages).
    fn public_key(&self) -> Vec<u8>;
}

// ════════════════════════════════════════════════════════════════════════
// Canonical Payload Builders
// ════════════════════════════════════════════════════════════════════════
//
// Each message type has a deterministic byte representation that gets
// signed/verified. These functions define what bytes are covered by
// the signature — the "signing envelope".

/// Canonical payload for a TickMessage signature.
/// Covers: tick number + timestamp_ms + sender pk + payload hash +
/// downstream approvals + prev_sig (chain continuity).
/// SEC-9 FIX: timestamp_ms prevents post-signing TARDIS window manipulation.
/// prev_sig enforces tick chain continuity (cannot reorder or forge chains).
pub fn tick_sign_payload(tick: &TickMessage) -> Vec<u8> {
    // Covers: tick.number, timestamp_ms, upstream_pk (= sender's
    // node_id), payload, downstream_approvals, prev_sig. The trust
    // anchor tying `upstream_pk` to a verification key lives in the
    // NBC chain — the receiver looks up `verified_nbcs[upstream_pk]`,
    // extracts the bound Ed25519 PK from that NBC, and verifies this
    // signature against THAT key. No signer_pk in the wire: the NBC
    // already serves as the trust binding, and putting another key in
    // the tick would be trust-on-first-byte (KI#18 fix discussion).
    let mut buf = Vec::with_capacity(8 + 8 + 32 + 32 + 1 + tick.prev_sig.len());
    buf.extend_from_slice(&tick.number.to_le_bytes());
    buf.extend_from_slice(&tick.timestamp_ms.to_le_bytes());
    buf.extend_from_slice(&tick.upstream_pk);
    buf.extend_from_slice(&tick.payload);
    buf.push(tick.downstream_approvals);
    buf.extend_from_slice(&tick.prev_sig);
    // YPX-021 §6 — cover the OODS-tardis accumulator so each forwarder attests
    // the value it propagates (the receiver recomputes over the same received
    // Vec, so no canonical-ordering step is needed — bytes match by construction).
    for e in &tick.oods_tardis {
        buf.extend_from_slice(&e.channel.to_le_bytes());
        buf.extend_from_slice(&e.raw.to_le_bytes());
        buf.extend_from_slice(&e.identity);
    }
    buf
}

/// BLAKE3 of the OODS-tardis accumulator — folded into the tick commitment BY HASH
/// (YPX-003 §7.6) so oods stays attested without being re-carried in a lineage proof.
pub fn oods_tardis_hash(oods: &[axiom_core_logic::oods_verify::OodsExtremum]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_TICK_OODS_v1");
    for e in oods {
        h.update(&e.channel.to_le_bytes());
        h.update(&e.raw.to_le_bytes());
        h.update(&e.identity);
    }
    *h.finalize().as_bytes()
}

/// Recompute a tick commitment from explicit fields — used to reconstruct the
/// GRANDPARENT's commitment (from the carried `gp_commitment` fields) so `prev_sig`
/// can be verified against it. Deterministic; length-prefixed so no field can bleed
/// into another. YPX-003 §7.6.
#[allow(clippy::too_many_arguments)]
pub fn tick_commitment_fields(
    number: u64,
    timestamp_ms: u64,
    upstream_pk: &[u8],
    payload: &[u8],
    downstream_approvals: u8,
    prev_sig: &[u8],
    child_pks: &[PeerId],
    oods_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_TICK_COMMIT_v1");
    h.update(&number.to_le_bytes());
    h.update(&timestamp_ms.to_le_bytes());
    h.update(upstream_pk);
    h.update(&(payload.len() as u32).to_le_bytes());
    h.update(payload);
    h.update(&[downstream_approvals]);
    h.update(&(prev_sig.len() as u32).to_le_bytes());
    h.update(prev_sig);
    h.update(&(child_pks.len() as u32).to_le_bytes());
    for pk in child_pks {
        h.update(pk);
    }
    h.update(oods_hash);
    *h.finalize().as_bytes()
}

/// The tick COMMITMENT (YPX-003 §7.6) — the fixed-size digest the tick signature
/// covers, replacing the raw `tick_sign_payload` for signing. Binds the sender's
/// `child_pks` (strict-parent) and attests `oods_tardis` by hash.
pub fn tick_commitment(tick: &TickMessage) -> [u8; 32] {
    tick_commitment_fields(
        tick.number,
        tick.timestamp_ms,
        &tick.upstream_pk,
        &tick.payload,
        tick.downstream_approvals,
        &tick.prev_sig,
        &tick.child_pks,
        &oods_tardis_hash(&tick.oods_tardis),
    )
}

/// Canonical payload for a TickApproval signature.
pub fn approval_sign_payload(approval: &TickApproval) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 32);
    buf.extend_from_slice(&approval.tick_number.to_le_bytes());
    buf.extend_from_slice(&approval.approver_pk);
    buf
}

/// Canonical payload for a SubtreeAuditResponse signature.
pub fn audit_response_sign_payload(response: &SubtreeAuditResponse) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + 32 + 8 + 32);
    buf.extend_from_slice(&response.prefix);
    buf.extend_from_slice(&response.root_hash);
    buf.extend_from_slice(&response.response_tick.to_le_bytes());
    buf.extend_from_slice(&response.responder_pk);
    buf
}

/// Canonical payload for a QuestionableAlert signature.
pub fn alert_sign_payload(alert: &QuestionableAlert) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 32 + 8 + 32);
    buf.extend_from_slice(&alert.suspect_pk);
    buf.extend_from_slice(&alert.reporter_pk);
    buf.extend_from_slice(&alert.tick.to_le_bytes());
    buf.extend_from_slice(&alert.evidence_hash);
    buf
}

/// Canonical payload for a `GossipMessage::PoolSync` signature
/// (Phase B Layer 4 — `docs/AXIOM_DESIGN_NablaPoolCaps.md` §5.6.5).
/// Covers the entire claim: which pool, what balance, how many
/// claims, when, and who. The receiver looks up the sender's
/// Ed25519 pk via `verified_nbcs[sender_node_id]` and verifies
/// the signature against this payload. A forged PoolSync (wrong
/// balance) with a real signature attributes the forgery
/// unambiguously to its signer — this is the attribution path the
/// `PoolViolationDetected` → `Alert.accused` chain depends on.
pub fn pool_sync_sign_payload(
    pool_byte: u8,
    balance: u64,
    total_claims: u64,
    tick: u64,
    sender_node_id: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(18 + 1 + 8 + 8 + 8 + 32);
    buf.extend_from_slice(b"AXIOM_POOL_SYNC_v1");
    buf.push(pool_byte);
    buf.extend_from_slice(&balance.to_le_bytes());
    buf.extend_from_slice(&total_claims.to_le_bytes());
    buf.extend_from_slice(&tick.to_le_bytes());
    buf.extend_from_slice(sender_node_id);
    buf
}

/// Canonical payload for a RegistrationAck signature.
pub fn ack_sign_payload(ack: &RegistrationAck) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 32 + 8 + 32);
    buf.extend_from_slice(&ack.wallet_id);
    buf.extend_from_slice(&ack.new_state);
    buf.extend_from_slice(&ack.tick.to_le_bytes());
    buf.extend_from_slice(&ack.root_hash);
    buf
}

/// Canonical payload for a NablaResponse signature.
///
/// Covers (in order):
///   wallet_id(32) | current_state(32) | root_hash(32) | synced_to_tick(8LE)
///   | nbc_issuer_pk_len(4LE) | nbc_issuer_pk(N)
///   | registration_tick(8LE) | wallet_status(1)
///
/// `nbc_issuer_pk`, `registration_tick`, and `wallet_status` were added in
/// YPX-002 §4.6. Including them here means the responding node Ed25519-signs
/// its cross-branch identity, maturity data, and BANNED status — a receiver
/// following §4.6 can verify these fields are genuine rather than injected
/// in transit. A length-prefix on `nbc_issuer_pk` prevents ambiguity when
/// the key is absent (zero-length Vec from a pre-§4.6 node).
pub fn response_sign_payload(resp: &NablaResponse) -> Vec<u8> {
    let pk_len = resp.nbc_issuer_pk.len();
    let mut buf = Vec::with_capacity(32 + 32 + 32 + 8 + 4 + pk_len + 8 + 1);
    buf.extend_from_slice(&resp.wallet_id);
    buf.extend_from_slice(&resp.current_state);
    buf.extend_from_slice(&resp.root_hash);
    buf.extend_from_slice(&resp.synced_to_tick.to_le_bytes());
    buf.extend_from_slice(&(pk_len as u32).to_le_bytes());
    buf.extend_from_slice(&resp.nbc_issuer_pk);
    buf.extend_from_slice(&resp.registration_tick.to_le_bytes());
    buf.push(match resp.wallet_status {
        WalletStatus::Normal  => 0u8,
        WalletStatus::Frozen  => 1u8,
        WalletStatus::Tainted => 2u8,
        WalletStatus::Banned  => 3u8,
    });
    buf
}

// NBC: All cryptographic operations (signing commitment, signing, verification)
// are done by Core via execute(PublicInputs) → PublicOutputs.
// Same verification path as VBC. Nabla never does NBC crypto.

/// Canonical payload for Companion Certificate proof.
/// Covers all fields except the proof itself.
pub fn cc_sign_payload(
    node_id: &NodeId,
    tick: u64,
    registrations_this_tick: u32,
    total_registrations: u64,
    ticks_helped: u64,
    score: u64,
    prev_cc_hash: &Hash256,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 8 + 4 + 8 + 8 + 8 + 32);
    buf.extend_from_slice(node_id);
    buf.extend_from_slice(&tick.to_le_bytes());
    buf.extend_from_slice(&registrations_this_tick.to_le_bytes());
    buf.extend_from_slice(&total_registrations.to_le_bytes());
    buf.extend_from_slice(&ticks_helped.to_le_bytes());
    buf.extend_from_slice(&score.to_le_bytes());
    buf.extend_from_slice(prev_cc_hash);
    buf
}

/// Canonical payload for NablaConfirmation (FACT link healing).
///
/// V2 (2026-05-15): now includes `committed_at_tick` — the writer's
/// TARDIS tick at SMT commit.  Core CL5 redeem enforces
/// `current_tick > committed_at_tick` so a receiver cannot redeem
/// in the same tick the sender's commit landed.  See YP §17.10.5.3.
///
/// Domain: BLAKE3("AXIOM_FACT_CONFIRM_V2"
///                || tx_hash
///                || new_state
///                || committed_at_tick.to_le_bytes())
/// where tx_hash = BLAKE3("AXIOM_TXHASH" || old_state || new_state).
///
/// Used by BOTH TCP (registration.rs) and HTTP (nabla_node.rs) paths.
/// Core's matching recompute lives in `core/logic/src/fact.rs::verify_fact_link`.
pub fn fact_confirm_payload(
    old_state: &StateId,
    new_state: &StateId,
    committed_at_tick: u64,
) -> [u8; 32] {
    let tx_hash = {
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_TXHASH");
        h.update(old_state);
        h.update(new_state);
        *h.finalize().as_bytes()
    };
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_FACT_CONFIRM_V2");
    h.update(&tx_hash);
    h.update(new_state);
    h.update(&committed_at_tick.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Canonical payload for a k=3 receipt witness signature.
///
/// Each validator signs: wallet_id + consumed_state + tick.
///
/// `produced_state_id` is NOT in the payload — it depends on aggregate
/// `total_fee` (sum of k slot amounts), which no single validator can know
/// at witness time in a serial round (Lambda only knows its OWN rate/slot).
///
/// `tx_hash` / `txid` is also NOT in the payload, because the SDK
/// (`BLAKE3("AXIOM_TXHASH" || old_state || new_state)`) and Lambda
/// (`compute_txid(transaction)`) historically derived different
/// representations. Including either would force one side to mirror the
/// other's formula, which is fragile.
///
/// Replay protection comes from `(wallet_id, consumed_state)` alone:
/// the wallet's `state_id` advances strictly forward with every TX, so the
/// same consumed_state can never be re-witnessed by the same wallet.
///
/// Tampering with the resulting `produced_state_id` is detected by
/// recomputation downstream: anyone holding the receipt computes
/// `produced_state_id` from `(pk, new_balance, new_wallet_seq, txid)`,
/// where `new_balance = prev_balance + amount − sum(fee_breakdown)` and
/// each `fee_breakdown[i].slot_amount` is cross-checked against
/// `WitnessSig[i].slot_amount` (which IS self-attested via the validator's
/// own Core via `verify_slot_math`).
pub fn receipt_sign_payload(
    wallet_id: &WalletId,
    consumed_state: &StateId,
    tick: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 32 + 8);
    buf.extend_from_slice(wallet_id);
    buf.extend_from_slice(consumed_state);
    buf.extend_from_slice(&tick.to_le_bytes());
    buf
}

// ════════════════════════════════════════════════════════════════════════
// Ed25519 Implementation — for sim and tests
// ════════════════════════════════════════════════════════════════════════

use ed25519_dalek::{SigningKey, VerifyingKey, Signature};
use ed25519_dalek::Signer as DalekSigner;
use ed25519_dalek::Verifier as DalekVerifier;

/// Ed25519 signer for simulation and testing.
///
/// Each SimNode gets one. Keypair is deterministic from seed so the
/// sim is reproducible. In production, Core manages the real keys.
pub struct Ed25519Signer {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Ed25519Signer {
    /// Create from a 32-byte seed (deterministic).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Create from a node index (deterministic — for sim).
    /// Derives a unique keypair from the node's index.
    pub fn from_node_index(id: usize) -> Self {
        let seed = blake3::hash(&(id as u64).to_le_bytes());
        Self::from_seed(seed.as_bytes())
    }

    /// Get the 32-byte Ed25519 public key (also used as NodeId in sim).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing_key.sign(payload);
        sig.to_bytes().to_vec()
    }

    fn verify(&self, public_key: &[u8], payload: &[u8], signature: &[u8]) -> bool {
        if public_key.len() != 32 || signature.len() != 64 {
            return false;
        }
        let pk_bytes: [u8; 32] = public_key.try_into().unwrap();
        let sig_bytes: [u8; 64] = signature.try_into().unwrap();

        let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(payload, &sig).is_ok()
    }

    fn public_key(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
}

/// Standalone Ed25519 signature verification.
///
/// Used for verifying third-party signatures (e.g., wallet binding) where
/// the signer trait is not appropriate (the signer is the node's own key,
/// not the third party's key). This keeps Ed25519 verification in Nabla's
/// own code without importing from axiom_core_logic.
pub fn verify_ed25519(public_key: &[u8], payload: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    let pk_bytes: [u8; 32] = public_key.try_into().unwrap();
    let sig_bytes: [u8; 64] = signature.try_into().unwrap();

    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(payload, &sig).is_ok()
}

/// No-op signer for backward compatibility during incremental migration.
/// Signs produce empty signatures. Verify always returns true.
/// ONLY for tests and dev-mode — never in production.
/// Production code must use Ed25519Signer or CoreIpcSigner.
#[cfg(debug_assertions)]
pub struct NoopSigner;

#[cfg(debug_assertions)]
impl Signer for NoopSigner {
    fn sign(&self, _payload: &[u8]) -> Vec<u8> {
        Vec::new()
    }

    fn verify(&self, _public_key: &[u8], _payload: &[u8], _signature: &[u8]) -> bool {
        true
    }

    fn public_key(&self) -> Vec<u8> {
        vec![0u8; 32]
    }
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let signer = Ed25519Signer::from_node_index(42);
        let payload = b"test payload";
        let sig = signer.sign(payload);

        assert_eq!(sig.len(), 64);
        assert!(signer.verify(&signer.public_key(), payload, &sig));
    }

    #[test]
    fn ed25519_wrong_payload_fails() {
        let signer = Ed25519Signer::from_node_index(42);
        let sig = signer.sign(b"correct payload");

        assert!(!signer.verify(&signer.public_key(), b"wrong payload", &sig));
    }

    #[test]
    fn ed25519_wrong_key_fails() {
        let signer1 = Ed25519Signer::from_node_index(1);
        let signer2 = Ed25519Signer::from_node_index(2);
        let payload = b"test";
        let sig = signer1.sign(payload);

        // Verify with wrong public key
        assert!(signer2.verify(&signer1.public_key(), payload, &sig));
        // Correct key works
        assert!(signer1.verify(&signer1.public_key(), payload, &sig));
        // Wrong key fails
        assert!(!signer2.verify(&signer2.public_key(), payload, &sig));
    }

    #[test]
    fn ed25519_deterministic_from_index() {
        let s1 = Ed25519Signer::from_node_index(7);
        let s2 = Ed25519Signer::from_node_index(7);
        assert_eq!(s1.public_key_bytes(), s2.public_key_bytes());

        let s3 = Ed25519Signer::from_node_index(8);
        assert_ne!(s1.public_key_bytes(), s3.public_key_bytes());
    }

    #[test]
    fn tick_payload_canonical() {
        let tick = TickMessage {
            number: 100,
            upstream_pk: [1u8; 32],
            payload: [2u8; 32].to_vec(),
            signature: vec![],
            prev_sig: vec![],
            grandparent_pk: None,
            timestamp_ms: 0,
            available_slots: vec![],
            downstream_approvals: 2,
            subtree_d_available: 0,
            oods_tardis: Vec::new(),
            child_pks: Vec::new(),
            gp_commitment: None,
        };
        let p1 = tick_sign_payload(&tick);
        let p2 = tick_sign_payload(&tick);
        assert_eq!(p1, p2); // deterministic
        assert!(!p1.is_empty());
    }

    #[test]
    fn noop_signer_always_passes() {
        let signer = NoopSigner;
        assert!(signer.verify(&[0u8; 32], b"anything", &[]));
        assert_eq!(signer.sign(b"anything"), Vec::<u8>::new());
    }

    // §7.6 Phase 2: the receiver must recompute the GRANDPARENT's commitment from the
    // carried gp_commitment fields and get EXACTLY the digest the grandparent signed —
    // otherwise prev_sig verification (and the whole lineage check) can never pass.
    #[test]
    fn gp_commitment_reconstruction_matches_the_grandparents_commitment() {
        // A grandparent's own tick.
        let gp_tick = TickMessage {
            number: 500,
            upstream_pk: [7u8; 32],
            payload: vec![9, 9, 9],
            signature: vec![],
            prev_sig: vec![3u8; 8],
            grandparent_pk: Some([6u8; 32]),
            timestamp_ms: 500_000,
            available_slots: vec![],
            downstream_approvals: 2,
            subtree_d_available: 0,
            oods_tardis: Vec::new(),
            child_pks: vec![[42u8; 32], [43u8; 32]], // the grandparent's children
            gp_commitment: None,
        };
        let gp_commit = tick_commitment(&gp_tick);

        // What a forwarder carries about that grandparent (upstream_pk == grandparent_pk).
        let carried = GpCommitment {
            number: gp_tick.number,
            timestamp_ms: gp_tick.timestamp_ms,
            payload: gp_tick.payload.clone(),
            downstream_approvals: gp_tick.downstream_approvals,
            prev_sig: gp_tick.prev_sig.clone(),
            child_pks: gp_tick.child_pks.clone(),
            oods_hash: oods_tardis_hash(&gp_tick.oods_tardis),
        };
        let reconstructed = tick_commitment_fields(
            carried.number, carried.timestamp_ms, &gp_tick.upstream_pk, &carried.payload,
            carried.downstream_approvals, &carried.prev_sig, &carried.child_pks, &carried.oods_hash,
        );
        assert_eq!(reconstructed, gp_commit, "reconstructed gp commitment must equal what gp signed");

        // Tamper any carried field → digest diverges (so a forged lineage can't verify).
        let mut bad = carried.clone();
        bad.number += 1;
        let tampered = tick_commitment_fields(
            bad.number, bad.timestamp_ms, &gp_tick.upstream_pk, &bad.payload,
            bad.downstream_approvals, &bad.prev_sig, &bad.child_pks, &bad.oods_hash,
        );
        assert_ne!(tampered, gp_commit, "tampering must change the digest");
    }
}
