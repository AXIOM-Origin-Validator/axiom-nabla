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
    // KI#48 follow-up: subtree_hash + siblings are now covered — pre-fix the
    // signature bound only prefix/root/tick/pk, so the actual audit ANSWER
    // was unsigned and could be tampered in flight without detection.
    let mut buf =
        Vec::with_capacity(response.prefix.len() + 32 + 32 + 8 + 32 + response.siblings.len() * 32);
    buf.extend_from_slice(&response.prefix);
    buf.extend_from_slice(&response.subtree_hash);
    buf.extend_from_slice(&response.root_hash);
    buf.extend_from_slice(&response.response_tick.to_le_bytes());
    buf.extend_from_slice(&response.responder_pk);
    for sib in &response.siblings {
        buf.extend_from_slice(sib);
    }
    buf
}

/// Verify that a QuestionableAlert's evidence actually PROVES the accusation.
///
/// The alert's own signature proves only WHO accused. This checks the suspect's
/// own signed statements, so a receiver never has to trust the reporter.
///
/// `suspect_key` is the suspect's NBC-anchored Ed25519 key. Returns the reason
/// it proves the accusation, or `None` if it proves nothing.
pub fn verify_questionable_evidence(
    ev: &QuestionableEvidence,
    suspect_pk: &[u8; 32],
    suspect_key: &[u8],
    verify: &dyn Fn(&[u8], &[u8], &[u8]) -> bool,
) -> Option<&'static str> {
    // The audit answer must be signed BY THE SUSPECT — otherwise the reporter
    // could have fabricated it.
    if ev.audit_response.responder_pk != *suspect_pk {
        return None;
    }
    if !verify(
        suspect_key,
        &audit_response_sign_payload(&ev.audit_response),
        &ev.audit_response.signature,
    ) {
        return None;
    }

    match &ev.advertised_root {
        // Claim: SELF-CONTRADICTION. Needs the suspect's signed advertisement
        // for the same tick, and the two roots must actually differ.
        Some(adv) => {
            if !verify(
                suspect_key,
                &tickhash_sign_payload(ev.audit_response.response_tick, adv, suspect_pk),
                &ev.advertised_sig,
            ) {
                return None;
            }
            if *adv == ev.audit_response.root_hash {
                return None; // no contradiction — the accusation is empty
            }
            Some("self_contradiction")
        }
        // Claim: the answer refutes itself. Re-run the merkle fold; if it
        // reconstructs, there is no defect and the accusation is empty.
        None => {
            let ok = crate::smt::SparseMerkleTree::verify_subtree_proof(
                &ev.audit_response.root_hash,
                &ev.audit_response.prefix,
                &ev.audit_response.subtree_hash,
                &ev.audit_response.siblings,
            );
            if ok { None } else { Some("proof_does_not_reconstruct") }
        }
    }
}

/// Commitment over a `QuestionableEvidence`, for `QuestionableAlert.evidence_hash`.
///
/// Binds the suspect's two signed statements so the alert signature covers the
/// proof, not just the accusation. Domain-tagged.
pub fn evidence_commitment(ev: &QuestionableEvidence) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_QALERT_EVIDENCE_v1");
    h.update(&audit_response_sign_payload(&ev.audit_response));
    h.update(&ev.audit_response.signature);
    match &ev.advertised_root {
        Some(r) => {
            h.update(&[1u8]);
            h.update(r);
        }
        None => {
            h.update(&[0u8]);
        }
    }
    h.update(&(ev.advertised_sig.len() as u32).to_le_bytes());
    h.update(&ev.advertised_sig);
    *h.finalize().as_bytes()
}

/// Canonical payload for a QuestionableAlert signature.
/// Canonical payload for a `GossipMessage::TickHash` signature.
///
/// Binds the advertisement to (tick, root, advertiser) so it cannot be replayed
/// onto another tick or attributed to another node. Domain-tagged so a TickHash
/// signature can never be mistaken for a tick or alert signature.
pub fn tickhash_sign_payload(tick: u64, root_hash: &[u8; 32], node_pk: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + 8 + 32 + 32);
    buf.extend_from_slice(b"AXIOM_TICKHASH_v1");
    buf.extend_from_slice(&tick.to_le_bytes());
    buf.extend_from_slice(root_hash);
    buf.extend_from_slice(node_pk);
    buf
}

pub fn alert_sign_payload(alert: &QuestionableAlert) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 32 + 8 + 32);
    buf.extend_from_slice(&alert.suspect_pk);
    buf.extend_from_slice(&alert.reporter_pk);
    buf.extend_from_slice(&alert.tick.to_le_bytes());
    buf.extend_from_slice(&alert.evidence_hash);
    buf
}

/// Canonical payload for a `GossipMessage::Alert`'s per-hop signature
/// (`AXIOM_DESIGN_NablaPoolCaps.md` §5.6.4 step 1, KI#72).
///
/// §5.6.4 requires the receiver to "verify `alert.intermediate_emitter` == P
/// (NBC-bound TCP identity)", and the §5.6.5 dual-uniqueness argument rests
/// entirely on it — A1/A6/A7 are each defended by "intermediate = self,
/// TCP-source-verified". No such transport identity exists: `Envelope` carries
/// only a `SocketAddr` and there is no NBC handshake, so the field was whatever
/// the sender wrote and the check compared it to itself.
///
/// Rather than build a connection handshake, this reuses the KI#18/19/20
/// pattern already used for ticks, audit responses and approvals: **nothing new
/// travels except a 64-byte signature.** The forwarding node signs this payload
/// with its NBC-bound Ed25519 key; the receiver looks that key up in its OWN
/// `verified_nbcs[intermediate_emitter]` (warm from the KI#32 snapshot) and
/// verifies. The NBC itself is never sent.
///
/// Binds every field a forwarder could otherwise tamper with:
///   - `intermediate_emitter` — so a peer cannot claim to be someone else
///     (§5.6.7 A6); the signature only verifies against the named node's key.
///   - `origin_emitter` + `accused` + `alert_type` — the accusation itself.
///   - a hash of `evidence` — so a forwarder cannot substitute evidence
///     (§3.5.2 evidence-pool binding) without invalidating the signature.
///   - `emitted_at_tick` — pins the 10-tick dedup/consensus window.
pub fn pool_alert_sign_payload(
    alert_type: u8,
    accused: &[u8; 32],
    evidence: &[u8],
    origin_emitter: &[u8; 32],
    intermediate_emitter: &[u8; 32],
    emitted_at_tick: u64,
) -> Vec<u8> {
    let evidence_hash = blake3::hash(evidence);
    let mut buf = Vec::with_capacity(1 + 32 + 32 + 32 + 32 + 8);
    buf.extend_from_slice(b"AXIOM_POOL_ALERT_v1");
    buf.push(alert_type);
    buf.extend_from_slice(accused);
    buf.extend_from_slice(evidence_hash.as_bytes());
    buf.extend_from_slice(origin_emitter);
    buf.extend_from_slice(intermediate_emitter);
    buf.extend_from_slice(&emitted_at_tick.to_le_bytes());
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
    // KI#191 — the conservation terms are SIGNED. A receiver decides whether a
    // peer is structurally violating from these numbers, so unsigned they would
    // be an attacker's lever on JUDOON's verdict — a new security surface in
    // the middle of the mechanism meant to remove one.
    paid_out: u64,
    topped_up: u64,
    tick: u64,
    sender_node_id: &[u8; 32],
    // BoundedFee pools share the `pool_byte` 0x05, so the `(validator_id,
    // is_dev)` is appended here (and ONLY here) to bind which pool AND which
    // CLASS the sig covers — a sig for one validator's pool or class cannot be
    // replayed onto another. `None` for the singleton pools → their payload is
    // byte-identical to before, so existing Airdrop/Deed signatures keep
    // verifying (same append-suffix discipline as the OODS baseline binding).
    bounded_fee_key: Option<([u8; 32], bool)>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(18 + 1 + 8 + 8 + 8 + 8 + 8 + 32 + 32 + 1);
    buf.extend_from_slice(b"AXIOM_POOL_SYNC_v1");
    buf.push(pool_byte);
    buf.extend_from_slice(&balance.to_le_bytes());
    buf.extend_from_slice(&total_claims.to_le_bytes());
    buf.extend_from_slice(&paid_out.to_le_bytes());
    buf.extend_from_slice(&topped_up.to_le_bytes());
    buf.extend_from_slice(&tick.to_le_bytes());
    buf.extend_from_slice(sender_node_id);
    if let Some((vid, is_dev)) = bounded_fee_key {
        buf.extend_from_slice(&vid);
        buf.push(is_dev as u8);
    }
    buf
}

/// ForkSettlement R50 (wave 4a) / §9o [R59] (W1) — THE canonical payload for
/// every SIGNED AE message: the witness directory's (`VbcRegistrationDigest`
/// request, kind 1 / `VbcRegistrationEntries` reply, kind 2) and record-AE's
/// (`RecordAeAsk`, kind 3 / `RecordAeAnswer`, kind 4 — `record_sync::
/// RECORD_AE_KIND_*`). The PoolSync pattern: the sender signs with its node
/// key; the receiver verifies against the Ed25519 key in `verified_nbcs[from]`.
/// `from`, the per-round `nonce` and the BODY (as `body_hash` —
/// `vbc_directory::have_body_hash` / `entries_body_hash`, `record_sync::
/// ask_body_hash` / `answer_body_hash`) are all inside the signature, and
/// `kind` separates request from reply AND protocol from protocol, so none
/// can be replayed as another. ~~`vbc_directory_ae_sign_payload`~~ — renamed
/// 2026-09-30 when record-AE became its second user (ONE builder, RULE 1). The
/// domain tag keeps its historical bytes `AXIOM_VBC_DIRECTORY_AE` on purpose:
/// changing it would break the directory AE between rolled and unrolled nodes
/// for no security gain (the kind byte is the separator).
pub fn ae_sign_payload(kind: u8, from: &[u8; 32], nonce: u64, body_hash: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(22 + 1 + 32 + 8 + 32);
    buf.extend_from_slice(b"AXIOM_VBC_DIRECTORY_AE");
    buf.push(kind);
    buf.extend_from_slice(from);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(body_hash);
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

/// YP §25 domain table / GUIDE_Nabla §5.6 — the NBC-renewal signing digest:
/// `BLAKE3("AXIOM_NBC_RENEW" ‖ validator_id ‖ request_time_le)`.
///
/// KI#55 (Pattern 1): ONE builder for the requester's signature
/// (`nabla_node.rs::check_nbc_renewal`) and the issuer's verify
/// (`handle_nbc_renewal_request`). They were two inline copies; a drift in
/// either silently refuses every renewal ("renewal signature invalid") until the
/// NBC expires. Guarded by the Python-computed KAT in
/// `tests::ki55_nbc_renew_kat` and the bin's `ki55_anchor` tests.
pub fn nbc_renew_sign_payload(validator_id: &[u8; 32], request_time: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_NBC_RENEW");
    hasher.update(validator_id);
    hasher.update(&request_time.to_le_bytes());
    *hasher.finalize().as_bytes()
}

// (KI#247, owner ruling 2026-10-02: `role_attestation_sign_payload` — the
// `AXIOM_NABLA_ROLE` builder — was DELETED with both of its signers. Nothing in
// the tree verified the signature: a signature nobody checks is a ghost
// (RULE 3). The query reply's `role` remains, unsigned and informational.)

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
/// Domain: BLAKE3("AXIOM_FACT_CONFIRM"
///                || tx_hash
///                || new_state
///                || committed_at_tick.to_le_bytes())
/// where tx_hash = BLAKE3("AXIOM_TXHASH" || old_state || new_state).
///
/// Used by BOTH TCP (registration.rs) and HTTP (nabla_node.rs) paths.
/// Core's matching recompute lives in `core/logic/src/fact.rs::verify_fact_link`.
// Pattern 1 sweep — ONE builder, owned by Core. This function used to
// assemble `AXIOM_TXHASH` and `AXIOM_FACT_CONFIRM` independently of
// `core/logic/src/fact.rs::verify_nabla_confirmation`, which verifies what we
// sign. Re-exported through `registration.rs` because the crypto-boundary
// tripwire forbids a fifth exempt file.
pub use crate::registration::{fact_confirm_payload, fact_tx_hash};

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

    // ── KI#55 KATs — constants computed in Python (`blake3`) from the YP layouts
    // (scratchpad kat.py, ts = 1774070000), NOT from this crate. ──

    /// MUTATION (run 2026-10-02): drop `request_time` from the builder ⇒ red.
    #[test]
    fn ki55_nbc_renew_kat() {
        assert_eq!(hex::encode(super::nbc_renew_sign_payload(&[0xAB; 32], 1774070000)),
            "9b4781dd94490861ac7c9bc91996764ebb635243fa30c96f4e25cd23f5ef86e9");
    }

    /// KI#72 — the per-hop Alert signature must bind WHO is forwarding.
    ///
    /// §5.6.5's dual-uniqueness argument assumes an attacker's alerts always
    /// carry `intermediate = self`. That only holds if a signature for node A
    /// cannot be presented as node B's. The payload therefore binds
    /// `intermediate_emitter`, so the receiver's verify — which uses the key of
    /// the node the packet NAMES — fails for anyone else (§5.6.7 A6).
    #[test]
    fn ki72_alert_payload_binds_the_forwarding_identity() {
        let accused = [0xAA; 32];
        let origin = [0xB0; 32];
        let a = [0x0A; 32];
        let b = [0x0B; 32];
        let ev = b"pool-sync-evidence".to_vec();

        let as_a = pool_alert_sign_payload(1, &accused, &ev, &origin, &a, 100);
        let as_b = pool_alert_sign_payload(1, &accused, &ev, &origin, &b, 100);
        assert_ne!(as_a, as_b,
            "KI#72: the payload MUST depend on intermediate_emitter — otherwise a \
             signature made by one node verifies for another, and a single \
             attacker can supply every 'distinct intermediate' the quorum counts");

        // Same node, same everything → stable (a forwarder can re-sign
        // deterministically, and a replay of OUR OWN hop is caught by dedup,
        // not by signature churn).
        assert_eq!(as_a, pool_alert_sign_payload(1, &accused, &ev, &origin, &a, 100));
    }

    /// The payload must bind the evidence, the accusation and the tick, so a
    /// forwarder cannot swap any of them while keeping a valid signature.
    #[test]
    fn ki72_alert_payload_binds_evidence_accusation_and_tick() {
        let accused = [0xAA; 32];
        let origin = [0xB0; 32];
        let inter = [0x0A; 32];
        let ev = b"real-evidence".to_vec();
        let base = pool_alert_sign_payload(1, &accused, &ev, &origin, &inter, 100);

        assert_ne!(base, pool_alert_sign_payload(1, &accused, b"swapped", &origin, &inter, 100),
            "evidence must be bound (§3.5.2 evidence-pool binding)");
        assert_ne!(base, pool_alert_sign_payload(1, &[0xCC; 32], &ev, &origin, &inter, 100),
            "the accused must be bound");
        assert_ne!(base, pool_alert_sign_payload(1, &accused, &ev, &[0xC0; 32], &inter, 100),
            "origin_emitter must be bound");
        assert_ne!(base, pool_alert_sign_payload(1, &accused, &ev, &origin, &inter, 101),
            "emitted_at_tick must be bound — it pins the 10-tick consensus window");
        assert_ne!(base, pool_alert_sign_payload(2, &accused, &ev, &origin, &inter, 100),
            "alert_type must be bound");
    }
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
