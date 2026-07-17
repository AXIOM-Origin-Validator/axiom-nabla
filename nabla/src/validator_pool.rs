// AXIOM Nabla — Validator Pool registration handler + storage (YP §19.6)
//
// Operator-driven (per-validator dashboard at :7700-7709 / Lambda admin).
// Wallet SDK is NOT a consumer — wallet users have no business binding a
// validator's fee pool.
//
// What this module does:
//   - Holds the per-Nabla `validator_pool` map (validator_id → linkage)
//   - Verifies RegisterValidatorPoolRequest (SPHINCS+ sig + linkage_epoch
//     monotonicity + freshness)
//   - Serves QueryValidatorPoolRequest
//
// What it does NOT do:
//   - Make withdrawal decisions (that's Lambda's `process_validator_withdrawal`
//     in Step 8.3)
//   - Track earnings (those live in SMT `txid_records` / `validator_earnings`)
//   - DEED-redirect for unregistered-validator earnings (deferred per
//     2026-06-02 design discussion — TODO(DEED-redirect))

use std::collections::HashMap;

use crate::types::{NablaError, WalletId};
use axiom_core_logic::wire_client::{
    QueryValidatorPoolRequest, QueryValidatorPoolResponse,
    RegisterValidatorPoolRequest, RegisterValidatorPoolResponse,
};

/// Maximum drift between the validator's claimed `tick` and Nabla's
/// current virtual tick. ±5 ticks = ~25 seconds at the default 5-second
/// tick. Wide enough to absorb clock skew and queueing; tight enough
/// that an attacker can't bank an SPHINCS+ signature for future use.
pub const POOL_LINK_FRESHNESS_TICKS: u64 = 5;

/// Count Ed25519 signatures over `payload` that verify under distinct
/// validator_pks. Used by `process_mark_claimed` to enforce the
/// k-floor + distinct-validator rule (same shape as registration step 5).
///
/// Returns the count of distinct valid signatures. Caller compares to
/// the desired k floor (3 by current protocol).
fn count_distinct_valid_lambda_sigs(
    sigs: &[axiom_core_logic::nabla_wire::K3WitnessSig],
    payload: &[u8; 32],
) -> usize {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    use std::collections::BTreeSet;
    let mut seen_pks: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut valid = 0;
    for ws in sigs {
        // Step 5 uses `signature` field; we use the same here since
        // Lambda's existing sign primitive over a 32-byte hash.
        if ws.signature.len() != 64 {
            continue;
        }
        // K3WitnessSig.validator_pk is the 32-byte Ed25519 pk
        // (post Step 5 K3WitnessSig refactor).
        if !seen_pks.insert(ws.validator_pk) {
            continue; // duplicate sig from same validator
        }
        let Ok(vk) = VerifyingKey::from_bytes(&ws.validator_pk) else { continue };
        let sig_bytes: [u8; 64] = ws.signature.as_slice()
            .try_into().expect("len == 64 checked above");
        let sig = Signature::from_bytes(&sig_bytes);
        if vk.verify(payload, &sig).is_ok() {
            valid += 1;
        }
    }
    valid
}

/// In-memory storage for validator pool linkages. Persisted via
/// snapshot (Step 8.1 follow-up — snapshot extension lands when first
/// real linkage is recorded; pre-mainnet there is none yet).
#[derive(Debug, Default, Clone)]
pub struct ValidatorPoolStore {
    /// validator_id → (linked_wallet_id, linkage_epoch, registered_at_tick).
    entries: HashMap<[u8; 32], (WalletId, u64, u64)>,
    /// YP §19.6 Step 8.3.B — validator_id → highest tick whose earnings
    /// have been withdrawn. Future earnings queries treat this as a
    /// floor (`since_tick = max(requested_since, last_claimed_tick)`).
    /// Advanced ONLY by `process_mark_claimed` after k-Lambda sig
    /// verification; replay-protected by strict-greater check.
    last_claimed_tick: HashMap<[u8; 32], u64>,
}

impl ValidatorPoolStore {
    pub fn new() -> Self { Self::default() }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Look up the current linkage for a validator.
    /// Returns (linked_wallet_id, linkage_epoch, registered_at_tick).
    pub fn get(&self, validator_id: &[u8; 32]) -> Option<(WalletId, u64, u64)> {
        self.entries.get(validator_id).copied()
    }

    /// Process a RegisterValidatorPoolRequest. Performs full validation;
    /// on success, persists the linkage and returns `"REGISTERED"` (first
    /// time) or `"RELINKED"` (epoch-bump).
    pub fn process_register(
        &mut self,
        req: &RegisterValidatorPoolRequest,
        current_tick: u64,
    ) -> Result<RegisterValidatorPoolResponse, NablaError> {
        // 1. Freshness — replay-protect by clamping the signed tick to
        //    a narrow window around the current Nabla tick.
        if current_tick.abs_diff(req.tick) > POOL_LINK_FRESHNESS_TICKS {
            return Ok(self.rejected(
                req, "REJECTED_STALE_TICK", current_tick,
            ));
        }

        // 2. Identity binding — validator_id MUST equal BLAKE3(sphincs_pk).
        //    Closes the trivial spoof where an attacker forges a binding
        //    for someone else's validator_id.
        let computed_id: [u8; 32] = *blake3::hash(&req.sphincs_pk).as_bytes();
        if computed_id != req.validator_id {
            log::warn!(
                "[validator_pool] register rejected — validator_id mismatch \
                 (claimed={:02x}{:02x}…, derived={:02x}{:02x}…)",
                req.validator_id[0], req.validator_id[1],
                computed_id[0], computed_id[1],
            );
            return Ok(self.rejected(
                req, "REJECTED_ID_MISMATCH", current_tick,
            ));
        }

        // 3. Linkage epoch monotonicity — strictly greater than stored.
        //    A re-link signature can't be replayed to revert to an older
        //    linkage; even at the same epoch, the registration is rejected
        //    (operators bump on every re-link).
        if let Some((_, stored_epoch, _)) = self.entries.get(&req.validator_id) {
            if req.linkage_epoch <= *stored_epoch {
                log::warn!(
                    "[validator_pool] register rejected — non-monotonic epoch \
                     (stored={}, requested={})",
                    stored_epoch, req.linkage_epoch,
                );
                return Ok(self.rejected(
                    req, "REJECTED_EPOCH", current_tick,
                ));
            }
        }

        // 4. SPHINCS+ signature verifies over the canonical payload.
        //    Done last because SPHINCS+ verification is the most expensive
        //    step — runs only after cheaper checks pass.
        let payload = axiom_core_logic::compute::compute_validator_pool_link_payload(
            &req.validator_id, &req.linked_wallet_id,
            req.linkage_epoch, req.tick,
        );
        if axiom_core_logic::verify::verify_sphincs(
            &req.sphincs_pk, &payload, &req.sphincs_sig,
        ).is_err() {
            log::warn!(
                "[validator_pool] register rejected — bad SPHINCS+ signature",
            );
            return Ok(self.rejected(
                req, "REJECTED_SIG", current_tick,
            ));
        }

        // All checks passed — persist.
        let status = if self.entries.contains_key(&req.validator_id) {
            "RELINKED"
        } else {
            "REGISTERED"
        };
        self.entries.insert(
            req.validator_id,
            (req.linked_wallet_id, req.linkage_epoch, current_tick),
        );
        log::info!(
            "[validator_pool] {} — validator_id={:02x}{:02x}… → wallet={:02x}{:02x}… \
             (epoch={}, tick={})",
            status,
            req.validator_id[0], req.validator_id[1],
            req.linked_wallet_id[0], req.linked_wallet_id[1],
            req.linkage_epoch, current_tick,
        );
        Ok(RegisterValidatorPoolResponse {
            status: status.to_string(),
            validator_id: req.validator_id,
            stored_linked_wallet_id: req.linked_wallet_id,
            stored_linkage_epoch: req.linkage_epoch,
            stored_at_tick: current_tick,
        })
    }

    /// YP §19.6 Step 8.3.B — current `last_claimed_tick` for the
    /// validator. Returns 0 if no withdrawal has ever been claimed.
    pub fn last_claimed_tick(&self, validator_id: &[u8; 32]) -> u64 {
        self.last_claimed_tick.get(validator_id).copied().unwrap_or(0)
    }

    /// YP §19.6 Step 8.3.B — process a MarkValidatorEarningsClaimedRequest.
    ///
    /// Lambda sends this after a withdrawal round finalises. Nabla:
    ///   1. Verifies the claim payload was signed by ≥3 DISTINCT
    ///      Lambda Ed25519 keys (matches the existing k-floor pattern).
    ///   2. Asserts strict monotonic advance: stored tick MUST be
    ///      strictly less than the requested `claimed_through_tick`
    ///      (replay protection — an old claim can't be re-submitted).
    ///   3. Updates `last_claimed_tick`.
    ///
    /// Returns the new stored tick on success, or the unchanged stored
    /// tick + rejection status on failure.
    pub fn process_mark_claimed(
        &mut self,
        req: &axiom_core_logic::wire_client::MarkValidatorEarningsClaimedRequest,
    ) -> axiom_core_logic::wire_client::MarkValidatorEarningsClaimedResponse {
        let stored = self.last_claimed_tick(&req.validator_id);

        // (1) k-floor + distinct-validator sig check.
        let payload = axiom_core_logic::compute::compute_validator_claim_payload(
            &req.validator_id, req.claimed_through_tick,
        );
        let valid_count = count_distinct_valid_lambda_sigs(
            &req.lambda_signatures, &payload,
        );
        if valid_count < 3 {
            log::warn!(
                "[validator_pool] mark_claimed rejected — only {} of {} sigs valid",
                valid_count, req.lambda_signatures.len(),
            );
            return axiom_core_logic::wire_client::MarkValidatorEarningsClaimedResponse {
                status: "REJECTED_SIG".to_string(),
                validator_id: req.validator_id,
                stored_last_claimed_tick: stored,
            };
        }

        // (2) Strict monotonic advance.
        if req.claimed_through_tick <= stored {
            log::warn!(
                "[validator_pool] mark_claimed rejected — replay/non-monotonic \
                 (stored={}, requested={})",
                stored, req.claimed_through_tick,
            );
            return axiom_core_logic::wire_client::MarkValidatorEarningsClaimedResponse {
                status: "REJECTED_REPLAY".to_string(),
                validator_id: req.validator_id,
                stored_last_claimed_tick: stored,
            };
        }

        // (3) Persist.
        self.last_claimed_tick.insert(req.validator_id, req.claimed_through_tick);
        log::info!(
            "[validator_pool] CLAIMED — validator_id={:02x}{:02x}… advanced \
             to tick {} (was {})",
            req.validator_id[0], req.validator_id[1],
            req.claimed_through_tick, stored,
        );
        axiom_core_logic::wire_client::MarkValidatorEarningsClaimedResponse {
            status: "CLAIMED".to_string(),
            validator_id: req.validator_id,
            stored_last_claimed_tick: req.claimed_through_tick,
        }
    }

    /// Process a QueryValidatorPoolRequest. Always succeeds — `registered`
    /// flag distinguishes hit/miss.
    pub fn process_query(
        &self,
        req: &QueryValidatorPoolRequest,
    ) -> QueryValidatorPoolResponse {
        match self.entries.get(&req.validator_id) {
            Some((wid, epoch, tick)) => QueryValidatorPoolResponse {
                validator_id: req.validator_id,
                registered: true,
                linked_wallet_id: *wid,
                linkage_epoch: *epoch,
                registered_at_tick: *tick,
            },
            None => QueryValidatorPoolResponse {
                validator_id: req.validator_id,
                registered: false,
                linked_wallet_id: [0u8; 32],
                linkage_epoch: 0,
                registered_at_tick: 0,
            },
        }
    }

    /// Internal: build a rejection response with the current stored
    /// linkage (if any) so the operator dashboard can show the diff
    /// between what the operator just tried and what's on file.
    fn rejected(
        &self,
        req: &RegisterValidatorPoolRequest,
        status: &str,
        current_tick: u64,
    ) -> RegisterValidatorPoolResponse {
        let (stored_wid, stored_epoch, stored_at) = self.entries.get(&req.validator_id)
            .copied()
            .unwrap_or(([0u8; 32], 0, 0));
        RegisterValidatorPoolResponse {
            status: status.to_string(),
            validator_id: req.validator_id,
            stored_linked_wallet_id: stored_wid,
            stored_linkage_epoch: stored_epoch,
            stored_at_tick: if stored_at > 0 { stored_at } else { current_tick },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_core_logic::wire_client::RegisterValidatorPoolRequest;

    /// Generate a SPHINCS+ keypair for tests. fips205's `try_keygen`
    /// is non-deterministic but that's fine — each test gets a fresh
    /// keypair, and the validator_id is derived from the pk.
    fn make_keypair(_seed: u8) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes;
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("sphincs keygen");
        let pk_bytes = pk.into_bytes().to_vec();
        let sk_bytes = sk.into_bytes().to_vec();
        let validator_id: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();
        (pk_bytes, sk_bytes, validator_id)
    }

    fn signed_request(
        sk: &[u8],
        pk: &[u8],
        validator_id: [u8; 32],
        linked_wallet_id: [u8; 32],
        linkage_epoch: u64,
        tick: u64,
    ) -> RegisterValidatorPoolRequest {
        let payload = axiom_core_logic::compute::compute_validator_pool_link_payload(
            &validator_id, &linked_wallet_id, linkage_epoch, tick,
        );
        let sig = axiom_core_logic::compute::sign_sphincs(sk, &payload)
            .expect("sphincs sign");
        RegisterValidatorPoolRequest {
            validator_id,
            linked_wallet_id,
            sphincs_pk: pk.to_vec(),
            sphincs_sig: sig,
            linkage_epoch,
            tick,
        }
    }

    #[test]
    fn first_time_registration_succeeds_and_stores() {
        let (pk, sk, vid) = make_keypair(0x01);
        let wallet = [0xAA; 32];
        let mut store = ValidatorPoolStore::new();

        let req = signed_request(&sk, &pk, vid, wallet, 1, 100);
        let resp = store.process_register(&req, 100).unwrap();
        assert_eq!(resp.status, "REGISTERED");
        assert_eq!(resp.stored_linked_wallet_id, wallet);
        assert_eq!(resp.stored_linkage_epoch, 1);
        assert_eq!(store.len(), 1);

        let (got_w, got_e, got_t) = store.get(&vid).unwrap();
        assert_eq!(got_w, wallet);
        assert_eq!(got_e, 1);
        assert_eq!(got_t, 100);
    }

    #[test]
    fn relink_with_higher_epoch_succeeds() {
        let (pk, sk, vid) = make_keypair(0x02);
        let mut store = ValidatorPoolStore::new();
        let w1 = [0x11; 32];
        let w2 = [0x22; 32];

        store.process_register(
            &signed_request(&sk, &pk, vid, w1, 1, 100), 100,
        ).unwrap();
        let resp = store.process_register(
            &signed_request(&sk, &pk, vid, w2, 2, 200), 200,
        ).unwrap();
        assert_eq!(resp.status, "RELINKED");
        let (got_w, got_e, _) = store.get(&vid).unwrap();
        assert_eq!(got_w, w2);
        assert_eq!(got_e, 2);
    }

    #[test]
    fn relink_with_equal_or_lower_epoch_rejects() {
        let (pk, sk, vid) = make_keypair(0x03);
        let mut store = ValidatorPoolStore::new();
        let w1 = [0x11; 32];

        store.process_register(
            &signed_request(&sk, &pk, vid, w1, 5, 100), 100,
        ).unwrap();
        // Same epoch
        let resp = store.process_register(
            &signed_request(&sk, &pk, vid, w1, 5, 100), 100,
        ).unwrap();
        assert_eq!(resp.status, "REJECTED_EPOCH");
        // Lower epoch
        let resp = store.process_register(
            &signed_request(&sk, &pk, vid, w1, 3, 100), 100,
        ).unwrap();
        assert_eq!(resp.status, "REJECTED_EPOCH");
    }

    #[test]
    fn bad_signature_rejects() {
        let (pk, sk, vid) = make_keypair(0x04);
        let mut store = ValidatorPoolStore::new();
        let w = [0x11; 32];

        let mut req = signed_request(&sk, &pk, vid, w, 1, 100);
        // Corrupt the signature
        req.sphincs_sig[0] ^= 0x01;
        let resp = store.process_register(&req, 100).unwrap();
        assert_eq!(resp.status, "REJECTED_SIG");
        assert!(store.is_empty(), "rejected register must not persist");
    }

    #[test]
    fn validator_id_pk_mismatch_rejects() {
        let (pk, sk, _vid) = make_keypair(0x05);
        let bogus_vid = [0xFF; 32]; // not BLAKE3(pk)
        let mut store = ValidatorPoolStore::new();
        let w = [0x11; 32];

        // Sign with the real key but claim a different validator_id.
        let payload = axiom_core_logic::compute::compute_validator_pool_link_payload(
            &bogus_vid, &w, 1, 100,
        );
        let sig = axiom_core_logic::compute::sign_sphincs(&sk, &payload)
            .expect("sphincs sign");
        let req = RegisterValidatorPoolRequest {
            validator_id: bogus_vid,
            linked_wallet_id: w,
            sphincs_pk: pk,
            sphincs_sig: sig,
            linkage_epoch: 1,
            tick: 100,
        };
        let resp = store.process_register(&req, 100).unwrap();
        assert_eq!(resp.status, "REJECTED_ID_MISMATCH");
    }

    #[test]
    fn stale_tick_rejects() {
        let (pk, sk, vid) = make_keypair(0x06);
        let mut store = ValidatorPoolStore::new();
        let w = [0x11; 32];

        // Signed at tick 100, Nabla's now at 200 — outside the
        // POOL_LINK_FRESHNESS_TICKS=5 window.
        let req = signed_request(&sk, &pk, vid, w, 1, 100);
        let resp = store.process_register(&req, 200).unwrap();
        assert_eq!(resp.status, "REJECTED_STALE_TICK");
    }

    #[test]
    fn query_returns_registered_false_when_no_linkage() {
        let store = ValidatorPoolStore::new();
        let resp = store.process_query(&QueryValidatorPoolRequest {
            validator_id: [0xCC; 32],
        });
        assert!(!resp.registered);
        assert_eq!(resp.linked_wallet_id, [0u8; 32]);
        assert_eq!(resp.linkage_epoch, 0);
    }

    #[test]
    fn query_returns_current_linkage_after_register() {
        let (pk, sk, vid) = make_keypair(0x07);
        let mut store = ValidatorPoolStore::new();
        let w = [0x11; 32];

        store.process_register(
            &signed_request(&sk, &pk, vid, w, 7, 100), 100,
        ).unwrap();
        let resp = store.process_query(&QueryValidatorPoolRequest { validator_id: vid });
        assert!(resp.registered);
        assert_eq!(resp.linked_wallet_id, w);
        assert_eq!(resp.linkage_epoch, 7);
        assert_eq!(resp.registered_at_tick, 100);
    }

    // ───────────────────────────────────────────────────────────────────
    // YP §19.6 Step 8.3.B — mark_claimed (last_claimed_tick advance)
    // ───────────────────────────────────────────────────────────────────

    use axiom_core_logic::wire_client::MarkValidatorEarningsClaimedRequest;
    use ed25519_dalek::Signer as Ed25519Signer;

    /// Build k Lambda Ed25519 signatures over the canonical claim
    /// payload. `n_distinct` is how many DISTINCT validator_pks to use.
    /// `n_total` is the total signatures emitted (some may duplicate
    /// if n_total > n_distinct).
    fn lambda_claim_sigs(
        validator_id: &[u8; 32],
        claimed_through_tick: u64,
        n_distinct: usize,
        n_total: usize,
    ) -> Vec<axiom_core_logic::nabla_wire::K3WitnessSig> {
        let payload = axiom_core_logic::compute::compute_validator_claim_payload(
            validator_id, claimed_through_tick,
        );
        let lambdas: Vec<ed25519_dalek::SigningKey> = (0..n_distinct.max(1))
            .map(|i| ed25519_dalek::SigningKey::from_bytes(&[(i as u8) + 1; 32]))
            .collect();
        (0..n_total).map(|i| {
            let sk = &lambdas[i % lambdas.len()];
            let sig = sk.sign(&payload);
            axiom_core_logic::nabla_wire::K3WitnessSig {
                validator_pk: sk.verifying_key().to_bytes(),
                signature: sig.to_bytes().to_vec(),
                execution_proof: vec![],
                proof_type: 0,
                receipt_commitment_sig: vec![],
                validator_id: [0u8; 32],
                slot_amount: 0,
            }
        }).collect()
    }

    #[test]
    fn mark_claimed_advances_last_claimed_tick_on_3_valid_sigs() {
        let mut store = ValidatorPoolStore::new();
        let vid = [0x11; 32];
        let req = MarkValidatorEarningsClaimedRequest {
            validator_id: vid,
            claimed_through_tick: 100,
            lambda_signatures: lambda_claim_sigs(&vid, 100, 3, 3),
        };
        let resp = store.process_mark_claimed(&req);
        assert_eq!(resp.status, "CLAIMED");
        assert_eq!(resp.stored_last_claimed_tick, 100);
        assert_eq!(store.last_claimed_tick(&vid), 100);
    }

    #[test]
    fn mark_claimed_rejects_non_monotonic_replay() {
        let mut store = ValidatorPoolStore::new();
        let vid = [0x22; 32];

        // First claim succeeds.
        store.process_mark_claimed(&MarkValidatorEarningsClaimedRequest {
            validator_id: vid,
            claimed_through_tick: 100,
            lambda_signatures: lambda_claim_sigs(&vid, 100, 3, 3),
        });
        // Replay at SAME tick → REJECTED_REPLAY.
        let resp = store.process_mark_claimed(&MarkValidatorEarningsClaimedRequest {
            validator_id: vid,
            claimed_through_tick: 100,
            lambda_signatures: lambda_claim_sigs(&vid, 100, 3, 3),
        });
        assert_eq!(resp.status, "REJECTED_REPLAY");
        assert_eq!(store.last_claimed_tick(&vid), 100);
        // LOWER tick → also REJECTED.
        let resp = store.process_mark_claimed(&MarkValidatorEarningsClaimedRequest {
            validator_id: vid,
            claimed_through_tick: 50,
            lambda_signatures: lambda_claim_sigs(&vid, 50, 3, 3),
        });
        assert_eq!(resp.status, "REJECTED_REPLAY");
        // Strictly greater → succeeds.
        let resp = store.process_mark_claimed(&MarkValidatorEarningsClaimedRequest {
            validator_id: vid,
            claimed_through_tick: 200,
            lambda_signatures: lambda_claim_sigs(&vid, 200, 3, 3),
        });
        assert_eq!(resp.status, "CLAIMED");
        assert_eq!(store.last_claimed_tick(&vid), 200);
    }

    #[test]
    fn mark_claimed_rejects_below_k_floor() {
        let mut store = ValidatorPoolStore::new();
        let vid = [0x33; 32];
        // Only 2 distinct Lambda sigs (below k=3 floor).
        let resp = store.process_mark_claimed(&MarkValidatorEarningsClaimedRequest {
            validator_id: vid,
            claimed_through_tick: 100,
            lambda_signatures: lambda_claim_sigs(&vid, 100, 2, 2),
        });
        assert_eq!(resp.status, "REJECTED_SIG");
        assert_eq!(store.last_claimed_tick(&vid), 0);
    }

    #[test]
    fn mark_claimed_rejects_duplicate_same_validator_sigs() {
        let mut store = ValidatorPoolStore::new();
        let vid = [0x44; 32];
        // 3 total sigs but only 1 distinct validator (3 copies of same).
        let resp = store.process_mark_claimed(&MarkValidatorEarningsClaimedRequest {
            validator_id: vid,
            claimed_through_tick: 100,
            lambda_signatures: lambda_claim_sigs(&vid, 100, 1, 3),
        });
        // count_distinct_valid_lambda_sigs counts 1 distinct → REJECTED_SIG.
        assert_eq!(resp.status, "REJECTED_SIG");
    }

    #[test]
    fn mark_claimed_rejects_bad_signature() {
        let mut store = ValidatorPoolStore::new();
        let vid = [0x55; 32];
        // Build valid sigs, then corrupt one.
        let mut sigs = lambda_claim_sigs(&vid, 100, 3, 3);
        sigs[0].signature[0] ^= 0x01;
        let resp = store.process_mark_claimed(&MarkValidatorEarningsClaimedRequest {
            validator_id: vid,
            claimed_through_tick: 100,
            lambda_signatures: sigs,
        });
        // 1 corrupt + 2 valid = 2 distinct valid → below k=3 floor.
        assert_eq!(resp.status, "REJECTED_SIG");
    }

    #[test]
    fn last_claimed_tick_defaults_to_zero() {
        let store = ValidatorPoolStore::new();
        assert_eq!(store.last_claimed_tick(&[0xAB; 32]), 0);
    }
}
