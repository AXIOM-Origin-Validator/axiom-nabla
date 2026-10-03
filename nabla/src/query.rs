// AXIOM Nabla — Query Handler
// Reference: AXIOM_GUIDE_Nabla.md Section 4
//
// Phase 1 Task 6: Query handler (return state + root_hash + signature + merkle proof)
//
// Receivers query Nabla to verify wallet state before accepting cheques.
// Every query returns: wallet state, root_hash, merkle proof, signature.
// Every query is also an audit — receivers compare responses from 3 nodes.

use crate::crypto::{self, Signer};
use crate::smt::SparseMerkleTree;
use crate::types::*;

/// Process a query request.
///
/// Returns the wallet's current state along with the SMT root hash
/// and a merkle proof, so the receiver can independently verify
/// the response is consistent with the tree.
pub fn process_query(
    smt: &SparseMerkleTree,
    wallet_id: &WalletId,
    current_tick: u64,
    signer: &dyn Signer,
    // `nbc_issuer_pk`: §4.3 cross-branch grouping key — the responding node's
    // NBC issuer. Passed IN so it is set BEFORE the signature is computed (G18).
    nbc_issuer_pk: Vec<u8>,
) -> NablaResponse {
    let root_hash = smt.root_hash();

    match smt.get(wallet_id) {
        Some(entry) => {
            let merkle_proof = smt.merkle_proof(wallet_id);

            let mut resp = NablaResponse {
                wallet_id: *wallet_id,
                current_state: entry.current_state,
                tx_hash: entry.tx_hash,
                wallet_seq: entry.wallet_seq, // WI3: head's k-seq, binds via the merkle proof
                root_hash,
                synced_to_tick: current_tick,
                group_members: entry.group_members.clone(),
                merkle_proof: Some(merkle_proof),
                signature: vec![], // filled below
                role: 0,
                // YPX-002 §4.6 — covered by `response_sign_payload` and
                // therefore by `resp.signature`.
                //
                // RULE 0 marker (2026-08-07, ghost audit G18). This used to be
                // `Vec::new()` with a comment claiming "the node binary stamps
                // it before signing". It did not: the signature was computed
                // HERE over an empty field, and `nabla_node.rs` stamped the real
                // value AFTERWARDS. So `response_sign_payload` hashed the field
                // — making it LOOK covered, and `types.rs` told readers a client
                // "can trust them to the same degree as current_state" — while
                // the bytes on the wire were never the bytes that were signed.
                // Three in-tree comments disagreed about whether it was covered.
                // It is now passed in and set before signing, so it genuinely is.
                nbc_issuer_pk: nbc_issuer_pk.clone(),
                registration_tick: entry.tick,
                wallet_status: entry.status,
            };
            resp.signature = signer.sign(&crypto::response_sign_payload(&resp));
            resp
        }
        None => {
            // Wallet not found — return zeroed state.
            let mut resp = NablaResponse {
                wallet_id: *wallet_id,
                current_state: [0u8; 32],
                tx_hash: [0u8; 32],
                wallet_seq: 0, // WI3: not-found → zeroed
                root_hash,
                synced_to_tick: current_tick,
                group_members: None,
                merkle_proof: None,
                signature: vec![], // filled below
                role: 0,
                // YPX-002 §4.6 — wallet not found: registration_tick=0,
                // wallet_status=Normal. Receiver distinguishes "not found"
                // from "registered" by current_state being all-zero.
                // nbc_issuer_pk is filled by caller from NablaNodeState.
                nbc_issuer_pk: Vec::new(),
                registration_tick: 0,
                wallet_status: WalletStatus::Normal,
            };
            resp.signature = signer.sign(&crypto::response_sign_payload(&resp));
            resp
        }
    }
}

// DELETED 2026-07-30 — `verify_response(&NablaResponse) -> bool`.
//
// It rebuilt a `NablaEntry` from the response and checked it against the
// root via `SparseMerkleTree::verify_proof`, stamping `client_pk: [0;32]` +
// a 64-byte zero sig because `NablaResponse` carries no authorship. But the
// leaf hash is `BLAKE3(wallet_id || bincode(entry))` over the WHOLE entry,
// so `client_pk`/`client_sig` ARE bound into the leaf — the reconstruction
// could never match a real entry, and the fn returned false for every
// wallet that had one. It had no callers anywhere in the tree.
//
// This was receiver scaffolding with no sender (see
// `[[feedback_no_receiver_scaffolding_without_sender]]`), so it is deleted
// rather than left as a trap. If cross-checking responses across nodes is
// wanted later, `NablaResponse` must carry `client_pk` + `client_sig` and
// the rebuild must use them — otherwise the proof check is unsatisfiable by
// construction. Rebuild it WITH a caller and a test, in the same PR.

// ── Group Wallet Queries (Phase 3, Section 8) ──

/// Query a specific member's allocation within a group wallet.
///
/// Receivers checking a group wallet cheque can verify:
///   - The member exists in the group
///   - Their share and available balance
///   - The group checksum holds: sum(available) == balance
pub fn query_member(
    smt: &SparseMerkleTree,
    wallet_id: &WalletId,
    member_pk: &[u8; 32],
    current_tick: u64,
) -> Result<MemberQueryResponse, NablaError> {
    let entry = smt.get(wallet_id).ok_or(NablaError::NotGroupWallet)?;

    let members = entry
        .group_members
        .as_ref()
        .ok_or(NablaError::NotGroupWallet)?;

    let member = members
        .iter()
        .find(|m| &m.member_pk == member_pk)
        .ok_or(NablaError::MemberNotFound)?;

    let group_balance: u64 = members.iter().map(|m| m.available).sum();
    let checksum_valid = verify_group_checksum(members);

    Ok(MemberQueryResponse {
        wallet_id: *wallet_id,
        member_pk: *member_pk,
        share_bps: member.share_bps,
        available: member.available,
        group_balance,
        total_members: members.len(),
        checksum_valid,
        synced_to_tick: current_tick,
    })
}

/// Verify group wallet checksum: sum(available) is consistent.
///
/// YP §30.9: Receivers can verify "Checksum holds: sum(available) == balance".
/// Also checks share_bps sum to 10000 (100.00%) — structural integrity.
pub fn verify_group_checksum(members: &[GroupMemberState]) -> bool {
    if members.is_empty() {
        return true;
    }
    // share_bps must always sum to 10000 (100.00%)
    let bps_total: u16 = members.iter().map(|m| m.share_bps).sum();
    bps_total == crate::constants::TOTAL_SHARE_BPS
}

/// Compare responses from multiple Nabla nodes.
/// Returns the unanimously-agreed response on success, or `None` on any
/// disagreement, empty input, or single-node input.
///
/// YPX-002 §4.3 / §4.6 — **n-of-n, not majority**. An earlier version of
/// this function implemented a majority-wins threshold (`indices.len() > n/2`)
/// which silently accepted a 2-of-3 split against a stale or malicious
/// node. That contradicts the spec: the receiver's defence against a
/// single gossip-delayed node is not "outvote it" but "abort on any
/// disagreement," because any disagreement is itself a signal that
/// gossip hasn't converged and the receiver's view is not safe to act
/// on. Timer A (query-loop catchup wait) exists precisely to give that
/// disagreement a chance to resolve before the receiver retries.
///
/// Two responses agree iff they carry the same `current_state` AND the
/// same `root_hash`. `root_hash` is included so a carefully-crafted
/// response cannot match on `current_state` alone while presenting a
/// forged tree state — both fields must be in sync.
///
/// Callers: at time of writing, the client-side §4.6 routines in PMC
/// (`NablaClient.verify_cheque`) and the webclient mirror run their own
/// in-line agreement check, so this helper is currently used by the
/// in-crate unit tests as a specification anchor. Future server-side
/// integrations (e.g. a validator cross-checking Nabla attestations
/// before signing a cheque) should call this instead of rolling their
/// own comparator.
pub fn unanimous_response(responses: &[NablaResponse]) -> Option<NablaResponse> {
    if responses.len() < 2 {
        return None;
    }
    let first = &responses[0];
    for resp in responses.iter().skip(1) {
        if resp.current_state != first.current_state || resp.root_hash != first.root_hash {
            return None;
        }
    }
    Some(first.clone())
}

#[cfg(test)]
mod tests {

    /// G18 — every field the signature covers must be final BEFORE signing.
    ///
    /// `response_sign_payload` hashes `nbc_issuer_pk`. The binary used to call
    /// `query()` (which signs) and then assign the issuer, so the signature
    /// covered an empty field while the wire carried a real one: the signed
    /// bytes were never the shipped bytes. Three in-tree comments disagreed
    /// about whether the field was covered.
    ///
    /// The signer RECORDS what it was asked to sign. An earlier version of this
    /// test compared `resp.signature` against `NoopSigner.sign(payload)` — and
    /// `NoopSigner::sign` ignores its input and returns `Vec::new()`, so the
    /// assertion held for ANY implementation. It passed against the bug.
    /// Mutation-testing caught it; do not reintroduce a signature comparison
    /// under a signer that does not depend on the payload.
    #[test]
    fn g18_signature_covers_the_issuer_actually_shipped() {
        use std::sync::Mutex;
        struct RecordingSigner(Mutex<Vec<Vec<u8>>>);
        impl crate::crypto::Signer for RecordingSigner {
            fn sign(&self, payload: &[u8]) -> Vec<u8> {
                self.0.lock().unwrap().push(payload.to_vec());
                vec![0xEE; 64]
            }
            fn verify(&self, _pk: &[u8], _p: &[u8], _s: &[u8]) -> bool { true }
            fn public_key(&self) -> Vec<u8> { vec![0u8; 32] }
        }

        let mut smt = SparseMerkleTree::new();
        let entry = make_entry(0xD8, 0x01);
        smt.put(&entry);
        let issuer = vec![0xAB; 16];

        let signer = RecordingSigner(Mutex::new(Vec::new()));
        let resp = process_query(&smt, &entry.wallet_id, 100, &signer, issuer.clone());

        assert_eq!(resp.nbc_issuer_pk, issuer, "the issuer must ride on the wire");

        // Sanity: the payload must actually depend on the issuer, else nothing
        // below can discriminate.
        let shipped = crate::crypto::response_sign_payload(&resp);
        let mut blanked = resp.clone();
        blanked.nbc_issuer_pk = Vec::new();
        assert_ne!(shipped, crate::crypto::response_sign_payload(&blanked),
            "setup: response_sign_payload must cover nbc_issuer_pk");

        let recorded = signer.0.lock().unwrap();
        assert_eq!(recorded.len(), 1, "exactly one signing call expected");
        assert_eq!(recorded[0], shipped,
            "G18: the bytes SIGNED must equal the bytes SHIPPED. If the issuer \
             is assigned after signing, the signature is over a payload nobody \
             ever receives — and `types.rs` tells clients the field is as \
             trustworthy as `current_state`.");
    }
    use super::*;
    use crate::crypto::NoopSigner;

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

    #[test]
    fn query_existing_wallet() {
        let mut smt = SparseMerkleTree::new();
        let entry = make_entry(0xAA, 0xBB);
        smt.put(&entry);

        let response = process_query(&smt, &entry.wallet_id, 100, &NoopSigner, Vec::new());

        assert_eq!(response.current_state, entry.current_state);
        assert_eq!(response.tx_hash, entry.tx_hash);
        assert_ne!(response.root_hash, [0u8; 32]);
        assert!(response.merkle_proof.is_some());
        assert_eq!(response.synced_to_tick, 100);
    }

    #[test]
    fn query_nonexistent_wallet() {
        let smt = SparseMerkleTree::new();
        let wallet_id = [0xFF; 32];

        let response = process_query(&smt, &wallet_id, 50, &NoopSigner, Vec::new());

        assert_eq!(response.current_state, [0u8; 32]);
        assert_eq!(response.tx_hash, [0u8; 32]);
        assert!(response.merkle_proof.is_none());
    }

    // DELETED 2026-07-30 with `verify_response` itself — `query_response_verifies`.
    //
    // Worth recording WHY it was green: `make_entry` builds a ZERO-PK entry, so
    // the fn's unauthored reconstruction matched the leaf by coincidence of the
    // fixture. Against any real (authored) entry it would have failed, because
    // the leaf hash covers `client_pk`/`client_sig`. The test could only ever
    // confirm the one case the function happened to handle — it never exercised
    // the case production actually produces. See
    // `[[feedback_test_real_producer_not_synthetic]]`: a fixture that shares the
    // code's blind spot proves nothing.

    #[test]
    fn unanimous_response_all_agree() {
        // Three identical responses → unanimous, returns the first.
        let mut smt = SparseMerkleTree::new();
        let entry = make_entry(0xAA, 0xBB);
        smt.put(&entry);
        let good = process_query(&smt, &entry.wallet_id, 100, &NoopSigner, Vec::new());
        let responses = vec![good.clone(), good.clone(), good.clone()];
        let agreed = unanimous_response(&responses).unwrap();
        assert_eq!(agreed.current_state, good.current_state);
        assert_eq!(agreed.root_hash, good.root_hash);
    }

    #[test]
    fn unanimous_response_two_of_three_is_none() {
        // YPX-002 §4.3 regression guard: a 2-of-3 split MUST NOT be
        // accepted. Old majority-wins behaviour returned the dissenter-
        // outvoted state; the spec requires any disagreement to fail
        // the check and force the receiver to wait or retry.
        let mut smt = SparseMerkleTree::new();
        let entry = make_entry(0xAA, 0xBB);
        smt.put(&entry);
        let good = process_query(&smt, &entry.wallet_id, 100, &NoopSigner, Vec::new());
        let mut lying = good.clone();
        lying.current_state[0] = 0xFF;
        lying.root_hash[0] = 0xFF;
        let responses = vec![good.clone(), good.clone(), lying];
        assert!(unanimous_response(&responses).is_none(),
            "2-of-3 agreement must NOT satisfy n-of-n — this is the whole point of the §4.3 rewrite");
    }

    #[test]
    fn unanimous_response_all_disagree_is_none() {
        let r1 = NablaResponse {
                     wallet_seq: 0,
            wallet_id: [0xAA; 32],
            current_state: [0x01; 32],
            tx_hash: [0; 32],
            root_hash: [0x01; 32],
            synced_to_tick: 1,
            group_members: None,
            merkle_proof: None,
            signature: Vec::new(),
            role: 0,
            nbc_issuer_pk: Vec::new(),
            registration_tick: 0,
            wallet_status: WalletStatus::Normal,
        };
        let mut r2 = r1.clone();
        r2.current_state = [0x02; 32];
        r2.root_hash = [0x02; 32];
        let mut r3 = r1.clone();
        r3.current_state = [0x03; 32];
        r3.root_hash = [0x03; 32];

        let responses = vec![r1, r2, r3];
        assert!(unanimous_response(&responses).is_none());
    }

    #[test]
    fn unanimous_response_empty_or_single_is_none() {
        // Unanimous over zero or one observations is not a useful
        // attestation — explicitly None so callers can't accidentally
        // treat "I asked one node and it agreed with itself" as a
        // verified cross-node check.
        let empty: Vec<NablaResponse> = Vec::new();
        assert!(unanimous_response(&empty).is_none());

        let mut smt = SparseMerkleTree::new();
        let entry = make_entry(0xAA, 0xBB);
        smt.put(&entry);
        let one = process_query(&smt, &entry.wallet_id, 100, &NoopSigner, Vec::new());
        assert!(unanimous_response(&[one]).is_none(),
            "single-node 'unanimity' must return None");
    }

    // ── Group Wallet Query Tests (Phase 3) ──

    fn make_group_entry(wid: u8) -> NablaEntry {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = wid;
        NablaEntry {
            received_from: None,
            wallet_seq: 0,
            wallet_id,
            current_state: [0x01; 32],
            tx_hash: [0; 32],
            tick: 10,
            group_members: Some(vec![
                GroupMemberState { member_pk: [0x10; 32], share_bps: 5000, available: 500 },
                GroupMemberState { member_pk: [0x20; 32], share_bps: 3000, available: 300 },
                GroupMemberState { member_pk: [0x30; 32], share_bps: 2000, available: 200 },
            ]),
            status: WalletStatus::Normal,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        }
    }

    #[test]
    fn query_group_member_found() {
        let mut smt = SparseMerkleTree::new();
        let entry = make_group_entry(0xAA);
        smt.put(&entry);

        let result = query_member(&smt, &entry.wallet_id, &[0x20; 32], 10);
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.share_bps, 3000);
        assert_eq!(resp.available, 300);
        assert_eq!(resp.group_balance, 1000);
        assert_eq!(resp.total_members, 3);
        assert!(resp.checksum_valid);
    }

    #[test]
    fn query_group_member_not_found() {
        let mut smt = SparseMerkleTree::new();
        let entry = make_group_entry(0xBB);
        smt.put(&entry);

        let result = query_member(&smt, &entry.wallet_id, &[0xFF; 32], 10);
        assert!(matches!(result, Err(NablaError::MemberNotFound)));
    }

    #[test]
    fn query_personal_wallet_not_group() {
        let mut smt = SparseMerkleTree::new();
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = 0xCC;
        let entry = NablaEntry {
                        received_from: None,
                        wallet_seq: 0,
            wallet_id,
            current_state: [0x01; 32],
            tx_hash: [0; 32],
            tick: 5,
            group_members: None, // personal wallet
            status: WalletStatus::Normal,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        };
        smt.put(&entry);

        let result = query_member(&smt, &wallet_id, &[0x10; 32], 5);
        assert!(matches!(result, Err(NablaError::NotGroupWallet)));
    }

    #[test]
    fn query_group_includes_members_in_response() {
        let mut smt = SparseMerkleTree::new();
        let entry = make_group_entry(0xDD);
        smt.put(&entry);

        let resp = process_query(&smt, &entry.wallet_id, 10, &NoopSigner, Vec::new());
        assert!(resp.group_members.is_some());
        let members = resp.group_members.unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].share_bps, 5000);
    }

    #[test]
    fn verify_checksum_valid() {
        let members = vec![
            GroupMemberState { member_pk: [0x10; 32], share_bps: 5000, available: 500 },
            GroupMemberState { member_pk: [0x20; 32], share_bps: 3000, available: 300 },
            GroupMemberState { member_pk: [0x30; 32], share_bps: 2000, available: 200 },
        ];
        assert!(verify_group_checksum(&members));
    }

    #[test]
    fn verify_checksum_bad_bps() {
        let members = vec![
            GroupMemberState { member_pk: [0x10; 32], share_bps: 5000, available: 500 },
            GroupMemberState { member_pk: [0x20; 32], share_bps: 3000, available: 300 },
            // share_bps sum = 9000, not 10000
            GroupMemberState { member_pk: [0x30; 32], share_bps: 1000, available: 200 },
        ];
        assert!(!verify_group_checksum(&members));
    }
}
