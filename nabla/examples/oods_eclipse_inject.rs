// YPX-021 §8.2 — LIVE eclipse harness: healthy=false end to end.
//
// The tamper harness (oods_tamper_inject) proves attestation INTEGRITY on the
// deployed ELF, but every live node is baseline-exempt (baseline=0 ⇒ trivially
// healthy), so it can't exercise the actual wash-out gate. This harness closes
// that: it mints a genuinely-verifying attestation with a NON-ZERO baseline
// (an NBC signed by a real NABLA_ROOT_AUTHORITY key from nabla-root-keys/) and
// an eclipsed live estimate, then proves BOTH halves of §8.2:
//
//   Phase A (deployed ELF): the eclipsed-but-valid attestation runs through
//     core/artifacts/axiom-core.elf via the real RV32IM DMAP-VM and Core
//     stamps oods_flag.healthy = FALSE onto the receipt — computed in-guest
//     from the baseline suffix it verified. Healthy / boundary sizes stamp
//     true/false exactly per oods_healthy(size, baseline) (dip factor 3).
//
//   Phase B (wash-out gate): a receipt carrying healthy=false blocks
//     FACT-chain compression — advance_fact_checkpoint refuses to PROPOSE or
//     FINALIZE, so laundered value can't be washed out. healthy=true is the
//     control (compression proceeds).
//
// This needs the dev NABLA_ROOT secret key (nabla-root-keys/root_1.key), so it
// is a dev/ceremony-tree tool, not a mainnet path — the root SK is exactly the
// "genesis-rooted colluder" §7 prices; here we hold it only to forge a VALID
// baselined cert for the test.
//
// Usage: cargo run -p axiom-nabla --example oods_eclipse_inject

use axiom_core_logic::types::{
    CoreLogicMode, FactChain, FactLink, FactWitness, NablaConfirmation, NablaOodsAttestation,
    PublicInputs, Transaction, TxKind, ValidationResult, WalletState, VBC,
};
use axiom_core_logic::genesis::compute_genesis_state_id;
use axiom_core_logic::validation::oods_healthy;
use axiom_core_logic::wallet_id::generate_wallet_id;
use axiom_dmap_vm::AvmInterpreter;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes};

const ELF_PATH: &str = "core/artifacts/axiom-core.elf";
const ROOT_SK_PATH: &str = "../nabla-root-keys/root_1.key";
const ROOT_PK_PATH: &str = "../nabla-root-keys/root_1.pub";
const BASELINE: u32 = 100; // issuer-stamped network-size baseline
const BASELINE_TICK: u64 = 5_000;

// ── Wallet helper (mirrors examples/generate_vectors.rs) ──────────────────
struct Wallet {
    sk: SigningKey,
    pk: VerifyingKey,
    state_id: [u8; 32],
    balance: u64,
    address: String,
}
impl Wallet {
    fn new(seed: [u8; 32], email: &str, balance: u64) -> Self {
        let sk = SigningKey::from_bytes(&seed);
        let pk = VerifyingKey::from(&sk);
        let state_id = compute_genesis_state_id(&pk.to_bytes(), balance, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP);
        let address = generate_wallet_id(email, "42", &pk.to_bytes())
            .unwrap_or_else(|_| format!("{}/0000000042", email));
        Wallet { sk, pk, state_id, balance, address }
    }
    fn sign_tx(&self, tx: &mut Transaction) {
        tx.client_pk = self.pk.to_bytes().to_vec();
        let mut msg = Vec::new();
        msg.extend_from_slice(&tx.consumed_state_id);
        msg.extend_from_slice(&tx.wallet_seq.to_le_bytes());
        msg.extend_from_slice(tx.sender_wallet_id.as_bytes());
        msg.extend_from_slice(tx.receiver_wallet_id.as_bytes());
        msg.extend_from_slice(&tx.amount.to_le_bytes());
        msg.extend_from_slice(tx.reference.as_bytes());
        msg.extend_from_slice(&tx.nonce.to_le_bytes());
        msg.extend_from_slice(&tx.epoch.to_le_bytes());
        msg.extend_from_slice(tx.burn_target_tx_id.as_ref().unwrap_or(&[0u8; 32]));
        msg.extend_from_slice(axiom_core_logic::types::AXIOM_PROTOCOL_VERSION.as_bytes());
        tx.client_sig = self.sk.sign(&msg).to_bytes().to_vec();
    }
    fn ws(&self) -> WalletState {
        WalletState {
            hibernation_until: 0,
            // §5.2.2c — these harnesses drive OODS, not the subsidy claim: no
            // stake lock held. Field added 2026-09-05.
            wall_clock_lock: 0, public_key: self.pk.to_bytes().to_vec(),
            emission_claimed_epoch: 0,
            stake_floor_until: 0, wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
            balance: self.balance, wallet_seq: 0, state_id: self.state_id,
            auth_hash: None, wallet_id: None, group_members: None,
        }
    }
    fn tx(&self, receiver: &str, amount: u64) -> Transaction {
        let mut tx = Transaction {
            recall_target_tx_id: None,
            consumed_state_id: self.state_id, client_pk: self.pk.to_bytes().to_vec(),
            sender_wallet_id: String::new(), wallet_seq: 1,
            receiver_wallet_id: receiver.to_string(), receiver_address: None,
            core_id: [0u8; 32], amount, reference: "vector-test".to_string(),
            nonce: 12345, epoch: 1, client_sig: vec![],
            scar_passcode: None, burn_target_tx_id: None, oracle_claim: None,
            required_k: 0, proof_type: 0, core_version: String::new(), kind: TxKind::Normal,
        };
        self.sign_tx(&mut tx);
        tx
    }
}

fn base_inputs(mode: CoreLogicMode, tx: Transaction, state: Option<WalletState>) -> PublicInputs {
    PublicInputs {
        zkq_request: None,
        fact_certificates: Vec::new(),
        receiver_witness: None,
        receiver_signing_key: None,
        recall_attestation: None,
        fob_claim_attestation: None, // §10.0 FOB fee-claim — not exercised here
        oods_attestation: None, receiver_current_hibernation: None,
        // §5.2.2b/c — added 2026-09-05; this harness drives OODS, not a claim.
        receiver_current_wall_clock_lock: None, claimant_vbc: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: None,
        mode, transaction: tx, prev_receipts: vec![], current_state: state,
        vbc_bundle: None, cheque_bundle: None, receiver_pk: None,
        receiver_current_balance: None, receiver_wallet_seq: None,
        receiver_new_balance: None, receiver_new_state_id: None,
        my_validator_pk: None, overlapped_signatures: vec![],
        group_member_index: None, sender_fact_chain: None, receiver_fact_chain: None,
        my_dilithium_sk: None, my_dilithium_pk: None, my_validator_id: None,
        fact_witness_sigs: vec![], issuer_sphincs_sk: None,
        cl1_execution_proof: None, zkp_nonce: None,
        audit_confirmation: None, nonce_response: None, audit_response: None,
        wallet_secret: None, fanout_message: None, nabla_stake_proof: None, frozen_wallets: None,
        console_current_cert: None, console_new_cert: None,
        console_selector_picks: None, console_nominations: None,
        txid_attestation: None, cheque_claim_proof: None, clara_attestation: None,
        phase_out_payload: None, phase_out_era_end_ticks: vec![],
        phase_out_blocked_era_ids: vec![],
        local_core_id: [0u8; 32],
        max_fact_links: None, current_tick: 0,
    }
}

/// Mint a VALID, root-anchored, baselined attestation for a given live
/// estimate `oods_size`. The NBC pre-image is signed by NABLA_ROOT_1 (real
/// dev ceremony key) and embeds both the node's Ed25519 pk (window check)
/// and the baseline suffix (§7 binding). Verifies end to end in Core; only
/// `oods_size` varies, so `healthy` is a pure function of the eclipse.
fn baselined_attestation(oods_size: u32) -> NablaOodsAttestation {
    // Node's operational Ed25519 identity.
    let node_sk = SigningKey::from_bytes(&[0x5e; 32]);
    let node_pk = VerifyingKey::from(&node_sk).to_bytes();

    // Root ceremony key material (SPHINCS+ SLH-DSA-SHA2-128s).
    let root_sk = std::fs::read(ROOT_SK_PATH)
        .unwrap_or_else(|e| panic!("read {ROOT_SK_PATH}: {e} (run from src/, dev tree only)"));
    let root_pk = std::fs::read(ROOT_PK_PATH)
        .unwrap_or_else(|e| panic!("read {ROOT_PK_PATH}: {e}"));

    // Build the baselined NBC and take its canonical signing pre-image. The
    // baseline suffix rides ONLY because network_size_baseline != 0 (§7).
    let nbc = VBC {
        version: 0x09,
        // §5.3 — an NBC issued by a root authority is chain_depth 0; zero is
        // the genesis/no-lineage sentinel it legitimately carries.
        genesis_lineage: [0u8; 32],
        validator_id: axiom_core_logic::compute::compute_validator_id(&root_pk),
        subject_pubkey_sphincs: root_pk.clone(),
        subject_pubkey_dilithium: vec![0u8; 1952],
        subject_pubkey_ed25519: node_pk.to_vec(), // ← window check binds here
        pgp_fingerprint: vec![],
        node_name: "eclipse-test".to_string(),
        proof_cap: String::new(),
        issued_at: 1,
        expires_at: u64::MAX,
        chain_depth: 0,
        issuer_set: vec![root_pk.clone()],
        signatures: vec![],
        max_tx: 0,
        founding_vbc_hash: [0u8; 32],
        network_size_baseline: BASELINE,
        baseline_tick: BASELINE_TICK,
        nabla_registration: None,
    };
    let pre_image = axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&nbc);
    let nbc_hash = blake3::hash(&pre_image);
    let nbc_signature = axiom_core_logic::compute::sign_sphincs(&root_sk, nbc_hash.as_bytes())
        .expect("root SPHINCS+ sign");

    // Sign the live reading (binds size + baseline into the Ed25519 payload).
    let tick = BASELINE_TICK + 1_000;
    let payload = axiom_core_logic::compute::compute_oods_attestation_payload(
        oods_size, tick, BASELINE, BASELINE_TICK,
    );
    let nabla_signature = node_sk.sign(&payload).to_bytes().to_vec();

    NablaOodsAttestation {
        oods_size, tick,
        baseline_size: BASELINE, baseline_tick: BASELINE_TICK,
        nabla_node_pk: node_pk,
        nabla_signature,
        nbc_issuer_pk: root_pk,
        nbc_signature,
        nbc_commitment: pre_image,
    }
}

fn accepting_cl3() -> PublicInputs {
    let alice = Wallet::new([0x01; 32], "alice@axiom.internal", 5_000_000);
    let bob = Wallet::new([0x02; 32], "bob@axiom.internal", 5_000_000);
    let tx = alice.tx(&bob.address, 500_000);
    base_inputs(CoreLogicMode::CL3, tx, Some(alice.ws()))
}

// ── Phase B: a resolved chain deep enough to trigger a checkpoint PROPOSE.
// Links are marked resolved with a (dummy) NablaConfirmation — the PROPOSE
// path only checks is_resolved() + hashes the links, it does not verify the
// confirmations (that happens elsewhere), so this faithfully exercises the
// oods_view_healthy gate in advance_fact_checkpoint.
fn resolved_chain(n: usize) -> FactChain {
    let mut links = Vec::new();
    for i in 0..n {
        links.push(FactLink {
            burn_target_tx_id: None,
            tx_id: [100 + i as u8; 32],
            previous_state_id: [i as u8; 32],
            new_state_id: [(i + 1) as u8; 32],
            amount: 100,
            tick: 0,
            required_k: 3,
            witnesses: vec![],
            nabla_confirmation: Some(NablaConfirmation::default()), // resolved
            burn_proof: None,
            sender_anchor: None,
            is_dev_class: false,
            recall_proof: None,
            out_of_order_confirmation: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
            receiver_witness: None,
        });
    }
    FactChain { checkpoint: None, links }
}

fn main() {
    let elf = std::fs::read(ELF_PATH)
        .unwrap_or_else(|e| panic!("read deployed ELF {ELF_PATH}: {e}"));
    println!("Deployed ELF CoreID: {}", hex::encode(blake3::hash(&elf).as_bytes()));
    let avm = AvmInterpreter::new(elf, [0u8; 32]);

    let mut pass = 0usize;
    let mut fail = 0usize;

    // ── Phase A: healthy computed in-guest from a real baselined attestation.
    println!("\n── Phase A: healthy=? out of the deployed ELF (baseline={BASELINE}, dip factor 3) ──");
    // size*3 >= 100 ⇒ healthy. 34→102 healthy; 33→99 eclipsed; 10→30 eclipsed; 200→huge healthy.
    for (size, want_healthy, label) in [
        (10u32, false, "deep eclipse"),
        (33u32, false, "just below dip band"),
        (34u32, true, "just above dip band"),
        (200u32, true, "grown network"),
    ] {
        let mut inputs = accepting_cl3();
        inputs.oods_attestation = Some(baselined_attestation(size));
        let out = match avm.execute(inputs) {
            Ok(o) => o,
            Err(e) => { println!("  [FAIL] {label}: AVM error {e:?}"); fail += 1; continue; }
        };
        let flag = out.oods_flag;
        let accepted = out.result == ValidationResult::Accept;
        let healthy_ok = flag.map(|f| f.healthy) == Some(want_healthy);
        // Sanity: our expectation must match the canonical predicate.
        assert_eq!(want_healthy, oods_healthy(size, BASELINE));
        let ok = accepted && healthy_ok && flag.map(|f| f.oods_size) == Some(size);
        println!(
            "  [{}] size={:<4} {:<22} accept={} flag={:?}",
            if ok { "PASS" } else { "FAIL" }, size, label, accepted, flag,
        );
        if ok { pass += 1 } else { fail += 1 }
    }

    // ── Phase B: the eclipse flag blocks FACT-chain compression (wash-out).
    println!("\n── Phase B: healthy=false blocks compression (advance_fact_checkpoint) ──");
    let (dpk, dsk) = ml_dsa_65::try_keygen().expect("dilithium keygen");
    let (dpk, dsk) = (dpk.into_bytes().to_vec(), dsk.into_bytes().to_vec());
    let vid = [0x11u8; 32];

    // Eclipsed view (healthy=false): no PROPOSE, no links touched.
    let mut eclipsed = resolved_chain(6);
    axiom_core_logic::compute::advance_fact_checkpoint(&mut eclipsed, vid, &dpk, &dsk, [0u8; 32], false)
        .expect("advance");
    let blocked = eclipsed.checkpoint.is_none() && eclipsed.links.len() == 6;
    println!(
        "  [{}] eclipsed view → no compression (checkpoint={}, links={})",
        if blocked { "PASS" } else { "FAIL" },
        eclipsed.checkpoint.is_some(), eclipsed.links.len(),
    );
    if blocked { pass += 1 } else { fail += 1 }

    // Healthy view (control): PROPOSE fires, a checkpoint appears.
    let mut healthy = resolved_chain(6);
    axiom_core_logic::compute::advance_fact_checkpoint(&mut healthy, vid, &dpk, &dsk, [0u8; 32], true)
        .expect("advance");
    let proceeded = healthy.checkpoint.is_some();
    println!(
        "  [{}] healthy view  → compression proposes (checkpoint={})",
        if proceeded { "PASS" } else { "FAIL" }, proceeded,
    );
    if proceeded { pass += 1 } else { fail += 1 }

    println!("\n{} passed, {} failed", pass, fail);
    std::process::exit(if fail == 0 { 0 } else { 1 });
}
