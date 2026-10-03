// YPX-021 §8.2 — LIVE tampered-OODS-attestation enforcement harness.
//
// Runs a real, root-anchored OODS attestation and four forgeries of it
// through the DEPLOYED Core ELF (`core/artifacts/axiom-core.elf`, the exact
// bytes every validator runs) via the RV32IM DMAP-VM. Proves Core's
// `verify_oods_attestation` gate fires on the deployed binary — not just in
// host-compiled unit tests — and that a tampered attestation is a HARD reject
// (`OodsAttestationInvalid`), never a silent downgrade to "no flag".
//
// The attestation is MINTED locally with the real NABLA_ROOT_1 ceremony key
// (the OodsReadingRequest wire query was removed 2026-07-03 — the reading now
// rides the register response), so the harness is self-contained and needs no
// live mesh. In-process only; touches no wallet or network. Dev-tree tool
// (holds the root SK — the genesis-rooted-colluder cost §7 prices).
//
// Usage: cargo run -p axiom-nabla --example oods_tamper_inject

use axiom_core_logic::types::{
    CoreLogicMode, NablaOodsAttestation, PublicInputs, Transaction, TxKind,
    ValidationResult, ValidationError, VBC, WalletState,
};
use axiom_core_logic::genesis::compute_genesis_state_id;
use axiom_core_logic::wallet_id::generate_wallet_id;
use axiom_dmap_vm::AvmInterpreter;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

const ELF_PATH: &str = "core/artifacts/axiom-core.elf";
const ROOT_SK_PATH: &str = "../nabla-root-keys/root_1.key";
const ROOT_PK_PATH: &str = "../nabla-root-keys/root_1.pub";

// ── Minimal wallet helper (mirrors examples/generate_vectors.rs) ──────────
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
            wall_clock_lock: 0,
            emission_claimed_epoch: 0,
            stake_floor_until: 0, wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
            public_key: self.pk.to_bytes().to_vec(),
            balance: self.balance,
            wallet_seq: 0,
            state_id: self.state_id,
            auth_hash: None,
            wallet_id: None,
            group_members: None,
        }
    }
    fn tx(&self, receiver: &str, amount: u64) -> Transaction {
        let mut tx = Transaction {
            recall_target_tx_id: None,
            consumed_state_id: self.state_id,
            client_pk: self.pk.to_bytes().to_vec(),
            sender_wallet_id: String::new(),
            wallet_seq: 1,
            receiver_wallet_id: receiver.to_string(),
            receiver_address: None,
            core_id: [0u8; 32],
            amount,
            reference: "vector-test".to_string(),
            nonce: 12345,
            epoch: 1,
            client_sig: vec![],
            scar_passcode: None,
            burn_target_tx_id: None,
            oracle_claim: None,
            required_k: 0,
            proof_type: 0,
            core_version: String::new(),
            kind: TxKind::Normal,
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
        oods_attestation: None,
        receiver_current_hibernation: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: None,
        claimant_vbc: None, // §5.2.2b — not a subsidy claim
        mode, transaction: tx, prev_receipts: vec![], current_state: state,
        vbc_bundle: None, cheque_bundle: None, receiver_pk: None,
        receiver_current_balance: None, receiver_wallet_seq: None,
        receiver_new_balance: None, receiver_new_state_id: None,
        my_validator_pk: None, overlapped_signatures: vec![],
        group_member_index: None, sender_fact_chain: None,
        receiver_fact_chain: None,
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

/// Mint a VALID, root-anchored OODS attestation (baseline 0 → genesis-exempt,
/// so it reads healthy). Signed by the real NABLA_ROOT_1 ceremony key so it
/// passes Core's NBC-anchor + Ed25519 gates end to end — the pristine control
/// the four tampers below each break. Self-contained: no live-mesh query (the
/// OodsReadingRequest wire op was removed 2026-07-03 — the reading now rides
/// the register response). Dev-tree only (holds the root SK).
fn mint_valid_attestation() -> NablaOodsAttestation {
    let node_sk = SigningKey::from_bytes(&[0x5e; 32]);
    let node_pk = VerifyingKey::from(&node_sk).to_bytes();
    let root_sk = std::fs::read(ROOT_SK_PATH)
        .unwrap_or_else(|e| panic!("read {ROOT_SK_PATH}: {e} (run from src/, dev tree only)"));
    let root_pk = std::fs::read(ROOT_PK_PATH)
        .unwrap_or_else(|e| panic!("read {ROOT_PK_PATH}: {e}"));
    let nbc = VBC {
        version: 0x09,
        // §5.3 — an NBC issued by a root authority is chain_depth 0; zero is
        // the genesis/no-lineage sentinel it legitimately carries.
        genesis_lineage: [0u8; 32],
        validator_id: axiom_core_logic::compute::compute_validator_id(&root_pk),
        subject_pubkey_sphincs: root_pk.clone(),
        subject_pubkey_dilithium: vec![0u8; 1952],
        subject_pubkey_ed25519: node_pk.to_vec(),
        pgp_fingerprint: vec![],
        node_name: "tamper-test".to_string(),
        proof_cap: String::new(),
        issued_at: 1,
        expires_at: u64::MAX,
        chain_depth: 0,
        issuer_set: vec![root_pk.clone()],
        signatures: vec![],
        max_tx: 0,
        founding_vbc_hash: [0u8; 32],
        network_size_baseline: 0, // genesis-exempt → healthy
        baseline_tick: 0,
        nabla_registration: None,
    };
    let pre_image = axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&nbc);
    let nbc_signature = axiom_core_logic::compute::sign_sphincs(
        &root_sk, blake3::hash(&pre_image).as_bytes()).expect("root SPHINCS+ sign");
    let (oods_size, tick) = (11u32, 6_000u64);
    let payload = axiom_core_logic::compute::compute_oods_attestation_payload(oods_size, tick, 0, 0);
    let nabla_signature = node_sk.sign(&payload).to_bytes().to_vec();
    NablaOodsAttestation {
        oods_size, tick, baseline_size: 0, baseline_tick: 0,
        nabla_node_pk: node_pk, nabla_signature,
        nbc_issuer_pk: root_pk, nbc_signature,
        nbc_commitment: pre_image,
    }
}

/// Build a known-accepting CL3 send. A genesis-funded first send has an
/// empty prev_receipts + current_state == genesis, so it clears
/// validate_witnesses and validate_transaction and reaches the OODS
/// derivation at the end of execute_cl3 — where a supplied attestation is
/// verified. (CL5 is unusable here: it hard-rejects on the earlier
/// ChequeClaimProofMissing gate before the OODS block, needing a real
/// Nabla-writer claim proof.)
fn accepting_cl3() -> PublicInputs {
    let alice = Wallet::new([0x01; 32], "alice@axiom.internal", 5_000_000);
    let bob = Wallet::new([0x02; 32], "bob@axiom.internal", 5_000_000);
    let tx = alice.tx(&bob.address, 500_000);
    base_inputs(CoreLogicMode::CL3, tx, Some(alice.ws()))
}

fn run(avm: &AvmInterpreter, inputs: PublicInputs) -> (ValidationResult, Option<ValidationError>) {
    match avm.execute(inputs) {
        Ok(out) => (out.result, out.rejection_reason),
        Err(e) => {
            eprintln!("  AVM error: {:?}", e);
            (ValidationResult::Fatal, None)
        }
    }
}

fn main() {
    let elf = std::fs::read(ELF_PATH)
        .unwrap_or_else(|e| panic!("read deployed ELF {ELF_PATH}: {e}"));
    let core_id = *blake3::hash(&elf).as_bytes();
    println!("Deployed ELF CoreID: {}", hex::encode(core_id));
    let avm = AvmInterpreter::new(elf, [0u8; 32]);

    let live = mint_valid_attestation();
    println!(
        "Minted root-anchored attestation: oods_size={} tick={} baseline_size={} nbc_commitment={}B",
        live.oods_size, live.tick, live.baseline_size, live.nbc_commitment.len(),
    );

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut check = |name: &str, got: (ValidationResult, Option<ValidationError>),
                     want_reject_oods: bool| {
        let is_oods_reject = got.0 == ValidationResult::Reject
            && got.1 == Some(ValidationError::OodsAttestationInvalid);
        let ok = if want_reject_oods {
            is_oods_reject
        } else {
            got.0 == ValidationResult::Accept
        };
        println!(
            "  [{}] {:<34} result={:?} reason={:?}",
            if ok { "PASS" } else { "FAIL" }, name, got.0, got.1,
        );
        if ok { pass += 1 } else { fail += 1 }
    };

    // Control: base CL5 with no attestation must ACCEPT (flagless, Phase 1).
    println!("\n── running through deployed ELF ──");
    let mut base = accepting_cl3();
    base.oods_attestation = None;
    check("control: no attestation → accept", run(&avm, base.clone()), false);

    // Pristine live attestation → ACCEPT (real NBC anchor + real sig verify
    // inside the deployed ELF; the healthy flag is stamped).
    let mut good = base.clone();
    good.oods_attestation = Some(live.clone());
    check("live attestation → accept", run(&avm, good), false);

    // Tamper 1: flip one signature byte → OodsAttestationInvalid (sig gate).
    let mut t_sig = live.clone();
    t_sig.nabla_signature[5] ^= 0x01;
    let mut i_sig = base.clone();
    i_sig.oods_attestation = Some(t_sig);
    check("tampered sig → reject", run(&avm, i_sig), true);

    // Tamper 2: re-pair a healthier baseline (claim lower baseline → would
    // read "healthy") — breaks the Ed25519 payload binding.
    let mut t_base = live.clone();
    t_base.baseline_size = t_base.baseline_size.saturating_add(1_000_000);
    let mut i_base = base.clone();
    i_base.oods_attestation = Some(t_base);
    check("re-paired baseline → reject", run(&avm, i_base), true);

    // Tamper 3: strip the NBC trust anchor → OodsAttestationInvalid.
    let mut t_anchor = live.clone();
    t_anchor.nbc_issuer_pk = Vec::new();
    let mut i_anchor = base.clone();
    i_anchor.oods_attestation = Some(t_anchor);
    check("stripped NBC anchor → reject", run(&avm, i_anchor), true);

    // Tamper 4: substitute a foreign Ed25519 pk (breaks sig + anchor window).
    let mut t_pk = live.clone();
    t_pk.nabla_node_pk = [0xAB; 32];
    let mut i_pk = base.clone();
    i_pk.oods_attestation = Some(t_pk);
    check("foreign node pk → reject", run(&avm, i_pk), true);

    println!("\n{} passed, {} failed", pass, fail);
    std::process::exit(if fail == 0 { 0 } else { 1 });
}
