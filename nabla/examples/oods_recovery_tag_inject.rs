// RECALL Phase-2 §8.3/§8.4 — LIVE recovery-op OODS-TAG enforcement harness.
//
// Runs a CL3 HAL-reanchor (recovery op) through the REBUILT Phase-2 Core ELF
// (core/avm-guest/target/riscv32im-unknown-none-elf/release/axiom-avm-guest)
// via the RV32IM DMAP-VM and asserts the RETURNED receipt's `oods_flag`:
//   (a) no attestation  → oods_flag == Some({tick:0, oods_size:0, healthy:false})
//                         (the SCAR flag) AND result == Accept  (never reject).
//   (b) healthy attestation (root-anchored, baseline 0 → healthy=true)
//                         → oods_flag.healthy == true AND result == Accept.
//
// This is the gold-standard confirmation that the Phase-2 recovery-tag logic is
// baked into the deployed *bytes*, not just host-compiled unit tests. The valid
// attestation is minted locally with the NABLA_ROOT_1 ceremony key (self-
// contained, no live mesh). In-process only; touches no wallet or network.
//
// Usage: cargo run -p axiom-nabla --example oods_recovery_tag_inject \
//            --features axiom-core-logic/dev-mode

use axiom_core_logic::types::{
    CoreLogicMode, NablaOodsAttestation, OodsFlag, PublicInputs, Transaction, TxKind,
    ValidationResult, VBC, WalletState,
};
use axiom_core_logic::genesis::compute_genesis_state_id;
use axiom_core_logic::wallet_id::generate_wallet_id;
use axiom_dmap_vm::AvmInterpreter;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

const ELF_PATH: &str =
    "core/avm-guest/target/riscv32im-unknown-none-elf/release/axiom-avm-guest";
const ROOT_SK_PATH: &str = "../nabla-root-keys/root_1.key";
const ROOT_PK_PATH: &str = "../nabla-root-keys/root_1.pub";

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
        let state_id = compute_genesis_state_id(&pk.to_bytes(), balance);
        let address = generate_wallet_id(email, "42", &pk.to_bytes())
            .unwrap_or_else(|_| format!("{}/0000000042", email));
        Wallet { sk, pk, state_id, balance, address }
    }
    fn sign_tx(&self, tx: &mut Transaction) {
        tx.client_pk = self.pk.to_bytes().to_vec();
        let msg = axiom_core_logic::validation::compute_signing_message_public(tx);
        tx.client_sig = self.sk.sign(&msg).to_bytes().to_vec();
    }
    fn ws(&self) -> WalletState {
        WalletState {
            hibernation_until: 0,
            public_key: self.pk.to_bytes().to_vec(),
            balance: self.balance,
            wallet_seq: 0,
            state_id: self.state_id,
            auth_hash: None,
            wallet_id: None,
            group_members: None,
        }
    }
    // A HAL re-anchor self-send: receiver == self, kind = HalReanchor.
    fn hal_reanchor(&self, amount: u64) -> Transaction {
        let mut tx = Transaction {
            recall_target_tx_id: None,
            consumed_state_id: self.state_id,
            client_pk: self.pk.to_bytes().to_vec(),
            sender_wallet_id: String::new(),
            wallet_seq: 1,
            receiver_wallet_id: self.address.clone(),
            receiver_address: None,
            core_id: [0u8; 32],
            amount,
            reference: "hal-reanchor".to_string(),
            nonce: 12345,
            epoch: 1,
            client_sig: vec![],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            oracle_claim: None,
            required_k: 0,
            proof_type: 0,
            core_version: String::new(),
            kind: TxKind::HalReanchor,
        };
        self.sign_tx(&mut tx);
        tx
    }
}

fn base_inputs(mode: CoreLogicMode, tx: Transaction, state: Option<WalletState>) -> PublicInputs {
    PublicInputs {
        recall_attestation: None,
        oods_attestation: None,
        receiver_current_hibernation: None,
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
        scar_heal_tx_id: None, scar_heal_nabla_id: None, scar_heal_root_hash: None,
        wallet_secret: None, fanout_message: None, candidate_balance: None,
        nabla_stake_proof: None, frozen_wallets: None,
        console_current_cert: None, console_new_cert: None,
        console_selector_picks: None, console_nominations: None,
        txid_attestation: None, cheque_claim_proof: None, clara_attestation: None,
        phase_out_payload: None, phase_out_era_end_ticks: vec![],
        phase_out_blocked_era_ids: vec![],
        local_core_id: [0u8; 32], withdrawal_inputs: None,
        max_fact_links: None, current_tick: 0,
    }
}

fn mint_valid_attestation() -> NablaOodsAttestation {
    let node_sk = SigningKey::from_bytes(&[0x5e; 32]);
    let node_pk = VerifyingKey::from(&node_sk).to_bytes();
    let root_sk = std::fs::read(ROOT_SK_PATH)
        .unwrap_or_else(|e| panic!("read {ROOT_SK_PATH}: {e} (run from src/, dev tree only)"));
    let root_pk = std::fs::read(ROOT_PK_PATH)
        .unwrap_or_else(|e| panic!("read {ROOT_PK_PATH}: {e}"));
    let nbc = VBC {
        version: 0x09,
        validator_id: axiom_core_logic::compute::compute_validator_id(&root_pk),
        subject_pubkey_sphincs: root_pk.clone(),
        subject_pubkey_dilithium: vec![0u8; 1952],
        subject_pubkey_ed25519: node_pk.to_vec(),
        pgp_fingerprint: vec![],
        node_name: "recovery-tag-test".to_string(),
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

fn accepting_hal_reanchor() -> PublicInputs {
    let alice = Wallet::new([0x01; 32], "alice@axiom.internal", 5_000_000);
    let tx = alice.hal_reanchor(500_000);
    base_inputs(CoreLogicMode::CL3, tx, Some(alice.ws()))
}

fn run(avm: &AvmInterpreter, inputs: PublicInputs) -> (ValidationResult, Option<OodsFlag>) {
    match avm.execute(inputs) {
        Ok(out) => (out.result, out.oods_flag),
        Err(e) => {
            eprintln!("  AVM error: {:?}", e);
            (ValidationResult::Fatal, None)
        }
    }
}

fn main() {
    let elf = std::fs::read(ELF_PATH)
        .unwrap_or_else(|e| panic!("read rebuilt Phase-2 ELF {ELF_PATH}: {e}"));
    let core_id = *blake3::hash(&elf).as_bytes();
    println!("Rebuilt Phase-2 ELF CoreID: {}", hex::encode(core_id));
    let avm = AvmInterpreter::new(elf, [0u8; 32]);

    let live = mint_valid_attestation();
    println!(
        "Minted root-anchored attestation: oods_size={} tick={} baseline_size={} → healthy",
        live.oods_size, live.tick, live.baseline_size,
    );

    let mut pass = 0usize;
    let mut fail = 0usize;

    // (a) Recovery op, NO attestation → SCAR flag {0,0,false} + ACCEPT.
    let mut a = accepting_hal_reanchor();
    a.oods_attestation = None;
    let (res_a, flag_a) = run(&avm, a);
    let want_a = Some(OodsFlag { tick: 0, oods_size: 0, healthy: false });
    let ok_a = res_a == ValidationResult::Accept && flag_a == want_a;
    println!(
        "  [{}] (a) recovery + no attestation → SCAR flag + accept   result={:?} oods_flag={:?}",
        if ok_a { "PASS" } else { "FAIL" }, res_a, flag_a,
    );
    if ok_a { pass += 1 } else { fail += 1 }

    // (b) Recovery op, HEALTHY attestation → healthy=true flag + ACCEPT.
    let mut b = accepting_hal_reanchor();
    b.oods_attestation = Some(live.clone());
    let (res_b, flag_b) = run(&avm, b);
    let ok_b = res_b == ValidationResult::Accept
        && flag_b.as_ref().map_or(false, |f| f.healthy);
    println!(
        "  [{}] (b) recovery + healthy attestation → healthy flag + accept   result={:?} oods_flag={:?}",
        if ok_b { "PASS" } else { "FAIL" }, res_b, flag_b,
    );
    if ok_b { pass += 1 } else { fail += 1 }

    println!("\n{} passed, {} failed", pass, fail);
    std::process::exit(if fail == 0 { 0 } else { 1 });
}
