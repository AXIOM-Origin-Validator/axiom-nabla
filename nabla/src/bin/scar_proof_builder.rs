//! scar-proof-builder — CLI tool for E2E scar healing integration tests
//!
//! Generates a valid ScarRecoveryProof with 3 ML-DSA-65 (Dilithium) keypairs
//! using Core's exact fips204 crate. Outputs CBOR to stdout (YP §16.8.5).
//!
//! Usage:
//!   scar-proof-builder --tx-id <hex32> --node-id <hex32> \
//!       --root-hash <hex32> --tick <u64> --receiver <wallet_id>

use axiom_core_logic::fact::sign_scar_heal_commitment;
use axiom_core_logic::types::{FactWitness, NablaConfirmation, ScarRecoveryProof};

fn parse_hex32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("invalid hex");
    assert_eq!(bytes.len(), 32, "expected 32 bytes, got {}", bytes.len());
    bytes.try_into().unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut tx_id_hex = None;
    let mut node_id_hex = None;
    let mut root_hash_hex = None;
    let mut tick: u64 = 100;
    let mut receiver = String::from("receiver@test.local");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--tx-id" => { tx_id_hex = Some(args[i + 1].clone()); i += 2; }
            "--node-id" => { node_id_hex = Some(args[i + 1].clone()); i += 2; }
            "--root-hash" => { root_hash_hex = Some(args[i + 1].clone()); i += 2; }
            "--tick" => { tick = args[i + 1].parse().expect("invalid tick"); i += 2; }
            "--receiver" => { receiver = args[i + 1].clone(); i += 2; }
            other => { eprintln!("Unknown arg: {}", other); std::process::exit(1); }
        }
    }

    let original_tx_id = parse_hex32(
        &tx_id_hex.expect("--tx-id required"),
    );
    let nabla_node_id = parse_hex32(
        &node_id_hex.expect("--node-id required"),
    );
    let root_hash = parse_hex32(
        &root_hash_hex.expect("--root-hash required"),
    );

    // Generate 3 ML-DSA-65 keypairs and sign the heal commitment
    use fips204::ml_dsa_65;
    use fips204::traits::SerDes;

    let mut witnesses = Vec::new();
    for _ in 0..3 {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("Dilithium keygen failed");
        let pk_bytes = pk.into_bytes().to_vec();
        let sk_bytes = sk.into_bytes().to_vec();

        // validator_id = BLAKE3(pk)
        let validator_id: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();

        let signature = sign_scar_heal_commitment(
            &sk_bytes,
            &original_tx_id,
            &nabla_node_id,
            &root_hash,
        )
        .expect("sign_scar_heal_commitment failed");

        witnesses.push(FactWitness {
            validator_id,
            validator_pk: pk_bytes,
            signature,
            vbc_genesis_anchor: None,
        });
    }

    // Build dummy NablaConfirmation (signature not verified in scar heal path)
    let nabla_confirmation = NablaConfirmation {
        nabla_node_id,
        nabla_signature: vec![0u8; 64],
        root_hash,
        synced_to_tick: tick,
        ..Default::default()
    };

    let proof = ScarRecoveryProof {
        original_tx_id,
        nabla_confirmation,
        healing_witnesses: witnesses,
        receiver_wallet_id: receiver,
        fact_link_index: None,
    };

    // Output as CBOR to stdout (YP §16.8.5 — CBOR everywhere)
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&proof, &mut cbor_bytes).expect("CBOR serialization failed");
    use std::io::Write;
    std::io::stdout().write_all(&cbor_bytes).expect("stdout write failed");
}
