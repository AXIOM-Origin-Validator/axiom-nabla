//! Measure the ON-THE-WIRE size of a Nabla node's steady-state mesh messages.
//!
//! `cargo run -p axiom-nabla --release --example measure_wire`
//!
//! Mesh peer-to-peer traffic is BINCODE (`transport.rs:1256`), not CBOR — CBOR
//! is used only for `cbor_client` replies (`transport.rs:886`). Both are
//! reported; bincode is the number that matters for gossip cost.
//!
//! Sizes are of the serialized message body. The wire adds a 4-byte big-endian
//! length prefix per message (`transport.rs`), counted separately below.

use axiom_nabla::transport::WireMessage;
use axiom_nabla::types::{GpCommitment, TickMessage};

const FRAME_HEADER: usize = 4; // u32 BE length prefix

fn sizes(label: &str, msg: &WireMessage) -> (usize, usize) {
    let bin = bincode::serialize(msg).expect("bincode");
    let mut cbor = Vec::new();
    ciborium::into_writer(msg, &mut cbor).expect("cbor");
    println!(
        "{:<34} bincode {:>8}  (+4 frame = {:>8})   cbor {:>8}",
        label,
        bin.len(),
        bin.len() + FRAME_HEADER,
        cbor.len()
    );
    (bin.len(), cbor.len())
}

fn main() {
    println!("== steady-state mesh messages, one instance each ==\n");

    // A tick as `nabla_node.rs:6824` builds it: unix-second number, Ed25519
    // signature (64), prev_sig from the upstream tick (64), the grandparent
    // pk, and the TARDIS slot/child vectors for a node with 2 children.
    let tick = WireMessage::Tick(TickMessage {
        number: 1_789_180_000,
        upstream_pk: [7u8; 32],
        payload: vec![],
        signature: vec![0xAB; 64],
        timestamp_ms: 1_789_180_000_000,
        prev_sig: vec![0xCD; 64],
        grandparent_pk: Some([9u8; 32]),
        available_slots: vec![([1u8; 32], 2), ([2u8; 32], 1)],
        downstream_approvals: 2,
        subtree_d_available: 4,
        oods_tardis: vec![],
        child_pks: vec![[3u8; 32], [4u8; 32]],
        gp_commitment: Some(GpCommitment::default()),
    });
    let (tick_b, _) = sizes("Tick (2 children, signed)", &tick);

    // Hello carries the node's NBC. 1704 bytes is the measured size of a real
    // certificate blob on the live fleet (vbc_registrations.cbor, alpha).
    let hello = WireMessage::Hello {
        node_id: [1u8; 32],
        external_port: 7300,
        downstream_count: 2,
        nbc_bytes: vec![0u8; 1704],
        nbc_supporting_bytes: vec![],
        txid_service: "full".to_string(),
        observed_peer_ip: Some([0u8; 16]),
    };
    let (hello_b, _) = sizes("Hello (with 1704-byte NBC)", &hello);

    // TickHash — the anti-entropy probe, every ANTI_ENTROPY_INTERVAL (6) ticks
    // to 2 peers. AeDigest only follows when root hashes DISAGREE, so it is
    // repair traffic, not steady state.
    let tickhash = WireMessage::Gossip(axiom_nabla::types::GossipMessage::TickHash {
        tick: 1_789_180_000,
        root_hash: [0x11u8; 32],
        node_pk: [1u8; 32],
        signature: vec![0xABu8; 64],
    });
    let (th_b, _) = sizes("Gossip::TickHash", &tickhash);

    let ping = WireMessage::Ping { from: [1u8; 32], nonce: 42 };
    let (ping_b, _) = sizes("Ping", &ping);

    // AeDigest is the one that scales with the ledger: every SMT leaf, as
    // (WalletId, Hash256) = 32 + 32 bytes before encoding overhead.
    println!("\n== AeDigest — anti-entropy digest, scales with registered wallets ==\n");
    let mut ae_per_wallet = 0f64;
    let mut ae_at = std::collections::BTreeMap::new();
    for n in [0usize, 10, 100, 1_000, 10_000, 100_000] {
        let leaves: Vec<([u8; 32], [u8; 32])> =
            (0..n).map(|i| {
                let mut w = [0u8; 32];
                w[..8].copy_from_slice(&(i as u64).to_le_bytes());
                (w, [0xEEu8; 32])
            }).collect();
        let msg = WireMessage::AeDigest { from: [1u8; 32], leaves };
        let (b, _) = sizes(&format!("AeDigest ({} wallets)", n), &msg);
        ae_at.insert(n, b);
        if n == 100_000 {
            ae_per_wallet = (b - ae_at[&0]) as f64 / n as f64;
        }
    }
    println!("\nAeDigest bytes per wallet (from the 0 → 100k difference, so fixed overhead excluded): {:.2}", ae_per_wallet);

    println!("\n== steady-state totals ==\n");
    println!("Tick   body {:>6} B  → sent to each DOWNSTREAM child (0..2), every tick", tick_b);
    println!("Hello  body {:>6} B  → all active peers every 12 ticks; 5 peers every 3 ticks when downstream_count==1", hello_b);
    println!("Ping   body {:>6} B  → every LATENCY_PING_INTERVAL ticks, to every active peer", ping_b);
    println!("TickHash    {:>6} B  → 2 peers every 6 ticks (anti-entropy probe)", th_b);
    println!("\nframe overhead: {} B per message", FRAME_HEADER);
}
