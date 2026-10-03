// KI#34 WI3 hole-1 — LIVE forged-seq rejection harness.
//
// hole-1: `wallet_seq` is the PRIMARY merge key, and a bare seq gossiped over the
// flood path is forgeable. The fix (merged) makes `apply_state_update` reject a
// seq-ADVANCE unless it carries a valid k=3 receipt-commitment proof. This talks
// to the running mesh over real TCP and proves it end-to-end:
//
//   ATTACK   — establish head Y (seq 0), then gossip a forged head Z at
//              wallet_seq=999 with NO seq_proof  -> mesh REJECTS, head stays Y.
//   CONTROL  — gossip head Z' at wallet_seq=5 WITH a valid self-minted k=3
//              proof (3 distinct Ed25519 keys signing compute_receipt_commitment
//              over the entry's txid+seq, exactly what registration.rs verifies)
//              -> mesh ACCEPTS, head advances to Z'.
//
// Self-contained throwaway wallet (0xD1) + zero client_pk (skips client-sig
// verify, the soak's zero-pk path), so it never touches a real soak wallet and
// is safe to run alongside a live soak.
//
// Usage: ki34_hole1_inject [addr ...]   (default 127.0.0.1:7300..=7309)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use axiom_nabla::transport::WireMessage;
use axiom_nabla::types::{GossipMessage, SeqProof, SeqProofSig};
use axiom_nabla::wire_client::QueryWalletStateRequest;

type B32 = [u8; 32];

/// KI#241 F-2 (2026-10-01): a redeem leg CARRIES its cheque's origin and every
/// node refuses it unless `origin.preimage.txid(origin.epoch) == cheque txid`
/// (`nabla_wire::cheque_origin_matches`). A probe's txid can therefore no
/// longer be an arbitrary literal: the literal is now a TAG, and the txid on
/// the wire is the txid of this probe origin.
fn probe_origin(tag: &[u8; 32]) -> axiom_core_logic::types::OriginRecord {
    axiom_core_logic::types::OriginRecord {
        preimage: axiom_core_logic::types::WitnessPreimage {
            consumed_state_id: *tag, client_pk: [0xEE; 32], wallet_seq: 1,
            receiver_wallet_id: "probe@axiom.internal/0123456789".to_string(), amount: 1_000, nonce: 1,
        },
        epoch: 7,
        kind: axiom_core_logic::types::LegKind::Send,
    }
}

/// The wire txid of probe TAG `tag` (see [`probe_origin`]).
fn probe_txid(tag: &[u8; 32]) -> [u8; 32] {
    let o = probe_origin(tag);
    o.preimage.txid(o.epoch)
}

fn id(tag: u8, w: u8) -> B32 {
    let mut a = [0u8; 32];
    a[0] = tag;
    a[1] = w;
    a
}

fn send_oneway(addr: &str, msg: &WireMessage) {
    if let Ok(mut s) = TcpStream::connect(addr) {
        let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
        let bytes = bincode::serialize(msg).expect("serialize");
        let _ = s.write_all(&(bytes.len() as u32).to_be_bytes());
        let _ = s.write_all(&bytes);
        let _ = s.flush();
    }
}

/// Returns current_state or None on NOT_FOUND / IO error.
fn query_head(addr: &str, wallet: &B32) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(3))).ok()?;
    let req = WireMessage::QueryWalletStateRequest(QueryWalletStateRequest { wallet_pk: *wallet });
    let bytes = bincode::serialize(&req).ok()?;
    s.write_all(&(bytes.len() as u32).to_be_bytes()).ok()?;
    s.write_all(&bytes).ok()?;
    s.flush().ok()?;
    let mut lb = [0u8; 4];
    s.read_exact(&mut lb).ok()?;
    let n = u32::from_be_bytes(lb) as usize;
    if n > 10_000_000 {
        return None;
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).ok()?;
    match bincode::deserialize::<WireMessage>(&buf).ok()? {
        WireMessage::QueryWalletStateResponse(r) => {
            if r.status == "NOT_FOUND" { None } else { Some(r.current_state) }
        }
        _ => None,
    }
}

/// Mint a VALID k=3 seq proof over `(txid, wallet_seq)` — 3 distinct self-made
/// Ed25519 keys signing the same `compute_receipt_commitment`. `verify_seq_proof`
/// counts ≥3 distinct valid sigs over the commitment; it does NOT pin the keys to
/// a known validator set, so a self-minted proof passes exactly as a real one
/// would. (A real attacker can mint this too — but only by ALSO having the
/// matching registered state; here we only assert the GATE's accept/reject, not
/// the broader registration chain.)
fn mint_proof(txid: &B32, wallet_seq: u64, leg_client_pk: B32, leg_consumed: B32, leg_new_state: B32) -> SeqProof {
    use ed25519_dalek::{Signer, SigningKey};
    let tag = txid; // KI#241 F-2: the caller's txid is a TAG
    let txid = &probe_txid(tag);
    let tx_for_leg = txid;
    let (state_hash, epoch, dev) = ([0x5au8; 32], 7u64, false);
    let redeem = axiom_core_logic::types::RedeemPreimage { cheque_txid: *tx_for_leg, receiver_pk: leg_client_pk, new_balance: 0, new_state_id: leg_new_state, consumed_state_id: leg_consumed };
    let commitment_hash = redeem.commitment_hash();
    let c = axiom_core_logic::compute::compute_receipt_commitment(
        txid, &state_hash, wallet_seq, &commitment_hash, epoch, dev,
        None,
        None, // CI — P3.6 trailing arg
        None, // sender_state — §32.3 received-from lineage (38a8cdd6)
    );
    let sigs = (0..3)
        .map(|i| {
            let sk = SigningKey::from_bytes(&[0x50 + i as u8; 32]);
            SeqProofSig {
                validator_pk: sk.verifying_key().to_bytes(),
                receipt_commitment_sig: sk.sign(&c).to_bytes().to_vec(),
            }
        })
        .collect();
    SeqProof { state_hash, commitment_hash, epoch, is_dev_class: dev, sigs, oods_flag: None, confidence_index: None, sender_state: None, required_k: 3, preimage: axiom_nabla::types::LegPreimage::Redeem { redeem, cheque: probe_origin(tag) } /* Fork Settlement W7a: the leg is a GENUINE redeem leg bound to this probe's carrier (cheque_txid = tx, receiver = client_pk, consumed, produced) and the k sign over its recompute — W7a verifies redeem legs on the flood, so the pre-W7a unit `Redeem` ("no preimage") would now be refused at the leg check and this probe would measure THAT instead of its target */, declared: axiom_nabla::types::DeclaredState { balance: 0, wallet_seq: wallet_seq } /* W7b: the seq the k signed rides with a redeem leg */ }
}

fn state_update(w: &B32, new: &B32, tx: &B32, tick: u64, seq: u64, proof: Option<SeqProof>) -> WireMessage {
    WireMessage::Gossip(GossipMessage::StateUpdate {
        old_state: [0u8; 32],
        is_genesis_claim: false,
        wallet_id: *w,
        new_state: *new,
        tx_hash: *tx,
        tick,
        wallet_seq: seq,
        client_pk: [0u8; 32],
        client_sig: vec![0u8; 64],
        amount: 0,
        fee_breakdown: Vec::new(),
        seq_proof: proof,
    })
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}

fn sleep(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let nodes: Vec<String> = if args.is_empty() {
        (7300..=7309).map(|p| format!("127.0.0.1:{p}")).collect()
    } else {
        args
    };
    let n = nodes.len();
    println!("KI#34 WI3 hole-1 live forged-seq rejection against {n} nodes\n");
    let mut failures = 0u32;

    let w = id(0xD1, 0x01);
    let (x, y, z_forged, z_valid) = (id(0xA0, 0x01), id(0xA1, 0x01), id(0xAF, 0x01), id(0xCE, 0x01));
    let tx_y = id(0xB1, 0x01);
    let tx_forged = id(0xBF, 0x01);
    let tag_valid = id(0xBC, 0x01);
    let tx_valid = probe_txid(&tag_valid); // KI#241 F-2

    // ── Setup: head Y at seq 0 (no proof needed; accepted on the tick path) ──
    println!("[setup] establish head Y (seq 0) on all nodes");
    for addr in &nodes {
        send_oneway(addr, &state_update(&w, &x, &id(0xB0, 0x01), 1, 0, None));
        send_oneway(addr, &state_update(&w, &y, &tx_y, 2, 0, None));
    }
    sleep(1000);

    let count_head = |target: &B32| -> usize {
        nodes.iter().filter(|a| query_head(a, &w).as_deref() == Some(target.as_ref())).count()
    };
    let base_y = count_head(&y);
    println!("  -> {base_y}/{n} nodes hold head Y ({})\n", hex8(&y));

    // ── ATTACK: forged high seq, NO proof — must be REJECTED (head stays Y) ──
    println!("[attack] gossip forged head Z @ wallet_seq=999, NO seq_proof");
    for addr in &nodes {
        send_oneway(addr, &state_update(&w, &z_forged, &tx_forged, 50, 999, None));
    }
    sleep(1200);
    let still_y = count_head(&y);
    let took_forged = count_head(&z_forged);
    if took_forged == 0 && still_y >= base_y.max(1) {
        println!("  [PASS] forged seq REJECTED — {still_y}/{n} still Y, 0 adopted Z'\n");
    } else {
        println!("  [FAIL] forged seq leaked — {took_forged}/{n} adopted forged Z (head should stay Y)\n");
        failures += 1;
    }

    // ── CONTROL: valid k=3-proven seq advance — must be ACCEPTED (head -> Z') ──
    println!("[control] gossip head Z' @ wallet_seq=5 WITH a valid k=3 proof");
    // The carrier: zero client_pk, parent unknown ([0; 32]), produced z_valid (see `state_update`).
    let proof = mint_proof(&tag_valid, 5, [0u8; 32], [0u8; 32], z_valid);
    for addr in &nodes {
        send_oneway(addr, &state_update(&w, &z_valid, &tx_valid, 60, 5, Some(proof.clone())));
    }
    sleep(1200);
    let took_valid = count_head(&z_valid);
    if took_valid >= 1 {
        println!("  [PASS] proven seq ACCEPTED — {took_valid}/{n} advanced to Z' ({})\n", hex8(&z_valid));
    } else {
        println!("  [FAIL] proven seq rejected — 0/{n} advanced (gate too strict)\n");
        failures += 1;
    }

    if failures == 0 {
        println!("KI#34 hole-1 LIVE: PASS — bare forged seq dropped, k=3-proven seq adopted");
    } else {
        println!("KI#34 hole-1 LIVE: {failures} FAILURE(S)");
        std::process::exit(1);
    }
}
