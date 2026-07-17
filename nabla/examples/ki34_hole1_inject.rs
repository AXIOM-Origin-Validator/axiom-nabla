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
fn mint_proof(txid: &B32, wallet_seq: u64) -> SeqProof {
    use ed25519_dalek::{Signer, SigningKey};
    let (state_hash, commitment_hash, epoch, dev) = ([0x5au8; 32], [0x7cu8; 32], 7u64, false);
    let c = axiom_core_logic::compute::compute_receipt_commitment(
        txid, &state_hash, wallet_seq, &commitment_hash, epoch, dev,
        None,
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
    SeqProof { state_hash, commitment_hash, epoch, is_dev_class: dev, sigs, oods_flag: None }
}

fn state_update(w: &B32, new: &B32, tx: &B32, tick: u64, seq: u64, proof: Option<SeqProof>) -> WireMessage {
    WireMessage::Gossip(GossipMessage::StateUpdate {
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
    let tx_valid = id(0xBC, 0x01);

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
    let proof = mint_proof(&tx_valid, 5);
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
