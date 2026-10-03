// §32.3 LIVE forced-fork taint injection — over real TCP against an ISOLATED
// nabla-node (the deployed binary). Proves the deployed merge-quarantine →
// fork-scan → received_from taint → restore chain end to end on the wire.
//
// Requires TWO real peer identities the isolated node warm-loaded into its
// verified_nbcs (from a copied snapshot): their `validator_id` (the TickHash
// node_pk) and their `nabla_ed25519.key` (32-byte seed) to sign the TickHash.
// The isolated node is NOT joined to the live mesh, so nothing here touches it.
//
// Scenario:
//   1. Establish S (source) at state X  — authored + k=3 attested.
//   2. Establish R (receiver) whose k=3 SeqProof carries sender_state = X, so
//      the deployed apply_state_update sets R.received_from = X.
//   3. Two CONFLICTING signed TickHash advertisements (same tick, different
//      roots, two distinct verified peers) → node enters merge quarantine.
//   4. A DIVERGENT StateUpdate for S (state X') during quarantine → the §32
//      scan detects the fork → handle_fork_evidence → propagate_taint seeds
//      {X, X'} → R.received_from == X is TAINTED.
//   5. Assert over the wire: R.status == Tainted, S frozen/banned.
//
// Usage:
//   taint_socket_inject <addr> <vid1_hex> <key1> <vid2_hex> <key2>

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use axiom_nabla::crypto::tickhash_sign_payload;
use axiom_nabla::gossip::client_state_sign_payload;
use axiom_nabla::transport::WireMessage;
use axiom_nabla::types::{GossipMessage, SeqProof, SeqProofSig};
use axiom_nabla::wire_client::QueryWalletStateRequest;
use ed25519_dalek::{Signer as _, SigningKey};

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

fn b(tag: u8) -> B32 { let mut a = [0u8; 32]; a[0] = tag; a }

fn send(addr: &str, msg: &WireMessage) {
    let bytes = bincode::serialize(msg).expect("serialize");
    for _ in 0..4 {
        if let Ok(mut s) = TcpStream::connect(addr) {
            let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
            if s.write_all(&(bytes.len() as u32).to_be_bytes()).is_ok()
                && s.write_all(&bytes).is_ok() && s.flush().is_ok() { return; }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    panic!("send failed to {addr}");
}

fn query(addr: &str, wallet: &B32) -> Option<(String, Vec<u8>)> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(2000))).ok()?;
    s.set_write_timeout(Some(Duration::from_millis(2000))).ok()?;
    let req = WireMessage::QueryWalletStateRequest(QueryWalletStateRequest { wallet_pk: *wallet });
    let bytes = bincode::serialize(&req).ok()?;
    s.write_all(&(bytes.len() as u32).to_be_bytes()).ok()?;
    s.write_all(&bytes).ok()?; s.flush().ok()?;
    let mut lb = [0u8; 4]; s.read_exact(&mut lb).ok()?;
    let n = u32::from_be_bytes(lb) as usize;
    if n > 10_000_000 { return None; }
    let mut buf = vec![0u8; n]; s.read_exact(&mut buf).ok()?;
    match bincode::deserialize::<WireMessage>(&buf).ok()? {
        WireMessage::QueryWalletStateResponse(r) =>
            if r.status == "NOT_FOUND" { None } else { Some((r.wallet_status, r.current_state)) },
        _ => None,
    }
}

/// k=3 SeqProof over compute_receipt_commitment(tx, .., sender_state), folded
/// exactly as Core CL5 does so verify_seq_proof's recompute matches.
fn seqproof(tx: &B32, seq: u64, sender_state: Option<&B32>, leg_client_pk: B32, leg_consumed: B32, leg_new_state: B32) -> SeqProof {
    let tag = tx; // KI#241 F-2: the caller's tx is a TAG
    let tx = &probe_txid(tag);
    let tx_for_leg = tx;
    let (state_hash, epoch, is_dev_class) = ([0x5au8; 32], 7u64, false);
    let redeem = axiom_core_logic::types::RedeemPreimage { cheque_txid: *tx_for_leg, receiver_pk: leg_client_pk, new_balance: 0, new_state_id: leg_new_state, consumed_state_id: leg_consumed };
    let commitment_hash = redeem.commitment_hash();
    let commitment = axiom_core_logic::compute::compute_receipt_commitment(
        tx, &state_hash, seq, &commitment_hash, epoch, is_dev_class, None, None, sender_state);
    let sigs = (0..3).map(|i| {
        let sk = SigningKey::from_bytes(&[0x10 + i as u8; 32]);
        SeqProofSig { validator_pk: sk.verifying_key().to_bytes(), receipt_commitment_sig: sk.sign(&commitment).to_bytes().to_vec() }
    }).collect();
    SeqProof { state_hash, commitment_hash, epoch, is_dev_class, oods_flag: None, confidence_index: None, sigs, sender_state: sender_state.copied(), required_k: 3, preimage: axiom_nabla::types::LegPreimage::Redeem { redeem, cheque: probe_origin(tag) } /* Fork Settlement W7a: the leg is a GENUINE redeem leg bound to this probe's carrier (cheque_txid = tx, receiver = client_pk, consumed, produced) and the k sign over its recompute — W7a verifies redeem legs on the flood, so the pre-W7a unit `Redeem` ("no preimage") would now be refused at the leg check and this probe would measure THAT instead of its target */, declared: axiom_nabla::types::DeclaredState { balance: 0, wallet_seq: seq } /* W7b: the seq the k signed rides with a redeem leg */ }
}

/// Authored StateUpdate. `sender_state` = Some → its SeqProof carries the §32.3
/// lineage (sets received_from on apply).
fn state_update(wid: &B32, new_state: &B32, old_state: &B32, seq: u64, tick: u64, sender_state: Option<&B32>) -> WireMessage {
    // tx_hash is the wallet's own redeem txid — deliberately NOT the sender state.
    let mut tag = [0u8; 32]; tag[0] = wid[0] ^ new_state[0]; tag[1] = new_state[0]; tag[31] = 0xAA;
    let tx = probe_txid(&tag); // KI#241 F-2
    // Wallet authorship (KI#46): non-zero client_pk + valid client_sig, key derived from wid[0].
    let wallet_sk = SigningKey::from_bytes(&[wid[0].wrapping_add(0xC0); 32]);
    let client_pk = wallet_sk.verifying_key().to_bytes();
    let proof = seqproof(&tag, seq, sender_state, client_pk, *old_state, *new_state);
    let payload = client_state_sign_payload(wid, new_state, &tx);
    let client_sig = wallet_sk.sign(&payload).to_bytes().to_vec();
    WireMessage::Gossip(GossipMessage::StateUpdate {
        old_state: *old_state, wallet_seq: seq, seq_proof: Some(proof),
        wallet_id: *wid, new_state: *new_state, tx_hash: tx, tick,
        is_genesis_claim: false, client_pk, client_sig, amount: 0, fee_breakdown: Vec::new(),
    })
}

/// A signed TickHash advertisement AS a verified peer (node_pk = its validator_id,
/// signed with its ed25519 key). Two conflicting ones trip merge quarantine.
fn tickhash(node_pk: &B32, key: &SigningKey, tick: u64, root: &B32) -> WireMessage {
    let payload = tickhash_sign_payload(tick, root, node_pk);
    let sig = key.sign(&payload).to_bytes().to_vec();
    WireMessage::Gossip(GossipMessage::TickHash { tick, root_hash: *root, node_pk: *node_pk, signature: sig })
}

fn load_key(path: &str) -> SigningKey {
    let seed = std::fs::read(path).unwrap_or_else(|e| panic!("read key {path}: {e}"));
    let arr: [u8; 32] = seed.as_slice().try_into().expect("ed25519 key must be 32 bytes");
    SigningKey::from_bytes(&arr)
}

fn hex32(s: &str) -> B32 {
    let v = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect::<Vec<_>>();
    let mut a = [0u8; 32]; a.copy_from_slice(&v[..32]); a
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 { eprintln!("usage: {} <addr> <vid1_hex> <key1> <vid2_hex> <key2>", args[0]); std::process::exit(2); }
    let addr = &args[1];
    let (vid1, key1) = (hex32(&args[2]), load_key(&args[3]));
    let (vid2, key2) = (hex32(&args[4]), load_key(&args[5]));

    // Distinct throwaway ids (won't collide with the copied snapshot's real wallets).
    let s_wid = b(0xE1);          // source S
    let base = b(0xE0);           // S's base state B (the fork's shared parent)
    let x = b(0xE2);              // S's state X (consumes B; the tainted lineage)
    let x_prime = b(0xE3);        // S's divergent fork state X' (also consumes B)
    let r_wid = b(0xE4);          // receiver R
    let r_state = b(0xE5);        // R's own state
    let root1 = b(0xF1);          // conflicting advertised roots (≠ node's real root)
    let root2 = b(0xF2);
    let tick = 9_000_000u64;

    println!("── §32.3 live forced-fork taint (isolated node {addr}) ──");

    // 1. 3-step provable-fork setup (dsfork DS-POS shape): base B, then X
    // consuming B (adoption records previous_states[S]=B), so a later X' also
    // consuming B at the SAME seq is a PROVEN same-parent double-spend. Plus R
    // with received_from = X (via its SeqProof.sender_state).
    send(addr, &state_update(&s_wid, &base, &b(0x00), 4, tick - 2, None)); // base B @ seq 4
    std::thread::sleep(Duration::from_millis(150));
    send(addr, &state_update(&s_wid, &x, &base, 5, tick, None));           // X consumes B @ seq 5
    send(addr, &state_update(&r_wid, &r_state, &b(0x00), 5, tick, Some(&x)));
    std::thread::sleep(Duration::from_millis(400));
    let up = |o: Option<String>| o.map(|s| s.to_uppercase());
    let s0 = up(query(addr, &s_wid).map(|(st,_)| st));
    let r0 = up(query(addr, &r_wid).map(|(st,_)| st));
    println!("[1] established: S={s0:?}  R={r0:?}");
    assert!(s0.is_some() && r0.is_some(), "S and R must register (authored + attested)");
    assert_eq!(r0.as_deref(), Some("NORMAL"), "R starts Normal (received_from set, not yet tainted)");

    let s_cur = query(addr, &s_wid).map(|(_,c)| c.iter().take(2).map(|b| format!("{b:02x}")).collect::<String>());
    println!("    S held state = {s_cur:?} (want 'e200…')");

    // 2. Two conflicting signed TickHash → the node enters merge quarantine.
    // Then IMMEDIATELY (no delay — quarantine TTL is short in dev) inject the
    // divergent X' so the §32 scan runs while in_quarantine.
    send(addr, &tickhash(&vid1, &key1, tick, &root1));
    send(addr, &tickhash(&vid2, &key2, tick, &root2));
    println!("[2] injected 2 conflicting TickHash (peers {:02x}.. / {:02x}..) → expect quarantine", vid1[0], vid2[0]);

    // 3. Divergent X' — consumes the SAME parent B at the SAME seq 5 as X: a
    // PROVEN same-parent double-spend. apply_state_update bans S (and stays at X).
    send(addr, &state_update(&s_wid, &x_prime, &base, 5, tick + 1, None));
    std::thread::sleep(Duration::from_millis(500));
    let s_mid = up(query(addr, &s_wid).map(|(st,_)| st));
    println!("[3] injected S's divergent X' (provable fork) → S={s_mid:?}");

    // 4. Propagate the taint downstream exactly as the real mesh does: a
    // TaintAlert(victim=R, source=S). The deployed g2 confirm path
    // (gossip.rs:815) accepts it ONLY because S is locally Banned AND
    // propagate_taint re-derives R from S via R.received_from == X. This is the
    // §32.3 received_from edge firing over the wire on the deployed binary.
    let taint_alert = WireMessage::Gossip(GossipMessage::TaintAlert {
        wallet_id: r_wid, tainted_source: s_wid, detected_at_tick: tick,
    });
    send(addr, &taint_alert);
    std::thread::sleep(Duration::from_millis(600));
    println!("[4] injected TaintAlert(R←S) — expect R Tainted iff received_from(R)==S's state");

    // 5. Assert over the wire.
    let s_q = query(addr, &s_wid);
    let s_final = up(s_q.clone().map(|(st,_)| st));
    let s_state = s_q.map(|(_,c)| c.iter().take(2).map(|b| format!("{b:02x}")).collect::<String>());
    let r_final = up(query(addr, &r_wid).map(|(st,_)| st));
    println!("[5] RESULT: S={s_final:?} (state={s_state:?}, held X=e200)  R={r_final:?}");

    let s_ok = matches!(s_final.as_deref(), Some("FROZEN") | Some("BANNED"));
    let r_ok = r_final.as_deref() == Some("TAINTED");
    if s_ok && r_ok {
        println!("✓ §32.3 LIVE: fork source {s_final:?}, downstream received_from wallet TAINTED — taint propagated over the wire on the deployed binary");
        std::process::exit(0);
    } else {
        eprintln!("✗ FAIL: expected S∈{{Frozen,Banned}} and R==Tainted; got S={s_final:?} R={r_final:?}");
        std::process::exit(1);
    }
}
