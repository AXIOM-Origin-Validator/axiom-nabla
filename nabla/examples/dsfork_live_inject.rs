// ⚠ RETIRED DETECTOR (2026-09-30, Fork Settlement §9o [R56], W2 — KI#235): this
// harness drives check-3, the `previous_states`-based seq-fork ban that flooded
// `SeqForkBan`. check-3 is DELETED and `SeqForkBan` is a dropped, counted
// tombstone (`seqforkban_dropped`), so on a W2+ build its positive scenario does
// NOT ban — read its output as history, not as a gate. Forks are judged only on
// self-proving `ForkClaim` evidence (`ban::verify_fork_claim`); the in-process
// gate is `nabla/src/fork_detection_mesh.rs` (S1–S13, fork_retire_proof_*), the
// live lost-flood gate mode is still owed (§9o proof obligations).
//
// Double-spend (seq-fork) ban — LIVE positive/negative injection harness.
//
// Talks to a running nabla-node mesh over real TCP (length-prefixed bincode
// WireMessage), exercising the deployed double-spend ban-origination path end to
// end: real binary, real serialization of the StateUpdate + SeqForkBan variants,
// real verify_seq_proof (k=3 Ed25519 receipt-commitment sigs) AND the new
// anti-framing authorship gate (client_pk != 0 + valid client_sig).
//
// Self-contained: it establishes a throwaway wallet's mesh state by injecting
// StateUpdate gossip directly, so it never touches a real soak wallet. The k=3
// SeqProof sigs and the wallet authorship sig are self-generated Ed25519 keypairs
// that verify under the carried pks exactly as the shipped verifiers check them,
// hitting the identical code path a genuine cross-node double-spend would.
//
// SHAPE (KI#46 check-3 alignment, reworked 2026-07-30): a ban requires a PROVEN
// same-parent fork — the incoming update's `old_state` must equal the receiving
// node's authoritative `previous_states[W]`. So every scenario is 3-STEP:
//   1. base X at seq-1              (establish the wallet)
//   2. A' consuming X at seq        (ADOPTION records previous_states[W] = X —
//                                    `put()` records a parent only on REPLACE)
//   3. B' also consuming X at seq   (two children of X = the provable fork)
// The pre-rework harness injected parent-less A/B pairs, which correctly no
// longer banned, making every ban assertion vacuous.
//
// Scenarios (all assert via QueryWalletStateRequest across EVERY node):
//   DS-POS    3-step, both k3-attested + WALLET-AUTHORED -> every node BANS the
//             wallet (status flips to BANNED so §4.6 reads it). The
//             inflation-closing positive path.
//   DS-FORGE  same shape but client_pk=0 / no client_sig (the framing attack:
//             forged validator sigs on a victim's wallet_id) -> post-KI#46
//             zero-pk flip the update is DROPPED outright (YPX-009 enforced), so
//             no entry ever exists and no ban can be framed.
//   DS-ADV    A' at seq=5 (parent X) then B' at a HIGHER seq=6 (parent A') ->
//             normal sequential advance, NOT banned.
//   DS-CONT   A' at seq=5 (parent X) then B' at the SAME seq=5 with parent A'
//             (the held head) -> a redeem's chain continuation, NOT banned. This
//             is the shape that false-banned honest wallet A in gate run
//             1785338039 (Core keeps wallet_seq unchanged on receive).
//   DS-SUBQ   same-parent conflict at seq=5 with only k=2 sigs -> sub-quorum, the
//             fork is unprovable, NOT banned.
//
// Usage: dsfork_live_inject [addr ...]   (default 127.0.0.1:7300..=7309)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axiom_nabla::crypto::{Ed25519Signer, Signer};
use axiom_nabla::gossip::client_state_sign_payload;
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

// Per-run nonce stamped into byte [2] of every id, so each run targets brand-new
// wallet/state ids and never collides with a wallet a prior run already banned
// (an irreversible ban would otherwise wedge a re-run at NOT_FOUND forever).
static RUN_NONCE: AtomicU8 = AtomicU8::new(0);

fn id(tag: u8, w: u8) -> B32 {
    let mut a = [0u8; 32];
    a[0] = tag;
    a[1] = w;
    a[2] = RUN_NONCE.load(Ordering::Relaxed);
    a
}

fn send_oneway(addr: &str, msg: &WireMessage) {
    // Retry the connect: under soak load a single connect can time out and the
    // inject is silently lost, which surfaces later as a spurious NOT_FOUND.
    let bytes = bincode::serialize(msg).expect("serialize");
    for _ in 0..4 {
        if let Ok(mut s) = TcpStream::connect(addr) {
            let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
            if s.write_all(&(bytes.len() as u32).to_be_bytes()).is_ok()
                && s.write_all(&bytes).is_ok()
                && s.flush().is_ok()
            {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(120));
    }
}

/// Returns (wallet_status, current_state) or None on NOT_FOUND / IO error.
fn query(addr: &str, wallet: &B32) -> Option<(String, Vec<u8>)> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(1500))).ok()?;
    s.set_write_timeout(Some(Duration::from_millis(1500))).ok()?;
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
            if r.status == "NOT_FOUND" {
                None
            } else {
                Some((r.wallet_status, r.current_state))
            }
        }
        _ => None,
    }
}

/// k=`n` SeqProof over `compute_receipt_commitment(tx, …, wallet_seq, …)`, signed
/// by `n` distinct self-generated Ed25519 keypairs (mirrors the shipped
/// verify_seq_proof inputs exactly).
fn mint_seq_proof(tx: &B32, wallet_seq: u64, n: usize, leg_client_pk: B32, leg_consumed: B32, leg_new_state: B32) -> SeqProof {
    let tag = tx; // KI#241 F-2: the caller's tx is a TAG
    let tx = &probe_txid(tag);
    let tx_for_leg = tx;
    let state_hash = [0x5a_u8; 32];
    let redeem = axiom_core_logic::types::RedeemPreimage { cheque_txid: *tx_for_leg, receiver_pk: leg_client_pk, new_balance: 0, new_state_id: leg_new_state, consumed_state_id: leg_consumed };
    let commitment_hash = redeem.commitment_hash();
    let (epoch, is_dev_class) = (7u64, false);
    let commitment = axiom_core_logic::compute::compute_receipt_commitment(
        tx, &state_hash, wallet_seq, &commitment_hash, epoch, is_dev_class,
        None,
        None, // CI — P3.6 trailing arg
        None, // §32.3 sender_state — send/inject path, no lineage
    );
    let sigs = (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = 0x10 + i as u8;
            seed[1] = tx[1];
            let signer = Ed25519Signer::from_seed(&seed);
            SeqProofSig {
                validator_pk: signer.public_key_bytes(),
                receipt_commitment_sig: signer.sign(&commitment),
            }
        })
        .collect();
    SeqProof { state_hash, commitment_hash, epoch, is_dev_class, sigs, oods_flag: None, confidence_index: None, sender_state: None, required_k: 3, preimage: axiom_nabla::types::LegPreimage::Redeem { redeem, cheque: probe_origin(tag) } /* Fork Settlement W7a: the leg is a GENUINE redeem leg bound to this probe's carrier (cheque_txid = tx, receiver = client_pk, consumed, produced) and the k sign over its recompute — W7a verifies redeem legs on the flood, so the pre-W7a unit `Redeem` ("no preimage") would now be refused at the leg check and this probe would measure THAT instead of its target */, declared: axiom_nabla::types::DeclaredState { balance: 0, wallet_seq: wallet_seq } /* W7b: the seq the k signed rides with a redeem leg */ }
}

/// A StateUpdate carrying a k=`n` SeqProof for (wid, new_state, wallet_seq). When
/// `wallet` is Some, it is wallet-AUTHORED (non-zero client_pk + a valid client_sig
/// over the §32 wallet-state payload); when None, it is forged/unauthored (zero pk).
///
/// `old_state` is the PARENT this advance consumed — load-bearing since the KI#46
/// check-3 alignment: the dsfork ban fires only when `old_state` equals the
/// receiving node's authoritative `previous_states[W]`. All-zero = parent unknown
/// (never ban material). Hence the 3-step scenario shape below: establish base X,
/// adopt A′ consuming X (which is what makes the node record X as W's parent —
/// `put()` records a parent only when REPLACING an entry), then inject B′ also
/// consuming X. Two children of X at the same seq = the provable double-spend.
#[allow(clippy::too_many_arguments)]
fn seq_update(
    wallet: Option<&Ed25519Signer>,
    wid: &B32,
    new_state: &B32,
    old_state: &B32,
    tx: &B32,
    tick: u64,
    wallet_seq: u64,
    n_sigs: usize,
) -> WireMessage {
    let tag = tx; // KI#241 F-2: the caller's tx is a TAG; the wire txid is its probe origin's
    let tx = &probe_txid(tag);
    let (client_pk, client_sig) = match wallet {
        Some(sk) => {
            let payload = client_state_sign_payload(wid, new_state, tx);
            (sk.public_key_bytes(), sk.sign(&payload))
        }
        None => ([0u8; 32], vec![0u8; 64]),
    };
    let proof = mint_seq_proof(tag, wallet_seq, n_sigs, client_pk, *old_state, *new_state);
    WireMessage::Gossip(GossipMessage::StateUpdate {
        is_genesis_claim: false,
        wallet_id: *wid,
        new_state: *new_state,
        old_state: *old_state,
        tx_hash: *tx,
        tick,
        wallet_seq,
        seq_proof: Some(proof),
        client_pk,
        client_sig,
        amount: 0,
        fee_breakdown: Vec::new(),
    })
}

/// Zero id — "no parent" (`old_state` unknown), used for a base establishment.
fn no_parent() -> B32 {
    [0u8; 32]
}

fn sleep(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

fn hex16(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let nodes: Vec<String> = if args.is_empty() {
        (7300..=7309).map(|p| format!("127.0.0.1:{p}")).collect()
    } else {
        args
    };
    let nonce = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
        & 0xff) as u8;
    RUN_NONCE.store(nonce, Ordering::Relaxed);
    println!(
        "double-spend ban LIVE injection against {} nodes (run nonce {:#04x}): {:?}\n",
        nodes.len(),
        nonce,
        nodes
    );
    let mut failures = 0u32;
    let mode = std::env::var("AXIOM_DSFORK_MODE").unwrap_or_default();
    let prop_mode = mode == "prop";

    // QUERY mode: one-shot status of a given wallet across all nodes (no inject).
    // Used to observe cross-node propagation of a ban originated elsewhere.
    // AXIOM_DSFORK_WID = hex of the leading wallet_id bytes (rest zero-padded).
    if mode == "query" {
        let hexw = std::env::var("AXIOM_DSFORK_WID").unwrap_or_default();
        let mut w = [0u8; 32];
        let bytes: Vec<u8> = (0..hexw.len() / 2)
            .map(|i| u8::from_str_radix(&hexw[2 * i..2 * i + 2], 16).unwrap_or(0))
            .collect();
        w[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        println!("[QUERY] wallet {} across {} nodes:", hexw, nodes.len());
        let mut banned = 0usize;
        for addr in &nodes {
            match query(addr, &w) {
                Some((s, head)) => {
                    // `head=` is load-bearing for the CLARA propagation gate:
                    // status alone cannot tell you WHICH head a node holds, so a
                    // mesh that is converged and one that is split both read
                    // "NORMAL" everywhere.
                    println!("  {addr}: {s} head={}", hex16(&head));
                    if s == "BANNED" {
                        banned += 1;
                    }
                }
                None => println!("  {addr}: NOT_FOUND"),
            }
        }
        println!("[QUERY] BANNED on {}/{} nodes", banned, nodes.len());
        return;
    }

    // Establish the first update mesh-wide BEFORE injecting the conflict,
    // RE-INJECTING `msg` to any node still missing it each round. One-way gossip
    // injects are lossy against a soak-saturated recv loop (the node's gossip
    // queue drops them under backpressure), so a single send isn't enough; we
    // retry per-node until the entry sticks everywhere. This also closes the
    // SeqForkBan-races-ahead-of-own-first-update window (a harness artifact, not a
    // protocol gap): with A' present on every node first, the ban always has an
    // SMT entry to flip.
    let establish = |w: &B32, msg: &WireMessage| -> bool {
        for _ in 0..30 {
            let missing: Vec<&String> =
                nodes.iter().filter(|a| query(a, w).is_none()).collect();
            if missing.is_empty() {
                return true;
            }
            for a in &missing {
                send_oneway(a, msg);
            }
            sleep(400);
        }
        false
    };

    // Establish a SPECIFIC head mesh-wide. Presence alone is not enough for the
    // 3-step fork shape: step 2 (A′ consuming X) must actually REPLACE X on every
    // node, because `put()` records `previous_states[W]` only on replacement —
    // that recorded parent is the exact discriminator the ban predicate needs.
    // Polls each node's head and re-injects to the ones not yet holding `want`.
    let establish_head = |w: &B32, want: &B32, msg: &WireMessage| -> bool {
        for _ in 0..30 {
            let behind: Vec<&String> = nodes
                .iter()
                .filter(|a| !matches!(query(a, w), Some((_, head)) if head == want.as_slice()))
                .collect();
            if behind.is_empty() {
                return true;
            }
            for a in &behind {
                send_oneway(a, msg);
            }
            sleep(400);
        }
        false
    };

    // Assert every node reports `want_status`, polling to absorb propagation lag.
    // `reinject` (the conflict message) is re-sent to any node not yet matching —
    // defeats lossy one-way injects: a node that has A' but missed B' (and the
    // SeqForkBan flood) re-detects locally on the resend. Re-injecting to an
    // already-banned node is a harmless Duplicate.
    let assert_all = |label: &str, w: &B32, want_status: &str, reinject: Option<&WireMessage>, fails: &mut u32| {
        let mut last: Vec<String> = Vec::new();
        for _ in 0..40 {
            last.clear();
            let mut all_ok = true;
            for addr in &nodes {
                match query(addr, w) {
                    Some((status, _)) if status == want_status => {}
                    Some((status, head)) => {
                        all_ok = false;
                        if let Some(m) = reinject {
                            send_oneway(addr, m);
                        }
                        last.push(format!("{addr} status={status:?} head={}", hex16(&head)));
                    }
                    None => {
                        all_ok = false;
                        if let Some(m) = reinject {
                            send_oneway(addr, m);
                        }
                        last.push(format!("{addr} NOT_FOUND"));
                    }
                }
            }
            if all_ok {
                println!("  [PASS] {label}: all {} nodes report {want_status}", nodes.len());
                return;
            }
            sleep(350);
        }
        println!("  [FAIL] {label}: want {want_status} — stragglers: {}", last.join(", "));
        *fails += 1;
    };

    // ── FUNDED — ban a REAL funded SDK wallet by injecting an S-AUTHORED seq-fork.
    // The Python funded harness (tests/dsfork_funded_repro.py) funds S for real, does
    // ONE real send (a real cheque to a receiver), then calls this mode to author +
    // inject a conflicting successor PAIR at a fresh seq using S's OWN Ed25519 key
    // (the anti-framing authorship gate is satisfied because S IS the adversary — the
    // model's "sender is the adversary"; a real funded wallet double-spending its own
    // state is legitimate, not framing). Nabla SeqForkBans S's real wallet_pk → the
    // receiver's real cheque becomes unredeemable (§4.6), which the Python side then
    // verifies + reads final balances (credited must be 0 → no inflation). The second
    // fork is injected to nabla (not organically witnessed) because an organic
    // two-both-witnessed fork is impossible on a connected mesh (S-ABR overlap); the
    // injection is the faithful single-host stand-in for the partition/collusion case.
    //   AXIOM_DSFORK_WID  = hex of S.public_key (32-byte wallet_id)
    //   AXIOM_DSFORK_SEED = hex of S.private_key (32-byte Ed25519 seed)
    //   AXIOM_DSFORK_SEQ  = seq at which to author the fork (S's current wallet_seq)
    if mode == "funded" {
        let hex_b32 = |v: &str| -> B32 {
            let mut w = [0u8; 32];
            let bytes: Vec<u8> = (0..v.len() / 2)
                .map(|i| u8::from_str_radix(&v[2 * i..2 * i + 2], 16).unwrap_or(0))
                .collect();
            let n = bytes.len().min(32);
            w[..n].copy_from_slice(&bytes[..n]);
            w
        };
        let wid = hex_b32(&std::env::var("AXIOM_DSFORK_WID").unwrap_or_default());
        let seed = hex_b32(&std::env::var("AXIOM_DSFORK_SEED").unwrap_or_default());
        let seq: u64 = std::env::var("AXIOM_DSFORK_SEQ")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let signer = Ed25519Signer::from_seed(&seed);
        let derived = signer.public_key_bytes();
        println!("[FUNDED] target wid={} seq={}", hex16(&wid), seq);
        if derived != wid {
            println!(
                "  [WARN] from_seed → pk={} != wid={} — SDK Ed25519 derivation differs; the \
                 authorship gate (client_pk==wallet_id) will reject. Need a Python-signed payload.",
                hex16(&derived),
                hex16(&wid)
            );
        }
        // Two S-authored conflicting successors at the SAME seq, BOTH consuming
        // the same parent X (KI#46 check-3: only a same-parent fork is provable).
        // X is injected first so every node records previous_states[S] = X when it
        // adopts A′; B′ then re-consumes X = the provable double-spend.
        let (x, a, b) = (id(0xF5, 0x01), id(0xA5, 0x01), id(0xB5, 0x01));
        let (txx, txa, txb) = (id(0x04, 0x01), id(0x05, 0x01), id(0x06, 0x01));
        let x_msg = seq_update(Some(&signer), &wid, &x, &no_parent(), &txx, 9, seq.saturating_sub(1), 3);
        let a_msg = seq_update(Some(&signer), &wid, &a, &x, &txa, 10, seq, 3);
        let b_msg = seq_update(Some(&signer), &wid, &b, &x, &txb, 11, seq, 3);
        // Establish base X, then A′ as the adopted head (records the parent), then B′.
        establish(&wid, &x_msg);
        if !establish_head(&wid, &a, &a_msg) {
            println!("  [WARN] FUNDED: A' (parent X) not adopted everywhere — fork unprovable on stragglers");
        }
        for addr in &nodes {
            send_oneway(addr, &b_msg);
        }
        assert_all("FUNDED-BAN", &wid, "BANNED", Some(&b_msg), &mut failures);
        let banned = nodes
            .iter()
            .filter(|a| matches!(query(a, &wid), Some((s, _)) if s == "BANNED"))
            .count();
        println!(
            "[FUNDED] BANNED on {}/{} nodes  failures={}",
            banned,
            nodes.len(),
            failures
        );
        std::process::exit(if banned >= 1 { 0 } else { 1 });
    }

    // ── PROP — CROSS-NODE propagation: inject the double-spend to ONE node, the
    // ban must FLOOD (SeqForkBan) to every node and flip each entry to BANNED.
    // This is the cross-node case the fix targets: the two conflicting registers
    // land on different nodes; one detects + bans + floods; the rest independently
    // re-verify the SeqConflictProof and ban. We inject A' (establish on node[0])
    // then B' to node[0] ONLY, then assert BANNED on ALL nodes (re-inject B' to
    // node[0] each round to defeat lossy one-way injects, NOT to the others — the
    // others must learn the ban purely via propagation).
    if prop_mode {
        let wallet = Ed25519Signer::from_seed(&[0xCC; 32]);
        let w = id(0xDC, 0x09);
        let (x, a, b) = (id(0xFC, 0x09), id(0xAC, 0x09), id(0xBC, 0x09));
        let (txx, txa, txb) = (id(0x0B, 0x09), id(0x0C, 0x09), id(0x0D, 0x09));
        println!("[PROP] cross-node: inject 3-step double-spend to node[0] only; Banned status must reach all {} nodes", nodes.len());
        // NOTE (KI#46 follow-up 2): SeqForkBan remote ADOPTION was removed as
        // unsound (remote evidence lacks parent binding). node[0] detects the
        // fork LOCALLY and flips its entry to Banned; the rest learn via the
        // merge's Banned-rank monotonicity as that entry replicates — not by
        // adopting packaged evidence. That is what this scenario now measures.
        let x_msg = seq_update(Some(&wallet), &w, &x, &no_parent(), &txx, 9, 4, 3);
        let a_msg = seq_update(Some(&wallet), &w, &a, &x, &txa, 10, 5, 3);
        // establish base X then A' on node[0] only (it is the detector — it must
        // hold previous_states[W]=X); other nodes learn via gossip.
        for _ in 0..30 {
            if query(&nodes[0], &w).is_some() { break; }
            send_oneway(&nodes[0], &x_msg);
            sleep(400);
        }
        for _ in 0..30 {
            if matches!(query(&nodes[0], &w), Some((_, head)) if head == a.as_slice()) { break; }
            send_oneway(&nodes[0], &a_msg);
            sleep(400);
        }
        let b_msg = seq_update(Some(&wallet), &w, &b, &x, &txb, 11, 5, 3);
        send_oneway(&nodes[0], &b_msg);
        // assert BANNED on ALL nodes; reinject the conflict to node[0] only.
        let node0 = nodes[0].clone();
        let b_for_node0 = b_msg.clone();
        let mut last: Vec<String> = Vec::new();
        let mut banned_count = 0usize;
        for _ in 0..50 {
            last.clear();
            banned_count = 0;
            for addr in &nodes {
                match query(addr, &w) {
                    Some((s, _)) if s == "BANNED" => banned_count += 1,
                    Some((s, _)) => last.push(format!("{addr}={s}")),
                    None => last.push(format!("{addr}=NF")),
                }
            }
            if banned_count == nodes.len() {
                break;
            }
            send_oneway(&node0, &b_for_node0); // drive node[0] only; rest must propagate
            sleep(400);
        }
        if banned_count == nodes.len() {
            println!("  [PASS] PROP: ban propagated to ALL {}/{} nodes from a single injection point", banned_count, nodes.len());
        } else {
            println!("  [FAIL] PROP: only {}/{} nodes BANNED — non-banned: {}", banned_count, nodes.len(), last.join(", "));
            failures += 1;
        }
        println!();
        if failures == 0 {
            println!("DOUBLE-SPEND BAN LIVE (prop): PASS");
        } else {
            println!("DOUBLE-SPEND BAN LIVE (prop): {failures} FAILED");
            std::process::exit(1);
        }
        return;
    }

    // ── DS-POS — two authored k3 children of the SAME parent → BANNED ──────────
    // The 3-step shape (KI#46 check-3): base X (seq 4) → A′ consumes X (seq 5,
    // which records previous_states[W]=X on every node) → B′ ALSO consumes X at
    // seq 5. Only now can a node PROVE the fork; the pre-rework parent-less pair
    // correctly did not ban and the scenario was vacuous.
    {
        let wallet = Ed25519Signer::from_seed(&[0xC1; 32]);
        let w = id(0xD5, 0x01);
        let (x, a, b) = (id(0xF1, 0x01), id(0xA1, 0x01), id(0xB1, 0x01));
        let (txx, txa, txb) = (id(0x0F, 0x01), id(0x0A, 0x01), id(0x0B, 0x01));
        println!("[DS-POS] 3-step authored double-spend: base X@seq=4 → A' consumes X @seq=5 → B' consumes X @seq=5");
        let x_msg = seq_update(Some(&wallet), &w, &x, &no_parent(), &txx, 9, 4, 3);
        if !establish(&w, &x_msg) {
            println!("  [WARN] DS-POS: base X not established on all nodes");
        }
        let a_msg = seq_update(Some(&wallet), &w, &a, &x, &txa, 10, 5, 3);
        if !establish_head(&w, &a, &a_msg) {
            println!("  [WARN] DS-POS: A' (parent X) not adopted on all nodes — the fork may be unprovable there");
        }
        let b_msg = seq_update(Some(&wallet), &w, &b, &x, &txb, 11, 5, 3);
        for addr in &nodes {
            send_oneway(addr, &b_msg);
        }
        assert_all("DS-POS", &w, "BANNED", Some(&b_msg), &mut failures);
    }

    // ── DS-FORGE — forged (unauthored) fork must NOT ban (anti-framing) ────────
    // Post-KI#46 zero-pk flip this is refused EARLIER than the authorship gate
    // it was written for: an unauthored StateUpdate is dropped outright (YPX-009
    // enforced), so the wallet never even appears on the mesh.
    {
        let w = id(0xD5, 0x02);
        let (x, a, b) = (id(0xF1, 0x02), id(0xA1, 0x02), id(0xB1, 0x02));
        let (txx, txa, txb) = (id(0x0F, 0x02), id(0x0A, 0x02), id(0x0B, 0x02));
        println!("[DS-FORGE] framing attack: forged k=3 SeqProofs, client_pk=0 (unauthored) → dropped, never banned");
        for (state, tx, tick, seq, parent) in [
            (x, txx, 9u64, 4u64, no_parent()),
            (a, txa, 10, 5, x),
            (b, txb, 11, 5, x),
        ] {
            let msg = seq_update(None, &w, &state, &parent, &tx, tick, seq, 3);
            for addr in &nodes {
                send_oneway(addr, &msg);
            }
        }
        sleep(1500);
        // Zero-pk is rejected at the top of apply_state_update → NO entry exists.
        let present: Vec<&String> = nodes.iter().filter(|a| query(a, &w).is_some()).collect();
        if present.is_empty() {
            println!("  [PASS] DS-FORGE: unauthored fork rejected on all {} nodes (no entry, no ban)", nodes.len());
        } else {
            println!("  [FAIL] DS-FORGE: unauthored update was STORED on: {}", present.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
            failures += 1;
        }
    }

    // ── DS-ADV — authored sequential advance (different seq) must NOT ban ──────
    {
        let wallet = Ed25519Signer::from_seed(&[0xC3; 32]);
        let w = id(0xD5, 0x03);
        let (x, a, b) = (id(0xF1, 0x03), id(0xA1, 0x03), id(0xB1, 0x03));
        let (txx, txa, txb) = (id(0x0F, 0x03), id(0x0A, 0x03), id(0x0B, 0x03));
        println!("[DS-ADV] authored sequential advance: A'@seq=5 (parent X) then B'@seq=6 (parent A') → NOT a conflict");
        let x_msg = seq_update(Some(&wallet), &w, &x, &no_parent(), &txx, 9, 4, 3);
        establish(&w, &x_msg);
        let a_msg = seq_update(Some(&wallet), &w, &a, &x, &txa, 10, 5, 3);
        if !establish_head(&w, &a, &a_msg) {
            println!("  [WARN] DS-ADV: A' not adopted on all nodes before advance");
        }
        // A genuine next tx: chain continuation off A' at a HIGHER seq.
        let b_msg = seq_update(Some(&wallet), &w, &b, &a, &txb, 11, 6, 3);
        for addr in &nodes {
            send_oneway(addr, &b_msg);
        }
        sleep(1500);
        assert_all("DS-ADV", &w, "NORMAL", None, &mut failures);
    }

    // ── DS-CONT — same-seq CHAIN CONTINUATION (a redeem) must NOT ban ─────────
    // The live counterpart of `dsfork_same_seq_chain_continuation_redeem_NO_ban`
    // — the shape that false-banned honest wallet A in gate run 1785338039.
    // Core keeps wallet_seq unchanged on receive, so a redeem is a same-seq
    // advance whose parent is the HELD HEAD (not the head's parent).
    {
        let wallet = Ed25519Signer::from_seed(&[0xC5; 32]);
        let w = id(0xD5, 0x05);
        let (x, a, b) = (id(0xF1, 0x05), id(0xA1, 0x05), id(0xB1, 0x05));
        let (txx, txa, txb) = (id(0x0F, 0x05), id(0x0A, 0x05), id(0x0B, 0x05));
        println!("[DS-CONT] same-seq chain continuation (redeem): A'@seq=5 parent X, then B'@seq=5 parent A' → NOT a fork");
        let x_msg = seq_update(Some(&wallet), &w, &x, &no_parent(), &txx, 9, 4, 3);
        establish(&w, &x_msg);
        let a_msg = seq_update(Some(&wallet), &w, &a, &x, &txa, 10, 5, 3);
        if !establish_head(&w, &a, &a_msg) {
            println!("  [WARN] DS-CONT: A' not adopted on all nodes before the continuation");
        }
        // Parent = A' (the held head) at the SAME seq: legitimate receive advance.
        let b_msg = seq_update(Some(&wallet), &w, &b, &a, &txb, 11, 5, 3);
        for addr in &nodes {
            send_oneway(addr, &b_msg);
        }
        sleep(1500);
        assert_all("DS-CONT", &w, "NORMAL", None, &mut failures);
    }

    // ── DS-SUBQ — authored conflict but sub-quorum (k=2) must NOT ban ──────────
    {
        let wallet = Ed25519Signer::from_seed(&[0xC4; 32]);
        let w = id(0xD5, 0x04);
        let (x, a, b) = (id(0xF1, 0x04), id(0xA1, 0x04), id(0xB1, 0x04));
        let (txx, txa, txb) = (id(0x0F, 0x04), id(0x0A, 0x04), id(0x0B, 0x04));
        println!("[DS-SUBQ] same-parent conflict at seq=5 but only k=2 sigs → sub-quorum, NOT banned");
        let x_msg = seq_update(Some(&wallet), &w, &x, &no_parent(), &txx, 9, 4, 3);
        establish(&w, &x_msg);
        let a_msg = seq_update(Some(&wallet), &w, &a, &x, &txa, 10, 5, 3);
        if !establish_head(&w, &a, &a_msg) {
            println!("  [WARN] DS-SUBQ: A' not adopted on all nodes before conflict");
        }
        // Same parent X, same seq — but only 2 sigs, so the fork is unprovable.
        let b_msg = seq_update(Some(&wallet), &w, &b, &x, &txb, 11, 5, 2);
        for addr in &nodes {
            send_oneway(addr, &b_msg);
        }
        sleep(1500);
        assert_all("DS-SUBQ", &w, "NORMAL", None, &mut failures);
    }

    println!();
    if failures == 0 {
        println!("DOUBLE-SPEND BAN LIVE: ALL SCENARIOS PASS");
    } else {
        println!("DOUBLE-SPEND BAN LIVE: {failures} SCENARIO(S) FAILED");
        std::process::exit(1);
    }
}
