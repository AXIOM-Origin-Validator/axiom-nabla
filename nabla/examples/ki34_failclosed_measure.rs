// ⚠ RETIRED PATH (2026-09-30, Fork Settlement §9q, design B2 — docs/AXIOM_DESIGN_ForkSettlement.md):
// this harness drives the KI#34 check-3 / YPX-025 E3 `HalAdvance` arm, which is now a TOMBSTONE — a node of
// this build DROPS every `HalAdvance` unverified (counted `haladvance_dropped` on /status) and never freezes
// on it. A HAL re-anchor floods as a plain `StateUpdate` with its leg and a revival is BANNED on A1 evidence.
// Its assertions (freeze / freeze-race / shed) describe the retired behaviour; kept compiling as history.
// The in-process proofs of the replacement are `fork_detection_mesh::b2_*`.
// KI#34 T2.6 — fail-closed receiver, consultation-WIDTH measurement (no special node).
//
// `ki34_wi4_race` showed an OPTIMISTIC receiver (accept on >=2 nodes serving the
// fork X' as NORMAL) loses intermittently. The fix is a FAIL-CLOSED receiver:
//   * REJECT if ANY consulted node reports the sender FROZEN/BANNED/TAINTED
//     (one honest detector beats any number of blind nodes), AND
//   * consult WIDER ("always ask other Nabla") so a detector is actually in the set.
// Every node is EQUAL — the receiver picks a RANDOM K-subset (Secure/Random
// selection); no node is trusted or designated. This harness measures how the
// forged-accept rate falls as K grows, to size the production expansion.
//
// Method: inject the WI4 fork (X->Y consumed, then HAL re-anchor X->X' to ONE node),
// let it settle to the §4.6 decision window, snapshot all nodes once, then for each
// width K simulate MANY random K-subset consultations and count how often a
// fail-closed receiver would still ACCEPT the forged value (no node in its subset
// is Frozen AND >=2 serve X' as NORMAL). Repeat over rounds; report per-K rate.
//
// Usage: ki34_failclosed_measure [rounds] [addr ...]   (default 6 rounds, 7300..=7309)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use axiom_nabla::crypto::{receipt_sign_payload, Ed25519Signer, Signer};
use axiom_nabla::transport::WireMessage;
use axiom_nabla::types::{GossipMessage, WitnessSig};
use axiom_nabla::wire_client::QueryWalletStateRequest;

type B32 = [u8; 32];
const POSITIVE_QUORUM: usize = 2;
const TRIALS_PER_K: usize = 400; // random K-subsets simulated per width per round
const DECISION_WAIT_MS: u64 = 5000; // §4.6 floor — when the receiver decides

fn id(tag: u8, w: u8) -> B32 { let mut a = [0u8; 32]; a[0] = tag; a[1] = w; a }

fn send_oneway(addr: &str, msg: &WireMessage) {
    if let Ok(mut s) = TcpStream::connect(addr) {
        let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
        let bytes = bincode::serialize(msg).expect("serialize");
        let _ = s.write_all(&(bytes.len() as u32).to_be_bytes());
        let _ = s.write_all(&bytes);
        let _ = s.flush();
    }
}

/// View as the receiver sees a node:
///   Frozen        — negative signal (detector); ANY one hard-blocks.
///   ServesForged  — serves X' as NORMAL (the forged head).
///   ServesOther   — serves a DIFFERENT NORMAL head (the honest Y) → conflicts with X'.
///   Absent        — NOT_FOUND / unreachable (no opinion).
#[derive(Clone, Copy, PartialEq)]
enum View { Frozen, ServesForged, ServesOther, Absent }

fn view_of(addr: &str, wallet: &B32, xp: &B32) -> View {
    let mut conn = match TcpStream::connect(addr) { Ok(s) => s, Err(_) => return View::Absent };
    let _ = conn.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(3)));
    let req = WireMessage::QueryWalletStateRequest(QueryWalletStateRequest { wallet_pk: *wallet });
    let bytes = match bincode::serialize(&req) { Ok(b) => b, Err(_) => return View::Absent };
    if conn.write_all(&(bytes.len() as u32).to_be_bytes()).is_err() { return View::Absent; }
    if conn.write_all(&bytes).is_err() { return View::Absent; }
    let _ = conn.flush();
    let mut lb = [0u8; 4];
    if conn.read_exact(&mut lb).is_err() { return View::Absent; }
    let n = u32::from_be_bytes(lb) as usize;
    if n > 10_000_000 { return View::Absent; }
    let mut buf = vec![0u8; n];
    if conn.read_exact(&mut buf).is_err() { return View::Absent; }
    match bincode::deserialize::<WireMessage>(&buf) {
        Ok(WireMessage::QueryWalletStateResponse(r)) => {
            if r.status == "NOT_FOUND" { return View::Absent; }
            if r.wallet_status == "FROZEN" || r.wallet_status == "BANNED" || r.wallet_status == "TAINTED" {
                View::Frozen
            } else if r.current_state == xp.to_vec() {
                View::ServesForged
            } else {
                View::ServesOther // a NORMAL but DIFFERENT head than X' = the honest Y
            }
        }
        _ => View::Absent,
    }
}

fn state_update(w: &B32, new: &B32, tick: u64) -> WireMessage {
    let mut tx = *w; tx[31] = (tick & 0xff) as u8;
    WireMessage::Gossip(GossipMessage::StateUpdate {
        old_state: [0u8; 32],
        is_genesis_claim: false,
        wallet_id: *w, new_state: *new, tx_hash: tx, tick,
        wallet_seq: 0, seq_proof: None, client_pk: [0u8; 32],
        client_sig: vec![0u8; 64], amount: 0, fee_breakdown: Vec::new(),
    })
}

fn hal_advance(w: &B32, old: &B32, new: &B32, tick: u64) -> WireMessage {
    let payload = receipt_sign_payload(w, old, tick);
    let sigs: Vec<WitnessSig> = (0..3).map(|i| {
        let mut seed = [0u8; 32]; seed[0] = 0xE0 ^ i as u8; seed[1] = w[1];
        let signer = Ed25519Signer::from_seed(&seed);
        WitnessSig {
            validator_pk: signer.public_key_bytes(), signature: signer.sign(&payload),
            execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![],
            validator_id: [0u8; 32], slot_amount: 0,
        }
    }).collect();
    let mut tx = *w; tx[30] = 0xAF;
    WireMessage::Gossip(GossipMessage::HalAdvance {
        wallet_id: *w, old_state: *old, new_state: *new, tx_hash: tx, tick,
        client_pk: [0u8; 32], client_sig: vec![0u8; 64], k3_signatures: sigs,
        amount: 0, fee_breakdown: Vec::new(),
        required_k: 3, // KI#150 wire field (LAST)
    })
}

/// Tiny xorshift PRNG — deterministic per (seed), no Math.random dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x
    }
    /// A random K-subset of indices 0..n (partial Fisher–Yates).
    fn subset(&mut self, n: usize, k: usize) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..n).collect();
        for i in 0..k.min(n) {
            let j = i + (self.next() as usize) % (n - i);
            idx.swap(i, j);
        }
        idx.truncate(k.min(n));
        idx
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let rounds: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(6);
    if !args.is_empty() && args[0].parse::<u64>().is_ok() { args.remove(0); }
    let nodes: Vec<String> = if args.is_empty() {
        (7300..=7309).map(|p| format!("127.0.0.1:{p}")).collect()
    } else { args };
    let n = nodes.len();
    let widths = [3usize, 5, 7, n];

    println!("KI#34 fail-closed receiver — forged-accept rate vs consultation WIDTH (no special node)");
    println!("  {n} EQUAL nodes; receiver picks a RANDOM K-subset; REJECT on any FROZEN, else accept if >=2 serve X'");
    println!("  {rounds} rounds × {TRIALS_PER_K} random subsets per width\n");

    // Two fail-closed models, per width:
    //   A = FROZEN-gate only       (accept if no Frozen in subset AND >=2 serve X')
    //   B = FROZEN + AGREEMENT-block (also REJECT if any subset node serves a
    //       conflicting head Y — divergence = fork present)
    let mut accept_a = vec![0u64; widths.len()];
    let mut accept_b = vec![0u64; widths.len()];
    let mut total = vec![0u64; widths.len()];
    let mut seed = 0x9E3779B97F4A7C15u64;

    for r in 0..rounds {
        let salt = ((r as u8).wrapping_mul(91)) | 1;
        let w = id(0xC8, salt);
        let (x, y, xp) = (id(0xA0, salt), id(0xA1, salt), id(0xAF, salt));
        for addr in &nodes {
            send_oneway(addr, &state_update(&w, &x, 1));
            send_oneway(addr, &state_update(&w, &y, 2));
        }
        std::thread::sleep(Duration::from_millis(1200));
        send_oneway(&nodes[0], &hal_advance(&w, &x, &xp, 3));
        std::thread::sleep(Duration::from_millis(DECISION_WAIT_MS));

        // Snapshot every node once at the decision window.
        let views: Vec<View> = nodes.iter().map(|a| view_of(a, &w, &xp)).collect();
        let frozen = views.iter().filter(|v| **v == View::Frozen).count();
        let forged = views.iter().filter(|v| **v == View::ServesForged).count();
        let other = views.iter().filter(|v| **v == View::ServesOther).count();
        println!("  round {:>2}: mesh frozen={frozen}/{n}  serving-X'={forged}/{n}  serving-Y(honest)={other}/{n}", r + 1);

        for (ki, &k) in widths.iter().enumerate() {
            for _ in 0..TRIALS_PER_K {
                seed = seed.wrapping_add(0x2545F4914F6CDD1D);
                let mut rng = Rng(seed | 1);
                let sub = rng.subset(n, k);
                let any_frozen = sub.iter().any(|&i| views[i] == View::Frozen);
                let any_conflicting_y = sub.iter().any(|&i| views[i] == View::ServesOther);
                let forged_seen = sub.iter().filter(|&&i| views[i] == View::ServesForged).count();
                // A: FROZEN-gate only.
                if !any_frozen && forged_seen >= POSITIVE_QUORUM { accept_a[ki] += 1; }
                // B: FROZEN + AGREEMENT-block (divergence on the head also blocks).
                if !any_frozen && !any_conflicting_y && forged_seen >= POSITIVE_QUORUM { accept_b[ki] += 1; }
                total[ki] += 1;
            }
        }
    }

    println!("\n── FORGED-ACCEPT RATE vs CONSULTATION WIDTH ──");
    println!("  (A = FROZEN-gate only;  B = FROZEN + agreement-block)");
    for (ki, &k) in widths.iter().enumerate() {
        let ra = if total[ki] == 0 { 0.0 } else { 100.0 * accept_a[ki] as f64 / total[ki] as f64 };
        let rb = if total[ki] == 0 { 0.0 } else { 100.0 * accept_b[ki] as f64 / total[ki] as f64 };
        let label = if k == n { format!("all {n}") } else { k.to_string() };
        println!("  K = {label:>6} : A {ra:>6.2}%   B {rb:>6.2}%   ({}/{} trials)", accept_a[ki].max(accept_b[ki]), total[ki]);
    }
    println!(
        "\nReads: the FROZEN gate alone (A) leaves a residual — the rounds where NO node froze\n\
         (fully substrate-blind mesh): nothing for the gate to fire on. Adding the AGREEMENT-block\n\
         (B) — REJECT when consulted nodes DISAGREE on the head (some serve X', some the honest Y) —\n\
         catches those too, because a fork means the honest Y is still served somewhere. Every node\n\
         is EQUAL; the receiver just refuses on ANY dissent over its own random pick. The irreducible\n\
         residual is the case where the WHOLE mesh serves only X' (no honest Y, no freeze anywhere) =\n\
         total wipe / full eclipse — the bounded-trust floor, not closable by consultation."
    );
}
