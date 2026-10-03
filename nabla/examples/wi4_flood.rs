// ⚠ RETIRED PATH (2026-09-30, Fork Settlement §9q, design B2 — docs/AXIOM_DESIGN_ForkSettlement.md):
// this harness drives the KI#34 check-3 / YPX-025 E3 `HalAdvance` arm, which is now a TOMBSTONE — a node of
// this build DROPS every `HalAdvance` unverified (counted `haladvance_dropped` on /status) and never freezes
// on it. A HAL re-anchor floods as a plain `StateUpdate` with its leg and a revival is BANNED on A1 evidence.
// Its assertions (freeze / freeze-race / shed) describe the retired behaviour; kept compiling as history.
// The in-process proofs of the replacement are `fork_detection_mesh::b2_*`.
// WI4 flood — tick-liveness regression for the gossip/AE load-shedding fix
// (docs/AXIOM_DESIGN_NablaAntiEntropy.md §11).
//
// Seeds N distinct wallets X->Y mesh-wide (each node then holds
// previous_state=X, the conflict substrate), then BURSTS N forged HalAdvance
// re-anchors (X -> X', fresh wallet id each to defeat dedup) at ONE node
// CONCURRENTLY. Pre-load-shed, the node ran k=3 SPHINCS+ verify + freeze UNDER
// the single global node lock, starving the TARDIS tick loop -> nodes fell to
// Orphan (the branch measured 8/10 orphan, convergence 0.8s->43s). With the
// load-shedding fix the verify runs OFF the lock and the budget sheds beyond
// GOSSIP_VERIFY_BUDGET_PER_WINDOW, so ticks keep advancing.
//
// Observe tick-liveness OUT OF BAND via each node's HTTP /status
// (`current_tick`, `tardis_slot`) and the `[GOSSIP-VERIFY-SHED]` WARN in
// nabla.log. This harness only drives the injection.
//
// Usage: wi4_flood [N] [addr ...]   (default N=40, 127.0.0.1:7300..=7309)

use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use axiom_nabla::crypto::{receipt_sign_payload, Ed25519Signer, Signer};
use axiom_nabla::transport::WireMessage;
use axiom_nabla::types::{GossipMessage, WitnessSig};

type B32 = [u8; 32];

fn id(tag: u8, w: u8, salt: u8) -> B32 {
    let mut a = [0u8; 32];
    a[0] = tag;
    a[1] = w;
    a[2] = salt;
    a
}
fn st(b: u8) -> B32 {
    let mut a = [0u8; 32];
    a[0] = b;
    a
}

fn state_update(w: &B32, new: &B32, tick: u64) -> WireMessage {
    let mut tx = *w;
    tx[31] = (tick & 0xff) as u8;
    WireMessage::Gossip(GossipMessage::StateUpdate {
        old_state: [0u8; 32],
        is_genesis_claim: false,
        wallet_id: *w,
        new_state: *new,
        tx_hash: tx,
        tick,
        wallet_seq: 0,
        seq_proof: None,
        client_pk: [0u8; 32],
        client_sig: vec![0u8; 64],
        amount: 0,
        fee_breakdown: Vec::new(),
    })
}

fn hal_advance(w: &B32, old: &B32, new: &B32, tick: u64, n_sigs: usize) -> WireMessage {
    let payload = receipt_sign_payload(w, old, tick);
    let sigs: Vec<WitnessSig> = (0..n_sigs)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = 0xE0 ^ i as u8;
            seed[1] = w[1];
            let signer = Ed25519Signer::from_seed(&seed);
            WitnessSig {
                validator_pk: signer.public_key_bytes(),
                signature: signer.sign(&payload),
                execution_proof: vec![],
                proof_type: 0,
                receipt_commitment_sig: vec![],
                validator_id: [0u8; 32],
                slot_amount: 0,
            }
        })
        .collect();
    let mut tx = *w;
    tx[30] = 0xAF;
    WireMessage::Gossip(GossipMessage::HalAdvance {
        wallet_id: *w,
        old_state: *old,
        new_state: *new,
        tx_hash: tx,
        tick,
        client_pk: [0u8; 32],
        client_sig: vec![0u8; 64],
        k3_signatures: sigs,
        amount: 0,
        fee_breakdown: Vec::new(),
        required_k: 3, // KI#150 wire field (LAST)
    })
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

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let n: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(40);
    if !args.is_empty() && args[0].parse::<usize>().is_ok() {
        args.remove(0);
    }
    let nodes: Vec<String> = if args.is_empty() {
        (7300..=7309).map(|p| format!("127.0.0.1:{p}")).collect()
    } else {
        args
    };
    let target = nodes[0].clone();
    println!(
        "[flood] N={n} forged HalAdvance conflicts -> {target}  (mesh {} nodes)",
        nodes.len()
    );

    // 1. Seed N distinct wallets X->Y on ALL nodes so every node retains
    //    previous_state=X (the fork-detection substrate).
    let x = st(0x01);
    let y = st(0x02);
    // Fresh wallet ids per run (SystemTime-salted) — reusing ids across runs
    // re-seeds wallets a prior run already froze, and a frozen wallet won't
    // re-adopt the seed (Frozen-monotonicity), so the conflict substrate never
    // reforms. Salt the id so every run works on virgin wallets.
    let run_salt = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() & 0xff) as u8)
        .unwrap_or(0);
    let wallets: Vec<B32> = (0..n)
        .map(|i| id(0x5A ^ run_salt, (i & 0xff) as u8, (i >> 8) as u8))
        .collect();
    for w in &wallets {
        for node in &nodes {
            send_oneway(node, &state_update(w, &x, 1));
            send_oneway(node, &state_update(w, &y, 2));
        }
    }
    let converge_s: u64 = std::env::var("FLOOD_CONVERGE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    println!("[flood] seeded {n} wallets X->Y on all nodes; converging ({converge_s}s)...");
    thread::sleep(Duration::from_secs(converge_s));

    // 2. BURST: fork every wallet (X -> X') at the ONE target node concurrently
    //    (a thread per inject) to maximize lock pressure — the WI4 flood.
    let xp = st(0x03);
    println!("[flood] BURST: {n} concurrent forged re-anchors -> {target}");
    let handles: Vec<_> = wallets
        .iter()
        .cloned()
        .map(|w| {
            let target = target.clone();
            thread::spawn(move || {
                send_oneway(&target, &hal_advance(&w, &x, &xp, 3, 3));
            })
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
    println!(
        "[flood] burst complete ({n} injects). Watch /status current_tick + tardis_slot \
         on all nodes and the [GOSSIP-VERIFY-SHED] WARN count in nabla.log."
    );
}
