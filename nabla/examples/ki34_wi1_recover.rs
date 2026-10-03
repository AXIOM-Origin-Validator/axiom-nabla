// KI#34 WI1 — LIVE consume-once recovery + rollback-rejection harness.
//
// WI1 is the work item the whole KI#34 net rests on: a wiped/recovering Nabla
// must re-arm its anti-rollback (consume-once) memory from honest peers via the
// StatePull bootstrap payload, so a spent state can never be revived. The unit
// test (`node::tests::ki34_wipe_recover_rejects_revival_rollback`) proves the
// in-process flow; this proves the DEPLOYED binary actually:
//
//   1. SERVES the recovery payload — a StatePull Bootstrap response from a live
//      node carries a non-empty `consumed_bloom` AND a `previous_states` entry
//      mapping our wallet -> the consumed state X. This is exactly what a wiped
//      node merges to re-arm (`merge_consumed_bloom` + `merge_previous_states`).
//   2. ENFORCES the consume-once gate live — a tick-path rollback to the consumed
//      X (seq unchanged, no proof) is REJECTED by every node; the head stays Y.
//
// Together: the live mesh both hands out the WI1 re-arm data and refuses the
// revival it defends against. Self-contained throwaway wallet (0xD2) + zero
// client_pk (skips client-sig verify), safe alongside a running soak.
//
// Usage: ki34_wi1_recover [addr ...]   (default 127.0.0.1:7300..=7309)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use axiom_nabla::transport::WireMessage;
use axiom_nabla::types::{GossipMessage, StatePullMode};
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

/// Send a request and read one length-prefixed WireMessage reply on the same conn.
fn request(addr: &str, msg: &WireMessage) -> Option<WireMessage> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(4))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(4))).ok()?;
    let bytes = bincode::serialize(msg).ok()?;
    s.write_all(&(bytes.len() as u32).to_be_bytes()).ok()?;
    s.write_all(&bytes).ok()?;
    s.flush().ok()?;
    let mut lb = [0u8; 4];
    s.read_exact(&mut lb).ok()?;
    let n = u32::from_be_bytes(lb) as usize;
    if n > 20_000_000 {
        return None;
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).ok()?;
    bincode::deserialize::<WireMessage>(&buf).ok()
}

fn query_head(addr: &str, wallet: &B32) -> Option<Vec<u8>> {
    let req = WireMessage::QueryWalletStateRequest(QueryWalletStateRequest { wallet_pk: *wallet });
    match request(addr, &req)? {
        WireMessage::QueryWalletStateResponse(r) => {
            if r.status == "NOT_FOUND" { None } else { Some(r.current_state) }
        }
        _ => None,
    }
}

/// Pull the WI1 recovery payload (consumed eras + previous_states) from a node.
/// KI#42 step 4d: the anti-rollback view travels as consumed-state ERAS now.
/// `from: None` — this tool is an external client that reads the reply on its
/// own connection (the send_reply path), not a mesh node.
fn state_pull_bootstrap(addr: &str) -> Option<(Vec<Vec<u8>>, Vec<(B32, B32)>)> {
    let req = WireMessage::StatePullRequest {
        mode: StatePullMode::Bootstrap,
        from: None,
        our_root_hash: [0u8; 32],
        from_tick: 0,
        to_tick: u64::MAX,
        section_hash: None,
        have_era_ids: Vec::new(),
        have_consumed_era_ids: Vec::new(),
    };
    match request(addr, &req)? {
        WireMessage::StatePullResponse { consumed_eras, previous_states, .. } => {
            Some((consumed_eras, previous_states))
        }
        _ => None,
    }
}

fn state_update(w: &B32, new: &B32, tx: &B32, tick: u64, seq: u64) -> WireMessage {
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
        seq_proof: None,
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
    println!("KI#34 WI1 live consume-once recovery + rollback rejection against {n} nodes\n");
    let mut failures = 0u32;

    // Fresh wallet + states + tick base each run, so a re-run never collides with
    // its own retained mesh state (the wallet head persists across harness runs).
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    let salted = |tag: u8| -> B32 {
        let mut a = [0u8; 32];
        a[0] = tag;
        a[1..9].copy_from_slice(&nonce.to_le_bytes());
        a
    };
    let w = salted(0xD2);
    let (x, y) = (salted(0xA0), salted(0xA1));
    let tx_x = salted(0xB0);
    let tx_y = salted(0xB1);
    let t0 = (nonce % 1_000_000) + 1; // monotone, high base — never below a stale head

    // ── Setup: advance X→Y on the tick path → X becomes consumed mesh-wide. ──
    // Settle X FULLY before sending Y, so every node witnesses the X→Y transition
    // locally (records X in its consumed-set) rather than learning Y fresh via a
    // gossip-forward race — a node that only ever sees the head Y, never the
    // predecessor X, has no record X was consumed (the §5.2 consumed-set-presence
    // limitation; such a node re-arms via the WI1 StatePull bootstrap in Part 1).
    println!("[setup] advance head X({})→Y({}) — X gets consumed", hex8(&x), hex8(&y));
    for addr in &nodes {
        send_oneway(addr, &state_update(&w, &x, &tx_x, t0, 0));
    }
    sleep(1500);
    for addr in &nodes {
        send_oneway(addr, &state_update(&w, &y, &tx_y, t0 + 1, 0));
    }
    sleep(1500);
    let count_head = |target: &B32| -> usize {
        nodes.iter().filter(|a| query_head(a, &w).as_deref() == Some(target.as_ref())).count()
    };
    let base_y = count_head(&y);
    println!("  -> {base_y}/{n} nodes hold head Y\n");

    // ── Part 1: the live StatePull bootstrap SERVES the WI1 re-arm payload. ──
    println!("[recover] StatePull Bootstrap → must carry consumed era(s) + previous_states[w]=X");
    let mut served = 0u32;
    for addr in &nodes {
        if let Some((eras, prev)) = state_pull_bootstrap(addr) {
            let has_prev_x = prev.iter().any(|(wid, st)| wid == &w && st == &x);
            if !eras.is_empty() && has_prev_x {
                served += 1;
            }
        }
    }
    if served >= 1 {
        println!("  [PASS] {served}/{n} nodes served a live WI1 recovery payload (bloom + prev=X)\n");
    } else {
        println!("  [FAIL] no node served the WI1 re-arm payload — wiped nodes would come back blind\n");
        failures += 1;
    }

    // ── Part 2: the consume-once gate REJECTS a live rollback to X. ──
    println!("[reject] gossip rollback to consumed X @ high tick (seq 0, no proof)");
    for addr in &nodes {
        send_oneway(addr, &state_update(&w, &x, &salted(0xBF), t0 + 10_000, 0));
    }
    sleep(1200);
    let still_y = count_head(&y);
    let took_x = count_head(&x);
    if took_x == 0 && still_y >= base_y.max(1) {
        println!("  [PASS] rollback REJECTED — {still_y}/{n} still Y, 0 reverted to consumed X\n");
    } else {
        println!("  [FAIL] rollback leaked — {took_x}/{n} reverted to X (head should stay Y)\n");
        failures += 1;
    }

    if failures == 0 {
        println!(
            "KI#34 WI1 LIVE: PASS — the mesh serves the consume-once recovery payload AND \
             refuses to revive a spent state. A wiped node re-arms and stays safe."
        );
    } else {
        println!("KI#34 WI1 LIVE: {failures} FAILURE(S)");
        std::process::exit(1);
    }
}
