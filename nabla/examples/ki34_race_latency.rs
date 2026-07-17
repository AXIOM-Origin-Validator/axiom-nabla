// KI#34 WI4 — ASYNC / VERIFIED freeze-vs-value race harness for an INJECTED-LATENCY env.
//
// `ki34_wi4_race` assumes near-instant loopback: it seeds fire-and-forget and polls
// tightly. Under `AXIOM_SIM_NET_DELAY_MAX_MS` (a blocking 0–N ms sleep per message)
// that breaks — the seed never establishes. This harness is built for the latency
// regime, the closest single-box approximation of the multi-host race (T2.2):
//
//   * VERIFIED SEEDING — for each node, (re)send X→Y, wait > max per-message delay,
//     query the node back, and RETRY until it actually holds Y (or give up after K).
//     No fire-and-forget; the substrate is confirmed before the clock starts.
//   * SEQUENTIAL SAMPLING — one query at a time (10 simultaneous connections fare
//     worse under the per-connection blocking delay), on a generous cadence.
//   * LONG WINDOWS — freeze propagation under latency is genuinely slow; that IS the
//     finding the multi-host run is meant to surface.
//
// Verbose per-node seeding output so a first run reveals whether the substrate
// establishes under the injected latency at all.
//
// Usage: ki34_race_latency [addr ...]   (default 127.0.0.1:7300..=7309)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use axiom_nabla::crypto::{receipt_sign_payload, Ed25519Signer, Signer};
use axiom_nabla::transport::WireMessage;
use axiom_nabla::types::{GossipMessage, WitnessSig};
use axiom_nabla::wire_client::QueryWalletStateRequest;

type B32 = [u8; 32];

const POSITIVE_QUORUM: usize = 2;
const SEED_TRIES: usize = 12;
const SEED_WAIT_MS: u64 = 900; // > max per-message delay (600) so the node has processed Y
const SAMPLE_WINDOW_MS: u64 = 120_000;
const SAMPLE_GAP_MS: u64 = 1200;

fn id(tag: u8, w: u8) -> B32 { let mut a = [0u8; 32]; a[0] = tag; a[1] = w; a }

fn send_oneway(addr: &str, msg: &WireMessage) {
    if let Ok(mut s) = TcpStream::connect(addr) {
        let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
        let bytes = bincode::serialize(msg).expect("serialize");
        let _ = s.write_all(&(bytes.len() as u32).to_be_bytes());
        let _ = s.write_all(&bytes);
        let _ = s.flush();
        // Brief linger so the node's delayed handler reads before FIN/RST (the
        // fire-and-forget close-race is one suspect for seeds vanishing under latency).
        std::thread::sleep(Duration::from_millis(30));
    }
}

/// (wallet_status, current_state) or None on NOT_FOUND / IO error. Generous timeout
/// to ride out the per-message delay.
fn query(addr: &str, wallet: &B32) -> Option<(String, Vec<u8>)> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
    let req = WireMessage::QueryWalletStateRequest(QueryWalletStateRequest { wallet_pk: *wallet });
    let bytes = bincode::serialize(&req).ok()?;
    s.write_all(&(bytes.len() as u32).to_be_bytes()).ok()?;
    s.write_all(&bytes).ok()?;
    s.flush().ok()?;
    let mut lb = [0u8; 4];
    s.read_exact(&mut lb).ok()?;
    let n = u32::from_be_bytes(lb) as usize;
    if n > 10_000_000 { return None; }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).ok()?;
    match bincode::deserialize::<WireMessage>(&buf).ok()? {
        WireMessage::QueryWalletStateResponse(r) => {
            if r.status == "NOT_FOUND" { None } else { Some((r.wallet_status, r.current_state)) }
        }
        _ => None,
    }
}

fn state_update(w: &B32, new: &B32, tick: u64) -> WireMessage {
    let mut tx = *w; tx[31] = (tick & 0xff) as u8;
    WireMessage::Gossip(GossipMessage::StateUpdate {
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
    })
}

fn hex8(b: &[u8]) -> String { b.iter().take(8).map(|x| format!("{x:02x}")).collect() }

/// Seed ONE node to head Y and CONFIRM it (query-back), retrying under latency.
/// Returns (held_Y, tries_used, final_state_label).
fn seed_node_verified(addr: &str, w: &B32, x: &B32, y: &B32) -> (bool, usize, String) {
    for t in 1..=SEED_TRIES {
        send_oneway(addr, &state_update(w, x, 1));
        send_oneway(addr, &state_update(w, y, 2));
        std::thread::sleep(Duration::from_millis(SEED_WAIT_MS));
        match query(addr, w) {
            Some((_, head)) if head == y.to_vec() => return (true, t, "Y".into()),
            Some((_, head)) => { let _ = head; }
            None => {}
        }
    }
    let label = match query(addr, w) {
        Some((st, head)) => format!("{st} head={}", hex8(&head)),
        None => "NOT_FOUND".into(),
    };
    (false, SEED_TRIES, label)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let nodes: Vec<String> = if args.is_empty() {
        (7300..=7309).map(|p| format!("127.0.0.1:{p}")).collect()
    } else { args };
    let n = nodes.len();
    let salt = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_nanos() as u8) | 1).unwrap_or(0x01);
    let w = id(0xC9, salt);
    let (x, y, xp) = (id(0xA0, salt), id(0xA1, salt), id(0xAF, salt));

    println!("KI#34 WI4 ASYNC/VERIFIED race (latency-grade) against {n} nodes");
    println!("  wallet={} X={} Y={} X'={}", hex8(&w), hex8(&x), hex8(&y), hex8(&xp));
    println!("  (each query/gossip is delayed 0–AXIOM_SIM_NET_DELAY_MAX_MS ms)\n");

    // ── Phase 1: VERIFIED seeding (the substrate) ──
    println!("[seed] establishing X→Y on each node (verified, retry under latency):");
    let seed_start = Instant::now();
    let mut held = 0usize;
    for (i, addr) in nodes.iter().enumerate() {
        let (ok, tries, label) = seed_node_verified(addr, &w, &x, &y);
        if ok { held += 1; }
        println!("  node {i:>2} {addr}: {}  ({tries} tr{})", if ok { "HELD Y".into() } else { format!("FAILED → {label}") }, if tries == 1 { "y" } else { "ies" });
    }
    println!("[seed] {held}/{n} nodes hold Y after {} ms\n", seed_start.elapsed().as_millis());
    if held < POSITIVE_QUORUM + 1 {
        println!("[abort] substrate too weak ({held}/{n}) to measure the race — even verified seeding \
                  can't establish enough nodes under this latency. (This itself is the multi-host finding.)");
        std::process::exit(2);
    }

    // ── Phase 2: inject the fork, start the clock ──
    println!("[inject] HAL re-anchor X→X' (k=3) to ONE node ({}); clock starts\n", nodes[0]);
    let t0 = Instant::now();
    send_oneway(&nodes[0], &hal_advance(&w, &x, &xp, 3));

    // ── Phase 3: SEQUENTIAL sampling over a long window ──
    let mut t_freeze_all: Option<u64> = None;
    let mut forged_open: Option<u64> = None;
    let mut forged_close: Option<u64> = None;
    let mut max_forged = 0usize;
    let mut samples = 0u64;
    loop {
        let mut frozen = 0usize;
        let mut forged = 0usize;
        for addr in &nodes {
            if let Some((status, head)) = query(addr, &w) {
                if status == "FROZEN" || status == "BANNED" { frozen += 1; }
                else if head == xp.to_vec() { forged += 1; }
            }
        }
        samples += 1;
        max_forged = max_forged.max(forged);
        let ms = t0.elapsed().as_millis() as u64;
        if forged >= POSITIVE_QUORUM { forged_open.get_or_insert(ms); forged_close = Some(ms); }
        println!("  [t+{ms:>6}ms] frozen={frozen}/{n}  serving-X'={forged}/{n}");
        if frozen == n { t_freeze_all = Some(ms); break; }
        if ms >= SAMPLE_WINDOW_MS { break; }
        std::thread::sleep(Duration::from_millis(SAMPLE_GAP_MS));
    }

    // ── Report ──
    println!("\n── RESULT (latency-grade, single-box approximation of multi-host) ──");
    match t_freeze_all {
        Some(ms) => println!("freeze-propagation : ALL {n} frozen by t+{ms} ms ({samples} samples)"),
        None => println!("freeze-propagation : INCOMPLETE within {SAMPLE_WINDOW_MS} ms ({samples} samples) — mesh did NOT fully freeze"),
    }
    println!("value-realization  : peak forged servers = {max_forged}/{n} (need {POSITIVE_QUORUM})");
    match (forged_open, forged_close) {
        (Some(o), Some(c)) => println!("forged-value window: clean {POSITIVE_QUORUM}-of-N X' servable t+{o}..{c} ms (open {} ms)", c.saturating_sub(o)),
        _ => println!("forged-value window: NONE — forged X' never reached a {POSITIVE_QUORUM}-of-N clean confirmation"),
    }
    let lost = forged_open.is_some();
    println!("\nKI#34 WI4 (latency): {}", if lost {
        "RETROACTIVE DEFENSE LOSES — forged value was realizable before the freeze (receiver must be fail-closed)"
    } else {
        "forged value never reached a clean quorum in this run"
    });
}
