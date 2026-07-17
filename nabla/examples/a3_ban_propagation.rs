// A3 measurement — SeqForkBan origination → mesh-wide propagation latency,
// measured against the redeem maturity window. Closes the one empirical
// assumption of the paper's safety theorem: A3, "ban propagation completes
// inside the maturity window."
//
// It reuses the proven fork-injection path of `dsfork_live_inject` (PROP mode):
// establish A' on node[0], inject the conflicting B' to node[0] ONLY, and let the
// ban FLOOD to the rest of the mesh via real SeqForkBan gossip + independent
// re-verification. The addition here is timing: at high poll resolution and over
// many runs it records, from the instant the conflict is injected,
//   t_first   — first node reports BANNED (origination reached the mesh),
//   t_quorum  — POSITIVE_QUORUM (2) nodes BANNED (any receiver's 2-of-N
//               redeem consultation would now hit a detector),
//   t_all     — every reachable node BANNED,
// and reports the p50/p95/p99/max distribution and the margin against the
// maturity window (MATURITY_TICKS_MIN × TICK = 25 s).
//
// Loopback is an OPTIMISTIC lower bound. Set AXIOM_SIM_NET_DELAY_MAX_MS on the
// nabla-node processes to approximate a multi-host mesh; the reported margin is
// then closer to a real deployment. This is stated honestly in the artifact.
//
// Usage:
//   AXIOM_A3_RUNS=25 AXIOM_A3_POLL_MS=5 \
//   cargo run -p axiom-nabla --example a3_ban_propagation -- 127.0.0.1:7300 ... 127.0.0.1:7309
// Output: a summary to stdout + an archived artifact log (AXIOM_A3_OUT, default
// ./a3_ban_propagation_<unixtime>.log).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axiom_nabla::crypto::{Ed25519Signer, Signer};
use axiom_nabla::gossip::client_state_sign_payload;
use axiom_nabla::transport::WireMessage;
use axiom_nabla::types::{GossipMessage, SeqProof, SeqProofSig};
use axiom_nabla::wire_client::QueryWalletStateRequest;

type B32 = [u8; 32];

const POSITIVE_QUORUM: usize = 2; // the redeem-side 2-of-N gate (verify_cheque)
const MATURITY_TICKS_MIN: u64 = 5; // §4.6 maturity floor
const TICK_SECS: u64 = 5; // TARDIS tick
const MATURITY_WINDOW_MS: u128 = (MATURITY_TICKS_MIN * TICK_SECS * 1000) as u128; // 25_000

static RUN_NONCE: AtomicU8 = AtomicU8::new(0);

fn id(tag: u8, w: u8) -> B32 {
    let mut a = [0u8; 32];
    a[0] = tag;
    a[1] = w;
    a[2] = RUN_NONCE.load(Ordering::Relaxed);
    a
}

fn send_oneway(addr: &str, msg: &WireMessage) {
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
        std::thread::sleep(Duration::from_millis(80));
    }
}

/// (wallet_status, current_state) or None on NOT_FOUND / IO error.
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

fn mint_seq_proof(tx: &B32, wallet_seq: u64, n: usize) -> SeqProof {
    let state_hash = [0x5a_u8; 32];
    let commitment_hash = [0x7c_u8; 32];
    let (epoch, is_dev_class) = (7u64, false);
    let commitment = axiom_core_logic::compute::compute_receipt_commitment(
        tx, &state_hash, wallet_seq, &commitment_hash, epoch, is_dev_class,
        None,
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
    SeqProof { state_hash, commitment_hash, epoch, is_dev_class, sigs, oods_flag: None }
}

fn seq_update(
    wallet: &Ed25519Signer,
    wid: &B32,
    new_state: &B32,
    tx: &B32,
    tick: u64,
    wallet_seq: u64,
) -> WireMessage {
    let proof = mint_seq_proof(tx, wallet_seq, 3);
    let payload = client_state_sign_payload(wid, new_state, tx, tick);
    WireMessage::Gossip(GossipMessage::StateUpdate {
        wallet_id: *wid,
        new_state: *new_state,
        tx_hash: *tx,
        tick,
        wallet_seq,
        seq_proof: Some(proof),
        client_pk: wallet.public_key_bytes(),
        client_sig: wallet.sign(&payload),
        amount: 0,
        fee_breakdown: Vec::new(),
    })
}

fn banned_count(nodes: &[String], w: &B32) -> usize {
    let mut c = 0;
    for a in nodes {
        if let Some((s, _)) = query(a, w) {
            if s == "BANNED" {
                c += 1;
            }
        }
    }
    c
}

fn pct(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[idx]
}

fn summarize(label: &str, mut v: Vec<u128>, out: &mut String) {
    v.sort_unstable();
    let line = format!(
        "  {label:<8}  n={:<3} p50={:>6}ms  p95={:>6}ms  p99={:>6}ms  max={:>6}ms",
        v.len(),
        pct(&v, 0.50),
        pct(&v, 0.95),
        pct(&v, 0.99),
        v.last().copied().unwrap_or(0),
    );
    println!("{line}");
    out.push_str(&line);
    out.push('\n');
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let nodes: Vec<String> = if args.is_empty() {
        (7300..=7309).map(|p| format!("127.0.0.1:{p}")).collect()
    } else {
        args
    };
    let runs: usize = std::env::var("AXIOM_A3_RUNS").ok().and_then(|s| s.parse().ok()).unwrap_or(25);
    let poll_ms: u64 = std::env::var("AXIOM_A3_POLL_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    let timeout_ms: u128 = 30_000;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let out_path = std::env::var("AXIOM_A3_OUT")
        .unwrap_or_else(|_| format!("a3_ban_propagation_{}.log", now.as_secs()));

    println!(
        "A3 ban-propagation measurement: {} nodes, {} runs, poll {}ms, maturity window {}ms\n  nodes: {:?}\n",
        nodes.len(), runs, poll_ms, MATURITY_WINDOW_MS, nodes
    );
    let mut artifact = String::new();
    artifact.push_str(&format!(
        "# A3 ban-propagation measurement\nunix={} nodes={} runs={} poll_ms={} maturity_window_ms={}\n\
         net_delay_note=set AXIOM_SIM_NET_DELAY_MAX_MS on the nodes for a multi-host approximation; \
         loopback is an optimistic lower bound.\n\n",
        now.as_secs(), nodes.len(), runs, poll_ms, MATURITY_WINDOW_MS
    ));

    let (mut firsts, mut quorums, mut alls) = (Vec::new(), Vec::new(), Vec::new());
    let mut dropped = 0usize;

    for run in 0..runs {
        // fresh, never-before-banned ids each run (an irreversible ban would wedge a re-use)
        let nonce = ((now.subsec_nanos() as usize + run.wrapping_mul(37)) & 0xff) as u8;
        RUN_NONCE.store(nonce, Ordering::Relaxed);
        let wallet = Ed25519Signer::from_seed(&[0xC0u8.wrapping_add(run as u8); 32]);
        let w = id(0xDC, run as u8);
        let (a, b) = (id(0xAC, run as u8), id(0xBC, run as u8));
        let (txa, txb) = (id(0x0C, run as u8), id(0x0D, run as u8));

        // establish A' on node[0] (the detector) — verified before the clock starts
        let a_msg = seq_update(&wallet, &w, &a, &txa, 10, 5);
        let mut established = false;
        for _ in 0..30 {
            if query(&nodes[0], &w).is_some() {
                established = true;
                break;
            }
            send_oneway(&nodes[0], &a_msg);
            std::thread::sleep(Duration::from_millis(200));
        }
        if !established {
            eprintln!("  run {run}: A' failed to establish on node[0] — dropped");
            dropped += 1;
            continue;
        }

        // inject the conflict B' to node[0] ONLY, in a tight burst to beat lossy
        // one-way gossip, and start the clock at the first send. Other nodes must
        // learn the ban purely via propagation.
        let b_msg = seq_update(&wallet, &w, &b, &txb, 11, 5);
        let t0 = Instant::now();
        for _ in 0..3 {
            send_oneway(&nodes[0], &b_msg);
        }

        // tight, timestamped poll of the WHOLE mesh
        let (mut t_first, mut t_quorum, mut t_all): (Option<u128>, Option<u128>, Option<u128>) =
            (None, None, None);
        loop {
            let el = t0.elapsed().as_millis();
            let bc = banned_count(&nodes, &w);
            if bc >= 1 && t_first.is_none() {
                t_first = Some(el);
            }
            if bc >= POSITIVE_QUORUM && t_quorum.is_none() {
                t_quorum = Some(el);
            }
            if bc == nodes.len() {
                t_all = Some(el);
                break;
            }
            if el > timeout_ms {
                break;
            }
            std::thread::sleep(Duration::from_millis(poll_ms));
        }

        match (t_first, t_quorum, t_all) {
            (Some(f), Some(q), Some(al)) => {
                firsts.push(f);
                quorums.push(q);
                alls.push(al);
                let line = format!("run {run:>3}: first={f}ms quorum={q}ms all={al}ms");
                println!("  {line}");
                artifact.push_str(&line);
                artifact.push('\n');
            }
            _ => {
                eprintln!("  run {run}: did not reach all-BANNED within {timeout_ms}ms — dropped");
                dropped += 1;
            }
        }
    }

    println!("\n=== A3 summary ({} completed, {} dropped) ===", alls.len(), dropped);
    artifact.push_str(&format!("\n# summary: completed={} dropped={}\n", alls.len(), dropped));
    summarize("first", firsts, &mut artifact);
    summarize("quorum", quorums, &mut artifact);
    let mut alls_sorted = alls.clone();
    alls_sorted.sort_unstable();
    summarize("all", alls, &mut artifact);

    let all_p99 = pct(&alls_sorted, 0.99).max(1);
    let margin = MATURITY_WINDOW_MS as f64 / all_p99 as f64;
    let verdict = if all_p99 < MATURITY_WINDOW_MS {
        format!(
            "A3 HOLDS: all-BANNED p99 = {}ms is {:.0}x inside the {}ms maturity window",
            all_p99, margin, MATURITY_WINDOW_MS
        )
    } else {
        format!(
            "A3 AT RISK: all-BANNED p99 = {}ms is NOT inside the {}ms maturity window",
            all_p99, MATURITY_WINDOW_MS
        )
    };
    println!("\n{verdict}");
    artifact.push_str(&format!("\n{verdict}\n"));

    if let Err(e) = std::fs::write(&out_path, &artifact) {
        eprintln!("could not write artifact {out_path}: {e}");
    } else {
        println!("artifact: {out_path}");
    }
    if alls_sorted.is_empty() {
        std::process::exit(1);
    }
}
