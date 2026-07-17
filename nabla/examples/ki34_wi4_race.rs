// KI#34 WI4 — DUAL-TIMING freeze-vs-value race harness (the Tier-0 gate).
//
// The HAL-revival threat is a RACE: when a coalition re-anchors a spent wallet
// (consumed X -> head Y, now forge X -> X') and re-spends X' to a victim, two
// clocks start:
//
//   * freeze-propagation  — check-3's fork detector (an honest node holding
//     previous_state=X sees the X->X' double-consume) FREEZES + the Frozen
//     status propagates mesh-wide.
//   * value-realization    — the victim runs a §4.6 consultation; a "clean
//     forked confirmation" is >= POSITIVE_QUORUM (2) nodes serving head=X' as
//     NORMAL (not Frozen).
//
// PASS (for the retroactive defense alone): the forged head X' never reaches a
// 2-of-N clean confirmation before the mesh freezes — i.e. freeze wins. If it
// LOSES, the forged value is realizable in the gap, which is exactly why the
// PREVENTIVE layer (WI6 genesis-anchor: always consult >=1 honest node, so the
// victim sees the frozen/honest node and diverges) is required. This harness
// MEASURES the margin instead of assuming it.
//
// Method (what is REPRODUCIBLE on a single-host converged mesh):
//   * Seed X -> Y on ALL nodes so the whole mesh retains previous_state=X (the
//     detection substrate). A FRESH wallet id per run (SystemTime-salted) avoids
//     cross-run state pollution.
//   * Inject the forged re-anchor X -> X' to ONE node only (single-point — the
//     realistic entry: the fork lands at one compromised / lagging node, not the
//     whole mesh at once). check-3's endorsement model then propagates: every
//     honest holder independently re-detects and freezes.
//   * Time BOTH clocks from injection: T_freeze (all nodes Frozen) and the
//     forged-value window (any moment >= POSITIVE_QUORUM nodes serve head=X' as
//     NORMAL). Report the margin vs the §4.6 value-realization floor.
//
// NOT reproduced here (DEFERRED to multi-host, per the design): a GENUINELY
// wiped / partitioned node that ADOPTS X' and serves forged value before the
// Frozen status reaches it. On one converged host, gossip + anti-entropy keep
// every node synced, so no node ever serves the forged head — which is itself
// the key single-host finding (the forged value never reaches a clean quorum).
// The partition case is exactly where the PREVENTIVE WI6 genesis-anchor is
// load-bearing; measuring it requires real partition tooling (kill connectivity
// + wipe + rejoin) across hosts.
//
// Self-contained (zero-pk gossip, fresh throwaway 0xC4 wallet id) — never
// touches a real soak wallet. Master-compatible wire (no WI3 seq_proof).
//
// Usage: ki34_wi4_race [addr ...]   (default 127.0.0.1:7300..=7309)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use axiom_nabla::crypto::{receipt_sign_payload, Ed25519Signer, Signer};
use axiom_nabla::transport::WireMessage;
use axiom_nabla::types::{GossipMessage, WitnessSig};
use axiom_nabla::wire_client::QueryWalletStateRequest;

type B32 = [u8; 32];

/// §4.6 positive-quorum: 2 agreeing nodes needed to certify forked value.
const POSITIVE_QUORUM: usize = 2;
/// §4.6 value-realization FLOOR — a receiver's verify_cheque sleeps one TARDIS
/// tick (Timer A) plus two query waves, so it cannot complete in under ~one
/// tick. The reference the freeze margin is judged against.
const TICK_SECS: u64 = 5;
/// How long to watch the race before giving up (a freeze that hasn't completed
/// by here is itself a finding — report it).
// Latency-aware: under injected per-node network delay (AXIOM_SIM_NET_DELAY_MAX_MS)
// every query eats 0–600 ms and freeze/AE propagation is genuinely slow, so the watch
// window is generous. With no delay this just exits early on the freeze/convergence.
const WATCH_MS: u64 = 180_000;
const POLL_MS: u64 = 50;
/// Max wait for the seed `X→Y` to CONVERGE mesh-wide before injecting the fork —
/// under latency the seed itself takes seconds to reach every node; injecting before
/// it converges measures nothing (the substrate isn't established).
const SEED_CONVERGE_MS: u64 = 90_000;

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

/// (wallet_status, current_state) or None on NOT_FOUND / IO error.
fn query(addr: &str, wallet: &B32) -> Option<(String, Vec<u8>)> {
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
            if r.status == "NOT_FOUND" {
                None
            } else {
                Some((r.wallet_status, r.current_state))
            }
        }
        _ => None,
    }
}

/// Query ALL nodes IN PARALLEL (one thread each) — under per-node latency a
/// sequential sweep would take sum(delays) ≈ 3 s and blur the timing; parallel makes
/// a poll ≈ max(delay) ≈ 600 ms, preserving resolution. Returns each node's
/// (wallet_status, current_state) or None (NOT_FOUND / unreachable), index-aligned.
fn poll_all(nodes: &[String], w: &B32) -> Vec<Option<(String, Vec<u8>)>> {
    let handles: Vec<_> = nodes
        .iter()
        .map(|a| {
            let a = a.clone();
            let w = *w;
            std::thread::spawn(move || query(&a, &w))
        })
        .collect();
    handles.into_iter().map(|h| h.join().unwrap_or(None)).collect()
}

fn state_update(w: &B32, new: &B32, tick: u64) -> WireMessage {
    let mut tx = *w;
    tx[31] = (tick & 0xff) as u8;
    WireMessage::Gossip(GossipMessage::StateUpdate {
        wallet_id: *w,
        new_state: *new,
        tx_hash: tx,
        tick,
        wallet_seq: 0,           // wire-fix (WI3 merge): seq 0 + no proof => accepted on the tick path
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
    })
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let nodes: Vec<String> = if args.is_empty() {
        (7300..=7309).map(|p| format!("127.0.0.1:{p}")).collect()
    } else {
        args
    };
    let n = nodes.len();
    // Fresh wallet per run (salt the id's 2nd byte from SystemTime) so repeated
    // runs never collide on accumulated SMT state.
    let salt = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_nanos() as u8) | 1)
        .unwrap_or(0x01);
    let w = id(0xC4, salt);
    let (x, y, xp) = (id(0xA0, salt), id(0xA1, salt), id(0xAF, salt));
    println!("KI#34 WI4 dual-timing freeze-vs-value race against {n} nodes: {nodes:?}");
    println!("  wallet={} (fresh)  X={} Y={} X'={}\n", hex8(&w), hex8(&x), hex8(&y), hex8(&xp));

    // ── Seed X -> Y on ALL nodes so the whole mesh holds previous_state=X, then
    //    WAIT FOR CONVERGENCE (latency-aware): poll until every node serves head Y
    //    before injecting. Under injected latency a fixed settle is far too short —
    //    the seed itself takes seconds to reach every node, and injecting before it
    //    converges measures nothing (no substrate). Re-send periodically to overcome
    //    dropped/late gossip. ──
    let conv_start = Instant::now();
    let mut converged = 0usize;
    loop {
        for addr in &nodes {
            send_oneway(addr, &state_update(&w, &x, 1));
            send_oneway(addr, &state_update(&w, &y, 2));
        }
        std::thread::sleep(Duration::from_millis(800)); // let the latency-delayed gossip land
        converged = poll_all(&nodes, &w)
            .iter()
            .filter(|v| matches!(v, Some((_, h)) if h == &y.to_vec()))
            .count();
        if converged == n {
            println!("[seed] X→Y converged on {n}/{n} nodes in {} ms", conv_start.elapsed().as_millis());
            break;
        }
        if conv_start.elapsed().as_millis() as u64 >= SEED_CONVERGE_MS {
            println!(
                "[seed] convergence INCOMPLETE: {converged}/{n} hold Y after {} ms — race result \
                 below may understate the substrate (some nodes never got the seed).",
                conv_start.elapsed().as_millis()
            );
            break;
        }
    }

    // ── Inject the forged re-anchor X->X' to ONE node (single-point entry).
    //    T0 = the moment of injection; check-3 endorsement must propagate the
    //    freeze across the rest of the mesh. ──
    println!("[inject] HAL re-anchor X->X' (k=3) to ONE node ({}); starting race clock\n", nodes[0]);
    let t0 = Instant::now();
    send_oneway(&nodes[0], &hal_advance(&w, &x, &xp, 3, 3));
    let detectors = n; // all nodes hold previous_state; labelling for the dump

    // ── Poll both clocks until the mesh fully freezes or WATCH_MS elapses. ──
    let mut t_freeze_all_ms: Option<u64> = None;
    let mut forged_window_open_ms: Option<u64> = None; // first ms a 2-of-N clean X' was servable
    let mut forged_window_close_ms: Option<u64> = None; // last such ms
    let mut max_forged_servers = 0usize;

    let mut polls = 0u64;
    // PARALLEL polls (poll_all) so per-node latency doesn't blur the timing. Each
    // poll ≈ max single-node delay (~600 ms under injection), not the sum.
    loop {
        let mut frozen = 0usize;
        let mut forged_normal = 0usize; // serving head=X' as NORMAL (= forged value)
        for v in poll_all(&nodes, &w) {
            match v {
                Some((status, head)) => {
                    let is_frozen = status == "FROZEN" || status == "BANNED";
                    if is_frozen {
                        frozen += 1;
                    } else if head == xp.to_vec() {
                        forged_normal += 1;
                    }
                }
                None => {} // NOT_FOUND
            }
        }
        polls += 1;
        max_forged_servers = max_forged_servers.max(forged_normal);
        let now_ms = t0.elapsed().as_millis() as u64; // stamp AFTER the queries

        // Value clock: is forged value realizable RIGHT NOW (>= quorum clean X')?
        if forged_normal >= POSITIVE_QUORUM {
            forged_window_open_ms.get_or_insert(now_ms);
            forged_window_close_ms = Some(now_ms);
        }
        // Freeze clock: all nodes Frozen — stamp at CONFIRMATION (includes the
        // confirming poll's round-trips, so the number never reads as instant).
        if frozen == n {
            t_freeze_all_ms = Some(now_ms);
            break;
        }
        if now_ms >= WATCH_MS {
            break;
        }
        std::thread::sleep(Duration::from_millis(POLL_MS));
    }

    // ── Per-node final state (transparency: shows what each node ended as) ──
    println!("── PER-NODE FINAL STATE ────────────────────────────────────────");
    let _ = detectors;
    for (i, addr) in nodes.iter().enumerate() {
        let role = if i == 0 { "inject" } else { "holder" };
        let s = match query(addr, &w) {
            Some((status, head)) => {
                let tag = if status == "FROZEN" || status == "BANNED" {
                    "FROZEN".to_string()
                } else if head == xp.to_vec() {
                    "SERVING-X'(forged,NORMAL)".to_string()
                } else if head == y.to_vec() {
                    "honest head Y".to_string()
                } else {
                    format!("{status} head={}", hex8(&head))
                };
                tag
            }
            None => "NOT_FOUND".to_string(),
        };
        println!("  {addr} [{role}] -> {s}");
    }
    println!();

    // ── Report ──────────────────────────────────────────────────────────────
    println!("── RESULT ──────────────────────────────────────────────────────");
    println!("wallet={}  X={} Y={} X'={}", hex8(&w), hex8(&x), hex8(&y), hex8(&xp));
    match t_freeze_all_ms {
        Some(ms) => {
            let res = if polls <= 1 {
                " (complete by the FIRST poll — propagation below harness resolution, \
                 but decisively under the floor)"
            } else {
                ""
            };
            println!("freeze-propagation : ALL {n} nodes Frozen by T+{ms} ms over {polls} poll(s){res}");
        }
        None => println!(
            "freeze-propagation : INCOMPLETE within {WATCH_MS} ms ({polls} polls) — mesh did NOT \
             fully freeze (THIS WOULD BE A FINDING)"
        ),
    }
    let floor_ms = TICK_SECS * 1000;
    println!(
        "value-realization  : §4.6 floor (1 TARDIS tick Timer-A) = {floor_ms} ms; \
         peak forged servers = {max_forged_servers}/{n} (need {POSITIVE_QUORUM})"
    );
    match (forged_window_open_ms, forged_window_close_ms) {
        (Some(o), Some(c)) => println!(
            "forged-value window: clean {POSITIVE_QUORUM}-of-N X' was servable T+{o}..{c} ms \
             (open {} ms)",
            c.saturating_sub(o)
        ),
        _ => println!(
            "forged-value window: NONE — forged X' never reached a {POSITIVE_QUORUM}-of-N clean \
             confirmation (n-of-N defeated it on its own)"
        ),
    }
    println!();

    // Verdict. Two independent ways the retroactive defense can hold:
    //   (1) the forged head never reached a clean quorum at all (n-of-N win), OR
    //   (2) the mesh froze before the §4.6 value-realization floor could elapse.
    let nofn_win = forged_window_open_ms.is_none();
    let freeze_before_floor = t_freeze_all_ms.map(|f| f < floor_ms).unwrap_or(false);
    let verdict_pass = nofn_win || freeze_before_floor;

    if nofn_win {
        println!("[reason] forged value never reached a clean {POSITIVE_QUORUM}-of-N quorum.");
    }
    if let Some(f) = t_freeze_all_ms {
        let margin = floor_ms as i64 - f as i64;
        println!(
            "[margin] freeze-all {f} ms vs §4.6 floor {floor_ms} ms = {margin:+} ms \
             ({})",
            if margin >= 0 { "freeze wins" } else { "freeze LOSES the race" }
        );
    }
    if !verdict_pass {
        println!(
            "\n[note] retroactive freeze did NOT clearly win — this is exactly the case the \n\
             PREVENTIVE WI6 genesis-anchor closes: a receiver always consults >=1 honest node \n\
             (a detector / Frozen holder), diverges, and never accepts the forged value."
        );
    }

    println!(
        "\nKI#34 WI4: {}",
        if verdict_pass {
            "RETROACTIVE DEFENSE HOLDS (freeze wins or n-of-N defeats forged value)"
        } else {
            "RETROACTIVE DEFENSE INSUFFICIENT — WI6 preventive layer is load-bearing"
        }
    );
    if !verdict_pass {
        std::process::exit(1);
    }
}
