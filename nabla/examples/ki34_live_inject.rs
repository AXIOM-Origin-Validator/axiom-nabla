// ⚠ RETIRED PATH (2026-09-30, Fork Settlement §9q, design B2 — docs/AXIOM_DESIGN_ForkSettlement.md):
// this harness drives the KI#34 check-3 / YPX-025 E3 `HalAdvance` arm, which is now a TOMBSTONE — a node of
// this build DROPS every `HalAdvance` unverified (counted `haladvance_dropped` on /status) and never freezes
// on it. A HAL re-anchor floods as a plain `StateUpdate` with its leg and a revival is BANNED on A1 evidence.
// Its assertions (freeze / freeze-race / shed) describe the retired behaviour; kept compiling as history.
// The in-process proofs of the replacement are `fork_detection_mesh::b2_*`.
// KI#34 check-3 — LIVE A/B/C fork-ban injection harness.
//
// Talks to a running nabla-node mesh over real TCP (length-prefixed bincode
// WireMessage), exercising the deployed HAL-revival fork detector end to end:
// real binary, real serialization of the new HalAdvance variant, real Ed25519
// k3-sig verification (prod uses Ed25519Signer, not NoopSigner).
//
// Self-contained: it establishes a throwaway wallet's mesh state by injecting
// StateUpdate gossip directly (zero client_pk skips client-sig verification, the
// same path the soak's zero-pk registrations take), so it never touches a real
// soak wallet. Forged HalAdvance k3 sigs are self-generated Ed25519 keypairs —
// they verify under the carried validator_pk exactly as the shipped
// BanTable::verify_conflict standard checks them, hitting the identical code path
// a genuine wipe+re-anchor would.
//
// Scenarios (all assert via QueryWalletStateRequest across EVERY node):
//   A     respend of a consumed state X (head moved X->Y) -> every holder FREEZES,
//         forked head X' is NOT adopted (head stays Y).
//   A-neg under-witnessed (<k=3) revival -> NOT frozen (anti-framing).
//   B     wiped memory (no retained previous_state) -> NOT frozen (no false +ve).
//   C     inject HAL to ONE node only -> the forwarded advance makes the OTHER
//         holders independently re-detect + freeze (endorsement propagation).
//
// Usage: ki34_live_inject [addr ...]   (default 127.0.0.1:7300..=7309)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use axiom_nabla::crypto::{receipt_sign_payload, Ed25519Signer, Signer};
use axiom_nabla::transport::WireMessage;
use axiom_nabla::types::{GossipMessage, WitnessSig};
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
        let len = (bytes.len() as u32).to_be_bytes();
        let _ = s.write_all(&len);
        let _ = s.write_all(&bytes);
        let _ = s.flush();
    }
}

/// Returns (wallet_status, current_state) or None on NOT_FOUND / IO error.
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

fn state_update(w: &B32, new: &B32, tick: u64) -> WireMessage {
    let mut tx = *w;
    tx[31] = (tick & 0xff) as u8;
    WireMessage::Gossip(GossipMessage::StateUpdate {
        is_genesis_claim: false,
        old_state: [0u8; 32],
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
            // Distinct self-generated Ed25519 keypair per sig.
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
    println!("KI#34 live A/B/C injection against {} nodes: {:?}\n", nodes.len(), nodes);
    let mut failures = 0u32;

    // Helper: assert every node reports `want_status` and (if Some) head==want_head.
    let assert_all = |label: &str, w: &B32, want_status: &str, want_head: Option<&B32>, fails: &mut u32| {
        let mut ok = true;
        for addr in &nodes {
            match query(addr, w) {
                Some((status, head)) => {
                    if status != want_status {
                        println!("  [FAIL] {label}: {addr} status={status} want={want_status}");
                        ok = false;
                    }
                    if let Some(wh) = want_head {
                        if head != wh.to_vec() {
                            println!("  [FAIL] {label}: {addr} head={} want={}",
                                hex16(&head), hex16(&wh.to_vec()));
                            ok = false;
                        }
                    }
                }
                None => {
                    println!("  [FAIL] {label}: {addr} NOT_FOUND (expected {want_status})");
                    ok = false;
                }
            }
        }
        if ok {
            println!("  [PASS] {label}: all {} nodes report {want_status}{}",
                nodes.len(),
                want_head.map(|h| format!(" + head={}", hex16(&h.to_vec()))).unwrap_or_default());
        } else {
            *fails += 1;
        }
    };

    // ── FUNDED — HAL-revival respend ban against a REAL funded wallet ─────────
    // The Python partition harness (tests/dsfork_funded_partition.py) funds S for
    // real, does a real send (S advances X0 -> X1, so the mesh retains the consumed
    // old_state X0 as this wallet's previous_state), then calls this to inject the
    // HAL-revival conflict: re-anchor X0 -> Z with Z != X1 (S, on a would-be second
    // partition half, tries to HAL-re-anchor its PRE-send state and re-spend it — the
    // exact overlap-bypass double-spend). check-3: an honest node retaining
    // previous_state=X0 detects the fork of a consumed state, emits an endorsed
    // BanAlert -> FROZEN mesh-wide RETROACTIVELY, even though X1 already happened.
    //   AXIOM_KI34_MODE      = "funded"
    //   AXIOM_KI34_WID       = hex S.public_key (wallet_id)
    //   AXIOM_KI34_X0        = hex S's pre-send (post-genesis) state = the consumed old_state
    //   AXIOM_KI34_X1        = hex S's post-send head (for the head assert)
    //   AXIOM_KI34_ESTABLISH = "1" to also inject the X0->X1 chain (fallback when the
    //                          real registration did not set previous_state on the mesh)
    if std::env::var("AXIOM_KI34_MODE").as_deref() == Ok("funded") {
        let hexb = |v: &str| -> B32 {
            let mut w = [0u8; 32];
            let by: Vec<u8> = (0..v.len() / 2)
                .map(|i| u8::from_str_radix(&v[2 * i..2 * i + 2], 16).unwrap_or(0))
                .collect();
            let n = by.len().min(32);
            w[..n].copy_from_slice(&by[..n]);
            w
        };
        let wid = hexb(&std::env::var("AXIOM_KI34_WID").unwrap_or_default());
        let x0 = hexb(&std::env::var("AXIOM_KI34_X0").unwrap_or_default());
        let x1 = hexb(&std::env::var("AXIOM_KI34_X1").unwrap_or_default());
        let mut z = wid; // synthetic revival successor, != x0 and != x1
        z[0] = 0xFA;
        z[31] = 0x01;
        println!(
            "[FUNDED] HAL-revival: wid={} x0(consumed)={} x1(head)={} -> re-anchor to Z={}",
            hex16(&wid), hex16(&x0), hex16(&x1), hex16(&z)
        );
        if std::env::var("AXIOM_KI34_ESTABLISH").as_deref() == Ok("1") {
            println!("  establishing X0->X1 chain (previous_state=X0) via injected state_updates");
            for addr in &nodes {
                send_oneway(addr, &state_update(&wid, &x0, 1));
                send_oneway(addr, &state_update(&wid, &x1, 2));
            }
            sleep(1000);
        }
        // SINGLE mode: inject the HAL-revival to node[0] ONLY. The freeze must then
        // PROPAGATE to every other node via the check-3 endorsement model (node[0]
        // detects → emits BanAlert → ≥3 nodes endorse against their own retained
        // previous_state → mesh-wide FROZEN). Re-inject to node[0] each poll round to
        // defeat lossy one-way gossip (NOT to the others — they must learn via
        // endorsement propagation, the whole point). Default (non-SINGLE) injects to all
        // = independent detection only.
        let single = std::env::var("AXIOM_KI34_SINGLE").as_deref() == Ok("1");
        let hal = hal_advance(&wid, &x0, &z, 3, 3);
        if single {
            println!("  [SINGLE] inject HAL-revival to node[0] ONLY; freeze must PROPAGATE via endorsement");
            send_oneway(&nodes[0], &hal);
        } else {
            for addr in &nodes {
                send_oneway(addr, &hal);
            }
        }
        // Fine-grained timing: record the elapsed-ms at which each node FIRST reports
        // FROZEN, relative to the injection at t0. In SINGLE mode node[0] is the injected
        // detector (self-detect); every OTHER node freezing is endorsement propagation.
        let t0 = std::time::Instant::now();
        let mut first_ms: Vec<Option<u128>> = vec![None; nodes.len()];
        loop {
            for (i, a) in nodes.iter().enumerate() {
                if first_ms[i].is_none() {
                    if let Some((s, _)) = query(a, &wid) {
                        if s == "FROZEN" || s == "BANNED" {
                            first_ms[i] = Some(t0.elapsed().as_millis());
                        }
                    }
                }
            }
            let n = first_ms.iter().filter(|x| x.is_some()).count();
            if n == nodes.len() || t0.elapsed().as_secs() >= 20 {
                break;
            }
            if single {
                send_oneway(&nodes[0], &hal); // re-inject to the detector only
            }
            sleep(20);
        }
        let frozen = first_ms.iter().filter(|x| x.is_some()).count();
        // t_first = earliest frozen among nodes OTHER than the injected detector (index 0
        // in SINGLE); t_quorum = 3rd node to freeze; t_all = last.
        let mut times: Vec<u128> = first_ms.iter().filter_map(|x| *x).collect();
        times.sort();
        let t_quorum = times.get(2).copied();
        let t_all = if frozen == nodes.len() { times.last().copied() } else { None };
        let t_first_prop = if single {
            (1..nodes.len()).filter_map(|i| first_ms[i]).min()
        } else {
            times.first().copied()
        };
        let detail: Vec<String> = nodes
            .iter()
            .enumerate()
            .map(|(i, a)| match query(a, &wid) {
                Some((s, h)) => format!(
                    "{a}={s}(head={}){}",
                    hex16(&h),
                    first_ms[i].map(|m| format!(" first_frozen={m}ms")).unwrap_or_default()
                ),
                None => format!("{a}=NOT_FOUND"),
            })
            .collect();
        println!(
            "[FUNDED] FROZEN/BANNED on {}/{} nodes  (mode={})",
            frozen,
            nodes.len(),
            if single { "SINGLE-point→propagate" } else { "all-node" }
        );
        println!(
            "[TIMING] t_inject=0ms  t_first_propagated={}  t_quorum(3)={}  t_all(10)={}  \
             (poll resolution ~10-20ms; SINGLE: node[0] self-detects, others via endorsement)",
            t_first_prop.map(|m| format!("{m}ms")).unwrap_or("n/a".into()),
            t_quorum.map(|m| format!("{m}ms")).unwrap_or("n/a".into()),
            t_all.map(|m| format!("{m}ms")).unwrap_or("NOT-ALL".into())
        );
        for d in &detail {
            println!("    {d}");
        }
        // SINGLE requires FULL propagation (all nodes) to prove endorsement; all-node
        // mode requires >=1 (independent detection).
        let pass = if single { frozen == nodes.len() } else { frozen >= 1 };
        std::process::exit(if pass { 0 } else { 1 });
    }

    // ── Scenario A — respend of a consumed state is detected + frozen ────────
    {
        let w = id(0xC0, 0xA1);
        let (x0, x1, x0p) = (id(0xA0, 0xA1), id(0xA1, 0xA1), id(0xAF, 0xA1));
        println!("[A] respend-detect: establish head Y via X on all nodes, then re-anchor X->X'");
        for addr in &nodes {
            send_oneway(addr, &state_update(&w, &x0, 1));
            send_oneway(addr, &state_update(&w, &x1, 2));
        }
        sleep(800);
        for addr in &nodes {
            send_oneway(addr, &hal_advance(&w, &x0, &x0p, 3, 3));
        }
        sleep(1200);
        assert_all("A", &w, "FROZEN", Some(&x1), &mut failures);
    }

    // ── Scenario A-neg — under-witnessed revival must NOT freeze ─────────────
    {
        let w = id(0xC0, 0xA2);
        let (x0, x1, x0p) = (id(0xA0, 0xA2), id(0xA1, 0xA2), id(0xAF, 0xA2));
        println!("[A-neg] anti-framing: same fork shape but only 2 sigs (<k=3)");
        for addr in &nodes {
            send_oneway(addr, &state_update(&w, &x0, 1));
            send_oneway(addr, &state_update(&w, &x1, 2));
        }
        sleep(800);
        for addr in &nodes {
            send_oneway(addr, &hal_advance(&w, &x0, &x0p, 3, 2));
        }
        sleep(1200);
        assert_all("A-neg", &w, "NORMAL", Some(&x1), &mut failures);
    }

    // ── Scenario B — no false-freeze when old_state != retained previous_state ──
    // Wiped/never-recorded memory: a single head, so previous_state is unknown
    // mesh-wide. A HalAdvance whose old_state the node never recorded as THIS
    // wallet's consumed state is NOT a detectable conflict — it must NOT freeze
    // (no false positive). It instead applies as an ordinary advance (head moves
    // to new_state). This is also the documented residual floor: with NO honest
    // holder retaining previous_state the revival goes undetected — which is
    // exactly why check-3 requires >=1 honest holder (provided by A and C).
    {
        let w = id(0xC0, 0xB1);
        let (x1, x1p) = (id(0xA1, 0xB1), id(0xAF, 0xB1));
        let x0_unknown = id(0xA0, 0xB1); // a state the mesh never recorded as consumed
        println!("[B] no-false-freeze: old_state never recorded as this wallet's previous_state");
        for addr in &nodes {
            send_oneway(addr, &state_update(&w, &x1, 1)); // single update, no prior advance
        }
        sleep(800);
        for addr in &nodes {
            send_oneway(addr, &hal_advance(&w, &x0_unknown, &x1p, 2, 3));
        }
        sleep(1200);
        // Must NOT freeze; non-conflicting advance is applied (head -> new_state).
        assert_all("B", &w, "NORMAL", Some(&x1p), &mut failures);
    }

    // ── Scenario B2 — honest active wallet not false-frozen by unrelated fork ──
    // The node DOES retain previous_state=X0 (head moved X0->X1), but the incoming
    // HalAdvance re-anchors a DIFFERENT state Z (Z != X0). The detector keys on an
    // EXACT previous_state match, so this is not a conflict -> no freeze. Proves an
    // honest active wallet can't be griefed by a re-anchor of some other state.
    {
        let w = id(0xC0, 0xB2);
        let (x0, x1) = (id(0xA0, 0xB2), id(0xA1, 0xB2));
        let (z, zp) = (id(0xD0, 0xB2), id(0xDF, 0xB2)); // unrelated state Z and Z'
        println!("[B2] honest wallet (previous_state=X0) gets unrelated re-anchor of Z (!=X0)");
        for addr in &nodes {
            send_oneway(addr, &state_update(&w, &x0, 1));
            send_oneway(addr, &state_update(&w, &x1, 2));
        }
        sleep(800);
        for addr in &nodes {
            send_oneway(addr, &hal_advance(&w, &z, &zp, 3, 3));
        }
        sleep(1200);
        // Z != previous_state(X0) -> not a conflict -> must stay NORMAL.
        assert_all("B2", &w, "NORMAL", None, &mut failures);
    }

    // ── Scenario C — single-point injection, endorsement propagates freeze ───
    {
        let w = id(0xC0, 0xC1);
        let (x0, x1, x0p) = (id(0xA0, 0xC1), id(0xA1, 0xC1), id(0xAF, 0xC1));
        println!("[C] endorsement propagation: setup on all, inject HAL to ONE node only");
        for addr in &nodes {
            send_oneway(addr, &state_update(&w, &x0, 1));
            send_oneway(addr, &state_update(&w, &x1, 2));
        }
        sleep(800);
        send_oneway(&nodes[0], &hal_advance(&w, &x0, &x0p, 3, 3)); // ONE node
        sleep(2500); // allow forward + independent re-detection across the mesh
        assert_all("C", &w, "FROZEN", Some(&x1), &mut failures);
    }

    println!();
    if failures == 0 {
        println!("KI#34 LIVE A/B/C: ALL SCENARIOS PASS");
    } else {
        println!("KI#34 LIVE A/B/C: {failures} SCENARIO(S) FAILED");
        std::process::exit(1);
    }
}

fn hex16(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}
