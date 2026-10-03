// Diagnose a persistent multi-root mesh: find WHICH wallet entries differ.
//
// A root-hash mismatch tells you the trees differ; it never tells you where.
// This loads each node's latest on-disk snapshot and diffs the entries
// field-by-field, so the answer is an artifact (a wallet id and the exact field
// that disagrees) rather than an inference. RULE 0 §2.
//
// READ-ONLY. Safe to run against a live mesh.
//
// ⚠ LIVE ROOTS ARE AUTHORITATIVE; SNAPSHOTS LAG (fixed 2026-08-07).
// The first version read ONLY on-disk snapshots and reported "2 wallets in
// disagreement / theta on a different root" at a moment when all ten nodes were
// LIVE-identical — theta's newest snapshot was 11 minutes old, written before it
// adopted. A convergence check that reads stale state produces false failures,
// and this tool is the pass condition for the KI#77 convergence soak, so a false
// failure there would have been read as the fix not working.
//
// Now: live `/status` decides convergence. Snapshots are used only to say WHICH
// wallet differs when the live roots genuinely disagree, and their age is
// printed so a stale answer is never mistaken for a current one.
//
//   cargo run -p axiom-nabla --example root_divergence_diff \
//     --features dev-mode --features axiom-core-logic/dev-mode

use std::collections::{BTreeMap, HashMap};

use axiom_nabla::snapshot::SnapshotManager;
use axiom_nabla::types::NablaEntry;

const NODES: [&str; 10] = [
    "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
];

fn hx(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}

/// The fields that actually feed the SMT leaf hash / merge ordering. If two
/// nodes disagree on any of these for the same wallet, the roots MUST differ.
fn fingerprint(e: &NablaEntry) -> String {
    format!(
        "state={} tx={} seq={} tick={} status={:?} pk={} siglen={}",
        hx(&e.current_state),
        hx(&e.tx_hash),
        e.wallet_seq,
        e.tick,
        e.status,
        hx(&e.client_pk),
        e.client_sig.len(),
    )
}

/// Minimal HTTP GET — no dep needed for one line of JSON.
fn http_get(port: u16, path: &str) -> Option<String> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok()?;
    write!(s, "GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    buf.split_once("\r\n\r\n").map(|(_, body)| body.to_string())
}

/// The authoritative convergence signal: each node's LIVE root hash.
fn live_roots() -> Vec<(&'static str, Option<String>)> {
    NODES.iter().enumerate().map(|(i, name)| {
        let root = http_get(6226 + i as u16, "/status")
            .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("root_hash_hex").and_then(|r| r.as_str().map(String::from)));
        (*name, root)
    }).collect()
}

fn main() {
    let home = std::env::var("AXIOM_HOME").unwrap_or_else(|_| {
        format!("{}/axiom", std::env::var("HOME").expect("HOME"))
    });

    // ── Live roots first — this is what "converged" means ────────────────────
    println!("── LIVE roots (authoritative) ──");
    let live = live_roots();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut unreachable = 0;
    for (name, root) in &live {
        match root {
            Some(r) => { println!("  {name:<9} {r}"); seen.insert(r.clone()); }
            None => { println!("  {name:<9} UNREACHABLE"); unreachable += 1; }
        }
    }
    if unreachable > 0 {
        println!("\n  ⚠ {unreachable} node(s) unreachable — cannot judge convergence");
        std::process::exit(1);
    }
    if seen.len() == 1 {
        println!("\n✓ CONVERGED — all {} nodes on one live root", live.len());
        println!("  (snapshot diff skipped: it can only disagree by being stale)");
        return;
    }
    println!("\n✗ {} distinct live roots — digging into snapshots for WHICH wallet", seen.len());
    println!("  ⚠ snapshots lag; entries below may name wallets that have since converged\n");

    // node -> (wallet_id -> fingerprint)
    let mut per_node: BTreeMap<&str, HashMap<[u8; 32], String>> = BTreeMap::new();
    // node -> set of wallets it retains a k=3 seq attestation for (KI#38).
    // AE refuses an unattested head (`seq-unattested proof=ABSENT`), so a node
    // holding a head WITHOUT a proof can never hand it to anyone.
    let mut proofs: BTreeMap<&str, std::collections::HashSet<[u8; 32]>> = BTreeMap::new();
    let mut roots: BTreeMap<&str, String> = BTreeMap::new();

    for name in NODES {
        let dir = format!("{home}/axiom-first-penguin-{name}/snapshots");
        let store = match SnapshotManager::new(&dir) {
            Ok(s) => s,
            Err(e) => {
                println!("  [{name}] snapshot dir unreadable: {e:?}");
                continue;
            }
        };
        match store.load_latest() {
            Ok(Some(snap)) => {
                println!(
                    "  [{name}] tick={} root={} entries={}",
                    snap.tick,
                    hx(&snap.root_hash),
                    snap.entries.len()
                );
                roots.insert(name, hx(&snap.root_hash));
                per_node.insert(
                    name,
                    snap.entries
                        .iter()
                        .map(|e| (e.wallet_id, fingerprint(e)))
                        .collect(),
                );
                proofs.insert(name, snap.seq_proofs.iter().map(|(w, _)| *w).collect());
            }
            Ok(None) => println!("  [{name}] no snapshot"),
            Err(e) => println!("  [{name}] load failed: {e:?}"),
        }
    }

    // Majority fingerprint per wallet, then report every node that disagrees.
    let all_wallets: std::collections::BTreeSet<[u8; 32]> =
        per_node.values().flat_map(|m| m.keys().copied()).collect();

    println!("\n── per-wallet disagreement ──");
    let mut disagreements = 0usize;
    let mut blamed: BTreeMap<&str, usize> = BTreeMap::new();

    for w in &all_wallets {
        let mut tally: HashMap<&str, Vec<&str>> = HashMap::new();
        for (node, m) in &per_node {
            let fp = m.get(w).map(|s| s.as_str()).unwrap_or("<ABSENT>");
            tally.entry(fp).or_default().push(node);
        }
        if tally.len() <= 1 {
            continue;
        }
        disagreements += 1;
        // majority = largest group
        let mut groups: Vec<(&&str, &Vec<&str>)> = tally.iter().collect();
        groups.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
        println!("\n  wallet {}", hx(w));
        for (fp, nodes) in &groups {
            let tag = if nodes.len() == groups[0].1.len() { "majority" } else { "DIFFERS " };
            println!("    {tag} n={:<2} {:?}", nodes.len(), nodes);
            println!("             {fp}");
        }
        // Decisive question: does the MINORITY holder retain a seq proof for
        // the head it is offering? If not, AE can never adopt it and the
        // divergence is permanent — the node stored what it cannot justify.
        for (_, nodes) in groups.iter().skip(1) {
            for n in nodes.iter() {
                let has = proofs.get(*n).is_some_and(|s| s.contains(w));
                println!("             ^ {n} seq_proof retained: {}",
                    if has { "YES" } else { "NO  <-- cannot attest -> AE refuses forever" });
            }
        }
        for (_, nodes) in groups.iter().skip(1) {
            for n in nodes.iter() {
                *blamed.entry(n).or_default() += 1;
            }
        }
    }

    println!("\n── summary ──");
    println!("  wallets compared: {}", all_wallets.len());
    println!("  wallets in disagreement: {disagreements}");
    if blamed.is_empty() {
        println!("  no minority entries — snapshots agree (divergence is in-memory only,");
        println!("  or the snapshots were taken at different ticks)");
    } else {
        println!("  minority-side entry count by node:");
        for (n, c) in &blamed {
            println!("    {n:<9} {c}");
        }
    }
    println!("\n  roots: {roots:?}");
}
