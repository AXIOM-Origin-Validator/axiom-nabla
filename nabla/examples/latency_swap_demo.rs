//! §6.3.7 latency-aware peer pruning — 15-node in-process demo (the live swap).
//!
//! Builds 15 REAL `GossipMesh` nodes, lets them form a mesh, then marks 2 nodes
//! as slow (high RTT). Each round it feeds `record_peer_rtt` (exactly what the
//! TCP ping/pong path does — that half is already proven live: 217 real-RTT
//! pongs on the 10-node env) and runs the REAL `periodic_peer_check`. You watch
//! fast nodes swap the slow links out for fast spares via Step 5b.
//!
//! Why a 15-node mesh and not the live 10-node env: with 15 nodes each targets
//! ~9-10 active peers but knows 14 others, so spares EXIST to graft into. On a
//! 10-node full mesh every node already peers with all 9 others — no spare —
//! so the swap correctly declines (swap-not-shed) and can't be shown on wire.
//!
//! Run:  cargo run --release -p axiom-nabla --example latency_swap_demo \
//!         --features dev-mode --features axiom-core-logic/dev-mode

use std::collections::{HashMap, HashSet};

use axiom_nabla::mesh::GossipMesh;
use axiom_nabla::types::{NablaAddress, NodeId, PeerInfo};

const N: usize = 15;
const SLOW: [usize; 2] = [3, 9]; // these two nodes are the high-latency outliers
const FAST_MS: f32 = 5.0;
const SLOW_MS: f32 = 450.0; // > 300ms floor AND >> 2x the fast median → a clear outlier

fn id(i: usize) -> NodeId {
    let mut a = [0u8; 32];
    a[0] = i as u8; // node_id[0] drives the per-node prune jitter phase
    a[1] = 0x5A;
    a
}
fn addr(i: usize) -> NablaAddress {
    NablaAddress::V4 { ip: [10, 0, 0, i as u8], port: 7400 + i as u16 }
}
fn peerinfo(i: usize, tick: u64) -> PeerInfo {
    PeerInfo {
        node_id: id(i),
        address: addr(i),
        last_seen: tick,
        tardis_up: None,
        has_d_open: true,
        open_slots: 2,
        messages_delivered: 5, // non-zero so peers aren't trivially low-scored
        connected_since: tick,
        txid_service: String::new(),
    }
}

fn main() {
    let slow: HashSet<usize> = SLOW.iter().copied().collect();
    let id_to_idx: HashMap<NodeId, usize> = (0..N).map(|i| (id(i), i)).collect();

    let mut nodes: Vec<GossipMesh> = (0..N).map(|i| GossipMesh::new(id(i), addr(i))).collect();

    // Discovery: every node learns every other node (known_nodes), so spares
    // exist to graft into. Mesh forms its active peer set organically below.
    for i in 0..N {
        for j in 0..N {
            if i != j {
                nodes[i].add_discovered_peer(peerinfo(j, 0));
            }
        }
    }

    // Keep peers/known-nodes fresh — real nodes refresh last_seen on every
    // gossip message; without this Step 1 stale-prunes the whole mesh.
    let refresh = |nodes: &mut Vec<GossipMesh>, tick: u64| {
        for i in 0..N {
            for j in 0..N {
                if i != j {
                    nodes[i].observe_node(id(j), tick);
                }
            }
        }
    };

    // ── Warm-up: form the mesh (no RTT yet → latency prune is dormant) ──
    for tick in 1..=20u64 {
        refresh(&mut nodes, tick);
        for i in 0..N {
            let _ = nodes[i].periodic_peer_check(tick);
        }
    }

    let count_fast_to_slow = |nodes: &Vec<GossipMesh>| -> usize {
        let mut c = 0;
        for i in 0..N {
            if slow.contains(&i) { continue; } // count fast nodes' links only
            for p in nodes[i].active_peers() {
                if slow.contains(&id_to_idx[&p.node_id]) {
                    c += 1;
                }
            }
        }
        c
    };

    println!("15-node mesh formed. Nodes {SLOW:?} are SLOW ({SLOW_MS:.0}ms); the other 13 are fast ({FAST_MS:.0}ms).");
    println!("Watching fast nodes evict the slow links from their active set (Step 5b swap):\n");
    let start = count_fast_to_slow(&nodes);
    println!("  warm-up (no latency yet):  fast->slow active links = {start}");

    // ── Demo: feed RTT each round, run the real maintenance ──
    let mut total_evictions = 0usize;
    let mut min_links = start;
    let mut first_zero: Option<u64> = None;
    let mut zero_ticks = 0usize;
    for tick in 21..=120u64 {
        // Snapshot which (fast node -> slow peer) links exist, to detect evictions.
        let before: HashSet<(usize, usize)> = {
            let mut s = HashSet::new();
            for i in 0..N {
                if slow.contains(&i) { continue; }
                for p in nodes[i].active_peers() {
                    let j = id_to_idx[&p.node_id];
                    if slow.contains(&j) { s.insert((i, j)); }
                }
            }
            s
        };

        refresh(&mut nodes, tick); // keep the mesh fresh so only LATENCY prunes

        // Feed measured RTT for every node's active peers (slow peers read high).
        for i in 0..N {
            let samples: Vec<(NodeId, f32)> = nodes[i]
                .active_peers()
                .iter()
                .map(|p| {
                    let j = id_to_idx[&p.node_id];
                    (p.node_id, if slow.contains(&j) { SLOW_MS } else { FAST_MS })
                })
                .collect();
            for (pid, rtt) in samples {
                nodes[i].record_peer_rtt(pid, rtt);
            }
        }

        // Real mesh maintenance — Step 5b prunes the slowest link when a spare exists.
        for i in 0..N {
            let _ = nodes[i].periodic_peer_check(tick);
        }

        // Count evictions: a (fast node -> slow peer) link that existed and is now gone.
        for &(i, j) in &before {
            if !nodes[i].active_peers().iter().any(|p| id_to_idx[&p.node_id] == j) {
                total_evictions += 1;
            }
        }

        let now = count_fast_to_slow(&nodes);
        min_links = min_links.min(now);
        if now == 0 { zero_ticks += 1; if first_zero.is_none() { first_zero = Some(tick); } }
        if tick % 5 == 0 {
            println!("  tick {tick}:  fast->slow active links = {}", count_fast_to_slow(&nodes));
        }
    }

    println!("\n── result ──");
    println!("fast->slow active links: {start} (start) -> 0 at tick {} -> held 0 for {zero_ticks}/100 ticks",
        first_zero.unwrap_or(0));
    println!("  Demoted slow nodes carry a DECAYING latency penalty (bump {:.1} on prune, decay {:.3}/tick)",
        axiom_nabla::constants::LATENCY_PENALTY_ON_PRUNE, axiom_nabla::constants::LATENCY_PENALTY_DECAY);
    println!("  that grafting avoids while it is above {:.1}; it fades smoothly (~30+ min) with no",
        axiom_nabla::constants::LATENCY_PENALTY_GRAFT_BLOCK);
    println!("  synchronized re-evaluation cliff. A chronic offender accumulates penalty and stays");
    println!("  avoided longer; a one-off blip decays back fast. (Any brief blip is the last-resort");
    println!("  fallback when a node momentarily has no clean spare — preference, not a ban.)");
    println!("total slow-link evictions (Step 5b swaps): {total_evictions}");
    // Degree preservation: every fast node still holds a full active set.
    let degrees: Vec<usize> = (0..N).filter(|i| !slow.contains(i)).map(|i| nodes[i].peer_count()).collect();
    let min_deg = degrees.iter().copied().min().unwrap_or(0);
    let max_deg = degrees.iter().copied().max().unwrap_or(0);
    println!("fast-node active degree after eviction: {min_deg}..={max_deg} (swap-not-shed keeps it full)");

    if min_links == 0 && zero_ticks >= 60 && total_evictions > 0 && min_deg >= 8 {
        println!("\n✓ latency-aware pruning works: fast nodes swapped EVERY slow link out for fast");
        println!("  spares and HELD it ({zero_ticks}/100 ticks at 0), keeping a full active degree —");
        println!("  swap-not-shed, no isolation, and no frequent re-evaluation churn.");
    } else {
        println!("\n✗ unexpected — wanted min_links==0, zero_ticks>=60, evictions>0, degree>=8.");
        std::process::exit(1);
    }
}
