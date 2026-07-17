// AXIOM Nabla — Binary Simulator
//
// Spawns real nabla-node processes in --mode=stdio and routes messages
// between them. Same metrics as the in-process (lib) simulator.
//
// Architecture:
//   - Each node is a child process: `nabla-node --mode stdio --port <virtual_port>`
//   - Sim writes StdioEnvelope JSON to each process's stdin
//   - Sim reads StdioEnvelope JSON from each process's stdout
//   - Sim acts as the network: routes, delays, drops (chaos)
//   - StatusRequest/StatusResponse for metrics collection
//
// Protocol/Simulator separation (YPX-003 §2.6):
//   All protocol decisions are inside the nabla-node binary (library code).
//   This module only orchestrates message routing and collects metrics.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::sim::{NetworkState, NodeState, LinkStateExport, TardisLinkExport, TardisApprovalExport, NetworkStats};
use crate::transport::{StdioEnvelope, WireMessage};
use crate::types::NodeId;

/// Status snapshot for a single binary node.
#[derive(Debug, Clone, Default)]
pub struct BinaryNodeStatus {
    pub node_id: NodeId,
    pub node_name: String,
    pub needs_parent: bool,
    pub downstream_count: usize,
    pub is_leaf: bool,
    pub has_d_open: bool,
    pub alive: bool,
    pub smt_len: usize,
    pub peer_count: usize,
    // dev-status enrichment
    pub tardis_tick: u64,
    pub root_hash: [u8; 32],
    pub messages_received: u64,
    pub upstream_id: Option<NodeId>,
    pub d1_id: Option<NodeId>,
    pub d2_id: Option<NodeId>,
    pub d1_approved: bool,
    pub d2_approved: bool,
    pub known_nodes: usize,
    pub gossip_active: bool,
    // Persistence metrics
    pub wal_file_bytes: u64,
    pub wal_ops_since_snapshot: u64,
    pub snapshot_count: usize,
    pub snapshot_total_bytes: u64,
    pub last_snapshot_tick: u64,
    pub total_disk_bytes: u64,
    pub smt_memory_bytes: u64,
    pub nbc_issuer: String,
}

/// Stats matching the lib-mode NetworkStats for dashboard compatibility.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BinaryNetworkStats {
    pub total_nodes: usize,
    pub alive_nodes: usize,
    pub total_messages: u64,
    pub tardis_sync_pct: f64,
    pub tardis_writer_pct: f64,
    pub tardis_orphans: usize,
}

/// A child node process.
struct NodeProcess {
    /// Index in the node array.
    idx: usize,
    /// Virtual address for routing (10.0.{idx/256}.{idx%256}:6225).
    virtual_addr: SocketAddr,
    /// Child process handle.
    child: Child,
    /// Write to this to send messages to the node's stdin.
    stdin_tx: Arc<Mutex<Box<dyn Write + Send>>>,
    /// Messages read from this node's stdout, waiting to be routed.
    outbox: Arc<Mutex<Vec<StdioEnvelope>>>,
    /// Last known status.
    status: BinaryNodeStatus,
    /// Whether the process is alive.
    alive: bool,
}

/// Binary sim network: manages child processes and routes messages.
pub struct BinarySimNetwork {
    /// All node processes.
    nodes: Vec<NodeProcess>,
    /// Virtual address → node index mapping.
    addr_to_idx: HashMap<String, usize>,
    /// Blocked links (idx, idx) for chaos simulation.
    blocked: HashSet<(usize, usize)>,
    /// Total messages routed.
    pub total_messages: u64,
    /// Current tick counter.
    pub tick: u64,
    /// Path to nabla-node binary.
    binary_path: PathBuf,
    /// Base data directory.
    base_dir: PathBuf,
    /// Target node count.
    target_count: usize,
    /// Tick interval in ms (passed to child processes via --tick-ms).
    tick_ms: u64,
    /// Shared wall-clock start (unix ms) so all nodes compute synchronized
    /// virtual clocks from the same reference point.
    epoch_ms: u64,
    /// Sim option: 1=default, 2=non-genesis obtain NBC from peers, 3=skip genesis.
    sim_option: u8,
}

impl BinarySimNetwork {
    /// Create a new binary sim network.
    ///
    /// `binary_path`: path to the compiled nabla-node binary.
    /// `base_dir`: AXIOM_DATA_DIR (for ceremony NBCs, etc.).
    /// `total_count`: total number of nodes to spawn.
    pub fn new(binary_path: PathBuf, base_dir: PathBuf, total_count: usize, speed: u64, sim_option: u8) -> Self {
        let tick_ms = if speed == 0 { 5000 } else { 1000 / speed };
        let epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            nodes: Vec::new(),
            addr_to_idx: HashMap::new(),
            blocked: HashSet::new(),
            total_messages: 0,
            tick: 0,
            binary_path,
            base_dir,
            target_count: total_count,
            tick_ms,
            epoch_ms,
            sim_option,
        }
    }

    /// Update tick interval when speed changes.
    pub fn set_speed(&mut self, speed: u64) {
        self.tick_ms = if speed == 0 { 5000 } else { 1000 / speed };
    }

    /// Number of node slots (alive + dead).
    pub fn nodes_len(&self) -> usize {
        self.nodes.len()
    }

    /// Virtual address for node at index.
    fn virtual_addr(idx: usize) -> SocketAddr {
        let ip = format!("10.0.{}.{}", idx / 256, idx % 256);
        format!("{}:6225", ip).parse().unwrap()
    }

    /// Launch a nabla-node child process at the given index.
    /// Writes bootstrap.toml, spawns the process, starts the reader thread.
    /// Returns a ready-to-use NodeProcess (caller decides where to store it).
    fn launch_node_process(&self, idx: usize) -> std::io::Result<NodeProcess> {
        let virtual_addr = Self::virtual_addr(idx);
        let data_dir = crate::ceremony::node_config_dir(&self.base_dir, idx)
            .parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&data_dir)?;

        // Write bootstrap.toml — every node knows all genesis nodes (0-9)
        // plus a few spread-out peers. Mirrors production where genesis are well-known.
        let peers_file = data_dir.join("bootstrap.toml");
        let mut peers_content = String::from("# AXIOM Nabla — Bootstrap Peers\n\n");
        let mut added: std::collections::HashSet<usize> = std::collections::HashSet::new();

        // All genesis nodes (0-9) — include by virtual address even if not spawned
        // yet. Genesis nodes boot together so they'll all be up shortly.
        let genesis_count = 10.min(self.target_count);
        for g in 0..genesis_count {
            if g != idx {
                let peer_addr = Self::virtual_addr(g);
                peers_content.push_str(&format!("[[peer]]\naddress = \"{}\"\n\n", peer_addr));
                added.insert(g);
            }
        }

        // Nearby neighbors + spread-out peers
        for offset in &[1usize, 2, 5, 10, 20] {
            if idx >= *offset {
                let peer_idx = idx - offset;
                if !added.contains(&peer_idx) && peer_idx < self.nodes.len() && self.nodes[peer_idx].alive {
                    let peer_addr = Self::virtual_addr(peer_idx);
                    peers_content.push_str(&format!("[[peer]]\naddress = \"{}\"\n\n", peer_addr));
                    added.insert(peer_idx);
                }
            }
        }
        std::fs::write(&peers_file, &peers_content)?;

        let mut child = Command::new(&self.binary_path)
            .arg("--mode").arg("stdio")
            .arg("--port").arg(virtual_addr.port().to_string())
            .arg("--bind").arg(virtual_addr.ip().to_string())
            .arg("--data").arg(data_dir.to_str().unwrap())
            .arg("--bootstrap").arg(peers_file.to_str().unwrap())
            .arg("--tick-ms").arg(self.tick_ms.to_string())
            .arg("--epoch-ms").arg(self.epoch_ms.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();

        let outbox: Arc<Mutex<Vec<StdioEnvelope>>> = Arc::new(Mutex::new(Vec::new()));

        // Background reader thread: reads JSON lines from stdout
        let outbox_clone = outbox.clone();
        thread::Builder::new()
            .name(format!("binread-{}", idx))
            .spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    let line = match line {
                        Ok(l) => l,
                        Err(_) => break,
                    };
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }
                    if let Ok(env) = serde_json::from_str::<StdioEnvelope>(&line) {
                        outbox_clone.lock().unwrap().push(env);
                    }
                }
            })?;

        Ok(NodeProcess {
            idx,
            virtual_addr,
            child,
            stdin_tx: Arc::new(Mutex::new(Box::new(stdin))),
            outbox,
            status: BinaryNodeStatus {
                alive: true,
                ..Default::default()
            },
            alive: true,
        })
    }

    /// Spawn a new node at the end of the nodes vec.
    fn spawn_node(&mut self, idx: usize) -> std::io::Result<()> {
        let node = self.launch_node_process(idx)?;
        self.addr_to_idx.insert(node.virtual_addr.to_string(), idx);
        self.nodes.push(node);
        Ok(())
    }

    /// Revive a killed node by respawning its child process in-place.
    /// The new process rejoins the network via normal TARDIS attach protocol.
    pub fn revive_node(&mut self, idx: usize) -> std::io::Result<()> {
        if idx >= self.nodes.len() || self.nodes[idx].alive {
            return Ok(()); // nothing to revive
        }
        // Reap the old process
        let _ = self.nodes[idx].child.wait();
        // Spawn a fresh process at the same index
        let node = self.launch_node_process(idx)?;
        self.nodes[idx] = node;
        Ok(())
    }

    /// Send a StdioEnvelope to a node's stdin.
    fn send_to_node(&self, idx: usize, env: &StdioEnvelope) -> std::io::Result<()> {
        if idx >= self.nodes.len() || !self.nodes[idx].alive {
            return Ok(());
        }
        let json = serde_json::to_string(env)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut stdin = self.nodes[idx].stdin_tx.lock().unwrap();
        writeln!(*stdin, "{}", json)?;
        stdin.flush()
    }

    /// Advance one simulation step:
    /// 1. Spawn new nodes if needed
    /// 2. Collect outbound messages from all nodes
    /// 3. Route messages to destinations
    /// 4. Request status from all nodes
    ///
    /// Returns number of messages delivered.
    pub fn step(&mut self) -> u64 {
        // Phase 1: Spawn nodes (ramp up gradually)
        let spawned = self.nodes.len();
        if spawned < self.target_count {
            let to_add = if spawned < 10 { 1 } else { 3.min(self.target_count - spawned) };
            for _ in 0..to_add {
                let idx = self.nodes.len();
                // Option 3: skip genesis nodes (indices 0-9)
                if self.sim_option == 3 && idx < 10 {
                    // Create a placeholder (dead) node entry for genesis indices
                    self.addr_to_idx.insert(Self::virtual_addr(idx).to_string(), idx);
                    self.nodes.push(NodeProcess {
                        idx,
                        virtual_addr: Self::virtual_addr(idx),
                        child: std::process::Command::new("true").spawn().unwrap(),
                        stdin_tx: Arc::new(Mutex::new(Box::new(std::io::sink()))),
                        outbox: Arc::new(Mutex::new(Vec::new())),
                        status: BinaryNodeStatus::default(),
                        alive: false,
                    });
                    continue;
                }
                if let Err(e) = self.spawn_node(idx) {
                    eprintln!("[BIN-SIM] Failed to spawn node {}: {}", idx, e);
                }
            }
        }

        // Phase 2: Collect outbound messages from all nodes
        let mut messages: Vec<(usize, StdioEnvelope)> = Vec::new();
        for node in &self.nodes {
            if !node.alive {
                continue;
            }
            let mut outbox = node.outbox.lock().unwrap();
            for env in outbox.drain(..) {
                messages.push((node.idx, env));
            }
        }

        // Phase 3: Route messages to destinations
        let mut delivered = 0u64;
        for (from_idx, env) in &messages {
            // Skip StatusResponse — consumed by status collection, not routed
            if matches!(&env.msg, WireMessage::StatusResponse { .. }) {
                // Capture status inline
                if let WireMessage::StatusResponse {
                    node_id, node_name, needs_parent, downstream_count,
                    is_leaf, has_d_open, alive, smt_len, peer_count,
                    tardis_tick, root_hash, messages_received,
                    upstream_id, d1_id, d2_id,
                    d1_approved, d2_approved, known_nodes, gossip_active,
                    wal_file_bytes, wal_ops_since_snapshot, snapshot_count,
                    snapshot_total_bytes, last_snapshot_tick, total_disk_bytes,
                    smt_memory_bytes, nbc_issuer,
                } = &env.msg {
                    if *from_idx < self.nodes.len() {
                        self.nodes[*from_idx].status = BinaryNodeStatus {
                            node_id: *node_id,
                            node_name: node_name.clone(),
                            needs_parent: *needs_parent,
                            downstream_count: *downstream_count,
                            is_leaf: *is_leaf,
                            has_d_open: *has_d_open,
                            alive: *alive,
                            smt_len: *smt_len,
                            peer_count: *peer_count,
                            tardis_tick: *tardis_tick,
                            root_hash: *root_hash,
                            messages_received: *messages_received,
                            upstream_id: *upstream_id,
                            d1_id: *d1_id,
                            d2_id: *d2_id,
                            d1_approved: *d1_approved,
                            d2_approved: *d2_approved,
                            known_nodes: *known_nodes,
                            gossip_active: *gossip_active,
                            wal_file_bytes: *wal_file_bytes,
                            wal_ops_since_snapshot: *wal_ops_since_snapshot,
                            snapshot_count: *snapshot_count,
                            snapshot_total_bytes: *snapshot_total_bytes,
                            last_snapshot_tick: *last_snapshot_tick,
                            total_disk_bytes: *total_disk_bytes,
                            smt_memory_bytes: *smt_memory_bytes,
                            nbc_issuer: nbc_issuer.clone(),
                        };
                    }
                }
                continue;
            }
            if let Some(&to_idx) = self.addr_to_idx.get(&env.to) {
                // Check if link is blocked (chaos)
                if self.blocked.contains(&(*from_idx, to_idx))
                    || self.blocked.contains(&(to_idx, *from_idx))
                {
                    continue;
                }
                if self.nodes[to_idx].alive
                    && self.send_to_node(to_idx, env).is_ok()
                {
                    delivered += 1;
                }
            }
        }

        self.total_messages += delivered;
        self.tick += 1;

        // Phase 4: Request status every tick for live dashboard data
        self.request_status_all();

        delivered
    }

    /// Send StatusRequest to all alive nodes.
    /// Responses are captured in Phase 3 of step() when StatusResponse comes back.
    fn request_status_all(&mut self) {
        for i in 0..self.nodes.len() {
            if !self.nodes[i].alive {
                continue;
            }
            let addr = self.nodes[i].virtual_addr;
            let env = StdioEnvelope {
                to: addr.to_string(),
                from: "10.255.255.255:0".to_string(), // sim control address
                msg: WireMessage::StatusRequest,
            };
            let _ = self.send_to_node(i, &env);
        }
    }

    /// Compute stats matching the lib-mode format.
    pub fn stats(&self) -> BinaryNetworkStats {
        let alive_count = self.nodes.iter().filter(|n| n.alive).count();
        let synced = self.nodes.iter()
            .filter(|n| n.alive && !n.status.needs_parent)
            .count();
        let writers = self.nodes.iter()
            .filter(|n| n.alive && n.status.downstream_count == 2)
            .count();
        let orphans = self.nodes.iter()
            .filter(|n| n.alive && n.status.needs_parent)
            .count();

        let sync_pct = if alive_count > 0 {
            (synced as f64 / alive_count as f64) * 100.0
        } else { 100.0 };
        let writer_pct = if alive_count > 0 {
            (writers as f64 / alive_count as f64) * 100.0
        } else { 100.0 };

        BinaryNetworkStats {
            total_nodes: self.nodes.len(),
            alive_nodes: alive_count,
            total_messages: self.total_messages,
            tardis_sync_pct: sync_pct,
            tardis_writer_pct: writer_pct,
            tardis_orphans: orphans,
        }
    }

    /// Kill a node (terminate its process).
    pub fn kill_node(&mut self, idx: usize) {
        if idx < self.nodes.len() && self.nodes[idx].alive {
            self.nodes[idx].alive = false;
            let _ = self.nodes[idx].child.kill();
        }
    }

    /// Kill a link between two nodes.
    pub fn kill_link(&mut self, a: usize, b: usize) {
        self.blocked.insert((a, b));
        self.blocked.insert((b, a));
    }

    /// Restore a link.
    pub fn restore_link(&mut self, a: usize, b: usize) {
        self.blocked.remove(&(a, b));
        self.blocked.remove(&(b, a));
    }

    /// Restore all: revive killed nodes and clear blocked links.
    pub fn restore_all(&mut self) {
        // Respawn all dead node processes
        let dead: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| !self.nodes[i].alive)
            .collect();
        for idx in dead {
            if let Err(e) = self.revive_node(idx) {
                eprintln!("[BIN-SIM] Failed to revive node {}: {}", idx, e);
            }
        }
        self.blocked.clear();
    }

    /// Mass kill a percentage of nodes.
    pub fn mass_kill(&mut self, percent: u8) {
        let count = (self.nodes.len() * percent as usize) / 100;
        let mut killed = 0;
        // Kill non-genesis nodes first (indices >= 10)
        for i in (10..self.nodes.len()).rev() {
            if killed >= count { break; }
            if self.nodes[i].alive {
                self.kill_node(i);
                killed += 1;
            }
        }
    }

    /// Kill N random non-genesis nodes. Returns indices of killed nodes.
    pub fn kill_random(&mut self, count: usize) -> Vec<usize> {
        // Collect eligible (alive, non-genesis) indices
        let mut eligible: Vec<usize> = (10..self.nodes.len())
            .filter(|&i| self.nodes[i].alive)
            .collect();
        // Shuffle using Fisher-Yates with time-based seed
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let mut rng = seed;
        for i in (1..eligible.len()).rev() {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (rng >> 33) as usize % (i + 1);
            eligible.swap(i, j);
        }
        let to_kill: Vec<usize> = eligible.into_iter().take(count).collect();
        for &idx in &to_kill {
            self.kill_node(idx);
        }
        let mut sorted = to_kill;
        sorted.sort();
        sorted
    }

    /// Export state in the same format as lib-mode SimNetwork::export_state().
    /// This allows binary mode to serve the exact same dashboard.
    pub fn export_state(&self) -> NetworkState {
        let genesis_count = 10.min(self.target_count);
        let alive_count = self.nodes.iter().filter(|n| n.alive).count();

        // Build NodeId → index map for resolving upstream/downstream IDs
        let mut id_to_idx: HashMap<NodeId, usize> = HashMap::new();
        for n in &self.nodes {
            if n.status.node_id != [0u8; 32] {
                id_to_idx.insert(n.status.node_id, n.idx);
            }
        }

        let nodes: Vec<NodeState> = self.nodes.iter().map(|n| {
            let is_genesis = n.idx < genesis_count;

            // Build tardis_approvals from d1/d2 child indices
            let mut approvals = Vec::new();
            if let Some(ref d1) = n.status.d1_id {
                if let Some(&child_idx) = id_to_idx.get(d1) {
                    approvals.push(TardisApprovalExport {
                        child: child_idx,
                        approved: n.status.d1_approved,
                    });
                }
            }
            if let Some(ref d2) = n.status.d2_id {
                if let Some(&child_idx) = id_to_idx.get(d2) {
                    approvals.push(TardisApprovalExport {
                        child: child_idx,
                        approved: n.status.d2_approved,
                    });
                }
            }

            NodeState {
                id: n.idx,
                name: n.status.node_name.clone(),
                alive: n.alive,
                is_genesis,
                is_seed: is_genesis, // in binary sim, all genesis are seeds
                entries: n.status.smt_len,
                bans: 0,
                peers: n.status.peer_count,
                enquiry_peers: 0,
                known_nodes: n.status.known_nodes,
                target_peers: 9,
                d_lo: 3,
                root_hash: hex::encode(n.status.root_hash),
                messages_received: n.status.messages_received,
                gossip_active: n.status.gossip_active,
                tardis_tick: n.status.tardis_tick,
                has_upstream: n.status.upstream_id.is_some(),
                downstream_count: n.status.downstream_count,
                is_tardis_leaf: n.status.is_leaf,
                tardis_approvals: approvals,
                has_nbc: n.alive, // alive nodes have NBCs (ceremony or peer-issued)
                nbc_issuer: n.status.nbc_issuer.clone(),
                // Persistence metrics
                wal_file_bytes: n.status.wal_file_bytes,
                wal_ops_since_snapshot: n.status.wal_ops_since_snapshot,
                snapshot_count: n.status.snapshot_count,
                snapshot_total_bytes: n.status.snapshot_total_bytes,
                last_snapshot_tick: n.status.last_snapshot_tick,
                total_disk_bytes: n.status.total_disk_bytes,
                smt_memory_bytes: n.status.smt_memory_bytes,
            }
        }).collect();

        // Gossip mesh links: mirror the bootstrap.toml topology written by
        // spawn_node(). Genesis nodes form a ring (0→1→…→9→0), and every
        // non-genesis node connects to peers at offsets [1, 2, 5, 10, 20].
        // This gives D3 an evenly-distributed mesh (like lib mode) instead
        // of a sequential chain that clusters nodes together.
        let mut link_set: HashSet<(usize, usize)> = HashSet::new();
        let n_nodes = self.nodes.len();

        // Genesis ring: adjacent pairs + wrap-around (clamped to spawned count)
        let ring_count = genesis_count.min(n_nodes);
        if ring_count > 1 {
            for i in 0..ring_count {
                let j = (i + 1) % ring_count;
                if self.nodes[i].alive && self.nodes[j].alive {
                    let (a, b) = if i < j { (i, j) } else { (j, i) };
                    link_set.insert((a, b));
                }
            }
        }

        // Spread-out peer links matching bootstrap.toml offsets
        let offsets: &[usize] = &[1, 2, 5, 10, 20];
        for i in 0..n_nodes {
            if !self.nodes[i].alive { continue; }
            for &off in offsets {
                if i >= off {
                    let j = i - off;
                    if self.nodes[j].alive {
                        let (a, b) = if j < i { (j, i) } else { (i, j) };
                        link_set.insert((a, b));
                    }
                }
            }
        }

        let links: Vec<LinkStateExport> = link_set.into_iter()
            .map(|(a, b)| {
                let blocked = self.blocked.contains(&(a, b))
                    || self.blocked.contains(&(b, a));
                LinkStateExport { source: a, target: b, alive: !blocked }
            })
            .collect();

        // TARDIS tree links: reconstruct from upstream/downstream IDs
        let mut tardis_links = Vec::new();
        for n in &self.nodes {
            if !n.alive { continue; }
            // If this node has an upstream, add parent→child link
            if let Some(ref up_id) = n.status.upstream_id {
                if let Some(&parent_idx) = id_to_idx.get(up_id) {
                    tardis_links.push(TardisLinkExport {
                        parent: parent_idx,
                        child: n.idx,
                    });
                }
            }
        }

        let synced = self.nodes.iter()
            .filter(|n| n.alive && !n.status.needs_parent)
            .count();
        let writers = self.nodes.iter()
            .filter(|n| n.alive && n.status.downstream_count == 2)
            .count();
        let orphans = self.nodes.iter()
            .filter(|n| n.alive && n.status.needs_parent)
            .count();

        let sync_pct = if alive_count > 0 {
            (synced as f64 / alive_count as f64) * 100.0
        } else { 100.0 };
        let writer_pct = if alive_count > 0 {
            (writers as f64 / alive_count as f64) * 100.0
        } else { 100.0 };

        let stats = NetworkStats {
            total_nodes: self.nodes.len(),
            alive_nodes: alive_count,
            total_messages: self.total_messages,
            convergence_pct: 100.0, // binary mode doesn't track gossip convergence
            tardis_sync_pct: sync_pct,
            tardis_writer_pct: writer_pct,
            tardis_orphans: orphans,
            delay_min_ms: 0,
            delay_max_ms: 0,
            pending_gossip: 0,
            pending_tardis: 0,
            tardis_in_tree: synced,
            tardis_tree_links: tardis_links.len(),
            tardis_isolated: 0,
            tardis_pending: 0,
            tardis_reader_pct: if alive_count > 0 {
                let leaves = self.nodes.iter()
                    .filter(|n| n.alive && n.status.is_leaf)
                    .count();
                (leaves as f64 / alive_count as f64) * 100.0
            } else { 0.0 },
            // Persistence aggregates
            total_smt_entries: self.nodes.iter()
                .filter(|n| n.alive)
                .map(|n| n.status.smt_len)
                .sum(),
            total_disk_bytes: self.nodes.iter()
                .filter(|n| n.alive)
                .map(|n| n.status.total_disk_bytes)
                .sum(),
            avg_wal_bytes: if alive_count > 0 {
                self.nodes.iter()
                    .filter(|n| n.alive)
                    .map(|n| n.status.wal_file_bytes)
                    .sum::<u64>() / alive_count as u64
            } else { 0 },
        };

        NetworkState {
            tick: self.tick,
            tick_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            nodes,
            links,
            tardis_links,
            stats,
        }
    }
}

impl Drop for BinarySimNetwork {
    fn drop(&mut self) {
        for node in &mut self.nodes {
            let _ = node.child.kill();
            let _ = node.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ceremony;

    #[test]
    fn binary_sim_data_dir_matches_ceremony() {
        // Genesis 0-9 must use penguin directories, not nabla_{i}
        let base = std::path::Path::new("/tmp/axiom_test");
        for i in 0..10 {
            let expected = ceremony::node_config_dir(base, i)
                .parent().unwrap().to_path_buf();
            let penguin_name = ceremony::GENESIS_NAMES[i];
            assert!(expected.ends_with(format!("axiom-first-penguin-{}", penguin_name)),
                "Genesis node {} should use penguin dir, got {:?}", i, expected);
        }
        // Non-genesis 10+ must use nabla_{i}
        for i in 10..15 {
            let expected = ceremony::node_config_dir(base, i)
                .parent().unwrap().to_path_buf();
            assert!(expected.ends_with(format!("nabla_{}", i)),
                "Non-genesis node {} should use nabla_{} dir, got {:?}", i, i, expected);
        }
    }
}
