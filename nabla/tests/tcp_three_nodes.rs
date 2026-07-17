// Integration test: 3-node TCP nabla-node cluster
//
// 1. Run nabla_ceremony(3, tmp_dir) for real NBCs
// 2. Write per-node bootstrap.toml
// 3. Spawn 3 nabla-node --mode tcp processes
// 4. Poll StatusRequest until TARDIS tree forms
// 5. Verify tree structure (upstream/downstream)
// 6. Kill one node, verify the others recover

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use axiom_nabla::transport::WireMessage;

/// Simplified status response for test assertions.
#[derive(Debug)]
struct StatusResponse {
    node_id: [u8; 32],
    needs_parent: bool,
    downstream_count: usize,
    upstream_id: Option<[u8; 32]>,
    peer_count: usize,
}

/// Send a StatusRequest via raw TCP and read the reply on the same connection.
/// The node uses send_reply() to write the StatusResponse back on the inbound stream.
fn send_status_request(addr: &str) -> Option<StatusResponse> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok()?;

    // Send StatusRequest: 4-byte big-endian length + bincode
    let msg = bincode::serialize(&WireMessage::StatusRequest).ok()?;
    let len = (msg.len() as u32).to_be_bytes();
    stream.write_all(&len).ok()?;
    stream.write_all(&msg).ok()?;
    stream.flush().ok()?;

    // Read response on the same connection (send_reply writes back here)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).ok()?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > 10_000_000 {
        return None;
    }
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf).ok()?;
    let resp: WireMessage = bincode::deserialize(&buf).ok()?;
    match resp {
        WireMessage::StatusResponse {
            node_id,
            needs_parent,
            downstream_count,
            upstream_id,
            peer_count,
            ..
        } => Some(StatusResponse {
            node_id,
            needs_parent,
            downstream_count,
            upstream_id,
            peer_count,
        }),
        _ => None,
    }
}

fn write_bootstrap_toml(path: &Path, ports: &[u16]) {
    let mut content = String::new();
    for port in ports {
        content.push_str(&format!(
            "[[peer]]\naddress = \"127.0.0.1:{}\"\n\n",
            port
        ));
    }
    std::fs::write(path, &content).expect("write bootstrap.toml");
}

fn spawn_node(
    binary: &Path,
    data_dir: &Path,
    port: u16,
    bootstrap: &Path,
) -> Child {
    Command::new(binary)
        .arg("--mode").arg("tcp")
        .arg("--port").arg(port.to_string())
        .arg("--bind").arg("127.0.0.1")
        .arg("--data").arg(data_dir)
        .arg("--bootstrap").arg(bootstrap)
        .arg("--log").arg("warn")
        .arg("--tick-ms").arg("200")
        .arg("--dev")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn nabla-node")
}

fn kill_all(children: &mut [Child]) {
    for child in children.iter_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Poll all nodes until at least one has downstream children and none are orphaned.
fn wait_for_tree(ports: &[u16], timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(500));

        let mut all_connected = true;
        let mut has_parent = false;
        for port in ports {
            let addr = format!("127.0.0.1:{}", port);
            match send_status_request(&addr) {
                Some(sr) => {
                    if sr.needs_parent && sr.downstream_count == 0 {
                        all_connected = false;
                    }
                    if sr.downstream_count > 0 {
                        has_parent = true;
                    }
                }
                None => {
                    all_connected = false;
                }
            }
        }

        if all_connected && has_parent {
            return true;
        }
    }
    false
}

#[test]
#[ignore] // SPHINCS+ is ~30s/op in debug; run with: cargo test --release -p axiom-nabla --test tcp_three_nodes -- --ignored
fn three_node_tcp_cluster() {
    let tmp = tempfile::tempdir().expect("create tmpdir");
    let base = tmp.path();

    // Step 1: Run ceremony for 3 nodes
    let nodes = axiom_nabla_ceremony::nabla_ceremony(3, base);
    assert_eq!(nodes.len(), 3);

    // Verify ceremony wrote the expected files
    for i in 0..3 {
        let config_dir = axiom_nabla::ceremony::node_config_dir(base, i);
        assert!(config_dir.join("nbc.json").exists(), "nbc.json missing for node {}", i);
        assert!(config_dir.join("nabla_ed25519.key").exists(), "ed25519 key missing for node {}", i);
    }

    // Step 2: Write bootstrap.toml for each node
    let ports: Vec<u16> = vec![6300, 6301, 6302];
    for i in 0..3 {
        let config_dir = axiom_nabla::ceremony::node_config_dir(base, i);
        write_bootstrap_toml(&config_dir.join("bootstrap.toml"), &ports);
    }

    // Step 3: Find the nabla-node binary
    let binary = std::env::current_exe()
        .unwrap()
        .parent().unwrap()   // deps/
        .parent().unwrap()   // debug/
        .join("nabla-node");
    if !binary.exists() {
        eprintln!("nabla-node binary not found at {:?} — skipping TCP integration test", binary);
        eprintln!("Build with: cargo build -p axiom-nabla");
        return;
    }

    // Step 4: Spawn 3 nabla-node processes
    let mut children: Vec<Child> = Vec::new();
    for i in 0..3 {
        let data_dir = axiom_nabla::ceremony::node_config_dir(base, i)
            .parent().unwrap().to_path_buf();
        let bootstrap = axiom_nabla::ceremony::node_config_dir(base, i)
            .join("bootstrap.toml");
        children.push(spawn_node(&binary, &data_dir, ports[i], &bootstrap));
    }

    // Give nodes time to start listening
    std::thread::sleep(Duration::from_secs(2));

    // Check if any child exited early
    for (i, child) in children.iter_mut().enumerate() {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stderr_output = String::new();
                if let Some(ref mut stderr) = child.stderr {
                    let _ = stderr.read_to_string(&mut stderr_output);
                }
                eprintln!("Node {} (port {}) exited with {}: {}", i, ports[i], status, stderr_output);
            }
            Ok(None) => eprintln!("Node {} (port {}) is running", i, ports[i]),
            Err(e) => eprintln!("Node {} error: {}", i, e),
        }
    }

    // Step 5: Verify all nodes are alive (respond to StatusRequest)
    let mut all_alive = false;
    for attempt in 0..15 {
        let mut alive = 0;
        for port in &ports {
            let addr = format!("127.0.0.1:{}", port);
            if send_status_request(&addr).is_some() {
                alive += 1;
            }
        }
        if alive == 3 {
            all_alive = true;
            break;
        }
        eprintln!("Attempt {}: {}/3 nodes alive", attempt + 1, alive);
        std::thread::sleep(Duration::from_secs(1));
    }

    if !all_alive {
        for (i, child) in children.iter_mut().enumerate() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stderr_output = String::new();
                    if let Some(ref mut stderr) = child.stderr {
                        let _ = stderr.read_to_string(&mut stderr_output);
                    }
                    eprintln!("Node {} exited {}: {}", i, status, stderr_output);
                }
                Ok(None) => eprintln!("Node {} still running", i),
                Err(e) => eprintln!("Node {} error: {}", i, e),
            }
        }
        kill_all(&mut children);
        panic!("Not all 3 nodes became alive within timeout");
    }

    // Step 6: Wait for TARDIS tree to form.
    // Timeout must accommodate SPHINCS+ verification in debug builds
    // (~30 seconds per operation, each Hello triggers verify_nbc,
    // 3 nodes × 2 peers = 6 verifications, plus system load from full test suite).
    let tree_formed = wait_for_tree(&ports, Duration::from_secs(300));

    if !tree_formed {
        for port in &ports {
            let addr = format!("127.0.0.1:{}", port);
            if let Some(sr) = send_status_request(&addr) {
                eprintln!(
                    "Node on port {}: needs_parent={}, downstream={}, upstream={:?}, peers={}",
                    port, sr.needs_parent, sr.downstream_count,
                    sr.upstream_id.map(|id| hex::encode(&id[..4])),
                    sr.peer_count,
                );
            } else {
                eprintln!("Node on port {}: unreachable", port);
            }
        }
        kill_all(&mut children);
        panic!("TARDIS tree did not form within 300 seconds");
    }

    // Step 7: Verify tree structure
    let mut statuses = Vec::new();
    for port in &ports {
        let addr = format!("127.0.0.1:{}", port);
        let sr = send_status_request(&addr).expect("node should be alive");
        statuses.push(sr);
    }

    // At least one node must have downstream children
    let parents: Vec<usize> = statuses.iter().enumerate()
        .filter(|(_, sr)| sr.downstream_count > 0)
        .map(|(i, _)| i)
        .collect();
    assert!(!parents.is_empty(), "at least one node should have children");

    for (i, sr) in statuses.iter().enumerate() {
        eprintln!(
            "Node {}: dc={}, needs_parent={}, upstream={}, peers={}",
            i, sr.downstream_count, sr.needs_parent,
            sr.upstream_id.map(|id| hex::encode(&id[..4])).unwrap_or_else(|| "none".into()),
            sr.peer_count,
        );
    }

    // All nodes have real NBC-derived node_ids (non-zero)
    for sr in &statuses {
        assert_ne!(sr.node_id, [0; 32], "node_id should be NBC-derived, not zero");
    }

    // Step 8: Kill one node, verify the other two remain alive
    let kill_idx = parents[0].min(2);
    eprintln!("Killing node {} (port {})", kill_idx, ports[kill_idx]);
    let _ = children[kill_idx].kill();
    let _ = children[kill_idx].wait();

    std::thread::sleep(Duration::from_secs(5));

    let mut surviving_alive = 0;
    for (i, port) in ports.iter().enumerate() {
        if i == kill_idx { continue; }
        let addr = format!("127.0.0.1:{}", port);
        if send_status_request(&addr).is_some() {
            surviving_alive += 1;
        }
    }
    assert_eq!(surviving_alive, 2, "both surviving nodes should still be alive");

    kill_all(&mut children);
    eprintln!("TCP 3-node integration test passed!");
}
