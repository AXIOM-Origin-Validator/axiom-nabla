// AXIOM Nabla — Network Binary
//
// Runs N real NablaNode-equivalent instances with simulated network.
// Serves browser UI on localhost:6226 with:
//   GET /           → D3 visualization dashboard
//   GET /events     → SSE stream (network state every tick)
//   POST /cmd       → Chaos commands (kill, partition, inject, etc.)
//   GET /state      → One-shot JSON snapshot
//
// Usage:
//   cargo run --bin nabla-sim                  # 500 nodes (default)
//   cargo run --bin nabla-sim -- -n 100         # custom count
//   cargo run --bin nabla-sim -- --nodes 200   # 200 nodes
//   cargo run --bin nabla-sim -- --speed 10    # 10 ticks/sec

use std::io::{Read, Write, BufRead, BufReader};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axiom_nabla::sim::SimNetwork;
use axiom_nabla::binary_sim::BinarySimNetwork;

const DEFAULT_PORT: u16 = 6226;
const DEFAULT_NODES: usize = 500;
const DEFAULT_SPEED: u64 = 2; // ticks per second

#[derive(Debug, Clone, Copy, PartialEq)]
enum SimMode {
    Lib,
    Binary,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut node_count = DEFAULT_NODES;
    let mut speed = DEFAULT_SPEED;
    let mut port = DEFAULT_PORT;
    let mut base_dir: Option<String> = None;
    let mut sim_mode = SimMode::Lib;
    let mut kill_at: Option<u64> = None;   // tick to kill nodes
    let mut kill_count: usize = 0;         // how many to kill
    let mut max_ticks: Option<u64> = None; // stop after N ticks
    let mut sim_option: u8 = 1;            // --option 1|2|3
    let mut option_explicit = false;       // true if --option was passed on CLI

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" | "-m" => {
                i += 1;
                if i < args.len() {
                    match args[i].as_str() {
                        "lib" => sim_mode = SimMode::Lib,
                        "binary" => sim_mode = SimMode::Binary,
                        other => {
                            eprintln!("Unknown mode: {} (expected 'lib' or 'binary')", other);
                            std::process::exit(1);
                        }
                    }
                }
            }
            "--nodes" | "-n" => {
                i += 1;
                if i < args.len() {
                    node_count = args[i].parse().unwrap_or(DEFAULT_NODES);
                }
            }
            "--speed" | "-s" => {
                i += 1;
                if i < args.len() {
                    speed = args[i].parse().unwrap_or(DEFAULT_SPEED);
                }
            }
            "--port" | "-p" => {
                i += 1;
                if i < args.len() {
                    port = args[i].parse().unwrap_or(DEFAULT_PORT);
                }
            }
            "--base-dir" | "--base" | "-d" => {
                i += 1;
                if i < args.len() {
                    base_dir = Some(args[i].clone());
                }
            }
            "--kill-at" => {
                i += 1;
                if i < args.len() {
                    kill_at = Some(args[i].parse().unwrap_or(50));
                }
            }
            "--kill-count" => {
                i += 1;
                if i < args.len() {
                    kill_count = args[i].parse().unwrap_or(20);
                }
            }
            "--ticks" => {
                i += 1;
                if i < args.len() {
                    max_ticks = Some(args[i].parse().unwrap_or(200));
                }
            }
            "--option" => {
                i += 1;
                if i < args.len() {
                    sim_option = match args[i].as_str() {
                        "1" => 1,
                        "2" => 2,
                        "3" => 3,
                        other => {
                            eprintln!("Unknown option: {} (expected 1, 2, or 3)", other);
                            std::process::exit(1);
                        }
                    };
                    option_explicit = true;
                }
            }
            "--help" | "-h" => {
                println!("∇ AXIOM Nabla Network");
                println!();
                println!("Usage: nabla-sim --base-dir <AXIOM_DATA_DIR> [OPTIONS]");
                println!();
                println!("Options:");
                println!("  -m, --mode <MODE>     lib (default, in-process) or binary (child processes)");
                println!("  -d, --base-dir <DIR>  AXIOM_DATA_DIR (required, contains nbc.json files)");
                println!("  -n, --nodes <N>       Number of nodes (default: {})", DEFAULT_NODES);
                println!("  -s, --speed <N>       Ticks per second (default: {})", DEFAULT_SPEED);
                println!("  -p, --port <N>        HTTP port (default: {})", DEFAULT_PORT);
                println!("  -h, --help            Show this help");
                println!("  --option <1|2|3>      Sim option (binary mode only, default: 1)");
                println!();
                println!("Modes:");
                println!("  lib      In-process simulation (default). All nodes run in the same process.");
                println!("           Uses SimNetwork from sim.rs. Full chaos + dashboard support.");
                println!("  binary   Spawns real nabla-node --mode=stdio child processes.");
                println!("           Sim routes messages between processes via stdin/stdout.");
                println!("           Tests the real binary with real protocol execution.");
                println!();
                println!("Binary sim options:");
                println!("  1  Run as-is (default). All nodes use existing ceremony NBCs.");
                println!("  2  Delete non-genesis dirs before launch. Non-genesis nodes obtain");
                println!("     NBC from genesis peers via peer issuance protocol.");
                println!("  3  Skip genesis nodes (indices 0-9). Tests network survival");
                println!("     without genesis. Requires prior Option 2 run.");
                println!();
                println!("Run nabla-ceremony first to generate NBC keys (dev.sh → 28n).");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    let base_dir = match base_dir {
        Some(d) => std::path::PathBuf::from(d),
        None => {
            if sim_mode == SimMode::Lib {
                eprintln!("ERROR: --base-dir is required");
                eprintln!("Usage: nabla-sim --base-dir <AXIOM_DATA_DIR> [OPTIONS]");
                eprintln!();
                eprintln!("Run nabla-ceremony first to generate NBC keys (dev.sh → 28n).");
                std::process::exit(1);
            } else {
                // Binary mode can use a temp directory
                std::env::temp_dir().join("nabla-binary-sim")
            }
        }
    };

    // ── Interactive option prompt for binary mode ──
    if sim_mode == SimMode::Binary && !option_explicit {
        println!();
        println!("∇ AXIOM Nabla Binary Simulator");
        println!();
        println!("Select sim option:");
        println!("  1  Run as-is (all nodes use existing ceremony NBCs)");
        println!("  2  Delete non-genesis dirs; non-genesis obtain NBC from peers");
        println!("  3  Skip genesis nodes (indices 0-9); test network without genesis");
        println!();
        print!("Option [1/2/3]: ");
        std::io::stdout().flush().unwrap_or(());
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() {
            sim_option = match input.trim() {
                "1" | "" => 1,
                "2" => 2,
                "3" => 3,
                other => {
                    eprintln!("Unknown option: {} (expected 1, 2, or 3)", other);
                    std::process::exit(1);
                }
            };
        }
    }

    match sim_mode {
        SimMode::Lib => run_lib_mode(node_count, speed, port, &base_dir),
        SimMode::Binary => run_binary_mode(node_count, speed, port, &base_dir, kill_at, kill_count, max_ticks, sim_option),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_binary_mode(
    node_count: usize,
    speed: u64,
    port: u16,
    base_dir: &std::path::Path,
    kill_at: Option<u64>,
    kill_count: usize,
    max_ticks: Option<u64>,
    sim_option: u8,
) {
    // Find the nabla-node binary
    let binary_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("nabla-node")))
        .unwrap_or_else(|| std::path::PathBuf::from("target/debug/nabla-node"));

    if !binary_path.exists() {
        eprintln!("ERROR: nabla-node binary not found at {:?}", binary_path);
        eprintln!("Build it first: cargo build -p axiom-nabla --bin nabla-node");
        std::process::exit(1);
    }

    // ── Option 2: Delete non-genesis directories ──
    if sim_option == 2 {
        println!("[BIN-SIM] Option 2: Deleting non-genesis node directories...");
        for i in 10..node_count {
            let node_dir = base_dir.join(format!("nabla_{}", i));
            if node_dir.exists() {
                if let Err(e) = std::fs::remove_dir_all(&node_dir) {
                    eprintln!("[BIN-SIM] WARNING: Cannot remove {:?}: {}", node_dir, e);
                } else if i % 10 == 0 || i == node_count - 1 {
                    println!("[BIN-SIM]   Removed nabla_{}", i);
                }
            }
        }
        println!("[BIN-SIM] Non-genesis dirs cleaned. Nodes will obtain NBC from peers.");
    }

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║         ∇ AXIOM Nabla Binary Simulator                     ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Mode:   binary (real child processes)                     ║");
    println!("║  Nodes:  {:<49}║", node_count);
    println!("║  Speed:  {:<3} ticks/sec{:<35}║", speed, "");
    println!("║  Option: {:<49}║", sim_option);
    println!("║  Binary: {:<49}║", binary_path.display());
    println!("║  Base:   {:<49}║", base_dir.display());
    println!("║  Dashboard: http://localhost:{:<37}║", format!("{}/", port));
    if let Some(kt) = kill_at {
        println!("║  Chaos:  kill {} random nodes at tick {:<28}║", kill_count, kt);
    }
    if let Some(mt) = max_ticks {
        println!("║  Ticks:  {:<49}║", mt);
    }
    println!("╚══════════════════════════════════════════════════════════════╝");

    let network = Arc::new(Mutex::new(BinarySimNetwork::new(
        binary_path,
        base_dir.to_path_buf(),
        node_count,
        speed,
        sim_option,
    )));
    let speed = Arc::new(Mutex::new(speed));

    // HTTP server thread — serves the SAME dashboard as lib mode
    let net_http = Arc::clone(&network);
    let speed_http = Arc::clone(&speed);
    std::thread::spawn(move || {
        let listener = match TcpListener::bind(format!("127.0.0.1:{}", port)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[HTTP] Failed to bind port {}: {}", port, e);
                return;
            }
        };
        println!("[HTTP] Dashboard on http://localhost:{}/", port);
        for stream in listener.incoming().flatten() {
            let net = Arc::clone(&net_http);
            let spd = Arc::clone(&speed_http);
            std::thread::spawn(move || {
                handle_binary_dashboard(stream, net, spd);
            });
        }
    });

    println!("[BIN-SIM] Running... Press Ctrl+C to stop.");

    let mut killed = false;

    loop {
        let tick_interval = {
            let s = speed.lock().unwrap();
            if *s == 0 { Duration::from_secs(60) }
            else { Duration::from_millis(1000 / *s) }
        };

        let start = Instant::now();

        let (tick, delivered, stats) = {
            let mut net = network.lock().unwrap();
            let delivered = net.step();

            // ── Chaos event: kill random nodes at specified tick ──
            if let Some(kt) = kill_at {
                if net.tick == kt && !killed {
                    killed = true;
                    let victims = net.kill_random(kill_count);
                    println!();
                    println!("╔══════════════════════════════════════════════════════════════╗");
                    println!("║  ☠  CHAOS EVENT — tick {}                                  ║", kt);
                    println!("║  Killed {} random nodes (non-genesis):                     ║", victims.len());
                    print!("║  ");
                    for (i, v) in victims.iter().enumerate() {
                        print!("{}", v);
                        if i < victims.len() - 1 { print!(", "); }
                        if (i + 1) % 10 == 0 && i < victims.len() - 1 {
                            println!();
                            print!("║  ");
                        }
                    }
                    println!();
                    println!("╚══════════════════════════════════════════════════════════════╝");
                    println!();
                }
            }

            let stats = net.stats();
            (net.tick, delivered, stats)
        };

        // Print every tick after chaos, every 5 ticks otherwise
        let verbose = killed && kill_at.is_some_and(|kt| tick >= kt);
        if verbose || tick % 5 == 0 {
            println!(
                "[T{:>6}] alive={}/{} msgs={} tardis=sync:{:.0}%|write:{:.0}%|orph:{}",
                tick, stats.alive_nodes, stats.total_nodes,
                delivered, stats.tardis_sync_pct, stats.tardis_writer_pct,
                stats.tardis_orphans
            );
        }

        // Auto-stop: if chaos was triggered and orphans recovered to 0
        if killed && stats.tardis_orphans == 0 && stats.tardis_sync_pct >= 99.0
            && tick > kill_at.unwrap_or(0) + 10
        {
            println!();
            println!("╔══════════════════════════════════════════════════════════════╗");
            println!("║  RECOVERY COMPLETE at tick {}                        ║", tick);
            println!("║  Sync: {:.0}%  Write: {:.0}%  Orphans: {}                        ║",
                stats.tardis_sync_pct, stats.tardis_writer_pct, stats.tardis_orphans);
            println!("╚══════════════════════════════════════════════════════════════╝");
            // Keep running for 20 more ticks to show stability
            for _ in 0..20 {
                std::thread::sleep(tick_interval);
                let mut net = network.lock().unwrap();
                let delivered = net.step();
                let stats = net.stats();
                println!(
                    "[T{:>6}] alive={}/{} msgs={} tardis=sync:{:.0}%|write:{:.0}%|orph:{}",
                    net.tick, stats.alive_nodes, stats.total_nodes,
                    delivered, stats.tardis_sync_pct, stats.tardis_writer_pct,
                    stats.tardis_orphans
                );
            }
            break;
        }

        // Stop after --ticks N
        if let Some(mt) = max_ticks {
            if tick >= mt {
                println!();
                println!("╔══════════════════════════════════════════════════════════════╗");
                println!("║  STOPPED at tick {:<6} ({} ticks requested)              ║", tick, mt);
                println!("║  Sync: {:.0}%  Write: {:.0}%  Orphans: {}                        ║",
                    stats.tardis_sync_pct, stats.tardis_writer_pct, stats.tardis_orphans);
                println!("╚══════════════════════════════════════════════════════════════╝");
                break;
            }
        }

        let elapsed = start.elapsed();
        if elapsed < tick_interval {
            std::thread::sleep(tick_interval - elapsed);
        }
    }
}

fn run_lib_mode(node_count: usize, speed: u64, port: u16, base_dir: &std::path::Path) {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║             ∇ AXIOM Nabla Network                ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Nodes:  {:<49}║", node_count);
    println!("║  Speed:  {:<3} ticks/sec{:<35}║", speed, "");
    println!("║  Base:   {:<49}║", base_dir.display());
    println!("║  Dashboard: http://localhost:{:<37}║", format!("{}/", port));
    println!("╚══════════════════════════════════════════════════════════════╝");

    let network = Arc::new(Mutex::new(SimNetwork::new(node_count, base_dir)));
    let speed = Arc::new(Mutex::new(speed));

    // HTTP server thread
    let net_http = Arc::clone(&network);
    let speed_http = Arc::clone(&speed);
    std::thread::spawn(move || {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .expect("Failed to bind HTTP port");
        listener.set_nonblocking(false).ok();
        println!("[HTTP] Listening on port {}", port);

        for stream in listener.incoming().flatten() {
            let net = Arc::clone(&net_http);
            let spd = Arc::clone(&speed_http);
            std::thread::spawn(move || {
                handle_http(stream, net, spd);
            });
        }
    });

    // Main simulation tick loop
    println!("[SIM] Running... Press Ctrl+C to stop.");
    let mut auto_inject_counter: u64 = 0;
    let mut low_write_dumped = false;
    loop {
        let tick_interval = {
            let s = speed.lock().unwrap();
            if *s == 0 { Duration::from_secs(60) } // paused
            else { Duration::from_millis(1000 / *s) }
        };

        let start = Instant::now();

        let (tick, delivered, alive, convergence, tardis_sync, tardis_write, tardis_orphans, tardis_isolated, orphan_diag_summary) = {
            let mut net = network.lock().unwrap();

            // Auto-inject a registration every 5 ticks to keep the network alive
            // (not too fast — gossip needs time to propagate before new state diverges)
            auto_inject_counter += 1;
            if auto_inject_counter.is_multiple_of(5) {
                // Pick a node based on tick (deterministic pseudo-random)
                let alive_count = net.nodes.iter().filter(|n| n.alive).count();
                if alive_count > 0 {
                    let target_offset = (auto_inject_counter.wrapping_mul(2654435761)) as usize % alive_count;
                    let target_idx = net.nodes.iter()
                        .enumerate()
                        .filter(|(_, n)| n.alive)
                        .nth(target_offset)
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    net.inject_registration(target_idx);
                }
            }

            let delivered = net.step();
            let state = net.export_state();
            let diag = net.orphan_diag_line();
            (state.tick, delivered, state.stats.alive_nodes, state.stats.convergence_pct, state.stats.tardis_sync_pct, state.stats.tardis_writer_pct, state.stats.tardis_orphans, state.stats.tardis_isolated, diag)
        };

        if tick % 50 == 0 {
            println!(
                "[T{:>6}] alive={}/{} msgs={} conv={:.1}% tardis=sync:{:.0}%|write:{:.0}%|orph:{}|isol:{}",
                tick, alive, node_count, delivered, convergence, tardis_sync, tardis_write, tardis_orphans, tardis_isolated
            );
        }
        // Print orphan diagnostic every 500 ticks (or whenever persistent orphans exist)
        if tick % 500 == 0 || (tick % 50 == 0 && !orphan_diag_summary.contains("persistent=0 ")) {
            println!("  {}", orphan_diag_summary);
        }

        // Auto-dump when Write% drops below 40% after all nodes deployed.
        // Only dump once per episode (reset when Write% recovers above 40%).
        if alive >= node_count && tardis_write < 40.0 && !low_write_dumped {
            low_write_dumped = true;
            let net = network.lock().unwrap();
            let path = net.dump_orphan_diag();
            eprintln!("⚠ AUTO-DUMP: Write% {:.1}% < 40% at tick {} → {}", tardis_write, tick, path);
        } else if tardis_write >= 40.0 {
            low_write_dumped = false;
        }

        let elapsed = start.elapsed();
        if elapsed < tick_interval {
            std::thread::sleep(tick_interval - elapsed);
        }
    }
}

/// HTTP handler for binary mode — serves the SAME dashboard as lib mode.
/// Same endpoints: GET / (dashboard HTML), GET /state (JSON), GET /events (SSE), POST /cmd.
fn handle_binary_dashboard(
    mut stream: std::net::TcpStream,
    network: Arc<Mutex<BinarySimNetwork>>,
    speed: Arc<Mutex<u64>>,
) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }

    // Read headers
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
            break;
        }
        if header.to_lowercase().starts_with("content-length:") {
            content_length = header.split(':').nth(1)
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 { return; }
    let method = parts[0];
    let path = parts[1];

    match (method, path) {
        ("GET", "/") => {
            let html = dashboard_html();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                html.len(), html
            );
            let _ = stream.write_all(response.as_bytes());
        }
        ("GET", "/state") => {
            let net = network.lock().unwrap();
            let state = net.export_state();
            let json = serde_json::to_string(&state).unwrap_or_default();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
                json
            );
            let _ = stream.write_all(response.as_bytes());
        }
        ("GET", "/events") => {
            // SSE stream — same as lib mode
            let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nAccess-Control-Allow-Origin: *\r\nConnection: keep-alive\r\n\r\n";
            if stream.write_all(header.as_bytes()).is_err() {
                return;
            }

            loop {
                let json = {
                    let net = network.lock().unwrap();
                    let state = net.export_state();
                    serde_json::to_string(&state).unwrap_or_default()
                };

                let event = format!("data: {}\n\n", json);
                if stream.write_all(event.as_bytes()).is_err() {
                    break;
                }
                if stream.flush().is_err() {
                    break;
                }

                let interval = {
                    let s = speed.lock().unwrap();
                    if *s == 0 { 1000 } else { (1000 / *s).max(100) }
                };
                std::thread::sleep(Duration::from_millis(interval));
            }
        }
        ("POST", "/cmd") => {
            // Read body
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                let _ = reader.read_exact(&mut body);
            }
            let body_str = String::from_utf8_lossy(&body);

            let result = handle_binary_command(&body_str, &network, &speed);

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
                result
            );
            let _ = stream.write_all(response.as_bytes());
        }
        ("OPTIONS", _) => {
            let response = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response.as_bytes());
        }
        _ => {
            let response = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response.as_bytes());
        }
    }
}

/// Handle chaos commands for binary mode.
/// Supports the subset of commands that make sense for binary sim
/// (kill_node, kill_link, restore_link, restore_all, mass_kill, speed).
fn handle_binary_command(
    body: &str,
    network: &Arc<Mutex<BinarySimNetwork>>,
    speed: &Arc<Mutex<u64>>,
) -> String {
    let body = body.trim();

    let cmd = extract_json_str(body, "cmd").unwrap_or_default();
    let arg1 = extract_json_int(body, "node").or_else(|| extract_json_int(body, "a"));
    let arg2 = extract_json_int(body, "b");
    let pct = extract_json_int(body, "percent");
    let spd = extract_json_int(body, "speed");

    let mut net = network.lock().unwrap();

    match cmd.as_str() {
        "kill_node" => {
            if let Some(idx) = arg1 {
                net.kill_node(idx as usize);
                format!("{{\"ok\":true,\"action\":\"killed node {}\"}}", idx)
            } else {
                "{\"ok\":false,\"error\":\"missing node\"}".into()
            }
        }
        "revive_node" => {
            if let Some(idx) = arg1 {
                match net.revive_node(idx as usize) {
                    Ok(()) => format!("{{\"ok\":true,\"action\":\"revived node {}\"}}", idx),
                    Err(e) => format!("{{\"ok\":false,\"error\":\"revive failed: {}\"}}", e),
                }
            } else {
                "{\"ok\":false,\"error\":\"missing node\"}".into()
            }
        }
        "kill_link" => {
            if let (Some(a), Some(b)) = (arg1, arg2) {
                net.kill_link(a as usize, b as usize);
                format!("{{\"ok\":true,\"action\":\"killed link {}-{}\"}}", a, b)
            } else {
                "{\"ok\":false,\"error\":\"missing a or b\"}".into()
            }
        }
        "restore_link" => {
            if let (Some(a), Some(b)) = (arg1, arg2) {
                net.restore_link(a as usize, b as usize);
                format!("{{\"ok\":true,\"action\":\"restored link {}-{}\"}}", a, b)
            } else {
                "{\"ok\":false,\"error\":\"missing a or b\"}".into()
            }
        }
        "restore_all" => {
            net.restore_all();
            "{\"ok\":true,\"action\":\"restored all (revived nodes + cleared blocks)\"}".into()
        }
        "mass_kill" => {
            let p = pct.unwrap_or(30) as u8;
            net.mass_kill(p);
            format!("{{\"ok\":true,\"action\":\"mass killed {}%\"}}", p)
        }
        "kill_random" => {
            let p = pct.unwrap_or(20) as usize;
            let count = (net.nodes_len() * p) / 100;
            let victims = net.kill_random(count);
            format!("{{\"ok\":true,\"action\":\"killed {} random nodes\",\"victims\":{:?}}}", victims.len(), victims)
        }
        "speed" => {
            if let Some(s) = spd {
                net.set_speed(s as u64);
                drop(net);
                let mut sp = speed.lock().unwrap();
                *sp = s as u64;
                format!("{{\"ok\":true,\"action\":\"speed set to {}\"}}", s)
            } else {
                "{\"ok\":false,\"error\":\"missing speed\"}".into()
            }
        }
        _ => {
            format!("{{\"ok\":false,\"error\":\"binary mode: unsupported command '{}'\"}}", cmd)
        }
    }
}

fn handle_http(
    mut stream: std::net::TcpStream,
    network: Arc<Mutex<SimNetwork>>,
    speed: Arc<Mutex<u64>>,
) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }

    // Read headers
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
            break;
        }
        if header.to_lowercase().starts_with("content-length:") {
            content_length = header.split(':').nth(1)
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1];

    match (method, path) {
        ("GET", "/") => {
            let html = dashboard_html();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                html.len(), html
            );
            let _ = stream.write_all(response.as_bytes());
        }
        ("GET", "/state") => {
            let net = network.lock().unwrap();
            let state = net.export_state();
            let json = serde_json::to_string(&state).unwrap_or_default();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
                json
            );
            let _ = stream.write_all(response.as_bytes());
        }
        ("GET", "/events") => {
            // SSE stream
            let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nAccess-Control-Allow-Origin: *\r\nConnection: keep-alive\r\n\r\n";
            if stream.write_all(header.as_bytes()).is_err() {
                return;
            }

            loop {
                let json = {
                    let net = network.lock().unwrap();
                    let state = net.export_state();
                    serde_json::to_string(&state).unwrap_or_default()
                };

                let event = format!("data: {}\n\n", json);
                if stream.write_all(event.as_bytes()).is_err() {
                    break; // client disconnected
                }
                if stream.flush().is_err() {
                    break;
                }

                let interval = {
                    let s = speed.lock().unwrap();
                    if *s == 0 { 1000 } else { (1000 / *s).max(100) }
                };
                std::thread::sleep(Duration::from_millis(interval));
            }
        }
        ("POST", "/cmd") => {
            // Read body
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                let _ = reader.read_exact(&mut body);
            }
            let body_str = String::from_utf8_lossy(&body);

            let result = handle_command(&body_str, &network, &speed);

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
                result
            );
            let _ = stream.write_all(response.as_bytes());
        }
        ("OPTIONS", _) => {
            // CORS preflight
            let response = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response.as_bytes());
        }
        _ => {
            let response = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response.as_bytes());
        }
    }
}

fn handle_command(
    body: &str,
    network: &Arc<Mutex<SimNetwork>>,
    speed: &Arc<Mutex<u64>>,
) -> String {
    let body = body.trim();

    let cmd = extract_json_str(body, "cmd").unwrap_or_default();
    let arg1 = extract_json_int(body, "node").or_else(|| extract_json_int(body, "a"));
    let arg2 = extract_json_int(body, "b");
    let pct = extract_json_int(body, "percent");
    let spd = extract_json_int(body, "speed");
    let nodes_arr = extract_json_array(body, "nodes");

    let mut net = network.lock().unwrap();

    match cmd.as_str() {
        "kill_node" => {
            if let Some(idx) = arg1 {
                net.kill_node(idx as usize);
                format!("{{\"ok\":true,\"action\":\"killed node {}\"}}", idx)
            } else {
                "{\"ok\":false,\"error\":\"missing node\"}".into()
            }
        }
        "revive_node" => {
            if let Some(idx) = arg1 {
                net.revive_node(idx as usize);
                format!("{{\"ok\":true,\"action\":\"revived node {}\"}}", idx)
            } else {
                "{\"ok\":false,\"error\":\"missing node\"}".into()
            }
        }
        "kill_link" => {
            if let (Some(a), Some(b)) = (arg1, arg2) {
                net.kill_link(a as usize, b as usize);
                format!("{{\"ok\":true,\"action\":\"killed link {}-{}\"}}", a, b)
            } else {
                "{\"ok\":false,\"error\":\"missing a or b\"}".into()
            }
        }
        "restore_link" => {
            if let (Some(a), Some(b)) = (arg1, arg2) {
                net.restore_link(a as usize, b as usize);
                format!("{{\"ok\":true,\"action\":\"restored link {}-{}\"}}", a, b)
            } else {
                "{\"ok\":false,\"error\":\"missing a or b\"}".into()
            }
        }
        "partition" => {
            if let Some(nodes) = nodes_arr {
                net.partition(&nodes.iter().map(|&x| x as usize).collect::<Vec<_>>());
                format!("{{\"ok\":true,\"action\":\"partitioned {:?}\"}}", nodes)
            } else {
                "{\"ok\":false,\"error\":\"missing nodes array\"}".into()
            }
        }
        "restore_all" => {
            net.restore_all();
            "{\"ok\":true,\"action\":\"restored all\"}".into()
        }
        "human_bridge" => {
            if let (Some(a), Some(b)) = (arg1, arg2) {
                let (sa, sb) = net.human_bridge(a as usize, b as usize);
                format!(
                    "{{\"ok\":true,\"action\":\"§6.6 bridge {}-{}: healed | node {} recv:{} new:{} upd:{} | node {} recv:{} new:{} upd:{}\"}}",
                    a, b, a, sa.0, sa.1, sa.2, b, sb.0, sb.1, sb.2
                )
            } else {
                "{\"ok\":false,\"error\":\"missing a or b (select 2 nodes)\"}".into()
            }
        }
        "mass_kill" => {
            let p = pct.unwrap_or(30) as u8;
            net.mass_kill(p);
            format!("{{\"ok\":true,\"action\":\"mass killed {}%\"}}", p)
        }
        "inject" => {
            let idx = arg1.unwrap_or(0) as usize;
            let ok = net.inject_registration(idx);
            format!("{{\"ok\":{},\"action\":\"inject at node {}\"}}", ok, idx)
        }
        "speed" => {
            drop(net); // release network lock
            if let Some(s) = spd {
                let mut sp = speed.lock().unwrap();
                *sp = s as u64;
                format!("{{\"ok\":true,\"action\":\"speed set to {}\"}}", s)
            } else {
                "{\"ok\":false,\"error\":\"missing speed\"}".into()
            }
        }
        "set_delay" => {
            let dmin = extract_json_int(body, "min").unwrap_or(0) as u32;
            let dmax = extract_json_int(body, "max").unwrap_or(0) as u32;
            net.set_delay(dmin, dmax);
            format!("{{\"ok\":true,\"action\":\"delay set to {}–{} (x100ms)\"}}", dmin, dmax)
        }
        "chaos" => {
            let events = net.chaos();
            let events_json: Vec<String> = events.iter()
                .map(|e| format!("\"{}\"", e.replace('"', "\\\""))).collect();
            let summary = format!("{} events", events.len());
            format!("{{\"ok\":true,\"summary\":\"{}\",\"events\":[{}]}}",
                summary, events_json.join(","))
        }
        "chaos_heal" => {
            net.chaos_heal();
            let alive = net.nodes.iter().filter(|n| n.alive).count();
            let total = net.nodes.len();
            format!("{{\"ok\":true,\"summary\":\"All healed: {}/{} alive, partitions cleared, delay reset\"}}", alive, total)
        }
        "toggle_rotation" => {
            net.rotation_enabled = !net.rotation_enabled;
            format!("{{\"ok\":true,\"action\":\"rotation {}\"}}", if net.rotation_enabled { "enabled" } else { "disabled" })
        }
        "dump_orphan_diag" => {
            let path = net.dump_orphan_diag();
            let line = net.orphan_diag_line();
            format!("{{\"ok\":true,\"action\":\"orphan diagnostic dumped to {}\",\"summary\":\"{}\"}}", path, line)
        }
        _ => {
            format!("{{\"ok\":false,\"error\":\"unknown command: {}\"}}", cmd)
        }
    }
}

// ── Minimal JSON helpers (no serde for input) ──

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let pos = json.find(&pattern)?;
    let after = &json[pos + pattern.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        None
    }
}

fn extract_json_int(json: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{}\"", key);
    let pos = json.find(&pattern)?;
    let after = &json[pos + pattern.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn extract_json_array(json: &str, key: &str) -> Option<Vec<i64>> {
    let pattern = format!("\"{}\"", key);
    let pos = json.find(&pattern)?;
    let after = &json[pos + pattern.len()..];
    let bracket_start = after.find('[')?;
    let bracket_end = after.find(']')?;
    let inner = &after[bracket_start + 1..bracket_end];
    let nums: Vec<i64> = inner.split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if nums.is_empty() { None } else { Some(nums) }
}

fn dashboard_html() -> String {
    // The HTML embeds `"{{KUAIKUAI_ART}}"` as a placeholder that is
    // substituted with axiom_denomination::KUAIKUAI_ART below. The art
    // lives in denomination/assets/kuaikuai.txt; this binary's dependency
    // on axiom-denomination is what carries it into the served page.
    // If the served HTML still contains the raw placeholder, the
    // workspace's L$/atom/AXC conversion lib is no longer linked into
    // nabla-sim — a CONSOLIDATION REGRESSION, not a rendering bug.
    let html = r##"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>∇ AXIOM Nabla Network</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0a0a0f; color: #c8ccd0; font-family: "Segoe UI", "Noto Sans", "Noto Sans CJK SC", "Noto Sans CJK TC", "Noto Sans CJK JP", sans-serif; overflow: hidden; display: flex; flex-direction: column; height: 100vh; }

#top-bar {
    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
    padding: 8px 16px; background: #111118; border-bottom: 1px solid #2a2a3a;
    min-height: 48px; gap: 4px 16px;
}
#top-bar h1 { font-size: 16px; color: #7faaff; white-space: nowrap; }
#stats { font-size: 13px; color: #8a8a9a; display: flex; flex-wrap: wrap; gap: 2px 12px; }
#stats span { }
.stat-val { color: #e0e0e0; font-weight: bold; }

#main { display: flex; flex: 1; overflow: hidden; }

#graph-area { flex: 1; position: relative; }
#graph-area svg { width: 100%; height: 100%; }

#sidebar {
    width: 280px; background: #111118; border-left: 1px solid #2a2a3a;
    padding: 12px; overflow-y: auto;
}
#sidebar h2 { font-size: 14px; color: #7faaff; margin: 12px 0 8px 0; }
#sidebar h2:first-child { margin-top: 0; }

.btn {
    display: block; width: 100%; padding: 8px 12px; margin: 4px 0;
    background: #1a1a2e; border: 1px solid #2a2a4a; color: #c8ccd0;
    font-family: inherit; font-size: 12px; cursor: pointer; text-align: left;
    border-radius: 4px;
}
.btn:hover { background: #252545; border-color: #4a4a6a; }
.btn.danger { border-color: #5a2a2a; }
.btn.danger:hover { background: #3a1a1a; border-color: #8a3a3a; }
.btn.success { border-color: #2a5a2a; }
.btn.success:hover { background: #1a3a1a; border-color: #3a8a3a; }

.slider-row { display: flex; align-items: center; margin: 8px 0; }
.slider-row label { font-size: 12px; width: 60px; }
.slider-row input[type="range"] { flex: 1; }
.slider-row .val { width: 30px; text-align: right; font-size: 12px; color: #7faaff; }

#node-info {
    margin-top: 12px; padding: 8px; background: #0d0d15; border: 1px solid #2a2a3a;
    border-radius: 4px; font-size: 12px; min-height: 60px;
}
#node-info .label { color: #6a6a8a; }

#log {
    margin-top: 12px; padding: 8px; background: #0d0d15; border: 1px solid #2a2a3a;
    border-radius: 4px; font-size: 11px; height: 120px; overflow-y: auto;
}
.log-entry { color: #6a8a6a; margin: 1px 0; }

/* Convergence bar */
#conv-bar { width: 100%; height: 6px; background: #1a1a2e; border-radius: 3px; margin: 8px 0; }
#conv-fill { height: 100%; border-radius: 3px; transition: width 0.3s, background 0.3s; }

/* Node tooltip */
.node-tip {
    position: absolute; background: #1a1a2e; border: 1px solid #3a3a5a;
    padding: 6px 10px; border-radius: 4px; font-size: 11px; pointer-events: none;
    display: none; z-index: 100;
}
</style>
</head>
<body>

<div id="top-bar">
    <h1 onclick="kuaikuaiRegisterTap()" style="cursor:default;">∇ AXIOM Nabla Network</h1>
    <div id="stats">
        <span>Tick: <span class="stat-val" id="s-tick">0</span></span>
        <span>⏱ <span class="stat-val" id="s-tick-time" style="color:#40d0e0">--:--:--</span></span>
        <span>Nodes: <span class="stat-val" id="s-alive">0</span>/<span class="stat-val" id="s-total">0</span></span>
        <span>Messages: <span class="stat-val" id="s-msgs">0</span></span>
        <span>Convergence: <span class="stat-val" id="s-conv">100%</span></span>
        <span>Links: <span class="stat-val" id="s-links">0</span></span>
        <span>◆ Genesis: <span class="stat-val" id="s-genesis">10</span></span>
        <span>⚠ Homeless: <span class="stat-val" id="s-homeless" style="color:#ff4040">0</span></span>
        <span>🔑 NBC: <span class="stat-val" id="s-nbc">0</span></span>
        <span>⏱ TARDIS: Sync <span class="stat-val" id="s-tardis-sync">0%</span> | Write <span class="stat-val" id="s-tardis-write">0%</span> | Orphans <span class="stat-val" id="s-tardis-orph">0</span> | Isolated <span class="stat-val" id="s-tardis-isol">0</span></span>
        <span>🌳 Tree: <span class="stat-val" id="s-tree">0/0</span> (<span class="stat-val" id="s-tree-links">0</span> links)</span>
        <span>💾 SMT: <span class="stat-val" id="s-smt-entries">0</span> wallets | Disk: <span class="stat-val" id="s-disk-total">0</span></span>
    </div>
</div>

<div id="main">
    <div id="graph-area">
        <svg id="graph"></svg>
        <canvas id="dot-canvas" style="position:absolute;top:0;left:0;pointer-events:none"></canvas>
        <div class="node-tip" id="tooltip"></div>
        <div id="legend" style="position:absolute;top:10px;left:10px;background:rgba(16,16,32,0.92);border:1px solid #3a3a5a;border-radius:6px;padding:10px 14px;font-size:12px;line-height:2;pointer-events:none;z-index:5;min-width:180px;">
            <div style="font-weight:bold;color:#ddd;margin-bottom:2px;font-size:13px;border-bottom:1px solid #3a3a5a;padding-bottom:4px;">Nodes</div>
            <div><span style="color:#cc9920;">◆</span> Genesis node</div>
            <div><span style="color:#3a8a3a;">●</span> Regular node</div>
            <div><span style="color:#40a0ff;">●</span> Gossip active</div>
            <div><span style="color:#ff6040;">●</span> Homeless</div>
            <div><span style="color:#4a2020;">●</span> Dead</div>
        </div>
    </div>

    <div id="sidebar">
        <h2>⚡ Chaos Controls</h2>

        <button class="btn danger" onclick="cmd({cmd:'kill_random',percent:20})">☠ Kill 20% Random</button>
        <button class="btn danger" onclick="cmd({cmd:'kill_random',percent:40})">☠ Kill 40% Random</button>
        <button class="btn success" onclick="cmd({cmd:'restore_all'})">✓ Restore All</button>

        <h2>🔗 Network</h2>
        <button class="btn danger" onclick="partitionSelected()">✂ Partition Selected</button>
        <button class="btn success" onclick="bridgeSelected()">🌉 §6.6 Human Bridge</button>
        <button class="btn" onclick="cmd({cmd:'inject',node:randomAlive()})">📡 Inject Registration</button>
        <button class="btn" onclick="injectBurst()">📡 Burst 10 Registrations</button>

        <h2>⏱ Speed</h2>
        <div class="slider-row">
            <label>Rate:</label>
            <input type="range" id="speed-slider" min="0" max="20" value="2"
                   oninput="setSpeed(this.value)">
            <span class="val" id="speed-val">2</span>
        </div>
        <button class="btn" onclick="setSpeed(0)">⏸ Pause</button>
        <button class="btn" onclick="setSpeed(2)">▶ Normal (2/s)</button>
        <button class="btn" onclick="setSpeed(10)">⏩ Fast (10/s)</button>

        <h2>Convergence</h2>
        <div id="conv-bar"><div id="conv-fill"></div></div>

        <h2>🔗 Layers</h2>
        <div style="display:flex;flex-direction:column;gap:4px;font-size:12px;">
            <label><input type="checkbox" id="layer-gossip" checked onchange="render()">
                <span style="color:rgba(255,255,255,0.5)">━</span> Gossip mesh</label>
            <label><input type="checkbox" id="layer-tardis-down" checked onchange="render()">
                <span style="color:#20cc60">●━━▶</span> TARDIS downlink (dot=parent, arrow=child)</label>
            <label><input type="checkbox" id="layer-tardis-up" checked onchange="render()">
                <span style="color:#40d0e0">╌</span> TARDIS uplink (approval ↑)</label>
            <label><input type="checkbox" id="layer-blocked" checked onchange="render()">
                <span style="color:#aa3333">╌</span> Blocked (partition)</label>
        </div>
        <div class="slider-row" style="margin-top:6px;">
            <label>Width:</label>
            <input type="range" id="link-slider" min="0" max="30" value="5" step="1"
                   oninput="document.getElementById('link-val').textContent=this.value/10; render()">
            <span class="val" id="link-val">0.5</span>
        </div>

        <h2>📶 Network Delay</h2>
        <div class="slider-row">
            <label>Min:</label>
            <input type="range" id="delay-min" min="0" max="50" value="0" step="1"
                   oninput="setDelay()">
            <span class="val" id="delay-min-val">0ms</span>
        </div>
        <div class="slider-row">
            <label>Max:</label>
            <input type="range" id="delay-max" min="0" max="50" value="0" step="1"
                   oninput="setDelay()">
            <span class="val" id="delay-max-val">0ms</span>
        </div>
        <div style="font-size:11px;color:#888;margin:4px 0;">
            <span>Pending: gossip=<span id="s-pend-g" style="color:#7faaff">0</span>
            tardis=<span id="s-pend-t" style="color:#20cc60">0</span></span>
        </div>
        <div style="display:flex;gap:4px;flex-wrap:wrap;">
            <button class="btn" onclick="setDelayPreset(0,0)">No delay</button>
            <button class="btn" onclick="setDelayPreset(1,5)">Light</button>
            <button class="btn" onclick="setDelayPreset(5,20)">Medium</button>
            <button class="btn" onclick="setDelayPreset(15,50)">Heavy</button>
        </div>

        <h2>Selected Node</h2>
        <div id="node-info">
            <span class="label">Click a node to inspect</span>
        </div>

        <h2>🔥 Chaos</h2>
        <button class="btn" style="background:#8a2020;width:100%;font-size:14px;padding:8px;"
                onclick="chaos()">💥 CHAOS</button>
        <div id="chaos-log" style="font-size:11px;color:#ff8866;margin-top:6px;max-height:120px;overflow-y:auto;"></div>
        <button class="btn" style="margin-top:4px;width:100%;" onclick="chaosHeal()">🩹 Heal All</button>
        <button class="btn" id="rotation-btn" style="margin-top:4px;width:100%;" onclick="toggleRotation()">🔄 Rotation: ON</button>
        <button class="btn" style="margin-top:4px;width:100%;background:#2a4a5a;" onclick="dumpOrphanDiag()">📊 Dump Orphan Diagnostic</button>

        <h2>Log</h2>
        <div id="log"></div>
    </div>
</div>

<script>
// ── 乖乖 (椰子口味) — decorative inert easter egg. ──────────────
// The art bytes live in denomination/assets/kuaikuai.txt and are
// substituted into this HTML by dashboard_html() in nabla_sim.rs
// (see the .replace("{{KUAIKUAI_ART}}", ...) below). If the served page
// still contains the raw "{{KUAIKUAI_ART}}" string, nabla-sim lost its
// dependency on axiom-denomination — that's a CONSOLIDATION
// REGRESSION, not a rendering bug.
//
// Cosmetic rules: flavor stays 椰子, dismiss stays click-anywhere,
// never a button labeled "open" / "打開".
const KUAIKUAI_ART = "{{KUAIKUAI_ART}}";
let _kuaikuaiTaps = 0;
let _kuaikuaiLastTap = 0;
let _kuaikuaiOverlay = null;
function kuaikuaiRegisterTap() {
  const now = Date.now();
  if (now - _kuaikuaiLastTap > 2000) _kuaikuaiTaps = 0;
  _kuaikuaiLastTap = now;
  _kuaikuaiTaps += 1;
  if (_kuaikuaiTaps < 7) return;
  _kuaikuaiTaps = 0;
  if (_kuaikuaiOverlay) return;
  const overlay = document.createElement("div");
  // Backticks need solid pixels to form the figure's face/eye detail —
  // 9px anti-aliases them to nothing. 13px / line-height 1 is the
  // smallest size where the punctuation texture survives on 1x.
  overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.92);"
    + "z-index:99999;display:flex;flex-direction:column;align-items:center;"
    + "justify-content:center;color:#7fff7f;cursor:pointer;"
    + "padding:24px;text-align:center;overflow:auto;"
    + "font-family:ui-monospace,'SF Mono',Menlo,Consolas,'Courier New',monospace;";
  // text-align:left on the pre is LOAD-BEARING — the parent's
  // text-align:center would otherwise center each art line
  // independently, skewing the figure (lines vary 45–80 chars).
  overlay.innerHTML = `<pre style="margin:0;white-space:pre;line-height:1;font-size:13px;color:#7fff7f;font-family:inherit;text-align:left;">`
    + KUAIKUAI_ART.replace(/</g, "&lt;").replace(/>/g, "&gt;")
    + `</pre><div style="margin-top:18px;color:#a0ffa0;font-size:13px;line-height:1.6;">`
    + `乖乖 (椰子口味) · the mesh is well-behaved<br/>`
    + `本機乖乖聽話 — 請勿打開，請勿食用</div>`;
  overlay.addEventListener("click", () => {
    if (_kuaikuaiOverlay) {
      _kuaikuaiOverlay.remove();
      _kuaikuaiOverlay = null;
    }
  });
  _kuaikuaiOverlay = overlay;
  document.body.appendChild(overlay);
}
// ────────────────────────────────────────────────────────────────

// ── State ──
let state = null;
let selectedNode = null;
let selectedNodes = new Set();
let nodePositions = {};

// ── SVG Setup ──
const svg = document.getElementById('graph');
const W = () => svg.clientWidth;
const H = () => svg.clientHeight;

// ── SSE Connection ──
const evtSource = new EventSource('/events');
evtSource.onmessage = (e) => {
    state = JSON.parse(e.data);
    updateStats();
    render();
};
evtSource.onerror = () => {
    logMsg('SSE connection lost — retrying...');
};

// ── Commands ──
function cmd(obj) {
    fetch('/cmd', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(obj)
    }).then(r => r.json()).then(r => {
        if (r.action) logMsg(r.action);
    }).catch(e => logMsg('Error: ' + e));
}

function setSpeed(v) {
    v = parseInt(v);
    document.getElementById('speed-slider').value = v;
    document.getElementById('speed-val').textContent = v;
    cmd({cmd: 'speed', speed: v});
}

function setDelay() {
    let mn = parseInt(document.getElementById('delay-min').value);
    let mx = parseInt(document.getElementById('delay-max').value);
    // Enforce min <= max
    if (mx < mn) { mx = mn; document.getElementById('delay-max').value = mx; }
    document.getElementById('delay-min-val').textContent = (mn * 100) + 'ms';
    document.getElementById('delay-max-val').textContent = (mx * 100) + 'ms';
    cmd({cmd: 'set_delay', min: mn, max: mx});
}

function setDelayPreset(mn, mx) {
    document.getElementById('delay-min').value = mn;
    document.getElementById('delay-max').value = mx;
    setDelay();
}

function randomAlive() {
    if (!state) return 0;
    const alive = state.nodes.filter(n => n.alive);
    return alive.length > 0 ? alive[Math.floor(Math.random() * alive.length)].id : 0;
}

function injectBurst() {
    for (let i = 0; i < 10; i++) {
        setTimeout(() => cmd({cmd: 'inject', node: randomAlive()}), i * 50);
    }
}

function partitionSelected() {
    if (selectedNodes.size < 2) {
        logMsg('Select nodes first (click to select, shift+click for multi)');
        return;
    }
    cmd({cmd: 'partition', nodes: Array.from(selectedNodes)});
}

function bridgeSelected() {
    if (selectedNodes.size !== 2) {
        logMsg('§6.6 Bridge: select exactly 2 nodes (one from each side)');
        return;
    }
    const ids = Array.from(selectedNodes);
    cmd({cmd: 'human_bridge', node: ids[0], b: ids[1]});
}

function logMsg(msg) {
    const log = document.getElementById('log');
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.textContent = '[T' + (state ? state.tick : '?') + '] ' + msg;
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;
    while (log.children.length > 50) log.removeChild(log.firstChild);
}

function chaosLog(msg) {
    const cl = document.getElementById('chaos-log');
    cl.innerHTML = '<div>T' + (state ? state.tick : '?') + ': ' + msg + '</div>' + cl.innerHTML;
    while (cl.children.length > 20) cl.removeChild(cl.lastChild);
}

async function chaos() {
    const resp = await fetch('/cmd', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({cmd:'chaos'})
    });
    const data = await resp.json();
    if (data.events) {
        data.events.forEach(ev => chaosLog(ev));
    }
    logMsg('💥 CHAOS: ' + (data.summary || 'havoc'));
}

async function chaosHeal() {
    const resp = await fetch('/cmd', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({cmd:'chaos_heal'})
    });
    const data = await resp.json();
    chaosLog('🩹 ' + (data.summary || 'healed'));
    logMsg('🩹 Heal all');
    // Reset delay sliders
    document.getElementById('delay-min').value = 0;
    document.getElementById('delay-max').value = 0;
    document.getElementById('delay-min-val').textContent = '0ms';
    document.getElementById('delay-max-val').textContent = '0ms';
}

let rotationOn = true;
async function toggleRotation() {
    const resp = await fetch('/cmd', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({cmd:'toggle_rotation'})
    });
    const data = await resp.json();
    rotationOn = !rotationOn;
    document.getElementById('rotation-btn').textContent = '🔄 Rotation: ' + (rotationOn ? 'ON' : 'OFF');
    logMsg(data.action || 'rotation toggled');
}

async function dumpOrphanDiag() {
    const resp = await fetch('/cmd', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({cmd:'dump_orphan_diag'})
    });
    const data = await resp.json();
    logMsg(data.summary || data.action || 'orphan diagnostic dumped');
}

// ── Stats ──
function fmtBytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
    return (b / 1073741824).toFixed(1) + ' GB';
}

function fmtNum(n) {
    return n.toLocaleString();
}

function updateStats() {
    if (!state) return;
    document.getElementById('s-tick').textContent = state.tick;
    if (state.tick_time) {
        const d = new Date(state.tick_time * 1000);
        document.getElementById('s-tick-time').textContent = d.toLocaleTimeString();
    }
    document.getElementById('s-alive').textContent = state.stats.alive_nodes;
    document.getElementById('s-total').textContent = state.stats.total_nodes;
    document.getElementById('s-msgs').textContent = state.stats.total_messages;
    document.getElementById('s-conv').textContent = state.stats.convergence_pct.toFixed(1) + '%';
    document.getElementById('s-links').textContent = state.links.length;
    const genesisAlive = state.nodes.filter(n => n.is_genesis && n.alive).length;
    document.getElementById('s-genesis').textContent = genesisAlive + '/10';
    document.getElementById('s-genesis').style.color = genesisAlive === 0 ? '#ff4040' : genesisAlive < 5 ? '#ffaa40' : '#cccccc';

    const homeless = state.nodes.filter(n => n.alive && n.peers < n.d_lo).length;
    document.getElementById('s-homeless').textContent = homeless;
    document.getElementById('s-homeless').style.color = homeless === 0 ? '#3a8a3a' : homeless > 5 ? '#ff4040' : '#ffaa40';

    const nbcCount = state.nodes.filter(n => n.has_nbc).length;
    document.getElementById('s-nbc').textContent = nbcCount + '/' + state.stats.total_nodes;
    document.getElementById('s-nbc').style.color = nbcCount === state.stats.total_nodes ? '#cc8800' : '#ffaa40';

    // TARDIS health: 3 metrics
    // Sync: should be ~100%, red if drops
    const tsync = state.stats.tardis_sync_pct || 0;
    document.getElementById('s-tardis-sync').textContent = tsync.toFixed(0) + '%';
    document.getElementById('s-tardis-sync').style.color = tsync > 95 ? '#3a8a3a' : tsync > 80 ? '#ffaa40' : '#ff4040';

    // Writers: ~50% is healthy for binary tree, red only if very low
    const twrite = state.stats.tardis_writer_pct || 0;
    document.getElementById('s-tardis-write').textContent = twrite.toFixed(0) + '%';
    document.getElementById('s-tardis-write').style.color = twrite > 40 ? '#3a8a3a' : twrite > 20 ? '#ffaa40' : '#ff4040';

    // Orphans: should be 0
    const torph = state.stats.tardis_orphans || 0;
    document.getElementById('s-tardis-orph').textContent = torph;
    document.getElementById('s-tardis-orph').style.color = torph === 0 ? '#3a8a3a' : '#ff4040';

    // Isolated: nodes with upstream but no path to a seed — should be 0
    const tisol = state.stats.tardis_isolated || 0;
    document.getElementById('s-tardis-isol').textContent = tisol;
    document.getElementById('s-tardis-isol').style.color = tisol === 0 ? '#3a8a3a' : '#ff4040';

    const tit = state.stats.tardis_in_tree || 0;
    const ttl = state.stats.tardis_tree_links || 0;
    const alv = state.stats.alive_nodes || 1;
    document.getElementById('s-tree').textContent = tit + '/' + alv;
    document.getElementById('s-tree').style.color = tit >= alv ? '#3a8a3a' : tit > alv*0.8 ? '#ffaa40' : '#ff4040';
    document.getElementById('s-tree-links').textContent = ttl;

    const pg = state.stats.pending_gossip || 0;
    const pt = state.stats.pending_tardis || 0;
    document.getElementById('s-pend-g').textContent = pg;
    document.getElementById('s-pend-t').textContent = pt;
    if (pg > 0) document.getElementById('s-pend-g').style.color = '#ffaa40';
    else document.getElementById('s-pend-g').style.color = '#7faaff';
    if (pt > 0) document.getElementById('s-pend-t').style.color = '#ffaa40';
    else document.getElementById('s-pend-t').style.color = '#20cc60';

    const fill = document.getElementById('conv-fill');
    fill.style.width = state.stats.convergence_pct + '%';
    const c = state.stats.convergence_pct;
    fill.style.background = c > 90 ? '#3a8a3a' : c > 50 ? '#8a8a3a' : '#8a3a3a';

    // Persistence aggregates
    document.getElementById('s-smt-entries').textContent = fmtNum(state.stats.total_smt_entries || 0);
    document.getElementById('s-disk-total').textContent = fmtBytes(state.stats.total_disk_bytes || 0);
}

// ── Render ──
let lastNodeCount = 0;
function render() {
    if (!state) return;
    const w = W(), h = H();

    // Recalculate ALL positions when node count changes
    const n = state.nodes.length;
    if (n !== lastNodeCount) {
        lastNodeCount = n;
        const radius = Math.min(w, h) * 0.38;
        state.nodes.forEach((node, i) => {
            const angle = (2 * Math.PI * i) / n - Math.PI / 2;
            nodePositions[node.id] = {
                x: w / 2 + Math.cos(angle) * radius,
                y: h / 2 + Math.sin(angle) * radius,
            };
        });
    }

    // Build SVG
    let html = '';

    // TARDIS tree links — directed arrows (behind gossip mesh)
    const showTardisDown = document.getElementById('layer-tardis-down').checked;
    const showTardisUp = document.getElementById('layer-tardis-up').checked;
    if (state.tardis_links && state.tardis_links.length > 0 && (showTardisDown || showTardisUp)) {
        // SVG markers: arrowhead at destination + filled dot at origin.
        // Without the origin dot the line is visually symmetric — you
        // can't tell which end is the parent. Cycle members appear to
        // have 2 downlinks (1 incoming + 1 outgoing in same color).
        // Adding a clear source dot disambiguates: "the line emanates
        // FROM this end."
        html += '<defs>';
        // Arrowheads bumped ~35% (16×11 vs prior 12×8 vs original 6×4)
        html += '<marker id="tarrow-down" markerWidth="16" markerHeight="11" refX="15" refY="5.5" orient="auto"><path d="M0,0 L16,5.5 L0,11 L4,5.5 Z" fill="#20cc60" opacity="0.95"/></marker>';
        html += '<marker id="tarrow-up"   markerWidth="16" markerHeight="11" refX="15" refY="5.5" orient="auto"><path d="M0,0 L16,5.5 L0,11 L4,5.5 Z" fill="#40d0e0" opacity="0.95"/></marker>';
        // Origin markers — filled dots at the source end (8×8 vs prior 6×6)
        html += '<marker id="tdot-down" markerWidth="8" markerHeight="8" refX="4" refY="4" orient="auto"><circle cx="4" cy="4" r="3.5" fill="#20cc60" opacity="0.95"/></marker>';
        html += '<marker id="tdot-up"   markerWidth="8" markerHeight="8" refX="4" refY="4" orient="auto"><circle cx="4" cy="4" r="3.5" fill="#40d0e0" opacity="0.95"/></marker>';
        html += '</defs>';
        state.tardis_links.forEach(tl => {
            const s = nodePositions[tl.parent];
            const t = nodePositions[tl.child];
            if (!s || !t) return;
            const bright = selectedNodes.size > 0 && (selectedNodes.has(tl.parent) || selectedNodes.has(tl.child));
            const op = bright ? '0.9' : '0.35';
            const sw = bright ? '2.5' : '1.2';
            const dx = t.x - s.x, dy = t.y - s.y;
            const len = Math.sqrt(dx*dx + dy*dy) || 1;
            const off = 4;
            const px = -dy/len * off, py = dx/len * off;
            if (showTardisDown) {
                // Single green line: dot at parent (source) → arrowhead at child (destination).
                // Direction is unambiguous from the markers alone.
                html += '<line x1="'+s.x+'" y1="'+s.y+'" x2="'+t.x+'" y2="'+t.y+'" stroke="#20cc60" stroke-width="'+sw+'" opacity="'+op+'" marker-start="url(#tdot-down)" marker-end="url(#tarrow-down)"/>';
            }
            if (showTardisUp) {
                // Uplink reverses direction: source = child (t), destination = parent (s).
                html += '<line x1="'+(t.x+px)+'" y1="'+(t.y+py)+'" x2="'+(s.x+px)+'" y2="'+(s.y+py)+'" stroke="#40d0e0" stroke-width="'+sw+'" opacity="'+(bright?'0.7':'0.25')+'" marker-start="url(#tdot-up)" marker-end="url(#tarrow-up)" stroke-dasharray="3,3"/>';
            }
        });
    }

    // Links — dim by default, bright for selected node's connections
    const showGossip = document.getElementById('layer-gossip').checked;
    const showBlocked = document.getElementById('layer-blocked').checked;
    const linkWidth = parseInt(document.getElementById('link-slider').value) / 10;
    if (linkWidth > 0) {
        // First pass: dim background links
        const activeNodes = new Set();
        state.nodes.forEach(nd => { if (nd.gossip_active) activeNodes.add(nd.id); });
        state.links.forEach(link => {
            const s = nodePositions[link.source];
            const t = nodePositions[link.target];
            if (!s || !t) return;
            if (selectedNodes.size > 0 && (selectedNodes.has(link.source) || selectedNodes.has(link.target))) return;
            if (!link.alive) {
                if (!showBlocked) return;
                const dash = 'stroke-dasharray="4,4"';
                html += '<line x1="'+s.x+'" y1="'+s.y+'" x2="'+t.x+'" y2="'+t.y+'" stroke="#aa3333" stroke-width="'+(linkWidth*1.5)+'" opacity="0.5" '+dash+'/>';
            } else {
                if (!showGossip) return;
                const active = activeNodes.has(link.source) && activeNodes.has(link.target);
                if (active) {
                    html += '<line x1="'+s.x+'" y1="'+s.y+'" x2="'+t.x+'" y2="'+t.y+'" stroke="#40a0ff" stroke-width="'+(linkWidth*1.5)+'" opacity="0.25"/>';
                } else {
                    html += '<line x1="'+s.x+'" y1="'+s.y+'" x2="'+t.x+'" y2="'+t.y+'" stroke="#ffffff" stroke-width="'+linkWidth+'" opacity="0.06"/>';
                }
            }
        });
        // Second pass: bright links for selected node(s)
        if (selectedNodes.size > 0) {
            state.links.forEach(link => {
                const s = nodePositions[link.source];
                const t = nodePositions[link.target];
                if (!s || !t) return;
                if (!selectedNodes.has(link.source) && !selectedNodes.has(link.target)) return;
                if (!link.alive) {
                    if (!showBlocked) return;
                    html += '<line x1="'+s.x+'" y1="'+s.y+'" x2="'+t.x+'" y2="'+t.y+'" stroke="#ff4040" stroke-width="'+(linkWidth*2)+'" opacity="0.9" stroke-dasharray="4,4"/>';
                } else {
                    if (!showGossip) return;
                    const active = activeNodes.has(link.source) && activeNodes.has(link.target);
                    if (active) {
                        html += '<line x1="'+s.x+'" y1="'+s.y+'" x2="'+t.x+'" y2="'+t.y+'" stroke="#60c0ff" stroke-width="'+(linkWidth*2)+'" opacity="0.9"/>';
                    } else {
                        html += '<line x1="'+s.x+'" y1="'+s.y+'" x2="'+t.x+'" y2="'+t.y+'" stroke="#ffffff" stroke-width="'+(linkWidth*2)+'" opacity="0.9"/>';
                    }
                }
            });
        }
    }

    // Divergence rings (before nodes so they appear behind)
    const hashGroups = {};
    state.nodes.forEach(nd => {
        if (nd.alive) {
            if (!hashGroups[nd.root_hash]) hashGroups[nd.root_hash] = [];
            hashGroups[nd.root_hash].push(nd.id);
        }
    });
    const hashColors = ['#3a8a3a', '#8a8a3a', '#8a3a3a', '#3a3a8a', '#8a3a8a'];
    const hashes = Object.keys(hashGroups);
    if (hashes.length > 1) {
        hashes.forEach((hash, hi) => {
            const c = hashColors[hi % hashColors.length];
            hashGroups[hash].forEach(id => {
                const pos = nodePositions[id];
                if (!pos) return;
                const r = (n > 100 ? 3 : n > 50 ? 4 : 6) + 3;
                html += '<circle cx="'+pos.x+'" cy="'+pos.y+'" r="'+r+'" fill="none" stroke="'+c+'" stroke-width="1" opacity="0.6"/>';
            });
        });
    }

    // Nodes
    state.nodes.forEach(node => {
        const pos = nodePositions[node.id];
        if (!pos) return;
        const r = n > 100 ? 3 : n > 50 ? 4 : 6;
        const events = ' data-id="'+node.id+'" onmouseenter="showTip(event,'+node.id+')" onmouseleave="hideTip()" onclick="selectNode(event,'+node.id+')" style="cursor:pointer"';
        const homeless = node.alive && node.peers < node.d_lo;

        // §6.3 visual: red pulsing ring for homeless nodes (below D_lo)
        if (homeless) {
            html += '<circle cx="'+pos.x+'" cy="'+pos.y+'" r="'+(r+4)+'" fill="none" stroke="#ff4040" stroke-width="2" opacity="0.7"><animate attributeName="r" values="'+(r+2)+';'+(r+6)+';'+(r+2)+'" dur="1.5s" repeatCount="indefinite"/><animate attributeName="opacity" values="0.8;0.3;0.8" dur="1.5s" repeatCount="indefinite"/></circle>';
        }

        // Writer splash: gold pulsing ring on nodes with downstream_count==2
        // (real writer rule per nabla/src/node.rs:1815). Each visible pulse
        // = "this node has received signed ticks from both downstream
        // children and is currently authorized to write to the SMT."
        if (node.alive && node.is_writer) {
            html += '<circle cx="'+pos.x+'" cy="'+pos.y+'" r="'+(r+5)+'" fill="none" stroke="#ffd060" stroke-width="2.5" opacity="0.85"><animate attributeName="r" values="'+(r+3)+';'+(r+9)+';'+(r+3)+'" dur="1.2s" repeatCount="indefinite"/><animate attributeName="opacity" values="0.95;0.35;0.95" dur="1.2s" repeatCount="indefinite"/></circle>';
        }

        if (node.is_seed) {
            // Seed + Genesis: gold diamond (gossip) with green triangle overlay (TARDIS)
            // Diamond first (gossip identity)
            let color;
            if (!node.alive) color = '#4a3010';
            else if (homeless) color = '#ff6040';
            else if (node.gossip_active) color = '#ffd060';
            else if (selectedNodes.has(node.id)) color = '#ffaa40';
            else color = '#cc9920';
            const stroke = selectedNodes.has(node.id) ? '#ffaa40' : (homeless ? '#ff4040' : (node.alive ? '#aa7710' : '#4a3010'));
            const d = r * 1.4;
            html += '<polygon points="'+(pos.x)+','+(pos.y-d)+' '+(pos.x+d)+','+(pos.y)+' '+(pos.x)+','+(pos.y+d)+' '+(pos.x-d)+','+(pos.y)+'" fill="'+color+'" stroke="'+stroke+'" stroke-width="1.5"'+events+'/>';
            // Green triangle overlay (TARDIS seed marker) — smaller, on top
            if (node.alive) {
                const t = r * 0.8;
                html += '<polygon points="'+(pos.x)+','+(pos.y-t)+' '+(pos.x+t*0.87)+','+(pos.y+t*0.5)+' '+(pos.x-t*0.87)+','+(pos.y+t*0.5)+'" fill="none" stroke="#20cc60" stroke-width="1.5" opacity="0.9"'+events+'/>';
            }
        } else if (node.is_genesis) {
            // Genesis: diamond shape, gold palette
            let color;
            if (!node.alive) color = '#4a3010';
            else if (homeless) color = '#ff6040';
            else if (node.gossip_active) color = '#ffd060';
            else if (selectedNodes.has(node.id)) color = '#ffaa40';
            else color = '#cc9920';
            const stroke = selectedNodes.has(node.id) ? '#ffaa40' : (homeless ? '#ff4040' : (node.alive ? '#aa7710' : '#4a3010'));
            const d = r * 1.4;
            html += '<polygon points="'+(pos.x)+','+(pos.y-d)+' '+(pos.x+d)+','+(pos.y)+' '+(pos.x)+','+(pos.y+d)+' '+(pos.x-d)+','+(pos.y)+'" fill="'+color+'" stroke="'+stroke+'" stroke-width="1.5"'+events+'/>';
        } else {
            // Regular: circle
            let color;
            if (!node.alive) color = '#4a2020';
            else if (homeless) color = '#ff6040';
            else if (node.gossip_active) color = '#40a0ff';
            else if (selectedNodes.has(node.id)) color = '#ffaa40';
            else color = '#3a8a3a';
            const stroke = selectedNodes.has(node.id) ? '#ffaa40' : (homeless ? '#ff4040' : (node.alive ? '#2a4a2a' : '#3a1a1a'));
            html += '<circle cx="'+pos.x+'" cy="'+pos.y+'" r="'+r+'" fill="'+color+'" stroke="'+stroke+'" stroke-width="1.5"'+events+'/>';
        }
        // Add text label when <= 50 nodes
        if (state.nodes.length <= 50 && node.name) {
            const label = node.name.length > 10 ? node.name.substring(0, 10) : node.name;
            html += '<text x="'+pos.x+'" y="'+(pos.y + r + 12)+'" text-anchor="middle" font-size="9" fill="#8a8a9a" pointer-events="none">'+label+'</text>';
            // YPX-014 settlement mode chip: hashmap (UNCLE §8.3 audit-grade) = green H,
            // bloom (consumer-grade) = blue B, unknown = grey ?.
            // Sits one line below the name so the mesh-mode mix is visible at a glance.
            if (node.txid_service) {
                const mode = node.txid_service.toLowerCase();
                const txt = mode === 'hashmap' ? 'HASHMAP'
                          : mode === 'bloom'   ? 'BLOOM'
                          : '?';
                const tcol = mode === 'hashmap' ? '#4caf50'
                           : mode === 'bloom'   ? '#40a0ff'
                           : '#778';
                html += '<text x="'+pos.x+'" y="'+(pos.y + r + 22)+'" text-anchor="middle" font-size="8" font-weight="700" fill="'+tcol+'" pointer-events="none" letter-spacing="0.5">'+txt+'</text>';
            }
        }
    });

    svg.innerHTML = html;
}

// Gossip flow dots — animated on canvas overlay
const dotCanvas = document.getElementById('dot-canvas');
const dotCtx = dotCanvas ? dotCanvas.getContext('2d') : null;
let flowDots = [];

function resizeDotCanvas() {
    if (!dotCanvas) return;
    const container = dotCanvas.parentElement;
    dotCanvas.width = container.clientWidth;
    dotCanvas.height = container.clientHeight;
}
window.addEventListener('resize', resizeDotCanvas);
resizeDotCanvas();

function spawnFlowDots() {
    if (!state || !nodePositions) return;
    const activeSet = new Set();
    state.nodes.forEach(nd => { if (nd.gossip_active) activeSet.add(nd.id); });
    const candidates = [];
    state.links.forEach(link => {
        if (link.alive && activeSet.has(link.source) && activeSet.has(link.target)) {
            const s = nodePositions[link.source];
            const t = nodePositions[link.target];
            if (s && t) candidates.push({s, t});
        }
    });
    if (candidates.length === 0) return;
    while (flowDots.length < 12) {
        const l = candidates[Math.floor(Math.random() * candidates.length)];
        const rev = Math.random() > 0.5;
        flowDots.push({
            x1: rev ? l.t.x : l.s.x, y1: rev ? l.t.y : l.s.y,
            x2: rev ? l.s.x : l.t.x, y2: rev ? l.s.y : l.t.y,
            t: Math.random(), speed: 0.003 + Math.random() * 0.004,
        });
    }
}

function animateDots() {
    if (!dotCtx) { requestAnimationFrame(animateDots); return; }
    resizeDotCanvas();
    dotCtx.clearRect(0, 0, dotCanvas.width, dotCanvas.height);
    spawnFlowDots();
    const alive = [];
    flowDots.forEach(d => {
        d.t += d.speed;
        if (d.t > 1) return;
        const x = d.x1 + (d.x2 - d.x1) * d.t;
        const y = d.y1 + (d.y2 - d.y1) * d.t;
        dotCtx.beginPath();
        dotCtx.arc(x, y, 2.5, 0, Math.PI * 2);
        dotCtx.fillStyle = 'rgba(96, 192, 255, ' + (0.9 - d.t * 0.5) + ')';
        dotCtx.fill();
        alive.push(d);
    });
    flowDots = alive;
    requestAnimationFrame(animateDots);
}
requestAnimationFrame(animateDots);

function showTip(e, id) {
    if (!state) return;
    const node = state.nodes.find(n => n.id === id);
    if (!node) return;
    const tip = document.getElementById('tooltip');
    const tt = node.tardis_tick || 0;
    const ttStr = tt > 1000000000 ? new Date(tt*1000).toLocaleTimeString() : String(tt);
    // Build TARDIS approval signature line
    let sigLine = '';
    if (node.tardis_approvals && node.tardis_approvals.length > 0) {
        const parts = node.tardis_approvals.map((a, i) =>
            '<span style="color:' + (a.approved ? '#20cc60' : '#ff6040') + '">' +
            'D' + (i+1) + '(#' + a.child + ')' + (a.approved ? '✓' : '✗') + '</span>'
        );
        sigLine = '<br><span style="color:#dda0ff">🔑 Sig: ' + parts.join('  ') + '</span>';
        const approvedCount = node.tardis_approvals.filter(a => a.approved).length;
        const total = node.tardis_approvals.length;
        if (approvedCount === total && total > 0) {
            sigLine += ' <span style="color:#20cc60;font-weight:bold">WRITER</span>';
        } else if (approvedCount > 0) {
            sigLine += ' <span style="color:#ffaa40">PARTIAL ' + approvedCount + '/' + total + '</span>';
        }
    } else if (!node.is_tardis_leaf) {
        sigLine = '<br><span style="color:#666">🔑 Sig: no downstream</span>';
    } else {
        sigLine = '<br><span style="color:#4488cc">📖 READER (enquiry only)</span>';
    }
    const displayName = node.name ? (node.name + ' (#' + id + ')') : ('Node ' + id);
    tip.innerHTML = '<b>' + displayName + (node.is_seed ? ' ▲ SEED' : node.is_genesis ? ' ◆ GENESIS' : '') + '</b><br>' +
        (node.alive ? '🟢 alive' : '🔴 dead') +
        (node.alive && node.peers < node.d_lo ? ' <span style="color:#ff4040">⚠ HOMELESS</span>' : '') + '<br>' +
        'Entries: ' + node.entries + '<br>' +
        'Peers: ' + node.peers + '/' + node.target_peers +
        ' | E-peer: ' + node.enquiry_peers + '/1' +
        ' | Known: ' + node.known_nodes + '<br>' +
        'Root: ' + node.root_hash + ' | Msgs: ' + node.messages_received + '<br>' +
        '<span style="color:#20cc60">⏱ TARDIS: ' + ttStr + '</span>' +
        ' | UP: ' + (node.has_upstream ? '✓' : '✗') +
        ' | D: ' + (node.downstream_count||0) +
        (node.is_tardis_leaf ? ' (leaf)' : '') +
        sigLine +
        (node.has_nbc ? '<br><span style="color:#cc8800">🔑 NBC ✓' + (node.nbc_issuer ? ' (' + node.nbc_issuer + ')' : '') + '</span>' : '') +
        (node.total_disk_bytes ? '<br><span style="color:#88aacc">💾 Disk: ' + fmtBytes(node.total_disk_bytes) + ' (WAL ' + fmtBytes(node.wal_file_bytes||0) + ' + Snap ' + fmtBytes(node.snapshot_total_bytes||0) + ')</span>' : '');
    tip.style.display = 'block';
    tip.style.left = (e.clientX + 12) + 'px';
    tip.style.top = (e.clientY - 40) + 'px';
}

function hideTip() {
    document.getElementById('tooltip').style.display = 'none';
}

function selectNode(e, id) {
    if (e.shiftKey) {
        if (selectedNodes.has(id)) selectedNodes.delete(id);
        else selectedNodes.add(id);
    } else {
        selectedNodes.clear();
        selectedNodes.add(id);
    }
    selectedNode = id;

    const node = state.nodes.find(n => n.id === id);
    if (node) {
        const sideDisplayName = node.name ? (node.name + ' (#' + id + ')') : ('Node ' + id);
        const ticksAgo = node.last_snapshot_tick > 0 ? ' (' + fmtNum(node.tardis_tick - node.last_snapshot_tick) + ' ticks ago)' : '';
        document.getElementById('node-info').innerHTML =
            '<b>' + sideDisplayName + '</b> ' + (node.alive ? '🟢' : '🔴') +
            (node.alive && node.peers < node.d_lo ? ' <span style="color:#ff4040">⚠ HOMELESS</span>' : '') + '<br>' +
            '<span class="label">Entries:</span> ' + node.entries + '<br>' +
            '<span class="label">Peers:</span> ' + node.peers + ' / ' + node.target_peers + ' (D_lo=' + node.d_lo + ')' + '<br>' +
            '<span class="label">E-peer:</span> ' + (node.enquiry_peers > 0 ? '<span style="color:#f0ad4e">' + node.enquiry_peers + '/1 observer</span>' : '0/1') + '<br>' +
            '<span class="label">Known:</span> ' + node.known_nodes + ' nodes<br>' +
            '<span class="label">Root:</span> ' + node.root_hash + '<br>' +
            '<span class="label">Msgs:</span> ' + node.messages_received + '<br>' +
            '<br><div style="border-top:1px solid #3a3a5a;margin:4px 0;padding-top:4px;font-size:11px;color:#88aacc;">── Storage ──</div>' +
            '<span class="label">SMT entries:</span> ' + fmtNum(node.entries) + '<br>' +
            '<span class="label">SMT memory:</span> ~' + fmtBytes(node.smt_memory_bytes || 0) + '<br>' +
            '<span class="label">Root hash:</span> ' + node.root_hash + '<br>' +
            '<span class="label">Bans:</span> ' + (node.bans || 0) + '<br>' +
            '<div style="border-top:1px solid #3a3a5a;margin:4px 0;padding-top:4px;font-size:11px;color:#88aacc;">── Persistence ──</div>' +
            '<span class="label">WAL size:</span> ' + fmtBytes(node.wal_file_bytes || 0) + '<br>' +
            '<span class="label">WAL ops:</span> ' + fmtNum(node.wal_ops_since_snapshot || 0) + ' since snapshot<br>' +
            '<span class="label">Snapshots:</span> ' + (node.snapshot_count || 0) + ' on disk (' + fmtBytes(node.snapshot_total_bytes || 0) + ')<br>' +
            '<span class="label">Last snap:</span> tick ' + fmtNum(node.last_snapshot_tick || 0) + ticksAgo + '<br>' +
            '<span class="label">Total disk:</span> ' + fmtBytes(node.total_disk_bytes || 0) + '<br>' +
            '<br>' +
            '<button class="btn danger" onclick="cmd({cmd:\'kill_node\',node:'+id+'})">Kill</button>' +
            '<button class="btn success" onclick="cmd({cmd:\'revive_node\',node:'+id+'})">Revive</button>' +
            '<button class="btn" onclick="cmd({cmd:\'inject\',node:'+id+'})">Inject</button>';
    }
}

window.addEventListener('resize', render);
</script>
</body>
</html>"##;
    // JSON-escape the art so it lands inside a JS "..." string literal.
    // The art uses backslashes and newlines; everything else is ASCII.
    let mut escaped = String::with_capacity(axiom_denomination::KUAIKUAI_ART.len() + 32);
    for ch in axiom_denomination::KUAIKUAI_ART.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"'  => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if (c as u32) < 0x20 => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    html.replace("{{KUAIKUAI_ART}}", &escaped)
}
