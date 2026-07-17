// AXIOM Nabla Node — Binary Entry Point
//
// Boots the Nabla node, initializes all subsystems, starts the
// monitoring HTTP server, and runs the tick loop.
//
// Usage:
//   cargo run --bin nabla                    # default data dir + port
//   cargo run --bin nabla -- --port 8080     # custom port
//   cargo run --bin nabla -- --data /tmp/nbl # custom data dir
//   cargo run --bin nabla -- --help

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use axiom_nabla::cc::sim_nbc;
use axiom_nabla::config::NablaConfig;
use axiom_nabla::crypto::Ed25519Signer;
use axiom_nabla::monitor::{self, MonitorConfig};
use axiom_nabla::node::NablaNode;
use axiom_nabla::types::*;

/// CLI arguments (hand-parsed — no extra deps).
struct Args {
    data_dir: PathBuf,
    port: u16,
    bind: String,
    auth_token: Option<String>,
    config_path: Option<PathBuf>,
}

impl Args {
    fn parse() -> Self {
        let mut args = std::env::args().skip(1);
        let mut data_dir = PathBuf::from("nabla_data");
        let mut port = monitor::DEFAULT_MONITOR_PORT;
        let mut bind = "127.0.0.1".to_string();
        let mut auth_token = None;
        let mut config_path = None;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--data" | "-d" => {
                    if let Some(val) = args.next() {
                        data_dir = PathBuf::from(val);
                    }
                }
                "--port" | "-p" => {
                    if let Some(val) = args.next() {
                        port = val.parse().unwrap_or(port);
                    }
                }
                "--bind" | "-b" => {
                    if let Some(val) = args.next() {
                        bind = val;
                    }
                }
                "--token" | "-t" => {
                    auth_token = args.next();
                }
                "--config" | "-c" => {
                    if let Some(val) = args.next() {
                        config_path = Some(PathBuf::from(val));
                    }
                }
                "--help" | "-h" => {
                    println!("AXIOM Nabla Node v{}", env!("CARGO_PKG_VERSION"));
                    println!();
                    println!("Usage: nabla [OPTIONS]");
                    println!();
                    println!("Options:");
                    println!("  -d, --data <DIR>     Data directory (default: nabla_data)");
                    println!("  -p, --port <PORT>    Monitor port (default: {})", monitor::DEFAULT_MONITOR_PORT);
                    println!("  -b, --bind <ADDR>    Bind address (default: 127.0.0.1)");
                    println!("  -t, --token <TOKEN>  Auth token for remote access");
                    println!("  -c, --config <FILE>  Bootstrap peers config file (bootstrap.toml)");
                    println!("  -h, --help           Show this help");
                    std::process::exit(0);
                }
                _ => {
                    eprintln!("Unknown argument: {}", arg);
                    std::process::exit(1);
                }
            }
        }

        Self { data_dir, port, bind, auth_token, config_path }
    }
}

fn main() {
    let args = Args::parse();

    // ── Banner ──
    println!("╔══════════════════════════════════════════╗");
    println!("║    ∇  AXIOM Nabla Node v{}      ║", env!("CARGO_PKG_VERSION"));
    println!("╠══════════════════════════════════════════╣");
    println!("║  Citizen infrastructure for AXIOM        ║");
    println!("║  \"Can crash, must not lie\"               ║");
    println!("╚══════════════════════════════════════════╝");
    println!();

    // ── Create data directory ──
    std::fs::create_dir_all(&args.data_dir).expect("Failed to create data directory");
    println!("[INIT] Data directory: {}", args.data_dir.display());

    // ── Load known nodes config ──
    let config = if let Some(ref config_path) = args.config_path {
        match NablaConfig::load_bootstrap(config_path) {
            Ok(cfg) => {
                println!("[INIT] Loaded {} bootstrap peers from {}", cfg.peer_count(), config_path.display());
                cfg
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to load config: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Check default location: data_dir/bootstrap.toml
        let default_path = args.data_dir.join("bootstrap.toml");
        if default_path.exists() {
            match NablaConfig::load_bootstrap(&default_path) {
                Ok(cfg) => {
                    println!("[INIT] Loaded {} bootstrap peers from {}", cfg.peer_count(), default_path.display());
                    cfg
                }
                Err(e) => {
                    eprintln!("[WARN] Failed to load {}: {}", default_path.display(), e);
                    println!("[INIT] Starting in standalone mode (no bootstrap peers)");
                    NablaConfig::new()
                }
            }
        } else {
            println!("[INIT] No bootstrap config — standalone mode");
            NablaConfig::new()
        }
    };

    // ── Open node ──
    let signer = Ed25519Signer::from_node_index(0); // Real Ed25519 signer
    let mut node = NablaNode::open(&args.data_dir, Box::new(signer)).expect("Failed to open NablaNode");
    println!("[INIT] NablaNode opened (tick={}, entries={})", node.current_tick(), node.entry_count());

    // ── Generate node identity ──
    // ── Node Identity ──
    // In production: Core generates keypairs and derives node_id = BLAKE3(sphincs_pk).
    // For sim: deterministic from data dir path for consistency across restarts.
    let node_id = {
        let path_bytes = args.data_dir.to_string_lossy().as_bytes().to_vec();
        let hash = blake3::hash(&path_bytes);
        let mut id = [0u8; 32];
        id.copy_from_slice(hash.as_bytes());
        id
    };

    println!("[INIT] Node ID: {}", monitor::hex_short(&node_id));

    // ── Initialize TARDIS ──
    node.init_tardis(node_id);
    println!("[INIT] TARDIS initialized");

    // ── Initialize Mesh ──
    let address = NablaAddress::V4 {
        ip: [127, 0, 0, 1],
        port: args.port + 1, // gossip on port+1
    };
    if config.peer_count() > 0 {
        let bootstrap = config.bootstrap_peer_infos(node.current_tick());
        node.init_mesh_with_bootstrap(node_id, address, bootstrap);
        println!("[INIT] Gossip mesh initialized with {} bootstrap peers", config.peer_count());
    } else {
        node.init_mesh(node_id, address);
        println!("[INIT] Gossip mesh initialized (standalone — no known nodes)");
    }

    // ── Initialize CC chain ──
    // NBC = VBC from Core. This is a sim placeholder until Core provides the real one.
    let nbc = sim_nbc(node_id, node.current_tick());
    node.init_cc(nbc);
    println!("[INIT] CC chain initialized");

    // ── Wrap node in Arc<Mutex> for shared access ──
    let node = Arc::new(Mutex::new(node));

    // ── Start HTTP monitor ──
    let monitor_config = MonitorConfig {
        port: args.port,
        bind_addr: args.bind.clone(),
        auth_token: args.auth_token.clone(),
    };

    let listen_addr = format!("{}:{}", args.bind, args.port);
    let listener = TcpListener::bind(&listen_addr).unwrap_or_else(|e| {
        eprintln!("[ERROR] Cannot bind to {}: {}", listen_addr, e);
        std::process::exit(1);
    });
    // Non-blocking so tick loop isn't blocked
    listener.set_nonblocking(true).ok();

    println!("[HTTP] Dashboard: http://{}", listen_addr);
    if args.auth_token.is_some() {
        println!("[HTTP] Auth token required");
    }
    println!();
    println!("[RUNNING] Press Ctrl+C to stop");
    println!();

    // ── HTTP server thread ──
    let node_http = Arc::clone(&node);
    let _http_thread = thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // Read request (simple HTTP/1.1 parsing)
                    let mut buf = [0u8; 2048];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 { continue; }

                    let request = String::from_utf8_lossy(&buf[..n]);
                    let (path, query) = parse_request(&request);

                    // Collect status snapshot
                    let status = {
                        let node = node_http.lock().unwrap();
                        node.status_snapshot()
                    };

                    // Route and respond
                    let (code, content_type, body) = monitor::route_request(
                        &path,
                        query.as_deref(),
                        &status,
                        &monitor_config,
                    );

                    let status_text = match code {
                        200 => "OK",
                        401 => "Unauthorized",
                        404 => "Not Found",
                        503 => "Service Unavailable",
                        _ => "Unknown",
                    };

                    let response = format!(
                        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        code, status_text, content_type, body.len(), body
                    );

                    stream.write_all(response.as_bytes()).ok();
                    stream.flush().ok();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection pending — sleep briefly
                    thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    eprintln!("[HTTP] Accept error: {}", e);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });

    // ── Tick loop (main thread) ──
    let tick_interval = Duration::from_secs(5);
    loop {
        thread::sleep(tick_interval);

        let mut node = node.lock().unwrap();
        let new_tick = node.current_tick() + 1;
        node.advance_tick(new_tick);

        // Produce CC for this tick
        if let Some(cc) = node.cc_tick() {
            if cc.tick % 100 == 0 {
                println!(
                    "[TICK] {} | entries={} | bans={} | cc_score={} | ticks_helped={}",
                    cc.tick, node.entry_count(), node.ban_count(), cc.score, cc.ticks_helped
                );
            }
        }

        // Mesh maintenance
        node.mesh_tick();
    }
}

/// Parse an HTTP request line to extract path and query string.
fn parse_request(request: &str) -> (String, Option<String>) {
    // GET /path?query HTTP/1.1
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        return ("/".into(), None);
    }

    let full_path = parts[1];
    if let Some(idx) = full_path.find('?') {
        (full_path[..idx].to_string(), Some(full_path[idx + 1..].to_string()))
    } else {
        (full_path.to_string(), None)
    }
}
