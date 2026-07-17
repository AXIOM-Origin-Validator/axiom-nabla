// AXIOM Nabla — Node Configuration (Runtime Loader)
//
// ARCHITECTURE:
//   This file (config.rs) compiles into the binary.
//   The DATA (peer list) lives in an EXTERNAL TOML FILE read at RUNTIME.
//   The TOML file can be edited without recompiling.
//
//   Binary reads: bootstrap.toml → at startup → used for bootstrap
//   To add/remove peers: edit bootstrap.toml, restart the node.
//
// File format: bootstrap.toml
//   [[peer]]
//   address = "203.0.113.10:6225"
//
//   [[peer]]
//   address = "[2001:db8::1]:6225"
//
//   [[peer]]
//   address = "node1.axiom.network:6225"    # domain name (DNS resolved at load)
//
//   Lines starting with # are TOML comments.
//
// At bootstrap, a node connects to these peers to join the
// TARDIS tree and gossip mesh. After joining, the node discovers
// more peers through gossip — the bootstrap list is just the entry
// point, not a permanent dependency.
//
// Node IDs are NOT included — they are discovered on connect via Hello.
// Bootstrap only needs reachable addresses.
//
// NOTHING in this file is hardcoded node data. All peer address
// information comes from the external TOML file.

use crate::constants::BOOTSTRAP_PEERS_MAX;
use crate::types::{NablaAddress, PeerInfo};

/// A bootstrap peer entry from configuration.
/// Address-only: node_id and name are discovered on connect via Hello/NBC.
#[derive(Debug, Clone)]
pub struct BootstrapPeer {
    pub address: NablaAddress,
}

/// Configuration for a Nabla node.
#[derive(Debug, Clone)]
pub struct NablaConfig {
    /// Bootstrap peers to connect to at startup.
    /// Read from bootstrap.toml or provided programmatically.
    pub bootstrap_peers: Vec<BootstrapPeer>,
}

impl Default for NablaConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl NablaConfig {
    /// Create an empty config (standalone mode).
    pub fn new() -> Self {
        Self {
            bootstrap_peers: Vec::new(),
        }
    }

    /// Load bootstrap peers from a TOML file.
    ///
    /// Format:
    /// ```toml
    /// [[peer]]
    /// address = "10.0.0.1:6225"
    ///
    /// [[peer]]
    /// address = "[2001:db8::1]:6225"
    /// ```
    pub fn load_bootstrap(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;

        let mut peers = Vec::new();
        let mut in_peer_block = false;

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line == "[[peer]]" {
                in_peer_block = true;
                continue;
            }

            if in_peer_block {
                // Skip unknown fields (e.g. legacy "name = ...")
                if parse_toml_string_field(line, "name").is_some() {
                    continue;
                }
                // Expect: address = "..."
                if let Some(addr_str) = parse_toml_address_line(line) {
                    let address = parse_address(&addr_str)
                        .map_err(|e| format!("line {}: {}", line_num + 1, e))?;
                    peers.push(BootstrapPeer { address });
                    in_peer_block = false;

                    if peers.len() >= BOOTSTRAP_PEERS_MAX {
                        log::warn!(
                            "bootstrap peers capped at {} entries (file has more)",
                            BOOTSTRAP_PEERS_MAX
                        );
                        break;
                    }
                } else {
                    return Err(format!(
                        "line {}: expected 'address = \"...\"', got '{}'",
                        line_num + 1, line
                    ));
                }
            }
        }

        Ok(Self { bootstrap_peers: peers })
    }

    /// Create config from a list of bootstrap peers (for testing / sim).
    pub fn from_peers(peers: Vec<BootstrapPeer>) -> Self {
        Self { bootstrap_peers: peers }
    }

    /// Convert bootstrap peers to PeerInfo for mesh bootstrap.
    /// Node IDs are zeroed — they will be discovered on connect via Hello.
    pub fn bootstrap_peer_infos(&self, initial_tick: u64) -> Vec<PeerInfo> {
        self.bootstrap_peers
            .iter()
            .map(|bp| PeerInfo {
                node_id: [0u8; 32], // discovered on connect
                address: bp.address.clone(),
                last_seen: initial_tick,
                tardis_up: None,
                has_d_open: true, open_slots: 2, // assume open at bootstrap
                messages_delivered: 0,
                connected_since: initial_tick,
            txid_service: String::new(),
            })
            .collect()
    }

    /// Number of bootstrap peers.
    pub fn peer_count(&self) -> usize {
        self.bootstrap_peers.len()
    }
}

/// Parse a TOML string field like `name = "alpha"`.
/// Returns the string value without quotes, or None if the field name doesn't match.
fn parse_toml_string_field(line: &str, field: &str) -> Option<String> {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix(field) {
        let rest = rest.trim();
        if let Some(rest) = rest.strip_prefix('=') {
            let rest = rest.trim();
            if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
                return Some(rest[1..rest.len()-1].to_string());
            }
        }
    }
    None
}

/// Parse a TOML address line like `address = "10.0.0.1:6225"`.
/// Returns the address string without quotes, or None if not matching.
fn parse_toml_address_line(line: &str) -> Option<String> {
    let line = line.trim();
    // Match: address = "..."
    if let Some(rest) = line.strip_prefix("address") {
        let rest = rest.trim();
        if let Some(rest) = rest.strip_prefix('=') {
            let rest = rest.trim();
            if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
                return Some(rest[1..rest.len()-1].to_string());
            }
        }
    }
    None
}

/// Parse an address string like "1.2.3.4:6225", "[2001:db8::1]:6225",
/// or "node1.axiom.network:6225" (DNS resolved at config load time).
fn parse_address(addr: &str) -> Result<NablaAddress, String> {
    // Try IPv6 first: [addr]:port
    if addr.starts_with('[') {
        if let Some(bracket_end) = addr.find(']') {
            let ip_str = &addr[1..bracket_end];
            let port_str = addr.get(bracket_end + 2..).unwrap_or("6225");
            let port: u16 = port_str.parse()
                .map_err(|_| format!("invalid port: {}", port_str))?;
            let ip = parse_ipv6(ip_str)?;
            return Ok(NablaAddress::V6 { ip, port });
        }
    }

    // IPv4: addr:port
    if let Some(colon_idx) = addr.rfind(':') {
        let ip_str = &addr[..colon_idx];
        let port_str = &addr[colon_idx + 1..];
        let port: u16 = port_str.parse()
            .map_err(|_| format!("invalid port: {}", port_str))?;
        if let Ok(ip) = parse_ipv4(ip_str) {
            return Ok(NablaAddress::V4 { ip, port });
        }

        // Not a numeric IPv4 — try DNS resolution (domain:port)
        use std::net::ToSocketAddrs;
        let resolved = addr.to_socket_addrs()
            .map_err(|e| format!("DNS resolution failed for '{}': {}", addr, e))?
            .next()
            .ok_or_else(|| format!("DNS returned no addresses for '{}'", addr))?;
        match resolved {
            std::net::SocketAddr::V4(v4) => {
                Ok(NablaAddress::V4 { ip: v4.ip().octets(), port: v4.port() })
            }
            std::net::SocketAddr::V6(v6) => {
                Ok(NablaAddress::V6 { ip: v6.ip().octets(), port: v6.port() })
            }
        }
    } else {
        Err(format!("missing port in address: {}", addr))
    }
}

fn parse_ipv4(s: &str) -> Result<[u8; 4], String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("invalid IPv4: {}", s));
    }
    let mut ip = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        ip[i] = part.parse()
            .map_err(|_| format!("invalid IPv4 octet: {}", part))?;
    }
    Ok(ip)
}

fn parse_ipv6(s: &str) -> Result<[u8; 16], String> {
    // Simple IPv6 parser — handles full and :: compressed forms
    let addr: std::net::Ipv6Addr = s.parse()
        .map_err(|_| format!("invalid IPv6: {}", s))?;
    Ok(addr.octets())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bootstrap_toml() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let content = "# AXIOM Bootstrap Peers\n\
             [[peer]]\n\
             address = \"10.0.0.1:6225\"\n\
             \n\
             [[peer]]\n\
             address = \"10.0.0.2:6225\"\n";
        std::fs::write(tmp.path(), content).unwrap();

        let config = NablaConfig::load_bootstrap(tmp.path()).unwrap();
        assert_eq!(config.peer_count(), 2);
        assert_eq!(config.bootstrap_peers[0].address,
            NablaAddress::V4 { ip: [10, 0, 0, 1], port: 6225 });
        assert_eq!(config.bootstrap_peers[1].address,
            NablaAddress::V4 { ip: [10, 0, 0, 2], port: 6225 });
    }

    #[test]
    fn parse_ipv4_address() {
        let addr = parse_address("10.0.0.1:6225").unwrap();
        assert_eq!(addr, NablaAddress::V4 { ip: [10, 0, 0, 1], port: 6225 });
    }

    #[test]
    fn parse_ipv6_address() {
        let addr = parse_address("[::1]:6225").unwrap();
        let mut expected = [0u8; 16];
        expected[15] = 1;
        assert_eq!(addr, NablaAddress::V6 { ip: expected, port: 6225 });
    }

    #[test]
    fn bootstrap_peers_from_config() {
        let config = NablaConfig::from_peers(vec![
            BootstrapPeer {
                address: NablaAddress::V4 { ip: [10, 0, 0, 1], port: 6225 },
            },
        ]);
        let peers = config.bootstrap_peer_infos(0);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, [0u8; 32]); // zeroed — discovered on connect
        assert!(peers[0].has_d_open); // assumed at bootstrap
    }

    #[test]
    fn empty_config() {
        let config = NablaConfig::new();
        assert_eq!(config.peer_count(), 0);
        assert!(config.bootstrap_peer_infos(0).is_empty());
    }

    #[test]
    fn comments_and_blank_lines_skipped() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let content = "# comment\n\
             \n\
             [[peer]]\n\
             address = \"10.0.0.1:6225\"\n\
             # another comment\n\
             \n";
        std::fs::write(tmp.path(), content).unwrap();

        let config = NablaConfig::load_bootstrap(tmp.path()).unwrap();
        assert_eq!(config.peer_count(), 1);
    }

    #[test]
    fn genesis_port_range() {
        use crate::constants::{GENESIS_BASE_PORT, GENESIS_NABLA_COUNT};
        assert_eq!(GENESIS_BASE_PORT, 6225);
        assert_eq!(GENESIS_BASE_PORT + (GENESIS_NABLA_COUNT as u16) - 1, 6234);
    }

    #[test]
    fn bootstrap_toml_loads_all_genesis() {
        let bootstrap_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("bootstrap.toml");
        let config = NablaConfig::load_bootstrap(&bootstrap_path).unwrap();
        assert_eq!(config.peer_count(), 10,
            "bootstrap.toml must have all 10 genesis nodes");

        // Verify correct port assignments
        use crate::constants::GENESIS_BASE_PORT;
        for (i, peer) in config.bootstrap_peers.iter().enumerate() {
            let expected_port = GENESIS_BASE_PORT + i as u16;
            match &peer.address {
                NablaAddress::V4 { port, .. } => {
                    assert_eq!(*port, expected_port,
                        "genesis node {} should be on port {}", i, expected_port);
                }
                _ => panic!("expected IPv4 for test bootstrap"),
            }
        }
    }

    #[test]
    fn bootstrap_toml_legacy_name_field_skipped() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let content = "[[peer]]\nname = \"alpha\"\naddress = \"127.0.0.1:6225\"\n\n\
                       [[peer]]\naddress = \"127.0.0.1:6226\"\n";
        std::fs::write(tmp.path(), content).unwrap();

        let config = NablaConfig::load_bootstrap(tmp.path()).unwrap();
        assert_eq!(config.peer_count(), 2, "name lines should be silently skipped");
    }

    #[test]
    fn parse_address_domain() {
        let addr = parse_address("localhost:6225").unwrap();
        // localhost resolves to 127.0.0.1 (V4) or ::1 (V6) depending on system
        match &addr {
            NablaAddress::V4 { ip, port } => {
                assert_eq!(*ip, [127, 0, 0, 1]);
                assert_eq!(*port, 6225);
            }
            NablaAddress::V6 { port, .. } => {
                assert_eq!(*port, 6225);
            }
        }
    }

    #[test]
    fn probation_constant() {
        use crate::constants::NABLA_PROBATION_SECS;
        assert_eq!(NABLA_PROBATION_SECS, 48 * 3600,
            "probation must be 48 hours in seconds");
    }
}
