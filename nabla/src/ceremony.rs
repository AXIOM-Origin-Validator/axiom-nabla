// AXIOM Nabla — Ceremony Helpers
//
// Non-crypto ceremony types and helpers used by sim.rs and binary_sim.rs.
// The actual ceremony crypto (keygen, signing) lives in axiom-nabla-ceremony.
//
// NBC = VBC struct (YPX-002) but with Nabla's OWN separate keypairs.
// Same machine, same directory as Lambda, different keys. Key isolation.
//
// Directory layout (batch/dev):
//   {base_dir}/
//     axiom-first-penguin-alpha/config/nbc.json            (genesis node 0)
//     ...
//     axiom-first-penguin-kappa/config/nbc.json            (genesis node 9)
//     nabla_10/config/nbc.json                             (non-genesis)
//     ...

use std::fs;
use std::path::{Path, PathBuf};

use crate::cc::NBC;
use crate::types::NodeId;

/// The 10 genesis validator directory names, in node index order.
/// Matches GENESIS_NAMES in dev.sh and install_genesis.sh.
pub const GENESIS_NAMES: [&str; 10] = [
    "alpha", "beta", "gamma", "delta", "epsilon",
    "zeta", "eta", "theta", "iota", "kappa",
];

/// Dev/test node names for non-genesis nodes (index 10-49).
/// Mix of English, Traditional Chinese (繁體中文), and Japanese (日本語).
/// All are real penguin species, properly translated.
/// In production, operators choose their own name.
pub const PENGUIN_NAMES: [&str; 40] = [
    "Emperor",              // 10 — Aptenodytes forsteri
    "皇帝企鵝",             // 11 — Emperor penguin (zh-TW)
    "コウテイペンギン",       // 12 — Emperor penguin (ja)
    "King",                 // 13 — Aptenodytes patagonicus
    "國王企鵝",             // 14 — King penguin (zh-TW)
    "オウサマペンギン",       // 15 — King penguin (ja)
    "Gentoo",               // 16 — Pygoscelis papua
    "巴布亞企鵝",           // 17 — Gentoo penguin (zh-TW)
    "ジェンツーペンギン",     // 18 — Gentoo penguin (ja)
    "Chinstrap",            // 19 — Pygoscelis antarcticus
    "南極企鵝",             // 20 — Chinstrap penguin (zh-TW)
    "ヒゲペンギン",          // 21 — Chinstrap penguin (ja)
    "Adelie",               // 22 — Pygoscelis adeliae
    "阿德利企鵝",           // 23 — Adélie penguin (zh-TW)
    "アデリーペンギン",       // 24 — Adélie penguin (ja)
    "Rockhopper",           // 25 — Eudyptes chrysocome
    "跳岩企鵝",             // 26 — Rockhopper penguin (zh-TW)
    "イワトビペンギン",       // 27 — Rockhopper penguin (ja)
    "Macaroni",             // 28 — Eudyptes chrysolophus
    "馬可羅尼企鵝",         // 29 — Macaroni penguin (zh-TW)
    "マカロニペンギン",       // 30 — Macaroni penguin (ja)
    "Little-Blue",          // 31 — Eudyptula minor
    "小藍企鵝",             // 32 — Little blue penguin (zh-TW)
    "コガタペンギン",        // 33 — Little penguin (ja)
    "Magellanic",           // 34 — Spheniscus magellanicus
    "麥哲倫企鵝",           // 35 — Magellanic penguin (zh-TW)
    "マゼランペンギン",       // 36 — Magellanic penguin (ja)
    "African",              // 37 — Spheniscus demersus
    "非洲企鵝",             // 38 — African penguin (zh-TW)
    "ケープペンギン",        // 39 — African/Cape penguin (ja)
    "Galapagos",            // 40 — Spheniscus mendiculus
    "加拉巴哥企鵝",         // 41 — Galápagos penguin (zh-TW)
    "ガラパゴスペンギン",     // 42 — Galápagos penguin (ja)
    "Humboldt",             // 43 — Spheniscus humboldti
    "漢波德企鵝",           // 44 — Humboldt penguin (zh-TW)
    "フンボルトペンギン",     // 45 — Humboldt penguin (ja)
    "Yellow-Eyed",          // 46 — Megadyptes antipodes
    "黃眼企鵝",             // 47 — Yellow-eyed penguin (zh-TW)
    "キガシラペンギン",       // 48 — Yellow-eyed penguin (ja)
    "Fairy",                // 49 — Eudyptula minor (alternate name)
];

/// Get the human-readable name for a node by index.
/// Genesis (0-9): Greek letter names (alpha-kappa).
/// Non-genesis (10-49): Penguin species in English/Chinese/Japanese.
/// 50+: Fallback to "Nabla-{idx}".
pub fn node_name(idx: usize) -> String {
    if idx < 10 {
        GENESIS_NAMES[idx].to_string()
    } else if idx - 10 < PENGUIN_NAMES.len() {
        PENGUIN_NAMES[idx - 10].to_string()
    } else {
        format!("Nabla-{}", idx)
    }
}

/// Result of ceremony for one node.
#[derive(Debug)]
pub struct CeremonyNode {
    /// Real NBC (= VBC struct with Nabla's own SPHINCS+ signatures).
    pub nbc: NBC,
    /// Nabla's Ed25519 secret key (32 bytes) for day-to-day tick signing.
    pub ed25519_sk: [u8; 32],
    /// node_id = BLAKE3(nabla_sphincs_pk) — Nabla's own identity.
    pub node_id: NodeId,
}

/// Get the config directory path for a given node index.
///   0-9  → {base_dir}/axiom-first-penguin-{name}/config/
///   10+  → {base_dir}/nabla_{i}/config/
pub fn node_config_dir(base_dir: &Path, node_idx: usize) -> PathBuf {
    if node_idx < 10 {
        base_dir
            .join(format!("axiom-first-penguin-{}", GENESIS_NAMES[node_idx]))
            .join("config")
    } else {
        base_dir
            .join(format!("nabla_{}", node_idx))
            .join("config")
    }
}

// ═══════════════════════════════════════════════════════════════════
// Config-driven single-node ceremony
// ═══════════════════════════════════════════════════════════════════

/// Minimal TOML config for a single production node.
#[derive(Debug, serde::Deserialize)]
pub struct NodeToml {
    pub name: String,
    pub port: u16,
    /// Dashboard HTTP port (default: 6226, avoids collision with P2P port).
    #[serde(default = "default_dashboard_port")]
    pub dashboard_port: u16,
    /// Bind dashboard to 0.0.0.0 for remote access (default: false = localhost only).
    #[serde(default)]
    pub dashboard_remote: bool,
}

fn default_dashboard_port() -> u16 { 6226 }

impl NodeToml {
    /// Load and validate a node.toml file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        let node: NodeToml = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;
        if node.name.is_empty() {
            return Err("node name must not be empty".to_string());
        }
        if node.name.len() > 64 {
            return Err(format!(
                "node name exceeds 64 byte limit: {} ({} bytes)",
                node.name, node.name.len()
            ));
        }
        if node.port == 0 {
            return Err("port must be > 0".to_string());
        }
        Ok(node)
    }
}

/// Load a single node's NBC from its config directory.
/// Counterpart to `nabla_ceremony_single()` for runtime loading.
pub fn load_single_nbc(config_dir: &Path) -> Result<CeremonyNode, String> {
    let nbc_path = config_dir.join("nbc.json");
    if !nbc_path.exists() {
        return Err(format!(
            "NBC not found: {}\n\
             Run nabla-ceremony --config <path/to/node.toml> first.",
            nbc_path.display()
        ));
    }

    let nbc_json = fs::read_to_string(&nbc_path)
        .map_err(|e| format!("Failed to read {}: {}", nbc_path.display(), e))?;
    let nbc: NBC = serde_json::from_str(&nbc_json)
        .map_err(|e| format!("Failed to parse {}: {}", nbc_path.display(), e))?;

    let sk_path = config_dir.join("nabla_ed25519.key");
    let ed25519_sk_bytes = fs::read(&sk_path)
        .map_err(|e| format!("Failed to read {}: {}", sk_path.display(), e))?;
    if ed25519_sk_bytes.len() != 32 {
        return Err(format!(
            "Invalid Ed25519 key size in {}: {} bytes",
            sk_path.display(), ed25519_sk_bytes.len()
        ));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&ed25519_sk_bytes);

    let node_id = nbc.validator_id;

    Ok(CeremonyNode {
        nbc,
        ed25519_sk: sk,
        node_id,
    })
}

/// Load ceremony results from per-node nbc.json files on disk.
/// Returns error message if any node is missing its NBC.
#[allow(clippy::needless_range_loop)]
pub fn load_nbcs(base_dir: &Path, count: usize) -> Result<Vec<CeremonyNode>, String> {
    let mut results = Vec::with_capacity(count);

    for i in 0..count {
        let config_dir = node_config_dir(base_dir, i);
        let nbc_path = config_dir.join("nbc.json");

        if !nbc_path.exists() {
            let _dir_label = if i < 10 {
                format!("axiom-first-penguin-{}", GENESIS_NAMES[i])
            } else {
                format!("nabla_{}", i)
            };
            return Err(format!(
                "NBC not found for node {}: {}\n\
                 Run Nabla ceremony first (dev.sh → option 28n)",
                i, nbc_path.display()
            ));
        }

        // Read nbc.json
        let nbc_json = fs::read_to_string(&nbc_path)
            .map_err(|e| format!("Failed to read {}: {}", nbc_path.display(), e))?;
        let nbc: NBC = serde_json::from_str(&nbc_json)
            .map_err(|e| format!("Failed to parse {}: {}", nbc_path.display(), e))?;

        // Read Nabla's Ed25519 secret key
        let sk_path = config_dir.join("nabla_ed25519.key");
        let ed25519_sk_bytes = fs::read(&sk_path)
            .map_err(|e| format!("Failed to read {}: {}", sk_path.display(), e))?;
        if ed25519_sk_bytes.len() != 32 {
            return Err(format!("Invalid Ed25519 key size in {}: {} bytes",
                sk_path.display(), ed25519_sk_bytes.len()));
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&ed25519_sk_bytes);

        let node_id = nbc.validator_id;

        results.push(CeremonyNode {
            nbc,
            ed25519_sk: sk,
            node_id,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_name_genesis() {
        assert_eq!(node_name(0), "alpha");
        assert_eq!(node_name(5), "zeta");
        assert_eq!(node_name(9), "kappa");
    }

    #[test]
    fn test_node_name_penguins() {
        assert_eq!(node_name(10), "Emperor");
        assert_eq!(node_name(11), "皇帝企鵝");
        assert_eq!(node_name(12), "コウテイペンギン");
        assert_eq!(node_name(49), "Fairy");
    }

    #[test]
    fn test_node_name_fallback() {
        assert_eq!(node_name(50), "Nabla-50");
        assert_eq!(node_name(100), "Nabla-100");
    }

    #[test]
    fn test_all_names_within_64_bytes() {
        for i in 0..50 {
            let name = node_name(i);
            assert!(
                name.len() <= 64,
                "node_name({}) = {:?} is {} bytes, exceeds 64",
                i, name, name.len()
            );
        }
    }

    // ── NodeToml tests ──

    #[test]
    fn test_node_toml_parse_minimal() {
        // Existing node.toml without dashboard fields — must still parse with defaults.
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("node.toml");
        fs::write(&toml_path, "name = \"my-node\"\nport = 6225\n").unwrap();
        let node = NodeToml::load(&toml_path).unwrap();
        assert_eq!(node.name, "my-node");
        assert_eq!(node.port, 6225);
        assert_eq!(node.dashboard_port, 6226);
        assert!(!node.dashboard_remote);
    }

    #[test]
    fn test_node_toml_dashboard_fields() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("node.toml");
        fs::write(&toml_path, "name = \"my-node\"\nport = 6225\ndashboard_port = 7000\ndashboard_remote = true\n").unwrap();
        let node = NodeToml::load(&toml_path).unwrap();
        assert_eq!(node.dashboard_port, 7000);
        assert!(node.dashboard_remote);
    }

    #[test]
    fn test_node_toml_reject_empty_name() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("node.toml");
        fs::write(&toml_path, "name = \"\"\nport = 6225\n").unwrap();
        let err = NodeToml::load(&toml_path).unwrap_err();
        assert!(err.contains("empty"), "expected 'empty' in error: {}", err);
    }

    #[test]
    fn test_node_toml_reject_long_name() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("node.toml");
        let long = "x".repeat(65);
        fs::write(&toml_path, format!("name = \"{}\"\nport = 6225\n", long)).unwrap();
        let err = NodeToml::load(&toml_path).unwrap_err();
        assert!(err.contains("64"), "expected '64' in error: {}", err);
    }

    #[test]
    fn test_node_toml_reject_zero_port() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("node.toml");
        fs::write(&toml_path, "name = \"test\"\nport = 0\n").unwrap();
        let err = NodeToml::load(&toml_path).unwrap_err();
        assert!(err.contains("port"), "expected 'port' in error: {}", err);
    }
}
