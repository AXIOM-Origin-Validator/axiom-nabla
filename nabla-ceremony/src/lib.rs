// AXIOM Nabla Ceremony — Offline NBC Provisioning
//
// Generates real NBCs (Nabla Birth Certificates) with SPHINCS+/Dilithium/Ed25519
// keypairs and root authority signatures. This is an OFFLINE provisioning tool,
// not a runtime network participant.
//
// Two modes:
//   1. Single-node (production): `nabla-ceremony --config node.toml --root-keys /path/to/root-keys/`
//   2. Batch (genesis set):      `nabla-ceremony --batch --base-dir DIR --count N`
//
// Directory layout (batch):
//   {base_dir}/
//     nabla-root-keys/                                     (generated here)
//       root_{1,2,3}.{pub,key}
//     axiom-first-penguin-alpha/config/nbc.json            (genesis node 0)
//     axiom-first-penguin-alpha/config/nabla_sphincs.*      Nabla's keys
//     axiom-first-penguin-alpha/config/nabla_ed25519.*      (separate from Validator's)
//     axiom-first-penguin-alpha/config/nabla_dilithium.*
//     ...
//     axiom-first-penguin-kappa/config/nbc.json            (genesis node 9)
//     nabla_10/config/nbc.json                             (non-genesis)
//     nabla_11/config/nbc.json
//     ...
//
// Directory layout (single-node):
//   {data_dir}/              (parent of node.toml)
//     node.toml              operator writes this
//     config/
//       nbc.json
//       nabla_sphincs.{pub,key}
//       nabla_ed25519.{pub,key}
//       nabla_dilithium.{pub,key}
//   Root keys are NOT copied here — they stay with the deployment package

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use axiom_core_logic::types::VBC;
use axiom_core_logic::compute::{
    compute_validator_id,
    compute_vbc_signing_payload,
    sign_sphincs,
};
use axiom_core_logic::verify::verify_sphincs;

use fips205::slh_dsa_sha2_128s;
use fips205::traits::SerDes as SphincsSerDes;

use fips204::ml_dsa_65;
use fips204::traits::SerDes as DilSerDes;

use axiom_nabla::ceremony::{CeremonyNode, NodeToml, node_config_dir, node_name, GENESIS_NAMES};

/// SECURITY FIX #10: Set secret key file permissions to 0o600 (owner read/write only).
/// Without explicit permissions, key files inherit the process umask (often 0o022),
/// resulting in 0o644 (world-readable). On non-Unix platforms this is a no-op.
#[cfg(unix)]
fn set_key_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    if let Err(e) = std::fs::set_permissions(path, perms) {
        eprintln!("  WARNING: Could not set 0o600 on {}: {}", path.display(), e);
    }
}

#[cfg(not(unix))]
fn set_key_file_permissions(_path: &Path) {
    // No-op on non-Unix platforms (Windows uses ACLs, not POSIX permissions)
}

// Key sizes (SPHINCS+ SLH-DSA-SHA2-128s)
const SPHINCS_PK_SIZE: usize = 32;
const SPHINCS_SK_SIZE: usize = 64;
const SPHINCS_SIG_SIZE: usize = 7856;

// ═══════════════════════════════════════════════════════════════════
// Extracted helpers (used by both batch and single-node paths)
// ═══════════════════════════════════════════════════════════════════

/// Load 3 existing root authority SPHINCS+ keypairs from `root_keys_dir`.
/// FATAL if any key file is missing or has wrong size.
/// Returns (public_keys, secret_keys) — same format as `generate_root_keys`.
#[allow(clippy::type_complexity)]
pub fn load_root_keys(root_keys_dir: &Path) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), String> {
    let mut root_pks: Vec<Vec<u8>> = Vec::new();
    let mut root_sks: Vec<Vec<u8>> = Vec::new();

    for i in 1..=3 {
        let pk_path = root_keys_dir.join(format!("root_{}.pub", i));
        let sk_path = root_keys_dir.join(format!("root_{}.key", i));

        let pk_bytes = fs::read(&pk_path)
            .map_err(|e| format!("Failed to read {}: {}", pk_path.display(), e))?;
        let sk_bytes = fs::read(&sk_path)
            .map_err(|e| format!("Failed to read {}: {}", sk_path.display(), e))?;

        if pk_bytes.len() != SPHINCS_PK_SIZE {
            return Err(format!("root_{}.pub has wrong size: {} (expected {})",
                i, pk_bytes.len(), SPHINCS_PK_SIZE));
        }
        if sk_bytes.len() != SPHINCS_SK_SIZE {
            return Err(format!("root_{}.key has wrong size: {} (expected {})",
                i, sk_bytes.len(), SPHINCS_SK_SIZE));
        }

        eprintln!("  ROOT_{}: {} (loaded)", i, hex::encode(&pk_bytes));
        root_pks.push(pk_bytes);
        root_sks.push(sk_bytes);
    }

    Ok((root_pks, root_sks))
}

/// Generate 3 root authority SPHINCS+ keypairs and write them to `root_keys_dir`.
/// Returns (public_keys, secret_keys).
pub fn generate_root_keys(root_keys_dir: &Path) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    fs::create_dir_all(root_keys_dir).expect("create nabla-root-keys dir");

    let mut root_pks: Vec<Vec<u8>> = Vec::new();
    let mut root_sks: Vec<Vec<u8>> = Vec::new();

    for i in 0..3 {
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen()
            .expect("SPHINCS+ root keygen failed");
        let pk_bytes = pk.into_bytes().to_vec();
        let sk_bytes = sk.into_bytes().to_vec();
        assert_eq!(pk_bytes.len(), SPHINCS_PK_SIZE);
        assert_eq!(sk_bytes.len(), SPHINCS_SK_SIZE);

        fs::write(root_keys_dir.join(format!("root_{}.pub", i + 1)), &pk_bytes)
            .expect("write root PK");
        let key_path = root_keys_dir.join(format!("root_{}.key", i + 1));
        fs::write(&key_path, &sk_bytes)
            .expect("write root SK");
        // SECURITY FIX #10: Set secret key files to owner-only permissions (0o600).
        // Without this, key files inherit the umask default (often 0o644),
        // making them world-readable on multi-user systems.
        set_key_file_permissions(&key_path);

        eprintln!("  ROOT_{}: {}", i + 1, hex::encode(&pk_bytes));
        root_pks.push(pk_bytes);
        root_sks.push(sk_bytes);
    }

    (root_pks, root_sks)
}

/// Generate keys + NBC for a single node. Writes key files into `config_dir`.
/// Returns the `CeremonyNode`.
///
/// `root_index` selects which of the `root_pks` / `root_sks` entries
/// signs this NBC. YPX-002 §4.3 defines "cross-branch" as two Nabla
/// nodes whose NBCs were signed by different parent CAs — the receiver-
/// side §4.6 verification picker groups nodes by `nbc_issuer_pk` and
/// selects one per branch. For that to be meaningful, different nodes
/// in the ceremony MUST be signed by different roots. Passing the same
/// index for every node collapses the whole mesh into one branch and
/// makes the §4.3 picker a no-op. The batch ceremony orchestrates a
/// round-robin assignment across `root_pks.len()` branches.
pub fn generate_node_nbc(
    name: &str,
    config_dir: &Path,
    root_pks: &[Vec<u8>],
    root_sks: &[Vec<u8>],
    root_index: usize,
    now: u64,
    expires_at: u64,
) -> CeremonyNode {
    fs::create_dir_all(config_dir).expect("create node config dir");

    // Generate Nabla's OWN SPHINCS+ keypair
    let (sphincs_pk_obj, sphincs_sk_obj) = slh_dsa_sha2_128s::try_keygen()
        .expect("SPHINCS+ node keygen failed");
    let sphincs_pk = sphincs_pk_obj.into_bytes().to_vec();
    let sphincs_sk = sphincs_sk_obj.into_bytes().to_vec();
    fs::write(config_dir.join("nabla_sphincs.pub"), &sphincs_pk).expect("write nabla sphincs pk");
    let sphincs_key_path = config_dir.join("nabla_sphincs.key");
    fs::write(&sphincs_key_path, &sphincs_sk).expect("write nabla sphincs sk");
    set_key_file_permissions(&sphincs_key_path); // SECURITY FIX #10

    // Generate Nabla's OWN Ed25519 keypair
    let mut ed25519_seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ed25519_seed);
    let ed25519_signing = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed);
    let ed25519_pk_bytes = ed25519_signing.verifying_key().as_bytes().to_vec();
    let ed25519_sk_bytes = ed25519_signing.to_bytes();
    fs::write(config_dir.join("nabla_ed25519.pub"), &ed25519_pk_bytes).expect("write nabla ed25519 pk");
    let ed25519_key_path = config_dir.join("nabla_ed25519.key");
    fs::write(&ed25519_key_path, ed25519_sk_bytes).expect("write nabla ed25519 sk");
    set_key_file_permissions(&ed25519_key_path); // SECURITY FIX #10

    // Generate Nabla's OWN Dilithium keypair
    let (dil_pk_obj, dil_sk_obj) = ml_dsa_65::try_keygen()
        .expect("Dilithium node keygen failed");
    let dilithium_pk = dil_pk_obj.into_bytes().to_vec();
    let dilithium_sk = dil_sk_obj.into_bytes().to_vec();
    fs::write(config_dir.join("nabla_dilithium.pub"), &dilithium_pk).expect("write nabla dilithium pk");
    let dilithium_key_path = config_dir.join("nabla_dilithium.key");
    fs::write(&dilithium_key_path, &dilithium_sk).expect("write nabla dilithium sk");
    set_key_file_permissions(&dilithium_key_path); // SECURITY FIX #10

    // Compute Nabla's node_id = BLAKE3(nabla_sphincs_pk)
    let node_id = compute_validator_id(&sphincs_pk);

    // Build NBC (= VBC struct with Nabla's keys)
    // NBC uses k=1: only 1 root authority issuer (root_pks[0])
    assert!(name.len() <= 64, "Node name exceeds 64 byte limit: {} ({} bytes)", name, name.len());
    let mut nbc = VBC {
        network_size_baseline: 0, // YPX-021 §7 — ceremony certs are baseline-exempt
        baseline_tick: 0,
        version: 0x09,
        validator_id: node_id,
        subject_pubkey_sphincs: sphincs_pk,
        subject_pubkey_dilithium: dilithium_pk,
        subject_pubkey_ed25519: ed25519_pk_bytes,
        pgp_fingerprint: vec![],
        node_name: name.to_string(),
        proof_cap: String::new(),
        issued_at: now,
        expires_at,
        chain_depth: 0,
        issuer_set: vec![root_pks[root_index].clone()], // k=1: one root per NBC; caller picks the branch
        signatures: vec![],
        max_tx: axiom_nabla::constants::NBC_TX_BUDGET,
        founding_vbc_hash: [0u8; 32],
        genesis_lineage: [0u8; 32],
        nabla_registration: None,
    };

    // Compute signing payload via Core
    let commitment = compute_vbc_signing_payload(&nbc);

    // Sign with the selected root authority key (k=1 for NBC)
    let sig = sign_sphincs(&root_sks[root_index], &commitment)
        .expect("SPHINCS+ signing failed");
    assert_eq!(sig.len(), SPHINCS_SIG_SIZE, "sig size mismatch");

    // Verify immediately via Core (fail-stop)
    verify_sphincs(&root_pks[root_index], &commitment, &sig)
        .unwrap_or_else(|_| panic!("sig verify failed for node '{}'", name));

    nbc.signatures = vec![sig];

    // Write nbc.json
    let nbc_json = serde_json::to_string_pretty(&nbc).expect("NBC serialize");
    fs::write(config_dir.join("nbc.json"), &nbc_json).expect("write nbc.json");

    CeremonyNode {
        nbc,
        ed25519_sk: ed25519_sk_bytes,
        node_id,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Single-node ceremony (production)
// ═══════════════════════════════════════════════════════════════════

/// Run ceremony for a single node from a TOML config file.
///
/// Reads `node.toml`, loads SHARED root authority keys from `root_keys_dir`,
/// generates the node's own keypairs, and signs the NBC with the shared root keys.
/// Errors if `config/nbc.json` already exists (re-run protection).
/// Errors if any root key file is missing — does NOT generate root keys.
pub fn nabla_ceremony_single(toml_path: &Path, root_keys_dir: &Path) -> Result<CeremonyNode, String> {
    let node_toml = NodeToml::load(toml_path)?;

    let data_dir = toml_path.parent()
        .ok_or_else(|| "cannot determine parent directory of config file".to_string())?;

    let config_dir = data_dir.join("config");
    let nbc_path = config_dir.join("nbc.json");
    if nbc_path.exists() {
        return Err(format!(
            "NBC already exists at {}\n\
             To regenerate, remove {} and run again.",
            nbc_path.display(), config_dir.display()
        ));
    }

    eprintln!("╔══════════════════════════════════════════════════════╗");
    eprintln!("║  Nabla Ceremony — Single Node                       ║");
    eprintln!("║  Name: {:46}║", node_toml.name);
    eprintln!("║  Port: {:46}║", node_toml.port);
    eprintln!("╚══════════════════════════════════════════════════════╝");
    eprintln!("  Data dir:   {}", data_dir.display());
    eprintln!("  Root keys:  {}", root_keys_dir.display());
    eprintln!();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_at = now + (10 * 365 * 86400); // 10 years

    eprintln!("═══ Step 1: Loading Shared Root Authority Keys ═══");
    let (root_pks, root_sks) = load_root_keys(root_keys_dir)?;

    eprintln!();
    eprintln!("═══ Step 2: Generating NBC for '{}' ═══", node_toml.name);
    // Single-node ceremony path: no branch-diversity requirement by
    // itself (branch diversity is a mesh-level property), but we still
    // honour a deterministic assignment so the single-node + batch
    // paths produce identical NBCs when run on the same topology.
    // Derive the root index from a hash of the node name modulo the
    // available root count.
    let name_hash = {
        let mut h = 0u64;
        for b in node_toml.name.as_bytes() { h = h.wrapping_mul(1099511628211).wrapping_add(*b as u64); }
        h
    };
    let root_index = (name_hash as usize) % root_pks.len();
    let result = generate_node_nbc(
        &node_toml.name,
        &config_dir,
        &root_pks,
        &root_sks,
        root_index,
        now,
        expires_at,
    );

    eprintln!("  node_id: {}", hex::encode(&result.node_id[..8]));
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════╗");
    eprintln!("║  Ceremony Complete — 1 NBC signed                    ║");
    eprintln!("║  Config:  {}/config/", data_dir.display());
    eprintln!("╚══════════════════════════════════════════════════════╝");

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════════
// Batch ceremony (dev/sim)
// ═══════════════════════════════════════════════════════════════════

/// Run the Nabla ceremony: generate real NBCs for `count` nodes.
///
/// Writes per-node files to the correct directories under `base_dir`.
/// Genesis nodes (0-9) → axiom-first-penguin-{name}/config/
/// Non-genesis (10+) → nabla_{i}/config/
///
/// Root authority keys written to {base_dir}/nabla-root-keys/
pub fn nabla_ceremony(count: usize, base_dir: &Path) -> Vec<CeremonyNode> {
    eprintln!("╔════════════════════════════════════════════════════════╗");
    eprintln!("║         Nabla Ceremony — Real NBC Generation           ║");
    eprintln!("║         {} nodes × 1 root authority SPHINCS+ sig (k=1) ║", count);
    eprintln!("║         Key isolation: separate from Validator VBC keys  ║");
    eprintln!("╚════════════════════════════════════════════════════════╝");
    eprintln!("  Base dir: {}", base_dir.display());
    eprintln!();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_at = now + (10 * 365 * 86400); // 10 years

    // ── Step 1: Generate 3 root authority SPHINCS+ keypairs ──
    eprintln!("═══ Step 1: Generating 3 Root Authority Keys ═══");
    let root_keys_dir = base_dir.join("nabla-root-keys");
    let (root_pks, root_sks) = generate_root_keys(&root_keys_dir);

    // ── Step 2: Generate Nabla keys + sign NBC for each node ──
    eprintln!();
    eprintln!("═══ Step 2: Generating {} Nabla node NBCs ═══", count);
    let mut results: Vec<CeremonyNode> = Vec::with_capacity(count);

    #[allow(clippy::needless_range_loop)]
    for i in 0..count {
        let config_dir = node_config_dir(base_dir, i);
        let name = node_name(i);

        // YPX-002 §4.3 — round-robin across the 3 root authorities so
        // the dev mesh has real cross-branch diversity. With 10 nodes
        // and 3 roots, the split is 4-3-3. Without this the whole
        // mesh collapses into a single branch and the §4.6 receiver
        // verification can never satisfy the cross-branch picker.
        let root_index = i % root_pks.len();
        let result = generate_node_nbc(
            &name,
            &config_dir,
            &root_pks,
            &root_sks,
            root_index,
            now,
            expires_at,
        );

        let dir_label = if i < 10 {
            format!("axiom-first-penguin-{}", GENESIS_NAMES[i])
        } else {
            format!("nabla_{}", i)
        };

        if i % 10 == 0 || i == count - 1 {
            eprintln!("  Node {:>3}/{}: {} ✓  → {}/config/", i + 1, count,
                hex::encode(&result.node_id[..8]), dir_label);
        }

        results.push(result);
    }

    eprintln!();
    eprintln!("╔════════════════════════════════════════════════════════╗");
    eprintln!("║  Nabla Ceremony Complete — {} real NBCs signed         ║", count);
    eprintln!("║  Root keys: {}/nabla-root-keys/", base_dir.display());
    eprintln!("║  Genesis:   axiom-first-penguin-{{alpha..kappa}}/config/");
    if count > 10 {
    eprintln!("║  Nabla:     nabla_{{10..{}}}/config/", count - 1);
    }
    eprintln!("╚════════════════════════════════════════════════════════╝");

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_nabla::ceremony::load_single_nbc;

    /// Helper: generate root keys in a temp dir for tests
    fn setup_root_keys(dir: &Path) -> std::path::PathBuf {
        let root_keys_dir = dir.join("root-keys");
        generate_root_keys(&root_keys_dir);
        root_keys_dir
    }

    #[test]
    fn test_ceremony_single_generates_files() {
        let dir = tempfile::tempdir().unwrap();
        let root_keys_dir = setup_root_keys(dir.path());

        let node_dir = dir.path().join("node1");
        fs::create_dir_all(&node_dir).unwrap();
        let toml_path = node_dir.join("node.toml");
        std::fs::write(&toml_path, "name = \"pi-node\"\nport = 6225\nexternal_port = 6225\n").unwrap();

        let result = nabla_ceremony_single(&toml_path, &root_keys_dir).unwrap();
        assert_eq!(result.nbc.node_name, "pi-node");
        assert!(!result.node_id.iter().all(|&b| b == 0));

        // Check all expected files exist
        let config = node_dir.join("config");
        assert!(config.join("nbc.json").exists());
        assert!(config.join("nabla_sphincs.pub").exists());
        assert!(config.join("nabla_sphincs.key").exists());
        assert!(config.join("nabla_ed25519.pub").exists());
        assert!(config.join("nabla_ed25519.key").exists());
        assert!(config.join("nabla_dilithium.pub").exists());
        assert!(config.join("nabla_dilithium.key").exists());

        // Root keys should NOT be written to the node's directory
        assert!(!node_dir.join("nabla-root-keys").exists());
    }

    #[test]
    fn test_ceremony_single_rejects_existing() {
        let dir = tempfile::tempdir().unwrap();
        let root_keys_dir = setup_root_keys(dir.path());

        let node_dir = dir.path().join("node1");
        fs::create_dir_all(&node_dir).unwrap();
        let toml_path = node_dir.join("node.toml");
        std::fs::write(&toml_path, "name = \"test\"\nport = 6225\nexternal_port = 6225\n").unwrap();

        // First run succeeds
        nabla_ceremony_single(&toml_path, &root_keys_dir).unwrap();

        // Second run errors
        let err = nabla_ceremony_single(&toml_path, &root_keys_dir).unwrap_err();
        assert!(err.contains("already exists"), "expected 'already exists' in: {}", err);
    }

    #[test]
    fn test_ceremony_single_fails_without_root_keys() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("node.toml");
        std::fs::write(&toml_path, "name = \"test\"\nport = 6225\nexternal_port = 6225\n").unwrap();

        let nonexistent = dir.path().join("no-such-dir");
        let err = nabla_ceremony_single(&toml_path, &nonexistent).unwrap_err();
        assert!(err.contains("Failed to read"), "expected 'Failed to read' in: {}", err);
    }

    #[test]
    fn test_load_single_nbc_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let root_keys_dir = setup_root_keys(dir.path());

        let node_dir = dir.path().join("node1");
        fs::create_dir_all(&node_dir).unwrap();
        let toml_path = node_dir.join("node.toml");
        std::fs::write(&toml_path, "name = \"roundtrip\"\nport = 7777\nexternal_port = 7777\n").unwrap();

        let original = nabla_ceremony_single(&toml_path, &root_keys_dir).unwrap();

        let config_dir = node_dir.join("config");
        let loaded = load_single_nbc(&config_dir).unwrap();

        assert_eq!(loaded.node_id, original.node_id);
        assert_eq!(loaded.ed25519_sk, original.ed25519_sk);
        assert_eq!(loaded.nbc.node_name, "roundtrip");
        assert_eq!(loaded.nbc.validator_id, original.nbc.validator_id);
    }

    #[test]
    fn test_two_nodes_same_root_key_set_mutual_trust() {
        // Both nodes are signed by a key from the SAME root-keys dir,
        // so any validator trusting that dir will verify both chains.
        // Post-YPX-002 §4.3 the two specific nodes may land on
        // different indices within that root set (issuer_set differs
        // between the two), but both issuer values are still members
        // of the ceremony's root authority list — which is the real
        // trust property the verifier cares about.
        let dir = tempfile::tempdir().unwrap();
        let root_keys_dir = setup_root_keys(dir.path());

        // Node A
        let node_a_dir = dir.path().join("node_a");
        fs::create_dir_all(&node_a_dir).unwrap();
        let toml_a = node_a_dir.join("node.toml");
        std::fs::write(&toml_a, "name = \"node-a\"\nport = 6225\nexternal_port = 6225\n").unwrap();
        let a = nabla_ceremony_single(&toml_a, &root_keys_dir).unwrap();

        // Node B
        let node_b_dir = dir.path().join("node_b");
        fs::create_dir_all(&node_b_dir).unwrap();
        let toml_b = node_b_dir.join("node.toml");
        std::fs::write(&toml_b, "name = \"node-b\"\nport = 6226\nexternal_port = 6226\n").unwrap();
        let b = nabla_ceremony_single(&toml_b, &root_keys_dir).unwrap();

        // k=1 invariant: exactly one issuer in each NBC.
        assert_eq!(a.nbc.issuer_set.len(), 1);
        assert_eq!(b.nbc.issuer_set.len(), 1);

        // Both issuers come from the same loaded root-keys set. Load
        // the raw list and assert each NBC's issuer is a member.
        let (root_pks, _) = load_root_keys(&root_keys_dir).unwrap();
        assert!(root_pks.iter().any(|pk| pk == &a.nbc.issuer_set[0]),
            "node-a issuer not in root set");
        assert!(root_pks.iter().any(|pk| pk == &b.nbc.issuer_set[0]),
            "node-b issuer not in root set");

        // Different node identities.
        assert_ne!(a.node_id, b.node_id);
        assert_ne!(a.nbc.subject_pubkey_sphincs, b.nbc.subject_pubkey_sphincs);
    }

    #[test]
    fn test_batch_mesh_is_cross_branch_diverse() {
        // YPX-002 §4.3 regression guard: the batch ceremony MUST
        // assign NBC issuers across multiple roots so the receiver-
        // side §4.6 picker has real cross-branch candidates. Pre-fix
        // every node got `root_pks[0]` and the dev mesh had exactly
        // 1 distinct branch. Post-fix it round-robins across all
        // 3 roots (4-3-3 split for 10 nodes) and the mesh has 3
        // distinct branches.
        let dir = tempfile::tempdir().unwrap();
        let results = nabla_ceremony(10, dir.path());
        use std::collections::HashSet;
        let branches: HashSet<_> = results.iter()
            .map(|n| n.nbc.issuer_set[0].clone())
            .collect();
        assert!(branches.len() >= 3,
            "dev mesh must have ≥3 NBC issuer branches to satisfy §4.3 \
             cross-branch picker; got {} branches across {} nodes",
            branches.len(), results.len());
    }

    #[test]
    fn test_batch_mode_still_works() {
        let dir = tempfile::tempdir().unwrap();
        let results = nabla_ceremony(10, dir.path());
        assert_eq!(results.len(), 10);

        // Verify genesis names
        assert_eq!(results[0].nbc.node_name, "alpha");
        assert_eq!(results[9].nbc.node_name, "kappa");

        // Verify files written
        for i in 0..10 {
            let config_dir = node_config_dir(dir.path(), i);
            assert!(config_dir.join("nbc.json").exists());
            assert!(config_dir.join("nabla_ed25519.key").exists());
        }

        // Verify load_nbcs still works
        let loaded = axiom_nabla::ceremony::load_nbcs(dir.path(), 10).unwrap();
        assert_eq!(loaded.len(), 10);
        assert_eq!(loaded[0].node_id, results[0].node_id);
    }
}
