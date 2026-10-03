//! ONE definition of what a Nabla node persists under its data directory (KI#182).
//!
//! Why this exists (2026-09-25). Two hand-written wipe lists — `_clean_data` in
//! `scripts/axiom-env.py` and the two `WIPE_DATA=1` blocks in `deploy/deploy-node.sh`
//! — each named the files a WIPE rotation must remove, and each had drifted from
//! what the node actually writes: `vbc_registrations.cbor`, `fob_*.cbor`,
//! `emission.state`, `garbage_chain.state` and the two emission pools survived a
//! "fresh genesis" on every remote node. A survivor from the previous genesis is
//! exactly the un-verifiable state the wipe exists to prevent (RULE 1: a second
//! copy of a rule is a bug with a delay fuse).
//!
//! The rule now lives HERE, in the crate that writes the files:
//! - [`PERSISTED_STATE_DIRS`] / [`PERSISTED_STATE_FILES`] are the consensus /
//!   retention set: everything a wipe must remove and a retain-rotation must keep.
//! - [`CONFIG_NOT_STATE`] are the operator's files under the same directory that a
//!   wipe must NEVER touch.
//! - `nabla/persisted_state.txt` is the same list as a text manifest for the
//!   scripts (Python and bash cannot link this crate); the test
//!   `persisted_state_manifest_matches_the_source` fails the build the moment the
//!   two differ, and `every_data_dir_write_is_in_the_manifest` fails it the moment
//!   a new `data_dir.join("…")` literal or pool filename appears in the source
//!   without being listed. Add a persisted file → add it to BOTH constants below
//!   and to the manifest, in that order, and the tests tell you if you missed one.

/// Directories under the data dir that hold consensus / retention state.
/// `smt` and `wal` are legacy names no current code writes (the WAL is the file
/// `nabla.wal`, the SMT lives in `snapshots/`); they stay in the wipe set so a
/// node upgraded in place from an older build is cleaned exactly as before.
pub const PERSISTED_STATE_DIRS: &[&str] = &["smt", "wal", "snapshots", "consumed_exact"];

/// Files under the data dir that hold consensus / retention state.
pub const PERSISTED_STATE_FILES: &[&str] = &[
    "nabla.wal",
    // pools — `PoolKind::state_filename()`
    "airdrop_pool.state",
    "dev_treasury_pool.state",
    "deed_pool.state",
    "dev_deed_pool.state",
    "bootstrap_pool.state",
    "foundation_bootstrap_pool.state",
    "emission_validators_pool.state",
    "emission_nabla_pool.state",
    // emission lattice — `PersistedEmissionState::FILENAME`
    "emission.state",
    // FOB (§10.0) + validator certificates + fee ledgers
    "fob_pools.cbor",
    "fob_claims.cbor",
    "fob_tranches.cbor",
    "vbc_registrations.cbor",
    "validator_net_ledger.cbor",
    "validator_dev_net_ledger.cbor",
    // ForkSettlement §9r (F-6 path 11) — redeem fee credits parked until clean
    "held_fee_credits.cbor",
    // YPX-020 §2 garbage-state chain
    "garbage_chain.state",
];

/// Operator configuration under the same directory — a wipe must never touch these.
pub const CONFIG_NOT_STATE: &[&str] = &["node.toml", "bootstrap.toml", "config", "backups"];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const MANIFEST: &str = include_str!("../persisted_state.txt");

    fn manifest_sets() -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
        let (mut dirs, mut files, mut config) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        for line in MANIFEST.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(d) = line.strip_prefix("dir ") {
                dirs.insert(d.trim().to_string());
            } else if let Some(f) = line.strip_prefix("file ") {
                files.insert(f.trim().to_string());
            } else if let Some(c) = line.strip_prefix("config ") {
                config.insert(c.trim().to_string());
            } else {
                panic!("persisted_state.txt: unknown line {line:?} (expect `dir `, `file ` or `config `)");
            }
        }
        (dirs, files, config)
    }

    /// The text manifest the scripts read is byte-for-byte the same rule as the
    /// constants the node compiles. Mutation: add a file to one side only → red.
    #[test]
    fn persisted_state_manifest_matches_the_source() {
        let (dirs, files, config) = manifest_sets();
        let cd: BTreeSet<String> = PERSISTED_STATE_DIRS.iter().map(|s| s.to_string()).collect();
        let cf: BTreeSet<String> = PERSISTED_STATE_FILES.iter().map(|s| s.to_string()).collect();
        let cc: BTreeSet<String> = CONFIG_NOT_STATE.iter().map(|s| s.to_string()).collect();
        assert_eq!(dirs, cd, "persisted_state.txt `dir` lines != PERSISTED_STATE_DIRS");
        assert_eq!(files, cf, "persisted_state.txt `file` lines != PERSISTED_STATE_FILES");
        assert_eq!(config, cc, "persisted_state.txt `config` lines != CONFIG_NOT_STATE");
    }

    /// Every `data_dir.join("<literal>")` in the sources that write state, every
    /// `PoolKind::state_filename()` value and the emission filename is listed —
    /// so a new persisted file cannot appear without the wipe learning about it.
    #[test]
    fn every_data_dir_write_is_in_the_manifest() {
        let sources: &[(&str, &str)] = &[
            ("node.rs", include_str!("node.rs")),
            ("bin/nabla_node.rs", include_str!("bin/nabla_node.rs")),
        ];
        let listed: BTreeSet<&str> = PERSISTED_STATE_DIRS
            .iter()
            .chain(PERSISTED_STATE_FILES.iter())
            .chain(CONFIG_NOT_STATE.iter())
            .copied()
            .collect();
        let mut missing = Vec::new();
        for (name, src) in sources {
            for (i, line) in src.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                let mut rest = line;
                while let Some(p) = rest.find("data_dir.join(\"") {
                    let after = &rest[p + "data_dir.join(\"".len()..];
                    if let Some(q) = after.find('"') {
                        let lit = &after[..q];
                        if !listed.contains(lit) {
                            missing.push(format!("{name}:{}: {lit}", i + 1));
                        }
                        rest = &after[q..];
                    } else {
                        break;
                    }
                }
            }
        }
        for kind in [
            crate::types::PoolKind::Airdrop,
            crate::types::PoolKind::DevTreasury,
            crate::types::PoolKind::Deed,
            crate::types::PoolKind::DevDeed,
            crate::types::PoolKind::Bootstrap,
            crate::types::PoolKind::FoundationBootstrap,
            crate::types::PoolKind::EmissionValidators,
            crate::types::PoolKind::EmissionNabla,
        ] {
            let f = kind.state_filename();
            if !PERSISTED_STATE_FILES.contains(&f) {
                missing.push(format!("PoolKind::state_filename → {f}"));
            }
        }
        if !PERSISTED_STATE_FILES.contains(&crate::emission::PersistedEmissionState::FILENAME) {
            missing.push("PersistedEmissionState::FILENAME".to_string());
        }
        assert!(missing.is_empty(), "persisted paths written by the node but NOT in the wipe manifest: {missing:?}");
    }
}
