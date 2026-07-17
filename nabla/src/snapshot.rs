// AXIOM Nabla — Snapshot (periodic full tree serialization)
// Reference: AXIOM_GUIDE_Nabla.md Section 2.5
//
// Phase 1 Task 4: Snapshot and restore
//
// Snapshot contains the complete SMT state serialized to disk.
// Recovery: load last snapshot → replay WAL entries after snapshot tick.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cc::{CompanionCertificate, NBC};
use crate::types::{BannedEntry, Hash256, NablaEntry, NablaError, TxHash, TxRecord};
#[cfg(test)]
use crate::types::WalletStatus;

/// Serializable snapshot of the complete Nabla state.
#[derive(Debug, Serialize, Deserialize)]
pub struct NablaSnapshot {
    /// Tick at which this snapshot was taken.
    pub tick: u64,
    /// Root hash at snapshot time (for verification).
    pub root_hash: Hash256,
    /// All wallet entries.
    pub entries: Vec<NablaEntry>,
    /// All banned wallets.
    pub bans: Vec<BannedEntry>,
    /// DEED atoms collected.
    pub deed_collected: u64,
    /// Latest Companion Certificate (for CC chain persistence across restarts).
    #[serde(default)]
    pub latest_cc: Option<CompanionCertificate>,
    /// YPX-009 §12: WAL checksums at snapshot time for fast audit recovery.
    #[serde(default)]
    pub wal_checksums: Vec<(u64, [u8; 32])>,
    /// YPX-011: Genesis FACT #0 payload (permanent, never compressed).
    /// Stored as serialized GenesisFact bytes. Absent = pre-genesis node.
    #[serde(default)]
    pub genesis_fact_payload: Option<Vec<u8>>,
    /// YP §19.6 fee ledger — per-tx records (hashmap mode only).
    /// Bloom-mode snapshots leave this empty. `validator_earnings` is NOT
    /// snapshotted directly — it's a derived index rebuilt from these
    /// records on boot (one source of truth).
    #[serde(default)]
    pub tx_records: Vec<(TxHash, TxRecord)>,
    /// KI#32: verified peer NBCs at snapshot time. A restarting node restores
    /// these (re-validating `expires_at` on load) so it comes back with a WARM
    /// NBC cache instead of dropping PoolSync from each peer for ~15 min while
    /// Hello re-exchange repopulates `verified_nbcs`. Without this the soft
    /// path is load-bearing on every restart (see KnownIssues #32 +
    /// nabla_node.rs:~1825 decision record).
    #[serde(default)]
    pub peer_nbcs: Vec<NBC>,
    /// YPX-022 §5 — the three exact txid terminals (`live → {Redeemed |
    /// Recalled} → consumed`, plus the monotonic completion ledger the recall
    /// window reads). A restart must never forget a recall: these are the
    /// archive layer a garbage-chain bloom Hit resolves through.
    #[serde(default)]
    pub completed_txids: Vec<(TxHash, u64)>,
    #[serde(default)]
    pub redeemed_txids: Vec<TxHash>,
    #[serde(default)]
    pub recalled_txids: Vec<(TxHash, crate::smt::RecallMarker)>,
    /// KI#38 — retained k=3 seq attestations (parallel to `entries`).
    /// Pre-fix these were in-memory only: a restart wiped every retained
    /// proof, so the node could no longer attest ANY held head over
    /// anti-entropy (`seq-unattested proof=ABSENT`), and a whole-mesh
    /// restart re-stranded every head at once.
    #[serde(default)]
    pub seq_proofs: Vec<(crate::types::WalletId, crate::types::SeqProof)>,
}

/// Manages snapshot files on disk.
pub struct SnapshotManager {
    dir: PathBuf,
}

impl SnapshotManager {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, NablaError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)
            .map_err(|e| NablaError::SnapshotError(format!("create dir: {e}")))?;
        Ok(Self { dir })
    }

    /// Write a snapshot to disk.
    /// Filename: snapshot_{tick}.bin
    pub fn write(&self, snapshot: &NablaSnapshot) -> Result<PathBuf, NablaError> {
        let filename = format!("snapshot_{}.bin", snapshot.tick);
        let path = self.dir.join(&filename);
        let tmp_path = self.dir.join(format!("{filename}.tmp"));

        let bytes = bincode::serialize(snapshot)
            .map_err(|e| NablaError::SnapshotError(format!("serialize: {e}")))?;

        // Write to temp file first, then rename (atomic on most filesystems)
        {
            let mut file = File::create(&tmp_path)
                .map_err(|e| NablaError::SnapshotError(format!("create tmp: {e}")))?;
            file.write_all(&bytes)
                .map_err(|e| NablaError::SnapshotError(format!("write: {e}")))?;
            file.flush()
                .map_err(|e| NablaError::SnapshotError(format!("flush: {e}")))?;
        }

        fs::rename(&tmp_path, &path)
            .map_err(|e| NablaError::SnapshotError(format!("rename: {e}")))?;

        log::info!(
            "Snapshot written: tick={}, entries={}, bans={}, size={} bytes",
            snapshot.tick,
            snapshot.entries.len(),
            snapshot.bans.len(),
            bytes.len()
        );

        Ok(path)
    }

    /// Load the most recent snapshot from disk.
    pub fn load_latest(&self) -> Result<Option<NablaSnapshot>, NablaError> {
        let mut snapshots: Vec<(u64, PathBuf)> = Vec::new();

        let entries = fs::read_dir(&self.dir)
            .map_err(|e| NablaError::SnapshotError(format!("read dir: {e}")))?;

        for entry in entries {
            let entry =
                entry.map_err(|e| NablaError::SnapshotError(format!("dir entry: {e}")))?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.starts_with("snapshot_") && name_str.ends_with(".bin") {
                // Parse tick from filename
                if let Some(tick_str) = name_str
                    .strip_prefix("snapshot_")
                    .and_then(|s| s.strip_suffix(".bin"))
                {
                    if let Ok(tick) = tick_str.parse::<u64>() {
                        snapshots.push((tick, entry.path()));
                    }
                }
            }
        }

        // Sort by tick descending (newest first).
        snapshots.sort_by(|a, b| b.0.cmp(&a.0));

        // Load the newest snapshot that DESERIALIZES; skip any that don't. A
        // snapshot-schema change (e.g. KI#32 adding `peer_nbcs`) makes older
        // files unloadable — bincode is positional, so the trailing field hits
        // EOF. Skipping to an older compatible snapshot, or falling back to
        // Ok(None) (→ WAL replay / fresh + anti-entropy re-sync), is the
        // documented "clean restart on schema bump" path. We must NEVER return
        // Err here: `NablaNode::open` unwraps it into a panic, which would brick
        // every node on a format upgrade.
        for (tick, path) in &snapshots {
            match self.load_from(path) {
                Ok(snapshot) => {
                    log::info!("Loading snapshot: tick={}, path={}", tick, path.display());
                    return Ok(Some(snapshot));
                }
                Err(e) => {
                    log::warn!(
                        "Skipping unloadable snapshot tick={} ({}): {} — \
                         likely a format change; falling back to WAL/clean",
                        tick, path.display(), e,
                    );
                }
            }
        }
        Ok(None)
    }

    /// Load a specific snapshot file.
    pub fn load_from(&self, path: &Path) -> Result<NablaSnapshot, NablaError> {
        let mut file = File::open(path)
            .map_err(|e| NablaError::SnapshotError(format!("open: {e}")))?;

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| NablaError::SnapshotError(format!("read: {e}")))?;

        let snapshot: NablaSnapshot = bincode::deserialize(&bytes)
            .map_err(|e| NablaError::SnapshotError(format!("deserialize: {e}")))?;

        log::info!(
            "Snapshot loaded: tick={}, entries={}, bans={}",
            snapshot.tick,
            snapshot.entries.len(),
            snapshot.bans.len()
        );

        Ok(snapshot)
    }

    /// List all snapshot files sorted by tick (ascending).
    fn list_snapshots(&self) -> Result<Vec<PathBuf>, NablaError> {
        let mut snapshots: Vec<(u64, PathBuf)> = Vec::new();
        let entries = fs::read_dir(&self.dir)
            .map_err(|e| NablaError::SnapshotError(format!("list read dir: {e}")))?;
        for entry in entries {
            let entry =
                entry.map_err(|e| NablaError::SnapshotError(format!("list dir entry: {e}")))?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("snapshot_") && name_str.ends_with(".bin") {
                if let Some(tick_str) = name_str
                    .strip_prefix("snapshot_")
                    .and_then(|s| s.strip_suffix(".bin"))
                {
                    if let Ok(tick) = tick_str.parse::<u64>() {
                        snapshots.push((tick, entry.path()));
                    }
                }
            }
        }
        snapshots.sort_by_key(|(t, _)| *t);
        Ok(snapshots.into_iter().map(|(_, p)| p).collect())
    }

    /// Number of snapshot files on disk.
    pub fn snapshot_count(&self) -> usize {
        self.list_snapshots().map(|v| v.len()).unwrap_or(0)
    }

    /// Size of latest snapshot file in bytes.
    pub fn latest_size_bytes(&self) -> u64 {
        self.list_snapshots()
            .ok()
            .and_then(|v| v.last().cloned())
            .and_then(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Total size of all snapshot files in bytes.
    pub fn total_size_bytes(&self) -> u64 {
        self.list_snapshots()
            .unwrap_or_default()
            .iter()
            .filter_map(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .sum()
    }

    /// Remove old snapshots, keeping only the N most recent.
    pub fn prune(&self, keep: usize) -> Result<(), NablaError> {
        let mut snapshots: Vec<(u64, PathBuf)> = Vec::new();

        let entries = fs::read_dir(&self.dir)
            .map_err(|e| NablaError::SnapshotError(format!("prune read dir: {e}")))?;

        for entry in entries {
            let entry =
                entry.map_err(|e| NablaError::SnapshotError(format!("prune dir entry: {e}")))?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.starts_with("snapshot_") && name_str.ends_with(".bin") {
                if let Some(tick_str) = name_str
                    .strip_prefix("snapshot_")
                    .and_then(|s| s.strip_suffix(".bin"))
                {
                    if let Ok(tick) = tick_str.parse::<u64>() {
                        snapshots.push((tick, entry.path()));
                    }
                }
            }
        }

        snapshots.sort_by(|a, b| b.0.cmp(&a.0));

        // Remove all but the most recent `keep` snapshots
        for (_, path) in snapshots.iter().skip(keep) {
            if let Err(e) = fs::remove_file(path) {
                log::warn!("Failed to prune snapshot {}: {e}", path.display());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_write_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();

        let entry = NablaEntry {
                        wallet_seq: 0,
            wallet_id: [0xAA; 32],
            current_state: [0xBB; 32],
            tx_hash: [0xCC; 32],
            tick: 100,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        };

        let snap = NablaSnapshot {
            tick: 100,
            root_hash: [0xDD; 32],
            entries: vec![entry.clone()],
            bans: vec![],
            deed_collected: 50,
            latest_cc: None,
            wal_checksums: vec![],
            genesis_fact_payload: None,
            tx_records: vec![],
            peer_nbcs: vec![],
            completed_txids: vec![],
            redeemed_txids: vec![],
            recalled_txids: vec![],
            seq_proofs: vec![],
        };

        mgr.write(&snap).unwrap();

        let loaded = mgr.load_latest().unwrap().expect("should find snapshot");
        assert_eq!(loaded.tick, 100);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].wallet_id, [0xAA; 32]);
        assert_eq!(loaded.deed_collected, 50);
    }

    #[test]
    fn snapshot_loads_latest() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();

        for tick in [100, 200, 300] {
            let snap = NablaSnapshot {
                tick,
                root_hash: [tick as u8; 32],
                entries: vec![],
                bans: vec![],
                deed_collected: 0,
                latest_cc: None,
                wal_checksums: vec![],
                genesis_fact_payload: None,
            tx_records: vec![],
            peer_nbcs: vec![],
            completed_txids: vec![],
            redeemed_txids: vec![],
            recalled_txids: vec![],
            seq_proofs: vec![],
            };
            mgr.write(&snap).unwrap();
        }

        let loaded = mgr.load_latest().unwrap().expect("should find snapshot");
        assert_eq!(loaded.tick, 300);
    }

    #[test]
    fn snapshot_prune() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();

        for tick in [100, 200, 300, 400, 500] {
            let snap = NablaSnapshot {
                tick,
                root_hash: [0; 32],
                entries: vec![],
                bans: vec![],
                deed_collected: 0,
                latest_cc: None,
                wal_checksums: vec![],
                genesis_fact_payload: None,
            tx_records: vec![],
            peer_nbcs: vec![],
            completed_txids: vec![],
            redeemed_txids: vec![],
            recalled_txids: vec![],
            seq_proofs: vec![],
            };
            mgr.write(&snap).unwrap();
        }

        mgr.prune(2).unwrap();

        // Only 2 most recent should remain
        let files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("snapshot_")
            })
            .collect();
        assert_eq!(files.len(), 2);
    }

    /// YP §19.6 — snapshot persists tx_records and they round-trip
    /// byte-identically. Closes the persistence-tier rule AXIOM Origin
    /// emphasised: hashmap = authoritative, WAL = fast access. The
    /// snapshot is part of the hashmap-authoritative tier.
    #[test]
    fn snapshot_round_trips_tx_records() {
        use axiom_core_logic::types::FeeShare;

        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();

        let rec = TxRecord {
            receiver_wallet_id: [0xAA; 32],
            amount: 1_000_000,
            fee_breakdown: vec![
                FeeShare { validator_id: [0x11; 32], amount: 1500 },
                FeeShare { validator_id: [0x22; 32], amount: 1500 },
            ],
            tick: 42,
        };
        let mut tx_records: Vec<(TxHash, TxRecord)> = Vec::new();
        tx_records.push(([0x01; 32], rec.clone()));
        tx_records.push(([0x02; 32], rec.clone()));

        let snap = NablaSnapshot {
            tick: 100,
            root_hash: [0xDD; 32],
            entries: vec![],
            bans: vec![],
            deed_collected: 0,
            latest_cc: None,
            wal_checksums: vec![],
            genesis_fact_payload: None,
            tx_records: tx_records.clone(),
            peer_nbcs: vec![],
            completed_txids: vec![],
            redeemed_txids: vec![],
            recalled_txids: vec![],
            seq_proofs: vec![],
        };
        mgr.write(&snap).unwrap();
        let loaded = mgr.load_latest().unwrap().expect("snapshot present");
        assert_eq!(loaded.tx_records.len(), 2);
        // Records may be reordered (HashMap iteration is undefined) — sort
        // both sides by tx_hash before comparing.
        let mut got = loaded.tx_records.clone();
        got.sort_by_key(|(h, _)| *h);
        let mut want = tx_records;
        want.sort_by_key(|(h, _)| *h);
        assert_eq!(got, want);
    }

    // Note on schema evolution: per CLAUDE.md §13 (no backward-compat
    // pre-mainnet), bincode does not honor `#[serde(default)]` for
    // trailing fields. Adding `tx_records` to NablaSnapshot breaks
    // pre-Step-3 snapshot files on disk — operators restart from a
    // clean state (replay from WAL) when struct shapes change. Post-
    // mainnet, this needs a versioned snapshot format with explicit
    // migration; today the cost is one clean restart per operator per
    // schema bump, paid at upgrade time and tracked by the release notes.

    #[test]
    fn snapshot_roundtrips_peer_nbcs() {
        // KI#32: peer NBCs must survive a snapshot write/load so a restarting
        // node warms verified_nbcs instead of dropping PoolSync for ~15 min
        // during Hello re-exchange. Fails without the peer_nbcs field.
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();
        let nbc = crate::cc::sim_nbc([0x11; 32], 1000);
        let snap = NablaSnapshot {
            tick: 7,
            root_hash: [0; 32],
            entries: vec![],
            bans: vec![],
            deed_collected: 0,
            latest_cc: None,
            wal_checksums: vec![],
            genesis_fact_payload: None,
            tx_records: vec![],
            peer_nbcs: vec![nbc.clone()],
            completed_txids: vec![],
            redeemed_txids: vec![],
            recalled_txids: vec![],
            seq_proofs: vec![],
        };
        mgr.write(&snap).unwrap();
        let loaded = mgr.load_latest().unwrap().expect("snapshot present");
        assert_eq!(loaded.peer_nbcs.len(), 1);
        assert_eq!(loaded.peer_nbcs[0].validator_id, [0x11; 32]);
        assert_eq!(loaded.peer_nbcs[0].expires_at, nbc.expires_at);
    }

    #[test]
    fn load_latest_skips_undeserializable_snapshot() {
        // A snapshot-format change (e.g. KI#32 peer_nbcs) makes old files
        // unloadable. load_latest must SKIP them and return Ok(None) (→ WAL /
        // clean), NEVER Err — `NablaNode::open` unwraps Err into a panic, which
        // would brick every node on a format upgrade. Fails without the tolerant
        // load loop.
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();
        std::fs::write(dir.path().join("snapshot_99.bin"), b"not valid bincode").unwrap();
        let loaded = mgr.load_latest().expect("must be Ok, not Err");
        assert!(loaded.is_none(), "unloadable snapshot must be skipped → Ok(None)");
    }
}
