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
    /// YPX-022 §2.1.2a (KI#205) — the authenticated cheque claims (the
    /// delivery terminal `register_recall` reads). A restart must not forget a
    /// delivery, or the sender's recall would be granted after the receiver
    /// had the cheque. No `serde(default)` (§13): a snapshot without it is a
    /// decode error, not an empty table.
    pub cheque_claims: Vec<(TxHash, crate::smt::ChequeClaim)>,
    /// GUIDE §5.6c "Persistence" (KI#75) — JUDOON's live quarantine set
    /// (accused → expiry tick VALUE) and its re-activation cooldowns. Until
    /// this field a restart silently lifted every quarantine and re-admitted
    /// the peer. Restored by `QuarantineState::restore_entries` (expired
    /// entries dropped on load) and re-armed into the mesh filter by
    /// `init_mesh*`. LAST — bincode is positional. No `serde(default)`.
    pub quarantine_active: Vec<(crate::types::NodeId, u64)>,
    pub quarantine_cooldown: Vec<(crate::types::NodeId, u64)>,
    /// YPX-002 §9.1.1a (RULED 2026-09-25) — the NBC issuer's per-epoch signing
    /// budget, so a restart cannot reset the cap. LAST — bincode is positional.
    /// No `serde(default)` (§13): a snapshot without it is a decode error.
    pub nbc_issuance_budget: crate::cc::NbcIssuanceBudget,
    /// ForkSettlement §2.4 Q5 [R32] — the origin ledger (every verified send
    /// leg this node recorded, with `first_seen_secs` + `contested`
    /// verbatim), sorted by txid. Before wave 3 the registered set was not
    /// snapshotted at all — rebuilt from current heads at load, so historical
    /// txids were forgotten after a restart (and the rebuild itself was the
    /// HIGH-1 hole). Restored through `restore_origin_entry` (verbatim,
    /// R27); the [R28] detector then re-runs over it at load. LAST — bincode
    /// is positional. No `serde(default)` (§13): a snapshot without it is a
    /// decode error (`persisted_shape_prior_snapshot_without_origin_ledger_…`).
    pub origin_ledger: Vec<(TxHash, crate::types::OriginLedgerEntry)>,
    /// Fork Settlement W7b (spec R52c) — the REDEEM ledger (every verified
    /// redeem leg with a non-zero consumed state, `first_seen_secs` +
    /// `contested` verbatim), sorted by id. A SEPARATE field from
    /// `origin_ledger` on purpose (a redeem is never an origin, R5). Restored
    /// through `restore_redeem_entry` (verbatim, R27); the [R28]
    /// detector then re-runs over the shared index at load. LAST — bincode is
    /// positional. No `serde(default)` (§13): a snapshot without it is a
    /// decode error (`persisted_shape_prior_snapshot_without_redeem_ledger_…`).
    pub redeem_ledger: Vec<(crate::smt::RedeemRecordId, crate::types::OriginLedgerEntry)>,
}

/// Snapshot files this process refused to load (undecodable), cumulative.
/// Surfaced on `/status` as `snapshot_decode_refused` (RULE 3 §2 / RULE 6).
///
/// WHY a counter and an ERROR log (ForkSettlement wave 2a, 2026-09-28): the
/// loader below deliberately never returns `Err` (a panic would brick every
/// node on a format bump), and a refused snapshot falls back to WAL replay /
/// clean + anti-entropy. That fallback is correct but it was SILENT — one
/// `warn!` line — and the snapshot is the only home of several facts (the
/// retained seq proofs, cheque claims, quarantine, NBC issuance budget …).
/// A shape change (`SeqProof::preimage`, wave 2a) that drops every node's
/// snapshot must be seen, not inferred: the rotation-#14 hazard
/// ([[feedback_retain_rotation_needs_persisted_shape_check]]).
static SNAPSHOT_DECODE_REFUSED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Read the refused-snapshot counter (see [`SNAPSHOT_DECODE_REFUSED`]).
pub fn snapshot_decode_refused_total() -> u64 {
    SNAPSHOT_DECODE_REFUSED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Decode snapshot bytes STRICTLY: the same fixint little-endian encoding
/// `bincode::serialize` writes, but TRAILING BYTES ARE AN ERROR.
/// `bincode::deserialize` allows trailing bytes, and the snapshot is
/// positional with no version tag — so a prior-shape file whose new field
/// happens to decode from the bytes of the next field could be MIS-READ
/// "successfully" and leave bytes over. Rejecting leftovers turns that
/// silent mis-read into a refusal (ForkSettlement wave 2a).
pub fn decode_snapshot_bytes(bytes: &[u8]) -> Result<NablaSnapshot, NablaError> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| NablaError::SnapshotError(format!("deserialize: {e}")))
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
                    SNAPSHOT_DECODE_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    log::error!(
                        "[SNAPSHOT-REFUSED] tick={} ({}): {} — the file does not decode \
                         under this build's NablaSnapshot shape (a persisted-shape change \
                         such as ForkSettlement wave 2a's SeqProof::preimage, or \
                         corruption). NOT loaded: falling back to an older snapshot, then \
                         WAL replay / clean + anti-entropy. Every fact held ONLY in this \
                         snapshot is gone on this node. Counted: /status \
                         snapshot_decode_refused.",
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

        let snapshot: NablaSnapshot = decode_snapshot_bytes(&bytes)?;

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
                        received_from: None,
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
            cheque_claims: vec![],
            quarantine_active: vec![],
            quarantine_cooldown: vec![],
            nbc_issuance_budget: crate::cc::NbcIssuanceBudget::default(), origin_ledger: vec![], redeem_ledger: vec![],
        };

        mgr.write(&snap).unwrap();

        let loaded = mgr.load_latest().unwrap().expect("should find snapshot");
        assert_eq!(loaded.tick, 100);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].wallet_id, [0xAA; 32]);
        assert_eq!(loaded.deed_collected, 50);
    }

    /// YPX-002 §9.1.1a — the NBC issuer budget survives a snapshot round-trip
    /// (the property "a restart does not reset the cap" rests on this field).
    /// MUTATION: drop `nbc_issuance_budget` from `take_snapshot` / the restore
    /// in `NablaNode::new` → the bin's budget test reads 0 after restart; here,
    /// zeroing the field before `write` goes red.
    #[test]
    fn snapshot_round_trips_nbc_issuance_budget() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();
        let mut b = crate::cc::NbcIssuanceBudget::default();
        for _ in 0..7 { b.record(42); }
        let snap = NablaSnapshot {
            tick: 100, root_hash: [0; 32], entries: vec![], bans: vec![], deed_collected: 0,
            latest_cc: None, wal_checksums: vec![], genesis_fact_payload: None, tx_records: vec![],
            peer_nbcs: vec![], completed_txids: vec![], redeemed_txids: vec![], recalled_txids: vec![],
            seq_proofs: vec![], cheque_claims: vec![], quarantine_active: vec![], quarantine_cooldown: vec![],
            nbc_issuance_budget: b, origin_ledger: vec![], redeem_ledger: vec![],
        };
        mgr.write(&snap).unwrap();
        let loaded = mgr.load_latest().unwrap().expect("snapshot");
        assert_eq!(loaded.nbc_issuance_budget, b, "budget (epoch 42, count 7) survives the round-trip");
        assert!(loaded.nbc_issuance_budget.at_cap(42, 7));
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
            cheque_claims: vec![],
            quarantine_active: vec![],
            quarantine_cooldown: vec![],
            nbc_issuance_budget: crate::cc::NbcIssuanceBudget::default(), origin_ledger: vec![], redeem_ledger: vec![],
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
            cheque_claims: vec![],
            quarantine_active: vec![],
            quarantine_cooldown: vec![],
            nbc_issuance_budget: crate::cc::NbcIssuanceBudget::default(), origin_ledger: vec![], redeem_ledger: vec![],
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
            cheque_claims: vec![],
            quarantine_active: vec![],
            quarantine_cooldown: vec![],
            nbc_issuance_budget: crate::cc::NbcIssuanceBudget::default(), origin_ledger: vec![], redeem_ledger: vec![],
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

    /// GUIDE §5.6c "Persistence" (KI#75) — the JUDOON quarantine set and its
    /// cooldowns survive a snapshot write/load byte-for-byte. Fails if either
    /// field is dropped from the struct or its order moves (bincode is
    /// positional).
    #[test]
    fn snapshot_roundtrips_quarantine_state() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();
        let active = vec![([0x11u8; 32], 5_000u64), ([0x22u8; 32], 6_500u64)];
        let cooldown = vec![([0x11u8; 32], 9_000u64)];
        let snap = NablaSnapshot {
            tick: 100,
            root_hash: [0xDD; 32],
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
            cheque_claims: vec![],
            quarantine_active: active.clone(),
            quarantine_cooldown: cooldown.clone(),
            nbc_issuance_budget: crate::cc::NbcIssuanceBudget::default(), origin_ledger: vec![], redeem_ledger: vec![],
        };
        mgr.write(&snap).unwrap();
        let loaded = mgr.load_latest().unwrap().expect("snapshot present");
        assert_eq!(loaded.quarantine_active, active, "active quarantines must ride the snapshot");
        assert_eq!(loaded.quarantine_cooldown, cooldown, "cooldowns must ride the snapshot");
    }

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
            cheque_claims: vec![],
            quarantine_active: vec![],
            quarantine_cooldown: vec![],
            nbc_issuance_budget: crate::cc::NbcIssuanceBudget::default(), origin_ledger: vec![], redeem_ledger: vec![],
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

    // ── ForkSettlement wave 2a — the persisted-shape check ──────────────────
    //
    // [[feedback_retain_rotation_needs_persisted_shape_check]]: rotation #14
    // crash-looped alpha because a restored type changed shape. Wave 2a changes
    // `snapshot.seq_proofs` (`SeqProof` gains `preimage`, LAST). This test
    // feeds the loader a snapshot in the PRIOR shape and demands it be
    // REFUSED loudly (Err from the strict decoder, `Ok(None)` + counter from
    // `load_latest`) — never mis-read, never a panic.
    //
    // How the prior-shape bytes are made (no git fixture, no mirror struct —
    // RULE 2 / `check_mirror_structs.py`): bincode is POSITIONAL, so a TUPLE of
    // `SeqProof`'s fields as of 9c64f889 (the commit before wave 2a), in that
    // order, encodes byte-identically to the prior struct. `prior_bytes_of`
    // asserts that encoding equals the new proof's bincode minus its trailing
    // `preimage` — proving the splice below yields a genuine prior-shape
    // record — and the new proof's bytes inside a real `NablaSnapshot`
    // encoding are replaced by it.

    fn wave2a_proof(leg: crate::types::LegPreimage) -> crate::types::SeqProof {
        crate::types::SeqProof {
            state_hash: [0x51; 32],
            commitment_hash: [0x52; 32],
            epoch: 7,
            is_dev_class: false,
            oods_flag: None,
            confidence_index: None,
            sender_state: None,
            sigs: vec![crate::types::SeqProofSig {
                validator_pk: [0x53; 32],
                receipt_commitment_sig: vec![0x54; 64],
            }],
            required_k: 3,
            preimage: leg,
            declared: crate::types::test_legs::no_declared(),
        }
    }

    fn prior_bytes_of(p: &crate::types::SeqProof) -> Vec<u8> {
        // FROZEN field order of the pre-wave-2a `SeqProof`: state_hash,
        // commitment_hash, epoch, is_dev_class, oods_flag, confidence_index,
        // sender_state, sigs, required_k. Do not "update" it — it IS the old shape.
        bincode::serialize(&(
            p.state_hash,
            p.commitment_hash,
            p.epoch,
            p.is_dev_class,
            p.oods_flag,
            p.confidence_index.clone(),
            p.sender_state,
            p.sigs.clone(),
            p.required_k,
        ))
        .unwrap()
    }

    fn snapshot_with(seq_proofs: Vec<([u8; 32], crate::types::SeqProof)>) -> NablaSnapshot {
        NablaSnapshot {
            tick: 1_790_000_000, root_hash: [0x0D; 32], entries: vec![], bans: vec![],
            deed_collected: 9, latest_cc: None, wal_checksums: vec![], genesis_fact_payload: None,
            tx_records: vec![], peer_nbcs: vec![], completed_txids: vec![], redeemed_txids: vec![],
            recalled_txids: vec![], seq_proofs, cheque_claims: vec![], quarantine_active: vec![],
            quarantine_cooldown: vec![], nbc_issuance_budget: crate::cc::NbcIssuanceBudget::default(), origin_ledger: vec![], redeem_ledger: vec![],
        }
    }

    /// Replace every new-shape proof encoding inside `bytes` by its prior shape.
    fn splice_to_prior(mut bytes: Vec<u8>, proofs: &[crate::types::SeqProof]) -> Vec<u8> {
        for p in proofs {
            let new_b = bincode::serialize(p).unwrap();
            let old_b = prior_bytes_of(p);
            assert_eq!(&new_b[..old_b.len()], &old_b[..],
                "the prior shape must be the new shape minus the trailing preimage — \
                 otherwise this fixture is not the old format");
            let at = bytes.windows(new_b.len()).position(|w| w == &new_b[..])
                .expect("proof encoding present in the snapshot");
            bytes.splice(at..at + new_b.len(), old_b);
        }
        bytes
    }

    /// RULE 6 — the instrument must fail on the hazard it exists for.
    /// MUTATION (run 2026-09-28): delete the `SNAPSHOT_DECODE_REFUSED` bump in
    /// `load_latest` → THIS test goes red (the refusal is silent again). For
    /// THIS fixture a lenient decoder also errors (it runs out of bytes), so
    /// the lenient/strict distinction is pinned by
    /// `snapshot_decoder_rejects_trailing_bytes` instead (mutation
    /// `.allow_trailing_bytes()` → that test red, this one green — measured).
    #[test]
    fn persisted_shape_prior_seq_proofs_snapshot_is_refused_loudly() {
        let send_leg = crate::types::LegPreimage::Send(axiom_core_logic::types::WitnessPreimage {
            consumed_state_id: [0x61; 32],
            client_pk: [0x62; 32],
            wallet_seq: 4,
            receiver_wallet_id: "bob@axiom.internal/0123456789".into(),
            amount: 1_000,
            nonce: 77,
        });
        let proofs = vec![
            wave2a_proof(send_leg),
            wave2a_proof(crate::types::test_legs::opaque_redeem_leg()),
        ];
        let snap = snapshot_with(vec![([0xA1; 32], proofs[0].clone()), ([0xA2; 32], proofs[1].clone())]);
        let new_bytes = bincode::serialize(&snap).unwrap();

        // Control: the CURRENT shape decodes under the strict decoder and keeps the legs.
        let back = decode_snapshot_bytes(&new_bytes).expect("current shape decodes");
        assert_eq!(back.seq_proofs.len(), 2);
        assert_eq!(back.seq_proofs[0].1, proofs[0], "Send leg survives the snapshot");
        assert_eq!(back.seq_proofs[1].1, proofs[1], "Redeem leg survives the snapshot");

        // The PRIOR shape is refused by the decoder …
        let prior = splice_to_prior(new_bytes, &proofs);
        assert!(decode_snapshot_bytes(&prior).is_err(),
            "a pre-wave-2a snapshot must NOT decode as the new shape");

        // … and by the loader: Ok(None) (clean fallback, never a panic), COUNTED.
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();
        std::fs::write(dir.path().join("snapshot_1790000000.bin"), &prior).unwrap();
        let before = snapshot_decode_refused_total();
        let loaded = mgr.load_latest().expect("never Err — NablaNode::open would panic");
        assert!(loaded.is_none(), "the prior-shape snapshot is refused, not loaded");
        assert!(snapshot_decode_refused_total() > before,
            "the refusal is COUNTED (/status snapshot_decode_refused) — not a silent skip");
    }

    /// The strict decoder rejects leftover bytes — the silent-mis-read guard.
    /// MUTATION: `.allow_trailing_bytes()` in `decode_snapshot_bytes` → red.
    #[test]
    fn snapshot_decoder_rejects_trailing_bytes() {
        let mut b = bincode::serialize(&snapshot_with(vec![])).unwrap();
        assert!(decode_snapshot_bytes(&b).is_ok());
        b.extend_from_slice(&[0u8; 4]);
        assert!(decode_snapshot_bytes(&b).is_err(),
            "bytes left over after a full decode mean the file is not this shape");
    }

    // ── ForkSettlement wave 3 S4 — origin ledger + BanEvidence persisted shape ──

    fn genuine_origin_entry(seed: u8, first_seen_secs: u64, contested: bool)
        -> (crate::types::TxHash, crate::types::OriginLedgerEntry)
    {
        let leg = crate::types::test_legs::genuine_send_leg(
            &crate::types::test_legs::wallet(seed), [0x01; 32], 5,
            "p@axiom.internal/0123456789", 400, seed as u64, 3,
        );
        (leg.tx_hash, crate::types::OriginLedgerEntry { leg, first_seen_secs, contested })
    }

    /// Test 25 — the origin ledger round-trips a snapshot VERBATIM (both
    /// `contested` values, `first_seen_secs`, the whole leg).
    /// MUTATION: zero the field before `write` (the `take_snapshot` drop) ⇒ red.
    #[test]
    fn snapshot_roundtrips_origin_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();
        let ledger = vec![genuine_origin_entry(0x81, 111, false), genuine_origin_entry(0x82, 222, true)];
        let mut snap = snapshot_with(vec![]);
        snap.origin_ledger = ledger.clone();
        mgr.write(&snap).unwrap();
        let loaded = mgr.load_latest().unwrap().expect("snapshot");
        assert_eq!(loaded.origin_ledger, ledger);
    }

    /// Persisted shape — a snapshot written BEFORE wave 3 has no trailing
    /// `origin_ledger`. It must be REFUSED (never read as an empty ledger —
    /// that would silently forget every record) and the refusal COUNTED.
    /// MUTATIONS (run 2026-09-28): drop the `SNAPSHOT_DECODE_REFUSED` bump in
    /// `load_latest` ⇒ THIS test red. `.allow_trailing_bytes()` ⇒ green (a
    /// truncated file errors either way) — the trailing-bytes guard is pinned
    /// by `snapshot_decoder_rejects_trailing_bytes`.
    #[test]
    fn persisted_shape_prior_snapshot_without_origin_ledger_is_refused_loudly() {
        let snap = snapshot_with(vec![]);
        let new_bytes = bincode::serialize(&snap).unwrap();
        assert!(decode_snapshot_bytes(&new_bytes).is_ok(), "control: current shape decodes");
        // Prior shape = the same bytes without the trailing Vecs (u64 length 0
        // each): `origin_ledger` (wave 3) and `redeem_ledger` (W7b).
        let empty_vec_len = bincode::serialize(&Vec::<(crate::types::TxHash, crate::types::OriginLedgerEntry)>::new()).unwrap().len();
        let prior = new_bytes[..new_bytes.len() - 2 * empty_vec_len].to_vec();
        assert!(decode_snapshot_bytes(&prior).is_err(), "a pre-wave-3 snapshot must NOT decode");
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();
        std::fs::write(dir.path().join("snapshot_1790000000.bin"), &prior).unwrap();
        let before = snapshot_decode_refused_total();
        assert!(mgr.load_latest().expect("never Err").is_none(), "refused, not loaded");
        assert!(snapshot_decode_refused_total() > before, "COUNTED, not a silent skip");
    }

    // ── Fork Settlement W7b — redeem ledger + `SeqProof.declared` persisted shape ──

    fn genuine_redeem_entry(seed: u8, first_seen_secs: u64, contested: bool)
        -> (crate::smt::RedeemRecordId, crate::types::OriginLedgerEntry)
    {
        let leg = crate::types::test_legs::genuine_redeem_leg(
            &crate::types::test_legs::wallet(seed), [0x02; 32], &crate::types::test_legs::stray_origin([seed; 32]), 700, 3, 3,
        );
        ((leg.key(), leg.tx_hash), crate::types::OriginLedgerEntry { leg, first_seen_secs, contested })
    }

    /// W7b — the redeem ledger round-trips a snapshot VERBATIM, in its OWN
    /// field (never folded into `origin_ledger`).
    /// MUTATION (run 2026-09-28): write `redeem_ledger: vec![]` in
    /// `NablaNode::take_snapshot` ⇒ `node::w7b_tests::redeem_records_survive_snapshot_and_wal_restart`
    /// red; zeroing it here before `write` ⇒ THIS test red.
    #[test]
    fn snapshot_roundtrips_redeem_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();
        let ledger = vec![genuine_redeem_entry(0x83, 333, false), genuine_redeem_entry(0x84, 444, true)];
        let mut snap = snapshot_with(vec![]);
        snap.redeem_ledger = ledger.clone();
        mgr.write(&snap).unwrap();
        let loaded = mgr.load_latest().unwrap().expect("snapshot");
        assert_eq!(loaded.redeem_ledger, ledger);
        assert!(loaded.origin_ledger.is_empty(), "a redeem record is never an origin record (R5)");
    }

    /// Persisted shape — a pre-W7b snapshot has no trailing `redeem_ledger`:
    /// REFUSED (never read as an empty ledger) and COUNTED.
    /// MUTATION (run 2026-09-28): drop the `SNAPSHOT_DECODE_REFUSED` bump ⇒ red.
    #[test]
    fn persisted_shape_prior_snapshot_without_redeem_ledger_is_refused_loudly() {
        let snap = snapshot_with(vec![]);
        let new_bytes = bincode::serialize(&snap).unwrap();
        assert!(decode_snapshot_bytes(&new_bytes).is_ok(), "control: current shape decodes");
        let empty_vec_len = bincode::serialize(&Vec::<(crate::smt::RedeemRecordId, crate::types::OriginLedgerEntry)>::new()).unwrap().len();
        let prior = new_bytes[..new_bytes.len() - empty_vec_len].to_vec();
        assert!(decode_snapshot_bytes(&prior).is_err(), "a pre-W7b snapshot must NOT decode");
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();
        std::fs::write(dir.path().join("snapshot_1790000000.bin"), &prior).unwrap();
        let before = snapshot_decode_refused_total();
        assert!(mgr.load_latest().expect("never Err").is_none(), "refused, not loaded");
        assert!(snapshot_decode_refused_total() > before, "COUNTED, not a silent skip");
    }

    /// Persisted shape — a `SeqProof` WITHOUT the trailing `declared` (the
    /// W7a shape, inside `seq_proofs`) is refused loudly, never mis-read.
    /// MUTATION (run 2026-09-28): drop the `SNAPSHOT_DECODE_REFUSED` bump ⇒ red.
    #[test]
    fn persisted_shape_seq_proof_without_declared_is_refused_loudly() {
        let leg = crate::types::test_legs::genuine_send_leg(
            &crate::types::test_legs::wallet(0x85), [0x03; 32], 2, "p@axiom.internal/0123456789", 5, 1, 3,
        );
        let proof = leg.seq_proof.clone();
        let snap = snapshot_with(vec![([0xA3; 32], proof.clone())]);
        let new_bytes = bincode::serialize(&snap).unwrap();
        let back = decode_snapshot_bytes(&new_bytes).expect("current shape decodes");
        assert_eq!(back.seq_proofs[0].1.declared, proof.declared, "declared survives the snapshot");
        // The W7a shape: the same proof bytes minus the trailing `declared`.
        let p_new = bincode::serialize(&proof).unwrap();
        let d_len = bincode::serialize(&proof.declared).unwrap().len();
        let p_old = p_new[..p_new.len() - d_len].to_vec();
        let at = new_bytes.windows(p_new.len()).position(|w| w == &p_new[..]).expect("proof present");
        let mut prior = new_bytes.clone();
        prior.splice(at..at + p_new.len(), p_old);
        assert!(decode_snapshot_bytes(&prior).is_err(), "a pre-W7b SeqProof must NOT decode");
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();
        std::fs::write(dir.path().join("snapshot_1790000000.bin"), &prior).unwrap();
        let before = snapshot_decode_refused_total();
        assert!(mgr.load_latest().expect("never Err").is_none(), "refused, not loaded");
        assert!(snapshot_decode_refused_total() > before, "COUNTED, not a silent skip");
    }

    /// KI#241 F-2 (Fable test 7) — persisted shape: a redeem record whose leg
    /// is the PRIOR `LegPreimage::Redeem(RedeemPreimage)` (no carried cheque
    /// origin) is REFUSED loudly and COUNTED, never mis-read (a missing origin
    /// would leave the provenance burn exit without its amount). The rotation
    /// wipes data dirs anyway (§13); this pins that a stale file cannot load.
    /// MUTATION (run 2026-10-01): drop the `SNAPSHOT_DECODE_REFUSED` bump ⇒ red.
    #[test]
    fn persisted_shape_redeem_leg_without_cheque_origin_is_refused_loudly() {
        /// FROZEN prior shape (before KI#241 F-2). Do not "update" it.
        #[derive(serde::Serialize)]
        #[allow(dead_code)]
        enum PriorLegPreimage {
            Send(axiom_core_logic::types::WitnessPreimage),
            Redeem(axiom_core_logic::types::RedeemPreimage),
        }
        let (id, entry) = genuine_redeem_entry(0x86, 555, false);
        let mut snap = snapshot_with(vec![]);
        snap.redeem_ledger = vec![(id, entry.clone())];
        let new_bytes = bincode::serialize(&snap).unwrap();
        let back = decode_snapshot_bytes(&new_bytes).expect("current shape decodes");
        assert_eq!(back.redeem_ledger[0].1.leg.cheque_origin(), entry.leg.cheque_origin(), "the origin survives");
        let p_new = bincode::serialize(&entry.leg.seq_proof.preimage).unwrap();
        let p_old = bincode::serialize(&PriorLegPreimage::Redeem(entry.leg.redeem_preimage().unwrap().clone())).unwrap();
        assert!(p_old.len() < p_new.len() && p_new.starts_with(&p_old), "fixture: the prior shape lacks only the origin");
        let at = new_bytes.windows(p_new.len()).position(|w| w == &p_new[..]).expect("leg present");
        let mut prior = new_bytes.clone();
        prior.splice(at..at + p_new.len(), p_old);
        assert!(decode_snapshot_bytes(&prior).is_err(), "a pre-F-2 redeem leg must NOT decode");
        let dir = tempfile::tempdir().unwrap();
        let mgr = SnapshotManager::new(dir.path()).unwrap();
        std::fs::write(dir.path().join("snapshot_1790000000.bin"), &prior).unwrap();
        let before = snapshot_decode_refused_total();
        assert!(mgr.load_latest().expect("never Err").is_none(), "refused, not loaded");
        assert!(snapshot_decode_refused_total() > before, "COUNTED, not a silent skip");
    }

    /// FROZEN prior `BannedEntry` shape (before wave 3): wallet_id, evidence_1,
    /// evidence_2, seq_fork, status — as a positional tuple (bincode encodes a
    /// struct and the tuple of its fields identically). Do not "update" it.
    fn prior_banned_entry_bytes(
        wallet_id: [u8; 32],
        e1: &crate::types::ConflictProof,
        e2: &crate::types::ConflictProof,
        seq_fork: &Option<crate::types::SeqConflictProof>,
    ) -> Vec<u8> {
        bincode::serialize(&(wallet_id, e1, e2, seq_fork, crate::types::BanStatus::Active)).unwrap()
    }

    /// Persisted shape — `snapshot.bans` written in the prior `BannedEntry`
    /// shape is REFUSED loudly, for BOTH prior kinds: an E1 pair, and the
    /// hard case — a seq-fork ban, whose zero-filled `evidence_1` starts with
    /// four zero bytes that read as `BanEvidence` tag 0 (`LegacyConflict`).
    /// The strict decoder must still refuse it (misaligned decode / trailing
    /// bytes), never mis-read an irreversible verdict.
    /// MUTATIONS (run 2026-09-28): drop the `SNAPSHOT_DECODE_REFUSED` bump ⇒
    /// THIS test red. `.allow_trailing_bytes()` ⇒ green: MEASURED, both
    /// prior-shape fixtures (incl. the tag-0 hard case) fail mid-decode even
    /// leniently, so the strictness is pinned by
    /// `snapshot_decoder_rejects_trailing_bytes`, not here.
    #[test]
    fn persisted_shape_prior_banned_entry_is_refused_loudly() {
        use crate::types::{BanEvidence, BanStatus, BannedEntry, ConflictProof, SeqConflictProof};
        let cp = |b: u8| ConflictProof {
            old_state: [0x10; 32], new_state: [b; 32], tx_hash: [b ^ 0xFF; 32],
            k3_signatures: vec![], tick: 3, required_k: 3,
        };
        let sf = SeqConflictProof {
            wallet_seq: 5, state_a: [1; 32], tx_a: [2; 32], proof_a: wave2a_proof(crate::types::test_legs::opaque_redeem_leg()),
            state_b: [3; 32], tx_b: [4; 32], proof_b: wave2a_proof(crate::types::test_legs::opaque_redeem_leg()),
        };
        let cases: Vec<(&str, BannedEntry, Vec<u8>)> = vec![
            ("E1 pair",
             BannedEntry { wallet_id: [0xB1; 32], evidence: BanEvidence::LegacyConflict(cp(0x20), cp(0x30)), status: BanStatus::Active },
             prior_banned_entry_bytes([0xB1; 32], &cp(0x20), &cp(0x30), &None)),
            ("seq-fork with zero-filled ConflictProofs",
             BannedEntry { wallet_id: [0xB2; 32], evidence: BanEvidence::SeqFork(sf.clone()), status: BanStatus::Active },
             prior_banned_entry_bytes([0xB2; 32], &ConflictProof::default(), &ConflictProof::default(), &Some(sf.clone()))),
        ];
        for (why, current, prior_entry) in cases {
            let mut snap = snapshot_with(vec![]);
            snap.bans = vec![current.clone()];
            let new_bytes = bincode::serialize(&snap).unwrap();
            let back = decode_snapshot_bytes(&new_bytes).expect("control: current shape decodes");
            assert_eq!(back.bans, vec![current.clone()], "{why}: current shape round-trips");
            let cur_entry = bincode::serialize(&current).unwrap();
            let at = new_bytes.windows(cur_entry.len()).position(|w| w == &cur_entry[..]).unwrap();
            let mut prior = new_bytes.clone();
            prior.splice(at..at + cur_entry.len(), prior_entry);
            assert!(decode_snapshot_bytes(&prior).is_err(), "{why}: prior BannedEntry shape must NOT decode");
            let dir = tempfile::tempdir().unwrap();
            let mgr = SnapshotManager::new(dir.path()).unwrap();
            std::fs::write(dir.path().join("snapshot_1790000000.bin"), &prior).unwrap();
            let before = snapshot_decode_refused_total();
            assert!(mgr.load_latest().expect("never Err").is_none(), "{why}: refused");
            assert!(snapshot_decode_refused_total() > before, "{why}: COUNTED");
        }
    }
}
