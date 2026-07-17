// AXIOM Nabla — Write-Ahead Log (WAL)
// Reference: AXIOM_GUIDE_Nabla.md Section 2.5
//
// Phase 1 Task 3: WAL for crash recovery
//
// Architecture:
//   All SMT mutations are first written to the WAL (append-only, sequential).
//   On crash recovery: load last snapshot, replay WAL entries after snapshot.
//   WAL is compacted on each snapshot.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::types::{Hash256, NablaError, WalletId};

/// WAL operation types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalOp {
    /// Insert or update a wallet entry in the SMT.
    Put {
        key: WalletId,
        value: Vec<u8>, // serialized NablaEntry
        /// Wallet owner's Ed25519 public key (YPX-009 client-signed state records).
        #[serde(default)]
        client_pk: [u8; 32],
        /// Ed25519 sig over BLAKE3("AXIOM_WALLET_STATE" || fields).
        #[serde(default)]
        client_sig: Vec<u8>,
    },
    /// Ban a wallet (conflict detected).
    Ban {
        wallet_id: WalletId,
        evidence: Vec<u8>, // serialized BannedEntry
    },
    /// Snapshot marker — WAL entries before this can be discarded.
    Snapshot {
        tick: u64,
        root: Hash256,
    },
    /// CC chain update — latest CC produced at this tick.
    CcUpdate {
        tick: u64,
        cc_bytes: Vec<u8>, // bincode-serialized CompanionCertificate
    },
    /// YP §19.6 fee ledger — per-tx record (hashmap mode only).
    /// Persisted alongside the WAL so `txid_records` + `validator_earnings`
    /// reconstruct on boot from snapshot + WAL replay. Bloom-mode nodes
    /// never append this op; replay no-ops if `record_tx_meta` is called
    /// on a bloom-mode SMT (defensive guard inside the SMT).
    RecordTx {
        tx_hash: [u8; 32],
        record: Vec<u8>, // bincode-serialized TxRecord
    },
    /// YPX-022 §5 — txid completion terminal (k-witnessed registration).
    /// Durable so the recall eligibility base survives a crash between
    /// snapshots. Replay: `mark_txid_completed`.
    TxCompleted {
        tx_hash: [u8; 32],
        tick: u64,
    },
    /// YPX-022 §5 — txid REDEEMED terminal (redeem-finalize). Durable so a
    /// crash cannot forget that a cheque was consumed — a recall of a
    /// redeemed txid must refuse forever. Replay: `mark_txid_redeemed`.
    TxRedeemed {
        tx_hash: [u8; 32],
    },
    /// YPX-022 §5 — txid RECALLED terminal (sender recall, consume-once).
    /// Durable so a crash cannot resurrect a recalled cheque. Replay:
    /// `apply_remote_recall` (pure marker merge, first-wins).
    TxRecalled {
        tx_hash: [u8; 32],
        sender_pk: Vec<u8>,
        recall_tick: u64,
    },
    /// YPX-001 §1.5.1a — a k-witnessed BURN register named this txid as its
    /// `burn_target_tx_id`: the scarred origin transition was resolved by
    /// destroying the tainted amount. Durable so query-txid can attest
    /// "BURNED" forever (downstream inherited-scar resolutions depend on
    /// it). Replay: `mark_txid_burn_resolved`.
    TxBurnResolved {
        target_tx_hash: [u8; 32],
    },
}

impl WalOp {
    /// YPX-009 §12 checksum discriminant — the op-type byte folded into every
    /// entry's BLAKE3 checksum. ONE source of truth for all checksum sites
    /// (append / read-verify / compact / truncate); a new variant added here
    /// is automatically consistent everywhere.
    fn type_byte(&self) -> u8 {
        match self {
            WalOp::Put { .. } => 0,
            WalOp::Ban { .. } => 1,
            WalOp::Snapshot { .. } => 2,
            WalOp::CcUpdate { .. } => 3,
            WalOp::RecordTx { .. } => 4,
            WalOp::TxCompleted { .. } => 5,
            WalOp::TxRedeemed { .. } => 6,
            WalOp::TxRecalled { .. } => 7,
            WalOp::TxBurnResolved { .. } => 8,
        }
    }
}

/// Write-Ahead Log for crash recovery.
///
/// Append-only file on disk. Every SMT mutation is written here before
/// the in-memory tree is updated. On crash recovery, replay all entries
/// after the last snapshot marker.
pub struct WriteAheadLog {
    path: PathBuf,
    file: File,
    /// Tick of last snapshot (WAL entries before this are redundant).
    pub last_snapshot_tick: u64,
    /// Number of operations since last snapshot.
    ops_since_snapshot: u64,
    /// YPX-009 §12: Monotonic sequence counter for integrity auditing.
    sequence: u64,
    /// YPX-009 §12: In-memory checksums for quick verification.
    /// Each entry is (sequence, BLAKE3 checksum of the WAL entry).
    checksums: Vec<(u64, [u8; 32])>,
    /// KnownIssue #4 fix: sequences already reported as corrupted in
    /// this process's lifetime. Without dedup, `audit_recent` re-flags
    /// the same bad sequence on every audit cycle (every WAL_AUDIT_INTERVAL_TICKS),
    /// producing the spammy log loop documented in soak `s2r12039`.
    /// Cleared by `truncate_at` after recovery.
    acknowledged_corruptions: std::collections::BTreeSet<u64>,
}

impl WriteAheadLog {
    /// Open or create a WAL file at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NablaError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| NablaError::WalError(format!("failed to open WAL: {e}")))?;

        Ok(Self {
            path,
            file,
            last_snapshot_tick: 0,
            ops_since_snapshot: 0,
            sequence: 0,
            checksums: Vec::new(),
            acknowledged_corruptions: std::collections::BTreeSet::new(),
        })
    }

    /// Append an operation to the WAL.
    /// Each entry is a bincode-serialized WalOp followed by a newline delimiter.
    pub fn append(&mut self, op: &WalOp) -> Result<(), NablaError> {
        let bytes = bincode::serialize(op)
            .map_err(|e| NablaError::WalError(format!("serialize failed: {e}")))?;

        // YPX-009 §12: Compute BLAKE3 checksum for integrity auditing.
        // Checksum = BLAKE3("AXIOM_WAL" || sequence_le || op_discriminant || payload).
        let entry_type_byte = op.type_byte();
        let checksum = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"AXIOM_WAL");
            hasher.update(&self.sequence.to_le_bytes());
            hasher.update(&[entry_type_byte]);
            hasher.update(&bytes);
            *hasher.finalize().as_bytes()
        };

        // Write length-prefixed entry: [4-byte LE length][payload][32-byte checksum]
        let len = bytes.len() as u32;
        self.file
            .write_all(&len.to_le_bytes())
            .map_err(|e| NablaError::WalError(format!("write len failed: {e}")))?;
        self.file
            .write_all(&bytes)
            .map_err(|e| NablaError::WalError(format!("write payload failed: {e}")))?;
        self.file
            .write_all(&checksum)
            .map_err(|e| NablaError::WalError(format!("write checksum failed: {e}")))?;
        self.file
            .flush()
            .map_err(|e| NablaError::WalError(format!("flush failed: {e}")))?;

        self.checksums.push((self.sequence, checksum));
        self.sequence += 1;

        if let WalOp::Snapshot { tick, .. } = op {
            self.last_snapshot_tick = *tick;
            self.ops_since_snapshot = 0;
        } else {
            self.ops_since_snapshot += 1;
        }

        Ok(())
    }

    /// Read all WAL entries from disk.
    /// Used during crash recovery to replay operations after last snapshot.
    pub fn read_all(path: impl AsRef<Path>) -> Result<Vec<WalOp>, NablaError> {
        Self::read_all_with_checksums(path).map(|(ops, _)| ops)
    }

    /// Read all WAL entries from disk, returning ops and their checksums.
    /// YPX-009 §12: Entries written with checksums are verified on load.
    /// Legacy entries (without checksums) are accepted with a warning.
    #[allow(clippy::type_complexity)]
    pub fn read_all_with_checksums(path: impl AsRef<Path>) -> Result<(Vec<WalOp>, Vec<(u64, [u8; 32])>), NablaError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok((Vec::new(), Vec::new()));
        }

        let file = File::open(path)
            .map_err(|e| NablaError::WalError(format!("failed to open WAL for read: {e}")))?;

        let mut reader = BufReader::new(file);
        let mut ops = Vec::new();
        let mut checksums = Vec::new();
        let mut len_buf = [0u8; 4];
        let mut sequence: u64 = 0;

        loop {
            // Read length prefix
            match io::Read::read_exact(&mut reader, &mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => {
                    return Err(NablaError::WalError(format!(
                        "failed to read WAL entry length: {e}"
                    )));
                }
            }

            let len = u32::from_le_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];

            match io::Read::read_exact(&mut reader, &mut payload) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    log::warn!("WAL truncated entry at end — ignoring incomplete write");
                    break;
                }
                Err(e) => {
                    return Err(NablaError::WalError(format!(
                        "failed to read WAL entry payload: {e}"
                    )));
                }
            }

            // YPX-009: Try to read 32-byte checksum after payload.
            // If present, verify it. If missing (legacy WAL), accept with warning.
            let mut checksum_buf = [0u8; 32];
            let has_checksum = io::Read::read_exact(&mut reader, &mut checksum_buf).is_ok();

            match bincode::deserialize::<WalOp>(&payload) {
                Ok(op) => {
                    if has_checksum {
                        // Verify checksum
                        let entry_type_byte = op.type_byte();
                        let expected = {
                            let mut hasher = blake3::Hasher::new();
                            hasher.update(b"AXIOM_WAL");
                            hasher.update(&sequence.to_le_bytes());
                            hasher.update(&[entry_type_byte]);
                            hasher.update(&payload);
                            *hasher.finalize().as_bytes()
                        };
                        if checksum_buf != expected {
                            log::warn!(
                                "WAL checksum mismatch at sequence {} — corruption detected",
                                sequence
                            );
                            // YPX-009 §12.7: discard from this point, re-sync from peers.
                            break;
                        }
                        checksums.push((sequence, checksum_buf));
                    }
                    ops.push(op);
                    sequence += 1;
                }
                Err(e) => {
                    log::warn!("WAL corrupt entry — stopping replay: {e}");
                    break;
                }
            }
        }

        Ok((ops, checksums))
    }

    /// Read WAL entries that come after the given snapshot tick.
    /// These are the entries that need to be replayed during recovery.
    pub fn read_after_snapshot(
        path: impl AsRef<Path>,
        snapshot_tick: u64,
    ) -> Result<Vec<WalOp>, NablaError> {
        let all_ops = Self::read_all(path)?;

        // Find the last snapshot marker and return everything after it
        let mut last_snapshot_idx = None;
        for (i, op) in all_ops.iter().enumerate() {
            if let WalOp::Snapshot { tick, .. } = op {
                if *tick == snapshot_tick {
                    last_snapshot_idx = Some(i);
                }
            }
        }

        match last_snapshot_idx {
            Some(idx) => Ok(all_ops[idx + 1..].to_vec()),
            None => {
                // No matching snapshot found — replay everything
                Ok(all_ops)
            }
        }
    }

    /// Compact the WAL by removing all entries before the last snapshot.
    /// Creates a new file with only the entries after the last snapshot.
    pub fn compact(&mut self) -> Result<(), NablaError> {
        let all_ops = Self::read_all(&self.path)?;

        // Find last snapshot
        let mut last_snapshot_idx = None;
        for (i, op) in all_ops.iter().enumerate().rev() {
            if matches!(op, WalOp::Snapshot { .. }) {
                last_snapshot_idx = Some(i);
                break;
            }
        }

        let keep_from = last_snapshot_idx.unwrap_or(0);
        let keep_ops = &all_ops[keep_from..];

        // Write to temp file with fresh sequence numbers and checksums, then rename
        let tmp_path = self.path.with_extension("wal.tmp");
        let mut new_checksums = Vec::new();
        {
            let mut tmp_file = File::create(&tmp_path)
                .map_err(|e| NablaError::WalError(format!("compact: create tmp: {e}")))?;

            for (new_seq, op) in keep_ops.iter().enumerate() {
                let bytes = bincode::serialize(op)
                    .map_err(|e| NablaError::WalError(format!("compact: serialize: {e}")))?;
                let entry_type_byte = op.type_byte();
                let checksum = {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(b"AXIOM_WAL");
                    hasher.update(&(new_seq as u64).to_le_bytes());
                    hasher.update(&[entry_type_byte]);
                    hasher.update(&bytes);
                    *hasher.finalize().as_bytes()
                };
                let len = bytes.len() as u32;
                tmp_file
                    .write_all(&len.to_le_bytes())
                    .map_err(|e| NablaError::WalError(format!("compact: write: {e}")))?;
                tmp_file
                    .write_all(&bytes)
                    .map_err(|e| NablaError::WalError(format!("compact: write: {e}")))?;
                tmp_file
                    .write_all(&checksum)
                    .map_err(|e| NablaError::WalError(format!("compact: write checksum: {e}")))?;
                new_checksums.push((new_seq as u64, checksum));
            }
            tmp_file
                .flush()
                .map_err(|e| NablaError::WalError(format!("compact: flush: {e}")))?;
        }

        fs::rename(&tmp_path, &self.path)
            .map_err(|e| NablaError::WalError(format!("compact: rename: {e}")))?;

        // Reopen the file in append mode
        self.file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|e| NablaError::WalError(format!("compact: reopen: {e}")))?;

        self.sequence = keep_ops.len() as u64;
        self.checksums = new_checksums;
        self.ops_since_snapshot = (keep_ops.len().saturating_sub(1)) as u64;

        Ok(())
    }

    /// Number of operations since last snapshot.
    pub fn ops_since_snapshot(&self) -> u64 {
        self.ops_since_snapshot
    }

    /// WAL file size in bytes (O(1) stat call, no file read).
    pub fn file_size_bytes(&self) -> u64 {
        std::fs::metadata(&self.path)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// YPX-009 §12: Current sequence counter (total entries written).
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// YPX-009 §12: Number of in-memory checksums.
    pub fn checksum_count(&self) -> usize {
        self.checksums.len()
    }

    /// YPX-009 §12: Recent audit — pick 1 random entry from last WAL_AUDIT_WINDOW,
    /// re-read from disk and verify its checksum.
    /// Returns `Some(sequence)` if corruption found, `None` if clean.
    ///
    /// **KnownIssue #4 dedup:** sequences already reported as corrupted
    /// in this process are not re-reported. The previous behaviour
    /// re-flagged the same sequence on every audit cycle, producing
    /// ~1,243 warnings/6h per affected node in soak `s2r12039` (line
    /// 3304 of nabla_node.rs is invoked but does no recovery). Caller
    /// should invoke `truncate_at(seq)` to actually drop the corrupted
    /// tail; that clears the dedup set and the next audit can re-flag
    /// fresh corruption.
    pub fn audit_recent(&mut self) -> Result<Option<u64>, NablaError> {
        use crate::constants::WAL_AUDIT_WINDOW;
        if self.checksums.is_empty() {
            return Ok(None);
        }
        let window_start = self.checksums.len().saturating_sub(WAL_AUDIT_WINDOW as usize);
        let window = &self.checksums[window_start..];
        if window.is_empty() {
            return Ok(None);
        }
        // Pick one random entry from the window
        let idx = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            self.sequence.hash(&mut h);
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .hash(&mut h);
            h.finish() as usize % window.len()
        };
        let (seq, expected_checksum) = window[idx];
        // Re-read from disk and verify
        let (_, disk_checksums) = Self::read_all_with_checksums(&self.path)?;
        for (dseq, dcheck) in &disk_checksums {
            if *dseq == seq {
                if *dcheck != expected_checksum {
                    if self.acknowledged_corruptions.insert(seq) {
                        return Ok(Some(seq));
                    }
                    // Already reported this seq in a prior cycle — caller
                    // hasn't recovered yet, suppress to avoid log spam.
                    return Ok(None);
                }
                return Ok(None);
            }
        }
        // Sequence not found on disk — corruption or truncation
        if self.acknowledged_corruptions.insert(seq) {
            Ok(Some(seq))
        } else {
            Ok(None)
        }
    }

    /// YPX-009 §12: Deep scan — pick WAL_DEEP_SCAN_COUNT random entries from ALL,
    /// re-read from disk and verify checksums.
    /// Returns list of corrupted sequences (usually empty).
    pub fn audit_deep(&self) -> Result<Vec<u64>, NablaError> {
        use crate::constants::WAL_DEEP_SCAN_COUNT;
        if self.checksums.is_empty() {
            return Ok(Vec::new());
        }
        let (_, disk_checksums) = Self::read_all_with_checksums(&self.path)?;

        let mut corrupted = Vec::new();
        let count = (WAL_DEEP_SCAN_COUNT as usize).min(self.checksums.len());

        // Deterministic but spread-out sampling
        let step = self.checksums.len().max(1) / count.max(1);
        for i in 0..count {
            let idx = (i * step).min(self.checksums.len() - 1);
            let (seq, expected) = self.checksums[idx];
            let found = disk_checksums.iter().find(|(s, _)| *s == seq);
            match found {
                Some((_, actual)) if *actual != expected => corrupted.push(seq),
                None => corrupted.push(seq),
                _ => {}
            }
        }

        Ok(corrupted)
    }

    /// KnownIssue #4 fix: discard WAL entries from `seq` onward and
    /// rewrite the file so the corrupted tail is gone. Clears the
    /// matching `acknowledged_corruptions` entries so future audits
    /// can re-flag fresh corruption.
    ///
    /// Sequencer is set to `seq` so the next `append` writes at the
    /// truncation point. Caller is responsible for deciding what to
    /// do with the lost data (in production: trigger `RangeSync` from
    /// peers; in dev / soak: accept the gap, the validator can rebuild
    /// state from peer gossip on next reconnect).
    pub fn truncate_at(&mut self, seq: u64) -> Result<(), NablaError> {
        if seq == 0 {
            // Truncate everything — fresh WAL.
            drop(std::mem::replace(
                &mut self.file,
                File::create(&self.path).map_err(|e| {
                    NablaError::WalError(format!("truncate_at: create empty: {e}"))
                })?,
            ));
            self.file = OpenOptions::new()
                .append(true)
                .open(&self.path)
                .map_err(|e| NablaError::WalError(format!("truncate_at: reopen: {e}")))?;
            self.sequence = 0;
            self.checksums.clear();
            self.acknowledged_corruptions.clear();
            self.ops_since_snapshot = 0;
            return Ok(());
        }

        // Read entries 0..seq from disk, rewrite. Entries past seq are
        // discarded. read_all_with_checksums stops at the first bad
        // entry, so if `seq` itself is past a worse corruption we may
        // get fewer ops back — that's the correct behaviour: keep
        // only bytes that round-trip cleanly.
        let (all_ops, all_checksums) = Self::read_all_with_checksums(&self.path)?;
        let keep_count = (seq as usize).min(all_ops.len());
        let keep_ops = &all_ops[..keep_count];
        let keep_checksums = &all_checksums[..keep_count.min(all_checksums.len())];

        let tmp_path = self.path.with_extension("wal.truncate.tmp");
        {
            let mut tmp_file = File::create(&tmp_path).map_err(|e| {
                NablaError::WalError(format!("truncate_at: create tmp: {e}"))
            })?;

            for (idx, op) in keep_ops.iter().enumerate() {
                let bytes = bincode::serialize(op).map_err(|e| {
                    NablaError::WalError(format!("truncate_at: serialize: {e}"))
                })?;
                let checksum = keep_checksums
                    .get(idx)
                    .map(|(_, c)| *c)
                    .unwrap_or_else(|| {
                        // Fallback — recompute (should not happen if
                        // entry was previously verified on read).
                        let entry_type_byte = op.type_byte();
                        let mut h = blake3::Hasher::new();
                        h.update(b"AXIOM_WAL");
                        h.update(&(idx as u64).to_le_bytes());
                        h.update(&[entry_type_byte]);
                        h.update(&bytes);
                        *h.finalize().as_bytes()
                    });
                let len = bytes.len() as u32;
                tmp_file
                    .write_all(&len.to_le_bytes())
                    .map_err(|e| NablaError::WalError(format!("truncate_at: write: {e}")))?;
                tmp_file
                    .write_all(&bytes)
                    .map_err(|e| NablaError::WalError(format!("truncate_at: write: {e}")))?;
                tmp_file
                    .write_all(&checksum)
                    .map_err(|e| NablaError::WalError(format!("truncate_at: write checksum: {e}")))?;
            }
            tmp_file
                .flush()
                .map_err(|e| NablaError::WalError(format!("truncate_at: flush: {e}")))?;
        }

        fs::rename(&tmp_path, &self.path)
            .map_err(|e| NablaError::WalError(format!("truncate_at: rename: {e}")))?;

        self.file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|e| NablaError::WalError(format!("truncate_at: reopen: {e}")))?;

        self.sequence = keep_count as u64;
        self.checksums = keep_checksums.to_vec();
        // Drop dedup entries that the caller has now actually recovered.
        self.acknowledged_corruptions.retain(|s| *s < self.sequence);
        // Snapshot tracking — best effort: if a snapshot was past the
        // truncation point we've lost it, tracking goes back to 0
        // until the next snapshot is written.
        self.ops_since_snapshot = keep_count.saturating_sub(1) as u64;

        Ok(())
    }

    /// YPX-009 §12: Return a copy of current checksums for snapshot inclusion.
    pub fn checksums_snapshot(&self) -> Vec<(u64, [u8; 32])> {
        self.checksums.clone()
    }

    /// YPX-009 §12: Restore checksums from a snapshot (fast audit recovery).
    pub fn restore_checksums(&mut self, checksums: Vec<(u64, [u8; 32])>) {
        self.sequence = checksums.last().map(|(s, _)| s + 1).unwrap_or(0);
        self.checksums = checksums;
    }

    /// YPX-009 §12: Compute a BLAKE3 section hash over a tick range for peer cross-verification.
    /// Hash = BLAKE3("AXIOM_WAL_SECTION" || from_tick_le || to_tick_le || checksum_0 || ... || checksum_n).
    pub fn section_hash(&self, from_seq: u64, to_seq: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_WAL_SECTION");
        hasher.update(&from_seq.to_le_bytes());
        hasher.update(&to_seq.to_le_bytes());
        for (seq, checksum) in &self.checksums {
            if *seq >= from_seq && *seq < to_seq {
                hasher.update(checksum);
            }
        }
        *hasher.finalize().as_bytes()
    }

    /// YPX-009 §12: Load checksums from disk into in-memory table.
    /// Called during recovery to restore audit state.
    pub fn load_checksums(&mut self) -> Result<(), NablaError> {
        let (_, checksums) = Self::read_all_with_checksums(&self.path)?;
        self.sequence = checksums.last().map(|(s, _)| s + 1).unwrap_or(0);
        self.checksums = checksums;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wal_write_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut wal = WriteAheadLog::open(&wal_path).unwrap();

        let op1 = WalOp::Put {
            key: [0xAA; 32],
            value: vec![1, 2, 3],
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        };
        let op2 = WalOp::Put {
            key: [0xBB; 32],
            value: vec![4, 5, 6],
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        };
        let op3 = WalOp::Snapshot {
            tick: 100,
            root: [0xCC; 32],
        };

        wal.append(&op1).unwrap();
        wal.append(&op2).unwrap();
        wal.append(&op3).unwrap();

        let ops = WriteAheadLog::read_all(&wal_path).unwrap();
        assert_eq!(ops.len(), 3);
    }

    #[test]
    fn wal_read_after_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut wal = WriteAheadLog::open(&wal_path).unwrap();

        wal.append(&WalOp::Put {
            key: [0x01; 32],
            value: vec![1],
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        })
        .unwrap();
        wal.append(&WalOp::Snapshot {
            tick: 50,
            root: [0xFF; 32],
        })
        .unwrap();
        wal.append(&WalOp::Put {
            key: [0x02; 32],
            value: vec![2],
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        })
        .unwrap();
        wal.append(&WalOp::Put {
            key: [0x03; 32],
            value: vec![3],
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        })
        .unwrap();

        let after = WriteAheadLog::read_after_snapshot(&wal_path, 50).unwrap();
        assert_eq!(after.len(), 2); // only the 2 puts after snapshot
    }

    #[test]
    fn wal_compact() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut wal = WriteAheadLog::open(&wal_path).unwrap();

        // Write 100 ops, then snapshot, then 5 more
        for i in 0..100u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            })
            .unwrap();
        }
        wal.append(&WalOp::Snapshot {
            tick: 200,
            root: [0xDD; 32],
        })
        .unwrap();
        for i in 200..205u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            })
            .unwrap();
        }

        // Before compact: 106 entries
        let before = WriteAheadLog::read_all(&wal_path).unwrap();
        assert_eq!(before.len(), 106);

        // Compact
        wal.compact().unwrap();

        // After compact: snapshot + 5 entries = 6
        let after = WriteAheadLog::read_all(&wal_path).unwrap();
        assert_eq!(after.len(), 6);
    }

    // ── YPX-009: WAL Checksum + Audit Tests ──

    #[test]
    fn wal_checksum_write_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut wal = WriteAheadLog::open(&wal_path).unwrap();

        for i in 0..5u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i, i + 1, i + 2],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            }).unwrap();
        }

        // Checksums should be stored in memory
        assert_eq!(wal.checksum_count(), 5);
        assert_eq!(wal.sequence(), 5);

        // Re-read from disk and verify checksums match
        let (ops, checksums) = WriteAheadLog::read_all_with_checksums(&wal_path).unwrap();
        assert_eq!(ops.len(), 5);
        assert_eq!(checksums.len(), 5);

        // Verify sequence monotonicity
        for (i, (seq, _)) in checksums.iter().enumerate() {
            assert_eq!(*seq, i as u64);
        }
    }

    #[test]
    fn wal_corrupt_byte_detected_on_read() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        // Write 3 entries with checksums
        {
            let mut wal = WriteAheadLog::open(&wal_path).unwrap();
            for i in 0..3u8 {
                wal.append(&WalOp::Put {
                    key: [i; 32],
                    value: vec![i; 10],
                    client_pk: [0u8; 32],
                    client_sig: vec![0u8; 64],
                }).unwrap();
            }
        }

        // Corrupt a byte in the middle of the file
        {
            let mut data = std::fs::read(&wal_path).unwrap();
            let mid = data.len() / 2;
            data[mid] ^= 0xFF; // flip bits
            std::fs::write(&wal_path, &data).unwrap();
        }

        // Re-read — should detect corruption and stop early
        let (ops, _checksums) = WriteAheadLog::read_all_with_checksums(&wal_path).unwrap();
        // We should get fewer ops than the 3 we wrote (corruption stops replay)
        assert!(ops.len() < 3, "corruption should stop replay early, got {} ops", ops.len());
    }

    #[test]
    fn wal_audit_deep_clean() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut wal = WriteAheadLog::open(&wal_path).unwrap();
        for i in 0..20u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            }).unwrap();
        }

        let corrupted = wal.audit_deep().unwrap();
        assert!(corrupted.is_empty(), "clean WAL should have no corruption");
    }

    #[test]
    fn wal_sequence_monotonic_across_compact() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut wal = WriteAheadLog::open(&wal_path).unwrap();

        // Write 10 ops, snapshot, 3 more
        for i in 0..10u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            }).unwrap();
        }
        wal.append(&WalOp::Snapshot { tick: 50, root: [0xAA; 32] }).unwrap();
        for i in 10..13u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            }).unwrap();
        }

        assert_eq!(wal.sequence(), 14); // 10 + 1 snapshot + 3

        // Compact — sequence should be reset to compacted size
        wal.compact().unwrap();

        // After compact: snapshot + 3 = 4 entries, sequence = 4
        assert_eq!(wal.sequence(), 4);
        assert_eq!(wal.checksum_count(), 4);

        // Writing more continues from new sequence
        wal.append(&WalOp::Put {
            key: [0xFF; 32],
            value: vec![0xFF],
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        }).unwrap();
        assert_eq!(wal.sequence(), 5);
    }

    #[test]
    fn wal_audit_recent_detects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        // Write 10 entries
        let mut wal = WriteAheadLog::open(&wal_path).unwrap();
        for i in 0..10u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i; 20],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            }).unwrap();
        }

        // Corrupt the last entry on disk (flip byte near end of file)
        {
            let mut data = std::fs::read(&wal_path).unwrap();
            // Corrupt near the end — within the last entry's payload
            let pos = data.len() - 40;
            data[pos] ^= 0xFF;
            std::fs::write(&wal_path, &data).unwrap();
        }

        // audit_recent should detect the corruption (the corrupted entry
        // won't match in-memory checksum when re-read from disk)
        // Note: audit_recent picks randomly so we run it multiple times
        // to increase probability of catching it.
        let mut found_corruption = false;
        for _ in 0..50 {
            match wal.audit_recent() {
                Ok(Some(_seq)) => { found_corruption = true; break; }
                Ok(None) => {} // random sample missed the bad entry
                Err(_) => { found_corruption = true; break; } // IO error = also bad
            }
        }
        assert!(found_corruption, "audit should detect corruption after multiple samples");
    }

    /// KnownIssue #4 regression test (part 1): audit_recent must dedupe.
    ///
    /// Pre-fix: every audit cycle re-flagged the same corrupted seq,
    /// producing ~1,243 warnings/6h per affected node in soak.
    /// Post-fix: a corrupted sequence is reported exactly once until
    /// `truncate_at` actually recovers, then the dedup state clears
    /// and a *new* corruption can be detected.
    #[test]
    fn wal_audit_recent_dedupes_repeated_corruption_reports() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut wal = WriteAheadLog::open(&wal_path).unwrap();
        for i in 0..10u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i; 20],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            }).unwrap();
        }

        // Corrupt the file. Use a position deep enough that read_all stops
        // early, forcing audit_recent to find sequences "missing on disk"
        // — this is the exact case that caused the soak's repeating loop.
        {
            let mut data = std::fs::read(&wal_path).unwrap();
            let pos = data.len() / 2;
            data[pos] ^= 0xFF;
            std::fs::write(&wal_path, &data).unwrap();
        }

        // Run audit_recent enough times that all seqs in the audit window
        // get sampled at least once. Across 200 random picks each unique
        // bad seq will be hit multiple times, but the post-fix code must
        // report each one exactly once.
        let mut reported_seqs: Vec<u64> = Vec::new();
        for _ in 0..200 {
            if let Ok(Some(seq)) = wal.audit_recent() {
                reported_seqs.push(seq);
            }
        }

        // The set of unique seqs reported equals the total reports — no
        // duplicates. Pre-fix this would have been (200, fewer-uniques).
        let mut sorted = reported_seqs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            reported_seqs.len(),
            "audit_recent should report each corrupted seq at most once; got reports={:?}",
            reported_seqs,
        );
    }

    /// KnownIssue #4 regression test (part 2): truncate_at recovers.
    ///
    /// After truncate_at(seq), the WAL no longer contains entries from
    /// seq onward, the in-memory state matches, and the dedup set is
    /// cleared so future audits can detect fresh corruption.
    #[test]
    fn wal_truncate_at_drops_tail_and_clears_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut wal = WriteAheadLog::open(&wal_path).unwrap();
        for i in 0..10u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i; 20],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            }).unwrap();
        }
        let pre_len = std::fs::metadata(&wal_path).unwrap().len();
        assert_eq!(wal.sequence(), 10);

        wal.truncate_at(7).unwrap();

        // Post-truncate: seq capped at 7, file shrank, in-memory checksums
        // shrank, acknowledged_corruptions did not retain entries >= 7.
        assert_eq!(wal.sequence(), 7, "sequence should reset to truncation point");
        assert_eq!(
            wal.checksum_count(),
            7,
            "in-memory checksums should match new sequence count",
        );
        let post_len = std::fs::metadata(&wal_path).unwrap().len();
        assert!(post_len < pre_len, "file should shrink after truncate");

        // Re-reading from disk: only entries 0..7 should round-trip.
        let (ops, _) = WriteAheadLog::read_all_with_checksums(&wal_path).unwrap();
        assert_eq!(ops.len(), 7);

        // Append a fresh entry — sequence advances from 7.
        wal.append(&WalOp::Put {
            key: [99u8; 32],
            value: vec![1, 2, 3],
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        }).unwrap();
        assert_eq!(wal.sequence(), 8);
    }

    #[test]
    fn wal_audit_deep_detects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut wal = WriteAheadLog::open(&wal_path).unwrap();
        for i in 0..20u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i; 50],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            }).unwrap();
        }

        // Corrupt near the beginning
        {
            let mut data = std::fs::read(&wal_path).unwrap();
            data[50] ^= 0xFF;
            std::fs::write(&wal_path, &data).unwrap();
        }

        // Deep scan samples across all entries — should find corruption
        let corrupted = wal.audit_deep().unwrap();
        // Due to the corruption, read_all_with_checksums will stop early,
        // so some sequences in our in-memory checksums won't be on disk.
        assert!(!corrupted.is_empty(), "deep scan should detect corruption");
    }

    #[test]
    fn wal_section_hash_consistent() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut wal = WriteAheadLog::open(&wal_path).unwrap();
        for i in 0..10u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
            }).unwrap();
        }

        // Same range produces same hash
        let h1 = wal.section_hash(0, 10);
        let h2 = wal.section_hash(0, 10);
        assert_eq!(h1, h2);

        // Different range produces different hash
        let h3 = wal.section_hash(0, 5);
        assert_ne!(h1, h3);

        // Empty range produces deterministic hash
        let h4 = wal.section_hash(100, 200);
        let h5 = wal.section_hash(100, 200);
        assert_eq!(h4, h5);
    }

    #[test]
    fn wal_restore_checksums_from_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        // Write entries and capture checksums
        let saved_checksums;
        {
            let mut wal = WriteAheadLog::open(&wal_path).unwrap();
            for i in 0..5u8 {
                wal.append(&WalOp::Put {
                    key: [i; 32],
                    value: vec![i],
                    client_pk: [0u8; 32],
                    client_sig: vec![0u8; 64],
                }).unwrap();
            }
            saved_checksums = wal.checksums_snapshot();
            assert_eq!(saved_checksums.len(), 5);
        }

        // Simulate recovery: open new WAL and restore checksums
        let mut wal2 = WriteAheadLog::open(dir.path().join("test2.wal")).unwrap();
        assert_eq!(wal2.checksum_count(), 0);
        wal2.restore_checksums(saved_checksums.clone());
        assert_eq!(wal2.checksum_count(), 5);
        assert_eq!(wal2.sequence(), 5);

        // Section hash should match original
        let mut wal_orig = WriteAheadLog::open(&wal_path).unwrap();
        wal_orig.load_checksums().unwrap();
        assert_eq!(wal_orig.section_hash(0, 5), wal2.section_hash(0, 5));
    }

    #[test]
    fn wal_load_checksums_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        // Write entries
        {
            let mut wal = WriteAheadLog::open(&wal_path).unwrap();
            for i in 0..5u8 {
                wal.append(&WalOp::Put {
                    key: [i; 32],
                    value: vec![i],
                    client_pk: [0u8; 32],
                    client_sig: vec![0u8; 64],
                }).unwrap();
            }
        }

        // Reopen and load checksums (simulating crash recovery)
        let mut wal2 = WriteAheadLog::open(&wal_path).unwrap();
        assert_eq!(wal2.checksum_count(), 0); // fresh open has no checksums
        wal2.load_checksums().unwrap();
        assert_eq!(wal2.checksum_count(), 5);
        assert_eq!(wal2.sequence(), 5);
    }

    /// YP §19.6 — WalOp::RecordTx round-trips through append + read_all
    /// with valid checksum, so the per-tx fee record reconstructs on boot.
    #[test]
    fn wal_record_tx_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("wal.bin");
        let mut wal = WriteAheadLog::open(&wal_path).unwrap();

        let tx_hash = [0xCC; 32];
        // Serialize a TxRecord shape — fee_breakdown stays empty so the
        // test focuses on the WAL plumbing, not on FeeShare-specific
        // edge cases (covered separately by smt::tests).
        let record_bytes = bincode::serialize(&crate::types::TxRecord {
            receiver_wallet_id: [0xAA; 32],
            amount: 1_000_000,
            fee_breakdown: Vec::new(),
            tick: 42,
        }).unwrap();
        wal.append(&WalOp::RecordTx {
            tx_hash,
            record: record_bytes.clone(),
        }).unwrap();

        let ops = WriteAheadLog::read_all(&wal_path).unwrap();
        assert_eq!(ops.len(), 1, "exactly one op should round-trip");
        match &ops[0] {
            WalOp::RecordTx { tx_hash: h, record } => {
                assert_eq!(*h, tx_hash);
                assert_eq!(record, &record_bytes);
            }
            other => panic!("expected RecordTx, got {:?}", other),
        }
    }
}
