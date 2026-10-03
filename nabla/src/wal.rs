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
use std::sync::atomic::{AtomicU64, Ordering};

/// KI#248 / RULE 3 §2 — WAL reads that met an entry with NO (or a cut-short)
/// checksum and REFUSED it (not replayed, `clean = false`). Cumulative per
/// process and per READ: the periodic audits re-read the file, so one
/// persistent torn tail counts once per read — non-zero means "a checksum-less
/// entry exists / existed", the growth rate is the audit cadence. On `/status`
/// as `wal_checksum_missing_refused`.
static WAL_CHECKSUM_MISSING_REFUSED: AtomicU64 = AtomicU64::new(0);

/// `/status wal_checksum_missing_refused` (KI#248).
pub fn wal_checksum_missing_refused_total() -> u64 {
    WAL_CHECKSUM_MISSING_REFUSED.load(Ordering::Relaxed)
}

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
        /// KI#73 — the k=3 seq attestation for THIS head.
        ///
        /// Recovery is snapshot-then-WAL-replay. Without this field, a head
        /// committed after the last snapshot came back unattestable: the
        /// snapshot restored the OLD head's proof, replay `put` installed the
        /// NEWER head, and `put`'s KI#38 lock-step DELETED that proof because
        /// the tx_hash changed — with nothing to re-establish it. The node then
        /// held a head it could not serve (`seq-unattested proof=ABSENT`) while
        /// its higher seq stopped it adopting anyone else's: permanent
        /// single-node divergence that survived every restart, because each
        /// restart replayed the same WAL. KI#38 persisted proofs in
        /// `NablaSnapshot.seq_proofs` and stopped at that boundary.
        ///
        /// APPENDED LAST ON PURPOSE: bincode is positional. `None` is the
        /// honest value for a put with no attestation (group wallets, the
        /// advance-on-proof bridge's intermediate P), NOT a compat default —
        /// those heads genuinely have no proof to carry.
        seq_proof: Option<crate::types::SeqProof>,
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
    /// ForkSettlement §2.4 [R19, R27] — one origin record (an
    /// `OriginLedgerEntry`: the whole verified send leg + `first_seen_secs` +
    /// `contested`), appended when `record_verified_leg` creates it (a send leg)
    /// — and again when record-AE UPGRADES it in place (§9o [R58]). Heads
    /// adopted from flood/AE are never WAL-logged, so without this a crash
    /// would lose every record since the last snapshot. Carries
    /// `first_seen_secs` and `contested` VERBATIM; replay is
    /// `restore_origin_entry` (verbatim; the LAST copy of the same leg wins
    /// since W1 — an upgrade) — never `put()`, never a
    /// `contested` recompute (R24/R27). TYPED field, not a `Vec<u8>` blob:
    /// strict decode, the `Put.seq_proof` precedent — a record in another
    /// shape stops replay (clean = false), it is never mis-read.
    ///
    /// APPENDED LAST ON PURPOSE: `WalOp` is bincode-positional (the variant
    /// index is the tag) and `type_byte` is folded into every checksum.
    OriginRecord {
        tx_hash: [u8; 32],
        entry: crate::types::OriginLedgerEntry,
    },
    /// Fork Settlement W7b (spec R52c) — one REDEEM record (a verified redeem
    /// leg + `first_seen_secs` + `contested`), appended when
    /// `record_verified_leg` creates it in the SEPARATE redeem ledger (never an
    /// origin, R5). `id` = `((receiver_pk, consumed), cheque_txid)`. Same rules
    /// as `OriginRecord`: verbatim, replay = `restore_redeem_entry`
    /// (last copy of the same leg wins — W1 upgrade; never a recompute —
    /// R24/R27), typed + strict decode.
    ///
    /// APPENDED LAST ON PURPOSE (type byte 10): bincode-positional.
    RedeemRecord {
        id: crate::smt::RedeemRecordId,
        entry: crate::types::OriginLedgerEntry,
    },
}

/// YPX-009 §12 — THE builder of a WAL entry checksum:
/// `BLAKE3("AXIOM_WAL" ‖ seq_le ‖ type_byte ‖ payload)`, where `payload` is the
/// entry's raw bincode bytes exactly as written to / read from disk.
///
/// KI#55 (Pattern 1, one builder per bound value): this preimage was assembled
/// INLINE at four sites (`append`, `read_all_with_report`, `compact`,
/// `truncate_at`). A one-byte drift between the write and read copies makes
/// every existing WAL replay as corrupt (`clean == false`, re-sync from peers),
/// and no round-trip test could see it — both sides agree with themselves.
/// Every site calls this; the guard is the Python-computed KAT in
/// `tests::ki55_wal_entry_checksum_kat` + the on-disk anchor beside it.
fn wal_entry_checksum(seq: u64, entry_type: u8, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_WAL");
    hasher.update(&seq.to_le_bytes());
    hasher.update(&[entry_type]);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
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
            WalOp::OriginRecord { .. } => 9,
            WalOp::RedeemRecord { .. } => 10,
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

        // YPX-009 §12: BLAKE3 checksum for integrity auditing (one builder, KI#55).
        let checksum = wal_entry_checksum(self.sequence, op.type_byte(), &bytes);

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

    /// KI#43a — like [`Self::read_after_snapshot`], plus a continuity report:
    /// `clean == false` iff the read stopped EARLY (truncated final entry,
    /// checksum mismatch, or corrupt entry) — i.e. the WAL's tail is lost and
    /// the replayed ops do NOT provably cover everything up to the crash.
    /// The exact consumed-state store uses this to decide whether a restart
    /// counts as a recording gap (`AXIOM_DESIGN_NablaAntiEntropy.md` §12.4.1):
    /// clean replay ⇒ the era file re-derives completely ⇒ NOT a gap.
    pub fn read_after_snapshot_with_report(
        path: impl AsRef<Path>,
        snapshot_tick: u64,
    ) -> Result<(Vec<WalOp>, bool), NablaError> {
        let (ops, clean, _found) =
            Self::read_after_snapshot_reporting_marker(path, snapshot_tick)?;
        Ok((ops, clean))
    }

    /// As `read_after_snapshot_with_report`, plus whether the snapshot marker
    /// was located. See the KI#73 note below for why that matters.
    pub fn read_after_snapshot_reporting_marker(
        path: impl AsRef<Path>,
        snapshot_tick: u64,
    ) -> Result<(Vec<WalOp>, bool, bool), NablaError> {
        let (all_ops, _checksums, clean) = Self::read_all_with_report(path)?;

        let mut last_snapshot_idx = None;
        for (i, op) in all_ops.iter().enumerate() {
            if let WalOp::Snapshot { tick, .. } = op {
                if *tick == snapshot_tick {
                    last_snapshot_idx = Some(i);
                }
            }
        }
        // KI#73 — report whether the snapshot marker was actually FOUND.
        //
        // `None` is ambiguous and the ambiguity is dangerous: on a fresh node it
        // means "no snapshot, replay everything", but on a node that DID load a
        // snapshot it means the scan stopped early (torn tail, checksum stop, or
        // an undecodable record) before reaching the marker — and replaying
        // `all_ops` then puts PRE-snapshot entries on top of newer snapshot
        // state, silently rolling heads backwards. Replay is a raw `put`; it
        // does not consult `superseded_by`, so nothing downstream catches it.
        // The caller distinguishes the two cases.
        let ops = match last_snapshot_idx {
            Some(idx) => all_ops[idx + 1..].to_vec(),
            None => all_ops,
        };
        Ok((ops, clean, last_snapshot_idx.is_some()))
    }

    /// Read all WAL entries from disk, returning ops and their checksums
    /// (one checksum per op, in order). YPX-009 §12: every entry's checksum is
    /// verified on load; an entry WITHOUT one is refused like a bad one (KI#248
    /// — ~~"legacy entries (without checksums) are accepted with a warning"~~).
    #[allow(clippy::type_complexity)]
    pub fn read_all_with_checksums(path: impl AsRef<Path>) -> Result<(Vec<WalOp>, Vec<(u64, [u8; 32])>), NablaError> {
        Self::read_all_with_report(path).map(|(ops, sums, _clean)| (ops, sums))
    }

    /// Full read with the KI#43a continuity flag (see
    /// [`Self::read_after_snapshot_with_report`]). `clean` is true iff the
    /// reader reached EOF at an entry boundary with every checksum verifying.
    #[allow(clippy::type_complexity)]
    pub fn read_all_with_report(path: impl AsRef<Path>) -> Result<(Vec<WalOp>, Vec<(u64, [u8; 32])>, bool), NablaError> {
        let path = path.as_ref();
        if !path.exists() {
            // No WAL at all is a FRESH boot, not a torn one — clean.
            return Ok((Vec::new(), Vec::new(), true));
        }

        let file = File::open(path)
            .map_err(|e| NablaError::WalError(format!("failed to open WAL for read: {e}")))?;

        let mut reader = BufReader::new(file);
        let mut ops = Vec::new();
        let mut checksums = Vec::new();
        let mut len_buf = [0u8; 4];
        let mut sequence: u64 = 0;
        let mut clean = true;

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
                    clean = false;
                    break;
                }
                Err(e) => {
                    return Err(NablaError::WalError(format!(
                        "failed to read WAL entry payload: {e}"
                    )));
                }
            }

            // YPX-009 §12: every entry carries its 32-byte checksum, and it is
            // verified before the op is accepted.
            //
            // KI#248 (owner ruling 2026-10-02) — ~~"If missing (legacy WAL),
            // accept with warning."~~ WRONG: pre-mainnet there is no legacy WAL
            // (no backward compat), and every writer of this build — `append`,
            // `compact`, `truncate_at` — writes the checksum. An entry whose
            // checksum is absent or cut short is a TORN TAIL (a crash between
            // the payload write and the checksum write): it used to replay
            // UNVERIFIED with `clean` still true, so the restart was not even
            // counted as a gap. Now it is refused exactly like a bad checksum —
            // not replayed, `clean = false`, read stops — and COUNTED
            // (`/status wal_checksum_missing_refused`).
            let mut checksum_buf = [0u8; 32];
            match io::Read::read_exact(&mut reader, &mut checksum_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    WAL_CHECKSUM_MISSING_REFUSED.fetch_add(1, Ordering::Relaxed);
                    log::warn!(
                        "[KI#248] WAL entry at sequence {} has NO checksum (torn tail) — \
                         REFUSED, not replayed; replay stops here (clean = false)",
                        sequence
                    );
                    clean = false;
                    break;
                }
                Err(e) => {
                    return Err(NablaError::WalError(format!(
                        "failed to read WAL entry checksum: {e}"
                    )));
                }
            }

            match bincode::deserialize::<WalOp>(&payload) {
                Ok(op) => {
                    let expected = wal_entry_checksum(sequence, op.type_byte(), &payload);
                    if checksum_buf != expected {
                        log::warn!(
                            "WAL checksum mismatch at sequence {} — corruption detected",
                            sequence
                        );
                        // YPX-009 §12.7: discard from this point, re-sync from peers.
                        clean = false;
                        break;
                    }
                    checksums.push((sequence, checksum_buf));
                    ops.push(op);
                    sequence += 1;
                }
                Err(e) => {
                    log::warn!("WAL corrupt entry — stopping replay: {e}");
                    clean = false;
                    break;
                }
            }
        }

        Ok((ops, checksums, clean))
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
                let checksum = wal_entry_checksum(new_seq as u64, op.type_byte(), &bytes);
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
    /// Deep scan, and RECOVER what it finds (ghost audit G11).
    ///
    /// `audit_deep` detects and cannot act — it takes `&self`. That was the
    /// pre-KI#4 shape left unfixed in the sibling of `audit_recent`, and it
    /// mattered because the two cover different ranges: `audit_recent` samples
    /// one entry from the last `WAL_AUDIT_WINDOW` entries and never reaches an
    /// old one, while this samples across the WHOLE file. A corrupted OLD entry
    /// was detectable nowhere else and was never acted on.
    ///
    /// Recovery was deliberately withheld until KI#74 was fixed: the checksum
    /// machinery was reporting corruption on a healthy mesh (19 warnings per
    /// roll), and truncating on a false positive would have converted a bug in
    /// our own sequence accounting into real data loss. With the append cursor
    /// now taken from the file, a full 10-node roll reports ZERO warnings, so
    /// the signal is trustworthy and the consequence can be wired.
    ///
    /// Truncates at the reader's CLEAN PREFIX — see the note in the body for
    /// why `min(corrupted)` is the wrong point and would loop forever. No more
    /// destructive than the status quo: `read_all_*` stops at the first bad
    /// entry, so everything past it is already unreachable on read. Returns the
    /// number of entries kept.
    pub fn audit_deep_and_recover(&mut self) -> Result<Option<u64>, NablaError> {
        let corrupted = self.audit_deep()?;
        if corrupted.is_empty() {
            return Ok(None);
        }

        // Truncate at the READER'S CLEAN PREFIX, not at `min(corrupted)`.
        //
        // `audit_deep` reports "sampled sequences that do not verify against
        // disk", and `read_all_with_checksums` STOPS at the first bad entry —
        // so every sampled sequence past the break reads as missing. With a
        // corruption at entry 3 and sampling every 4th, it reports [4, 8, 12,
        // 16]: the real corruption is not in the list at all. Truncating at
        // min=4 would KEEP entry 3, the next read would break at 3 again, and
        // the scan would truncate forever without ever fixing anything.
        //
        // The clean prefix — how many entries read back verified — is exactly
        // the recovery point: it keeps every good entry and drops the corrupt
        // one plus everything the reader could not reach anyway.
        let (_, clean_checksums) = Self::read_all_with_checksums(&self.path)?;
        let clean_len = clean_checksums.len() as u64;
        log::warn!(
            "WAL deep scan: {} sampled entr(ies) {:?} do not verify — truncating \
             at the clean prefix ({} entries). Everything past it was already \
             unreachable on read (the reader stops at the first bad entry); \
             subsequent ticks rebuild from peer gossip. Repeat truncations are a \
             hardware-error signal.",
            corrupted.len(), corrupted, clean_len,
        );
        self.truncate_at(clean_len)?;
        Ok(Some(clean_len))
    }

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
        // KI#78 — persist the truncation as a durable marker BEFORE any file
        // surgery. The rewrite below produces a CLEAN file, so without the
        // marker the next boot's replay reads continuity PROVEN over a WAL
        // with a hole in it, and the exact consumed-state record (§12.4.1)
        // treats the restart as not-a-gap — an era with missing entries
        // adjudicated as complete. Ordering is fail-closed both ways: a crash
        // after the marker but before the rewrite leaves the corrupt tail
        // (replay stops unclean anyway; the marker only over-flags, the safe
        // direction), and a marker-write FAILURE aborts the truncation — a
        // truncated WAL with no marker is exactly the clean-reading hole
        // this exists to close. Consumed at boot only after the gap is
        // durably recorded (nabla_node::init_consumed_exact).
        {
            let marker = Self::truncation_marker_path_for(&self.path);
            let mut f = File::create(&marker).map_err(|e| {
                NablaError::WalError(format!("truncate_at: marker create: {e}"))
            })?;
            f.write_all(format!("truncated_at_seq={seq}\n").as_bytes())
                .map_err(|e| NablaError::WalError(format!("truncate_at: marker write: {e}")))?;
            f.sync_all()
                .map_err(|e| NablaError::WalError(format!("truncate_at: marker sync: {e}")))?;
        }
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
                // KI#248: the reader returns exactly one VERIFIED checksum
                // per op (a checksum-less entry is refused, never returned),
                // so the kept checksums are parallel to the kept ops. The old
                // "recompute" fallback existed only for legacy checksum-less
                // entries; a missing one now is an invariant break — fail.
                let checksum = keep_checksums.get(idx).map(|(_, c)| *c).ok_or_else(|| {
                    NablaError::WalError(format!(
                        "truncate_at: no verified checksum for kept entry {idx} (KI#248 invariant)"
                    ))
                })?;
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

    /// KI#78 — the durable truncation marker lives beside the WAL file
    /// (`<wal>.truncated`). Presence means a `truncate_at` ran since the
    /// marker was last consumed; the content (the truncation seq) is
    /// forensic only.
    fn truncation_marker_path_for(wal_path: &Path) -> PathBuf {
        let mut os = wal_path.as_os_str().to_os_string();
        os.push(".truncated");
        PathBuf::from(os)
    }

    /// KI#78 — has this WAL been truncated since the marker was last
    /// consumed? Boot ORs this into `wal_replay_clean = false` so a
    /// recovered (rewritten-clean) WAL still counts the restart as a
    /// recording gap.
    pub fn truncation_marker_present(wal_path: &Path) -> bool {
        Self::truncation_marker_path_for(wal_path).exists()
    }

    /// KI#78 — consume the truncation marker. Call ONLY after the recording
    /// gap it signals has been durably recorded (the exact consumed-state
    /// store's era meta) — consuming earlier re-creates the clean-reading
    /// hole. Absent marker is a no-op; a failed removal only over-flags a
    /// gap on the next boot (the safe direction).
    pub fn clear_truncation_marker(&self) -> Result<(), NablaError> {
        let marker = Self::truncation_marker_path_for(&self.path);
        match fs::remove_file(&marker) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(NablaError::WalError(format!("clear truncation marker: {e}"))),
        }
    }

    /// YPX-009 §12: Restore checksums from a snapshot (fast audit recovery).
    ///
    /// KI#74 — the append cursor comes from the **FILE**, never from the
    /// snapshot.
    ///
    /// This used to do `self.sequence = checksums.last().seq + 1`. A snapshot's
    /// `wal_checksums` describe the WAL **as it was at snapshot time**, and the
    /// file keeps growing afterwards. So every restart where the WAL had grown
    /// past the last snapshot set the cursor BEHIND the file's real end, and
    /// the next append was written with a sequence number for a position it was
    /// not at. The checksum covers `("AXIOM_WAL", seq, type, payload)`, so that
    /// record — and every record after it — could never verify again. The audit
    /// then truncated the tail, DISCARDING everything committed since the last
    /// snapshot.
    ///
    /// Observed in production as 2 warnings per node on almost every boot since
    /// 2026-07-31 (69 events across 43 boots on alpha). Harmless on an idle
    /// mesh because the post-snapshot window is empty; under load it silently
    /// loses committed state, the same damage class as KI#73.
    ///
    /// The snapshot checksums are still restored — they are audit REFERENCE
    /// data, which is what makes recovery fast. Only the cursor changed source.
    /// KI#81 — rebuild the audit reference (in-memory checksums) and the
    /// append cursor from the FILE. The file is the ONLY truth at boot.
    ///
    /// This replaces `restore_checksums(snapshot.wal_checksums)`. The
    /// snapshot's list was captured BEFORE `compact()` renumbered the file
    /// from 0 (`take_snapshot` builds the snapshot first, compacts after),
    /// so on every boot the audit inherited a reference describing a file
    /// that no longer existed. The first `audit_recent` then sampled a stale
    /// entry, manufactured "corruption" on a file boot itself had just read
    /// CLEAN, and the recovery truncated GOOD records — one false truncation
    /// per restart-under-traffic, self-healing (truncate_at rebuilds the
    /// list from the file), which is exactly why it fired once and went
    /// quiet. KI#74 fixed the CURSOR side of this; the list was the sibling.
    ///
    /// The checksum list comes from the verifying read (clean prefix —
    /// records past a torn/corrupt point cannot verify and are the existing
    /// torn-tail path's job). The CURSOR still comes from the frame-walk
    /// (KI#74): it must be the file's real end even when content fails
    /// verification, or the next append lands mid-file.
    pub fn rebuild_checksums_from_file(&mut self) -> Result<(), NablaError> {
        let (_, sums) = Self::read_all_with_checksums(&self.path)?;
        self.checksums = sums;
        self.sequence = Self::count_entries(&self.path)?;
        Ok(())
    }

    /// Number of framed records in the WAL, by walking length prefixes only.
    ///
    /// Deliberately does NOT verify checksums: this answers "where does the
    /// next append go?", and that must be the file's real end even when the
    /// existing content fails verification (KI#74). A torn final record — a
    /// length prefix whose payload is short — is not counted, matching the
    /// reader, and is handled by the existing torn-tail path.
    fn count_entries(path: &Path) -> Result<u64, NablaError> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(NablaError::WalError(format!("count_entries: open: {e}"))),
        };
        let mut reader = io::BufReader::new(file);
        let mut len_buf = [0u8; 4];
        let mut count: u64 = 0;
        loop {
            match io::Read::read_exact(&mut reader, &mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(NablaError::WalError(format!("count_entries: len: {e}"))),
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            if io::Read::read_exact(&mut reader, &mut payload).is_err() {
                break; // torn tail — not a whole record
            }
            // KI#248 — the trailing 32-byte checksum is MANDATORY in the
            // framing (~~"optional"~~): a record whose checksum is absent or
            // short is a torn tail, not a whole record — counted neither here
            // nor by the reader.
            let mut checksum_buf = [0u8; 32];
            if io::Read::read_exact(&mut reader, &mut checksum_buf).is_err() {
                break;
            }
            count += 1;
        }
        Ok(count)
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

}

#[cfg(test)]
mod tests {
    use super::*;

    // ── KI#55 (Pattern 1) — ONE builder for the `AXIOM_WAL` entry checksum ──
    //
    // The constants below were computed in Python (`blake3`) from the YPX-009
    // §12 layout `BLAKE3("AXIOM_WAL" ‖ seq_le ‖ type_byte ‖ payload)` — NOT from
    // this crate — so a builder that drifts by one byte turns these red even
    // though every round-trip test (which agrees with itself) stays green.

    /// `TxRedeemed { tx_hash: [7; 32] }` bincode = `06000000 ‖ 07×32` (type 6).
    fn kat_redeemed_op() -> WalOp { WalOp::TxRedeemed { tx_hash: [7; 32] } }
    const KAT_WAL_REDEEMED_SEQ0: &str = "304fc5740dbc2dd507a55dfaebb89cc0cd1c8f9753e2b8e1bc282116067cd817";
    const KAT_WAL_REDEEMED_SEQ7: &str = "cae6f683abc2710f0855420e811434d1952454fcd6e305a5fcaee41d61fb3a58";

    /// Step-0 anchor (KI#55): the bytes the WRITE path (`append`) puts on disk
    /// and the READ path (`read_all_with_report`) accepts equal the
    /// independently computed constant — at seq 0 and seq 7. Written and run
    /// GREEN against the four inline copies BEFORE they were folded into
    /// `wal_entry_checksum`, so "byte-identical" is measured, not inferred.
    /// MUTATION (run 2026-10-02): `wal_entry_checksum` hashes `type` before
    /// `seq` ⇒ red here AND in `ki55_wal_entry_checksum_kat`.
    #[test]
    fn ki55_wal_checksum_on_disk_matches_independent_constant() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("kat.wal");
        {
            let mut wal = WriteAheadLog::open(&wal_path).unwrap();
            for _ in 0..8 { wal.append(&kat_redeemed_op()).unwrap(); }
        }
        let raw = std::fs::read(&wal_path).unwrap();
        // Each entry: [4-byte len][36-byte payload][32-byte checksum] = 72 bytes.
        assert_eq!(raw.len(), 8 * 72);
        assert_eq!(hex::encode(&raw[4 + 36..72]), KAT_WAL_REDEEMED_SEQ0, "append, seq 0");
        assert_eq!(hex::encode(&raw[raw.len() - 32..]), KAT_WAL_REDEEMED_SEQ7, "append, seq 7");
        let (ops, sums, clean) = WriteAheadLog::read_all_with_report(&wal_path).unwrap();
        assert!(clean, "read path accepts the on-disk checksums");
        assert_eq!((ops.len(), sums.len()), (8, 8));
        assert_eq!(hex::encode(sums[7].1), KAT_WAL_REDEEMED_SEQ7, "read, seq 7");
    }

    /// KAT for the builder itself: seq 7, type 0x03, payload `01020304`
    /// (kat.py, Python `blake3`). MUTATION (run 2026-10-02): swap the `seq` /
    /// `type` order inside `wal_entry_checksum` ⇒ red (and the on-disk anchor
    /// above red), while every round-trip test stays green.
    #[test]
    fn ki55_wal_entry_checksum_kat() {
        assert_eq!(hex::encode(wal_entry_checksum(7, 0x03, &[1, 2, 3, 4])),
            "62f9fd8be7d0ceef5eda435e63522c418d6b403455812b0323d58424c14f54fa");
    }

    // ── ForkSettlement wave 3 S4 — `WalOp::OriginRecord` [R19, R27] ─────────

    fn origin_entry(seed: u8, first_seen_secs: u64, contested: bool) -> ([u8; 32], crate::types::OriginLedgerEntry) {
        let leg = crate::types::test_legs::genuine_send_leg(
            &crate::types::test_legs::wallet(seed), [0x01; 32], 5,
            "p@axiom.internal/0123456789", 400, 1, 3,
        );
        (leg.tx_hash, crate::types::OriginLedgerEntry { leg, first_seen_secs, contested })
    }

    /// The op round-trips VERBATIM (`first_seen_secs` and `contested` included)
    /// through append → checksummed read, under its own type byte 9, and the
    /// variant sits LAST (bincode tag 9 — the positional contract).
    /// MUTATION (run 2026-09-28): give it an existing type byte (8) ⇒ red.
    #[test]
    fn wal_origin_record_round_trips_verbatim_last_variant() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");
        let (tx, entry) = origin_entry(0x71, 4242, true);
        let op = WalOp::OriginRecord { tx_hash: tx, entry: entry.clone() };
        assert_eq!(op.type_byte(), 9);
        assert_eq!(&bincode::serialize(&op).unwrap()[..4], &9u32.to_le_bytes(), "appended LAST");
        {
            let mut wal = WriteAheadLog::open(&wal_path).unwrap();
            wal.append(&op).unwrap();
            wal.append(&WalOp::TxRedeemed { tx_hash: [7; 32] }).unwrap();
        }
        let (ops, sums, clean) = WriteAheadLog::read_all_with_report(&wal_path).unwrap();
        assert!(clean);
        assert_eq!(sums.len(), 2, "both checksummed");
        match &ops[0] {
            WalOp::OriginRecord { tx_hash, entry: e } => {
                assert_eq!(tx_hash, &tx);
                assert_eq!(e, &entry, "first_seen_secs + contested persist verbatim");
            }
            other => panic!("expected OriginRecord, got {other:?}"),
        }
    }

    /// Fork Settlement W7b — `WalOp::RedeemRecord` round-trips VERBATIM under
    /// its own type byte 10, as the LAST variant (bincode tag 10), and is a
    /// DIFFERENT op from `OriginRecord` (a redeem is never an origin, R5).
    /// MUTATION (run 2026-09-28): give it type byte 9 (OriginRecord's) ⇒ red.
    #[test]
    fn wal_redeem_record_round_trips_verbatim_last_variant() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");
        let leg = crate::types::test_legs::genuine_redeem_leg(
            &crate::types::test_legs::wallet(0x73), [0x04; 32], &crate::types::test_legs::stray_origin([0x74; 32]), 900, 2, 3,
        );
        let id = (leg.key(), leg.tx_hash);
        let entry = crate::types::OriginLedgerEntry { leg, first_seen_secs: 777, contested: true };
        let op = WalOp::RedeemRecord { id, entry: entry.clone() };
        assert_eq!(op.type_byte(), 10);
        assert_eq!(&bincode::serialize(&op).unwrap()[..4], &10u32.to_le_bytes(), "appended LAST");
        {
            let mut wal = WriteAheadLog::open(&wal_path).unwrap();
            wal.append(&op).unwrap();
        }
        let (ops, _sums, clean) = WriteAheadLog::read_all_with_report(&wal_path).unwrap();
        assert!(clean);
        match &ops[0] {
            WalOp::RedeemRecord { id: i, entry: e } => {
                assert_eq!(i, &id);
                assert_eq!(e, &entry, "first_seen_secs + contested persist verbatim");
            }
            other => panic!("expected RedeemRecord, got {other:?}"),
        }
    }

    /// Persisted-shape check for the new op: an `OriginRecord` whose entry is
    /// in another shape (here: the prior-draft `{leg, first_seen_secs}` without
    /// `contested`) is NOT mis-read — replay STOPS there and reports NOT clean
    /// (the restart counts as a recording gap, KI#43a; logged `WAL corrupt
    /// entry — stopping replay`). Nothing after it is replayed.
    /// MUTATION (run 2026-09-28): make the reader skip an undecodable entry
    /// (`sequence += 1; continue;` instead of `break`) ⇒ red (the later op is
    /// read and the bad record is silently dropped).
    #[test]
    fn wal_origin_record_in_another_shape_stops_replay_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");
        let (tx, entry) = origin_entry(0x72, 1, false);
        {
            let mut wal = WriteAheadLog::open(&wal_path).unwrap();
            wal.append(&WalOp::TxRedeemed { tx_hash: [1; 32] }).unwrap();
        }
        // Hand-write the other-shape record: tag 9, tx_hash, leg, first_seen — no `contested`.
        let mut payload = 9u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&bincode::serialize(&(tx, entry.leg.clone(), entry.first_seen_secs)).unwrap());
        {
            use std::io::Write;
            let mut f = OpenOptions::new().append(true).open(&wal_path).unwrap();
            f.write_all(&(payload.len() as u32).to_le_bytes()).unwrap();
            f.write_all(&payload).unwrap();
            f.write_all(&[0u8; 32]).unwrap();
        }
        {
            // As `NablaNode::open` does: position the sequence at the file's
            // real end, so the later op's checksum is valid on its own.
            let mut wal = WriteAheadLog::open(&wal_path).unwrap();
            wal.rebuild_checksums_from_file().unwrap();
            wal.append(&WalOp::TxRedeemed { tx_hash: [2; 32] }).unwrap();
        }
        let (ops, _sums, clean) = WriteAheadLog::read_all_with_report(&wal_path).unwrap();
        assert!(!clean, "an undecodable OriginRecord makes the replay NOT clean");
        assert_eq!(ops.len(), 1, "replay stops AT the bad record — nothing after it is read");
        assert!(!ops.iter().any(|o| matches!(o, WalOp::OriginRecord { .. })), "never mis-read");
    }

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
            seq_proof: None,
        };
        let op2 = WalOp::Put {
            key: [0xBB; 32],
            value: vec![4, 5, 6],
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
            seq_proof: None,
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
            seq_proof: None,
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
            seq_proof: None,
        })
        .unwrap();
        wal.append(&WalOp::Put {
            key: [0x03; 32],
            value: vec![3],
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
            seq_proof: None,
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
                seq_proof: None,
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
                seq_proof: None,
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
                seq_proof: None,
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
                    seq_proof: None,
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
                seq_proof: None,
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
                seq_proof: None,
            }).unwrap();
        }
        wal.append(&WalOp::Snapshot { tick: 50, root: [0xAA; 32] }).unwrap();
        for i in 10..13u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
                seq_proof: None,
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
            seq_proof: None,
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
                seq_proof: None,
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
                seq_proof: None,
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
                seq_proof: None,
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
            seq_proof: None,
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
                seq_proof: None,
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
                seq_proof: None,
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

    /// KI#81 — boot's audit reference comes from the FILE (the only truth
    /// post-compaction). Reopen + rebuild recovers count, cursor, and a
    /// matching section hash.
    #[test]
    fn ki81_checksums_rebuild_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut section_before = None;
        {
            let mut wal = WriteAheadLog::open(&wal_path).unwrap();
            for i in 0..5u8 {
                wal.append(&WalOp::Put {
                    key: [i; 32],
                    value: vec![i],
                    client_pk: [0u8; 32],
                    client_sig: vec![0u8; 64],
                    seq_proof: None,
                }).unwrap();
            }
            section_before = Some(wal.section_hash(0, 5));
        }

        // Reopen (simulating boot) and rebuild from the file.
        let mut wal2 = WriteAheadLog::open(&wal_path).unwrap();
        assert_eq!(wal2.checksum_count(), 0); // fresh open has no checksums
        wal2.rebuild_checksums_from_file().unwrap();
        assert_eq!(wal2.checksum_count(), 5);
        assert_eq!(wal2.sequence(), 5, "cursor = the file's real end");
        assert_eq!(Some(wal2.section_hash(0, 5)), section_before);
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

    /// The ordering is load-bearing: `put` deletes any proof bound to the
    /// superseded tx_hash, so setting the proof BEFORE `put` loses it.
    #[test]
    fn ki73_proof_must_be_set_after_put_not_before() {
        use crate::smt::SparseMerkleTree;
        use crate::types::{NablaEntry, SeqProof, SeqProofSig, WalletStatus};
        let mut wallet_id = [0u8; 32]; wallet_id[0] = 0x77;
        let mk = |s: u8, tx: u8, seq: u64| NablaEntry {
            received_from: None,
            wallet_seq: seq, wallet_id,
            current_state: { let mut a = [0u8; 32]; a[0] = s; a },
            tx_hash: { let mut a = [0u8; 32]; a[0] = tx; a },
            tick: 100 + seq, group_members: None, status: WalletStatus::Normal,
            client_pk: [9u8; 32], client_sig: vec![1u8; 64],
        };
        let pr = SeqProof {
            sender_state: None,
            state_hash: [0xB2; 32], commitment_hash: [0xB2; 32], epoch: 1,
            is_dev_class: false, oods_flag: None, confidence_index: None,
            sigs: vec![SeqProofSig { validator_pk: [2u8; 32],
                                     receipt_commitment_sig: vec![2u8; 64] }],
            required_k: 3,
            preimage: crate::types::test_legs::opaque_redeem_leg(), // wave 2a — test proof, no WITNESS_V2 preimage
            declared: crate::types::test_legs::no_declared(),
        };
        let mut smt = SparseMerkleTree::new();
        smt.put(&mk(0xAA, 0xA1, 21));
        // WRONG order — proof first, then put.
        smt.set_seq_proof(wallet_id, pr);
        smt.put(&mk(0xBB, 0xB2, 22));
        assert!(smt.seq_proof(&wallet_id).is_none(),
            "put MUST drop a proof across a tx_hash change (KI#38 lock-step) — \
             if this ever passes, set-before-put would look correct and the \
             KI#73 fix could be silently reordered into a no-op");
    }

    /// KI#74 REPRODUCTION — a restart after the WAL grew past the last snapshot
    /// mis-numbers every subsequent append.
    ///
    /// `restore_checksums` derives the append cursor from the SNAPSHOT's
    /// `wal_checksums`, which by definition describe the WAL as it was AT
    /// snapshot time. The file keeps growing afterwards. So on boot the cursor
    /// is set behind the file's real end, and the next append is written with a
    /// sequence number for a position it is not at — the checksum covers
    /// `("AXIOM_WAL", seq, type, payload)`, so it can never verify again.
    ///
    /// Effect in production: 2 warnings per node on almost every boot since
    /// 2026-07-31 (69 events across 43 boots on alpha), each followed by the
    /// audit truncating the tail — which DISCARDS every WAL record committed
    /// since the last snapshot.
    #[test]
    fn ki74_restart_after_wal_grew_past_snapshot_misnumbers_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.wal");
        let op = |i: u8| WalOp::Put {
            key: [i; 32], value: vec![i; 8],
            client_pk: [0u8; 32], client_sig: vec![0u8; 64], seq_proof: None,
        };

        {
            let mut wal = WriteAheadLog::open(&path).unwrap();
            for i in 0..5u8 { wal.append(&op(i)).unwrap(); }
            // A snapshot was taken HERE (pre-KI#81 it captured checksums 0..4);
            // the node keeps running and the WAL keeps growing past it.
            for i in 5..10u8 { wal.append(&op(i)).unwrap(); }
        }

        // Restart: recovery rebuilds from the FILE (KI#81); the cursor lands
        // at the file's real end (KI#74), never at the snapshot's.
        let mut wal = WriteAheadLog::open(&path).unwrap();
        wal.rebuild_checksums_from_file().unwrap();
        assert_eq!(wal.sequence(), 10, "KI#74: cursor = file's real end, not snapshot's 5");
        // One more append, exactly as the node does on its first tick.
        wal.append(&op(99)).unwrap();

        let (_, clean) = WriteAheadLog::read_after_snapshot_with_report(&path, 0).unwrap();
        assert!(clean,
            "KI#74: the WAL no longer round-trips — the new record was written \
             with a sequence number for a position it is not at.");
    }

    /// KI#81 REPRODUCTION — the exact production shape: snapshot captures the
    /// checksum list, `compact()` renumbers the file from 0, the process
    /// restarts, and the audit must NOT manufacture corruption on the clean
    /// renumbered file. Pre-fix, boot restored the snapshot's STALE list and
    /// the first `audit_recent` reported corruption within ~10 ticks on a
    /// file boot had just read CLEAN — then `truncate_at` destroyed good
    /// records. Observed on ALL TEN nodes of the 2026-08-08 KI#79 roll.
    /// Mutation check performed during development: installing the stale
    /// pre-compact list instead of rebuilding turns this red.
    #[test]
    fn ki81_stale_snapshot_checksums_cannot_poison_audit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.wal");
        let op = |i: u8| WalOp::Put {
            key: [i; 32], value: vec![i; 8],
            client_pk: [0u8; 32], client_sig: vec![0u8; 64], seq_proof: None,
        };

        {
            let mut wal = WriteAheadLog::open(&path).unwrap();
            for i in 0..5u8 { wal.append(&op(i)).unwrap(); }
            // take_snapshot order: snapshot built (captured the list HERE,
            // pre-KI#81), Snapshot marker appended, compact() renumbers.
            wal.append(&WalOp::Snapshot { tick: 42, root: [0u8; 32] }).unwrap();
            wal.compact().unwrap();
            // post-compact traffic before the restart
            for i in 6..8u8 { wal.append(&op(i)).unwrap(); }
        }

        // Restart through the KI#81 path: rebuild from the FILE.
        let mut wal = WriteAheadLog::open(&path).unwrap();
        wal.rebuild_checksums_from_file().unwrap();
        // post-boot traffic, as under a live soak
        wal.append(&op(99)).unwrap();

        // The audit must stay clean across enough samples to cover the whole
        // window (it picks pseudo-randomly; 50 draws over ≤4 records leaves
        // no un-sampled corner).
        for _ in 0..50 {
            assert_eq!(
                wal.audit_recent().unwrap(),
                None,
                "KI#81: the audit manufactured corruption on a clean file — \
                 the reference list does not match the compacted file"
            );
        }
        assert!(wal.audit_deep().unwrap().is_empty(), "deep scan must agree");
    }

    /// G11 — the deep scan must RECOVER, not just warn.
    ///
    /// `audit_recent` samples only the last `WAL_AUDIT_WINDOW` entries, so a
    /// corrupted OLD entry is detectable only by the deep scan — which took
    /// `&self` and could not act. Alpha hit exactly that on 2026-07-31
    /// (`corrupted entries found: [15, 20]`) with nothing done.
    ///
    /// Corrupts a real entry's stored checksum ON DISK, so the detector has to
    /// find it the way it would in production rather than being handed a
    /// synthetic list.
    #[test]
    fn g11_deep_scan_recovers_a_corrupted_old_entry() {
        use std::io::{Read, Seek, SeekFrom, Write};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.wal");
        let op = |i: u8| WalOp::Put {
            key: [i; 32], value: vec![i; 8],
            client_pk: [0u8; 32], client_sig: vec![0u8; 64], seq_proof: None,
        };

        let mut wal = WriteAheadLog::open(&path).unwrap();
        for i in 0..20u8 { wal.append(&op(i)).unwrap(); }
        assert_eq!(wal.sequence(), 20, "setup: 20 entries");

        // Flip a byte in the STORED CHECKSUM of an early record (an "old" entry
        // that audit_recent's window cannot reach). Walk the framing to find it.
        let target = 3usize;
        {
            let mut f = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
            let mut pos: u64 = 0;
            for idx in 0..=target {
                f.seek(SeekFrom::Start(pos)).unwrap();
                let mut len_buf = [0u8; 4];
                f.read_exact(&mut len_buf).unwrap();
                let len = u32::from_le_bytes(len_buf) as u64;
                if idx == target {
                    // checksum sits right after the payload
                    let csum_at = pos + 4 + len;
                    f.seek(SeekFrom::Start(csum_at)).unwrap();
                    let mut b = [0u8; 1];
                    f.read_exact(&mut b).unwrap();
                    f.seek(SeekFrom::Start(csum_at)).unwrap();
                    f.write_all(&[b[0] ^ 0xFF]).unwrap();
                }
                pos += 4 + len + 32;
            }
        }

        // The detector must SEE that something is wrong …
        let found = wal.audit_deep().unwrap();
        assert!(!found.is_empty(),
            "setup: the deep scan must detect the corruption");
        // … but note it does NOT report the corrupt position itself. The reader
        // stops at entry 3, so every sampled sequence past it reads as missing
        // and the report is [4, 8, 12, 16]. This is exactly why recovery keys
        // on the clean prefix rather than on min(corrupted).
        assert!(!found.contains(&(target as u64)),
            "the detector cannot see the real position — it reports what lies \
             PAST the break ({found:?}); recovery must not trust it as an index");

        // … and now it must ACT on it.
        // Note what the detector actually reports: sampling every 4th entry
        // with the corruption at 3, it returns [4, 8, 12, 16] — the real
        // corruption is NOT in the list, because the reader stops at 3 and
        // everything after reads as missing. Recovering at min(corrupted)=4
        // would keep entry 3 and truncate forever without fixing anything.
        let recovered = wal.audit_deep_and_recover().unwrap();
        assert_eq!(recovered, Some(target as u64),
            "G11: recovery must land on the reader's CLEAN PREFIX ({target}), not \
             on min(corrupted) — audit_recent's window never reaches an old entry, \
             so nothing else would ever act on this");

        // The WAL round-trips again, and the corrupt entry is gone.
        let (ops, clean) = WriteAheadLog::read_after_snapshot_with_report(&path, 0).unwrap();
        assert!(clean, "G11: the WAL must round-trip cleanly after recovery");
        assert_eq!(ops.len(), target, "entries from the corrupt one onward are dropped");
    }

    /// KI#78 — the deep-scan recovery must leave a DURABLE marker: after
    /// `audit_deep_and_recover` the file itself reads clean (that is G11's
    /// job, asserted above), so the marker is the ONLY surviving evidence
    /// that entries are missing. Consuming it clears it.
    #[test]
    fn ki78_truncation_leaves_durable_marker_on_clean_reading_file() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut wal = WriteAheadLog::open(&wal_path).unwrap();
        for i in 0..10u8 {
            wal.append(&WalOp::Put {
                key: [i; 32],
                value: vec![i; 20],
                client_pk: [0u8; 32],
                client_sig: vec![0u8; 64],
                seq_proof: None,
            }).unwrap();
        }
        assert!(
            !WriteAheadLog::truncation_marker_present(&wal_path),
            "no marker before any truncation"
        );

        // Corrupt a payload byte mid-file, then run the real recovery.
        {
            let mut data = std::fs::read(&wal_path).unwrap();
            let pos = data.len() / 2;
            data[pos] ^= 0xFF;
            std::fs::write(&wal_path, &data).unwrap();
        }
        let recovered = wal.audit_deep_and_recover().unwrap();
        assert!(recovered.is_some(), "setup: recovery must have truncated");

        // The G11 shape: the FILE now reads perfectly clean...
        let (_, clean) = WriteAheadLog::read_after_snapshot_with_report(&wal_path, 0).unwrap();
        assert!(clean, "recovered WAL reads clean — which is exactly why the marker must exist");
        // ...so the marker is the only thing standing between a real hole
        // and continuity PROVEN.
        assert!(
            WriteAheadLog::truncation_marker_present(&wal_path),
            "KI#78: truncate_at must persist a durable truncation marker"
        );

        // Consume-once: clearing removes it; clearing again is a no-op.
        wal.clear_truncation_marker().unwrap();
        assert!(!WriteAheadLog::truncation_marker_present(&wal_path));
        wal.clear_truncation_marker().unwrap();
    }

    /// KI#248 (owner ruling 2026-10-02) — an entry with NO checksum (or a
    /// cut-short one) is REFUSED like a bad checksum: not replayed, replay
    /// `clean = false`, counted; the append cursor (`count_entries`) agrees
    /// with the reader. Control: the same two entries written by `append`
    /// alone read back clean — every current writer writes the checksum.
    /// MUTATION (run 2026-10-02): restore the legacy branch (on `UnexpectedEof`
    /// keep going and push the op unverified) ⇒ RED (3 ops, clean).
    #[test]
    fn ki248_checksumless_entry_is_refused_counted_and_unclean() {
        let put = |b: u8| WalOp::Put {
            key: [b; 32], value: vec![b], client_pk: [0u8; 32], client_sig: vec![0u8; 64], seq_proof: None,
        };
        for tail_checksum_bytes in [0usize, 10] {
            let dir = tempfile::tempdir().unwrap();
            let wal_path = dir.path().join("test.wal");
            {
                let mut wal = WriteAheadLog::open(&wal_path).unwrap();
                wal.append(&put(1)).unwrap();
                wal.append(&put(2)).unwrap();
            }
            // Control: every writer of this build wrote a verified checksum.
            let (ops, sums, clean) = WriteAheadLog::read_all_with_report(&wal_path).unwrap();
            assert_eq!((ops.len(), sums.len(), clean), (2, 2, true), "control: append writes checksums");
            // The torn third entry: length + payload, then 0 or 10 checksum bytes.
            {
                let bytes = bincode::serialize(&put(3)).unwrap();
                let mut f = OpenOptions::new().append(true).open(&wal_path).unwrap();
                f.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
                f.write_all(&bytes).unwrap();
                f.write_all(&wal_entry_checksum(2, 0, &bytes)[..tail_checksum_bytes]).unwrap();
            }
            let before = wal_checksum_missing_refused_total();
            let (ops, sums, clean) = WriteAheadLog::read_all_with_report(&wal_path).unwrap();
            assert_eq!(ops.len(), 2, "checksum bytes={tail_checksum_bytes}: the checksum-less entry must NOT replay");
            assert_eq!(sums.len(), 2, "one verified checksum per returned op");
            assert!(!clean, "checksum bytes={tail_checksum_bytes}: a checksum-less tail makes replay UNCLEAN");
            assert!(wal_checksum_missing_refused_total() > before, "the refusal is COUNTED");
            assert_eq!(WriteAheadLog::count_entries(&wal_path).unwrap(), 2,
                "the append cursor does not count a checksum-less record either");
        }
    }
}
