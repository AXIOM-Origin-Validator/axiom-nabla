//! KI#43a — exact consumed-state record (write path only).
//!
//! `is_state_consumed` is a bloom and FAILS CLOSED: a false positive
//! permanently blocks the affected wallet's heal (KI#43), and nothing exact
//! exists anywhere to adjudicate the hit. This module is the missing record:
//! one append-only file of raw 32-byte state ids per consumed bloom era, fed
//! from the same insert chokepoint that feeds `consumed_chain`, frozen when
//! the era freezes. It makes a future consumed-bloom hit *adjudicable*
//! (KI#43b: propagation-time rejection) instead of final.
//!
//! Design: `AXIOM_DESIGN_NablaAntiEntropy.md` §12.4.1. Deliberate properties:
//!
//! * **Write path only.** Nothing on the per-registration hot path reads
//!   these files — the A12 gate stays a bloom lookup. `contains` exists for
//!   tests and the future 43b adjudication.
//! * **Era-completeness is a per-file, locally-honest claim.** A frozen era
//!   file counts COMPLETE only if this store observed the era from its
//!   opening rotation and was never re-opened (restarted) inside it
//!   (`start_observed && gaps == 0`). Absence of a record is only meaningful
//!   evidence when the era is complete — §12.4's first constraint.
//! * **Duplicates are harmless.** WAL replay after a restart may re-feed
//!   inserts; membership is set-semantics, appends are idempotent for the
//!   consumer. No dedup on the write path.
//! * **No new retention machinery.** Files rotate when the consumed bloom
//!   chain rotates (the caller passes the era id the bloom insert landed in),
//!   and they are never expired — same retain-forever rule as the consumed
//!   eras themselves (expiry would forget marks exactly where they are
//!   load-bearing).

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// One record = one raw 32-byte state id, concatenated. No framing needed.
const RECORD_BYTES: usize = 32;

/// Per-era sidecar metadata (JSON, one small file per era).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EraMeta {
    pub era_id: u64,
    /// True iff this store was live at the rotation that OPENED the era
    /// (i.e. it wrote the previous era's freeze). A file first created
    /// mid-era can never claim completeness.
    pub start_observed: bool,
    /// Number of times the store was re-opened (node restart) while this era
    /// was active. Each re-open is a window in which consumptions may have
    /// been missed; > 0 disqualifies completeness. WAL replay usually
    /// re-feeds the gap, but "usually" is not a completeness proof.
    pub gaps: u32,
    /// BLAKE3 hex of the era file, set at freeze. Empty while active.
    #[serde(default)]
    pub frozen_blake3: String,
}

impl EraMeta {
    /// §12.4 constraint one: absence-of-record is only evidence when complete.
    pub fn is_complete(&self) -> bool {
        self.start_observed && self.gaps == 0 && !self.frozen_blake3.is_empty()
    }
}

/// Append-only exact consumed-state store. One instance per node; lives in
/// `<data_dir>/consumed_exact/`.
pub struct ConsumedExactStore {
    dir: PathBuf,
    active_era_id: u64,
    active_file: File,
    active_meta: EraMeta,
    /// Records appended since the last `flush()` (telemetry only).
    pending_since_flush: u64,
}

impl ConsumedExactStore {
    fn era_path(dir: &Path, era_id: u64) -> PathBuf {
        dir.join(format!("era_{era_id}.csr"))
    }
    fn meta_path(dir: &Path, era_id: u64) -> PathBuf {
        dir.join(format!("era_{era_id}.meta.json"))
    }

    fn write_meta(dir: &Path, meta: &EraMeta) -> std::io::Result<()> {
        let tmp = Self::meta_path(dir, meta.era_id).with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(meta)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, Self::meta_path(dir, meta.era_id))
    }

    fn read_meta(dir: &Path, era_id: u64) -> Option<EraMeta> {
        let bytes = fs::read(Self::meta_path(dir, era_id)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Conservative open: no continuity proof, no replayed events. Every
    /// resume counts as a gap. Kept for tooling/tests; the node boots via
    /// [`Self::open_at_boot`].
    pub fn open(dir: impl AsRef<Path>, current_era_id: u64) -> std::io::Result<Self> {
        Self::open_at_boot(dir, current_era_id, false, &[])
    }

    /// Boot-recovery open (KI#43a restart-gap fix, 2026-07-29).
    ///
    /// `continuity_proven` — true iff the boot WAL replay was CLEAN
    /// (`NablaNode::wal_replay_clean`): the WAL is then the continuity proof
    /// that nothing was consumed unrecorded while the store was closed, so
    /// this restart does NOT count as a recording gap. Without it, every
    /// coordinated full-mesh restart (routine ops — four happened on
    /// 2026-07-28 alone) would gap the ACTIVE era on every node at once and
    /// leave the mesh unadjudicable until the next rotation, up to 90 days.
    ///
    /// `replayed` — the exact-record events the SMT buffered during snapshot
    /// restore + WAL replay (recording is enabled BEFORE replay in
    /// `NablaNode::open_with_options`). They may span multiple eras if the
    /// downtime or the replayed span crossed a rotation. Events for already-
    /// FROZEN eras are dropped: a frozen file is sealed under its BLAKE3
    /// (if it was complete they are duplicates; if it was not, it honestly
    /// stays incomplete). Duplicates in appendable eras are harmless
    /// (membership semantics).
    pub fn open_at_boot(
        dir: impl AsRef<Path>,
        current_era_id: u64,
        continuity_proven: bool,
        replayed: &[(u64, [u8; 32])],
    ) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;

        // Scan disk: which eras exist, which are sealed.
        let mut on_disk: Vec<u64> = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            if let Some(id) = name
                .strip_prefix("era_")
                .and_then(|s| s.strip_suffix(".csr"))
                .and_then(|s| s.parse::<u64>().ok())
            {
                on_disk.push(id);
            }
        }
        on_disk.sort_unstable();
        let is_frozen = |dir: &Path, id: u64| -> bool {
            Self::read_meta(dir, id)
                .map(|m| !m.frozen_blake3.is_empty())
                .unwrap_or(false)
        };

        // Append replayed events into their eras (skipping sealed ones),
        // creating files as needed. Track which eras we touched/created.
        let mut created: Vec<u64> = Vec::new();
        let mut dropped_frozen = 0usize;
        {
            use std::collections::BTreeMap;
            let mut by_era: BTreeMap<u64, Vec<&[u8; 32]>> = BTreeMap::new();
            for (era, state) in replayed {
                by_era.entry(*era).or_default().push(state);
            }
            for (era, states) in by_era {
                if era > current_era_id {
                    // Cannot happen (replay derives eras ≤ the chain's active
                    // era) — but never manufacture a future era.
                    continue;
                }
                if is_frozen(&dir, era) {
                    dropped_frozen += states.len();
                    continue;
                }
                let existed = on_disk.contains(&era);
                let mut f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(Self::era_path(&dir, era))?;
                for s in states {
                    f.write_all(s.as_slice())?;
                }
                f.sync_data()?;
                if !existed {
                    created.push(era);
                    on_disk.push(era);
                }
            }
            on_disk.sort_unstable();
        }
        if dropped_frozen > 0 {
            log::info!(
                "[KI#43a] boot recovery: {} replayed mark(s) for sealed era(s) dropped (duplicates of frozen content, or honestly-incomplete eras stay incomplete)",
                dropped_frozen
            );
        }
        // Ensure the current era's file exists even with no replayed events.
        if !on_disk.contains(&current_era_id) {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(Self::era_path(&dir, current_era_id))?;
            created.push(current_era_id);
            on_disk.push(current_era_id);
            on_disk.sort_unstable();
        }

        // Meta accounting. A CLEAN replay proves continuity: resumes don't
        // gap, and an era whose file we just created counts start_observed iff
        // its predecessor era is also on disk (the replay/history spans the
        // rotation that opened it). Without the proof: every resume gaps,
        // every created file is a mid-era latecomer.
        for &era in on_disk.iter() {
            if is_frozen(&dir, era) {
                continue;
            }
            let existed_before_boot = !created.contains(&era);
            let mut meta = if existed_before_boot {
                let mut m = Self::read_meta(&dir, era).unwrap_or(EraMeta {
                    era_id: era,
                    start_observed: false,
                    gaps: 0,
                    frozen_blake3: String::new(),
                });
                if !continuity_proven {
                    m.gaps += 1;
                }
                m
            } else {
                EraMeta {
                    era_id: era,
                    // Era 0 is the chain origin — a node creating it under a
                    // clean boot genuinely witnessed the chain's birth (a
                    // latecomer never creates era 0: it has no era-0 events to
                    // replay and only the CURRENT era is force-created). Every
                    // later era needs its predecessor on disk (the history
                    // spans the rotation that opened it).
                    start_observed: continuity_proven
                        && (era == 0 || on_disk.contains(&(era - 1))),
                    gaps: if continuity_proven { 0 } else { 1 },
                    frozen_blake3: String::new(),
                }
            };
            // Seal every era behind the current one.
            if era < current_era_id {
                meta.frozen_blake3 = Self::blake3_of(&Self::era_path(&dir, era))?;
            }
            Self::write_meta(&dir, &meta)?;
        }

        let active_meta = Self::read_meta(&dir, current_era_id)
            .expect("active era meta written above");
        let active_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(Self::era_path(&dir, current_era_id))?;

        Ok(Self {
            dir,
            active_era_id: current_era_id,
            active_file,
            active_meta,
            pending_since_flush: 0,
        })
    }

    fn blake3_of(path: &Path) -> std::io::Result<String> {
        let mut f = File::open(path)?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize().to_hex().to_string())
    }

    /// Append one consumed state id into `era_id`'s file. `era_id` is the era
    /// the sibling `consumed_chain.insert` landed in (the bloom chain's
    /// post-insert ACTIVE era) — passing it in keeps exact-file placement
    /// byte-identical to bloom placement with no second tick→era mapping.
    ///
    /// A forward era jump freezes the outgoing file (fsync + BLAKE3 into its
    /// meta) and opens the next — this store witnessed the rotation, so the
    /// new era opens with `start_observed: true`.
    pub fn record(&mut self, era_id: u64, state_id: &[u8; 32]) -> std::io::Result<()> {
        if era_id < self.active_era_id {
            // Bloom marks with no per-entry tick (recovered `previous_states`)
            // land in the bloom's active era, so the caller can never hand us
            // a past era for those. A past era here means caller misuse.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "consumed_exact: record for past era {era_id} (active {})",
                    self.active_era_id
                ),
            ));
        }
        if era_id > self.active_era_id {
            self.freeze_active()?;
            self.active_era_id = era_id;
            self.active_meta = EraMeta {
                era_id,
                start_observed: true, // we were live at the rotation
                gaps: 0,
                frozen_blake3: String::new(),
            };
            Self::write_meta(&self.dir, &self.active_meta)?;
            self.active_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(Self::era_path(&self.dir, era_id))?;
        }
        self.active_file.write_all(state_id)?;
        self.pending_since_flush += 1;
        Ok(())
    }

    fn freeze_active(&mut self) -> std::io::Result<()> {
        self.active_file.sync_data()?;
        self.active_meta.frozen_blake3 =
            Self::blake3_of(&Self::era_path(&self.dir, self.active_era_id))?;
        Self::write_meta(&self.dir, &self.active_meta)
    }

    /// fsync the active file. Called on the node tick cadence — bounded loss
    /// window, and WAL replay re-feeds anything lost in it.
    pub fn flush(&mut self) -> std::io::Result<u64> {
        self.active_file.sync_data()?;
        let n = self.pending_since_flush;
        self.pending_since_flush = 0;
        Ok(n)
    }

    /// Era ids present on disk (frozen + active).
    pub fn era_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                e.file_name()
                    .to_string_lossy()
                    .strip_prefix("era_")
                    .and_then(|s| s.strip_suffix(".csr"))
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .collect();
        ids.sort_unstable();
        ids
    }

    pub fn meta(&self, era_id: u64) -> Option<EraMeta> {
        if era_id == self.active_era_id {
            return Some(self.active_meta.clone());
        }
        Self::read_meta(&self.dir, era_id)
    }

    /// Exact membership: was `state_id` recorded in `era_id`? NOT on the
    /// registration hot path — tests + future 43b adjudication only.
    pub fn contains(&self, era_id: u64, state_id: &[u8; 32]) -> std::io::Result<bool> {
        let path = Self::era_path(&self.dir, era_id);
        if !path.exists() {
            return Ok(false);
        }
        let bytes = fs::read(path)?;
        Ok(bytes
            .chunks_exact(RECORD_BYTES)
            .any(|c| c == state_id.as_slice()))
    }

    /// KI#43b barrier — whole-history membership: is `state_id` recorded in
    /// ANY era on disk? Run-3 of the model killed fired-era scoping (blooms
    /// are RAM; a restart can wipe the only firing bit while the exact mark
    /// survives), so the barrier question is deliberately era-blind. Off the
    /// registration hot path — adjudication only (~1-in-8000 heals).
    pub fn contains_anywhere(&self, state_id: &[u8; 32]) -> std::io::Result<bool> {
        for era_id in self.era_ids() {
            if self.contains(era_id, state_id)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// KI#43b barrier — is this node's record CLEAN for every era in
    /// `[born_era ..= active]`? Clean = the node was watching, from each era's
    /// opening, with zero gaps — the per-peer half of §12.4.4's acquittal
    /// (TLA+ `OwnComplete(n,e) == watched[n][e] /\ ~gapped[n][e]`). The ACTIVE
    /// era qualifies (frozen is a cross-node transfer claim, not a local one).
    ///
    /// ⚠ KI#199 — AN ABSENT ERA FILE IS CLEAN, NOT DIRTY. This read was
    /// INVERTED and it made the barrier un-acquittable on every real node.
    /// A file exists only for an era that had TRAFFIC (`record()` / a boot
    /// created it); an era in which nothing was consumed leaves no file. The
    /// v1 code (`_ => return false`) therefore read "nothing happened in era
    /// N" as "I wasn't watching era N" and refused every state whose range
    /// crossed a single idle era — which is every state on every node,
    /// constantly (alpha: 114 files across 26,269 eras, longest present run
    /// 13). `BLOOM-FP confirmed` had NEVER been logged anywhere.
    ///
    /// Why an absent era is sound to treat as watched-clean (the invariant
    /// that lets us reconstruct the model's `watched` flag from files alone):
    /// a genuine RECORDING GAP can never hide as an absent era, because it
    /// always leaves a PRESENT-and-unclean era to catch it —
    ///   * a restart INSIDE an era updates that era's file with `gaps += 1`
    ///     (or, under a clean WAL, KI#43a proves continuity and it is not a
    ///     gap — the one case an in-era restart is legitimately clean); and
    ///   * downtime spanning a whole era ends with a boot whose re-entry era
    ///     is created with `start_observed = continuity_proven &&
    ///     on_disk.contains(era-1)` (`open_at_boot`). Its predecessor is
    ///     absent (the downtime), so `start_observed` is FALSE and that era
    ///     reads unclean here.
    /// Every boot sets `active_era_id` to the current era and creates its
    /// file, so the re-entry era is always ≤ active and inside this range.
    /// Hence: absent era ⇒ no boot and no record occurred in it ⇒ the node
    /// was up-and-idle ⇒ watched-clean. Membership (`contains_anywhere`) is
    /// still whole-history and unchanged, so a state this node DID observe
    /// consumed still refuses regardless of era.
    ///
    /// `born_era > active_era_id` yields an empty range ⇒ `true`: the node's
    /// last boot predates x's birth and it has been continuously up-and-idle
    /// since (a reboot would have advanced `active_era_id`), so it genuinely
    /// saw no consumption of a state not yet born. Sound.
    pub fn clean_from(&self, born_era: u64) -> bool {
        for era_id in born_era..=self.active_era_id {
            match self.meta(era_id) {
                // present & clean — watched from opening, no gaps
                Some(m) if m.start_observed && m.gaps == 0 => {}
                // present but dirty — a real gap; refuse (absence of proof)
                Some(_) => return false,
                // ABSENT — up-and-idle era; watched-clean (see the invariant above)
                None => {}
            }
        }
        true
    }

    /// KI#43b barrier — the whole-history cleanliness answer (born_tick = 0):
    /// this node has been recording continuously since the CHAIN ORIGIN (era 0
    /// on disk, watched from its genesis opening, zero gaps through the active
    /// era — idle eras in between are clean, KI#199). Era ids are NODE-LOCAL
    /// (chains rebase), so cross-node the barrier exchanges only this boolean —
    /// never era ids. Prefer [`Self::clean_from`] scoped to x's birth era
    /// (§12.4.4 item 4: an old gap must not poison the mechanism forever);
    /// this is the conservative fallback when the birth era is unknown.
    pub fn clean_whole_history(&self) -> bool {
        self.era_ids().first() == Some(&0) && self.clean_from(0)
    }

    /// Distinct recorded states in an era (test/telemetry helper).
    pub fn era_distinct_count(&self, era_id: u64) -> std::io::Result<usize> {
        let path = Self::era_path(&self.dir, era_id);
        if !path.exists() {
            return Ok(0);
        }
        let bytes = fs::read(path)?;
        let set: HashSet<&[u8]> = bytes.chunks_exact(RECORD_BYTES).collect();
        Ok(set.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn record_freeze_reload_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ConsumedExactStore::open(dir.path(), 0).unwrap();
        store.record(0, &sid(1)).unwrap();
        store.record(0, &sid(2)).unwrap();
        // Era rotation: freezes era 0, opens era 1 with start_observed.
        store.record(1, &sid(3)).unwrap();
        store.flush().unwrap();

        assert!(store.contains(0, &sid(1)).unwrap());
        assert!(store.contains(0, &sid(2)).unwrap());
        assert!(!store.contains(0, &sid(3)).unwrap());
        assert!(store.contains(1, &sid(3)).unwrap());

        let m0 = store.meta(0).unwrap();
        assert!(!m0.frozen_blake3.is_empty(), "era 0 must be frozen");
        let m1 = store.meta(1).unwrap();
        assert!(m1.start_observed, "era 1 opened by a witnessed rotation");
        assert_eq!(m1.gaps, 0);
        // Era 1 is complete only once IT freezes; era 0 was created mid-era
        // (first-ever open) so it can never be complete.
        assert!(!m0.is_complete());

        // Reload (same era): records survive, gap counter bumps.
        drop(store);
        let store2 = ConsumedExactStore::open(dir.path(), 1).unwrap();
        assert!(store2.contains(0, &sid(1)).unwrap());
        assert!(store2.contains(1, &sid(3)).unwrap());
        assert_eq!(store2.meta(1).unwrap().gaps, 1, "restart inside era = gap");
        assert_eq!(store2.era_ids(), vec![0, 1]);
    }

    #[test]
    fn full_era_witnessed_end_to_end_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ConsumedExactStore::open(dir.path(), 4).unwrap();
        // Era 5 opens under our watch (rotation 4→5), closes under our watch
        // (rotation 5→6, no restart between): the only path to COMPLETE.
        store.record(5, &sid(9)).unwrap();
        store.record(6, &sid(10)).unwrap();
        let m5 = store.meta(5).unwrap();
        assert!(m5.is_complete(), "witnessed open + no gaps + frozen");
        assert!(!store.meta(6).unwrap().is_complete(), "era 6 still active");
    }

    #[test]
    fn reopen_across_missed_rotation_freezes_stale_era_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ConsumedExactStore::open(dir.path(), 2).unwrap();
        store.record(2, &sid(7)).unwrap();
        store.flush().unwrap();
        drop(store);
        // Node was down across rotation 2→3: era 2's file freezes on reopen
        // but is disqualified from completeness.
        let store2 = ConsumedExactStore::open(dir.path(), 3).unwrap();
        let m2 = store2.meta(2).unwrap();
        assert!(!m2.frozen_blake3.is_empty());
        assert!(!m2.is_complete());
        assert!(store2.contains(2, &sid(7)).unwrap(), "records survive");
        assert_eq!(store2.active_era_id, 3);
    }

    /// The 2026-07-29 restart-gap fix: a restart with a CLEAN WAL replay
    /// (continuity proven) does NOT bump the gap counter, and the replayed
    /// marks land in their era files — so routine coordinated restarts no
    /// longer destroy active-era completeness mesh-wide.
    #[test]
    fn clean_restart_with_replay_is_not_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        // Genesis-shaped first boot: era 0, clean (empty) WAL.
        let mut store = ConsumedExactStore::open_at_boot(dir.path(), 0, true, &[]).unwrap();
        assert!(store.meta(0).unwrap().start_observed, "era 0 = chain origin");
        store.record(0, &sid(1)).unwrap();
        store.flush().unwrap();
        drop(store);

        // Clean restart: replay re-derives mark 1 (duplicate, harmless) plus
        // mark 2 that only lived in the WAL tail.
        let store2 = ConsumedExactStore::open_at_boot(
            dir.path(), 0, true, &[(0, sid(1)), (0, sid(2))]).unwrap();
        let m0 = store2.meta(0).unwrap();
        assert_eq!(m0.gaps, 0, "clean restart must NOT count as a gap");
        assert!(m0.start_observed);
        assert!(store2.contains(0, &sid(2)).unwrap(), "replayed mark recorded");

        // Torn-WAL restart: same call with continuity_proven=false gaps it.
        drop(store2);
        let store3 = ConsumedExactStore::open_at_boot(dir.path(), 0, false, &[]).unwrap();
        assert_eq!(store3.meta(0).unwrap().gaps, 1, "torn WAL = gap");
    }

    /// A clean replay spanning a rotation the node slept through: the old
    /// era's replayed marks land in its (unfrozen) file, it freezes complete,
    /// and the new era opens start_observed (the WAL witnessed the boundary).
    #[test]
    fn clean_replay_across_rotation_keeps_completeness() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ConsumedExactStore::open_at_boot(dir.path(), 0, true, &[]).unwrap();
        store.record(0, &sid(1)).unwrap();
        store.flush().unwrap();
        drop(store);

        // Down across the 0→1 rotation; clean WAL replay re-derives an
        // era-0 mark and an era-1 mark.
        let store2 = ConsumedExactStore::open_at_boot(
            dir.path(), 1, true, &[(0, sid(2)), (1, sid(3))]).unwrap();
        let m0 = store2.meta(0).unwrap();
        assert!(m0.is_complete(),
            "era 0: origin + no gaps + frozen at boot roll-forward = complete");
        assert!(store2.contains(0, &sid(2)).unwrap(), "pre-rotation replay mark landed");
        let m1 = store2.meta(1).unwrap();
        assert!(m1.start_observed, "era 1 opened under WAL continuity");
        assert_eq!(m1.gaps, 0);
        assert!(store2.contains(1, &sid(3)).unwrap());

        // Replayed marks aimed at a SEALED era are dropped, never appended
        // (the frozen BLAKE3 stays valid).
        let frozen_hash = m0.frozen_blake3.clone();
        drop(store2);
        let store3 = ConsumedExactStore::open_at_boot(
            dir.path(), 1, true, &[(0, sid(9))]).unwrap();
        assert!(!store3.contains(0, &sid(9)).unwrap(), "sealed era not appended");
        assert_eq!(store3.meta(0).unwrap().frozen_blake3, frozen_hash);
    }

    #[test]
    fn past_era_record_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ConsumedExactStore::open(dir.path(), 3).unwrap();
        store.record(4, &sid(1)).unwrap();
        assert!(store.record(3, &sid(2)).is_err());
    }

    /// KI#199 — THE regression test. A node that recorded in eras {0, 5},
    /// both watched-clean, with eras 1-4 IDLE (no file, no traffic), is CLEAN.
    /// This is the shape of every real recorder (alpha: 114 files, longest
    /// present run 13) and the v1 `clean_from` returned FALSE for it, so the
    /// barrier could never acquit. MUTATION GUARD: change the absent-era arm
    /// in `clean_from` back to `None => return false` and THIS test goes red
    /// (the whole KI#199 fix in one assertion).
    #[test]
    fn idle_eras_do_not_break_cleanliness_ki199() {
        let dir = tempfile::tempdir().unwrap();
        // A continuously-running node that happened to consume in era 0, then
        // was idle through 1..=4, then consumed again in era 5. `record`'s
        // forward jump marks each opened era start_observed (we were live at
        // the rotation), so eras 0 and 5 are clean; 1..=4 have NO file.
        let mut store = ConsumedExactStore::open_at_boot(dir.path(), 0, true, &[]).unwrap();
        store.record(0, &sid(1)).unwrap();
        store.record(5, &sid(2)).unwrap();
        store.flush().unwrap();

        assert_eq!(store.era_ids(), vec![0, 5], "eras 1-4 are idle — no files");
        assert!(store.meta(0).unwrap().start_observed && store.meta(0).unwrap().gaps == 0);
        assert!(store.meta(5).unwrap().start_observed && store.meta(5).unwrap().gaps == 0);

        // The whole-history answer (born_tick = 0) must acquit despite the
        // four idle eras. THIS is what never worked before KI#199.
        assert!(store.clean_from(0), "idle eras 1-4 must not read as recording gaps");
        assert!(store.clean_whole_history(), "whole-history clean over idle eras");
        // Birth-era scoping past an early era is likewise clean.
        assert!(store.clean_from(3), "born-era scoped clean across idle 3,4");
    }

    /// KI#199 — the safety half: a REAL gap (a present era that was NOT
    /// watched from its opening, e.g. a mid-era torn-WAL restart) must still
    /// refuse, and born-era scoping must let a node vouch for a state born
    /// AFTER that gap (§12.4.4 item 4 — one old scar must not poison forever).
    #[test]
    fn real_gap_refuses_but_birth_era_scoping_recovers_ki199() {
        let dir = tempfile::tempdir().unwrap();
        // Era 0 recorded clean, then a torn-WAL restart INSIDE era 0 → gap.
        let mut store = ConsumedExactStore::open_at_boot(dir.path(), 0, true, &[]).unwrap();
        store.record(0, &sid(1)).unwrap();
        store.flush().unwrap();
        drop(store);
        let mut store = ConsumedExactStore::open_at_boot(dir.path(), 0, false, &[]).unwrap();
        assert_eq!(store.meta(0).unwrap().gaps, 1, "torn WAL inside era 0 = gap");
        // Later, clean activity in era 4.
        store.record(4, &sid(2)).unwrap();
        store.flush().unwrap();

        // Whole history is poisoned by era 0's gap — correctly refuses.
        assert!(!store.clean_from(0), "an unclean era 0 poisons the whole-history answer");
        assert!(!store.clean_whole_history());
        // But a state BORN in era 4 (after the gap) can be vouched for: the
        // range [4..=4] skips the old scar entirely.
        assert!(store.clean_from(4), "born-era scoping skips the pre-birth gap");
    }
}
