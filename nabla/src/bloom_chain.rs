// AXIOM Nabla — Bloom Chain (YPX-018 §3)
//
// A bloom chain is the sequence of bloom eras over time. There are two
// chains in Nabla: the txid bloom chain (`/query-txid` lookups) and the
// garbage state bloom chain (`/query-garbage-state` lookups). Both share
// the same time-bucketing structure and the same Bloom Age Index.
//
// The chain has exactly one Active era at any time. When the current
// TARDIS tick crosses the active era's `end_tick`, the chain rotates:
// the active era is frozen, a new active era is opened with the next
// `era_id`, and both events are reflected in the Bloom Age Index.
//
// Lookups walk the chain newest-first (since most queries hit recent eras).
//
// Reference:
//   - YPX-018 §3.1 Architecture
//   - YPX-018 §3.5 Active-era write path
//   - YPX-018 §3.6 Lookup flow
//   - Yellow Paper §39.9.5

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bloom_era::{BloomEra, BloomEraMeta, EraStatus, DEFAULT_ERA_DURATION_TICKS};
use crate::types::TxHash;

/// Result of a chain-walk lookup. Distinguishes definite-miss (no era hit)
/// from a bloom hit (which may be a true positive or a false positive — the
/// caller must resolve via the archive layer if needed) and from a hit in a
/// phased-out era.
///
/// In Phase 2 the chain itself only knows about bloom hits and miss; the
/// archive resolution path is wired in Phase 3 alongside the `POST /clara`
/// endpoint and the three-state attestation responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainLookup {
    /// No bloom hit in any walked era. Authoritative negative.
    Miss,
    /// Bloom hit in the named era. May be a true positive or a false positive.
    /// Caller resolves through the archive layer if it cares.
    Hit {
        era_id: u64,
        bloom_root: [u8; 32],
        era_status: EraStatus,
    },
}

/// Sequence of bloom eras, indexed by `era_id`. Always has exactly one Active
/// era; everything else is Frozen, ScheduledPhaseOut, or PhasedOut.
///
/// The chain is generic over what each era's bloom file holds — it's used
/// identically for the txid bloom chain and the garbage state bloom chain.
/// The semantic distinction is at the call site: txid hashes are inserted
/// into the txid chain, state_id hashes go into the garbage chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomChain {
    /// Eras keyed by `era_id`. BTreeMap so iteration is in order.
    eras: BTreeMap<u64, BloomEra>,

    /// Era id of the currently Active era. Exactly one era has Active status.
    active_era_id: u64,

    /// Configured era duration in ticks. Constant per chain.
    era_duration_ticks: u64,

    /// Configured `expected_items` for sizing each new era's bloom file.
    expected_items_per_era: u64,
}

/// KI#44 — **the global era grid.** Era identity is a pure function of the tick,
/// anchored at genesis, so every node computes the same id AND the same
/// boundaries without any coordination. Agreement does not require
/// communication when the function is total over constants.
///
/// Previously era ids were assigned sequentially and NODE-LOCALLY
/// (`next_id = active_era_id + 1` at whatever tick that node happened to
/// rebase at), so two nodes held DIFFERENT tick ranges for the SAME id and
/// `merge_era` could refuse or clobber. On the grid that is impossible.
///
/// Units: `GENESIS_NEWS_ANCHOR` is a unix-second CONSTANT on the tick NUMBERING
/// scale (YPX-003 §1.3.3a) — NOT a tick; a tick is a witnessed artifact needing
/// >= 2 downstream approvals, and none existed at genesis. It is purely a fixed
/// ORIGIN. `era_duration` here is a tick-VALUE span (already projected via
/// `.to_secs()`), never a raw tick COUNT — mixing those was KI#47.
#[inline]
pub const fn era_id_for_tick(tick: u64, era_duration: u64) -> u64 {
    let anchor = axiom_core_logic::genesis_integrity::GENESIS_NEWS_ANCHOR;
    // Ticks at or before the anchor collapse to era 0 (pre-genesis has no era).
    tick.saturating_sub(anchor) / era_duration
}

/// Start tick (inclusive) of grid era `id`. Inverse of [`era_id_for_tick`].
#[inline]
pub const fn era_start_tick(id: u64, era_duration: u64) -> u64 {
    axiom_core_logic::genesis_integrity::GENESIS_NEWS_ANCHOR + id * era_duration
}

impl BloomChain {
    /// Open a brand-new chain with a single Active era starting at `start_tick`.
    pub fn new(start_tick: u64, era_duration_ticks: u64, expected_items_per_era: u64) -> Self {
        // KI#44: id and boundaries come from the GRID, not from start_tick.
        let era_id = era_id_for_tick(start_tick, era_duration_ticks);
        let grid_start = era_start_tick(era_id, era_duration_ticks);
        let end_tick = grid_start + era_duration_ticks;
        let era = BloomEra::open(era_id, grid_start, end_tick, expected_items_per_era);
        let mut eras = BTreeMap::new();
        eras.insert(era_id, era);
        Self {
            eras,
            active_era_id: era_id,
            era_duration_ticks,
            expected_items_per_era,
        }
    }

    /// Convenience: open with default era duration and entry count.
    pub fn new_default(start_tick: u64) -> Self {
        Self::new(start_tick, DEFAULT_ERA_DURATION_TICKS, 1_000_000)
    }

    /// KI#42 step 4 — **per-era union merge**: adopt everything a peer knows.
    ///
    /// This is the primitive the era design was missing. `consumed_state_bloom`
    /// re-arms a fresh node today only because it is a single flat filter that can
    /// be shipped whole (`StatePullResponse.consumed_bloom`); an era chain had no
    /// equivalent, so moving a filter onto eras without this would have taken the
    /// one structure that syncs and put it on a structure that cannot. Build the
    /// sync path first — that ordering is the design (`AXIOM_DESIGN_NablaAntiEntropy.md` §12).
    ///
    /// Semantics, matching the flat filter's: **monotonic union, never subtraction**.
    /// A hash stays "seen" if ANY honest peer says so, so an attacker peer's empty
    /// or partial view cannot disarm us — it can only fail to add. Eras the peer has
    /// and we do not are adopted wholesale; eras we both have are OR-ed; eras we have
    /// and the peer does not are left untouched.
    ///
    /// Returns the number of eras that were newly adopted or updated.
    ///
    /// Fails closed on **any** size mismatch rather than silently skipping the era:
    /// two nodes disagreeing on an era's dimensions is the mesh-wide disarm failure
    /// the plan warns about, and it must be loud. This is why per-era sizing has to
    /// be deterministic (from the constant / era duration, never from a node's
    /// observed insert count) and why eras rotate on TICKS, not on entry count —
    /// nodes cross a tick together, but cross a count at different moments.
    pub fn merge(&mut self, other: &BloomChain) -> Result<usize, String> {
        if self.era_duration_ticks != other.era_duration_ticks {
            return Err(format!(
                "era duration mismatch: local {} vs peer {} — chains are not comparable",
                self.era_duration_ticks, other.era_duration_ticks
            ));
        }
        let mut changed = 0usize;
        for (era_id, their_era) in other.eras.iter() {
            match self.eras.get_mut(era_id) {
                Some(ours) => {
                    if ours.meta.start_tick != their_era.meta.start_tick
                        || ours.meta.end_tick != their_era.meta.end_tick
                    {
                        return Err(format!(
                            "era {} boundary mismatch: local [{},{}) vs peer [{},{})",
                            era_id, ours.meta.start_tick, ours.meta.end_tick,
                            their_era.meta.start_tick, their_era.meta.end_tick
                        ));
                    }
                    ours.filter.merge(&their_era.filter).map_err(|e| {
                        format!("era {era_id} filter merge failed ({e}) — \
                                 per-era sizing must be deterministic across nodes")
                    })?;
                    // Union only grows the set, so the count is a lower bound; take
                    // the larger so a re-armed node does not under-report its fill.
                    if their_era.meta.entry_count > ours.meta.entry_count {
                        ours.meta.entry_count = their_era.meta.entry_count;
                    }
                    changed += 1;
                }
                None => {
                    // An era we never opened — adopt it whole. This is the case that
                    // matters for a fresh node: it has one era and the peer has forty.
                    self.eras.insert(*era_id, their_era.clone());
                    changed += 1;
                }
            }
        }
        Ok(changed)
    }

    /// Adopt or union a SINGLE era — the incremental counterpart to [`merge`].
    ///
    /// Era transfer has to be incremental (an era is ~1.7 MiB at default sizing
    /// against a 5 MiB `STATE_PULL_MAX_BYTES`), so the wire hands us eras one at a
    /// time rather than a whole chain. Same guarantees as `merge`: monotonic union
    /// for an era we already hold, wholesale adopt for one we do not, and a LOUD
    /// error on any dimension or boundary mismatch rather than a silent skip.
    ///
    /// Returns `true` if this era was newly adopted, `false` if it was union-ed
    /// into an era we already had.
    pub fn merge_era(&mut self, incoming: BloomEra) -> Result<bool, String> {
        let era_id = incoming.meta.era_id;
        match self.eras.get_mut(&era_id) {
            Some(ours) => {
                if ours.meta.start_tick != incoming.meta.start_tick
                    || ours.meta.end_tick != incoming.meta.end_tick
                {
                    return Err(format!(
                        "era {} boundary mismatch: local [{},{}) vs incoming [{},{})",
                        era_id, ours.meta.start_tick, ours.meta.end_tick,
                        incoming.meta.start_tick, incoming.meta.end_tick
                    ));
                }
                ours.filter.merge(&incoming.filter).map_err(|e| {
                    format!("era {era_id} filter merge failed ({e}) — per-era sizing \
                             must be deterministic across nodes")
                })?;
                if incoming.meta.entry_count > ours.meta.entry_count {
                    ours.meta.entry_count = incoming.meta.entry_count;
                }
                Ok(false)
            }
            None => {
                self.eras.insert(era_id, incoming);
                Ok(true)
            }
        }
    }

    /// Per-era sizing this chain was constructed with. Exposed so callers and
    /// tests never GUESS it — a mismatch is the mesh-wide disarm failure, so the
    /// value must come from one place.
    pub fn expected_items_per_era(&self) -> u64 {
        self.expected_items_per_era
    }

    /// Number of eras in the chain.
    pub fn era_count(&self) -> usize {
        self.eras.len()
    }

    /// The currently Active era's id.
    pub fn active_era_id(&self) -> u64 {
        self.active_era_id
    }

    /// The GLOBAL-GRID era id a tick VALUE falls in, under THIS chain's era
    /// duration (KI#44: `era_id_for_tick` is anchored at genesis and total
    /// over constants, so every node computes the same id). Used by the
    /// KI#43b barrier to map a state's birth tick to a birth era locally
    /// (§12.4.4 item 4) — the exact-record store shares this chain's era ids
    /// by construction (`record()` is fed the bloom's active era id), so the
    /// answer is directly comparable to `ConsumedExactStore` metadata.
    /// ⚠ `tick` is a tick VALUE and `era_duration_ticks` is a tick-VALUE span
    /// (already `.to_secs()`-projected at construction); do not pass a raw
    /// tick COUNT here (KI#47).
    pub fn era_id_for_tick(&self, tick: u64) -> u64 {
        era_id_for_tick(tick, self.era_duration_ticks)
    }

    /// Borrow the Active era.
    pub fn active_era(&self) -> &BloomEra {
        self.eras
            .get(&self.active_era_id)
            .expect("invariant: active_era_id always points to an era")
    }

    /// Borrow an era by id.
    pub fn era(&self, era_id: u64) -> Option<&BloomEra> {
        self.eras.get(&era_id)
    }

    /// All era metadata in id order. Used by the Bloom Age Index to publish
    /// the chain's current state.
    pub fn metadata(&self) -> Vec<BloomEraMeta> {
        self.eras.values().map(|e| e.meta.clone()).collect()
    }

    /// Insert an entry into the active era.
    /// If `current_tick` indicates the active era has ended, the chain rotates
    /// first (freezing the previous era and opening a new active one), and the
    /// insert lands in the new active era.
    pub fn insert(&mut self, current_tick: u64, hash: &TxHash) {
        self.maybe_rotate(current_tick);
        let era = self
            .eras
            .get_mut(&self.active_era_id)
            .expect("invariant: active era exists");
        era.insert(hash);
    }

    /// Walk the chain newest-first looking for a bloom hit.
    /// Returns the first hit found, or `Miss` if no era's bloom contains the
    /// hash.
    ///
    /// Lookups skip eras that are PhasedOut at the *meta* level only when the
    /// caller passes `walk_phased_out: false` — by default, phased-out eras
    /// are ALSO walked because the bloom file may still be in memory; the
    /// caller decides what to do with a hit in a phased-out era based on
    /// `era_status`.
    pub fn lookup(&self, hash: &TxHash) -> ChainLookup {
        // Iterate newest first
        for era in self.eras.values().rev() {
            if era.may_contain(hash) {
                return ChainLookup::Hit {
                    era_id: era.meta.era_id,
                    bloom_root: era.meta.bloom_root,
                    era_status: era.meta.status.clone(),
                };
            }
        }
        ChainLookup::Miss
    }

    /// If `current_tick` is at or past the active era's `end_tick`, freeze
    /// the active era and open the next one. Idempotent and safe to call
    /// before every insert.
    ///
    /// Multiple eras may be skipped if `current_tick` jumps far ahead (e.g.,
    /// after a long downtime). All skipped eras are opened-and-frozen so the
    /// chain is contiguous.
    ///
    /// Catch-up cap: if the gap exceeds `MAX_CATCHUP_ERAS`, treat this as a
    /// fresh chain (the node was constructed with start_tick=0 but virtual_secs
    /// is wall-clock time). Snap forward by replacing the chain with a single
    /// fresh active era at `current_tick`. This prevents allocating ~1100
    /// bloom filters (each ~18MB) on first insert into a freshly-spawned node.
    pub fn maybe_rotate(&mut self, current_tick: u64) {
        const MAX_CATCHUP_ERAS: u64 = 16;

        let active = self
            .eras
            .get(&self.active_era_id)
            .expect("invariant: active era exists");
        if current_tick < active.meta.end_tick {
            return;
        }
        let gap_eras = (current_tick - active.meta.start_tick) / self.era_duration_ticks;
        if gap_eras > MAX_CATCHUP_ERAS {
            // KI#44: a long gap no longer "rebases" to a node-local id — it JUMPS
            // to the grid era that `current_tick` actually falls in. Every node
            // that jumps lands on the SAME id with the SAME boundaries, so this
            // path can no longer manufacture divergence. (It still exists to avoid
            // allocating ~MAX_CATCHUP_ERAS+ bloom files one at a time.)
            let target_id = era_id_for_tick(current_tick, self.era_duration_ticks);
            let start = era_start_tick(target_id, self.era_duration_ticks);
            let end = start + self.era_duration_ticks;
            self.eras.clear();
            let new_active =
                BloomEra::open(target_id, start, end, self.expected_items_per_era);
            self.eras.insert(target_id, new_active);
            self.active_era_id = target_id;
            return;
        }

        loop {
            let active = self
                .eras
                .get(&self.active_era_id)
                .expect("invariant: active era exists");
            if current_tick < active.meta.end_tick {
                return;
            }
            // Time to rotate. Freeze the active era and open the NEXT GRID era.
            // KI#44: the id is derived from the grid boundary, not incremented —
            // identical on every node by construction.
            let frozen_end = active.meta.end_tick;
            let next_id = era_id_for_tick(frozen_end, self.era_duration_ticks);
            let next_end = era_start_tick(next_id, self.era_duration_ticks)
                + self.era_duration_ticks;
            // Mutate the soon-to-be-frozen era
            if let Some(era) = self.eras.get_mut(&self.active_era_id) {
                era.freeze();
            }
            // Open a fresh active era
            let new_active =
                BloomEra::open(
                    next_id,
                    era_start_tick(next_id, self.era_duration_ticks),
                    next_end,
                    self.expected_items_per_era,
                );
            self.eras.insert(next_id, new_active);
            self.active_era_id = next_id;
        }
    }

    /// Mark a frozen era as Console-scheduled-for-phase-out.
    /// Called when a `BLOOM_PHASE_OUT` ConsoleCertificate is received.
    /// Returns true on success, false if the era doesn't exist or is not
    /// in a state that allows scheduling (must be Frozen).
    pub fn schedule_phase_out(
        &mut self,
        era_id: u64,
        effective_tick: u64,
        console_cert_hash: [u8; 32],
    ) -> bool {
        match self.eras.get_mut(&era_id) {
            Some(era) if matches!(era.meta.status, EraStatus::Frozen) => {
                era.meta.status = EraStatus::ScheduledPhaseOut {
                    effective_tick,
                    console_cert_hash,
                };
                true
            }
            _ => false,
        }
    }

    /// Transition any ScheduledPhaseOut eras whose effective_tick has arrived
    /// to PhasedOut. Returns the number of eras transitioned.
    pub fn apply_due_phase_outs(&mut self, current_tick: u64) -> usize {
        let mut applied = 0;
        for era in self.eras.values_mut() {
            if let EraStatus::ScheduledPhaseOut {
                effective_tick,
                console_cert_hash,
            } = era.meta.status
            {
                if current_tick >= effective_tick {
                    era.meta.status = EraStatus::PhasedOut {
                        effective_tick,
                        console_cert_hash,
                    };
                    applied += 1;
                }
            }
        }
        applied
    }
}

#[cfg(test)]
mod tests {
    /// KI#44: era identity is anchored at `GENESIS_NEWS_ANCHOR`, so a raw tick
    /// like `1000` is PRE-genesis and collapses to era 0. Real ticks are
    /// unix-scale. `t(n)` offsets a synthetic tick onto the real scale so these
    /// tests exercise the same arithmetic production does.
    fn t(offset: u64) -> u64 {
        axiom_core_logic::genesis_integrity::GENESIS_NEWS_ANCHOR + offset
    }

    /// The grid era id a synthetic offset falls in. Era ids are no longer
    /// 0,1,2 from an arbitrary origin — they are absolute grid cells.
    fn eid(offset: u64, dur: u64) -> u64 {
        super::era_id_for_tick(t(offset), dur)
    }

    /// Most tests open at offset 1000 with duration 100. Under the KI#44 grid
    /// their eras are absolute cells, so what used to be "era 0, 1, 2" is now
    /// `base() + 0, +1, +2`.
    fn base() -> u64 {
        eid(1000, 100)
    }

    use super::*;

    fn make_hash(n: u8) -> TxHash {
        let mut h = [0u8; 32];
        h[0] = n;
        h[31] = n;
        h
    }

    #[test]
    fn test_new_chain_has_one_active_era() {
        let chain = BloomChain::new(t(1000), 100, 100);
        assert_eq!(chain.era_count(), 1);
        assert_eq!(chain.active_era_id(), base() + 0);
        assert!(chain.active_era().meta.is_active());
        assert_eq!(chain.active_era().meta.start_tick, t(1000));
        assert_eq!(chain.active_era().meta.end_tick, t(1100));
    }

    #[test]
    fn test_insert_within_era_does_not_rotate() {
        let mut chain = BloomChain::new(t(1000), 100, 100);
        chain.insert(t(1050), &make_hash(1));
        chain.insert(t(1099), &make_hash(2));
        assert_eq!(chain.era_count(), 1);
        assert_eq!(chain.active_era_id(), base() + 0);
        assert_eq!(chain.active_era().meta.entry_count, 2);
    }

    #[test]
    fn test_insert_at_era_boundary_rotates() {
        let mut chain = BloomChain::new(t(1000), 100, 100);
        chain.insert(t(1050), &make_hash(1));
        // Crossing end_tick=1100 must rotate
        chain.insert(t(1100), &make_hash(2));
        assert_eq!(chain.era_count(), 2);
        assert_eq!(chain.active_era_id(), base() + 1);
        // The frozen era still has its insert
        let frozen = chain.era(base() + 0).unwrap();
        assert!(matches!(frozen.meta.status, EraStatus::Frozen));
        assert!(frozen.may_contain(&make_hash(1)));
        // The new active era has the new insert
        assert!(chain.active_era().may_contain(&make_hash(2)));
    }

    #[test]
    fn test_long_jump_creates_contiguous_eras() {
        let mut chain = BloomChain::new(t(1000), 100, 100);
        // Jump 5 era widths forward
        chain.insert(t(1500), &make_hash(99));
        // Should have 6 eras: 0-4 frozen, 5 active
        assert_eq!(chain.era_count(), 6);
        assert_eq!(chain.active_era_id(), base() + 5);
        for n in 0..5 {
            assert!(matches!(chain.era(base() + n).unwrap().meta.status, EraStatus::Frozen));
        }
        assert!(chain.active_era().may_contain(&make_hash(99)));
    }

    #[test]
    fn test_catastrophic_jump_snaps_to_the_grid() {
        // Regression: a node started far behind would have allocated ~1100 18MB
        // bloom filters on first insert. The MAX_CATCHUP_ERAS guard still avoids
        // that — but since KI#44 the jump lands on the GRID era containing
        // current_tick, NOT an era starting AT current_tick. That is the whole
        // point: every node that jumps computes the SAME id and boundaries, so
        // this path can no longer manufacture the divergence KI#44 describes.
        let dur = 1_555_200;
        let mut chain = BloomChain::new(t(0), dur, 1_000_000);
        // The gap must exceed MAX_CATCHUP_ERAS (16) to take the jump branch —
        // otherwise this exercises ordinary rotation and proves nothing.
        let now = t(20 * dur);
        chain.insert(now, &make_hash(42));
        assert_eq!(chain.era_count(), 1, "no historical eras materialised");
        assert!(chain.active_era().may_contain(&make_hash(42)));

        let expected_id = super::era_id_for_tick(now, dur);
        let expected_start = super::era_start_tick(expected_id, dur);
        let active = chain.active_era();
        assert_eq!(chain.active_era_id(), expected_id, "id is the grid cell");
        assert_eq!(active.meta.start_tick, expected_start, "start SNAPS to the grid");
        assert_eq!(active.meta.end_tick, expected_start + dur);
        assert!(
            active.meta.start_tick <= now && now < active.meta.end_tick,
            "current_tick must fall inside its own grid cell"
        );
    }

    #[test]
    fn test_lookup_walks_all_eras_newest_first() {
        let mut chain = BloomChain::new(t(1000), 100, 100);
        chain.insert(t(1050), &make_hash(1)); // era 0
        chain.insert(t(1150), &make_hash(2)); // era 1
        chain.insert(t(1250), &make_hash(3)); // era 2

        // Lookup must find each entry in its respective era
        match chain.lookup(&make_hash(1)) {
            ChainLookup::Hit { era_id, .. } => assert_eq!(era_id, base() + 0),
            ChainLookup::Miss => panic!("expected hit for hash 1"),
        }
        match chain.lookup(&make_hash(2)) {
            ChainLookup::Hit { era_id, .. } => assert_eq!(era_id, base() + 1),
            ChainLookup::Miss => panic!("expected hit for hash 2"),
        }
        match chain.lookup(&make_hash(3)) {
            ChainLookup::Hit { era_id, .. } => assert_eq!(era_id, base() + 2),
            ChainLookup::Miss => panic!("expected hit for hash 3"),
        }
    }

    #[test]
    fn test_lookup_miss_returns_miss() {
        let mut chain = BloomChain::new(t(1000), 100, 100);
        chain.insert(t(1050), &make_hash(1));
        chain.insert(t(1150), &make_hash(2));
        assert_eq!(chain.lookup(&make_hash(99)), ChainLookup::Miss);
    }

    #[test]
    fn test_metadata_lists_all_eras_in_order() {
        let mut chain = BloomChain::new(t(0), 100, 100);
        chain.insert(t(50), &make_hash(1));
        chain.insert(t(150), &make_hash(2));
        chain.insert(t(250), &make_hash(3));
        let meta = chain.metadata();
        assert_eq!(meta.len(), 3);
        for (i, m) in meta.iter().enumerate() {
            assert_eq!(m.era_id, i as u64);
        }
        assert!(matches!(meta[0].status, EraStatus::Frozen));
        assert!(matches!(meta[1].status, EraStatus::Frozen));
        assert!(matches!(meta[2].status, EraStatus::Active));
    }

    #[test]
    fn test_schedule_phase_out_only_works_for_frozen() {
        let mut chain = BloomChain::new(t(0), 100, 100);
        chain.insert(t(50), &make_hash(1));
        chain.insert(t(150), &make_hash(2)); // forces era 0 to Frozen
        // Era 0 is Frozen — schedule should succeed
        assert!(chain.schedule_phase_out(0, 999, [0xAA; 32]));
        assert!(matches!(
            chain.era(0).unwrap().meta.status,
            EraStatus::ScheduledPhaseOut { .. }
        ));
        // Era 1 is Active — schedule must fail
        assert!(!chain.schedule_phase_out(1, 999, [0xAA; 32]));
        // Nonexistent era must fail
        assert!(!chain.schedule_phase_out(99, 999, [0xAA; 32]));
        // Re-scheduling an already-scheduled era must fail (not Frozen anymore)
        assert!(!chain.schedule_phase_out(0, 999, [0xBB; 32]));
    }

    #[test]
    fn test_apply_due_phase_outs_transitions_only_due_eras() {
        let mut chain = BloomChain::new(t(0), 100, 100);
        chain.insert(t(50), &make_hash(1));
        chain.insert(t(150), &make_hash(2));
        chain.insert(t(250), &make_hash(3));
        // Era 0 and 1 are Frozen; schedule both with different effective_ticks
        chain.schedule_phase_out(0, 1000, [0xAA; 32]);
        chain.schedule_phase_out(1, 2000, [0xBB; 32]);

        // tick=1500: only era 0's phase-out is due
        let applied = chain.apply_due_phase_outs(1500);
        assert_eq!(applied, 1);
        assert!(matches!(chain.era(0).unwrap().meta.status, EraStatus::PhasedOut { .. }));
        assert!(matches!(
            chain.era(1).unwrap().meta.status,
            EraStatus::ScheduledPhaseOut { .. }
        ));

        // tick=2500: era 1's phase-out becomes due
        let applied = chain.apply_due_phase_outs(2500);
        assert_eq!(applied, 1);
        assert!(matches!(chain.era(1).unwrap().meta.status, EraStatus::PhasedOut { .. }));

        // No more transitions
        let applied = chain.apply_due_phase_outs(99999);
        assert_eq!(applied, 0);
    }

    #[test]
    fn test_two_chains_with_same_inputs_converge_on_same_roots() {
        let mut a = BloomChain::new(t(0), 100, 100);
        let mut b = BloomChain::new(t(0), 100, 100);
        for i in 1..50u8 {
            let tick = 50 + (i as u64 * 5);
            a.insert(tick, &make_hash(i));
            b.insert(tick, &make_hash(i));
        }
        // Force both into the next era so era 0 freezes
        a.insert(t(200), &make_hash(99));
        b.insert(t(200), &make_hash(99));

        // Era 0 should now be Frozen with the same root in both chains
        let a0 = a.era(0).unwrap();
        let b0 = b.era(0).unwrap();
        assert!(matches!(a0.meta.status, EraStatus::Frozen));
        assert!(matches!(b0.meta.status, EraStatus::Frozen));
        assert_eq!(a0.meta.bloom_root, b0.meta.bloom_root);
        assert_eq!(a0.meta.entry_count, b0.meta.entry_count);
    }

    // ══════════════════════════════════════════════════════════════════
    // KI#42 — rotation must not lose data, and a chain must be syncable
    // ══════════════════════════════════════════════════════════════════

    /// SEARCH ACROSS ROTATION: a hash inserted before a rotation must still be
    /// found after it. This is the property that makes era-sharding safe for a
    /// consume-once gate at all — if a rotation dropped older marks from the
    /// answer, a rolled-back state would look unconsumed the moment the era
    /// turned over.
    #[test]
    fn lookup_finds_hashes_in_both_current_and_rotated_eras() {
        let mut chain = BloomChain::new(t(0), 100, 1000);

        let old = make_hash(1);
        chain.insert(t(10), &old);                    // era 0
        assert!(matches!(chain.lookup(&old), ChainLookup::Hit { era_id: 0, .. }));

        // Roll over several times, writing one hash per era.
        let mid = make_hash(2);
        chain.insert(t(150), &mid);                   // era 1
        let recent = make_hash(3);
        chain.insert(t(520), &recent);                // era 5
        assert!(chain.era_count() > 2, "expected rotation to have occurred");
        assert_ne!(chain.active_era_id(), 0, "active era must have moved on");

        // Every one of them is still findable, from the oldest frozen era to the
        // live one — the union query spans the whole chain, not just the active era.
        assert!(matches!(chain.lookup(&old), ChainLookup::Hit { era_id: 0, .. }),
            "hash from a ROTATED era must still be found");
        assert!(matches!(chain.lookup(&mid), ChainLookup::Hit { .. }));
        assert!(matches!(chain.lookup(&recent), ChainLookup::Hit { .. }));
        // And something never inserted is still a miss.
        assert!(matches!(chain.lookup(&make_hash(99)), ChainLookup::Miss));
    }

    /// SYNC: a fresh node holding one era adopts a peer's whole history, and can
    /// then answer for hashes it never saw itself. This is the bootstrap case —
    /// without it, era-sharding a fail-closed filter would leave new nodes blind.
    #[test]
    fn merge_re_arms_a_fresh_chain_from_a_peer() {
        // Peer has been running: several eras, one hash in each.
        let mut peer = BloomChain::new(t(0), 100, 1000);
        let h_old = make_hash(11);
        let h_mid = make_hash(12);
        let h_new = make_hash(13);
        peer.insert(t(10), &h_old);
        peer.insert(t(150), &h_mid);
        peer.insert(t(420), &h_new);
        assert!(peer.era_count() >= 3);

        // Fresh node: one era, knows nothing.
        let mut fresh = BloomChain::new(t(0), 100, 1000);
        assert_eq!(fresh.era_count(), 1);
        assert!(matches!(fresh.lookup(&h_old), ChainLookup::Miss));

        let adopted = fresh.merge(&peer).expect("merge must succeed on matching config");
        assert_eq!(adopted, peer.era_count(), "every peer era should be adopted or updated");
        assert_eq!(fresh.era_count(), peer.era_count());

        // Now it answers for history it never witnessed — including across the
        // eras it adopted wholesale, not merely the one it already had.
        assert!(matches!(fresh.lookup(&h_old), ChainLookup::Hit { .. }));
        assert!(matches!(fresh.lookup(&h_mid), ChainLookup::Hit { .. }));
        assert!(matches!(fresh.lookup(&h_new), ChainLookup::Hit { .. }));
    }

    /// Merge is a monotonic UNION, never a subtraction: an empty or partial peer
    /// cannot erase what we already know. This is what stops a hostile peer
    /// disarming us by offering a blank view.
    #[test]
    fn merge_is_union_and_cannot_disarm_us() {
        let mut ours = BloomChain::new(t(0), 100, 1000);
        let mine = make_hash(21);
        ours.insert(t(10), &mine);

        let empty_peer = BloomChain::new(t(0), 100, 1000);
        ours.merge(&empty_peer).expect("empty peer merges fine");
        assert!(matches!(ours.lookup(&mine), ChainLookup::Hit { .. }),
            "an empty peer must not erase our knowledge");

        // And a peer that knows something different ADDS to us.
        let mut other_peer = BloomChain::new(t(0), 100, 1000);
        let theirs = make_hash(22);
        other_peer.insert(t(10), &theirs);
        ours.merge(&other_peer).unwrap();
        assert!(matches!(ours.lookup(&mine), ChainLookup::Hit { .. }));
        assert!(matches!(ours.lookup(&theirs), ChainLookup::Hit { .. }));
    }

    /// Divergent per-era sizing must FAIL LOUDLY, not silently skip. Two nodes
    /// disagreeing on an era's dimensions is the mesh-wide disarm failure the
    /// design warns about — it is why per-era sizing must be deterministic and
    /// why eras rotate on ticks rather than on entry count.
    #[test]
    fn merge_rejects_divergent_sizing_rather_than_skipping() {
        let mut a = BloomChain::new(t(0), 100, 1_000);
        let mut b = BloomChain::new(t(0), 100, 9_999);   // different per-era size
        a.insert(t(10), &make_hash(31));
        b.insert(t(10), &make_hash(32));
        let err = a.merge(&b).expect_err("size mismatch must be an error");
        assert!(err.contains("deterministic"), "error should name the cause: {err}");

        // Different era DURATION is likewise incomparable.
        let mut c = BloomChain::new(t(0), 250, 1_000);
        c.insert(t(10), &make_hash(33));
        let err2 = a.merge(&c).expect_err("duration mismatch must be an error");
        assert!(err2.contains("era duration mismatch"), "got: {err2}");
    }

    // ── KI#44: the global era grid ──────────────────────────────────────────

    /// THE regression this fix exists for. Two nodes that open their chains at
    /// DIFFERENT moments must still agree on era identity AND boundaries.
    /// Pre-fix both started at `era_id = 0` with `start_tick` = their own local
    /// moment, so "era 0" meant two different tick ranges and `merge_era` would
    /// refuse (same id, different boundaries) or clobber.
    #[test]
    fn ki44_two_nodes_starting_at_different_ticks_agree_on_era_identity() {
        let dur = DEFAULT_ERA_DURATION_TICKS;
        let anchor = axiom_core_logic::genesis_integrity::GENESIS_NEWS_ANCHOR;

        // Node A boots early in some era; node B boots most of the way through
        // the SAME era. Different local moments, same grid cell.
        let a = BloomChain::new(anchor + 7 * dur + 5, dur, 1_000);
        let b = BloomChain::new(anchor + 7 * dur + (dur - 5), dur, 1_000);

        assert_eq!(a.active_era_id(), b.active_era_id(), "same era id");
        assert_eq!(a.active_era_id(), 7, "id is derived from the grid, not from boot order");

        let (as_, ae) = (a.active_era().meta.start_tick, a.active_era().meta.end_tick);
        let (bs, be) = (b.active_era().meta.start_tick, b.active_era().meta.end_tick);
        assert_eq!((as_, ae), (bs, be), "IDENTICAL boundaries — this is what merge_era needs");
        assert_eq!(as_, anchor + 7 * dur, "start snaps to the grid, not to boot tick");
    }

    /// A node that has been down for a long gap must land on the SAME era as a
    /// node that stayed up — the old code took a "fresh-chain rebase" branch
    /// that invented a node-local id here.
    #[test]
    fn ki44_long_gap_jump_lands_on_the_same_grid_era_as_a_live_node() {
        let dur = DEFAULT_ERA_DURATION_TICKS;
        let anchor = axiom_core_logic::genesis_integrity::GENESIS_NEWS_ANCHOR;
        let now = anchor + 900 * dur + 17; // far past MAX_CATCHUP_ERAS

        // Node A: alive since era 0, rotating forward.
        let mut a = BloomChain::new(anchor + 1, dur, 1_000);
        a.maybe_rotate(now);
        // Node B: freshly opened right now.
        let b = BloomChain::new(now, dur, 1_000);

        assert_eq!(a.active_era_id(), b.active_era_id(),
            "a long-gap jump and a fresh open must agree");
        assert_eq!(a.active_era_id(), 900);
        assert_eq!((a.active_era().meta.start_tick, a.active_era().meta.end_tick), (b.active_era().meta.start_tick, b.active_era().meta.end_tick), "and on boundaries");
    }

    /// era_id -> start -> era_id round-trips, and ticks before the anchor
    /// collapse to era 0 rather than underflowing.
    #[test]
    fn ki44_grid_helpers_round_trip_and_clamp() {
        let dur = DEFAULT_ERA_DURATION_TICKS;
        let anchor = axiom_core_logic::genesis_integrity::GENESIS_NEWS_ANCHOR;
        for id in [0u64, 1, 42, 900] {
            let start = era_start_tick(id, dur);
            assert_eq!(era_id_for_tick(start, dur), id, "round-trip at boundary");
            assert_eq!(era_id_for_tick(start + dur - 1, dur), id, "round-trip at end");
        }
        assert_eq!(era_id_for_tick(0, dur), 0, "pre-anchor clamps to era 0");
        assert_eq!(era_id_for_tick(anchor.saturating_sub(1), dur), 0);
    }
}
