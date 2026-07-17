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

impl BloomChain {
    /// Open a brand-new chain with a single Active era starting at `start_tick`.
    pub fn new(start_tick: u64, era_duration_ticks: u64, expected_items_per_era: u64) -> Self {
        let era_id = 0;
        let end_tick = start_tick + era_duration_ticks;
        let era = BloomEra::open(era_id, start_tick, end_tick, expected_items_per_era);
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

    /// Number of eras in the chain.
    pub fn era_count(&self) -> usize {
        self.eras.len()
    }

    /// The currently Active era's id.
    pub fn active_era_id(&self) -> u64 {
        self.active_era_id
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
            // Fresh-chain rebase. Drop all eras, open one active era at current_tick.
            let next_id = self.active_era_id + 1;
            let next_end = current_tick + self.era_duration_ticks;
            self.eras.clear();
            let new_active =
                BloomEra::open(next_id, current_tick, next_end, self.expected_items_per_era);
            self.eras.insert(next_id, new_active);
            self.active_era_id = next_id;
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
            // Time to rotate. Freeze the active era.
            let frozen_end = active.meta.end_tick;
            let next_id = self.active_era_id + 1;
            let next_end = frozen_end + self.era_duration_ticks;
            // Mutate the soon-to-be-frozen era
            if let Some(era) = self.eras.get_mut(&self.active_era_id) {
                era.freeze();
            }
            // Open a fresh active era
            let new_active =
                BloomEra::open(next_id, frozen_end, next_end, self.expected_items_per_era);
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
    use super::*;

    fn make_hash(n: u8) -> TxHash {
        let mut h = [0u8; 32];
        h[0] = n;
        h[31] = n;
        h
    }

    #[test]
    fn test_new_chain_has_one_active_era() {
        let chain = BloomChain::new(1000, 100, 100);
        assert_eq!(chain.era_count(), 1);
        assert_eq!(chain.active_era_id(), 0);
        assert!(chain.active_era().meta.is_active());
        assert_eq!(chain.active_era().meta.start_tick, 1000);
        assert_eq!(chain.active_era().meta.end_tick, 1100);
    }

    #[test]
    fn test_insert_within_era_does_not_rotate() {
        let mut chain = BloomChain::new(1000, 100, 100);
        chain.insert(1050, &make_hash(1));
        chain.insert(1099, &make_hash(2));
        assert_eq!(chain.era_count(), 1);
        assert_eq!(chain.active_era_id(), 0);
        assert_eq!(chain.active_era().meta.entry_count, 2);
    }

    #[test]
    fn test_insert_at_era_boundary_rotates() {
        let mut chain = BloomChain::new(1000, 100, 100);
        chain.insert(1050, &make_hash(1));
        // Crossing end_tick=1100 must rotate
        chain.insert(1100, &make_hash(2));
        assert_eq!(chain.era_count(), 2);
        assert_eq!(chain.active_era_id(), 1);
        // The frozen era still has its insert
        let frozen = chain.era(0).unwrap();
        assert!(matches!(frozen.meta.status, EraStatus::Frozen));
        assert!(frozen.may_contain(&make_hash(1)));
        // The new active era has the new insert
        assert!(chain.active_era().may_contain(&make_hash(2)));
    }

    #[test]
    fn test_long_jump_creates_contiguous_eras() {
        let mut chain = BloomChain::new(1000, 100, 100);
        // Jump 5 era widths forward
        chain.insert(1500, &make_hash(99));
        // Should have 6 eras: 0-4 frozen, 5 active
        assert_eq!(chain.era_count(), 6);
        assert_eq!(chain.active_era_id(), 5);
        for id in 0..5 {
            assert!(matches!(chain.era(id).unwrap().meta.status, EraStatus::Frozen));
        }
        assert!(chain.active_era().may_contain(&make_hash(99)));
    }

    #[test]
    fn test_catastrophic_jump_rebases_chain() {
        // Regression: a node started with start_tick=0 but virtual_secs ≈
        // wall-clock would have allocated ~1100 18MB bloom filters on first
        // insert. The MAX_CATCHUP_ERAS guard rebases the chain instead.
        let mut chain = BloomChain::new(0, 1_555_200, 1_000_000);
        // Insert at wall-clock seconds — > 1000 era widths beyond start_tick.
        chain.insert(1_776_000_000, &make_hash(42));
        assert_eq!(chain.era_count(), 1);
        // Active era now starts AT current_tick, no historical eras created.
        assert!(chain.active_era().may_contain(&make_hash(42)));
        let active = chain.active_era();
        assert_eq!(active.meta.start_tick, 1_776_000_000);
        assert_eq!(active.meta.end_tick, 1_776_000_000 + 1_555_200);
    }

    #[test]
    fn test_lookup_walks_all_eras_newest_first() {
        let mut chain = BloomChain::new(1000, 100, 100);
        chain.insert(1050, &make_hash(1)); // era 0
        chain.insert(1150, &make_hash(2)); // era 1
        chain.insert(1250, &make_hash(3)); // era 2

        // Lookup must find each entry in its respective era
        match chain.lookup(&make_hash(1)) {
            ChainLookup::Hit { era_id, .. } => assert_eq!(era_id, 0),
            ChainLookup::Miss => panic!("expected hit for hash 1"),
        }
        match chain.lookup(&make_hash(2)) {
            ChainLookup::Hit { era_id, .. } => assert_eq!(era_id, 1),
            ChainLookup::Miss => panic!("expected hit for hash 2"),
        }
        match chain.lookup(&make_hash(3)) {
            ChainLookup::Hit { era_id, .. } => assert_eq!(era_id, 2),
            ChainLookup::Miss => panic!("expected hit for hash 3"),
        }
    }

    #[test]
    fn test_lookup_miss_returns_miss() {
        let mut chain = BloomChain::new(1000, 100, 100);
        chain.insert(1050, &make_hash(1));
        chain.insert(1150, &make_hash(2));
        assert_eq!(chain.lookup(&make_hash(99)), ChainLookup::Miss);
    }

    #[test]
    fn test_metadata_lists_all_eras_in_order() {
        let mut chain = BloomChain::new(0, 100, 100);
        chain.insert(50, &make_hash(1));
        chain.insert(150, &make_hash(2));
        chain.insert(250, &make_hash(3));
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
        let mut chain = BloomChain::new(0, 100, 100);
        chain.insert(50, &make_hash(1));
        chain.insert(150, &make_hash(2)); // forces era 0 to Frozen
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
        let mut chain = BloomChain::new(0, 100, 100);
        chain.insert(50, &make_hash(1));
        chain.insert(150, &make_hash(2));
        chain.insert(250, &make_hash(3));
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
        let mut a = BloomChain::new(0, 100, 100);
        let mut b = BloomChain::new(0, 100, 100);
        for i in 1..50u8 {
            let tick = 50 + (i as u64 * 5);
            a.insert(tick, &make_hash(i));
            b.insert(tick, &make_hash(i));
        }
        // Force both into the next era so era 0 freezes
        a.insert(200, &make_hash(99));
        b.insert(200, &make_hash(99));

        // Era 0 should now be Frozen with the same root in both chains
        let a0 = a.era(0).unwrap();
        let b0 = b.era(0).unwrap();
        assert!(matches!(a0.meta.status, EraStatus::Frozen));
        assert!(matches!(b0.meta.status, EraStatus::Frozen));
        assert_eq!(a0.meta.bloom_root, b0.meta.bloom_root);
        assert_eq!(a0.meta.entry_count, b0.meta.entry_count);
    }
}
