// AXIOM Nabla — Bloom Era (YPX-018 §3.3)
//
// A bloom era is a fixed TARDIS-tick window during which a bloom file accepts
// new entries. Each era has its own bloom file. Once an era ends, its bloom
// file is FROZEN — no more entries can be added, and the file's count and
// false-positive rate are fixed forever.
//
// Era freezing is the structural fix for the YPX-014 saturation bug. The
// original single-bloom design accepted entries indefinitely, causing the
// bloom's effective FPR to climb as more entries accumulated. By freezing
// at era close, each era's FPR is locked at its design target.
//
// Era duration is 90 days (quarterly) by default — see DEFAULT_ERA_DURATION_TICKS.
//
// Reference:
//   - YPX-018 §3.3 BloomEra structure
//   - YPX-018 §3.4 Bloom sizing and false-positive math
//   - Yellow Paper §39.9.5 Tiered bloom storage

use serde::{Deserialize, Serialize};

use crate::bloom::TxidBloomFilter;
use crate::types::TxHash;

/// Default era duration in TARDIS ticks.
/// 90 days × 86400 s/day ÷ 5 s/tick = 1,555,200 ticks.
pub const DEFAULT_ERA_DURATION_TICKS: u64 = 90 * 86400 / 5;

/// Target false positive rate for individual era bloom files at era close.
/// 10⁻¹² — chosen so that compounded FPR over 1000 eras (~250 years of
/// quarterly) stays below 10⁻⁹, effectively zero. See YPX-018 §3.4.
pub const BLOOM_ERA_FPR_TARGET: f64 = 1e-12;

/// Status of a bloom era in the Bloom Age Index (YPX-018 §3.3, mirrors
/// `axiom_core_logic::types::EraStatus`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum EraStatus {
    /// Currently accepting writes. Exactly one era is Active at any time.
    #[default]
    Active,
    /// Closed; bloom file is immutable. Can be queried but not modified.
    Frozen,
    /// Console-approved phase-out scheduled. Queries return real answers
    /// during the grace period, tagged with a phase-out warning.
    ScheduledPhaseOut {
        effective_tick: u64,
        console_cert_hash: [u8; 32],
    },
    /// Phase-out has taken effect. Archive nodes are FREE to drop the era's
    /// full hash records. The age-index entry remains forever for auditability.
    PhasedOut {
        effective_tick: u64,
        console_cert_hash: [u8; 32],
    },
}


/// One era in a bloom chain (YPX-018 §3.3).
///
/// Each era covers a TARDIS tick range `[start_tick, end_tick)`. Both the
/// txid bloom chain and the garbage state bloom chain share this era
/// metadata, so an era is the unit of phase-out for both chains.
///
/// The bloom file itself is owned by the chain (`BloomChain`) — this struct
/// only carries metadata that lives in the Bloom Age Index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomEraMeta {
    /// Monotonic era id. Increments when an era closes and the next opens.
    pub era_id: u64,

    /// First TARDIS tick in this era's range (inclusive).
    pub start_tick: u64,

    /// First TARDIS tick of the *next* era (exclusive).
    /// `end_tick - start_tick == era_duration` for all eras in a chain.
    pub end_tick: u64,

    /// BLAKE3 root of the bloom file at era close. Zero while the era is Active.
    /// Computed via `compute_bloom_root` over the serialized bloom bytes.
    pub bloom_root: [u8; 32],

    /// Exact entry count at era close (or current count for an Active era).
    pub entry_count: u64,

    /// Era status — drives query semantics and Console phase-out lifecycle.
    pub status: EraStatus,
}

impl BloomEraMeta {
    /// Build a fresh Active era metadata block.
    pub fn new_active(era_id: u64, start_tick: u64, end_tick: u64) -> Self {
        Self {
            era_id,
            start_tick,
            end_tick,
            bloom_root: [0u8; 32],
            entry_count: 0,
            status: EraStatus::Active,
        }
    }

    /// True if a given TARDIS tick falls within this era's range.
    pub fn contains_tick(&self, tick: u64) -> bool {
        tick >= self.start_tick && tick < self.end_tick
    }

    /// True if this era is still accepting writes.
    pub fn is_active(&self) -> bool {
        matches!(self.status, EraStatus::Active)
    }

    /// True if this era has been Console-phased-out (effective).
    /// Queries against this era return PhasedOut with the certificate hash.
    pub fn is_phased_out(&self) -> bool {
        matches!(self.status, EraStatus::PhasedOut { .. })
    }
}

/// One bloom era — metadata plus the actual bloom file for an Active era.
///
/// `BloomEra` owns its `TxidBloomFilter` while Active. After freezing, the
/// chain stores the immutable filter alongside the metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomEra {
    pub meta: BloomEraMeta,
    pub filter: TxidBloomFilter,
}

impl BloomEra {
    /// Open a new Active era.
    /// `expected_items` sizes the bloom for the era's expected entry count.
    pub fn open(era_id: u64, start_tick: u64, end_tick: u64, expected_items: u64) -> Self {
        Self {
            meta: BloomEraMeta::new_active(era_id, start_tick, end_tick),
            filter: TxidBloomFilter::new(expected_items),
        }
    }

    /// Insert an entry into the active era's bloom.
    /// Caller MUST ensure the era is Active before calling.
    pub fn insert(&mut self, hash: &TxHash) {
        self.filter.insert(hash);
        self.meta.entry_count = self.filter.count();
    }

    /// Query the era's bloom. Returns true if the entry MIGHT be present.
    pub fn may_contain(&self, hash: &TxHash) -> bool {
        self.filter.may_contain(hash)
    }

    /// Freeze this era — mark it immutable, compute and store the bloom root.
    /// After freezing, no more entries can be inserted.
    pub fn freeze(&mut self) {
        self.meta.bloom_root = compute_bloom_root(&self.filter);
        self.meta.entry_count = self.filter.count();
        self.meta.status = EraStatus::Frozen;
    }
}

/// Compute the canonical BLAKE3 root of a bloom filter.
/// The root is what gets stored in the Bloom Age Index and gossiped to peers
/// for cross-node convergence verification.
pub fn compute_bloom_root(filter: &TxidBloomFilter) -> [u8; 32] {
    let bytes = filter.to_bytes();
    *blake3::hash(&bytes).as_bytes()
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
    fn test_default_era_duration_is_90_days() {
        // 90 days * 86400 s/day / 5 s/tick = 1,555,200
        assert_eq!(DEFAULT_ERA_DURATION_TICKS, 1_555_200);
    }

    #[test]
    fn test_open_new_era_is_active() {
        let era = BloomEra::open(0, 1000, 1000 + DEFAULT_ERA_DURATION_TICKS, 100);
        assert!(era.meta.is_active());
        assert_eq!(era.meta.era_id, 0);
        assert_eq!(era.meta.entry_count, 0);
        assert_eq!(era.meta.bloom_root, [0u8; 32]);
    }

    #[test]
    fn test_contains_tick_inclusive_start_exclusive_end() {
        let era = BloomEra::open(0, 100, 200, 100);
        assert!(era.meta.contains_tick(100));
        assert!(era.meta.contains_tick(150));
        assert!(era.meta.contains_tick(199));
        assert!(!era.meta.contains_tick(99));
        assert!(!era.meta.contains_tick(200));
    }

    #[test]
    fn test_insert_advances_entry_count() {
        let mut era = BloomEra::open(0, 0, 100, 100);
        era.insert(&make_hash(1));
        era.insert(&make_hash(2));
        era.insert(&make_hash(3));
        assert_eq!(era.meta.entry_count, 3);
    }

    #[test]
    fn test_may_contain_after_insert() {
        let mut era = BloomEra::open(0, 0, 100, 100);
        let h = make_hash(42);
        assert!(!era.may_contain(&h));
        era.insert(&h);
        assert!(era.may_contain(&h));
    }

    #[test]
    fn test_freeze_locks_status_and_computes_root() {
        let mut era = BloomEra::open(0, 0, 100, 100);
        era.insert(&make_hash(7));
        assert_eq!(era.meta.bloom_root, [0u8; 32]);
        era.freeze();
        assert!(matches!(era.meta.status, EraStatus::Frozen));
        assert_ne!(era.meta.bloom_root, [0u8; 32]);
        // Insertion was preserved into the frozen era — still queryable
        assert!(era.may_contain(&make_hash(7)));
    }

    #[test]
    fn test_freeze_root_is_deterministic() {
        let mut a = BloomEra::open(0, 0, 100, 100);
        let mut b = BloomEra::open(0, 0, 100, 100);
        for i in 1..10u8 {
            a.insert(&make_hash(i));
            b.insert(&make_hash(i));
        }
        a.freeze();
        b.freeze();
        assert_eq!(
            a.meta.bloom_root, b.meta.bloom_root,
            "two eras with the same content must produce the same root"
        );
    }

    #[test]
    fn test_freeze_root_differs_when_content_differs() {
        let mut a = BloomEra::open(0, 0, 100, 100);
        let mut b = BloomEra::open(0, 0, 100, 100);
        a.insert(&make_hash(1));
        b.insert(&make_hash(2));
        a.freeze();
        b.freeze();
        assert_ne!(
            a.meta.bloom_root, b.meta.bloom_root,
            "different content must produce different roots"
        );
    }

    #[test]
    fn test_era_status_phased_out_detection() {
        let mut era = BloomEra::open(0, 0, 100, 100);
        era.freeze();
        assert!(!era.meta.is_phased_out());
        era.meta.status = EraStatus::PhasedOut {
            effective_tick: 999_999,
            console_cert_hash: [0xCC; 32],
        };
        assert!(era.meta.is_phased_out());
    }
}
