// AXIOM Nabla — Bloom Age Index (YPX-018 §3.1, §3.3)
//
// The Bloom Age Index is the protocol-level directory of which bloom eras
// exist, what tick range each covers, and what status each is in. It is
// the source of truth for "what does this Nabla node currently know about
// the bloom chain".
//
// Both bloom chains (txid + garbage state) share the same era boundaries,
// so the age index keys eras by `era_id` and stores the metadata for both
// chains' eras side-by-side.
//
// In Phase 2 the index lives entirely in memory, with persistence to come
// in Phase 3 (via Nabla's existing snapshot/WAL pattern). Cross-node
// gossip propagation is also Phase 3.
//
// Reference:
//   - YPX-018 §3.1 Architecture (light vs archive tiers)
//   - YPX-018 §3.3 BloomEra structure
//   - Yellow Paper §39.9.5 Tiered bloom storage

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bloom_era::BloomEraMeta;

/// One row in the Bloom Age Index — combines metadata for both bloom
/// chains' eras at a given era_id.
///
/// `txid_meta` and `garbage_meta` always share the same `era_id`,
/// `start_tick`, and `end_tick`. Their `bloom_root`, `entry_count`,
/// and `status` evolve independently per chain (e.g., the txid bloom
/// for a given era has many more entries than the garbage state bloom).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgeIndexEntry {
    pub txid_meta: BloomEraMeta,
    pub garbage_meta: BloomEraMeta,

    /// Optional list of archive node IDs known to hold this era's full hash
    /// records. Used as a routing hint when bloom hits need archive
    /// resolution. Not authoritative — any node may volunteer to archive.
    #[serde(default)]
    pub archive_nodes: Vec<[u8; 32]>,
}

/// The Bloom Age Index — a sorted directory of every era this node knows
/// about. The index is queried on every txid/garbage lookup to walk the
/// bloom chain in order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BloomAgeIndex {
    /// Eras keyed by `era_id`. BTreeMap so iteration is in order.
    entries: BTreeMap<u64, AgeIndexEntry>,
}

impl BloomAgeIndex {
    /// Create an empty Bloom Age Index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of eras tracked.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert or replace an era's metadata.
    pub fn upsert(&mut self, entry: AgeIndexEntry) {
        let era_id = entry.txid_meta.era_id;
        // Sanity: both metadatas must share the same era_id and tick range
        debug_assert_eq!(
            era_id, entry.garbage_meta.era_id,
            "txid and garbage meta must share era_id"
        );
        debug_assert_eq!(
            entry.txid_meta.start_tick, entry.garbage_meta.start_tick,
            "txid and garbage meta must share start_tick"
        );
        debug_assert_eq!(
            entry.txid_meta.end_tick, entry.garbage_meta.end_tick,
            "txid and garbage meta must share end_tick"
        );
        self.entries.insert(era_id, entry);
    }

    /// Borrow an era's metadata by id.
    pub fn get(&self, era_id: u64) -> Option<&AgeIndexEntry> {
        self.entries.get(&era_id)
    }

    /// All entries in id order.
    pub fn entries(&self) -> Vec<AgeIndexEntry> {
        self.entries.values().cloned().collect()
    }

    /// All entries in id order, newest first. Used by lookups walking the
    /// bloom chain in reverse era order.
    pub fn entries_newest_first(&self) -> Vec<AgeIndexEntry> {
        self.entries.values().rev().cloned().collect()
    }

    /// Find the era that contains a given tick. There is at most one such
    /// era for any given tick (eras are non-overlapping).
    pub fn era_for_tick(&self, tick: u64) -> Option<&AgeIndexEntry> {
        self.entries
            .values()
            .find(|e| e.txid_meta.contains_tick(tick))
    }

    /// Compute a single BLAKE3 root over the entire age index, for cross-node
    /// convergence verification. Two nodes with the same eras+roots produce
    /// the same `index_root`.
    ///
    /// Domain: `"AXIOM_BLOOM_AGE_INDEX_ROOT"`.
    pub fn index_root(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_BLOOM_AGE_INDEX_ROOT");
        hasher.update(&(self.entries.len() as u64).to_le_bytes());
        for entry in self.entries.values() {
            hasher.update(&entry.txid_meta.era_id.to_le_bytes());
            hasher.update(&entry.txid_meta.start_tick.to_le_bytes());
            hasher.update(&entry.txid_meta.end_tick.to_le_bytes());
            hasher.update(&entry.txid_meta.bloom_root);
            hasher.update(&entry.txid_meta.entry_count.to_le_bytes());
            hasher.update(&entry.garbage_meta.bloom_root);
            hasher.update(&entry.garbage_meta.entry_count.to_le_bytes());
            // Status is intentionally NOT in the root — phase-out events change
            // status without changing the underlying bloom data, and the root's
            // job is to verify bloom convergence, not phase-out coordination.
        }
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bloom_era::EraStatus;

    fn make_meta(era_id: u64, start: u64, end: u64) -> BloomEraMeta {
        let mut m = BloomEraMeta::new_active(era_id, start, end);
        m.status = EraStatus::Frozen;
        m.bloom_root = [era_id as u8; 32];
        m.entry_count = era_id * 10;
        m
    }

    fn make_entry(era_id: u64, start: u64, end: u64) -> AgeIndexEntry {
        AgeIndexEntry {
            txid_meta: make_meta(era_id, start, end),
            garbage_meta: make_meta(era_id, start, end),
            archive_nodes: vec![],
        }
    }

    #[test]
    fn test_new_index_is_empty() {
        let idx = BloomAgeIndex::new();
        assert_eq!(idx.len(), 0);
        assert!(idx.is_empty());
    }

    #[test]
    fn test_upsert_and_get() {
        let mut idx = BloomAgeIndex::new();
        idx.upsert(make_entry(0, 0, 100));
        idx.upsert(make_entry(1, 100, 200));
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.get(0).unwrap().txid_meta.era_id, 0);
        assert_eq!(idx.get(1).unwrap().txid_meta.era_id, 1);
        assert!(idx.get(99).is_none());
    }

    #[test]
    fn test_upsert_replaces_existing() {
        let mut idx = BloomAgeIndex::new();
        idx.upsert(make_entry(0, 0, 100));
        // Same era_id, different end_tick — should replace
        let mut replacement = make_entry(0, 0, 200);
        replacement.txid_meta.entry_count = 999;
        idx.upsert(replacement);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.get(0).unwrap().txid_meta.entry_count, 999);
        assert_eq!(idx.get(0).unwrap().txid_meta.end_tick, 200);
    }

    #[test]
    fn test_entries_in_order() {
        let mut idx = BloomAgeIndex::new();
        idx.upsert(make_entry(2, 200, 300));
        idx.upsert(make_entry(0, 0, 100));
        idx.upsert(make_entry(1, 100, 200));
        let entries = idx.entries();
        assert_eq!(entries[0].txid_meta.era_id, 0);
        assert_eq!(entries[1].txid_meta.era_id, 1);
        assert_eq!(entries[2].txid_meta.era_id, 2);
    }

    #[test]
    fn test_entries_newest_first() {
        let mut idx = BloomAgeIndex::new();
        idx.upsert(make_entry(0, 0, 100));
        idx.upsert(make_entry(1, 100, 200));
        idx.upsert(make_entry(2, 200, 300));
        let entries = idx.entries_newest_first();
        assert_eq!(entries[0].txid_meta.era_id, 2);
        assert_eq!(entries[1].txid_meta.era_id, 1);
        assert_eq!(entries[2].txid_meta.era_id, 0);
    }

    #[test]
    fn test_era_for_tick_finds_containing_era() {
        let mut idx = BloomAgeIndex::new();
        idx.upsert(make_entry(0, 0, 100));
        idx.upsert(make_entry(1, 100, 200));
        idx.upsert(make_entry(2, 200, 300));
        assert_eq!(idx.era_for_tick(50).unwrap().txid_meta.era_id, 0);
        assert_eq!(idx.era_for_tick(100).unwrap().txid_meta.era_id, 1);
        assert_eq!(idx.era_for_tick(199).unwrap().txid_meta.era_id, 1);
        assert_eq!(idx.era_for_tick(250).unwrap().txid_meta.era_id, 2);
        assert!(idx.era_for_tick(999).is_none());
    }

    #[test]
    fn test_index_root_is_deterministic() {
        let mut a = BloomAgeIndex::new();
        let mut b = BloomAgeIndex::new();
        a.upsert(make_entry(0, 0, 100));
        a.upsert(make_entry(1, 100, 200));
        b.upsert(make_entry(0, 0, 100));
        b.upsert(make_entry(1, 100, 200));
        assert_eq!(a.index_root(), b.index_root());
    }

    #[test]
    fn test_index_root_differs_when_entries_differ() {
        let mut a = BloomAgeIndex::new();
        let mut b = BloomAgeIndex::new();
        a.upsert(make_entry(0, 0, 100));
        b.upsert(make_entry(1, 0, 100));
        assert_ne!(a.index_root(), b.index_root());
    }

    #[test]
    fn test_index_root_ignores_status_changes() {
        let mut a = BloomAgeIndex::new();
        let mut b = BloomAgeIndex::new();
        let entry = make_entry(0, 0, 100);
        a.upsert(entry.clone());

        let mut scheduled_entry = entry.clone();
        scheduled_entry.txid_meta.status = EraStatus::ScheduledPhaseOut {
            effective_tick: 9999,
            console_cert_hash: [0xCC; 32],
        };
        b.upsert(scheduled_entry);

        // Status differs but bloom data is identical — roots should match
        assert_eq!(a.index_root(), b.index_root());
    }

    #[test]
    #[should_panic]
    fn test_upsert_rejects_mismatched_meta_in_debug() {
        let mut idx = BloomAgeIndex::new();
        let mut bad = make_entry(0, 0, 100);
        bad.garbage_meta = make_meta(99, 0, 100); // wrong era_id
        idx.upsert(bad);
    }
}
