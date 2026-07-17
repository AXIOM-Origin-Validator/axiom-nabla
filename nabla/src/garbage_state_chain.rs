// AXIOM Nabla — Garbage State Bloom Chain (YPX-018 §3.2)
//
// The garbage state bloom chain runs alongside the txid bloom chain. Where
// the txid chain records "this txid was redeemed", the garbage chain records
// "this state_id was declared garbage by a CLARA wallet heal".
//
// Used to reject any future transaction that tries to consume a state that
// a wallet has explicitly abandoned via CLARA. This is the protocol-level
// enforcement of YPX-018 Attack 2 ("extend the broken chain"): once a state
// is in the garbage bloom, no FACT link can be registered against it.
//
// Structurally identical to the txid bloom chain — same era boundaries,
// same Bloom Age Index integration, same Console phase-out rules. The
// chains are kept separate so the entry counts don't pollute each other's
// FPR calculations and so phase-out can be reasoned about independently.
//
// Reference:
//   - YPX-018 §2 CLARA — wallet heal protocol
//   - YPX-018 §3.2 The two bloom chains
//   - Yellow Paper §17.10.14 CLARA
//   - Yellow Paper §39.9.5 Tiered bloom storage

use serde::{Deserialize, Serialize};

use crate::bloom_chain::{BloomChain, ChainLookup};
use crate::bloom_era::DEFAULT_ERA_DURATION_TICKS;

/// Garbage state bloom chain. Thin newtype around `BloomChain` so call sites
/// can't accidentally insert a state hash into the txid chain or vice-versa.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GarbageStateChain {
    inner: BloomChain,
}

impl GarbageStateChain {
    /// Open a brand-new garbage state chain.
    pub fn new(start_tick: u64, era_duration_ticks: u64, expected_items_per_era: u64) -> Self {
        Self {
            inner: BloomChain::new(start_tick, era_duration_ticks, expected_items_per_era),
        }
    }

    /// Open with default era duration. Garbage entries are rare (only on
    /// CLARA heals), so we size for ~10K entries per era by default.
    pub fn new_default(start_tick: u64) -> Self {
        Self {
            inner: BloomChain::new(start_tick, DEFAULT_ERA_DURATION_TICKS, 10_000),
        }
    }

    /// Number of eras tracked.
    pub fn era_count(&self) -> usize {
        self.inner.era_count()
    }

    /// Active era id.
    pub fn active_era_id(&self) -> u64 {
        self.inner.active_era_id()
    }

    /// Insert a state_id declared garbage by a CLARA heal.
    /// Auto-rotates the chain if the era boundary has been crossed.
    pub fn insert(&mut self, current_tick: u64, state_id: &[u8; 32]) {
        self.inner.insert(current_tick, state_id);
    }

    /// Look up whether a state_id might have been declared garbage.
    /// Returns Hit (with the era id where the bloom hit) or Miss.
    /// A Hit must be resolved against an archive node for an authoritative
    /// answer; the bloom alone is not the source of truth.
    pub fn lookup(&self, state_id: &[u8; 32]) -> ChainLookup {
        self.inner.lookup(state_id)
    }

    /// Borrow the underlying bloom chain (for metadata extraction by the
    /// Bloom Age Index and for tests).
    pub fn inner(&self) -> &BloomChain {
        &self.inner
    }

    /// Mutably borrow the underlying bloom chain (used by the age index
    /// and Console phase-out plumbing).
    pub fn inner_mut(&mut self) -> &mut BloomChain {
        &mut self.inner
    }

    /// YPX-022 §5 persistence — atomic CBOR write (tmp + rename, mirroring
    /// `PersistedPoolState::save`). The garbage chain is the durable
    /// "this cheque/state is dead" record under the 55-year retention floor
    /// (YP §21.10.6); it must survive a node restart, not just a process
    /// lifetime. Inserts are rare (recalls + CLARA heals), so save-on-mutate
    /// is cheap.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("state.tmp");
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)
    }

    /// YPX-022 §5 persistence — load from `path`. `None` if the file doesn't
    /// exist (fresh node — caller opens a new chain). `Err` only on real
    /// IO / decode failure so a corrupted record fails loudly.
    pub fn load(path: &std::path::Path) -> std::io::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        let chain: Self = ciborium::from_reader(&bytes[..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Some(chain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(n: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = n;
        h[31] = n;
        h
    }

    /// YPX-022 §5 — the garbage chain survives a restart via save/load
    /// (atomic CBOR). A recalled txid inserted before the save must still
    /// Hit after a reload; a fresh path loads None.
    #[test]
    fn garbage_chain_save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage_chain.state");
        assert!(GarbageStateChain::load(&path).unwrap().is_none(), "fresh path → None");

        let mut chain = GarbageStateChain::new_default(0);
        let recalled = make_state(0xE5);
        chain.insert(100, &recalled);
        chain.save(&path).unwrap();

        let reloaded = GarbageStateChain::load(&path).unwrap().expect("file exists");
        assert!(matches!(reloaded.lookup(&recalled), ChainLookup::Hit { .. }),
            "a recalled entry must survive the save/load round trip");
        assert_eq!(reloaded.lookup(&make_state(0x11)), ChainLookup::Miss,
            "an unknown entry still misses after reload");
    }

    #[test]
    fn test_new_garbage_chain_starts_with_one_era() {
        let chain = GarbageStateChain::new_default(1000);
        assert_eq!(chain.era_count(), 1);
        assert_eq!(chain.active_era_id(), 0);
    }

    #[test]
    fn test_insert_and_lookup_round_trip() {
        let mut chain = GarbageStateChain::new(0, 100, 1000);
        let s1 = make_state(1);
        let s2 = make_state(2);
        assert_eq!(chain.lookup(&s1), ChainLookup::Miss);
        chain.insert(50, &s1);
        match chain.lookup(&s1) {
            ChainLookup::Hit { era_id, .. } => assert_eq!(era_id, 0),
            ChainLookup::Miss => panic!("expected hit for s1"),
        }
        assert_eq!(chain.lookup(&s2), ChainLookup::Miss);
    }

    #[test]
    fn test_insert_at_boundary_rotates_era() {
        let mut chain = GarbageStateChain::new(0, 100, 1000);
        chain.insert(50, &make_state(1)); // era 0
        chain.insert(150, &make_state(2)); // crosses end_tick=100
        assert_eq!(chain.era_count(), 2);
        assert_eq!(chain.active_era_id(), 1);
        // Old garbage still findable in frozen era 0
        match chain.lookup(&make_state(1)) {
            ChainLookup::Hit { era_id, .. } => assert_eq!(era_id, 0),
            ChainLookup::Miss => panic!("garbage from prior era was lost"),
        }
        // New garbage in active era 1
        match chain.lookup(&make_state(2)) {
            ChainLookup::Hit { era_id, .. } => assert_eq!(era_id, 1),
            ChainLookup::Miss => panic!("expected hit in active era"),
        }
    }

    #[test]
    fn test_garbage_chain_is_separate_from_txid_chain() {
        // Two chains with the same content should NOT cross-pollute.
        // (This is more a type-system check than a runtime check — the
        // newtype prevents accidental insertion into the wrong chain.)
        let mut g1 = GarbageStateChain::new(0, 100, 1000);
        let mut g2 = GarbageStateChain::new(0, 100, 1000);
        g1.insert(50, &make_state(1));
        g2.insert(50, &make_state(1));
        // Both should agree on the same root since their content is identical
        let r1 = g1.inner().era(0).map(|e| e.meta.bloom_root);
        let r2 = g2.inner().era(0).map(|e| e.meta.bloom_root);
        assert_eq!(r1, r2);
    }
}
