// AXIOM Nabla — Bloom Filter for Txid Double-Redeem Detection
//
// Every Nabla node maintains a bloom filter of all txids ever registered.
// This provides O(1) double-redeem detection with bounded memory.
//
// Design:
//   - Every node has a bloom filter (baseline, ~12MB for 10M txids)
//   - Operators can ALSO enable HashMap mode (full txid→wallet_id map)
//   - HashMap nodes earn 5x CC score bonus (SCORE_TXID_HASHMAP_MULTIPLIER)
//   - HashMap nodes serve as authoritative txid oracles (zero false positives)
//   - Bloom-only nodes have ~0.1% false positive rate (client retries on rejection)
//
// Economics (§CC.txid):
//   HashMap mode requires more RAM but provides a higher-value service.
//   The 5x CC multiplier incentivizes operators with resources to run HashMap,
//   ensuring the network always has authoritative txid oracles available.
//   Bloom-only nodes still earn standard CC — they contribute to the baseline
//   security layer. The multiplier only applies while HashMap is complete
//   (fully synced). Incomplete or disabled HashMap = standard CC.
//
// Sync:
//   - Bloom is built locally from registrations arriving via gossip
//   - Each entry's tx_hash is inserted on put()
//   - On restart: bloom is rebuilt from WAL + snapshots (same as txid_index)
//   - Bloom is persisted to disk for fast restart (avoids full rebuild)
//   - HashMap nodes can export a fresh bloom for peers (periodic rebuild)
//
// Persistence:
//   - Bloom: serialized bit array + metadata, saved to `txid_bloom.bin`
//   - HashMap: entries persisted via existing WAL + snapshot mechanism
//   - Both rebuilt from the same source data (NablaEntry.tx_hash)

use serde::{Deserialize, Serialize};

use crate::types::TxHash;

/// Number of hash functions (k). With k=7 and m/n=10, false positive ≈ 0.8%.
/// With k=10 and m/n=14.4, false positive ≈ 0.1%.
const BLOOM_K: usize = 10;

/// Bloom filter for txid double-redeem detection.
///
/// Fixed-size bit array with k hash functions derived from BLAKE3.
/// Supports insert and query. No delete (txids are permanent).
#[derive(Clone, Serialize, Deserialize)]
pub struct TxidBloomFilter {
    /// Bit array (packed as bytes).
    bits: Vec<u8>,
    /// Number of bits in the filter (m).
    num_bits: u64,
    /// Number of items inserted.
    count: u64,
}

impl TxidBloomFilter {
    /// Create a bloom filter sized for `expected_items` with ~0.1% false positive rate.
    ///
    /// Formula: m = -n * ln(p) / (ln(2)^2)
    /// For p=0.001 (0.1%): m ≈ 14.4 * n bits
    pub fn new(expected_items: u64) -> Self {
        let num_bits = (expected_items as f64 * 14.4).ceil() as u64;
        // Minimum 1KB, round up to byte boundary
        let num_bits = num_bits.max(8192);
        let num_bytes = num_bits.div_ceil(8) as usize;
        Self {
            bits: vec![0u8; num_bytes],
            num_bits,
            count: 0,
        }
    }

    /// Create a bloom filter with a specific size in bytes.
    /// Used for deserialization / fixed-size allocation.
    pub fn with_size_bytes(size_bytes: usize) -> Self {
        Self {
            bits: vec![0u8; size_bytes],
            num_bits: (size_bytes as u64) * 8,
            count: 0,
        }
    }

    /// Insert a txid into the filter.
    pub fn insert(&mut self, txid: &TxHash) {
        if *txid == [0u8; 32] {
            return; // Skip zero txid (no transaction)
        }
        for i in 0..BLOOM_K {
            let bit_pos = self.hash_position(txid, i);
            let byte_idx = (bit_pos / 8) as usize;
            let bit_idx = (bit_pos % 8) as u8;
            if byte_idx < self.bits.len() {
                self.bits[byte_idx] |= 1 << bit_idx;
            }
        }
        self.count += 1;
    }

    /// Check if a txid MIGHT be in the filter.
    ///
    /// Returns:
    ///   false → DEFINITELY not in the filter (guaranteed)
    ///   true  → PROBABLY in the filter (false positive rate ~0.1%)
    pub fn may_contain(&self, txid: &TxHash) -> bool {
        if *txid == [0u8; 32] {
            return false;
        }
        for i in 0..BLOOM_K {
            let bit_pos = self.hash_position(txid, i);
            let byte_idx = (bit_pos / 8) as usize;
            let bit_idx = (bit_pos % 8) as u8;
            if byte_idx >= self.bits.len() {
                return false;
            }
            if self.bits[byte_idx] & (1 << bit_idx) == 0 {
                return false; // Bit not set → definitely not present
            }
        }
        true // All bits set → probably present
    }

    /// Number of items inserted.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Size of the filter in bytes.
    pub fn size_bytes(&self) -> usize {
        self.bits.len()
    }

    /// Estimated false positive rate at current fill level.
    pub fn estimated_fpr(&self) -> f64 {
        let m = self.num_bits as f64;
        let n = self.count as f64;
        let k = BLOOM_K as f64;
        if n == 0.0 {
            return 0.0;
        }
        (1.0 - (-k * n / m).exp()).powf(k)
    }

    /// BLAKE3-derived hash position for the i-th hash function.
    /// Uses domain separation: BLAKE3("AXIOM_BLOOM" || i_le || txid) mod num_bits.
    fn hash_position(&self, txid: &TxHash, i: usize) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_BLOOM");
        hasher.update(&(i as u32).to_le_bytes());
        hasher.update(txid);
        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();
        // Use first 8 bytes as u64, mod num_bits
        let val = u64::from_le_bytes([
            hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3],
            hash_bytes[4], hash_bytes[5], hash_bytes[6], hash_bytes[7],
        ]);
        val % self.num_bits
    }

    /// Serialize the bloom filter to bytes for disk persistence or network transfer.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("bloom serialize cannot fail")
    }

    /// Deserialize a bloom filter from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| format!("bloom deserialize: {}", e))
    }

    /// Merge another bloom filter into this one (bitwise OR).
    /// Used when syncing from a hashmap peer's exported bloom.
    /// Both filters must have the same size.
    /// Test-only: saturate every bit, to model a peer offering a poisoned filter.
    #[cfg(test)]
    pub fn set_all_bits_for_test(&mut self) {
        for b in self.bits.iter_mut() {
            *b = 0xFF;
        }
    }

    /// Fraction of bits set (0.0–1.0). Used to sanity-check a filter offered by a
    /// peer before adopting it — see `MAX_ADOPTABLE_BIT_DENSITY`.
    pub fn bit_density(&self) -> f64 {
        if self.bits.is_empty() {
            return 0.0;
        }
        let set: u32 = self.bits.iter().map(|b| b.count_ones()).sum();
        set as f64 / (self.bits.len() as f64 * 8.0)
    }

    pub fn merge(&mut self, other: &TxidBloomFilter) -> Result<(), String> {
        if self.bits.len() != other.bits.len() {
            return Err(format!(
                "bloom size mismatch: {} vs {}",
                self.bits.len(),
                other.bits.len()
            ));
        }
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= *b;
        }
        // Count is approximate after merge
        self.count = self.count.max(other.count);
        Ok(())
    }
}

impl std::fmt::Debug for TxidBloomFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TxidBloomFilter {{ size={}KB, count={}, fpr={:.4}% }}",
            self.bits.len() / 1024,
            self.count,
            self.estimated_fpr() * 100.0
        )
    }
}

/// Txid service mode — operator configurable.
///
/// Controls how this node stores and serves txid lookups.
/// Both modes maintain a bloom filter (baseline).
/// HashMap mode adds the full txid→wallet_id map for zero false positives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum TxidServiceMode {
    /// Bloom filter only. Low memory (~12MB for 10M txids). ~0.1% false positive.
    #[default]
    Bloom,
    /// Bloom + full HashMap. Higher memory but zero false positives.
    /// Earns 5x CC score multiplier (§CC.txid economics).
    Hashmap,
}


impl std::fmt::Display for TxidServiceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxidServiceMode::Bloom => write!(f, "bloom"),
            TxidServiceMode::Hashmap => write!(f, "hashmap"),
        }
    }
}

/// CC score multiplier for hashmap txid service nodes.
/// Applied when the node is running complete (fully synced) hashmap mode.
/// Standard CC = 1x. Hashmap CC = 5x.
pub const SCORE_TXID_HASHMAP_MULTIPLIER: u64 = 5;

/// Default bloom filter size: 10M expected txids (~18MB on disk).
pub const DEFAULT_BLOOM_EXPECTED_ITEMS: u64 = 10_000_000;

/// Maximum bit density we will ADOPT from a peer (KI#42).
///
/// `merge` validates only that dimensions match, then ORs the bits — and union is
/// permanent, since nothing ever clears a bloom. So a peer offering a heavily-set
/// filter permanently poisons the receiver: `is_state_consumed` starts answering
/// "yes" to everything, and because that gate FAILS CLOSED the node then rejects
/// every legitimate registration as a replay. Unrecoverable without wiping state.
/// The existing comment "an attacker peer's empty/forged view can't disarm us" is
/// true but covers only one direction — a hostile peer cannot disarm us, it can
/// OVER-arm us.
///
/// 0.80 is chosen so the guard costs nothing real: at k=10 a filter is ~50% set at
/// its design capacity and ~75% at twice it, and past ~80% its false-positive rate
/// exceeds ~10% — such a filter is not worth adopting anyway, because all it can
/// contribute is false positives. Refusing it loses no legitimate information.
pub const MAX_ADOPTABLE_BIT_DENSITY: f64 = 0.80;

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_txid(n: u8) -> TxHash {
        let mut h = [0u8; 32];
        h[0] = n;
        h[31] = n;
        h
    }

    #[test]
    fn insert_and_query() {
        let mut bloom = TxidBloomFilter::new(1000);
        let txid = make_txid(1);
        assert!(!bloom.may_contain(&txid));
        bloom.insert(&txid);
        assert!(bloom.may_contain(&txid));
        assert_eq!(bloom.count(), 1);
    }

    #[test]
    fn zero_txid_ignored() {
        let mut bloom = TxidBloomFilter::new(1000);
        bloom.insert(&[0u8; 32]);
        assert!(!bloom.may_contain(&[0u8; 32]));
        assert_eq!(bloom.count(), 0);
    }

    #[test]
    fn no_false_negatives() {
        let mut bloom = TxidBloomFilter::new(10000);
        let mut txids = Vec::new();
        for i in 1..1001u32 {  // Start at 1: i=0 produces zero txid which is skipped
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_le_bytes());
            txids.push(h);
            bloom.insert(&h);
        }
        // Every inserted txid MUST be found (no false negatives)
        for txid in &txids {
            assert!(bloom.may_contain(txid), "false negative for {:?}", &txid[..4]);
        }
    }

    #[test]
    fn false_positive_rate_bounded() {
        let mut bloom = TxidBloomFilter::new(10000);
        // Insert 10000 items
        for i in 0..10000u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_le_bytes());
            bloom.insert(&h);
        }
        // Check 10000 items that were NOT inserted
        let mut false_positives = 0;
        for i in 10000..20000u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_le_bytes());
            if bloom.may_contain(&h) {
                false_positives += 1;
            }
        }
        let fpr = false_positives as f64 / 10000.0;
        // Should be well under 1% for a filter sized for 10K items
        assert!(fpr < 0.01, "false positive rate too high: {:.2}%", fpr * 100.0);
    }

    #[test]
    fn serialize_roundtrip() {
        let mut bloom = TxidBloomFilter::new(1000);
        let txid = make_txid(42);
        bloom.insert(&txid);

        let bytes = bloom.to_bytes();
        let restored = TxidBloomFilter::from_bytes(&bytes).unwrap();
        assert!(restored.may_contain(&txid));
        assert!(!restored.may_contain(&make_txid(99)));
        assert_eq!(restored.count(), 1);
    }

    #[test]
    fn merge_combines_filters() {
        let mut a = TxidBloomFilter::new(1000);
        let mut b = TxidBloomFilter::new(1000);
        a.insert(&make_txid(1));
        b.insert(&make_txid(2));
        a.merge(&b).unwrap();
        assert!(a.may_contain(&make_txid(1)));
        assert!(a.may_contain(&make_txid(2)));
    }

    #[test]
    fn size_reasonable() {
        // 10M items should be ~18MB
        let bloom = TxidBloomFilter::new(10_000_000);
        let mb = bloom.size_bytes() as f64 / (1024.0 * 1024.0);
        assert!(mb < 20.0, "bloom too large: {:.1}MB", mb);
        assert!(mb > 10.0, "bloom too small: {:.1}MB", mb);
    }
}
