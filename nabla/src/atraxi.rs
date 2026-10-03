// AXIOM Nabla — ATRAXI: Adjudicated Threat and Risk Assessment & eXclusion Index
// Spec: docs/AXIOM_YPX-025_ATRAXI.md · Design: docs/AXIOM_DESIGN_ATRAXI.md
// Model (green): docs/models/atraxi/
//
// ⚠ BUILD IN PROGRESS. WIRED (increment 2) at the KI#205 register-door refusal:
// `nabla_node.rs` opens an A2 hold here when a redeem of a committed-recalled txid is
// refused, and `/status` exposes `atraxi_open_keys` / `atraxi_claims_opened` /
// `atraxi_held_refusals`. The hold RECORDS the refusal (the register-door gate in
// process_registration is what actually refuses); ATRAXI is not yet the sole
// authority. STILL TO COME: the evidence-carrying gossip variant (A2's PROVABLE
// recall commit, KI#205 residual 1 — today the committed marker is trusted, not
// self-verifying), and the CONSOLIDATION of the existing ban/freeze paths (E1
// double-spend, E2 seq-fork, E3 HAL fork, E4 §32 merge, E5 leaf status, E6 taint)
// onto this one table and vocabulary (YPX-025 §3). The index is in-memory; a hold
// missed on restart is re-derived when the evidence re-arrives (the register-door
// gate refuses regardless — fail-safe). WAL persistence lands with consolidation.
//
// THE RULE (YPX-025 §2, model-checked): a CLAIM opens on evidence a node verifies
// ITSELF and closes only on verified counter-evidence — never a node's word, a
// node-count threshold, or a timeout (those are the removed S6 endorsement model).
// The index of a key is the number of OPEN claims on it; index > 0 means the key is
// HELD (honest nodes refuse to lift its scar). A HOLD is not a BAN: a ban stays the
// existing permanent, proof-carrying verdict (ban.rs). This module records HOLDS.

use std::collections::HashMap;

use crate::types::{TxHash, WalletId};

/// The state a claim is about — a wallet bucket + a specific state id. Keying per
/// (wallet, state) (not per wallet) is a YPX-025 §4 ruling: a hold is about ONE state
/// and must not outlive it, and a per-wallet total could be diluted by unrelated
/// honest activity.
pub type AtraxiKey = (WalletId, [u8; 32]);

/// Why a key is held. Each kind names the two facts that cannot both stand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtraxiClaimKind {
    /// A2 (KI#205): a COMMITTED recall of `txid` and a k-attested redeem register of
    /// the same `txid`. The recall won by TARDIS stamp; the redeem's link is never
    /// confirmed and stays a permanent scar — a HOLD, never a wallet ban (the
    /// receiver's key is on one fact only). YPX-025 §5 A2.
    RecalledTxidRedeem { txid: TxHash },
    // A1 state fork / A4 HAL fork (→ existing BAN) and A5 derived taint are the
    // consolidation targets (YPX-025 §3 E1/E2/E4/E3/E6); added when those paths fold in.
}

/// One open claim on a key.
#[derive(Debug, Clone)]
pub struct AtraxiClaim {
    pub kind: AtraxiClaimKind,
    /// The node's own tick when it opened the claim (observability only — never a
    /// timeout input; a claim closes on evidence, not time).
    pub opened_tick: u64,
}

/// The per-node hold index. Lives BESIDE the SMT (like `bans`), never inside the leaf
/// (YPX-025 §4): a leaf-shape change would diverge the root while a dispute is open.
#[derive(Default)]
pub struct AtraxiIndex {
    /// key → its open claims. A key is present iff it has ≥ 1 open claim (HELD).
    claims: HashMap<AtraxiKey, Vec<AtraxiClaim>>,
    // ── /status counters (RULE 3 §2 — a hold nobody can see is a ghost) ──
    opened_total: u64,
    closed_total: u64,
    /// register/gossip operations refused because the key was HELD.
    held_refusals: u64,
}

impl AtraxiIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a claim on `key`. The CALLER has already verified the evidence (the
    /// index records verdicts, it does not verify — YPX-025 §2). Idempotent per
    /// (key, kind): re-opening the same claim is a no-op, so a replayed evidence
    /// gossip cannot inflate the index. Returns true iff this opened a NEW claim.
    pub fn open(&mut self, key: AtraxiKey, kind: AtraxiClaimKind, tick: u64) -> bool {
        let claims = self.claims.entry(key).or_default();
        if claims.iter().any(|c| c.kind == kind) {
            return false; // already open — idempotent, no double-count
        }
        claims.push(AtraxiClaim { kind, opened_tick: tick });
        self.opened_total = self.opened_total.saturating_add(1);
        true
    }

    /// Close a claim on `key` (verified counter-evidence resolved it). Returns true
    /// iff a claim of that kind was open. Never closes by vote or timeout — the caller
    /// passes a resolved kind only after verifying the resolving artifact.
    pub fn close(&mut self, key: &AtraxiKey, kind: &AtraxiClaimKind) -> bool {
        if let Some(claims) = self.claims.get_mut(key) {
            let before = claims.len();
            claims.retain(|c| &c.kind != kind);
            let removed = claims.len() < before;
            if claims.is_empty() {
                self.claims.remove(key);
            }
            if removed {
                self.closed_total = self.closed_total.saturating_add(1);
            }
            return removed;
        }
        false
    }

    /// Is this (wallet, state) HELD? (≥ 1 open claim.)
    pub fn is_held(&self, key: &AtraxiKey) -> bool {
        self.claims.get(key).is_some_and(|c| !c.is_empty())
    }

    /// The open-claim count on a key (the index value; 0 = not held).
    pub fn index(&self, key: &AtraxiKey) -> usize {
        self.claims.get(key).map_or(0, |c| c.len())
    }

    /// Record that a HELD key refused an operation (observability).
    pub fn note_held_refusal(&mut self) {
        self.held_refusals = self.held_refusals.saturating_add(1);
    }

    pub fn opened_total(&self) -> u64 { self.opened_total }
    pub fn closed_total(&self) -> u64 { self.closed_total }
    pub fn held_refusals(&self) -> u64 { self.held_refusals }
    /// Number of keys currently held (index > 0).
    pub fn open_keys(&self) -> usize { self.claims.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(w: u8, s: u8) -> AtraxiKey {
        let mut wid = [0u8; 32]; wid[0] = w;
        let mut st = [0u8; 32]; st[0] = s;
        (wid, st)
    }
    fn a2(t: u8) -> AtraxiClaimKind {
        let mut txid = [0u8; 32]; txid[0] = t;
        AtraxiClaimKind::RecalledTxidRedeem { txid }
    }

    #[test]
    fn open_holds_close_releases() {
        let mut ix = AtraxiIndex::new();
        let k = key(1, 2);
        assert!(!ix.is_held(&k));
        assert!(ix.open(k, a2(9), 100));
        assert!(ix.is_held(&k) && ix.index(&k) == 1 && ix.open_keys() == 1);
        assert!(ix.close(&k, &a2(9)));
        assert!(!ix.is_held(&k) && ix.index(&k) == 0 && ix.open_keys() == 0);
        assert_eq!((ix.opened_total(), ix.closed_total()), (1, 1));
    }

    #[test]
    fn open_is_idempotent_per_kind() {
        // A replayed evidence gossip must NOT inflate the index (YPX-025 §2 idempotent).
        let mut ix = AtraxiIndex::new();
        let k = key(1, 2);
        assert!(ix.open(k, a2(9), 100));
        assert!(!ix.open(k, a2(9), 101), "same (key,kind) re-open is a no-op");
        assert_eq!(ix.index(&k), 1);
        assert_eq!(ix.opened_total(), 1);
    }

    #[test]
    fn distinct_claims_stack_on_a_key_and_both_hold() {
        let mut ix = AtraxiIndex::new();
        let k = key(1, 2);
        ix.open(k, a2(9), 100);
        ix.open(k, a2(10), 101);         // a different txid = a different claim
        assert_eq!(ix.index(&k), 2, "two distinct claims both hold the key");
        assert!(ix.close(&k, &a2(9)));
        assert!(ix.is_held(&k), "still held while the second claim stands");
        assert!(ix.close(&k, &a2(10)));
        assert!(!ix.is_held(&k), "released only when the LAST claim closes");
    }

    #[test]
    fn close_absent_is_false_and_uncounted() {
        let mut ix = AtraxiIndex::new();
        assert!(!ix.close(&key(1, 2), &a2(9)));
        assert_eq!(ix.closed_total(), 0);
    }

    #[test]
    fn keys_are_independent_per_wallet_state() {
        let mut ix = AtraxiIndex::new();
        ix.open(key(1, 2), a2(9), 100);
        assert!(ix.is_held(&key(1, 2)));
        assert!(!ix.is_held(&key(1, 3)), "same wallet, different state — not held");
        assert!(!ix.is_held(&key(2, 2)), "different wallet — not held");
    }
}
