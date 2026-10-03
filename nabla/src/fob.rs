//! FOB — Fixed Outflow Balance (Bounded Pools). Design +
//! model: `docs/AXIOM_DESIGN_BoundedPools.md`,
//! `docs/models/fob_bounded_pools/` (all §9 obligations TLC-discharged).
//!
//! This module is the SELF-CONTAINED value-logic core of FOB — the two-state
//! pool, the pure tranche function, and the mover-sortition / eligibility
//! helpers. It touches NO wire format, NO PoolKind enum, NO CoreID artifact:
//! it is pure logic that mirrors the TLC conservation + uniqueness specs, so it
//! is native-testable in isolation (Phase 1a). Wiring it into `PoolKind`,
//! PoolSync, and the tick loop is Phase 1b–d.
//!
//! Naming: a **FOB** is a fob watch — value sits sealed and inert while FULL,
//! the operator OPENS it (withdraws in full) to release it (§11; the fob watch
//! and JUDOON share one Doctor Who episode, *Fugitive of the Judoon*).
//!
//! Invariants this module enforces (each maps to a `docs/models/fob_bounded_pools`
//! obligation), so the wiring layers cannot violate them:
//!   * **two-state** — a Fee FOB is only ever EMPTY (0) or FULL (a valid
//!     tranche amount); a tranche fires ONLY onto an empty pool
//!     (refill-requires-empty, §4.1), a withdrawal is the WHOLE balance
//!     (withdraw-full-only, §4.1).
//!   * **NoWedge** — a tranche is SKIPPED below the spendable dust floor
//!     (rule 3, §4): a sub-`tranche_min` FOB balance could never be
//!     withdrawn (the sweep tx would itself dust-reject) and would wedge the
//!     pool forever.
//!   * **conservation** — the pool only rises by a valid tranche and only
//!     falls by a full sweep, so nothing is minted or lost.

// FOB economics AND §5 mover eligibility live in CORE (validation.rs:
// `compute_fob_tranche`, `fob_mover_eligible`, `fob_assert_boot_guard`) — both
// the tranche AMOUNT and WHO may author it gate a value movement, so they are
// Core-computed + Core-verified by every Nabla, RULE 5 (design §4/§5, decided
// 2026-08-09). Nabla owns only the carrier TIMING (sortition rank, epoch
// length, gossip). Do NOT reintroduce a Nabla-side tranche function OR a
// Nabla-side eligibility floor — those were the Pattern-1 / RULE-5 duplicates
// this consolidation removed. Imported via the `validation` path (economic
// math, NOT crypto), same as the sibling `compute_deed_split` — the crypto
// boundary gate (`cc.rs::no_direct_core_crypto_in_production_code`) reserves
// the `compute::`/`verify::` re-export modules for hashing/signature primitives.
use axiom_core_logic::validation::{compute_deed_split, compute_fob_tranche, fob_mover_eligible};

/// The convergent per-validator NET accumulator (§10.1b, RULE 5). Sums this
/// validator's post-DEED `net_per_slot` across its earnings entries, applying
/// Core's `compute_deed_split` PER TX — so the leftover-atom distribution
/// matches every recording node byte-for-byte (the split's remainder is seeded
/// by `tx_hash`+`tick`, NOT a flat 90%). The `entries` come from
/// `smt::validator_earnings` (GROSS), itself rebuilt from the replicated
/// `txid_records` "one source of truth" (`ValidatorFeeLedger.md` §3.5) — so
/// every recording node derives the SAME number. **Never** source this from
/// `validator_net_ledger` (local-only, non-convergent). This is the raw net
/// EARNED; the amount available to tranche is this minus the pool's
/// `tranched_total` (what has already moved into the FOB).
pub fn fob_net_earned(
    vid: &[u8; 32],
    entries: &[axiom_core_logic::wire_client::EarningsEntry],
    genesis_news_anchor: u64,
) -> u64 {
    let mut net_total: u64 = 0;
    for e in entries {
        let split =
            compute_deed_split(&e.full_fee_breakdown, &e.tx_hash, e.tick, genesis_news_anchor);
        // A validator can hold at most one slot per TX, but sum defensively.
        for (i, share) in e.full_fee_breakdown.iter().enumerate() {
            if &share.validator_id == vid {
                net_total =
                    net_total.saturating_add(split.net_per_slot.get(i).copied().unwrap_or(0));
            }
        }
    }
    net_total
}

/// A per-validator Fee FOB pool. Two-state by construction: `balance` is
/// private and moves ONLY through [`FobPool::try_tranche`] (empty → full) and
/// [`FobPool::withdraw_full`] (full → empty). No other mutator exists, so a
/// partial balance is unrepresentable — the audit reduces to `balance == 0 ||
/// balance == last tranche amount`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FobPool {
    balance: u64,
    /// cumulative value ever tranched in (conservation bookkeeping / audit).
    /// MUST persist across restarts — the FOB accumulator available to tranche
    /// is `fob_net_earned(vid) - tranched_total`, so a lost `tranched_total`
    /// re-tranches already-moved value (double-count). It is the durable
    /// debit-cursor against the convergent earnings.
    tranched_total: u64,
    /// cumulative value ever withdrawn (full sweeps).
    withdrawn_total: u64,
}

/// Why a tranche into a FOB was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrancheRefused {
    /// The pool is not EMPTY — refill-requires-empty (§4.1). The prior tranche
    /// must be withdrawn (in full) before another lands.
    NotEmpty,
    /// `f` said SKIP (amount below the spendable dust floor, rule 3).
    Skipped,
}

impl FobPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// KI#84 — build a pool DIRECTLY from the two replicated ledgers:
    /// `plus` = Σ committee tranches for this pool, `minus` = Σ claim sweeps.
    /// `balance = plus − minus` (saturating; under refill-requires-empty this is
    /// 0 or the last tranche amount). This is the convergence primitive — a
    /// pool is a pure function of the ledgers, so set-union AE of the ledgers
    /// converges every recorder to the identical pool. Conservation
    /// (`balance + withdrawn == tranched`) holds by construction.
    pub fn from_ledgers(plus: u64, minus: u64) -> Self {
        Self {
            balance: plus.saturating_sub(minus),
            tranched_total: plus,
            withdrawn_total: minus,
        }
    }

    pub fn balance(&self) -> u64 {
        self.balance
    }
    pub fn is_empty(&self) -> bool {
        self.balance == 0
    }
    pub fn tranched_total(&self) -> u64 {
        self.tranched_total
    }
    pub fn withdrawn_total(&self) -> u64 {
        self.withdrawn_total
    }

    /// Apply an epoch tranche of `accumulator` into this pool. Fee FOBs are
    /// refill-requires-empty: a tranche onto a non-empty pool is a REFUSAL
    /// (`NotEmpty`), not an add — that is the two-state guarantee and the
    /// second wall against double-tranche. Returns the amount moved (to debit
    /// the accumulator) or a refusal. Rule 3 SKIP is a refusal too (the value
    /// stays in the accumulator).
    pub fn try_tranche(&mut self, accumulator: u64) -> Result<u64, TrancheRefused> {
        if self.balance != 0 {
            return Err(TrancheRefused::NotEmpty);
        }
        // CORE computes the authoritative amount (0 = rule-3 SKIP).
        match compute_fob_tranche(accumulator) {
            0 => Err(TrancheRefused::Skipped),
            amount => {
                self.balance = amount;
                self.tranched_total = self.tranched_total.saturating_add(amount);
                Ok(amount)
            }
        }
    }

    /// Adopt a PRE-VERIFIED tranche `amount` (the RECEIVE path). Unlike
    /// [`FobPool::try_tranche`], this does NOT recompute from an accumulator: the
    /// caller has already judged `amount == compute_fob_tranche(balance_used)`
    /// over the statement's PINNED input, so every node adopts the identical
    /// value regardless of its own (skewed) accumulator view — that is what keeps
    /// `tranched_total` and `balance` convergent across the mesh. Empty → full
    /// (refill-requires-empty); a zero amount is a SKIP refusal.
    pub fn adopt_tranche(&mut self, amount: u64) -> Result<(), TrancheRefused> {
        if self.balance != 0 {
            return Err(TrancheRefused::NotEmpty);
        }
        if amount == 0 {
            return Err(TrancheRefused::Skipped);
        }
        self.balance = amount;
        self.tranched_total = self.tranched_total.saturating_add(amount);
        Ok(())
    }

    /// Adopt a committee-authorised tranche `amount`, SWEEPING any stale full
    /// balance first (the missed-withdrawal RESYNC path — see `fob_reconcile`).
    /// Unlike [`FobPool::adopt_tranche`] this does NOT refuse a non-empty pool:
    /// a valid current-epoch credit proves the committee saw the pool empty
    /// (refill-requires-empty at authoring), so a local full balance means this
    /// node MISSED the withdrawal — and stranding the pool is worse than
    /// sweeping the stale balance. The swept amount is booked to
    /// `withdrawn_total` exactly as a real sweep, so conservation
    /// (`tranched_total == balance + withdrawn_total`) still holds. Used ONLY by
    /// the PoolSync reconcile-adopt arm, never by authoring.
    pub fn adopt_tranche_resync(&mut self, amount: u64) -> Result<(), TrancheRefused> {
        if amount == 0 {
            return Err(TrancheRefused::Skipped);
        }
        if self.balance != 0 {
            self.withdraw_full();
        }
        self.balance = amount;
        self.tranched_total = self.tranched_total.saturating_add(amount);
        Ok(())
    }

    /// Withdraw the WHOLE balance (withdraw-full-only, §4.1) — the only legal
    /// decrease. Returns the swept amount (0 if already empty). Leaves the pool
    /// EMPTY, ready to refill next epoch.
    pub fn withdraw_full(&mut self) -> u64 {
        let swept = self.balance;
        self.balance = 0;
        self.withdrawn_total = self.withdrawn_total.saturating_add(swept);
        swept
    }

    /// Conservation invariant (audit / debug): everything ever tranched in is
    /// either still held or has been withdrawn. Must hold at every point.
    pub fn conserves(&self) -> bool {
        self.balance + self.withdrawn_total == self.tranched_total
    }
}

/// Mover sortition — the deterministic committee rank (§3). Every node computes
/// this identically for the current epoch over the NBC-eligible roster; the 3
/// LOWEST ranks are the movers. Mirrors the normative `AXIOM_MV_SELECT`
/// precedent but keyed `AXIOM_FOB_MOVER` and (Phase 1b) fed the TARDIS tick,
/// never `SystemTime`.
pub fn mover_rank(node_pk: &[u8; 32], epoch_id: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_FOB_MOVER");
    h.update(node_pk);
    h.update(&epoch_id.to_le_bytes());
    *h.finalize().as_bytes()
}

// The §5 eligibility gate is CORE-OWNED: `validation::fob_mover_eligible(oods_size,
// baseline)` (fails closed on baseline==0; floor `FOB_MOVER_OODS_FLOOR_PCT`).
// It was a Nabla-local `mover_eligible(oods, baseline, floor_pct)` here until
// 2026-08-09 — a RULE-5 hole, since a mover's eligibility gates whether it may
// author a value-moving tranche and every Nabla's Core must judge it with the
// SAME floor. Moved to Core (validation.rs) alongside the tranche amount; the
// floor param is gone from every signature below.

/// The FOB mover committee size (§3): the 3 lowest-ranked eligible nodes.
pub const FOB_COMMITTEE_SIZE: usize = 3;

/// §4 skew-ALERT tolerance (atoms): how far a statement's pinned `balance_used`
/// may diverge from a RECORDING auditor's own accumulator view before an
/// alert-grade discrepancy is raised. It NEVER blocks (the exact math over the
/// pinned input is the gate); it only bounds fee-arrival-lag noise. Bloom nodes
/// hold no accumulator, so the caller passes `u64::MAX` to disable the skew
/// check for them and leans on the exact check (which runs everywhere).
/// Infrastructure/alert-grade — tunable without CoreID impact.
pub const FOB_SKEW_ALERT_TOLERANCE_ATOMS: u64 = 1_000_000_000; // 0.1 AXC

/// One NBC-eligible node's inputs to the §5 gate for an epoch.
#[derive(Debug, Clone, Copy)]
pub struct MoverCandidate {
    pub node_pk: [u8; 32],
    /// current attested OODS view size (the LHS of the §5 gate).
    pub oods_size_now: u64,
    /// the node's NBC-stamped `network_size_baseline` (the RHS yardstick).
    pub nbc_baseline: u64,
}

/// Epoch id for a TARDIS tick (§6): `floor(tick / duration)`. The shared clock
/// is the tick VALUE (unix secs, KI#47) — NEVER `SystemTime` (unlike the
/// legacy `AXIOM_MV_SELECT` hour bucket). Every node computes the same number;
/// nobody acts at the same instant (§6). Duration 0 ⇒ epoch 0 (defensive).
///
/// ⚠ UNIT (KI#165, 2026-09-25): `epoch_duration_ticks` MUST be a tick-VALUE span in
/// the same unit as `tardis_tick` — i.e. the COUNT register projected through
/// `constants::fob_epoch_span_secs`. Passing the raw COUNT (`fob_epoch_ticks`) made
/// every real epoch 150,000 s (1.74 d) instead of the ~8.7 d the register promises.
pub fn epoch_id(tardis_tick: u64, epoch_duration_ticks: u64) -> u64 {
    if epoch_duration_ticks == 0 {
        return 0;
    }
    tardis_tick / epoch_duration_ticks
}

/// The ordered eligible mover roster for an epoch (§3+§5): the NBC-eligible
/// candidates, sorted ascending by `mover_rank` (ties broken by pk for total
/// determinism — a rank collision is a 256-bit BLAKE3 event, but the order
/// must be identical on every node regardless). The COMMITTEE is the first
/// [`FOB_COMMITTEE_SIZE`]; the remainder are the deterministic substitutes a
/// caller promotes when a top-3 mover is silent past the grace window. Returns
/// pks in rank order.
///
/// A result shorter than `FOB_COMMITTEE_SIZE` means NO valid committee this
/// epoch — the caller SKIPS the tranche (SkipIsSafe, §5): bounded pools simply
/// do not refill, one-way safety holds, it self-heals next epoch.
pub fn ranked_eligible_movers(roster: &[MoverCandidate], epoch: u64) -> Vec<[u8; 32]> {
    let mut ranked: Vec<([u8; 32], [u8; 32])> = roster
        .iter()
        .filter(|c| fob_mover_eligible(c.oods_size_now, c.nbc_baseline))
        .map(|c| (mover_rank(&c.node_pk, epoch), c.node_pk))
        .collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    ranked.into_iter().map(|(_, pk)| pk).collect()
}

/// A single pool's tranche in an epoch statement (§4). `balance_used` is the
/// accumulator value the movers PINNED (so the audit is exact against the
/// statement's own input, not a racing live view); `amount` is their claim of
/// `f(balance_used)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TrancheEntry {
    /// the FOB this funds — a validator_id for a Fee FOB (DEED uses a fixed
    /// marker, out of Phase-1 scope).
    pub pool_id: [u8; 32],
    pub balance_used: u64,
    pub amount: u64,
}

/// One epoch's batched tranche (§4, §8): ONE statement covers every pool that
/// moved. The mover signatures + eligibility attestations attach at the wire
/// layer (Phase 1d); this is the signed CONTENT.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TrancheStatement {
    pub epoch_id: u64,
    /// The fund CLASS this statement tranches (§10.2a) — dev fund vs real fund.
    /// One statement is entirely one class (dev/real run different epochs), and
    /// the bit is bound into the signed payload so a dev statement can't be
    /// replayed as a real one. Every entry applies to `(pool_id, is_dev)`.
    pub is_dev: bool,
    pub entries: Vec<TrancheEntry>,
}

/// One mover's contribution to a `GossipMessage::FobTranche` (§4, §5): the
/// mover's `NablaOodsAttestation` (Core-verifiable — proves the signer's
/// identity `nabla_node_pk`, its current OODS-gossip `oods_size`, and its
/// NBC-stamped `baseline_size`, so the auditor can run the §5 gate) plus the
/// mover's Ed25519 signature over `tranche_statement_payload(epoch, entries)`
/// (proves it authored THIS statement). The signing key is
/// `att.nabla_node_pk`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FobMoverSig {
    pub att: axiom_core_logic::types::NablaOodsAttestation,
    /// 64-byte Ed25519 sig by `att.nabla_node_pk` over the statement payload.
    pub statement_sig: Vec<u8>,
}

/// The canonical payload the movers sign over a statement (domain tag
/// `AXIOM_FOB_TRANCHE`). ONE builder — every signer and auditor recomputes it
/// identically (Pattern-1 discipline). Length-prefixed so entry boundaries are
/// unambiguous.
pub fn tranche_statement_payload(epoch_id: u64, is_dev: bool, entries: &[TrancheEntry]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_FOB_TRANCHE");
    h.update(&epoch_id.to_le_bytes());
    h.update(&[is_dev as u8]); // bind the class — a dev statement is not a real one
    h.update(&(entries.len() as u64).to_le_bytes());
    // CANONICAL ORDER — the committee has NO coordination (§3): each recorder
    // builds `entries` by iterating `validator_ids_with_earnings()`, a HashMap
    // whose key order is per-PROCESS random. Hashing in that order would make
    // the 3 recorders derive the SAME entries in DIFFERENT order → three
    // different payload hashes → their partials land in different `fob_pending`
    // buckets and NEVER aggregate to a committee (found live 2026-08-10: 100+
    // authored, 0 accepted). Hash in pool_id order so every recorder AND every
    // receiver derives ONE payload regardless of input order.
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by(|&a, &b| entries[a].pool_id.cmp(&entries[b].pool_id));
    for i in order {
        let e = &entries[i];
        h.update(&e.pool_id);
        h.update(&e.balance_used.to_le_bytes());
        h.update(&e.amount.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// The verdict of auditing ONE tranche entry (§4 pinned-input audit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditVerdict {
    /// exact math holds and the pinned input is within skew of the auditor's
    /// own accumulator view.
    Ok,
    /// `amount != f(balance_used)` (or an entry exists for a SKIP). Structurally
    /// impossible from honest movers ⇒ JUDOON Layer-1 quarantine of ALL signers,
    /// single observer, no consensus (§4). Proof-shaped.
    Quarantine,
    /// exact math holds, but `balance_used` diverges from the auditor's own
    /// accumulator view beyond `skew_tolerance` — fee records arrive async, so
    /// this is ALERT-grade only; NEVER quarantine on it alone (§4).
    Alert,
}

/// Audit one tranche entry against the auditor's own view (§4). The exact
/// check (quarantine-grade) is separate from the skew check (alert-grade) —
/// mixing them would false-quarantine on ordinary fee-arrival lag.
pub fn audit_tranche_entry(
    entry: &TrancheEntry,
    own_accumulator_view: u64,
    skew_tolerance: u64,
) -> AuditVerdict {
    // exact math FIRST, over the statement's OWN pinned balance_used — the
    // authoritative amount is CORE's `compute_fob_tranche` (0 = rule-3 skip; an
    // honest statement never contains a skip entry).
    let expected = compute_fob_tranche(entry.balance_used);
    if expected == 0 || entry.amount != expected {
        return AuditVerdict::Quarantine;
    }
    // skew (alert-grade): is the pinned input close to what we hold?
    if entry.balance_used.abs_diff(own_accumulator_view) > skew_tolerance {
        AuditVerdict::Alert
    } else {
        AuditVerdict::Ok
    }
}

/// A bounded-fee PoolSync reconcile outcome (§7 new arm). The wire layer
/// (Phase 1d) verifies mover sigs + eligibility + audits the statement, then
/// hands the decision here as a pure function of balances + an optional
/// already-verified tranche credit. Keeping the DECISION pure is what lets the
/// TLC obligations (NoMint, RefillRequiresEmpty, two-state) be reproduced as
/// unit tests without a live mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FobReconcile {
    /// peer balance == local — nothing to do.
    NoOp,
    /// a valid current-epoch tranche credits this pool — adopt the new (full)
    /// balance.
    AdoptTranche(u64),
    /// peer swept the pool to zero (a full withdrawal) — adopt EMPTY.
    AdoptWithdrawal,
    /// JUDOON structural violation — quarantine the advertising peer (§7).
    StructuralViolation(FobViolation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FobViolation {
    /// the pool ROSE with no valid tranche statement backing it (NoMint).
    IncreaseWithoutTranche,
    /// the advertised balance != the tranche amount the statement authorises.
    /// (A tranche landing on a still-full pool is NOT a violation when a valid
    /// current-epoch credit matches it — that is a missed-withdrawal resync,
    /// see `fob_reconcile`. Only a credit-vs-balance MISMATCH is structural.)
    IncreaseAmountMismatch,
    /// the pool DECREASED to a nonzero value — not a full sweep
    /// (withdraw-full-only, §4.1); a two-state pool has no partial-drain state.
    PartialDecrease,
}

/// The §7 reconcile decision for one bounded-fee pool. `verified_tranche` is
/// `Some(amount)` iff the wire layer confirmed a valid current-epoch statement
/// crediting THIS pool with `amount` (movers signed + eligible + audit-clean);
/// `None` otherwise. Pure — no crypto, no IO.
pub fn fob_reconcile(
    local_balance: u64,
    peer_balance: u64,
    verified_tranche: Option<u64>,
) -> FobReconcile {
    use core::cmp::Ordering::*;
    if peer_balance == local_balance {
        return FobReconcile::NoOp;
    }
    // MISSED-WITHDRAWAL CONVERGENCE (design decision 2026-08-10). PoolSync carries only the
    // CURRENT balance, not an event log, so a node can miss the intermediate
    // empty state of a withdraw→re-tranche cycle and see the new tranche land
    // directly on its still-full pool. A valid current-epoch tranche credit for
    // the EXACT advertised balance is the committee's authorization to adopt it:
    // the committee authors a tranche ONLY onto an empty pool (refill-requires-
    // empty, enforced at authoring AND in the judge), so a valid credit PROVES
    // the pool was empty at that epoch — any non-empty local balance is stale
    // (this node missed the withdrawal). Adopt it, sweeping the stale balance
    // (the application resyncs via `FobPool::adopt_tranche_resync`). This is what
    // stops a withdrawal from STRANDING a pool. Conservation still rests on Core
    // at the withdrawal mint (RULE 5); the Nabla arm is local hygiene.
    if let Some(amount) = verified_tranche {
        if amount == peer_balance {
            // amount != 0 always here: peer_balance == local_balance == 0 was
            // the NoOp above, and a 0 credit is never produced (rule-3 SKIP).
            return FobReconcile::AdoptTranche(amount);
        }
    }
    match peer_balance.cmp(&local_balance) {
        Equal => FobReconcile::NoOp, // unreachable — handled above
        Greater => {
            // an INCREASE with no matching credit: never a tranche.
            match verified_tranche {
                None => FobReconcile::StructuralViolation(FobViolation::IncreaseWithoutTranche),
                // a credit exists but for a DIFFERENT amount → the advertised
                // balance is not what the committee authorised.
                Some(_) => FobReconcile::StructuralViolation(FobViolation::IncreaseAmountMismatch),
            }
        }
        Less => {
            // a DECREASE is legal ONLY as a full sweep to zero.
            if peer_balance == 0 {
                FobReconcile::AdoptWithdrawal
            } else {
                FobReconcile::StructuralViolation(FobViolation::PartialDecrease)
            }
        }
    }
}

/// A mover whose crypto the node has ALREADY verified (attestation signature +
/// NBC chain via `verify_oods_attestation`, and the `statement_sig` over the
/// payload). `judge_tranche_statement` takes these so it stays pure — the
/// crypto lives at the node boundary, the DECISION is testable in isolation.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedMover {
    pub node_pk: [u8; 32],
    /// the mover's attested current OODS-gossip size (§5 LHS).
    pub oods_size: u64,
    /// the mover's NBC-stamped baseline (§5 RHS).
    pub baseline: u64,
}

/// The receive-path verdict for a whole `FobTranche` statement (§4/§5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatementVerdict {
    /// Reconcile these `(pool_id, amount)` credits. `alerted` = an alert-grade
    /// discrepancy was seen (committee-roster mismatch under §5 tolerance, or a
    /// view-skew on an entry per §4) — the math is EXACT so the value is real
    /// and IS accepted; the caller ALSO raises an operator/K-of-N alert. A
    /// skew/roster alert MUST NOT block the tranche (§4: "must NOT quarantine").
    Accept { credits: Vec<([u8; 32], u64)>, alerted: bool },
    /// A structural violation — a signer that attested itself INELIGIBLE, an
    /// under-sized committee, or an exact-math mismatch on an entry. JUDOON
    /// Layer-1 quarantines ALL signers, single observer, no consensus (§4).
    Quarantine(FobViolation),
}

/// Rank a roster of pks by `mover_rank` for an epoch (ties by pk, total order)
/// and return the first `n` — the committee. The caller passes an
/// already-eligible roster.
pub fn rank_committee(roster: &[[u8; 32]], epoch: u64, n: usize) -> Vec<[u8; 32]> {
    let mut ranked: Vec<([u8; 32], [u8; 32])> =
        roster.iter().map(|pk| (mover_rank(pk, epoch), *pk)).collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    ranked.into_iter().take(n).map(|(_, pk)| pk).collect()
}

/// The receive-path judgment (§4/§5), PURE. Crypto (attestation + statement
/// sig) is the caller's job; this decides eligibility + committee + math.
///
/// Quarantine-grade checks (a self-attested-ineligible signer, an under-sized
/// committee, an exact-math violation) fire BEFORE the alert-grade ones
/// (committee-roster mismatch, view skew) — a real violation must never be
/// downgraded to an alert by a coincident roster difference.
pub fn judge_tranche_statement(
    epoch_id: u64,
    entries: &[TrancheEntry],
    movers: &[VerifiedMover],
    eligible_roster: &[[u8; 32]],
    own_accumulator_view: impl Fn(&[u8; 32]) -> u64,
    skew_tolerance: u64,
) -> StatementVerdict {
    // (1) QUARANTINE: a statement needs a full committee.
    if movers.len() < FOB_COMMITTEE_SIZE {
        return StatementVerdict::Quarantine(FobViolation::IncreaseWithoutTranche);
    }
    // (2) QUARANTINE: every signer must have attested itself ELIGIBLE (its OWN
    //     signed oods_size >= floor% of its OWN baseline). Authoring while your
    //     own signed attestation says ineligible is proof-shaped.
    for m in movers {
        if !fob_mover_eligible(m.oods_size, m.baseline) {
            return StatementVerdict::Quarantine(FobViolation::IncreaseWithoutTranche);
        }
    }
    // (3) QUARANTINE: exact math on every entry, over its PINNED input; collect
    //     skew alerts (do NOT block — the math is exact, so the value is real).
    let mut credits: Vec<([u8; 32], u64)> = Vec::with_capacity(entries.len());
    let mut alerted = false;
    for e in entries {
        match audit_tranche_entry(e, own_accumulator_view(&e.pool_id), skew_tolerance) {
            AuditVerdict::Quarantine => {
                return StatementVerdict::Quarantine(FobViolation::IncreaseAmountMismatch)
            }
            AuditVerdict::Alert => alerted = true,
            AuditVerdict::Ok => {}
        }
        credits.push((e.pool_id, e.amount));
    }
    // (4) ALERT (tolerant, §5): are the signers the auditor's own committee for
    //     this epoch? A mismatch alerts but does not block — rosters differ by
    //     gossip lag, and any eligible committee is safe (bounded + one-per-
    //     epoch via refill-requires-empty).
    let mut signer_pks: Vec<[u8; 32]> = movers.iter().map(|m| m.node_pk).collect();
    signer_pks.sort();
    let mut expected = rank_committee(eligible_roster, epoch_id, FOB_COMMITTEE_SIZE);
    expected.sort();
    if signer_pks != expected {
        alerted = true;
    }
    StatementVerdict::Accept { credits, alerted }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Core-scale accumulators (the economics + their edge cases are tested in
    // core/logic::fob_tranche_tests; here we test the POOL behaviour against the
    // authoritative Core amount). 1 AXC = the rule-2 boundary.
    const ONE_AXC: u64 = 10_000_000_000;
    const SUB_FLOOR: u64 = 400_000; // < 500_000 floor => compute_fob_tranche == 0 (skip)

    #[test]
    fn try_tranche_uses_core_amount_and_skips_sub_floor() {
        let mut pool = FobPool::new();
        let amt = compute_fob_tranche(ONE_AXC); // 30% of 1 AXC
        assert_eq!(pool.try_tranche(ONE_AXC), Ok(amt));
        assert_eq!(pool.balance(), amt);
        // a sub-floor accumulator => Core returns 0 => Skipped (rule-3 wedge guard)
        let mut p2 = FobPool::new();
        assert_eq!(p2.try_tranche(SUB_FLOOR), Err(TrancheRefused::Skipped));
        assert!(p2.is_empty());
    }

    #[test]
    fn two_state_refill_requires_empty_and_full_sweep() {
        let amt = compute_fob_tranche(ONE_AXC);
        let mut pool = FobPool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.try_tranche(ONE_AXC), Ok(amt));       // empty -> FULL
        assert_eq!(pool.balance(), amt);
        assert_eq!(pool.try_tranche(ONE_AXC), Err(TrancheRefused::NotEmpty)); // refill-requires-empty
        assert_eq!(pool.balance(), amt, "refused tranche did not stack");
        assert_eq!(pool.withdraw_full(), amt);               // withdraw-full-only
        assert!(pool.is_empty());
        assert_eq!(pool.try_tranche(ONE_AXC), Ok(amt));       // refillable again
        assert!(pool.conserves());
    }

    #[test]
    fn adopt_tranche_is_two_state_and_refill_requires_empty() {
        let mut pool = FobPool::new();
        // pre-verified amount adopted directly (the receive path).
        assert_eq!(pool.adopt_tranche(3_000_000_000), Ok(()));
        assert_eq!(pool.balance(), 3_000_000_000);
        assert_eq!(pool.tranched_total(), 3_000_000_000);
        // refill onto a full pool refuses (the double-count guard).
        assert_eq!(pool.adopt_tranche(1), Err(TrancheRefused::NotEmpty));
        assert_eq!(pool.balance(), 3_000_000_000, "refused adopt did not stack");
        // a zero amount is a SKIP refusal.
        let mut p2 = FobPool::new();
        assert_eq!(p2.adopt_tranche(0), Err(TrancheRefused::Skipped));
        assert!(p2.is_empty());
    }

    #[test]
    fn fob_net_earned_applies_the_deed_split_per_tx() {
        use axiom_core_logic::wire_client::EarningsEntry;
        use axiom_core_logic::types::FeeShare;
        let vid = [0x11u8; 32];
        let anchor = axiom_core_logic::genesis_integrity::GENESIS_NEWS_ANCHOR;
        // Two TXs, each a single 100-atom slot for `vid`. DEED = 10% of each TX's
        // total (100) = 10; net_per_slot = 90. Two TXs → 180 net.
        let entries = vec![
            EarningsEntry {
                tx_hash: [1u8; 32],
                amount: 100,
                tick: 0, // <= DEED cutoff → DEED collects
                full_fee_breakdown: vec![FeeShare { validator_id: vid, amount: 100 }],
            },
            EarningsEntry {
                tx_hash: [2u8; 32],
                amount: 100,
                tick: 0,
                full_fee_breakdown: vec![FeeShare { validator_id: vid, amount: 100 }],
            },
        ];
        assert_eq!(fob_net_earned(&vid, &entries, anchor), 180, "90% net × 2 TXs");
        // a validator not in any breakdown earns nothing.
        assert_eq!(fob_net_earned(&[0x22u8; 32], &entries, anchor), 0);
    }

    #[test]
    fn conservation_holds_across_cycles() {
        let mut pool = FobPool::new();
        for _ in 0..5 {
            let _ = pool.try_tranche(ONE_AXC);
            assert!(pool.conserves());
            pool.withdraw_full();
            assert!(pool.conserves());
        }
        assert_eq!(pool.tranched_total(), pool.withdrawn_total());
    }

    // The §5 eligibility gate itself (floor boundary, fail-closed baseline==0,
    // the >50% double-tranche-impossibility property) is CORE-owned now — its
    // unit tests live in `core/logic::fob_tranche_tests` alongside
    // `fob_mover_eligible` (RULE 1: test the rule where it is defined). Here we
    // only test the Nabla-owned SORTITION that consumes it (below).

    #[test]
    fn mover_rank_is_deterministic_and_epoch_bound() {
        let pk = [7u8; 32];
        assert_eq!(mover_rank(&pk, 5), mover_rank(&pk, 5), "deterministic");
        assert_ne!(mover_rank(&pk, 5), mover_rank(&pk, 6), "epoch-bound");
        assert_ne!(mover_rank(&pk, 5), mover_rank(&[8u8; 32], 5), "pk-bound");
    }
}

#[cfg(test)]
mod tests_selection {
    use super::*;

    fn cand(pk: u8, oods: u64, base: u64) -> MoverCandidate {
        MoverCandidate { node_pk: [pk; 32], oods_size_now: oods, nbc_baseline: base }
    }

    #[test]
    fn epoch_id_floors_by_duration() {
        assert_eq!(epoch_id(0, 100), 0);
        assert_eq!(epoch_id(99, 100), 0);
        assert_eq!(epoch_id(100, 100), 1);
        assert_eq!(epoch_id(150_001, 150_000), 1);
        assert_eq!(epoch_id(42, 0), 0, "zero duration is defensive epoch 0");
    }

    /// KI#165 — the register is a tick COUNT; the divisor `epoch_id` receives must be
    /// its projection. 150_000 ticks × 5 s = 750_000 s ≈ 8.68 d, the promised "~8.7d".
    /// Mutation: make `fob_epoch_span_secs` return the raw count → this goes red.
    #[test]
    fn fob_epoch_span_is_the_projected_register_not_the_raw_count() {
        use crate::constants::{fob_epoch_span_secs, fob_epoch_ticks, TICK_INTERVAL_SECS};
        assert_eq!(fob_epoch_span_secs(false), fob_epoch_ticks(false) * TICK_INTERVAL_SECS);
        assert_eq!(fob_epoch_span_secs(true), fob_epoch_ticks(true) * TICK_INTERVAL_SECS);
        assert!(fob_epoch_span_secs(false) > fob_epoch_ticks(false), "a projection is longer than its count");
        // a tick VALUE just past one real epoch lands in epoch 1, not epoch 5
        let one_epoch = fob_epoch_span_secs(false);
        assert_eq!(epoch_id(one_epoch + 1, one_epoch), 1);
        assert_eq!(epoch_id(one_epoch + 1, fob_epoch_ticks(false)), TICK_INTERVAL_SECS,
            "dividing by the raw COUNT over-counts epochs by TICK_INTERVAL_SECS — the KI#165 bug");
    }

    #[test]
    fn selection_is_deterministic_eligible_only_and_rank_ordered() {
        // 5 candidates, base 10; floor 70 => need oods >= 7. Two are below.
        let roster = [
            cand(1, 10, 10), cand(2, 6, 10), cand(3, 9, 10),
            cand(4, 3, 10), cand(5, 8, 10),
        ];
        let a = ranked_eligible_movers(&roster, 42);
        let b = ranked_eligible_movers(&roster, 42);
        assert_eq!(a, b, "deterministic across calls");
        // only the 3 eligible (pk 1,3,5) appear; 2 and 4 filtered out
        assert_eq!(a.len(), 3);
        assert!(a.contains(&[1u8; 32]) && a.contains(&[3u8; 32]) && a.contains(&[5u8; 32]));
        assert!(!a.contains(&[2u8; 32]) && !a.contains(&[4u8; 32]));
        // order == ascending mover_rank
        let mut expected: Vec<[u8;32]> = vec![[1u8;32],[3u8;32],[5u8;32]];
        expected.sort_by(|x,y| mover_rank(x,42).cmp(&mover_rank(y,42)).then(x.cmp(y)));
        assert_eq!(a, expected);
    }

    #[test]
    fn fewer_than_committee_means_skip() {
        // only 2 eligible => caller sees < FOB_COMMITTEE_SIZE => SkipIsSafe
        let roster = [cand(1, 10, 10), cand(2, 9, 10), cand(3, 1, 10)];
        let movers = ranked_eligible_movers(&roster, 7);
        assert_eq!(movers.len(), 2);
        assert!(movers.len() < FOB_COMMITTEE_SIZE, "no valid committee -> tranche skipped");
    }

    #[test]
    fn committee_membership_rotates_across_epochs() {
        let roster: Vec<MoverCandidate> = (1..=9u8).map(|p| cand(p, 10, 10)).collect();
        let e1 = ranked_eligible_movers(&roster, 1);
        let e2 = ranked_eligible_movers(&roster, 2);
        // same eligible set, but the top-3 committee differs by epoch (rotation)
        assert_eq!(e1.len(), 9);
        assert_ne!(&e1[..FOB_COMMITTEE_SIZE], &e2[..FOB_COMMITTEE_SIZE],
            "the committee rotates across epochs");
    }
}

#[cfg(test)]
mod tests_audit {
    use super::*;

    // Core scale: 1 AXC accumulator, amount = the authoritative Core tranche.
    const ACC: u64 = 10_000_000_000;
    fn amt() -> u64 { compute_fob_tranche(ACC) } // 30% of 1 AXC
    fn entry(bal: u64, a: u64) -> TrancheEntry {
        TrancheEntry { pool_id: [9u8; 32], balance_used: bal, amount: a }
    }

    #[test]
    fn exact_math_ok_within_skew() {
        assert_eq!(audit_tranche_entry(&entry(ACC, amt()), ACC, 5), AuditVerdict::Ok);
    }

    #[test]
    fn wrong_amount_quarantines() {
        assert_eq!(audit_tranche_entry(&entry(ACC, amt() + 1), ACC, 5), AuditVerdict::Quarantine);
        assert_eq!(audit_tranche_entry(&entry(ACC, amt() - 1), ACC, 5), AuditVerdict::Quarantine);
    }

    #[test]
    fn entry_for_a_skip_quarantines() {
        // a sub-floor balance_used => Core f == 0 (rule-3 skip); any entry for it
        // is a violation (honest movers omit skips).
        assert_eq!(audit_tranche_entry(&entry(400_000, 400_000), 400_000, 5), AuditVerdict::Quarantine);
    }

    #[test]
    fn exact_ok_but_view_skew_only_alerts() {
        // math exact, but the auditor's own view is far from the pinned input
        assert_eq!(audit_tranche_entry(&entry(ACC, amt()), ACC - 100, 5), AuditVerdict::Alert);
        assert_eq!(audit_tranche_entry(&entry(ACC, amt()), ACC - 3, 5), AuditVerdict::Ok);
    }

    #[test]
    fn statement_payload_is_deterministic_and_content_bound() {
        let e = vec![entry(ACC, amt()), entry(ACC * 2, compute_fob_tranche(ACC * 2))];
        assert_eq!(tranche_statement_payload(5, false, &e), tranche_statement_payload(5, false, &e));
        assert_ne!(tranche_statement_payload(5, false, &e), tranche_statement_payload(6, false, &e), "epoch-bound");
        let mut e2 = e.clone(); e2[0].amount += 1;
        assert_ne!(tranche_statement_payload(5, false, &e), tranche_statement_payload(5, false, &e2), "amount-bound");
        let mut e3 = e.clone(); e3[0].balance_used += 1;
        assert_ne!(tranche_statement_payload(5, false, &e), tranche_statement_payload(5, false, &e3), "balance-bound");
    }

    /// The committee has no coordination (§3) and each recorder builds `entries`
    /// from a per-process HashMap order. The payload MUST be order-independent
    /// or the 3 recorders' partials never aggregate (found live 2026-08-10:
    /// authored-not-accepted). Same entries, reversed order → SAME payload.
    #[test]
    fn statement_payload_is_order_independent() {
        // Distinct pool_ids (one entry per validator, as the authoring loop
        // builds them) — the canonical sort is by pool_id.
        let a = TrancheEntry { pool_id: [1u8; 32], balance_used: ACC, amount: amt() };
        let b = TrancheEntry { pool_id: [2u8; 32], balance_used: ACC * 2, amount: compute_fob_tranche(ACC * 2) };
        let c = TrancheEntry { pool_id: [3u8; 32], balance_used: ACC * 3, amount: compute_fob_tranche(ACC * 3) };
        let fwd = vec![a, b, c];
        let mut rev = fwd.clone();
        rev.reverse();
        assert_eq!(
            tranche_statement_payload(5, false, &fwd),
            tranche_statement_payload(5, false, &rev),
            "reordering the same entries must not change the payload — else no committee aggregates"
        );
        // and still content-bound after canonicalisation
        let mut diff = fwd.clone();
        diff[0].amount += 1;
        assert_ne!(
            tranche_statement_payload(5, false, &fwd),
            tranche_statement_payload(5, false, &diff),
        );
    }
}

#[cfg(test)]
mod tests_reconcile {
    use super::*;

    #[test]
    fn equal_balance_is_noop() {
        // KI#84 — pool = pure function of the two ledgers, so set-union of the
        // ledgers converges two nodes with DIFFERENT subsets to the identical
        // pool regardless of arrival order. `from_ledgers` is that function.
        {
            // Node A saw tranche e1(100); node B saw e2(50) + a claim(50).
            // After each unions the other's facts (set sums), both hold
            // plus=150, minus=50 → balance=100 → same pool, conserving.
            let a = FobPool::from_ledgers(100 + 50, 50);
            let b = FobPool::from_ledgers(50 + 100, 50);
            assert_eq!(a.balance(), b.balance());
            assert_eq!(a.balance(), 100);
            assert!(a.conserves() && b.conserves());
            // A reset node (empty ledgers) rebuilds to exactly this once AE
            // delivers the union — no local cursor to strand.
            let reset_then_synced = FobPool::from_ledgers(150, 50);
            assert_eq!(reset_then_synced.balance(), a.balance());
        }
        assert_eq!(fob_reconcile(30, 30, None), FobReconcile::NoOp);
        assert_eq!(fob_reconcile(0, 0, Some(30)), FobReconcile::NoOp);
    }

    #[test]
    fn increase_needs_a_valid_tranche_onto_empty() {
        // NoMint: rise with no tranche -> violation
        assert_eq!(fob_reconcile(0, 30, None),
            FobReconcile::StructuralViolation(FobViolation::IncreaseWithoutTranche));
        // valid tranche onto empty -> adopt
        assert_eq!(fob_reconcile(0, 30, Some(30)), FobReconcile::AdoptTranche(30));
        // credit exists but the advertised balance (60) != the authorised
        // amount (30) -> structural mismatch (not a valid resync).
        assert_eq!(fob_reconcile(30, 60, Some(30)),
            FobReconcile::StructuralViolation(FobViolation::IncreaseAmountMismatch));
        // amount mismatch: tranche says 30 but balance rose to 40 -> violation
        assert_eq!(fob_reconcile(0, 40, Some(30)),
            FobReconcile::StructuralViolation(FobViolation::IncreaseAmountMismatch));
    }

    #[test]
    fn decrease_must_be_a_full_sweep() {
        // full sweep to zero -> adopt
        assert_eq!(fob_reconcile(30, 0, None), FobReconcile::AdoptWithdrawal);
        // partial drain -> violation (two-state has no partial state)
        assert_eq!(fob_reconcile(30, 10, None),
            FobReconcile::StructuralViolation(FobViolation::PartialDecrease));
        // a tranche present is irrelevant to a decrease
        assert_eq!(fob_reconcile(30, 5, Some(99)),
            FobReconcile::StructuralViolation(FobViolation::PartialDecrease));
    }

    #[test]
    fn no_mint_exhaustive_small() {
        // over a small grid, the ONLY way peer_balance exceeds local without a
        // violation is a VALID committee credit (Some(amount==peer)). Local need
        // NOT be empty — a valid credit resyncs a stale (missed-withdrawal) full
        // pool (see fob_reconcile); a rise with no matching credit is a violation.
        for local in 0..8u64 {
            for peer in 0..8u64 {
                for t in [None, Some(0u64), Some(3), Some(peer)] {
                    let r = fob_reconcile(local, peer, t);
                    if peer > local {
                        let ok = matches!(r, FobReconcile::AdoptTranche(a) if a == peer)
                            && t == Some(peer) && peer > 0;
                        let violated = matches!(r, FobReconcile::StructuralViolation(_));
                        assert!(ok || violated, "increase local={local} peer={peer} t={t:?} -> {r:?}");
                    }
                }
            }
        }
    }

    /// CONVERGENCE THROUGH A WITHDRAWAL (review concern, 2026-08-10). PoolSync
    /// carries only the CURRENT balance, not an event log, so a node can miss the
    /// intermediate empty state of a withdraw→re-tranche cycle. It must still
    /// converge, never strand — a valid current-epoch credit is the committee's
    /// authorisation to resync (the committee only authors onto an empty pool).
    #[test]
    fn pool_converges_through_a_withdrawal_even_when_missed() {
        let a = 30u64;       // epoch E tranche
        let bigger = 45u64;  // epoch E+k re-tranche (larger)
        let smaller = 20u64; // ...or smaller

        // Saw the withdrawal: A -> 0 -> A'. Both legal.
        assert_eq!(fob_reconcile(a, 0, None), FobReconcile::AdoptWithdrawal);
        assert_eq!(fob_reconcile(0, bigger, Some(bigger)), FobReconcile::AdoptTranche(bigger));

        // MISSED the withdrawal: still full at A, receives the new tranche
        // directly WITH its valid credit → resync-adopt, never quarantine.
        assert_eq!(fob_reconcile(a, bigger, Some(bigger)), FobReconcile::AdoptTranche(bigger),
            "missed-withdrawal + larger re-tranche must resync, not strand");
        assert_eq!(fob_reconcile(a, smaller, Some(smaller)), FobReconcile::AdoptTranche(smaller),
            "missed-withdrawal + smaller re-tranche must resync, not strand");

        // Safety preserved: no valid credit -> still a violation (no laundering).
        assert_eq!(fob_reconcile(a, bigger, None),
            FobReconcile::StructuralViolation(FobViolation::IncreaseWithoutTranche));
        assert_eq!(fob_reconcile(a, smaller, None),
            FobReconcile::StructuralViolation(FobViolation::PartialDecrease));
        // a credit for the WRONG amount -> mismatch, not adopt.
        assert_eq!(fob_reconcile(a, bigger, Some(a)),
            FobReconcile::StructuralViolation(FobViolation::IncreaseAmountMismatch));
    }

    /// The TRANCHE must converge too, not just the pool balance (design decision 2026-08-10).
    /// Two pools reach the same state via DIFFERENT paths — one sees every step,
    /// one misses the withdrawal and resyncs — and MUST end with identical
    /// `tranched_total`, because `available = settled_earnings - tranched_total`
    /// drives the NEXT tranche: a divergent tranched_total would desync the next
    /// epoch's amount and break aggregation all over again.
    #[test]
    fn withdraw_then_retranche_converges_tranched_total_and_next_tranche() {
        let a = 30u64;
        let a2 = 45u64;

        // P1 sees every step: 0 -> A -> 0 -> A'.
        let mut p1 = FobPool::new();
        p1.adopt_tranche(a).unwrap();
        p1.withdraw_full();
        p1.adopt_tranche(a2).unwrap();

        // P2 missed the withdrawal: 0 -> A -> (resync) A'.
        let mut p2 = FobPool::new();
        p2.adopt_tranche(a).unwrap();
        p2.adopt_tranche_resync(a2).unwrap();

        // Balances converge...
        assert_eq!(p1.balance(), a2);
        assert_eq!(p2.balance(), a2);
        // ...AND the debit cursors converge (the load-bearing part): both
        // tranched A+A' and withdrew A, so conservation holds on both.
        assert_eq!(p1.tranched_total(), a + a2);
        assert_eq!(p2.tranched_total(), a + a2, "tranched_total MUST match P1 or the next tranche desyncs");
        assert_eq!(p1.withdrawn_total(), a);
        assert_eq!(p2.withdrawn_total(), a);
        assert_eq!(p1.balance() + p1.withdrawn_total(), p1.tranched_total(), "conservation P1");
        assert_eq!(p2.balance() + p2.withdrawn_total(), p2.tranched_total(), "conservation P2");

        // Therefore the NEXT tranche is identical: same settled earnings (the
        // watermark guarantees this across nodes) minus the same tranched_total.
        let settled_net = 10 * 10_000_000_000u64; // convergent settled earnings
        let avail_p1 = settled_net.saturating_sub(p1.tranched_total());
        let avail_p2 = settled_net.saturating_sub(p2.tranched_total());
        assert_eq!(avail_p1, avail_p2);
        assert_eq!(
            compute_fob_tranche(avail_p1),
            compute_fob_tranche(avail_p2),
            "the NEXT tranche must converge across nodes, not just the pool balance"
        );
    }
}

#[cfg(test)]
mod tests_wire {
    use super::*;
    use crate::types::GossipMessage;

    fn att(pk: u8, oods: u32, base: u32) -> axiom_core_logic::types::NablaOodsAttestation {
        axiom_core_logic::types::NablaOodsAttestation {
            oods_size: oods, tick: 100, baseline_size: base, baseline_tick: 50,
            nabla_node_pk: [pk; 32], nabla_signature: vec![1u8; 64],
            nbc_issuer_pk: vec![2u8; 8], nbc_signature: vec![3u8; 8],
            nbc_commitment: vec![4u8; 8],
        }
    }

    #[test]
    fn fob_tranche_bincode_round_trips() {
        let msg = GossipMessage::FobTranche { epoch_id: 42, is_dev: false, entries: vec![
                TrancheEntry { pool_id: [7u8; 32], balance_used: 1000, amount: 300 },
                TrancheEntry { pool_id: [8u8; 32], balance_used: 50, amount: 50 },
            ],
            movers: vec![
                FobMoverSig { att: att(1, 10, 10), statement_sig: vec![9u8; 64] },
                FobMoverSig { att: att(2, 9, 10), statement_sig: vec![9u8; 64] },
                FobMoverSig { att: att(3, 8, 10), statement_sig: vec![9u8; 64] },
            ],
        };
        // bincode is the gossip wire codec (transport.rs); the variant MUST
        // round-trip identically or the mesh mis-decodes it.
        let bytes = bincode::serialize(&msg).expect("serialize");
        let back: GossipMessage = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(msg, back, "FobTranche must survive a bincode round-trip");
    }

    #[test]
    fn fob_tranche_is_the_last_discriminant() {
        // Positional-bincode safety: FobTranche must be the HIGHEST discriminant
        // (appended last), so a not-yet-rolled node fails to decode it and drops
        // it, rather than mis-decoding it as an earlier variant. We assert this
        // by checking a prior variant (JfpSecret) decodes to a LOWER 4-byte
        // little-endian discriminant than FobTranche.
        let jfp = GossipMessage::JfpSecret { dwp_wallet_id: [0u8; 32], secret: [0u8; 32] };
        let fob = GossipMessage::FobTranche { epoch_id: 0, is_dev: false, entries: vec![], movers: vec![] };
        let d = |m: &GossipMessage| -> u32 {
            let b = bincode::serialize(m).unwrap();
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        };
        assert!(d(&fob) > d(&jfp),
            "FobTranche discriminant {} must be > JfpSecret {} (appended LAST)", d(&fob), d(&jfp));
    }
}

#[cfg(test)]
mod tests_judge {
    use super::*;

    const ACC: u64 = 10_000_000_000;           // 1 AXC accumulator
    fn amt() -> u64 { compute_fob_tranche(ACC) } // 30% of 1 AXC = the Core amount
    const FLOOR: u64 = 70;

    fn mover(pk: u8, oods: u64, base: u64) -> VerifiedMover {
        VerifiedMover { node_pk: [pk; 32], oods_size: oods, baseline: base }
    }
    fn entry(pool: u8, bal: u64, a: u64) -> TrancheEntry {
        TrancheEntry { pool_id: [pool; 32], balance_used: bal, amount: a }
    }
    fn roster() -> Vec<[u8; 32]> { (1..=5u8).map(|p| [p; 32]).collect() }
    fn committee(epoch: u64) -> Vec<VerifiedMover> {
        rank_committee(&roster(), epoch, 3).iter().map(|pk| mover(pk[0], 10, 10)).collect()
    }

    #[test]
    fn clean_statement_accepts_without_alert() {
        let e = vec![entry(9, ACC, amt())];
        let v = judge_tranche_statement(1, &e, &committee(1), &roster(), |_| ACC, 5);
        assert_eq!(v, StatementVerdict::Accept { credits: vec![([9u8;32], amt())], alerted: false });
    }

    #[test]
    fn wrong_amount_quarantines_the_committee() {
        let e = vec![entry(9, ACC, amt() + 1)];
        let v = judge_tranche_statement(1, &e, &committee(1), &roster(), |_| ACC, 5);
        assert_eq!(v, StatementVerdict::Quarantine(FobViolation::IncreaseAmountMismatch));
    }

    #[test]
    fn a_self_ineligible_signer_quarantines() {
        // one signer's OWN attestation says 6/10 = 60% < 70% floor
        let mut movers = committee(1);
        movers[0].oods_size = 6;
        let e = vec![entry(9, ACC, amt())];
        let v = judge_tranche_statement(1, &e, &movers, &roster(), |_| ACC, 5);
        assert_eq!(v, StatementVerdict::Quarantine(FobViolation::IncreaseWithoutTranche));
    }

    #[test]
    fn under_sized_committee_quarantines() {
        let two = &committee(1)[..2];
        let e = vec![entry(9, ACC, amt())];
        let v = judge_tranche_statement(1, &e, two, &roster(), |_| ACC, 5);
        assert_eq!(v, StatementVerdict::Quarantine(FobViolation::IncreaseWithoutTranche));
    }

    #[test]
    fn view_skew_accepts_but_alerts() {
        let e = vec![entry(9, ACC, amt())];
        let v = judge_tranche_statement(1, &e, &committee(1), &roster(), |_| ACC - 100, 5);
        assert_eq!(v, StatementVerdict::Accept { credits: vec![([9u8;32], amt())], alerted: true });
    }

    #[test]
    fn wrong_committee_accepts_but_alerts() {
        let top = rank_committee(&roster(), 1, 3);
        let others: Vec<[u8;32]> = roster().into_iter().filter(|p| !top.contains(p)).collect();
        let mut signers = vec![mover(others[0][0], 10, 10), mover(others[1][0], 10, 10), mover(top[0][0], 10, 10)];
        signers.sort_by_key(|m| m.node_pk);
        let e = vec![entry(9, ACC, amt())];
        let v = judge_tranche_statement(1, &e, &signers, &roster(), |_| ACC, 5);
        assert_eq!(v, StatementVerdict::Accept { credits: vec![([9u8;32], amt())], alerted: true });
    }
}
