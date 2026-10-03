//! JUDOON — **J**udgment **U**pon **D**ivergent **O**r **O**ffending
//! **N**ablas. Pool quarantine subsystem: three-layer defense in depth.
//!
//! The backronym encodes the two response tiers Mac christened:
//! *Divergent* peers (honest-but-skewed, e.g. behind on PoolSync gossip)
//! land in the Zero Room — single-observer probation that recovers
//! quietly or escalates. *Offending* peers (structurally impossible
//! state, cross-mesh consensus against them) get sealed off via
//! K-of-N quarantine.
//!
//! Per `docs/AXIOM_DESIGN_NablaJudoon.md`. Three independent
//! layers, each with different detection scope and response cost:
//!
//! - **Layer 1 — single-observer probation** for structural-impossibility
//!   violations (`BalanceExceedsInitial`, `IntraSnapshotInconsistent`,
//!   `MagnitudeBlatant`). Catches what's self-evident from one PoolSync;
//!   responds with 10-tick probation (suppress relay, no Alert).
//!   Probation expiry without recovery escalates to quarantine via the
//!   `§5.6` WAL/TTL/cooldown machinery WITHOUT routing through K-of-N
//!   consensus — structural violations are their own proof.
//!
//! - **Layer 2 — cross-node D2 magnitude gate, floored slack**. Lives
//!   in `AirdropPool::reconcile()`. Slack scales `16× → 4× → 1×` from
//!   fresh to low pool but NEVER drops below `CLAIM_AMOUNT` — that
//!   floor preserves gossip-skew tolerance.
//!
//! - **Layer K-curve — social consensus with `K=3` floor**. Threshold
//!   value is a function of pool depletion; 3 / 5 / 8 / 10 at lifetime
//!   bands 0-10 / 11-30 / 31-70 / 71+. K=3 floor preserves the original
//!   3-Byzantine collusion bar against manufactured-quarantine attacks.
//!
//! Layer precedence (Mac's review): L1 wins over L2 on the same
//! evidence. The canonical `reconcile()` order is
//! `structural_violation()` first, then higher-balance NoOp, then D2.

use crate::types::PoolKind;

// ---------------------------------------------------------------------------
// DrainOnlyPool trait
// ---------------------------------------------------------------------------

/// Implemented by any pool that:
///   1. Has a fixed initial budget.
///   2. Drains monotonically toward zero (never refills).
///   3. Carries critical security implications worth quarantining over.
///
/// Non-critical drain-only pools (DevTreasury) deliberately do NOT
/// implement this trait, so they fall through to the `None` arm in
/// `alert_threshold_for` AND get no Layer 1 probation (since the trait
/// is what gates `structural_violation`).
///
/// # Contract — fixed-claim-size precondition (Mac's review)
///
/// Implementors MUST guarantee the conservation invariant
///
/// ```text
/// balance + total_claims × CLAIM_AMOUNT == initial_atoms
/// ```
///
/// at every honest state, where `CLAIM_AMOUNT` is a single per-pool
/// class constant exactly equal to the atoms debited per claim. Future
/// pools with variable-size grants (per-recipient claim amounts) would
/// NOT satisfy this invariant — `total_claims × CLAIM_AMOUNT` would be
/// meaningless and the `IntraSnapshotInconsistent` check in
/// `structural_violation` would false-positive on honest distribution.
/// Such pools must NOT implement this trait as currently shaped.
pub trait DrainOnlyPool {
    /// Current local balance (the observer's view; converges via
    /// monotonic-decrease gossip).
    fn balance(&self) -> u64;
    /// Class constant — the pool's initial budget at network genesis.
    fn initial_atoms(&self) -> u64;
    /// Mesh-wide max-wins claim count (the observer's converged view).
    fn total_claims(&self) -> u64;
    /// Local claim count for this cycle (not gossiped).
    fn local_claims_this_cycle(&self) -> u64;
    /// Snapshot of `total_claims` at the start of the current cycle.
    fn mesh_claims_at_cycle_start(&self) -> u64;
    /// Per-pool class constant — atoms debited per single claim.
    /// Implementors return the same value for every call (it's a class
    /// constant). Used by `structural_violation` for the
    /// `IntraSnapshotInconsistent` check.
    fn claim_amount(&self) -> u64;
    /// KI#191 — Σminus: atoms ACTUALLY debited by claims. For a fixed-grant
    /// pool this equals `total_claims × claim_amount`; for a variable-grant
    /// pool (the emission pools, whose per-claim grant is an epoch share) the
    /// product is meaningless and only this is correct.
    fn paid_out(&self) -> u64;
    /// KI#191 — Σplus beyond the genesis opening: the ACCOUNTED inflow. 0 for a
    /// drain-only pool; the DEED top-up total for a two-way pool (YP §25.2.4
    /// rule 4). Truthful only because the transfer verifies debit == credit
    /// (KI#193).
    fn topped_up(&self) -> u64;
}

// ---------------------------------------------------------------------------
// Layer 1 — structural-violation detection (single-observer probation)
// ---------------------------------------------------------------------------

/// The three structural violations a single observer can verify from
/// one PoolSync. All are intra-snapshot invariants — they check the
/// peer's coherent single-message snapshot against universal constants
/// and the observer's own consensus baseline. None depend on
/// cross-node deltas that gossip propagation skew can corrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    /// `ps.balance > pool.initial_atoms()` — the peer claims more
    /// atoms in the pool than the network ever started with. No honest
    /// Nabla, however stale, can emit this; the initial budget is a
    /// class constant.
    BalanceExceedsInitial,
    /// `ps.balance + ps.total_claims × CLAIM_AMOUNT > pool.initial_atoms()`
    /// — the peer's own coherent snapshot violates the conservation
    /// law for fixed-claim-size pools. Skew-immune because it's a
    /// single-observer check on one message.
    IntraSnapshotInconsistent,
    /// `(initial − balance) % CLAIM_AMOUNT != 0` — the peer's balance is not on
    /// the pool's drain lattice, so it cannot have come from THIS pool.
    ///
    /// A drain-only pool with a fixed claim size only ever holds
    /// `initial − k × claim_amount`. Any other value means the pool was built
    /// from a different declared initial. Measured 2026-09-05: the Community
    /// pool was re-cut 200,000 → 202,000 (400 × the 505 claim), the local mesh
    /// was rebuilt and wiped, and un-rolled remotes gossiped the OLD pool back.
    /// Every node then served 198,495 — which is 3,505 below the declared
    /// initial, and 3,505 is not a whole number of 505 claims. Nothing
    /// objected, because a low balance is indistinguishable from an honestly
    /// drained one by every other check here.
    ///
    /// ⚠ READS THE BALANCE ONLY, NEVER THE CLAIM COUNT — that is what makes it
    /// safe. An earlier attempt asserted `balance + claims × claim == initial`
    /// and had to be reverted: KI#30 is a DOCUMENTED honest condition where
    /// concurrent grants leave the claim counter behind, so that equality
    /// turned honest nodes into accusers. The counter can lag; the balance
    /// still lands on the lattice, so this stays quiet through KI#30 and
    /// through any gossip stagger.
    PoolBalanceOffLattice,
    /// `drop > 100× expected_drop` — the peer reports a drop wildly
    /// inconsistent with their own claimed claim-count delta. Far
    /// beyond any honest-mesh bursting; only fabricated values reach
    /// this.
    MagnitudeBlatant,
    /// FOB Bounded-Fee conservation violation (`AXIOM_DESIGN_BoundedPools.md`
    /// §7 pt 3): a per-validator pool rose with no valid current-epoch
    /// `TrancheStatement` authorising it, rose onto a non-empty pool, rose by
    /// the wrong amount, or fell to a nonzero value (not a full sweep). Unlike
    /// the drain-pool proofs above, the ceiling is not a class constant — it is
    /// the pool's own tranche history (`tranched_total − withdrawn_total`). A
    /// merely stale auditor NEVER reaches here: an increase whose authorising
    /// statement this node has not yet seen is HELD (NoOp), not accused (§4.1).
    BoundedFeeConservation,
}

/// Detect a structural violation from a single PoolSync. Returns
/// `Some(ProofKind)` if the violation is self-evident from the message,
/// `None` otherwise.
///
/// This is the Layer 1 entry point. Callers route `Some(_)` to
/// probation; `None` falls through to the higher-balance NoOp branch
/// or the Layer 2 D2 magnitude gate.
///
/// IMPORTANT: must run BEFORE any `peer_balance > local_balance` early
/// return in the caller's reconcile path. Two of the three triggers
/// (`BalanceExceedsInitial`, high-direction `IntraSnapshotInconsistent`)
/// imply `peer_balance > local_balance` and would be unreachable
/// otherwise.
pub fn structural_violation<P: DrainOnlyPool>(
    peer_balance: u64,
    peer_total_claims: u64,
    // KI#191 — Σminus from the PEER's own snapshot (atoms, not claim count).
    peer_paid_out: u64,
    pool: &P,
) -> Option<ProofKind> {
    // KI#191 — THE BUDGET IS THE OPENING PLUS THE ACCOUNTED INFLOW.
    // A drain-only pool has `topped_up() == 0` and this is the original rule
    // unchanged. A TWO-WAY pool (the emission pools) legitimately RISES when
    // DEED tops it up (YP §25.2.4 rule 4), so `balance > initial_atoms` alone
    // is not a violation for it — reading it as one is what made honest nodes
    // look guilty 5,166 times in ten minutes of soak_r22.
    let budget = pool.initial_atoms().saturating_add(pool.topped_up());

    // 1. Balance exceeds the budget this pool can ever have held.
    if peer_balance > budget {
        return Some(ProofKind::BalanceExceedsInitial);
    }
    // 2. Intra-snapshot conservation law — YP §25.2.4: "conserved on every node
    //    (Σplus − Σminus). No coin is created."  EXACT equality, no tolerance:
    //    The owner, 2026-09-16 — "this is a finianical system, 1 atom diff is not
    //    acceptable."
    //
    //    This used to be `balance + total_claims × claim_amount > initial`.
    //    The product is only Σminus while every claim costs the same; the
    //    emission pools' per-claim grant is an epoch SHARE, so the product was
    //    meaningless for them and the check false-positived by construction.
    //    `paid_out` is Σminus in atoms and stays exact when the grant varies.
    //
    //    Still intra-snapshot and skew-immune (§2.5): every term but the
    //    genesis constant comes from the peer's OWN single coherent message.
    if peer_balance.saturating_add(peer_paid_out) != budget {
        return Some(ProofKind::IntraSnapshotInconsistent);
    }
    // 3. Drop magnitude blatantly inconsistent with claim delta.
    if peer_balance < pool.balance() {
        let drop = pool.balance() - peer_balance;
        let claims_delta = peer_total_claims.saturating_sub(pool.total_claims());
        let max_legitimate = claims_delta
            .saturating_mul(pool.claim_amount())
            .saturating_mul(100);
        if drop > max_legitimate {
            return Some(ProofKind::MagnitudeBlatant);
        }
    }
    // 4. Balance must sit on the pool's drain lattice: every atom that left did
    //    so in units of one grant. Balance-only, so a lagging claim counter
    //    (KI#30) never trips it.
    //
    //    KI#191 — this is tested on Σminus and ONLY for a pool whose grant is a
    //    constant. A lattice presumes one step size; the emission pools' grant
    //    is a per-epoch share, so their balance legitimately lands between steps
    //    and this check false-positived on them exactly as the conservation one
    //    did. `topped_up > 0` marks the two-way (variable-grant) pools — for a
    //    fixed-grant drain pool `paid_out == initial − balance` by the identity
    //    just checked, so this stays bit-for-bit the original rule there.
    let claim = pool.claim_amount();
    if claim > 0 && pool.topped_up() == 0 && peer_paid_out % claim != 0 {
        return Some(ProofKind::PoolBalanceOffLattice);
    }
    None
}

// ---------------------------------------------------------------------------
// Layer 2 — D2 slack scaling (floored)
// ---------------------------------------------------------------------------

/// Cross-node D2 magnitude-gate slack as a function of pool depletion.
///
/// The slack absorbs gossip-propagation stagger between two honest
/// peers (one counter propagates ahead of the other). Setting it to
/// zero at low pool — which an earlier draft of the design proposed —
/// would re-arm the very view-skew false-positive flood the redesign
/// exists to eliminate. The floor of `claim_amount` is load-bearing.
pub fn d2_slack_for_lifetime_pct(lifetime_pct: u64, claim_amount: u64) -> u64 {
    match lifetime_pct {
        0..=30  => claim_amount,         // FLOOR — preserves gossip-skew tolerance
        31..=70 => claim_amount * 4,
        _       => claim_amount * 16,    // fresh pool — absorbs bursting
    }
}

// ---------------------------------------------------------------------------
// Layer K-curve — social consensus threshold with K=3 floor
// ---------------------------------------------------------------------------

/// Compute the K threshold for K-of-N social-consensus quarantine, as
/// a function of the drain-only pool's lifetime depletion state.
///
/// `K=3` is the floor at every band — preserving the original
/// 3-Byzantine-node collusion bar for manufactured-quarantine attacks
/// against honest peers (Mac's review).
pub fn drain_pool_alert_threshold<P: DrainOnlyPool>(pool: &P) -> usize {
    let lifetime_pct = pool.balance() * 100 / pool.initial_atoms().max(1);
    match lifetime_pct {
        0..=10  => 3,    // near depletion — Byzantine collusion bar preserved
        11..=30 => 5,
        31..=70 => 8,
        _       => 10,   // fresh pool — max noise filtering
    }
}

/// Alert-emission predicate: should I emit an Alert about peer Z's
/// PoolSync? Compares the peer's claimed `total_claims` against the
/// uniform-distribution prediction with a 30% tolerance band.
///
/// One signal among four (probation, D2, predicate, K-curve). Catches
/// subtle drift the magnitude gate misses.
pub fn drain_pool_should_alert<P: DrainOnlyPool>(
    pool: &P,
    n_active: usize,
    peer_total_claims: u64,
) -> bool {
    // Count-gate the predicate — at low local_claims the estimator
    // CV ≈ 1/√local_claims is too noisy to be meaningful.
    const N_MIN_CLAIMS: u64 = 5;
    if pool.local_claims_this_cycle() < N_MIN_CLAIMS {
        return false;
    }

    let predicted = pool.local_claims_this_cycle() * n_active as u64;
    let peer_says_used = peer_total_claims
        .saturating_sub(pool.mesh_claims_at_cycle_start());
    let lower = predicted * 70 / 100;
    let upper = predicted * 130 / 100;
    peer_says_used < lower || peer_says_used > upper
}

// ---------------------------------------------------------------------------
// Increase-pool rate detector (KI#28 — replaces the fd1bcad6 workaround)
// ---------------------------------------------------------------------------
//
// DEED / DevDeed are monotonic-INCREASE pools (AXIOM_DESIGN_DeedDistribution).
// The drain-pool detectors above expect exact-equality PoolSync convergence;
// gossip lag on a growing pool produces persistent false "violations" (KI#28).
// This detector replaces exact-equality with a statistical range check that
// rides the EXISTING PoolSync handler and emits the SAME Alert into the SAME
// K-of-N pipeline — by the book (AXIOM_DESIGN_NablaJudoon.md §10).
//
// State lives in `DeedPool` as an in-memory rolling window of locally-observed
// credits (NOT persisted). The math is here, pure and unit-testable.
//
// NOTE: per-Nabla random window (§10.2 `rand(300,600)`) is deferred — it needs
// a per-node seed plumbed from NodeId and buys anti-gaming margin that only
// matters once the detector is engaged at mainnet load. The fixed window below
// is sufficient for KI#28's goal (stop gossip-lag false positives). Tracked in
// §10.4 open questions.

/// Rolling-window length in seconds for the local credit-rate estimate.
pub const INCREASE_POOL_WINDOW_SECS: u64 = 480; // 8 min (§10.2 midpoint)
/// Max samples retained in the window (drop oldest beyond this).
pub const INCREASE_POOL_WINDOW_MAX_SAMPLES: usize = 100;
/// Statistical-safety gate: below this many samples the estimator is too
/// noisy to judge, so the detector self-disables (returns "no alert").
pub const INCREASE_POOL_MIN_SAMPLES: usize = 20;
/// Tolerance band around the expected mesh-wide growth (±%).
pub const INCREASE_POOL_MARGIN_PCT: u64 = 15;

/// Rate-based alert predicate for the increase pools (Deed / DevDeed).
///
/// Returns `true` when a peer's reported cumulative `total_credited` is
/// implausibly far AHEAD of this observer's converged view given the local
/// credit rate — i.e. likely fabricated, emit an Alert. Returns `false`
/// (treat as honest gossip lag) when:
///   - sample count is below `INCREASE_POOL_MIN_SAMPLES` (self-disable), or
///   - the peer is at-or-behind our cumulative view (min-wins / staleness,
///     not over-reporting), or
///   - the peer's excess fits within one window's worth of expected mesh-wide
///     growth (`local_window_sum × N_validators`) plus the ±margin.
///
/// `local_window_sum` is the sum of atoms credited LOCALLY within the rolling
/// window; multiplying by `n_validators` estimates mesh-wide growth (uniform
/// 1/N register sampling). This is the high-direction (over-report) check —
/// the only direction a growing pool can be attacked on in Phase 1. The
/// under-report direction needs the Step 9B drain counter (§10.2, deferred).
pub fn increase_pool_should_alert(
    local_window_sum: u64,
    n_samples: usize,
    n_validators: usize,
    local_total_credited: u64,
    peer_total_credited: u64,
) -> bool {
    // Statistical-safety gate — self-disables under low load (soak scale).
    if n_samples < INCREASE_POOL_MIN_SAMPLES {
        return false;
    }
    // Peer at-or-behind us: min-wins / stale gossip, never an over-report.
    if peer_total_credited <= local_total_credited {
        return false;
    }
    let peer_excess = peer_total_credited - local_total_credited;
    // u128 intermediates: `local_window_sum × N × 1.15` can exceed u64 at
    // mainnet N. Saturating u64 math would truncate the ceiling BELOW the
    // estimate after the `/100` and false-positive on honest peers, so do
    // the whole comparison in u128 (max ~3.4e38 ≫ any realistic product).
    let mesh_estimate = (local_window_sum as u128) * (n_validators as u128);
    let upper = mesh_estimate * (100 + INCREASE_POOL_MARGIN_PCT as u128) / 100;
    (peer_excess as u128) > upper
}

// ---------------------------------------------------------------------------
// Dispatch — per-pool policy at one call site
// ---------------------------------------------------------------------------

/// Result of the per-pool dispatch.
///
/// `Some(k)` means: Alert pipeline runs for this pool, with `K=k`
/// distinct-emitter threshold at the social-consensus layer.
///
/// `None` means: Alert pipeline skips entirely (non-critical pools, or
/// pools whose quarantine is deliberately disabled pending a separate
/// module).
///
/// Layer 1 probation runs INDEPENDENTLY of this dispatch — it's gated
/// on the `DrainOnlyPool` trait, not on `alert_threshold_for`. Pools
/// that don't implement the trait get no probation either.
pub fn alert_threshold_for<P: DrainOnlyPool>(
    pool_kind: PoolKind,
    airdrop_pool: &P,
) -> Option<usize> {
    match pool_kind {
        // Critical drain-only pools → K-curve dispatch.
        PoolKind::Airdrop => Some(drain_pool_alert_threshold(airdrop_pool)),
        // Validator-join subsidy pools. These are VALUE-BEARING and drain-only,
        // and a grant is gated on the gossiped balance — which is exactly the
        // condition the DEED arm below names as requiring quarantine. So they
        // take the K-curve, same as the airdrop pool.
        PoolKind::Bootstrap | PoolKind::FoundationBootstrap =>
            Some(drain_pool_alert_threshold(airdrop_pool)),
        // Contribution emission pools: value-bearing, drain-only between the
        // epoch rolls — the same K-curve.
        PoolKind::EmissionValidators | PoolKind::EmissionNabla =>
            Some(drain_pool_alert_threshold(airdrop_pool)),

        // Non-critical → Alert pipeline skips entirely.
        PoolKind::DevTreasury | PoolKind::DevDeed => None,

        // DEED — see AXIOM_DESIGN_NablaJudoon.md §6.1.
        // This PR DISABLES existing DEED quarantine pending the
        // separate bidirectional-pool module. PR2 (9475150a) wired
        // DEED through the K=3 path; we are turning that off, not
        // deferring its addition.
        //
        // INVARIANT (load-bearing): if a future PR gates any payout,
        // mint, or value-bearing operation on the gossiped DEED
        // balance, it MUST re-enable DEED quarantine first (either by
        // implementing this match arm or by landing the bidirectional
        // module).
        PoolKind::Deed => None,

        // BoundedFee is NOT a drain-only pool (two-state, rises by tranche), so
        // it takes no drain-pool K-curve threshold here (§7 "JUDOON itself does
        // not change"). Its value-bearing protection is the PoolSync reconcile
        // arm — an INCREASE is a StructuralViolation unless a valid current-epoch
        // TrancheStatement authorises it (gossip.rs), which routes through the
        // SAME PoolStructuralViolation / K-of-N pipeline the drain pools use. So
        // the invariant above is satisfied by the arm, not by this dispatch.
        PoolKind::BoundedFee(_, _) => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// KI#191 — the fixtures' budget; an honest peer's Σminus is what it drained.
    const TP_INITIAL: u64 = 1_000_000;

    /// Test fixture — a minimal `DrainOnlyPool` impl that lets us
    /// vary inputs freely. Production users go through `AirdropPool`.
    struct TestPool {
        balance: u64,
        initial: u64,
        total_claims: u64,
        local_claims_cycle: u64,
        mesh_claims_at_start: u64,
        claim_amount: u64,
        /// KI#191 — the observer's own Σplus. 0 for a drain-only pool, which
        /// is every fixture here unless a test says otherwise.
        topped_up: u64,
    }

    impl DrainOnlyPool for TestPool {
        fn balance(&self) -> u64 { self.balance }
        fn initial_atoms(&self) -> u64 { self.initial }
        fn total_claims(&self) -> u64 { self.total_claims }
        fn local_claims_this_cycle(&self) -> u64 { self.local_claims_cycle }
        fn mesh_claims_at_cycle_start(&self) -> u64 { self.mesh_claims_at_start }
        fn claim_amount(&self) -> u64 { self.claim_amount }
        // KI#191 — the fixture's Σminus is derived from what it says it drained,
        // so a test that sets up an HONEST pool balances by construction and one
        // that lies does not. `paid_out()` is only read for the LOCAL pool; the
        // peer's value arrives as an argument.
        fn paid_out(&self) -> u64 { self.initial.saturating_sub(self.balance) }
        fn topped_up(&self) -> u64 { self.topped_up }
    }

    fn fresh_pool() -> TestPool {
        TestPool {
            balance: 1_000_000,
            initial: 1_000_000,
            total_claims: 0,
            local_claims_cycle: 0,
            mesh_claims_at_start: 0,
            claim_amount: 100,
            topped_up: 0,
        }
    }

    fn depleted_pool(balance: u64, claims: u64) -> TestPool {
        let mut p = fresh_pool();
        p.balance = balance;
        p.total_claims = claims;
        p
    }

    // -- Threshold curve --

    #[test]
    fn threshold_fresh_pool_is_10() {
        assert_eq!(drain_pool_alert_threshold(&fresh_pool()), 10);
    }

    #[test]
    fn threshold_70_band_is_8() {
        // 70% lifetime — still on the upper-bound boundary
        assert_eq!(drain_pool_alert_threshold(&depleted_pool(700_000, 3000)), 8);
    }

    #[test]
    fn threshold_30_band_is_5() {
        assert_eq!(drain_pool_alert_threshold(&depleted_pool(300_000, 7000)), 5);
    }

    #[test]
    fn threshold_10_band_is_3_floor() {
        assert_eq!(drain_pool_alert_threshold(&depleted_pool(100_000, 9000)), 3);
    }

    #[test]
    fn threshold_near_zero_stays_at_3_floor() {
        // K=3 floor preserves the 3-Byzantine collusion bar even at
        // pool exhaustion — Mac's review.
        assert_eq!(drain_pool_alert_threshold(&depleted_pool(1, 9999)), 3);
        assert_eq!(drain_pool_alert_threshold(&depleted_pool(0, 10000)), 3);
    }

    // -- Structural violations --

    #[test]
    fn structural_balance_exceeds_initial_fires() {
        let pool = fresh_pool();
        let r = structural_violation(2_000_000, 0, TP_INITIAL.saturating_sub(2_000_000), &pool);
        assert_eq!(r, Some(ProofKind::BalanceExceedsInitial));
    }

    #[test]
    fn structural_intra_snapshot_inconsistent_fires() {
        // initial=1M, peer claims balance=999,500 + claims=5 × 100 = 500
        // → 999,500 + 500 = 1M (exactly on the conservation line).
        // NOT a violation.
        let pool = fresh_pool();
        assert_eq!(structural_violation(999_500, 5, TP_INITIAL.saturating_sub(999_500), &pool), None);

        // initial=1M, peer claims balance=999,999 + claims=20 × 100 = 2000
        // → 999,999 + 2000 = 1,001,999 > 1M.
        // Conservation violated; intra-snapshot fires BEFORE magnitude
        // (drop=1, claims_delta=20, max_legitimate=200K, magnitude OK).
        // KI#191 — the peer ASSERTS it paid out 20 × 100 while its balance fell
        // by 1. Σminus now comes from the peer instead of being inferred from a
        // claim count, so the lie is stated outright: 999,999 + 2,000 ≠ 1M.
        let r = structural_violation(999_999, 20, 20 * 100, &pool);
        assert_eq!(r, Some(ProofKind::IntraSnapshotInconsistent));
    }

    #[test]
    fn structural_honest_drain_trajectory_passes() {
        let pool = fresh_pool();
        // Anywhere on the conservation line: balance + claims×amount == initial
        // initial = 1M, claim_amount = 100
        // balance=999,900, claims=1 → 999,900 + 100 = 1,000,000 ✓
        assert_eq!(structural_violation(999_900, 1, TP_INITIAL.saturating_sub(999_900), &pool), None);
        // balance=500_000, claims=5000 → 500,000 + 500,000 = 1,000,000 ✓
        assert_eq!(structural_violation(500_000, 5000, TP_INITIAL.saturating_sub(500_000), &pool), None);
        // balance=0, claims=10000 → 0 + 1,000,000 = 1,000,000 ✓
        assert_eq!(structural_violation(0, 10000, TP_INITIAL.saturating_sub(0), &pool), None);
    }

    /// THE DEFECT THIS EXISTS FOR, with the numbers it actually had.
    ///
    /// 2026-09-05: the Community pool was re-cut to 202,000 (400 x 505), the
    /// local mesh was rebuilt and wiped, and un-rolled remotes gossiped the OLD
    /// 200,000 pool back in. Every node served 198,495 with 3 claims and no
    /// check objected — a low balance looks exactly like an honestly drained
    /// pool. That pool cannot fund the 400 slots it is declared to fund.
    #[test]
    fn a_pool_from_a_stale_distribution_is_caught() {
        // A SYNTHETIC pool, not the live register — the lattice rule under
        // test is `initial - k x claim`, which holds for any consistent
        // pair. (These were the declared figures until KI#152 raised the
        // claim to 508; the fixture is deliberately left alone so the
        // arithmetic below stays readable.)
        let pool = TestPool {
            balance: 202_000, initial: 202_000, total_claims: 0,
            local_claims_cycle: 0, mesh_claims_at_start: 0, claim_amount: 505,
                    topped_up: 0,
        };
        // What the mesh actually served: 200,000 less two 500-claims and one
        // 505-claim. Internally coherent, under the initial, drop is gentle —
        // it passes every other structural check.
        let stale = 198_495u64;
        assert_eq!(
            // KI#191 — conservation-COHERENT on this pool's own budget
            // (202,000 − 198,495 = 3,505), so it passes the identity and the
            // LATTICE is what must catch it. Using the 1M fixture constant here
            // would make it fail conservation instead and the test would stop
            // proving what it says.
            structural_violation(stale, 3, 202_000u64.saturating_sub(stale), &pool),
            Some(ProofKind::PoolBalanceOffLattice),
            "a balance that is not initial - k x claim cannot have come from \
             this pool, however plausible it looks",
        );

        // ⚠ AND THE HONEST STATES STAY QUIET. Every legitimate balance is on
        // the lattice, whatever the claim counter says — which is why this is
        // balance-only and survives KI#30's lagging counter.
        for k in [0u64, 1, 7, 399, 400] {
            let honest = 202_000 - k * 505;
            assert_eq!(
                // KI#191 — Σminus on THIS pool's budget (202,000), not the 1M
                // fixture constant: k grants of 505 is exactly what left.
                structural_violation(honest, k, k * 505, &pool), None,
                "initial - {k} x 505 is an honest balance and must not accuse",
            );
        }

        // ⚠ AND THE KI#30 SHAPE — a balance on the lattice whose claim counter
        // lags — is quiet for THIS check. Asserted against the lattice rule
        // directly, because a large balance drop reported alongside a stale
        // counter legitimately trips the MagnitudeBlatant proof above, which
        // is a different rule and not what this test is about.
        let claim = pool.claim_amount();
        for k in [1u64, 7, 400] {
            let honest = 202_000 - k * claim;
            assert_eq!(
                (pool.initial_atoms() - honest) % claim, 0,
                "an honest balance is always initial - k x claim, whatever the \
                 claim counter says — that is why this check reads the balance \
                 alone and survives KI#30",
            );
        }
    }

    #[test]
    fn structural_magnitude_blatant_fires() {
        // local balance = 500_000, local total_claims = 5000
        let pool = depleted_pool(500_000, 5000);
        // peer says: balance = 100, total_claims = 5001
        // drop = 499_900; expected = 1 × 100 = 100; 100 × 100 = 10_000
        // 499_900 > 10_000 → MagnitudeBlatant
        let r = structural_violation(100, 5001, TP_INITIAL.saturating_sub(100), &pool);
        assert_eq!(r, Some(ProofKind::MagnitudeBlatant));
    }

    #[test]
    fn structural_no_violation_on_honest_drop() {
        // local 500K, peer says 499K with claims advanced by 10
        let pool = depleted_pool(500_000, 5000);
        // drop = 1000; expected = 10 × 100 = 1000; 100 × 1000 = 100_000
        // 1000 ≤ 100_000 → No violation
        assert_eq!(structural_violation(499_000, 5010, TP_INITIAL.saturating_sub(499_000), &pool), None);
    }

    #[test]
    fn structural_saturating_arithmetic_is_safe_direction() {
        // u64::MAX claims should saturate and fire (not wrap to small)
        let pool = fresh_pool();
        // KI#191 — the saturation risk moved to the peer-reported Σminus: a
        // peer asserting it paid out u64::MAX must saturate UPWARD and fire,
        // never wrap to a small number that looks conserved.
        let r = structural_violation(1, u64::MAX, u64::MAX, &pool);
        assert_eq!(r, Some(ProofKind::IntraSnapshotInconsistent));
    }

    // -- D2 slack scaling --

    #[test]
    fn d2_slack_never_goes_below_claim_amount() {
        // Floor preserves cross-node gossip-skew tolerance — Mac's
        // first landmine fix.
        assert_eq!(d2_slack_for_lifetime_pct(0, 100), 100);
        assert_eq!(d2_slack_for_lifetime_pct(5, 100), 100);
        assert_eq!(d2_slack_for_lifetime_pct(30, 100), 100);
    }

    #[test]
    fn d2_slack_widens_with_pool_fullness() {
        assert_eq!(d2_slack_for_lifetime_pct(50, 100), 400);
        assert_eq!(d2_slack_for_lifetime_pct(80, 100), 1600);
        assert_eq!(d2_slack_for_lifetime_pct(99, 100), 1600);
    }

    // -- Should-alert predicate --

    #[test]
    fn should_alert_count_gates_below_minimum() {
        // local_claims_this_cycle below N_MIN_CLAIMS → predicate skips
        let mut p = fresh_pool();
        p.local_claims_cycle = 0;
        assert_eq!(drain_pool_should_alert(&p, 10, 99999), false);
        p.local_claims_cycle = 4;
        assert_eq!(drain_pool_should_alert(&p, 10, 99999), false);
    }

    #[test]
    fn should_alert_within_30_pct_band_passes() {
        let mut p = fresh_pool();
        p.local_claims_cycle = 10;
        p.mesh_claims_at_start = 0;
        // predicted = 10 × 10 = 100; band [70, 130]
        assert_eq!(drain_pool_should_alert(&p, 10, 100), false);
        assert_eq!(drain_pool_should_alert(&p, 10, 70), false);
        assert_eq!(drain_pool_should_alert(&p, 10, 130), false);
    }

    #[test]
    fn should_alert_outside_30_pct_band_fires() {
        let mut p = fresh_pool();
        p.local_claims_cycle = 10;
        p.mesh_claims_at_start = 0;
        assert_eq!(drain_pool_should_alert(&p, 10, 69), true);   // under-band
        assert_eq!(drain_pool_should_alert(&p, 10, 131), true);  // over-band
    }

    // -- Dispatch --

    #[test]
    fn dispatch_airdrop_returns_some_k() {
        let r = alert_threshold_for(PoolKind::Airdrop, &fresh_pool());
        assert_eq!(r, Some(10));
    }

    #[test]
    fn dispatch_dev_pools_return_none() {
        let p = fresh_pool();
        assert_eq!(alert_threshold_for(PoolKind::DevTreasury, &p), None);
        assert_eq!(alert_threshold_for(PoolKind::DevDeed, &p), None);
    }

    // -- Increase-pool rate detector (KI#28) --

    #[test]
    fn increase_pool_self_disables_below_min_samples() {
        // Even a wildly over-reporting peer is ignored when we lack the
        // sample density to judge — self-disable under low load (soak).
        assert_eq!(
            increase_pool_should_alert(
                1_000,                              // window_sum
                INCREASE_POOL_MIN_SAMPLES - 1,      // too few samples
                100,                                // n_validators
                10_000,                             // local_total
                u64::MAX,                           // peer claims absurd total
            ),
            false
        );
    }

    #[test]
    fn increase_pool_peer_behind_is_not_alert() {
        // Peer at-or-behind our cumulative view = min-wins / stale gossip,
        // never an over-report.
        assert_eq!(
            increase_pool_should_alert(1_000, 50, 10, 10_000, 9_999),
            false
        );
        assert_eq!(
            increase_pool_should_alert(1_000, 50, 10, 10_000, 10_000),
            false
        );
    }

    #[test]
    fn increase_pool_within_margin_passes() {
        // local window sum = 1_000, N = 10 → mesh_estimate = 10_000.
        // upper = 10_000 × 1.15 = 11_500. peer_excess = 11_000 ≤ 11_500.
        assert_eq!(
            increase_pool_should_alert(1_000, 50, 10, 100_000, 111_000),
            false
        );
        // Exactly on the upper bound is NOT an alert (strict >).
        assert_eq!(
            increase_pool_should_alert(1_000, 50, 10, 100_000, 111_500),
            false
        );
    }

    #[test]
    fn increase_pool_beyond_margin_fires() {
        // mesh_estimate = 10_000, upper = 11_500. peer_excess = 11_501 > upper.
        assert_eq!(
            increase_pool_should_alert(1_000, 50, 10, 100_000, 111_501),
            true
        );
        // Blatant fabrication: peer_excess huge vs a small local rate.
        assert_eq!(
            increase_pool_should_alert(1_000, 50, 10, 100_000, 10_000_000),
            true
        );
    }

    #[test]
    fn increase_pool_saturating_estimate_is_safe() {
        // Enormous window_sum × N must not panic; saturates high so an
        // honest peer is never falsely flagged.
        assert_eq!(
            increase_pool_should_alert(u64::MAX, 50, 1_000_000, 0, u64::MAX - 1),
            false
        );
    }

    #[test]
    fn dispatch_deed_returns_none_disabled() {
        let p = fresh_pool();
        // §6.1 honest framing: this PR disables existing DEED quarantine
        // pending bidirectional module.
        assert_eq!(alert_threshold_for(PoolKind::Deed, &p), None);
    }
}
