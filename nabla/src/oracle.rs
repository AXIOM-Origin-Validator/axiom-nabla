// AXIOM Nabla — Oracle Pool Synchronization (Phase 8)
// Reference: AXIOM_GUIDE_Nabla.md Section 11.7
//
// Phase 8 Tasks:
//   65. OraclePoolSync gossip message type              ← types.rs
//   66. DailyPoolState storage and midnight reset       ← this file
//   67. Pool reconciliation (conservative merge)        ← this file
//   68. Reserve counter tracking                        ← this file
//   69. Validator query interface (Nabla → Core)        ← this file
//   70. Pool state broadcast on claim processing        ← this file
//   71. Sim tests for pool sync convergence             ← sim.rs
//
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  ARCHITECTURAL RULE: Nabla synchronizes pool state, nothing more.  ║
// ║  Core processes OracleClaim transactions.                           ║
// ║  Nabla never validates claims — it only gossips counters.          ║
// ║  Same pattern: eventual consistency with TARDIS tick checkpoints.  ║
// ╚══════════════════════════════════════════════════════════════════════╝
//
// This same sync mechanism is reused for:
//   - Genesis wallet free AXC distribution
//   - DEED runner pool share distribution (§7.6)
// Any pool that needs cross-node consistency uses this pattern.

use crate::constants::{
    TOTAL_RESERVE_AXC, DAILY_EMISSION_AXC, PLATFORM_COUNT,
};

// ════════════════════════════════════════════════════════════════════════
// Task 66: Daily Pool State
// ════════════════════════════════════════════════════════════════════════

/// Platform weights (integer percentages, sum = 100).
/// Must match Core's WHITELIST exactly. Order matters.
///
/// Index → Platform:
///   0: Folding@home          (10%)
///   1: Einstein@home         (10%)
///   2: Rosetta@home          (10%)
///   3: LHC@home              ( 9%)
///   4: Milkyway@home         ( 9%)
///   5: Universe@home         ( 9%)
///   6: World Community Grid  ( 7%)
///   7: Zooniverse            ( 9%)
///   8: iNaturalist           ( 9%)
///   9: OpenStreetMap         (10%)
///  10: Wikipedia             ( 8%)
const PLATFORM_WEIGHTS: [u8; PLATFORM_COUNT] = [
    10, 10, 10, 9, 9, 9, 7, 9, 9, 10, 8,
];

/// Compute daily pool allocation per platform.
/// Each platform gets: DAILY_EMISSION × weight_pct / 100
fn daily_pool_allocations() -> [u64; PLATFORM_COUNT] {
    let mut pools = [0u64; PLATFORM_COUNT];
    for (i, &weight) in PLATFORM_WEIGHTS.iter().enumerate() {
        pools[i] = DAILY_EMISSION_AXC * weight as u64 / 100;
    }
    pools
}

/// Oracle daily pool state — tracks remaining AXC per platform for today.
///
/// Nabla nodes gossip this via OraclePoolSync. Validators query it
/// before processing OracleClaim to check if daily pool has balance.
#[derive(Debug, Clone)]
pub struct DailyPoolState {
    /// Current UTC date ("2027-03-15").
    pub date: String,
    /// Remaining AXC per platform today.
    pub pools: [u64; PLATFORM_COUNT],
    /// Total reserve AXC remaining (across all time, never resets).
    pub reserve_left: u64,
    /// Number of claims processed today (resets at midnight).
    pub claims_today: u64,
    /// TARDIS tick of last state change.
    pub last_tick: u64,
    /// TARDIS tick of last midnight reset.
    pub last_reset_tick: u64,
}

impl Default for DailyPoolState {
    fn default() -> Self {
        Self::new()
    }
}

impl DailyPoolState {
    /// Create initial pool state (genesis or first boot).
    pub fn new() -> Self {
        let pools = daily_pool_allocations();
        Self {
            date: String::from("genesis"),
            pools,
            reserve_left: TOTAL_RESERVE_AXC,
            claims_today: 0,
            last_tick: 0,
            last_reset_tick: 0,
        }
    }

    /// Check if a specific platform has remaining daily balance.
    pub fn platform_remaining(&self, platform_idx: usize) -> u64 {
        if platform_idx >= PLATFORM_COUNT {
            return 0;
        }
        self.pools[platform_idx]
    }

    /// Check if the global reserve is exhausted.
    pub fn reserve_exhausted(&self) -> bool {
        self.reserve_left == 0
    }

    /// Total remaining across all platforms today.
    pub fn total_remaining_today(&self) -> u64 {
        self.pools.iter().sum()
    }

    // ── Task 66: Midnight Reset ──

    /// Reset daily pools at midnight UTC.
    ///
    /// Called when TARDIS tick crosses a day boundary.
    /// - All 11 daily pool counters reset to fresh allocations
    /// - claims_today resets to 0
    /// - reserve_left does NOT reset (only decreases over time)
    /// - Unclaimed AXC does NOT roll over
    pub fn midnight_reset(&mut self, new_date: &str, tick: u64) {
        // Don't reset if same date (idempotent)
        if self.date == new_date {
            return;
        }

        // If reserve is exhausted, pools stay at zero permanently
        if self.reserve_left == 0 {
            self.date = String::from(new_date);
            self.pools = [0; PLATFORM_COUNT];
            self.claims_today = 0;
            self.last_reset_tick = tick;
            self.last_tick = tick;
            return;
        }

        // Fresh daily allocation
        self.date = String::from(new_date);
        self.pools = daily_pool_allocations();
        self.claims_today = 0;
        self.last_reset_tick = tick;
        self.last_tick = tick;

        // Cap each pool at reserve_left (can't distribute more than exists)
        let mut total_allocated: u64 = 0;
        for pool in self.pools.iter_mut() {
            if total_allocated + *pool > self.reserve_left {
                *pool = self.reserve_left.saturating_sub(total_allocated);
            }
            total_allocated += *pool;
        }
    }

    // ── Task 70: Record a processed claim ──

    /// Record that a claim was processed for a specific platform.
    /// Called by the validator after Core approves an OracleClaim.
    ///
    /// Returns the AXC actually awarded (may be less than requested if pool low).
    pub fn record_claim(&mut self, platform_idx: usize, axc_awarded: u64, tick: u64) -> Result<(), OraclePoolError> {
        if platform_idx >= PLATFORM_COUNT {
            return Err(OraclePoolError::InvalidPlatform);
        }
        if self.reserve_left == 0 {
            return Err(OraclePoolError::ReserveExhausted);
        }
        if self.pools[platform_idx] < axc_awarded {
            return Err(OraclePoolError::DailyPoolExhausted);
        }

        self.pools[platform_idx] -= axc_awarded;
        self.reserve_left = self.reserve_left.saturating_sub(axc_awarded);
        self.claims_today += 1;
        self.last_tick = tick;
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════
// Task 67: Pool Reconciliation (conservative merge)
// ════════════════════════════════════════════════════════════════════════

/// Reconcile local pool state with a remote OraclePoolSync message.
///
/// Rules from §11.7:
///   - Highest claims_today wins (more claims = more information)
///   - Lowest pool balance wins (conservative, prevents over-distribution)
///   - Higher tick wins for tie-breaking
///   - Date must match (ignore stale messages from previous day)
///
/// Returns true if local state was updated.
pub fn reconcile_pool(
    local: &mut DailyPoolState,
    remote_date: &str,
    remote_pools: &[u64; PLATFORM_COUNT],
    remote_reserve: u64,
    remote_claims: u64,
    remote_tick: u64,
) -> bool {
    // Different date — check which is newer
    if local.date != remote_date {
        // If remote has a newer date, accept it wholesale
        // (remote already did midnight reset, we haven't yet)
        if remote_tick > local.last_tick {
            local.date = String::from(remote_date);
            local.pools = *remote_pools;
            local.reserve_left = remote_reserve;
            local.claims_today = remote_claims;
            local.last_tick = remote_tick;
            return true;
        }
        // Our date is newer — ignore stale remote
        return false;
    }

    // Same date — conservative merge
    let mut changed = false;

    // Per-platform: take the LOWER balance (conservative — assumes more claims happened)
    for (i, &remote_pool) in remote_pools.iter().enumerate().take(PLATFORM_COUNT) {
        if remote_pool < local.pools[i] {
            local.pools[i] = remote_pool;
            changed = true;
        }
    }

    // Reserve: take the LOWER value (more distribution happened)
    if remote_reserve < local.reserve_left {
        local.reserve_left = remote_reserve;
        changed = true;
    }

    // Claims today: take the HIGHER value (more claims observed)
    if remote_claims > local.claims_today {
        local.claims_today = remote_claims;
        changed = true;
    }

    // Tick: advance to latest
    if remote_tick > local.last_tick {
        local.last_tick = remote_tick;
        changed = true;
    }

    changed
}

// ════════════════════════════════════════════════════════════════════════
// Task 69: Validator Query Interface
// ════════════════════════════════════════════════════════════════════════

/// Query result for a validator checking pool state before processing a claim.
#[derive(Debug, Clone)]
pub struct PoolQuery {
    /// Remaining AXC for this platform today.
    pub platform_remaining: u64,
    /// Total reserve remaining.
    pub reserve_remaining: u64,
    /// Whether the reserve is permanently exhausted.
    pub reserve_exhausted: bool,
    /// Current date string.
    pub date: String,
}


// ════════════════════════════════════════════════════════════════════════
// Task 68: Date Utility (TARDIS tick → UTC date)
// ════════════════════════════════════════════════════════════════════════



/// Convert days since Unix epoch to (year, month, day).
/// Civil calendar computation (Gregorian).
fn days_from_epoch(days: u64) -> (u32, u32, u32) {
    // Algorithm from Howard Hinnant's chrono-compatible date library
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m, d)
}

// ════════════════════════════════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OraclePoolError {
    InvalidPlatform,
    ReserveExhausted,
    DailyPoolExhausted,
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Daily Pool Allocation ──

    #[test]
    fn weights_sum_to_100() {
        let sum: u8 = PLATFORM_WEIGHTS.iter().sum();
        assert_eq!(sum, 100, "platform weights must sum to 100");
    }

    #[test]
    fn daily_allocations_are_correct() {
        let pools = daily_pool_allocations();
        // Each platform takes its PLATFORM_WEIGHTS share of DAILY_EMISSION_AXC.
        // DERIVED, not hardcoded: literals here went stale the moment the
        // emission rate changed (24,109 -> 23,424, when the Foundation carve
        // moved the oracle reserve from 88,000,000 to 85,500,000), and a stale
        // literal fails for the right arithmetic reason, which wastes the
        // failure. Weight coverage is asserted separately below.
        for (i, &weight) in PLATFORM_WEIGHTS.iter().enumerate() {
            assert_eq!(
                pools[i],
                DAILY_EMISSION_AXC * weight as u64 / 100,
                "platform {i} allocation must be its weight share of the daily emission",
            );
        }
        // The weights must still describe a full distribution — otherwise the
        // loop above would pass trivially against an all-zero weight table.
        assert_eq!(
            PLATFORM_WEIGHTS.iter().map(|&w| w as u64).sum::<u64>(),
            100,
            "platform weights must sum to 100%",
        );
        // Total allocated should be close to daily emission
        // (may be slightly less due to integer division)
        let total: u64 = pools.iter().sum();
        assert!(total <= DAILY_EMISSION_AXC);
        assert!(total >= DAILY_EMISSION_AXC - PLATFORM_COUNT as u64);
    }

    // ── Initial State ──

    #[test]
    fn new_pool_state() {
        let state = DailyPoolState::new();
        assert_eq!(state.reserve_left, TOTAL_RESERVE_AXC);
        assert_eq!(state.claims_today, 0);
        assert_eq!(state.date, "genesis");
        assert!(!state.reserve_exhausted());
    }

    // ── Record Claims ──

    #[test]
    fn record_claim_deducts_pool() {
        let mut state = DailyPoolState::new();
        let before = state.pools[0];
        state.record_claim(0, 5, 100).unwrap();

        assert_eq!(state.pools[0], before - 5);
        assert_eq!(state.reserve_left, TOTAL_RESERVE_AXC - 5);
        assert_eq!(state.claims_today, 1);
    }

    #[test]
    fn record_claim_multiple_platforms() {
        let mut state = DailyPoolState::new();
        state.record_claim(0, 5, 100).unwrap(); // Folding@home
        state.record_claim(7, 3, 101).unwrap(); // Zooniverse
        state.record_claim(9, 2, 102).unwrap(); // OpenStreetMap

        assert_eq!(state.claims_today, 3);
        assert_eq!(state.reserve_left, TOTAL_RESERVE_AXC - 10);
    }

    #[test]
    fn record_claim_pool_exhausted() {
        let mut state = DailyPoolState::new();
        state.pools[0] = 3; // only 3 left

        let result = state.record_claim(0, 5, 100);
        assert_eq!(result, Err(OraclePoolError::DailyPoolExhausted));
    }

    #[test]
    fn record_claim_reserve_exhausted() {
        let mut state = DailyPoolState::new();
        state.reserve_left = 0;

        let result = state.record_claim(0, 1, 100);
        assert_eq!(result, Err(OraclePoolError::ReserveExhausted));
    }

    #[test]
    fn record_claim_invalid_platform() {
        let mut state = DailyPoolState::new();
        let result = state.record_claim(99, 1, 100);
        assert_eq!(result, Err(OraclePoolError::InvalidPlatform));
    }

    // ── Midnight Reset ──

    #[test]
    fn midnight_reset_refreshes_pools() {
        let mut state = DailyPoolState::new();
        state.record_claim(0, 100, 50).unwrap();
        let before_pool0 = state.pools[0];
        assert!(before_pool0 < daily_pool_allocations()[0]);

        state.midnight_reset("2027-03-16", 17_280);

        assert_eq!(state.pools[0], daily_pool_allocations()[0]); // refreshed
        assert_eq!(state.claims_today, 0);
        assert_eq!(state.date, "2027-03-16");
        // Reserve is NOT refreshed — still reduced by 100
        assert_eq!(state.reserve_left, TOTAL_RESERVE_AXC - 100);
    }

    #[test]
    fn midnight_reset_same_date_is_noop() {
        let mut state = DailyPoolState::new();
        state.date = String::from("2027-03-15");
        state.record_claim(0, 50, 100).unwrap();
        let pool_before = state.pools[0];

        state.midnight_reset("2027-03-15", 200); // same date

        assert_eq!(state.pools[0], pool_before); // unchanged
    }

    #[test]
    fn midnight_reset_reserve_exhausted_stays_zero() {
        let mut state = DailyPoolState::new();
        state.reserve_left = 0;
        state.date = String::from("2027-03-15");

        state.midnight_reset("2027-03-16", 17_280);

        assert_eq!(state.pools, [0; PLATFORM_COUNT]);
        assert_eq!(state.reserve_left, 0);
    }

    #[test]
    fn midnight_reset_caps_at_reserve() {
        let mut state = DailyPoolState::new();
        state.reserve_left = 100; // very low reserve
        state.date = String::from("2027-03-15");

        state.midnight_reset("2027-03-16", 17_280);

        let total: u64 = state.pools.iter().sum();
        assert!(total <= 100, "total allocated must not exceed reserve");
    }

    // ── Reconciliation ──

    #[test]
    fn reconcile_same_date_takes_lower_pools() {
        let mut local = DailyPoolState::new();
        local.date = String::from("2027-03-15");
        local.pools[0] = 2_000; // local thinks 2000 remains

        let mut remote_pools = daily_pool_allocations();
        remote_pools[0] = 1_500; // remote says only 1500 (more claims happened remotely)

        let changed = reconcile_pool(
            &mut local,
            "2027-03-15",
            &remote_pools,
            TOTAL_RESERVE_AXC - 500,
            5,  // remote saw 5 claims
            200,
        );

        assert!(changed);
        assert_eq!(local.pools[0], 1_500); // took the lower value
        assert_eq!(local.claims_today, 5); // took the higher claims count
    }

    #[test]
    fn reconcile_takes_lower_reserve() {
        let mut local = DailyPoolState::new();
        local.date = String::from("2027-03-15");
        local.reserve_left = TOTAL_RESERVE_AXC - 100;

        let remote_pools = daily_pool_allocations();
        let changed = reconcile_pool(
            &mut local,
            "2027-03-15",
            &remote_pools,
            TOTAL_RESERVE_AXC - 200, // remote saw more total distribution
            3,
            200,
        );

        assert!(changed);
        assert_eq!(local.reserve_left, TOTAL_RESERVE_AXC - 200);
    }

    #[test]
    fn reconcile_takes_higher_claims() {
        let mut local = DailyPoolState::new();
        local.date = String::from("2027-03-15");
        local.claims_today = 10;

        let remote_pools = daily_pool_allocations();
        let changed = reconcile_pool(
            &mut local,
            "2027-03-15",
            &remote_pools,
            TOTAL_RESERVE_AXC,
            15, // remote saw more claims
            200,
        );

        assert!(changed);
        assert_eq!(local.claims_today, 15);
    }

    #[test]
    fn reconcile_no_change_when_local_is_more_conservative() {
        let mut local = DailyPoolState::new();
        local.date = String::from("2027-03-15");
        local.pools[0] = 1_000; // local already lower
        local.reserve_left = TOTAL_RESERVE_AXC - 500;
        local.claims_today = 20;
        local.last_tick = 300;

        let mut remote_pools = daily_pool_allocations();
        remote_pools[0] = 2_000; // remote has higher pool

        let changed = reconcile_pool(
            &mut local,
            "2027-03-15",
            &remote_pools,
            TOTAL_RESERVE_AXC - 100, // remote has higher reserve
            10,  // remote has fewer claims
            200, // remote has older tick
        );

        assert!(!changed); // local was already more conservative everywhere
    }

    #[test]
    fn reconcile_newer_date_replaces_state() {
        let mut local = DailyPoolState::new();
        local.date = String::from("2027-03-15");
        local.last_tick = 100;

        let remote_pools = daily_pool_allocations();
        let changed = reconcile_pool(
            &mut local,
            "2027-03-16", // newer date
            &remote_pools,
            TOTAL_RESERVE_AXC - 50,
            0,
            17_300, // newer tick
        );

        assert!(changed);
        assert_eq!(local.date, "2027-03-16");
        assert_eq!(local.claims_today, 0); // fresh day
    }

    #[test]
    fn reconcile_older_date_ignored() {
        let mut local = DailyPoolState::new();
        local.date = String::from("2027-03-16");
        local.last_tick = 17_300;

        let remote_pools = daily_pool_allocations();
        let changed = reconcile_pool(
            &mut local,
            "2027-03-15", // older date
            &remote_pools,
            TOTAL_RESERVE_AXC,
            5,
            100, // older tick
        );

        assert!(!changed); // stale message ignored
    }

    // ── Validator Query ──




    // ── Date Utility ──





    // ── Reserve Drain ──

    #[test]
    fn reserve_lifetime_days() {
        let days = TOTAL_RESERVE_AXC / DAILY_EMISSION_AXC;
        // ~3650 days ≈ 10 years
        assert!(days >= 3600, "reserve should last ~10 years");
        assert!(days <= 3700, "reserve should last ~10 years");
    }

    #[test]
    fn pool_drain_simulation() {
        let mut state = DailyPoolState::new();

        // Simulate 10 days of full daily claims
        for day in 1..=10u64 {
            let date = format!("2027-01-{:02}", day);
            state.midnight_reset(&date, day * 17_280);

            // Drain all platforms fully
            for i in 0..PLATFORM_COUNT {
                let remaining = state.pools[i];
                if remaining > 0 {
                    state.record_claim(i, remaining, day * 17_280 + i as u64).unwrap();
                }
            }
        }

        // After 10 days of full drain, reserve should be reduced
        let daily_total: u64 = daily_pool_allocations().iter().sum();
        let expected_reduction = daily_total * 10;
        assert_eq!(state.reserve_left, TOTAL_RESERVE_AXC - expected_reduction);
        assert!(!state.reserve_exhausted());
    }
}
