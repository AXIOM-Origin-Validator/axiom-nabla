// AXIOM Nabla — Connection Resilience
// Reference: AXIOM_GUIDE_Nabla.md Phase 6 Task 47
//
// Handles reconnection, timeouts, and retry logic for:
//   - TARDIS tree connections (upstream/downstream)
//   - Mesh peer connections
//   - Core communication
//
// Design:
//   Exponential backoff with jitter. Max retries before fallback.
//   TARDIS: on disconnect → announce LostUpstream → mesh self-healing
//   Mesh: on disconnect → replace with known_nodes candidate
//   Core: on timeout → retry with backoff, fail-stop if persistent

/// Connection state for a remote peer or service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnState {
    /// Connected and healthy.
    Connected,
    /// Attempting to reconnect.
    Reconnecting { attempt: u32, next_retry_tick: u64 },
    /// Permanently failed (exceeded max retries).
    Failed,
}

/// Retry policy configuration.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Initial delay in ticks before first retry.
    pub initial_delay_ticks: u64,
    /// Maximum delay between retries (cap for exponential backoff).
    pub max_delay_ticks: u64,
    /// Maximum number of retry attempts before giving up.
    pub max_retries: u32,
    /// Backoff multiplier (2 = double each time).
    pub backoff_factor: u64,
}

impl RetryPolicy {
    /// Default policy for TARDIS connections (aggressive — tree is critical).
    pub fn tardis() -> Self {
        Self {
            initial_delay_ticks: 1,   // 5 seconds
            max_delay_ticks: 12,      // 60 seconds
            max_retries: 10,
            backoff_factor: 2,
        }
    }

    /// Default policy for mesh peer connections (relaxed — mesh is redundant).
    pub fn mesh() -> Self {
        Self {
            initial_delay_ticks: 2,   // 10 seconds
            max_delay_ticks: 60,      // 5 minutes
            max_retries: 5,
            backoff_factor: 2,
        }
    }

    /// Default policy for Core communication (critical — fail-stop).
    pub fn core() -> Self {
        Self {
            initial_delay_ticks: 1,   // 5 seconds
            max_delay_ticks: 6,       // 30 seconds
            max_retries: 3,           // fail fast — "can crash, must not lie"
            backoff_factor: 2,
        }
    }

    /// Compute the delay for a given attempt number.
    /// Uses exponential backoff: delay = initial × factor^attempt
    /// Clamped to max_delay_ticks.
    pub fn delay_for_attempt(&self, attempt: u32) -> u64 {
        let delay = self
            .initial_delay_ticks
            .saturating_mul(self.backoff_factor.saturating_pow(attempt));
        delay.min(self.max_delay_ticks)
    }
}

/// Manages reconnection state for a single connection.
#[derive(Debug, Clone)]
pub struct ConnectionManager {
    /// Identifier for this connection (node_id or service name hash).
    pub id: [u8; 32],
    /// Current state.
    pub state: ConnState,
    /// Retry policy.
    pub policy: RetryPolicy,
    /// Tick when last successful communication occurred.
    pub last_success_tick: u64,
}

impl ConnectionManager {
    pub fn new(id: [u8; 32], policy: RetryPolicy) -> Self {
        Self {
            id,
            state: ConnState::Connected,
            policy,
            last_success_tick: 0,
        }
    }

    /// Mark connection as healthy.
    pub fn mark_success(&mut self, tick: u64) {
        self.state = ConnState::Connected;
        self.last_success_tick = tick;
    }

    /// Mark connection as failed — begin reconnection.
    pub fn mark_failure(&mut self, current_tick: u64) {
        match &self.state {
            ConnState::Connected => {
                // First failure — start reconnecting
                let delay = self.policy.delay_for_attempt(0);
                self.state = ConnState::Reconnecting {
                    attempt: 1,
                    next_retry_tick: current_tick + delay,
                };
            }
            ConnState::Reconnecting { attempt, .. } => {
                if *attempt >= self.policy.max_retries {
                    self.state = ConnState::Failed;
                } else {
                    let delay = self.policy.delay_for_attempt(*attempt);
                    self.state = ConnState::Reconnecting {
                        attempt: attempt + 1,
                        next_retry_tick: current_tick + delay,
                    };
                }
            }
            ConnState::Failed => {} // already given up
        }
    }

    /// Check if we should attempt reconnection now.
    pub fn should_retry(&self, current_tick: u64) -> bool {
        match &self.state {
            ConnState::Reconnecting {
                next_retry_tick, ..
            } => current_tick >= *next_retry_tick,
            _ => false,
        }
    }

    /// Is the connection healthy?
    pub fn is_connected(&self) -> bool {
        matches!(self.state, ConnState::Connected)
    }

    /// Is the connection permanently failed?
    pub fn is_failed(&self) -> bool {
        matches!(self.state, ConnState::Failed)
    }

    /// Current retry attempt (0 if connected or failed).
    pub fn attempt(&self) -> u32 {
        match &self.state {
            ConnState::Reconnecting { attempt, .. } => *attempt,
            _ => 0,
        }
    }

    /// Reset to connected state (e.g., after manual intervention).
    pub fn reset(&mut self) {
        self.state = ConnState::Connected;
    }
}

/// Timeout tracker — detects unresponsive connections.
#[derive(Debug, Clone)]
pub struct TimeoutTracker {
    /// Maximum ticks without a response before considering disconnected.
    pub timeout_ticks: u64,
}

impl TimeoutTracker {
    pub fn new(timeout_ticks: u64) -> Self {
        Self { timeout_ticks }
    }

    /// Check if a connection has timed out.
    pub fn is_timed_out(&self, last_seen_tick: u64, current_tick: u64) -> bool {
        current_tick.saturating_sub(last_seen_tick) > self.timeout_ticks
    }
}

impl Default for TimeoutTracker {
    fn default() -> Self {
        // Default: 12 ticks (60 seconds)
        Self::new(12)
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn retry_policy_exponential_backoff() {
        let policy = RetryPolicy::tardis();
        assert_eq!(policy.delay_for_attempt(0), 1);  // 1 × 2^0 = 1
        assert_eq!(policy.delay_for_attempt(1), 2);  // 1 × 2^1 = 2
        assert_eq!(policy.delay_for_attempt(2), 4);  // 1 × 2^2 = 4
        assert_eq!(policy.delay_for_attempt(3), 8);  // 1 × 2^3 = 8
        assert_eq!(policy.delay_for_attempt(4), 12); // capped at max_delay_ticks
    }

    #[test]
    fn connection_first_failure_starts_reconnect() {
        let mut conn = ConnectionManager::new(test_id(1), RetryPolicy::tardis());
        assert!(conn.is_connected());

        conn.mark_failure(10);
        assert!(!conn.is_connected());
        assert_eq!(conn.attempt(), 1);
    }

    #[test]
    fn connection_retry_timing() {
        let mut conn = ConnectionManager::new(test_id(1), RetryPolicy::tardis());
        conn.mark_failure(10); // attempt 1, next retry at 10+1=11

        assert!(!conn.should_retry(10));
        assert!(conn.should_retry(11));
    }

    #[test]
    fn connection_escalating_retries() {
        let mut conn = ConnectionManager::new(test_id(1), RetryPolicy::tardis());

        conn.mark_failure(10);  // attempt 1
        conn.mark_failure(11);  // attempt 2
        conn.mark_failure(13);  // attempt 3
        assert_eq!(conn.attempt(), 3);
        assert!(!conn.is_failed());
    }

    #[test]
    fn connection_max_retries_fails() {
        let mut conn = ConnectionManager::new(test_id(1), RetryPolicy::core()); // max 3

        conn.mark_failure(10); // attempt 1
        conn.mark_failure(11); // attempt 2
        conn.mark_failure(13); // attempt 3
        assert!(!conn.is_failed());

        conn.mark_failure(19); // attempt 4 > max 3 → Failed
        assert!(conn.is_failed());
    }

    #[test]
    fn connection_success_resets() {
        let mut conn = ConnectionManager::new(test_id(1), RetryPolicy::mesh());
        conn.mark_failure(10);
        conn.mark_failure(12);
        assert_eq!(conn.attempt(), 2);

        conn.mark_success(15);
        assert!(conn.is_connected());
        assert_eq!(conn.attempt(), 0);
    }

    #[test]
    fn timeout_tracker_basic() {
        let tracker = TimeoutTracker::new(12);
        assert!(!tracker.is_timed_out(100, 110)); // 10 < 12
        assert!(tracker.is_timed_out(100, 113));  // 13 > 12
    }

    #[test]
    fn timeout_tracker_boundary() {
        let tracker = TimeoutTracker::new(12);
        assert!(!tracker.is_timed_out(100, 112)); // exactly 12 = not timed out
        assert!(tracker.is_timed_out(100, 113));  // 13 > 12 = timed out
    }

    #[test]
    fn different_policies() {
        let tardis = RetryPolicy::tardis();
        let mesh = RetryPolicy::mesh();
        let core = RetryPolicy::core();

        // TARDIS: most retries (tree is critical)
        assert!(tardis.max_retries > core.max_retries);
        // Core: fewest retries (fail-stop)
        assert_eq!(core.max_retries, 3);
        // Mesh: relaxed delay
        assert!(mesh.max_delay_ticks > tardis.max_delay_ticks);
    }
}
