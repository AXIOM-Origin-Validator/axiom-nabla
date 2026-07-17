//! Simulated network delay injection for local soak / chaos testing.
//!
//! Gated entirely behind the `AXIOM_SIM_NET_DELAY_MAX_MS` environment
//! variable. When unset or `0`, every call site is effectively a single
//! atomic load + compare; no sleep happens and there is no per-message
//! allocation. When set to N > 0, every ingress point that opts in
//! sleeps a uniform-random duration in `[0, N]` milliseconds before
//! processing the message. This approximates multi-host network
//! latency on a single machine so the YPX-002 P5/P6 soak suites can
//! exercise gossip-delay edges without standing up a real multi-IP mesh.
//!
//! The env var is read exactly once, at the first call site on the
//! process — subsequent reads return the cached value via `OnceLock`.
//! This means operators set it before launching the binary and cannot
//! change it without a restart, which is the correct contract for a
//! test-knob.
//!
//! USAGE
//!   AXIOM_SIM_NET_DELAY_MAX_MS=300 python3 scripts/axiom-env.py start
//!
//! CALL SITES
//!   Nabla TCP message dispatch (`nabla_node.rs::handle_message`) and
//!   Nabla HTTP request router — both in the per-connection thread,
//!   synchronous `std::thread::sleep` is fine and does not contend
//!   with a shared executor.
//!
//!   Lambda uses `tokio` so its equivalent (`lambda::sim_delay`) uses
//!   `tokio::time::sleep` instead — same env var, same semantics, but
//!   async so it yields the executor instead of blocking a worker
//!   thread.
//!
//! WHY NOT A COMPILE-TIME FEATURE
//!   Flipping a `cfg(feature = "sim-delay")` on and off means
//!   recompiling release binaries for every soak tweak. An env var
//!   keeps a single binary and lets operators dial latency without
//!   touching the build. The cost of a disabled sample is one atomic
//!   load + one compare + one branch; negligible compared to a real
//!   message decode.

use std::sync::OnceLock;
use std::time::Duration;

static MAX_MS: OnceLock<u64> = OnceLock::new();

fn max_ms() -> u64 {
    *MAX_MS.get_or_init(|| {
        std::env::var("AXIOM_SIM_NET_DELAY_MAX_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    })
}

/// Synchronous simulated ingress delay.
///
/// Returns immediately when `AXIOM_SIM_NET_DELAY_MAX_MS` is unset or
/// `0`. Otherwise sleeps `rand::thread_rng().gen_range(0..=max)` ms.
/// Safe to call from any sync context including per-connection
/// threads in the Nabla TCP dispatcher.
pub fn maybe_sim_delay() {
    let max = max_ms();
    if max == 0 {
        return;
    }
    use rand::Rng;
    let ms = rand::thread_rng().gen_range(0..=max);
    std::thread::sleep(Duration::from_millis(ms));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_by_default_is_zero_cost() {
        // When env var is unset the helper returns immediately.
        // Running it 10k times must take well under a millisecond.
        let t0 = std::time::Instant::now();
        for _ in 0..10_000 {
            maybe_sim_delay();
        }
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_millis(10),
            "disabled sim_delay should be ~free: took {:?}", elapsed,
        );
    }
}
