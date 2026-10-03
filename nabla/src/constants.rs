// AXIOM Nabla — Protocol Constants
// Reference: AXIOM_GUIDE_Nabla.md Section 13
//
// TUNABLE constants are loaded from nabla_tuning.conf via build.rs.
// Edit nabla_tuning.conf, then recompile. No code changes needed.
//
// FIXED constants (protocol-level, never change) are defined directly below.

// ── Generated tuning constants (from nabla_tuning.conf) ──
// All generated as u64. We re-export with correct types below so
// existing code doesn't need to change.
#[path = "tuning_gen.rs"]
mod tuning_gen;

// ── Tunable constants (typed from tuning_gen) ──
// Same names as before. Edit nabla_tuning.conf to change values.

// TARDIS tick
pub const TICK_INTERVAL_SECS: u64 = tuning_gen::TICK_INTERVAL_SECS;

/// KI#71 — §5.5 audit challenge lifetime before a re-issue may overwrite it.
/// Tick COUNT (KI#47); compare against a tick VALUE only via `ticks_to_secs`.
pub const AUDIT_CHALLENGE_PENDING_TICKS: u64 = tuning_gen::AUDIT_CHALLENGE_PENDING_TICKS;
/// KI#71 — cap on queued AuditRequests that are not from a current downstream.
pub const AUDIT_INBOX_OTHER_CAP: usize = tuning_gen::AUDIT_INBOX_OTHER_CAP as usize;

/// KI#63 §3.3 — window for the AE stall alarm. Tick COUNT (KI#47).
pub const AE_STALL_ALARM_INTERVAL_TICKS: u64 = tuning_gen::AE_STALL_ALARM_INTERVAL_TICKS;
/// Rejections needed in a window before "applied nothing" is evidence.
pub const AE_STALL_ALARM_MIN_REJECTS: u64 = tuning_gen::AE_STALL_ALARM_MIN_REJECTS;
/// Fork detections needed before "applied nothing" is a STALL not CONVERGENCE.
pub const AE_STALL_ALARM_MIN_FORKS: u64 = tuning_gen::AE_STALL_ALARM_MIN_FORKS;

/// KI#42 bloom-era sizing — expected REAL items per 90-day era, per chain.
/// See `protocol_nabla.toml` for the error-rate table, the placeholder warning
/// (these are not measured throughputs), and why they may only change at a
/// coordinated release boundary.
pub const CONSUMED_ERA_REAL_ITEMS: u64 = tuning_gen::CONSUMED_ERA_REAL_ITEMS;
pub const TXID_ERA_REAL_ITEMS: u64 = tuning_gen::TXID_ERA_REAL_ITEMS;
/// KI#43b — total recording (hashmap) nodes deployed; the adjudication
/// barrier needs answers from ALL `TOTAL - 1` peers before acquitting.
pub const RECORDING_NODES_TOTAL: usize = tuning_gen::RECORDING_NODES_TOTAL as usize;
pub const TICK_SLOT_PIGGYBACK_MAX: usize = tuning_gen::TICK_SLOT_PIGGYBACK_MAX as usize;

/// Fork Settlement §9o [R58/R59] — R48 record-AE bounds (`record_sync.rs`);
/// see `protocol_nabla.toml` for each register's meaning. `RECORD_AE_BUCKET_SPLIT`
/// is part of the record trie's HASH: one value per mesh.
pub const RECORD_AE_BUCKET_SPLIT: usize = tuning_gen::RECORD_AE_BUCKET_SPLIT as usize;
pub const RECORD_AE_MAX_PREFIXES_PER_ASK: usize = tuning_gen::RECORD_AE_MAX_PREFIXES_PER_ASK as usize;
pub const RECORD_AE_MAX_LEGS_PER_ANSWER: usize = tuning_gen::RECORD_AE_MAX_LEGS_PER_ANSWER as usize;
pub const RECORD_AE_MAX_ANSWER_BYTES: u64 = tuning_gen::RECORD_AE_MAX_ANSWER_BYTES;
pub const RECORD_AE_ASKS_PER_FROM_PER_WINDOW: u32 = tuning_gen::RECORD_AE_ASKS_PER_FROM_PER_WINDOW as u32;
pub const RECORD_AE_ANSWERS_PER_WINDOW: u64 = tuning_gen::RECORD_AE_ANSWERS_PER_WINDOW;
/// Wall-clock seconds (`virtual_secs`), not ticks.
pub const RECORD_AE_WINDOW_SECS: u64 = tuning_gen::RECORD_AE_WINDOW_SECS;
/// Wall-clock seconds (`virtual_secs`), not ticks.
pub const RECORD_AE_REPLY_TTL_SECS: u64 = tuning_gen::RECORD_AE_REPLY_TTL_SECS;

/// FOB (Bounded Pools) — the tranche EPOCH length + mover substitution grace,
/// as TARDIS tick COUNTs (KI#47). Infrastructure/carrier timing (Nabla owns the
/// clock); the tranche ECONOMICS + §5 eligibility floor are Core-owned
/// (`protocol_core.toml`). See `docs/AXIOM_DESIGN_BoundedPools.md` §6.
pub const FOB_TRANCHE_EPOCH_DURATION_TICKS: u64 = tuning_gen::FOB_TRANCHE_EPOCH_DURATION_TICKS;
pub const FOB_SUBSTITUTION_GRACE_TICKS: u64 = tuning_gen::FOB_SUBSTITUTION_GRACE_TICKS;
/// The DEV-FUND tranche epoch (§10.2a) — short in BOTH builds so `@axiom.internal`
/// funds tranche continually for testing while the real fund waits the week.
pub const FOB_DEV_FUND_EPOCH_TICKS: u64 = tuning_gen::FOB_DEV_FUND_EPOCH_TICKS;

/// The FOB epoch length for a pool's class (§10.2a): the ONE codepath picks the
/// dev-fund cadence or the real cadence purely by this data bit — no fork.
pub const fn fob_epoch_ticks(is_dev: bool) -> u64 {
    if is_dev {
        FOB_DEV_FUND_EPOCH_TICKS
    } else {
        FOB_TRANCHE_EPOCH_DURATION_TICKS
    }
}

/// KI#165 (fixed 2026-09-25): the FOB epoch length as a **tick-VALUE span** (unix
/// seconds) — the ONE projection of the tick-COUNT register above, exactly as
/// `emission::epoch_span_secs` does for the emission epoch. `fob::epoch_id` divides a
/// TARDIS tick VALUE (unix secs, KI#47), so its divisor must be in the same unit; the
/// three call sites used the raw COUNT and made the real epoch 150,000 s (1.74 d)
/// instead of the ~8.7 d the register promises. Never divide or multiply a tick
/// VALUE by `fob_epoch_ticks` directly — use this.
pub const fn fob_epoch_span_secs(is_dev: bool) -> u64 {
    axiom_core_logic::types::ticks_to_secs(fob_epoch_ticks(is_dev))
}
pub const PARENTLESS_TIMEOUT_TICKS: u64 = tuning_gen::PARENTLESS_TIMEOUT_TICKS;

/// Contribution emission claim caps (`AXIOM_DESIGN_ValidatorEmission.md` §7):
/// the airdrop cycle's two layers, on the emission pools, per FOB epoch.
pub const EMISSION_CLAIMS_MESH_CAP_PER_EPOCH: u64 = tuning_gen::EMISSION_CLAIMS_MESH_CAP_PER_EPOCH;
pub const EMISSION_CLAIMS_PER_EPOCH_PER_NABLA: u64 = tuning_gen::EMISSION_CLAIMS_PER_EPOCH_PER_NABLA;

/// Orphan recovery pass 0 (strict, dc=1-only) lasts this many orphan ticks;
/// afterwards the node relaxes and accepts any open D slot (YPX-003 §2.6).
/// Without the relaxed pass an orphan can deadlock permanently — see the
/// register comment.
pub const ORPHAN_STRICT_PASS_TICKS: u64 = tuning_gen::ORPHAN_STRICT_PASS_TICKS;
/// KI#79 — consecutive unarmed bootstrap-pull rounds before the node
/// escalates its unarmed logging from info! to warn!. See
/// protocol_nabla.toml for the rationale.
pub const UNARMED_ESCALATION_ROUNDS: u64 = tuning_gen::UNARMED_ESCALATION_ROUNDS;

/// Grace, in ticks, before a child starts counting grandpa-tick misses against
/// a NEWLY attached parent (KI#48). Breaks the circular condition where a child
/// leaves any parent that is not already a writer, while a parent becomes a
/// writer only by keeping two children.
pub const GRANDPA_SETTLE_TICKS: u32 = tuning_gen::GRANDPA_SETTLE_TICKS as u32;

/// Consecutive grandpa-tick misses before detaching. Register-sourced since
/// 2026-08-01 (was hardcoded in tardis.rs).
pub const GRANDPA_MISS_DETACH_THRESHOLD: u32 =
    tuning_gen::GRANDPA_MISS_DETACH_THRESHOLD as u32;

// Writer check
pub const WRITER_GRACE_TICKS: u8 = tuning_gen::WRITER_GRACE_TICKS as u8;
pub const WRITER_SETTLE_TICKS: u32 = tuning_gen::WRITER_SETTLE_TICKS as u32;

// Rebalance
pub const REBALANCE_COOLDOWN_TICKS: u8 = tuning_gen::REBALANCE_COOLDOWN_TICKS as u8;
pub const D_RESERVATION_TICKS: u64 = tuning_gen::D_RESERVATION_TICKS;

// Rotation
pub const PARENT_ROTATION_INTERVAL_TICKS: u32 = tuning_gen::PARENT_ROTATION_INTERVAL_TICKS as u32;
pub const PARENT_ROTATION_JITTER_TICKS: u32 = tuning_gen::PARENT_ROTATION_JITTER_TICKS as u32;
pub const CHILD_ROTATION_INTERVAL_TICKS: u32 = tuning_gen::CHILD_ROTATION_INTERVAL_TICKS as u32;
pub const CHILD_ROTATION_JITTER_TICKS: u32 = tuning_gen::CHILD_ROTATION_JITTER_TICKS as u32;

// Reattach (§2.16.5)
pub const REATTACH_STABILITY_TICKS: u32 = tuning_gen::REATTACH_STABILITY_TICKS as u32;
pub const REATTACH_MAX_PER_TICK: usize = tuning_gen::REATTACH_MAX_PER_TICK as usize;

// Gossip mesh
pub const MESH_PEER_BASE: usize = tuning_gen::MESH_PEER_BASE as usize;
pub const MESH_PEER_MAX: usize = tuning_gen::MESH_PEER_MAX as usize;
pub const ROTATION_INTERVAL: u64 = tuning_gen::ROTATION_INTERVAL;
pub const OPPORTUNISTIC_INTERVAL: u64 = tuning_gen::OPPORTUNISTIC_INTERVAL;
pub const STALE_PEER_THRESHOLD: u64 = tuning_gen::STALE_PEER_THRESHOLD;
pub const KNOWLEDGE_REFRESH_INTERVAL: u64 = tuning_gen::KNOWLEDGE_REFRESH_INTERVAL;

// ── Fixed Protocol Constants (not tunable) ──

// Group Wallet
pub const MAX_GROUP_MEMBERS: usize = 32;
pub const TOTAL_SHARE_BPS: u16 = 10_000; // 100.00%

// TARDIS
pub const MATURITY_TICKS_MIN: u64 = 5;
pub const MATURITY_TICKS_MAX: u64 = 7;
pub const TIME_BUFFER_MS: u64 = 1_000;

// Rebalance
pub const MAX_REBALANCE_PER_TICK: usize = 5;

// Mesh topology
pub const MESH_D_LO_OFFSET: usize = 2;
pub const MESH_D_HI_OFFSET: usize = 3;
pub const OPPORTUNISTIC_GRAFT_COUNT: usize = 2;
pub const E_PEER_MAX: usize = 1;
pub const E_PEER_TTL: u64 = 12;

// Peer scoring weights (§6.3.2)
pub const PEER_W1: f64 = 10.0;
pub const PEER_W2: f64 = 1.0;
pub const PEER_W3: f64 = 0.1;

// §6.3.7 Latency-aware peer pruning (LOCAL RTT — never gossiped, never in a fact).
// Latency ranks WHO a node talks to, never WHOSE money is valid. Safety
// (consume-once, k-witness, freeze) never consults this. See
// docs/AXIOM_GUIDE_Nabla.md §6.3.7 for the full rationale.
/// How often (ticks) a node evaluates its slowest link. 10 ticks ≈ 50s at
/// TICK_INTERVAL_SECS=5 — the existing topology-change horizon (tardis re-seek
/// ~10 ticks, peer TTL 12 ticks). A per-node phase jitter spreads evaluations
/// so the mesh never rewires in lockstep.
pub const LATENCY_PRUNE_INTERVAL: u64 = 10;
/// How often (ticks) a node pings its active peers to refresh RTT. Half the
/// prune interval so a fresh sample always precedes a prune evaluation.
pub const LATENCY_PING_INTERVAL: u64 = 5;
/// A pending ping with no Pong after this many seconds is swept (peer slow or
/// gone — no RTT recorded, so it is never pruned FOR latency on silence; the
/// existing stale-peer path handles a truly dead peer).
pub const LATENCY_PING_TIMEOUT_SECS: u64 = 30;
/// EWMA smoothing for RTT samples (0..1). 0.2 = act on SUSTAINED slowness and
/// ignore a single jittery packet, with no per-sample history to keep.
pub const RTT_EWMA_ALPHA: f32 = 0.2;
/// "Good enough" floor (ms). Below this a link is fine and is NEVER pruned for
/// latency, so a healthy fast mesh never churns. This is the stability
/// stopping-condition. It is deliberately NOT an absolute drop-cap: 600ms is a
/// normal global/satellite RTT, so an absolute cap would eject honest remote
/// nodes. The cap belongs on the "stop optimizing" side, not the "eject" side.
pub const LATENCY_FLOOR_MS: f32 = 300.0;
/// Relative-outlier multiple over the node's OWN median peer RTT. Only a link
/// slower than median × this is a prune candidate. In a uniformly-slow region
/// worst ≈ median, so nothing is an outlier → no prune, no self-isolation.
pub const LATENCY_OUTLIER_RATIO: f32 = 2.0;
/// Always keep this many fastest links — never pruned for latency.
pub const LATENCY_KEEP_FASTEST: usize = 2;
/// Minimum measured peers before latency pruning engages (need a stable median
/// to compare against; below this there is no reliable "outlier").
pub const LATENCY_MIN_SAMPLES: usize = 3;
// §6.3.7 Decaying latency penalty (gossipsub-style; replaces a binary cooldown).
// Each peer carries a latency penalty that BUMPS when it is pruned for latency
// and DECAYS continuously every tick. The grafting paths avoid a peer while its
// penalty is above a block threshold, so a just-dropped slow node is strongly
// avoided, fades back smoothly as it decays, and a CHRONICALLY slow node (pruned
// again on each re-evaluation) accumulates penalty and stays avoided longer —
// while a one-off blip decays back fast. No synchronized re-evaluation cliff.
/// Penalty added each time a peer is dropped for latency.
pub const LATENCY_PENALTY_ON_PRUNE: f32 = 1.0;
/// Per-tick multiplicative decay. 0.994/tick: a single prune (penalty 1.0) falls
/// below the block threshold after ~380 ticks (~32 min at TICK_INTERVAL_SECS=5);
/// a maxed-out chronic offender clears in ~51 min — bounded, never a permanent ban.
pub const LATENCY_PENALTY_DECAY: f32 = 0.994;
/// Grafting paths avoid a peer whose penalty exceeds this (still a LAST-resort
/// candidate if it is the only one — degree beats latency).
pub const LATENCY_PENALTY_GRAFT_BLOCK: f32 = 0.1;
/// Cap on accumulated penalty, so even a chronically-slow node is re-evaluated
/// within a bounded time of its last prune (a preference, never a ban).
pub const LATENCY_PENALTY_MAX: f32 = 4.0;

// Anti-entropy
pub const ANTI_ENTROPY_INTERVAL: u64 = 6;

/// KI#82 — fee-ledger (`txid_records`) anti-entropy bucket width, in ticks. The
/// §19.6 fee ledger has no AE backstop (gossip-only), so recorders diverge under
/// load. AE partitions records by `tick / TXID_AE_BUCKET_TICKS`: because the
/// ledger is append-only, old buckets' digests are frozen and only the recent
/// bucket churns, so only divergent buckets ever transfer records. Coarse enough
/// that the digest vector stays small, fine enough that a divergent bucket is a
/// bounded transfer. ~5 min at 1 tick/s. See AXIOM_DESIGN_NablaAntiEntropy.md §13.
pub const TXID_AE_BUCKET_TICKS: u64 = 300;

// (§32 Merge Protocol: `MERGE_QUARANTINE_SECS` / `MERGE_QUARANTINE_TICKS` —
// the 75 s quarantine — deleted 2026-10-02 with the timer, ForkSettlement
// §9r-E4 / D-E4-1. The `merge_quarantine_ticks` register is gone too.)

/// Bloom-era duration. KI#47: this is an EVENT count while `maybe_rotate`
/// divides a tick-VALUE span by it, so the effective era is 1/5th of the
/// stated 90 days. Value moved to protocol_nabla.toml UNCHANGED; correcting
/// it is KI#47 (type as TickCount so rustc finds every mixing site).
pub const DEFAULT_ERA_DURATION_TICKS: axiom_core_logic::types::TickCount =
    axiom_core_logic::types::TickCount(tuning_gen::DEFAULT_ERA_DURATION_TICKS);

// DEED and Runner Reward — keep in sync with protocol_core.toml [deed]
pub const DEED_WRITE_FEE: u64 = 1_000;
pub const DEED_READ_FEE: u64 = 100;
pub const DEED_RUNNER_POOL_PCT: u8 = 30;
pub const DEED_RUNNER_POOL_FINAL_PCT: u8 = 100;
pub const DEED_TRANSITION_TICKS: u64 = 10 * 365 * 24 * 720;
/// KI#53 — receipt freshness on `/register`. Was a bare literal `300` inline in
/// registration.rs with no name and no unit. See `protocol_nabla.toml` for the
/// two caveats that matter: the check is INERT today (`receipt.tick` is always
/// 0), and if switched on it must exceed the supplemental queue's 1-hour retry
/// horizon or it will reject legitimate re-registrations.
pub const RECEIPT_STALENESS_MAX_TICKS: axiom_core_logic::types::TickCount =
    axiom_core_logic::types::TickCount(tuning_gen::RECEIPT_STALENESS_MAX_TICKS);

pub const RUNNER_CLAIM_INTERVAL_SECS: u64 = 86_400;
pub const RUNNER_CLAIM_TICKS: axiom_core_logic::types::TickCount =
    axiom_core_logic::types::TickCount(tuning_gen::RUNNER_CLAIM_TICKS);

// NBC (Nabla Birth Certificate) — Section 7.8
// NBC = VBC from Core (YPX-002: "same VBC function with role = nabla").
// These constants are for sim use only. In production, Core sets all NBC/VBC fields.
pub const NBC_EXPIRY_SECS: u64 = 30 * 86_400; // 30 days (sim default)
/// DEV-ONLY (design decision 2026-08-10) — the fixed OODS baseline a dev mesh substitutes
/// when its genesis NBC carries baseline 0 (YPX-021 §7 exempt). Genesis
/// baseline 0 fails `fob_mover_eligible` closed forever, so a dev mesh could
/// never author a FOB tranche to validate the path; stamping the 10-node dev
/// mesh's size makes eligibility match a healthy production mesh. Used ONLY by
/// `build_oods_attestation(for_fob=true)` when core/logic is built `dev-mode`
/// (`version::TUNING_PROFILE == "dev"` — KI#240; it was this crate's feature);
/// RELEASE stamps the real NBC-bound baseline and `verify_oods_attestation`
/// compares it properly. NEVER a production value.
pub const DEV_OODS_BASELINE: u32 = 10;
pub const NBC_RENEWAL_WINDOW_SECS: u64 = 7 * 86_400; // renew in last 7 days (sim default)
/// Transaction budget per NBC (Yellow Paper §25.2 "NBC TX Budget", VBC/NBC `max_tx` field).
/// Peers track registrations processed by a node and reject once past this limit.
/// On renewal, counter resets (new NBC = new budget).
/// At max throughput (1 reg/tick = 720/hr), ~3 days to exhaust.
/// Enforced in nabla_node.rs registration handler. Set on NBC in cc.rs issuance.
pub const NBC_TX_BUDGET: u64 = 50_000;
/// Transaction renewal window: node should start renewal at (max_tx - NBC_TX_RENEWAL_WINDOW).
pub const NBC_TX_RENEWAL_WINDOW: u64 = 5_000;
/// How often (in ticks) to check whether NBC needs renewal (time-based or tx-based).
/// 720 ticks = 1 hour. During a 7-day time window, this gives ~168 attempts.
pub const NBC_RENEWAL_CHECK_TICKS: u64 = 720;
// All crypto (generation, signing, verification) → Core.execute()

/// Minimum age (seconds) an issuer's NBC must have before it can issue NBCs to peers.
/// 48 hours — prevents fresh NBC from immediately issuing peer NBCs (Sybil defense).
pub const NBC_ISSUER_MATURITY_SECS: u64 = 48 * 3600; // 172800 seconds = 48 hours

// Score Weights (Phase 5, Section 7.7)
pub const SCORE_W1: u64 = 1;
pub const SCORE_W2: u64 = 10;

/// YPX-014 §6.1: CC score multiplier for HashMap txid service nodes.
/// HashMap mode provides zero false positives + full forensic data.
/// Standard (bloom) CC = 1x. HashMap CC = 5x.
pub const SCORE_TXID_HASHMAP_MULTIPLIER: u64 = 5;

// Network
pub const GENESIS_NABLA_COUNT: usize = 10;
pub const KNOWN_NODES_MAX: usize = 256;
pub const BOOTSTRAP_PEERS_MAX: usize = 128;

/// Genesis Nabla node base port (test/dev). Genesis node i listens on GENESIS_BASE_PORT + i.
pub const GENESIS_BASE_PORT: u16 = 6225;

/// GUIDE §5.6c (KI#75, ruled 2026-09-25) — join probation window as a TARDIS
/// tick COUNT (KI#47): a citizen NBC younger than this is probationary on
/// every node that reads it. `_dev` twin selected by the `dev-mode` feature
/// (build.rs pair convention). The ONE predicate is `cc::is_probationary`;
/// never compare this count to a tick VALUE directly — use
/// `nabla_probation_span_secs`.
///
/// Replaces `NABLA_PROBATION_SECS = 48 * 3600` (a .rs const the tuning rule
/// forbids), whose only readers were `#[cfg(test)]` from 2026-03-26 until
/// this ruling.
pub const NABLA_PROBATION_TICKS: u64 = tuning_gen::NABLA_PROBATION_TICKS;

/// The probation window as a **tick-VALUE span** (unix seconds) — the ONE
/// projection of the count above, exactly as `fob_epoch_span_secs` does for
/// the FOB epoch. `issued_at` is a unix-second stamp, so the age it is compared
/// against must be in the same unit (KI#40/#165 class).
pub const fn nabla_probation_span_secs() -> u64 {
    axiom_core_logic::types::ticks_to_secs(NABLA_PROBATION_TICKS)
}

/// YPX-002 §9.1.1a (RULED 2026-09-25) — NBC issuer self-cap: the most
/// `NbcIssuanceRequest`s one issuer SIGNS within one FOB epoch
/// (`fob_epoch_span_secs(false)`, the mesh's epoch clock). A COUNT, not a
/// time unit. `_dev` twin selected by the `dev-mode` feature. Enforced by
/// `cc::NbcIssuanceBudget` on the issuer (refusal `ISSUER_CAP_REACHED`,
/// persisted in the snapshot) and observed by every peer
/// (`[NBC-ISSUER-OVER-CAP]`, never a refusal). Genesis (chain_depth 0) exempt.
pub const NBC_ISSUANCE_MAX_PER_EPOCH: u64 = tuning_gen::NBC_ISSUANCE_MAX_PER_EPOCH;

/// The FOB epoch id an NBC `issued_at` stamp (unix seconds, a tick VALUE)
/// falls in — the ONE projection both the issuer's budget and the peer alarm
/// use (KI#165 style: VALUE ÷ VALUE-span, never ÷ the raw tick COUNT).
pub const fn nbc_issuance_epoch(issued_at: u64) -> u64 {
    let span = fob_epoch_span_secs(false);
    issued_at / if span == 0 { 1 } else { span }
}

pub const IPV6_RECOMMENDED: bool = true;

// Nabla
pub const QUERY_NODES: usize = 3;
pub const GOSSIP_WAIT_SECS: f64 = 2.0;

// Persistence
pub const SNAPSHOT_INTERVAL_TICKS: u64 = 720;

// SMT
pub const SMT_EMPTY_LEAF_LABEL: &[u8] = b"AXIOM_SMT_EMPTY_LEAF";

// Pool daily-cap (per-Nabla + mesh-wide rate limits on genesis claims)
//
// Defense-in-depth: even if an evil Nabla bypasses Core's k=3 claim
// validation, the per-Nabla per-cycle cap bounds the blast radius.
// Mesh-wide cap bounds total protocol emission regardless of mesh size
// (crossover at N=625 for Airdrop, N=1111 for DevTreasury).
//
// Cycle is anchored on TARDIS tick counter, not wall clock — all nodes
// agree on duration deterministically. Each Nabla starts its cycle
// independently (Scenario A); cycle-phase drift between Nablas is a
// defense feature, not a bug (raises coordination cost for attackers).
//
// See docs/AXIOM_DESIGN_NablaPoolCaps.md for full design + analysis.
//
// Airdrop:  8888 ticks × 5 s/tick = 44,440 s ≈ 12.34 h per cycle
// DevTreasury: 9999 ticks × 5 s/tick = 49,995 s ≈ 13.89 h per cycle
pub const AIRDROP_CYCLE_TICKS: u64 = 8888;
pub const AIRDROP_CYCLE_SECS: u64 = AIRDROP_CYCLE_TICKS * TICK_INTERVAL_SECS;
// Bumped from 8 → 100 for dev/test (Session 13, 2026-05-26): the
// 50-wallet adversarial soak distributes ~5 claims/Nabla on average
// but SDK picker bias can cluster 20+ on one Nabla. 100 gives ample
// headroom so a soak doesn't hit the cap during normal funding;
// the cap is still in place and exercised by targeted cap-tests in
// `nabla/src/node.rs::tests` (those use lower test-scoped values).
// Production should narrow this back to a tighter limit (e.g. 8)
// once the cap-saturation behaviour is soak-validated end-to-end.
pub const AIRDROP_CLAIMS_PER_CYCLE_PER_NABLA: u64 = 100;
pub const AIRDROP_MESH_CAP_PER_CYCLE: u64 = 5000;

/// SEC-03: maximum `total_claims` increase a single gossip reconcile may
/// apply when the peer reports the SAME balance (no corresponding drain).
/// Legitimate claims each drop the pool balance by one `claim_amount`, so
/// an equal-balance message that raises the claim counter is pure gossip
/// ordering skew (the peer saw a claim whose balance-drop we will see on a
/// later message) or forgery. A few claims of skew across the mesh is
/// plausible; a large jump is an attempt to poison the mesh-wide cap
/// counter so honest nodes trip `RefusedMeshCap` and stop funding genesis.
/// Bound the per-merge skew to the per-Nabla per-cycle cap — generous
/// enough never to reject honest convergence, tight enough that a single
/// lying node can't inflate the counter toward the mesh cap.
pub const POOL_SYNC_MAX_CLAIMS_SKEW_PER_MERGE: u64 =
    AIRDROP_CLAIMS_PER_CYCLE_PER_NABLA;

/// Initial atoms in the AXIOM Airdrop pool at network genesis.
/// 6 × 10^15 atoms = 600,000 AXC. Drains monotonically over the pool's
/// lifetime; never refills. Used by `DrainOnlyPool::initial_atoms` so
/// the quarantine threshold function can compute `lifetime_pct`, and
/// by `structural_violation` for the `BalanceExceedsInitial` and
/// `IntraSnapshotInconsistent` checks. Previously hardcoded at
/// `AirdropPool::new()` call sites in `sim.rs:417, :457`.
/// Airdrop pool initial balance in atoms. The AXC magnitude is the tunable register
/// (protocol_nabla.toml `airdrop_pool_initial_axc`); atoms are DERIVED via axc() so
/// they can never drift from ATOMS_PER_AXC. Compile-time const (no runtime conversion).
pub const AIRDROP_POOL_INITIAL_ATOMS: u64 =
    axiom_denomination::axc(axiom_core_logic::types::POOL_AIRDROP_AXC);
/// Dev treasury pool initial balance — 1,000,000 dev-AXC (FACT class isolation §4).
/// AXC magnitude from protocol_nabla.toml `dev_treasury_pool_initial_axc`; atoms derived.
/// Single source for every `DevTreasuryPool::new()` site.
pub const DEV_TREASURY_POOL_INITIAL_ATOMS: u64 =
    axiom_denomination::axc(axiom_core_logic::types::POOL_DEV_TREASURY_AXC);

/// Tier-3 (Community) validator-join subsidy — 400 slots x the tier-3 CLAIM.
///
/// ⚠ READ FROM THE GENESIS DISTRIBUTION TABLE, NOT FROM protocol_nabla.toml
/// (2026-09-04). This number had three homes — Nabla's TOML, the FACT #0
/// declaration, and the Rust tier constants — and a test in each of two crates
/// policing the equality. When the claim payout changed, one home was missed:
/// Nabla matched a claim at 505 AXC while debiting the pool 500, i.e. Core
/// minting supply the pool never paid. It is now DERIVED once, in
/// core/logic/protocol_core.toml, where `build.rs` refuses to compile a
/// distribution that does not add up to the declared 100,000,000 supply.
pub const BOOTSTRAP_POOL_INITIAL_ATOMS: u64 =
    axiom_denomination::axc(axiom_core_logic::types::POOL_BOOTSTRAP_AXC);
/// Tier-2 (Foundation) validator-join subsidy — 5 slots x the tier-2 CLAIM.
/// Same single source as the Community pool above.
pub const FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS: u64 =
    axiom_denomination::axc(axiom_core_logic::types::POOL_FOUNDATION_BOOTSTRAP_AXC);

pub const DEV_TREASURY_CYCLE_TICKS: u64 = 9999;
pub const DEV_TREASURY_CYCLE_SECS: u64 = DEV_TREASURY_CYCLE_TICKS * TICK_INTERVAL_SECS;
// Bumped 9 → 100 for dev/test (same rationale as Airdrop above).
pub const DEV_TREASURY_CLAIMS_PER_CYCLE_PER_NABLA: u64 = 100;
pub const DEV_TREASURY_MESH_CAP_PER_CYCLE: u64 = 10000;

// Layer 4 — Infected Nabla Quarantine (PoolCaps design §5.6)
//
// 3-of-N consensus with dual-uniqueness: an alert about an accused
// Nabla counts toward quarantine only when 3 distinct origin_emitter
// AND 3 distinct intermediate_emitter values arrive within
// ALERT_CONSENSUS_WINDOW_TICKS. Hits cap → quarantine for
// QUARANTINE_DURATION_TICKS, after which the formerly-accused can
// reconnect and re-sync via existing PoolSync gossip.
// `ALERT_CONSENSUS_THRESHOLD` removed — superseded by
// `judoon::drain_pool_alert_threshold` (depletion-aware
// K=3/5/8/10 per `AXIOM_DESIGN_NablaJudoon.md` §2.3).
// Test sites that previously imported the constant now pass `3`
// directly as the threshold argument to `record_alert`, matching
// the K=3 floor's behaviour. No production caller remains.

/// Layer 1 probation countdown — ticks a structurally-violating peer
/// stays in probation before escalating to quarantine. 10 ticks ≈ 50 s
/// (at TICK_INTERVAL_SECS = 5). Long enough for an honest-but-corrupted
/// peer to receive correct PoolSyncs and converge via gossip;
/// short enough that a malicious peer can't sustain attack reach.
/// Per `AXIOM_DESIGN_NablaJudoon.md` §2.5 — flagged for
/// tuning from post-fix soak data.
pub const PROBATION_COUNTDOWN_TICKS: u64 = 10;
pub const ALERT_CONSENSUS_WINDOW_TICKS: u64 = 10;
/// Quarantine TTL — 50 ticks (~4 min at TICK_INTERVAL_SECS=5).
/// Long enough that a re-attempted attack pays a meaningful cost;
/// short enough that a node that briefly misbehaved isn't wedged
/// out of the mesh longer than necessary. Was temporarily 10 in
/// the 2026-05-26 dev cycle (Session 13) to observe the rejoin
/// path live inside a 1-minute window; restored to 50 after the
/// rejoin + mesh-filter + cooldown mechanics were validated.
pub const QUARANTINE_DURATION_TICKS: u64 = 50;

/// After a quarantine TTL expires, late-arriving forwarded Alerts
/// for the SAME accused are silently dropped for this many additional
/// ticks. Without the cooldown, the Alert flood that originally
/// triggered quarantine rebuilds a fresh consensus bucket the moment
/// the active TTL elapses, re-quarantining the same peer immediately.
/// 10 ticks (~50s) gives the forwarded-Alert population time to drain
/// — empirically the Alert flood is mostly first-second after consensus
/// and the rest of the 10-tick cooldown is conservative cushion.
pub const QUARANTINE_REACTIVATION_COOLDOWN_TICKS: u64 = 10;

/// Periodic pool-state heartbeat. Every N ticks, each Nabla
/// broadcasts its current `PoolSync` for Airdrop + DevTreasury +
/// Deed so peers that missed an event-driven gossip (e.g. came
/// back from quarantine, were briefly offline, dropped a packet)
/// converge without needing a new claim event. Matches the spirit
/// of SMT anti-entropy but for the pool counters specifically.
///
/// Lowered from 6 → 1 (2026-06-04) for thousand-node scale: at the
/// previous 30 s cadence a node coming back from a brief partition
/// stayed inconsistent for tens of seconds. PoolSync payloads are
/// tiny (single u64 balance + total + tick + sig per pool × 3
/// pools), so per-tick gossip cost is well under 1 KB outbound per
/// peer per second; latency-bound convergence wins out over the
/// negligible bandwidth saving of the 30 s cadence.
pub const POOL_SYNC_HEARTBEAT_TICKS: u64 = 1;

// Oracle Distribution (YPX-012). The OPEN share of the Market Allocation
// category = the Market sub-pool register (`pool_market_axc`,
// protocol_core.toml). DERIVED from Core, never typed (KI#164): until
// 2026-09-14 these were hand-copied literals (85,500,000 / 23,424) that both
// 2026-09 re-cuts missed. The sub-pool is also the source of the ruled
// validator service emission (YP §25.2.4), which shares it.
pub const TOTAL_RESERVE_AXC: u64 = axiom_core_logic::oracle::TOTAL_RESERVE;
pub const DAILY_EMISSION_AXC: u64 = axiom_core_logic::oracle::DAILY_EMISSION;
pub const PLATFORM_COUNT: usize = 11;
pub const MIN_CLAIM_INTERVAL_SECS: u64 = 86_400;
pub const MAX_CLAIMS_PER_USER_PER_DAY: usize = 11;

// WAL Audit (YPX-009 §12)
/// Check 1 random recent WAL entry every 10 ticks (~50 seconds).
pub const WAL_AUDIT_INTERVAL_TICKS: u64 = 10;
/// Recent audit window: sample from last 100 WAL entries.
pub const WAL_AUDIT_WINDOW: u64 = 100;
/// Full deep scan every 720 ticks (~1 hour).
pub const WAL_DEEP_SCAN_INTERVAL_TICKS: u64 = 720;
/// Number of random entries to verify during deep scan.
pub const WAL_DEEP_SCAN_COUNT: u32 = 5;
/// Peer cross-verification every 2160 ticks (~3 hours).
pub const WAL_PEER_VERIFY_INTERVAL_TICKS: u64 = 2160;
/// Number of records per section for peer verification.
pub const WAL_PEER_VERIFY_SECTION_SIZE: u64 = 50;
/// Maximum retries for WAL repair before halting.
pub const WAL_REPAIR_MAX_RETRIES: u32 = 3;

// State Sync (YPX-009 §12.8)
/// Maximum bytes per StatePull response SECTION (entries / bloom_eras /
/// consumed_eras each budget against this independently).
///
/// KI#79 ROOT-CAUSE CONSTRAINT — this MUST fit at least ONE serialized bloom
/// era, or era transfer starves SILENTLY and a node whose local chain lags
/// the manifest can never re-arm (delta's 8-hour UNARMED livelock, gamma's
/// 2026-08-08 reproduction). A fully-allocated era is
/// `*_ERA_REAL_ITEMS (2.25M) × 4/3 × 14.4 bits ≈ 5.41 MiB` — allocated up
/// front, so every era is that size regardless of fill. 6 MiB admits exactly
/// one era per section per pull: monotonic, atomic, whole-era progress
/// (chunking was deliberately REJECTED — chunks cannot be mixed across peers,
/// because two peers' filters for the same era are different byte strings).
/// ENFORCED at boot (nabla_node panics if an era outgrows the caps) and by
/// `ki79_era_fits_transfer_caps`. If you raise `*_ERA_REAL_ITEMS`, raise
/// this and `WIRE_MAX_MSG_BYTES` in the same commit — the guard will not let
/// you forget.
pub const STATE_PULL_MAX_BYTES: usize = 6_291_456;
/// Timeout for StatePull requests (seconds).
pub const STATE_PULL_TIMEOUT_SECS: u64 = 30;
/// Cooldown between StatePull requests to same peer (seconds).
pub const STATE_PULL_COOLDOWN_SECS: u64 = 2;
/// Number of records per RangeSync section for hash comparison.
pub const RANGE_SYNC_SECTION_SIZE: u64 = 500;
/// Maximum bytes per RangeSync transfer.
pub const RANGE_SYNC_MAX_TRANSFER_BYTES: usize = 5_242_880;
/// Timeout for RangeSync requests (seconds).
pub const RANGE_SYNC_TIMEOUT_SECS: u64 = 30;
/// Maximum concurrent StatePull requests being served.
pub const STATE_PULL_MAX_CONCURRENT_SERVE: usize = 3;

// Silicon Pulse Gossip (YPX-009 §5)
// (`PULSE_PROOF_DOMAIN` DELETED 2026-10-02 — KI#55 leftover: an unread second
// copy of the `AXIOM_PULSE_PROOF` tag; Core's `pulse::pulse_proof_sign_payload`
// is the ONE builder.)
/// How often (in ticks) Nabla evaluates pulse delivery for peer scoring.
/// Matches PULSE_EPOCH_LENGTH_TICKS (720 ticks = 1 hour).
pub const PULSE_EVAL_INTERVAL_TICKS: u64 = 720;

/// OODS-tardis epoch-seed rotation window + tick-lineage prev_sig freshness bound.
/// Single source: protocol_nabla.toml (were hardcoded 720/3 placeholders).
pub const OODS_EPOCH_TICKS: u64 = tuning_gen::OODS_EPOCH_TICKS;
pub const LINEAGE_FRESHNESS_TICKS: i64 = tuning_gen::LINEAGE_FRESHNESS_TICKS as i64;
/// Maximum epoch age for accepting pulse proofs (2 epochs = 2 hours).
pub const PULSE_MAX_EPOCH_AGE: u64 = 2;
