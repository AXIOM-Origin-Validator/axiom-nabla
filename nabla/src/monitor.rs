// AXIOM Nabla — Operator Dashboard & Health Monitoring
// Reference: AXIOM_GUIDE_Nabla.md Phase 6 Task 49
//
// Embedded HTTP server for monitoring. Serves:
//   GET /           → HTML dashboard (interactive D3 operator console)
//   GET /status     → JSON status (auto-refresh every 2s via fetch)
//   GET /health     → JSON health check (for scripts/load balancers)
//   GET /api/status → Full JSON status (for programmatic access)
//
// Architecture:
//   The monitor collects a NodeStatus snapshot from NablaNode.
//   The web server is optional — node works fine without it.
//   Default: localhost:6226 (avoids collision with P2P port 6225)
//
// Penguin Scoring System (10-year scale):
//   Contribution Score = ticks_online/1000 + writes_approved*5/1000
//                      + transactions*10/1000 + orphans_rescued*50
//                      + rotations_survived*100
//   Reliability Multiplier (30-day uptime):
//     99.9% → 3x, 99% → 2x, 95% → 1x, <90% → 0.5x
//   Combined = Contribution × Reliability
//
//   Levels:
//     0-1000      Hatchling    (~first month)
//     1000-10000  Penguin      (~6 months)
//     10000-100k  Ice Runner   (~2 years)
//     100k-500k   Emperor      (~5 years)
//     500k+       Colony Elder (~8+ years)
//
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  The monitor reads state. It never writes. No mutations.           ║
// ║  It is a read-only window into the node.                          ║
// ╚══════════════════════════════════════════════════════════════════════╝

use serde::Serialize;
use std::time::SystemTime;

/// Default monitor port (6226 to avoid collision with P2P port 6225).
pub const DEFAULT_MONITOR_PORT: u16 = 6226;

/// ForkSettlement wave 3 `/status` counters (flattened into
/// `NodeStatusSnapshot`). Gauges are marked; everything else is cumulative
/// since process start. RULE 3 §2 / RULE 6: each one distinguishes "0" from
/// "never ran".
#[derive(Debug, Clone, Default, Serialize)]
pub struct OriginStatus {
    /// Gauge — origin records held (the TXID RECORDS, §2.4).
    pub origin_records: u64,
    /// Gauge — records born contested (R16); a contested record never vouches.
    pub origin_records_contested: u64,
    /// Origin (send) records created by `record_verified_leg`.
    pub origin_records_created: u64,
    /// Fork Settlement W7b (spec R52c/R52j) — gauge: REDEEM records held (the
    /// separate redeem ledger — never read as an origin).
    pub redeem_records: u64,
    /// Gauge — redeem records born contested (R16).
    pub redeem_records_contested: u64,
    /// Redeem records created by `record_verified_leg`.
    pub redeem_records_created: u64,
    /// Verified redeem legs that declared an all-zero consumed state ([R33]) —
    /// since W7c RECORDED as provenance roots (redeem ledger, never the fork
    /// index); before W7c they were dropped.
    pub redeem_leg_zero_consumed: u64,
    /// Spec R52d — records whose declared produced state is not k-bound
    /// (detection legs, never producers).
    pub producer_binding_refused: u64,
    /// KI#226 — messages refused because their `wallet_id` is not a bucket
    /// derived from their own `client_pk` (door + flood + AE, cumulative).
    pub wallet_id_key_mismatch: u64,
    /// Legs a path accepted that `verify_fork_leg` refused (excl. the expected
    /// redeem / zero-pk). Non-zero = the record hook and the path's own gate
    /// disagree.
    pub origin_leg_unrecordable: u64,
    /// Local fork detections from the records (door / flood / AE).
    pub origin_fork_claims_detected: u64,
    /// Verified remote `ForkBan` claims adopted.
    pub origin_fork_claims_adopted: u64,
    /// Verdicts (any carrier) that banned ≥1 new key.
    pub fork_claims_applied: u64,
    /// Fork claims refused by the ONE `verify_fork_claim` chokepoint, any
    /// carrier (design-named, [R25]).
    pub atraxi_evidence_refused: u64,
    /// [R28] claims re-derived from the persisted records at load that banned
    /// ≥1 key the node no longer held banned.
    pub origin_fork_bans_rederived_at_load: u64,
    /// Txid attestations that vouched an origin.
    pub origin_attest_vouched: u64,
    /// Txid attestations that withheld (`origin = None`, tick 0).
    pub origin_attest_withheld: u64,
    /// ForkSettlement §9p — of the withheld ones, those SIGNED `Held` (the
    /// origin descends from a fork / held receive in this node's records).
    /// `withheld − held` = signed `Unknown` (WAIT). Cumulative.
    pub origin_attest_held: u64,
    /// Fork Settlement W7c — provenance derivation visits (cumulative). With
    /// `provenance_held_states` it tells "ran, found nothing" from "never ran".
    pub provenance_states_derived: u64,
    /// Gauge — states whose DERIVED verdict is HELD (descend from a fork or a
    /// held receive; nothing sent from them is vouched).
    pub provenance_held_states: u64,
    /// Gauge — legs queued for re-derivation. Non-zero ⇒ this node vouches
    /// nothing until drained (fail closed).
    pub provenance_dirty_queue: u64,
    /// ForkSettlement §9r (F-6 path 11) — gauge: redeem fee credits PARKED
    /// because the redeemed cheque is held/waiting in this node's provenance.
    pub fee_credits_held: u64,
    /// Cumulative — redeem fee credits parked / released (credited once on Ok).
    /// `parked − released − held` ≠ 0 only across a restart (the gauge is
    /// persisted, the counters are not).
    pub fee_credits_parked: u64,
    pub fee_credits_released: u64,
    /// Gauge — this node's boot floor (`virtual_secs` when `recv_loop` went
    /// live, re-floored after a tick-loop stall, R9/R13). 0 = not yet
    /// listening (the node vouches nothing).
    pub origin_boot_secs: u64,
    /// R13 re-floors: consecutive tick-loop iterations further apart than the
    /// DEV settle twin (R34).
    pub origin_boot_refloors: u64,
    /// `BanTable::refused_malformed` — bans refused for malformed E1
    /// evidence (never surfaced before wave 3).
    pub ban_refused_malformed: u64,
    /// Undecodable WAL `Ban` records refused at replay ([R36]).
    pub wal_ban_decode_refused: u64,
    /// Failed writes of the ONE Nabla ban file (`nabla_bans.txt`, the list a
    /// co-located ANTIE reads). Non-zero = ANTIE may be reading a stale list.
    pub ban_file_write_failed: u64,
    // ── Fork Settlement §9o [R58/R59] (W1) — R48 record-AE ──
    /// Record-AE asks this node sent (every descent step, the root included).
    pub record_ae_asks_sent: u64,
    /// Record-AE answers this node signed and sent.
    pub record_ae_answers_sent: u64,
    /// Record-AE asks / answers REFUSED, all kinds (the sum of the seven below).
    pub record_ae_refused: u64,
    /// …no verified NBC for `from`.
    pub record_ae_refused_unknown_sender: u64,
    /// …signature not by `from`'s NBC key (spoofed `from`, tampered body).
    pub record_ae_refused_bad_signature: u64,
    /// …an ask nonce already answered.
    pub record_ae_refused_replayed_nonce: u64,
    /// …`from` over its asks-per-window budget.
    pub record_ae_refused_over_budget: u64,
    /// …an answer to no live ask of ours (spoofed / replayed / late).
    pub record_ae_refused_unsolicited: u64,
    /// …an ask / answer over a count bound.
    pub record_ae_refused_oversize: u64,
    /// …malformed (invalid prefix, empty ask, ill-formed view, wrong kind).
    pub record_ae_refused_malformed: u64,
    /// Authenticated asks SHED at the global answers-per-window cap (liveness).
    pub record_ae_shed_global: u64,
    /// Descents that reached the leaves with nothing cut.
    pub record_ae_descents_completed: u64,
    /// Descents that timed out, made no progress, or lost their peer.
    pub record_ae_descents_aborted: u64,
    /// Descents that ended with part of a level / of the wanted legs left for
    /// the next descent (the per-level budget).
    pub record_ae_descents_truncated: u64,
    /// Legs carried by accepted answers.
    pub record_ae_legs_received: u64,
    /// …asked, but refused by `verify_fork_leg` (off the lock).
    pub record_ae_legs_refused: u64,
    /// …GRADED and recorded as new records (receiver clock, R16 here).
    pub record_ae_legs_recorded: u64,
    /// …verified but UNGRADED here (directory lag) — detect-only, not stored.
    pub record_ae_legs_ungraded: u64,
    /// …not asked — refused unverified.
    pub record_ae_legs_unrequested: u64,
    /// Held ungraded records replaced in place by a graded copy (first_seen
    /// and contested kept).
    pub origin_records_upgraded: u64,
    /// Gauge — leaves in this node's record trie (graded records).
    pub record_trie_leaves: u64,
    // ── Fork Settlement §9o [R56/R57] (W2/W3) ──
    /// `SeqForkBan` gossip DROPPED — check-3, its only emitter, is retired
    /// (KI#235); the variant is a tombstone. Non-zero = a pre-W2 build or a
    /// hostile party on the mesh. Never adopted, never forwarded.
    pub seqforkban_dropped: u64,
    /// Fork Settlement §9q (B2) — `HalAdvance` gossip DROPPED: the E3 arm
    /// (KI#34 check-3's `previous_states` freeze) is retired and HAL re-anchors
    /// flood as `StateUpdate` with their leg; the variant is a tombstone.
    /// Non-zero = a pre-B2 build or a hostile party on the mesh.
    pub haladvance_dropped: u64,
    /// ForkSettlement §9r-E4 — `TaintAlert` gossip DROPPED: §32 taint is retired
    /// into ATRAXI A5 (`provenance.rs`); the variant is a tombstone. Non-zero =
    /// a pre-E4 build or a hostile party (the old arm let anyone block a proven
    /// forker's downstream at the door). Replaces `taint_applied` /
    /// `taint_unconfirmed`.
    pub taintalert_dropped: u64,
    /// ForkSettlement §9r-E4 (D-E4-1) — `MergeResolved` gossip DROPPED (its
    /// only emitter, the 75 s quarantine expiry, is deleted).
    pub mergeresolved_dropped: u64,
    /// AE entries whose non-`Normal` status was DISCARDED before the merge —
    /// the leaf status is a local projection (KI#236). Expected non-zero
    /// wherever a peer holds a local hold; also what a forged push looks like.
    pub ae_status_discarded: u64,
    /// Restored leaves at `open` whose status this node cannot back (`Banned`
    /// without a BanTable entry, plus `Frozen` / `Tainted`). Counted, never
    /// changed.
    pub status_unbacked_at_load: u64,
}

/// Complete node status snapshot — collected once and served to all endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatusSnapshot {
    // ── Identity ──
    pub version: String,
    pub node_name: String,
    pub node_id_hex: String,
    pub uptime_secs: u64,
    /// YPX-014 txid service mode this node is running — `"hashmap"`
    /// or `"bloom"`. Operator's `--txid-mode` choice. Surfaced on
    /// `/status` so the dashboard can show it per-node, and so
    /// audit-grade consumers (UNCLE, regulator clients) can verify
    /// directly from the source rather than going through a gossiped
    /// peer cache.
    #[serde(default)]
    pub txid_service: String,
    /// Number of (txid → wallet_id) entries in the exact hashmap.
    /// Always 0 in bloom mode. Operators capacity-plan against this
    /// — hashmap memory grows linearly with this count.
    #[serde(default)]
    pub txid_hashmap_len: u64,
    /// Estimated resident bytes of the exact hashmap (~96 B/entry).
    /// Always 0 in bloom mode.
    #[serde(default)]
    pub txid_hashmap_bytes: u64,
    /// Number of distinct txids inserted into the bloom filter since
    /// boot. ALWAYS populated (both modes use bloom — it's the only
    /// tier in bloom mode and the fast negative pre-check in hashmap
    /// mode).
    #[serde(default)]
    pub txid_bloom_count: u64,
    /// Physical bytes of the bloom filter. Fixed at boot.
    #[serde(default)]
    pub txid_bloom_bytes: u64,
    /// Current estimated false-positive rate of the bloom filter
    /// (0.0..=1.0). Climbs as the filter saturates; operators watch
    /// this to decide when to bump `--bloom-size`.
    #[serde(default)]
    pub txid_bloom_fpr: f64,
    /// KI#42 — fill ratio of the txid bloom against its design capacity
    /// (`DEFAULT_BLOOM_EXPECTED_ITEMS`). >1.0 means the network has outgrown the
    /// filter; the FPR above climbs steeply past that point.
    #[serde(default)]
    pub txid_bloom_fill_ratio: f64,
    /// KI#42 — the CONSUMED-STATE bloom, which previously had no exposed health
    /// signal at all. Its false positives fail CLOSED at the A12 anti-rollback
    /// gate, refusing legitimate registrations as replays, so this is the more
    /// consequential of the two filters to watch. Both are lifetime filters that
    /// never roll over: these numbers only climb. Plan:
    /// `AXIOM_DESIGN_NablaAntiEntropy.md` §12.
    #[serde(default)]
    pub consumed_bloom_count: u64,
    #[serde(default)]
    pub consumed_bloom_fpr: f64,
    #[serde(default)]
    pub consumed_bloom_fill_ratio: f64,

    // ── Network ──
    pub listen_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_addr: Option<String>,

    /// Unix seconds when this snapshot was BUILT — not when it was served.
    /// `/status` serves a cached snapshot whenever the node lock is contended
    /// (see the try_lock path in nabla_node.rs: a blocking lock once wedged
    /// the accept loop and killed the dashboard for days on busy hashmap
    /// recorders). That fallback is correct, but without this stamp it is
    /// INVISIBLE: a permanently contended node serves one frozen snapshot
    /// forever and every consumer reads it as live. Measured 2026-09-01 —
    /// zeta reported the same `current_tick` for 20+ minutes while its TARDIS
    /// ticked normally, which made `driver.py tardis` report a 1000 s tick
    /// spread and a second root_hash on a converged mesh. A status surface
    /// that cannot be told from a lying one is worse than no status surface,
    /// so: stamp it, and let the reader decide.
    pub built_at: u64,

    // ── TARDIS ──
    pub current_tick: u64,
    pub tardis_active: bool,
    pub tardis_slot: String,
    pub has_upstream: bool,
    pub downstream_count: usize,
    pub is_writer: bool,
    /// GUIDE §5.6a — peers do not all observe the same source address for us,
    /// so we are demoted to a READ node. RULE 3: a security-relevant demotion
    /// needs a COUNTER, not just a log line — without this, "never disputed"
    /// and "the check never ran" are indistinguishable on a live node.
    pub address_disputed: bool,
    /// How many distinct peers have reported our source address. 0 means the
    /// check has had NOTHING to evaluate — that is missing coverage, not a pass.
    pub address_reports: usize,
    /// GUIDE §5.6a — the ACTUAL reports behind `address_reports`: who observed
    /// us, and at what source address.
    ///
    /// ⚠ WHY THIS EXISTS. Until 2026-08-26 `/status` carried only the COUNT and
    /// the verdict (`address_reports`, `address_disputed`) — a conclusion with
    /// its evidence withheld. An operator seeing `disputed: true` could not tell
    /// WHICH addresses disagreed or WHO reported them, which is the entire
    /// diagnostic content. Worse in the other direction: `address_reports: 0`
    /// looked identical whether nobody had reported or the mechanism was inert,
    /// and on the Pi it was inert for six days without anything able to say so.
    ///
    /// A demotion is security-relevant, so it needs more than a boolean
    /// (RULE 3): a rejection you cannot inspect cannot be distinguished from a
    /// rejection that never ran.
    pub address_observers: Vec<AddressObservation>,
    /// GUIDE §5.6a — peers AGREE on our address, but it is not globally
    /// routable (private / loopback / link-local / CGNAT). We are demoted to
    /// READ for a reason DISTINCT from disagreement, and the two need
    /// different operator responses: a dispute means fix your network view,
    /// this means you have no WAN address at all.
    ///
    /// `address_disputed` stays the single predicate the write gate reads;
    /// this says WHY it is true (RULE 3 — a demotion an operator cannot
    /// explain is a demotion they will work around).
    pub address_unroutable: bool,
    /// Own NBC — the node's identity certificate. NONE of this was on `/status`
    /// before 2026-08-26, so an operator could not answer "how old is my
    /// certificate, when does it expire, and who issued it?" from the one
    /// surface they have. `nbc_expires_at` matters operationally: an expired NBC
    /// takes the node out of the mesh, and renewal is the ONE sanctioned
    /// periodic Nabla dependency a validator has.
    pub nbc_issued_at: u64,
    pub nbc_expires_at: u64,
    /// Seconds until expiry at the moment this snapshot was taken. Negative
    /// means ALREADY EXPIRED — surfaced as a signed value rather than clamped,
    /// because "expired 40 minutes ago" and "expires in 0s" are different
    /// operational situations.
    pub nbc_expires_in_secs: i64,
    /// 0 = genesis (ceremony-issued, address curated in the seed list and
    /// therefore exempt from §5.6a self-checking); >0 = citizen, issued by a
    /// peer at that chain depth.
    pub nbc_chain_depth: u8,
    /// Who issued it — "ceremony" for genesis, else the issuing peer's name.
    pub nbc_issuer: String,
    /// §5.6a-bis — `SlotAvailable` hints discarded because we hold no OBSERVED
    /// address for the announcing node, so its open slot is not dialable.
    ///
    /// RULE 3 shape 2: the hint is now identity-only, so a node we have never
    /// contacted can tell us it has a slot but not where it is. Dropping that
    /// is correct; dropping it SILENTLY is not — "we discard every hint" and
    /// "no hints ever arrive" would render identically.
    pub slot_hints_dropped_unobserved: u64,
    pub d1_approved: bool,
    pub d2_approved: bool,

    // ── Writer-rotation observability (KI#18 diagnostic, 2026-05-28) ──
    /// Ticks accumulated with the current parent since last reattach.
    /// Advances ONLY in `process_tick()` (`tardis.rs:350`) — i.e. when a
    /// child receives a TickMessage from its upstream over the wire.
    /// `wants_rotate()` fires when this exceeds `CHILD_ROTATION_INTERVAL_TICKS
    /// + jitter` (150-170 ticks ≈ 2.5-3 min). If it stays at 0 or doesn't
    /// advance, parent→child Tick delivery is broken.
    #[serde(default)]
    pub ticks_with_current_parent: u32,
    /// Decrements 1/tick. Set to `REBALANCE_COOLDOWN_TICKS + 1 = 11`
    /// after a rotation fires. If > 0 in steady state without a recent
    /// rotation, the cooldown gate is wedged.
    #[serde(default)]
    pub rebalance_cooldown: u8,
    /// Orphan-cause counters (KI#48 observability). Why this node has lost its
    /// upstream, split two ways: `via_*` = the code path that cleared `up`
    /// (counts paths that orphan a node WITHOUT emitting a DetachReason);
    /// `detach_*` = the protocol reason on TardisAction::DetachUpstream,
    /// counted where it is emitted because the handler calls remove_peer() and
    /// the reason is lost by the time `up` is cleared.
    ///
    /// Live-mesh equivalent of `sim.rs::OrphanCause`, which could not be reused:
    /// that enum predates the grandpa rule and has no GrandpaTickMissing variant
    /// (~95% of real detaches), and its WriterCheck is "disabled v0.9.1".
    #[serde(default)]
    pub orphan_causes: std::collections::BTreeMap<String, u64>,
    /// §7.6 lineage verification outcomes (see nabla_node.rs). Present so the
    /// check is observable at `info` — `[LINEAGE-OK]` is debug + rate-limited.
    #[serde(default)]
    pub lineage_ok: u64,
    #[serde(default)]
    pub lineage_reject: u64,
    #[serde(default)]
    pub lineage_skip: u64,
    /// Self-contradiction flags suppressed because the answer matched our own
    /// root (§5.5.1 exonerate-only guard). Exposed so the guard is observable —
    /// a silent guard is indistinguishable from a dead one.
    #[serde(default)]
    pub audit_exonerated: u64,
    /// KI#71 — the §5.5 bottom-up audit counters (`TardisNode::audit_counters`):
    /// `selfcontra_flags` isolates SELF-CONTRADICTION convictions (which
    /// `orphan_causes.via_flag_questionable` mixes with merkle-proof and cascade
    /// causes); `response_stale`, `responses_unmatched`, `responses_unauthorized`,
    /// `requests_shed`, `exonerated`.
    #[serde(default)]
    pub tardis_audit: std::collections::BTreeMap<String, u64>,
    /// TickHash advertisements accepted / rejected as audit evidence (§5.5).
    #[serde(default)]
    pub tickhash_verified: u64,
    #[serde(default)]
    pub tickhash_unverified: u64,
    /// Alerts whose carried evidence proved / did not prove the accusation.
    #[serde(default)]
    pub alert_proven: u64,
    #[serde(default)]
    pub alert_unproven: u64,
    /// §5.6 alert quorums met but NOT acted on because the forwarder's identity
    /// could not be proven (ghost audit G4 / **KI#72** — the doc here said KI#71,
    /// which is the TARDIS-churn issue, not this one).
    ///
    /// Since KI#72 shipped the per-hop `Alert.intermediate_sig`, a hop from a
    /// peer whose NBC we hold IS provable, so this should stay 0 in a healthy
    /// mesh. Non-zero now means alerts are arriving from nodes we cannot
    /// attribute — or that `--skip-verify` is on, which forces `None`.
    #[serde(default)]
    pub quarantine_withheld: u64,
    /// KI#63(c) — `AE_STALL_ALARM_INTERVAL_TICKS` windows in which anti-entropy
    /// applied NOTHING while rejecting a meaningful number of entries
    /// (`ae_stall_detected`). The `[AE-STALL]` log line alone is unobservable
    /// from a dashboard or a gate (RULE 3 §2); this is the same verdict as a
    /// counter. Non-zero = replication was not converging for at least one
    /// window — the condition that read as a healthy run for six hours on
    /// 2026-08-04.
    #[serde(default)]
    pub ae_stall_windows: u64,
    /// §5.2.2c KI#132 — registers that declared a LIVE stake lock and were NOT
    /// the wallet's own stake claim.
    ///
    /// ⚠ **NON-ZERO MEANS A CORE GATE LEAKED.** Core's CL1 send gate and CL5
    /// redeem gate should make this unreachable: a stake-locked wallet cannot
    /// produce a registerable receipt except the claim redeem that stamps the
    /// lock, which is excluded here. Nabla refuses nothing on this (it fails
    /// open by design and is not the enforcement) — it REPORTS.
    #[serde(default)]
    pub stake_lock_observed_not_own_claim: u64,
    /// §5.5 audit responses refused: sender was not our upstream (a
    /// denial-of-audit attempt), or matched no pending challenge.
    #[serde(default)]
    pub audit_resp_unauthorized: u64,
    #[serde(default)]
    pub audit_resp_unmatched: u64,
    /// G8 — PoolSync dropped for an unresolvable sender NBC. Non-zero at a
    /// steady rate means honest PoolSync is being lost (a known-open bug);
    /// the per-event line is `debug!` and invisible in production.
    #[serde(default)]
    pub poolsync_drop_unverified: u64,
    /// G16 — approvals accepted WITHOUT signature verification (`--skip-verify`,
    /// implied by `--dev`). Non-zero means this node's YPX-003 writer
    /// qualification rests on unauthenticated approvals.
    #[serde(default)]
    pub approvals_unverified: u64,
    /// KI#72 — Alert hops with a PROVEN `intermediate_emitter` (verified against
    /// its NBC-bound Ed25519 key) vs. hops that could not be proven. `unproven`
    /// non-zero means alerts are arriving that cannot be attributed.
    #[serde(default)]
    pub alert_identity_proven: u64,
    #[serde(default)]
    pub alert_identity_unproven: u64,
    /// G11 — WAL deep-scan RECOVERIES. Counts truncations performed, not raw
    /// findings.
    ///
    /// This comment previously said the deep scan "has NO recovery path" and
    /// that "nothing was done". True when written; G11 wired
    /// `audit_deep_and_recover` the same day, once KI#74 made the detector
    /// trustworthy. Left stale it would have been exactly the shape RULE 3
    /// calls out — a comment describing behaviour the code no longer has.
    ///
    /// Recovery truncates at the reader's CLEAN PREFIX (not at
    /// `min(corrupted)`, which would keep the corrupt entry and loop forever).
    /// Non-zero is a hardware-error signal if it repeats.
    #[serde(default)]
    pub wal_deep_scan_corrupt: u64,
    /// G15 — H3 data-availability messages received for an UNBUILT protocol
    /// (no emitter, no CHALLENGE_WINDOW_TICKS, no SCAR path). Dropped, never
    /// relayed. Non-zero means something is emitting them.
    #[serde(default)]
    pub h3_unbuilt_dropped: u64,
    /// KI#222 — `BanAlert` gossip messages DROPPED by the retired receiver
    /// (forgeable E1 proof, no honest emitter; the variant is a bincode
    /// tombstone). Nothing honest sends one, so non-zero means a stale build or
    /// an attempted false ban is on the mesh.
    #[serde(default)]
    pub ki222_banalert_dropped: u64,

    // ── SMT / Data ──
    pub root_hash_hex: String,
    pub entry_count: usize,
    pub ban_count: usize,

    // ── Mesh ──
    pub mesh_active: bool,
    pub mesh_peer_count: usize,
    pub mesh_target_peers: usize,
    pub mesh_known_nodes: usize,
    pub estimated_network_size: usize,
    /// OODS (YPX-021) size estimate over this node's learned mesh view, via
    /// Extrema Propagation with identity-bound draws. Read-only telemetry — NOT
    /// a consensus gate. Distinct from `estimated_network_size` (the naive
    /// `unique_seen`-count heuristic, which a Sybil can inflate); OODS is the
    /// forgery-resistant readout. Watch it drop under a partition/eclipse.
    pub oods_estimate: f64,
    /// OODS-tardis (YPX-021 §6) size estimate — the SECOND, Core-produced OODS,
    /// computed by `oods_estimate` over the tick's cascaded extrema accumulator
    /// (`latest_oods_tardis`). Independent of `oods_estimate` above (gossip mesh
    /// view): this rides the TARDIS tick tree. A gap between the two flags a
    /// partition (tree view vs mesh view disagree). 0 until the first tick.
    #[serde(default)]
    pub tardis_depth: u32,
    /// E-peer (enquiry peer): reader node used for TARDIS tree exploration.
    /// Max 1 per node (E_PEER_MAX=1), TTL=12 ticks.
    pub enquiry_peer_count: usize,

    // ── CC / Runner ──
    pub cc_active: bool,
    pub cc_tick: u64,
    pub cc_ticks_helped: u64,
    pub cc_total_registrations: u64,
    pub cc_score: u64,
    pub runner_pool_balance: u64,

    // ── Airdrop Pool (§17.11) ──
    pub airdrop_pool_balance: u64,
    pub airdrop_pool_claims: u64,
    pub airdrop_local_claims: u64,

    // ── Dev Treasury Pool (FACT class isolation §6) ──
    // 1M dev-AXC, OUTSIDE the 100M public cap. Surfaced in the
    // dashboard mirror of airdrop so operators can see dev-AXC
    // consumption distinct from public-AXC airdrop consumption.
    pub dev_pool_balance: u64,
    pub dev_pool_claims: u64,
    pub dev_pool_local_claims: u64,

    // ── Bootstrap subsidy pools (ValidatorJoin §5.2.3; KI#250 gap note) ──
    // Before KI#250 these two pools were invisible on /status, so a drain
    // (refused-but-debited claims) could only be found by reading the
    // persisted `*_pool.state` files (`scripts/read_subsidy_pools.py`).
    pub bootstrap_pool_balance: u64,
    pub bootstrap_pool_claims: u64,
    pub foundation_pool_balance: u64,
    pub foundation_pool_claims: u64,

    // ── DEED ──
    pub deed_collected: u64,
    pub deed_split: String,
    /// PR3: DEED Pool current balance — 10% of every receiver-pays
    /// validator fee accumulated for the first 10 years
    /// (`docs/AXIOM_DESIGN_DeedDistribution.md`). Surfaced on the
    /// Protocol Pools card so operators can watch the pool grow in
    /// real time. Distinct from `deed_collected`, which counts the
    /// 1000-atom write fee on every register.
    #[serde(default)]
    pub deed_pool_balance: u64,
    #[serde(default)]
    pub deed_pool_total_credited: u64,

    /// Dev-class DEED Pool — same 10% slice mechanism, but credited
    /// from `@axiom.internal` TXs only. Observability for the dev
    /// economy; NEVER convertible to public AXC
    /// (`AXIOM_DESIGN_FactClassIsolation.md`). Surfaced on the Protocol
    /// Pools card as a small-text sub-line under the public DEED rows
    /// so operators can see what's collecting from test traffic without
    /// confusing it with the real DEED accounting.
    #[serde(default)]
    pub dev_deed_pool_balance: u64,
    #[serde(default)]
    pub dev_deed_pool_total_credited: u64,

    /// FOB (Fixed Outflow Balance / Bounded Pools) — tranche activity counters.
    /// `authored` = statements this node broadcast (recording nodes only);
    /// `applied` = statements judged valid + debited into local pools;
    /// `rejected` = statements failed crypto/judge (RULE 3: a reject is a
    /// counter, not just a log). See `docs/AXIOM_DESIGN_BoundedPools.md`.
    /// FOB pool balances (§10.0 dashboard display): "vidhex16:class:balance"
    /// per pool, sorted. Recording nodes only; empty on bloom nodes.
    #[serde(default)]
    pub fob_pools: Vec<String>,
    #[serde(default)]
    pub fob_tranches_authored: u64,
    #[serde(default)]
    pub fob_tranches_applied: u64,
    #[serde(default)]
    pub fob_tranches_rejected: u64,
    #[serde(default)]
    pub fob_conservation_rejects: u64,
    /// Contribution emission (`AXIOM_DESIGN_ValidatorEmission.md`): the epoch this
    /// node last rolled to, rolls since boot, atoms drawn from DEED, claims granted
    /// and refused (RULE 6 — every path observable).
    #[serde(default)]
    pub emission_epoch: u64,
    #[serde(default)]
    pub emission_rolls: u64,
    #[serde(default)]
    pub emission_top_up_atoms: u64,
    #[serde(default)]
    pub emission_claims_ok: u64,
    #[serde(default)]
    pub emission_claims_refused: u64,
    /// KI#193 residual — epoch rolls refused because DEED moved fewer atoms than
    /// requested (the debit and the credit must be equal). Non-zero = the
    /// DEED→emission transfer did not conserve and the epoch did NOT roll.
    #[serde(default)]
    pub emission_conservation_refusals: u64,

    // ── Gossip ──
    pub gossip_seen_count: usize,
    pub last_gossip_tick: u64,

    // ── Transport observability (2026-04-15 fix `af79958` companion) ──
    /// Total TCP send failures across recv_loop + tick_loop drain paths.
    /// Counts how often the cached-connection eviction recovery in
    /// `TcpTransport::send` had to re-establish a TCP socket. Code:
    /// `E_NABLA_TRANSPORT_SEND_FAILED`. Persistent non-zero indicates
    /// network instability or peer churn — investigate per-peer breakdown.
    #[serde(default)]
    pub transport_send_failures_total: u64,
    /// Per-peer send failure breakdown. Key is "ip:port" string.
    /// Empty in steady-state; non-empty entries are recovery events.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub transport_send_failures_per_peer: std::collections::HashMap<String, u64>,

    /// KI#37 — outbound-storm circuit breaker (backstop against any
    /// re-broadcast loop/flood). `storm_shed_active` is true while the
    /// node is dropping forward/broadcast traffic because its 1s
    /// forward-send rate crossed the shed ceiling; `storm_dropped_total`
    /// and `storm_trips_total` accumulate since boot. All three are 0 /
    /// false on a healthy mesh — any non-zero value means a storm was
    /// detected and contained.
    #[serde(default)]
    pub storm_shed_active: bool,
    #[serde(default)]
    pub storm_dropped_total: u64,
    #[serde(default)]
    pub storm_trips_total: u64,

    /// Fix #1: Cumulative TARDIS tick-signature verify failures since
    /// boot. Counts how often `process_tick` saw an incoming tick
    /// whose `signature` failed Core's `signer.verify` against the
    /// claimed `upstream_pk`. Non-zero in steady state flags:
    /// transport corruption (different payload_hash from same
    /// sender), signing-key drift, or replay of stale ticks. Detail
    /// per-failure lives in `nabla.log` as `[TICK-SIG-FAIL] …`
    /// structured lines. See node.rs `TardisNode::tick_sig_failures`.
    #[serde(default)]
    pub tick_sig_failures: u64,
    /// YPX-003 §2.1 (KI#48, RULED 2026-09-25) — this node is PARKED in a
    /// host's P slot right now: receiving the host's ticks, `needs_parent`
    /// still true, still seeking a D seat (`tardis_slot` reads "Parked").
    #[serde(default)]
    pub tardis_parked: bool,
    /// P grants this node accepted as a requester (cumulative), and parks
    /// that ended by landing a D slot elsewhere. A rising `grants` with a
    /// flat `to_seated` on a mesh with open D slots = the "keep seeking"
    /// half is not working (the 08-01 stall shape).
    #[serde(default)]
    pub tardis_parked_grants: u64,
    #[serde(default)]
    pub tardis_parked_to_seated: u64,

    /// Phase B Layer 4: number of currently-active mesh-wide
    /// quarantines this Nabla is enforcing. Non-zero means we are
    /// dropping all gossip from quarantined peers per
    /// `is_peer_quarantined`. Auto-expires after
    /// QUARANTINE_DURATION_TICKS.
    #[serde(default)]
    pub quarantine_active_count: usize,
    /// Phase B Layer 4: number of in-flight pending-alert buckets
    /// (accused-peer aggregations within the 10-tick consensus
    /// window). Increments as alerts arrive; decrements when a
    /// bucket either crosses the 3-of-N threshold (→ quarantine
    /// fires, bucket removed) or expires (sweep at window close).
    #[serde(default)]
    pub quarantine_pending_count: usize,
    /// KI#191 residual (RULED 2026-09-25, NablaJudoon §2.5) — emission-pool
    /// PoolSyncs whose structural violation escalated to JUDOON probation on
    /// this node, cumulative since start. ONE RULE FOR EVERY POOL: this is the
    /// same `PoolStructuralViolation` path the airdrop pool takes. The first
    /// soak after the build must show 0 here (precondition measured: 0
    /// structural warnings live). Non-zero = a peer advertised an emission
    /// snapshot that violates the conservation identity.
    #[serde(default)]
    pub emission_structural_violations: u64,
    /// YPX-002 §9.1.1a (RULED 2026-09-25) — NBC issuer self-cap + peer alarm.
    /// `nbc_issued_this_epoch`: certificates THIS node signed in the current
    /// FOB epoch (budget, persisted). `nbc_issuance_refused_cap`: requests
    /// answered `ISSUER_CAP_REACHED`, cumulative. `nbc_issuer_over_cap_seen`:
    /// verified citizen certificates that took some issuer's per-epoch count
    /// above the cap — `[NBC-ISSUER-OVER-CAP]` — observability only.
    #[serde(default)]
    pub nbc_issued_this_epoch: u64,
    #[serde(default)]
    pub nbc_issuance_refused_cap: u64,
    #[serde(default)]
    pub nbc_issuer_over_cap_seen: u64,

    // ── GUIDE §5.6c join probation (KI#75) ──
    /// Peers in `verified_nbcs` whose NBC is inside the probation window
    /// (`cc::is_probationary` at the current tick). Not counted in OODS,
    /// skipped as upstream candidates, Alerts withheld.
    #[serde(default)]
    pub probationary_peers: usize,
    /// Refusals this node issued BECAUSE of probation, summed over the three
    /// refusing levers: TardisAttachRequests refused while OUR NBC was
    /// probationary + EmissionNabla claims answered NOT_ELIGIBLE for a
    /// probationary certificate + Alerts withheld from probationary peers.
    /// Cumulative since start. "0" with `probationary_peers > 0` and no
    /// traffic is normal; "0" forever on a busy mesh means a lever is dead
    /// (RULE 3 §2).
    #[serde(default)]
    pub probation_refusals: u64,
    /// Lever 5 — the pool kinds for which at least one AUTHENTICATED
    /// PoolSync has been applied since start (`PoolKind::status_name`).
    /// The serve-gate stays `not_ready_syncing` until every
    /// `PoolKind::SERVE_GATE_KINDS` entry is present.
    #[serde(default)]
    pub pool_synced_kinds: Vec<String>,
    /// Lever 5 — true once every serve-gate pool kind has synced (or the
    /// node is the first of its mesh, which has nobody to sync from — the
    /// same KI#42 exemption as `anti_rollback_armed`). While false the node
    /// refuses every registration even when `anti_rollback_armed` is true.
    #[serde(default)]
    pub pool_sync_gate_open: bool,

    // ── Scoring ──
    pub penguin_score: u64,
    pub penguin_level: String,
    pub penguin_emoji: String,
    pub uptime_streak_days: u64,
    pub writes_approved: u64,
    pub orphans_rescued: u64,
    pub rotations_survived: u64,
    pub reliability_multiplier: f64,

    // ── Persistence / Storage ──
    pub wal_file_bytes: u64,
    pub wal_ops_since_snapshot: u64,
    pub snapshot_count: usize,
    pub snapshot_total_bytes: u64,
    pub last_snapshot_tick: u64,
    pub total_disk_bytes: u64,
    pub smt_memory_bytes: u64,

    // ── Peer details (for D3 graph) ──
    pub upstream_hex: String,
    pub upstream_name: String,
    pub d1_hex: String,
    pub d1_name: String,
    pub d2_hex: String,
    pub d2_name: String,
    pub peer_list: Vec<PeerEntry>,

    // ── Bootstrap ──
    pub bootstrap_peers: Vec<BootstrapPeerEntry>,

    // ── Health ──
    /// KI#79 — the KI#42 serve-gate: is this node serving registrations?
    /// UNARMED means every registration is refused, which for 8 hours on
    /// delta (2026-08-07) coexisted with `healthy: true` because no status
    /// field carried it.
    #[serde(default)]
    pub anti_rollback_armed: bool,
    /// KI#79 — consecutive bootstrap-pull rounds spent unarmed (0 when armed).
    #[serde(default)]
    pub unarmed_rounds: u64,
    /// KI#79 — TARDIS tick span (tick VALUE = unix secs, KI#47) of the
    /// current unarmed episode (0 when armed or unknown).
    #[serde(default)]
    pub unarmed_ticks: u64,
    /// KI#65 — same-seq provisional consumed-marks manufactured (cumulative).
    /// A lateral same-seq head swap records a FALSIFIABLE mark instead of a
    /// permanent bloom entry; this counter makes the manufacture visible
    /// instead of invisible-until-it-vetoes (RULE 3 §2).
    #[serde(default)]
    pub same_seq_marks_manufactured: u64,
    /// KI#65 — provisional marks cleared by a seq advance (cumulative).
    #[serde(default)]
    pub same_seq_marks_cleared: u64,
    /// KI#65 — provisional marks currently active (gauge).
    #[serde(default)]
    pub same_seq_marks_active: u64,
    /// YPX-025 ATRAXI — (wallet, state) keys currently HELD (gauge).
    #[serde(default)]
    pub atraxi_open_keys: u64,
    /// YPX-025 ATRAXI — claims opened / operations refused because HELD (cumulative).
    #[serde(default)]
    pub atraxi_claims_opened: u64,
    #[serde(default)]
    pub atraxi_held_refusals: u64,
    /// YPX-022 §2.1.2a (KI#205) — cheque claims refused
    /// `CLAIM_UNAUTHENTICATED` (bad claimant signature, address not bound to
    /// the key, or key ≠ this node's registered head), local TCP path + gossip
    /// receive arm, cumulative. RULE 3 §2: without this, "0 refusals" and
    /// "the check never ran" read identically.
    #[serde(default)]
    pub claims_unauthenticated: u64,
    /// YPX-022 §2.1.2a (KI#205) — recalls refused `CLAIMED` because the
    /// addressed receiver's authenticated claim was live (cumulative).
    /// Non-zero is the double-settlement being STOPPED, not an error.
    #[serde(default)]
    pub recalls_refused_claimed: u64,
    /// ForkSettlement wave 2a (§2.3 [R17], [R‑MEDIUM-3]) — carried legs
    /// refused because the preimage did not reproduce the k-signed
    /// commitment/txid (or disagreed with the message's pk / parent / seq, or
    /// the register lacked a witness-sig quorum): register door step 5b′ +
    /// StateUpdate flood + anti-entropy, cumulative. RULE 3 §2.
    pub leg_preimage_refused: u64,
    /// KI#224 (owner ruling 2026-10-02) — carried witness proofs NOT counted
    /// as attesting a head because a witness key is not in this node's R42
    /// directory: register door 5b⁗ refusals + flood + head-AE, cumulative.
    /// Non-zero while the directory fills (fresh / wiped node) is expected —
    /// the head is re-offered; growth on a full directory is junk-witness
    /// traffic being stopped. RULE 3 §2.
    pub witness_not_in_directory_refused: u64,
    /// KI#251 — registrations whose DECLARED §15 state did not reproduce the
    /// receipt's k-signed `state_hash` at the door's stake-lock recompute,
    /// passed un-judged (non-fatal this rotation). Expected 0 from honest
    /// clients; one soak at 0 promotes the recompute to a refusal. RULE 3 §2.
    pub declared_state_unanchored: u64,
    /// KI#248 (owner ruling 2026-10-02) — WAL reads that REFUSED an entry
    /// with no checksum (a torn tail; no legacy WAL exists pre-mainnet):
    /// not replayed, replay `clean = false`. Per read (audits re-read).
    pub wal_checksum_missing_refused: u64,
    /// Snapshot files this process REFUSED to load (undecodable — the
    /// persisted-shape hazard of rotation #14), cumulative since start. A
    /// refused snapshot falls back to WAL replay / clean + anti-entropy, which
    /// is survivable but LOSES every snapshot-only fact; non-zero here is the
    /// signal that a restart did that. RULE 6: "0" and "never looked" differ.
    pub snapshot_decode_refused: u64,
    /// ForkSettlement wave 4a (R42) — certificates REFUSED admission to the
    /// witness directory (registration or AE adopt: oversize chain, not a VBC,
    /// provisional, unstamped, unbound stamp, unverifiable), cumulative.
    pub vbc_directory_refused: u64,
    /// ValidatorJoin §6b.13 (KI#225) — certificates REFUSED a stamp because the
    /// stake wallet's registered head carried no stake floor reaching the
    /// certificate's expiry (§6b.4 check 5), cumulative. RULE 3 §2.
    pub vbc_stamp_refused_no_floor: u64,
    /// ForkSettlement §9r F-1(c) (KI#244) — certificates REFUSED a stamp
    /// because the stake wallet's registered head is HELD by this node's
    /// provenance (ATRAXI A5), cumulative. RULE 3 §2.
    pub vbc_stamp_refused_held: u64,
    /// …answered `WAIT` (no provenance verdict for the head yet; retryable),
    /// cumulative.
    pub vbc_stamp_refused_wait: u64,
    /// ForkSettlement wave 4a — `vbc_registrations.cbor` files refused at boot
    /// (pre-4a shape or corrupt; the directory then starts EMPTY). Non-zero
    /// after a retain rotation is EXPECTED once and means validators must
    /// re-register; "0" and "never looked" differ (RULE 6).
    pub vbc_registry_decode_refused: u64,
    /// ForkSettlement wave 4a (R50) — directory AE requests / replies refused
    /// (unknown sender, bad signature, replayed nonce, over budget,
    /// unsolicited, oversize), cumulative.
    pub vbc_directory_ae_refused: u64,
    /// ForkSettlement wave 4a — verified entries in the witness directory now.
    pub vbc_directory_entries: u64,
    /// ForkSettlement wave 3 (§2.3 / §2.4) — the origin ledger, fork detection
    /// / adoption and the attestation vouch. FLATTENED: every field reaches the
    /// JSON top level under its own name. ONE builder (`NablaNode::
    /// origin_status`) feeds both status builders (RULE 1).
    #[serde(flatten)]
    pub origin: OriginStatus,
    pub healthy: bool,
    pub health_issues: Vec<String>,
}

/// GUIDE §5.6a — one peer's observation of OUR source address.
///
/// The unanimity rule is `distinct(observed_ip) > 1 ⇒ disputed`, so seeing the
/// distinct values and their reporters is what makes a demotion diagnosable:
/// "alpha and beta say 172.20.0.61, theta says 60.250.239.116" is actionable;
/// "2 distinct addresses from 3 peers" is not.
#[derive(Debug, Clone, Serialize)]
pub struct AddressObservation {
    pub node_id_hex: String,
    /// Peer's name where known — empty if we have no NBC for them yet.
    pub node_name: String,
    /// The source address THIS peer observed for us, rendered v4 where the
    /// stored IPv6-mapped form permits.
    pub observed_ip: String,
}

/// A mesh peer for the dashboard graph.
#[derive(Debug, Clone, Serialize)]
pub struct PeerEntry {
    pub node_id_hex: String,
    pub node_name: String,
    pub is_genesis: bool,
    /// YPX-014 txid service mode, as advertised by that peer via Hello
    /// gossip (`"hashmap"` or `"bloom"`). Empty for peers running a
    /// pre-2026-05-30 binary that doesn't carry the field. Audit-grade
    /// consumers (UNCLE, regulator clients) gate register/query routing
    /// on this — empty + non-hashmap both mean "not audit-grade for k=5
    /// institutional traffic."
    #[serde(default)]
    pub txid_service: String,
}

/// A bootstrap peer with connection status.
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapPeerEntry {
    pub address: String,
    pub status: String,
    pub status_emoji: String,
    pub last_seen: String,
    pub latency_ms: Option<u64>,
}

/// Health check result (lightweight, for /health endpoint).
#[derive(Debug, Clone, Serialize)]
pub struct HealthCheck {
    pub healthy: bool,
    pub version: String,
    pub tick: u64,
    pub entry_count: usize,
    pub peer_count: usize,
    pub issues: Vec<String>,
}

impl From<&NodeStatusSnapshot> for HealthCheck {
    fn from(s: &NodeStatusSnapshot) -> Self {
        Self {
            healthy: s.healthy,
            version: s.version.clone(),
            tick: s.current_tick,
            entry_count: s.entry_count,
            peer_count: s.mesh_peer_count,
            issues: s.health_issues.clone(),
        }
    }
}

/// Determine health issues from a status snapshot.
pub fn diagnose(status: &mut NodeStatusSnapshot) {
    let mut issues = Vec::new();

    if !status.tardis_active {
        issues.push("TARDIS not initialized".into());
    }
    if !status.mesh_active {
        issues.push("Mesh not initialized".into());
    }
    if status.mesh_active && status.mesh_peer_count == 0 {
        issues.push("No mesh peers connected".into());
    }
    if status.mesh_active && status.mesh_peer_count < status.mesh_target_peers / 2 {
        issues.push(format!(
            "Low peer count: {} / {} target",
            status.mesh_peer_count, status.mesh_target_peers
        ));
    }
    if !status.cc_active {
        issues.push("CC chain not initialized".into());
    }
    // ── TARDIS attachment ──
    //
    // A node with no upstream is an ORPHAN. Per YPX-003 §1.1 and the tier
    // discussion in §1.2.1, Orphan is "the only state that's actually a problem" —
    // it receives no ticks, cannot approve a chain, and its SMT drifts away
    // from the mesh.
    //
    // This check did not exist until 2026-08-01, and its absence is why a mesh
    // with 8 of 10 nodes orphaned and THREE distinct SMT roots reported
    // `healthy: true, issues: []` on every node. KI#46's fix plan called for
    // exactly this ("a convergence gate + health metric so a wedged mesh can
    // never again report healthy"); the gate shipped, the metric did not.
    //
    // Note what was here instead: a check for `tardis_slot == "E"`. E is the
    // ENQUIRY slot — stateless connect/query/disconnect, entirely normal
    // (§1.1). It was flagging the benign state and ignoring the fatal one. It
    // also could never fire: `tardis_slot` is only ever emitted as
    // "Writer" / "D{n}" / "Orphan" (nabla_node.rs), so no node ever reports E.
    if status.tardis_active && !status.has_upstream {
        issues.push(format!(
            "TARDIS ORPHAN — no upstream (slot: {}); receives no ticks and its \
             SMT will diverge",
            status.tardis_slot,
        ));
    }
    // ── KI#79: serve-gate arming ──
    //
    // A node that is not serving registrations is not healthy — flagged
    // IMMEDIATELY, not after a grace window: a normal restart sits unarmed
    // ~2 minutes and watchers already wait for [ARMED] after a roll, while
    // a grace window is exactly the shape that let delta's 8-hour episode
    // read `healthy: true` throughout (same blind-spot class as the orphan
    // check above, and the precedent it documents).
    if !status.anti_rollback_armed {
        issues.push(format!(
            "UNARMED — refusing all registrations ({} consecutive round(s), \
             {} tick(s) so far)",
            status.unarmed_rounds, status.unarmed_ticks,
        ));
    }
    // GUIDE §5.6c lever 5 — the same blind spot as UNARMED: a node whose pool
    // view is incomplete refuses every registration, and must not read
    // `healthy: true` while it does.
    if !status.pool_sync_gate_open {
        issues.push(format!(
            "POOL-SYNC-GATE CLOSED — refusing all registrations until every pool kind \
             has synced (have {}/{}: {})",
            status.pool_synced_kinds.len(),
            crate::types::PoolKind::SERVE_GATE_KINDS.len(),
            status.pool_synced_kinds.join(","),
        ));
    }

    status.healthy = issues.is_empty();
    status.health_issues = issues;
}

// ── Penguin Scoring ──

/// Compute the penguin contribution score.
pub fn penguin_contribution(
    ticks_online: u64,
    writes_approved: u64,
    transactions_served: u64,
    orphans_rescued: u64,
    rotations_survived: u64,
) -> u64 {
    ticks_online / 1000
        + writes_approved * 5 / 1000
        + transactions_served * 10 / 1000
        + orphans_rescued * 50
        + rotations_survived * 100
}

/// Compute the reliability multiplier from 30-day uptime percentage.
pub fn reliability_multiplier(uptime_pct: f64) -> f64 {
    if uptime_pct >= 99.9 { 3.0 }
    else if uptime_pct >= 99.0 { 2.0 }
    else if uptime_pct >= 95.0 { 1.0 }
    else if uptime_pct >= 90.0 { 0.75 }
    else { 0.5 }
}

/// Return (level_name, emoji) for a given score.
pub fn penguin_level(score: u64) -> (&'static str, &'static str) {
    if score >= 500_000      { ("Colony Elder", "\u{1F3D4}\u{FE0F}") }
    else if score >= 100_000 { ("Emperor Penguin", "\u{1F451}") }
    else if score >= 10_000  { ("Ice Runner", "\u{2744}\u{FE0F}") }
    else if score >= 1_000   { ("Penguin", "\u{1F427}") }
    else                     { ("Hatchling", "\u{1F95A}") }
}

/// Format a byte array as hex string (first 8 bytes).
pub fn hex_short(bytes: &[u8; 32]) -> String {
    bytes[..8]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Format uptime from a start timestamp.
pub fn uptime_secs(start: SystemTime) -> u64 {
    start.elapsed().map(|d| d.as_secs()).unwrap_or(0)
}

/// Format a NablaAddress as a display string.
pub fn format_address(addr: &crate::types::NablaAddress) -> String {
    match addr {
        crate::types::NablaAddress::V4 { ip, port } =>
            format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port),
        crate::types::NablaAddress::V6 { ip, port } => {
            let segs: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([ip[i*2], ip[i*2+1]])))
                .collect();
            format!("[{}]:{}", segs.join(":"), port)
        }
        // Show the NAME as advertised — never the address it happens to resolve
        // to here. This string is what an operator reads on /status, and
        // resolving it for display would show one box's view of the peer.
        crate::types::NablaAddress::Name { host, port } => format!("{host}:{port}"),
    }
}

// ── HTTP Response Builders ──

/// Build JSON response body for /api/status or /status.
pub fn json_status(status: &NodeStatusSnapshot) -> String {
    // Dev-only flood chaos (feature `flood-chaos`, src/flood_chaos.rs): its counters and the
    // watched wallets' BanTable evidence ride /status as `flood_chaos` — absent on every other
    // build, which is how a gate tells "not built with it" from "built, suppressed nothing".
    #[cfg(feature = "flood-chaos")]
    {
        if let Ok(serde_json::Value::Object(mut m)) = serde_json::to_value(status) {
            m.insert("flood_chaos".into(), crate::flood_chaos::status_json());
            return serde_json::to_string_pretty(&m).unwrap_or_else(|_| "{}".into());
        }
    }
    serde_json::to_string_pretty(status).unwrap_or_else(|_| "{}".into())
}

/// Build JSON response body for /health.
pub fn json_health(status: &NodeStatusSnapshot) -> String {
    let health: HealthCheck = status.into();
    serde_json::to_string_pretty(&health).unwrap_or_else(|_| "{}".into())
}

/// Build HTML dashboard page — single-page app with D3 network graph,
/// cockpit bar, stats cards, and auto-refresh via fetch().
pub fn html_dashboard(_status: &NodeStatusSnapshot) -> String {
    // The dashboard is fully client-side: the HTML is static, and JS
    // fetches /status every 2 seconds for live updates.
    //
    // `{{ATOMS_PER_AXC}}` is substituted from `axiom_denomination::ATOMS_PER_AXC`
    // — the workspace's single source of truth for the AXC↔atom divisor.
    // If the served HTML still shows the raw placeholder, the nabla
    // binary's dependency on the denomination crate has been severed
    // — CONSOLIDATION REGRESSION, not a UI bug.
    DASHBOARD_HTML.replace(
        "{{ATOMS_PER_AXC}}",
        &axiom_denomination::ATOMS_PER_AXC.to_string(),
    )
}

/// Format seconds into human-readable uptime.
#[cfg(test)]
fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m {}s", mins, secs % 60)
    }
}

/// Monitor configuration.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Port to listen on.
    pub port: u16,
    /// Bind address (default: 127.0.0.1).
    pub bind_addr: String,
    /// Optional auth token (if set, requires ?token=xxx on all endpoints).
    pub auth_token: Option<String>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_MONITOR_PORT,
            bind_addr: "127.0.0.1".into(),
            auth_token: None,
        }
    }
}

/// Route an HTTP request to the appropriate handler.
///
/// Returns (status_code, content_type, body).
pub fn route_request(
    path: &str,
    query: Option<&str>,
    status: &NodeStatusSnapshot,
    config: &MonitorConfig,
) -> (u16, &'static str, String) {
    // Auth check
    if let Some(ref token) = config.auth_token {
        let provided = query
            .and_then(|q| {
                q.split('&')
                    .find(|p| p.starts_with("token="))
                    .map(|p| &p[6..])
            });
        match provided {
            Some(t) if t == token => {} // OK
            _ => return (401, "text/plain", "Unauthorized".into()),
        }
    }

    match path {
        "/" => (200, "text/html; charset=utf-8", html_dashboard(status)),
        "/status" => (200, "application/json", json_status(status)),
        "/health" => {
            let code = if status.healthy { 200 } else { 503 };
            (code, "application/json", json_health(status))
        }
        "/api/status" => (200, "application/json", json_status(status)),
        "/genesis" => (200, "application/json", json_genesis()),
        _ => (404, "text/plain", "Not Found".into()),
    }
}

/// GET /genesis — public endpoint, no auth required.
/// Returns FACT #0 with headlines, sub-pools, and genesis hash.
fn json_genesis() -> String {
    use axiom_core_logic::genesis_integrity::{build_genesis_fact, compute_genesis_fact_hash, GENESIS_POOL_TOTAL};

    let fact = build_genesis_fact(1); // tick=1 for genesis
    let hash = compute_genesis_fact_hash(&fact);

    serde_json::json!({
        "fact_id": 0,
        "pool_total": GENESIS_POOL_TOTAL,
        "genesis_date": axiom_core_logic::genesis_integrity::GENESIS_DATE,
        "genesis_fact_hash": hex::encode(hash),
        "sub_pools": fact.sub_pools.iter().map(|p| {
            serde_json::json!({
                "pool_id": format!("{:?}", p.pool_id),
                "initial_balance": p.initial_balance,
            })
        }).collect::<Vec<_>>(),
        "headlines": fact.headlines.iter().map(|h| {
            serde_json::json!({
                "country": h.country,
                "organisation": h.organisation,
                "timestamp": h.timestamp,
                "headline": h.headline,
            })
        }).collect::<Vec<_>>(),
        "signed": !fact.core_signature.is_empty(),
    }).to_string()
}

// ══════════════════════════════════════════════════════════════════════
// Dashboard HTML — single-page app with embedded JS/CSS
// ══════════════════════════════════════════════════════════════════════

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AXIOM Nabla — Operator Dashboard</title>
<style>
:root {
  --bg: #0a0e17; --bg2: #111827; --bg3: #141b2d;
  --border: #1e2a3a; --text: #c8d6e5; --dim: #78909c;
  --gold: #f5a623; --green: #2ecc71; --yellow: #f39c12;
  --red: #e74c3c; --blue: #3498db; --purple: #9b59b6;
  --cyan: #00d2d3;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'SF Mono', 'Fira Code', -apple-system, BlinkMacSystemFont, 'Noto Sans CJK SC', 'Noto Sans CJK TC', 'Noto Sans CJK JP', monospace;
       background: var(--bg); color: var(--text); overflow-x: hidden; }

/* ── Cockpit Bar ── */
.cockpit { position: fixed; top: 0; left: 0; right: 0; z-index: 100;
  background: linear-gradient(180deg, #111827 0%, #0d1117 100%);
  border-bottom: 1px solid var(--border); padding: 8px 16px;
  display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
  min-height: 48px; }
.cockpit .logo { color: var(--gold); font-size: 1.1em; font-weight: 700;
  white-space: nowrap; }
.cockpit .sep { color: #333; }
.chip { display: inline-flex; align-items: center; gap: 4px;
  background: #1a1f2e; border: 1px solid var(--border); border-radius: 12px;
  padding: 2px 10px; font-size: 0.72em; white-space: nowrap; }
.chip .label { color: var(--dim); }
.chip .val { color: #e8e8e8; font-weight: 600; }
.chip .val.gold { color: var(--gold); }
.chip .val.green { color: var(--green); }
.chip .val.red { color: var(--red); }
.chip .val.cyan { color: var(--cyan); }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 2px; }
.dot.green { background: var(--green); box-shadow: 0 0 6px var(--green); }
.dot.yellow { background: var(--yellow); }
.dot.red { background: var(--red); }

/* ── Main Content ── */
.main { padding: 60px 16px 16px 16px; max-width: 1400px; margin: 0 auto; }

/* ── Network Graph ── */
.graph-container { background: var(--bg3); border: 1px solid var(--border);
  border-radius: 12px; margin-bottom: 16px; position: relative;
  overflow: hidden; }
.graph-container svg { width: 100%; display: block; }
.graph-title { position: absolute; top: 8px; left: 12px; color: var(--dim);
  font-size: 0.7em; text-transform: uppercase; letter-spacing: 2px;
  pointer-events: none; }
.graph-legend { position: absolute; bottom: 8px; right: 12px;
  font-size: 0.6em; color: var(--dim); pointer-events: none; }
.node-popup { position: absolute; background: #1a2030; border: 1px solid var(--gold);
  border-radius: 8px; padding: 10px 14px; font-size: 0.72em;
  color: var(--text); pointer-events: none; z-index: 10;
  box-shadow: 0 4px 20px rgba(0,0,0,0.5); display: none; }
.node-popup .pp-id { color: var(--gold); font-weight: 700; }
.node-popup .pp-row { margin-top: 2px; }

/* ── Stats Cards ── */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 12px; margin-bottom: 16px; }
.card { background: var(--bg3); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px; }
.card-title { color: var(--dim); font-size: 0.7em; text-transform: uppercase;
  letter-spacing: 2px; margin-bottom: 10px; display: flex;
  align-items: center; gap: 6px; }
.card-title .icon { font-size: 1.1em; }
.stat-row { display: flex; justify-content: space-between; align-items: baseline;
  padding: 3px 0; border-bottom: 1px solid #1a2030; }
.stat-row:last-child { border-bottom: none; }
.stat-label { color: var(--dim); font-size: 0.75em; }
.stat-value { color: #e8e8e8; font-weight: 600; font-size: 0.85em; }
.stat-value.gold { color: var(--gold); }
.stat-value.green { color: var(--green); }
.stat-value.cyan { color: var(--cyan); }
.stat-value.yellow { color: var(--yellow); }
.stat-value.red { color: var(--red); }
.sparkline { margin-top: 8px; height: 30px; }
.sparkline svg { width: 100%; height: 30px; }

/* ── Technical Details ── */
.details-toggle { background: none; border: 1px solid var(--border);
  color: var(--dim); padding: 6px 14px; border-radius: 6px;
  cursor: pointer; font-family: inherit; font-size: 0.72em;
  letter-spacing: 1px; text-transform: uppercase; margin-bottom: 8px; }
.details-toggle:hover { border-color: var(--gold); color: var(--gold); }
.details-panel { display: none; background: var(--bg3); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px; margin-bottom: 16px; }
.details-panel.open { display: block; }
.detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 8px; }
.detail-row { display: flex; justify-content: space-between; padding: 3px 0;
  font-size: 0.72em; }
.detail-label { color: var(--dim); }
.detail-value { color: var(--text); font-weight: 500; }

/* ── Bootstrap Peers ── */
.bp-table { width: 100%; border-collapse: collapse; font-size: 0.75em; }
.bp-table th { text-align: left; color: var(--dim); font-weight: 500;
  padding: 4px 8px; border-bottom: 1px solid var(--border);
  text-transform: uppercase; font-size: 0.85em; letter-spacing: 1px; }
.bp-table td { padding: 5px 8px; border-bottom: 1px solid #1a2030; }
.bp-table tr:last-child td { border-bottom: none; }
.bp-addr { color: var(--text); font-weight: 500; }
.bp-latency { color: var(--dim); }

/* ── Footer ── */
.footer { text-align: center; color: #333; font-size: 0.65em; padding: 16px 0; }
.footer a { color: #444; }

/* ── Mobile ── */
@media (max-width: 768px) {
  .cockpit { gap: 6px; padding: 6px 10px; }
  .chip { font-size: 0.65em; padding: 2px 6px; }
  .cards { grid-template-columns: 1fr; }
  .main { padding: 56px 8px 8px 8px; }
  .detail-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>

<!-- Cockpit Bar -->
<div class="cockpit">
  <span class="logo">&#x2207; AXIOM Nabla</span>
  <span class="sep">|</span>
  <span class="chip"><span id="ck-emoji"></span><span class="val gold" id="ck-level">--</span></span>
  <span class="chip"><span class="label">Score</span><span class="val gold" id="ck-score">0</span></span>
  <span class="chip"><span class="label">Uptime</span><span class="val green" id="ck-uptime">--</span></span>
  <span class="chip"><span class="label">AXC</span><span class="val cyan" id="ck-axc">0</span></span>
  <span class="chip"><span class="val gold" id="ck-name">--</span></span>
  <span class="chip"><span class="label">ID</span><span class="val" id="ck-id">--</span></span>
  <span class="chip"><span class="label">Addr</span><span class="val" id="ck-addr">--</span></span>
  <span class="chip"><span class="label">Settlement</span><span class="val" id="ck-txid-mode">--</span></span>
  <span class="chip"><span id="ck-role-dot" class="dot green"></span><span class="val" id="ck-role">--</span></span>
  <span class="chip"><span class="label">Tick</span><span class="val" id="ck-tick">0</span></span>
</div>

<div class="main">

<!-- Network Graph -->
<div class="graph-container">
  <div class="graph-title">Network Topology</div>
  <svg id="graph" viewBox="0 0 900 400"></svg>
  <div class="graph-legend">
    &#x25C6; genesis &nbsp; &#x25CF; peer &nbsp;
    <span style="color:var(--gold)">&#x2B24;</span> me &nbsp;
    <span style="color:var(--green)">&#x25CF;</span> healthy &nbsp;
    <span style="color:var(--yellow)">&#x25CF;</span> stale &nbsp;
    <span style="color:var(--red)">&#x25CF;</span> lost
  </div>
  <div class="node-popup" id="popup">
    <div class="pp-id" id="pp-id">--</div>
    <div class="pp-row" id="pp-role">--</div>
    <div class="pp-row" id="pp-detail">--</div>
    <div class="pp-row" id="pp-txid">--</div>
  </div>
</div>

<!-- Stats Cards -->
<div class="cards">
  <!-- Card 1: Transactions -->
  <div class="card">
    <div class="card-title"><span class="icon">&#x1F4CA;</span> Transactions</div>
    <div class="stat-row"><span class="stat-label">Total Served</span><span class="stat-value" id="s-tx-total">0</span></div>
    <div class="stat-row"><span class="stat-label">Ticks Helped</span><span class="stat-value" id="s-tx-helped">0</span></div>
    <div class="stat-row"><span class="stat-label">Entries (SMT)</span><span class="stat-value" id="s-tx-entries">0</span></div>
    <div class="stat-row"><span class="stat-label">Root Hash</span><span class="stat-value" id="s-tx-hash" style="font-size:0.65em">--</span></div>
    <div class="sparkline"><svg id="spark-tx" viewBox="0 0 280 30"></svg></div>
  </div>

  <!-- Card 2: Earnings -->
  <div class="card">
    <div class="card-title"><span class="icon">&#x1F4B0;</span> Earnings</div>
    <div class="stat-row"><span class="stat-label">AXC Accumulated</span><span class="stat-value cyan" id="s-earn-total">0</span></div>
    <div class="stat-row"><span class="stat-label">DEED Collected</span><span class="stat-value" id="s-earn-deed">0</span></div>
    <div class="stat-row"><span class="stat-label">Fee Split</span><span class="stat-value" id="s-earn-split">--</span></div>
    <div class="sparkline"><svg id="spark-earn" viewBox="0 0 280 30"></svg></div>
  </div>

  <!-- Card 2b: Protocol Pools -->
  <div class="card">
    <div class="card-title"><span class="icon">&#x1F3E6;</span> Protocol Pools</div>
    <div class="stat-row"><span class="stat-label">Runner</span><span class="stat-value" id="s-earn-pool">0</span></div>
    <div class="stat-row"><span class="stat-label">Airdrop</span><span class="stat-value cyan" id="s-airdrop-balance">--</span></div>
    <div class="stat-row"><span class="stat-label">Claims Processed</span><span class="stat-value" id="s-airdrop-claims">0</span></div>
    <div class="stat-row"><span class="stat-label">Dev Treasury</span><span class="stat-value cyan" id="s-dev-balance" title="1M dev-AXC pool — outside the 100M public cap, funds @axiom.internal genesis claims">--</span></div>
    <div class="stat-row"><span class="stat-label">Dev Claims Processed</span><span class="stat-value" id="s-dev-claims" title="local / network total">0</span></div>
    <div class="stat-row"><span class="stat-label">DEED Pool</span><span class="stat-value cyan" id="s-deed-pool-balance" title="10% of every receiver-pays validator fee, collected for the first 10 years from GENESIS_NEWS_ANCHOR. See AXIOM_DESIGN_DeedDistribution.md.">--</span></div>
    <div class="stat-row"><span class="stat-label">DEED Lifetime</span><span class="stat-value" id="s-deed-pool-total" title="Cumulative atoms ever credited to the DEED pool — informational; balance can only grow during Phase 1, never decrease.">--</span></div>
    <!-- Dev-class DEED Pool — observability for @axiom.internal traffic.
         Visually nested under the public DEED rows with dim color so
         operators see what's collecting from test wallets without
         confusing it with real DEED. NEVER convertible to public AXC
         (newtype-distinct from DeedPool — see nabla/src/node.rs LEAK
         BOUNDARY + AXIOM_DESIGN_FactClassIsolation.md). -->
    <div class="stat-row" style="border-left:2px solid var(--c-dim); padding-left:6px; opacity:0.75;"><span class="stat-label" style="font-size:11px;">Dev DEED Pool</span><span class="stat-value" id="s-dev-deed-pool-balance" style="font-size:11px;" title="10% slice from @axiom.internal TXs only. Observability only — cannot mint public AXC. See AXIOM_DESIGN_FactClassIsolation.md.">--</span></div>
    <div class="stat-row" style="border-left:2px solid var(--c-dim); padding-left:6px; opacity:0.75;"><span class="stat-label" style="font-size:11px;">Dev DEED Lifetime</span><span class="stat-value" id="s-dev-deed-pool-total" style="font-size:11px;" title="Cumulative dev-AXC ever credited to the dev DEED pool — testnet only.">--</span></div>
  </div>

  <!-- Card 3: Health -->
  <div class="card">
    <div class="card-title"><span class="icon">&#x1F3E5;</span> Health</div>
    <div class="stat-row"><span class="stat-label">Uptime</span><span class="stat-value green" id="s-hp-uptime">--</span></div>
    <div class="stat-row"><span class="stat-label">Writes Approved</span><span class="stat-value" id="s-hp-writes">0</span></div>
    <div class="stat-row"><span class="stat-label">Orphans Rescued</span><span class="stat-value" id="s-hp-orphans">0</span></div>
    <div class="stat-row"><span class="stat-label">Rotations Survived</span><span class="stat-value" id="s-hp-rotations">0</span></div>
    <div class="stat-row"><span class="stat-label">Mesh Peers</span><span class="stat-value" id="s-hp-peers">0</span></div>
    <div class="stat-row"><span class="stat-label">Known Nodes</span><span class="stat-value" id="s-hp-known">0</span></div>
    <div class="stat-row"><span class="stat-label" title="OODS-gossip (YPX-021): the size of the Nabla NETWORK — OODS Extrema-Propagation estimate over this node's verified-NBC mesh view. Forgery-resistant. Watch it drop under a partition/eclipse.">Nabla network size (OODS-gossip)</span><span class="stat-value cyan" id="s-hp-oods">0</span></div>
    <div class="stat-row"><span class="stat-label" title="TARDIS depth (YPX-021 §6): this node's DEPTH in the tick tree — OODS estimate over the tick's down-cascade accumulator = the count of verified writers in its lineage from the root. NOT a network-size count. A snapshot can be inherited by attaching under a chain; SUSTAINED depth = durable integration under a long verified writer-chain. Collapses to ~0 when the node orphans/partitions. Future use: a hard-to-forge tiebreaker for gossip conflicts.">TARDIS depth</span><span class="stat-value cyan" id="s-hp-oods-tardis">0</span></div>
  </div>

  <!-- Card 4: Storage -->
  <div class="card">
    <div class="card-title"><span class="icon">&#x1F4BE;</span> Storage</div>
    <div class="stat-row"><span class="stat-label">SMT Entries</span><span class="stat-value" id="s-st-entries">0</span></div>
    <div class="stat-row"><span class="stat-label">SMT Memory</span><span class="stat-value" id="s-st-smtmem">0</span></div>
    <div class="stat-row"><span class="stat-label">Txid Bloom</span><span class="stat-value" id="s-st-bloom">--</span></div>
    <div class="stat-row"><span class="stat-label">Txid Hashmap</span><span class="stat-value" id="s-st-hashmap">--</span></div>
    <div class="stat-row"><span class="stat-label">WAL Size</span><span class="stat-value" id="s-st-wal">0</span></div>
    <div class="stat-row"><span class="stat-label">WAL Ops</span><span class="stat-value" id="s-st-walops">0</span></div>
    <div class="stat-row"><span class="stat-label">Snapshots</span><span class="stat-value" id="s-st-snaps">0</span></div>
    <div class="stat-row"><span class="stat-label">Snapshot Size</span><span class="stat-value" id="s-st-snapsize">0</span></div>
    <div class="stat-row"><span class="stat-label">Last Snapshot</span><span class="stat-value" id="s-st-lastsnap">0</span></div>
    <div class="stat-row"><span class="stat-label">Total Disk</span><span class="stat-value cyan" id="s-st-disk">0</span></div>
  </div>
</div>

<!-- Bootstrap Peers -->
<button class="details-toggle" id="btn-bootstrap" onclick="toggleBootstrap()">&#x25B6; Bootstrap Peers <span id="bp-summary" style="font-size:0.85em;color:#78909c"></span></button>
<div class="details-panel" id="bootstrap-panel">
  <table class="bp-table">
    <thead><tr><th>Address</th><th>Status</th><th>Last Seen</th><th>Latency</th></tr></thead>
    <tbody id="bp-body"></tbody>
  </table>
</div>

<!-- Technical Details -->
<button class="details-toggle" id="btn-details" onclick="toggleDetails()">&#x25B6; Technical Details</button>
<div class="details-panel" id="details-panel">
  <div class="detail-grid">
    <div>
      <div class="detail-row"><span class="detail-label">NBC Status</span><span class="detail-value" id="d-nbc">--</span></div>
      <div class="detail-row"><span class="detail-label">CC Tick</span><span class="detail-value" id="d-cc-tick">0</span></div>
      <div class="detail-row"><span class="detail-label">CC Score</span><span class="detail-value" id="d-cc-score">0</span></div>
      <div class="detail-row"><span class="detail-label">TARDIS Slot</span><span class="detail-value" id="d-tardis-slot">--</span></div>
      <div class="detail-row"><span class="detail-label">Downstream</span><span class="detail-value" id="d-downstream">0</span></div>
    </div>
    <div>
      <div class="detail-row"><span class="detail-label">Network Size (est.)</span><span class="detail-value" id="d-net-size">0</span></div>
      <div class="detail-row"><span class="detail-label">Gossip Seen</span><span class="detail-value" id="d-gossip-seen">0</span></div>
      <div class="detail-row"><span class="detail-label">Bans Active</span><span class="detail-value" id="d-bans">0</span></div>
      <div class="detail-row"><span class="detail-label">Reliability</span><span class="detail-value" id="d-reliability">--</span></div>
      <div class="detail-row"><span class="detail-label">Version</span><span class="detail-value" id="d-version">--</span></div>
    </div>
  </div>
  <div style="margin-top:10px;font-size:0.65em;color:#555">
    <span id="d-issues"></span>
  </div>
</div>

<div class="footer">
  AXIOM Nabla Operator Dashboard &middot; Auto-refresh 2s &middot;
  <a href="/health">Health</a> &middot; <a href="/status">JSON</a>
</div>

</div><!-- /main -->

<script>
// ── State ──
let txHistory = [];
let earnHistory = [];
let prevTxTotal = null;

function formatUptime(s) {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
  if (h > 0) return h + 'h ' + m + 'm';
  return m + 'm ' + (s % 60) + 's';
}

function fmtNum(n) {
  if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
  return String(n);
}

// Substituted at serve time from `axiom_denomination::ATOMS_PER_AXC`
// (see `html_dashboard` above). Single source of truth for the
// AXC↔atom divisor — never hand-mirror this literal.
const ATOMS_PER_AXC = {{ATOMS_PER_AXC}}n;
// BigInt-based AXC formatter: keeps full precision down to the atom,
// trims trailing zeros so display stays compact. Same approach the
// per-validator dashboard (console/src/static/index.html:587) uses —
// 60,000 atoms renders as "0.000006 AXC" instead of rounding to
// "0.0000 AXC" with a lossy toFixed(4).
function fmtAxc(atoms) {
  const a = BigInt(atoms || 0);
  const whole = a / ATOMS_PER_AXC;
  const frac  = a - whole * ATOMS_PER_AXC;
  const wholeStr = whole.toLocaleString();
  if (frac === 0n) return wholeStr + ' AXC';
  const fracStr = frac.toString().padStart(10, '0').replace(/0+$/, '');
  return wholeStr + '.' + fracStr + ' AXC';
}

function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(1) + ' GB';
}

function shortId(hex) {
  if (!hex || hex.length < 8) return hex || '--';
  return hex.substring(0, 8) + '..';
}

// ── Sparkline ──
function drawSparkline(svgId, data, color) {
  const svg = document.getElementById(svgId);
  if (!svg || data.length < 2) return;
  const w = 280, h = 30;
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - (v / max) * (h - 4) - 2;
    return x + ',' + y;
  });
  svg.innerHTML =
    '<polyline points="' + pts.join(' ') + '" fill="none" stroke="' + color +
    '" stroke-width="1.5" opacity="0.8"/>' +
    '<circle cx="' + (w) + '" cy="' + (h - (data[data.length-1] / max) * (h-4) - 2) +
    '" r="2" fill="' + color + '"/>';
}

// ── Network Graph ──
function renderGraph(st) {
  const svg = document.getElementById('graph');
  const W = 900, H = 400;
  const cx = W / 2, cy = H / 2;
  let html = '';

  // Build node list: me, upstream, d1, d2, peers
  const nodes = [];
  const myId = st.node_id_hex;

  // Me (center)
  nodes.push({ id: myId, name: st.node_name, x: cx, y: cy, role: 'me', genesis: false });

  // Parent (above)
  if (st.upstream_hex && st.upstream_hex.length > 1) {
    nodes.push({ id: st.upstream_hex, name: st.upstream_name, x: cx, y: cy - 100, role: 'parent', genesis: false });
  }

  // Children (below)
  if (st.d1_hex && st.d1_hex.length > 1) {
    nodes.push({ id: st.d1_hex, name: st.d1_name, x: cx - 80, y: cy + 100, role: 'd1', genesis: false });
  }
  if (st.d2_hex && st.d2_hex.length > 1) {
    nodes.push({ id: st.d2_hex, name: st.d2_name, x: cx + 80, y: cy + 100, role: 'd2', genesis: false });
  }

  // Known peers in orbit ring
  const treeIds = new Set(nodes.map(n => n.id));
  const peers = (st.peer_list || []).filter(p => !treeIds.has(p.node_id_hex));
  const peerCount = peers.length;
  const ringR = 160;
  peers.forEach((p, i) => {
    const angle = (i / Math.max(peerCount, 1)) * Math.PI * 2 - Math.PI / 2;
    nodes.push({
      id: p.node_id_hex,
      name: p.node_name,
      x: cx + Math.cos(angle) * ringR,
      y: cy + Math.sin(angle) * ringR,
      role: 'peer',
      genesis: p.is_genesis
    });
  });

  // Draw links
  const drawLink = (ax, ay, bx, by, color, label) => {
    html += '<line x1="'+ax+'" y1="'+ay+'" x2="'+bx+'" y2="'+by+
      '" stroke="'+color+'" stroke-width="1.5" opacity="0.5"/>';
    // Animated particle (random duration + delay so dots desync)
    const mx = (ax + bx) / 2, my = (ay + by) / 2;
    const dur = (0.6 + Math.random() * 0.9).toFixed(2);
    const delay = (Math.random() * 0.1).toFixed(2);
    html += '<circle r="2" fill="'+color+'" opacity="0.8">'+
      '<animateMotion dur="'+dur+'s" begin="'+delay+'s" repeatCount="indefinite" path="M'+ax+','+ay+' L'+bx+','+by+'"/></circle>';
    if (label) {
      html += '<text x="'+mx+'" y="'+(my-5)+'" fill="'+color+
        '" font-size="8" text-anchor="middle" opacity="0.7">'+label+'</text>';
    }
  };

  // TARDIS links
  if (st.upstream_hex && st.upstream_hex.length > 1) {
    drawLink(cx, cy - 100, cx, cy, '#3498db', 'tick');
    // Red dot: ME → Parent (approval sent upstream after collecting child approvals)
    // Leaf nodes (no children) always approve; writers approve when both children approved
    const meApproved = st.downstream_count === 0
      || (st.d1_approved && st.d2_approved);
    if (meApproved) {
      drawLink(cx, cy, cx, cy - 100, '#e74c3c', 'sig');
    }
  }
  if (st.d1_hex && st.d1_hex.length > 1) {
    const approved = st.downstream_count >= 1;
    drawLink(cx, cy, cx - 80, cy + 100, approved ? '#2ecc71' : '#f39c12',
      approved ? 'approved' : 'pending');
    // Red dot: D1 → ME (child sent approval/signature back)
    if (st.d1_approved) {
      drawLink(cx - 80, cy + 100, cx, cy, '#e74c3c', 'sig');
    }
  }
  if (st.d2_hex && st.d2_hex.length > 1) {
    const approved = st.downstream_count >= 2;
    drawLink(cx, cy, cx + 80, cy + 100, approved ? '#2ecc71' : '#f39c12',
      approved ? 'approved' : 'pending');
    // Red dot: D2 → ME (child sent approval/signature back)
    if (st.d2_approved) {
      drawLink(cx + 80, cy + 100, cx, cy, '#e74c3c', 'sig');
    }
  }

  // Mesh links (faint)
  peers.forEach((p, i) => {
    const angle = (i / Math.max(peerCount, 1)) * Math.PI * 2 - Math.PI / 2;
    const px = cx + Math.cos(angle) * ringR;
    const py = cy + Math.sin(angle) * ringR;
    html += '<line x1="'+cx+'" y1="'+cy+'" x2="'+px+'" y2="'+py+
      '" stroke="#ffffff" stroke-width="0.5" opacity="0.08"/>';
  });

  // Draw nodes
  nodes.forEach(n => {
    const r = n.role === 'me' ? 14 : 8;
    const color = n.role === 'me' ? '#f5a623' :
                  n.role === 'parent' ? '#3498db' :
                  (n.role === 'd1' || n.role === 'd2') ? '#2ecc71' :
                  n.genesis ? '#9b59b6' : '#78909c';

    const dn = n.name ? ' data-name="'+n.name+'"' : '';
    if (n.genesis) {
      // Diamond shape for genesis
      const s = r;
      html += '<polygon points="'+(n.x)+','+(n.y-s)+' '+(n.x+s)+','+(n.y)+
        ' '+(n.x)+','+(n.y+s)+' '+(n.x-s)+','+(n.y)+
        '" fill="'+color+'" opacity="0.9" stroke="#fff" stroke-width="0.5"' +
        ' data-id="'+n.id+'" data-role="'+n.role+'"'+dn+' class="gnode" style="cursor:pointer"/>';
    } else if (n.role === 'me') {
      // Gold circle with glow
      html += '<circle cx="'+n.x+'" cy="'+n.y+'" r="'+(r+4)+'" fill="none" stroke="'+color+
        '" stroke-width="1" opacity="0.3"/>';
      html += '<circle cx="'+n.x+'" cy="'+n.y+'" r="'+r+'" fill="'+color+
        '" opacity="0.95" stroke="#fff" stroke-width="1"' +
        ' data-id="'+n.id+'" data-role="'+n.role+'"'+dn+' class="gnode" style="cursor:pointer"/>';
      const meLabel = st.node_name || 'ME';
      html += '<text x="'+n.x+'" y="'+(n.y+3)+'" fill="#0a0e17" font-size="10"' +
        ' text-anchor="middle" font-weight="700">'+meLabel+'</text>';
    } else {
      html += '<circle cx="'+n.x+'" cy="'+n.y+'" r="'+r+'" fill="'+color+
        '" opacity="0.85" stroke="#fff" stroke-width="0.5"' +
        ' data-id="'+n.id+'" data-role="'+n.role+'"'+dn+' class="gnode" style="cursor:pointer"/>';
    }
    // Label
    if (n.role !== 'me') {
      const lbl = n.name || shortId(n.id);
      html += '<text x="'+n.x+'" y="'+(n.y + r + 11)+'" fill="'+color+
        '" font-size="7" text-anchor="middle" opacity="0.7">'+lbl+'</text>';
    }
  });

  svg.innerHTML = html;

  // Click handler for popup
  const popup = document.getElementById('popup');
  svg.querySelectorAll('.gnode').forEach(el => {
    el.addEventListener('click', e => {
      const id = el.getAttribute('data-id');
      const role = el.getAttribute('data-role');
      const peerName = el.getAttribute('data-name');
      const shortHex = id ? (id.substring(0, 8) + '…') : '--';
      document.getElementById('pp-id').textContent = peerName ? (peerName + ' — ' + shortHex) : shortHex;
      document.getElementById('pp-role').textContent = 'Role: ' + role;
      const labels = { me: 'This node', parent: 'TARDIS parent',
        d1: 'Downstream 1', d2: 'Downstream 2', peer: 'Mesh peer' };
      document.getElementById('pp-detail').textContent = labels[role] || role;
      // YPX-014 txid service mode for the clicked node. For 'me' it's
      // on the top-level status; for everyone else look it up in
      // peer_list by node_id_hex.
      let mode = '';
      if (role === 'me') {
        mode = st.txid_service || '';
      } else {
        const row = (st.peer_list || []).find(p => p.node_id_hex === id);
        mode = row ? (row.txid_service || '') : '';
      }
      document.getElementById('pp-txid').textContent = 'Settlement: ' + (mode || '(unknown)');
      popup.style.display = 'block';
      const rect = svg.getBoundingClientRect();
      const svgW = rect.width, svgH = rect.height;
      const viewBox = svg.viewBox.baseVal;
      const scaleX = svgW / viewBox.width;
      const scaleY = svgH / viewBox.height;
      const bx = parseFloat(el.getAttribute('cx') || el.getBBox().x + el.getBBox().width/2);
      const by = parseFloat(el.getAttribute('cy') || el.getBBox().y);
      popup.style.left = (bx * scaleX + 10) + 'px';
      popup.style.top = (by * scaleY - 10) + 'px';
      setTimeout(() => { popup.style.display = 'none'; }, 3000);
    });
  });
}

// ── Toggle panels ──
function toggleBootstrap() {
  const p = document.getElementById('bootstrap-panel');
  const b = document.getElementById('btn-bootstrap');
  const open = p.classList.toggle('open');
  const summary = document.getElementById('bp-summary').outerHTML;
  b.innerHTML = (open ? '&#x25BC;' : '&#x25B6;') + ' Bootstrap Peers ' + summary;
}
function toggleDetails() {
  const p = document.getElementById('details-panel');
  const b = document.getElementById('btn-details');
  const open = p.classList.toggle('open');
  b.innerHTML = (open ? '&#x25BC;' : '&#x25B6;') + ' Technical Details';
}

// ── Update loop ──
function update() {
  fetch('/status')
    .then(r => r.json())
    .then(st => {
      // Cockpit
      document.getElementById('ck-emoji').textContent = st.penguin_emoji || '';
      document.getElementById('ck-level').textContent = st.penguin_level || '--';
      document.getElementById('ck-score').textContent = fmtNum(st.penguin_score || 0);
      const streak = st.uptime_streak_days || 0;
      document.getElementById('ck-uptime').textContent =
        formatUptime(st.uptime_secs || 0) + (streak > 0 ? ' \uD83D\uDD25' + streak + 'd' : '');
      document.getElementById('ck-axc').textContent = fmtNum(st.deed_collected || 0);
      document.getElementById('ck-name').textContent = st.node_name || shortId(st.node_id_hex);
      document.getElementById('ck-id').textContent = shortId(st.node_id_hex);
      document.getElementById('ck-addr').textContent =
        st.wan_addr ? st.listen_addr + ' / WAN ' + st.wan_addr : (st.listen_addr || '--');
      // YPX-014 settlement mode chip — hashmap (audit-grade exact lookups,
      // UNCLE §8.3) or bloom (low memory, probabilistic). Identity-only
      // here; the live entry count lives on the Storage card below.
      const txidEl = document.getElementById('ck-txid-mode');
      const txidMode = st.txid_service || '';
      txidEl.textContent = txidMode || '--';
      txidEl.className = 'val ' + (txidMode === 'hashmap' ? 'green' : txidMode === 'bloom' ? 'cyan' : '');
      const isWriter = st.is_writer;
      document.getElementById('ck-role').textContent = isWriter ? 'WRITER' : 'READER';
      const roleDot = document.getElementById('ck-role-dot');
      roleDot.className = 'dot ' + (st.healthy ? 'green' : 'red');
      document.getElementById('ck-tick').textContent = st.current_tick || 0;

      // Graph
      renderGraph(st);

      // Card 1: Transactions
      document.getElementById('s-tx-total').textContent = fmtNum(st.cc_total_registrations || 0);
      document.getElementById('s-tx-helped').textContent = fmtNum(st.cc_ticks_helped || 0);
      document.getElementById('s-tx-entries').textContent = fmtNum(st.entry_count || 0);
      document.getElementById('s-tx-hash').textContent = st.root_hash_hex || '--';

      // Track transaction sparkline
      const txNow = st.cc_total_registrations || 0;
      if (prevTxTotal !== null) {
        txHistory.push(txNow - prevTxTotal);
        if (txHistory.length > 60) txHistory.shift();
      }
      prevTxTotal = txNow;
      drawSparkline('spark-tx', txHistory.length > 1 ? txHistory : [0, 0], '#3498db');

      // Card 2: Earnings
      document.getElementById('s-earn-total').textContent = fmtNum(st.deed_collected || 0);
      document.getElementById('s-earn-deed').textContent = fmtNum(st.deed_collected || 0);
      document.getElementById('s-earn-split').textContent = st.deed_split || '--';
      document.getElementById('s-earn-pool').textContent = fmtNum(st.runner_pool_balance || 0);
      document.getElementById('s-airdrop-balance').textContent = fmtAxc(st.airdrop_pool_balance || 0);
      var localC = st.airdrop_local_claims || 0;
      var netC = st.airdrop_pool_claims || 0;
      document.getElementById('s-airdrop-claims').textContent = localC + '/' + netC;
      // Dev Treasury (FACT class isolation §6 — 1M dev-AXC, outside the
      // 100M public cap). Same shape as airdrop: balance + local/network
      // claim count.
      document.getElementById('s-dev-balance').textContent = fmtAxc(st.dev_pool_balance || 0);
      var devLocalC = st.dev_pool_local_claims || 0;
      var devNetC = st.dev_pool_claims || 0;
      document.getElementById('s-dev-claims').textContent = devLocalC + '/' + devNetC;
      // PR3 DEED Pool — 10% of every receiver-pays validator fee.
      // Current balance and lifetime cumulative ride side-by-side; in
      // Phase 1 (first 10 years from anchor) they stay equal, after the
      // cutoff balance freezes while total_credited can still grow if
      // we later wire a re-attestation path.
      document.getElementById('s-deed-pool-balance').textContent = fmtAxc(st.deed_pool_balance || 0);
      document.getElementById('s-deed-pool-total').textContent = fmtAxc(st.deed_pool_total_credited || 0);
      // Dev DEED — testnet-only observability. Shown always (even at 0)
      // so operators can confirm the line is wired.
      document.getElementById('s-dev-deed-pool-balance').textContent = fmtAxc(st.dev_deed_pool_balance || 0);
      document.getElementById('s-dev-deed-pool-total').textContent = fmtAxc(st.dev_deed_pool_total_credited || 0);
      earnHistory.push(st.deed_collected || 0);
      if (earnHistory.length > 60) earnHistory.shift();
      drawSparkline('spark-earn', earnHistory.length > 1 ? earnHistory : [0, 0], '#00d2d3');

      // Card 3: Health
      document.getElementById('s-hp-uptime').textContent = formatUptime(st.uptime_secs || 0);
      document.getElementById('s-hp-writes').textContent = fmtNum(st.writes_approved || 0);
      document.getElementById('s-hp-orphans').textContent = st.orphans_rescued || 0;
      document.getElementById('s-hp-rotations').textContent = st.rotations_survived || 0;
      document.getElementById('s-hp-peers').textContent =
        (st.mesh_peer_count || 0) + ' / ' + (st.mesh_target_peers || 0);
      document.getElementById('s-hp-known').textContent = fmtNum(st.mesh_known_nodes || 0);
      document.getElementById('s-hp-oods').textContent = Math.round(st.oods_estimate || 0);
      document.getElementById('s-hp-oods-tardis').textContent = st.tardis_depth || 0;

      // Card 4: Storage
      document.getElementById('s-st-entries').textContent = fmtNum(st.entry_count || 0);
      document.getElementById('s-st-smtmem').textContent = '~' + fmtBytes(st.smt_memory_bytes || 0);
      // YPX-014 txid tiers. Bloom is ALWAYS populated (fast negative
      // pre-check in hashmap mode, sole tier in bloom mode). Hashmap is
      // populated only in hashmap mode; bloom-mode nodes render "off".
      const bloomCount = fmtNum(st.txid_bloom_count || 0);
      const bloomSize  = fmtBytes(st.txid_bloom_bytes || 0);
      const bloomFprPct = ((st.txid_bloom_fpr || 0) * 100);
      const bloomFprTxt = bloomFprPct < 0.01
        ? bloomFprPct.toExponential(1) + '%'
        : bloomFprPct.toFixed(2) + '%';
      document.getElementById('s-st-bloom').textContent =
        bloomCount + ' / ' + bloomSize + ' (fpr ' + bloomFprTxt + ')';
      document.getElementById('s-st-hashmap').textContent =
        (st.txid_service === 'hashmap')
          ? fmtNum(st.txid_hashmap_len || 0) + ' / ~' + fmtBytes(st.txid_hashmap_bytes || 0)
          : (st.txid_service === 'bloom' ? 'off (bloom-only mode)' : '--');
      document.getElementById('s-st-wal').textContent = fmtBytes(st.wal_file_bytes || 0);
      document.getElementById('s-st-walops').textContent = fmtNum(st.wal_ops_since_snapshot || 0) + ' since snapshot';
      document.getElementById('s-st-snaps').textContent = (st.snapshot_count || 0) + ' on disk';
      document.getElementById('s-st-snapsize').textContent = fmtBytes(st.snapshot_total_bytes || 0);
      var tAgo = st.last_snapshot_tick > 0 ? ' (' + fmtNum(st.current_tick - st.last_snapshot_tick) + ' ticks ago)' : '';
      document.getElementById('s-st-lastsnap').textContent = 'tick ' + fmtNum(st.last_snapshot_tick || 0) + tAgo;
      document.getElementById('s-st-disk').textContent = fmtBytes(st.total_disk_bytes || 0);

      // Technical Details
      document.getElementById('d-nbc').textContent = st.cc_active ? 'Active' : 'Inactive';
      document.getElementById('d-cc-tick').textContent = st.cc_tick || 0;
      document.getElementById('d-cc-score').textContent = fmtNum(st.cc_score || 0);
      document.getElementById('d-tardis-slot').textContent = st.tardis_slot || '--';
      document.getElementById('d-downstream').textContent = st.downstream_count || 0;
      document.getElementById('d-net-size').textContent = st.estimated_network_size || 0;
      document.getElementById('d-gossip-seen').textContent = fmtNum(st.gossip_seen_count || 0);
      document.getElementById('d-bans').textContent = st.ban_count || 0;
      document.getElementById('d-reliability').textContent =
        (st.reliability_multiplier || 1).toFixed(1) + 'x';
      document.getElementById('d-version').textContent = st.version || '--';
      const issues = st.health_issues || [];
      document.getElementById('d-issues').textContent =
        issues.length > 0 ? 'Issues: ' + issues.join(' | ') : 'No issues';

      // Bootstrap Peers
      const bps = st.bootstrap_peers || [];
      const tbody = document.getElementById('bp-body');
      let bpHtml = '';
      let connCount = 0;
      bps.forEach(bp => {
        if (bp.status === 'connected') connCount++;
        const latStr = bp.latency_ms != null ? bp.latency_ms + 'ms' : '--';
        bpHtml += '<tr><td class="bp-addr">' + bp.address + '</td>' +
          '<td>' + bp.status_emoji + ' ' + bp.status + '</td>' +
          '<td>' + bp.last_seen + '</td>' +
          '<td class="bp-latency">' + latStr + '</td></tr>';
      });
      tbody.innerHTML = bpHtml;
      const sumEl = document.getElementById('bp-summary');
      if (bps.length > 0) {
        sumEl.textContent = '(' + connCount + '/' + bps.length + ' connected)';
      }
    })
    .catch(() => {});
}

// Start
update();
setInterval(update, 2000);
</script>
</body>
</html>"##;

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    /// A served snapshot must be able to FAIL a freshness check.
    ///
    /// `/status` is served from a cache the refresher keeps warm; when that
    /// refresher stops, the endpoint keeps answering with an ever-older
    /// snapshot and every consumer reads it as live. That is what happened on
    /// 2026-09-01 — zeta reported a 4509 s-old tick while its TARDIS was
    /// current, and `driver.py tardis` turned it into a phantom 1000 s tick
    /// spread and a second root_hash on a converged mesh. Visibility alone is
    /// not enough: a check that cannot fail is not a check, so this asserts
    /// staleness is DETECTABLE from the wire, not merely recorded.
    #[test]
    fn built_at_makes_staleness_detectable() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut fresh = make_status();
        fresh.built_at = now;
        let age = now.saturating_sub(fresh.built_at);
        assert!(age <= 1, "a just-built snapshot must read as fresh, got {age}s");

        // The failing direction is the one that matters: a refresher that
        // died an hour ago must be visibly an hour old, not silently "live".
        let mut stale = make_status();
        stale.built_at = now - 3600;
        let age = now.saturating_sub(stale.built_at);
        assert!(
            age >= 3600,
            "a snapshot built an hour ago MUST be detectable as stale; \
             if this ever reads fresh, /status has become unfalsifiable"
        );

        // And it must survive serialization — a consumer reads JSON, not the
        // struct, so an unserialized field would restore the original lie.
        let body = serde_json::to_string(&stale).expect("status serializes");
        assert!(
            body.contains("built_at"),
            "built_at must reach the wire or consumers cannot judge freshness"
        );
    }

    /// RULE 6 — the KI#205 claim counters are instruments: a consumer reads
    /// JSON, not the struct, so both must reach the wire with the value set
    /// (an unserialized counter restores "never ran" == "0 refusals").
    #[test]
    fn ki205_claim_counters_reach_the_wire() {
        let mut s = make_status();
        s.claims_unauthenticated = 7;
        s.recalls_refused_claimed = 3;
        let body = serde_json::to_string(&s).expect("status serializes");
        assert!(body.contains("\"claims_unauthenticated\":7"), "claims_unauthenticated must reach the wire: {body}");
        assert!(body.contains("\"recalls_refused_claimed\":3"), "recalls_refused_claimed must reach the wire: {body}");
    }

    /// RULE 6 — the ForkSettlement wave-2a instruments (refused legs, refused
    /// snapshots) are read as JSON; both must reach the wire with their value.
    #[test]
    fn wave2a_leg_and_snapshot_counters_reach_the_wire() {
        let mut s = make_status();
        s.leg_preimage_refused = 5;
        s.snapshot_decode_refused = 2;
        s.witness_not_in_directory_refused = 4;
        s.wal_checksum_missing_refused = 6;
        s.declared_state_unanchored = 8;
        let body = serde_json::to_string(&s).expect("status serializes");
        assert!(body.contains("\"declared_state_unanchored\":8"), "KI#251 counter must reach the wire: {body}");
        assert!(body.contains("\"witness_not_in_directory_refused\":4"), "KI#224 counter must reach the wire: {body}");
        assert!(body.contains("\"wal_checksum_missing_refused\":6"), "KI#248 counter must reach the wire: {body}");
        assert!(body.contains("\"leg_preimage_refused\":5"), "leg_preimage_refused must reach the wire: {body}");
        assert!(body.contains("\"snapshot_decode_refused\":2"), "snapshot_decode_refused must reach the wire: {body}");
    }

    /// RULE 6 — the ForkSettlement wave-4a witness-directory instruments are
    /// read as JSON; each must reach the wire with its value.
    #[test]
    fn wave4a_directory_counters_reach_the_wire() {
        let mut s = make_status();
        s.vbc_directory_refused = 3;
        s.vbc_registry_decode_refused = 1;
        s.vbc_directory_ae_refused = 4;
        s.vbc_directory_entries = 9;
        s.vbc_stamp_refused_no_floor = 6; // §6b.13 check 5
        s.vbc_stamp_refused_held = 7; // §9r F-1(c)
        s.vbc_stamp_refused_wait = 8;
        let body = serde_json::to_string(&s).expect("status serializes");
        for (k, v) in [("vbc_directory_refused", 3), ("vbc_registry_decode_refused", 1),
                       ("vbc_directory_ae_refused", 4), ("vbc_directory_entries", 9),
                       ("vbc_stamp_refused_no_floor", 6), ("vbc_stamp_refused_held", 7),
                       ("vbc_stamp_refused_wait", 8)] {
            assert!(body.contains(&format!("\"{k}\":{v}")), "{k} must reach the wire: {body}");
        }
    }

    /// RULE 6 — every ForkSettlement wave-3 counter is read as JSON (the
    /// struct is flattened); each must reach the TOP LEVEL of the wire with
    /// its value. Mutation: drop `#[serde(flatten)]` → the keys nest under
    /// `"origin"` and every assert here goes red.
    #[test]
    fn wave3_origin_counters_reach_the_wire() {
        let mut s = make_status();
        s.origin = OriginStatus {
            origin_records: 101,
            origin_records_contested: 102,
            origin_records_created: 103,
            origin_leg_unrecordable: 104,
            redeem_records: 116,
            redeem_records_contested: 117,
            redeem_records_created: 118,
            redeem_leg_zero_consumed: 119,
            producer_binding_refused: 120,
            wallet_id_key_mismatch: 121,
            origin_fork_claims_detected: 105,
            origin_fork_claims_adopted: 106,
            fork_claims_applied: 107,
            atraxi_evidence_refused: 108,
            origin_fork_bans_rederived_at_load: 109,
            origin_attest_vouched: 110,
            origin_attest_withheld: 111,
            origin_attest_held: 150,
            provenance_states_derived: 122,
            provenance_held_states: 123,
            provenance_dirty_queue: 124,
            fee_credits_held: 153,
            fee_credits_parked: 154,
            fee_credits_released: 155,
            origin_boot_secs: 112,
            origin_boot_refloors: 113,
            ban_refused_malformed: 114,
            wal_ban_decode_refused: 115,
            ban_file_write_failed: 125,
            record_ae_asks_sent: 126,
            record_ae_answers_sent: 127,
            record_ae_refused: 128,
            record_ae_refused_unknown_sender: 129,
            record_ae_refused_bad_signature: 130,
            record_ae_refused_replayed_nonce: 131,
            record_ae_refused_over_budget: 132,
            record_ae_refused_unsolicited: 133,
            record_ae_refused_oversize: 134,
            record_ae_refused_malformed: 135,
            record_ae_shed_global: 136,
            record_ae_descents_completed: 137,
            record_ae_descents_aborted: 138,
            record_ae_descents_truncated: 139,
            record_ae_legs_received: 140,
            record_ae_legs_refused: 141,
            record_ae_legs_recorded: 142,
            record_ae_legs_ungraded: 143,
            record_ae_legs_unrequested: 144,
            origin_records_upgraded: 145,
            record_trie_leaves: 146,
            seqforkban_dropped: 147,
            haladvance_dropped: 150,
            taintalert_dropped: 151,
            mergeresolved_dropped: 152,
            ae_status_discarded: 148,
            status_unbacked_at_load: 149,
        };
        let body = serde_json::to_string(&s).expect("status serializes");
        for (k, v) in [
            ("origin_records", 101), ("origin_records_contested", 102),
            ("origin_records_created", 103), ("origin_leg_unrecordable", 104),
            ("origin_fork_claims_detected", 105), ("origin_fork_claims_adopted", 106),
            ("fork_claims_applied", 107), ("atraxi_evidence_refused", 108),
            ("origin_fork_bans_rederived_at_load", 109), ("origin_attest_vouched", 110),
            ("origin_attest_withheld", 111), ("origin_boot_secs", 112),
            ("origin_boot_refloors", 113), ("ban_refused_malformed", 114),
            ("wal_ban_decode_refused", 115),
            ("redeem_records", 116), ("redeem_records_contested", 117),
            ("redeem_records_created", 118), ("redeem_leg_zero_consumed", 119),
            ("producer_binding_refused", 120), ("wallet_id_key_mismatch", 121),
            ("provenance_states_derived", 122), ("provenance_held_states", 123),
            ("provenance_dirty_queue", 124), ("ban_file_write_failed", 125),
            ("record_ae_asks_sent", 126), ("record_ae_answers_sent", 127),
            ("record_ae_refused", 128), ("record_ae_refused_unknown_sender", 129),
            ("record_ae_refused_bad_signature", 130), ("record_ae_refused_replayed_nonce", 131),
            ("record_ae_refused_over_budget", 132), ("record_ae_refused_unsolicited", 133),
            ("record_ae_refused_oversize", 134), ("record_ae_refused_malformed", 135),
            ("record_ae_shed_global", 136), ("record_ae_descents_completed", 137),
            ("record_ae_descents_aborted", 138), ("record_ae_descents_truncated", 139),
            ("record_ae_legs_received", 140), ("record_ae_legs_refused", 141),
            ("record_ae_legs_recorded", 142), ("record_ae_legs_ungraded", 143),
            ("record_ae_legs_unrequested", 144), ("origin_records_upgraded", 145),
            ("record_trie_leaves", 146), ("seqforkban_dropped", 147), ("haladvance_dropped", 150),
            ("ae_status_discarded", 148), ("status_unbacked_at_load", 149),
            ("taintalert_dropped", 151), ("mergeresolved_dropped", 152),
            ("origin_attest_held", 150),
            ("fee_credits_held", 153), ("fee_credits_parked", 154), ("fee_credits_released", 155),
        ] {
            assert!(body.contains(&format!("\"{k}\":{v}")), "{k} must reach the wire top level: {body}");
        }
        assert!(!body.contains("\"origin\":{"), "flattened, not nested: {body}");
    }

    fn make_status() -> NodeStatusSnapshot {
        let mut s = NodeStatusSnapshot {
            address_disputed: false,
            address_reports: 0,
            slot_hints_dropped_unobserved: 0,
            // §5.6a / NBC — this builder has no node handle in scope; the live
            // values come from the nabla_node.rs snapshot builder.
            address_observers: Vec::new(),
            address_unroutable: false,
            nbc_issued_at: 0,
            nbc_expires_at: 0,
            nbc_expires_in_secs: 0,
            nbc_chain_depth: 0,
            nbc_issuer: String::new(),
            version: format!("v{}", env!("CARGO_PKG_VERSION")),
            node_name: String::new(),
            node_id_hex: "aabbccdd11223344".into(),
            uptime_secs: 3661,
            txid_service: "hashmap".into(),
            txid_hashmap_len: 123,
            txid_hashmap_bytes: 123 * 96,
            txid_bloom_count: 123,
            txid_bloom_bytes: 18_000_000,
            txid_bloom_fpr: 0.0001,
            txid_bloom_fill_ratio: 0.0,
            consumed_bloom_count: 0,
            consumed_bloom_fpr: 0.0,
            consumed_bloom_fill_ratio: 0.0,
            listen_addr: "[::]:1211".into(),
            wan_addr: None,
            anti_rollback_armed: true,
            unarmed_rounds: 0,
            unarmed_ticks: 0,
            same_seq_marks_manufactured: 0,
            same_seq_marks_cleared: 0,
            same_seq_marks_active: 0,
            atraxi_open_keys: 0,
            atraxi_claims_opened: 0,
            atraxi_held_refusals: 0,
            claims_unauthenticated: 0,
            recalls_refused_claimed: 0,
            leg_preimage_refused: 0,
            witness_not_in_directory_refused: 0,
            declared_state_unanchored: 0,
            wal_checksum_missing_refused: 0,
            snapshot_decode_refused: 0,
            vbc_directory_refused: 0,
            vbc_stamp_refused_no_floor: 0,
            vbc_stamp_refused_held: 0,
            vbc_stamp_refused_wait: 0,
            vbc_registry_decode_refused: 0,
            vbc_directory_ae_refused: 0,
            vbc_directory_entries: 0,
            origin: OriginStatus::default(),
            built_at: 1_700_000_000,
            current_tick: 1000,
            tardis_active: true,
            tardis_slot: "D1".into(),
            has_upstream: true,
            downstream_count: 2,
            is_writer: true,
            d1_approved: true,
            d2_approved: false,
            ticks_with_current_parent: 0,
            rebalance_cooldown: 0,
            orphan_causes: Default::default(),
            lineage_ok: 0,
            lineage_reject: 0,
            lineage_skip: 0,
            audit_exonerated: 0,
            tardis_audit: Default::default(),
            tickhash_verified: 0,
            tickhash_unverified: 0,
            alert_proven: 0,
            alert_unproven: 0,
            quarantine_withheld: 0,
            ae_stall_windows: 0,
            stake_lock_observed_not_own_claim: 0,
            audit_resp_unauthorized: 0,
            audit_resp_unmatched: 0,
            poolsync_drop_unverified: 0,
            approvals_unverified: 0,
            alert_identity_proven: 0,
            alert_identity_unproven: 0,
            wal_deep_scan_corrupt: 0,
            h3_unbuilt_dropped: 0,
            ki222_banalert_dropped: 0,
            root_hash_hex: "0123456789abcdef".into(),
            entry_count: 5000,
            ban_count: 2,
            mesh_active: true,
            mesh_peer_count: 9,
            mesh_target_peers: 9,
            mesh_known_nodes: 50,
            estimated_network_size: 200,
            oods_estimate: 0.0,
            tardis_depth: 0,
            enquiry_peer_count: 0,
            cc_active: true,
            cc_tick: 999,
            cc_ticks_helped: 900,
            cc_total_registrations: 4500,
            cc_score: 45900,
            runner_pool_balance: 300,
            airdrop_pool_balance: crate::constants::AIRDROP_POOL_INITIAL_ATOMS,
            airdrop_pool_claims: 42,
            airdrop_local_claims: 12,
            dev_pool_balance: crate::constants::DEV_TREASURY_POOL_INITIAL_ATOMS,
            dev_pool_claims: 3,
            dev_pool_local_claims: 1,
            bootstrap_pool_balance: crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS,
            bootstrap_pool_claims: 0,
            foundation_pool_balance: crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS,
            foundation_pool_claims: 0,
            deed_collected: 50000,
            deed_split: "30/70".into(),
            deed_pool_balance: 9_000_000_000,    // 0.9 AXC — demo only
            deed_pool_total_credited: 9_000_000_000,
            dev_deed_pool_balance: 0,
            dev_deed_pool_total_credited: 0,
            fob_pools: Vec::new(),
            fob_tranches_authored: 0,
            fob_tranches_applied: 0,
            fob_tranches_rejected: 0,
            fob_conservation_rejects: 0,
            emission_epoch: 0, emission_rolls: 0, emission_top_up_atoms: 0,
            emission_claims_ok: 0, emission_claims_refused: 0, emission_conservation_refusals: 0,
            gossip_seen_count: 12345,
            last_gossip_tick: 998,
            transport_send_failures_total: 0,
            transport_send_failures_per_peer: std::collections::HashMap::new(),
            storm_shed_active: false,
            storm_dropped_total: 0,
            storm_trips_total: 0,
            tick_sig_failures: 0,
            tardis_parked: false,
            tardis_parked_grants: 0,
            tardis_parked_to_seated: 0,
            quarantine_active_count: 0,
            quarantine_pending_count: 0,
            emission_structural_violations: 0,
            nbc_issued_this_epoch: 0,
            nbc_issuance_refused_cap: 0,
            nbc_issuer_over_cap_seen: 0,
            probationary_peers: 0,
            probation_refusals: 0,
            pool_synced_kinds: vec![],
            pool_sync_gate_open: true,
            penguin_score: 5500,
            penguin_level: "Penguin".into(),
            penguin_emoji: "\u{1F427}".into(),
            uptime_streak_days: 12,
            writes_approved: 800,
            orphans_rescued: 3,
            rotations_survived: 5,
            reliability_multiplier: 2.0,
            wal_file_bytes: 4200000,
            wal_ops_since_snapshot: 847,
            snapshot_count: 3,
            snapshot_total_bytes: 14100000,
            last_snapshot_tick: 960,
            total_disk_bytes: 18300000,
            smt_memory_bytes: 1000000,
            upstream_hex: "1122334455667788".into(),
            upstream_name: "beta".into(),
            d1_hex: "aabb000000000001".into(),
            d1_name: "Emperor".into(),
            d2_hex: "aabb000000000002".into(),
            d2_name: "皇帝企鵝".into(),
            peer_list: vec![
                PeerEntry { node_id_hex: "ddee000000000001".into(), node_name: "gamma".into(), is_genesis: true, txid_service: "hashmap".into() },
                PeerEntry { node_id_hex: "ddee000000000002".into(), node_name: String::new(), is_genesis: false, txid_service: "bloom".into() },
            ],
            bootstrap_peers: vec![
                BootstrapPeerEntry {
                    address: "10.0.0.1:6225".into(),
                    status: "connected".into(),
                    status_emoji: "\u{1F7E2}".into(),
                    last_seen: "2m ago".into(),
                    latency_ms: Some(12),
                },
                BootstrapPeerEntry {
                    address: "10.0.0.2:6225".into(),
                    status: "unreachable".into(),
                    status_emoji: "\u{1F534}".into(),
                    last_seen: "never".into(),
                    latency_ms: None,
                },
            ],
            healthy: true,
            health_issues: Vec::new(),
        };
        diagnose(&mut s);
        s
    }

    // ── Health Diagnosis ──

    #[test]
    fn healthy_node() {
        let status = make_status();
        assert!(status.healthy);
        assert!(status.health_issues.is_empty());
    }

    #[test]
    fn unhealthy_no_tardis() {
        let mut s = make_status();
        s.tardis_active = false;
        diagnose(&mut s);

        assert!(!s.healthy);
        assert!(s.health_issues.iter().any(|i| i.contains("TARDIS")));
    }

    #[test]
    fn unhealthy_no_peers() {
        let mut s = make_status();
        s.mesh_peer_count = 0;
        diagnose(&mut s);

        assert!(!s.healthy);
        assert!(s.health_issues.iter().any(|i| i.contains("peer")));
    }

    #[test]
    fn unhealthy_low_peers() {
        let mut s = make_status();
        s.mesh_peer_count = 2;
        s.mesh_target_peers = 9;
        diagnose(&mut s);

        assert!(!s.healthy);
    }

    /// KI#79 — an UNARMED node refuses every registration, so it must not
    /// read healthy. delta was unarmed for 8 hours (2026-08-07) while
    /// `healthy: true, issues: []` — armed state was not among the checked
    /// conditions, the same blind-spot class the orphan check's comment
    /// documents.
    /// GUIDE §5.6c lever 5 — a closed pool-sync gate refuses every
    /// registration exactly like UNARMED, so it must surface as an issue and
    /// the field must survive JSON (consumers read the wire, not the struct).
    #[test]
    fn probation_pool_sync_gate_closed_is_a_health_issue() {
        let mut s = make_status();
        s.pool_sync_gate_open = false;
        s.pool_synced_kinds = vec!["airdrop".into(), "deed".into()];
        diagnose(&mut s);
        assert!(!s.healthy, "a node refusing registrations must not report healthy");
        assert!(
            s.health_issues.iter().any(|i| i.contains("POOL-SYNC-GATE") && i.contains("2/8")),
            "the issue must name the gate and the progress: {:?}", s.health_issues
        );
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"pool_sync_gate_open\":false"));
        assert!(json.contains("\"probationary_peers\""));
        assert!(json.contains("\"probation_refusals\""));
        // KI#191 residual + KI#48 P slot + §9.1.1a issuer cap: consumers read
        // the wire, so every new counter must reach JSON.
        for f in ["emission_structural_violations", "tardis_parked", "tardis_parked_grants",
                  "tardis_parked_to_seated", "nbc_issued_this_epoch", "nbc_issuance_refused_cap",
                  "nbc_issuer_over_cap_seen"] {
            assert!(json.contains(&format!("\"{f}\"")), "/status must carry {f}");
        }

        let mut open = make_status();
        open.pool_sync_gate_open = true;
        diagnose(&mut open);
        assert!(!open.health_issues.iter().any(|i| i.contains("POOL-SYNC-GATE")),
            "an open gate is not an issue");
    }

    #[test]
    fn ki79_unarmed_is_a_health_issue() {
        let mut s = make_status();
        s.anti_rollback_armed = false;
        s.unarmed_rounds = 5760; // 8 hours at one round per 5s tick
        s.unarmed_ticks = 28_800;
        diagnose(&mut s);

        assert!(!s.healthy, "an unarmed node must not report healthy");
        assert!(
            s.health_issues.iter().any(|i| i.contains("UNARMED")),
            "the issue must name the condition: {:?}", s.health_issues
        );
        // And the counters that separate a livelock from a startup delay
        // must be IN the message — that is the whole point of KI#79.
        assert!(s.health_issues.iter().any(|i| i.contains("5760")));
    }

    /// KI#79 — armed is the healthy default (the fixture is armed).
    #[test]
    fn ki79_armed_produces_no_unarmed_issue() {
        let mut s = make_status();
        diagnose(&mut s);
        assert!(!s.health_issues.iter().any(|i| i.contains("UNARMED")));
    }

    // ── Routing ──

    #[test]
    fn route_dashboard() {
        let status = make_status();
        let config = MonitorConfig::default();

        let (code, content_type, body) = route_request("/", None, &status, &config);
        assert_eq!(code, 200);
        assert!(content_type.contains("html"));
        assert!(body.contains("AXIOM Nabla"));
    }

    /// Nabla has no functional HTTP (YP "Transport — functional endpoints",
    /// amended 2026-09-26): each former functional path is simply not a
    /// dashboard route and answers 404 — no handler, no 410 gate.
    #[test]
    fn former_functional_paths_are_not_routes() {
        let status = make_status();
        let config = MonitorConfig::default();
        for path in ["/register", "/clara", "/query", "/query-txid", "/register-cheque-claim",
                     "/query-cheque-claim", "/pulse-proof", "/jfp-secret", "/jfp-secrets",
                     "/bridge", "/endorse-ban-challenge", "/challenge-ban"] {
            let (code, _, _) = route_request(path, None, &status, &config);
            assert_eq!(code, 404, "{path} must not be a dashboard route");
        }
    }

    #[test]
    fn route_status_json() {
        let status = make_status();
        let config = MonitorConfig::default();

        let (code, content_type, body) = route_request("/status", None, &status, &config);
        assert_eq!(code, 200);
        assert!(content_type.contains("json"));
        assert!(body.contains("\"current_tick\": 1000"));
        assert!(body.contains("\"penguin_score\": 5500"));
    }

    #[test]
    fn route_health_ok() {
        let status = make_status();
        let config = MonitorConfig::default();

        let (code, content_type, body) = route_request("/health", None, &status, &config);
        assert_eq!(code, 200);
        assert!(content_type.contains("json"));
        assert!(body.contains("\"healthy\": true"));
    }

    #[test]
    fn route_health_unhealthy() {
        let mut status = make_status();
        status.tardis_active = false;
        diagnose(&mut status);

        let config = MonitorConfig::default();
        let (code, _, body) = route_request("/health", None, &status, &config);
        assert_eq!(code, 503);
        assert!(body.contains("\"healthy\": false"));
    }

    #[test]
    fn route_api_status() {
        let status = make_status();
        let config = MonitorConfig::default();

        let (code, _, body) = route_request("/api/status", None, &status, &config);
        assert_eq!(code, 200);
        assert!(body.contains("\"current_tick\": 1000"));
        assert!(body.contains("\"entry_count\": 5000"));
    }

    #[test]
    fn route_not_found() {
        let status = make_status();
        let config = MonitorConfig::default();

        let (code, _, _) = route_request("/unknown", None, &status, &config);
        assert_eq!(code, 404);
    }

    // ── Auth ──

    #[test]
    fn auth_required() {
        let status = make_status();
        let config = MonitorConfig {
            auth_token: Some("secret123".into()),
            ..Default::default()
        };

        // No token -> 401
        let (code, _, _) = route_request("/", None, &status, &config);
        assert_eq!(code, 401);

        // Wrong token -> 401
        let (code, _, _) = route_request("/", Some("token=wrong"), &status, &config);
        assert_eq!(code, 401);

        // Correct token -> 200
        let (code, _, _) = route_request("/", Some("token=secret123"), &status, &config);
        assert_eq!(code, 200);
    }

    // ── Formatting ──

    #[test]
    fn format_uptime_minutes() {
        assert_eq!(format_uptime(90), "1m 30s");
    }

    #[test]
    fn format_uptime_hours() {
        assert_eq!(format_uptime(3661), "1h 1m");
    }

    #[test]
    fn format_uptime_days() {
        assert_eq!(format_uptime(90061), "1d 1h 1m");
    }

    // ── Dashboard Content ──

    #[test]
    fn dashboard_contains_key_elements() {
        let status = make_status();
        let html = html_dashboard(&status);

        assert!(html.contains("AXIOM Nabla"));
        assert!(html.contains("Network Topology"));
        assert!(html.contains("Transactions"));
        assert!(html.contains("Earnings"));
        assert!(html.contains("Health"));
        assert!(html.contains("Technical Details"));
        assert!(html.contains("/status"));
    }

    #[test]
    fn dashboard_shows_issues_in_json() {
        let mut status = make_status();
        status.tardis_active = false;
        diagnose(&mut status);

        let json = json_status(&status);
        assert!(json.contains("TARDIS not initialized"));
    }

    // ── Hex Formatting ──

    #[test]
    fn hex_short_format() {
        let bytes = [0xAA; 32];
        assert_eq!(hex_short(&bytes), "aaaaaaaaaaaaaaaa");
    }

    // ── Penguin Scoring ──

    #[test]
    fn penguin_score_hatchling() {
        let score = penguin_contribution(500, 0, 0, 0, 0);
        assert_eq!(score, 0); // 500/1000 = 0
        let (level, _) = penguin_level(score);
        assert_eq!(level, "Hatchling");
    }

    #[test]
    fn penguin_score_penguin_level() {
        let score = penguin_contribution(2_000_000, 200_000, 100_000, 5, 10);
        // 2000 + 1000 + 1000 + 250 + 1000 = 5250
        assert!((1_000..10_000).contains(&score));
        let (level, _) = penguin_level(score);
        assert_eq!(level, "Penguin");
    }

    #[test]
    fn penguin_score_colony_elder() {
        let score = penguin_contribution(100_000_000, 50_000_000, 50_000_000, 500, 2000);
        // 100000 + 250000 + 500000 + 25000 + 200000 = 1,075,000
        assert!(score >= 500_000);
        let (level, _) = penguin_level(score);
        assert_eq!(level, "Colony Elder");
    }

    #[test]
    fn reliability_multiplier_tiers() {
        assert_eq!(reliability_multiplier(100.0), 3.0);
        assert_eq!(reliability_multiplier(99.9), 3.0);
        assert_eq!(reliability_multiplier(99.5), 2.0);
        assert_eq!(reliability_multiplier(99.0), 2.0);
        assert_eq!(reliability_multiplier(97.0), 1.0);
        assert_eq!(reliability_multiplier(95.0), 1.0);
        assert_eq!(reliability_multiplier(92.0), 0.75);
        assert_eq!(reliability_multiplier(85.0), 0.5);
    }
}
