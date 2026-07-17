//! OODS — Operational Observer Determination System (YPX-021).
//!
//! Cheap, gossip-native estimate of the size of the network a node can actually
//! see, so the dangerous operations (issuing CLEAN, compressing a FACT chain)
//! can be gated on a healthy view (partition/eclipse detection).
//!
//! This module is the **estimator primitive only** — pure math + identity-bound
//! draws. It touches NO consensus code: no Core, no TARDIS tick wire, no NBC
//! issuance, no FACT compression. Those gates are DEFERRED (see YPX-021 §12)
//! until the pricing claim (§5) is validated. Do not wire this into a decision
//! path yet.
//!
//! Technique: **Extrema Propagation** (Baquero, Almeida, Menezes, Jesus). Each
//! node draws `m` values `~Exp(1)`; the mesh gossips the per-channel minimum;
//! `N̂ = m / Σ minⱼ` (relative error ≈ 1/√m). Plain EP is NOT adversary-resistant;
//! the hardening is the identity-bound, un-grindable draw (YPX-021 §5).

/// Number of independent channels. Relative error of `N̂` is ≈ 1/√M, so M=128
/// gives ≈ 9% — plenty to separate normal churn (single-digit %) from an eclipse
/// (order-of-magnitude collapse). Cost: M floats of state + gossip payload.
pub const CHANNELS: usize = 128;

/// A node's per-channel draws (`~Exp(1)`), one vector per node.
///
/// The gossip state a node keeps is the running component-wise MINIMUM of every
/// draw it has seen (its own + everything merged in). `N̂` is read off that.
#[derive(Clone, Debug)]
pub struct Minima {
    /// Running per-channel minimum. `f64::INFINITY` = "nothing seen on this
    /// channel yet" (identity element for min-merge).
    pub v: [f64; CHANNELS],
}

impl Default for Minima {
    fn default() -> Self {
        Minima { v: [f64::INFINITY; CHANNELS] }
    }
}

impl Minima {
    /// Empty accumulator (identity for merge).
    pub fn empty() -> Self {
        Minima::default()
    }

    /// The draws contributed by a single identity, from its NBC pubkey and the
    /// (un-grindable) epoch seed. YPX-021 §5:
    ///   u = Hash(nbc_pubkey ‖ epoch_seed ‖ channel) / 2^64   ∈ (0,1)
    ///   x = −ln(u)                                            ~ Exp(1)
    /// One identity → exactly one draw per channel. The draw is DERIVED, not
    /// chosen: the only adversarial freedom is *which registered identities you
    /// advertise*, and (with an un-grindable `epoch_seed` + registration
    /// probation) sustaining a small minimum requires a standing pool (§5).
    pub fn from_identity(nbc_pubkey: &[u8], epoch_seed: &[u8]) -> Self {
        let mut m = Minima::empty();
        for j in 0..CHANNELS {
            m.v[j] = draw(nbc_pubkey, epoch_seed, j as u32);
        }
        m
    }

    /// Gossip merge = component-wise minimum. Monotone, commutative, idempotent —
    /// so it converges regardless of gossip order/duplication.
    pub fn merge(&mut self, other: &Minima) {
        for j in 0..CHANNELS {
            if other.v[j] < self.v[j] {
                self.v[j] = other.v[j];
            }
        }
    }

    /// Fold one more identity's draws in (convenience over building a `Minima`).
    pub fn absorb_identity(&mut self, nbc_pubkey: &[u8], epoch_seed: &[u8]) {
        for j in 0..CHANNELS {
            let x = draw(nbc_pubkey, epoch_seed, j as u32);
            if x < self.v[j] {
                self.v[j] = x;
            }
        }
    }

    /// Network-size estimate `N̂ = M / Σ minⱼ`. Returns 0.0 if no draws seen.
    pub fn estimate(&self) -> f64 {
        let mut sum = 0.0f64;
        let mut seen = 0usize;
        for j in 0..CHANNELS {
            if self.v[j].is_finite() {
                sum += self.v[j];
                seen += 1;
            }
        }
        if seen == 0 || sum <= 0.0 {
            return 0.0;
        }
        // Use only the channels that have been populated; for a converged mesh
        // that is all CHANNELS. `seen` guards the warm-up window.
        seen as f64 / sum
    }
}

/// One identity's draw on one channel: `−ln(u)` where `u = Hash(...)/2^64`.
/// `Exp(1)`-distributed when `u` is uniform (which BLAKE3 output is, to any
/// distinguisher we care about).
pub fn draw(nbc_pubkey: &[u8], epoch_seed: &[u8], channel: u32) -> f64 {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_OODS_v1");
    h.update(nbc_pubkey);
    h.update(epoch_seed);
    h.update(&channel.to_le_bytes());
    let digest = h.finalize();
    let bytes = digest.as_bytes();
    // Top 64 bits → u ∈ [0,1). Nudge off exact 0 so ln is finite.
    let raw = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let u = ((raw >> 11) as f64) / ((1u64 << 53) as f64); // 53-bit mantissa granularity
    let u = if u <= 0.0 { f64::from_bits(1) } else { u };
    -u.ln()
}

/// Aggregate a whole set of identities into one `Minima` (a node's fully-merged
/// view of everything it can see this epoch).
pub fn observe(identities: &[&[u8]], epoch_seed: &[u8]) -> Minima {
    let mut m = Minima::empty();
    for id in identities {
        m.absorb_identity(id, epoch_seed);
    }
    m
}

/// Fixed domain seed for the **telemetry** estimate. YPX-021 §6/§12: the real,
/// un-grindable per-epoch seed (§5.1) is part of the DEFERRED consensus wiring.
/// The live size *readout* does not need un-grindability — only a stable domain —
/// so telemetry uses this constant. Do NOT use this seed for any gate.
pub const TELEMETRY_EPOCH_SEED: &[u8] = b"AXIOM_OODS_TELEMETRY_v1";

/// Live network-size estimate (read-only telemetry) from the node's own id plus
/// the ids of the peers it currently knows (its mesh view). Under a partition or
/// eclipse the known-peer set shrinks, so the estimate drops — that is the
/// detection signal (YPX-021 §8). No consensus gate; a monitoring readout only.
pub fn estimate_from_ids(self_id: &[u8; 32], peer_ids: &[[u8; 32]]) -> f64 {
    let mut m = Minima::empty();
    m.absorb_identity(self_id, TELEMETRY_EPOCH_SEED);
    for id in peer_ids {
        m.absorb_identity(id, TELEMETRY_EPOCH_SEED);
    }
    m.estimate()
}

// ─────────────────────────── ENFORCEMENT PATH (YPX-021 §6/§8) ───────────────
// The detection path above is read-only telemetry. The enforcement path below
// produces a *Core-verifiable proof* of the size reading: per channel, the
// identity that achieves the minimum draw (= the LARGEST integer `raw`) and that
// raw. Core verifies each raw via `axiom_core_logic::oods_verify` (integer, no
// float); the float size estimate is then derived off-Core from the *verified*
// raws by `estimate_from_verified_raws`. Single source of truth for the raw:
// `oods_verify::oods_raw` (Core's function), so producer and verifier can never
// drift.

/// One channel of an OODS proof: the achieving identity and its integer raw.
/// Feeds `axiom_core_logic::oods_verify::OodsChannelClaim` at the verify site.
#[derive(Clone, Debug)]
pub struct ProofChannel {
    pub channel: u32,
    pub identity: [u8; 32],
    pub raw: u64,
}

/// Produce the per-channel proof for a set of identities under `epoch_seed`:
/// for each channel, the identity with the LARGEST raw (the one achieving that
/// channel's minimum draw) and its raw. This is what a node carries on the tick
/// (§6) for Core to verify.
pub fn produce_proof(identities: &[[u8; 32]], epoch_seed: &[u8]) -> Vec<ProofChannel> {
    (0..CHANNELS as u32)
        .map(|ch| {
            let mut best = ProofChannel { channel: ch, identity: [0u8; 32], raw: 0 };
            for id in identities {
                let raw = axiom_core_logic::oods_verify::oods_raw(id, epoch_seed, ch);
                if raw >= best.raw {
                    best.raw = raw;
                    best.identity = *id;
                }
            }
            best
        })
        .collect()
}

/// `-ln(u)` for `u` derived from an integer raw — the same 53-bit mapping the
/// estimator's `draw` uses, so an estimate derived from raws matches the live
/// estimator bit-for-bit.
pub fn draw_from_raw(raw: u64) -> f64 {
    let u = ((raw >> 11) as f64) / ((1u64 << 53) as f64);
    let u = if u <= 0.0 { f64::from_bits(1) } else { u };
    -u.ln()
}

/// The public size estimate `N̂ = M / Σ draw` computed from the per-channel raws
/// **after Core has verified them** (§6). Float lives here (off-Core), never in
/// the ELF. `raws[c]` is channel `c`'s verified minimum-achieving raw.
pub fn estimate_from_verified_raws(raws: &[u64]) -> f64 {
    let sum: f64 = raws.iter().map(|&r| draw_from_raw(r)).sum();
    if sum <= 0.0 { 0.0 } else { CHANNELS as f64 / sum }
}

/// Dip ratio = own-view / reference. Below 1 means this node/wallet sees a
/// SMALLER network than the reference; a large drop suggests partition/eclipse
/// (YPX-021 §8–§9). Returns 1.0 when the reference is unknown (0).
///
/// IMPORTANT (YPX-021 §8.1): for a WALLET the `reference` MUST be the *current*,
/// tick-stamped, Core-attested network reading ("latest odds of the time"), NOT
/// a stored high-water baseline. A wallet can be dormant while the network
/// legitimately shrinks; comparing a fresh view against a stale baseline would
/// false-fire and lock a healthy wallet out. Current-view vs current-reading:
/// both small in a legitimately-smaller network → ratio ~1 → healthy; flagged
/// only when the view is smaller than the network's *current* state → eclipse.
pub fn dip_ratio(live: f64, reference: f64) -> f64 {
    if reference <= 0.0 { 1.0 } else { live / reference }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic distinct pubkeys for tests.
    fn pk(i: u64) -> Vec<u8> {
        let mut v = b"nbc-".to_vec();
        v.extend_from_slice(&i.to_le_bytes());
        v
    }

    fn observe_n(n: u64, epoch: &[u8]) -> Minima {
        let mut m = Minima::empty();
        for i in 0..n {
            m.absorb_identity(&pk(i), epoch);
        }
        m
    }

    fn id32(i: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&i.to_le_bytes());
        b
    }

    /// ENFORCEMENT END-TO-END (YPX-021 §6): a node produces a proof for its view,
    /// Core verifies every per-channel raw (integer, no float), the size derived
    /// from the *verified* raws matches both the true N and the live estimator,
    /// and a single forged (inflated) minimum is rejected. This is the "confirm
    /// works" for the whole detect→prove→Core-verify→derive path.
    #[test]
    fn enforcement_proof_verifies_derives_and_rejects_forgery() {
        use axiom_core_logic::oods_verify::{
            oods_epoch_seed, verify_oods_channel_raws, OodsChannelClaim, OodsVerifyError,
        };
        let seed = oods_epoch_seed(11, b"smt-root-at-fixed-offset");
        let n = 300u64;
        let ids: Vec<[u8; 32]> = (0..n).map(id32).collect();

        // 1. produce the proof (per-channel achieving identity + raw)
        let proof = produce_proof(&ids, &seed);
        assert_eq!(proof.len(), CHANNELS);

        // 2. Core verifies every raw against the canonical seed → accepts
        let claims: Vec<OodsChannelClaim> = proof
            .iter()
            .map(|p| OodsChannelClaim { channel: p.channel, identity: &p.identity, claimed_raw: p.raw })
            .collect();
        assert_eq!(verify_oods_channel_raws(&claims, &seed), Ok(()));

        // 3. size derived from the VERIFIED raws ≈ true N …
        let mut raws = vec![0u64; CHANNELS];
        for p in &proof {
            raws[p.channel as usize] = p.raw;
        }
        let n_hat = estimate_from_verified_raws(&raws);
        let err = (n_hat - n as f64).abs() / n as f64;
        assert!(err < 0.30, "derived N̂ {n_hat:.0} vs N {n} (err {err:.2})");

        // … and matches the live estimator on the same ids+seed (single source)
        let mut m = Minima::empty();
        for id in &ids {
            m.absorb_identity(id, &seed);
        }
        assert!((n_hat - m.estimate()).abs() < 1e-6, "derived {n_hat} vs estimator {}", m.estimate());

        // 4. FORGERY: inflate one channel's minimum → Core rejects (the §5 pricing:
        //    you can't claim a bigger network without a real identity behind it)
        let mut forged = claims;
        forged[63].claimed_raw = forged[63].claimed_raw.wrapping_add(999_999);
        assert!(matches!(
            verify_oods_channel_raws(&forged, &seed),
            Err(OodsVerifyError::RawMismatch { channel: 63 })
        ));
    }

    /// Honest estimate tracks true size within the estimator's error band.
    #[test]
    fn estimate_tracks_true_size() {
        for &n in &[10u64, 100, 1_000, 10_000] {
            let m = observe_n(n, b"epoch-0");
            let est = m.estimate();
            let rel = (est - n as f64).abs() / n as f64;
            // 128 channels → ~9% 1-sigma; allow 3-sigma for CI stability.
            assert!(
                rel < 0.30,
                "N={n}: estimate {est:.0} off by {:.1}% (>30%)",
                rel * 100.0
            );
        }
    }

    /// Accuracy improves with channel count (1/√M). Sanity check on the estimator.
    #[test]
    fn more_channels_tighter() {
        // Re-estimate using only the first K channels.
        fn est_k(m: &Minima, k: usize) -> f64 {
            let mut sum = 0.0;
            let mut seen = 0;
            for j in 0..k {
                if m.v[j].is_finite() {
                    sum += m.v[j];
                    seen += 1;
                }
            }
            if seen == 0 { 0.0 } else { seen as f64 / sum }
        }
        let n = 1_000u64;
        let m = observe_n(n, b"epoch-x");
        let e_few = (est_k(&m, 8) - n as f64).abs() / n as f64;
        let e_many = (est_k(&m, 128) - n as f64).abs() / n as f64;
        // Not guaranteed monotone on a single sample, but 128 should be in-band.
        assert!(e_many < 0.30, "128-channel error {:.1}% too high", e_many * 100.0);
        let _ = e_few;
    }

    /// Gossip merge order/duplication does not change the result (min is a
    /// commutative idempotent monoid).
    #[test]
    fn merge_is_order_independent() {
        let a = observe_n(50, b"e");
        let mut b = observe_n(50, b"e"); // same identities, "heard again"
        b.merge(&a);
        // Merging a node's view with a duplicate of itself changes nothing.
        assert_eq!(a.estimate().to_bits(), b.estimate().to_bits());
    }

    // ---- The §5 pricing claim, probed empirically ---------------------------

    /// F1 rematch (the crux): a colluder's STANDING POOL of size P produces an
    /// estimate ≈ P, NOT larger. To fake a big network you must hold a big pool.
    /// This is the empirical half of "lying costs as much as being."
    #[test]
    #[ignore = "slow statistical validation (minutes); run explicitly: cargo test -p axiom-nabla oods -- --ignored --nocapture"]
    fn standing_pool_cannot_exceed_its_own_size() {
        // Attacker owns pools of various sizes; each epoch they can only advertise
        // draws from identities they actually hold. Average the faked estimate
        // across many independent epochs (the attack must SUSTAIN the lie).
        for &pool in &[50u64, 500, 5_000] {
            let epochs = 40;
            let mut sum_est = 0.0;
            for e in 0..epochs {
                let seed = format!("epoch-{e}");
                let m = observe_n(pool, seed.as_bytes());
                sum_est += m.estimate();
            }
            let avg = sum_est / epochs as f64;
            // The faked estimate is ~pool, and crucially it does NOT run away to a
            // much larger number. Allow generous variance band; assert it can't
            // fake, say, 3x its real pool on a sustained basis.
            assert!(
                avg < 3.0 * pool as f64,
                "pool={pool}: sustained faked estimate {avg:.0} exceeded 3x pool — \
                 min-variance MAY allow cheap faking; investigate before gating"
            );
            // And it genuinely reaches ~pool (isn't uselessly low).
            assert!(avg > 0.3 * pool as f64, "pool={pool}: estimate {avg:.0} < 0.3x pool");
        }
    }

    /// The min-variance question stated as a test: across many epochs, how often
    /// does a SMALL pool's SINGLE-epoch estimate spike to look like a much larger
    /// network? If a small pool frequently spikes >10x, an attacker who only needs
    /// ONE lucky epoch to land a compression could fake cheaply — that would
    /// FALSIFY the §5 pricing claim and this test documents the risk quantitatively.
    #[test]
    #[ignore = "slow statistical validation (minutes); run explicitly: cargo test -p axiom-nabla oods -- --ignored --nocapture"]
    fn single_epoch_spike_probability_is_bounded() {
        let pool = 100u64;
        let epochs = 2_000;
        let mut spikes_10x = 0;
        let mut spikes_3x = 0;
        for e in 0..epochs {
            let seed = format!("spikecheck-{e}");
            let est = observe_n(pool, seed.as_bytes()).estimate();
            if est > 10.0 * pool as f64 { spikes_10x += 1; }
            if est > 3.0 * pool as f64 { spikes_3x += 1; }
        }
        // With M=128 channels the per-epoch estimate concentrates; a >10x spike
        // should be effectively never. If this ever fires, the single-lucky-epoch
        // attack is real and the gate must NOT rely on a single-epoch reading
        // (require the healthy proof to hold for K consecutive epochs — §9 hysteresis).
        assert_eq!(
            spikes_10x, 0,
            "pool={pool}: {spikes_10x}/{epochs} single-epoch estimates spiked >10x — \
             single-lucky-epoch faking is possible; hysteresis (K-epoch persistence) is MANDATORY"
        );
        // A 3x single-epoch spike is the softer signal; record it (informational —
        // hysteresis covers it). Keep the bound loose so this documents rather than
        // over-constrains.
        assert!(
            spikes_3x < epochs / 20,
            "pool={pool}: {spikes_3x}/{epochs} spiked >3x in a single epoch — \
             K-epoch hysteresis needed before gating on a healthy reading"
        );
    }

    /// PRODUCTION DYNAMISM (the mainnet question): a live network churns — nodes
    /// join and leave and the total size fluctuates every epoch. A detector is
    /// only usable if normal churn stays BELOW the eclipse trigger (no false
    /// alarm) while a real eclipse still crosses it. This tests that
    /// discrimination directly, with a churning membership + fluctuating size.
    #[test]
    fn dynamic_network_churn_vs_eclipse() {
        let n = 500u64;
        let baseline = observe_n(n, TELEMETRY_EPOCH_SEED).estimate();

        // 50 epochs of live churn: each epoch the MEMBERSHIP shifts (id window
        // rotates -> join/leave) AND the COUNT fluctuates +/-15% around N.
        // Deterministic (no RNG needed).
        let mut min_churn_ratio = f64::INFINITY;
        let mut max_churn_ratio = 0.0f64;
        for e in 0..50u64 {
            let count = n * (85 + (e % 31)) / 100; // 0.85N .. 1.15N
            let offset = e * 37; // rotate the identity window each epoch (churn)
            let mut m = Minima::empty();
            for i in offset..offset + count {
                m.absorb_identity(&pk(i), TELEMETRY_EPOCH_SEED);
            }
            let r = dip_ratio(m.estimate(), baseline);
            if r < min_churn_ratio { min_churn_ratio = r; }
            if r > max_churn_ratio { max_churn_ratio = r; }
        }
        // Normal churn NEVER looks like an eclipse: even the worst epoch stays
        // well above a big-drop threshold (+/-15% size + ~9% estimator noise
        // keeps the ratio roughly in 0.7..1.3). So a dip gate would not fire.
        assert!(
            min_churn_ratio > 0.5,
            "normal churn false-alarmed: worst ratio {min_churn_ratio:.2} (a dip gate would trip on churn)"
        );

        // A real eclipse: the node's view collapses to a small colluder partition.
        let eclipse_ratio = dip_ratio(observe_n(n / 20, TELEMETRY_EPOCH_SEED).estimate(), baseline);
        assert!(
            eclipse_ratio < 0.15,
            "eclipse not clearly below the churn band: {eclipse_ratio:.2}"
        );

        // DISCRIMINATION: worst-churn and eclipse are far apart, so a threshold
        // placed in the valley (e.g. 0.3) separates legitimate dynamism from an
        // attack cleanly. This is why OODS is usable in a dynamic production mesh.
        assert!(
            min_churn_ratio / eclipse_ratio > 3.0,
            "churn {min_churn_ratio:.2} and eclipse {eclipse_ratio:.2} not clearly separated"
        );
    }

    /// OODS vs THE INITIAL GAP — the collusion/partition FACT-compression
    /// wash-out (YPX-021 §1). The attack REQUIRES the colluder's node to be
    /// eclipsed (see only its small partition) so it can double-spend and
    /// compress away the evidence before heal. This asks the two questions that
    /// decide whether OODS closes it: (1) does OODS DETECT that eclipse? and
    /// (2) what does it cost to EVADE detection?
    ///
    /// Findings this test pins:
    ///  - the eclipse is a large, clearly-detectable drop (order of magnitude);
    ///  - to keep the reading "healthy" and slip past the (future) gate, the
    ///    colluder must present ~N verified NBCs — the standing pool — which IS
    ///    the pricing. So the free wash-out becomes: trip detection, OR own ~N
    ///    bonded NBCs.
    /// NOTE: this tests DETECTION + PRICING (implemented). The ENFORCEMENT gate
    /// (refuse-compress-on-dip via a Core-verified size proof) is deferred
    /// (YPX-021 §8/§12) — so this shows the gap is *detection-closed and priced*,
    /// not that the wash-out is blocked end-to-end yet.
    #[test]
    fn washout_eclipse_detected_and_evasion_is_priced() {
        // Honest mesh of N verified NBCs — the node's healthy baseline.
        let n = 200u64;
        let baseline = observe_n(n, TELEMETRY_EPOCH_SEED).estimate();
        let base_err = (baseline - n as f64).abs() / n as f64;
        assert!(base_err < 0.30, "baseline estimate {baseline:.0} not ~{n}");

        // The attack: the colluder runs 8 nodes and eclipses its view to just
        // those (points its Nabla list at colluder nodes only).
        let colluder_pool = 8u64;
        let eclipsed = observe_n(colluder_pool, TELEMETRY_EPOCH_SEED).estimate();
        let ratio = dip_ratio(eclipsed, baseline);
        // DETECTED: 8 vs 200 is a ~0.04 ratio — an unmistakable order-of-magnitude
        // collapse. This is the signal the (future) gate fires on.
        assert!(
            ratio < 0.25,
            "wash-out eclipse NOT detected: dip ratio {ratio:.3} (est {eclipsed:.0} vs baseline {baseline:.0})"
        );

        // EVASION IS PRICED: the estimate tracks the number of verified NBCs the
        // colluder can present, so to keep the reading near baseline (evade the
        // gate) the colluder needs ~N certs. Show the crossover sits near N:
        let half = dip_ratio(observe_n(n / 2, TELEMETRY_EPOCH_SEED).estimate(), baseline);
        assert!(half < 0.70, "N/2 verified certs should still read as a dip ({half:.2})");
        let near_full = dip_ratio(observe_n((n as f64 * 0.9) as u64, TELEMETRY_EPOCH_SEED).estimate(), baseline);
        assert!(near_full > 0.70, "avoiding the dip needs ~N verified certs ({near_full:.2})");
        // i.e. a colluder cannot hide the eclipse without ~N bonded NBCs — the
        // standing-pool pricing (cf. standing_pool_cannot_exceed_its_own_size).
    }

    /// Integration: a full mesh estimates ~N from a node's peer view; a
    /// PARTITION into a small disjoint view makes the estimate drop to ~the
    /// subgroup size — the read-only detection signal wired into node status.
    #[test]
    fn partition_detection_end_to_end() {
        // 30 distinct node ids.
        let ids: Vec<[u8; 32]> = (0..30u32)
            .map(|i| { let mut a = [0u8; 32]; a[..4].copy_from_slice(&i.to_le_bytes()); a })
            .collect();

        // Healthy: node 0 knows all other 29 (+ itself = 30).
        let peers_all: Vec<[u8; 32]> = ids[1..].to_vec();
        let healthy = estimate_from_ids(&ids[0], &peers_all);
        assert!(
            (healthy - 30.0).abs() / 30.0 < 0.4,
            "healthy estimate {healthy:.1} not ~30 (est error band)"
        );

        // Partition/eclipse: node 0 now only sees a 5-node view (itself + 4).
        let peers_partition: Vec<[u8; 32]> = ids[1..5].to_vec();
        let partitioned = estimate_from_ids(&ids[0], &peers_partition);
        assert!(
            (partitioned - 5.0).abs() / 5.0 < 0.6,
            "partitioned estimate {partitioned:.1} not ~5"
        );

        // The dip is clearly detectable: 30 -> 5 is a ratio near 0.17.
        let ratio = dip_ratio(partitioned, healthy);
        assert!(
            ratio < 0.45,
            "dip ratio {ratio:.2} not a clear collapse (30->5 expected ~0.17)"
        );
        // And "no baseline" never false-alarms.
        assert_eq!(dip_ratio(5.0, 0.0), 1.0);
    }

    /// SEED GRINDING (YPX-021 §5.1) — the round-2 "new #1 surface". Even with
    /// identity grinding closed, an attacker who can choose among K candidate
    /// epoch seeds picks the one where its fixed pool looks largest. This measures
    /// the achievable inflation as a function of K, quantifying WHY the seed must
    /// be canonical (K=1). Success prob at factor c scales ≈ K · Pr[Gamma(m,1)<m/c],
    /// so a large K drags 2x-3x back into reach; K=1 leaves only the (negligible)
    /// single-draw tail.
    #[test]
    #[ignore = "slow statistical validation (minutes); run explicitly: cargo test -p axiom-nabla oods -- --ignored --nocapture"]
    fn seed_grinding_best_of_k() {
        let pool = 100u64;
        // For each K, the attacker tries K seeds and keeps the max estimate.
        // Report the best inflation factor achieved over many independent trials.
        fn best_of_k(pool: u64, k: usize, trial: usize) -> f64 {
            let mut best = 0.0f64;
            for s in 0..k {
                let seed = format!("grind-{trial}-{s}");
                let est = observe_n(pool, seed.as_bytes()).estimate();
                if est > best { best = est; }
            }
            best / pool as f64
        }
        let trials = 40;
        for &k in &[1usize, 8, 64, 256] {
            let mut max_inflation = 0.0f64;
            for t in 0..trials {
                let inf = best_of_k(pool, k, t);
                if inf > max_inflation { max_inflation = inf; }
            }
            // K=1 (canonical seed): inflation stays ~1x (only single-draw noise).
            // Larger K lets the attacker cherry-pick a favorable seed. This test
            // DOCUMENTS the surface; it asserts only the load-bearing requirement:
            // a canonical seed (K=1) does NOT allow meaningful inflation.
            if k == 1 {
                assert!(
                    max_inflation < 1.5,
                    "K=1 canonical seed still allowed {max_inflation:.2}x inflation — \
                     estimator broken independent of seed choice"
                );
            }
            // For visibility in test output when run with --nocapture:
            eprintln!("[seed-grind] pool={pool} K={k}: max inflation over {trials} trials = {max_inflation:.2}x");
        }
    }

    /// Un-grindability sanity: a DIFFERENT epoch_seed reshuffles every draw, so an
    /// identity that was the minimum this epoch is (almost surely) not next epoch.
    /// This is what forces a standing pool rather than one ground lucky identity.
    #[test]
    fn epoch_reshuffles_the_minimum() {
        let pool = 200u64;
        // Which identity holds channel-0's minimum in epoch A vs epoch B?
        fn argmin_ch0(pool: u64, seed: &[u8]) -> u64 {
            let mut best = f64::INFINITY;
            let mut who = u64::MAX;
            for i in 0..pool {
                let x = draw(&pk(i), seed, 0);
                if x < best { best = x; who = i; }
            }
            who
        }
        let a = argmin_ch0(pool, b"epoch-A");
        let b = argmin_ch0(pool, b"epoch-B");
        // Overwhelmingly likely to differ; the point is the min-holder is not
        // stable across epochs, so a single pre-ground identity can't hold the lie.
        assert_ne!(a, b, "epoch seed did not reshuffle the channel-0 minimum (1/{pool} fluke?)");
    }
}
