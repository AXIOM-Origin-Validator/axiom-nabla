//! Contribution emission — the Nabla side (`AXIOM_DESIGN_ValidatorEmission.md`,
//! YP §25.2.4 v2.21.0). Two instances of the airdrop pool gear — one per group
//! so each has its own PoolSync claim count — rolled once per FOB epoch:
//!   share_g(e) = need_g / max(K_g(e−1), 1)      (Core: `emission::share_for_epoch`)
//!   top-up     = the shortfall to need_g, drawn from DEED within its cap
//!              (Core: `emission::top_up`), the ONE legal way a balance rises.
//! Claims come through the airdrop path (`try_claim_amount`: the two cap layers,
//! the JUDOON lattice re-anchored every epoch) and are consume-once per
//! (identity, epoch). Nothing here is a mint: the opening balance is FACT #0 and
//! every top-up is DEED — fee income already paid.

use crate::node::{AirdropPool, ClaimOutcome, DeedPool, PersistedPoolState, ReconcileOutcome};
use axiom_core_logic::emission as core_em;
use axiom_core_logic::types::{FOB_CLAIM_POOL_EMISSION, FOB_CLAIM_POOL_EMISSION_NABLA};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The FOB epoch, real-fund cadence (one clock for fees and emission): a tick
/// COUNT register (`fob_tranche_epoch_duration_ticks`, dev twin 100).
pub fn epoch_ticks() -> u64 {
    crate::constants::fob_epoch_ticks(false).max(1)
}
/// The epoch's wall length. A TARDIS tick VALUE is a unix-second stamp and the
/// register is a COUNT, so the ONE projection (`ticks_to_secs`) sits here and
/// everything else — the boundary, the per-epoch need, the airdrop cycle — reads
/// it (KI#40 class; `fob::epoch_id` still divides VALUE by COUNT — KI#165).
pub fn epoch_secs() -> u64 {
    axiom_core_logic::types::ticks_to_secs(epoch_ticks()).max(1)
}
/// Epoch id of a TARDIS tick: `floor(tick_secs / epoch_secs)` — identical on
/// every node, nobody acts at the same instant.
pub fn epoch_of(tick: u64) -> u64 {
    tick / epoch_secs()
}

/// What one epoch roll did — for the log, the counters and PoolSync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochRoll {
    pub epoch: u64,
    pub share_v: u64,
    pub share_n: u64,
    pub draw_v: u64,
    pub draw_n: u64,
}

#[derive(Debug, Clone)]
pub struct EmissionPools {
    pub validators: AirdropPool,
    pub nabla: AirdropPool,
    pub epoch: u64,
    pub share_v: u64,
    pub share_n: u64,
    /// Lifetime DEED draws per group — the 20 % / 30 % caps are on these.
    pub drawn_v: u64,
    pub drawn_n: u64,
    /// (pool, identity) claimed THIS epoch — one claim per identity per epoch.
    claimed: HashSet<(u8, [u8; 32])>,
    /// `total_claims` of each pool at the last roll — K(e−1) is the delta.
    last_total_v: u64,
    last_total_n: u64,
    // RULE 6 counters (surface on /status).
    pub rolls: u64,
    pub top_up_atoms: u64,
    pub claims_ok: u64,
    pub claims_refused: u64,
    /// KI#193 residual (RULE 3 §2): epoch rolls REFUSED because DEED moved fewer
    /// atoms than requested. A `log::error!` alone is unobservable in
    /// production — "0 refusals" and "never checked" read identically. Non-zero
    /// means the DEED→emission transfer is NOT conserving; the epoch did not roll.
    pub conservation_refusals: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedEmissionState {
    pub validators: PersistedPoolState,
    pub nabla: PersistedPoolState,
    pub epoch: u64,
    pub share_v: u64,
    pub share_n: u64,
    pub drawn_v: u64,
    pub drawn_n: u64,
    pub claimed: Vec<(u8, [u8; 32])>,
    pub last_total_v: u64,
    pub last_total_n: u64,
}

impl PersistedEmissionState {
    pub const FILENAME: &'static str = "emission.state";
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("state.tmp");
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)
    }
    pub fn load(path: &std::path::Path) -> std::io::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        let state: Self = ciborium::from_reader(&bytes[..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Some(state))
    }
}

fn pool_with_caps(p: AirdropPool, initial: u64, share: u64) -> AirdropPool {
    p.with_class_constants(initial, share).with_caps(
        epoch_secs(),
        crate::constants::EMISSION_CLAIMS_PER_EPOCH_PER_NABLA,
        crate::constants::EMISSION_CLAIMS_MESH_CAP_PER_EPOCH,
    )
}

impl EmissionPools {
    /// Fresh from the registers: the FACT #0 opening balance split between the
    /// two groups in the targets' proportion (the only split that is a pure
    /// function of registers). Shares start at `need / launch set` for the
    /// validators and `need` for the (still empty) Nabla set.
    pub fn new_from_registers(opening_atoms: u64) -> Self {
        let need_v = core_em::validator_epoch_need(epoch_secs());
        let need_n = core_em::nabla_epoch_need(epoch_secs());
        let total = (need_v as u128 + need_n as u128).max(1);
        let open_v = (opening_atoms as u128 * need_v as u128 / total) as u64;
        let open_n = opening_atoms - open_v;
        let launch_set = axiom_core_logic::types::COMMUNITY_SUBSIDISED_SLOTS
            + axiom_core_logic::types::FOUNDATION_SUBSIDISED_SLOTS;
        let share_v = core_em::share_for_epoch(need_v, launch_set);
        let share_n = core_em::share_for_epoch(need_n, 0);
        Self {
            validators: pool_with_caps(AirdropPool::new(open_v), open_v, share_v),
            nabla: pool_with_caps(AirdropPool::new(open_n), open_n, share_n),
            epoch: 0, share_v, share_n, drawn_v: 0, drawn_n: 0,
            claimed: HashSet::new(), last_total_v: 0, last_total_n: 0,
            rolls: 0, top_up_atoms: 0, claims_ok: 0, claims_refused: 0, conservation_refusals: 0,
        }
    }

    pub fn to_persisted(&self, tick: u64) -> PersistedEmissionState {
        PersistedEmissionState {
            validators: self.validators.to_persisted(tick),
            nabla: self.nabla.to_persisted(tick),
            epoch: self.epoch, share_v: self.share_v, share_n: self.share_n,
            drawn_v: self.drawn_v, drawn_n: self.drawn_n,
            claimed: self.claimed.iter().copied().collect(),
            last_total_v: self.last_total_v, last_total_n: self.last_total_n,
        }
    }

    pub fn from_persisted(s: &PersistedEmissionState) -> Self {
        let v = AirdropPool::from_persisted(&s.validators);
        let n = AirdropPool::from_persisted(&s.nabla);
        // JUDOON's Layer-1 anchor is the GENESIS OPENING (KI#191: `initial_atoms`
        // never changes; growth is `topped_up`), and the conservation identity is
        //     balance + paid_out == initial_atoms + topped_up.
        // All three right-hand terms are persisted mesh-wide truth, so the opening
        // is recovered EXACTLY. ⚠ WRONG READING, live until 2026-09-24: this passed
        // the bare restored `balance()` as the opening — the same re-anchor the F8
        // fix removed from `roll_epoch` — so after ANY restart with prior claims
        // every peer advertisement failed `IntraSnapshotInconsistent` at every
        // node (~70,000 refusals/node in one day on `ab98b539`), min-wins could
        // never adopt a lower balance, and the pool sat permanently diverged
        // (alpha 7 claims / beta 6 / gamma 5 — `emission.rolls` + `emission.claim`
        // red). Measured from `[JUDOON/POOL-STRUCTURAL] … initial_atoms=<local
        // balance>` on every lagging node.
        let opening = |p: &AirdropPool| p.balance().saturating_add(p.paid_out()).saturating_sub(p.topped_up());
        let (ov, on) = (opening(&v), opening(&n));
        Self {
            validators: pool_with_caps(v, ov, s.share_v),
            nabla: pool_with_caps(n, on, s.share_n),
            epoch: s.epoch, share_v: s.share_v, share_n: s.share_n,
            drawn_v: s.drawn_v, drawn_n: s.drawn_n,
            claimed: s.claimed.iter().copied().collect(),
            last_total_v: s.last_total_v, last_total_n: s.last_total_n,
            rolls: 0, top_up_atoms: 0, claims_ok: 0, claims_refused: 0, conservation_refusals: 0,
        }
    }

    pub fn pool(&self, pool: u8) -> Option<&AirdropPool> {
        match pool {
            FOB_CLAIM_POOL_EMISSION => Some(&self.validators),
            FOB_CLAIM_POOL_EMISSION_NABLA => Some(&self.nabla),
            _ => None,
        }
    }
    fn pool_mut(&mut self, pool: u8) -> Option<&mut AirdropPool> {
        match pool {
            FOB_CLAIM_POOL_EMISSION => Some(&mut self.validators),
            FOB_CLAIM_POOL_EMISSION_NABLA => Some(&mut self.nabla),
            _ => None,
        }
    }
    /// This epoch's share for a pool (0 for an unknown pool).
    pub fn share(&self, pool: u8) -> u64 {
        match pool {
            FOB_CLAIM_POOL_EMISSION => self.share_v,
            FOB_CLAIM_POOL_EMISSION_NABLA => self.share_n,
            _ => 0,
        }
    }
    fn need(pool: u8) -> u64 {
        match pool {
            FOB_CLAIM_POOL_EMISSION => core_em::validator_epoch_need(epoch_secs()),
            FOB_CLAIM_POOL_EMISSION_NABLA => core_em::nabla_epoch_need(epoch_secs()),
            _ => 0,
        }
    }

    /// The epoch roll (§4.1–§4.3): idempotent per epoch, ONE rule every node
    /// applies. Returns what moved when the epoch advanced.
    pub fn maybe_roll(&mut self, tick: u64, deed: &mut DeedPool) -> Option<EpochRoll> {
        let epoch = epoch_of(tick);
        if epoch <= self.epoch || tick == 0 {
            return None;
        }
        let secs = epoch_secs();
        let need_v = core_em::validator_epoch_need(secs);
        let need_n = core_em::nabla_epoch_need(secs);
        // K(e−1): the mesh-wide claim count since the last roll (PoolSync max-wins).
        // The FIRST roll has no previous epoch: K is the launch set from the
        // registers for validators (85 + 5) and 0 (→ one whole share) for the
        // still-empty Nabla set — design §4.1.
        let first = self.epoch == 0;
        let launch_set = axiom_core_logic::types::COMMUNITY_SUBSIDISED_SLOTS
            + axiom_core_logic::types::FOUNDATION_SUBSIDISED_SLOTS;
        let k_v = if first { launch_set } else { self.validators.total_claims.saturating_sub(self.last_total_v) };
        let k_n = if first { 0 } else { self.nabla.total_claims.saturating_sub(self.last_total_n) };
        self.share_v = core_em::share_for_epoch(need_v, k_v);
        self.share_n = core_em::share_for_epoch(need_n, k_n);
        // Top-up: the shortfall only, each group within its DEED draw cap.
        let inflow = deed.total_credited();
        let cap_v = core_em::validator_cap_remaining(inflow, self.drawn_v);
        let cap_n = core_em::nabla_cap_remaining(inflow, self.drawn_n);
        let (draw_v, _) = core_em::top_up(need_v, 0, self.validators.balance(), deed.balance(), cap_v, 0);
        let (_, draw_n) = core_em::top_up(0, need_n, self.nabla.balance(), deed.balance().saturating_sub(draw_v), 0, cap_n);
        // KI#193 (2026-09-16, the owner: "verify the deduction and the increase are
        // equally right. dont just assume") — CREDIT WHAT MOVED, NEVER WHAT WAS
        // ASKED. `DeedPool::draw` returns `amount.min(self.balance)`: it gives
        // less when short and says so in its return value. This used to credit
        // the pools `draw_v`/`draw_n` regardless, with the only guard a
        // `debug_assert_eq!` — compiled OUT of the release binaries every node
        // runs. Short DEED would therefore have meant: DEED loses `moved`, the
        // pools gain the full request, and the difference is atoms created from
        // nothing, silently, in a financial system.
        //
        // It was not reachable when written — `core_em::top_up` caps each draw
        // by its `deed_settled` argument and the caller passes the LIVE
        // `deed.balance()`, so the sum could not exceed it. That is an accident
        // of one argument in another crate, and the design intends to remove it:
        // AXIOM_DESIGN_ValidatorEmission.md §4.3 specifies `deed_settled` as
        // "the DEED balance at a watermark two epochs back" so gossip lag cannot
        // make honest nodes disagree. A watermark CAN exceed the live balance.
        // Implement §4.3 as written with the old code and the mint goes live.
        //
        // So the equality is now enforced HERE, in release, at the transfer:
        // a short draw refuses the whole roll and is returned to the caller.
        // Nothing is credited, nothing is recorded, and the epoch does not
        // advance on a transfer that did not happen in full.
        let requested = draw_v + draw_n;
        let moved = deed.draw(requested, need_v + need_n);
        if moved != requested {
            log::error!(
                "[EMISSION-TOPUP] CONSERVATION REFUSED: DEED moved {} but {} was requested \
                 (draw_v={} draw_n={} deed_balance_after={}) — epoch NOT rolled, pools NOT \
                 credited. The debit and the credit must be equal (KI#193).",
                moved, requested, draw_v, draw_n, deed.balance(),
            );
            // Put back exactly what was taken: the roll is abandoned, so the
            // atoms belong to DEED. `credit` is the inverse of `draw`.
            deed.credit(moved, tick);
            self.conservation_refusals += 1;
            return None;
        }
        self.validators.roll_epoch(tick, draw_v, self.share_v);
        self.nabla.roll_epoch(tick, draw_n, self.share_n);
        self.drawn_v += draw_v;
        self.drawn_n += draw_n;
        self.last_total_v = self.validators.total_claims;
        self.last_total_n = self.nabla.total_claims;
        self.claimed.clear();
        self.epoch = epoch;
        self.rolls += 1;
        self.top_up_atoms += draw_v + draw_n;
        Some(EpochRoll { epoch, share_v: self.share_v, share_n: self.share_n, draw_v, draw_n })
    }

    /// Writer `verify #1` (design §5 rule 1): the attested amount must be THIS
    /// epoch's share from this node's own counter, and the identity must not
    /// have claimed this epoch. Pure check — no state change.
    pub fn check_claim(&self, pool: u8, identity: [u8; 32], amount: u64) -> Result<(), &'static str> {
        if self.pool(pool).is_none() {
            return Err("unknown emission pool");
        }
        if amount == 0 || amount != self.share(pool) {
            return Err("amount is not this epoch's share");
        }
        if self.claimed.contains(&(pool, identity)) {
            return Err("already claimed this epoch");
        }
        Ok(())
    }

    /// The claim itself, after the register committed: the airdrop path (caps,
    /// strict-decrease) plus the (identity, epoch) consume-once.
    pub fn record_claim(&mut self, pool: u8, identity: [u8; 32], amount: u64, tick: u64) -> ClaimOutcome {
        if self.check_claim(pool, identity, amount).is_err() {
            self.claims_refused += 1;
            return ClaimOutcome::RefusedExhausted;
        }
        let outcome = self.pool_mut(pool).map(|p| p.try_claim_amount(tick, amount))
            .unwrap_or(ClaimOutcome::RefusedExhausted);
        if matches!(outcome, ClaimOutcome::Granted) {
            self.claimed.insert((pool, identity));
            self.claims_ok += 1;
        } else {
            self.claims_refused += 1;
        }
        outcome
    }

    /// PoolSync reconcile for an emission pool: roll to the peer's epoch first
    /// (same rule, same inputs), then a peer balance ABOVE ours but within the
    /// group's need is a roll-order difference (its top-up landed before ours),
    /// never a violation; everything else is the airdrop's own reconcile.
    pub fn reconcile(&mut self, pool: u8, peer_balance: u64, peer_claims: u64, peer_paid_out: u64, peer_tick: u64, deed: &mut DeedPool) -> ReconcileOutcome {
        let _ = self.maybe_roll(peer_tick, deed);
        let need = Self::need(pool);
        let Some(p) = self.pool_mut(pool) else { return ReconcileOutcome::NoOp };
        if peer_balance > p.balance() && peer_balance <= need {
            if peer_claims > p.total_claims {
                p.total_claims = peer_claims;
            }
            return ReconcileOutcome::NoOp;
        }
        p.reconcile(peer_balance, peer_claims, peer_paid_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn deed_with(atoms: u64) -> DeedPool {
        let mut d = DeedPool::new();
        d.credit(atoms, 1);
        d
    }

    #[test]
    fn opening_balance_splits_in_target_proportion_and_conserves() {
        let e = EmissionPools::new_from_registers(1_000_000);
        assert_eq!(e.validators.balance() + e.nabla.balance(), 1_000_000);
        assert!(e.nabla.balance() > e.validators.balance(), "185/day > 123.3/day");
        assert_eq!(e.share_v, core_em::validator_epoch_need(epoch_secs()) / 90);
    }

    #[test]
    fn roll_is_idempotent_per_epoch_and_tops_up_only_the_shortfall() {
        let mut e = EmissionPools::new_from_registers(0);
        let mut deed = deed_with(10_000_000_000_000_000); // plenty
        let t = epoch_secs() * 3;
        let r = e.maybe_roll(t, &mut deed).expect("epoch advanced");
        assert_eq!(r.epoch, 3);
        assert_eq!(r.draw_v, core_em::validator_epoch_need(epoch_secs()), "empty pool → the whole need");
        assert_eq!(e.validators.balance(), r.draw_v);
        assert_eq!(r.share_v, r.draw_v / 90, "first epoch: the launch set sets the share");
        assert!(e.maybe_roll(t + 1, &mut deed).is_none(), "same epoch → no second roll");
        // Next epoch with an untouched full pool → nothing moves.
        let r2 = e.maybe_roll(t + epoch_secs(), &mut deed).unwrap();
        assert_eq!((r2.draw_v, r2.draw_n), (0, 0));
        assert_eq!(deed.drawn_total(), r.draw_v + r.draw_n);
    }

    /// KI#193 — THE DEED DEBIT AND THE POOL CREDIT MUST BE EQUAL, to the atom.
    /// The owner, 2026-09-16: "this is a finianical system, 1 atom diff is not
    /// acceptable … the check should verify the deduction and the increase are
    /// equaly right. dont just assume."
    ///
    /// Drives `maybe_roll` across a range of DEED balances — including ones far
    /// below the epoch need, which is the shape that would expose a short draw —
    /// and asserts the exact equality every time:
    ///
    ///     deed_before - deed_after  ==  (validators_after - validators_before)
    ///                                 + (nabla_after      - nabla_before)
    ///
    /// ⚠ This pins the WIRING, not the refusal branch. With today's caller the
    /// refusal is UNREACHABLE — `core_em::top_up` bounds each draw by the LIVE
    /// `deed.balance()`, so `moved` always equals the request, which is exactly
    /// why KI#193 is latent rather than live. When §4.3's "watermark two epochs
    /// back" replaces the live balance, the branch becomes reachable and a test
    /// that DRIVES it must land with that change. Until then this test proves
    /// the property holds; it cannot prove the guard fires.
    #[test]
    fn the_deed_debit_equals_the_pool_credit_to_the_atom() {
        for deed_atoms in [0u64, 1, 1_000, 1_000_000, 10_000_000_000_000_000] {
            let mut e = EmissionPools::new_from_registers(0);
            let mut deed = deed_with(deed_atoms);
            let (dv0, dn0, deed0) =
                (e.validators.balance(), e.nabla.balance(), deed.balance());
            let rolled = e.maybe_roll(epoch_secs(), &mut deed);
            let debited = deed0 - deed.balance();
            let credited = (e.validators.balance() - dv0) + (e.nabla.balance() - dn0);
            assert_eq!(
                debited, credited,
                "deed={deed_atoms}: DEED lost {debited} atoms and the pools gained \
                 {credited} — a transfer that is not equal on both sides MINTS or \
                 BURNS money (KI#193)",
            );
            if let Some(r) = rolled {
                assert_eq!(
                    r.draw_v + r.draw_n, debited,
                    "deed={deed_atoms}: the roll REPORTED a draw that differs from \
                     what DEED actually lost — the accounted inflow feeds JUDOON's \
                     budget (KI#191), so a lie here propagates",
                );
            }
        }
    }

    #[test]
    fn top_up_is_bounded_by_the_deed_draw_cap() {
        let mut e = EmissionPools::new_from_registers(0);
        let mut deed = deed_with(1_000_000); // inflow 1,000,000 → validators may draw 20 %
        let r = e.maybe_roll(epoch_secs(), &mut deed).unwrap();
        assert_eq!(r.draw_v, 200_000);
        assert_eq!(r.draw_n, 300_000);
        assert_eq!(deed.balance(), 500_000, "the developer 50 % never leaves DEED");
    }

    #[test]
    fn claim_is_share_exact_once_per_identity_and_share_follows_last_count() {
        let mut e = EmissionPools::new_from_registers(0);
        let mut deed = deed_with(10_000_000_000_000_000);
        let t = epoch_secs();
        e.maybe_roll(t, &mut deed).unwrap();
        let share = e.share(FOB_CLAIM_POOL_EMISSION);
        let id = [7u8; 32];
        assert!(e.check_claim(FOB_CLAIM_POOL_EMISSION, id, share + 1).is_err(), "wrong amount");
        assert_eq!(e.record_claim(FOB_CLAIM_POOL_EMISSION, id, share, t + 1), ClaimOutcome::Granted);
        assert!(e.check_claim(FOB_CLAIM_POOL_EMISSION, id, share).is_err(), "second claim same epoch");
        assert_eq!(e.record_claim(FOB_CLAIM_POOL_EMISSION, [8u8; 32], share, t + 2), ClaimOutcome::Granted);
        assert_eq!(e.claims_ok, 2);
        // Two claimants last epoch → next epoch's share is need / 2.
        e.maybe_roll(t + epoch_secs(), &mut deed).unwrap();
        assert_eq!(e.share(FOB_CLAIM_POOL_EMISSION), core_em::validator_epoch_need(epoch_secs()) / 2);
        // The JUDOON lattice must still hold for this node's OWN snapshot after a
        // roll that follows claims (live gate #2: it did not — every peer went
        // into probation). A peer advertising exactly this state is consistent.
        assert_eq!(crate::judoon::structural_violation(
            e.validators.balance(), e.validators.total_claims, e.validators.paid_out(), &e.validators), None,
            "the re-anchored lattice must accept the node's own post-roll snapshot");
        // And a claim in the NEW epoch keeps it consistent.
        let s2 = e.share(FOB_CLAIM_POOL_EMISSION);
        assert_eq!(e.record_claim(FOB_CLAIM_POOL_EMISSION, [9u8; 32], s2, t + epoch_secs() + 1), ClaimOutcome::Granted);
        assert_eq!(crate::judoon::structural_violation(
            e.validators.balance(), e.validators.total_claims, e.validators.paid_out(), &e.validators), None);
        assert!(e.check_claim(FOB_CLAIM_POOL_EMISSION, id, e.share(FOB_CLAIM_POOL_EMISSION)).is_ok(), "new epoch, may claim again");
    }

    /// A RESTART must re-anchor JUDOON's lattice at the genesis opening, not at
    /// the bare restored balance (KI#191 identity `balance + paid_out ==
    /// initial + topped_up`). Live 2026-09-24: after the 00:55 restart every
    /// node refused every peer's emission advertisement as
    /// `IntraSnapshotInconsistent` (~70k/node) and the pool never converged.
    /// Red on the old `from_persisted` (opening = balance): the restored pool
    /// rejects its OWN snapshot and cannot adopt a peer that saw one more claim.
    #[test]
    fn restart_re_anchors_the_lattice_at_the_genesis_opening_not_the_bare_balance() {
        let mut e = EmissionPools::new_from_registers(0);
        let mut deed = deed_with(10_000_000_000_000_000);
        let t = epoch_secs();
        e.maybe_roll(t, &mut deed).unwrap();
        let share = e.share(FOB_CLAIM_POOL_EMISSION);
        assert_eq!(e.record_claim(FOB_CLAIM_POOL_EMISSION, [1u8; 32], share, t + 1), ClaimOutcome::Granted);
        assert_eq!(e.record_claim(FOB_CLAIM_POOL_EMISSION, [2u8; 32], share, t + 2), ClaimOutcome::Granted);
        assert!(e.validators.paid_out() > 0 && e.validators.topped_up() > 0, "claims and a top-up on record");

        // Persist + restore, as a node restart does.
        let r = EmissionPools::from_persisted(&e.to_persisted(t + 3));
        assert_eq!(r.validators.balance(), e.validators.balance());
        assert_eq!(r.validators.paid_out(), e.validators.paid_out());
        assert_eq!(r.validators.topped_up(), e.validators.topped_up());
        // The restored node accepts its OWN advertisement (the identity holds).
        assert_eq!(crate::judoon::structural_violation(
            r.validators.balance(), r.validators.total_claims, r.validators.paid_out(), &r.validators), None,
            "a restart must not make the node's own snapshot look inconsistent");

        // A peer that granted ONE MORE claim (lower balance, higher paid_out) is
        // structurally consistent and min-wins ADOPTS it — that is how a missed
        // claim converges mesh-wide.
        let mut r2 = r;
        let mut peer = EmissionPools::from_persisted(&e.to_persisted(t + 3));
        assert_eq!(peer.record_claim(FOB_CLAIM_POOL_EMISSION, [3u8; 32], share, t + 4), ClaimOutcome::Granted);
        let out = r2.reconcile(FOB_CLAIM_POOL_EMISSION, peer.validators.balance(), peer.validators.total_claims,
                               peer.validators.paid_out(), t + 4, &mut deed);
        assert!(!matches!(out, ReconcileOutcome::StructuralViolation { .. }),
                "a consistent lower peer balance must not be refused after a restart: {out:?}");
        assert_eq!(r2.validators.balance(), peer.validators.balance(), "min-wins adopted the missed claim");
        assert_eq!(r2.validators.total_claims, peer.validators.total_claims);
    }

    #[test]
    fn peer_ahead_by_a_roll_is_tolerated_and_deed_tolerates_the_draw() {
        let mut a = EmissionPools::new_from_registers(0);
        let mut deed_a = deed_with(10_000_000_000_000_000);
        let t = epoch_secs();
        let r = a.maybe_roll(t, &mut deed_a).unwrap();
        // A fresh node that has not rolled receives A's advertisement.
        let mut b = EmissionPools::new_from_registers(0);
        let mut deed_b = deed_with(10_000_000_000_000_000);
        let out = b.reconcile(FOB_CLAIM_POOL_EMISSION, r.draw_v, 0, 0, t, &mut deed_b);
        assert!(!matches!(out, ReconcileOutcome::StructuralViolation { .. }), "{out:?}");
        assert_eq!(b.validators.balance(), r.draw_v, "B rolled to A's epoch by the same rule");
        // DEED: a peer lower by the draw is order, not loss.
        let mut d = deed_with(10_000_000_000_000_000);
        let _ = d.draw(1_000, 5_000);
        assert!(matches!(d.reconcile(d.balance() - 4_000, d.total_credited()), ReconcileOutcome::NoOp));
        assert!(matches!(d.reconcile(d.balance() - 6_000, d.total_credited()), ReconcileOutcome::InvariantViolation { .. }));
    }
}
