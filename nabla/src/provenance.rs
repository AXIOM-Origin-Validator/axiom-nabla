//! Fork Settlement W7c/W7d (MINIMAL) — the DERIVED provenance verdict.
//!
//! Plan: `docs/handoff_forksettlement/plan_w7cd_minimal.md` §2; rulings
//! `docs/AXIOM_DESIGN_ForkSettlement.md` §9k. The ONE Nabla signature that can
//! make tainted money look clean in Core is the txid attestation's ORIGIN
//! VOUCH (`NablaNode::origin_vouch` → `sign_txid_attestation`): a door
//! confirmation never clears inherited taint (`fact.rs` `link_is_resolved`)
//! nor the cheque's own origin (R52a). So this module decides ONE thing — may
//! this node vouch for a send's origin — from its OWN records, transitively to
//! a structural root:
//!
//! - **M1 derived vouch** — `judge_send`: a send is vouchable only if its
//!   input state's verdict is OK; the answer carries the ancestry's
//!   `ready_at` (the youngest ancestor's first sight), so Core's settle floor
//!   runs from the LATEST hop, not only this one.
//! - **M2 transitive grounding** — a state is judged only if every ancestor's
//!   producer is recorded HERE (a missing producer ⇒ no verdict ⇒ WAIT, never
//!   OK); a producer must be state-bound (R52d) and witnessed by directory
//!   witnesses only (R42 — else a junk-witnessed send could "produce" the
//!   state of a hidden redeem, TLA+ c12).
//! - **M3 retroactive re-derivation** — a second leg under a key re-queues
//!   every leg under it; a changed state re-queues its consumers (and a send
//!   the redeems of its cheque). Drained under a visit budget; while work is
//!   queued the node vouches NOTHING (fail closed). No latch: a late fork
//!   re-holds everything descended from the forked parent (ruling 3, c19);
//!   states before it are never touched (c19 `NoFalseHold`).
//! - **M4 burn exit** — a recorded send to `BURN_ADDRESS` whose k-bound
//!   amount equals ONE held/pending receive's amount removes that receive's
//!   root from the post-burn state (ruling 2). A fork root is unburnable.
//!   The receive's amount is the cheque's GROSS amount from the origin the
//!   redeem leg CARRIES (KI#241 F-2), so the exit opens even when the sender
//!   never registered here. An [`Root::Overflow`] collapse keeps a value
//!   LEDGER (`owed`, KI#241 F-9) that each burn pays down; it releases at 0.
//!
//! Roots are structural: the wallet's opening (genesis) state, or its UNIQUE
//! zero-consumed first redeem (F8 — two of them ground neither).
//!
//! Nothing is persisted (plan C6): the verdicts are re-derived at `open`
//! with no budget, before the node listens. Nothing is refused and nothing is
//! pushed to a wallet (RULE 5, ruling 3): the hold is discovered at the next
//! Nabla interaction (the register ack's `provenance`, a withheld vouch).
//!
//! RULE 5: Nabla HYGIENE. A hostile Nabla vouches anything — the defence
//! that holds regardless is Core's: inherited taint clears ONLY on a settled
//! vouch (`fact::origin_settled_link`), and an honest receiver's SDK accepts
//! "settled" only when ≥2 answers agree (R21 as ruled, §9k.2). This module
//! makes an HONEST node never be the one that launders.
//!
//! Pure CPU over hash maps — no I/O, no crypto, nothing blocks: safe under
//! the node mutex.

use std::collections::{HashMap, VecDeque};

use crate::smt::{LegRef, OriginKey, SparseMerkleTree};
use crate::types::{ForkLeg, OriginLedgerEntry, ProvenanceView, StateId, TxHash};

/// More roots than this on one state collapse into ONE [`Root::Overflow`]
/// (residual C7). DELIBERATELY NOT RAISED (owner ruling 2026-10-01): it bounds
/// the work per derivation against deliberately long FACT chains.
///
/// ✅ FIXED IN SOURCE 2026-10-01 (KI#241 F-9, Fable review, not deployed): was
/// "an `Overflow` state has NO Nabla-side exit by definition". The collapse
/// now keeps a value LEDGER — `Overflow { owed: Some(Σ) }`, the k-bound total
/// of the folded receives — that every exact `BURN_ADDRESS` burn pays down
/// (O(1): one compare + subtract), and the root is removed at 0. `owed: None`
/// (a FORK root was folded) stays unburnable, as before. Core's half: the
/// `BURN_ADDRESS`+target burn is now depth-exempt (`validation.rs` Step 0b',
/// F-9.4), so such a burn can land on a > `max_fact_links` chain. Pending
/// roots that collapse become HELD (as before); the wallet may wait — a
/// sender registering later re-derives the ancestor below the cap and the
/// Overflow disappears by itself (a pure function of the records) — or burn.
pub const ROOTS_MAX: usize = 32;

/// Cascade visits per budgeted drain (plan §2 "Cost bound"). The remainder is
/// drained on the next call — every register / gossip / AE drain and the
/// binary's per-message + per-tick `fork_ban_fanout`.
pub const CASCADE_BUDGET: usize = 4096;

/// Why a state is not clean.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Root {
    /// The leg that produced the state (or an ancestor) sits under a
    /// `(pk, consumed)` key carrying ≥ 2 legs — a fork. HELD, unburnable.
    Fork(OriginKey),
    /// More than [`ROOTS_MAX`] roots, folded — HELD. `owed` is the burn LEDGER
    /// (KI#241 F-9): `Some(Σ)` = the k-bound gross amounts of every folded
    /// receive (+ any folded ledger), paid down by each `BURN_ADDRESS` burn
    /// that matches no individual receive, removed at 0; `None` = a fork was
    /// folded (or the sum overflowed u64) — unburnable.
    Overflow { owed: Option<u64> },
    /// A receive of `cheque` whose origin is HELD (`held`) or not yet
    /// judgeable here (`!held` ⇒ WAIT). `amount` is the cheque's GROSS
    /// amount from the origin the redeem leg carries (KI#241 F-2: k-bound by
    /// txid recomputation at the door / flood / AE — always known, even when
    /// the sender never registered here; was `Option`, `None` in that case,
    /// which left the burn exit unreachable).
    Receive { cheque: TxHash, amount: u64, held: bool },
}

impl Root {
    fn is_held(&self) -> bool {
        !matches!(self, Root::Receive { held: false, .. })
    }
}

/// The verdict of one `(pk, state)`: its roots (empty = OK) and the youngest
/// ancestor's first sight (`first_seen_secs`, wall clock [R13]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateVerdict {
    pub roots: Vec<Root>,
    pub ready_at: u64,
}

/// The judgment of a SEND (may this node vouch its origin?).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Judgment {
    /// Vouchable; `ready_at` = max(ancestry first sight, the send's own).
    Ok { ready_at: u64 },
    /// Not judgeable yet (a gap / a pending receive / contested) — WAIT.
    Wait,
    /// Descends from a fork or a held receive — never vouched.
    Held,
}

/// The engine. Owned by `NablaNode`; fed by `SparseMerkleTree::
/// take_provenance_pending` in `drain_fork_side_effects`.
#[derive(Debug, Default)]
pub struct Provenance {
    verdict: HashMap<([u8; 32], StateId), StateVerdict>,
    dirty: VecDeque<(OriginKey, LegRef)>,
    /// Legs refused as producers ONLY because a witness is not (yet) in the
    /// directory — re-queued when the directory admits an entry.
    awaiting_directory: Vec<(OriginKey, LegRef)>,
    /// Cumulative derivation visits (`/status provenance_states_derived`).
    states_derived: u64,
    /// Gauge — states whose verdict carries a HELD root
    /// (`/status provenance_held_states`).
    held_states: u64,
}

enum Derived {
    /// Not a producer of its state (unbound, or a non-directory witness):
    /// the state's verdict is left untouched.
    NotProducer { awaiting_directory: bool },
    /// Producer, but its input is ungrounded here: the state has no verdict.
    Ungrounded,
    Verdict(StateVerdict),
}

impl Provenance {
    /// Queue legs for (re-)derivation.
    pub fn enqueue(&mut self, work: Vec<(OriginKey, LegRef)>) {
        self.dirty.extend(work);
    }

    /// Re-queue the legs that waited on a directory witness (called when the
    /// directory admits an entry).
    pub fn requeue_awaiting_directory(&mut self) {
        let w = std::mem::take(&mut self.awaiting_directory);
        self.dirty.extend(w);
    }

    /// Queue length (`/status provenance_dirty_queue`). Non-zero ⇒ the node
    /// vouches nothing (fail closed).
    pub fn dirty_len(&self) -> usize {
        self.dirty.len()
    }

    pub fn states_derived(&self) -> u64 {
        self.states_derived
    }

    pub fn held_states(&self) -> u64 {
        self.held_states
    }

    /// Drain up to `budget` visits (`None` = until empty — the load-time
    /// re-derivation). `is_witness` is the R42 directory query.
    pub fn drain(
        &mut self,
        smt: &SparseMerkleTree,
        is_witness: &dyn Fn(&[u8; 32]) -> bool,
        budget: Option<usize>,
    ) {
        let mut left = budget.unwrap_or(usize::MAX);
        while left > 0 {
            let Some((key, member)) = self.dirty.pop_front() else { break };
            left -= 1;
            self.visit(smt, is_witness, key, member);
        }
    }

    fn visit(
        &mut self,
        smt: &SparseMerkleTree,
        is_witness: &dyn Fn(&[u8; 32]) -> bool,
        key: OriginKey,
        member: LegRef,
    ) {
        self.states_derived = self.states_derived.saturating_add(1);
        let Some(rec) = smt.leg_record(&key, &member) else { return };
        // A re-judged send changes what its cheque's redeems see (legV).
        if let LegRef::Send(t) = member {
            for (k, _) in smt.redeem_records_of_cheque(&t) {
                self.dirty.push_back((k, LegRef::Redeem(t)));
            }
        }
        let x = (key.0, rec.leg.new_state);
        let new = match self.derive(smt, is_witness, &key, rec) {
            Derived::NotProducer { awaiting_directory } => {
                if awaiting_directory {
                    self.awaiting_directory.push((key, member));
                }
                return;
            }
            Derived::Ungrounded => None,
            Derived::Verdict(v) => Some(v),
        };
        let old = self.verdict.get(&x);
        if old == new.as_ref() {
            return;
        }
        let was_held = old.is_some_and(|v| v.roots.iter().any(Root::is_held));
        let is_held = new.as_ref().is_some_and(|v| v.roots.iter().any(Root::is_held));
        match new {
            Some(v) => { self.verdict.insert(x, v); }
            None => { self.verdict.remove(&x); }
        }
        match (was_held, is_held) {
            (false, true) => self.held_states += 1,
            (true, false) => self.held_states = self.held_states.saturating_sub(1),
            _ => {}
        }
        // The state changed: every leg that consumed it is re-judged.
        for m in smt.legs_under(&x) {
            self.dirty.push_back((x, m));
        }
    }

    /// The input verdict of a leg `pk: consumed → …` — a structural root, or
    /// the memoized verdict of `consumed`. `None` = ungrounded here.
    fn input(&self, smt: &SparseMerkleTree, key: &OriginKey, leg: &ForkLeg) -> Option<StateVerdict> {
        let (pk, consumed) = key;
        let root = StateVerdict { roots: Vec::new(), ready_at: 0 };
        // The wallet's opening state (§6c — the ONE builder every layer uses).
        if *consumed
            == axiom_core_logic::genesis::opening_state_id_for(
                pk,
                leg.k_tier(),
                axiom_core_logic::wallet_id::PROOF_TYPE_DMAP,
            )
        {
            return Some(root);
        }
        if *consumed == [0u8; 32] {
            // F8: a fresh wallet's first receive grounds iff it is the ONLY
            // zero-consumed redeem recorded for this pk (order-independent).
            let is_redeem = leg.redeem_preimage().is_some();
            return (is_redeem && smt.zero_redeem_count(pk) == 1).then_some(root);
        }
        self.verdict.get(&(*pk, *consumed)).cloned()
    }

    fn derive(
        &self,
        smt: &SparseMerkleTree,
        is_witness: &dyn Fn(&[u8; 32]) -> bool,
        key: &OriginKey,
        rec: &OriginLedgerEntry,
    ) -> Derived {
        let leg = &rec.leg;
        // 1. Producer admission: the produced state is k-bound (R52d) AND every
        //    witness is a directory witness (R42 — c12).
        if !crate::ban::leg_is_state_bound(leg) {
            return Derived::NotProducer { awaiting_directory: false };
        }
        //    ONE predicate with the record trie's grade (`ban::
        //    leg_is_directory_witnessed`, W1 — RULE 1).
        if !crate::ban::leg_is_directory_witnessed(leg, is_witness) {
            return Derived::NotProducer { awaiting_directory: true };
        }
        // 2. Base input.
        //
        // ── RULE 0 §4 marker (ForkSettlement §9r F-6 (b), 2026-10-02) ──
        // WRONG reading: "Core's inherited-scar set carries a fork's taint to
        //   every descendant, so this engine only has to agree with it." It does
        //   not: `fact::compute_inherited_scar_txids` SKIPS a `required_k == 0`
        //   (Ark offline) link AND the txids it carries, so Core's set is not
        //   transitive across an Ark hop (YPX-001 §1.5.1a "Consequence of the Ark
        //   carve-out").
        // RIGHT reading: past such a hop the ONLY carrier of the taint is THIS
        //   step. An offline (k=0) state is produced by no record here, so a leg
        //   consuming it has no input verdict ⇒ `Ungrounded` ⇒ no verdict ⇒ every
        //   send descended from it judges WAIT — never OK, never vouched (fail
        //   closed; pinned by `w7c_hidden_redeem_is_wait_never_ok`). Never treat
        //   an absent input as a root (`unwrap_or(root)` is the named mutation).
        //   The same holds for a zero-pk GROUP wallet (no record — KI#255).
        let Some(input) = self.input(smt, key, leg) else { return Derived::Ungrounded };
        let mut roots = input.roots;
        let mut ready_at = input.ready_at.max(rec.first_seen_secs);
        // 3. The leg's own key forked.
        if smt.legs_under(key).len() >= 2 {
            roots.push(Root::Fork(*key));
        }
        // 4. A redeem inherits its cheque's judgment. KI#241 F-2: the amount
        //    is the GROSS cheque amount the leg CARRIES (`cheque_origin`,
        //    bound to the k-signed `cheque_txid` by `cheque_origin_matches`
        //    on every recording path) — not a lookup of the sender's record,
        //    which a never-registering sender leaves empty. If the sender's
        //    record exists its amount is equal (same txid ⇒ same preimage,
        //    BLAKE3 collision resistance).
        if let (Some(p), Some(origin)) = (leg.redeem_preimage(), leg.cheque_origin()) {
            let t = p.cheque_txid;
            let amount = origin.preimage.amount;
            debug_assert!(smt
                .vouch_record(&t)
                .and_then(|e| e.leg.send_preimage().map(|w| w.amount))
                .is_none_or(|a| a == amount));
            match self.judge_send(smt, &t) {
                Judgment::Held => roots.push(Root::Receive { cheque: t, amount, held: true }),
                Judgment::Wait => roots.push(Root::Receive { cheque: t, amount, held: false }),
                Judgment::Ok { ready_at: r } => ready_at = ready_at.max(r),
            }
        }
        roots.sort();
        roots.dedup();
        // 5. M4 burn exit: a burn of EXACTLY a receive's amount clears ONE
        //    such root (the lowest cheque txid — `burn_target_tx_id` is
        //    unsigned and not on the record; equal amounts are equal value).
        //    Else (KI#241 F-9) it pays down an `Overflow` ledger it does not
        //    exceed (Core: "no overpayment"), removing it at 0. Each burn is
        //    credited ONCE (a root or the ledger), so Σ credited = Σ burned.
        //    ✅ FIXED IN SOURCE 2026-10-01 (KI#241 F-2): was "`amount` is
        //    `None` while the cheque's SEND is unrecorded here, so no burn
        //    ever matches" — the amount now rides the redeem leg (step 4).
        //    The burn must be the YPX-001 §1.5.4 shape (`receiver ==
        //    BURN_ADDRESS`, only `receiver_wallet_id` is k-bound here): the
        //    SDK's `burn_scars` emits it since F-2b (2026-10-01).
        if let Some(w) = leg.send_preimage() {
            if w.receiver_wallet_id == axiom_core_logic::types::BURN_ADDRESS {
                if let Some(i) = roots
                    .iter()
                    .position(|r| matches!(r, Root::Receive { amount, .. } if *amount == w.amount))
                {
                    roots.remove(i);
                } else if let Some(i) = roots
                    .iter()
                    .position(|r| matches!(r, Root::Overflow { owed: Some(o) } if w.amount <= *o))
                {
                    if let Root::Overflow { owed: Some(o) } = roots[i] {
                        let rest = o - w.amount;
                        if rest == 0 {
                            roots.remove(i);
                        } else {
                            roots[i] = Root::Overflow { owed: Some(rest) };
                        }
                    }
                }
            }
        }
        if roots.len() > ROOTS_MAX {
            roots = vec![Root::Overflow { owed: overflow_ledger(&roots) }];
        }
        Derived::Verdict(StateVerdict { roots, ready_at })
    }

    /// legV — may this node vouch the origin of send `t` (M1)? From its own
    /// records only: no record / contested / an ungrounded input ⇒ WAIT; the
    /// send's key forked or its input HELD ⇒ HELD.
    pub fn judge_send(&self, smt: &SparseMerkleTree, t: &TxHash) -> Judgment {
        let Some(e) = smt.vouch_record(t) else { return Judgment::Wait };
        if e.contested {
            return Judgment::Wait;
        }
        let key = e.leg.key();
        if smt.legs_under(&key).len() >= 2 {
            return Judgment::Held;
        }
        let Some(input) = self.input(smt, &key, &e.leg) else { return Judgment::Wait };
        match judge_roots(&input.roots) {
            Some(j) => j,
            None => Judgment::Ok { ready_at: input.ready_at.max(e.first_seen_secs) },
        }
    }

    /// The register ack's `provenance` for the registrant's new state (W7d,
    /// UX only — ruling 1: a held state is ACCEPTED and MARKED, never
    /// refused). Queued work ⇒ `Wait` (fail closed, like the vouch).
    pub fn view(&self, pk: &[u8; 32], state: &StateId) -> ProvenanceView {
        if !self.dirty.is_empty() {
            return ProvenanceView::Wait;
        }
        let Some(v) = self.verdict.get(&(*pk, *state)) else { return ProvenanceView::Wait };
        match judge_roots(&v.roots) {
            None => ProvenanceView::Ok,
            Some(Judgment::Wait) => ProvenanceView::Wait,
            Some(_) => ProvenanceView::Held(
                v.roots
                    .iter()
                    .filter_map(|r| match r {
                        Root::Receive { cheque, held: true, .. } => Some(*cheque),
                        _ => None,
                    })
                    .collect(),
            ),
        }
    }

    /// The memoized verdict of `(pk, state)` (tests / diagnostics).
    pub fn verdict_of(&self, pk: &[u8; 32], state: &StateId) -> Option<&StateVerdict> {
        self.verdict.get(&(*pk, *state))
    }
}

/// The `owed` of an [`Root::Overflow`] collapse (KI#241 F-9): Σ of every
/// folded receive's gross amount and every folded ledger; `None` if any folded
/// root is a fork or an unburnable ledger (or the sum overflows). Order-free
/// — the collapse stays a pure function of the records (M3 reproduces it).
fn overflow_ledger(roots: &[Root]) -> Option<u64> {
    roots.iter().try_fold(0u64, |acc, r| match r {
        Root::Receive { amount, .. } => acc.checked_add(*amount),
        Root::Overflow { owed: Some(o) } => acc.checked_add(*o),
        Root::Overflow { owed: None } | Root::Fork(_) => None,
    })
}

/// Any HELD root ⇒ Held; else any pending ⇒ Wait; else `None` (OK).
fn judge_roots(roots: &[Root]) -> Option<Judgment> {
    if roots.iter().any(Root::is_held) {
        Some(Judgment::Held)
    } else if roots.is_empty() {
        None
    } else {
        Some(Judgment::Wait)
    }
}

/// Fork Settlement W7c/W7d — the plan §5 tests, node-level with REAL keys:
/// every leg is a genuine k-witnessed, wallet-signed leg from the ONE test
/// builder (`types::test_legs`), recorded through the ONE creation point
/// (`record_verified_leg`, what the door / flood / AE / ForkBan paths call)
/// and derived through the production drain. Each names its TLA+ case and the
/// mutation that must turn it RED (RULE 6 §3a).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{wave3_hook_tests, NablaNode, OriginVouch};
    use crate::types::test_legs::{self, NOW_SECS};
    use crate::types::{ForkLeg, ProvenanceView};
    use ed25519_dalek::SigningKey;

    const P: &str = "p@axiom.internal/0123456789";
    const Q: &str = "q@axiom.internal/0123456789";
    const R: &str = "r@axiom.internal/0123456789";

    /// A node whose R42 directory holds the test witnesses.
    fn node() -> NablaNode {
        let mut n = NablaNode::new();
        n.admit_test_validators();
        n
    }

    fn w(seed: u8) -> SigningKey {
        test_legs::wallet(seed)
    }

    fn pk(seed: u8) -> [u8; 32] {
        w(seed).verifying_key().to_bytes()
    }

    fn send(seed: u8, consumed: StateId, seq: u64, to: &str, amount: u64, nonce: u64) -> ForkLeg {
        test_legs::genuine_send_leg(&w(seed), consumed, seq, to, amount, nonce, 3)
    }

    fn redeem(seed: u8, consumed: StateId, cheque: &ForkLeg, balance: u64) -> ForkLeg {
        test_legs::genuine_redeem_leg(&w(seed), consumed, &test_legs::origin_of(cheque), balance, 1, 3)
    }

    /// Record through the ONE record hook the door / flood / AE paths call
    /// (`ban::record_leg_and_detect` — a second leg under a key is a verdict),
    /// then the production drain.
    fn rec(n: &mut NablaNode, leg: &ForkLeg, now: u64) {
        assert!(crate::ban::verify_fork_leg(leg.clone()).is_ok(), "a genuine leg verifies");
        n.record_leg_for_test(leg.clone(), now);
    }

    fn vouched(n: &NablaNode, t: &ForkLeg) -> bool {
        n.origin_vouch(&t.tx_hash, Some(NOW_SECS)).origin.is_some()
    }

    /// The colluder chain: A forks ta/tb from its opening state; Q redeems
    /// tb; Q → Q2 (t_qq2); Q2 redeems; Q2 → R (t_q2r).
    struct Chain { ta: ForkLeg, tb: ForkLeg, rho_q: ForkLeg, t_qq2: ForkLeg, rho_q2: ForkLeg, t_q2r: ForkLeg }

    fn chain() -> Chain {
        let a0 = test_legs::opening(&w(0x61));
        let ta = send(0x61, a0, 1, P, 100, 1);
        let tb = send(0x61, a0, 1, Q, 100, 2);
        let rho_q = redeem(0x62, test_legs::opening(&w(0x62)), &tb, 100);
        let t_qq2 = send(0x62, rho_q.new_state, 1, "q2@axiom.internal/0123456789", 60, 1);
        let rho_q2 = redeem(0x63, test_legs::opening(&w(0x63)), &t_qq2, 60);
        let t_q2r = send(0x63, rho_q2.new_state, 1, R, 20, 1);
        Chain { ta, tb, rho_q, t_qq2, rho_q2, t_q2r }
    }

    /// KI#232 repro (live 2026-09-29, ypx001 step [5]): A sends #1 then #2
    /// with BOTH registers failed; B redeems #2; only THEN does A register #1
    /// and #2 late. Every honest node must vouch #2 once its grounding is
    /// known — the order the records arrive in cannot change the verdict.
    #[test]
    fn ki232_late_origin_after_redeem_is_vouched() {
        let a0 = test_legs::opening(&w(0x71));
        let t1 = send(0x71, a0, 1, Q, 100, 1);
        let t2 = send(0x71, t1.new_state, 2, Q, 50, 2);
        let rho = redeem(0x72, test_legs::opening(&w(0x72)), &t2, 50);

        let mut natural = node();
        for l in [&t1, &t2, &rho] {
            rec(&mut natural, l, NOW_SECS);
        }
        assert!(vouched(&natural, &t1) && vouched(&natural, &t2), "control: natural order vouches both");

        let mut late = node();
        for l in [&rho, &t1, &t2] {
            rec(&mut late, l, NOW_SECS);
        }
        assert!(vouched(&late, &t1), "#1 vouched after the late registration");
        assert_eq!(late.provenance().judge_send(late.smt(), &t2.tx_hash),
            natural.provenance().judge_send(natural.smt(), &t2.tx_hash),
            "late order must judge #2 exactly as the natural order");
        assert!(vouched(&late, &t2), "#2 (the redeemed cheque's origin) vouched after the late registration");
    }

    /// c17/c17e NoHonestClean — two hops downstream of a fork leg, an honest
    /// node vouches NOTHING. Non-vacuity: with only tb recorded (no fork
    /// known) the SAME chain is vouched end to end.
    /// MUTATION (run 2026-09-28): `judge_send` returns `Ok` whenever the
    /// send's OWN key is unforked (drop the input-roots judgment — one hop)
    /// ⇒ t_qq2 vouched ⇒ RED.
    #[test]
    fn w7c_two_hop_colluder_never_vouched() {
        let c = chain();
        let mut clean = node();
        for l in [&c.tb, &c.rho_q, &c.t_qq2, &c.rho_q2, &c.t_q2r] {
            rec(&mut clean, l, NOW_SECS);
        }
        assert!(vouched(&clean, &c.t_qq2) && vouched(&clean, &c.t_q2r), "control: no fork known ⇒ vouched");

        let mut n = node();
        for l in [&c.ta, &c.tb, &c.rho_q, &c.t_qq2, &c.rho_q2, &c.t_q2r] {
            rec(&mut n, l, NOW_SECS);
        }
        assert!(n.smt().origin_key_is_held(&c.ta.key()), "fixture: the fork is in the records");
        for t in [&c.ta, &c.tb, &c.t_qq2, &c.t_q2r] {
            // §9p: not merely withheld — signed HELD, the two-hop laundered
            // origins included (KI#221 residual 1).
            assert_eq!(n.origin_vouch(&t.tx_hash, Some(NOW_SECS)), OriginVouch::HELD,
                "an honest node did not sign HELD for {} downstream of a fork", hex::encode(&t.tx_hash[..4]));
        }
        assert!(n.origin_status(None, 0).provenance_held_states >= 3, "Q, Q's send, Q2 all HELD");
    }

    // ── ForkSettlement §9r (F-6 path 11, owner ruling 2026-10-02) — a held
    //    redeem's validator fee slots / DEED slice are PARKED, credited once
    //    when the cheque judges Ok, never while held. Real door path
    //    (`NablaNode::register` → `process_registration` 8c → park/release).

    /// A genuine redeem register carrying 3 × 10-atom fee slots (the
    /// receiver-pays signal Nabla derives from `slot_amount`).
    fn fee_redeem_reg(leg: &ForkLeg) -> (crate::types::Registration, crate::types::DeedTransaction) {
        let (mut reg, deed) = test_legs::registration_of(leg);
        for (i, ws) in reg.receipt.signatures.iter_mut().enumerate() {
            ws.slot_amount = 10;
            ws.validator_id = [0x11 + i as u8; 32];
        }
        (reg, deed)
    }

    /// Σ DEED credited, either class (the routing is tested in registration.rs).
    fn deed_credited(n: &NablaNode) -> u64 {
        n.deed_pool.total_credited() + n.dev_deed_pool.total_credited()
    }

    fn register(n: &mut NablaNode, reg: &crate::types::Registration, deed: &crate::types::DeedTransaction, now: u64) {
        n.register(reg, deed, now).expect("ruling 1: the register is ACCEPTED");
    }

    /// Honest: the cheque's send is recorded and clean ⇒ the redeem's fees
    /// are credited at once, exactly ONCE (a lost-ACK retry and later drains
    /// credit nothing more).
    /// MUTATION: `release_held_fee_credits` requires `Judgment::Held` instead
    /// of `Ok` ⇒ nothing credited ⇒ RED.
    #[test]
    fn fee_credit_honest_redeem_credited_once() {
        let a0 = test_legs::opening(&w(0x81));
        let t = send(0x81, a0, 1, Q, 100, 1);
        let rho = redeem(0x82, test_legs::opening(&w(0x82)), &t, 100);
        let mut n = node();
        let (sreg, sdeed) = test_legs::registration_of(&t);
        register(&mut n, &sreg, &sdeed, NOW_SECS);
        let (reg, deed) = fee_redeem_reg(&rho);
        register(&mut n, &reg, &deed, NOW_SECS + 1);
        assert_eq!(deed_credited(&n), 3, "10% of 30 atoms credited for an honest redeem");
        let st = n.origin_status(None, 0);
        assert_eq!((st.fee_credits_held, st.fee_credits_parked, st.fee_credits_released), (0, 1, 1));
        let _ = n.register(&reg, &deed, NOW_SECS + 2); // lost-ACK retry
        n.drain_fork_side_effects();
        assert_eq!(deed_credited(&n), 3, "credited exactly once");
    }

    /// Held: the cheque is one leg of a FORK ⇒ the redeem is ACCEPTED (ruling
    /// 1) but its fees are parked and NEVER credited, however often the node
    /// drains.
    /// MUTATION: credit the parked value in `NablaNode::register` regardless
    /// of the verdict (drop the park) ⇒ RED.
    #[test]
    fn fee_credit_held_redeem_never_credited() {
        let a0 = test_legs::opening(&w(0x83));
        let ta = send(0x83, a0, 1, P, 100, 1);
        let tb = send(0x83, a0, 1, Q, 100, 2);
        let rho_q = redeem(0x84, test_legs::opening(&w(0x84)), &tb, 100);
        let mut n = node();
        rec(&mut n, &ta, NOW_SECS);
        rec(&mut n, &tb, NOW_SECS);
        assert_eq!(n.provenance().judge_send(n.smt(), &tb.tx_hash), Judgment::Held, "fixture: tb is held");
        let (reg, deed) = fee_redeem_reg(&rho_q);
        register(&mut n, &reg, &deed, NOW_SECS + 1);
        for _ in 0..3 {
            n.drain_fork_side_effects();
        }
        assert_eq!(deed_credited(&n), 0, "a held redeem's DEED slice is never credited");
        assert!(n.validator_net_ledger.is_empty() && n.validator_dev_net_ledger.is_empty(),
            "…nor its validator fee slots");
        assert_eq!(n.origin_status(None, 0).fee_credits_held, 1, "parked, visible on /status");
    }

    /// Waiting, then cleared: the cheque's send is not recorded here when the
    /// redeem registers (WAIT) ⇒ parked; when the send's record arrives the
    /// cheque judges Ok and the fees are credited ONCE.
    /// MUTATION: drop the `release_held_fee_credits()` call in
    /// `drain_fork_side_effects` ⇒ never released ⇒ RED.
    #[test]
    fn fee_credit_waiting_redeem_credited_once_when_cleared() {
        let a0 = test_legs::opening(&w(0x85));
        let t = send(0x85, a0, 1, Q, 100, 1);
        let rho = redeem(0x86, test_legs::opening(&w(0x86)), &t, 100);
        let mut n = node();
        let (reg, deed) = fee_redeem_reg(&rho);
        register(&mut n, &reg, &deed, NOW_SECS);
        assert_eq!(n.provenance().judge_send(n.smt(), &t.tx_hash), Judgment::Wait, "fixture: WAIT");
        assert_eq!(deed_credited(&n), 0, "parked while waiting");
        rec(&mut n, &t, NOW_SECS + 5); // the send's record arrives (flood / AE / late register)
        n.drain_fork_side_effects();
        assert_eq!(deed_credited(&n), 3, "credited when the cheque clears");
        n.drain_fork_side_effects();
        assert_eq!(deed_credited(&n), 3, "exactly once");
        assert_eq!(n.origin_status(None, 0).fee_credits_held, 0);
    }

    /// THE mint gate (F-6 path 11): the FOB accumulator a
    /// `ValidatorWithdrawalMint` is funded from (`fob_available`, over the
    /// replicated `txid_records`) counts a redeem's fee slot only once the
    /// cheque judges Ok. Hashmap node (the only kind that records earnings);
    /// the redeem carries an explicit fee breakdown (3 × 1000 atoms on a
    /// 1 AXC cheque). Waiting ⇒ 0; cleared ⇒ the slot's net; the forked
    /// sibling's redeem ⇒ never.
    /// MUTATION: drop the `judge_send == Ok` filter in `NablaNode::
    /// fob_available` ⇒ the waiting / held slots count ⇒ RED.
    #[test]
    fn fee_credit_fob_accumulator_counts_only_clean_redeems() {
        const AMT: u64 = 1_000_000;
        let dir = tempfile::tempdir().unwrap();
        let mut n = NablaNode::open_with_txid_mode(
            dir.path(), Box::new(crate::crypto::NoopSigner), crate::bloom::TxidServiceMode::Hashmap,
        ).unwrap();
        n.admit_test_validators();
        n.set_current_tick(10);
        let fee_reg = |leg: &ForkLeg, vid0: u8| {
            let (mut reg, deed) = test_legs::registration_of(leg);
            reg.receipt.amount = AMT;
            reg.receipt.fee_breakdown = (0..reg.receipt.signatures.len() as u8)
                .map(|i| axiom_core_logic::types::FeeShare { validator_id: [vid0 + i; 32], amount: 1000 })
                .collect();
            (reg, deed)
        };
        let avail = |n: &NablaNode, v: u8| n.fob_available(&[v; 32], false, u64::MAX)
            + n.fob_available(&[v; 32], true, u64::MAX);
        // Honest-but-waiting: the cheque's send is not recorded here yet.
        let a0 = test_legs::opening(&w(0x91));
        let t = send(0x91, a0, 1, Q, AMT, 1);
        let rho = redeem(0x92, test_legs::opening(&w(0x92)), &t, AMT);
        let (reg, deed) = fee_reg(&rho, 0xA0);
        register(&mut n, &reg, &deed, NOW_SECS);
        assert!(n.smt().tx_record(&t.tx_hash).is_some(), "fixture: the fee record exists");
        assert_eq!(avail(&n, 0xA0), 0, "a WAITING redeem's fee slot is not mintable");
        rec(&mut n, &t, NOW_SECS + 5);
        n.drain_fork_side_effects();
        assert_eq!(avail(&n, 0xA0), 900, "cleared ⇒ the slot's post-DEED net (90%) counts");
        // Held: a forked cheque's redeem never counts.
        let b0 = test_legs::opening(&w(0x93));
        let ta = send(0x93, b0, 1, P, AMT, 1);
        let tb = send(0x93, b0, 1, Q, AMT, 2);
        rec(&mut n, &ta, NOW_SECS);
        rec(&mut n, &tb, NOW_SECS);
        let rho_q = redeem(0x94, test_legs::opening(&w(0x94)), &tb, AMT);
        let (reg, deed) = fee_reg(&rho_q, 0xB0);
        register(&mut n, &reg, &deed, NOW_SECS + 6);
        n.drain_fork_side_effects();
        assert!(n.smt().tx_record(&tb.tx_hash).is_some(), "fixture: the held redeem's fee record exists");
        assert_eq!(avail(&n, 0xB0), 0, "a HELD redeem's fee slot is never mintable");
        assert_eq!(avail(&n, 0xA0), 900, "the clean one is unaffected");
    }

    /// c17e hidden — Q's redeem of tb is NEVER recorded here: t_qq2 is WAIT
    /// forever (never OK); when the redeem record arrives it is still NONE —
    /// now HELD, not merely waiting.
    /// MUTATION (run 2026-09-28): `input` treats an absent verdict as a root
    /// (`unwrap_or(root)`) ⇒ t_qq2 vouched while the redeem is hidden ⇒ RED.
    #[test]
    fn w7c_hidden_redeem_is_wait_never_ok() {
        let c = chain();
        let mut n = node();
        for l in [&c.ta, &c.tb, &c.t_qq2] {
            rec(&mut n, l, NOW_SECS);
        }
        assert!(n.provenance().verdict_of(&pk(0x62), &c.rho_q.new_state).is_none(), "Q's state ungrounded here");
        assert_eq!(n.origin_vouch(&c.t_qq2.tx_hash, Some(NOW_SECS + 1_000_000)), OriginVouch::NONE, "WAIT, never OK");
        rec(&mut n, &c.rho_q, NOW_SECS + 5);
        assert_eq!(n.provenance().judge_send(n.smt(), &c.t_qq2.tx_hash), Judgment::Held, "now HELD");
        assert!(!vouched(&n, &c.t_qq2));
    }

    /// c19 HeldIsRetroactive — ta → P (P redeems), P → S (t_ps): vouched.
    /// Then tb arrives (the LATE fork leg): t_ps and S's next send are NONE,
    /// and P's state reports Held([ta]) — the next Nabla interaction.
    /// MUTATION (run 2026-09-28): drop the `held_other` re-queue in
    /// `record_verified_leg` (no enqueue on Conflict) ⇒ t_ps still vouched ⇒ RED.
    #[test]
    fn w7c_late_fork_holds_descendants_retroactively() {
        let a0 = test_legs::opening(&w(0x64));
        let ta = send(0x64, a0, 1, P, 100, 1);
        let tb = send(0x64, a0, 1, Q, 100, 2);
        let rho_p = redeem(0x65, test_legs::opening(&w(0x65)), &ta, 100);
        let t_ps = send(0x65, rho_p.new_state, 1, "s@axiom.internal/0123456789", 40, 1);
        let rho_s = redeem(0x66, test_legs::opening(&w(0x66)), &t_ps, 40);
        let t_su = send(0x66, rho_s.new_state, 1, "u@axiom.internal/0123456789", 10, 1);
        let mut n = node();
        for l in [&ta, &rho_p, &t_ps, &rho_s, &t_su] {
            rec(&mut n, l, NOW_SECS);
        }
        assert!(vouched(&n, &t_ps) && vouched(&n, &t_su), "control: settled before the fork is known");
        assert_eq!(n.provenance_view(&pk(0x65), &rho_p.new_state), ProvenanceView::Ok);
        rec(&mut n, &tb, NOW_SECS + 50);
        assert!(!vouched(&n, &t_ps), "the late fork re-holds P's payment");
        assert!(!vouched(&n, &t_su), "…and S's next send (whole-wallet, forward)");
        assert_eq!(n.provenance_view(&pk(0x65), &rho_p.new_state), ProvenanceView::Held(vec![ta.tx_hash]),
            "P discovers the hold at its next interaction");
    }

    /// c19/c19c NoFalseHold — A pays M from its opening state, THEN forks at
    /// the state after. A is banned; M's origin t_am is STILL vouched (ruling
    /// 3: payments before the fork are never held).
    /// MUTATION (run 2026-09-28): restore clause 4 (registrant banned ⇒ NONE)
    /// in `origin_vouch_inner` ⇒ RED.
    #[test]
    fn w7c_pre_fork_payment_vouched_after_ban() {
        let a0 = test_legs::opening(&w(0x67));
        let t_am = send(0x67, a0, 1, "m@axiom.internal/0123456789", 100, 1);
        let ta = send(0x67, t_am.new_state, 2, P, 100, 2);
        let tb = send(0x67, t_am.new_state, 2, Q, 100, 3);
        let mut n = node();
        for l in [&t_am, &ta, &tb] {
            rec(&mut n, l, NOW_SECS);
        }
        assert!(n.is_banned(&pk(0x67)), "fixture: A banned on the fork");
        assert!(vouched(&n, &t_am), "M, paid BEFORE the fork, stays settleable");
        assert!(!vouched(&n, &ta) && !vouched(&n, &tb));
    }

    /// c17h HonestChainClears — genesis → P → R: the vouch of R's origin
    /// t_pr reports `registered_at = max(ancestry first_seen)` — here A's send
    /// reached this node LAST — and Core's `origin_settled_link` accepts
    /// exactly at that + the floor, not one second before.
    /// MUTATION (run 2026-09-28): `judge_send` returns the send's OWN
    /// `first_seen` (drop `input.ready_at`) ⇒ Core accepts early ⇒ RED.
    /// Non-vacuity of the genesis root: with A's send from an arbitrary
    /// (non-opening) parent nothing is vouched.
    #[test]
    fn w7c_honest_chain_vouches_at_latest_ancestor_settle() {
        let dir = tempfile::tempdir().unwrap();
        let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::Ed25519Signer::from_seed(&[0x4D; 32]))).unwrap();
        n.admit_test_validators();
        let t_ap = send(0x68, test_legs::opening(&w(0x68)), 1, P, 100, 1);
        let rho_p = redeem(0x69, test_legs::opening(&w(0x69)), &t_ap, 100);
        let t_pr = send(0x69, rho_p.new_state, 1, R, 30, 1);
        let late = NOW_SECS + 500;
        rec(&mut n, &rho_p, NOW_SECS);
        rec(&mut n, &t_pr, NOW_SECS + 10);
        assert!(!vouched(&n, &t_pr), "A's send unrecorded here ⇒ WAIT");
        rec(&mut n, &t_ap, late);
        let floor = axiom_core_logic::validation::SCAR_SETTLE_TICKS.to_secs();
        let boot = Some(NOW_SECS - 1_000);
        let at = wave3_hook_tests::attestation(&n, &t_pr.tx_hash, late + floor, boot);
        assert_eq!(at.sender_registered_at_tick, late, "registered_at = the youngest ancestor's first sight");
        assert!(axiom_core_logic::fact::origin_settled_link(&at, &t_pr.tx_hash, false), "Core accepts at the floor");
        let early = wave3_hook_tests::attestation(&n, &t_pr.tx_hash, late + floor - 1, boot);
        assert!(!axiom_core_logic::fact::origin_settled_link(&early, &t_pr.tx_hash, false), "…not one second before");

        let mut m = node();
        let stray = send(0x6A, [0x6A; 32], 1, P, 100, 1);
        rec(&mut m, &stray, NOW_SECS);
        assert!(!vouched(&m, &stray), "a non-opening, unrecorded parent grounds nothing");
    }

    /// c17h liveness + F8 — a fresh wallet's FIRST receive (zero consumed) is
    /// recorded as a root: its later send is vouched. A SECOND zero-consumed
    /// redeem for the same pk (the reset shape) grounds NEITHER.
    /// MUTATIONS (run 2026-09-28): drop the zero-redeem branch in
    /// `record_verified_leg` (not recorded — the pre-W7c drop) ⇒ the control
    /// is RED; `input` grounds ANY zero redeem (ignore the count) ⇒ the reset
    /// case is RED.
    #[test]
    fn w7c_fresh_wallet_zero_redeem_grounds_once() {
        let t_ap = send(0x6B, test_legs::opening(&w(0x6B)), 1, P, 100, 1);
        let t_ap2 = send(0x6B, t_ap.new_state, 2, P, 50, 2);
        let rho1 = redeem(0x6C, [0u8; 32], &t_ap, 100);
        let t_pr = send(0x6C, rho1.new_state, 1, R, 30, 1);
        let mut n = node();
        for l in [&t_ap, &rho1, &t_pr] {
            rec(&mut n, l, NOW_SECS);
        }
        assert!(n.smt().legs_under(&(pk(0x6C), [0u8; 32])).is_empty(), "never in the fork index");
        assert!(vouched(&n, &t_pr), "the unique first receive grounds the fresh wallet");
        rec(&mut n, &t_ap2, NOW_SECS);
        rec(&mut n, &redeem(0x6C, [0u8; 32], &t_ap2, 50), NOW_SECS + 1);
        assert!(!n.is_banned(&pk(0x6C)), "two zero parents are no fork claim [R33]");
        assert!(!vouched(&n, &t_pr), "F8: a second zero-consumed redeem grounds neither");
    }

    /// Ruling 2 — burn exit per tainted receive. R holds TWO held receives
    /// (100 and 70). A burn of the wrong amount clears nothing; a burn of 100
    /// clears exactly one root (R still held by the 70); a burn of 70 then
    /// releases R: its next send is vouched.
    /// MUTATIONS (run 2026-09-28): match any burn amount ⇒ the wrong-amount
    /// case is RED; clear ALL receive roots on one burn ⇒ the one-root case
    /// is RED.
    #[test]
    fn w7c_burn_exact_amount_releases_wallet() {
        let burn = axiom_core_logic::types::BURN_ADDRESS;
        let a0 = test_legs::opening(&w(0x6D));
        let ta = send(0x6D, a0, 1, P, 100, 1);
        let tb = send(0x6D, a0, 1, R, 100, 2);
        let tc = send(0x6D, tb.new_state, 2, R, 70, 3);
        let r0 = test_legs::opening(&w(0x6E));
        let rho1 = redeem(0x6E, r0, &tb, 100);
        let rho2 = test_legs::genuine_redeem_leg(&w(0x6E), rho1.new_state, &test_legs::origin_of(&tc), 170, 1, 3);
        let mut n = node();
        for l in [&ta, &tb, &tc, &rho1, &rho2] {
            rec(&mut n, l, NOW_SECS);
        }
        let held = n.provenance_view(&pk(0x6E), &rho2.new_state);
        let ProvenanceView::Held(mut roots) = held else { panic!("R must be held: {held:?}") };
        roots.sort();
        let mut want = vec![tb.tx_hash, tc.tx_hash];
        want.sort();
        assert_eq!(roots, want, "both tainted receives listed");
        // A chain of burns from R's held state (each consumes the previous —
        // two legs from one state would be a fork).
        let wrong = send(0x6E, rho2.new_state, 2, burn, 99, 10);
        rec(&mut n, &wrong, NOW_SECS);
        let ProvenanceView::Held(after_wrong) = n.provenance_view(&pk(0x6E), &wrong.new_state) else {
            panic!("a burn of the WRONG amount clears nothing — R still held")
        };
        assert_eq!(after_wrong.len(), 2, "a burn of the WRONG amount clears nothing");
        let b1 = send(0x6E, wrong.new_state, 3, burn, 100, 12);
        rec(&mut n, &b1, NOW_SECS);
        assert_eq!(n.provenance_view(&pk(0x6E), &b1.new_state), ProvenanceView::Held(vec![tc.tx_hash]),
            "one burn clears ONE root — the 70 still holds R");
        let b2 = send(0x6E, b1.new_state, 4, burn, 70, 14);
        rec(&mut n, &b2, NOW_SECS);
        let after_b2 = send(0x6E, b2.new_state, 5, P, 1, 15);
        rec(&mut n, &after_b2, NOW_SECS);
        assert!(!n.is_banned(&pk(0x6E)), "fixture: R's burns are a chain, not a fork");
        assert!(vouched(&n, &after_b2), "both tainted amounts burned ⇒ R released");
        assert_eq!(n.provenance_view(&pk(0x6E), &b2.new_state), ProvenanceView::Ok);
    }

    // ── KI#241 F-2 / F-9 (Fable review 2026-10-01) ─────────────────────────

    const BURN: &str = axiom_core_logic::types::BURN_ADDRESS;

    /// Receiver `seed` redeems a cheque from a sender NEVER recorded here
    /// (`tag`, gross `amount`), consuming `consumed`, landing at `balance`.
    fn redeem_stray(seed: u8, consumed: StateId, tag: u8, amount: u64, balance: u64) -> ForkLeg {
        test_legs::genuine_redeem_leg(
            &w(seed), consumed, &test_legs::stray_origin_amount([tag; 32], amount), balance, 1, 3,
        )
    }

    fn roots_of(n: &NablaNode, seed: u8, state: &StateId) -> Vec<Root> {
        n.provenance().verdict_of(&pk(seed), state).expect("a grounded verdict").roots.clone()
    }

    /// `count` chained stray receives from `seed`'s opening state; amounts
    /// `1..=count` (distinct, so a burn's assignment is unambiguous). Returns
    /// the legs (recorded) and Σ amounts.
    fn stray_receive_chain(n: &mut NablaNode, seed: u8, count: u8) -> (Vec<ForkLeg>, u64) {
        let mut at = test_legs::opening(&w(seed));
        let (mut legs, mut sum) = (Vec::new(), 0u64);
        for i in 1..=count {
            sum += u64::from(i);
            let rho = redeem_stray(seed, at, i, u64::from(i), sum);
            rec(n, &rho, NOW_SECS);
            at = rho.new_state;
            legs.push(rho);
        }
        (legs, sum)
    }

    /// KI#241 F-2 (Fable test 3) — the SENDER NEVER REGISTERED here: only the
    /// receiver's redeem of a 100-atom cheque is recorded. Its state WAITs; a
    /// `BURN_ADDRESS` burn of 99 clears nothing; a burn of 100 releases the
    /// wallet — its next send is vouched. The amount comes from the cheque
    /// origin the redeem leg CARRIES (k-bound by txid recomputation).
    /// MUTATION (run 2026-10-01): step 4 reads the amount from the sender's
    /// record only (`smt.vouch_record(&t)…unwrap_or(0)`) ⇒ no burn matches ⇒
    /// still WAIT after the 100 burn ⇒ RED.
    #[test]
    fn ki241_f2_never_registered_sender_burn_exit_opens() {
        let mut n = node();
        let r0 = test_legs::opening(&w(0x81));
        let rho = redeem_stray(0x81, r0, 0x91, 100, 100);
        rec(&mut n, &rho, NOW_SECS);
        assert!(n.smt().vouch_record(&rho.tx_hash).is_none(), "fixture: the sender's send is NOT recorded here");
        assert_eq!(n.provenance_view(&pk(0x81), &rho.new_state), ProvenanceView::Wait, "a pending receive WAITs");
        assert_eq!(roots_of(&n, 0x81, &rho.new_state),
            vec![Root::Receive { cheque: rho.tx_hash, amount: 100, held: false }],
            "the root carries the GROSS cheque amount even with no sender record");
        let b99 = send(0x81, rho.new_state, 2, BURN, 99, 1);
        rec(&mut n, &b99, NOW_SECS);
        assert_eq!(n.provenance_view(&pk(0x81), &b99.new_state), ProvenanceView::Wait, "a burn of 99 clears nothing");
        let b100 = send(0x81, b99.new_state, 3, BURN, 100, 2);
        rec(&mut n, &b100, NOW_SECS);
        assert_eq!(n.provenance_view(&pk(0x81), &b100.new_state), ProvenanceView::Ok, "the exact burn releases");
        let next = send(0x81, b100.new_state, 4, P, 1, 3);
        rec(&mut n, &next, NOW_SECS);
        assert!(vouched(&n, &next), "the released wallet's next send is vouched");
    }

    /// KI#241 F-2 (Fable test 4) — a FORGED amount cannot reach the engine:
    /// a redeem leg whose carried cheque origin claims 5 (not the 100 the k
    /// bound) is refused by `verify_fork_leg` (the door / flood / AE leg
    /// check) and recorded nowhere, so no `Receive { amount: 5 }` root exists
    /// and a burn of 5 releases nothing.
    /// MUTATION (run 2026-10-01): delete the `cheque_origin_matches` check in
    /// `registration::verify_redeem_leg_preimage` ⇒ the forged leg verifies
    /// ⇒ RED.
    #[test]
    fn ki241_f2_forged_cheque_amount_never_reaches_the_engine() {
        let mut n = node();
        let r0 = test_legs::opening(&w(0x82));
        let genuine = redeem_stray(0x82, r0, 0x92, 100, 100);
        let mut forged = genuine.clone();
        if let crate::types::LegPreimage::Redeem { cheque, .. } = &mut forged.seq_proof.preimage {
            cheque.preimage.amount = 5;
        }
        assert_eq!(crate::ban::verify_fork_leg(forged.clone()).err(),
            Some(crate::ban::ForkLegRefusal::Leg(crate::registration::LegRefusal::ChequeOriginMismatch)),
            "the forged origin is refused upstream of the engine");
        let (reg, deed) = test_legs::registration_of(&forged);
        assert!(matches!(n.register(&reg, &deed, NOW_SECS),
            Err(crate::types::NablaError::LegUnverifiable(crate::registration::LegRefusal::ChequeOriginMismatch))),
            "…and at the door");
        n.drain_fork_side_effects();
        assert!(n.provenance().verdict_of(&pk(0x82), &forged.new_state).is_none(), "nothing derived from the forgery");
        rec(&mut n, &genuine, NOW_SECS);
        let b5 = send(0x82, genuine.new_state, 2, BURN, 5, 1);
        rec(&mut n, &b5, NOW_SECS);
        assert_eq!(roots_of(&n, 0x82, &b5.new_state),
            vec![Root::Receive { cheque: genuine.tx_hash, amount: 100, held: false }],
            "only the k-bound amount exists; a burn of the forged amount clears nothing");
    }

    /// KI#241 F-9 (Fable tests 1 + 2) — 33 pending receives (senders that
    /// never register) collapse to `Overflow { owed: Some(Σ) }` (HELD, no
    /// cheque listed); 33 chained exact `BURN_ADDRESS` burns pay the ledger
    /// down and release the wallet at the LAST burn, not one before.
    /// MUTATIONS (run 2026-10-01): (1) `overflow_ledger` sums only the first
    /// 32 roots ⇒ the Σ assertion is RED; (2) remove the ledger when
    /// `rest <= w.amount` instead of `rest == 0` ⇒ released one burn early
    /// (burns run in DESCENDING order so the penultimate rest ≤ its burn) ⇒ RED.
    #[test]
    fn ki241_f9_overflow_ledger_releases_at_the_last_burn() {
        let mut n = node();
        let (legs, sum) = stray_receive_chain(&mut n, 0x83, 33);
        let top = legs.last().unwrap().new_state;
        assert_eq!(roots_of(&n, 0x83, &top), vec![Root::Overflow { owed: Some(sum) }], "Σ of all 33 gross amounts");
        assert_eq!(roots_of(&n, 0x83, &legs[31].new_state).len(), 32, "fixture: 32 roots do not collapse");
        assert_eq!(n.provenance_view(&pk(0x83), &top), ProvenanceView::Held(vec![]), "Overflow is HELD, lists nothing");
        let mut at = top;
        for (k, amount) in (1..=33u64).rev().enumerate() {
            let b = send(0x83, at, 2 + k as u64, BURN, amount, 100 + k as u64);
            rec(&mut n, &b, NOW_SECS);
            at = b.new_state;
            let paid: u64 = (amount..=33).sum();
            if amount > 1 {
                assert_eq!(roots_of(&n, 0x83, &at), vec![Root::Overflow { owed: Some(sum - paid) }],
                    "after burning {amount}: the ledger is paid down, still HELD");
                assert!(matches!(n.provenance_view(&pk(0x83), &at), ProvenanceView::Held(_)), "held before the last burn");
            }
        }
        assert_eq!(n.provenance_view(&pk(0x83), &at), ProvenanceView::Ok, "released exactly at the last burn");
        let next = send(0x83, at, 40, P, 1, 999);
        rec(&mut n, &next, NOW_SECS);
        assert!(vouched(&n, &next), "the released wallet's next send is vouched");
    }

    /// KI#241 F-9 (Fable test 3) — no overpayment: a burn of `owed + 1`
    /// matches nothing; a burn of a non-link amount `a < owed` decrements the
    /// ledger (the burner's own value accounting) and the rest is still owed.
    /// MUTATION (run 2026-10-01): drop the `w.amount <= *o` guard on the
    /// ledger match (overpayment accepted) ⇒ RED.
    #[test]
    fn ki241_f9_overflow_ledger_refuses_overpayment_and_counts_any_burn() {
        let mut n = node();
        let (legs, sum) = stray_receive_chain(&mut n, 0x84, 33);
        let top = legs.last().unwrap().new_state;
        let over = send(0x84, top, 2, BURN, sum + 1, 1);
        rec(&mut n, &over, NOW_SECS);
        assert_eq!(roots_of(&n, 0x84, &over.new_state), vec![Root::Overflow { owed: Some(sum) }], "owed+1 matches nothing");
        let odd = send(0x84, over.new_state, 3, BURN, 1_000 + 1, 2);
        assert!(1_001 > sum, "fixture sanity");
        rec(&mut n, &odd, NOW_SECS);
        assert_eq!(roots_of(&n, 0x84, &odd.new_state), vec![Root::Overflow { owed: Some(sum) }], "> owed matches nothing");
        let part = send(0x84, odd.new_state, 4, BURN, 500, 3); // no link is 500
        rec(&mut n, &part, NOW_SECS);
        assert_eq!(roots_of(&n, 0x84, &part.new_state), vec![Root::Overflow { owed: Some(sum - 500) }],
            "a non-link amount still pays the ledger down");
        let rest = send(0x84, part.new_state, 5, BURN, sum - 500, 4);
        rec(&mut n, &rest, NOW_SECS);
        assert_eq!(n.provenance_view(&pk(0x84), &rest.new_state), ProvenanceView::Ok, "the full total releases");
    }

    /// KI#241 F-9 (Fable test 4) — a FORK folded into the collapse makes the
    /// ledger `None`: burning every receive's amount never releases.
    /// MUTATION (run 2026-10-01): `overflow_ledger` ignores `Fork` roots
    /// (treats the fork as owing 0) ⇒ the burns release ⇒ RED.
    #[test]
    fn ki241_f9_overflow_with_a_fork_is_unburnable() {
        let mut n = node();
        let r0 = test_legs::opening(&w(0x85));
        // The wallet forks at its opening state: two redeems from r0.
        let a = redeem_stray(0x85, r0, 0xF0, 7, 7);
        let b = redeem_stray(0x85, r0, 0xF1, 9, 9);
        rec(&mut n, &a, NOW_SECS);
        rec(&mut n, &b, NOW_SECS);
        assert!(n.smt().legs_under(&(pk(0x85), r0)).len() >= 2, "fixture: the wallet's own key forked");
        let (mut at, mut sum, mut bal) = (a.new_state, 7u64, 7u64);
        for i in 1..=32u8 {
            bal += u64::from(i);
            sum += u64::from(i);
            let rho = redeem_stray(0x85, at, i, u64::from(i), bal);
            rec(&mut n, &rho, NOW_SECS);
            at = rho.new_state;
        }
        // Fork + 7 + 1..=31 = 33 roots fold at i = 31; the 32nd receive rides beside the folded ledger.
        assert_eq!(roots_of(&n, 0x85, &at)[0], Root::Overflow { owed: None }, "a folded fork ⇒ no ledger");
        let mut seq = 2;
        for amount in std::iter::once(7u64).chain(1..=32u64).chain(std::iter::once(sum)) {
            let burn = send(0x85, at, seq, BURN, amount, 50 + seq);
            rec(&mut n, &burn, NOW_SECS);
            at = burn.new_state;
            seq += 1;
        }
        assert!(matches!(n.provenance_view(&pk(0x85), &at), ProvenanceView::Held(_)), "no burn ever releases a fork");
    }

    /// KI#241 F-9 (Fable test 5) — re-derivation: after the collapse ONE
    /// sender registers (its send grounds at the opening) ⇒ its receive root
    /// clears, the ancestor re-derives to 32 roots and the Overflow is GONE
    /// without any burn — the verdict is a pure function of the records.
    /// MUTATION (run 2026-10-01): make an Overflow verdict sticky in `visit`
    /// (`if old has Overflow { return }`) ⇒ still Overflow ⇒ RED.
    #[test]
    fn ki241_f9_overflow_uncollapses_when_a_sender_registers() {
        let mut n = node();
        let s_send = send(0x86, test_legs::opening(&w(0x86)), 1, R, 1_000, 1);
        let mut at = test_legs::opening(&w(0x87));
        let mut bal = 1_000u64;
        let rho0 = test_legs::genuine_redeem_leg(&w(0x87), at, &test_legs::origin_of(&s_send), bal, 1, 3);
        rec(&mut n, &rho0, NOW_SECS);
        at = rho0.new_state;
        for i in 1..=32u8 {
            bal += u64::from(i);
            let rho = redeem_stray(0x87, at, i, u64::from(i), bal);
            rec(&mut n, &rho, NOW_SECS);
            at = rho.new_state;
        }
        assert!(matches!(roots_of(&n, 0x87, &at)[..], [Root::Overflow { owed: Some(_) }]), "fixture: collapsed");
        rec(&mut n, &s_send, NOW_SECS); // the sender registers late
        let roots = roots_of(&n, 0x87, &at);
        assert_eq!(roots.len(), 32, "re-derived below the cap: {roots:?}");
        assert!(!roots.iter().any(|r| matches!(r, Root::Overflow { .. })), "the Overflow disappeared by itself");
        assert_eq!(n.provenance_view(&pk(0x87), &at), ProvenanceView::Wait, "32 pending receives: WAIT, not HELD");
    }

    /// KI#241 F-9 (Fable test 7) — work bound: a long chain of burns paying an
    /// Overflow ledger derives LINEARLY — every recorded leg is visited a
    /// bounded number of times (no superlinear term), and no verdict ever
    /// holds more than `ROOTS_MAX` roots.
    /// ⚠ 2 000 burns, not Fable's 10 000: every test leg is minted and
    /// verified with real Ed25519 (4 signs + 4 verifies) in a debug build;
    /// the bound asserted is per-leg, so the length only scales the run time.
    #[test]
    fn ki241_f9_long_burn_chain_derives_linearly() {
        const BURNS: u64 = 2_000;
        let mut n = node();
        let (legs, sum) = stray_receive_chain(&mut n, 0x88, 33);
        let mut at = legs.last().unwrap().new_state;
        let before = n.provenance().states_derived();
        for k in 0..BURNS {
            let b = send(0x88, at, 2 + k, BURN, 1, 10_000 + k);
            rec(&mut n, &b, NOW_SECS);
            at = b.new_state;
            let v = n.provenance().verdict_of(&pk(0x88), &at).expect("grounded");
            assert!(v.roots.len() <= ROOTS_MAX, "bounded roots per verdict");
        }
        let visits = n.provenance().states_derived() - before;
        assert!(visits <= 4 * BURNS, "{visits} visits for {BURNS} burns — must be linear");
        let paid = BURNS.min(sum);
        let want = if paid == sum { ProvenanceView::Ok } else { ProvenanceView::Held(vec![]) };
        assert_eq!(n.provenance_view(&pk(0x88), &at), want, "the ledger saw every 1-atom burn ({sum} owed)");
    }

    /// c12 / R42 — Q's redeem of tb is hidden; Q presents a send from its
    /// opening state witnessed by NON-directory keys (junk). It cannot produce
    /// a grounded state: Q's next send stays NONE. Re-witnessed by directory
    /// validators the same shape grounds (control).
    /// MUTATION (run 2026-09-28): drop the `is_witness` producer check in
    /// `derive` (since W1: the `ban::leg_is_directory_witnessed` call) ⇒ RED.
    #[test]
    fn w7c_junk_witness_producer_does_not_ground() {
        use ed25519_dalek::Signer as _;
        let q0 = test_legs::opening(&w(0x6F));
        let mut junk = send(0x6F, q0, 1, "self@axiom.internal/0123456789", 1, 1);
        let p = junk.send_preimage().unwrap().clone();
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            &junk.tx_hash, &junk.seq_proof.state_hash, p.wallet_seq, &junk.seq_proof.commitment_hash,
            junk.seq_proof.epoch, false, None, None, None,
        );
        junk.seq_proof.sigs = (0..3u8).map(|i| {
            let k = SigningKey::from_bytes(&[0xE0 + i; 32]);
            crate::types::SeqProofSig {
                validator_pk: k.verifying_key().to_bytes(),
                receipt_commitment_sig: k.sign(&commitment).to_bytes().to_vec(),
            }
        }).collect();
        let t_qr = send(0x6F, junk.new_state, 2, R, 1, 2);
        let mut n = node();
        rec(&mut n, &junk, NOW_SECS);
        rec(&mut n, &t_qr, NOW_SECS);
        assert!(vouched(&n, &junk), "control: the junk send's OWN input (opening) is grounded");
        assert!(!vouched(&n, &t_qr), "a junk-witnessed producer grounds nothing downstream");
        // Control: the same shape witnessed by directory validators grounds.
        let honest = send(0x6F, q0, 1, "self@axiom.internal/0123456789", 1, 1);
        let mut m = node();
        rec(&mut m, &honest, NOW_SECS);
        rec(&mut m, &send(0x6F, honest.new_state, 2, R, 1, 2), NOW_SECS);
        assert!(vouched(&m, &send(0x6F, honest.new_state, 2, R, 1, 2)));
    }

    /// Fail-closed bound — with a budget of ONE visit the queue is non-empty
    /// and the node vouches NOTHING, not even the already-OK origin; drained,
    /// it vouches again. `/status provenance_dirty_queue` shows the queue.
    /// MUTATION (run 2026-09-28): drop the `provenance_idle` gate in
    /// `origin_vouch_inner` ⇒ RED.
    #[test]
    fn w7c_cascade_pending_fails_closed() {
        let t_ap = send(0x70, test_legs::opening(&w(0x70)), 1, P, 100, 1);
        let rho = redeem(0x71, test_legs::opening(&w(0x71)), &t_ap, 100);
        let t_pr = send(0x71, rho.new_state, 1, R, 30, 1);
        let mut n = node();
        rec(&mut n, &t_ap, NOW_SECS);
        assert!(vouched(&n, &t_ap), "control");
        for l in [&rho, &t_pr] {
            let v = crate::ban::verify_fork_leg(l.clone()).unwrap();
            n.smt_mut().record_verified_leg(v, NOW_SECS);
        }
        n.provenance_drain(Some(1));
        assert!(n.origin_status(None, 0).provenance_dirty_queue > 0, "fixture: work queued");
        assert!(!vouched(&n, &t_ap), "queued work ⇒ vouch NOTHING");
        assert_eq!(n.provenance_view(&pk(0x71), &rho.new_state), ProvenanceView::Wait);
        n.provenance_drain(None);
        assert!(vouched(&n, &t_ap) && vouched(&n, &t_pr), "drained ⇒ vouched again");
    }

    /// Persistence: none (plan C6) — a snapshot + WAL restart re-derives the
    /// SAME answers (an OK chain, a held chain) from the records alone.
    /// MUTATION (run 2026-09-28): `restore_origin_entry` / `restore_redeem_entry`
    /// stop queuing for derivation ⇒ everything WAITs after the restart ⇒ RED.
    #[test]
    fn w7c_restart_rederives_identical_verdicts() {
        let dir = tempfile::tempdir().unwrap();
        let c = chain();
        let t_ap = send(0x72, test_legs::opening(&w(0x72)), 1, P, 100, 1);
        let rho = redeem(0x73, test_legs::opening(&w(0x73)), &t_ap, 100);
        let t_pr = send(0x73, rho.new_state, 1, R, 30, 1);
        let t_x = send(0x72, t_ap.new_state, 2, Q, 10, 2); // a send → send hop (A's own chain)
        let all = [&c.ta, &c.tb, &c.rho_q, &c.t_qq2, &c.rho_q2, &c.t_q2r, &t_ap, &rho, &t_pr, &t_x];
        let answers = |n: &NablaNode| -> Vec<OriginVouch> {
            all.iter().map(|l| n.origin_vouch(&l.tx_hash, Some(NOW_SECS))).collect()
        };
        let before = {
            let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
            n.admit_test_validators();
            for (i, l) in all.iter().enumerate().take(7) {
                rec(&mut n, l, NOW_SECS + i as u64);
            }
            n.take_snapshot().unwrap();
            // After the snapshot: the last two records live only in the WAL.
            for (i, l) in all.iter().enumerate().skip(7) {
                rec(&mut n, l, NOW_SECS + i as u64);
            }
            answers(&n)
        };
        assert!(before[8].origin.is_some() && before[9].origin.is_some() && before[3].origin.is_none(),
            "fixture: OK chains (redeem hop and send hop), one held");
        let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        // The R42 directory's test witnesses are not persisted by the test
        // helper (a real admission is) — re-admit, which re-queues producers.
        n.admit_test_validators();
        n.drain_fork_side_effects();
        assert_eq!(answers(&n), before, "re-derived at load, identical");
    }

    /// W7d — the register ack's `provenance` (UX, ruling 1: ACCEPTED and
    /// MARKED): through the DOOR, P's redeem of a fork leg registers Ok and its
    /// view is `Held([tb])`; an honest redeem's is `Ok`; the field reaches the
    /// SDK's CBOR map under `"provenance"`.
    /// MUTATION (run 2026-09-28): `Provenance::view` returns `Wait` always
    /// (the field never carries the verdict) ⇒ RED.
    #[test]
    fn w7d_register_ack_reports_held_roots() {
        let a0 = test_legs::opening(&w(0x74));
        let ta = send(0x74, a0, 1, P, 100, 1);
        let tb = send(0x74, a0, 1, Q, 100, 2);
        let mut n = node();
        rec(&mut n, &ta, NOW_SECS);
        rec(&mut n, &tb, NOW_SECS);
        let honest_src = send(0x76, test_legs::opening(&w(0x76)), 1, P, 5, 1);
        rec(&mut n, &honest_src, NOW_SECS);
        for (seed, cheque, want) in [
            (0x75u8, &tb, ProvenanceView::Held(vec![tb.tx_hash])),
            (0x77u8, &honest_src, ProvenanceView::Ok),
        ] {
            let rho = redeem(seed, test_legs::opening(&w(seed)), cheque, 100);
            let (reg, deed) = test_legs::registration_of(&rho);
            let r = n.register(&reg, &deed, NOW_SECS + 1);
            assert!(r.is_ok(), "a held redeem is ACCEPTED, never refused (ruling 1): {:?}", r.err());
            let view = n.provenance_view(&reg.client_pk, &reg.new_state);
            assert_eq!(view, want);
            let mut ack = r.unwrap().ack;
            ack.provenance = view.clone();
            let mut buf = Vec::new();
            ciborium::into_writer(&crate::transport::WireMessage::RegisterAck(ack), &mut buf).unwrap();
            let v: ciborium::Value = ciborium::from_reader(buf.as_slice()).unwrap();
            let body = v.as_map().unwrap().iter().find(|(k, _)| k.as_text() == Some("RegisterAck")).unwrap().1.clone();
            let field = body.as_map().unwrap().iter().find(|(k, _)| k.as_text() == Some("provenance")).map(|(_, v)| v.clone());
            assert!(field.is_some(), "the SDK reads `provenance` from the ack's CBOR map");
            let back: ProvenanceView = field.unwrap().deserialized().unwrap();
            assert_eq!(back, view);
        }
    }
}
