// AXIOM Nabla — CLARA registration (YPX-018 §2.4, hardened in Phase 5e/5f)
//
// Implements the protocol-level work of `POST /clara`:
//
//   1. Verify the heal cheque bundle has at least k=3 distinct validators.
//   2. Verify each validator's signature over the canonical cheque commitment
//      (Ed25519 against validator_pk).
//   3. Verify the bundle is internally consistent (matching txid/amount/etc).
//   4. Verify the SELF-SEND invariant — sender_wallet_id == receiver_wallet_id.
//   5. Verify the authoritative TX_HEAL transaction:
//        - tx.is_heal() == true (it's actually marked as a heal)
//        - compute_txid(&tx) == cheque.txid (binds tx to the bundle)
//        - tx.client_pk == request.wallet_pk (binds the request to the tx)
//        - verify_pk_binding(sender_wallet_id, wallet_pk) (binds wallet_id to pk)
//        - tx.sender_wallet_id == tx.receiver_wallet_id (in-tx self-send)
//   6. Derive heal_txid, healed_to_state_id, healed_from_state_id (= tx.consumed_state_id),
//      healed_at_seq (= tx.wallet_seq) from authoritative sources only.
//   7. Verify consumed_state_id is fresh in BOTH bloom chains.
//   8. Insert the heal txid into the active txid bloom era.
//   9. Insert each declared garbage state into the active garbage bloom era.
//  10. Caller (HTTP handler) signs and returns the `ClaraAttestation`.
//
// Phase 5e security hotfix: the previous version accepted a client-asserted
// `witness_sig_count: usize` instead of verifying real signatures.
//
// Phase 5f security hotfix: the previous version accepted caller-asserted
// `healed_from_state_id` and `healed_at_seq`, and never bound `wallet_pk` to
// the cheque's identity. Both are now derived from / verified against the
// authoritative TX_HEAL transaction included in the request.
//
// Reference:
//   - YPX-018 §2 CLARA protocol
//   - YPX-018 §2.2 ClaraAttestation structure
//   - YPX-018 §2.4 CLARA registration endpoint
//   - Yellow Paper §17.10.14 CLARA normative spec

use axiom_core_logic::types::{ChequeBundle, Transaction, ValidatorCheque};

use crate::bloom_chain::{BloomChain, ChainLookup};
use crate::garbage_state_chain::GarbageStateChain;

/// Phase 5f hardening: maximum entries in `declared_garbage` per single CLARA
/// registration. Caps DoS amplification — without it, one valid heal cheque
/// could ship millions of garbage entries, each of which costs a bloom lookup
/// + insertion under both bloom-chain write locks AND inflates the era's
///   fill level past its FPR target.
///
/// 32 is chosen because: (a) the realistic worst case is "wallet was poisoned
/// at every validator it ever talked to", which is bounded by k × number of
/// retried sends; (b) k=5 (max security tier) × 6 retries = 30; 32 gives one
/// round of headroom; (c) the wire-size of a 32-entry attestation
/// (32 × 32 bytes = 1 KB) is well below any reasonable HTTP body limit.
///
/// If a wallet legitimately needs more than 32 garbage entries, the client
/// must split the heal into multiple TX_HEAL self-sends, each with its own
/// CLARA registration. The intermediate state is still safe — the wallet's
/// state_id only advances on successful heals.
pub const MAX_DECLARED_GARBAGE: usize = 32;

/// Phase 5f Finding 3: per-wallet rate-limit for `POST /clara`.
///
/// A single wallet should never need more than a handful of CLARA
/// registrations in a short window — the recovery cadence is "one heal per
/// poisoning event", and a healthy wallet experiences ≪ 1 poisoning per day.
/// Three per hour gives ample headroom for back-to-back recovery attempts
/// (e.g., the heal hits a stale Nabla node on the first try and the client
/// retries against a fresh peer) while bounding the per-wallet DoS surface.
///
/// Capping per-wallet rather than globally is what makes this useful: a
/// global cap would be DoS'd by an attacker spinning up many wallets; a
/// per-wallet cap forces the attacker to either (a) generate sybil wallets
/// (which costs real keys + Nabla register fees) or (b) flood from a small
/// set of wallets, which the per-wallet cap stops cold.
pub const MAX_CLARA_REGISTRATIONS_PER_HOUR_PER_WALLET: usize = 3;

/// Window over which `MAX_CLARA_REGISTRATIONS_PER_HOUR_PER_WALLET` is enforced
/// (in TARDIS ticks, which are seconds in production).
pub const CLARA_RATE_LIMIT_WINDOW_SECS: u64 = 3600;

/// Maximum age (ticks) of a per-wallet entry before it's eligible for
/// memory eviction during the periodic prune. Twice the rate-limit window so
/// a wallet that just hit the cap doesn't have its history dropped on the
/// next prune cycle.
pub const CLARA_RATE_LIMIT_PRUNE_AGE_SECS: u64 = CLARA_RATE_LIMIT_WINDOW_SECS * 2;

/// In-memory per-wallet rate limiter for `POST /clara`. Lives on the
/// NablaNodeState so HTTP handlers can borrow it for the duration of a
/// request without holding bloom-chain locks.
///
/// Memory bound: O(active wallets × MAX_CLARA_REGISTRATIONS_PER_HOUR_PER_WALLET)
/// = O(wallets × 3). With periodic pruning every ~hour, memory stays
/// proportional to recently-active healers, which is tiny in practice.
#[derive(Debug, Default)]
pub struct ClaraRateLimiter {
    /// Per-wallet history: each entry is the tick at which a successful
    /// (or attempted-but-not-cap-rejected) registration occurred.
    history: std::collections::BTreeMap<[u8; 32], std::collections::VecDeque<u64>>,
    /// Next tick at which we should run the full-map prune. Initialized lazily.
    next_prune_at: u64,
}

impl ClaraRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether `wallet_pk` is within its rate limit at `now`. If yes,
    /// record this attempt and return Ok. If no, return Err — the caller
    /// MUST refuse the request with `RateLimited`.
    ///
    /// Records the attempt BEFORE checking the protocol-level register_clara
    /// outcome on purpose: this counts attempts (including malformed and
    /// rejected ones), which is what bounds CPU on invalid floods. Pure
    /// "successful registrations only" wouldn't help against verify-then-reject
    /// floods, which carry the same per-request CPU cost as accepted ones.
    pub fn check_and_record(
        &mut self,
        wallet_pk: &[u8; 32],
        now: u64,
    ) -> Result<(), ClaraRegistrationError> {
        // Periodic prune: evict per-wallet entries that haven't been touched
        // in CLARA_RATE_LIMIT_PRUNE_AGE_SECS. Cheap O(n) scan; runs at most
        // once per hour. Bound the unbounded-growth attack vector: an attacker
        // who registers under millions of distinct sybil wallets can't make us
        // hold their history forever — old entries get dropped automatically.
        if now >= self.next_prune_at {
            let cutoff = now.saturating_sub(CLARA_RATE_LIMIT_PRUNE_AGE_SECS);
            self.history.retain(|_pk, hist| {
                // Drop entries whose newest record is older than cutoff.
                hist.back().is_some_and(|&latest| latest >= cutoff)
            });
            self.next_prune_at = now + CLARA_RATE_LIMIT_WINDOW_SECS;
        }

        let entry = self.history.entry(*wallet_pk).or_default();

        // Drop entries from this wallet's history that are outside the window.
        let window_start = now.saturating_sub(CLARA_RATE_LIMIT_WINDOW_SECS);
        while entry.front().is_some_and(|&t| t < window_start) {
            entry.pop_front();
        }

        // Check the cap.
        if entry.len() >= MAX_CLARA_REGISTRATIONS_PER_HOUR_PER_WALLET {
            return Err(ClaraRegistrationError::RateLimited);
        }

        // Record the attempt.
        entry.push_back(now);
        Ok(())
    }

    /// Test/debug helper — current count for a wallet within the active window.
    #[cfg(test)]
    pub fn count_for(&self, wallet_pk: &[u8; 32], now: u64) -> usize {
        let window_start = now.saturating_sub(CLARA_RATE_LIMIT_WINDOW_SECS);
        self.history.get(wallet_pk)
            .map(|h| h.iter().filter(|&&t| t >= window_start).count())
            .unwrap_or(0)
    }
}

/// Outcome of a CLARA registration request, mirrored to a JSON HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaraRegistrationError {
    /// Body did not parse as the expected request shape.
    BadRequest,
    /// Heal cheque is not a self-send (sender_wallet_id != receiver_wallet_id).
    NotSelfSend,
    /// Heal cheque has fewer than 3 cheques in the bundle.
    InsufficientSignatures,
    /// Bundle internal consistency failed (mismatched txid/amount/etc, or
    /// non-distinct validators).
    InconsistentBundle,
    /// One of the cheques' validator signatures failed to verify.
    InvalidValidatorSignature,
    /// `declared_garbage` was empty. CLARA must declare at least one
    /// abandoned state (the whole point is to roll forward past garbage).
    EmptyGarbage,
    /// `consumed_state_id` (= the wallet's pre-heal state, derived from
    /// the cheque's produced_state_id chain) already appears in the txid
    /// bloom chain — the wallet has already healed or already double-spent.
    ConsumedAlreadyTxidRegistered,
    /// KI#43b: the HEALED-FROM state hit the consumed-state chain — the
    /// KI#43 case (real double-heal/double-spend OR a bloom false
    /// positive). Distinct from `ConsumedAlreadyTxidRegistered` (kept for
    /// the declared-garbage lookups) so the node handler can route THIS
    /// hit through the adjudication barrier (§12.4.4) instead of treating
    /// it as final. Fail-closed until a verdict exists.
    ConsumedHealedFromHit,
    /// `consumed_state_id` already appears in the garbage state bloom chain
    /// — the state was already declared garbage by a prior CLARA. Refuse.
    ConsumedAlreadyGarbage,
    /// `heal_txid` already appears in the txid bloom chain — this exact
    /// heal has already been registered. Idempotency: refuse the duplicate.
    HealAlreadyRegistered,
    /// `wallet_pk` declared in the request does not match the heal cheque's
    /// sender/receiver wallet identity (verified via wallet_id pk binding,
    /// or against the heal transaction's client_pk).
    WalletPkMismatch,
    /// The provided heal_transaction is not marked as a TX_HEAL (`is_heal != true`).
    NotMarkedHeal,
    /// `compute_txid(&heal_transaction)` does not match the cheque bundle's txid.
    /// This means the transaction in the request is not the one the validators
    /// witnessed and signed.
    HealTxidMismatch,
    /// The heal_transaction itself is not a self-send (sender != receiver in
    /// the tx, regardless of what the cheque says).
    HealTransactionNotSelfSend,
    /// `declared_garbage` exceeds `MAX_DECLARED_GARBAGE`. Phase 5f DoS bound:
    /// caps bloom-chain pollution, lock-hold time, and on-wire attestation size.
    /// A wallet legitimately needing more entries must split into multiple
    /// CLARA registrations.
    TooManyGarbageStates,
    /// This wallet has exceeded `MAX_CLARA_REGISTRATIONS_PER_HOUR_PER_WALLET`
    /// in the last `CLARA_RATE_LIMIT_WINDOW_SECS`. Phase 5f Finding 3 DoS
    /// bound. The cap counts attempts (not just successes) so that
    /// verify-then-reject floods can't bypass it. The client should back off
    /// for the rest of the hour and retry then.
    RateLimited,
    /// `request.healed_balance` does not match the heal cheque's `state_hash`.
    /// Phase 5f Finding 4: the wallet declared a balance, Nabla recomputed
    /// `BLAKE3(wallet_pk || healed_balance || healed_at_seq)` and got a
    /// different value than the cheque's signed `state_hash`. Either the
    /// declared balance is wrong or the cheque was tampered with. Either way,
    /// reject (the balance is signed into the attestation; since KI#260 no
    /// validator-side decision reads it).
    HealedBalanceMismatch,
}

/// `POST /clara` request body. Phase 5f: real cheque bundle + authoritative TX.
///
/// `wallet_pk`         — the healing wallet's Ed25519 public key. Bound to
///                       the heal transaction (via `tx.client_pk`) and to
///                       the cheque's wallet_id (via `verify_pk_binding`).
/// `heal_cheque`       — k=3 cheque bundle proving the wallet successfully
///                       sent TX_HEAL on fresh validators. Nabla verifies
///                       all signatures.
/// `heal_transaction`  — the actual TX_HEAL transaction the validators
///                       witnessed. Nabla verifies `compute_txid(tx) ==
///                       cheque.txid` to bind it to the bundle, then derives
///                       `healed_from_state_id`, `healed_at_seq` from it
///                       (NO caller assertion of these fields).
/// `declared_garbage`  — the wallet's list of states it considers garbage
///                       (post-poisoning states stored at validators).
#[derive(Debug, Clone)]
pub struct ClaraRegistrationRequest {
    pub wallet_pk: [u8; 32],
    pub heal_cheque: ChequeBundle,
    pub heal_transaction: Transaction,
    pub declared_garbage: Vec<[u8; 32]>,
    /// YPX-018 Phase 5f Finding 4: wallet's canonical post-heal balance.
    /// Nabla verifies this against the heal cheque's `state_hash` (which is
    /// `BLAKE3(wallet_pk || healed_balance || healed_at_seq)`). If the
    /// recomputed hash does not match, the registration is rejected with
    /// `HealedBalanceMismatch`. The cheque is k=3-witnessed, so each fresh
    /// validator has cryptographically committed to this balance via its
    /// signed `state_hash`. (No validator reads it since KI#256/KI#260 — the
    /// roll-forward that once refreshed a poisoned balance is deleted.)
    pub healed_balance: u64,
    /// §4.2a — carried into the recomputed §15 anchor (never cleared by a heal).
    pub declared_emission_claimed_epoch: u64,
    pub declared_stake_floor_until: u64, // ValidatorJoin §6b.13 — the seventh §15 field, same rule
    pub declared_wallet_format: axiom_core_logic::types::WalletFormat, // §6b.13 — the format block
}

/// Successful registration result. The caller (HTTP handler) wraps these
/// fields into the on-wire `ClaraAttestation`.
///
/// Phase 5f: now also returns the authoritative `healed_from_state_id` and
/// `healed_at_seq` derived from the heal transaction, so the HTTP handler
/// does not need to copy caller-asserted values into the attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaraRegistrationOk {
    pub heal_txid: [u8; 32],
    pub healed_to_state_id: [u8; 32],
    pub healed_from_state_id: [u8; 32],
    pub healed_at_seq: u64,
    /// Phase 5f Finding 4: verified-via-state_hash post-heal balance.
    pub healed_balance: u64,
    pub bloom_era_id: u64,
    pub bloom_era_root: [u8; 32],
}

/// Verify a single validator cheque's signature.
///
/// `ValidatorCheque.signature` is the validator's Ed25519 signature over
/// the canonical cheque commitment. One format, no version tag —
/// `compute_cheque_commitment` (CLAUDE.md §13).
fn verify_cheque_signature(cheque: &ValidatorCheque) -> bool {
    if cheque.validator_pk.len() != 32 {
        return false;
    }

    let commitment = axiom_core_logic::compute::compute_cheque_commitment(
        &cheque.txid,
        &cheque.state_hash,
        &cheque.produced_state_id,
        &cheque.sender_wallet_id,
        &cheque.receiver_wallet_id,
        cheque.amount,
        cheque.epoch,
        cheque.created_at,
        cheque.rate_bps,
        &cheque.dmap_input_hash,
        &cheque.dmap_output_hash,
        cheque.oracle_claim.as_ref(),
        cheque.recall_target_tx_id.as_ref(),
    );

    axiom_core_logic::verify::verify_ed25519(
        &cheque.validator_pk,
        &commitment,
        &cheque.signature,
    )
    .is_ok()
}

/// Pure protocol logic for CLARA registration. Verifies the heal cheque
/// bundle cryptographically, performs freshness checks, inserts into both
/// bloom chains, and returns the era info plus the canonical heal_txid /
/// healed_to_state_id derived from the cheque.
///
/// Caller (HTTP handler) is responsible for:
///   - Decoding the HTTP body into a `ClaraRegistrationRequest`
///   - Atomically holding both bloom chains' write locks for the duration
///     of this call
///   - Building the on-wire `ClaraAttestation` from the returned info
///   - Signing the attestation with the node's Ed25519 key + populating
///     the NBC trust anchor fields (Phase 5e fix #5)
///   - Returning the on-wire `ClaraAttestation` over HTTP
/// Two chains, split by DIRECTION (2026-07-28):
///
/// * `heal_chain` — CLARA's own, heal registrations only. **Written** to, for
///   idempotency. Kept out of the redeemed set on purpose: the 2026-07-07 "ONE
///   txid domain" decision feeds the YPX-014 service at redeem-finalize ONLY, so
///   writing heal txids there would make `/query-txid` answer REDEEMED for merely
///   healed txids — the exact pollution that decision removed.
/// * `redeemed_chain` — the SMT's redeemed-TXID chain, **read** only. Consulted
///   for the one lookup that is genuinely txid-domain: a heal txid must not
///   collide with an already-redeemed txid.
/// * `consumed_chain` — the SMT's consumed-STATE chain, **read** only. Every
///   state-id lookup goes here.
///
/// DOMAIN DISCIPLINE (2026-07-28): each lookup queries a set of ITS OWN domain.
/// Previously state ids were looked up in a filter of txids — 32-byte values in
/// different domains sharing a hash space, so a hit could only ever be
/// coincidence. YPX-018 §384 ("pre-TX1 state is now consumed in the txid bloom")
/// was written when there was ONE combined bloom; the implementation has since
/// split txids from consumed states, and `consumed_chain` is the set that answers
/// "has this state been advanced past" — exactly what the error doc means by
/// "already healed or already double-spent".
pub fn register_clara(
    request: &ClaraRegistrationRequest,
    heal_chain: &mut BloomChain,
    redeemed_chain: &BloomChain,
    consumed_chain: &BloomChain,
    garbage_chain: &mut GarbageStateChain,
    rate_limiter: &mut ClaraRateLimiter,
    current_tick: u64,
    // KI#43b: a state the adjudication barrier ACQUITTED (proven bloom
    // false positive — every recording node answered absent + clean, see
    // §12.4.4). The healed-from freshness check is skipped for EXACTLY
    // this state; the bloom itself is never edited. None on every path
    // that has no verdict.
    acquitted_state: Option<&crate::types::StateId>,
) -> Result<ClaraRegistrationOk, ClaraRegistrationError> {
    // (0) Phase 5f Finding 3: per-wallet rate limit. Run BEFORE any
    // signature verification or bloom-chain work — that's the whole point
    // of rate limiting. If the limit blocks the request, no verify CPU is
    // burned and no locks are taken.
    rate_limiter.check_and_record(&request.wallet_pk, current_tick)?;

    let bundle = &request.heal_cheque;
    let tx = &request.heal_transaction;

    // (1) The FLOOR half of `max(k, 3)` (YP §17.3.1.4 v2.19.0, KI#150). The
    // tier half is judged at (5f), once (5e) has authenticated the address
    // the k is read from — never from a constant.
    if bundle.cheques.len() < 3 {
        return Err(ClaraRegistrationError::InsufficientSignatures);
    }

    // (2) Bundle internal consistency (matching txid/receiver/amount/epoch
    // AND distinct validators — has_distinct_validators is implied by
    // verify_consistency).
    if !bundle.verify_consistency() {
        return Err(ClaraRegistrationError::InconsistentBundle);
    }

    // (3) Self-send invariant — heal cheque MUST be sender→self.
    let first = &bundle.cheques[0];
    if first.sender_wallet_id != first.receiver_wallet_id {
        return Err(ClaraRegistrationError::NotSelfSend);
    }

    // (4) Each cheque's validator signature must verify cryptographically
    // against the canonical cheque commitment using the cheque's validator_pk.
    for cheque in &bundle.cheques {
        if !verify_cheque_signature(cheque) {
            return Err(ClaraRegistrationError::InvalidValidatorSignature);
        }
    }

    // (5a) Phase 5f: the heal transaction MUST be marked as a TX_HEAL.
    if !tx.is_heal() {
        return Err(ClaraRegistrationError::NotMarkedHeal);
    }

    // (5b) Phase 5f: the heal transaction MUST itself be a self-send.
    // (This is independent from the cheque-level self-send check above —
    // here we're enforcing that the authoritative TX is also self-send,
    // not just the validators' echo of it in the cheque.)
    if tx.sender_wallet_id != tx.receiver_wallet_id {
        return Err(ClaraRegistrationError::HealTransactionNotSelfSend);
    }

    // (5c) Phase 5f: the heal transaction MUST be the one the cheques
    // signed. compute_txid binds tx.consumed_state_id, tx.client_pk,
    // tx.wallet_seq, tx.receiver_wallet_id, tx.amount, tx.nonce, tx.epoch.
    let computed_txid = axiom_core_logic::compute::compute_txid(tx);
    if computed_txid != first.txid {
        return Err(ClaraRegistrationError::HealTxidMismatch);
    }

    // (5d) Phase 5f: bind request.wallet_pk to the transaction's client_pk.
    // After (5c), tx is the authoritative one; this binds the request to it.
    if tx.client_pk.as_slice() != request.wallet_pk.as_slice() {
        return Err(ClaraRegistrationError::WalletPkMismatch);
    }

    // (5e) Phase 5f: bind wallet_pk to the cheque's wallet_id (string form)
    // via the YPX-007 wallet_id pk binding (the `pk_bind` field). This is
    // belt-and-suspenders on top of (5d) — even if a future code path were
    // to relax (5d), the wallet_id ↔ pk binding still holds.
    if axiom_core_logic::wallet_id::verify_pk_binding(
        &first.sender_wallet_id,
        &request.wallet_pk,
    ).is_err() {
        return Err(ClaraRegistrationError::WalletPkMismatch);
    }

    // (5f) The TIER half of `max(k, 3)` — YP §17.3.1.4 v2.19.0 (KI#150): the
    // heal's k is the receiver address's tier (== sender's: (3) proved the
    // self-send, (5e) proved the address). Never a literal.
    let heal_k = match axiom_core_logic::wallet_id::extract_security_level(&first.receiver_wallet_id) {
        Ok((k, _)) => (k as usize).max(3),
        Err(_) => return Err(ClaraRegistrationError::WalletPkMismatch),
    };
    if bundle.cheques.len() < heal_k {
        return Err(ClaraRegistrationError::InsufficientSignatures);
    }

    // (6a) Non-empty declared garbage list
    if request.declared_garbage.is_empty() {
        return Err(ClaraRegistrationError::EmptyGarbage);
    }

    // (6b) Phase 5f DoS bound: cap declared_garbage size BEFORE doing any
    // bloom-chain work. Without this cap a single valid request could ship
    // millions of entries, each costing a lookup + insertion under write
    // locks and inflating the active era's FPR past target.
    if request.declared_garbage.len() > MAX_DECLARED_GARBAGE {
        return Err(ClaraRegistrationError::TooManyGarbageStates);
    }

    // (7) Derive canonical heal info from the cheque + tx (NOT caller-asserted).
    // After (5c) the tx is bound to the cheques, so tx.consumed_state_id and
    // tx.wallet_seq are authoritative.
    let heal_txid = first.txid;
    let healed_to_state_id = first.produced_state_id;
    let healed_from_state_id = tx.consumed_state_id;
    let _healed_at_seq = tx.wallet_seq; // exposed via ClaraRegistrationOk below

    // (7b) Phase 5f Finding 4: verify the wallet-declared `healed_balance`
    // against the cheque's `state_hash`. The cheque is k=3-witnessed, so
    // each fresh validator has cryptographically committed to
    // `BLAKE3(wallet_pk || healed_balance || healed_at_seq)` via its
    // signature on the cheque commitment (which itself binds state_hash).
    // We recompute the same hash from the (wallet_pk, declared_balance,
    // wallet_seq) triple and compare. Match → trust the declared balance.
    // Mismatch → reject (the attestation must not sign an unanchored
    // balance, although no validator reads it since KI#260).
    let recomputed_state_hash = axiom_core_logic::compute::compute_state_hash(
        &request.wallet_pk,
        request.healed_balance,
        tx.wallet_seq,
        0, // YPX-020: a heal is not a re-anchor — its produced state is non-hibernating
        0, // §5.2.2c: a heal never stakes, and a staked wallet cannot reach here
        request.declared_emission_claimed_epoch, // §4.2a: carried, never cleared by a heal
        request.declared_stake_floor_until, // §6b.13: carried, never cleared by a heal
        &request.declared_wallet_format,    // §6b.13
    );
    if recomputed_state_hash != first.state_hash {
        return Err(ClaraRegistrationError::HealedBalanceMismatch);
    }

    // (8) Idempotency — refuse if this exact heal has already been registered
    // Idempotency: prior heals (CLARA's own set). Also refuse a heal txid that
    // collides with an already-REDEEMED txid — both are txid-domain lookups.
    if let ChainLookup::Hit { .. } = heal_chain.lookup(&heal_txid) {
        return Err(ClaraRegistrationError::HealAlreadyRegistered);
    }
    if let ChainLookup::Hit { .. } = redeemed_chain.lookup(&heal_txid) {
        return Err(ClaraRegistrationError::HealAlreadyRegistered);
    }

    // (9) Freshness — the authoritative consumed state must not already be
    // in either chain.
    let consumed = &healed_from_state_id;
    // STATE-domain lookup → the consumed-state set. For a legitimate heal this
    // state is the wallet's CURRENT head (the SMT advance happens only after this
    // call succeeds), so it is not yet consumed and the check passes. It fires
    // exactly when the wallet has already advanced past it — i.e. already healed
    // or already double-spent, which is what the error says.
    match consumed_chain.lookup(consumed) {
        ChainLookup::Hit { .. } if acquitted_state == Some(consumed) => {
            // KI#43b: barrier-acquitted bloom false positive — the exact
            // records of every recording node prove this state was never
            // consumed. Proceed; log at the call site.
        }
        ChainLookup::Hit { .. } => {
            return Err(ClaraRegistrationError::ConsumedHealedFromHit);
        }
        ChainLookup::Miss => {}
    }
    match garbage_chain.lookup(consumed) {
        ChainLookup::Hit { .. } => {
            return Err(ClaraRegistrationError::ConsumedAlreadyGarbage);
        }
        ChainLookup::Miss => {}
    }

    // Also verify none of the declared garbage states are already-txid
    // (trying to retroactively mark a confirmed transaction as abandoned).
    for gs in &request.declared_garbage {
        // KI#43b (§12.4.4 implementation note): the barrier acquittal for a
        // state applies at EVERY freshness lookup of that state in this
        // registration. The standard partial marker declares the healed-from
        // state itself as garbage, so the same bloom FP that check (9) just
        // skipped re-fires HERE — the v1 build stranded the acquitted victim
        // one line after acquitting it (found by the 2026-07-29 live gate).
        if acquitted_state == Some(gs) {
            continue;
        }
        // STATE-domain lookup: a state that was genuinely advanced past cannot be
        // retroactively declared abandoned.
        if let ChainLookup::Hit { .. } = consumed_chain.lookup(gs) {
            return Err(ClaraRegistrationError::ConsumedAlreadyTxidRegistered);
        }
    }

    // (10) Insert the heal txid into the active txid era
    // Heals are written to CLARA's own chain, never the redeemed set.
    heal_chain.insert(current_tick, &heal_txid);

    // (11) Insert each declared garbage state into the active garbage era
    for gs in &request.declared_garbage {
        garbage_chain.insert(current_tick, gs);
    }

    // (12) Return the canonical info for the caller to embed in the attestation
    let active = heal_chain.active_era();
    Ok(ClaraRegistrationOk {
        heal_txid,
        healed_to_state_id,
        healed_from_state_id,
        healed_at_seq: tx.wallet_seq,
        healed_balance: request.healed_balance, // verified via state_hash above
        bloom_era_id: active.meta.era_id,
        bloom_era_root: active.meta.bloom_root, // zero while active
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_core_logic::types::{Transaction, TxKind, ValidatorCheque};
    use ed25519_dalek::{Signer, SigningKey};

    fn make_state(n: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = n;
        h[31] = n;
        h
    }

    /// Build a real wallet keypair + bound wallet_id (k=3 dmap default).
    /// Returns (wallet_pk_bytes, wallet_id_string).
    fn make_wallet(seed: u8) -> ([u8; 32], String) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        // Use a deterministic salt and email derived from seed.
        let email = format!("heal{}@axiom", seed);
        let salt = "ab"; // 2 chars
        let wid = axiom_core_logic::wallet_id::generate_wallet_id(&email, salt, &pk)
            .expect("wallet_id generation");
        (pk, wid)
    }

    /// Build a real TX_HEAL self-send transaction. The cheque txid is
    /// derived from compute_txid(&tx) so the bundle binds to it.
    fn make_heal_transaction(
        wallet_pk: &[u8; 32],
        wallet_id: &str,
        consumed_state_id: [u8; 32],
        wallet_seq: u64,
        amount: u64,
        epoch: u64,
    ) -> Transaction {
        Transaction {
            consumed_state_id,
            client_pk: wallet_pk.to_vec(),
            sender_wallet_id: wallet_id.to_string(),
            wallet_seq,
            receiver_wallet_id: wallet_id.to_string(), // self-send
            receiver_address: None,
            amount,
            reference: "heal".to_string(),
            nonce: 0,
            epoch,
            client_sig: vec![],
            scar_passcode: None,
            burn_target_tx_id: None,
            oracle_claim: None,
            required_k: 3,
            proof_type: 1,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Heal,
            recall_target_tx_id: None,
        }
    }

    /// Build a real validator-signed cheque for the heal scenario.
    /// Each validator gets its own Ed25519 key and produces a real signature
    /// over the canonical cheque commitment.
    fn make_signed_cheque(
        validator_seed: u8,
        txid: [u8; 32],
        produced_state_id: [u8; 32],
        wallet_email: &str,
        amount: u64,
        epoch: u64,
    ) -> ValidatorCheque {
        make_signed_cheque_inner(
            validator_seed, txid, produced_state_id, wallet_email,
            amount, epoch, None,
        )
    }

    fn make_signed_cheque_inner(
        validator_seed: u8,
        txid: [u8; 32],
        produced_state_id: [u8; 32],
        wallet_email: &str,
        amount: u64,
        epoch: u64,
        dmap_hashes: Option<([u8; 32], [u8; 32])>,
    ) -> ValidatorCheque {
        make_signed_cheque_inner_with_state_hash(
            validator_seed, txid, produced_state_id, wallet_email,
            amount, epoch, dmap_hashes, [0u8; 32],
        )
    }

    fn make_signed_cheque_inner_with_state_hash(
        validator_seed: u8,
        txid: [u8; 32],
        produced_state_id: [u8; 32],
        wallet_email: &str,
        amount: u64,
        epoch: u64,
        dmap_hashes: Option<([u8; 32], [u8; 32])>,
        state_hash: [u8; 32],
    ) -> ValidatorCheque {
        let sk = SigningKey::from_bytes(&[validator_seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        let validator_id = {
            let mut id = [0u8; 32];
            id[0] = validator_seed;
            id
        };
        let (dmap_input_hash, dmap_output_hash) = dmap_hashes.unwrap_or(([0u8; 32], [0u8; 32]));
        let rate_bps: u32 = 10;
        let commitment = axiom_core_logic::compute::compute_cheque_commitment(
            // §5.2.2c — `sender_wallet_id` and `created_at` became SIGNED on
            // 2026-09-05. A CLARA heal cheque is a SELF-SEND, so the sender IS
            // `wallet_email`; passing it keeps the fixture truthful rather than
            // merely compiling. `created_at` is deliberately DIFFERENT from
            // `epoch` so an argument-order swap changes the commitment and the
            // signature check catches it.
            &txid, &state_hash, &produced_state_id, wallet_email, wallet_email,
            amount, epoch,
            0, // created_at — these fixtures do not exercise the stake-lock stamp
            rate_bps,
            &dmap_input_hash, &dmap_output_hash,
            None,
            None,
        );
        let signature = sk.sign(&commitment).to_bytes().to_vec();
        ValidatorCheque {
            fact_certificates: Vec::new(),
            recall_target_tx_id: None,
            txid,
            validator_id,
            validator_pk: pk.to_vec(),
            signature,
            execution_proof: vec![],
            vbc_bundle: None,
            carrier_type: "test".into(),
            carrier_address: "test@axiom".into(),
            sender_wallet_id: wallet_email.to_string(),     // self-send
            receiver_wallet_id: wallet_email.to_string(),   // self-send
            amount,
            rate_bps,
            reference: "heal".into(),
            epoch,
            created_at: 0,
            state_hash,
            produced_state_id,
            sender_fact_chain: None,
            zkp_nonce: None,
            proof_type: 0,
            dmap_input_hash,
            dmap_output_hash,
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        }
    }

    fn make_bundle(
        txid: [u8; 32],
        produced: [u8; 32],
        wallet_id: &str,
        amount: u64,
        epoch: u64,
        state_hash: [u8; 32],
    ) -> ChequeBundle {
        ChequeBundle {
            cheques: vec![
                make_signed_cheque_inner_with_state_hash(
                    1, txid, produced, wallet_id, amount, epoch, None, state_hash),
                make_signed_cheque_inner_with_state_hash(
                    2, txid, produced, wallet_id, amount, epoch, None, state_hash),
                make_signed_cheque_inner_with_state_hash(
                    3, txid, produced, wallet_id, amount, epoch, None, state_hash),
            ],
            fact_chain: None,
        }
    }

    /// Phase 5f: build a fully bound CLARA request — real wallet keypair,
    /// bound wallet_id, real TX_HEAL transaction, txid derived from the tx,
    /// state_hash derived from (wallet_pk, healed_balance, wallet_seq) so that
    /// Finding 4's `HealedBalanceMismatch` check passes.
    fn make_request() -> ClaraRegistrationRequest {
        let (wallet_pk, wallet_id) = make_wallet(0xC1);
        let consumed = make_state(0x10);
        let produced = make_state(0x20);
        let amount = 500_000u64;
        let epoch = 100u64;
        let wallet_seq = 5u64;
        let healed_balance = 1_000_000_000u64;
        let tx = make_heal_transaction(
            &wallet_pk, &wallet_id, consumed, wallet_seq, amount, epoch,
        );
        let txid = axiom_core_logic::compute::compute_txid(&tx);
        // Phase 5f Finding 4: state_hash binds (wallet_pk, healed_balance, wallet_seq)
        let state_hash = axiom_core_logic::compute::compute_state_hash(
            &wallet_pk, healed_balance, wallet_seq, 0, 0,
            0, // §4.2a
            0, &axiom_core_logic::types::WalletFormat::CURRENT, // §6b.13
        );
        ClaraRegistrationRequest {
            wallet_pk,
            heal_cheque: make_bundle(txid, produced, &wallet_id, amount, epoch, state_hash),
            heal_transaction: tx,
            declared_garbage: vec![make_state(0x11), make_state(0x12)],
            healed_balance,
            declared_emission_claimed_epoch: 0,
            declared_stake_floor_until: 0,
            declared_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
        }
    }

    /// An empty REDEEMED set — the default for tests that are not exercising the
    /// "consumed state was already redeemed" path. Same dimensions as the heal
    /// chain so a size mismatch never masks a logic error.
    fn empty_redeemed() -> BloomChain {
        BloomChain::new(0, 100_000, 1000)
    }

    fn fresh_chains() -> (BloomChain, GarbageStateChain) {
        (
            BloomChain::new(0, 100_000, 1000),
            GarbageStateChain::new(0, 100_000, 1000),
        )
    }

    /// Helper: build (txid_chain, garbage_chain, rate_limiter) for tests that
    /// don't care about the limiter — each fresh limiter starts empty so the
    /// first few attempts always pass.
    fn fresh_chains_with_limiter() -> (BloomChain, GarbageStateChain, ClaraRateLimiter) {
        let (txid, garbage) = fresh_chains();
        (txid, garbage, ClaraRateLimiter::new())
    }

    #[test]
    fn test_register_clara_happy_path_with_real_signatures() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let req = make_request();
        let expected_txid = axiom_core_logic::compute::compute_txid(&req.heal_transaction);
        let expected_consumed = req.heal_transaction.consumed_state_id;
        let expected_seq = req.heal_transaction.wallet_seq;
        let result = register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None)
            .expect("happy path must succeed");
        assert_eq!(result.bloom_era_id, 0);
        assert_eq!(result.heal_txid, expected_txid);
        assert_eq!(result.healed_to_state_id, make_state(0x20));
        // Phase 5f: from-state and seq are derived authoritatively from the tx.
        assert_eq!(result.healed_from_state_id, expected_consumed);
        assert_eq!(result.healed_at_seq, expected_seq);

        match txid.lookup(&result.heal_txid) {
            ChainLookup::Hit { era_id, .. } => assert_eq!(era_id, 0),
            ChainLookup::Miss => panic!("heal txid should be in chain"),
        }
        for gs in &req.declared_garbage {
            match garbage.lookup(gs) {
                ChainLookup::Hit { era_id, .. } => assert_eq!(era_id, 0),
                ChainLookup::Miss => panic!("garbage state should be in chain"),
            }
        }
    }

    /// Phase 5f: WalletPkMismatch must fire when request.wallet_pk does not
    /// match the heal transaction's client_pk.
    #[test]
    fn test_register_clara_rejects_wallet_pk_not_matching_tx_client_pk() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        // Replace request.wallet_pk with a different key while leaving the tx
        // and the cheque alone. tx.client_pk no longer matches → reject.
        req.wallet_pk = make_state(0xEE);
        assert_eq!(
            register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None),
            Err(ClaraRegistrationError::WalletPkMismatch)
        );
    }

    /// Phase 5f: WalletPkMismatch must also fire when wallet_pk doesn't bind
    /// to the cheque's wallet_id (verify_pk_binding fails). We construct this
    /// by re-signing the tx + bundle with a different wallet_id that does
    /// match the new pk, but the cheque's sender_wallet_id we leave at the
    /// original. Easier: swap both pk AND tx.client_pk to a new key whose
    /// wallet_id binding doesn't match the cheque's sender_wallet_id.
    #[test]
    fn test_register_clara_rejects_pk_not_bound_to_cheque_wallet_id() {
        let (mut txid_chain, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        // New wallet pk: tx.client_pk == request.wallet_pk (so 5d passes),
        // but the cheque's sender_wallet_id was generated for the OLD pk,
        // so verify_pk_binding(sender_wallet_id, new_pk) fails (5e).
        let evil_sk = SigningKey::from_bytes(&[0xAB; 32]);
        let evil_pk = evil_sk.verifying_key().to_bytes();
        req.wallet_pk = evil_pk;
        req.heal_transaction.client_pk = evil_pk.to_vec();
        // This also changes the txid (client_pk is in compute_txid), so the
        // cheque->tx binding (5c) fires before (5e). Check we get one of the
        // two binding-related errors.
        let err = register_clara(&req, &mut txid_chain, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None)
            .expect_err("must reject");
        assert!(
            matches!(
                err,
                ClaraRegistrationError::HealTxidMismatch
                    | ClaraRegistrationError::WalletPkMismatch
            ),
            "expected HealTxidMismatch or WalletPkMismatch, got {:?}",
            err,
        );
    }

    /// Phase 5f: NotMarkedHeal — clearing tx.is_heal() must reject.
    #[test]
    fn test_register_clara_rejects_tx_not_marked_heal() {
        let (mut txid_chain, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        req.heal_transaction.kind = axiom_core_logic::types::TxKind::Normal;
        // Mutating is_heal does NOT change compute_txid (is_heal is not in the
        // hash), so the cheques still bind to the tx. Only the is_heal check fires.
        assert_eq!(
            register_clara(&req, &mut txid_chain, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None),
            Err(ClaraRegistrationError::NotMarkedHeal)
        );
    }

    /// Phase 5f: HealTxidMismatch — mutating tx after the cheque was signed
    /// (e.g., consumed_state_id) must reject.
    #[test]
    fn test_register_clara_rejects_tx_consumed_state_mismatch_with_cheque() {
        let (mut txid_chain, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        req.heal_transaction.consumed_state_id = make_state(0x99);
        assert_eq!(
            register_clara(&req, &mut txid_chain, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None),
            Err(ClaraRegistrationError::HealTxidMismatch)
        );
    }

    /// Phase 5f: healed_from_state_id and healed_at_seq are now derived from
    /// the authoritative tx — caller cannot override them. This test proves
    /// that even if a caller "wanted" to assert different values, there's no
    /// path to do so (the request struct no longer has those fields, so any
    /// attempt fails to compile). Compile-time guarantee.
    #[test]
    fn test_register_clara_phase5f_caller_cannot_assert_from_state_or_seq() {
        // The struct literal below would fail to compile if the request still
        // accepted healed_from_state_id / healed_at_seq.
        let (wallet_pk, wallet_id) = make_wallet(0xD2);
        let tx = make_heal_transaction(
            &wallet_pk, &wallet_id, make_state(0x42), 7, 500_000, 100,
        );
        let txid = axiom_core_logic::compute::compute_txid(&tx);
        let healed_balance = 1_000u64;
        let state_hash = axiom_core_logic::compute::compute_state_hash(
            &wallet_pk, healed_balance, 7, 0, 0,
        0, 0, &axiom_core_logic::types::WalletFormat::CURRENT,
    );
        let _req = ClaraRegistrationRequest {
            wallet_pk,
            heal_cheque: make_bundle(txid, make_state(0x21), &wallet_id, 500_000, 100, state_hash),
            heal_transaction: tx,
            declared_garbage: vec![make_state(0x33)],
            healed_balance,
            declared_emission_claimed_epoch: 0,
            declared_stake_floor_until: 0,
            declared_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
        };
    }

    #[test]
    fn test_register_clara_rejects_fewer_than_3_cheques() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        req.heal_cheque.cheques.pop();
        assert_eq!(
            register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None),
            Err(ClaraRegistrationError::InsufficientSignatures)
        );
    }

    #[test]
    fn test_register_clara_rejects_inconsistent_bundle() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        // Tamper with one cheque's amount → consistency fails
        req.heal_cheque.cheques[1].amount = 999_999;
        assert_eq!(
            register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None),
            Err(ClaraRegistrationError::InconsistentBundle)
        );
    }

    #[test]
    fn test_register_clara_rejects_non_self_send() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        // Tamper with both sender + receiver via re-signing? Easier:
        // change all 3 cheques' receiver_wallet_id to a different wallet.
        // But that breaks consistency (mismatched receiver). Use a fresh
        // bundle where sender != receiver from the start.
        let txid_h = make_state(0xBB);
        let produced = make_state(0x30);
        let sk = SigningKey::from_bytes(&[7; 32]);
        let pk = sk.verifying_key().to_bytes();
        let sender = "alice@test";
        let receiver = "bob@test";
        let state_hash = [0u8; 32];
        let amount = 500_000u64;
        let epoch = 100u64;
        let mut cheques = Vec::new();
        let rate_bps: u32 = 10;
        for i in 1..=3u8 {
            let sk_i = SigningKey::from_bytes(&[i; 32]);
            let pk_i = sk_i.verifying_key().to_bytes();
            let commit = axiom_core_logic::compute::compute_cheque_commitment(
                // Now that `sender_wallet_id` is SIGNED, this fixture is
                // stronger than it was: the cheque genuinely COMMITS to a
                // sender that differs from the receiver, so the non-self-send
                // it asserts on is cryptographically real and not just a field.
                &txid_h, &state_hash, &produced, sender, receiver, amount, epoch,
                0, // created_at
                rate_bps,
                &[0u8; 32], &[0u8; 32],
                None,
                None,
            );
            let sig = sk_i.sign(&commit).to_bytes().to_vec();
            let mut id = [0u8; 32];
            id[0] = i;
            cheques.push(ValidatorCheque {
                fact_certificates: Vec::new(),
                recall_target_tx_id: None,
                txid: txid_h,
                validator_id: id,
                validator_pk: pk_i.to_vec(),
                signature: sig,
                execution_proof: vec![],
                vbc_bundle: None,
                carrier_type: "test".into(),
                carrier_address: "test@axiom".into(),
                sender_wallet_id: sender.to_string(),
                receiver_wallet_id: receiver.to_string(),
                amount,
                rate_bps,
                reference: "heal".into(),
                epoch,
                created_at: 0,
                state_hash,
                produced_state_id: produced,
                sender_fact_chain: None,
                zkp_nonce: None,
                proof_type: 0,
                dmap_input_hash: [0u8; 32],
                dmap_output_hash: [0u8; 32],
                oracle_claim: None,
                nabla_hint: None,
                sender_wallet_pk: None,
            });
        }
        req.heal_cheque = ChequeBundle { cheques, fact_chain: None };
        let _ = pk; // unused
        assert_eq!(
            register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None),
            Err(ClaraRegistrationError::NotSelfSend)
        );
    }

    #[test]
    fn test_register_clara_rejects_forged_validator_signature() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        // Replace signature with random bytes
        req.heal_cheque.cheques[0].signature = vec![0xDE; 64];
        assert_eq!(
            register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None),
            Err(ClaraRegistrationError::InvalidValidatorSignature)
        );
    }

    #[test]
    fn test_register_clara_rejects_empty_garbage() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        req.declared_garbage.clear();
        assert_eq!(
            register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None),
            Err(ClaraRegistrationError::EmptyGarbage)
        );
    }

    #[test]
    fn test_register_clara_double_call_rejected_by_idempotency() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let req = make_request();
        register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None).expect("first call ok");
        assert_eq!(
            register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 51, None),
            Err(ClaraRegistrationError::HealAlreadyRegistered)
        );
    }

    #[test]
    fn test_register_clara_rejects_already_garbage_consumed() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let req = make_request();
        // Phase 5f: consumed state is derived from tx.consumed_state_id.
        garbage.insert(10, &req.heal_transaction.consumed_state_id);
        assert_eq!(
            register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None),
            Err(ClaraRegistrationError::ConsumedAlreadyGarbage)
        );
    }

    /// KI#43b: a consumed-chain hit on the HEALED-FROM state must surface as
    /// the adjudicable `ConsumedHealedFromHit` (routed to the §12.4.4
    /// barrier by the node handler) — NOT the terminal garbage-path error.
    #[test]
    fn test_register_clara_healed_from_hit_is_adjudicable_variant() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let req = make_request();
        let mut consumed_chain = empty_redeemed();
        consumed_chain.insert(10, &req.heal_transaction.consumed_state_id);
        assert_eq!(
            register_clara(&req, &mut txid, &empty_redeemed(), &consumed_chain, &mut garbage, &mut limiter, 50, None),
            Err(ClaraRegistrationError::ConsumedHealedFromHit)
        );
    }

    /// KI#43b regression (2026-07-29 live gate): the LIVE heal shape declares
    /// the healed-from state ITSELF as garbage (the standard partial marker),
    /// so the acquitted FP is looked up TWICE — check (9) AND the
    /// declared-garbage cross-check. The v1 build skipped only check (9) and
    /// stranded the acquitted victim on the second lookup with the terminal
    /// `ConsumedAlreadyTxidRegistered`. The acquittal must cover every
    /// lookup site of the acquitted state (§12.4.4 implementation note).
    #[test]
    fn test_register_clara_acquittal_covers_declared_garbage_lookup() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        let healed_from = req.heal_transaction.consumed_state_id;
        // Live shape: the healed-from state is also the (only) declared garbage.
        req.declared_garbage = vec![healed_from];
        let mut consumed_chain = empty_redeemed();
        consumed_chain.insert(10, &healed_from); // the injected/bloom FP
        register_clara(
            &req, &mut txid, &empty_redeemed(), &consumed_chain,
            &mut garbage, &mut limiter, 50, Some(&healed_from),
        ).expect("acquitted FP must clear BOTH freshness lookups of the same state");
    }

    /// KI#43b: with a barrier-ACQUITTED verdict for exactly the healed-from
    /// state, the freshness check skips the proven false positive and the
    /// heal proceeds. An acquittal for a DIFFERENT state must not skip.
    #[test]
    fn test_register_clara_acquitted_state_skips_only_that_state() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let req = make_request();
        let healed_from = req.heal_transaction.consumed_state_id;
        let mut consumed_chain = empty_redeemed();
        consumed_chain.insert(10, &healed_from);
        // Acquitted for the hit state: proceeds past freshness (must be Ok —
        // make_request is the happy-path fixture).
        register_clara(&req, &mut txid, &empty_redeemed(), &consumed_chain, &mut garbage, &mut limiter, 50, Some(&healed_from))
            .expect("acquitted false positive must heal");
        // A verdict for some OTHER state must not skip the check.
        let (mut txid2, mut garbage2, mut limiter2) = fresh_chains_with_limiter();
        let other = make_state(0x77);
        assert_eq!(
            register_clara(&req, &mut txid2, &empty_redeemed(), &consumed_chain, &mut garbage2, &mut limiter2, 50, Some(&other)),
            Err(ClaraRegistrationError::ConsumedHealedFromHit)
        );
    }

    /// Phase 5f bug fix regression test: heal cheques with non-zero DMAP
    /// hashes (the production case) MUST verify in register_clara. Pre-fix,
    /// the verifier ignored the DMAP-hash binding in the commitment and
    /// rejected real heal cheques with InvalidValidatorSignature.
    #[test]
    fn test_register_clara_dmap_heal_cheques_verify() {
        let (mut txid_chain, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let (wallet_pk, wallet_id) = make_wallet(0xD3);
        let consumed = make_state(0x10);
        let produced = make_state(0x20);
        let amount = 500_000u64;
        let epoch = 100u64;
        let wallet_seq = 5u64;
        let tx = make_heal_transaction(
            &wallet_pk, &wallet_id, consumed, wallet_seq, amount, epoch,
        );
        let txid = axiom_core_logic::compute::compute_txid(&tx);
        // Production-style DMAP hashes (non-zero)
        let dmap_in = [0xD1; 32];
        let dmap_out = [0xD2; 32];
        let healed_balance = 1_000_000u64;
        let state_hash = axiom_core_logic::compute::compute_state_hash(
            &wallet_pk, healed_balance, wallet_seq, 0, 0,
        0, 0, &axiom_core_logic::types::WalletFormat::CURRENT,
    );
        let cheques = vec![
            make_signed_cheque_inner_with_state_hash(
                1, txid, produced, &wallet_id, amount, epoch,
                Some((dmap_in, dmap_out)), state_hash),
            make_signed_cheque_inner_with_state_hash(
                2, txid, produced, &wallet_id, amount, epoch,
                Some((dmap_in, dmap_out)), state_hash),
            make_signed_cheque_inner_with_state_hash(
                3, txid, produced, &wallet_id, amount, epoch,
                Some((dmap_in, dmap_out)), state_hash),
        ];
        let req = ClaraRegistrationRequest {
            wallet_pk,
            heal_cheque: ChequeBundle { cheques, fact_chain: None },
            heal_transaction: tx,
            declared_garbage: vec![make_state(0x11)],
            healed_balance,
            declared_emission_claimed_epoch: 0,
            declared_stake_floor_until: 0,
            declared_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
        };
        let result = register_clara(&req, &mut txid_chain, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None)
            .expect("DMAP heal cheques must verify");
        assert_eq!(result.heal_txid, txid);
    }

    /// Regression test for the consensus.rs sender_wallet_id bug fix:
    /// when the cheque carries a synthetic placeholder sender_wallet_id (the
    /// pre-fix Lambda behavior), CLARA registration must fail at the
    /// pk_binding check. This proves that if the bug ever regresses, CLARA
    /// will refuse the heal rather than silently accept it.
    #[test]
    fn test_register_clara_rejects_synthetic_sender_wallet_id() {
        let (mut txid_chain, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let (wallet_pk, wallet_id) = make_wallet(0xD4);
        let consumed = make_state(0x10);
        let produced = make_state(0x20);
        let amount = 500_000u64;
        let epoch = 100u64;
        let tx = make_heal_transaction(
            &wallet_pk, &wallet_id, consumed, 5, amount, epoch,
        );
        let txid = axiom_core_logic::compute::compute_txid(&tx);
        // Cheques signed against the synthetic placeholder receiver — what the
        // pre-fix Lambda was emitting.
        let synthetic = format!("sender-{}/00000000",
            hex::encode(&wallet_pk[..4]));
        let healed_balance = 1_000u64;
        let state_hash = axiom_core_logic::compute::compute_state_hash(
            &wallet_pk, healed_balance, 5, 0, 0,
        0, 0, &axiom_core_logic::types::WalletFormat::CURRENT,
    );
        let cheques = vec![
            make_signed_cheque_inner_with_state_hash(
                1, txid, produced, &synthetic, amount, epoch, None, state_hash),
            make_signed_cheque_inner_with_state_hash(
                2, txid, produced, &synthetic, amount, epoch, None, state_hash),
            make_signed_cheque_inner_with_state_hash(
                3, txid, produced, &synthetic, amount, epoch, None, state_hash),
        ];
        let req = ClaraRegistrationRequest {
            wallet_pk,
            heal_cheque: ChequeBundle { cheques, fact_chain: None },
            heal_transaction: tx,
            declared_garbage: vec![make_state(0x11)],
            healed_balance,
            declared_emission_claimed_epoch: 0,
            declared_stake_floor_until: 0,
            declared_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
        };
        // Either WalletPkMismatch (verify_pk_binding rejects the synthetic
        // wallet_id) or InvalidWalletId (parse fails) is acceptable. The point
        // is the heal must NOT register cleanly under the placeholder.
        let err = register_clara(&req, &mut txid_chain, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None)
            .expect_err("synthetic sender_wallet_id must be rejected");
        assert!(
            matches!(err, ClaraRegistrationError::WalletPkMismatch),
            "expected WalletPkMismatch, got {:?}", err,
        );
    }

    /// Phase 5f Finding 4: a wallet that lies about its post-heal balance
    /// must be rejected with HealedBalanceMismatch. The check is via the
    /// k=3-witnessed state_hash, so the lie cannot be hidden by simply
    /// flipping the field.
    #[test]
    fn test_register_clara_rejects_lied_healed_balance() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        // The cheque's state_hash binds to the original healed_balance.
        // Inflating the declared balance breaks the recomputed hash check.
        req.healed_balance = req.healed_balance.wrapping_add(999_999);
        assert_eq!(
            register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None),
            Err(ClaraRegistrationError::HealedBalanceMismatch)
        );
    }

    /// Phase 5f Finding 4: the verified healed_balance must propagate into
    /// `ClaraRegistrationOk` so the HTTP handler can put it in the on-wire
    /// attestation. (Without this assertion, a future refactor could
    /// silently zero it out.)
    #[test]
    fn test_register_clara_returns_verified_healed_balance() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let req = make_request();
        let expected_balance = req.healed_balance;
        let ok = register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None)
            .expect("happy path");
        assert_eq!(ok.healed_balance, expected_balance);
        assert_ne!(expected_balance, 0,
                   "test fixture must use a non-zero balance to be meaningful");
    }

    /// Phase 5f Finding 3: per-wallet rate limit. After 3 attempts inside the
    /// window, the 4th must be rejected with `RateLimited` regardless of
    /// payload validity. The rate limiter runs BEFORE any verify CPU.
    #[test]
    fn test_register_clara_rate_limit_blocks_4th_attempt_in_window() {
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        // Burn through the cap with 3 attempts at the same tick on the same
        // wallet. We use the standard happy-path request — the first attempt
        // succeeds, the next two will be either RateLimited or some other
        // protocol-level reject (idempotency, freshness). All that matters
        // is the 4th request hits RateLimited.
        let req = make_request();
        for _ in 0..MAX_CLARA_REGISTRATIONS_PER_HOUR_PER_WALLET {
            let _ = register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 100, None);
        }
        assert_eq!(
            register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 100, None),
            Err(ClaraRegistrationError::RateLimited)
        );
    }

    /// Outside the window the per-wallet limiter must reset.
    #[test]
    fn test_clara_rate_limiter_window_resets_after_an_hour() {
        let mut limiter = ClaraRateLimiter::new();
        let pk = [0x11u8; 32];
        for _ in 0..MAX_CLARA_REGISTRATIONS_PER_HOUR_PER_WALLET {
            assert!(limiter.check_and_record(&pk, 0).is_ok());
        }
        assert_eq!(
            limiter.check_and_record(&pk, 0),
            Err(ClaraRegistrationError::RateLimited),
        );
        // Move past the window — fresh attempts must succeed.
        let later = CLARA_RATE_LIMIT_WINDOW_SECS + 1;
        assert!(limiter.check_and_record(&pk, later).is_ok());
        assert_eq!(limiter.count_for(&pk, later), 1);
    }

    /// Different wallets MUST have independent quotas.
    #[test]
    fn test_clara_rate_limiter_per_wallet_isolation() {
        let mut limiter = ClaraRateLimiter::new();
        let pk_a = [0x01u8; 32];
        let pk_b = [0x02u8; 32];
        for _ in 0..MAX_CLARA_REGISTRATIONS_PER_HOUR_PER_WALLET {
            assert!(limiter.check_and_record(&pk_a, 0).is_ok());
        }
        assert_eq!(
            limiter.check_and_record(&pk_a, 0),
            Err(ClaraRegistrationError::RateLimited),
        );
        // Wallet B is fresh:
        assert!(limiter.check_and_record(&pk_b, 0).is_ok());
    }

    /// Phase 5f DoS bound regression: declared_garbage entries above
    /// MAX_DECLARED_GARBAGE must be rejected BEFORE any bloom work.
    #[test]
    fn test_register_clara_rejects_oversized_declared_garbage() {
        let (mut txid_chain, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        // Build MAX_DECLARED_GARBAGE + 1 distinct entries
        req.declared_garbage = (0..(MAX_DECLARED_GARBAGE + 1))
            .map(|i| {
                let mut s = [0u8; 32];
                s[0] = (i % 256) as u8;
                s[1] = ((i / 256) % 256) as u8;
                s
            })
            .collect();
        assert_eq!(
            register_clara(&req, &mut txid_chain, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None),
            Err(ClaraRegistrationError::TooManyGarbageStates)
        );
    }

    /// MAX_DECLARED_GARBAGE itself must still pass (boundary test).
    #[test]
    fn test_register_clara_accepts_max_declared_garbage() {
        let (mut txid_chain, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let mut req = make_request();
        req.declared_garbage = (0..MAX_DECLARED_GARBAGE)
            .map(|i| {
                let mut s = [0u8; 32];
                s[0] = (i % 256) as u8;
                s[1] = 0xAA;
                s
            })
            .collect();
        register_clara(&req, &mut txid_chain, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None)
            .expect("MAX_DECLARED_GARBAGE entries must pass");
    }

    #[test]
    fn test_register_clara_phase5e_witness_count_shortcut_no_longer_exists() {
        // Compile-time guarantee: Phase 5e removed witness_sig_count.
        // The request now requires a real ChequeBundle. This test exists
        // primarily as a regression marker — if witness_sig_count comes back
        // it would fail to compile (the field no longer exists).
        let req = make_request();
        let _ = req.heal_cheque.cheques.len();  // bundle is required
    }

    /// The freshness check must consult the REDEEMED set, not CLARA's heal chain.
    ///
    /// Before 2026-07-28 both checks read the heal chain — which nothing but
    /// `register_clara` writes — so a heal whose consumed state had actually been
    /// REDEEMED sailed through. This pins the fix: same request, empty redeemed set
    /// → accepted; redeemed set containing the consumed state → refused.
    #[test]
    fn freshness_check_consults_the_redeemed_set_not_the_heal_chain() {
        // Baseline: with an EMPTY redeemed set the heal is accepted.
        let (mut txid, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let req = make_request();
        let ok = register_clara(&req, &mut txid, &empty_redeemed(), &empty_redeemed(), &mut garbage, &mut limiter, 50, None)
            .expect("baseline heal must be accepted");
        let consumed = ok.healed_from_state_id;

        // Now the SAME heal, but the consumed state is present in the REDEEMED
        // set — i.e. that state was actually spent. Must be refused.
        let (mut txid2, mut garbage2, mut limiter2) = fresh_chains_with_limiter();
        let mut consumed_set = empty_redeemed();
        consumed_set.insert(10, &consumed);
        let err = register_clara(&req, &mut txid2, &empty_redeemed(), &consumed_set, &mut garbage2, &mut limiter2, 50, None)
            .expect_err("a heal from an already-REDEEMED state must be refused");
        assert!(
            // KI#43b: the healed-from hit surfaces as the ADJUDICABLE variant
            // (routed to the §12.4.4 barrier; still a refusal at this layer).
            matches!(err, ClaraRegistrationError::ConsumedHealedFromHit),
            "expected ConsumedHealedFromHit, got {err:?}"
        );
    }

    /// Heal txids must NOT land in the redeemed set — that would make
    /// `/query-txid` answer REDEEMED for a merely-healed txid, the pollution the
    /// 2026-07-07 "ONE txid domain" decision removed.
    #[test]
    fn heal_txids_are_written_to_the_heal_chain_only() {
        let (mut heal, mut garbage, mut limiter) = fresh_chains_with_limiter();
        let redeemed = empty_redeemed();
        let req = make_request();
        let ok = register_clara(&req, &mut heal, &redeemed, &empty_redeemed(), &mut garbage, &mut limiter, 50, None)
            .expect("heal accepted");

        assert!(matches!(heal.lookup(&ok.heal_txid), ChainLookup::Hit { .. }),
            "heal chain must record the heal (idempotency depends on it)");
        assert!(matches!(redeemed.lookup(&ok.heal_txid), ChainLookup::Miss),
            "redeemed set must NOT learn heal txids — that is domain pollution");
    }
}
