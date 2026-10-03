// AXIOM Nabla — Registration Handler
// Reference: AXIOM_GUIDE_Nabla.md Section 3
//
// Phase 1 Tasks:
//   5. Registration handler (verify k=3 receipt, update SMT)
//   7. DEED validation (Core pass-through, destination check)
//
// Flow (cheapest checks first):
//   1. Check ban status (O(1) lookup)
//   2. Check DEED destination (protocol or implementation wallet)
//   3. Check DEED amount
//   4. Verify registration matches receipt (field comparison)
//   5. Verify k=3 receipt signatures (crypto — expensive)
//   5b. Verify execution proofs (ZKP/DMAP — most expensive)
//   6. Check for conflicts and update SMT
//   7. Process DEED payment
//   8. Gossip update to peers
//   9. Return signed acknowledgment

use crate::ban::BanTable;
use crate::constants::DEED_WRITE_FEE;
use crate::crypto::{self, Signer};
use crate::smt::SparseMerkleTree;
use crate::types::*;
use crate::wal::{WalOp, WriteAheadLog};
use axiom_zk_vm::{ZkvmReceipt, ZkvmVerifier};

/// DEED wallet IDs — hardcoded protocol addresses.
/// In production, these are derived from genesis parameters.
/// For Phase 1, we use well-known constants.
pub const DEED_PROTOCOL_WALLET_ID: WalletId = [0xDE; 32];
pub const DEED_IMPLEMENTATION_WALLET_ID: WalletId = [0xED; 32];

/// Result of processing a registration.
#[derive(Debug)]
pub struct RegistrationResult {
    pub ack: RegistrationAck,
    pub gossip_msg: GossipMessage,
    /// YPX-020 HAL: when this register was a re-anchor (`is_hal_reanchor`),
    /// the hibernation deadline (tick stamp) this node stamped locally. The
    /// node handler floods it via `GossipMessage::Hibernation` so the
    /// cheque-claim's pick-set nodes learn the same value — single source,
    /// no recompute, no skew. `None` for ordinary registers.
    pub hibernation_until: Option<u64>,
    /// YPX-022 §2.2.1 — recall reservations COMMITTED by this register
    /// (`is_recall` hibernation-entry): `(txid, reservation_tick)` pairs.
    /// The node handler garbage-inserts each txid and floods the committed
    /// `GossipMessage::Recall` so the terminal reaches the whole mesh.
    /// Empty for ordinary registers.
    pub committed_recalls: Vec<(TxHash, u64)>,
    /// ForkSettlement §9r (F-6 path 11, owner ruling 2026-10-02) — a REDEEM's
    /// validator fee slots + DEED slice, computed and leak-checked at 8c but NOT
    /// credited: `(cheque_txid, credit)`. The caller (`NablaNode::register`)
    /// parks it and credits it ONCE when this node's provenance judges the
    /// cheque `Ok`; a cheque that stays held/waiting (e.g. burned) never credits.
    /// `None` for every non-redeem register (their fees credit at 8c directly).
    pub held_fee_credit: Option<(TxHash, FeeCredit)>,
}

/// ForkSettlement §9r (F-6 path 11) — one register's computed fee credit: the
/// DEED slice and the per-slot validator NETs (`compute_deed_split`), routed by
/// the k-bound `is_dev_class`. Built ONCE at 8c; applied by
/// [`apply_fee_credit`] — at once for a non-redeem, or when a held redeem's
/// cheque clears (`NablaNode::release_held_fee_credits`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FeeCredit {
    pub tx_hash: TxHash,
    pub is_dev_class: bool,
    /// `(validator_id, net)` per witness slot, in breakdown order.
    pub slots: Vec<([u8; 32], u64)>,
    pub deed_atoms: u64,
    /// Per-validator NETs are recorded only on hashmap-mode nodes (§19.6);
    /// captured at the register so a later release credits the same ledgers.
    pub hashmap_mode: bool,
}

/// Apply a [`FeeCredit`] to the class-matching pools (the 8c routing, ONE
/// site). Dev credits NEVER touch the public pools and vice versa.
pub fn apply_fee_credit(
    credit: &FeeCredit,
    current_tick: u64,
    deed_pool: Option<&mut crate::node::DeedPool>,
    validator_net_ledger: Option<&mut crate::node::ValidatorNetLedger>,
    dev_deed_pool: Option<&mut crate::node::DevDeedPool>,
    validator_dev_net_ledger: Option<&mut crate::node::ValidatorDevNetLedger>,
) {
    if credit.is_dev_class {
        let dev_pool_present = dev_deed_pool.is_some();
        let dev_ledger_present = validator_dev_net_ledger.is_some();
        if let Some(pool) = dev_deed_pool {
            let pre = pool.balance();
            pool.credit(credit.deed_atoms, current_tick);
            log::warn!(
                "[DEV-DEED-CREDIT] tx_hash={} added={} balance={}→{}",
                hex::encode(&credit.tx_hash[..8]),
                credit.deed_atoms, pre, pool.balance(),
            );
        }
        if credit.hashmap_mode {
            if let Some(ledger) = validator_dev_net_ledger {
                for (vid, net) in &credit.slots {
                    ledger.credit(vid, *net, current_tick);
                }
            }
        }
        log::warn!(
            "[DEV-CLASS-ROUTE] tx_hash={} dev_deed_credit={} validators={} \
             pool_present={} ledger_present={} hashmap={}",
            hex::encode(&credit.tx_hash[..8]),
            credit.deed_atoms, credit.slots.len(),
            dev_pool_present, dev_ledger_present, credit.hashmap_mode,
        );
    } else {
        if let Some(pool) = deed_pool {
            pool.credit(credit.deed_atoms, current_tick);
        }
        if credit.hashmap_mode {
            if let Some(ledger) = validator_net_ledger {
                for (vid, net) in &credit.slots {
                    ledger.credit(vid, *net, current_tick);
                }
            }
        }
    }
}

/// Process a registration request.
///
/// Verify each k witness's `receipt_commitment_sig` against the receipt's
/// commitment — which BINDS `is_dev_class` (and `oods_flag`). A missing,
/// malformed, or non-verifying sig means the class flag was tampered after the
/// k-witness round → reject `InvalidReceipt`.
///
/// Called on TWO paths: (1) the receiver-pays fee-ledger check (§5b', gated on a
/// non-empty `fee_breakdown`), and (2) the recall/HAL hibernation-stamp path
/// (§5b'', UNCONDITIONAL). Path (2) exists because a recall self-send / HAL
/// re-anchor carries an EMPTY `fee_breakdown`, so path (1) is skipped — which
/// would leave `is_dev_class` unverified on exactly the two paths that consume it
/// for the finish-gate window (`hibernation_until_for`). Recall + HAL are ALWAYS
/// k-witnessed (consensus.rs 3368/3753/3891/6261) so the sig is always present.
/// §5.2.2c KI#132 — how many registers declared a LIVE stake lock that was NOT
/// the wallet's own stake claim.
///
/// **This is the deliverable of KI#132, and the refusal is not.** Building the
/// refusal proved on a live fleet that it has nothing legitimate left to refuse:
/// Core's CL1 send gate and the CL5 redeem gate (KI#133) already stop a locked
/// wallet from producing ANY registerable receipt except the claim redeem that
/// stamps the lock — which must be allowed. So a gate there can only misfire,
/// which it did (it scarred the chain and killed the release send).
///
/// What remains genuinely useful is DETECTION: if this counter is ever non-zero,
/// a locked wallet registered something that was not its own stake claim, which
/// means **one of Core's gates leaked**. Nothing else on the mesh reports that.
///
/// RULE 3 §2: a security-relevant observation needs a COUNTER, not just a log
/// line — "0 rejections" and "never ran" read identically otherwise. Surfaced on
/// `/status` as `stake_lock_observed_not_own_claim`.
static STAKE_LOCK_OBSERVED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// ValidatorJoin §6b.13 (KI#225) — §6b.4 check 5, exactly as specified: the
/// registered head's `stake_floor_until` must be `>=` the certificate's
/// `expires_at`. ONE predicate (RULE 1), read by `register_vbc_core` and its
/// tests. A head with no floor (`0`) never covers a CL8-issued certificate —
/// CL8 refuses `expires_at <= issued_at`, so every certificate it signs has a
/// non-zero expiry.
///
/// ⚠ RESIDUAL, recorded not fixed: `expires_at == 0` is the "never expires"
/// SENTINEL (`validation::vbc_is_provisional`). `0 >= 0` holds, so a sentinel
/// certificate passes this check with no floor. That is what lets a GENESIS
/// derived head (floor = the cert's `expires_at`) pass uniformly as the spec
/// requires; no CL8-issued certificate can carry the sentinel, so only a
/// ceremony-signed certificate reaches this arm.
pub fn stake_floor_covers_certificate(stake_floor_until: u64, expires_at: u64) -> bool {
    stake_floor_until >= expires_at
}

/// §6b.13 — certificates this node REFUSED to stamp because the stake wallet's
/// head carried no floor reaching the certificate's expiry (check 5),
/// cumulative. RULE 3 §2: a security-relevant refusal needs a counter —
/// surfaced on `/status` as `vbc_stamp_refused_no_floor`.
static VBC_STAMP_REFUSED_NO_FLOOR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Count one §6b.13 check-5 refusal (see [`VBC_STAMP_REFUSED_NO_FLOOR`]).
pub fn note_vbc_stamp_refused_no_floor() {
    VBC_STAMP_REFUSED_NO_FLOOR.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Read the §6b.13 check-5 refusal counter.
pub fn vbc_stamp_refused_no_floor_total() -> u64 {
    VBC_STAMP_REFUSED_NO_FLOOR.load(core::sync::atomic::Ordering::Relaxed)
}

/// ForkSettlement §9r F-1(c) (KI#244) — stamps REFUSED because the stake
/// wallet's registered head is HELD by this node's provenance (ATRAXI A5:
/// it descends from a fork / a held receive). RULE 3 §2 — on `/status` as
/// `vbc_stamp_refused_held`.
static VBC_STAMP_REFUSED_HELD: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// …and stamps answered `WAIT` because this node has no provenance verdict
/// for the head yet (an ancestor unrecorded here / derivation queued — record-AE
/// fills it). Retryable, never a stamp. On `/status` as `vbc_stamp_refused_wait`.
static VBC_STAMP_REFUSED_WAIT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Count one F-1(c) HELD refusal (see [`VBC_STAMP_REFUSED_HELD`]).
pub fn note_vbc_stamp_refused_held() {
    VBC_STAMP_REFUSED_HELD.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}
/// Count one F-1(c) WAIT answer (see [`VBC_STAMP_REFUSED_WAIT`]).
pub fn note_vbc_stamp_refused_wait() {
    VBC_STAMP_REFUSED_WAIT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}
/// Read the F-1(c) HELD refusal counter.
pub fn vbc_stamp_refused_held_total() -> u64 {
    VBC_STAMP_REFUSED_HELD.load(core::sync::atomic::Ordering::Relaxed)
}
/// Read the F-1(c) WAIT counter.
pub fn vbc_stamp_refused_wait_total() -> u64 {
    VBC_STAMP_REFUSED_WAIT.load(core::sync::atomic::Ordering::Relaxed)
}

/// Read the KI#132 observation counter (see [`STAKE_LOCK_OBSERVED`]).
/// NON-ZERO MEANS A CORE GATE LEAKED — it is not routine noise.
pub fn stake_lock_observations() -> u64 {
    STAKE_LOCK_OBSERVED.load(core::sync::atomic::Ordering::Relaxed)
}

/// §5.2.2c KI#132 — **an honest node does not record a state its own receipt says
/// is STAKE-LOCKED.**
///
/// The owner asked for a plain local spot-check at registration. The obstacle was
/// that a registration describes the INCOMING transition, so a deadline derived
/// from it is the window this registration would STAMP — gating on that blocks
/// the very registration that starts a HAL or RECALL. The only local store
/// holding a PRIOR lock was the gossip-fed hibernation map, and reading that is
/// a mesh-wide DoS: `GossipMessage::Hibernation` is unauthenticated, so one
/// forged packet with `until = u64::MAX` would send-lock any wallet
/// (`g9_forged_hibernation_cannot_block_a_register` pins this — do NOT "fix"
/// this by reading that map).
///
/// The way through is the third one the KI recommends: **the client DECLARES the
/// state and the k-signed receipt PROVES it.** `receipt.state_hash` commits
/// `(pk, balance, seq, hibernation_until, wall_clock_lock)` and this node already
/// verifies k witness signatures over the commitment that binds it
/// (`verify_receipt_commitment_sigs`). So we recompute the hash from the declared
/// values. ⚠ A MISMATCH IS NOT A REJECTION (this rotation): it means the receipt
/// does not anchor the declared state, so Nabla cannot judge the lock and
/// passes — counted `/status declared_state_unanchored`. ~~"which is TRUE of the
/// legitimate genesis-fund path (deferred balance)"~~ — no longer (KI#251,
/// 2026-10-02: Core's claim send now binds the unchanged balance the fund
/// declares); promoted to a refusal after a soak measures zero. Only a
/// VERIFIED, unexpired lock is refused. The `healed_balance` check in
/// `clara.rs` uses the same recompute, but it can reject on mismatch because it
/// runs on one known shape; this runs on every register.
///
/// ⚠ **ARMOUR, NOT ENFORCEMENT (RULE 5).** Nabla FAILS OPEN — a patched node
/// simply does not run this, so nothing here defends against an adversary. The
/// lock's enforcement is CORE's: the attested-tick gate in `validate_transaction`
/// and the CL5 redeem gate (KI#133, proven live). This keeps an HONEST node's own
/// SMT clean.
///
/// ⚠ **HAL/RECALL MUST PASS.** They hibernate with `wall_clock_lock == 0`, and
/// the trigger here is the LOCK, never the hibernation term — the same
/// discrimination Core's CL5 gate makes. Keying this on `hibernation_until`
/// would strand every wallet mid-recovery.
///
/// ⚠ A receipt claiming NO §15 anchor (`state_hash` all-zero — partial and
/// provisional receipts) cannot be checked and is passed through. It is not a
/// bypass in practice: a stake-locked wallet cannot obtain a fresh receipt at
/// all, because Core refuses both its sends and its redeems.
fn verify_declared_state_and_stake_lock(
    reg: &Registration,
    current_tick: u64,
) -> Result<(), NablaError> {
    if reg.receipt.state_hash == [0u8; 32] {
        return Ok(());
    }
    let recomputed = axiom_core_logic::compute::compute_state_hash(
        &reg.client_pk,
        reg.declared_balance,
        reg.receipt.new_wallet_seq,
        reg.declared_hibernation_until,
        reg.declared_wall_clock_lock,
        reg.declared_emission_claimed_epoch,
        reg.declared_stake_floor_until,
        &reg.declared_wallet_format,
    );
    if recomputed != reg.receipt.state_hash {
        // ⚠ NOT FATAL — still, deliberately, for THIS rotation. History: this arm
        // used to `return Err(InvalidReceipt)` and it broke the GENESIS FUND on
        // the live fleet (2026-09-07): Core's claim send CREDITED the amount at
        // the SEND while the SDK committed (and declared) balance 0, so the
        // claim's receipt legitimately did not anchor the declaration, and
        // `Registration` carries no genesis flag to tell that case apart.
        //
        // ~~"genesis-fund and other deferred-balance shapes land here"~~ — RULE 0
        // marker: that carve-out reason is GONE (KI#251, 2026-10-02). The credit
        // at the send was the defect, contrary to YP §17.11.2 step 3; Core's
        // `compute_post_tx_balance` now binds the UNCHANGED balance for genesis
        // and stake claims, so an honest claim register's declared (0, seq 1)
        // reproduces its receipt's `state_hash` like every other kind. A
        // mismatch now means a client that garbled (or lied in) its declaration.
        //
        // Why still non-fatal: promoting it to a refusal widens a CoreID
        // rotation's blast radius; it is promoted only after one soak measures
        // ZERO hits on this counter (RULE 3: a pass-through must say why, and
        // must be observable — hence `warn` + `/status
        // declared_state_unanchored`, no longer a silent `debug!`). What is
        // given up meanwhile: a garbled declaration is not judged HERE. That
        // costs nothing real — Nabla FAILS OPEN (RULE 5) and Core's CL2/CL5 §15
        // anchor is the enforcement. What is kept: an HONEST node does not
        // record a state whose own k-signed receipt says it is stake-locked.
        DECLARED_STATE_UNANCHORED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        log::warn!(
            "[stake-lock] declared state does not reproduce the k-signed state_hash \
             (declared balance={} seq={} hib={} wcl={}) — cannot judge the lock, \
             passing (counted /status declared_state_unanchored; KI#251: an honest \
             register always reproduces it)",
            reg.declared_balance, reg.receipt.new_wallet_seq,
            reg.declared_hibernation_until, reg.declared_wall_clock_lock,
        );
        return Ok(());
    }
    // The declared values are now PROVEN by k signatures. Judge the lock.
    //
    // The comparand is the TARDIS tick VALUE, which is unix-encoded — this node
    // does NOT read SystemTime (constants.rs:287, and a local clock would make
    // two honest nodes disagree about the same registration).
    if reg.declared_wall_clock_lock != 0 && current_tick < reg.declared_wall_clock_lock {
        // ⚠⚠ OBSERVE-ONLY, PENDING THE OWNER'S RULING. This used to
        // `return Err(NablaError::StakeLocked)` and it BROKE THE CLAIM PATH on
        // the live fleet (2026-09-07, CoreID 34f331d3).
        //
        // WHY, and it is structural rather than a slip: the claim's REDEEM is
        // the transaction that STAMPS the lock. Its own registration therefore
        // declares the NEW, already-locked state — so refusing "a locked wallet
        // may not register" refuses the very registration that CREATES the lock.
        // The link never registers, that becomes a SCAR, and the release send
        // then dies at the scar-consent gate. Measured end to end:
        //   `Registration rejected for f8eb...: stake-locked wallet may not
        //    register state until its wall-clock deadline`
        // followed by `E_LAMBDA_SCAR_CONSENT_REQUIRED` on the release.
        //
        // This is EXACTLY the counter-position recorded in KI#132: "a
        // registration describes the INCOMING transition, so a deadline derived
        // from it is the window this registration would STAMP — gating on that
        // blocks the very registration that starts a HAL or RECALL." Same trap,
        // different op. The live fleet proved it.
        //
        // To refuse correctly Nabla needs the PRIOR lock, and it has none:
        // `NablaEntry` does not carry one, and the only local store that does is
        // the gossip-fed hibernation map — which is the unauthenticated
        // mesh-wide DoS that G9 forbids. So the honest states are:
        //   (a) put the lock on `NablaEntry` (KI#132's own second suggestion) —
        //       correct, but it changes the SMT leaf: all-node roll, and very
        //       likely a data wipe; or
        //   (b) exempt the stamping transition by amount, mirroring Core's own
        //       `amt == TIER2/TIER3_CLAIM_ATOMS` discrimination — cheap, no wire
        //       change, but a heuristic on a client-supplied amount.
        // Both are design calls with real costs, so neither is taken here.
        //
        // Until one is ruled: COUNT AND LOG, REFUSE NOTHING. An observe-only
        // check that says so is honest; one that silently refuses honest
        // registrations is not.
        // Is this the wallet's OWN stake claim — the redeem that STAMPS the
        // lock? That one is expected and must not be counted, or the counter is
        // noise. Discriminated by amount, mirroring Core's own test
        // (`execute_cl5`: `amt == TIER2_CLAIM_ATOMS` / `TIER3_CLAIM_ATOMS`).
        //
        // ⚠ A heuristic on a client-supplied amount — acceptable HERE precisely
        // because nothing is refused: a wrong guess miscounts a diagnostic, it
        // cannot break a flow. It would NOT be acceptable as a gate condition.
        let amt = reg.receipt.amount;
        let is_own_stake_claim = amt == axiom_core_logic::types::TIER2_CLAIM_ATOMS
            || amt == axiom_core_logic::types::TIER3_CLAIM_ATOMS;

        if is_own_stake_claim {
            log::debug!(
                "[stake-lock] the claim redeem that STAMPS the lock (amount={amt}) — \
                 expected, not counted",
            );
        } else {
            STAKE_LOCK_OBSERVED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            log::warn!(
                "[stake-lock] KI#132: a LIVE stake lock declared on a register that is \
                 NOT this wallet's own stake claim (wall_clock_lock={} > tick={}, \
                 amount={amt}). NOT refused — Nabla fails open and Core is the \
                 enforcement — but this should be UNREACHABLE: it means CL1 or the \
                 CL5 redeem gate let a locked wallet through. Investigate Core.",
                reg.declared_wall_clock_lock, current_tick,
            );
        }
    }
    Ok(())
}

fn verify_receipt_commitment_sigs(reg: &Registration) -> Result<(), NablaError> {
    // EVERY slot must carry a well-formed sig: fees are credited per slot
    // (`fee_breakdown.len() == signatures.len()`), so a slot no validator
    // signed must refuse the register, not merely fall outside a quorum count.
    for ws in &reg.receipt.signatures {
        if ws.receipt_commitment_sig.len() != 64 {
            log::warn!(
                "[receipt-commitment] missing or malformed receipt_commitment_sig (len={})",
                ws.receipt_commitment_sig.len(),
            );
            return Err(NablaError::InvalidReceipt);
        }
    }
    // RULE 1 (ForkSettlement [R17], 2026-09-28): the SAME count
    // `verify_seq_proof` applies, with the stricter threshold "every slot is
    // a distinct valid signer". This used to be a second hand-rolled
    // `ed25519_dalek` loop over the same commitment. `from_registration` is `Some`
    // here (every slot is 64 bytes and there is ≥1, checked at step 5).
    let matched = crate::types::SeqProof::from_registration(reg)
        .map(|p| count_valid_commitment_sigs(&p, &reg.tx_hash, reg.receipt.new_wallet_seq))
        .unwrap_or(0);
    if matched != reg.receipt.signatures.len() {
        log::warn!(
            "[receipt-commitment] {}/{} slots are distinct valid receipt_commitment_sigs — \
             rejecting register",
            matched, reg.receipt.signatures.len(),
        );
        return Err(NablaError::InvalidReceipt);
    }
    Ok(())
}

/// This is the core registration logic, separated from the NablaNode
/// for testability. The node calls this with references to its state.
#[allow(clippy::too_many_arguments)]
/// The (pk, tier) SMT bucket key (option-C ruling, 2026-07-19). Tier 3
/// (Standard — incl. every HTTP-path register, which defaults it) maps to the
/// pk itself, keeping all pre-pair behavior byte-identical; other tiers derive
/// a domain-tagged disjoint key so the single-keypair pair's members each key
/// their OWN sequential chain. `reg.wallet_id` itself stays the pk — the
/// validator-signed identity and the §10.4 ban key.
// Pattern 1 sweep — ONE derivation, owned by Core. This file previously
// carried a byte-identical copy; the SDK carried another. The bucket is the
// first input to `client_state_sign_payload`, so a drift in either copy makes
// every honest wallet's register fail to verify. Import lands here because
// `registration.rs` is already crypto-boundary exempt (the tripwire forbids a
// fifth exempt file); other nabla modules re-export from here.
pub use axiom_core_logic::compute::smt_bucket;
// Pattern 1 sweep — the FACT confirm payload and its tx_hash are Core-owned.
// Nabla SIGNS what Core VERIFIES, so an independent assembly here is the exact
// signer/verifier split that produced KI#54. Import lands in this file because
// it is already crypto-boundary exempt; `crypto.rs` re-exports from here.
pub use axiom_core_logic::compute::{fact_confirm_payload, fact_tx_hash, txid_attest_payload};

pub fn process_registration(
    smt: &mut SparseMerkleTree,
    wal: &mut WriteAheadLog,
    bans: &mut BanTable,
    reg: &Registration,
    deed_tx: &DeedTransaction,
    current_tick: u64,
    // ForkSettlement §2.4 [R13] — THIS node's wall clock (`virtual_secs`,
    // sampled once per tick-loop iteration in the binary), stamped as an
    // origin record's `first_seen_secs`. NOT `current_tick` (TARDIS): a tick
    // is a vector, the wall clock is the unit — never substitute one.
    now_secs: u64,
    deed_collected: &mut u64,
    signer: &dyn Signer,
    // KI#224 — THIS node's R42 witness directory (`VbcDirectory::is_witness`,
    // read LIVE per call — never a snapshot). Step 5b⁗ counts a head's
    // witness sigs only if every key walks back to the root through it.
    is_witness: &dyn Fn(&[u8; 32]) -> bool,
    airdrop_pool: Option<&mut crate::node::AirdropPool>,
    dev_treasury_pool: Option<&mut crate::node::DevTreasuryPool>,
    // ╔═ BOOTSTRAP SUBSIDY — REMOVE WHEN POOLS DRAIN ═══════════════╗
    // §5.2.3 subsidy pools. Same `AirdropPool` type as the airdrop — one pool
    // implementation, three instances. Threaded here because THIS is the live
    // grant site (§5.2.3a), not `fact_confirm_core`.
    // ╚═════════════════════════════════════════════════════════════╝
    bootstrap_pool: Option<&mut crate::node::AirdropPool>,
    foundation_bootstrap_pool: Option<&mut crate::node::AirdropPool>,
    // YP §20.8 — DEED fee pool (10% slice of each receiver-pays
    // fee_breakdown lands here). `None` in test paths that don't
    // model fees; the credit step is then skipped.
    deed_pool: Option<&mut crate::node::DeedPool>,
    // YP §20.8 / §20.11 — per-validator NET ledger. `compute_deed_split`
    // returns the per-slot NET (90% of slot, proportionally distributed
    // with deterministic atom-granular remainder); we credit each
    // validator's running balance here. `None` in test paths that don't
    // model fees; the credit step is then skipped.
    validator_net_ledger: Option<&mut crate::node::ValidatorNetLedger>,
    // Dev-class isolation pools (`AXIOM_DESIGN_FactClassIsolation.md`
    // + 2026-06-05 leak fix). When `receipt.is_dev_class == true`,
    // credits route HERE instead of the public pools above. NEVER
    // both — the routing is mutually exclusive at the call site
    // (registration.rs `if receipt.is_dev_class { dev_*.credit }
    // else { public.credit }`). Newtype wrapping at the struct
    // level makes a cross-credit a compile error.
    dev_deed_pool: Option<&mut crate::node::DevDeedPool>,
    validator_dev_net_ledger: Option<&mut crate::node::ValidatorDevNetLedger>,
) -> Result<RegistrationResult, NablaError> {
    // (ForkSettlement §9r-E4, 2026-10-02: step 0, the §32 merge-quarantine
    // refusal over `quarantined_wallets`, was deleted — the list was filled only
    // by the dead SCAN's `handle_fork_evidence`, so it was always empty. A
    // downstream hold never refuses a register: ATRAXI A5, §9k ruling 1.)

    // ── 0b. KI#226 — the wallet_id MUST be the signing key's own ──────────
    //
    // The SMT bucket is DERIVED from the key that signs (`smt_bucket(client_pk,
    // k_tier)`, the R7 principle `ban::check_fork_leg` already applies), never
    // taken from the message: a register whose `wallet_id` names another
    // bucket is REFUSED (counted `wallet_id_key_mismatch`), before anything is
    // read or written under that id. Before this step 5a′ checked the client
    // sig over `smt_bucket(reg.wallet_id, k)` under the FREE field
    // `reg.client_pk`, so any key holder could sign its own leg over a
    // victim's id and have it stored as the victim's head (measured:
    // `fork_detection_mesh::s8b_framing_legs_do_not_replace_victim_head`).
    //
    // Carve-out, stated: a ZERO `client_pk` (the group-wallet registers — no
    // key to derive from; `process_group_registration` is a separate path and
    // 5a′/5b′/5b‴ already skip zero pk) keeps the message's id. Genesis claims
    // are unaffected: the SDK sets `wallet_id = client_pk` on every register
    // (`nabla.rs` "Option-C", `genesis_claim.rs`), and the class anchor
    // (`verify_pk_binding` below) already binds the claimant string to
    // `client_pk`, not to `wallet_id`.
    //
    // RULE 5: hygiene — keeps an honest node's heads authored by their owners;
    // money is never moved by a Nabla head (Core re-anchors every send on
    // k-witnessed receipts).
    let bucket = if reg.client_pk != [0u8; 32] {
        let own = smt_bucket(&reg.client_pk, reg.k_tier);
        if smt_bucket(&reg.wallet_id, reg.k_tier) != own {
            note_wallet_id_key_mismatch(&reg.wallet_id, &reg.client_pk, &reg.tx_hash, "register");
            return Err(NablaError::InvalidReceipt);
        }
        own
    } else {
        smt_bucket(&reg.wallet_id, reg.k_tier)
    };

    // ── 1. Check ban status (cheapest check, O(1)) ──
    // Option-C: SMT operations below key by the (pk, tier) BUCKET; identity
    // checks (bans, quarantine, signed payloads, client_pk) stay on the pk.
    // Ban coverage is two-dimensional: pk-recorded bans (§10.4 — covers every
    // tier of the keypair) AND bucket-recorded bans (a fork detected on one
    // tier's chain floods the bucket key).
    if bans.is_banned(&reg.wallet_id) || bans.is_banned(&bucket) {
        return Err(NablaError::WalletBanned);
    }

    // ── KI#205 — register-door RECALL gate (YPX-022 §2.2 half; ATRAXI claim A2).
    // A REDEEM-finalize register (`fee_breakdown` non-empty = the receiver's
    // post-redeem register; genesis funds excluded, they are a claim self-redeem)
    // for a txid whose recall is COMMITTED is REFUSED. Whichever settled first
    // wins (§2.2.1): a redeem that finalized during the OPEN reservation deletes
    // it (`mark_txid_redeemed`) and wins — so this fires ONLY on a committed
    // terminal, never a reservation. The committed recall is earlier by TARDIS
    // stamp (an on-time redeem would have aborted the reservation before commit);
    // this late redeem loses and its link stays a permanent scar — it is never
    // confirmed, so exactly one of {recall, redeem} settles cleanly.
    //
    // MEASURED (KI#205, tests/recall_after_unregistered_redeem_gate.py): without
    // this gate a redeem that was k-witnessed but never registered re-registered
    // CLEAN after the recall completed — a full unrestricted duplicate.
    //
    // ⚠ ARMOUR SCOPE (RULE 5): the committed marker is trusted here. On THIS node
    // it is set only by a verified recall self-send registration (8a'); a marker
    // learned by gossip is applied on a peer's word today (`apply_remote_recall`)
    // — making it self-verifying (carry the recall self-send's k-witness proof)
    // is the ATRAXI evidence-gossip half, KI#205 residual. This gate closes the
    // measured no-collusion double-settle; it does not by itself stop a hostile
    // node from griefing with a forged committed marker (a surface that already
    // exists at query-txid, which serves a forged-recalled txid as REDEEMED).
    if !reg.is_genesis_claim
        && !reg.receipt.fee_breakdown.is_empty()
        && smt.is_txid_recalled(&reg.tx_hash)
    {
        return Err(NablaError::RedeemAfterRecallCommitted);
    }

    // §17.11 + AXIOM_DESIGN_FactClassIsolation.md §6: Genesis claims.
    // Skip DEED, then route the deduction to the matching class pool
    // with three layers of defense:
    //   (1) Crypto anchor: `claimant_wallet_id` must be pk-bound to
    //       the receipt's wallet pk. Stops an attacker pasting a
    //       fake wallet_id string onto an unrelated receipt.
    //   (2) Signal agreement: SDK's `is_dev_claim` flag must match
    //       Nabla's own `is_dev_wallet` derivation from the string.
    //       Closes the leak in BOTH directions — neither pool can be
    //       drained by a wallet of the opposite class.
    //   (3) Pool routing: deduct only from the matching pool — NOT HERE:
    //       the debit runs at step 7b, at the head write, after every
    //       refusal in the door (KI#250). (1) and (2) mutate nothing.
    // Hoisted: read again by the pool debit at step 7b (KI#250).
    let wallet_is_dev = axiom_core_logic::wallet_id::is_dev_wallet(&reg.claimant_wallet_id);
    if reg.is_genesis_claim {
        // (1) pk_bind anchor — string must derive from this registrant's PK.
        // `reg.client_pk` is the registrant's real Ed25519 key; `reg.wallet_id`
        // is the OPAQUE SMT key and — since the tier-encoded key derivation
        // (single-keypair collision fix) — no longer bytes-equal to the pk, so
        // binding against it rejected every legitimate claim.
        if axiom_core_logic::wallet_id::verify_pk_binding(
            &reg.claimant_wallet_id, &reg.client_pk,
        ).is_err() {
            log::warn!("[CLASS] Claim rejected: claimant_wallet_id {:?} not pk-bound to client_pk {}",
                reg.claimant_wallet_id, hex::encode(&reg.client_pk[..8]));
            return Err(NablaError::ClassSignalMismatch);
        }

        // (2) Signal agreement — Nabla derives class independently.
        if wallet_is_dev != reg.is_dev_claim {
            log::warn!("[CLASS] Claim rejected: is_dev_claim={} but is_dev_wallet({:?})={}",
                reg.is_dev_claim, reg.claimant_wallet_id, wallet_is_dev);
            return Err(NablaError::ClassSignalMismatch);
        }

    }

    if !reg.is_genesis_claim {
        // ── 2. Check DEED destination ──
        if deed_tx.receiver_wallet_id != DEED_PROTOCOL_WALLET_ID
            && deed_tx.receiver_wallet_id != DEED_IMPLEMENTATION_WALLET_ID
        {
            return Err(NablaError::InvalidDeedDestination);
        }

        // ── 3. Check DEED amount ──
        if deed_tx.amount < DEED_WRITE_FEE {
            return Err(NablaError::InvalidDeedPayment);
        }
    }

    // ── 4. Verify registration matches receipt ──
    if reg.old_state != reg.receipt.consumed_state_id {
        log::warn!("StateMismatch[OLD_VS_RECEIPT]: wallet={} reg.old={} receipt.consumed={}",
            hex::encode(&reg.wallet_id[..4]),
            hex::encode(&reg.old_state[..4]), hex::encode(&reg.receipt.consumed_state_id[..4]));
        return Err(NablaError::StateMismatch);
    }
    if reg.new_state != reg.receipt.produced_state_id {
        log::warn!("StateMismatch[NEW_VS_RECEIPT]: wallet={} reg.new={} receipt.produced={}",
            hex::encode(&reg.wallet_id[..4]),
            hex::encode(&reg.new_state[..4]), hex::encode(&reg.receipt.produced_state_id[..4]));
        return Err(NablaError::StateMismatch);
    }

    // ── 5. Verify the k receipt signatures via Core (Signer trait) ──
    // Each validator signed: wallet_id + old_state + new_state + tick.
    // YP §17.3.1.4 v2.19.0 (KI#150): k is the registration's tier, floor 3.
    if reg.receipt.signatures.len() < (reg.k_tier as usize).max(3) {
        // KI#185 diagnostic: the other silent InvalidReceipt.
        log::warn!(
            "[receipt-sig] too FEW signatures: {} < max(k_tier={}, 3) — wallet={}",
            reg.receipt.signatures.len(), reg.k_tier, hex::encode(&reg.wallet_id[..4]),
        );
        return Err(NablaError::InvalidReceipt);
    }
    // Use receipt's tick as-is for signature verification.
    // Lambda signs with tick=0 (the canonical "no timestamp" value).
    // Nabla previously substituted current_tick when tick=0, which
    // broke verification because the signature was over tick=0.
    // Staleness check only applies to non-zero ticks.
    let receipt_tick = if reg.receipt.tick > 0 {
        // KI#53: named + registered (was a bare `300`). `.0` is the raw tick
        // COUNT; both sides of this comparison are tick-domain values.
        if current_tick.saturating_sub(reg.receipt.tick)
            > crate::constants::RECEIPT_STALENESS_MAX_TICKS.0
        {
            return Err(NablaError::InvalidReceipt);
        }
        reg.receipt.tick
    } else {
        0 // Verify with the same tick=0 that Lambda signed with
    };
    let receipt_payload = crypto::receipt_sign_payload(
        &reg.wallet_id,
        &reg.receipt.consumed_state_id,
        receipt_tick,
    );
    for (i, ws) in reg.receipt.signatures.iter().enumerate() {
        if !signer.verify(&ws.validator_pk, &receipt_payload, &ws.signature) {
            // KI#185 diagnostic (2026-09-16): this was the ONE InvalidReceipt
            // return with no log, so a refused register said nothing about WHY.
            // Every field the payload is built from, plus the slot that failed.
            log::warn!(
                "[receipt-sig] slot {}/{} FAILED verify — wallet={} consumed={} produced={} \
                 tick={} (receipt.tick={}) k_tier={} validator_pk={} sig_len={} proof_type={} \
                 exec_proof_len={}",
                i + 1, reg.receipt.signatures.len(),
                hex::encode(&reg.wallet_id[..4]),
                hex::encode(&reg.receipt.consumed_state_id[..4]),
                hex::encode(&reg.receipt.produced_state_id[..4]),
                receipt_tick, reg.receipt.tick, reg.k_tier,
                hex::encode(&ws.validator_pk[..4]),
                ws.signature.len(), ws.proof_type, ws.execution_proof.len(),
            );
            return Err(NablaError::InvalidReceipt);
        }
    }

    // ── 5a'. AUTHORSHIP (KI#53) — the wallet must have signed this state ──
    //
    // The register path stored `reg.client_sig` into the SMT entry WITHOUT
    // ever verifying it, while BOTH replication paths verify it and reject on
    // failure (`gossip::apply_state_update`, `node::apply_remote_entry`, since
    // the KI#46 zero-pk flip). That is the KI#46 corollary inverted: a node
    // MUST NOT STORE WHAT IT WOULD REJECT FROM A PEER. An entry written with a
    // bad or foreign signature is structurally unreplicable — no peer can ever
    // adopt it over anti-entropy — so it becomes a permanent, silent
    // divergence, reachable without forging anything.
    //
    // It is also the only thing that authenticates the SUBMITTER. Everything
    // else here proves the TRANSACTION (k=3 receipt, execution proofs,
    // continuity); nothing proved that whoever sent the register speaks for the
    // wallet. Verifying the client signature closes that: only the holder of
    // the wallet key can produce it.
    //
    // ── RULE 0 §4 marker (KI#226, found 2026-09-28 by
    // `fork_detection_mesh::s8b_framing_legs_do_not_replace_victim_head`) ──
    // WRONG READING: "only the holder of the wallet key can produce it" — on
    // its own this step never proved that: the sig is checked under
    // `reg.client_pk`, a FREE message field, and until 2026-09-28 over the
    // bucket derived from `reg.wallet_id`, so any key holder signed over a
    // victim's id and its own leg was stored as the victim's head.
    // RIGHT READING: authorship of the ROW holds because step 0b above
    // derives `bucket` from `reg.client_pk` and refuses a `wallet_id` that is
    // not that key's own; THIS step then proves the key signed the state.
    // FIXED (pending rotation) — AXIOM_REPORT_KnownIssues.md KI#226; the flood
    // and AE paths apply the same binding (`bucket_derives_from_key`).
    //
    // Payload is Core's single definition and is bound to the SMT BUCKET (the
    // single-keypair tiers share a wallet_id, so the bucket identifies the row
    // being authored) — the same bytes the SDK signs in
    // `compute_client_state_payload`.
    //
    // Scope: enforced whenever a pk is present. A ZERO pk is left to the
    // existing paths (group wallets are written zero-pk BY DESIGN via
    // `apply_group_update`; that carve-out lives with the replication gates and
    // is not re-litigated here).
    if reg.client_pk != [0u8; 32]
        && !crate::gossip::verify_client_state_sig(
            &reg.client_pk,
            &reg.client_sig,
            &bucket,
            &reg.new_state,
            &reg.tx_hash,
        )
    {
        log::warn!(
            "[REGISTER-REJECT] client-sig wallet={} bucket={} sig_len={} — the \
             registration is not authored by the wallet key it claims. Storing \
             it would create an entry no peer can adopt (KI#53).",
            hex::encode(&reg.wallet_id[..4]),
            hex::encode(&bucket[..4]),
            reg.client_sig.len(),
        );
        return Err(NablaError::InvalidReceipt);
    }

    // ── 5b′. RECORD-GRADE LEG VERIFY (ForkSettlement §2.3 [R17], [R‑MEDIUM-3]) ──
    //
    // Mandatory for every non-zero-pk register (zero pk = the group-wallet
    // carve-out 5a′ leaves to the replication gates). Until 2026-09-28 the door
    // verified only the KI#222 `receipt_sign_payload(wallet_id, consumed, tick)`
    // sigs (step 5) — a payload binding neither `new_state` nor `tx_hash` — and
    // checked `receipt_commitment` sigs only on the fee path (5b') and the
    // recall/HAL class check (6c). Now: the carried leg must reproduce the
    // k-signed `commitment_hash` and this register's `tx_hash`, agree with the
    // message's UNSIGNED `old_state` / `client_pk` / seq, and the receipt must
    // carry ≥ max(k_tier, 3) distinct valid `receipt_commitment_sig`s. After
    // this, the leg retained in the head's SeqProof (§8) is exactly what the k
    // signed. RULE 5: hygiene — Core's `validate_transaction` is the
    // enforcement a hostile Nabla cannot skip.
    //
    if reg.client_pk != [0u8; 32] {
        if let Err(reason) = verify_registered_leg(reg) {
            note_leg_refused(reason, &reg.wallet_id, &reg.tx_hash, "register");
            return Err(NablaError::LegUnverifiable(reason));
        }

        // ── 5b‴. ORIGIN RECORD + record-keyed fork detection (ForkSettlement
        //        §2.3 [R10], §2.4 [R11, R24, R30]) ──
        //
        // The leg 5b′ just proved is recorded HERE — above EVERY later refusal
        // (5c, the 5d idempotent retry, 6a `StateMismatch` incl. `seq_newer`,
        // 6b A12 `DoubleSpendDetected`, 6c class / stake-lock, 7a) [R30], and
        // above the WAL `Put` / `put_with_proof` [R24]: `put_inner` inserts the
        // consumed head into the consumed set in the same write that installs
        // the child, so a record made after it would see its own consumption as
        // "consumed, no sibling" and every honest register would be born
        // contested (R16). A leg the door then refuses is still a k-witnessed,
        // wallet-signed leg — it meets the ban.rs verdict standard on the spot,
        // and R16 decides whether its record is born contested.
        //
        // Structural (R11): only `ban::verify_fork_leg` can make a record. A
        // `LegPreimage::Redeem(..)` leg (the receiver's redeem-finalize
        // register, keyed on the CHEQUE txid — HIGH-1 / R5; its preimage is
        // verified at 5b′ since W7a) is recorded since W7b in the SEPARATE
        // redeem ledger — never an origin record, never vouched — and joins
        // the shared `(pk, consumed)` fork index, so a receiver redeeming two
        // cheques from one state on two sets is detected HERE like a double
        // send (spec R52c). A redeem declaring a zero consumed state creates
        // nothing [R33]. A zero pk never reaches this block, and a `wallet_id`
        // that is not the key's own never passed step 0b (KI#226).
        //
        // RULE 5: hygiene. The Core enforcement a hostile node cannot skip is
        // `fact::origin_settled_link` / `origin_settled_cl5` (txid recompute +
        // settle floor on the vouching node's own clock).
        if let Some(seq_proof) = crate::types::SeqProof::from_registration(reg) {
            let leg = crate::types::ForkLeg {
                new_state: reg.new_state,
                tx_hash: reg.tx_hash,
                client_sig: reg.client_sig.clone(),
                seq_proof,
            };
            if let crate::ban::LegRecordOutcome::ForkBanned { .. } =
                crate::ban::record_leg_and_detect(smt, bans, leg, now_secs, "register")
            {
                // The claim is verified and the registrant banned (WAL + flood
                // go out through `NablaNode::drain_fork_side_effects`, which
                // `register` runs on the Err path too). Nothing of this leg is
                // applied.
                return Err(NablaError::WalletBanned);
            }
        }
    }

    // ── 5b⁗. KI#224 — the witness sigs must WALK BACK TO THE ROOT ──────────
    //
    // Owner ruling 2026-10-02: a head's witness signatures count only if EVERY
    // key is the subject of an R42 directory entry at this node (admitted only
    // after `vbc::verify_vbc_bundle` walked its certificate to the genesis
    // roots). 5b′ proved the sigs are VALID over the commitment — but carried
    // keys alone are not validators: three self-made keys sign a valid quorum.
    // Placed AFTER 5b‴ (the leg is still recorded, ungraded [R30], so fork
    // detection on junk-witnessed legs is untouched) and BEFORE every head
    // mutation. Gated on `from_registration` being `Some`, zero-pk group
    // registers included (D-K224-2: their commitment sigs are validator sigs
    // like any other). The SAME predicate gates the flood
    // (`gossip::apply_state_update`) and head-AE (`node::
    // apply_remote_entry_inner`) — door-only would be bypassed by one injected
    // StateUpdate. RETRYABLE (`WitnessNotInDirectory`): a node whose directory
    // is still filling refuses an honest head; the SDK walks on to the next
    // Nabla, and flood/AE re-offer it once the key is admitted.
    if let Some(p) = crate::types::SeqProof::from_registration(reg) {
        if !crate::ban::seq_proof_is_directory_witnessed(&p, is_witness) {
            let unknown = crate::ban::first_non_directory_witness(&p, is_witness).unwrap_or_default();
            note_witness_not_in_directory(&unknown, &reg.wallet_id, &reg.tx_hash, "register");
            return Err(NablaError::WitnessNotInDirectory(unknown));
        }
    }

    // ── 5b. Verify execution proofs (ZKP/DMAP) ──
    // Pin to the NODE'S canonical CoreID (welded at build), not the receipt's
    // self-declared program_digest — otherwise the DMAP check is self-referential
    // and enforces nothing (a non-canonical/old Core's attestation passes).
    let canonical = parse_canonical_core_id(axiom_core_logic::version::CANONICAL_CORE_ID);
    let zkp_verified = verify_zkp_proofs(&reg.receipt.signatures, &canonical, &reg.new_state)?;

    // ── 5b'. YP §19.6 — Lambda receipt-commitment attestation chain ──
    //
    // Two-part check that closes the receiver-pays-only fee ledger chain
    // at the Nabla-mesh boundary. Gated on `!fee_breakdown.is_empty()`: the
    // fee cap and the per-slot credit only exist when there are fees.
    // (Corrected 2026-09-28: this comment used to justify the gate by "older
    // SDKs shipped skeleton zeros". The four commitment fields are now
    // MANDATORY on the wire and step 5b′ above already required a ≥k quorum of
    // valid commitment sigs on every register; what THIS step adds is that
    // EVERY slot — each one credited a fee — is a distinct valid signer.)
    //
    // Dev-class leak boundary: the per-register defensive gate below
    // (Layer 4-bis) is independent of this verify — it cross-checks
    // `is_dev_wallet(claimant_wallet_id)` against the routing flag
    // BEFORE any public-pool write. So a forged is_dev_class still
    // can't leak fees even when the SDK skips the commitment fields.
    if !reg.receipt.fee_breakdown.is_empty() {
        // ⚠ RULE 0 §4 MARKER — the misreading, recorded at the site.
        // WRONG reading (mine, 2026-09-16): "invalid k=3 receipt: signature
        //   verification failed" names the signatures, so the k receipt sigs
        //   must be wrong. Two rounds of signature diagnostics were added and
        //   stayed silent; the sigs verified 3/3 by hand.
        // CORRECT reading: `validate_fee_breakdown`'s FIRST argument is the
        //   amount the REGISTER declared — not a field of the receipt. The caps
        //   are computed from it, so with `amount == 0` the per-validator cap is
        //   0 and ANY non-empty fee slot trips `FeeExceedsValidatorCap`. Every
        //   error here becomes `NablaError::InvalidReceipt`, whose wire text is
        //   generic (KI#122) — so this refusal reports itself as a signature
        //   problem. The KI#185 sweep shipped the real receipt with tx_amount 0
        //   and every retry read as a bad signature.
        // AUTHORITY: core/logic/src/validation.rs::validate_fee_breakdown
        //   (SEC-12c); KI#185 follow-on + KI#122 in AXIOM_REPORT_KnownIssues.md.
        // This marker lives HERE and not in Core deliberately: a comment in
        //   core/logic makes the zkVM guest read STALE against the avm-guest
        //   (verify_deploy.sh), and the honest remedy is a guest rebuild that
        //   moves ZKVM_IMAGE_ID — a consensus-critical artifact — for a comment.
        //
        // KI#185 follow-on (2026-09-16): this refusal used to be SILENT, and
        // `InvalidReceipt`'s wire text is the generic "signature verification
        // failed" (KI#122) — so the one rejection that is NOT about signatures
        // reported itself as one, and cost a soak to find. The breakdown is
        // checked against the REGISTER's amount, so a client that ships a real
        // receipt with amount 0 (the KI#185 sweep did) is refused here.
        if let Err(e) = axiom_core_logic::validation::validate_fee_breakdown(
            reg.receipt.amount, &reg.receipt.fee_breakdown,
        ) {
            let total: u64 = reg.receipt.fee_breakdown.iter().map(|f| f.amount).sum();
            log::warn!(
                "[fee_breakdown] REFUSED: amount={} slots={} total_fee={} reason={:?} — wallet={}",
                reg.receipt.amount, reg.receipt.fee_breakdown.len(), total, e,
                hex::encode(&reg.wallet_id[..4]),
            );
            return Err(NablaError::InvalidReceipt);
        }
        if reg.receipt.fee_breakdown.len() != reg.receipt.signatures.len() {
            log::warn!(
                "[fee_breakdown] fee_breakdown.len()={} ≠ signatures.len()={}",
                reg.receipt.fee_breakdown.len(),
                reg.receipt.signatures.len(),
            );
            return Err(NablaError::InvalidReceipt);
        }

        // Commitment-chain verify — runs only when the SDK populated
        // both fee_breakdown AND the skeleton fields (state_hash etc).
        // is_dev_class is included so an SDK that tampers with the
        // flag fails the verify and the register rejects before any
        // pool moves. (Extracted to a helper so the recall/HAL path —
        // §5b'' below — can require the same check on an empty fee_breakdown.)
        verify_receipt_commitment_sigs(reg)?;
    }

    // ── 5c. Txid double-redeem detection ──
    // If this txid was already registered by a DIFFERENT wallet, reject.
    // Same wallet re-registering same txid is OK (idempotent state update).
    //
    // ⚠ KI#231 (2026-09-29): `txid_index` is fed ONLY at redeem-finalize
    // (`record_txid`), so it answers "which wallet REDEEMED this txid". That is a
    // question about REDEEM legs. A redeem registers under the cheque's send-txid,
    // so the SENDER's own late registration of that send (the KI#221 settle path:
    // its first register failed, the receiver redeemed anyway and inherited the
    // unresolved origin) carries the SAME txid under a different wallet — and was
    // refused here as a "double-redeem". The receiver's inherited scar could then
    // never clear by settlement. A verified Send leg cannot be a double-redeem:
    // 5b′ proved its preimage recomputes this tx_hash under this client_pk, so
    // only the real sender reaches this line with it.
    if reg.tx_hash != [0u8; 32] {
        let existing = smt.get_wallet_by_txid(&reg.tx_hash);
        let verified_send_leg = reg.client_pk != [0u8; 32]
            && matches!(reg.preimage, axiom_core_logic::nabla_wire::LegPreimage::Send(_));
        if txid_holder_refuses(existing, &bucket, verified_send_leg) {
            log::warn!("Txid double-redeem: txid registered by different wallet");
            return Err(NablaError::DoubleSpendDetected);
        }
    }

    // ── 5d. Idempotent retry detection (lost-ACK recovery) ──
    //
    // If same wallet + same txid + SMT already at the claimed `new_state`,
    // this is a retry of a previously-succeeded register whose `RegisterAck`
    // was lost in transit (network drop on the return path AFTER Nabla
    // committed). Without this short-circuit the retry hits the
    // StateMismatch[SMT_VS_REG] check below and the sender's scarred FACT
    // link can never get its `nabla_confirmation` populated — heal-burn
    // becomes the only recovery for a fully-recoverable network glitch.
    //
    // We compare the SMT entry's stored `tx_hash` directly to `reg.tx_hash`
    // (NOT via the optional `txid_index`, which is only populated in
    // Hashmap txid mode — nodes running in default Bloom mode would skip
    // the idempotent path otherwise). The stored entry's tx_hash is always
    // present regardless of txid_mode.
    //
    // Re-issue an ACK that's byte-equivalent to what the sender would have
    // received originally:
    //   - fact_confirm_signature is deterministic over (old_state, new_state)
    //     via the shared `crypto::fact_confirm_payload` function — the
    //     sender gets the same signature whether this is first ACK or retry.
    //   - root_hash is the current SMT root (unchanged on retry).
    //   - tick is current_tick (retry's tick; root_hash binds to the original
    //     commitment, the tick on a retry ACK is informational).
    //
    // Safe because:
    //  1. Same-wallet check at 5c already excluded cross-wallet replay.
    //  2. `tx_hash` is BLAKE3 over the TX content including old/new state —
    //     same txid + same wallet + matching stored state ⇒ same state
    //     transition was already applied.
    //  3. SMT already at `new_state` means the transition was applied (WAL
    //     written, DEED collected, genesis-claim pool debited, gossiped).
    //     Retry MUST NOT redo any of those side-effects. KI#250: the pool
    //     debit (step 7b) sits BELOW this return, so a lost-ACK retry of a
    //     genesis claim debits nothing — before KI#250 it sat above and
    //     every such retry debited the pool a second time.
    //  4. The original receipt-signature verifications (steps 5/5b) passed
    //     when the entry was first committed; we trust the existing record.
    //
    // We re-emit StateUpdate gossip: peers' SMTs are idempotent on
    // (wallet_id, current_state) — a duplicate StateUpdate is a no-op
    // at their end too. No DEED charge, no WAL append.
    //
    // Closes the lost-ACK gap that prevented supplemental-registration
    // (YP §17.9.4.3) from clearing scarred FACT links when Nabla had
    // already committed but the original ACK was lost.
    if reg.tx_hash != [0u8; 32] {
        if let Some(existing) = smt.get(&bucket) {
            if existing.tx_hash == reg.tx_hash
                && existing.current_state == reg.new_state
            {
                log::debug!(
                    "Idempotent register retry: wallet={} txid={} state={} (lost-ACK recovery)",
                    hex::encode(&reg.wallet_id[..4]),
                    hex::encode(&reg.tx_hash[..4]),
                    hex::encode(&existing.current_state[..4]),
                );
                let confirm_payload = crate::crypto::fact_confirm_payload(
                    &reg.old_state, &reg.new_state, current_tick,
                );
                let fact_confirm_signature = signer.sign(&confirm_payload);
                let mut ack = RegistrationAck {
                    wallet_id: reg.wallet_id,
                    new_state: reg.new_state,
                    tick: current_tick,
                    root_hash: smt.root_hash(),
                    signature: vec![],
                    node_pk: vec![],
                    node_id: vec![],
                    known_peers: vec![],
                    zkp_verified: true,
                    cheque_status: ChequeStatus::Scarred,
                    fact_confirm_signature,
                    ..Default::default()
                };
                ack.signature = signer.sign(&crypto::ack_sign_payload(&ack));
                // Re-emit the *original* StateUpdate byte-for-byte: the
                // stored entry's tick, not the retry's `current_tick`.
                // `existing.client_sig` was signed over `existing.tick`, so
                // a `current_tick` here would fail peer signature checks;
                // and under the §5.2 merge rule a bumped tick on an
                // unchanged state would diverge the mesh. The original
                // gossip carried `existing.tick` — reproduce it exactly so
                // the retry is a true idempotent no-op everywhere.
                // YP §19.6 — idempotent retry re-emits the same data the
                // original gossip carried. If a hashmap-mode node already
                // stored the per-tx record, pull amount + fee_breakdown
                // from there so the retry is byte-equivalent to the
                // original /register's gossip; otherwise emit empty (the
                // re-broadcast still triggers anti-entropy if a peer is
                // behind).
                let (retry_amount, retry_breakdown) =
                    smt.tx_record(&reg.tx_hash)
                        .map(|r| (r.amount, r.fee_breakdown.clone()))
                        .unwrap_or((0, Vec::new()));
                let gossip_msg = GossipMessage::StateUpdate {
                    wallet_id: bucket,
                    new_state: reg.new_state,
                    // KI#46 check-3: an idempotent retry re-advertises the SAME
                    // advance, so the parent is the register's own old_state.
                    old_state: reg.old_state,
                    tx_hash: reg.tx_hash,
                    tick: existing.tick,
                    is_genesis_claim: reg.is_genesis_claim,
                    wallet_seq: reg.receipt.new_wallet_seq, // WI3: k-attested seq from receipt
                    client_pk: existing.client_pk,
                    client_sig: existing.client_sig.clone(),
                    amount: retry_amount,
                    fee_breakdown: retry_breakdown,
                    // WI3 hole-1: re-emit the original gossip's seq proof.
                    seq_proof: crate::types::SeqProof::from_registration(reg),
                };
                return Ok(RegistrationResult { ack, gossip_msg, hibernation_until: None, committed_recalls: Vec::new(), held_fee_credit: None });
            }
        }
    }

    // ── 6. Check local state and update SMT ──
    //
    // YPX-002 §3.3 — on local `current_state != old_state` mismatch, return
    // an error. NOT a ban.
    //
    // The `/register` path intentionally does not ban. Per YPX-002 §7.5 +
    // §7.4, a wallet ban is issued ONLY when the gossip-merge path observes
    // two independently-valid k=3 registrations with the same `old_state`
    // and two different `new_states`. That is the proof-of-double-spend
    // condition and it requires two k=3 receipts, not one. A mismatch at
    // `/register` only proves that THIS node has not yet observed the
    // intermediate state — which is normal during gossip propagation. The
    // sender's designated Nabla (§3.2, client sticky) is the mechanism that
    // keeps a single sender's write path from ever encountering this case
    // in steady state; any mismatch here reflects a client that hopped
    // nodes, a stale local view, or a real fraud attempt. All three are
    // handled at the correct layer: client retries against its sticky
    // node, gossip converges the stale local view, and gossip merge
    // catches the genuine conflict with two-k3 evidence.
    //
    // Regression guard: any future code that tries to call `bans.ban()`
    // from this call site is a re-introduction of the YPX-002 false-ban
    // bug. See P4.2 invariant assertion enforced at `bans.ban()` itself.
    //
    // ── KI#34 / HAL fail-closed precondition (threat: CollusionWipeRevival) ──
    // A HAL re-anchor relaxes the Lambda prior-witness overlap (modes.rs:479), so the
    // ONLY thing binding it to the wallet's true state is the held SMT entry checked
    // below. But the head-match below only runs inside `if let Some(existing)` — when
    // there is NO entry (a wiped/unknown wallet) it is skipped and the register
    // fresh-inserts. That is exactly the wipe-revival path: HAL re-anchoring a wallet
    // the network has no record of. Fail CLOSED — no held previous state ⇒ HAL cannot
    // start hibernation. A legit dead-overlap wallet still has its head replicated in
    // the SMT (only its *witnesses* are dead), so it matches `Some(existing)` and
    // proceeds; only a wiped/never-seen wallet hits this. Normal (non-HAL) registers
    // keep fresh-insert for genesis / first contact. PARTIAL fix (check 1 of KI#34):
    // it does not defend a forged head-rollback that poisons the held state to an
    // ancestor — pair with the seq-monotonic merge (KI#34 fix sketch).
    if reg.is_hal_reanchor && smt.get(&bucket).is_none() {
        log::warn!(
            "[KI#34] HAL re-anchor rejected: no held previous state for wallet={} (fail-closed)",
            hex::encode(&reg.wallet_id[..4])
        );
        return Err(NablaError::StateMismatch);
    }
    // KI#68 — set when the register-door adoption fallback fires (held head
    // is behind reg.old_state, adopted via the AE rule). Skips 6b's
    // old_state consumed-check, whose premise (`old_state == head`) does not
    // hold on this path; the fallback's own `target_fresh` gate is the
    // model-proven A12 guard (on reg.new_state).
    let mut ki68_adopting = false;
    if let Some(existing) = smt.get(&bucket) {
        if existing.current_state != reg.old_state {
            // ── 6a. Held head BEHIND reg.old_state ──
            //
            // RETIRED 2026-10-02 (owner-approved): the KI#5 advance-on-proof
            // `partial_bridge` arm that used to sit here is DELETED. It
            // verified 1-2 sigs over `receipt_sign_payload(wallet, X, 0)`,
            // which binds neither the claimed partial state nor its txid,
            // and wrote an unauthenticated txid + a proofless intermediate
            // head. For honest traffic the KI#68 adopt below is a strict
            // superset (it also covers multi-step gaps, which the bridge
            // could not). Exits for a stuck wallet: KI#59 out-of-order
            // registration, HAL re-anchor, CLARA heal + this KI#68 adopt,
            // resume (KI#153), re-register, RECALL — YP §17.9.4.7.
            // DO NOT weaken this adopt: the CLARA-heal exit depends on it.
            let smt_state = existing.current_state;
            let smt_seq = existing.wallet_seq;
            // ── KI#68 — register-door adoption fallback ──
            //
            // The held head is BEHIND `reg.old_state`. This is the acked-then-lost
            // wedge (wallet 024, 2026-08-08): the bridging link WAS
            // k-witnessed and registered — its ACK reached the wallet,
            // which dequeued it — but the acking node then lost it in a
            // torn WAL tail, so it exists in NO retry queue and nabla
            // can never be handed it in chain order. Strict chaining
            // would refuse this wallet forever.
            //
            // Fall back to the SAME adoption rule the AE/gossip door
            // already applies to a peer's head (`CanAdopt` in the
            // model): a node adopts what it would accept second-hand
            // from a peer, so this admits NO state the mesh cannot
            // already reach. Three guards, mirroring the model exactly:
            //   • attested   — the k=3 SeqProof CRYPTOGRAPHICALLY
            //     VERIFIES against `new_wallet_seq` (`verify_seq_proof`,
            //     the EXACT check the flood/AE doors run before any
            //     seq-advance — gossip.rs / apply_remote_entry). This
            //     MUST be the verified form, not `from_registration(..).
            //     is_some()` (presence only): `new_wallet_seq` is bound
            //     ONLY by `receipt_commitment_sig`, and that verify
            //     (`verify_receipt_commitment_sigs`) is SKIPPED on a
            //     sender /register (empty fee_breakdown). Without the
            //     recompute, a forged-high `new_wallet_seq` would
            //     satisfy `seq_newer`, adopt an un-attestable head, and
            //     strand the wallet on this node (AE then rejects it
            //     `seq-unattested` — the KI#38/73/77 divergence class).
            //     Caught by an adversarial review of this fallback,
            //     2026-08-09.
            //   • seq-newer  — reg.receipt.new_wallet_seq STRICTLY >
            //     the held seq. Equal-seq is the fork-sibling / same-seq
            //     redeem-forward case that seq ALONE cannot separate
            //     (smt.rs `superseded_by` note), so it is NOT adopted
            //     here — preserves per-node consume-once (NoDoubleChild).
            //   • target-fresh — reg.new_state not in THIS node's A12
            //     consumed bloom (never adopt a state we know was spent).
            //
            // On adopt we DO NOT return: fall through to the normal
            // §8 `smt.put`, which jumps the head to reg.new_state and
            // marks the superseded head consumed — the model's `Adopt`.
            // The gap's intermediate consumptions are recorded by the
            // SDK's order-free supplemental txid re-registers (the
            // model's `Backfill`); §12.4.1 adjudicability holds once
            // those land.
            //
            // SAFETY: TLA+ model docs/models/ki68_register_door
            // (RESULTS.md) — with this fallback and no retention loss,
            // NoRevival (A12 anti-rollback) and NoDoubleChild
            // (consume-once) HOLD under equivocation; the deadlock this
            // cures is TLC's own counterexample; the only residual
            // (NoDoubleChild under retention loss) is present
            // IDENTICALLY with strict chaining and is KI#34's, not
            // introduced here. YP §17.9.4.7.
            let attested = crate::types::SeqProof::from_registration(reg)
                .is_some_and(|p| verify_seq_proof(
                    &p, &reg.tx_hash, reg.receipt.new_wallet_seq));
            let seq_newer = reg.receipt.new_wallet_seq > smt_seq;
            let target_fresh = !smt.is_state_consumed(&reg.new_state);
            if attested && seq_newer && target_fresh {
                log::warn!(
                    "[KI#68] register-door ADOPT: wallet={} smt.current={} -> new={} \
                     (seq {} -> {}; acked-then-lost gap)",
                    hex::encode(&reg.wallet_id[..4]),
                    hex::encode(&smt_state[..4]), hex::encode(&reg.new_state[..4]),
                    smt_seq, reg.receipt.new_wallet_seq,
                );
                ki68_adopting = true;
                // fall through to §8 put — adopt.
            } else {
                log::warn!(
                    "StateMismatch[SMT_VS_REG]: wallet={} smt.current={} reg.old={} \
                     (KI#68 fallback declined: attested={} seq_newer={} target_fresh={})",
                    hex::encode(&reg.wallet_id[..4]),
                    hex::encode(&smt_state[..4]), hex::encode(&reg.old_state[..4]),
                    attested, seq_newer, target_fresh);
                return Err(NablaError::StateMismatch);
            }
        }
    }

    // ── 6b. YPX-020 A12 anti-rollback — consumed-state bloom gate ──
    // At this point `existing.current_state == reg.old_state` (a mismatch already
    // returned StateMismatch above) — EXCEPT on the KI#68
    // register-door adopt path (`ki68_adopting`), where the held head is behind
    // reg.old_state and the fallback's own `target_fresh` gate already enforced
    // the model's A12 guard on reg.new_state (docs/models/ki68_register_door).
    // A LEGIT register's `old_state` is the live head, never yet consumed. The
    // ONLY way `old_state` is already in the monotonic consumed-state bloom is a
    // forged head-rollback to an ancestor (A12) — the head says `old_state` is
    // current, but the bloom remembers it was advanced past. Reject. The bloom
    // never false-negatives, so this never misses a replay; a false positive
    // (bloom saturation) only ever rejects, never admits — bound it with
    // time-bucketing before production.
    if !ki68_adopting && smt.is_state_consumed(&reg.old_state) {
        log::warn!(
            "[A12] reject replay of consumed state: wallet={} old={}",
            hex::encode(&reg.wallet_id[..4]), hex::encode(&reg.old_state[..4]),
        );
        return Err(NablaError::DoubleSpendDetected);
    }

    // ── 6b. YPX-022 §2.2.1 — an `is_recall` register (the hibernation-entry
    // COMMIT) requires an OPEN reservation for this wallet. If the receiver's
    // redeem finalized during the reservation window it WON (first-wins,
    // `mark_txid_redeemed` deleted the reservation) and the recall must fail
    // closed BEFORE anything advances — the payment stands. Runs under the
    // same lock as the redeem-finalize marks, so exactly one settles.
    // (`reg.wallet_id` IS the wallet's raw Ed25519 pk for SDK registers —
    // the same pk `register_recall` reserved under; see the 8a comment.)
    if reg.is_recall {
        let reserved = smt.reserved_recall_txids(&bucket);
        if reserved.is_empty() {
            return Err(NablaError::RecallAborted);
        }
        // YPX-022 §2.1.2a item 4 (KI#205, RULED 2026-09-25) — CLAIM BEATS
        // RESERVATION. An authenticated claim that arrived while the
        // reservation was open proves the addressed receiver holds the cheque
        // (delivered); the commit fails closed exactly as it does when a redeem
        // finalized first. A recall self-send commits ALL of this wallet's open
        // reservations at once (`commit_recalls_for`), so one claimed txid
        // refuses the whole register — fail closed, the payment stands.
        if reserved.iter().any(|t| smt.has_live_claim(t, current_tick)) {
            return Err(NablaError::RecallAborted);
        }
    }

    // ── 6c. YPX-022 / YPX-020 — recall/HAL hibernation-stamp class integrity ──
    //
    // The finish-gate window (§8a below) is stamped from `reg.receipt.is_dev_class`
    // via `hibernation_until_for`. A recall self-send / HAL re-anchor carries an EMPTY
    // `fee_breakdown`, so §5b' above is skipped — leaving `is_dev_class` UNVERIFIED on
    // exactly the two paths that consume it for the window. A public-wallet recall
    // could then forge `is_dev_class=true` and receive the SHORT dev finish-gate window
    // (shortening its own redeem-wins convergence buffer under partition/eclipse — NOT
    // a fund leak: Core binds the window into `produced_state_id` via
    // `is_dev_wallet(sender)` on the SIGNED tx, checked by
    // `reg.new_state == receipt.produced_state_id` (§4) + `verify_zkp_proofs` (§5b) —
    // but a deviation from "public always gets the full window"). Recall + HAL are
    // ALWAYS k-witnessed, so the receipt_commitment_sig is ALWAYS present here; require
    // + verify it so the class flag is k-attested. Runs AFTER the state-machine gates
    // (6b RecallAborted / HAL no-held-state) and BEFORE the WAL write below → any
    // reject here is fail-closed, nothing has advanced.
    if reg.is_recall || reg.is_hal_reanchor {
        verify_receipt_commitment_sigs(reg)?;
    }

    // ── 6c. §5.2.2c KI#132 — the STAKE-LOCK spot-check ──────────────────────
    //
    // UNCONDITIONAL, and placed here for the same reason §5b'' is: after the
    // state-machine gates, BEFORE the WAL write below — so a reject is
    // fail-closed and nothing has advanced. It must not sit inside the
    // fee_breakdown branch above: a stake-locked wallet's register carries no
    // fees, which is exactly the shape that would skip the check.
    verify_declared_state_and_stake_lock(reg, current_tick)?;

    // ── 7. Write to WAL before updating SMT ──
    let new_entry = NablaEntry {
        // The BUCKET (pk-for-Standard, tier-derived otherwise): the mesh's
        // map key. The registrant's identity rides `client_pk` below.
        wallet_id: bucket,
        // WI3: k-witnessed chain position from the verified receipt (≥3 sigs
        // checked above). Authoritative register site → this seq is k-attested.
        wallet_seq: reg.receipt.new_wallet_seq,
        current_state: reg.new_state,
        tx_hash: reg.tx_hash,
        tick: current_tick,
        group_members: None, // personal wallet by default
        status: WalletStatus::Normal,
        client_pk: reg.client_pk,
        client_sig: reg.client_sig.clone(),
        // §32.3 — the k-attested sender lineage from the redeem receipt
        // (Core CL5 folded it into `receipt_commitment`, verified above for
        // recall/HAL and on the fee-ledger path; `None` for non-redeems).
        // This is the edge §32.4 taint propagation walks.
        received_from: reg.receipt.sender_state,
    };

    // ── 7a. Branch A — transactional gossip (AXIOM_DESIGN_NablaAntiEntropy §5.2.2) ──
    // Refuse to COMMIT a seq-ADVANCE that carries NO receipt_commitment_sig at all
    // (`from_registration` → None). Such a head comes from an INCOMPLETE k=3 witness
    // round — a partial commit, or a validator crash / network partition mid-round.
    // Committing it advances THIS node's seq but leaves it permanently
    // un-attestable: every anti-entropy peer rejects it `seq-unattested
    // proof=ABSENT`, so any node that missed the flood is stranded and the mesh
    // wedges at applied=0 (the §5.2.2 proof=ABSENT non-convergence, measured live
    // 2026-07-23: 4419 ABSENT rejects, 55 stuck wallets). Reject here so the head
    // never enters the mesh — the tx stays uncommitted at the client, which
    // re-witnesses (a COMPLETED round always signs the receipt_commitment:
    // send/heal/genesis via CL3, redeem via CL5, Step 7). Gated on `from_registration`
    // = None (ABSENT), NOT on `verify_seq_proof` (which would also fail a
    // CARRIED-BUT-FAILED entry — e.g. genesis via the legacy skeleton builder (GONE
    // since ForkSettlement wave 2a: 5b′ above now refuses a CARRIED-BUT-FAILED
    // authored register first, so this gate is reached with such a shape only
    // for zero-pk group registers) —
    // and false-reject legitimate traffic; live data shows 0 CARRIED-BUT-FAILED).
    // Equal/lower seq needs no proof (can't win the merge on seq) and is exempt.
    {
        let held_seq = smt.get(&bucket).map(|e| e.wallet_seq);
        let advances_seq = match held_seq {
            Some(h) => reg.receipt.new_wallet_seq > h,
            None => reg.receipt.new_wallet_seq > 0,
        };
        if advances_seq
            && crate::types::SeqProof::from_registration(reg).is_none()
        {
            log::warn!(
                "[branch-A] refusing un-attestable seq-advance wallet={:02x}{:02x} seq={} \
                 (incomplete witness round — no receipt_commitment_sig); client re-witnesses",
                bucket[0], bucket[1], reg.receipt.new_wallet_seq,
            );
            return Err(NablaError::InvalidReceipt);
        }
        // ── 7a'. KI#122 — the register door must not store what its own AE
        // door would reject. The exemption above reasons "equal/lower seq
        // can't win the merge" — true for MESH adoption, but §8's `smt.put`
        // still replaces THIS node's held head locally. Measured 2026-08-27:
        // a CLARA heal re-register shipped the skeleton receipt's hard-coded
        // `new_wallet_seq: 0`; exactly one node accepted it over its seq=17
        // head, every peer then AE-rejected the entry as `not-superseding`
        // while the acceptor refused to roll back its consumed state —
        // a permanent 10-vs-1 fork that §32's wallet-level resolve cannot
        // touch (KI#122, evidence-epsilon-fork-20260827).
        //
        // seq=0 is legitimate ONLY for a wallet with no attested history
        // (genesis-fresh, held=None). Core increments the seq on every link,
        // so no honest receipt can carry 0 over an existing seq>0 head. Scoped
        // deliberately to the measured poison — broader equal/lower-seq
        // semantics (same-seq redeem-forward, fork-siblings) stay untouched.
        if reg.receipt.new_wallet_seq == 0 && held_seq.is_some_and(|h| h > 0) {
            log::warn!(
                "[KI#122] refusing seq=0 register over attested head wallet={:02x}{:02x} \
                 held_seq={} (skeleton receipt — AE would reject this entry as \
                 not-superseding on every peer; client must re-register with the \
                 canonical receipt)",
                bucket[0], bucket[1], held_seq.unwrap_or(0),
            );
            return Err(NablaError::InvalidReceipt);
        }
    }

    let serialized = bincode::serialize(&new_entry)
        .map_err(|e| NablaError::SerializationError(e.to_string()))?;

    // KI#38 / KI#73 — ONE derivation of the k=3 seq attestation for the head
    // THIS node is about to commit, used for BOTH the WAL record (so replay
    // re-establishes byte-identically) and the in-memory retention below.
    // The receipt's commitment sigs were verified at §5b above, so this proof
    // is sound — it is the same attestation the outgoing StateUpdate flood
    // carries (step 10). §5b requires k verified 64-byte sigs, so
    // `from_registration` returning None here is structurally impossible; fail the
    // registration (closed, no panic) rather than commit an unattestable head
    // — an origin head without a retained proof is exactly the KI#38/KI#123
    // strand (AE refuses it forever, `seq-unattested proof=ABSENT`).
    let seq_proof = crate::types::SeqProof::from_registration(reg)
        .ok_or_else(|| {
            NablaError::SmtError(
                "verified k=3 receipt yielded no retainable seq attestation \
                 (impossible after §5b — refusing to commit an unattestable head)"
                    .to_string(),
            )
        })?;

    // ── 7b. KI#250 — genesis-claim POOL DEBIT, at the head write ──
    //
    // ⚠ WRONG READING (pre-KI#250): this block sat right after the two class
    // checks at the top of the door, BEFORE any signature was verified. A pool
    // debit is irrevocable (strict-decrease invariant `node.rs::set_balance`,
    // no credit path) and PoolSync broadcasts the in-memory balance every
    // heartbeat, so any refusal BELOW the debit (steps 4, 5, 5a′, 5b′, 5b‴,
    // 5b⁗, 5c, 6/6a/6b, 7a/7a′) left a mesh-wide, permanent drain: 5 unsigned
    // registers emptied Foundation, 85 emptied Bootstrap. The 5d lost-ACK
    // retry (`return Ok`) also debited a SECOND time for one claim.
    // CORRECT: the pool record is written only when the head is written —
    // HERE, after every refusal in the door and before the first irreversible
    // write (`wal.append` below). 5d now returns above this, so a retry never
    // debits, and `[POOL-GRANT]` fires only for a claim that reaches the head.
    // NO refund / snapshot-restore path exists or may be added — it would need
    // a way around the strict-decrease invariant (a security reduction).
    // Spec: AXIOM_DESIGN_FactClassIsolation.md §6, PoolCaps §4, YP §17.11.
    if reg.is_genesis_claim {
        // (3) Route deduction to the matching pool. `try_claim` now
        // takes `current_tick` for per-Nabla cycle-cap enforcement
        // (PoolCaps §4). `false` return can mean pool-exhausted OR
        // per-Nabla cap reached OR mesh-wide cap reached; for the
        // registration path we treat them the same (claim refused).
        // PRE-FIX BEHAVIOUR was: Dev pool hard-reject on cap; Airdrop pool
        // silently registered "at balance=0" (the §17.11.4 graceful-
        // degrade path). The graceful-degrade path was a monetary
        // expansion vector — Lambda witnessed the AXC creation
        // independently of Nabla, so a cap-refused claim still gave the
        // wallet 1 AXC with the pool counter unchanged. Session 13 soak:
        // 16/50 wallets, see `docs/AXIOM_REPORT_Soak_20260422.md`. POST-
        // FIX (this revision): both pools hard-reject for ALL three
        // refusal reasons (per-Nabla cap / mesh cap / exhausted), each
        // with a distinct error so the client can route correctly:
        //   - PerNablaCap → retry on a different Nabla (this one's full)
        //   - MeshCap     → wait for the cycle to reset
        //   - Exhausted   → permanent (no replenishment)
        use crate::node::ClaimOutcome;
        // ╔═ BOOTSTRAP SUBSIDY — REMOVE WHEN POOLS DRAIN ═══════════════╗
        // Design: AXIOM_DESIGN_ValidatorJoin.md §5.2.3a / §5.2.3b
        // Removal: delete the two subsidy arms below and the two pool
        // parameters. Nothing else here changes.
        // ╚═════════════════════════════════════════════════════════════╝
        // THE POOL IS A FUNCTION OF THE AMOUNT CORE PINNED — never of anything
        // the client asserts. Core pins `tx.amount` to the claim kind's floor
        // inside the ELF (GENESIS_CLAIM_AMOUNT / TIER3 / TIER2, all distinct),
        // every validator re-runs that, and the value rides the k-signed
        // `K3Receipt.amount`. So amount->pool is a lookup, not a decision, and
        // there is no field for a client to lie in. An earlier attempt put a
        // `stake_claim_tier` on the wire for the client to fill in; that
        // re-opened the hole it was meant to close and was discarded.
        //
        // The airdrop needs none of this because one flag maps to one pool
        // paying one fixed sum. The subsidy added three amounts spanning five
        // orders of magnitude; a client-selected pool against a
        // Core-determined mint is exactly what creates money.
        //
        // Each arm reads `balance()` INSIDE the match: taking the `&mut` out of
        // the Option moves it, so the balance cannot be read afterwards.
        let claim_amount = reg.receipt.amount;
        let (outcome, pool_label) = if wallet_is_dev {
            match dev_treasury_pool {
                Some(pool) => (pool.try_claim(current_tick), "DEV-TREASURY"),
                None => (ClaimOutcome::RefusedExhausted, "DEV-TREASURY"),
            }
        } else if claim_amount == axiom_core_logic::types::TIER2_CLAIM_ATOMS {
            match foundation_bootstrap_pool {
                Some(pool) => (
                    // ⚠ DEBIT THE PAYOUT, NOT THE FLOOR. Core mints the claim
                    // amount; if the pool is debited a smaller number the two
                    // diverge — money created, pool unpaid — which is the exact
                    // mismatch §5.2.2b was written for (2026-09-02: Core minted
                    // 500 AXC while the pool paid 1).
                    pool.try_claim_amount(current_tick,
                        axiom_core_logic::types::TIER2_CLAIM_ATOMS),
                    "SUBSIDY/Foundation",
                ),
                None => (ClaimOutcome::RefusedExhausted, "SUBSIDY/Foundation"),
            }
        } else if claim_amount == axiom_core_logic::types::TIER3_CLAIM_ATOMS {
            match bootstrap_pool {
                Some(pool) => (
                    // Debit the PAYOUT — see the tier-2 arm above.
                    pool.try_claim_amount(current_tick,
                        axiom_core_logic::types::TIER3_CLAIM_ATOMS),
                    "SUBSIDY/Bootstrap",
                ),
                None => (ClaimOutcome::RefusedExhausted, "SUBSIDY/Bootstrap"),
            }
        } else {
            // Includes GENESIS_CLAIM_AMOUNT and every legacy/zero receipt the
            // airdrop path has always accepted — behaviour for the airdrop is
            // byte-unchanged, which is what keeps 700+ existing claims working.
            match airdrop_pool {
                Some(pool) => (pool.try_claim(current_tick), "AIRDROP"),
                None => (ClaimOutcome::RefusedExhausted, "AIRDROP"),
            }
        };
        match outcome {
            // ⚠ A GRANT MOVES MONEY AND MUST SAY SO. This arm was `{}`: every
            // refusal logged and the one event that matters logged nothing, so
            // "no node logged a grant" read as "no node granted" and a
            // mis-grant was misdiagnosed twice (RULE 3 shape 2 — a check that
            // cannot be observed running). Do not make this silent again.
            ClaimOutcome::Granted => {
                log::info!(
                    "[POOL-GRANT] {} granted to wallet {} — {} atoms",
                    pool_label, hex::encode(&reg.wallet_id[..8]), claim_amount,
                );
            }
            ClaimOutcome::RefusedPerNablaCap { cycle_resets_at_tick } => {
                log::warn!(
                    "[{}] Claim refused for wallet {} — per-Nabla cycle cap reached (reset at tick {})",
                    pool_label,
                    hex::encode(&reg.wallet_id[..8]),
                    cycle_resets_at_tick,
                );
                return Err(NablaError::PoolCapPerNabla { reset_tick: cycle_resets_at_tick });
            }
            ClaimOutcome::RefusedMeshCap { cycle_resets_at_tick } => {
                log::warn!(
                    "[{}] Claim refused for wallet {} — mesh-wide cycle cap reached (reset at tick {})",
                    pool_label,
                    hex::encode(&reg.wallet_id[..8]),
                    cycle_resets_at_tick,
                );
                return Err(NablaError::PoolCapMesh { reset_tick: cycle_resets_at_tick });
            }
            ClaimOutcome::RefusedExhausted => {
                log::warn!(
                    "[{}] Claim refused for wallet {} — pool exhausted",
                    pool_label,
                    hex::encode(&reg.wallet_id[..8]),
                );
                return Err(NablaError::PoolExhausted);
            }
        }
    }

    wal.append(&WalOp::Put {
        key: bucket,
        value: serialized,
        client_pk: reg.client_pk,
        client_sig: reg.client_sig.clone(),
        // KI#73 — the head THIS node just committed is exactly the one that got
        // stranded: retained in memory at §8 below, persisted in the snapshot,
        // and lost on any restart before the next snapshot. Same derivation as
        // §8 so replay re-establishes byte-identically.
        seq_proof: Some(seq_proof.clone()),
    })
    .map_err(|e| NablaError::WalError(e.to_string()))?;

    // ── 8. Update SMT ──
    // §5.2.4 (KI#123): the proof is installed ATOMICALLY with the head — the
    // origin node is the one place the newest head is guaranteed to exist, and
    // before KI#38 it was the one place that never retained its own proof
    // (mesh wedged at applied=0, measured 2026-07-08 soak s2r70134).
    let new_root = smt.put_with_proof(&new_entry, crate::smt::PutProof::Attested(seq_proof));

    // ── 8a. YPX-020 HAL hibernation — stamp the lock on a re-anchor register ──
    let mut hibernation_until: Option<u64> = None;
    // YPX-022 §2.2.1 — reservations committed by this register (is_recall only).
    let mut committed_recalls: Vec<(TxHash, u64)> = Vec::new();
    // Nabla owns the authoritative tick, so it sets the deadline from its OWN
    // current tick (fresh by construction — a dead-overlap wallet's stale
    // fact-chain tick never enters). `register_tick + WINDOW` is derivable from
    // the gossiped register, so the mesh converges on one value.
    //
    // ⚠ CORRECTED 2026-09-05 (RULE 3 shape 7). This said the wallet's subsequent
    // cheque-claim "is refused in `register_cheque_claim` until `current_tick`
    // reaches this value". IT IS NOT. `register_cheque_claim` contains no
    // hibernation check — its `tick` argument is used only to expire stale
    // claims — and `smt.rs` states the opposite explicitly: the hibernation map
    // "gates nothing", and the claim path is "Clockless — the client self-times
    // the window". The value computed here is INFORMATIONAL. The authoritative
    // lock is the wallet's own §15-anchored `hibernation_until` at Core's SEND
    // gate, which is BINARY and never compares this deadline to a clock.
    //
    // Do not add an enforcement read here without first authenticating the map
    // (`g9_forged_hibernation_cannot_block_a_register` fails if you do) — an
    // unauthenticated reject turns a forged packet into a remote send-lock on
    // any wallet by public key.
    // is_dev_class = the k-signed, Core-attested flag on the receipt (gates the
    // dev-wallet short window; a public wallet always gets the full window — see
    // hibernation_until_for). MUST match Core's is_dev_wallet(sender) for §15 lock-step.
    let hib_until = axiom_core_logic::types::hibernation_until_for(
        current_tick, reg.is_hal_reanchor, reg.is_recall, reg.receipt.is_dev_class,
        false, false, // stake-claim kinds are not carried on the register path
    );
    if hib_until != 0 {
        // Key by `wallet_id` — for an SDK register this IS the wallet's raw
        // Ed25519 pubkey (build_register_message sets wallet_id = wallet_pk).
        // The YPX-020 re-anchor is a dust SELF-send X→X', so when the wallet
        // completes it the cheque-claim carries `sender_wallet_pk` = this same
        // raw pubkey — that is what `register_cheque_claim`'s gate checks.
        // Keying on `reg.client_pk` would NOT match that claim: the claim
        // names the sender's raw pubkey, and the two are only incidentally
        // equal. (This comment used to justify the choice by claiming
        // `client_pk` is hardcoded [0;32] in the SDK — that has been false
        // since KI#46: `build_register_message` sets it to the wallet pubkey
        // and signs `client_sig` over the state payload, which step 5a' above
        // now verifies. Keying stays on `wallet_id` for the reason given.)
        // The mesh-wide broadcast happens in the node handler (the writer
        // floods GossipMessage::Hibernation so the cheque-claim's pick-set
        // nodes — not just this writer — also learn the lock).
        //
        // HIBERNATION_WINDOW is a TICK count. `current_tick` is the tick's unix
        // stamp, which advances ≤ TICK_INTERVAL_SECS per tick. To project the
        // stamp WINDOW ticks ahead we use the max-per-tick estimate
        // (`WINDOW * TICK_INTERVAL_SECS`): real ticks may arrive faster, so the
        // actual tick is never beyond this stamp — the lock is guaranteed to
        // hold for at least WINDOW ticks. Mirrors `AIRDROP_CYCLE_SECS`.
        smt.set_hibernation(reg.wallet_id, hib_until);
        hibernation_until = Some(hib_until);

        // ── 8a'. YPX-022 §2.2.1 COMMIT — the same lock event as the
        // hibernation stamp flips this wallet's recall reservation(s) to the
        // Committed terminal: from here `C` is dead (point of no return).
        // WAL-first per terminal (a crash must never resurrect a recalled
        // cheque); the node handler garbage-inserts + floods each.
        if reg.is_recall {
            for (txid, reservation_tick) in smt.commit_recalls_for(&reg.wallet_id) {
                wal.append(&WalOp::TxRecalled {
                    tx_hash: txid,
                    sender_pk: reg.wallet_id.to_vec(),
                    recall_tick: reservation_tick,
                })
                .map_err(|e| NablaError::WalError(e.to_string()))?;
                committed_recalls.push((txid, reservation_tick));
            }
        }
    } else if smt.hibernation_until(&reg.wallet_id) != 0 {
        // YPX-020 §2: a hibernating wallet registering a NON-re-anchor advance has
        // completed (or moved past) HAL — its Core wallet-state lock is cleared by
        // the self-redeem (`execute_cl5`). Drop the informational Nabla entry and
        // gossip the clear (`until = 0`) so the mesh converges. The entry no longer
        // gates claims (§2 removed that gate), so an eager clear here is harmless;
        // Core's send-gate on the wallet state remains the authoritative lock.
        smt.clear_hibernation(&reg.wallet_id);
        hibernation_until = Some(0);
    }

    // ── 8b. YP §19.6 fee ledger — persist per-tx fee_breakdown ──
    //
    // Only hashmap-mode nodes hold authoritative per-tx records; bloom-mode
    // (light) nodes pay no storage cost. Order matters: WAL first (durable),
    // then in-memory record. Mirrors AXIOM Origin's "hashmap = correct info, WAL
    // = fast access" tiering. Step 4's gossip path (other hashmap nodes
    // hearing the StateUpdate below) calls record_tx_meta in-memory only;
    // this is THE producer site where WAL append lands.
    if !reg.receipt.fee_breakdown.is_empty()
        && smt.txid_mode() == crate::bloom::TxidServiceMode::Hashmap
    {
        let record = crate::types::TxRecord {
            receiver_wallet_id: reg.wallet_id,
            amount: reg.receipt.amount,
            fee_breakdown: reg.receipt.fee_breakdown.clone(),
            tick: current_tick,
        };
        let record_bytes = bincode::serialize(&record)
            .map_err(|e| NablaError::SerializationError(e.to_string()))?;
        wal.append(&WalOp::RecordTx {
            tx_hash: reg.tx_hash,
            record: record_bytes,
        })
        .map_err(|e| NablaError::WalError(e.to_string()))?;
        smt.record_tx_meta(reg.tx_hash, record);
    }

    // ── 8b'. YPX-022 §2.1 — mark this k-witnessed completion so a later RECALL of
    // `reg.tx_hash` is refused (it is now redeemable). Mode-INDEPENDENT (unlike the
    // Hashmap-gated fee ledger above). A sub-quorum (k<3) round never reaches
    // this point (step 5/5b′ refuse it; the KI#5 partial_bridge that once
    // recorded such a txid was RETIRED 2026-10-02), so its txid is never marked
    // completed and stays recallable. Reaching this point means the
    // registration verified + advanced.
    // WAL first (durable — §5: the recall eligibility base survives a crash),
    // then in-memory, mirroring 8b.
    wal.append(&WalOp::TxCompleted { tx_hash: reg.tx_hash, tick: current_tick })
        .map_err(|e| NablaError::WalError(e.to_string()))?;
    smt.mark_txid_completed(&reg.tx_hash, current_tick);

    // ── 8b'. YPX-001 §1.5.1a — a BURN register resolves its TARGET txid.
    // Reaching this point means the burn's registration verified (k=3
    // receipt) + advanced, so the origin wallet provably destroyed the
    // tainted amount. Record the TARGET as resolved-by-burn; query-txid
    // serves it "BURNED" so downstream inherited scars can clear via the
    // standard client-carried attestation. WAL first (durable), then
    // in-memory. v1 scope: recorded at the register-receiving writer
    // (single-attester trust, identical to every other txid attestation);
    // mesh gossip convergence is a follow-up — the SDK's resolution sweep
    // rotates Nablas so a local-only marker is still discoverable.
    if let Some(target) = reg.burn_target_tx_id {
        wal.append(&WalOp::TxBurnResolved { target_tx_hash: target })
            .map_err(|e| NablaError::WalError(e.to_string()))?;
        smt.mark_txid_burn_resolved(&target);
    }

    // ── 8b''. YPX-022 §2 (2026-07-07 repurpose) — a REDEEM finalize marks the cheque's
    // txid REDEEMED: the permanent consume terminal (symmetric with the recall marker).
    // Detected by the receiver-pays signal (`fee_breakdown` non-empty = "receiver's
    // /register after redeem", §8b); a plain send never carries it. Mode-INDEPENDENT.
    // A redeem's `reg.tx_hash` == the cheque's send-txid (redeem.rs), the same `T` the
    // RECALL gate reads — so this outlives the transient §4.6 cheque-claim and lets a
    // recall (window 18,000+) see "already redeemed" cleanly. first-wins vs a recall.
    if !reg.receipt.fee_breakdown.is_empty() && !reg.is_genesis_claim {
        // WAL first (durable — §5: a crash must never forget that a cheque was
        // consumed; a recall of a redeemed txid refuses forever), then in-memory.
        // Genesis funds are EXCLUDED: they carry claim fees but are the SEND
        // side of the claim's self-redeem — marking them here would make the
        // genesis self-redeem read its own txid as already-redeemed.
        wal.append(&WalOp::TxRedeemed { tx_hash: reg.tx_hash })
            .map_err(|e| NablaError::WalError(e.to_string()))?;
        smt.mark_txid_redeemed(&reg.tx_hash);
        // ONE txid domain (2026-07-07): the YPX-014 txid service ("was this
        // txid REDEEMED?") is fed HERE — at redeem-finalize with the cheque's
        // protocol txid — not by put() on every registration (that pollution
        // served REDEEMED for merely-sent txids the moment tx_hash became the
        // protocol txid).
        smt.record_txid(&reg.tx_hash, &reg.wallet_id, current_tick);
    }

    // YPX-010 §14 — the registered send txid is recorded by `Smt::put`, which
    // this path already reaches. Recording it here as well would be a second
    // site for the same fact, and the local-only version is precisely the bug
    // the §14 gate caught: it made readiness node-local. `put` is also on the
    // replication path, so every node learns it.

    // ── 8c. YP §20.8 / §20.11 — DEED pool credit + per-validator NET ──
    //
    // Receiver-pays model: when fee_breakdown is non-empty (receiver's
    // /register after redeem), `axiom_core_logic::validation::compute_deed_split`
    // returns (deed_atoms, net_per_slot) — 10% of the aggregate fee
    // floored to DEED, the remainder split proportionally across the
    // witnessing validators with a deterministic BLAKE3-seeded
    // distribution of the atom-granular remainder. After the 10-year
    // cutoff anchored at GENESIS_NEWS_ANCHOR, deed_atoms = 0 and
    // validators keep the full slot.
    //
    // Gated on fee_breakdown non-empty so sender's /register (no fees)
    // is byte-identical to today's behaviour. Credit only happens ONCE
    // per (wallet, tx_hash) — the idempotent-retry short-circuit at
    // line ~370 returns before reaching this block on retries, and
    // record_tx_meta dedup at the SMT means a re-gossiped register
    // never reaches here twice either.
    //
    // See docs/AXIOM_DESIGN_DeedDistribution.md §4 for the algorithm.
    // Derive fee_breakdown from the k K3WitnessSigs locally. Each
    // WitnessSig carries its validator's self-attested
    // (validator_id, slot_amount); Nabla walks them to build the
    // breakdown for this register. The SDK never reads or writes a
    // fee field — its only job is to forward the witnesses the
    // Lambdas signed. If receipt.fee_breakdown is already populated
    // (legacy SDKs), use that as-is; if it's empty AND the
    // signatures carry slot_amount, derive.
    let derived_fee_breakdown: Vec<axiom_core_logic::types::FeeShare> =
        if !reg.receipt.fee_breakdown.is_empty() {
            reg.receipt.fee_breakdown.clone()
        } else {
            reg.receipt.signatures.iter()
                .filter(|ws| ws.slot_amount > 0)
                .map(|ws| axiom_core_logic::types::FeeShare {
                    validator_id: ws.validator_id,
                    amount: ws.slot_amount,
                })
                .collect()
        };

    // DIAG (2026-06-05 PM-4): Mac reported dev TX didn't credit Dev DEED.
    // Lambda confirms is_dev_class=true at CL5 attest, but Nabla pool
    // stayed at 0. Print exactly what reaches this site so we can tell
    // whether (a) the SDK shipped K3Receipt.is_dev_class=false, (b)
    // fee_breakdown is empty (no routing block), or (c) routing fires
    // but the dev branch doesn't.
    log::debug!(
        "[DEED-DIAG] wallet={} tx_hash={} is_dev_class={} \
         claimant={:?} sigs={} fb.empty={} derived.len={} sigs_with_slot={}",
        hex::encode(&reg.wallet_id[..8]),
        hex::encode(&reg.tx_hash[..8]),
        reg.receipt.is_dev_class,
        reg.claimant_wallet_id,
        reg.receipt.signatures.len(),
        reg.receipt.fee_breakdown.is_empty(),
        derived_fee_breakdown.len(),
        reg.receipt.signatures.iter().filter(|ws| ws.slot_amount > 0).count(),
    );

    let mut held_fee_credit: Option<(TxHash, FeeCredit)> = None;
    if !derived_fee_breakdown.is_empty() {
        let split = axiom_core_logic::validation::compute_deed_split(
            &derived_fee_breakdown,
            &reg.tx_hash,
            current_tick,
            axiom_core_logic::genesis_integrity::GENESIS_NEWS_ANCHOR,
        );

        // ═══════════════════════════════════════════════════════════
        // DEV-CLASS LEAK BOUNDARY
        // ═══════════════════════════════════════════════════════════
        //
        // `reg.receipt.is_dev_class` was attested by Core CL3/CL5
        // from `tx.sender_wallet_id` and bound into
        // `receipt_commitment` (k=3 sigs already verified above at
        // line ~281). A forged flag is structurally impossible to
        // reach this point — the sig verify would have failed.
        //
        // BRANCH IS MUTUALLY EXCLUSIVE. Dev fees NEVER touch
        // `deed_pool` / `validator_net_ledger`. Public fees NEVER
        // touch `dev_deed_pool` / `validator_dev_net_ledger`.
        // The newtype wrappers on the dev variants make a
        // cross-credit (passing dev pool where public is expected,
        // or vice versa) a compile error.
        //
        // Withdrawal mint (`lambda::validator_withdrawal`) reads
        // which ledger the entry came from and gates mint type:
        // public-NET → mints public AXC; dev-NET → mints dev-AXC.
        // The boundary is enforced THREE TIMES:
        //   1. Core CL3/CL5 attests `is_dev_class` (this PR)
        //   2. Nabla routes by it HERE (this PR)
        //   3. Withdrawal mint gate reads source pool (this PR)
        // Any one alone closes the leak; the three together make a
        // leak structurally impossible.
        if !reg.receipt.is_dev_class {
            // ── DEFENSIVE PRE-WRITE GATE (2026-06-05 PM-3) ──────────
            //
            // AXIOM Origin's mandate: "before write to validator's fees and
            // to the DEED pool, verify AGAIN, defensive in depth, the
            // write is NOT from dev account."
            //
            // Even though `is_dev_class=false` already passed the
            // receipt_commitment_sig verify (k Lambdas signed it),
            // Nabla cross-checks the claimant's wallet_id string here
            // before any public-pool write. If the wallet ID resolves
            // to `@axiom.internal` but the routed-by flag says public,
            // SOMETHING is wrong: either a Lambda bug, a forged
            // claimant_wallet_id, or a missing layer above. Reject
            // loudly — the leak is the worst-case outcome.
            //
            // Layer 4-bis. Decisions:
            //   - Layer 3 (Core CL3/CL5) attests `is_dev_class` from
            //     `sender_wallet_id` and binds into receipt_commitment.
            //   - Layer 4 (commitment verify above) ensures the SDK
            //     can't ship a tampered flag.
            //   - Layer 4-bis (THIS check) ensures even a logic bug
            //     above can't write dev-claimant fees to public pools.
            //   - Layer 5 (withdrawal mint query) is type-isolated
            //     against dev-NET.
            if axiom_core_logic::wallet_id::is_dev_wallet(&reg.claimant_wallet_id) {
                log::error!(
                    "[LEAK-DEFENSE] receipt.is_dev_class=false but claimant_wallet_id \
                     is @axiom.internal (tx_hash={}) — rejecting register to prevent \
                     dev fees leaking into public pools. See \
                     AXIOM_DESIGN_FactClassIsolation.md.",
                    hex::encode(&reg.tx_hash[..8]),
                );
                return Err(NablaError::InvalidReceipt);
            }
        }
        let credit = FeeCredit {
            tx_hash: reg.tx_hash,
            is_dev_class: reg.receipt.is_dev_class,
            slots: derived_fee_breakdown.iter()
                .zip(split.net_per_slot.iter())
                .map(|(slot, net)| (slot.validator_id, *net))
                .collect(),
            deed_atoms: split.deed_atoms,
            hashmap_mode: smt.txid_mode() == crate::bloom::TxidServiceMode::Hashmap,
        };
        // ── ForkSettlement §9r (F-6 path 11, owner ruling 2026-10-02) ──
        // A REDEEM's fees are paid out of the cheque it redeems. A held
        // (fork-descended) redeem is still ACCEPTED (ruling 1), but its fee
        // slots / DEED slice must not be credited — and so never minted clean
        // by `ValidatorWithdrawalMint` — while that money is held or waiting in
        // THIS node's provenance. The verdict is the node's (`NablaNode::
        // register`), not this pure door's: hand the credit back, parked; it is
        // credited ONCE when the cheque judges `Ok`, never if it stays held.
        // Every other fee'd register credits here, unchanged.
        if let axiom_core_logic::nabla_wire::LegPreimage::Redeem { redeem, .. } = &reg.preimage {
            log::info!(
                "[FEE-CREDIT-HELD] redeem tx_hash={} cheque={} deed={} slots={} — \
                 parked until the cheque's provenance is Ok (§9r F-6 path 11)",
                hex::encode(&reg.tx_hash[..8]), hex::encode(&redeem.cheque_txid[..8]),
                credit.deed_atoms, credit.slots.len(),
            );
            held_fee_credit = Some((redeem.cheque_txid, credit));
        } else {
            apply_fee_credit(
                &credit, current_tick,
                deed_pool, validator_net_ledger, dev_deed_pool, validator_dev_net_ledger,
            );
        }
    }

    // ── 9. Process DEED payment ──
    *deed_collected += deed_tx.amount;

    // ── 10. Build gossip message ──
    // YP §19.6 — populate amount + fee_breakdown from the verified receipt
    // so peer hashmap nodes can rebuild their txid_records from the flood
    // (Step 4's apply_fee_record_from_gossip is the consumer).
    //
    // ── HAL re-anchors flood as a plain StateUpdate (Fork Settlement §9q, design
    //    B2, owner ruling 2026-09-30 "fix it with ATRAXI") ──
    // HISTORY (RULE 0 §4). A HAL re-anchor used to gossip as
    // `GossipMessage::HalAdvance` (old_state + the step-5 k3 sigs, NO SeqProof),
    // whose receiver arm froze W (YPX-025 E3, KI#34 check-3) when the held head
    // differed and `previous_states[W] == old_state`. Three defects, all measured
    // (`fork_detection_mesh::b2_*`, §9q):
    //   (1) GHOST: the arm verified the k3 sigs over
    //       `receipt_sign_payload(W, X, tick)` with THIS door's `current_tick`,
    //       but Lambda signs that payload with tick 0 — so a GENUINE door-emitted
    //       revival never verified and never froze anyone (0/4 holders frozen;
    //       4/4 with the tick aligned — the E3 probe, §9q);
    //   (2) `previous_states[W]` is the head this node's last put OVERWROTE (a
    //       VIEW, KI#235), not evidence — an honest HAL chain learned by a jump
    //       satisfied it;
    //   (3) no leg rode the flood, so every receiver adopted the head without a
    //       record (§9m B: born contested) and the fork could only be judged on
    //       that view.
    // NOW a HAL re-anchor is an ordinary A1 leg (a self-send `LegPreimage::Send`
    // from X, k-witnessed, wallet-signed; recorded at 5b‴ above): it floods with
    // its SeqProof like every other register, every receiver runs the ONE flood
    // record hook BEFORE any put ([R24]), and a revival X→X′ beside a recorded
    // X→Y is a `ForkClaim` under (pk, X) → `ban::apply_fork_verdict` (permanent
    // ban on evidence; the forked head is never adopted). Where the two legs
    // never meet by flood, R48 record-AE brings them together. No wire change:
    // `HalAdvance` is a received-dropped-counted tombstone (`haladvance_dropped`).
    let gossip_msg = GossipMessage::StateUpdate {
        wallet_id: bucket,
        new_state: reg.new_state,
        // The consumed parent (unsigned; `verify_seq_proof_leg` checks it
        // against the k-signed preimage). It fed check-3's
        // `previous_states` comparison until W2 (§9o [R56]).
        old_state: reg.old_state,
        tx_hash: reg.tx_hash,
        tick: current_tick,
        is_genesis_claim: reg.is_genesis_claim,
        wallet_seq: reg.receipt.new_wallet_seq, // WI3: k-attested seq from receipt
        client_pk: reg.client_pk,
        client_sig: reg.client_sig.clone(),
        amount: reg.receipt.amount,
        fee_breakdown: reg.receipt.fee_breakdown.clone(),
        // WI3 hole-1: carry the k=3 attestation of `new_wallet_seq` so peers
        // can verify the seq before adopting it (registration already verified
        // it at §5b). `None` when the receipt has no commitment sigs.
        seq_proof: crate::types::SeqProof::from_registration(reg),
    };

    // ── 11. Build signed acknowledgment ──
    //
    // FACT confirmation signature — single shared function (crypto.rs).
    // Core verifies this in CL2 FACT chain validation.
    let confirm_payload = crate::crypto::fact_confirm_payload(
        &reg.old_state, &reg.new_state, current_tick,
    );
    let fact_confirm_signature = signer.sign(&confirm_payload);

    let mut ack = RegistrationAck {
        wallet_id: reg.wallet_id,
        new_state: reg.new_state,
        tick: current_tick,
        root_hash: new_root,
        signature: vec![], // filled below
        node_pk: vec![],   // populated at dispatch layer
        node_id: vec![],   // populated at dispatch layer (BLAKE3 of SPHINCS+ key)
        known_peers: vec![], // populated at dispatch layer
        zkp_verified,
        cheque_status: ChequeStatus::Scarred, // overridden at dispatch layer via check_maturity()
        fact_confirm_signature,
        ..Default::default()
    };
    ack.signature = signer.sign(&crypto::ack_sign_payload(&ack));

    Ok(RegistrationResult { ack, gossip_msg, hibernation_until, committed_recalls, held_fee_credit })
}

// ── Group Wallet Registration (Phase 3, Section 8) ──
//
// Group wallet validation rules (share_bps sum, member_pk, checksums)
// are enforced by Core, not Nabla. Nabla records the result.
// The only check Nabla performs is the checksum: sum(available) == balance.
// This is a structural integrity check, not a business rule.

/// Process a group wallet registration.
///
/// Same flow as personal registration, but:
///   - Records member allocations in NablaEntry
///   - Emits GroupUpdate gossip instead of StateUpdate
///   - Verifies checksum: sum(available) == balance
#[allow(clippy::too_many_arguments)]
pub fn process_group_registration(
    smt: &mut SparseMerkleTree,
    wal: &mut WriteAheadLog,
    bans: &mut BanTable,
    greg: &GroupRegistration,
    deed_tx: &DeedTransaction,
    current_tick: u64,
    deed_collected: &mut u64,
    signer: &dyn Signer,
) -> Result<RegistrationResult, NablaError> {
    // ── 1. Check ban status (cheapest check, O(1)) ──
    if bans.is_banned(&greg.wallet_id) {
        return Err(NablaError::WalletBanned);
    }

    // ── 2. Check DEED destination ──
    if deed_tx.receiver_wallet_id != DEED_PROTOCOL_WALLET_ID
        && deed_tx.receiver_wallet_id != DEED_IMPLEMENTATION_WALLET_ID
    {
        return Err(NablaError::InvalidDeedDestination);
    }

    // ── 3. Check DEED amount ──
    if deed_tx.amount < DEED_WRITE_FEE {
        return Err(NablaError::InvalidDeedPayment);
    }

    // ── 4. Verify registration matches receipt ──
    if greg.old_state != greg.receipt.consumed_state_id {
        return Err(NablaError::StateMismatch);
    }
    if greg.new_state != greg.receipt.produced_state_id {
        return Err(NablaError::StateMismatch);
    }

    // ── 5. Verify the k receipt signatures via Core (Signer trait) ──
    // YP §17.3.1.4 v2.19.0 (KI#150): k is the group's tier, floor 3.
    if greg.receipt.signatures.len() < (greg.k_tier as usize).max(3) {
        return Err(NablaError::InvalidReceipt);
    }
    let receipt_tick = if greg.receipt.tick > 0 {
        if current_tick.saturating_sub(greg.receipt.tick) > 300 {
            return Err(NablaError::InvalidReceipt);
        }
        greg.receipt.tick
    } else {
        0 // Verify with tick=0 — Lambda signs with tick=0
    };
    let receipt_payload = crypto::receipt_sign_payload(
        &greg.wallet_id,
        &greg.receipt.consumed_state_id,
        receipt_tick,
    );
    for ws in &greg.receipt.signatures {
        if !signer.verify(&ws.validator_pk, &receipt_payload, &ws.signature) {
            return Err(NablaError::InvalidReceipt);
        }
    }

    // ── 5b. Verify execution proofs (ZKP/DMAP) ──
    // Pin to the node's canonical CoreID (see process_registration), not the
    // receipt's self-declared program_digest.
    let canonical = parse_canonical_core_id(axiom_core_logic::version::CANONICAL_CORE_ID);
    let zkp_verified = verify_zkp_proofs(&greg.receipt.signatures, &canonical, &greg.new_state)?;

    // ── 6. Verify group checksum: sum(available) == balance ──
    // This is structural integrity, not business logic.
    let sum_available: u64 = greg.members.iter().map(|m| m.available).sum();
    if sum_available != greg.balance {
        return Err(NablaError::GroupChecksumFailed);
    }

    // ── 6b. Verify share_bps sum to 10000 (100%) ──
    let total_bps: u64 = greg.members.iter().map(|m| m.share_bps as u64).sum();
    if total_bps != 10000 {
        return Err(NablaError::GroupChecksumFailed);
    }

    // ── 7. State check ──
    //
    // YPX-002 §3.3 — on local `current_state != old_state` mismatch, return an
    // error. NOT a ban. Identical to the personal path at §6; nothing in the
    // spec distinguishes group wallets here.
    //
    // RULE 0 marker (2026-08-07, ghost audit G3 — this was WRONG). This block
    // used to build a `ConflictProof` pair with `old_state: [0u8; 32]` and
    // `k3_signatures: Vec::new()`, WAL-persist it, and call `bans.ban()` —
    // permanently banning a group wallet (BanStatus has only `Active`) on
    // evidence that could never satisfy `verify_conflict`. It banned for the
    // exact condition §3.3 calls normal during gossip propagation: "a mismatch
    // at /register only proves that THIS node has not yet observed the
    // intermediate state".
    //
    // It was the YPX-002 false-ban bug the personal path's own comment warns
    // about — "any future code that tries to call `bans.ban()` from this call
    // site is a re-introduction" — pointing at a "P4.2 invariant assertion
    // enforced at `bans.ban()` itself" that did not exist. It does now
    // (`BanTable::conflict_is_well_formed`), so this is defended twice.
    //
    // A ban requires the §7.4/§7.5 proof-of-double-spend: two independently
    // valid k=3 registrations, same `old_state`, different `new_state`. That is
    // the gossip-merge path's job (`BanAlert` / `SeqForkBan`), not /register's.
    if let Some(existing) = smt.get(&greg.wallet_id) {
        if existing.current_state != greg.old_state {
            log::info!(
                "[GROUP-REGISTER] state mismatch for wallet={} (held={} offered={})                  — rejecting, NOT banning (YPX-002 §3.3)",
                hex::encode(&greg.wallet_id[..4]),
                hex::encode(&existing.current_state[..4]),
                hex::encode(&greg.old_state[..4]),
            );
            return Err(NablaError::StateMismatch);
        }
    }

    // ── 8. Write to WAL ──
    let new_entry = NablaEntry {
        wallet_id: greg.wallet_id,
        // WI3: k-witnessed seq from the group registration's receipt.
        wallet_seq: greg.receipt.new_wallet_seq,
        current_state: greg.new_state,
        tx_hash: greg.tx_hash,
        tick: current_tick,
        group_members: Some(greg.members.clone()),
        status: WalletStatus::Normal,
        client_pk: [0u8; 32], // group wallets: no single client sig (multi-party)
        client_sig: vec![0u8; 64],
        // §32.3 — a group redeem carries the same k-attested sender lineage.
        received_from: greg.receipt.sender_state,
    };

    let serialized = bincode::serialize(&new_entry)
        .map_err(|e| NablaError::SerializationError(e.to_string()))?;

    wal.append(&WalOp::Put {
        key: greg.wallet_id,
        value: serialized,
        client_pk: [0u8; 32],
        client_sig: vec![0u8; 64],
        // Group wallets carry `wallet_seq: 0` and their own GroupUpdate seq
        // wire; there is no per-head k=3 seq attestation to retain.
        seq_proof: None,
    }).map_err(|e| NablaError::WalError(e.to_string()))?;

    // ── 9. Update SMT ──
    let new_root = smt.put_with_proof(
        &new_entry,
        crate::smt::PutProof::ProoflessByDesign(crate::smt::ProoflessKind::GroupWallet),
    );

    // ── 10. Process DEED payment ──
    *deed_collected += deed_tx.amount;

    // ── 11. Build GroupUpdate gossip ──
    let gossip_msg = GossipMessage::GroupUpdate {
        wallet_id: greg.wallet_id,
        new_state: greg.new_state,
        tx_hash: greg.tx_hash,
        members: greg.members.clone(),
        tick: current_tick,
    };

    // ── 12. Build signed acknowledgment ──
    let fact_confirm_signature = {
        // Pattern 1 sweep — the group path used to assemble this itself, with
        // the OLD unversioned tag and WITHOUT `committed_at_tick`. Core
        // verifies the tick-bearing payload, so a group wallet's confirmation
        // could never verify here: same value, two preimages. It now uses the
        // one Core-owned builder, which is also what makes the tag collapse
        // safe — there is exactly one field set again.
        let payload = crate::registration::fact_confirm_payload(
            &greg.old_state, &greg.new_state, current_tick,
        );
        signer.sign(&payload)
    };

    let mut ack = RegistrationAck {
        wallet_id: greg.wallet_id,
        new_state: greg.new_state,
        tick: current_tick,
        root_hash: new_root,
        signature: vec![], // filled below
        node_pk: vec![],   // populated at dispatch layer
        node_id: vec![],   // populated at dispatch layer (BLAKE3 of SPHINCS+ key)
        known_peers: vec![], // populated at dispatch layer
        zkp_verified,
        cheque_status: ChequeStatus::Scarred, // overridden at dispatch layer via check_maturity()
        fact_confirm_signature,
        ..Default::default()
    };
    ack.signature = signer.sign(&crypto::ack_sign_payload(&ack));

    // Group registrations are not HAL re-anchors → no hibernation stamp.
    Ok(RegistrationResult { ack, gossip_msg, hibernation_until: None, committed_recalls: Vec::new(), held_fee_credit: None })
}

/// Verify execution proofs attached to witness signatures.
///
/// Supports both proof types:
/// - ZKP (proof_type=0): RISC Zero STARK verification
/// - DMAP (proof_type=1): Deterministic Memory Attestation verification
///
/// Returns `true` if proofs were present and verified,
/// `false` if no proofs were present (bootstrap/legacy).
///
/// Checks (ZKP):
///   1. STARK proof cryptographically valid (RISC Zero verify)
///   2. Program digest matches expected IMAGE_ID
///   3. Core logic result == Accept
///   4. produced_state_id matches registration's new_state
///
/// Checks (DMAP):
///   1. CoreID matches expected (BLAKE3 of canonical ELF)
///   2. Challenge indices correctly derived (Fiat-Shamir)
///   3. Merkle proofs valid against checkpoint commitment
///   4. Input/output hashes match
/// The node's canonical CoreID (BLAKE3 of the deployed ELF), welded at build via
/// `AXIOM_CANONICAL_CORE_ID` (`axiom_core_logic::version::CANONICAL_CORE_ID`).
///
/// This is what registration MUST pin incoming DMAP attestations against — NOT
/// the receipt's self-declared `program_digest`. Empty (unpinned dev/source
/// build) → `[0;32]`, which the DMAP path treats as bootstrap (no enforcement),
/// matching the startup ELF-pin (`nabla_node.rs`), which is also a no-op when
/// empty. A non-empty value is already validated at startup (loaded ELF's BLAKE3
/// must equal it, or the process exits), so it parses cleanly here.
fn parse_canonical_core_id(hex_str: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if hex_str.is_empty() {
        return out;
    }
    if let Ok(b) = hex::decode(hex_str) {
        if b.len() == 32 {
            out.copy_from_slice(&b);
        }
    }
    out
}

/// §10.0 FOB fee-claim — build the Ed25519-signed, NBC-anchored
/// `FobClaimAttestation` this node serves to the stake wallet before its claim
/// tx. Same trust chain as `build_oods_attestation` below (node Ed25519 sig
/// over the canonical payload + own-NBC anchor bundle). The CALLER supplies
/// pool facts (amount = the FULL pool balance, linked wallet from the
/// registered linkage) — this fn only binds + signs them.
pub fn build_fob_claim_attestation(
    own_nbc_bytes: &[u8],
    pool: u8,
    validator_id: [u8; 32],
    is_dev: bool,
    amount: u64,
    linked_wallet_id: &str,
    claim_tick: u64,
    epoch: u64,
    signer: &dyn crate::crypto::Signer,
) -> Option<axiom_core_logic::types::FobClaimAttestation> {
    let own_nbc = crate::cc::deserialize_nbc(own_nbc_bytes).ok()?;
    let payload = axiom_core_logic::compute::compute_fob_claim_attestation_payload(
        pool, &validator_id, is_dev, amount, linked_wallet_id, claim_tick, epoch,
    );
    let nabla_signature = signer.sign(&payload);
    let nabla_node_pk: [u8; 32] = signer.public_key().as_slice().try_into().ok()?;
    Some(axiom_core_logic::types::FobClaimAttestation {
        pool,
        validator_id,
        is_dev,
        amount,
        linked_wallet_id: linked_wallet_id.to_string(),
        claim_tick,
        epoch,
        nabla_node_pk,
        nabla_signature,
        nbc_issuer_pk: own_nbc.issuer_set.first().cloned().unwrap_or_default(),
        nbc_signature: own_nbc.signatures.first().cloned().unwrap_or_default(),
        nbc_commitment: axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&own_nbc),
    })
}


/// The ONE count of distinct validators whose `receipt_commitment_sig`
/// verifies over the commitment recomputed from `proof` + (`txid`,
/// `wallet_seq`). Both receipt-commitment verifiers in this crate call it —
/// `verify_seq_proof` (≥ quorum; flood / AE / KI#68 adopt / door step 5b′) and
/// `verify_receipt_commitment_sigs` (EVERY slot; the fee path and the
/// recall/HAL class check). ForkSettlement §2.3 [R17] named those two "two
/// verifiers of one fact" (RULE 1): until 2026-09-28 the second hand-rolled its
/// own `ed25519_dalek` loop; now both differ only in the THRESHOLD they apply.
///
/// RULE 1 (2026-08-09): the recompute + count-distinct-valid-sigs logic is the
/// ONE Core-owned `crypto::count_distinct_receipt_witness_sigs`, shared with
/// Core's `validate_witnesses`. No CoreID impact (Nabla links core-logic
/// natively).
///
/// ⚠ RULE 0 §4 marker (KI#224, owner ruling 2026-10-02). WRONG READING: "≥ k
/// distinct valid sigs here ⇒ k validators witnessed this head". RIGHT
/// READING: this counts sigs that verify under the keys the proof CARRIES —
/// three self-made keys pass it. Carried keys alone are not validators: a head
/// counts as witnessed only when ALSO every key is an R42 directory witness
/// (`ban::seq_proof_is_directory_witnessed`), checked on all three head-intake
/// paths (door 5b⁗, flood, head-AE). Ban evidence (`verify_fork_leg`) stays on
/// this count alone — R58. ForkSettlement §9r KI#224.
fn count_valid_commitment_sigs(proof: &SeqProof, txid: &TxHash, wallet_seq: u64) -> usize {
    axiom_core_logic::compute::count_distinct_receipt_witness_sigs(
        txid,
        &proof.state_hash,
        wallet_seq,
        &proof.commitment_hash,
        proof.epoch,
        proof.is_dev_class,
        proof.oods_flag.as_ref(),
        proof.confidence_index.as_ref(),
        proof.sender_state.as_ref(),
        proof
            .sigs
            .iter()
            .map(|s| (s.validator_pk.as_slice(), s.receipt_commitment_sig.as_slice())),
    )
}

/// YP §17.3.1.4 v2.19.0 (KI#150): a proof's quorum is its own k, floor 3.
fn seq_proof_quorum(proof: &SeqProof) -> usize {
    (proof.required_k as usize).max(axiom_core_logic::fact::MIN_FACT_WITNESSES)
}

// ── ForkSettlement wave 2a — the carried leg (§2.2, §2.3 [R17], [R‑MEDIUM-3]) ──

/// Why a carried leg (`Registration::preimage` / `SeqProof::preimage`) was
/// refused. Every variant is a distinct check; the variant rides the door's
/// wire reason (`E_NABLA_LEG_UNVERIFIABLE|reason=…`) and every log line, so a
/// refusal names WHICH binding broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegRefusal {
    /// `preimage.client_pk` ≠ the registrant's / entry's `client_pk` — the
    /// identity the fork verdict bans (§2.2 step 4) must be the key that
    /// authored the state.
    ClientPkMismatch,
    /// [R‑MEDIUM-3] the message's `old_state` (UNSIGNED) ≠
    /// `preimage.consumed_state_id` (bound into the k-signed commitment).
    ConsumedStateMismatch,
    /// `preimage.wallet_seq` ≠ the k-signed `new_wallet_seq` the proof attests
    /// (Core stamps `new_wallet_seq = tx.wallet_seq` on every send, CL3).
    WalletSeqMismatch,
    /// `preimage.commitment_hash()` ≠ the carried `commitment_hash`.
    CommitmentHashMismatch,
    /// `preimage.txid(epoch)` ≠ the registered/entry `tx_hash`.
    TxidMismatch,
    /// Fork Settlement W7a/W7b (spec R52c) — a `Redeem` leg's `new_state_id` ≠
    /// the message's produced state (the redeem commitment binds it).
    NewStateMismatch,
    /// Fork Settlement W7a/W7b (spec R52c) — the carried `RedeemPreimage` does
    /// not recompute, through Core's ONE verifier
    /// `validation::redeem_preimage_matches`, to the k-signed `commitment_hash`.
    RedeemPreimageMismatch,
    /// KI#241 F-2 (Fable review 2026-10-01) — a `Redeem` leg's carried cheque
    /// origin is not this cheque's: `kind != Send` or
    /// `cheque.preimage.txid(cheque.epoch) != cheque_txid` (Core's ONE
    /// predicate `nabla_wire::cheque_origin_matches`). Its amount is what the
    /// provenance burn exit (M4) reads, so a forged origin must never be
    /// recorded. Counted under `leg_preimage_refused`.
    ChequeOriginMismatch,
    /// Fewer than max(k_tier, 3) distinct valid `receipt_commitment_sig`s over
    /// the receipt commitment (door step 5b′ only — the flood / AE paths gate
    /// seq adoption on the same count via `verify_seq_proof`).
    WitnessSigsBelowQuorum,
}

impl core::fmt::Display for LegRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            LegRefusal::ClientPkMismatch => "client_pk",
            LegRefusal::ConsumedStateMismatch => "old_state_vs_preimage_consumed",
            LegRefusal::WalletSeqMismatch => "wallet_seq",
            LegRefusal::CommitmentHashMismatch => "commitment_hash",
            LegRefusal::TxidMismatch => "txid",
            LegRefusal::WitnessSigsBelowQuorum => "witness_sigs_below_quorum",
            LegRefusal::NewStateMismatch => "new_state_vs_redeem_preimage",
            LegRefusal::RedeemPreimageMismatch => "redeem_preimage_recompute",
            LegRefusal::ChequeOriginMismatch => "cheque_origin_vs_cheque_txid",
        };
        f.write_str(s)
    }
}

/// THE leg verifier — door (step 5b′), flood (`gossip::apply_state_update`) and
/// anti-entropy (`node::apply_remote_entry`) all call this ONE function (RULE 1)
/// with the values they hold. Pure; 2 BLAKE3 for a `Send` leg, 1 for a
/// `Redeem` leg.
///
/// `old_state`: the message's parent when it carries one (door: `reg.old_state`;
/// flood: the StateUpdate's `old_state`); `None` when the carrier has no parent
/// field (AE `NablaEntry`) or it is the all-zero "unknown" of a replay
/// reconstruction — callers pass `None` for those, never a zero array.
///
/// ~~A `Redeem` leg is accepted UNVERIFIED~~ — true until Fork Settlement W7a
/// (`54a44d23`): the `Redeem` variant now CARRIES its `RedeemPreimage` (the five
/// `compute_redeem_commitment` inputs, [R8] Part B bound `consumed_state_id`),
/// so a redeem leg is SELF-PROVING like a send leg. Its arm checks the
/// preimage against the carrier's UNSIGNED fields — `receiver_pk == client_pk`,
/// `cheque_txid == tx_hash` (a redeem registers under the CHEQUE txid),
/// `consumed_state_id == old_state` and `new_state_id == new_state` when the
/// carrier states them — then recomputes through Core's ONE verifier
/// `validation::redeem_preimage_matches` (1 BLAKE3). There is no `wallet_seq`
/// in a redeem preimage; the seq is bound by the receipt commitment the
/// witness-sig check (`verify_seq_proof`) verifies. A verified redeem leg
/// creates NO origin record (R5/R33): since W7b it is recorded in the SEPARATE
/// redeem ledger (`record_verified_leg`, spec R52c), never read as an origin.
///
/// `new_state`: the carrier's produced state (door `reg.new_state`, flood
/// `new_state`, AE `current_state`); `None` where the caller has none (the
/// fork-claim path, which is send-only). Unused by the `Send` arm (a send
/// preimage does not bind the produced state).
#[allow(clippy::too_many_arguments)]
pub fn verify_leg_preimage(
    leg: &LegPreimage,
    commitment_hash: &[u8; 32],
    epoch: u64,
    tx_hash: &TxHash,
    client_pk: &[u8; 32],
    old_state: Option<&StateId>,
    new_state: Option<&StateId>,
    wallet_seq: u64,
) -> Result<(), LegRefusal> {
    let p = match leg {
        LegPreimage::Send(p) => p,
        LegPreimage::Redeem { redeem, cheque } => {
            return verify_redeem_leg_preimage(redeem, cheque, commitment_hash, tx_hash, client_pk, old_state, new_state)
        }
    };
    if &p.client_pk != client_pk {
        return Err(LegRefusal::ClientPkMismatch);
    }
    if let Some(o) = old_state {
        if &p.consumed_state_id != o {
            return Err(LegRefusal::ConsumedStateMismatch);
        }
    }
    if p.wallet_seq != wallet_seq {
        return Err(LegRefusal::WalletSeqMismatch);
    }
    if &p.commitment_hash() != commitment_hash {
        return Err(LegRefusal::CommitmentHashMismatch);
    }
    if &p.txid(epoch) != tx_hash {
        return Err(LegRefusal::TxidMismatch);
    }
    Ok(())
}

/// The `Redeem` arm of [`verify_leg_preimage`] — cheap equalities first, then
/// the ONE Core recompute, then (KI#241 F-2) the carried cheque origin bound
/// to the now k-bound `cheque_txid` by txid RECOMPUTATION (one BLAKE3). Runs
/// identically on the door, flood and AE paths (`verify_seq_proof_leg`), so
/// every node that records the redeem holds the same verified gross amount.
fn verify_redeem_leg_preimage(
    r: &axiom_core_logic::types::RedeemPreimage,
    cheque: &axiom_core_logic::types::OriginRecord,
    commitment_hash: &[u8; 32],
    tx_hash: &TxHash,
    client_pk: &[u8; 32],
    old_state: Option<&StateId>,
    new_state: Option<&StateId>,
) -> Result<(), LegRefusal> {
    if &r.receiver_pk != client_pk {
        return Err(LegRefusal::ClientPkMismatch);
    }
    if &r.cheque_txid != tx_hash {
        return Err(LegRefusal::TxidMismatch);
    }
    if let Some(o) = old_state {
        if &r.consumed_state_id != o {
            return Err(LegRefusal::ConsumedStateMismatch);
        }
    }
    if let Some(n) = new_state {
        if &r.new_state_id != n {
            return Err(LegRefusal::NewStateMismatch);
        }
    }
    if !axiom_core_logic::validation::redeem_preimage_matches(r, commitment_hash) {
        return Err(LegRefusal::RedeemPreimageMismatch);
    }
    if !axiom_core_logic::nabla_wire::cheque_origin_matches(cheque, &r.cheque_txid) {
        return Err(LegRefusal::ChequeOriginMismatch);
    }
    Ok(())
}

/// The same check over a carried `SeqProof` — the flood / AE form. The proof
/// holds the k-signed `commitment_hash` + `epoch` + the leg; the entry supplies
/// `tx_hash`, `client_pk`, `wallet_seq`, (flood only) the parent, and the
/// produced state.
pub fn verify_seq_proof_leg(
    proof: &SeqProof,
    tx_hash: &TxHash,
    client_pk: &[u8; 32],
    old_state: Option<&StateId>,
    new_state: Option<&StateId>,
    wallet_seq: u64,
) -> Result<(), LegRefusal> {
    verify_leg_preimage(
        &proof.preimage,
        &proof.commitment_hash,
        proof.epoch,
        tx_hash,
        client_pk,
        old_state,
        new_state,
        wallet_seq,
    )
}

/// RULE 3 §2 — refused legs (door 5b′ + flood + AE, cumulative). Surfaced on
/// `/status` as `leg_preimage_refused`; without it "0 refusals" and "the
/// check never ran" read identically.
static LEG_PREIMAGE_REFUSED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Count + log one refused leg. `via` names the path (`register` / `flood` /
/// `anti-entropy`).
pub fn note_leg_refused(reason: LegRefusal, wallet: &[u8; 32], tx_hash: &TxHash, via: &str) {
    LEG_PREIMAGE_REFUSED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    log::warn!(
        "[LEG-REFUSED] via={} reason={} wallet={} tx_hash={} — the carried leg does not \
         reproduce what the k validators signed; nothing stored (ForkSettlement R17 / R-MEDIUM-3)",
        via, reason, hex::encode(&wallet[..4]), hex::encode(&tx_hash[..4]),
    );
}

/// KI#251 / RULE 3 §2 — registrations whose DECLARED §15 state does not
/// reproduce the receipt's k-signed `state_hash` at the door's stake-lock
/// recompute (`verify_declared_state_and_stake_lock`), which passes them
/// (non-fatal this rotation). Surfaced on `/status` as
/// `declared_state_unanchored`. Expected ZERO from honest clients since the
/// claim send binds the unchanged balance (KI#251); one soak at zero is the
/// condition for promoting the recompute to a refusal.
static DECLARED_STATE_UNANCHORED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// `/status declared_state_unanchored` (KI#251).
pub fn declared_state_unanchored_total() -> u64 {
    DECLARED_STATE_UNANCHORED.load(core::sync::atomic::Ordering::Relaxed)
}

/// KI#224 / RULE 3 §2 — heads refused because a witness key is not in this
/// node's R42 directory: register door 5b⁗ + StateUpdate flood + head-AE,
/// cumulative. Surfaced on `/status` as `witness_not_in_directory_refused`.
/// Non-zero on a node whose directory is still filling is EXPECTED (the head
/// is re-offered); sustained growth on a full directory is junk-witness
/// traffic being stopped.
static WITNESS_NOT_IN_DIRECTORY_REFUSED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Count + log one KI#224 refusal. `via` names the path (`register` /
/// `flood` / `anti-entropy`); `unknown` is the first non-directory key.
pub fn note_witness_not_in_directory(unknown: &[u8; 32], wallet: &[u8; 32], tx_hash: &TxHash, via: &str) {
    WITNESS_NOT_IN_DIRECTORY_REFUSED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    log::info!(
        "[KI#224] via={} witness={} wallet={} tx_hash={} — witness key not in this node's \
         R42 directory; head not adopted (retryable: re-offered once the key is admitted)",
        via, hex::encode(&unknown[..4]), hex::encode(&wallet[..4]), hex::encode(&tx_hash[..4]),
    );
}

/// `/status witness_not_in_directory_refused` (KI#224).
pub fn witness_not_in_directory_refused_total() -> u64 {
    WITNESS_NOT_IN_DIRECTORY_REFUSED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Fork Settlement W7b (spec R52d) — the send-leg half of
/// `ban::leg_is_state_bound`: `declared.wallet_seq == preimage.wallet_seq` and
/// Core's ONE builder `compute_produced_state_id(pk, balance, seq, consumed,
/// nonce)` (the formula `validation.rs` uses for a send's produced state)
/// reproduces `new_state`. Lives HERE because it touches a core-logic
/// primitive and this file is the crypto-boundary hot-path carve-out
/// (`cc::tests::no_direct_core_crypto_in_production_code`).
///
/// **The balance is `declared.balance`, for every leg** — the one input the
/// recompute does not take from the k-signed preimage (see `DeclaredState`):
/// ANY balance that reproduces `new_state` IS that state's balance; the
/// equality is the binding, not the number carried.
///
/// ~~"from the OPENING state, also the GENESIS-CLAIM CREDIT (`balance +
/// amount`)"~~ — RULE 0 marker (6349d56c, design §9m A1, 2026-09-29): that
/// second candidate existed because Core's `compute_post_tx_balance` credited a
/// genesis claim at the SEND, so a claim registered with the SDK's declared 0
/// never bound. The credit at the send was itself the defect (KI#251,
/// 2026-10-02; YP §17.11.2 step 3: the claim's send leaves the balance
/// unchanged, the pool funds it at the redeem). Core now binds the UNCHANGED
/// balance, a claim's declared 0 reproduces `new_state` directly, and the arm
/// (with `genesis_claim_credited_balance`) is DELETED — no backward compat: the
/// trustmesh wipe removes the only records it served.
/// (The k-signed `SeqProof.state_hash` is not consulted: it needs the full §15
/// tuple the leg does not carry — the stated R52d deviation on `DeclaredState`.)
pub fn send_leg_produced_state_matches(
    p: &axiom_core_logic::types::WitnessPreimage,
    declared: &DeclaredState,
    new_state: &StateId,
) -> bool {
    declared.wallet_seq == p.wallet_seq
        && axiom_core_logic::compute::compute_produced_state_id(
            &p.client_pk, declared.balance, p.wallet_seq, &p.consumed_state_id, p.nonce,
        ) == *new_state
}

/// KI#226 — does `bucket` DERIVE from `client_pk`? True iff it is
/// `smt_bucket(client_pk, k)` for one of the two state classes (`K_DEFAULT` —
/// every online tier shares the identity bucket — or `K_ARK`), i.e. the row
/// belongs to the key that signs. Used where the carrier names the bucket but
/// no trusted tier (flood `StateUpdate`, AE `NablaEntry`): any class is the
/// key's OWN row, so the unsigned tier needs no trust; a victim's bucket is
/// never among them. The door, which carries `k_tier`, derives the one bucket
/// directly (step 0b). ONE builder underneath (`smt_bucket`, Pattern 1).
pub fn bucket_derives_from_key(bucket: &WalletId, client_pk: &[u8; 32]) -> bool {
    [axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::K_ARK]
        .iter()
        .any(|k| smt_bucket(client_pk, *k) == *bucket)
}

/// RULE 3 §2 — messages refused because their `wallet_id` is not a bucket of
/// their own `client_pk` (KI#226; door + flood + AE, cumulative). On `/status`
/// as `wallet_id_key_mismatch`.
static WALLET_ID_KEY_MISMATCH: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Count + log one KI#226 refusal. `via` names the path.
pub fn note_wallet_id_key_mismatch(wallet: &WalletId, client_pk: &[u8; 32], tx_hash: &TxHash, via: &str) {
    WALLET_ID_KEY_MISMATCH.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    log::warn!(
        "[WALLET-ID-KEY-MISMATCH] via={} wallet={} client_pk={} tx_hash={} — the message's \
         wallet_id is not a bucket derived from its own signing key; refused, nothing \
         stored (KI#226)",
        via, hex::encode(&wallet[..4]), hex::encode(&client_pk[..4]), hex::encode(&tx_hash[..4]),
    );
}

/// Read the cumulative KI#226 counter (see [`WALLET_ID_KEY_MISMATCH`]).
pub fn wallet_id_key_mismatch_total() -> u64 {
    WALLET_ID_KEY_MISMATCH.load(core::sync::atomic::Ordering::Relaxed)
}

/// Read the cumulative refused-leg counter (see [`LEG_PREIMAGE_REFUSED`]).
pub fn leg_preimage_refused_total() -> u64 {
    LEG_PREIMAGE_REFUSED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Register door step 5b′ (ForkSettlement §2.3 [R17]) — RECORD-GRADE
/// verification, mandatory for every non-zero-pk register. After this passes,
/// the leg this node retains in the head's `SeqProof` (and later, wave 3, in
/// its origin record) is exactly what the k validators signed and the wallet
/// authored (5a′ verified the client sig over the same `tx_hash`).
///
/// 1. The carried leg reproduces the receipt (`verify_leg_preimage`, with the
///    message's `old_state` — [R‑MEDIUM-3]).
/// 2. ≥ max(k_tier, 3) DISTINCT valid `receipt_commitment_sig`s — the same
///    `verify_seq_proof` the flood/AE paths run, over the SAME `SeqProof` the
///    door is about to retain (so the retained proof is proven verifiable).
///
/// ⚠ RULE 5: Nabla hygiene. A hostile node skips this; the Core enforcement
/// that holds regardless is `validate_transaction` re-verifying the receipt
/// commitment at witness time. What this buys is that an HONEST node never
/// stores, floods or (wave 3) vouches for a leg it could not prove.
/// 5c double-redeem rule (KI#231). `existing` = the wallet that REDEEMED this
/// txid (`txid_index` is fed at redeem-finalize only). Refuse when a DIFFERENT
/// wallet presents it — unless the register is a VERIFIED Send leg, which 5b′
/// bound to this tx_hash under its own client_pk: that is the sender registering
/// its own send, never a second redeem.
pub(crate) fn txid_holder_refuses(existing: Option<WalletId>, bucket: &WalletId, verified_send_leg: bool) -> bool {
    match existing {
        Some(w) if &w != bucket => !verified_send_leg,
        _ => false,
    }
}

pub(crate) fn verify_registered_leg(reg: &Registration) -> Result<(), LegRefusal> {
    verify_leg_preimage(
        &reg.preimage,
        &reg.receipt.commitment_hash,
        reg.receipt.epoch,
        &reg.tx_hash,
        &reg.client_pk,
        Some(&reg.old_state),
        Some(&reg.new_state),
        reg.receipt.new_wallet_seq,
    )?;
    let proven = crate::types::SeqProof::from_registration(reg)
        .is_some_and(|p| verify_seq_proof(&p, &reg.tx_hash, reg.receipt.new_wallet_seq));
    if !proven {
        return Err(LegRefusal::WitnessSigsBelowQuorum);
    }
    Ok(())
}

/// KI#34 WI3 hole-1: verify that a gossiped/anti-entropy `SeqProof` genuinely
/// k-attests `wallet_seq` for `txid`. Mirrors the §5b receipt-commitment verify
/// above (`process_registration`) — recomputes the SAME canonical
/// `compute_receipt_commitment` (one builder, CLAUDE.md §12) and checks the
/// carried Ed25519 sigs. Lives HERE, not in `types.rs`, because this is the
/// sanctioned hot-path home for receipt-commitment verification (Core is the
/// sole crypto authority; nabla touches the core-logic primitive only in the
/// files exempted by `cc::tests::no_direct_core_crypto_in_production_code`).
///
/// Returns true iff ≥`max(proof.required_k, MIN_FACT_WITNESSES)` DISTINCT validators signed
/// `compute_receipt_commitment(txid, …, wallet_seq, …)`. A self-stamped seq with
/// no real validator sigs cannot pass, so the merge gate (`apply_state_update` /
/// `apply_remote_entry`) refuses to let it advance the head.
/// YPX-021 §8.2 — build the signed OODS reading a node serves to clients
/// served in the register RESPONSE (folded 2026-07-03). Lives HERE (not nabla_node.rs)
/// because it needs synchronous core-logic crypto primitives and
/// registration.rs is the sanctioned hot-path carve-out for exactly that
/// (see cc.rs `no_direct_core_crypto_in_production_code` + 
/// [[feedback_no_lazy_crypto_exemption]]).
///
/// `None` when the node has no NBC loaded (nothing to anchor to).
pub fn build_oods_attestation(
    own_nbc_bytes: &[u8],
    oods_size: u32,
    tick: u64,
    signer: &dyn crate::crypto::Signer,
    // DEV-ONLY switch (no effect unless core/logic is built `dev-mode` — see below):
    // when this attestation is for FOB mover-eligibility (not a client-facing
    // OODS reading), a dev mesh substitutes DEV_OODS_BASELINE for a genesis
    // baseline of 0 so `fob_mover_eligible` can pass (§10.2a, design decision 2026-08-10).
    // Client-facing readings pass `false` and keep the real baseline, because a
    // client TX carries the attestation to Core's committed ELF, which still
    // enforces the §7 suffix binding — only the FOB path is verified natively
    // by the dev-skip in `validation::verify_oods_attestation`.
    for_fob: bool,
) -> Option<axiom_core_logic::types::NablaOodsAttestation> {
    let own_nbc = crate::cc::deserialize_nbc(own_nbc_bytes).ok()?;
    // RELEASE: the baseline is exactly what the issuer NBC-stamped (0 = genesis
    // exempt), compared properly by verify_oods_attestation's §7 suffix binding.
    // DEV: a FOB-eligibility attestation over a genesis (baseline 0) NBC gets the
    // fixed dev baseline so the dev fund can author; the Core §7 suffix binding is
    // correspondingly dev-skipped (native verify only — see above).
    //
    // ⚠ KI#240 — keyed on core/logic's OWN build profile, NOT on nabla's `dev-mode`.
    // The substitution is only sound because core/logic's `dev-mode` skips the §7
    // suffix check; it used to be `#[cfg(feature = "dev-mode")]` on THIS crate, and
    // nabla `dev-mode` (needed for `--dev`) rides beside a REAL core/logic on a
    // ceremony-keyed tree — where the substituted baseline can never verify and the
    // mesh could not author a FOB tranche. One switch, read where it is set.
    let core_dev_build = axiom_core_logic::version::TUNING_PROFILE == "dev";
    let (baseline_size, baseline_tick) =
        if core_dev_build && for_fob && own_nbc.network_size_baseline == 0 {
            (crate::constants::DEV_OODS_BASELINE, tick)
        } else {
            (own_nbc.network_size_baseline, own_nbc.baseline_tick)
        };
    let payload = axiom_core_logic::compute::compute_oods_attestation_payload(
        oods_size, tick, baseline_size, baseline_tick,
    );
    let nabla_signature = signer.sign(&payload);
    let nabla_node_pk: [u8; 32] = signer.public_key().as_slice().try_into().ok()?;
    Some(axiom_core_logic::types::NablaOodsAttestation {
        oods_size,
        tick,
        baseline_size,
        baseline_tick,
        nabla_node_pk,
        nabla_signature,
        nbc_issuer_pk: own_nbc.issuer_set.first().cloned().unwrap_or_default(),
        nbc_signature: own_nbc.signatures.first().cloned().unwrap_or_default(),
        nbc_commitment: axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&own_nbc),
    })
}

/// §6b / ForkSettlement R42 — a certificate's consume-once registration key:
/// the issuer-signed commitment (`compute_vbc_signing_payload`), the value a
/// genuine stamp names (`NablaVbcStamp::vbc_hash`). Lives HERE, in the
/// crypto-boundary-exempt registration module (`cc::tests::no_direct_core_
/// crypto_in_production_code` — consolidate, never add an exemption), so the
/// witness directory (`vbc_directory`) recomputes it without a direct
/// `compute::` call of its own.
pub fn vbc_registration_hash(vbc: &axiom_core_logic::types::VBC) -> [u8; 32] {
    axiom_core_logic::compute::compute_vbc_signing_payload(vbc)
}

/// §6b — build the Nabla registration stamp for a certificate (this only signs
/// and anchors). ⚠ Since ForkSettlement wave 4a it is built OFF the node lock
/// in `prelock_directory_verify`, BEFORE `register_vbc_core`'s state checks,
/// because the witness directory verifies the STAMPED bundle (R42a). A stamp
/// built there never leaves the node unless `register_vbc_core` then proves the
/// declared balance against the head and records the verified entry. Mirrors `build_oods_attestation`'s NBC
/// trust-anchor + Ed25519 signing, and lives here for the same reason.
/// `None` when the node has no NBC loaded (nothing to anchor to).
pub fn build_vbc_stamp(
    own_nbc_bytes: &[u8],
    vbc_hash: [u8; 32],
    validator_id: [u8; 32],
    wallet_pk: [u8; 32],
    balance: u64,
    tick: u64,
    signer: &dyn crate::crypto::Signer,
) -> Option<axiom_core_logic::types::NablaVbcStamp> {
    let own_nbc = crate::cc::deserialize_nbc(own_nbc_bytes).ok()?;
    let payload = axiom_core_logic::compute::compute_vbc_register_payload(
        &vbc_hash, &validator_id, &wallet_pk, balance, tick,
    );
    let nabla_signature = signer.sign(&payload);
    let nabla_node_pk: [u8; 32] = signer.public_key().as_slice().try_into().ok()?;
    Some(axiom_core_logic::types::NablaVbcStamp {
        vbc_hash,
        wallet_pk,
        balance,
        tick,
        nabla_node_pk,
        nabla_signature,
        nbc_issuer_pk: own_nbc.issuer_set.first().cloned().unwrap_or_default(),
        nbc_signature: own_nbc.signatures.first().cloned().unwrap_or_default(),
        nbc_commitment: axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&own_nbc),
    })
}

/// YPX-022 §2.1 — build a Nabla-signed RecallAttestation. Mirrors
/// `build_oods_attestation`'s NBC trust-anchor + Ed25519 signing. The caller
/// (`register_recall`) has already RECOMPUTED `txid = compute_txid(failed_send_tx)`
/// and taken `presend_state_hash = failed_send_tx.consumed_state_id` from that same
/// verified tx, so the pre-send state is authoritatively bound to the recalled txid.
pub fn build_recall_attestation(
    own_nbc_bytes: &[u8],
    txid: [u8; 32],
    presend_state_hash: [u8; 32],
    amount: u64,
    recall_tick: u64,
    signer: &dyn crate::crypto::Signer,
) -> Option<axiom_core_logic::types::RecallAttestation> {
    let own_nbc = crate::cc::deserialize_nbc(own_nbc_bytes).ok()?;
    let payload = axiom_core_logic::compute::compute_recall_attestation_payload(
        &txid, &presend_state_hash, amount, recall_tick,
    );
    let nabla_signature = signer.sign(&payload);
    let nabla_node_pk: [u8; 32] = signer.public_key().as_slice().try_into().ok()?;
    Some(axiom_core_logic::types::RecallAttestation {
        txid,
        presend_state_hash,
        amount,
        recall_tick,
        nabla_node_pk,
        nabla_signature,
        nbc_issuer_pk: own_nbc.issuer_set.first().cloned().unwrap_or_default(),
        nbc_signature: own_nbc.signatures.first().cloned().unwrap_or_default(),
        nbc_commitment: axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&own_nbc),
    })
}

/// KI#59 — handle an `OooConfirmRequest` (the decision the binary's
/// `ooo_confirm_core` runs, here so lib tests drive the same function): verify
/// the submitted link's k-witness quorum, mark the txid out-of-order-attested
/// (NO head advance), and return a signed `OutOfOrderConfirmation`. Nabla can
/// only WITHHOLD (garbage/under-witnessed → refused); Core independently
/// re-verifies the link + the ooo sig when the wallet presents the chain
/// (RULE 5). Mirrors `register_recall_core`.
pub fn ooo_confirm(
    req: &crate::wire_client::OooConfirmRequest,
    smt: &mut SparseMerkleTree,
    own_nbc_bytes: &[u8],
    current_tick: u64,
    signer: &dyn crate::crypto::Signer,
) -> crate::wire_client::OooConfirmResponse {
    use crate::wire_client::OooConfirmResponse;
    // Griefing hygiene: refuse to sign for a garbage/under-witnessed link. The
    // AUTHORITATIVE k-witness + VBC-cert verification is Core's, on the presented
    // chain (RULE 5); this is Nabla's cheap self-contained gate.
    if !axiom_core_logic::fact::verify_link_witness_quorum(&req.link) {
        return OooConfirmResponse {
            status: "UNDERWITNESSED".to_string(),
            attestation: None,
            error: "submitted link failed the k-witness quorum check".to_string(),
        };
    }
    // Read (txid, new_state) straight off the k-signed link (the state binding).
    let txid = req.link.tx_id;
    let new_state_id = req.link.new_state_id;
    // Mark WITHOUT advancing the head (mirror `register_recall`'s marker) — a
    // later in-order head-registration of this txid must still succeed.
    smt.mark_ooo_attested(txid);
    match build_ooo_confirmation(own_nbc_bytes, txid, new_state_id, current_tick, signer) {
        Some(att) => OooConfirmResponse { status: "OK".to_string(), attestation: Some(att), error: String::new() },
        None => OooConfirmResponse {
            status: "ERROR".to_string(), attestation: None,
            error: "could not build ooo confirmation (no NBC loaded)".to_string(),
        },
    }
}

/// KI#59 — build a Nabla-signed `OutOfOrderConfirmation`. Mirrors
/// `build_recall_attestation`'s NBC trust-anchor + Ed25519 signing. The caller
/// (`ooo_confirm_core`) has already VERIFIED the submitted link's k-witness quorum
/// and taken `txid`/`new_state_id` straight off that k-signed link, so the state is
/// authoritatively bound to the link. Marks WITHOUT advancing the head.
pub fn build_ooo_confirmation(
    own_nbc_bytes: &[u8],
    txid: [u8; 32],
    new_state_id: [u8; 32],
    nabla_tick: u64,
    signer: &dyn crate::crypto::Signer,
) -> Option<axiom_core_logic::types::OutOfOrderConfirmation> {
    let own_nbc = crate::cc::deserialize_nbc(own_nbc_bytes).ok()?;
    let payload = axiom_core_logic::compute::compute_ooo_confirmation_payload(
        &txid, &new_state_id, nabla_tick,
    );
    let nabla_signature = signer.sign(&payload);
    let nabla_node_pk: [u8; 32] = signer.public_key().as_slice().try_into().ok()?;
    Some(axiom_core_logic::types::OutOfOrderConfirmation {
        txid,
        new_state_id,
        nabla_tick,
        nabla_node_pk,
        nabla_signature,
        nbc_issuer_pk: own_nbc.issuer_set.first().cloned().unwrap_or_default(),
        nbc_signature: own_nbc.signatures.first().cloned().unwrap_or_default(),
        nbc_commitment: axiom_core_logic::compute::compute_vbc_signing_payload_bytes(&own_nbc),
    })
}

/// KI#53 — Core's single definition of the client state-authorship payload,
/// re-exported from an ALREADY-EXEMPT file.
///
/// The crypto-boundary tripwire in `cc.rs` says explicitly: if you need a
/// core-logic crypto primitive in new code, consolidate it into one of the
/// four files already exempt — do NOT add a fifth. `gossip.rs` is not exempt
/// (its own ed25519 verify predates the rule and uses the dalek crate
/// directly), so the Core import lives here and gossip re-exports it.
pub use axiom_core_logic::compute::client_state_sign_payload;

pub fn verify_seq_proof(proof: &SeqProof, txid: &TxHash, wallet_seq: u64) -> bool {
    let matched = count_valid_commitment_sigs(proof, txid, wallet_seq);
    // YP §17.3.1.4 v2.19.0 (KI#150): the quorum is the proof's own k, floor 3.
    let need = seq_proof_quorum(proof);
    let ok = matched >= need;
    // KI#38 diagnosis: when a CARRIED proof fails, name WHY — how many of the k
    // sigs matched the recomputed commitment, and every commitment input — so we
    // can see which field (txid / seq / state_hash / commitment_hash / epoch /
    // dev / oods) diverges from what the k validators signed. Rate-bounded by
    // the AE reject cadence; remove once KI#38 is closed.
    if !ok {
        // Recompute the commitment ONLY on the failure path (rate-bounded by
        // the AE reject cadence) — the shared counter doesn't return it, and it
        // is worth logging to see which preimage field diverged.
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            txid, &proof.state_hash, wallet_seq, &proof.commitment_hash,
            proof.epoch, proof.is_dev_class, proof.oods_flag.as_ref(),
            proof.confidence_index.as_ref(), proof.sender_state.as_ref(),
        );
        log::info!(
            "[SEQPROOF-FAIL] matched={}/{} need={} txid={:02x}{:02x} seq={} state_hash={:02x}{:02x} cmit={:02x}{:02x} epoch={} dev={} oods={} commitment={:02x}{:02x}",
            matched, proof.sigs.len(), need,
            txid[0], txid[1], wallet_seq,
            proof.state_hash[0], proof.state_hash[1],
            proof.commitment_hash[0], proof.commitment_hash[1],
            proof.epoch, proof.is_dev_class, proof.oods_flag.is_some(),
            commitment[0], commitment[1],
        );
    }
    ok
}

/// Verify a receipt's execution proofs. The `canonical_core_id` is the node's
/// trusted CoreID (see `parse_canonical_core_id`) — the DMAP path pins each
/// attestation to it so a proof produced by a non-canonical / old Core is
/// rejected (`WrongCore`). The legacy `program_digest`-from-the-receipt behavior
/// was self-referential (it compared the cheque against its own claimed CoreID)
/// and enforced nothing — fixed 2026-06-17.
fn verify_zkp_proofs(
    signatures: &[WitnessSig],
    canonical_core_id: &[u8; 32],
    expected_new_state: &StateId,
) -> Result<bool, NablaError> {
    let program_digest = canonical_core_id;
    let has_proofs = signatures.iter().any(|ws| !ws.execution_proof.is_empty());
    if !has_proofs {
        // No proofs present — bootstrap / legacy registrations.
        return Ok(false);
    }

    // Lazy-init ZKP verifier only if we encounter a ZKP proof
    let mut zkvm_verifier: Option<ZkvmVerifier> = None;

    let mut verified_count = 0;
    for ws in signatures {
        if ws.execution_proof.is_empty() {
            continue;
        }

        match ws.proof_type {
            0 => {
                // ── ZKP STARK Verification ──
                let verifier = match &zkvm_verifier {
                    Some(v) => v,
                    None => {
                        let v = ZkvmVerifier::production()
                            .map_err(|e| NablaError::InvalidProof(
                                format!("production verifier: {}", e),
                            ))?;

                        // Cross-check program_digest
                        let expected_image_id = v.expected_digest();
                        if *program_digest != [0u8; 32] && *program_digest != expected_image_id {
                            return Err(NablaError::InvalidProof(format!(
                                "program_digest mismatch: receipt claims {} but verifier expects {}",
                                hex::encode(program_digest),
                                hex::encode(expected_image_id),
                            )));
                        }

                        zkvm_verifier = Some(v);
                        zkvm_verifier.as_ref().unwrap()
                    }
                };

                let receipt = ZkvmReceipt::from_bytes(&ws.execution_proof)
                    .map_err(|e| NablaError::InvalidProof(
                        format!("receipt deserialize: {}", e),
                    ))?;

                // verify_checkpoint, not verify: the guest commits
                // ZkpCheckpointOutputs. Until 2026-09-02 this called verify(),
                // which decoded the journal as PublicOutputs — so proof_type==0
                // rejected every proof, valid or not. Same STARK verification
                // and journal-integrity check; only the decoded type changed.
                let outputs = verifier.verify_checkpoint(&receipt)
                    .map_err(|e| NablaError::InvalidProof(
                        format!("STARK verification failed: {}", e),
                    ))?;

                if outputs.result != axiom_core_logic::ValidationResult::Accept {
                    return Err(NablaError::InvalidProof(
                        "proof valid but logic rejected".into(),
                    ));
                }

                if let Some(produced) = outputs.produced_state_id {
                    if produced != *expected_new_state {
                        return Err(NablaError::InvalidProof(
                            "produced_state_id mismatch".into(),
                        ));
                    }
                }

                verified_count += 1;
            }
            1 => {
                // ── DMAP Attestation Verification ──
                // Lambda emits the attestation as CBOR (CLAUDE.md §13: byte-carrying
                // types must use CBOR — JSON would coerce nabla_signature/Dilithium
                // sig bytes through Array-vs-Bytes conversions). Pre-fix this
                // deserialised with serde_json::from_slice and rejected every
                // register with "DMAP attestation deserialize: expected value at
                // line 1 column 1" — the JSON parser sees the first CBOR header
                // byte and immediately errors. Companion to Lambda's
                // 23bdcf2 (Lambda CBOR producer); Nabla side was not migrated.
                let attestation: axiom_dmap_vm::dmap::DmapAttestation =
                    ciborium::from_reader(ws.execution_proof.as_slice())
                        .map_err(|e| NablaError::InvalidProof(
                            format!("DMAP attestation deserialize: {}", e),
                        ))?;

                // Verify structural integrity (CoreID, challenges, Merkle proofs).
                // program_digest = the node's canonical (current) CoreID.
                //  - bootstrap/dev (all-zero digest): CoreID enforcement off (unchanged).
                //  - CoreID-lineage accept-set: attestation.core_id must be blessed (current ∪
                //    non-revoked priors — trusted, baked-in). If so, verify against it (required:
                //    it seeds challenge derivation). A non-accepted CoreID falls through to the
                //    canonical digest → Step-1 WrongCore. Preserves the "only trusted CoreIDs"
                //    invariant while honoring an outstanding cheque minted under a prior Core.
                //    See docs/AXIOM_DESIGN_CoreUpgradeMigration.md §11.
                let resolved_core_id = if *program_digest == [0u8; 32] {
                    *program_digest // sentinel; unused — bootstrap skips the CoreID gate below
                } else {
                    axiom_core_logic::version::resolve_dmap_verify_core_id(
                        &attestation.core_id, program_digest,
                    )
                };
                let expected_core_id = if *program_digest == [0u8; 32] {
                    &attestation.core_id // bootstrap/dev: CoreID enforcement off (unchanged)
                } else {
                    &resolved_core_id // blessed → att.core_id; else canonical → WrongCore
                };
                // AUDIT-FIX v2.11.14: Use witness's validator_pk as trusted identity
                // (covered by Ed25519 witness signature on commitment_hash).
                // Previously used attestation.input_hash/output_hash (self-declared)
                // and no validator_pk binding.
                let expected_vpk: [u8; 32] = ws.validator_pk;
                let result = axiom_dmap_vm::dmap::verify_dmap_attestation(
                    &attestation,
                    expected_core_id,
                    &attestation.input_hash,
                    &attestation.output_hash,
                    &expected_vpk,
                );

                match result {
                    axiom_dmap_vm::dmap::DmapResult::Valid => {}
                    other => {
                        return Err(NablaError::InvalidProof(
                            format!("DMAP verification failed: {:?}", other),
                        ));
                    }
                }

                verified_count += 1;
            }
            unknown => {
                return Err(NablaError::InvalidProof(
                    format!("Unknown proof type: {}", unknown),
                ));
            }
        }
    }

    Ok(verified_count > 0)
}


// ═══════════════════════════════════════════════════════════════════════
// YPX-022 §2.1.2a (KI#205) — the AUTHENTICATED cheque claim.
// Lives in registration.rs (not its own module) because the verify calls
// core-logic's `compute::`/`verify::` primitives synchronously on the TCP
// claim path, and `cc::tests::no_direct_core_crypto_in_production_code`
// allows that only in the four exempt hot-path files — consolidated here
// beside the register-path `verify_pk_binding` class defence rather than
// adding a fifth exemption ([[feedback_no_lazy_crypto_exemption]]).
// ═══════════════════════════════════════════════════════════════════════
// Background — why the claim is authenticated (YPX-022 §2.1.2a, KI#205):
//
// A payment settled TWICE when the receiver's post-redeem register never
// landed: `REDEEMED` is written only by that register, and it was the only
// terminal `register_recall` read. RULED 2026-09-25: the cheque CLAIM — which
// every online redeem MUST make first (Core CL5 Step 3.5b requires the
// Nabla-signed `ChequeClaimProof`) — is the delivery terminal Nabla reads.
// For that to hold, the claim has to be something only the ADDRESSED receiver
// can make. This module is that check; it is pure so it can be driven from a
// unit test, and it is called from BOTH the local TCP claim path
// (`nabla_node.rs::register_cheque_claim_core`) and the gossip receive arm
// (`gossip.rs`, `GossipMessage::ChequeClaimAnnounce`) so a flooded claim is
// re-verified by every node that applies it (§2.1.2a item 3).
//
// RULE 5: this is Nabla-side hygiene — it keeps an honest node's claim table
// clean and makes the recall gate read only authenticated delivery. The
// enforcement that survives a hostile Nabla is Core's: `claim_sig` is bound
// into the `ChequeClaimProof` preimage (`crypto::redeem_claim_nabla_payload`)
// and CL5 re-verifies it (`ChequeClaimProofUnauthenticated`).

use axiom_core_logic::wire_client::RegisterChequeClaimRequest;

/// Why a claim was refused `CLAIM_UNAUTHENTICATED`. Every variant is a
/// distinct check; the response `error` string names it so a client (and a
/// soak log) can tell a bad signature from a key that is not the head's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimRefusal {
    /// `client_pk` is not 32 bytes.
    MalformedClientPk,
    /// `claim_sig` does not verify under `client_pk` over
    /// `crypto::cheque_claim_signing_payload(cheque_id, client_pk, k_tier, wallet_address)`.
    BadSignature,
    /// `wallet_address` is not pk-bound to `client_pk`
    /// (`wallet_id::verify_pk_binding`) — the address↔key binding every
    /// receiver has. Binds ONE BYTE of the key (KI#216); layer (ii) below is
    /// what binds an anchored receiver fully.
    AddressNotBoundToKey,
    /// This node holds an SMT head for the claimant's bucket
    /// (`smt_bucket(client_pk, k_tier)`) and that head's registered
    /// `client_pk` is NOT the claimant's — an anchored receiver is bound by
    /// its full state-chain key (§2.1.2a item 1 (ii)).
    KeyDiffersFromRegisteredHead,
}

impl ClaimRefusal {
    /// The human-readable reason carried on the wire `error` field.
    pub fn message(self) -> &'static str {
        match self {
            ClaimRefusal::MalformedClientPk => "client_pk must be 32 bytes",
            ClaimRefusal::BadSignature =>
                "claim_sig does not verify under client_pk over AXIOM_CHEQUE_CLAIM",
            ClaimRefusal::AddressNotBoundToKey =>
                "wallet_address is not pk-bound to client_pk",
            ClaimRefusal::KeyDiffersFromRegisteredHead =>
                "client_pk differs from the key registered on this wallet's SMT head",
        }
    }
}

/// YPX-022 §2.1.2a item 1 — verify a cheque claim's authenticity, in order:
///
///   (a) `claim_sig` verifies under `client_pk` over the ONE builder
///       `crypto::cheque_claim_signing_payload` (Pattern 1 — never re-hash here);
///   (b) `verify_pk_binding(wallet_address, client_pk)` — the address the
///       claimant names is an address of the key that signed;
///   (c) if `smt_head_pk` is `Some` (the node holds a head for
///       `smt_bucket(client_pk, k_tier)` — see
///       `SparseMerkleTree::head_client_pk_for_claimant`), it MUST equal
///       `client_pk`.
///
/// Pure: no SMT, no clock, no I/O — the caller looks the head up and passes it.
/// `Err` means the claim is refused `CLAIM_UNAUTHENTICATED` and NOTHING is
/// stored (not the claim, not the YPX-010 §14 claim-chain entry).
pub fn verify_cheque_claim(
    req: &RegisterChequeClaimRequest,
    smt_head_pk: Option<&[u8; 32]>,
) -> Result<(), ClaimRefusal> {
    let pk: [u8; 32] = req
        .client_pk
        .as_slice()
        .try_into()
        .map_err(|_| ClaimRefusal::MalformedClientPk)?;

    // (a) the claimant's signature — ONE builder, shared with the SDK that
    // signs and Core CL5 that re-verifies.
    let payload = axiom_core_logic::compute::cheque_claim_signing_payload(
        &req.cheque_id, &req.client_pk, req.k_tier, &req.wallet_address,
    );
    axiom_core_logic::verify::verify_ed25519(&req.client_pk, &payload, &req.claim_sig)
        .map_err(|_| ClaimRefusal::BadSignature)?;

    // (b) address ↔ key. Core's own binding check (the same one the register
    // path's class defence uses); never re-derive the pk_bind here.
    axiom_core_logic::wallet_id::verify_pk_binding(&req.wallet_address, &pk)
        .map_err(|_| ClaimRefusal::AddressNotBoundToKey)?;

    // (c) an anchored receiver is bound by its full state-chain key.
    if let Some(head) = smt_head_pk {
        if *head != pk {
            return Err(ClaimRefusal::KeyDiffersFromRegisteredHead);
        }
    }
    Ok(())
}

/// RULE 3 §2 — a security-relevant rejection needs a COUNTER. Claims refused
/// `CLAIM_UNAUTHENTICATED` on this node (local TCP path + gossip receive arm,
/// cumulative). Surfaced on `/status` as `claims_unauthenticated`. Same
/// process-wide atomic shape as `registration::stake_lock_observations`, so
/// the lib status builder and the binary's builder read ONE source.
static CLAIMS_UNAUTHENTICATED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Count one refused claim (see [`CLAIMS_UNAUTHENTICATED`]).
pub fn note_claim_unauthenticated(reason: ClaimRefusal, cheque_id: &[u8; 32], via: &str) {
    CLAIMS_UNAUTHENTICATED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    log::warn!(
        "[CLAIM-UNAUTHENTICATED] cheque={} via={} reason={:?} — refused, nothing stored (YPX-022 §2.1.2a)",
        hex::encode(&cheque_id[..4]), via, reason,
    );
}

/// Read the cumulative refused-claim counter (see [`CLAIMS_UNAUTHENTICATED`]).
pub fn claims_unauthenticated_total() -> u64 {
    CLAIMS_UNAUTHENTICATED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Test fixture shared by the smt / registration / gossip / node tests: a
/// REAL Ed25519 key, an address generated for it by Core's own
/// `generate_wallet_id` (so `verify_pk_binding` holds), and a `claim_sig`
/// over Core's ONE builder. Returns the request plus the signing key so a test
/// can forge a variant of it.
#[cfg(test)]
pub fn signed_claim_request(
    seed: u8,
    email: &str,
    cheque_id: [u8; 32],
    k_tier: u8,
) -> (RegisterChequeClaimRequest, ed25519_dalek::SigningKey) {
    use ed25519_dalek::Signer as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let pk = sk.verifying_key().to_bytes();
    let salt_hash = blake3::hash(&pk);
    let salt = &hex::encode(salt_hash.as_bytes())[..2];
    let wallet_address =
        axiom_core_logic::wallet_id::generate_wallet_id(email, salt, &pk).unwrap();
    let payload = axiom_core_logic::compute::cheque_claim_signing_payload(
        &cheque_id, &pk, k_tier, &wallet_address,
    );
    let claim_sig = sk.sign(&payload).to_bytes().to_vec();
    (
        RegisterChequeClaimRequest {
            cheque_id,
            client_pk: pk.to_vec(),
            k_tier,
            wallet_address,
            claim_sig,
        },
        sk,
    )
}

#[cfg(test)]
mod cheque_claim_tests {
    use super::*;

    const REAL: &str = "alice@example.com";

    /// (a) A claim whose signature does not verify is refused — the check
    /// that makes the claim AUTHENTICATED at all. Goes red if the
    /// `verify_ed25519` call is removed or its payload is not the one builder.
    #[test]
    fn claim_with_bad_signature_is_refused() {
        let (mut req, _) = signed_claim_request(0x11, REAL, [0xC1; 32], 3);
        assert_eq!(verify_cheque_claim(&req, None), Ok(()), "control: the honest claim verifies");
        req.claim_sig[5] ^= 0x01;
        assert_eq!(verify_cheque_claim(&req, None), Err(ClaimRefusal::BadSignature));
        // A signature over a DIFFERENT cheque id must not carry over either.
        let (other, _) = signed_claim_request(0x11, REAL, [0xC2; 32], 3);
        let mut moved = req.clone();
        moved.claim_sig = other.claim_sig;
        assert_eq!(verify_cheque_claim(&moved, None), Err(ClaimRefusal::BadSignature),
            "claim_sig must bind the cheque id");
    }

    /// (b) A validly signed claim naming an address that is NOT this key's
    /// is refused — a stranger cannot claim under someone else's address by
    /// signing with their own key. Goes red if the `verify_pk_binding` call
    /// is removed.
    #[test]
    fn claim_whose_address_is_not_bound_to_its_key_is_refused() {
        use ed25519_dalek::Signer as _;
        let (victim, _) = signed_claim_request(0x21, REAL, [0xC3; 32], 3);
        let (thief, thief_sk) = signed_claim_request(0x22, REAL, [0xC3; 32], 3);
        // Thief signs a claim that names the VICTIM's address with its own key.
        let mut forged = thief.clone();
        forged.wallet_address = victim.wallet_address.clone();
        let payload = axiom_core_logic::compute::cheque_claim_signing_payload(
            &forged.cheque_id, &forged.client_pk, forged.k_tier, &forged.wallet_address,
        );
        forged.claim_sig = thief_sk.sign(&payload).to_bytes().to_vec();
        assert_eq!(verify_cheque_claim(&forged, None), Err(ClaimRefusal::AddressNotBoundToKey));
    }

    /// (c) With an SMT head for the claimant's bucket, the head's registered
    /// key MUST be the claimant's: a different key is refused, the same key
    /// is accepted. Goes red if the head comparison is removed or inverted.
    #[test]
    fn claim_key_must_match_registered_head_when_one_exists() {
        let (req, _) = signed_claim_request(0x31, REAL, [0xC4; 32], 3);
        let own: [u8; 32] = req.client_pk.as_slice().try_into().unwrap();
        let other = [0x99u8; 32];
        assert_eq!(verify_cheque_claim(&req, Some(&other)),
            Err(ClaimRefusal::KeyDiffersFromRegisteredHead));
        assert_eq!(verify_cheque_claim(&req, Some(&own)), Ok(()));
        assert_eq!(verify_cheque_claim(&req, None), Ok(()),
            "an un-anchored receiver (no head) passes on (a)+(b) alone");
    }

    /// RULE 6 — the counter is an instrument: it must move when a claim is
    /// refused, or "0 refusals" and "check never ran" read identically.
    #[test]
    fn unauthenticated_counter_moves() {
        let before = claims_unauthenticated_total();
        note_claim_unauthenticated(ClaimRefusal::BadSignature, &[0u8; 32], "test");
        assert!(claims_unauthenticated_total() > before);
    }

    #[test]
    fn malformed_client_pk_is_refused_before_any_crypto() {
        let (mut req, _) = signed_claim_request(0x41, REAL, [0xC5; 32], 3);
        req.client_pk.truncate(31);
        assert_eq!(verify_cheque_claim(&req, None), Err(ClaimRefusal::MalformedClientPk));
    }
}

#[cfg(test)]
mod tests {

    /// KI#251 NEGATIVE / MUTATION GUARD — the producer binding has ONE
    /// candidate balance, the declared one. The fixture is a REAL claim Core
    /// produced under the PRE-KI#251 rule (credit at the send), captured
    /// read-only from the trustmesh fleet (CoreID 4f915e6a): wallet
    /// `hal-str-1674737`, FACT link 0 (tx 6bbc5343…), registered with
    /// `declared = 0 / seq 1`, whose witnessed `new_state_id` 29244de6… is a
    /// CREDITED state (balance 10^10, Fable SHA3 recompute 2026-10-02). It is
    /// therefore NOT what a claim produces any more, and a declared 0 must NOT
    /// bind it — the deleted §9m opening-state credit arm (6349d56c) is what
    /// made it bind. The expected value is the fleet's, not recomputed here
    /// (RULE 1 / RULE 6).
    ///
    /// MUTATION (m4, KI#251): re-add the opening-state credit arm to
    /// `send_leg_produced_state_matches` ⇒ "declared 0" binds ⇒ THIS test red.
    #[test]
    fn credited_genesis_claim_state_does_not_bind_a_declared_zero() {
        let h = |s: &str| -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() };
        let pk = h("402ad4893a441b5eeaed487c2f231e79948bb3ee3238078618a65ddd6f73ffad");
        let opening = h("12b68334f1293e252474d4befa9c9e308097d724a8aefca6c696ca57b09fc022");
        let credited_new_state = h("29244de6d2aa1f7d610919fb3a3189d0dc0aa5f7f0c3b46906d60988f40743a4");
        let k = axiom_core_logic::wallet_id::K_DEFAULT;
        assert_eq!(
            axiom_core_logic::genesis::opening_state_id_for(&pk, k, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP),
            opening, "fixture: the claim consumed the wallet's OPENING state",
        );
        let p = axiom_core_logic::types::WitnessPreimage {
            consumed_state_id: opening,
            client_pk: pk,
            wallet_seq: 1,
            receiver_wallet_id: "hal-str-1674737@axiom/70927e2918".to_string(),
            amount: 10_000_000_000,
            nonce: 1_790_608_827_902_576,
        };
        let declared = |balance| crate::types::DeclaredState { balance, wallet_seq: 1 };
        assert!(!super::send_leg_produced_state_matches(&p, &declared(0), &credited_new_state),
            "a declared 0 must NOT bind a CREDITED claim state — no second candidate balance");
        assert!(!super::send_leg_produced_state_matches(&p, &declared(7), &credited_new_state));
        // Equality IS the binding: the balance that produced the state binds it.
        assert!(super::send_leg_produced_state_matches(&p, &declared(10_000_000_000), &credited_new_state),
            "the fixture's own (credited) balance reproduces it — the fixture is genuine");
        // … and a wrong seq never binds.
        assert!(!super::send_leg_produced_state_matches(
            &p, &crate::types::DeclaredState { balance: 10_000_000_000, wallet_seq: 2 }, &credited_new_state));
    }

    /// KI#251 POSITIVE — a genesis claim's send leg as Core produces it NOW
    /// binds on the SDK's declared balance (the UNCHANGED opening balance, 0).
    /// The produced state is built through Core's OWN builders — the ONE
    /// post-tx balance rule (`compute_post_tx_balance`) over the opening
    /// balance (`genesis_opening_balance`), then `compute_produced_state_id` —
    /// never a balance typed here. To be replaced by a real fleet capture after
    /// the rotation.
    ///
    /// MUTATION (KI#251 m1, Core): restore the send-side credit in Core's
    /// genesis arm ⇒ the produced state is the credited one ⇒ "declared 0" RED.
    #[test]
    fn genesis_claim_leg_binds_on_the_declared_unchanged_balance() {
        let h = |s: &str| -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() };
        let pk = h("402ad4893a441b5eeaed487c2f231e79948bb3ee3238078618a65ddd6f73ffad");
        let k = axiom_core_logic::wallet_id::K_DEFAULT;
        let opening = axiom_core_logic::genesis::opening_state_id_for(
            &pk, k, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP);
        let amount = axiom_core_logic::types::GENESIS_CLAIM_AMOUNT;
        let nonce = 1_790_608_827_902_576;
        let tx = axiom_core_logic::types::Transaction {
            kind: axiom_core_logic::types::TxKind::GenesisClaim,
            amount,
            ..Default::default()
        };
        let opening_balance = axiom_core_logic::genesis::genesis_opening_balance(&pk);
        assert_eq!(opening_balance, 0, "fixture: an ordinary (non-bonded) key opens at 0");
        let produced_balance = axiom_core_logic::validation::compute_post_tx_balance(&tx, opening_balance)
            .expect("Core's claim balance rule");
        let new_state = axiom_core_logic::compute::compute_produced_state_id(
            &pk, produced_balance, 1, &opening, nonce);
        let p = axiom_core_logic::types::WitnessPreimage {
            consumed_state_id: opening,
            client_pk: pk,
            wallet_seq: 1,
            receiver_wallet_id: "hal-str-1674737@axiom/70927e2918".to_string(),
            amount,
            nonce,
        };
        let declared = |balance| crate::types::DeclaredState { balance, wallet_seq: 1 };
        assert!(super::send_leg_produced_state_matches(&p, &declared(0), &new_state),
            "declared 0 (the SDK's register): a claim's send leaves the balance UNCHANGED (YP §17.11.2 step 3)");
        assert!(!super::send_leg_produced_state_matches(&p, &declared(amount), &new_state),
            "a declared CREDIT must not bind the claim's state");
    }

    /// §10.2a — DEV baseline floor for FOB eligibility. A genesis dev NBC carries
    /// baseline 0 (YPX-021 §7 exempt), which fails `fob_mover_eligible` closed
    /// forever, so a dev mesh could never author a FOB tranche. In DEV builds the
    /// FOB attestation (`for_fob=true`) substitutes `DEV_OODS_BASELINE`; the
    /// client-facing reading (`for_fob=false`) keeps the real baseline so the
    /// committed ELF's §7 gate still accepts it. RELEASE keeps the real baseline
    /// for both. "DEV" = core/logic built `dev-mode` (KI#240), not nabla's feature.
    /// FAILS without the `for_fob` dev substitution.
    #[test]
    fn build_oods_attestation_dev_baseline_floor_for_fob() {
        let mut nbc = crate::cc::sim_nbc([7u8; 32], 100);
        nbc.network_size_baseline = 0;
        nbc.baseline_tick = 0;
        let bytes = crate::cc::serialize_nbc(&nbc);
        let signer = crate::crypto::NoopSigner;

        // Client-facing reading NEVER gets the dev floor (ELF would reject it).
        let client = super::build_oods_attestation(&bytes, 10, 500, &signer, false)
            .expect("client attestation builds");
        assert_eq!(client.baseline_size, 0, "client reading keeps the genesis baseline");

        let fob = super::build_oods_attestation(&bytes, 10, 500, &signer, true)
            .expect("fob attestation builds");
        // KI#240: the floor follows core/logic's build profile (the switch that also
        // skips the §7 suffix check), not this crate's `dev-mode`.
        if axiom_core_logic::version::TUNING_PROFILE == "dev" {
            assert_eq!(
                fob.baseline_size,
                crate::constants::DEV_OODS_BASELINE,
                "DEV: FOB attestation floors the genesis baseline"
            );
            assert!(
                axiom_core_logic::validation::fob_mover_eligible(
                    fob.oods_size as u64,
                    fob.baseline_size as u64,
                ),
                "DEV: floored baseline makes a 10-node mesh eligible to author"
            );
        } else {
            assert_eq!(fob.baseline_size, 0, "RELEASE: FOB attestation keeps the real NBC baseline");
        }
    }

    /// G9 guard — a FORGED hibernation must not block a register.
    ///
    /// `GossipMessage::Hibernation` is unauthenticated: any peer can send
    /// `(client_pk, until)` for any wallet, and `client_pk` is public. That is
    /// safe today only because the Nabla-side hibernation map gates nothing —
    /// its one read site is the `else if` in §8a that CLEARS on a non-re-anchor
    /// register. It is not in `root_hash`, not snapshotted, not served.
    ///
    /// This test pins that property. If someone adds an enforcement read —
    /// "reject a register from a hibernating wallet" looks like an obvious
    /// hardening — this goes red, because that read would turn one forged
    /// packet into a permanent mesh-wide send-lock on any wallet by public key.
    /// Authenticate the gossip (carry the k=3 register attestation) BEFORE
    /// making this test pass again. YPX-020 §2b; ghost audit G9.
    #[test]
    fn g9_forged_hibernation_cannot_block_a_register() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (reg, deed) = make_valid_registration(0x9A, 0x00, 0x01);
        let bucket = smt_bucket(&reg.wallet_id, reg.k_tier);

        // An attacker floods a hibernation for this wallet, as far in the
        // future as u64 allows — exactly what the unauthenticated path accepts.
        assert!(smt.apply_remote_hibernation(&bucket, u64::MAX, 1));
        assert_eq!(smt.hibernation_until(&bucket), u64::MAX,
            "setup: the forged lock is in the map");

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed, 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, None, None, None, None,
        );
        assert!(result.is_ok(),
            "G9: a forged hibernation must NOT block a register — if this fails, \
             an enforcement read was added to an UNAUTHENTICATED map and one \
             packet can now send-lock any wallet by public key. Authenticate \
             the Hibernation gossip first (YPX-020 §2b).");
    }
    use super::*;

    // ── §5.2.2c KI#132 — the Nabla stake-lock spot-check ────────────────────

    /// Serialises the tests that touch the process-global KI#132 counter.
    ///
    /// ⚠ Rust runs tests in PARALLEL and the counter is a `static`, so a
    /// before/after delta is racy: another test observing a live lock ticks it
    /// mid-assertion. Caught immediately (`counter_moves_only_for...` failed on
    /// its first run). Every test that reads or moves the counter takes this.
    static COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Build a Registration whose k-signed `state_hash` genuinely commits the
    /// declared values — i.e. an HONEST wallet.
    fn reg_with_declared(balance: u64, hib: u64, wcl: u64, seq: u64) -> Registration {
        let (mut reg, _) = make_valid_registration(7, 1, 2);
        reg.declared_balance = balance;
        reg.declared_hibernation_until = hib;
        reg.declared_wall_clock_lock = wcl;
        reg.receipt.new_wallet_seq = seq;
        reg.receipt.state_hash = axiom_core_logic::compute::compute_state_hash(
            &reg.client_pk, balance, seq, hib, wcl,
         0, 0, &axiom_core_logic::types::WalletFormat::CURRENT,
    );
        reg
    }

    /// A stake-locked wallet's register is REFUSED before anything advances.
    ///
    /// MUTATION (RULE 6 §3a): delete the `current_tick < declared_wall_clock_lock`
    /// arm in `verify_declared_state_and_stake_lock` and THIS test goes red.
    #[test]
    fn ki132_a_live_lock_is_observed_but_not_refused_pending_ruling() {
        // Moves the global counter — serialise against the counter test.
        let _serial = COUNTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let deadline = 1_800_000_000u64;
        let reg = reg_with_declared(500_000, deadline + 964_000, deadline, 4);
        // ⚠ OBSERVE-ONLY pending ruling — see the fn. Refusing here blocked the
        // claim redeem that STAMPS the lock, scarred the chain, and killed the
        // release send on the live fleet (2026-09-07). The test now pins the
        // ACTUAL behaviour rather than the intended one, so it cannot quietly
        // pass while the feature is disabled.
        assert!(verify_declared_state_and_stake_lock(&reg, deadline - 1).is_ok(),
            "KI#132 is OBSERVE-ONLY: it must log a live lock and refuse NOTHING, \
             because Nabla cannot tell the lock-stamping redeem apart from a \
             wallet that was already locked");
    }

    /// ...and is admitted once the deadline has passed. The lock ends by TIME.
    #[test]
    fn ki132_the_same_wallet_registers_once_the_deadline_passes() {
        let deadline = 1_800_000_000u64;
        let reg = reg_with_declared(500_000, deadline + 964_000, deadline, 4);
        assert!(verify_declared_state_and_stake_lock(&reg, deadline).is_ok(),
            "at the deadline the lock is over — refusing here would strand the wallet");
    }

    /// ⚠ HAL / RECALL MUST PASS. They hibernate with NO wall-clock lock, and
    /// gating them here would strand every wallet mid-recovery — the exact
    /// mistake Core's CL5 gate documents. Switch the trigger in
    /// `verify_declared_state_and_stake_lock` from `declared_wall_clock_lock` to
    /// `declared_hibernation_until` and THIS test goes red.
    #[test]
    fn ki132_hal_recall_hibernation_is_not_a_stake_lock() {
        let reg = reg_with_declared(500_000, 1_900_000_000, 0, 9);
        assert!(verify_declared_state_and_stake_lock(&reg, 1_000).is_ok(),
            "a hibernating HAL/RECALL wallet carries wall_clock_lock == 0 and must \
             still be able to register — this is the leg that must not break");
    }

    /// A LIE about the declared state changes the recomputed hash and is refused.
    /// This is what makes the declaration safe to accept at all.
    #[test]
    fn ki132_a_lied_declaration_is_unjudged_not_refused() {
        let deadline = 1_800_000_000u64;
        let mut reg = reg_with_declared(500_000, deadline + 964_000, deadline, 4);
        // The attacker claims no lock, leaving the k-signed hash untouched.
        reg.declared_wall_clock_lock = 0;
        reg.declared_hibernation_until = 0;
        // ⚠ The lie is NOT judged — it is not "caught". A mismatch means the
        // receipt does not anchor the declared state; Nabla passes (non-fatal
        // this rotation) and COUNTS it (`declared_state_unanchored`).
        // ~~"which is also true of the legitimate genesis-fund shape"~~ — no
        // longer (KI#251, 2026-10-02: the claim's send now binds the unchanged
        // balance the fund declares); making this fatal broke every claim gate
        // run on 2026-09-07 only because of that Core deviation. Promote to a
        // refusal after one soak measures zero.
        //
        // What this pins is that lying BUYS THE ATTACKER NOTHING HERE: they are
        // simply un-judged by an armour layer that fails open anyway. Core still
        // refuses them.
        let before = declared_state_unanchored_total();
        assert!(verify_declared_state_and_stake_lock(&reg, deadline - 1).is_ok(),
            "a declaration that does not reproduce the hash is UNJUDGED (non-fatal), not refused");
        assert!(declared_state_unanchored_total() > before,
            "RULE 3 §2: the un-judged pass-through must be COUNTED on /status");
    }

    /// The KI#132 counter MOVES for a locked non-claim register, and does NOT
    /// move for the wallet's own stake claim.
    ///
    /// RULE 3 §2 / RULE 6: a counter that cannot be shown to increment is worth
    /// no more than a `debug!`. The second half is what makes the counter
    /// MEANINGFUL — if the stamping redeem were counted, every claim would tick
    /// it and "non-zero means a Core gate leaked" would be a lie.
    #[test]
    fn ki132_counter_moves_only_for_a_lock_that_is_not_its_own_claim() {
        let _serial = COUNTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let deadline = 1_800_000_000u64;
        let before = stake_lock_observations();

        // The wallet's OWN stake claim (tier-3 amount) — expected, NOT counted.
        let mut own = reg_with_declared(500_000, deadline + 964_000, deadline, 4);
        own.receipt.amount = axiom_core_logic::types::TIER3_CLAIM_ATOMS;
        own.receipt.state_hash = axiom_core_logic::compute::compute_state_hash(
            &own.client_pk, 500_000, 4, deadline + 964_000, deadline,
         0, 0, &axiom_core_logic::types::WalletFormat::CURRENT,
    );
        assert!(verify_declared_state_and_stake_lock(&own, deadline - 1).is_ok());
        assert_eq!(stake_lock_observations(), before,
            "the claim redeem that STAMPS the lock must NOT be counted — counting it \
             would make a non-zero counter meaningless");

        // A locked wallet registering something else — THIS is the leak signal.
        let mut other = reg_with_declared(500_000, deadline + 964_000, deadline, 5);
        other.receipt.amount = 1_234_567;
        other.receipt.state_hash = axiom_core_logic::compute::compute_state_hash(
            &other.client_pk, 500_000, 5, deadline + 964_000, deadline,
         0, 0, &axiom_core_logic::types::WalletFormat::CURRENT,
    );
        assert!(verify_declared_state_and_stake_lock(&other, deadline - 1).is_ok(),
            "still refuses nothing — observe-only");
        assert_eq!(stake_lock_observations(), before + 1,
            "a live lock on a NON-claim register must be COUNTED: it means CL1 or the \
             CL5 redeem gate let a locked wallet through");
    }

    /// An honest UNLOCKED wallet is untouched — the check must not tax normal use.
    #[test]
    fn ki132_an_unlocked_wallet_registers_normally() {
        let reg = reg_with_declared(12_345, 0, 0, 3);
        assert!(verify_declared_state_and_stake_lock(&reg, 1_800_000_000).is_ok());
    }

    /// A receipt claiming no §15 anchor cannot be checked and is passed through.
    #[test]
    fn ki132_a_receipt_with_no_anchor_is_passed_through() {
        let mut reg = reg_with_declared(1, 0, 0, 1);
        reg.receipt.state_hash = [0u8; 32];
        reg.declared_balance = 999; // would not reproduce any hash
        assert!(verify_declared_state_and_stake_lock(&reg, 1).is_ok(),
            "a provisional/partial receipt claims no anchor; refusing it would break \
             flows that legitimately carry none");
    }

    fn make_valid_registration(wid_byte: u8, old: u8, new: u8) -> (Registration, DeedTransaction) {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = wid_byte;
        let mut old_state = [0u8; 32];
        old_state[0] = old;
        let mut new_state = [0u8; 32];
        new_state[0] = new;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = wid_byte; tx_hash[1] = new;

        let reg = Registration {
            declared_balance: 0,
            declared_hibernation_until: 0,
            declared_wall_clock_lock: 0,
            declared_emission_claimed_epoch: 0,
            declared_stake_floor_until: 0,
            declared_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
            fob_claim: None,
            k_tier: 3,
            is_recall: false,
            wallet_id,
            old_state,
            new_state,
            tx_hash,
            receipt: K3Receipt {
                sender_state: None,
                oods_flag: None,
                confidence_index: None,
                consumed_state_id: old_state,
                produced_state_id: new_state,
                amount: 100,
                signatures: vec![
                    WitnessSig {
                        validator_pk: [0x01; 32],
                        signature: vec![0x01; 64],
                        execution_proof: vec![],
                        proof_type: 0,
                        receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0, },
                    WitnessSig {
                        validator_pk: [0x02; 32],
                        signature: vec![0x02; 64],
                        execution_proof: vec![],
                        proof_type: 0,
                        receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0, },
                    WitnessSig {
                        validator_pk: [0x03; 32],
                        signature: vec![0x03; 64],
                        execution_proof: vec![],
                        proof_type: 0,
                        receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0, },
                ],
                program_digest: [0u8; 32],
                tick: 0,
                state_hash: [0u8; 32],                 new_wallet_seq: 0,
                commitment_hash: [0u8; 32], epoch: 0,
                fee_breakdown: vec![],
            is_dev_class: false,
            },
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
            is_genesis_claim: false,
            is_hal_reanchor: false,
            claimant_wallet_id: String::new(),
            is_dev_claim: false,
            burn_target_tx_id: None,
            // ForkSettlement wave 2a — zero-pk fixture: door 5b′ does not run (group
            // carve-out), and no WITNESS_V2 preimage reproduces this arbitrary tx_hash.
            preimage: crate::types::test_legs::opaque_redeem_leg(),
        };

        let deed = DeedTransaction {
            sender_wallet_id: wallet_id,
            receiver_wallet_id: DEED_PROTOCOL_WALLET_ID,
            amount: DEED_WRITE_FEE,
            signature: vec![0xFF; 64],
        };

        // §5.2.4 (KI#123): the base fixture used to omit receipt_commitment
        // sigs "because non-recall paths never check them" — no longer true:
        // §8 refuses to commit a head it cannot derive a retainable SeqProof
        // from (an origin head without a proof is the strand class), and real
        // witness rounds ALWAYS carry these sigs (the witness signs the
        // commitment on every k-witness path — consensus.rs 3368/3753/3891).
        // A fixture without them was constructing what production never sends
        // (the KI#53 fixture lesson). Tests that specifically need the
        // no-proof shape clear the sigs explicitly.
        let mut reg = reg;
        attest_receipt_commitment(&mut reg);

        (reg, deed)
    }

    /// Test helper: sign the receipt_commitment with 3 real ed25519 keys so a
    /// registration passes `verify_receipt_commitment_sigs` (§6c) and yields a
    /// retainable `SeqProof` at §8. Real witness rounds ALWAYS carry these —
    /// the witness signs the commitment on every k-witness path
    /// (consensus.rs 3368/3753/3891). Call (again)
    /// AFTER any is_dev_class / field mutation so the sig covers the final commitment.
    fn attest_receipt_commitment(reg: &mut Registration) {
        use ed25519_dalek::{SigningKey, Signer as _};
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            &reg.tx_hash,
            &reg.receipt.state_hash,
            reg.receipt.new_wallet_seq,
            &reg.receipt.commitment_hash,
            reg.receipt.epoch,
            reg.receipt.is_dev_class,
            reg.receipt.oods_flag.as_ref(), None,
            reg.receipt.sender_state.as_ref(),
        );
        for (i, ws) in reg.receipt.signatures.iter_mut().enumerate() {
            let sk = SigningKey::from_bytes(&[(i as u8) + 1; 32]);
            ws.validator_pk = sk.verifying_key().to_bytes();
            ws.receipt_commitment_sig = sk.sign(&commitment).to_bytes().to_vec();
        }
    }

    // ── ForkSettlement wave 2a — door step 5b′ ──────────────────────────────

    /// Make `reg` an AUTHORED send register whose leg is GENUINE: a real wallet
    /// key (`client_pk` = `wallet_id` = pk), a `WitnessPreimage` whose consumed
    /// state / key / seq / amount are the register's own, and — exactly as Core
    /// CL3 produces them — `receipt.commitment_hash = preimage.commitment_hash()`
    /// and `tx_hash = preimage.txid(receipt.epoch)` (the ONE inner builders).
    /// Then the k commitment sigs and the wallet's client sig are (re)made over
    /// the final bytes. Everything the door recomputes is DERIVED, never pinned.
    fn bind_send_leg(reg: &mut Registration, sk: &ed25519_dalek::SigningKey, nonce: u64) {
        let pk = sk.verifying_key().to_bytes();
        reg.wallet_id = pk;
        reg.client_pk = pk;
        let preimage = axiom_core_logic::types::WitnessPreimage {
            consumed_state_id: reg.old_state,
            client_pk: pk,
            wallet_seq: reg.receipt.new_wallet_seq,
            receiver_wallet_id: "bob@axiom.internal/0123456789".into(),
            amount: reg.receipt.amount,
            nonce,
        };
        reg.receipt.epoch = 1_790_000_123;
        reg.receipt.commitment_hash = preimage.commitment_hash();
        reg.tx_hash = preimage.txid(reg.receipt.epoch);
        reg.preimage = LegPreimage::Send(preimage);
        resign_authored(reg, sk);
    }

    /// Re-make the k commitment sigs and the wallet's client sig over `reg`'s
    /// CURRENT bytes (after a deliberate tamper, so the tamper under test is
    /// the ONLY thing wrong with the register).
    fn resign_authored(reg: &mut Registration, sk: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer as _;
        attest_receipt_commitment(reg);
        let bucket = smt_bucket(&reg.wallet_id, reg.k_tier);
        let payload = client_state_sign_payload(&bucket, &reg.new_state, &reg.tx_hash);
        reg.client_sig = sk.sign(&payload).to_bytes().to_vec();
    }

    fn authored_send(pk_byte: u8, old: u8, new: u8) -> (Registration, DeedTransaction, ed25519_dalek::SigningKey) {
        let (mut reg, deed) = make_valid_registration(pk_byte, old, new);
        let sk = ed25519_dalek::SigningKey::from_bytes(&[pk_byte; 32]);
        bind_send_leg(&mut reg, &sk, 9);
        (reg, deed, sk)
    }

    fn run_door(reg: &Registration, deed: &DeedTransaction) -> (Result<RegistrationResult, NablaError>, SparseMerkleTree) {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let r = process_registration(
            &mut smt, &mut wal, &mut bans, reg, deed, 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None,
        );
        (r, smt)
    }

    /// 5b′ POSITIVE — a genuine authored send whose leg reproduces the k-signed
    /// receipt is ACCEPTED, and the leg is RETAINED in the head's SeqProof and
    /// carried on the outgoing flood (the SeqProof is the carrier).
    #[test]
    fn wave2a_door_accepts_a_genuine_leg_and_retains_it() {
        let (reg, deed, _sk) = authored_send(0x71, 0x00, 0x01);
        let (r, smt) = run_door(&reg, &deed);
        let res = r.expect("a genuine leg must register");
        let bucket = smt_bucket(&reg.wallet_id, reg.k_tier);
        assert_eq!(smt.seq_proof(&bucket).expect("head proof retained").preimage, reg.preimage,
            "the retained head proof carries the verified leg");
        match res.gossip_msg {
            GossipMessage::StateUpdate { seq_proof: Some(p), .. } => assert_eq!(p.preimage, reg.preimage,
                "the flood carries the leg"),
            other => panic!("expected a StateUpdate flood with a proof, got {other:?}"),
        }
    }

    /// 5b′ — wrong NONCE in the carried preimage. The nonce is bound into BOTH
    /// the commitment and the txid; the commitment is checked first, so the
    /// refusal names `commitment_hash`. MUTATION: skip the 5b′ call in
    /// `process_registration` → this test goes RED (the register is accepted).
    #[test]
    fn wave2a_door_refuses_a_tampered_preimage_nonce() {
        let (mut reg, deed, sk) = authored_send(0x72, 0x00, 0x01);
        if let LegPreimage::Send(p) = &mut reg.preimage { p.nonce += 1; }
        resign_authored(&mut reg, &sk);
        let before = leg_preimage_refused_total();
        let (r, smt) = run_door(&reg, &deed);
        assert!(matches!(r, Err(NablaError::LegUnverifiable(LegRefusal::CommitmentHashMismatch))),
            "a preimage that does not reproduce the k-signed commitment must be refused, got {r:?}");
        assert!(smt.is_empty(), "nothing stored");
        assert!(leg_preimage_refused_total() > before, "counted (RULE 3 §2)");
    }

    /// 5b′ — the preimage reproduces the commitment but NOT this register's
    /// tx_hash (everything else re-signed consistently, so the txid binding is
    /// the one thing wrong). MUTATION: drop the txid comparison in
    /// `verify_leg_preimage` → RED.
    #[test]
    fn wave2a_door_refuses_a_txid_that_the_preimage_does_not_reproduce() {
        let (mut reg, deed, sk) = authored_send(0x73, 0x00, 0x01);
        reg.tx_hash[31] ^= 0x01;
        resign_authored(&mut reg, &sk);
        let (r, _) = run_door(&reg, &deed);
        assert!(matches!(r, Err(NablaError::LegUnverifiable(LegRefusal::TxidMismatch))),
            "got {r:?}");
    }

    /// [R‑MEDIUM-3] — the message's `old_state` is UNSIGNED; the preimage's
    /// consumed state is bound into the k-signed commitment. A register whose
    /// `old_state` (and receipt.consumed, so step 4 passes) names a different
    /// parent than its own preimage is refused. MUTATION: drop the consumed
    /// comparison in `verify_leg_preimage` → RED.
    #[test]
    fn wave2a_door_refuses_old_state_that_is_not_the_preimage_consumed_state() {
        let (mut reg, deed, sk) = authored_send(0x74, 0x00, 0x01);
        reg.old_state = [0x0E; 32];
        reg.receipt.consumed_state_id = [0x0E; 32];
        resign_authored(&mut reg, &sk);
        let (r, _) = run_door(&reg, &deed);
        assert!(matches!(r, Err(NablaError::LegUnverifiable(LegRefusal::ConsumedStateMismatch))),
            "got {r:?}");
    }

    /// 5b′ — a genuine leg but NO witness-sig quorum over the receipt
    /// commitment (the incomplete-round shape) is refused at the door, before
    /// branch A, for every authored register.
    #[test]
    fn wave2a_door_refuses_a_leg_without_a_commitment_sig_quorum() {
        let (mut reg, deed, _sk) = authored_send(0x75, 0x00, 0x01);
        reg.receipt.signatures[2].receipt_commitment_sig = vec![0u8; 64]; // 2 of 3 valid
        let (r, _) = run_door(&reg, &deed);
        assert!(matches!(r, Err(NablaError::LegUnverifiable(LegRefusal::WitnessSigsBelowQuorum))),
            "got {r:?}");
    }

    /// The preimage's key must be the registrant's key (the identity a fork
    /// verdict bans, ForkSettlement §2.2 step 4).
    #[test]
    fn wave2a_door_refuses_a_preimage_under_another_key() {
        let (mut reg, deed, sk) = authored_send(0x76, 0x00, 0x01);
        if let LegPreimage::Send(p) = &mut reg.preimage { p.client_pk = [0x99; 32]; }
        resign_authored(&mut reg, &sk);
        let (r, _) = run_door(&reg, &deed);
        assert!(matches!(r, Err(NablaError::LegUnverifiable(LegRefusal::ClientPkMismatch))),
            "got {r:?}");
    }

    /// RULE 1 — the fee path's every-slot verifier and `verify_seq_proof` count
    /// through the ONE `count_valid_commitment_sigs`: a receipt with a
    /// duplicated validator slot has a ≥3 quorum of DISTINCT signers only if 3
    /// distinct remain, and "every slot" fails on the duplicate.
    #[test]
    fn wave2a_fee_path_every_slot_verifier_shares_the_distinct_count() {
        let (mut reg, _deed, _sk) = authored_send(0x77, 0x00, 0x01);
        assert!(verify_receipt_commitment_sigs(&reg).is_ok(), "3 distinct valid slots");
        let dup = reg.receipt.signatures[0].clone();
        reg.receipt.signatures.push(dup);
        assert!(verify_receipt_commitment_sigs(&reg).is_err(),
            "a duplicated slot is not a distinct signer — every-slot must refuse it");
    }


    #[test]
    fn register_new_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (reg, deed) = make_valid_registration(0xAA, 0x00, 0x01);

        let result =
            process_registration(&mut smt, &mut wal, &mut bans, &reg, &deed, 1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None)
                .unwrap();

        assert_eq!(result.ack.wallet_id[0], 0xAA);
        assert_eq!(result.ack.new_state[0], 0x01);
        assert_eq!(smt.len(), 1);
        assert_eq!(deed_collected, DEED_WRITE_FEE);
        // No execution proofs → zkp_verified must be false (bootstrap/legacy)
        assert!(!result.ack.zkp_verified, "empty proofs must NOT set zkp_verified");
    }

    /// Branch A (§5.2.2) — the direct proof. A seq-ADVANCE whose receipt carries
    /// NO receipt_commitment_sig (an incomplete witness round → from_registration =
    /// None) MUST be refused before the SMT commit, so an un-attestable head never
    /// enters the mesh (the proof=ABSENT wedge cannot form).
    #[test]
    fn branch_a_refuses_seq_advance_with_no_commitment_sig() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        // Fresh wallet, seq-advance (new_wallet_seq = 1 > 0 ⇒ advances_seq).
        // §5.2.4: the base fixture now signs the commitment (production
        // shape), so this test builds its incomplete-round shape EXPLICITLY —
        // clear every receipt_commitment_sig ⇒ from_registration None.
        let (mut reg, deed) = make_valid_registration(0xAB, 0x00, 0x01);
        reg.receipt.new_wallet_seq = 1;
        for ws in reg.receipt.signatures.iter_mut() {
            ws.receipt_commitment_sig = vec![];
        }
        assert!(
            crate::types::SeqProof::from_registration(&reg).is_none(),
            "precondition: an incomplete round carries no seq-proof",
        );

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed, 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None,
        );

        assert!(
            matches!(result, Err(NablaError::InvalidReceipt)),
            "branch A must REFUSE an un-attestable seq-advance, got {result:?}",
        );
        assert_eq!(smt.len(), 0, "the refused head must NOT enter the SMT");
    }

    /// KI#122 — the register door must not store what its own AE door would
    /// reject. Replays the measured poison (2026-08-27, epsilon 10-vs-1 fork):
    /// a re-register carrying the SKELETON receipt's `new_wallet_seq = 0` over
    /// a held head with seq > 0. Before the 7a' guard this committed locally
    /// (Branch A exempts non-advances), producing an entry every AE peer
    /// rejects `not-superseding` while the acceptor cannot roll back its
    /// consumed state — a permanent single-node fork §32 cannot resolve.
    /// Mutation-verified: removing the 7a' guard turns this red.
    #[test]
    fn ki122_refuses_seq_zero_register_over_attested_head() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let reg = |args: (&mut SparseMerkleTree, &mut WriteAheadLog, &mut BanTable,
                           &Registration, &DeedTransaction, u64, &mut u64)| {
            process_registration(args.0, args.1, args.2, args.3, args.4, args.5, crate::types::test_legs::NOW_SECS, args.6,
                &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None)
        };

        // Genesis head (seq 0), then an ATTESTED advance to seq 1 — the held head.
        let (gen, d0) = make_valid_registration(0x22, 0x00, 0x01);
        reg((&mut smt, &mut wal, &mut bans, &gen, &d0, 1, &mut deed_collected))
            .expect("genesis-fresh seq=0 register must PASS (the control: fresh wallets are exempt)");
        let (mut a1, d1) = make_valid_registration(0x22, 0x01, 0x02);
        a1.receipt.new_wallet_seq = 1;
        attest_receipt_commitment(&mut a1);
        reg((&mut smt, &mut wal, &mut bans, &a1, &d1, 2, &mut deed_collected))
            .expect("attested advance registers");
        let bucket = crate::registration::smt_bucket(&a1.wallet_id, a1.k_tier);
        assert_eq!(smt.get(&bucket).unwrap().wallet_seq, 1, "held head is seq=1");

        // THE POISON: consume the held head (old = 0x02) with a receipt whose
        // seq is the skeleton's hard-coded 0. Branch A exempts it (0 < 1 is not
        // an advance); without 7a' it would REPLACE the held head locally.
        let (mut poison, dp) = make_valid_registration(0x22, 0x02, 0x03);
        poison.receipt.new_wallet_seq = 0;
        let r = reg((&mut smt, &mut wal, &mut bans, &poison, &dp, 3, &mut deed_collected));
        assert!(
            matches!(r, Err(NablaError::InvalidReceipt)),
            "seq=0 over an attested head must be REFUSED at the door, got {r:?}",
        );
        let held = smt.get(&bucket).unwrap();
        assert_eq!(held.wallet_seq, 1, "held seq must be unchanged");
        assert_eq!(held.current_state[0], 0x02, "held head must be unchanged");
    }

    /// Branch A control — the SAME seq-advance WITH a valid receipt_commitment_sig
    /// set (a completed round) passes the gate and commits. Proves the gate does
    /// not over-reject legitimate advances (it targets ABSENT, not every advance).
    #[test]
    fn branch_a_accepts_attested_seq_advance() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        // Genesis (seq 0 — exempt from the gate) establishes the wallet head 0x01.
        let (gen, deed0) = make_valid_registration(0xAC, 0x00, 0x01);
        process_registration(&mut smt, &mut wal, &mut bans, &gen, &deed0, 1, crate::types::test_legs::NOW_SECS,
            &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None)
            .expect("genesis (seq 0) must register");

        // Attested seq-advance to seq 1 on the same wallet (old = held head 0x01).
        let (mut adv, deed1) = make_valid_registration(0xAC, 0x01, 0x02);
        adv.receipt.new_wallet_seq = 1;
        attest_receipt_commitment(&mut adv); // Step-7: populate receipt_commitment_sig
        assert!(
            crate::types::SeqProof::from_registration(&adv).is_some(),
            "precondition: a completed round carries a seq-proof",
        );

        let result = process_registration(&mut smt, &mut wal, &mut bans, &adv, &deed1, 2, crate::types::test_legs::NOW_SECS,
            &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None);
        assert!(
            result.is_ok(),
            "branch A must NOT refuse an attested seq-advance, got {result:?}",
        );
    }

    /// KI#68 — the register-door adoption fallback. Reproduces wallet 024's
    /// acked-then-lost wedge through the REAL register path and asserts the
    /// held head jumps forward, marks the superseded head consumed, and — the
    /// control — that the same non-chaining register WITHOUT a valid
    /// attestation is still refused (so the relaxation is gated exactly as the
    /// TLA+ model's `CanAdopt`, docs/models/ki68_register_door).
    #[test]
    fn ki68_register_door_adopts_acked_then_lost_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let reg = |args: (&mut SparseMerkleTree, &mut WriteAheadLog, &mut BanTable,
                           &Registration, &DeedTransaction, u64, &mut u64)| {
            process_registration(args.0, args.1, args.2, args.3, args.4, args.5, crate::types::test_legs::NOW_SECS, args.6,
                &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None)
        };

        // Genesis head at 0x01 (seq 0).
        let (gen, d0) = make_valid_registration(0x24, 0x00, 0x01);
        reg((&mut smt, &mut wal, &mut bans, &gen, &d0, 1, &mut deed_collected))
            .expect("genesis registers");
        // Seq-advance to 0x02 (seq 1) — this is nabla's held head X.
        let (mut a1, d1) = make_valid_registration(0x24, 0x01, 0x02);
        a1.receipt.new_wallet_seq = 1;
        attest_receipt_commitment(&mut a1);
        reg((&mut smt, &mut wal, &mut bans, &a1, &d1, 2, &mut deed_collected))
            .expect("held head X registers");
        let bucket = crate::registration::smt_bucket(&a1.wallet_id, a1.k_tier);
        assert_eq!(smt.get(&bucket).unwrap().current_state[0], 0x02, "held head is X=0x02");

        // The BRIDGE link X->X+1 (0x02->0x03, seq 2) was acked then LOST: it
        // never reaches nabla. The wallet's next queued link is X+1->X+2
        // (0x03->0x04, seq 3) whose old_state (0x03) does NOT chain onto the
        // held head (0x02) — the wedge.
        let (mut gap, dg) = make_valid_registration(0x24, 0x03, 0x04);
        gap.receipt.new_wallet_seq = 3;
        attest_receipt_commitment(&mut gap);

        // CONTROL: strip the attestation (incomplete round) — must still refuse.
        let (mut gap_unattested, dgu) = make_valid_registration(0x24, 0x03, 0x04);
        gap_unattested.receipt.new_wallet_seq = 3; // no attest_receipt_commitment
        let r_ctrl = reg((&mut smt, &mut wal, &mut bans, &gap_unattested, &dgu, 3, &mut deed_collected));
        assert!(matches!(r_ctrl, Err(_)),
            "KI#68 fallback must DECLINE a non-chaining register with no valid attestation");
        assert_eq!(smt.get(&bucket).unwrap().current_state[0], 0x02,
            "declined register must not move the head");

        // THE FALLBACK: attested + seq-newer(3>1) + target-fresh → adopt.
        let r = reg((&mut smt, &mut wal, &mut bans, &gap, &dg, 3, &mut deed_collected));
        assert!(r.is_ok(), "KI#68: attested seq-newer non-chaining register must ADOPT, got {r:?}");
        let head = smt.get(&bucket).unwrap();
        assert_eq!(head.current_state[0], 0x04, "head jumped forward to X+2=0x04");
        assert_eq!(head.wallet_seq, 3, "seq advanced to the adopted receipt's seq");
        // The superseded head X (0x02) is now marked consumed (the model's Adopt).
        let mut old_head = [0u8; 32]; old_head[0] = 0x02;
        assert!(smt.is_state_consumed(&old_head),
            "KI#68: the replaced head must be marked consumed (A12 net stays complete)");
    }

    /// KI#68 — the fallback must NOT adopt an equal-seq non-chaining register
    /// (the fork-sibling / same-seq redeem-forward case seq cannot separate).
    /// Preserves per-node consume-once; matches the model's strict `Seq(s) >`.
    #[test]
    fn ki68_register_door_declines_equal_seq() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut dc = 0u64;
        let reg = |a: (&mut SparseMerkleTree, &mut WriteAheadLog, &mut BanTable,
                       &Registration, &DeedTransaction, u64, &mut u64)| {
            process_registration(a.0, a.1, a.2, a.3, a.4, a.5, crate::types::test_legs::NOW_SECS, a.6,
                &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None)
        };
        let (gen, d0) = make_valid_registration(0x25, 0x00, 0x01);
        reg((&mut smt, &mut wal, &mut bans, &gen, &d0, 1, &mut dc)).unwrap();
        let (mut a1, d1) = make_valid_registration(0x25, 0x01, 0x02);
        a1.receipt.new_wallet_seq = 2;
        attest_receipt_commitment(&mut a1);
        reg((&mut smt, &mut wal, &mut bans, &a1, &d1, 2, &mut dc)).unwrap();

        // Non-chaining register at the SAME seq (2) — must be refused.
        let (mut eq, de) = make_valid_registration(0x25, 0x03, 0x04);
        eq.receipt.new_wallet_seq = 2;
        attest_receipt_commitment(&mut eq);
        let r = reg((&mut smt, &mut wal, &mut bans, &eq, &de, 3, &mut dc));
        assert!(matches!(r, Err(NablaError::StateMismatch)),
            "KI#68: equal-seq non-chaining register must be refused (fork-sibling ambiguity), got {r:?}");
    }

    /// KI#68 — the adopt guard must CRYPTOGRAPHICALLY verify the seq-proof, not
    /// just check its presence. A register whose `new_wallet_seq` was bumped
    /// AFTER the receipt was signed (sigs valid over the OLD seq, but the
    /// claimed seq is forged-high) MUST be declined. Under the presence-only
    /// bug (`from_registration(..).is_some()`) it would ADOPT at the forged seq and
    /// strand the wallet with an un-attestable head. Found by an adversarial
    /// review of the KI#68 fallback, 2026-08-09.
    /// Mutation-verified: reverting to `.is_some()` turns this red.
    #[test]
    fn ki68_register_door_declines_forged_seq() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut dc = 0u64;
        let reg = |a: (&mut SparseMerkleTree, &mut WriteAheadLog, &mut BanTable,
                       &Registration, &DeedTransaction, u64, &mut u64)| {
            process_registration(a.0, a.1, a.2, a.3, a.4, a.5, crate::types::test_legs::NOW_SECS, a.6,
                &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None)
        };
        // Held head at 0x02 / seq 1.
        let (gen, d0) = make_valid_registration(0x26, 0x00, 0x01);
        reg((&mut smt, &mut wal, &mut bans, &gen, &d0, 1, &mut dc)).unwrap();
        let (mut a1, d1) = make_valid_registration(0x26, 0x01, 0x02);
        a1.receipt.new_wallet_seq = 1;
        attest_receipt_commitment(&mut a1);
        reg((&mut smt, &mut wal, &mut bans, &a1, &d1, 2, &mut dc)).unwrap();
        let bucket = crate::registration::smt_bucket(&a1.wallet_id, a1.k_tier);
        assert_eq!(smt.get(&bucket).unwrap().current_state[0], 0x02);

        // A non-chaining register whose sigs were signed at seq 2, then
        // new_wallet_seq FORGED to 99 (> held seq 1 ⇒ passes seq_newer).
        let (mut forged, df) = make_valid_registration(0x26, 0x03, 0x04);
        forged.receipt.new_wallet_seq = 2;
        attest_receipt_commitment(&mut forged);   // sigs cover seq 2
        forged.receipt.new_wallet_seq = 99;       // now claim seq 99 — sigs no longer match
        let r = reg((&mut smt, &mut wal, &mut bans, &forged, &df, 3, &mut dc));
        assert!(matches!(r, Err(NablaError::StateMismatch)),
            "KI#68: a forged-high new_wallet_seq (sigs don't verify against it) must be \
             DECLINED — the adopt guard must run verify_seq_proof, not is_some(); got {r:?}");
        assert_eq!(smt.get(&bucket).unwrap().current_state[0], 0x02,
            "the forged register must not move the head");
    }

    /// Option-C ruling (2026-07-19): the single-keypair pair's members share
    /// `wallet_id` (the pk) but MUST key separate sequential chains — the pk
    /// keyed BOTH tiers into one chain and the second tier's first
    /// registration could never enter (StateMismatch[SMT_VS_REG] forever,
    /// the live Ark charge-redeem stall). `smt_bucket(pk, k_tier)` splits
    /// them; tier 3 maps to the pk itself (all pre-pair behavior identical).
    #[test]
    fn pair_tiers_key_separate_smt_chains() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        // Normal (k=3) member registers first — advances the pk chain.
        let (reg_normal, deed1) = make_valid_registration(0xC7, 0x00, 0x01);
        process_registration(&mut smt, &mut wal, &mut bans, &reg_normal, &deed1, 1, crate::types::test_legs::NOW_SECS,
            &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, None, None, None, None).expect("normal-tier register");

        // Ark (k=0) member — SAME wallet_id (the shared pk), its OWN genesis
        // states. Pre-fix this rejected StateMismatch (pk chain is at 0x01,
        // reg.old is 0x40); with (pk, tier) bucketing it keys a fresh chain.
        let (mut reg_ark, deed2) = make_valid_registration(0xC7, 0x40, 0x41);
        reg_ark.k_tier = 0;
        process_registration(&mut smt, &mut wal, &mut bans, &reg_ark, &deed2, 2, crate::types::test_legs::NOW_SECS,
            &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, None, None, None, None)
            .expect("ark-tier register must key its OWN chain, not collide with the pk's");

        // Both chains exist, independently headed.
        let pk_bucket = smt_bucket(&reg_normal.wallet_id, 3);
        let ark_bucket = smt_bucket(&reg_ark.wallet_id, 0);
        assert_eq!(pk_bucket, reg_normal.wallet_id, "tier 3 bucket IS the pk");
        assert_ne!(ark_bucket, pk_bucket, "tiers must bucket disjointly");
        assert_eq!(smt.get(&pk_bucket).unwrap().current_state[0], 0x01);
        assert_eq!(smt.get(&ark_bucket).unwrap().current_state[0], 0x41);
        // Identity stays ONE: a ban on the pk gates BOTH tiers' next register.
        assert_eq!(smt.len(), 2);
    }

    #[test]
    fn ki_b2_k_witnessed_register_marks_txid_completed_and_allows_recall() {
        // YPX-022 §2 (2026-07-07 repurpose): a k-witnessed registration (a completed
        // send) marks its txid completed AT REGISTRATION. RECALL is now the retract of a
        // COMPLETED-but-undelivered send, so while the send is held-unredeemed the sender
        // MAY recall it; only a REDEEMED (consumed) send is un-recallable.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let (reg, deed) = make_valid_registration(0xB2, 0x00, 0x01);
        process_registration(&mut smt, &mut wal, &mut bans, &reg, &deed, 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None).unwrap();
        assert!(smt.is_txid_completed(&reg.tx_hash),
            "B2: a k-witnessed register must mark the txid completed");
        // Completed + NOT redeemed → recallable (retract the undelivered cheque), when
        // aged into the recall window (completion tick was 1, so recall in [1+LOW, 1+HIGH]).
        let in_window = 1 + crate::smt::RECALL_INIT_WINDOW_LOW.to_secs() + 5;
        assert!(smt.register_recall(reg.tx_hash, vec![0xB2u8; 32], in_window, false).is_ok(),
            "B2: recall of a completed but NOT-redeemed send must be ALLOWED (retract)");
    }

    /// YPX-022 §2.2.1 — the two-phase flow: initiate RESERVES (`C` stays
    /// redeemable), the `is_recall` register COMMITS (terminal + garbage
    /// hand-off via `committed_recalls`), and a later `is_recall` register
    /// with no open reservation is refused (RecallAborted).
    #[test]
    fn recall_two_phase_reserve_then_commit_at_registration() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        // 1. A completed send.
        let (send_reg, deed) = make_valid_registration(0xB3, 0x00, 0x01);
        process_registration(&mut smt, &mut wal, &mut bans, &send_reg, &deed, 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None).unwrap();

        // 2. Initiate = RESERVATION: pending, NOT terminal — `C` still redeemable.
        let sender_pk = send_reg.wallet_id.to_vec();
        let in_window = 1 + crate::smt::RECALL_INIT_WINDOW_LOW.to_secs() + 5;
        smt.register_recall(send_reg.tx_hash, sender_pk.clone(), in_window, false).unwrap();
        assert!(smt.is_txid_recall_pending(&send_reg.tx_hash), "reserved = RETRACT_PENDING");
        assert!(!smt.is_txid_recalled(&send_reg.tx_hash),
            "a reservation must NOT block the redeem — C stays live until hibernation-entry");

        // 3. The recall self-send's register (is_recall) = COMMIT.
        let (mut recall_reg, deed2) = make_valid_registration(0xB3, 0x01, 0x02);
        recall_reg.is_recall = true;
        // Real recalls carry k-signed receipt_commitment_sigs; §6c now requires them.
        attest_receipt_commitment(&mut recall_reg);
        let result = process_registration(&mut smt, &mut wal, &mut bans, &recall_reg, &deed2,
            in_window + 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None).unwrap();
        assert_eq!(result.committed_recalls, vec![(send_reg.tx_hash, in_window)],
            "commit must hand the (txid, reservation_tick) to the node handler for garbage+flood");
        assert!(smt.is_txid_recalled(&send_reg.tx_hash), "committed = terminal, C is dead");
        assert!(!smt.is_txid_recall_pending(&send_reg.tx_hash));
        assert!(result.hibernation_until.is_some(), "recall commit stamps the hibernation lock");

        // 4. Another is_recall register with NO open reservation → refused.
        let (mut stray, deed3) = make_valid_registration(0xB3, 0x02, 0x03);
        stray.is_recall = true;
        let refused = process_registration(&mut smt, &mut wal, &mut bans, &stray, &deed3,
            in_window + 2, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None);
        assert!(matches!(refused, Err(NablaError::RecallAborted)),
            "is_recall register without an open reservation must fail closed, got {refused:?}");
    }

    /// YPX-022 §2.1.2a item 4 (KI#205) — CLAIM BEATS RESERVATION: an
    /// authenticated claim that arrives while the sender's recall reservation
    /// is open makes the recall's commit register fail closed (RecallAborted),
    /// exactly as a finalizing redeem does. Goes red if step 6b stops
    /// consulting `has_live_claim` on the reserved txid (the commit would then
    /// succeed and `committed_recalls` would carry the delivered cheque).
    #[test]
    fn recall_commit_is_aborted_when_reserved_txid_is_claimed() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        // 1. A completed send, 2. reserved for recall in-window.
        let (send_reg, deed) = make_valid_registration(0xB4, 0x00, 0x01);
        process_registration(&mut smt, &mut wal, &mut bans, &send_reg, &deed, 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None).unwrap();
        let sender_pk = send_reg.wallet_id.to_vec();
        let in_window = 1 + crate::smt::RECALL_INIT_WINDOW_LOW.to_secs() + 5;
        smt.register_recall(send_reg.tx_hash, sender_pk.clone(), in_window, false).unwrap();
        assert_eq!(smt.reserved_recall_txids(&sender_pk), vec![send_reg.tx_hash]);

        // 3. The addressed receiver CLAIMS while the reservation is open.
        let (req, _) = crate::registration::signed_claim_request(0x72, "alice@example.com", send_reg.tx_hash, 3);
        let claim = crate::smt::ChequeClaim::from_request(&req, in_window + 1);
        assert_eq!(smt.register_cheque_claim(send_reg.tx_hash, claim, in_window + 1), Ok(true));
        assert!(smt.is_txid_recall_pending(&send_reg.tx_hash), "the reservation itself is untouched");

        // 4. The recall self-send's register (is_recall) = COMMIT → refused.
        let (mut recall_reg, deed2) = make_valid_registration(0xB4, 0x01, 0x02);
        recall_reg.is_recall = true;
        attest_receipt_commitment(&mut recall_reg);
        let refused = process_registration(&mut smt, &mut wal, &mut bans, &recall_reg, &deed2,
            in_window + 2, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None);
        assert!(matches!(refused, Err(NablaError::RecallAborted)),
            "a claimed cheque was DELIVERED — the recall commit must fail closed, got {refused:?}");
        assert!(!smt.is_txid_recalled(&send_reg.tx_hash), "nothing committed; the payment stands");
        assert!(smt.get(&smt_bucket(&recall_reg.wallet_id, recall_reg.k_tier)).unwrap().current_state != recall_reg.new_state,
            "the refused register must not advance the head");
    }

    /// YPX-022 §2.2.1 — a redeem that finalizes during the reservation window
    /// WINS: the reservation is deleted, the recall's commit register refuses,
    /// and the payment stands (fail-closed, first-wins).
    #[test]
    fn recall_redeem_wins_reservation_window() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (send_reg, deed) = make_valid_registration(0xB4, 0x00, 0x01);
        process_registration(&mut smt, &mut wal, &mut bans, &send_reg, &deed, 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None).unwrap();

        let sender_pk = send_reg.wallet_id.to_vec();
        let in_window = 1 + crate::smt::RECALL_INIT_WINDOW_LOW.to_secs() + 5;
        smt.register_recall(send_reg.tx_hash, sender_pk.clone(), in_window, false).unwrap();
        assert!(smt.has_reserved_recall(&sender_pk));

        // The receiver's redeem finalizes DURING the reservation — it wins.
        smt.mark_txid_redeemed(&send_reg.tx_hash);
        assert!(!smt.has_reserved_recall(&sender_pk), "redeem-finalize deletes the reservation");
        assert!(!smt.is_txid_recall_pending(&send_reg.tx_hash));
        assert!(smt.is_txid_redeemed(&send_reg.tx_hash));

        // The recall's commit register now fails closed — the payment stands.
        let (mut recall_reg, deed2) = make_valid_registration(0xB4, 0x01, 0x02);
        recall_reg.is_recall = true;
        let refused = process_registration(&mut smt, &mut wal, &mut bans, &recall_reg, &deed2,
            in_window + 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None);
        assert!(matches!(refused, Err(NablaError::RecallAborted)),
            "recall must abort after the redeem won the reservation window, got {refused:?}");
        assert!(!smt.is_txid_recalled(&send_reg.tx_hash), "never recalled — the redeem settled");
    }

    /// YPX-022 §6c — a PUBLIC-wallet recall that FORGES `is_dev_class=true` (to grab
    /// the short dev finish-gate window) must reject at register: the k-signed
    /// receipt_commitment covers is_dev_class=false, so flipping the flag breaks the
    /// sig. An HONEST public recall (same flow, untampered) still commits and stamps
    /// its window. (Pre-§6c this stamped the short window unverified — Mac hardening.)
    #[test]
    fn recall_forged_is_dev_class_rejected_at_register() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        // A completed send + an open reservation (so 6b passes and we reach 6c).
        let (send_reg, deed) = make_valid_registration(0xC1, 0x00, 0x01);
        process_registration(&mut smt, &mut wal, &mut bans, &send_reg, &deed, 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None).unwrap();
        let in_window = 1 + crate::smt::RECALL_INIT_WINDOW_LOW.to_secs() + 5;
        smt.register_recall(send_reg.tx_hash, send_reg.wallet_id.to_vec(), in_window, false).unwrap();

        // PUBLIC recall, honestly attested over is_dev_class=false, then TAMPERED to
        // is_dev_class=true WITHOUT re-signing → the commitment sig no longer matches.
        let (mut forged_reg, deed2) = make_valid_registration(0xC1, 0x01, 0x02);
        forged_reg.is_recall = true;
        forged_reg.receipt.is_dev_class = false;
        attest_receipt_commitment(&mut forged_reg);      // sigs cover is_dev_class=false
        forged_reg.receipt.is_dev_class = true;          // FORGE the short-window flag
        let forged = process_registration(&mut smt, &mut wal, &mut bans, &forged_reg, &deed2,
            in_window + 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None);
        assert!(matches!(forged, Err(NablaError::InvalidReceipt)),
            "public recall forging is_dev_class=true must reject (sig covers false), got {forged:?}");
        assert!(!smt.is_txid_recalled(&send_reg.tx_hash),
            "forged recall must NOT commit — reservation intact, nothing advanced (fail-closed)");

        // HONEST public recall (untampered) still commits + stamps its window — the
        // reservation is still open because the forged attempt aborted before commit.
        let (mut honest, deed3) = make_valid_registration(0xC1, 0x01, 0x02);
        honest.is_recall = true;
        honest.receipt.is_dev_class = false;
        attest_receipt_commitment(&mut honest);
        let ok = process_registration(&mut smt, &mut wal, &mut bans, &honest, &deed3,
            in_window + 2, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None).unwrap();
        assert!(ok.hibernation_until.is_some(), "honest public recall stamps its finish-gate window");
        assert!(smt.is_txid_recalled(&send_reg.tx_hash), "honest recall commits — C dead");
    }

    /// KI#205 — the register-door RECALL gate. A REDEEM-finalize register
    /// (non-empty `fee_breakdown`) for a txid whose recall has COMMITTED is
    /// REFUSED (`RedeemAfterRecallCommitted`); a genuine send and a redeem of a
    /// non-recalled txid are unaffected; a redeem during an OPEN reservation is
    /// NOT blocked (redeem wins the reservation race, §2.2.1). Mutation: delete
    /// the `is_txid_recalled` gate in `process_registration` — the first assert
    /// goes green→red (the double-settle re-opens).
    #[test]
    fn ki205_redeem_finalize_after_committed_recall_is_refused() {
        use axiom_core_logic::types::FeeShare;
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut dc = 0u64;

        // A redeem-finalize registration is a normal register carrying a
        // non-empty fee_breakdown (the receiver-pays signal, §8b'').
        let redeem_finalize = |wid: u8, old: u8, new: u8| {
            let (mut r, d) = make_valid_registration(wid, old, new);
            r.receipt.fee_breakdown = vec![FeeShare { validator_id: [0u8; 32], amount: 1 }];
            (r, d)
        };

        // ── 1. txid with a COMMITTED recall → the redeem-finalize is REFUSED,
        //       before any state advances (fail-closed, the link stays a scar).
        let (rf, _d) = redeem_finalize(0xD5, 0x00, 0x01);
        smt.apply_remote_recall(&rf.tx_hash, &[0xAAu8; 32], 5, true); // committed marker
        assert!(smt.is_txid_recalled(&rf.tx_hash));
        let refused = process_registration(&mut smt, &mut wal, &mut bans, &rf, &_d, 10, crate::types::test_legs::NOW_SECS, &mut dc,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None);
        assert!(matches!(refused, Err(NablaError::RedeemAfterRecallCommitted)),
            "a redeem-finalize of a committed-recalled txid must be refused, got {refused:?}");
        assert!(smt.get(&rf.wallet_id).is_none(),
            "the refused redeem must NOT advance the receiver's head — the link is never confirmed");

        // ── 2. a redeem-finalize of a NON-recalled txid is NOT blocked by this
        //       gate (it proceeds to the ordinary path; a dummy fee fails LATER,
        //       proving only that OUR gate did not fire).
        let (ok, dok) = redeem_finalize(0xD6, 0x00, 0x01);
        let r2 = process_registration(&mut smt, &mut wal, &mut bans, &ok, &dok, 11, crate::types::test_legs::NOW_SECS, &mut dc,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None);
        assert!(!matches!(r2, Err(NablaError::RedeemAfterRecallCommitted)),
            "a non-recalled redeem must not hit the KI#205 gate, got {r2:?}");

        // ── 3. an OPEN reservation (not committed) does NOT block the redeem —
        //       the redeem wins the reservation race (§2.2.1). Again asserted by
        //       the ABSENCE of our error, not by success (dummy fee fails later).
        let (rf3, d3) = redeem_finalize(0xD7, 0x00, 0x01);
        smt.apply_remote_recall(&rf3.tx_hash, &[0xBBu8; 32], 6, false); // RESERVED only
        assert!(smt.is_txid_recall_pending(&rf3.tx_hash) && !smt.is_txid_recalled(&rf3.tx_hash));
        let r3 = process_registration(&mut smt, &mut wal, &mut bans, &rf3, &d3, 12, crate::types::test_legs::NOW_SECS, &mut dc,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None);
        assert!(!matches!(r3, Err(NablaError::RedeemAfterRecallCommitted)),
            "an OPEN reservation must not block the redeem (redeem wins §2.2.1), got {r3:?}");

        // ── 4. a GENESIS-claim self-redeem on a committed-recalled txid is
        //       exempt (it is the SEND side of the claim's self-redeem).
        let (mut gc, dg) = redeem_finalize(0xD8, 0x00, 0x01);
        gc.is_genesis_claim = true;
        smt.apply_remote_recall(&gc.tx_hash, &[0xCCu8; 32], 7, true);
        let r4 = process_registration(&mut smt, &mut wal, &mut bans, &gc, &dg, 13, crate::types::test_legs::NOW_SECS, &mut dc,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None);
        assert!(!matches!(r4, Err(NablaError::RedeemAfterRecallCommitted)),
            "a genesis-claim self-redeem is exempt from the KI#205 gate, got {r4:?}");
    }


    #[test]
    fn hal_reanchor_rejected_when_no_held_state() {
        // KI#34 check 1 (fail-closed): a HAL re-anchor against a wiped/unknown wallet
        // (no SMT entry) must be REJECTED, not fresh-inserted — closes the wipe-revival
        // path where HAL blindly re-anchors a wallet the network has no record of.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (mut reg, deed) = make_valid_registration(0xCD, 0x00, 0x01);
        reg.is_hal_reanchor = true; // HAL re-anchor against an EMPTY smt (wiped/unknown)

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed, 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None,
        );
        assert!(
            matches!(result, Err(NablaError::StateMismatch)),
            "KI#34: HAL re-anchor with no held previous state must fail-closed, got {:?}", result
        );
        assert_eq!(smt.len(), 0, "no fresh-insert on a wiped/unknown HAL re-anchor");

        // Control: the SAME shape as a NORMAL register (is_hal_reanchor=false) still
        // fresh-inserts — genesis / first-contact must keep working.
        let (reg2, deed2) = make_valid_registration(0xCE, 0x00, 0x01);
        process_registration(
            &mut smt, &mut wal, &mut bans, &reg2, &deed2, 1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None,
        ).unwrap();
        assert_eq!(smt.len(), 1, "normal (non-HAL) register still fresh-inserts");
    }

    #[test]
    fn register_update_existing() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        // First registration
        let (reg1, deed1) = make_valid_registration(0xAA, 0x00, 0x01);
        process_registration(
            &mut smt,
            &mut wal,
            &mut bans,
            &reg1,
            &deed1,
            1, crate::types::test_legs::NOW_SECS,
            &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None,
            None, None, None, None, None, None, None,
        )
        .unwrap();

        // Second registration (continues from state 0x01)
        let (reg2, deed2) = make_valid_registration(0xAA, 0x01, 0x02);
        let result = process_registration(
            &mut smt,
            &mut wal,
            &mut bans,
            &reg2,
            &deed2,
            2, crate::types::test_legs::NOW_SECS,
            &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None,
            None, None, None, None, None, None, None,
        )
        .unwrap();

        assert_eq!(result.ack.new_state[0], 0x02);
        assert_eq!(smt.len(), 1); // same wallet, count unchanged
        assert_eq!(deed_collected, DEED_WRITE_FEE * 2);
    }

    #[test]
    fn register_retry_after_lost_ack_returns_idempotent_ack() {
        // Phase 1 supplemental-registration fix (YP §17.9.4.3).
        //
        // Scenario: register #1 with state 0x00→0x01 succeeds at Nabla — SMT
        // is at 0x01, txid mapped to wallet 0xAA. But the RegisterAck is lost
        // in transit, so the sender doesn't know. The sender retries with
        // the same Registration.
        //
        // Pre-fix: retry hit StateMismatch[SMT_VS_REG] because smt.current=0x01
        // and reg.old=0x00 differ. Sender's FACT link stayed scarred forever.
        //
        // Post-fix: same wallet + same txid + smt.current == reg.new_state
        // returns an idempotent ACK with the same fact_confirm_signature
        // (deterministic over old/new state). SMT unchanged, no double DEED.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (reg, deed) = make_valid_registration(0xAA, 0x00, 0x01);

        // First register — commits state.
        let result1 = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None,
        ).unwrap();

        let smt_len_after_first = smt.len();
        let deed_after_first = deed_collected;
        let conf_sig_1 = result1.ack.fact_confirm_signature.clone();
        let new_state_1 = result1.ack.new_state;

        // Retry the SAME registration (simulates lost ACK on return path).
        let result2 = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            2, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None,
        ).unwrap();

        // SMT unchanged, no double DEED charge, no double WAL append
        // (WAL invariant verified indirectly: a second commit would
        // change smt.len for a fresh wallet because the txid index also
        // updates; if smt.len is stable, neither commit nor WAL fired).
        assert_eq!(smt.len(), smt_len_after_first,
            "idempotent retry MUST NOT advance SMT");
        assert_eq!(deed_collected, deed_after_first,
            "idempotent retry MUST NOT double-charge DEED");

        // ACK is byte-equivalent on the fields the sender needs:
        //   - same new_state
        //   - same fact_confirm_signature (deterministic over old/new)
        // The `tick` is informational and may differ on retry (current_tick
        // is passed from caller — we passed 1 vs 2). The `signature` field
        // is over the whole ACK including tick, so it WILL differ between
        // the two ACKs — that's fine, the sender only needs the
        // fact_confirm_signature for the FACT link.
        assert_eq!(result2.ack.new_state, new_state_1);
        assert_eq!(result2.ack.fact_confirm_signature, conf_sig_1,
            "fact_confirm_signature MUST be byte-equivalent on retry — \
             sender uses it to populate the scarred FACT link");
    }

    #[test]
    fn register_retry_with_different_new_state_still_rejects() {
        // Regression guard against the idempotent path being too permissive.
        // If the retry's new_state DIFFERS from the committed state, this is
        // NOT a lost-ACK retry — it's a genuine conflict (different TX
        // claiming the same old_state). The idempotent path MUST NOT fire;
        // fall through to the normal StateMismatch rejection.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        // Register A: state 0x00 → 0x01 (txid sourced from wallet+new_state).
        let (reg_a, deed_a) = make_valid_registration(0xAA, 0x00, 0x01);
        process_registration(
            &mut smt, &mut wal, &mut bans, &reg_a, &deed_a,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None,
        ).unwrap();

        // Register B: state 0x00 → 0x02. DIFFERENT txid (make_valid_registration
        // includes new_state in tx_hash), so the txid-double-spend branch
        // doesn't fire. The idempotent branch's
        // `smt.get_wallet_by_txid(reg_b.tx_hash) == Some(reg_b.wallet_id)`
        // check fails (no record of reg_b's txid). Falls through to the
        // StateMismatch check at step 6.
        let (reg_b, deed_b) = make_valid_registration(0xAA, 0x00, 0x02);
        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg_b, &deed_b,
            2, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None,
        );
        assert!(matches!(result, Err(NablaError::StateMismatch)),
            "different new_state with same old_state MUST hit StateMismatch \
             — idempotent path is for exact retries only");
    }

    #[test]
    fn register_conflict_returns_state_mismatch_no_ban() {
        // YPX-002 §3.3 regression guard. Pre-fix, `process_registration`
        // banned-on-conflict. That produced the false-ban cascade the spec
        // exists to prevent: two Nabla nodes behind by one gossip hop would
        // each see the client's write as a conflict and ban the wallet.
        // The fix: /register returns StateMismatch, ban issuance is the
        // exclusive domain of the gossip-merge path (§7.5) which requires
        // two independent k=3 receipts as evidence — something the single
        // /register call can never produce by itself.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        // First registration: state 0x00 → 0x01
        let (reg1, deed1) = make_valid_registration(0xAA, 0x00, 0x01);
        process_registration(
            &mut smt,
            &mut wal,
            &mut bans,
            &reg1,
            &deed1,
            1, crate::types::test_legs::NOW_SECS,
            &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None,
            None, None, None, None, None, None, None,
        )
        .unwrap();

        // Second registration claims old_state 0x00 again → 0x02. From the
        // single-node view this looks like a double-spend; from the network
        // view it may just be a stale local replica. The registration path
        // cannot tell the two apart from one call, so it returns
        // StateMismatch and leaves the ban decision to gossip merge.
        let (reg2, deed2) = make_valid_registration(0xAA, 0x00, 0x02);
        let result = process_registration(
            &mut smt,
            &mut wal,
            &mut bans,
            &reg2,
            &deed2,
            2, crate::types::test_legs::NOW_SECS,
            &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None,
            None, None, None, None, None, None, None,
        );

        assert!(matches!(result, Err(NablaError::StateMismatch)),
            "/register on conflict must be StateMismatch");
        assert!(!bans.is_banned(&reg1.wallet_id),
            "/register MUST NOT ban — §3.3 regression guard. Bans come from gossip merge only.");
    }

    #[test]
    fn register_banned_wallet_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        // Pre-ban the wallet
        let wid = {
            let mut w = [0u8; 32];
            w[0] = 0xAA;
            w
        };
        bans.ban(
            wid,
            ConflictProof {
                old_state: [0; 32],
                new_state: [1; 32],
                tx_hash: [2; 32],
                k3_signatures: vec![
                    WitnessSig { validator_pk: [1; 32], signature: vec![1; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [2; 32], signature: vec![2; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [3; 32], signature: vec![3; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                ],
                tick: 0,
                required_k: 3,
            },
            ConflictProof {
                old_state: [0; 32],
                new_state: [3; 32],
                tx_hash: [4; 32],
                k3_signatures: vec![
                    WitnessSig { validator_pk: [1; 32], signature: vec![1; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [2; 32], signature: vec![2; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [3; 32], signature: vec![3; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                ],
                tick: 0,
                required_k: 3,
            },
        );

        let (reg, deed) = make_valid_registration(0xAA, 0x00, 0x01);
        let result = process_registration(
            &mut smt,
            &mut wal,
            &mut bans,
            &reg,
            &deed,
            1, crate::types::test_legs::NOW_SECS,
            &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None,
            None, None, None, None, None, None, None,
        );

        assert!(matches!(result, Err(NablaError::WalletBanned)));
    }

    #[test]
    fn register_bad_deed_destination() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (reg, mut deed) = make_valid_registration(0xAA, 0x00, 0x01);
        deed.receiver_wallet_id = [0xFF; 32]; // wrong destination

        let result = process_registration(
            &mut smt,
            &mut wal,
            &mut bans,
            &reg,
            &deed,
            1, crate::types::test_legs::NOW_SECS,
            &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None,
            None, None, None, None, None, None, None,
        );

        assert!(matches!(result, Err(NablaError::InvalidDeedDestination)));
    }

    #[test]
    fn register_insufficient_deed() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (reg, mut deed) = make_valid_registration(0xAA, 0x00, 0x01);
        deed.amount = DEED_WRITE_FEE - 1; // too little

        let result = process_registration(
            &mut smt,
            &mut wal,
            &mut bans,
            &reg,
            &deed,
            1, crate::types::test_legs::NOW_SECS,
            &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None,
            None, None, None, None, None, None, None,
        );

        assert!(matches!(result, Err(NablaError::InvalidDeedPayment)));
    }

    #[test]
    fn register_receipt_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (mut reg, deed) = make_valid_registration(0xAA, 0x00, 0x01);
        reg.receipt.produced_state_id[0] = 0xFF; // mismatch

        let result = process_registration(
            &mut smt,
            &mut wal,
            &mut bans,
            &reg,
            &deed,
            1, crate::types::test_legs::NOW_SECS,
            &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None,
            None, None, None, None, None, None, None,
        );

        assert!(matches!(result, Err(NablaError::StateMismatch)));
    }

    #[test]
    fn register_insufficient_signatures() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (mut reg, deed) = make_valid_registration(0xAA, 0x00, 0x01);
        reg.receipt.signatures.truncate(2); // only 2 of 3

        let result = process_registration(
            &mut smt,
            &mut wal,
            &mut bans,
            &reg,
            &deed,
            1, crate::types::test_legs::NOW_SECS,
            &mut deed_collected,
            &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None,
            None, None, None, None, None, None, None,
        );

        assert!(matches!(result, Err(NablaError::InvalidReceipt)));
    }

    // ── Group Wallet Registration Tests (Phase 3) ──

    fn make_group_registration(wid_byte: u8, old: u8, new: u8) -> (GroupRegistration, DeedTransaction) {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = wid_byte;
        let mut old_state = [0u8; 32];
        old_state[0] = old;
        let mut new_state = [0u8; 32];
        new_state[0] = new;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = wid_byte; tx_hash[1] = new;

        let greg = GroupRegistration {
            wallet_id,
            old_state,
            new_state,
            tx_hash,
            receipt: K3Receipt {
                sender_state: None,
                oods_flag: None,
                confidence_index: None,
                consumed_state_id: old_state,
                produced_state_id: new_state,
                amount: 1000,
                signatures: vec![
                    WitnessSig { validator_pk: [0x01; 32], signature: vec![0x01; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [0x02; 32], signature: vec![0x02; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                    WitnessSig { validator_pk: [0x03; 32], signature: vec![0x03; 64], execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![], validator_id: [0u8; 32], slot_amount: 0 },
                ],
                program_digest: [0u8; 32],
                tick: 0,
                state_hash: [0u8; 32],                 new_wallet_seq: 0,
                commitment_hash: [0u8; 32], epoch: 0,
                fee_breakdown: vec![],
            is_dev_class: false,
            },
            members: vec![
                GroupMemberState { member_pk: [0x10; 32], share_bps: 5000, available: 500 },
                GroupMemberState { member_pk: [0x20; 32], share_bps: 3000, available: 300 },
                GroupMemberState { member_pk: [0x30; 32], share_bps: 2000, available: 200 },
            ],
            balance: 1000, // 500 + 300 + 200 = 1000 ✓
            k_tier: 3,
        };

        let deed = DeedTransaction {
            sender_wallet_id: wallet_id,
            receiver_wallet_id: DEED_PROTOCOL_WALLET_ID,
            amount: DEED_WRITE_FEE,
            signature: vec![0xFF; 64],
        };

        (greg, deed)
    }

    #[test]
    fn group_register_valid() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (greg, deed) = make_group_registration(0xBB, 0x00, 0x01);
        let result = process_group_registration(
            &mut smt, &mut wal, &mut bans, &greg, &deed, 1, &mut deed_collected,
            &crate::crypto::NoopSigner,
        );

        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.ack.new_state[0], 0x01);

        // Verify entry has group members
        let entry = smt.get(&greg.wallet_id).unwrap();
        assert!(entry.group_members.is_some());
        let members = entry.group_members.as_ref().unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].available, 500);
        assert_eq!(members[1].available, 300);
        assert_eq!(members[2].available, 200);
    }

    #[test]
    fn group_register_emits_group_update_gossip() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (greg, deed) = make_group_registration(0xCC, 0x00, 0x01);
        let result = process_group_registration(
            &mut smt, &mut wal, &mut bans, &greg, &deed, 1, &mut deed_collected,
            &crate::crypto::NoopSigner,
        ).unwrap();

        match result.gossip_msg {
            GossipMessage::GroupUpdate { wallet_id, members, .. } => {
                assert_eq!(wallet_id[0], 0xCC);
                assert_eq!(members.len(), 3);
            }
            _ => panic!("Expected GroupUpdate gossip"),
        }
    }

    #[test]
    fn group_register_checksum_fail() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (mut greg, deed) = make_group_registration(0xDD, 0x00, 0x01);
        greg.balance = 999; // checksum mismatch: 500+300+200 != 999

        let result = process_group_registration(
            &mut smt, &mut wal, &mut bans, &greg, &deed, 1, &mut deed_collected,
            &crate::crypto::NoopSigner,
        );

        assert!(matches!(result, Err(NablaError::GroupChecksumFailed)));
    }

    // ── DMAP Proof Verification Tests ──

    /// Build a valid DMAP attestation with real Ed25519 signature, for registration tests.
    fn make_dmap_witness_sig(core_id: [u8; 32], input_hash: [u8; 32], output_hash: [u8; 32]) -> (WitnessSig, [u8; 32]) {
        use axiom_dmap_vm::dmap::checkpoint::{DmapCheckpoint, DmapTrace};
        use axiom_dmap_vm::dmap::DmapAttestation;
        use ed25519_dalek::{SigningKey, Signer};

        // Generate real Ed25519 keypair for the validator
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vpk: [u8; 32] = sk.verifying_key().to_bytes();

        let checkpoints: Vec<DmapCheckpoint> = (0..50u64)
            .map(|i| DmapCheckpoint {
                instruction_count: (i + 1) * 10000,
                pc: 0x1000 + (i as u32) * 4,
                memory_root: {
                    let mut h = [0u8; 32];
                    h[0] = i as u8;
                    h
                },
                register_hash: [i as u8; 32],
            })
            .collect();

        let trace = DmapTrace::from_checkpoints(checkpoints);
        let mut attestation = DmapAttestation::from_trace(
            core_id, input_hash, output_hash, &trace, 1710000000, vpk,
        );

        // Sign the attestation with the validator's key (AUDIT-FIX v2.11.14)
        let payload = attestation.signing_payload();
        let sig = sk.sign(&payload);
        attestation.set_signature(sig.to_bytes().to_vec());

        // CBOR (was serde_json) — verify_zkp_proofs reads via
        // ciborium::from_reader (registration.rs:643), so the test
        // helper must produce the same encoding.  Pre-fix this wrote
        // JSON and every DMAP test rejected with
        // "expected value at line 1 column 1" because the CBOR parser
        // saw a JSON `{` as the first byte.  Same class as the Lambda
        // 23bdcf2 CBOR-producer migration.
        let mut proof_bytes = Vec::new();
        ciborium::into_writer(&attestation, &mut proof_bytes).unwrap();
        let ws = WitnessSig {
            validator_pk: vpk,
            signature: vec![0x01; 64], // Witness sig (not used for DMAP verification)
            execution_proof: proof_bytes,
            proof_type: 1, // DMAP
            receipt_commitment_sig: vec![],
            validator_id: [0u8; 32],
            slot_amount: 0,
        };
        (ws, core_id)
    }

    #[test]
    fn verify_dmap_attestation_valid() {
        // A valid DMAP attestation with matching program_digest should pass
        let core_id = [0xAA; 32];
        let input_hash = [0xBB; 32];
        let output_hash = [0xCC; 32];
        let (ws, _) = make_dmap_witness_sig(core_id, input_hash, output_hash);
        let new_state = [0x01; 32];

        let result = verify_zkp_proofs(&[ws], &core_id, &new_state);
        assert!(result.is_ok());
        assert!(result.unwrap(), "Valid DMAP attestation must be verified");
    }

    #[test]
    fn verify_dmap_rejects_wrong_canonical_core_id() {
        // program_digest (canonical CoreID) doesn't match attestation's core_id → reject
        let core_id = [0xAA; 32];
        let wrong_canonical = [0xFF; 32]; // receipt says different CoreID
        let input_hash = [0xBB; 32];
        let output_hash = [0xCC; 32];
        let (ws, _) = make_dmap_witness_sig(core_id, input_hash, output_hash);
        let new_state = [0x01; 32];

        let result = verify_zkp_proofs(&[ws], &wrong_canonical, &new_state);
        assert!(result.is_err(), "Wrong canonical CoreID must be rejected");
    }

    #[test]
    fn verify_dmap_bootstrap_skips_core_id_check() {
        // program_digest = [0; 32] (bootstrap) → falls back to attestation's own core_id
        let core_id = [0xAA; 32];
        let bootstrap_digest = [0u8; 32];
        let input_hash = [0xBB; 32];
        let output_hash = [0xCC; 32];
        let (ws, _) = make_dmap_witness_sig(core_id, input_hash, output_hash);
        let new_state = [0x01; 32];

        let result = verify_zkp_proofs(&[ws], &bootstrap_digest, &new_state);
        assert!(result.is_ok());
        assert!(result.unwrap(), "Bootstrap mode should accept valid DMAP attestation");
    }

    #[test]
    fn parse_canonical_core_id_empty_is_zero() {
        // unpinned dev/source build → [0;32] → DMAP bootstrap (no enforcement)
        assert_eq!(parse_canonical_core_id(""), [0u8; 32]);
    }

    #[test]
    fn parse_canonical_core_id_valid_hex() {
        let h = "aa".repeat(32);
        assert_eq!(parse_canonical_core_id(&h), [0xAA; 32]);
        // wrong length → fail-safe to zero (startup ELF-pin guards real builds)
        assert_eq!(parse_canonical_core_id("dead"), [0u8; 32]);
    }

    #[test]
    fn dmap_old_core_cheque_rejected_when_pinned() {
        // The fix (2026-06-17): registration now pins to the NODE's canonical
        // CoreID, not the receipt's self-declared one. A cheque produced by an
        // OLD Core (attestation.core_id = old) is rejected once the node is
        // pinned to the CURRENT canonical — the cross-Core registration that the
        // old self-referential check let through is now closed.
        let old_core = [0x11; 32];                 // cheque from a previous Core
        let current_canonical = [0x22; 32];        // node's welded canonical
        let (ws, _) = make_dmap_witness_sig(old_core, [0xBB; 32], [0xCC; 32]);
        let new_state = [0x01; 32];
        let result = verify_zkp_proofs(&[ws], &current_canonical, &new_state);
        assert!(result.is_err(), "old-Core cheque must be rejected when node is pinned");
    }

    #[test]
    fn group_register_share_bps_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (mut greg, deed) = make_group_registration(0xEE, 0x00, 0x01);
        // Change share_bps so they don't sum to 10000 (5000+3000+1000 = 9000)
        greg.members[2].share_bps = 1000;

        let result = process_group_registration(
            &mut smt, &mut wal, &mut bans, &greg, &deed, 1, &mut deed_collected,
            &crate::crypto::NoopSigner,
        );

        assert!(matches!(result, Err(NablaError::GroupChecksumFailed)),
            "share_bps not summing to 10000 should fail");
    }

    // ── Real-signer register fixtures ───────────────────────────────
    //
    // Shared by the held-head-behind (6a / KI#68) tests and the receipt
    // tests below. They use a REAL Ed25519 signer (not NoopSigner) so the
    // signature checks are genuinely exercised — a forged sig MUST be
    // caught. (The KI#5 `partial_bridge` tests that used to live here were
    // deleted with the bridge, 2026-10-02.)

    use crate::crypto::{Ed25519Signer, Signer as _};

    /// A test validator: a real Ed25519 keypair.
    struct TestValidator {
        signer: Ed25519Signer,
        pk: [u8; 32],
    }
    impl TestValidator {
        fn new(idx: usize) -> Self {
            let signer = Ed25519Signer::from_node_index(idx);
            let pk = signer.public_key_bytes();
            Self { signer, pk }
        }
    }

    /// Build a `K3WitnessSig` where `signature` is a real Ed25519 sig
    /// over `receipt_sign_payload(wallet_id, consumed, tick)`.
    fn signed_k3_sig(
        v: &TestValidator,
        wallet_id: &[u8; 32],
        consumed: &[u8; 32],
        _txid: &[u8; 32],
        tick: u64,
    ) -> WitnessSig {
        let payload = crypto::receipt_sign_payload(wallet_id, consumed, tick);
        WitnessSig {
            validator_pk: v.pk,
            signature: v.signer.sign(&payload),
            execution_proof: vec![],
            proof_type: 0,
            receipt_commitment_sig: vec![],
            validator_id: [0u8; 32],
            slot_amount: 0,
        }
    }

    /// Build a registration whose main `receipt` is k=3-signed with real
    /// keys, anchored at `consumed -> produced`.
    fn signed_registration(
        validators: &[TestValidator],
        wid_byte: u8,
        consumed: [u8; 32],
        produced: [u8; 32],
    ) -> (Registration, DeedTransaction) {
        signed_registration_at_seq(validators, wid_byte, consumed, produced, 0)
    }

    /// `signed_registration` with an explicit `new_wallet_seq` — set BEFORE the
    /// receipt-commitment sigs are made, so the SeqProof attests it.
    fn signed_registration_at_seq(
        validators: &[TestValidator],
        wid_byte: u8,
        consumed: [u8; 32],
        produced: [u8; 32],
        new_wallet_seq: u64,
    ) -> (Registration, DeedTransaction) {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = wid_byte;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = wid_byte;
        tx_hash[1] = produced[0];
        tx_hash[2] = 0xEE;

        let signatures: Vec<WitnessSig> = validators
            .iter()
            .map(|v| signed_k3_sig(v, &wallet_id, &consumed, &tx_hash, 0))
            .collect();

        let reg = Registration {
            declared_balance: 0,
            declared_hibernation_until: 0,
            declared_wall_clock_lock: 0,
            declared_emission_claimed_epoch: 0,
            declared_stake_floor_until: 0,
            declared_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
            fob_claim: None,
            k_tier: 3,
            is_recall: false,
            wallet_id,
            old_state: consumed,
            new_state: produced,
            tx_hash,
            receipt: K3Receipt {
                sender_state: None,
                oods_flag: None,
                confidence_index: None,
                consumed_state_id: consumed,
                produced_state_id: produced,
                amount: 100,
                signatures,
                program_digest: [0u8; 32],
                tick: 0,
                state_hash: [0u8; 32],
                new_wallet_seq,
                commitment_hash: [0u8; 32],
                epoch: 0,
                fee_breakdown: vec![],
            is_dev_class: false,
            },
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
            is_genesis_claim: false,
            is_hal_reanchor: false,
            claimant_wallet_id: String::new(),
            is_dev_claim: false,
            burn_target_tx_id: None,
            // ForkSettlement wave 2a — zero-pk fixture: door 5b′ does not run (group
            // carve-out), and no WITNESS_V2 preimage reproduces this arbitrary tx_hash.
            preimage: crate::types::test_legs::opaque_redeem_leg(),
        };
        let deed = DeedTransaction {
            sender_wallet_id: wallet_id,
            receiver_wallet_id: DEED_PROTOCOL_WALLET_ID,
            amount: DEED_WRITE_FEE,
            signature: vec![0xFF; 64],
        };
        // §5.2.4 (KI#123): real witness rounds ALWAYS sign the receipt
        // commitment, and §8 now refuses a head it cannot derive a retainable
        // SeqProof from — so the fixture signs it too, with each validator's
        // OWN key (validator_pk stays consistent with the witness signature).
        let mut reg = reg;
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            &reg.tx_hash,
            &reg.receipt.state_hash,
            reg.receipt.new_wallet_seq,
            &reg.receipt.commitment_hash,
            reg.receipt.epoch,
            reg.receipt.is_dev_class,
            reg.receipt.oods_flag.as_ref(),
            None,
            reg.receipt.sender_state.as_ref(),
        );
        for (v, ws) in validators.iter().zip(reg.receipt.signatures.iter_mut()) {
            ws.receipt_commitment_sig = v.signer.sign(&commitment);
        }
        (reg, deed)
    }

    fn st(b: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = b;
        s
    }

    /// Seed the SMT with a wallet pinned at state `x` (seq 0) — a held
    /// head BEHIND the register's `old_state`.
    fn smt_pinned_at(
        smt: &mut SparseMerkleTree,
        wallet_id: [u8; 32],
        x: [u8; 32],
    ) {
        let entry = NablaEntry {
                        received_from: None,
                        wallet_seq: 0,
            wallet_id,
            current_state: x,
            tx_hash: { let mut t = [0u8; 32]; t[0] = 0xA0; t },
            tick: 1,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
        };
        smt.put(&entry);
    }

    #[test]
    fn held_head_behind_without_seq_advance_rejects_state_mismatch() {
        // 6a: the held head is BEHIND reg.old_state and the register does NOT
        // carry a strictly-newer attested seq (both at 0) → the KI#68 adopt
        // declines (`seq_newer` false) and the register is a hard
        // StateMismatch. (Was the KI#5 "None bridge" guard; the bridge arm is
        // gone, this decline path is what remains.)
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let signer = Ed25519Signer::from_node_index(999);

        let (x, p, h) = (st(0x01), st(0x02), st(0x03));
        let heal_vals: Vec<TestValidator> =
            (10..13).map(TestValidator::new).collect();
        let (reg, deed) = signed_registration(&heal_vals, 0xC5, p, h);

        smt_pinned_at(&mut smt, reg.wallet_id, x);

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            5, crate::types::test_legs::NOW_SECS, &mut deed_collected, &signer, &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None,
        );
        assert!(matches!(result, Err(NablaError::StateMismatch)),
            "out-of-sync register without a seq advance must reject StateMismatch");
    }

    /// A k-witnessed FACT link `prev -> new` signed by `keys` (real ML-DSA-65
    /// over Core's ONE `compute_fact_commitment` builder), never registered —
    /// i.e. a scar until something resolves it.
    fn dilithium_link(
        keys: &[(Vec<u8>, Vec<u8>)],
        tx_id: [u8; 32],
        prev: [u8; 32],
        new: [u8; 32],
    ) -> axiom_core_logic::types::FactLink {
        let witnesses = keys.iter().map(|(pk, sk)| axiom_core_logic::types::FactWitness {
            validator_id: [0u8; 32],
            validator_pk: pk.clone(),
            signature: axiom_core_logic::compute::sign_fact_commitment(
                sk, &tx_id, &prev, &new, 10, None, false, 3, &[], None).unwrap(),
            vbc_hash: [0u8; 32],
        }).collect();
        axiom_core_logic::types::FactLink {
            tx_id, previous_state_id: prev, new_state_id: new, amount: 10, tick: 0,
            required_k: 3, witnesses,
            nabla_confirmation: None, burn_proof: None, burn_target_tx_id: None,
            sender_anchor: None, is_dev_class: false, recall_proof: None,
            out_of_order_confirmation: None,
            inherited_scar_txids: Vec::new(), inherited_scar_resolutions: Vec::new(),
            receiver_witness: None,
        }
    }

    #[test]
    fn ki59_scarred_gap_ooo_confirmed_then_wallet_resumes() {
        // Owner's point (2026-10-02, KI#5 partial-bridge deletion): with the
        // bridge gone, a wallet whose Nabla head is BEHIND by SEVERAL
        // unregistered (scarred) k-witnessed transactions must still recover.
        // Each scarred link is confirmed OUT OF ORDER through the KI#59 path
        // (`OooConfirmRequest` → `ooo_confirm` [the binary's `ooo_confirm_core`
        // delegates here] → `build_ooo_confirmation`), in a shuffled order and
        // WITHOUT advancing the head; then the wallet's next k=3 register jumps
        // the held head across the whole gap (KI#68 adopt) and the wallet is
        // back to normal.
        //
        // MUTATIONS (each turns this RED): drop `smt.mark_ooo_attested` in
        // `ooo_confirm`; make `ooo_confirm` skip `verify_link_witness_quorum`;
        // force the KI#68 `seq_newer` guard false.
        use fips204::ml_dsa_65;
        use fips204::traits::SerDes;
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let signer = Ed25519Signer::from_node_index(998);
        let node_pk = signer.public_key_bytes();
        // This node's own NBC (subject = its Ed25519 key) — what
        // `build_ooo_confirmation` anchors the attestation to.
        let nbc = axiom_core_logic::types::VBC {
            genesis_lineage: [0u8; 32], network_size_baseline: 0, baseline_tick: 0,
            version: 0x09, validator_id: [0x5E; 32],
            subject_pubkey_sphincs: vec![0x5E; 32], subject_pubkey_dilithium: vec![0u8; 1952],
            subject_pubkey_ed25519: node_pk.to_vec(), pgp_fingerprint: vec![],
            node_name: String::new(), proof_cap: String::new(),
            issued_at: 1, expires_at: u64::MAX, chain_depth: 1,
            issuer_set: vec![vec![0x15; 32]], signatures: vec![vec![0x16; 64]],
            max_tx: 0, founding_vbc_hash: [0u8; 32], nabla_registration: None,
        };
        let own_nbc = crate::cc::serialize_nbc(&nbc);

        // The wallet's registered head: S0 at seq 0.
        let fact_keys: Vec<(Vec<u8>, Vec<u8>)> = (0..3).map(|_| {
            let (pk, sk) = ml_dsa_65::try_keygen().unwrap();
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        }).collect();
        let reg_vals: Vec<TestValidator> = (20..23).map(TestValidator::new).collect();
        let s = [st(0x40), st(0x41), st(0x42), st(0x43), st(0x44)];
        let (reg, deed) = signed_registration_at_seq(&reg_vals, 0xD7, s[3], s[4], 4);
        smt_pinned_at(&mut smt, reg.wallet_id, s[0]);

        // Three k-witnessed transitions S0→S1→S2→S3 that never registered.
        let mut links: Vec<_> = (0..3).map(|i| {
            dilithium_link(&fact_keys, st(0xA0 + i as u8), s[i], s[i + 1])
        }).collect();
        assert!(links.iter().all(|l| !l.is_resolved()), "precondition: all three are scars");

        // A garbage / under-witnessed link is refused and marks nothing.
        let mut few = links[0].clone();
        few.witnesses.truncate(2);
        let refused = ooo_confirm(
            &crate::wire_client::OooConfirmRequest { link: few }, &mut smt, &own_nbc, 7, &signer);
        assert_eq!(refused.status, "UNDERWITNESSED");
        assert!(refused.attestation.is_none());
        assert!(!smt.is_txid_ooo_attested(&links[0].tx_id),
            "a refused request must not mark the txid");

        // Confirm each scar OUT OF ORDER (2, 0, 1).
        for &i in &[2usize, 0, 1] {
            let resp = ooo_confirm(
                &crate::wire_client::OooConfirmRequest { link: links[i].clone() },
                &mut smt, &own_nbc, 7 + i as u64, &signer);
            assert_eq!(resp.status, "OK", "link {i}: {}", resp.error);
            let att = resp.attestation.expect("OK carries the attestation");
            // Bound to exactly THIS link (txid + new state) and signed by this node.
            assert_eq!(att.txid, links[i].tx_id);
            assert_eq!(att.new_state_id, links[i].new_state_id);
            assert_eq!(att.nabla_node_pk, node_pk);
            let payload = axiom_core_logic::compute::compute_ooo_confirmation_payload(
                &att.txid, &att.new_state_id, att.nabla_tick);
            assert!(axiom_core_logic::verify::verify_ed25519(
                &att.nabla_node_pk, &payload, &att.nabla_signature).is_ok());
            assert!(att.nbc_commitment.windows(32).any(|w| w == node_pk),
                "the NBC commitment names the attesting key");
            assert!(smt.is_txid_ooo_attested(&links[i].tx_id));
            // NO head advance — the held head is still S0 after every confirm.
            assert_eq!(smt.get(&reg.wallet_id).unwrap().current_state, s[0],
                "an out-of-order confirm must not move the head");
            links[i].out_of_order_confirmation = Some(att);
        }
        // Every scar now carries its own-resolving confirmation (the structural
        // form; Core's `link_is_resolved` additionally walks the NBC root —
        // covered in core/logic fact.rs `verify_ooo_confirmation_*`).
        assert!(links.iter().all(|l| l.is_resolved()), "all three scars resolved");

        // The wallet's next k=3 transition S3→S4 (seq 4) registers: the held
        // head (S0, seq 0) is three links behind, and the KI#68 adopt takes it.
        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            9, crate::types::test_legs::NOW_SECS, &mut deed_collected, &signer,
            &crate::types::test_legs::dir_admits_all, None, None, None, None, None, None, None, None,
        );
        assert!(result.is_ok(), "the resumed register must be accepted: {:?}", result.err());
        let head = smt.get(&reg.wallet_id).unwrap();
        assert_eq!(head.current_state, s[4], "head jumped across the whole gap");
        assert_eq!(head.wallet_seq, 4);
        assert_eq!(head.status, WalletStatus::Normal, "the wallet is back to normal");
        assert!(!bans.is_banned(&reg.wallet_id));
    }

    #[test]
    fn group_register_state_mismatch_rejects_without_banning() {
        // RENAMED + INVERTED from `group_register_double_spend_bans`
        // (2026-08-07, ghost audit G3). The old test asserted
        // `bans.is_banned(...)` — it encoded the BUG as the contract.
        //
        // YPX-002 §3.3 is explicit: a local `current_state != old_state`
        // mismatch returns an error, NOT a ban, because it "only proves that
        // THIS node has not yet observed the intermediate state — which is
        // normal during gossip propagation". §7.4/§7.5 reserve a ban for two
        // independently-valid k=3 registrations with the same `old_state` and
        // different `new_state`, which is the gossip-merge path's job.
        //
        // The personal path has always done this correctly; only the group path
        // banned, and it banned PERMANENTLY (`BanStatus` has only `Active`) on a
        // `ConflictProof` with a zeroed `old_state` and no signatures — evidence
        // `verify_conflict` rejects 100% of the time.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let (greg1, deed1) = make_group_registration(0xEE, 0x00, 0x01);
        process_group_registration(
            &mut smt, &mut wal, &mut bans, &greg1, &deed1, 1, &mut deed_collected,
            &crate::crypto::NoopSigner,
        ).unwrap();

        // Second register against the SAME old_state — a stale view, or a fraud
        // attempt. Either way /register cannot tell them apart, so it rejects.
        let (greg2, deed2) = make_group_registration(0xEE, 0x00, 0x02);
        let result = process_group_registration(
            &mut smt, &mut wal, &mut bans, &greg2, &deed2, 2, &mut deed_collected,
            &crate::crypto::NoopSigner,
        );

        assert!(matches!(result, Err(NablaError::StateMismatch)),
            "YPX-002 §3.3: a /register state mismatch is an ERROR, got {result:?}");
        assert!(!bans.is_banned(&greg1.wallet_id),
            "YPX-002 false-ban: a group wallet must NOT be permanently banned for \
             a condition §3.3 calls normal during gossip propagation");
        assert_eq!(smt.get(&greg1.wallet_id).unwrap().current_state[0], 0x01,
            "the held head is untouched by the rejected register");
    }

    // ── FACT class isolation — genesis-claim defense in depth ──────

    /// Build a genesis-claim Registration whose `claimant_wallet_id` is
    /// PROPERLY pk-bound to a deterministic test pk.
    fn make_genesis_claim_reg(
        email: &str,
        is_dev_claim: bool,
        pk_byte0: u8,
        new_state_byte: u8,
    ) -> (Registration, DeedTransaction, [u8; 32]) {
        use axiom_core_logic::wallet_id::generate_wallet_id;
        use ed25519_dalek::SigningKey;
        // KI#53: a REAL keypair, not `pk[0] = byte` with 31 zero bytes. The
        // register path now verifies the wallet's authorship signature (as the
        // flood and anti-entropy paths already did), and an unsignable fake key
        // cannot produce one — the fixture was building a registration the mesh
        // would refuse from any peer, which is precisely the state this gate
        // exists to keep out of the SMT.
        let sk = SigningKey::from_bytes(&[pk_byte0; 32]);
        let pk = sk.verifying_key().to_bytes();
        let salt_hash = blake3::hash(&pk);
        let salt = &hex::encode(salt_hash.as_bytes())[..2];
        let claimant_wallet_id = generate_wallet_id(email, salt, &pk).unwrap();
        let (mut reg, deed) = make_valid_registration(pk_byte0, 0x00, new_state_byte);
        reg.wallet_id = pk;
        // Class-defense layer (1) binds `claimant_wallet_id` to the
        // registrant's REAL key — `client_pk`, not the opaque SMT key
        // (`wallet_id`), which is tier-derived since the single-keypair
        // collision fix and no longer bytes-equal to any pk.
        reg.client_pk = pk;
        reg.is_genesis_claim = true;
        reg.claimant_wallet_id = claimant_wallet_id;
        reg.is_dev_claim = is_dev_claim;
        // ForkSettlement wave 2a — an authored register must carry a GENUINE
        // leg (door step 5b′): derive commitment_hash + tx_hash from the claim's
        // preimage, then sign the state exactly as the SDK does — over the SMT
        // BUCKET, using Core's single payload builder (inside `bind_send_leg`).
        bind_send_leg(&mut reg, &sk, 1);
        (reg, deed, pk)
    }

    /// §5.2.3a — a tier-3 claim draws the BOOTSTRAP pool and leaves the airdrop
    /// alone, decided by the Core-pinned amount on the k-attested receipt.
    ///
    /// WHY THIS TEST EXISTS SEPARATELY FROM
    /// `subsidy_class_constants_match_the_amounts_actually_claimed` (node.rs):
    /// that one drives `try_validator_join_claim`, whose ONLY production caller
    /// is `fact_confirm_core` — and those arms never fire, because they are
    /// guarded by `!wallet_already_exists` and the primary register writes the
    /// wallet to the SMT first. So the invariant it protects was being asserted
    /// on a path that does not run. Its own failure message names the exact
    /// consequence: "JUDOON would be policing a pool that is not the one
    /// draining." That is what happened. This drives the LIVE path.
    ///
    /// It also pins the JUDOON coherence property directly: the debit must equal
    /// the drawn pool's DECLARED `claim_amount()`, because that declaration is
    /// what JUDOON measures the pool against (`with_class_constants`, ecea2d9e).
    #[test]
    fn tier3_claim_draws_bootstrap_and_leaves_the_airdrop_alone() {
        use crate::judoon::DrainOnlyPool;
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        let mut airdrop = crate::node::AirdropPool::new(
            2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let mut dev_treasury = crate::node::DevTreasuryPool::new(
            2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let mut bootstrap = crate::node::AirdropPool::new(
                crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS)
            .with_class_constants(
                crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS,
                axiom_core_logic::types::TIER3_CLAIM_ATOMS);
        let mut foundation = crate::node::AirdropPool::new(
                crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS)
            .with_class_constants(
                crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS,
                axiom_core_logic::types::TIER2_CLAIM_ATOMS);

        let declared = bootstrap.claim_amount();
        let (airdrop_before, boot_before, found_before) =
            (airdrop.balance(), bootstrap.balance(), foundation.balance());

        // The ONLY difference from a genesis claim: the k-attested receipt
        // carries the tier-3 floor, which is what Core pinned for that kind.
        let (mut reg, deed, _pk) = make_genesis_claim_reg("v@example.com", false, 0xB7, 0x01);
        reg.receipt.amount = axiom_core_logic::types::TIER3_CLAIM_ATOMS;

        process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            Some(&mut airdrop), Some(&mut dev_treasury),
            Some(&mut bootstrap), Some(&mut foundation),
            None, None, None, None,
        ).expect("tier-3 subsidy claim must succeed");

        let debited = boot_before - bootstrap.balance();
        assert_eq!(
            debited, axiom_core_logic::types::TIER3_CLAIM_ATOMS,
            "tier-3 claim debited {debited}, expected the tier-3 floor",
        );
        assert_eq!(
            debited, declared,
            "debited {debited} but Bootstrap declares {declared} per claim — JUDOON \
             would be policing a pool that is not the one draining",
        );
        assert_eq!(
            airdrop.balance(), airdrop_before,
            "the AIRDROP pool moved on a tier-3 claim. That is the 2026-09-02 defect: \
             the airdrop paid 1 AXC while Core minted 500, and every instrument read \
             clean because a pool draining its own declared amount looks perfect.",
        );
        assert_eq!(airdrop.local_claims, 0, "no airdrop claim should be counted");
        assert_eq!(foundation.balance(), found_before, "tier-3 must not touch Foundation");
    }

    #[test]
    fn test_public_claim_deducts_airdrop_pool() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let mut airdrop = crate::node::AirdropPool::new(2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let mut dev_treasury = crate::node::DevTreasuryPool::new(2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let (reg, deed, _pk) = make_genesis_claim_reg("alice@example.com", false, 0xA0, 0x01);
        process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, None, None,
        ).expect("public genesis claim must succeed");
        assert_eq!(airdrop.local_claims, 1, "public claim deducts Airdrop only");
        assert_eq!(dev_treasury.local_claims, 0);
    }

    #[test]
    fn test_dev_claim_deducts_dev_treasury_pool() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let mut airdrop = crate::node::AirdropPool::new(2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let mut dev_treasury = crate::node::DevTreasuryPool::new(2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let (reg, deed, _pk) = make_genesis_claim_reg("developer@axiom.internal", true, 0xD0, 0x01);
        process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, None, None,
        ).expect("dev genesis claim must succeed");
        assert_eq!(airdrop.local_claims, 0);
        assert_eq!(dev_treasury.local_claims, 1, "dev claim deducts DevTreasury only");
    }

    #[test]
    fn test_signal_mismatch_dev_wallet_with_public_flag_rejected() {
        // Defense in depth case A: dev wallet, forged is_dev_claim=false.
        // Without the cross-check, Airdrop would deduct public AXC to a
        // dev wallet (public->dev leak). Mismatch rejects entirely.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let mut airdrop = crate::node::AirdropPool::new(2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let mut dev_treasury = crate::node::DevTreasuryPool::new(2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let (reg, deed, _pk) = make_genesis_claim_reg("developer@axiom.internal", false, 0xD1, 0x01);
        let err = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, None, None,
        ).expect_err("dev wallet with public flag must reject");
        assert!(matches!(err, NablaError::ClassSignalMismatch));
        assert_eq!(airdrop.local_claims, 0, "no pool moves on rejection");
        assert_eq!(dev_treasury.local_claims, 0);
    }

    #[test]
    fn test_signal_mismatch_public_wallet_with_dev_flag_rejected() {
        // Defense in depth case B: public wallet, forged is_dev_claim=true.
        // This is the leak from dev->public we explicitly defend against.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let mut airdrop = crate::node::AirdropPool::new(2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let mut dev_treasury = crate::node::DevTreasuryPool::new(2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let (reg, deed, _pk) = make_genesis_claim_reg("alice@example.com", true, 0xA1, 0x01);
        let err = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, None, None,
        ).expect_err("public wallet with dev flag must reject");
        assert!(matches!(err, NablaError::ClassSignalMismatch));
        assert_eq!(airdrop.local_claims, 0);
        assert_eq!(dev_treasury.local_claims, 0);
    }

    #[test]
    fn test_forged_wallet_id_string_not_pk_bound_rejected() {
        // Defense in depth crypto anchor: attacker pastes a dev
        // wallet_id string onto a register whose pk is unrelated.
        // verify_pk_binding fails -> reject before any pool moves.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let mut airdrop = crate::node::AirdropPool::new(2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let mut dev_treasury = crate::node::DevTreasuryPool::new(2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let (mut reg, deed, _pk) = make_genesis_claim_reg("developer@axiom.internal", true, 0xD2, 0x01);
        reg.client_pk = [0xFFu8; 32];  // a key that didn't produce this wallet_id string
        // KI#226: keep the SMT id the new key's own row, so the door's step 0b
        // passes and THIS test still exercises the class anchor (1).
        reg.wallet_id = reg.client_pk;
        let err = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, None, None,
        ).expect_err("forged wallet_id (not pk-bound) must reject");
        assert!(matches!(err, NablaError::ClassSignalMismatch));
        assert_eq!(airdrop.local_claims, 0);
        assert_eq!(dev_treasury.local_claims, 0);
    }

    #[test]
    fn test_dev_pool_exhaustion_hard_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let mut airdrop = crate::node::AirdropPool::new(2 * axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let mut dev_treasury = crate::node::DevTreasuryPool::new(axiom_core_logic::types::GENESIS_CLAIM_AMOUNT);
        let (reg1, deed1, _pk1) = make_genesis_claim_reg("dev1@axiom.internal", true, 0xD3, 0x01);
        process_registration(
            &mut smt, &mut wal, &mut bans, &reg1, &deed1,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, None, None,
        ).expect("first dev claim must succeed");
        assert_eq!(dev_treasury.balance(), 0, "pool drained");

        let (reg2, deed2, _pk2) = make_genesis_claim_reg("dev2@axiom.internal", true, 0xD4, 0x01);
        let err = process_registration(
            &mut smt, &mut wal, &mut bans, &reg2, &deed2,
            2, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, None, None,
        ).expect_err("exhausted dev pool must hard-reject");
        assert!(matches!(err, NablaError::PoolExhausted));
        assert_eq!(airdrop.local_claims, 0, "public pool untouched");
    }

    // ── KI#250 — the genesis-claim pool debit sits at the head write ───────
    //
    // Before KI#250 the door debited the pool right after the two class
    // checks, BEFORE any signature was verified, and nothing refunded it when
    // a later step refused (pool debits are strict-decrease, PoolSync spreads
    // them mesh-wide each heartbeat): 5 unsigned registers emptied Foundation.
    // These tests assert the FULL ledger tuple of all four pools — not just
    // `local_claims` — so a debit that is "undone" in one counter but not
    // another cannot pass.

    /// (balance, total_claims, local_claims, claims_this_cycle, paid_out) for
    /// airdrop, dev-treasury, bootstrap, foundation. DevTreasury has no
    /// `paid_out` counter — its slot is reported as 0.
    type Ki250Ledger = [(u64, u64, u64, u64, u64); 4];

    struct Ki250Pools {
        airdrop: crate::node::AirdropPool,
        dev: crate::node::DevTreasuryPool,
        boot: crate::node::AirdropPool,
        found: crate::node::AirdropPool,
    }

    impl Ki250Pools {
        fn new() -> Self {
            use axiom_core_logic::types::{GENESIS_CLAIM_AMOUNT, TIER2_CLAIM_ATOMS, TIER3_CLAIM_ATOMS};
            Self {
                airdrop: crate::node::AirdropPool::new(4 * GENESIS_CLAIM_AMOUNT),
                dev: crate::node::DevTreasuryPool::new(4 * GENESIS_CLAIM_AMOUNT),
                boot: crate::node::AirdropPool::new(crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS)
                    .with_class_constants(crate::constants::BOOTSTRAP_POOL_INITIAL_ATOMS, TIER3_CLAIM_ATOMS),
                found: crate::node::AirdropPool::new(crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS)
                    .with_class_constants(crate::constants::FOUNDATION_BOOTSTRAP_POOL_INITIAL_ATOMS, TIER2_CLAIM_ATOMS),
            }
        }

        fn ledger(&self) -> Ki250Ledger {
            let a = |p: &crate::node::AirdropPool| {
                (p.balance(), p.total_claims, p.local_claims, p.claims_this_cycle, p.paid_out())
            };
            let d = &self.dev;
            [
                a(&self.airdrop),
                (d.balance(), d.total_claims, d.local_claims, d.claims_this_cycle, 0),
                a(&self.boot),
                a(&self.found),
            ]
        }

        fn register(
            &mut self,
            smt: &mut SparseMerkleTree,
            wal: &mut WriteAheadLog,
            reg: &Registration,
            deed: &DeedTransaction,
            is_witness: &dyn Fn(&[u8; 32]) -> bool,
        ) -> Result<RegistrationResult, NablaError> {
            let mut bans = BanTable::new();
            let mut deed_collected = 0u64;
            process_registration(
                smt, wal, &mut bans, reg, deed,
                1, crate::types::test_legs::NOW_SECS, &mut deed_collected,
                &crate::crypto::NoopSigner, is_witness,
                Some(&mut self.airdrop), Some(&mut self.dev),
                Some(&mut self.boot), Some(&mut self.found),
                None, None, None, None,
            )
        }
    }

    /// The three amounts that select the three public pools (airdrop,
    /// Bootstrap, Foundation), with the index of the pool each one draws.
    fn ki250_amounts() -> [(u64, usize, &'static str); 3] {
        use axiom_core_logic::types::{GENESIS_CLAIM_AMOUNT, TIER2_CLAIM_ATOMS, TIER3_CLAIM_ATOMS};
        [
            (GENESIS_CLAIM_AMOUNT, 0, "airdrop"),
            (TIER3_CLAIM_ATOMS, 2, "bootstrap"),
            (TIER2_CLAIM_ATOMS, 3, "foundation"),
        ]
    }

    /// Drive one refused drain attempt per amount and assert every pool's
    /// full ledger is byte-unchanged.
    fn ki250_assert_refused_drain_moves_nothing(
        label: &str,
        mutate: &dyn Fn(&mut Registration),
        is_witness: &dyn Fn(&[u8; 32]) -> bool,
        expect: &dyn Fn(&NablaError) -> bool,
    ) {
        for (i, (amount, _, pool)) in ki250_amounts().into_iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            let mut smt = SparseMerkleTree::new();
            let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
            let mut pools = Ki250Pools::new();
            let before = pools.ledger();
            // A self-made key: the attacker controls every field below.
            let (mut reg, deed, _pk) =
                make_genesis_claim_reg("drain@example.com", false, 0x50 + i as u8, 0x01);
            reg.receipt.amount = amount;
            mutate(&mut reg);
            let r = pools.register(&mut smt, &mut wal, &reg, &deed, is_witness);
            let err = r.err().unwrap_or_else(|| panic!("{label}/{pool}: the drain register must be refused"));
            assert!(expect(&err), "{label}/{pool}: wrong refusal {err:?}");
            assert_eq!(
                pools.ledger(), before,
                "KI#250 {label}/{pool}: a REFUSED register moved a pool ledger — the debit \
                 runs before this refusal and is irrevocable (strict-decrease + PoolSync), \
                 so unsigned messages drain the pool mesh-wide",
            );
        }
    }

    #[test]
    fn ki250_drain_with_self_made_keys_refused_at_step5_leaves_every_pool_unchanged() {
        // `NoopSigner::verify` is always true, so step 5 is reached through its
        // COUNT check: fewer than max(k, 3) receipt signatures.
        ki250_assert_refused_drain_moves_nothing(
            "step5",
            &|reg| reg.receipt.signatures.truncate(2),
            &crate::types::test_legs::dir_admits_all,
            &|e| matches!(e, NablaError::InvalidReceipt),
        );
    }

    #[test]
    fn ki250_drain_refused_at_5b4_witness_not_in_directory_leaves_every_pool_unchanged() {
        ki250_assert_refused_drain_moves_nothing(
            "step5b4",
            &|_| {},
            &|_| false,
            &|e| matches!(e, NablaError::WitnessNotInDirectory(_)),
        );
    }

    #[test]
    fn ki250_drain_refused_at_step4_state_mismatch_leaves_every_pool_unchanged() {
        ki250_assert_refused_drain_moves_nothing(
            "step4",
            &|reg| reg.new_state[0] ^= 1,
            &crate::types::test_legs::dir_admits_all,
            &|e| matches!(e, NablaError::StateMismatch),
        );
    }

    /// The expected ledger after exactly ONE grant of `amount` from pool `idx`.
    fn ki250_one_debit(before: Ki250Ledger, idx: usize, amount: u64) -> Ki250Ledger {
        let mut want = before;
        let (b, t, l, c, p) = want[idx];
        let paid = if idx == 1 { 0 } else { p + amount };
        want[idx] = (b - amount, t + 1, l + 1, c + 1, paid);
        want
    }

    #[test]
    fn ki250_honest_claim_debits_exactly_once() {
        for (i, (amount, idx, pool)) in ki250_amounts().into_iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            let mut smt = SparseMerkleTree::new();
            let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
            let mut pools = Ki250Pools::new();
            let before = pools.ledger();
            let (mut reg, deed, _pk) =
                make_genesis_claim_reg("honest@example.com", false, 0x60 + i as u8, 0x01);
            reg.receipt.amount = amount;
            pools.register(&mut smt, &mut wal, &reg, &deed, &crate::types::test_legs::dir_admits_all)
                .unwrap_or_else(|e| panic!("{pool}: honest claim must succeed, got {e:?}"));
            assert_eq!(pools.ledger(), ki250_one_debit(before, idx, amount),
                "{pool}: an honest claim must debit its own pool exactly once and no other");
        }
    }

    #[test]
    fn ki250_refused_then_retried_claim_debits_exactly_once() {
        // The honest KI#224 path: node's directory has not admitted a witness
        // yet → refused (retryable); the same claim then succeeds.
        for (i, (amount, idx, pool)) in ki250_amounts().into_iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            let mut smt = SparseMerkleTree::new();
            let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
            let mut pools = Ki250Pools::new();
            let before = pools.ledger();
            let (mut reg, deed, _pk) =
                make_genesis_claim_reg("retry@example.com", false, 0x70 + i as u8, 0x01);
            reg.receipt.amount = amount;
            let r1 = pools.register(&mut smt, &mut wal, &reg, &deed, &|_| false);
            assert!(matches!(r1, Err(NablaError::WitnessNotInDirectory(_))), "{pool}: {r1:?}");
            assert_eq!(pools.ledger(), before, "{pool}: the refused attempt must not debit");
            pools.register(&mut smt, &mut wal, &reg, &deed, &crate::types::test_legs::dir_admits_all)
                .unwrap_or_else(|e| panic!("{pool}: retry must succeed, got {e:?}"));
            assert_eq!(pools.ledger(), ki250_one_debit(before, idx, amount),
                "{pool}: refused-then-granted must debit exactly once");
        }
    }

    #[test]
    fn ki250_lost_ack_retry_does_not_debit_again() {
        // Step 5d: the same granted claim resubmitted after its RegisterAck was
        // lost returns Ok as an idempotent no-op. Before KI#250 the debit ran
        // above 5d, so every lost-ACK retry of a genesis claim debited twice.
        for (i, (amount, idx, pool)) in ki250_amounts().into_iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            let mut smt = SparseMerkleTree::new();
            let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
            let mut pools = Ki250Pools::new();
            let before = pools.ledger();
            let (mut reg, deed, _pk) =
                make_genesis_claim_reg("lostack@example.com", false, 0x80 + i as u8, 0x01);
            reg.receipt.amount = amount;
            for attempt in 1..=2 {
                pools.register(&mut smt, &mut wal, &reg, &deed, &crate::types::test_legs::dir_admits_all)
                    .unwrap_or_else(|e| panic!("{pool}: attempt {attempt} must be Ok, got {e:?}"));
            }
            assert_eq!(pools.ledger(), ki250_one_debit(before, idx, amount),
                "KI#250 {pool}: a lost-ACK retry (step 5d) debited the pool a SECOND time");
        }
    }

    #[test]
    fn ki250_pool_refusal_still_precedes_the_head_write() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("t.wal");
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(&wal_path).unwrap();
        let mut pools = Ki250Pools::new();
        pools.airdrop = crate::node::AirdropPool::new(0);
        let before = pools.ledger();
        let (reg, deed, pk) = make_genesis_claim_reg("late@example.com", false, 0x90, 0x01);
        let r = pools.register(&mut smt, &mut wal, &reg, &deed, &crate::types::test_legs::dir_admits_all);
        assert!(matches!(r, Err(NablaError::PoolExhausted)), "exhausted pool must refuse, got {r:?}");
        assert_eq!(pools.ledger(), before);
        let bucket = smt_bucket(&pk, reg.k_tier);
        assert!(smt.get(&bucket).is_none(), "a pool-refused claim must not leave a head in the SMT");
        drop(wal);
        let ops = WriteAheadLog::read_all(&wal_path).unwrap();
        assert!(
            !ops.iter().any(|op| matches!(op, WalOp::Put { key, .. } if *key == bucket)),
            "a pool-refused claim must not leave a WAL Put for its bucket",
        );
    }

    // ───────────────────────────────────────────────────────────────────
    // YP §19.6 — /register fee_breakdown chain verification + persistence
    // ───────────────────────────────────────────────────────────────────

    use axiom_core_logic::types::FeeShare;
    use crate::wal::{WriteAheadLog, WalOp};
    use crate::node::{AirdropPool, DevTreasuryPool};

    /// Build a fee-carrying signed registration. Receipt fields are bound
    /// into receipt_commitment exactly as Core CL3 would; receipt_commitment_sig
    /// is each validator's real Ed25519 sig over that commitment.
    fn fee_registration(
        validators: &[TestValidator],
        wid_byte: u8,
        consumed: [u8; 32],
        produced: [u8; 32],
        amount: u64,
        fee_breakdown: Vec<FeeShare>,
    ) -> (Registration, DeedTransaction) {
        fee_registration_with_class(
            validators, wid_byte, consumed, produced, amount, fee_breakdown, false,
        )
    }

    /// Class-aware variant of `fee_registration`.  Same skeleton, but
    /// folds `is_dev_class` into the receipt commitment so the chain of
    /// k=3 sigs binds the flag — and dev-class routing tests can drive
    /// it.  Public callers use `fee_registration(..)` (which delegates
    /// here with `false`) so existing tests stay byte-identical.
    fn fee_registration_with_class(
        validators: &[TestValidator],
        wid_byte: u8,
        consumed: [u8; 32],
        produced: [u8; 32],
        amount: u64,
        fee_breakdown: Vec<FeeShare>,
        is_dev_class: bool,
    ) -> (Registration, DeedTransaction) {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = wid_byte;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = wid_byte;
        tx_hash[1] = produced[0];
        tx_hash[2] = 0xFE; // distinct from the existing helper's 0xEE

        // Pinned values that will be hashed into receipt_commitment;
        // SDK Step 7 will source these from Core's PublicOutputs.
        //
        // ⚠ DERIVED, not an arbitrary constant (KI#132). This was `[0x33; 32]`,
        // which stopped being a valid fixture the moment Nabla began recomputing
        // `compute_state_hash` from the declared fields: an arbitrary hash with
        // zero declared values describes a wallet that is LYING about its own
        // state, and six fee/deed tests correctly began failing `InvalidReceipt`.
        // They are meant to model an HONEST wallet, so the fixture now derives
        // the hash the same way an honest wallet would.
        let new_wallet_seq = 7;
        // ⚠ Hash the CLIENT_PK, which this fixture sets to [0u8; 32] — NOT
        // `wallet_id`. Nabla recomputes from `reg.client_pk`, so deriving from
        // the wrong key produces the same InvalidReceipt the zeros did.
        let state_hash = axiom_core_logic::compute::compute_state_hash(
            &[0u8; 32], 0, new_wallet_seq, 0, 0,
         0, 0, &axiom_core_logic::types::WalletFormat::CURRENT,
    );
        let commitment_hash = [0x77; 32];
        let epoch = 1_700_000_000;

        let _ = produced; // skeleton-only commitment no longer binds produced_state_id
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            &tx_hash,
            &state_hash,
            new_wallet_seq,
            &commitment_hash,
            epoch,
            is_dev_class, None, None,
            None,
        );

        let signatures: Vec<WitnessSig> = validators.iter().map(|v| {
            let _ = produced; // skeleton payload no longer binds produced_state
            let pay = crypto::receipt_sign_payload(&wallet_id, &consumed, 0);
            WitnessSig {
                validator_pk: v.pk,
                signature: v.signer.sign(&pay),
                execution_proof: vec![],
                proof_type: 0,
                // The closure of the chain — each validator signs the
                // canonical commitment that binds fee_breakdown.
                receipt_commitment_sig: v.signer.sign(&commitment),
                validator_id: [0u8; 32],
                slot_amount: 0,
            }
        }).collect();

        let reg = Registration {
            declared_balance: 0,
            declared_hibernation_until: 0,
            declared_wall_clock_lock: 0,
            declared_emission_claimed_epoch: 0,
            declared_stake_floor_until: 0,
            declared_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
            fob_claim: None,
            k_tier: 3,
            is_recall: false,
            wallet_id,
            old_state: consumed,
            new_state: produced,
            tx_hash,
            receipt: K3Receipt {
                sender_state: None,
                oods_flag: None,
                confidence_index: None,
                consumed_state_id: consumed,
                produced_state_id: produced,
                amount,
                signatures,
                program_digest: [0u8; 32],
                tick: 0,
                state_hash,
                new_wallet_seq,
                commitment_hash,
                epoch,
                fee_breakdown,
                is_dev_class,
            },
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
            is_genesis_claim: false,
            is_hal_reanchor: false,
            claimant_wallet_id: String::new(),
            is_dev_claim: false,
            burn_target_tx_id: None,
            // ForkSettlement wave 2a — zero-pk fixture: door 5b′ does not run (group
            // carve-out), and no WITNESS_V2 preimage reproduces this arbitrary tx_hash.
            preimage: crate::types::test_legs::opaque_redeem_leg(),
        };
        let deed = DeedTransaction {
            sender_wallet_id: wallet_id,
            receiver_wallet_id: DEED_PROTOCOL_WALLET_ID,
            amount: DEED_WRITE_FEE,
            signature: vec![0xFF; 64],
        };
        (reg, deed)
    }

    fn make_smt_hashmap_for_fees() -> SparseMerkleTree {
        SparseMerkleTree::with_txid_mode(crate::bloom::TxidServiceMode::Hashmap)
    }

    #[test]
    fn ki38_origin_retains_seq_proof_for_ae_attestation() {
        // KI#38: the ORIGIN node must retain the k=3 seq attestation for the
        // head it just committed, so its AE digest pushes carry a verifiable
        // proof. Pre-fix only flood/AE adopters retained one — under a lossy
        // flood the newest head was stranded at the origin (`seq-unattested
        // proof=ABSENT` on every AE push) and the mesh wedged at applied=0.
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let amount = 1_000_000u64;
        let cap = (amount * 30) / 10_000;
        let breakdown = vec![
            FeeShare { validator_id: [0x11; 32], amount: cap },
            FeeShare { validator_id: [0x22; 32], amount: cap },
            FeeShare { validator_id: [0x33; 32], amount: cap },
        ];
        let (reg, deed) = fee_registration(
            &validators, 0xAB, [0u8; 32], [0x02; 32], amount, breakdown,
        );

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;

        process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, None, None, None, None,
        ).expect("valid fee-carrying register must succeed");

        // The retained proof exists AND verifies for this head's (txid, seq) —
        // i.e., the origin can now attest its own head over anti-entropy.
        let proof = smt.seq_proof(&reg.wallet_id)
            .expect("origin must retain the seq proof it just verified (KI#38)");
        assert!(
            verify_seq_proof(proof, &reg.tx_hash, reg.receipt.new_wallet_seq),
            "retained proof must verify for the committed head"
        );
    }

    #[test]
    fn register_with_valid_fee_chain_writes_record_and_gossips() {
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let amount = 1_000_000u64;
        let cap = (amount * 30) / 10_000;
        let breakdown = vec![
            FeeShare { validator_id: [0x11; 32], amount: cap },
            FeeShare { validator_id: [0x22; 32], amount: cap },
            FeeShare { validator_id: [0x33; 32], amount: cap },
        ];
        let (reg, deed) = fee_registration(
            &validators, 0xAA, [0u8; 32], [0x01; 32], amount, breakdown.clone(),
        );

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, None, None, None, None,
        ).expect("valid fee-carrying register must succeed");

        // Per-tx record is in-memory.
        assert_eq!(smt.tx_records_len(), 1);
        let rec = smt.tx_record(&reg.tx_hash).expect("record must exist");
        assert_eq!(rec.amount, amount);
        assert_eq!(rec.fee_breakdown, breakdown);

        // WAL recorded the new RecordTx variant.
        let ops = WriteAheadLog::read_all(dir.path().join("wal.bin")).unwrap();
        let record_tx_count = ops.iter()
            .filter(|op| matches!(op, WalOp::RecordTx { .. }))
            .count();
        assert_eq!(record_tx_count, 1, "expected exactly one RecordTx in WAL");

        // Gossip carries the populated fee data.
        if let GossipMessage::StateUpdate { amount: a, fee_breakdown: fb, .. } = &result.gossip_msg {
            assert_eq!(*a, amount);
            assert_eq!(*fb, breakdown);
        } else {
            panic!("expected StateUpdate gossip");
        }
    }

    #[test]
    fn register_with_empty_fee_breakdown_skips_chain_check() {
        // Byte-identical to today's behaviour: no fee chain check, no
        // record, no WAL RecordTx — every existing send/heal/genesis
        // path is unaffected.
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let (reg, deed) = signed_registration(
            &validators, 0xBB, [0u8; 32], [0x02; 32],
        );

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, None, None, None, None,
        ).expect("empty-fee register must succeed");

        assert_eq!(smt.tx_records_len(), 0);
        if let GossipMessage::StateUpdate { fee_breakdown: fb, .. } = &result.gossip_msg {
            // Empty fee_breakdown ⇒ no-fee path, no record persisted.
            // The gossip's `amount` field still carries the TX amount
            // (it's orthogonal to fee_breakdown); only the breakdown
            // being empty signals "no fees on this TX".
            assert!(fb.is_empty());
        } else {
            panic!("expected StateUpdate gossip");
        }
    }

    #[test]
    fn register_with_over_cap_fee_breakdown_rejects() {
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let amount = 1_000_000u64;
        // 50 bps × 3 = 150 bps total > 90 bps aggregate cap.
        let over_cap_slot = (amount * 50) / 10_000;
        let breakdown = vec![
            FeeShare { validator_id: [0x11; 32], amount: over_cap_slot },
            FeeShare { validator_id: [0x22; 32], amount: over_cap_slot },
            FeeShare { validator_id: [0x33; 32], amount: over_cap_slot },
        ];
        let (reg, deed) = fee_registration(
            &validators, 0xCC, [0u8; 32], [0x03; 32], amount, breakdown,
        );

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;

        let err = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, None, None, None, None,
        ).expect_err("over-cap fee_breakdown must reject");
        assert!(matches!(err, NablaError::InvalidReceipt));
        assert_eq!(smt.tx_records_len(), 0, "rejected register must not write a record");
    }

    #[test]
    fn register_with_count_mismatched_fee_breakdown_rejects() {
        // After the 2026-06-03 receipt_commitment refactor, fee_breakdown
        // is NOT bound into the commitment — each WitnessSig
        // self-attests its own (rate, slot), and per-slot validator-id
        // binding is verified by Lambda CL2 at the next-TX consume site.
        // What Nabla CAN catch independently is a count mismatch
        // (`fee_breakdown.len() != signatures.len()`), which any honest
        // SDK assembler never produces.
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let amount = 1_000_000u64;
        let cap = (amount * 30) / 10_000;
        let original = vec![
            FeeShare { validator_id: [0x11; 32], amount: cap },
            FeeShare { validator_id: [0x22; 32], amount: cap },
            FeeShare { validator_id: [0x33; 32], amount: cap },
        ];
        let (mut reg, deed) = fee_registration(
            &validators, 0xDD, [0u8; 32], [0x04; 32], amount, original,
        );
        // Drop one slot — 2 slots vs 3 signatures triggers the
        // parallelism check in process_registration.
        reg.receipt.fee_breakdown.pop();

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;

        let err = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, None, None, None, None,
        ).expect_err("count-mismatched fee_breakdown must reject");
        assert!(matches!(err, NablaError::InvalidReceipt));
        assert_eq!(smt.tx_records_len(), 0);
    }

    #[test]
    fn register_k5_with_one_bad_receipt_commitment_sig_rejects() {
        // k=5-tier wallet (high-assurance) — five Lambdas witnessed.
        // One Lambda's receipt_commitment_sig is corrupted post-hoc;
        // every sig MUST verify, so the register rejects. The fix for
        // the pre-bugfix "valid_count >= 3" weakness — at k=5, three
        // good sigs out of five must NOT be enough; the protocol
        // requires every present sig to match.
        let validators: Vec<TestValidator> = (0..5).map(TestValidator::new).collect();
        let amount = 1_000_000u64;
        let cap = (amount * 30) / 10_000;
        let breakdown = vec![
            FeeShare { validator_id: [0x11; 32], amount: cap },
            FeeShare { validator_id: [0x22; 32], amount: cap },
            FeeShare { validator_id: [0x33; 32], amount: cap },
        ];
        let (mut reg, deed) = fee_registration(
            &validators, 0xDF, [0u8; 32], [0x06; 32], amount, breakdown,
        );
        // Corrupt slot 3 (out of 5) — flip a byte in its commitment sig.
        reg.receipt.signatures[3].receipt_commitment_sig[0] ^= 0x01;

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;

        let err = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, None, None, None, None,
        ).expect_err("k=5 register with one bad commitment sig must reject");
        assert!(matches!(err, NablaError::InvalidReceipt));
        assert_eq!(smt.tx_records_len(), 0);
    }

    #[test]
    fn register_with_missing_receipt_commitment_sigs_fails_chain_check() {
        // SDK forgot to populate receipt_commitment_sig — every sig is
        // empty → first one fails the present-and-well-formed gate →
        // reject. Closes the gap where a pre-Step-7 SDK could attach
        // fee_breakdown without the chain.
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let amount = 1_000_000u64;
        let cap = (amount * 30) / 10_000;
        let breakdown = vec![
            FeeShare { validator_id: [0x11; 32], amount: cap },
            FeeShare { validator_id: [0x22; 32], amount: cap },
            FeeShare { validator_id: [0x33; 32], amount: cap },
        ];
        let (mut reg, deed) = fee_registration(
            &validators, 0xEE, [0u8; 32], [0x05; 32], amount, breakdown,
        );
        for ws in &mut reg.receipt.signatures {
            ws.receipt_commitment_sig.clear();
        }

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;

        let err = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, None, None, None, None,
        ).expect_err("missing receipt_commitment_sig must reject");
        assert!(matches!(err, NablaError::InvalidReceipt));
    }

    // ───────────────────────────────────────────────────────────────────
    // YP §20.8 / §20.11 — DEED pool credit at receiver's /register
    // ───────────────────────────────────────────────────────────────────

    use crate::node::DeedPool;

    /// `fee_registration`'s preimage is a REDEEM (`opaque_redeem_leg`), so 8c
    /// PARKS the fee credit (ForkSettlement §9r F-6 path 11) and the door
    /// credits NOTHING; `NablaNode::release_held_fee_credits` credits it once
    /// the cheque judges `Ok`. These routing/split tests credit the parked
    /// value exactly as that release does (ONE `apply_fee_credit`). The
    /// park-until-clean behaviour itself is tested node-level in
    /// `provenance.rs` (`fee_credit_*`).
    fn credit_parked(
        r: RegistrationResult,
        tick: u64,
        deed: Option<&mut DeedPool>,
        ledger: Option<&mut crate::node::ValidatorNetLedger>,
        dev_deed: Option<&mut crate::node::DevDeedPool>,
        dev_ledger: Option<&mut crate::node::ValidatorDevNetLedger>,
    ) {
        let (cheque, credit) = r.held_fee_credit
            .expect("a redeem's fee credit is PARKED at the door (§9r F-6 path 11)");
        assert_eq!(cheque, [0xC4; 32], "parked under the redeemed cheque's txid");
        apply_fee_credit(&credit, tick, deed, ledger, dev_deed, dev_ledger);
    }

    #[test]
    fn deed_pool_credited_with_10_percent_of_validator_fees() {
        // 3 validators × 10-atom fee = 30 gross → DEED gets 3.
        // (Mirrors YP §20.12 worked example.)
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let amount = 1_000_000u64;
        let breakdown = vec![
            FeeShare { validator_id: [0x11; 32], amount: 10 },
            FeeShare { validator_id: [0x22; 32], amount: 10 },
            FeeShare { validator_id: [0x33; 32], amount: 10 },
        ];
        let (reg, deed) = fee_registration(
            &validators, 0xE0, [0u8; 32], [0x07; 32], amount, breakdown,
        );

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;
        let mut deed_pool = DeedPool::new();

        let r = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, Some(&mut deed_pool), None, None, None,
        ).expect("valid fee-carrying register must succeed");
        assert_eq!(deed_pool.balance(), 0, "a redeem's DEED slice is parked, not credited, at the door");
        credit_parked(r, 1, Some(&mut deed_pool), None, None, None);

        assert_eq!(deed_pool.balance(), 3,
            "DEED pool must receive 10% of 30-atom validator fees");
        assert_eq!(deed_pool.total_credited(), 3);
        assert_eq!(deed_pool.last_credit_tick, 1);
    }

    /// Dev-class isolation Layer 4 (`AXIOM_DESIGN_FactClassIsolation.md`).
    ///
    /// When `receipt.is_dev_class == true`, the credit MUST land in
    /// `DevDeedPool` + `ValidatorDevNetLedger`, and the public
    /// `DeedPool` + `ValidatorNetLedger` MUST stay UNTOUCHED. Pre-fix,
    /// dev fees credited the public pools → validators could later mint
    /// public AXC from dev fees via the withdrawal mint path. Fix
    /// landed 2026-06-05.
    ///
    /// Layer 4 is the routing boundary; Layer 3 (Core CL3/CL5) attests
    /// the flag and binds it into receipt_commitment, Layer 5
    /// (withdrawal mint query) reads only public-NET.  This test
    /// covers Layer 4 directly + the type system covers any leak by
    /// construction (newtype distinct from public counterpart).
    #[test]
    fn dev_class_fees_route_to_dev_pools_not_public() {
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let amount = 1_000_000u64;
        let breakdown = vec![
            FeeShare { validator_id: [0x11; 32], amount: 10 },
            FeeShare { validator_id: [0x22; 32], amount: 10 },
            FeeShare { validator_id: [0x33; 32], amount: 10 },
        ];
        let (reg, deed) = fee_registration_with_class(
            &validators, 0xE1, [0u8; 32], [0x08; 32], amount, breakdown,
            /* is_dev_class = */ true,
        );

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;

        let mut public_deed_pool = DeedPool::new();
        let mut public_ledger = crate::node::ValidatorNetLedger::new();
        let mut dev_deed_pool = crate::node::DevDeedPool::new();
        let mut dev_ledger = crate::node::ValidatorDevNetLedger::new();

        let r = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None,
            None, None,
            Some(&mut public_deed_pool),
            Some(&mut public_ledger),
            Some(&mut dev_deed_pool),
            Some(&mut dev_ledger),
        ).expect("dev-class register must succeed (same wire path, different pool routing)");
        assert_eq!(dev_deed_pool.balance(), 0, "parked at the door, not credited");
        credit_parked(r, 1, Some(&mut public_deed_pool), Some(&mut public_ledger),
            Some(&mut dev_deed_pool), Some(&mut dev_ledger));

        // PUBLIC pools must be UNTOUCHED — this is the leak boundary.
        assert_eq!(public_deed_pool.balance(), 0,
            "dev-class TX must NOT credit the public DeedPool");
        assert_eq!(public_deed_pool.total_credited(), 0);
        assert!(public_ledger.is_empty(),
            "dev-class TX must NOT credit the public ValidatorNetLedger");

        // DEV pools must reflect the same 10%/90% split that the public
        // pools would have seen — same math, different destination.
        assert_eq!(dev_deed_pool.balance(), 3,
            "dev-class TX must credit the DevDeedPool with the 10% slice");
        assert_eq!(dev_deed_pool.total_credited(), 3);
        for vid in [[0x11; 32], [0x22; 32], [0x33; 32]] {
            assert!(dev_ledger.balance(&vid) > 0,
                "dev-class TX must credit each witnessing validator's dev NET ledger");
        }
    }

    /// Layer 4-bis defensive gate: when `is_dev_class=false` but the
    /// claimant's wallet_id resolves to `@axiom.internal`, Nabla MUST
    /// reject the register rather than credit the public pool.
    ///
    /// This is the fallback for the case where ALL other layers fail
    /// — the SDK ships a wrong is_dev_class, the receipt_commitment
    /// verify is skipped (because the SDK didn't populate the
    /// skeleton fields the verify needs), and Core CL5's attestation
    /// is overridden somehow. The wallet_id is the last sticky
    /// signal: if the claimant is @axiom.internal, no public-pool
    /// write can happen, period.
    #[test]
    fn registration_rejects_dev_claimant_routed_to_public() {
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let amount = 1_000_000u64;
        let breakdown = vec![
            FeeShare { validator_id: [0x11; 32], amount: 10 },
            FeeShare { validator_id: [0x22; 32], amount: 10 },
            FeeShare { validator_id: [0x33; 32], amount: 10 },
        ];

        // Build a register with the receipt explicitly saying
        // is_dev_class=false (the leak scenario — an old SDK or buggy
        // path that didn't propagate the flag).
        let (mut reg, deed) = fee_registration_with_class(
            &validators, 0xE3, [0u8; 32], [0x0A; 32], amount, breakdown,
            /* is_dev_class = */ false,
        );

        // BUT the claimant_wallet_id IS @axiom.internal — the
        // wallet-id signal contradicts the is_dev_class flag.
        // Layer 4-bis must catch this.
        reg.claimant_wallet_id = "dev@axiom.internal/aabb01ff".to_string();

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;
        let mut public_deed_pool = DeedPool::new();
        let mut public_ledger = crate::node::ValidatorNetLedger::new();
        let mut dev_deed_pool = crate::node::DevDeedPool::new();
        let mut dev_ledger = crate::node::ValidatorDevNetLedger::new();

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None,
            None, None,
            Some(&mut public_deed_pool),
            Some(&mut public_ledger),
            Some(&mut dev_deed_pool),
            Some(&mut dev_ledger),
        );

        assert!(
            matches!(result, Err(NablaError::InvalidReceipt)),
            "dev claimant routed to public MUST reject \
             (LEAK-DEFENSE) — got {:?}",
            result,
        );
        assert_eq!(public_deed_pool.balance(), 0,
            "rejected register must NOT credit any pool");
        assert_eq!(dev_deed_pool.balance(), 0);
        assert!(public_ledger.is_empty());
        assert!(dev_ledger.is_empty());
    }

    #[test]
    fn validator_net_ledger_credited_with_per_slot_nets() {
        // Same shape as the DEED-pool test above, but also wires the
        // ValidatorNetLedger and asserts each validator's NET balance.
        // breakdown = 3 × 10 atoms = 30 total. compute_deed_split returns
        // deed_atoms = 3, val_pool = 27, proportional split = 9 each.
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let amount = 1_000_000u64;
        let breakdown = vec![
            FeeShare { validator_id: [0x11; 32], amount: 10 },
            FeeShare { validator_id: [0x22; 32], amount: 10 },
            FeeShare { validator_id: [0x33; 32], amount: 10 },
        ];
        let (reg, deed) = fee_registration(
            &validators, 0xE7, [0u8; 32], [0x0B; 32], amount, breakdown,
        );

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;
        let mut deed_pool = DeedPool::new();
        let mut ledger = crate::node::ValidatorNetLedger::new();

        let r = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, Some(&mut deed_pool), Some(&mut ledger), None, None,
        ).expect("valid fee-carrying register must succeed");
        assert!(ledger.is_empty(), "a redeem's validator NETs are parked, not credited, at the door");
        credit_parked(r, 1, Some(&mut deed_pool), Some(&mut ledger), None, None);

        // 3 validators present, each credited 9 atoms (= floor(10 * 27 / 30)).
        assert_eq!(ledger.len(), 3);
        assert_eq!(ledger.balance(&[0x11; 32]), 9);
        assert_eq!(ledger.balance(&[0x22; 32]), 9);
        assert_eq!(ledger.balance(&[0x33; 32]), 9);
        // Conservation: DEED (3) + sum(net) (3 × 9 = 27) == 30 (total fees).
        assert_eq!(
            deed_pool.balance() + ledger.balance(&[0x11; 32])
                + ledger.balance(&[0x22; 32]) + ledger.balance(&[0x33; 32]),
            30,
        );
    }

    #[test]
    fn validator_net_ledger_unchanged_on_empty_fee_breakdown() {
        // Send-path / heal / genesis registers carry no fee_breakdown —
        // ledger stays empty just like the DEED pool.
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let (reg, deed) = signed_registration(&validators, 0xE8, [0u8; 32], [0x0C; 32]);

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;
        let mut ledger = crate::node::ValidatorNetLedger::new();

        process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, None, Some(&mut ledger), None, None,
        ).expect("empty-fee register must succeed");

        assert!(ledger.is_empty(), "no fee_breakdown → no NET credits");
    }

    #[test]
    fn deed_pool_not_credited_on_empty_fee_breakdown() {
        // Send-path / heal / genesis registers have no fee_breakdown —
        // DEED pool stays at zero (byte-identical to pre-Step-8.2).
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let (reg, deed) = signed_registration(&validators, 0xE1, [0u8; 32], [0x08; 32]);

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;
        let mut deed_pool = DeedPool::new();

        process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, Some(&mut deed_pool), None, None, None,
        ).expect("empty-fee register must succeed");

        assert_eq!(deed_pool.balance(), 0);
        assert_eq!(deed_pool.total_credited(), 0);
    }

    #[test]
    fn deed_pool_accumulates_across_multiple_registers() {
        // Two sequential fee-bearing registers credit DEED twice.
        // fee_breakdown has exactly one entry per K3WitnessSig — the
        // SDK-assembled receipt mirrors `witness_sigs.len()` by
        // construction (sdk/client/src/redeem.rs::assembled_fee_breakdown).
        // Nabla's parallelism check (process_registration) enforces this.
        let validators: Vec<TestValidator> = (0..3).map(TestValidator::new).collect();
        let amount = 1_000_000u64;
        let breakdown1 = vec![
            FeeShare { validator_id: [0x11; 32], amount: 4 },
            FeeShare { validator_id: [0x12; 32], amount: 3 },
            FeeShare { validator_id: [0x13; 32], amount: 3 },
        ];
        let breakdown2 = vec![
            FeeShare { validator_id: [0x21; 32], amount: 8 },
            FeeShare { validator_id: [0x22; 32], amount: 6 },
            FeeShare { validator_id: [0x23; 32], amount: 6 },
        ];
        let (reg1, deed1) = fee_registration(
            &validators, 0xE2, [0u8; 32], [0x09; 32], amount, breakdown1,
        );
        let (reg2, deed2) = fee_registration(
            &validators, 0xE3, [0u8; 32], [0x0A; 32], amount, breakdown2,
        );

        let mut smt = make_smt_hashmap_for_fees();
        let mut bans = BanTable::new();
        let dir = tempfile::tempdir().unwrap();
        let mut wal = WriteAheadLog::open(dir.path().join("wal.bin")).unwrap();
        let mut deed_collected = 0u64;
        let mut deed_pool = DeedPool::new();

        let r1 = process_registration(
            &mut smt, &mut wal, &mut bans, &reg1, &deed1,
            1, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, Some(&mut deed_pool), None, None, None,
        ).expect("first fee register OK");
        credit_parked(r1, 1, Some(&mut deed_pool), None, None, None);
        let r2 = process_registration(
            &mut smt, &mut wal, &mut bans, &reg2, &deed2,
            2, crate::types::test_legs::NOW_SECS, &mut deed_collected, &crate::crypto::NoopSigner, &crate::types::test_legs::dir_admits_all,
            None, None, None, None, Some(&mut deed_pool), None, None, None,
        ).expect("second fee register OK");
        credit_parked(r2, 2, Some(&mut deed_pool), None, None, None);

        // 10/10 + 20/10 = 1 + 2 = 3 atoms
        assert_eq!(deed_pool.balance(), 3,
            "DEED pool must accumulate across registers");
        assert_eq!(deed_pool.total_credited(), 3);
        assert_eq!(deed_pool.last_credit_tick, 2,
            "last_credit_tick must reflect most-recent register");
    }

}

#[cfg(test)]
mod ki231_late_origin_after_redeem {
    use super::txid_holder_refuses;

    #[test]
    fn second_redeem_by_another_wallet_is_refused() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert!(txid_holder_refuses(Some(a), &b, false));
    }

    #[test]
    fn senders_late_registration_of_a_redeemed_send_is_admitted() {
        let (receiver, sender) = ([1u8; 32], [2u8; 32]);
        assert!(!txid_holder_refuses(Some(receiver), &sender, true));
    }

    #[test]
    fn same_wallet_and_unseen_txid_are_admitted() {
        let w = [3u8; 32];
        assert!(!txid_holder_refuses(Some(w), &w, false));
        assert!(!txid_holder_refuses(None, &w, false));
    }
}
