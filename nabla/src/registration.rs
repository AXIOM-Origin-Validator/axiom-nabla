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
fn verify_receipt_commitment_sigs(reg: &Registration) -> Result<(), NablaError> {
    let expected_commitment = axiom_core_logic::compute::compute_receipt_commitment(
        &reg.tx_hash,
        &reg.receipt.state_hash,
        reg.receipt.new_wallet_seq,
        &reg.receipt.commitment_hash,
        reg.receipt.epoch,
        reg.receipt.is_dev_class,
        reg.receipt.oods_flag.as_ref(),
    );
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    for ws in &reg.receipt.signatures {
        if ws.receipt_commitment_sig.is_empty() || ws.receipt_commitment_sig.len() != 64 {
            log::warn!(
                "[receipt-commitment] missing or malformed receipt_commitment_sig (len={})",
                ws.receipt_commitment_sig.len(),
            );
            return Err(NablaError::InvalidReceipt);
        }
        let Ok(vk) = VerifyingKey::from_bytes(&ws.validator_pk) else {
            log::warn!("[receipt-commitment] invalid validator_pk in receipt sig");
            return Err(NablaError::InvalidReceipt);
        };
        let sig_bytes: [u8; 64] = ws.receipt_commitment_sig.as_slice()
            .try_into().expect("len == 64 checked above");
        let sig = Signature::from_bytes(&sig_bytes);
        if vk.verify(&expected_commitment, &sig).is_err() {
            log::warn!(
                "[receipt-commitment] receipt_commitment_sig verify failed for one slot — \
                 rejecting register"
            );
            return Err(NablaError::InvalidReceipt);
        }
    }
    Ok(())
}

/// This is the core registration logic, separated from the NablaNode
/// for testability. The node calls this with references to its state.
#[allow(clippy::too_many_arguments)]
pub fn process_registration(
    smt: &mut SparseMerkleTree,
    wal: &mut WriteAheadLog,
    bans: &mut BanTable,
    reg: &Registration,
    deed_tx: &DeedTransaction,
    current_tick: u64,
    deed_collected: &mut u64,
    signer: &dyn Signer,
    airdrop_pool: Option<&mut crate::node::AirdropPool>,
    dev_treasury_pool: Option<&mut crate::node::DevTreasuryPool>,
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
    // §32 Phase 1: list of wallet IDs under merge quarantine.
    // Registrations for quarantined wallets are rejected until quarantine resolves.
    quarantined_wallets: &[[u8; 32]],
) -> Result<RegistrationResult, NablaError> {
    // ── 0. §32 Merge quarantine check (cheapest, O(n) on small list) ──
    if quarantined_wallets.contains(&reg.wallet_id) {
        log::warn!("[§32] Registration rejected: wallet {} is under merge quarantine",
            hex::encode(&reg.wallet_id[..8]));
        return Err(NablaError::WalletBanned);
    }

    // ── 1. Check ban status (cheapest check, O(1)) ──
    if bans.is_banned(&reg.wallet_id) {
        return Err(NablaError::WalletBanned);
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
    //   (3) Pool routing: deduct only from the matching pool.
    if reg.is_genesis_claim {
        // (1) pk_bind anchor — string must derive from this pk.
        if axiom_core_logic::wallet_id::verify_pk_binding(
            &reg.claimant_wallet_id, &reg.wallet_id,
        ).is_err() {
            log::warn!("[CLASS] Claim rejected: claimant_wallet_id {:?} not pk-bound to wallet {}",
                reg.claimant_wallet_id, hex::encode(&reg.wallet_id[..8]));
            return Err(NablaError::ClassSignalMismatch);
        }

        // (2) Signal agreement — Nabla derives class independently.
        let wallet_is_dev = axiom_core_logic::wallet_id::is_dev_wallet(&reg.claimant_wallet_id);
        if wallet_is_dev != reg.is_dev_claim {
            log::warn!("[CLASS] Claim rejected: is_dev_claim={} but is_dev_wallet({:?})={}",
                reg.is_dev_claim, reg.claimant_wallet_id, wallet_is_dev);
            return Err(NablaError::ClassSignalMismatch);
        }

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
        let outcome = if wallet_is_dev {
            match dev_treasury_pool {
                Some(pool) => pool.try_claim(current_tick),
                None => ClaimOutcome::RefusedExhausted,
            }
        } else {
            match airdrop_pool {
                Some(pool) => pool.try_claim(current_tick),
                None => ClaimOutcome::RefusedExhausted,
            }
        };
        match outcome {
            ClaimOutcome::Granted => {}
            ClaimOutcome::RefusedPerNablaCap { cycle_resets_at_tick } => {
                log::warn!(
                    "[{}] Claim refused for wallet {} — per-Nabla cycle cap reached (reset at tick {})",
                    if wallet_is_dev { "DEV-TREASURY" } else { "AIRDROP" },
                    hex::encode(&reg.wallet_id[..8]),
                    cycle_resets_at_tick,
                );
                return Err(NablaError::PoolCapPerNabla { reset_tick: cycle_resets_at_tick });
            }
            ClaimOutcome::RefusedMeshCap { cycle_resets_at_tick } => {
                log::warn!(
                    "[{}] Claim refused for wallet {} — mesh-wide cycle cap reached (reset at tick {})",
                    if wallet_is_dev { "DEV-TREASURY" } else { "AIRDROP" },
                    hex::encode(&reg.wallet_id[..8]),
                    cycle_resets_at_tick,
                );
                return Err(NablaError::PoolCapMesh { reset_tick: cycle_resets_at_tick });
            }
            ClaimOutcome::RefusedExhausted => {
                log::warn!(
                    "[{}] Claim refused for wallet {} — pool exhausted",
                    if wallet_is_dev { "DEV-TREASURY" } else { "AIRDROP" },
                    hex::encode(&reg.wallet_id[..8]),
                );
                return Err(NablaError::PoolExhausted);
            }
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

    // ── 5. Verify k=3 receipt signatures via Core (Signer trait) ──
    // Each validator signed: wallet_id + old_state + new_state + tick.
    if reg.receipt.signatures.len() < 3 {
        return Err(NablaError::InvalidReceipt);
    }
    // Use receipt's tick as-is for signature verification.
    // Lambda signs with tick=0 (the canonical "no timestamp" value).
    // Nabla previously substituted current_tick when tick=0, which
    // broke verification because the signature was over tick=0.
    // Staleness check only applies to non-zero ticks.
    let receipt_tick = if reg.receipt.tick > 0 {
        if current_tick.saturating_sub(reg.receipt.tick) > 300 {
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
    for ws in &reg.receipt.signatures {
        if !signer.verify(&ws.validator_pk, &receipt_payload, &ws.signature) {
            return Err(NablaError::InvalidReceipt);
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
    // at the Nabla-mesh boundary. Gated on `!fee_breakdown.is_empty()`
    // because the K3Receipt skeleton fields (`state_hash`,
    // `commitment_hash`, `new_wallet_seq`, `epoch`) are populated by the
    // SDK on the same code path that fills `fee_breakdown` — see
    // `K3Receipt::from_witness_values_with_fees`. Older SDKs that
    // shipped K3Receipt via `from_witness_values` left those fields at
    // skeleton zeros and didn't populate fee_breakdown either, so the
    // gating is a self-consistent "if the SDK populated, we verify."
    //
    // Dev-class leak boundary: the per-register defensive gate below
    // (Layer 4-bis) is independent of this verify — it cross-checks
    // `is_dev_wallet(claimant_wallet_id)` against the routing flag
    // BEFORE any public-pool write. So a forged is_dev_class still
    // can't leak fees even when the SDK skips the commitment fields.
    if !reg.receipt.fee_breakdown.is_empty() {
        axiom_core_logic::validation::validate_fee_breakdown(
            reg.receipt.amount, &reg.receipt.fee_breakdown,
        ).map_err(|_| NablaError::InvalidReceipt)?;
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
    if reg.tx_hash != [0u8; 32] {
        if let Some(existing_wallet) = smt.get_wallet_by_txid(&reg.tx_hash) {
            if existing_wallet != reg.wallet_id {
                log::warn!("Txid double-redeem: txid registered by different wallet");
                return Err(NablaError::DoubleSpendDetected);
            }
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
    //     written, DEED collected, gossiped). Retry MUST NOT redo any of
    //     those side-effects.
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
        if let Some(existing) = smt.get(&reg.wallet_id) {
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
                    wallet_id: reg.wallet_id,
                    new_state: reg.new_state,
                    tx_hash: reg.tx_hash,
                    tick: existing.tick,
                    is_genesis_claim: reg.is_genesis_claim,
                    wallet_seq: reg.receipt.new_wallet_seq, // WI3: k-attested seq from receipt
                    client_pk: existing.client_pk,
                    client_sig: existing.client_sig.clone(),
                    amount: retry_amount,
                    fee_breakdown: retry_breakdown,
                    // WI3 hole-1: re-emit the original gossip's seq proof.
                    seq_proof: crate::types::SeqProof::from_receipt(&reg.tx_hash, &reg.receipt),
                };
                return Ok(RegistrationResult { ack, gossip_msg, hibernation_until: None, committed_recalls: Vec::new() });
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
    if reg.is_hal_reanchor && smt.get(&reg.wallet_id).is_none() {
        log::warn!(
            "[KI#34] HAL re-anchor rejected: no held previous state for wallet={} (fail-closed)",
            hex::encode(&reg.wallet_id[..4])
        );
        return Err(NablaError::StateMismatch);
    }
    if let Some(existing) = smt.get(&reg.wallet_id) {
        if existing.current_state != reg.old_state {
            // ── 6a. Advance-on-proof branch (KI #5) ──
            //
            // The SMT entry is *behind* `reg.old_state`. By default this is
            // a hard `StateMismatch` reject — and when `reg.partial_bridge`
            // is `None`, that is EXACTLY what happens (this is a pure ADD;
            // behaviour for every normal register is byte-identical to
            // pre-KI#5 code).
            //
            // When the register carries a `PartialBridgeReceipt`, the
            // sender is recovering from a sub-quorum (k<3) partial commit:
            // a transition `SMT_state → reg.old_state` that was real but
            // never registerable (a register needs a k=3 receipt). The
            // bridge PROVES that step. `verify_and_apply_partial_bridge`
            // runs the four §4.3 checks and, on all-pass, advances the SMT
            // `SMT_state → reg.old_state` and records the partial txid.
            // We then fall through to the normal SMT advance below, which
            // applies `reg.old_state → reg.new_state` against the now
            // up-to-date SMT entry.
            match &reg.partial_bridge {
                None => {
                    log::warn!("StateMismatch[SMT_VS_REG]: wallet={} smt.current={} reg.old={}",
                        hex::encode(&reg.wallet_id[..4]),
                        hex::encode(&existing.current_state[..4]), hex::encode(&reg.old_state[..4]));
                    return Err(NablaError::StateMismatch);
                }
                Some(bridge) => {
                    let smt_state = existing.current_state;
                    let smt_client_pk = existing.client_pk;
                    let smt_client_sig = existing.client_sig.clone();
                    verify_and_apply_partial_bridge(
                        smt, wal, reg, bridge,
                        &smt_state, &smt_client_pk, &smt_client_sig,
                        current_tick, signer,
                    )?;
                }
            }
        }
    }

    // ── 6b. YPX-020 A12 anti-rollback — consumed-state bloom gate ──
    // At this point `existing.current_state == reg.old_state` (a mismatch already
    // returned StateMismatch / advanced-on-proof above). A LEGIT register's
    // `old_state` is the live head, never yet consumed. The ONLY way `old_state`
    // is already in the monotonic consumed-state bloom is a forged head-rollback
    // to an ancestor (A12) — the head says `old_state` is current, but the bloom
    // remembers it was advanced past. Reject. The bloom never false-negatives, so
    // this never misses a replay; a false positive (bloom saturation) only ever
    // rejects, never admits — bound it with time-bucketing before production.
    if smt.is_state_consumed(&reg.old_state) {
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
    if reg.is_recall && !smt.has_reserved_recall(&reg.wallet_id) {
        return Err(NablaError::RecallAborted);
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

    // ── 7. Write to WAL before updating SMT ──
    let new_entry = NablaEntry {
        wallet_id: reg.wallet_id,
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
    };

    let serialized = bincode::serialize(&new_entry)
        .map_err(|e| NablaError::SerializationError(e.to_string()))?;

    wal.append(&WalOp::Put {
        key: reg.wallet_id,
        value: serialized,
        client_pk: reg.client_pk,
        client_sig: reg.client_sig.clone(),
    })
    .map_err(|e| NablaError::WalError(e.to_string()))?;

    // ── 8. Update SMT ──
    let new_root = smt.put(&new_entry);

    // KI#38 — retain the k=3 seq attestation for the head THIS node just
    // committed. The AE digest push serves `smt.seq_proof(wid)` alongside
    // the entry, but before this line only flood/AE ADOPTERS ever retained
    // one — the ORIGIN node (the one place the newest head is guaranteed
    // to exist) could never attest its own head's seq over anti-entropy.
    // Under a lossy flood (TARDIS churn) the newest head was stranded at
    // the origin, every AE push of it was rejected `seq-unattested
    // proof=ABSENT` by the WI3 gate, and the mesh wedged at applied=0
    // (the KI#38 non-convergence, measured 2026-07-08 soak s2r70134).
    // The receipt's commitment sigs were verified at §5b above, so
    // retaining this proof is sound — it is the same attestation the
    // outgoing StateUpdate flood carries (step 10).
    if let Some(proof) = crate::types::SeqProof::from_receipt(&reg.tx_hash, &reg.receipt) {
        smt.set_seq_proof(reg.wallet_id, proof);
    }

    // ── 8a. YPX-020 HAL hibernation — stamp the lock on a re-anchor register ──
    let mut hibernation_until: Option<u64> = None;
    // YPX-022 §2.2.1 — reservations committed by this register (is_recall only).
    let mut committed_recalls: Vec<(TxHash, u64)> = Vec::new();
    // Nabla owns the authoritative tick, so it sets the deadline from its OWN
    // current tick (fresh by construction — a dead-overlap wallet's stale
    // fact-chain tick never enters). The wallet's subsequent cheque-claim
    // (self-redeem) is refused in `register_cheque_claim` until `current_tick`
    // reaches this value. `register_tick + WINDOW` is derivable from the gossiped
    // register, so the mesh converges on one value.
    // is_dev_class = the k-signed, Core-attested flag on the receipt (gates the
    // dev-wallet short window; a public wallet always gets the full window — see
    // hibernation_until_for). MUST match Core's is_dev_wallet(sender) for §15 lock-step.
    let hib_until = axiom_core_logic::types::hibernation_until_for(
        current_tick, reg.is_hal_reanchor, reg.is_recall, reg.receipt.is_dev_class,
    );
    if hib_until != 0 {
        // Key by `wallet_id` — for an SDK register this IS the wallet's raw
        // Ed25519 pubkey (build_register_message sets wallet_id = wallet_pk).
        // The YPX-020 re-anchor is a dust SELF-send X→X', so when the wallet
        // completes it the cheque-claim carries `sender_wallet_pk` = this same
        // raw pubkey — that is what `register_cheque_claim`'s gate checks. The
        // old `reg.client_pk` is hardcoded [0;32] in the SDK (YPX-009 client
        // state-sig is unwired), so keying on it never matched the claim.
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
    // Hashmap-gated fee ledger above). The KI#5 partial_bridge sub-quorum txid is
    // recorded via `record_txid`, NOT here → genuine sub-quorum partials stay
    // recallable. Reaching this point means the registration verified + advanced.
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
        smt.record_txid(&reg.tx_hash, &reg.wallet_id);
    }

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
        if reg.receipt.is_dev_class {
            let dev_pool_present = dev_deed_pool.is_some();
            let dev_ledger_present = validator_dev_net_ledger.is_some();
            let mode = smt.txid_mode();
            if let Some(pool) = dev_deed_pool {
                let pre = pool.balance();
                pool.credit(split.deed_atoms, current_tick);
                log::warn!(
                    "[DEV-DEED-CREDIT] tx_hash={} added={} balance={}→{}",
                    hex::encode(&reg.tx_hash[..8]),
                    split.deed_atoms, pre, pool.balance(),
                );
            }
            if mode == crate::bloom::TxidServiceMode::Hashmap {
                if let Some(ledger) = validator_dev_net_ledger {
                    for (slot, net) in derived_fee_breakdown.iter()
                        .zip(split.net_per_slot.iter())
                    {
                        ledger.credit(&slot.validator_id, *net, current_tick);
                    }
                }
            }
            log::warn!(
                "[DEV-CLASS-ROUTE] tx_hash={} dev_deed_credit={} validators={} \
                 pool_present={} ledger_present={} txid_mode={:?}",
                hex::encode(&reg.tx_hash[..8]),
                split.deed_atoms,
                derived_fee_breakdown.len(),
                dev_pool_present, dev_ledger_present, mode,
            );
        } else {
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
            if let Some(pool) = deed_pool {
                pool.credit(split.deed_atoms, current_tick);
            }
            if smt.txid_mode() == crate::bloom::TxidServiceMode::Hashmap {
                if let Some(ledger) = validator_net_ledger {
                    for (slot, net) in derived_fee_breakdown.iter()
                        .zip(split.net_per_slot.iter())
                    {
                        ledger.credit(&slot.validator_id, *net, current_tick);
                    }
                }
            }
        }
    }

    // ── 9. Process DEED payment ──
    *deed_collected += deed_tx.amount;

    // ── 10. Build gossip message ──
    // YP §19.6 — populate amount + fee_breakdown from the verified receipt
    // so peer hashmap nodes can rebuild their txid_records from the flood
    // (Step 4's apply_fee_record_from_gossip is the consumer).
    // KI#34 check-3: a HAL re-anchor (overlap-relaxed re-activation) gossips as a
    // HalAdvance carrying old_state + the k=3 sigs (already verified above), so the
    // honest mesh can fork-check it against its own previous_state before adopting
    // the head. Every normal advance stays a plain StateUpdate (zero wire change).
    let gossip_msg = if reg.is_hal_reanchor {
        GossipMessage::HalAdvance {
            wallet_id: reg.wallet_id,
            old_state: reg.old_state,
            new_state: reg.new_state,
            tx_hash: reg.tx_hash,
            tick: current_tick,
            client_pk: reg.client_pk,
            client_sig: reg.client_sig.clone(),
            k3_signatures: reg.receipt.signatures.clone(),
            amount: reg.receipt.amount,
            fee_breakdown: reg.receipt.fee_breakdown.clone(),
        }
    } else {
        GossipMessage::StateUpdate {
            wallet_id: reg.wallet_id,
            new_state: reg.new_state,
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
            seq_proof: crate::types::SeqProof::from_receipt(&reg.tx_hash, &reg.receipt),
        }
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

    Ok(RegistrationResult { ack, gossip_msg, hibernation_until, committed_recalls })
}

/// Advance-on-proof: verify a `PartialBridgeReceipt` and, on all checks
/// passing, advance the Nabla SMT across the one sub-quorum link the
/// bridge proves (`smt_state → reg.old_state`) and record the partial
/// txid into the txid bloom
/// (KI #5, `docs/AXIOM_DESIGN_KI5_AdvanceOnProof.md` §4.3).
///
/// This is the consensus-critical core of advance-on-proof. It MUST stay
/// strict: every failure path returns an error; nothing about the bridge
/// is trusted on the client's word.
///
/// Called only from the `[SMT_VS_REG]` branch, *after* steps 4 and 5 of
/// `process_registration` have already run — so by the time we get here
/// `reg.receipt` is a fully k=3-verified receipt and
/// `reg.old_state == reg.receipt.consumed_state_id` (step 4 enforced it).
///
/// ## The four checks (spec §4.3)
///
/// 1. **Continuity.** The bridge spans *exactly* the gap — no more, no
///    less: `bridge.consumed_state_id == smt_state` (anchored — the
///    bridge starts where the SMT actually is) **and**
///    `bridge.produced_state_id == reg.old_state` (flush — the bridge
///    ends exactly where this register begins). The second equality is
///    also the multi-partial guard (spec §7): the bridge proves ONE
///    link, and a heal whose `old_state` is ≥2 steps past the SMT cannot
///    satisfy it.
///
/// 2. **Sub-quorum signatures valid, count `1 <= n < k`.** The partial
///    was sub-quorum by definition. `n == 0` (no committer) is rejected:
///    a partial with zero commits advanced nothing. `n >= k` (k=3) is
///    rejected as suspicious: a full-quorum transition is a *normal*
///    register, not a partial. Every signature is verified against
///    `crypto::receipt_sign_payload(wallet_id, X, P, tick)` — the same
///    payload Lambda's witnesses sign (mirrors step 5).
///
/// 3. **Superseding k=3 heal is real.** The bridge is honoured *only
///    because* a full k=3 heal supersedes `P`. That heal is the
///    register's own `reg.receipt` — already k=3-verified at step 5. We
///    additionally assert `reg.receipt.consumed_state_id == P` (the
///    partial's produced state). Without a superseding k=3 heal a bare
///    sub-quorum register is still rejected.
///
/// 4. **Advance-only / monotonic.** The SMT must move strictly forward,
///    never rewind (a rewind would un-see a registered txid → replay
///    vector). The spec phrases this as "`reg`'s wallet_seq strictly
///    greater than the SMT entry's"; `NablaEntry` carries no `wallet_seq`
///    field, so monotonicity is enforced structurally: check 1 pins the
///    bridge start to the SMT entry, and a degenerate / self-loop bridge
///    (`produced_state_id == smt_state`) is rejected here. The SMT is
///    only ever written to `bridge.produced_state_id` and then
///    `reg.new_state`; combined with the anchoring it can never be
///    written back to a prior state.
fn verify_and_apply_partial_bridge(
    smt: &mut SparseMerkleTree,
    wal: &mut WriteAheadLog,
    reg: &Registration,
    bridge: &crate::types::PartialBridgeReceipt,
    smt_state: &StateId,
    smt_client_pk: &[u8; 32],
    smt_client_sig: &[u8],
    current_tick: u64,
    signer: &dyn Signer,
) -> Result<(), NablaError> {
    // The sub-quorum threshold. k=3 is the protocol quorum; a "partial"
    // is by definition below it. Named local so the bounds in check 2
    // read as intent, not magic numbers.
    const QUORUM_K: usize = 3;

    // ── Check 1: continuity (anchored + flush) ──
    if bridge.consumed_state_id != *smt_state {
        log::warn!(
            "[advance-on-proof] reject: bridge not anchored — wallet={} bridge.consumed={} smt.current={}",
            hex::encode(&reg.wallet_id[..4]),
            hex::encode(&bridge.consumed_state_id[..4]),
            hex::encode(&smt_state[..4]),
        );
        return Err(NablaError::StateMismatch);
    }
    if bridge.produced_state_id != reg.old_state {
        // Bridge ends somewhere other than where this register begins.
        // Multi-partial guard (spec §7): the bridge proves ONE link; a
        // >1-step gap cannot be flush with the register.
        log::warn!(
            "[advance-on-proof] reject: bridge not flush with register (>1-step gap?) — \
             wallet={} bridge.produced={} reg.old={}",
            hex::encode(&reg.wallet_id[..4]),
            hex::encode(&bridge.produced_state_id[..4]),
            hex::encode(&reg.old_state[..4]),
        );
        return Err(NablaError::StateMismatch);
    }

    // ── Check 4 (advance-only): reject a degenerate / rewind bridge ──
    // A bridge whose endpoints coincide advances nothing. Combined with
    // check 1 (start pinned to the SMT entry) this guarantees the SMT
    // only ever moves to a NEW content-hash state.
    if bridge.produced_state_id == *smt_state {
        log::warn!(
            "[advance-on-proof] reject: degenerate/rewind bridge (consumed == produced == smt) — wallet={}",
            hex::encode(&reg.wallet_id[..4]),
        );
        return Err(NablaError::StateMismatch);
    }

    // ── Check 3: a superseding k=3 heal must consume P ──
    // `reg.receipt` is the k=3 receipt for `P → H` — already verified at
    // process_registration step 5. It is honoured as the superseding heal
    // ONLY if it genuinely consumed the partial state P. (Step 4 already
    // enforced reg.old_state == reg.receipt.consumed_state_id; we assert
    // the spec's check explicitly so a future reorder cannot silently
    // drop it.)
    if reg.receipt.consumed_state_id != bridge.produced_state_id {
        log::warn!(
            "[advance-on-proof] reject: register's k=3 receipt does not consume P — \
             wallet={} receipt.consumed={} bridge.produced(P)={}",
            hex::encode(&reg.wallet_id[..4]),
            hex::encode(&reg.receipt.consumed_state_id[..4]),
            hex::encode(&bridge.produced_state_id[..4]),
        );
        return Err(NablaError::StateMismatch);
    }
    if reg.receipt.signatures.len() < QUORUM_K {
        // Defensive: process_registration step 5 already rejects < k
        // sigs. A bare sub-quorum register with no superseding k=3 heal
        // must never be honoured via the bridge path.
        log::warn!(
            "[advance-on-proof] reject: no superseding k=3 heal ({} receipt sigs < k={}) — wallet={}",
            reg.receipt.signatures.len(), QUORUM_K, hex::encode(&reg.wallet_id[..4]),
        );
        return Err(NablaError::InvalidReceipt);
    }

    // ── Check 2: sub-quorum signatures — count bounds + crypto ──
    let n = bridge.witness_sigs.len();
    if n == 0 {
        log::warn!(
            "[advance-on-proof] reject: partial has zero committers — wallet={}",
            hex::encode(&reg.wallet_id[..4]),
        );
        return Err(NablaError::InvalidReceipt);
    }
    if n >= QUORUM_K {
        // A full-quorum transition is a normal register, never a partial.
        log::warn!(
            "[advance-on-proof] reject: bridge claims {} sigs (>= k={}) — \
             a full-quorum transition must use the normal /register path — wallet={}",
            n, QUORUM_K, hex::encode(&reg.wallet_id[..4]),
        );
        return Err(NablaError::InvalidReceipt);
    }
    // Each sub-quorum witness signed Nabla's receipt payload over the
    // X → P transition. The partial's signatures were created with the
    // same tick=0 convention Lambda uses for receipt payloads (it signs
    // Nabla receipt payloads with tick=0 — see step 5's comment); verify
    // with tick=0 to match.
    let partial_payload = crypto::receipt_sign_payload(
        &reg.wallet_id,
        &bridge.consumed_state_id,
        0,
    );
    for ws in &bridge.witness_sigs {
        if !signer.verify(&ws.validator_pk, &partial_payload, &ws.signature) {
            log::warn!(
                "[advance-on-proof] reject: forged/invalid partial sig — wallet={}",
                hex::encode(&reg.wallet_id[..4]),
            );
            return Err(NablaError::InvalidReceipt);
        }
    }

    // ── All four checks passed: advance the SMT across the proven link ──
    //
    // Record the partial txid FIRST (txid bloom is monotonic — recording
    // before the SMT write keeps double-redeem detection complete even if
    // the WAL append below fails and the caller aborts).
    smt.record_txid(&bridge.tx_hash, &reg.wallet_id);

    // The intervening SMT entry for the bridged state P. Reuse the SMT's
    // existing client_pk/client_sig — the wallet identity is unchanged
    // across the partial; the heal `Registration` that follows carries the
    // fresh client_pk/client_sig for the final P → H step.
    let bridged_entry = NablaEntry {
        wallet_id: reg.wallet_id,
        // WI3: the partial `P` sits one chain step below the heal `H` that
        // immediately overwrites it (seq is +1 per transition), so seq(P) =
        // heal_seq - 1. This keeps the bridge a forward-advance (above X) yet
        // strictly below the heal entry written next, which supersedes it.
        wallet_seq: reg.receipt.new_wallet_seq.saturating_sub(1),
        current_state: bridge.produced_state_id,
        tx_hash: bridge.tx_hash,
        tick: current_tick,
        group_members: None,
        status: WalletStatus::Normal,
        client_pk: *smt_client_pk,
        client_sig: smt_client_sig.to_vec(),
    };
    let serialized = bincode::serialize(&bridged_entry)
        .map_err(|e| NablaError::SerializationError(e.to_string()))?;
    wal.append(&WalOp::Put {
        key: reg.wallet_id,
        value: serialized,
        client_pk: *smt_client_pk,
        client_sig: smt_client_sig.to_vec(),
    })
    .map_err(|e| NablaError::WalError(e.to_string()))?;
    smt.put(&bridged_entry);

    log::info!(
        "[advance-on-proof] SMT advanced across proven sub-quorum link — \
         wallet={} {} -> {} (n={} partial sigs, superseding k=3 heal verified); \
         partial txid {} recorded",
        hex::encode(&reg.wallet_id[..4]),
        hex::encode(&bridge.consumed_state_id[..4]),
        hex::encode(&bridge.produced_state_id[..4]),
        n,
        hex::encode(&bridge.tx_hash[..4]),
    );

    Ok(())
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

    // ── 5. Verify k=3 receipt signatures via Core (Signer trait) ──
    if greg.receipt.signatures.len() < 3 {
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

    // ── 7. Check for conflicts ──
    if let Some(existing) = smt.get(&greg.wallet_id) {
        if existing.current_state != greg.old_state {
            let evidence_existing = ConflictProof {
                old_state: [0u8; 32],
                new_state: existing.current_state,
                tx_hash: existing.tx_hash,
                k3_signatures: Vec::new(),
                tick: existing.tick,
            };
            let evidence_new = ConflictProof {
                old_state: greg.old_state,
                new_state: greg.new_state,
                tx_hash: greg.tx_hash,
                k3_signatures: greg.receipt.signatures.iter().map(|s| WitnessSig {
                    validator_pk: s.validator_pk,
                    signature: s.signature.clone(),
                    execution_proof: s.execution_proof.clone(),
                    proof_type: s.proof_type,
                    receipt_commitment_sig: s.receipt_commitment_sig.clone(),
                    validator_id: s.validator_id,
                    slot_amount: s.slot_amount,
                }).collect(),
                tick: greg.receipt.tick,
            };

            let ban_evidence = BannedEntry {
                wallet_id: greg.wallet_id,
                evidence_1: evidence_existing,
                evidence_2: evidence_new,
                seq_fork: None,
                status: BanStatus::Active,
            };
            let ban_bytes = bincode::serialize(&ban_evidence)
                .map_err(|e| NablaError::SerializationError(e.to_string()))?;
            wal.append(&WalOp::Ban {
                wallet_id: greg.wallet_id,
                evidence: ban_bytes,
            }).map_err(|e| NablaError::WalError(e.to_string()))?;

            bans.ban(greg.wallet_id, ban_evidence.evidence_1, ban_evidence.evidence_2);
            return Err(NablaError::DoubleSpendDetected);
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
    };

    let serialized = bincode::serialize(&new_entry)
        .map_err(|e| NablaError::SerializationError(e.to_string()))?;

    wal.append(&WalOp::Put {
        key: greg.wallet_id,
        value: serialized,
        client_pk: [0u8; 32],
        client_sig: vec![0u8; 64],
    }).map_err(|e| NablaError::WalError(e.to_string()))?;

    // ── 9. Update SMT ──
    let new_root = smt.put(&new_entry);

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
        let tx_hash_payload = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_TXHASH");
            h.update(&greg.old_state);
            h.update(&greg.new_state);
            *h.finalize().as_bytes()
        };
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_FACT_CONFIRM");
        h.update(&tx_hash_payload);
        h.update(&greg.new_state);
        let payload = h.finalize();
        signer.sign(payload.as_bytes())
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
    Ok(RegistrationResult { ack, gossip_msg, hibernation_until: None, committed_recalls: Vec::new() })
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

/// KI#34 WI3 hole-1: verify that a gossiped/anti-entropy `SeqProof` genuinely
/// k-attests `wallet_seq` for `txid`. Mirrors the §5b receipt-commitment verify
/// above (`process_registration`) — recomputes the SAME canonical
/// `compute_receipt_commitment` (one builder, CLAUDE.md §12) and checks the
/// carried Ed25519 sigs. Lives HERE, not in `types.rs`, because this is the
/// sanctioned hot-path home for receipt-commitment verification (Core is the
/// sole crypto authority; nabla touches the core-logic primitive only in the
/// files exempted by `cc::tests::no_direct_core_crypto_in_production_code`).
///
/// Returns true iff ≥`MIN_FACT_WITNESSES` DISTINCT validators signed
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
) -> Option<axiom_core_logic::types::NablaOodsAttestation> {
    let own_nbc = crate::cc::deserialize_nbc(own_nbc_bytes).ok()?;
    let baseline_size = own_nbc.network_size_baseline;
    let baseline_tick = own_nbc.baseline_tick;
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

pub fn verify_seq_proof(proof: &SeqProof, txid: &TxHash, wallet_seq: u64) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let commitment = axiom_core_logic::compute::compute_receipt_commitment(
        txid,
        &proof.state_hash,
        wallet_seq,
        &proof.commitment_hash,
        proof.epoch,
        proof.is_dev_class,
        proof.oods_flag.as_ref(),
    );
    let mut distinct: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
    for s in &proof.sigs {
        if s.receipt_commitment_sig.len() != 64 {
            continue;
        }
        let Ok(vk) = VerifyingKey::from_bytes(&s.validator_pk) else {
            continue;
        };
        let sig_bytes: [u8; 64] = match s.receipt_commitment_sig.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => continue,
        };
        if vk.verify(&commitment, &Signature::from_bytes(&sig_bytes)).is_ok() {
            distinct.insert(s.validator_pk);
        }
    }
    let ok = distinct.len() >= axiom_core_logic::fact::MIN_FACT_WITNESSES;
    // KI#38 diagnosis: when a CARRIED proof fails, name WHY — how many of the k
    // sigs matched the recomputed commitment, and every commitment input — so we
    // can see which field (txid / seq / state_hash / commitment_hash / epoch /
    // dev / oods) diverges from what the k validators signed. Rate-bounded by
    // the AE reject cadence; remove once KI#38 is closed.
    if !ok {
        log::info!(
            "[SEQPROOF-FAIL] matched={}/{} need={} txid={:02x}{:02x} seq={} state_hash={:02x}{:02x} cmit={:02x}{:02x} epoch={} dev={} oods={} commitment={:02x}{:02x}",
            distinct.len(), proof.sigs.len(), axiom_core_logic::fact::MIN_FACT_WITNESSES,
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

                let outputs = verifier.verify(&receipt)
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

#[cfg(test)]
mod tests {
    use super::*;

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
            is_recall: false,
            wallet_id,
            old_state,
            new_state,
            tx_hash,
            receipt: K3Receipt {
                oods_flag: None,
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
            partial_bridge: None,
            claimant_wallet_id: String::new(),
            is_dev_claim: false,
            burn_target_tx_id: None,
        };

        let deed = DeedTransaction {
            sender_wallet_id: wallet_id,
            receiver_wallet_id: DEED_PROTOCOL_WALLET_ID,
            amount: DEED_WRITE_FEE,
            signature: vec![0xFF; 64],
        };

        (reg, deed)
    }

    /// Test helper: sign the receipt_commitment with 3 real ed25519 keys so a
    /// recall/HAL registration passes `verify_receipt_commitment_sigs` (§6c). Real
    /// recalls ALWAYS carry these — the witness signs the commitment on every
    /// k-witness path (consensus.rs 3368/3753/3891). The base fixture omits them
    /// because non-recall paths with an empty fee_breakdown never check them. Call
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
            reg.receipt.oods_flag.as_ref(),
        );
        for (i, ws) in reg.receipt.signatures.iter_mut().enumerate() {
            let sk = SigningKey::from_bytes(&[(i as u8) + 1; 32]);
            ws.validator_pk = sk.verifying_key().to_bytes();
            ws.receipt_commitment_sig = sk.sign(&commitment).to_bytes().to_vec();
        }
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
            process_registration(&mut smt, &mut wal, &mut bans, &reg, &deed, 1, &mut deed_collected, &crate::crypto::NoopSigner, None, None, None, None, None, None, &[])
                .unwrap();

        assert_eq!(result.ack.wallet_id[0], 0xAA);
        assert_eq!(result.ack.new_state[0], 0x01);
        assert_eq!(smt.len(), 1);
        assert_eq!(deed_collected, DEED_WRITE_FEE);
        // No execution proofs → zkp_verified must be false (bootstrap/legacy)
        assert!(!result.ack.zkp_verified, "empty proofs must NOT set zkp_verified");
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
        process_registration(&mut smt, &mut wal, &mut bans, &reg, &deed, 1, &mut deed_collected,
            &crate::crypto::NoopSigner, None, None, None, None, None, None, &[]).unwrap();
        assert!(smt.is_txid_completed(&reg.tx_hash),
            "B2: a k-witnessed register must mark the txid completed");
        // Completed + NOT redeemed → recallable (retract the undelivered cheque), when
        // aged into the recall window (completion tick was 1, so recall in [1+LOW, 1+HIGH]).
        let in_window = 1 + crate::smt::RECALL_INIT_WINDOW_LOW.to_secs() + 5;
        assert!(smt.register_recall(reg.tx_hash, vec![0xB2u8; 32], in_window).is_ok(),
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
        process_registration(&mut smt, &mut wal, &mut bans, &send_reg, &deed, 1, &mut deed_collected,
            &crate::crypto::NoopSigner, None, None, None, None, None, None, &[]).unwrap();

        // 2. Initiate = RESERVATION: pending, NOT terminal — `C` still redeemable.
        let sender_pk = send_reg.wallet_id.to_vec();
        let in_window = 1 + crate::smt::RECALL_INIT_WINDOW_LOW.to_secs() + 5;
        smt.register_recall(send_reg.tx_hash, sender_pk.clone(), in_window).unwrap();
        assert!(smt.is_txid_recall_pending(&send_reg.tx_hash), "reserved = RETRACT_PENDING");
        assert!(!smt.is_txid_recalled(&send_reg.tx_hash),
            "a reservation must NOT block the redeem — C stays live until hibernation-entry");

        // 3. The recall self-send's register (is_recall) = COMMIT.
        let (mut recall_reg, deed2) = make_valid_registration(0xB3, 0x01, 0x02);
        recall_reg.is_recall = true;
        // Real recalls carry k-signed receipt_commitment_sigs; §6c now requires them.
        attest_receipt_commitment(&mut recall_reg);
        let result = process_registration(&mut smt, &mut wal, &mut bans, &recall_reg, &deed2,
            in_window + 1, &mut deed_collected,
            &crate::crypto::NoopSigner, None, None, None, None, None, None, &[]).unwrap();
        assert_eq!(result.committed_recalls, vec![(send_reg.tx_hash, in_window)],
            "commit must hand the (txid, reservation_tick) to the node handler for garbage+flood");
        assert!(smt.is_txid_recalled(&send_reg.tx_hash), "committed = terminal, C is dead");
        assert!(!smt.is_txid_recall_pending(&send_reg.tx_hash));
        assert!(result.hibernation_until.is_some(), "recall commit stamps the hibernation lock");

        // 4. Another is_recall register with NO open reservation → refused.
        let (mut stray, deed3) = make_valid_registration(0xB3, 0x02, 0x03);
        stray.is_recall = true;
        let refused = process_registration(&mut smt, &mut wal, &mut bans, &stray, &deed3,
            in_window + 2, &mut deed_collected,
            &crate::crypto::NoopSigner, None, None, None, None, None, None, &[]);
        assert!(matches!(refused, Err(NablaError::RecallAborted)),
            "is_recall register without an open reservation must fail closed, got {refused:?}");
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
        process_registration(&mut smt, &mut wal, &mut bans, &send_reg, &deed, 1, &mut deed_collected,
            &crate::crypto::NoopSigner, None, None, None, None, None, None, &[]).unwrap();

        let sender_pk = send_reg.wallet_id.to_vec();
        let in_window = 1 + crate::smt::RECALL_INIT_WINDOW_LOW.to_secs() + 5;
        smt.register_recall(send_reg.tx_hash, sender_pk.clone(), in_window).unwrap();
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
            in_window + 1, &mut deed_collected,
            &crate::crypto::NoopSigner, None, None, None, None, None, None, &[]);
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
        process_registration(&mut smt, &mut wal, &mut bans, &send_reg, &deed, 1, &mut deed_collected,
            &crate::crypto::NoopSigner, None, None, None, None, None, None, &[]).unwrap();
        let in_window = 1 + crate::smt::RECALL_INIT_WINDOW_LOW.to_secs() + 5;
        smt.register_recall(send_reg.tx_hash, send_reg.wallet_id.to_vec(), in_window).unwrap();

        // PUBLIC recall, honestly attested over is_dev_class=false, then TAMPERED to
        // is_dev_class=true WITHOUT re-signing → the commitment sig no longer matches.
        let (mut forged_reg, deed2) = make_valid_registration(0xC1, 0x01, 0x02);
        forged_reg.is_recall = true;
        forged_reg.receipt.is_dev_class = false;
        attest_receipt_commitment(&mut forged_reg);      // sigs cover is_dev_class=false
        forged_reg.receipt.is_dev_class = true;          // FORGE the short-window flag
        let forged = process_registration(&mut smt, &mut wal, &mut bans, &forged_reg, &deed2,
            in_window + 1, &mut deed_collected,
            &crate::crypto::NoopSigner, None, None, None, None, None, None, &[]);
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
            in_window + 2, &mut deed_collected,
            &crate::crypto::NoopSigner, None, None, None, None, None, None, &[]).unwrap();
        assert!(ok.hibernation_until.is_some(), "honest public recall stamps its finish-gate window");
        assert!(smt.is_txid_recalled(&send_reg.tx_hash), "honest recall commits — C dead");
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
            &mut smt, &mut wal, &mut bans, &reg, &deed, 1, &mut deed_collected,
            &crate::crypto::NoopSigner, None, None, None, None, None, None, &[],
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
            &mut smt, &mut wal, &mut bans, &reg2, &deed2, 1, &mut deed_collected,
            &crate::crypto::NoopSigner, None, None, None, None, None, None, &[],
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
            1,
            &mut deed_collected,
            &crate::crypto::NoopSigner,
            None,
            None, None, None, None, None, &[],
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
            2,
            &mut deed_collected,
            &crate::crypto::NoopSigner,
            None,
            None, None, None, None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner, None, None, None, None, None, None, &[],
        ).unwrap();

        let smt_len_after_first = smt.len();
        let deed_after_first = deed_collected;
        let conf_sig_1 = result1.ack.fact_confirm_signature.clone();
        let new_state_1 = result1.ack.new_state;

        // Retry the SAME registration (simulates lost ACK on return path).
        let result2 = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            2, &mut deed_collected, &crate::crypto::NoopSigner, None, None, None, None, None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner, None, None, None, None, None, None, &[],
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
            2, &mut deed_collected, &crate::crypto::NoopSigner, None, None, None, None, None, None, &[],
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
            1,
            &mut deed_collected,
            &crate::crypto::NoopSigner,
            None,
            None, None, None, None, None, &[],
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
            2,
            &mut deed_collected,
            &crate::crypto::NoopSigner,
            None,
            None, None, None, None, None, &[],
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
                k3_signatures: vec![],
                tick: 0,
            },
            ConflictProof {
                old_state: [0; 32],
                new_state: [3; 32],
                tx_hash: [4; 32],
                k3_signatures: vec![],
                tick: 0,
            },
        );

        let (reg, deed) = make_valid_registration(0xAA, 0x00, 0x01);
        let result = process_registration(
            &mut smt,
            &mut wal,
            &mut bans,
            &reg,
            &deed,
            1,
            &mut deed_collected,
            &crate::crypto::NoopSigner,
            None,
            None, None, None, None, None, &[],
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
            1,
            &mut deed_collected,
            &crate::crypto::NoopSigner,
            None,
            None, None, None, None, None, &[],
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
            1,
            &mut deed_collected,
            &crate::crypto::NoopSigner,
            None,
            None, None, None, None, None, &[],
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
            1,
            &mut deed_collected,
            &crate::crypto::NoopSigner,
            None,
            None, None, None, None, None, &[],
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
            1,
            &mut deed_collected,
            &crate::crypto::NoopSigner,
            None,
            None, None, None, None, None, &[],
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
                oods_flag: None,
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

    // ── Advance-on-proof tests (KI #5) ──────────────────────────────
    //
    // These exercise the `verify_and_apply_partial_bridge` branch of
    // `process_registration`. They use a REAL Ed25519 signer (not
    // NoopSigner) so the signature checks are genuinely exercised —
    // a forged sig MUST be caught.

    use crate::crypto::{Ed25519Signer, Signer as _};
    use crate::types::PartialBridgeReceipt;

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
    /// keys, anchored at `consumed -> produced`. Used as the heal-forward
    /// register that carries a `partial_bridge`.
    fn signed_registration(
        validators: &[TestValidator],
        wid_byte: u8,
        consumed: [u8; 32],
        produced: [u8; 32],
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
            is_recall: false,
            wallet_id,
            old_state: consumed,
            new_state: produced,
            tx_hash,
            receipt: K3Receipt {
                oods_flag: None,
                consumed_state_id: consumed,
                produced_state_id: produced,
                amount: 100,
                signatures,
                program_digest: [0u8; 32],
                tick: 0,
                state_hash: [0u8; 32],
                new_wallet_seq: 0,
                commitment_hash: [0u8; 32],
                epoch: 0,
                fee_breakdown: vec![],
            is_dev_class: false,
            },
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
            is_genesis_claim: false,
            is_hal_reanchor: false,
            partial_bridge: None,
            claimant_wallet_id: String::new(),
            is_dev_claim: false,
            burn_target_tx_id: None,
        };
        let deed = DeedTransaction {
            sender_wallet_id: wallet_id,
            receiver_wallet_id: DEED_PROTOCOL_WALLET_ID,
            amount: DEED_WRITE_FEE,
            signature: vec![0xFF; 64],
        };
        (reg, deed)
    }

    /// Build a `PartialBridgeReceipt` proving the sub-quorum link `x -> p`.
    /// The superseding k=3 heal is the register's own `reg.receipt` (spec
    /// §4.3 check 3) — it is NOT carried inside the bridge.
    fn make_bridge(
        partial_validators: &[TestValidator],
        wallet_id: &[u8; 32],
        x: [u8; 32],
        p: [u8; 32],
        partial_txid: [u8; 32],
    ) -> PartialBridgeReceipt {
        let witness_sigs: Vec<WitnessSig> = partial_validators
            .iter()
            .map(|v| signed_k3_sig(v, wallet_id, &x, &partial_txid, 0))
            .collect();
        PartialBridgeReceipt {
            consumed_state_id: x,
            produced_state_id: p,
            tx_hash: partial_txid,
            witness_sigs,
        }
    }

    fn st(b: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = b;
        s
    }

    /// Seed the SMT with a wallet pinned at state `x` (the pre-partial
    /// state), simulating the post-k=2-partial lockout condition.
    fn smt_pinned_at(
        smt: &mut SparseMerkleTree,
        wallet_id: [u8; 32],
        x: [u8; 32],
    ) {
        let entry = NablaEntry {
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
    fn advance_on_proof_accepts_valid_k2_bridge() {
        // The happy path: SMT pinned at X, heal register at P->H carries a
        // bridge proving the k=2 partial X->P. Nabla must advance the SMT
        // across X->P, then apply P->H.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::with_txid_mode(
            crate::bloom::TxidServiceMode::Hashmap,
        );
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let signer = Ed25519Signer::from_node_index(999);

        let (x, p, h) = (st(0x01), st(0x02), st(0x03));
        // 3 heal validators (full quorum), 2 partial validators (sub-quorum).
        let heal_vals: Vec<TestValidator> =
            (10..13).map(TestValidator::new).collect();
        let partial_vals: Vec<TestValidator> =
            (10..12).map(TestValidator::new).collect();

        let (mut reg, deed) = signed_registration(&heal_vals, 0xC5, p, h);
        let partial_txid = st(0x77);
        let bridge = make_bridge(
            &partial_vals, &reg.wallet_id, x, p, partial_txid,
        );
        reg.partial_bridge = Some(bridge);

        // SMT pinned at X (the post-k=2-partial lockout).
        smt_pinned_at(&mut smt, reg.wallet_id, x);

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            5, &mut deed_collected, &signer, None, None, None, None, None, None, &[],
        );
        assert!(result.is_ok(), "valid k=2 bridge must be accepted: {:?}",
            result.err());

        // SMT advanced all the way to H (X -> P via bridge, then P -> H).
        let entry = smt.get(&reg.wallet_id).unwrap();
        assert_eq!(entry.current_state, h,
            "SMT must end at H after advance-on-proof + register");
        // Partial txid recorded for double-redeem detection.
        assert_eq!(smt.get_wallet_by_txid(&partial_txid), Some(reg.wallet_id),
            "the partial txid must be recorded in the txid index");
    }

    #[test]
    fn advance_on_proof_none_bridge_still_rejects_state_mismatch() {
        // Pure-ADD guarantee: with `partial_bridge: None` an out-of-sync
        // register is still a hard StateMismatch — byte-identical to
        // pre-KI#5 behaviour.
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
        // No bridge.
        assert!(reg.partial_bridge.is_none());

        smt_pinned_at(&mut smt, reg.wallet_id, x);

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            5, &mut deed_collected, &signer, None, None, None, None, None, None, &[],
        );
        assert!(matches!(result, Err(NablaError::StateMismatch)),
            "out-of-sync register with NO bridge must reject StateMismatch");
    }

    #[test]
    fn advance_on_proof_rejects_continuity_mismatch() {
        // The bridge's `consumed_state_id` does not equal the SMT entry —
        // the bridge is not anchored. Reject.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let signer = Ed25519Signer::from_node_index(999);

        let (x, p, h) = (st(0x01), st(0x02), st(0x03));
        let heal_vals: Vec<TestValidator> =
            (10..13).map(TestValidator::new).collect();
        let partial_vals: Vec<TestValidator> =
            (10..12).map(TestValidator::new).collect();

        let (mut reg, deed) = signed_registration(&heal_vals, 0xC5, p, h);
        // Bridge claims to start at a DIFFERENT state than the SMT (0x09).
        let bogus_x = st(0x09);
        let bridge = make_bridge(
            &partial_vals, &reg.wallet_id, bogus_x, p, st(0x77),
        );
        reg.partial_bridge = Some(bridge);

        smt_pinned_at(&mut smt, reg.wallet_id, x); // SMT at 0x01, bridge at 0x09

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            5, &mut deed_collected, &signer, None, None, None, None, None, None, &[],
        );
        assert!(matches!(result, Err(NablaError::StateMismatch)),
            "bridge not anchored to the SMT entry must reject");
    }

    #[test]
    fn advance_on_proof_rejects_multi_partial_gap() {
        // Multi-partial guard (spec §7): the bridge proves ONE link
        // (X -> P), but the heal register begins at P2 (a second,
        // unproven partial state). `produced_state_id != reg.old_state`.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let signer = Ed25519Signer::from_node_index(999);

        let (x, p, p2, h) = (st(0x01), st(0x02), st(0x04), st(0x03));
        let heal_vals: Vec<TestValidator> =
            (10..13).map(TestValidator::new).collect();
        let partial_vals: Vec<TestValidator> =
            (10..12).map(TestValidator::new).collect();

        // Heal register begins at P2 (two steps past X).
        let (mut reg, deed) = signed_registration(&heal_vals, 0xC5, p2, h);
        // Bridge only proves X -> P (one step). P != P2.
        let bridge = make_bridge(
            &partial_vals, &reg.wallet_id, x, p, st(0x77),
        );
        reg.partial_bridge = Some(bridge);

        smt_pinned_at(&mut smt, reg.wallet_id, x);

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            5, &mut deed_collected, &signer, None, None, None, None, None, None, &[],
        );
        assert!(matches!(result, Err(NablaError::StateMismatch)),
            "a >1-step gap (bridge.new != reg.old) must reject");
    }

    #[test]
    fn advance_on_proof_rejects_zero_sub_quorum_sigs() {
        // n == 0 — a partial with no committers advanced nothing.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let signer = Ed25519Signer::from_node_index(999);

        let (x, p, h) = (st(0x01), st(0x02), st(0x03));
        let heal_vals: Vec<TestValidator> =
            (10..13).map(TestValidator::new).collect();
        let (mut reg, deed) = signed_registration(&heal_vals, 0xC5, p, h);
        let mut bridge = make_bridge(
            &[], &reg.wallet_id, x, p, st(0x77),
        );
        bridge.witness_sigs.clear(); // n == 0
        reg.partial_bridge = Some(bridge);

        smt_pinned_at(&mut smt, reg.wallet_id, x);

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            5, &mut deed_collected, &signer, None, None, None, None, None, None, &[],
        );
        assert!(matches!(result, Err(NablaError::InvalidReceipt)),
            "n == 0 sub-quorum sigs must reject");
    }

    #[test]
    fn advance_on_proof_rejects_full_quorum_sub_sigs() {
        // n >= k (3) — a full-quorum transition is a normal register,
        // never a "partial". Must be rejected as suspicious.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let signer = Ed25519Signer::from_node_index(999);

        let (x, p, h) = (st(0x01), st(0x02), st(0x03));
        let heal_vals: Vec<TestValidator> =
            (10..13).map(TestValidator::new).collect();
        // THREE partial validators — full quorum, not a partial.
        let partial_vals: Vec<TestValidator> =
            (10..13).map(TestValidator::new).collect();

        let (mut reg, deed) = signed_registration(&heal_vals, 0xC5, p, h);
        let bridge = make_bridge(
            &partial_vals, &reg.wallet_id, x, p, st(0x77),
        );
        assert_eq!(bridge.witness_sigs.len(), 3);
        reg.partial_bridge = Some(bridge);

        smt_pinned_at(&mut smt, reg.wallet_id, x);

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            5, &mut deed_collected, &signer, None, None, None, None, None, None, &[],
        );
        assert!(matches!(result, Err(NablaError::InvalidReceipt)),
            "n >= k sub-quorum sigs must reject (not a real partial)");
    }

    #[test]
    fn advance_on_proof_rejects_forged_partial_sig() {
        // A forged sub-quorum sig (random bytes) must fail Ed25519 verify.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let signer = Ed25519Signer::from_node_index(999);

        let (x, p, h) = (st(0x01), st(0x02), st(0x03));
        let heal_vals: Vec<TestValidator> =
            (10..13).map(TestValidator::new).collect();
        let partial_vals: Vec<TestValidator> =
            (10..12).map(TestValidator::new).collect();

        let (mut reg, deed) = signed_registration(&heal_vals, 0xC5, p, h);
        let mut bridge = make_bridge(
            &partial_vals, &reg.wallet_id, x, p, st(0x77),
        );
        // Forge the first partial sig — keep the real pubkey, garbage sig.
        bridge.witness_sigs[0].signature = vec![0xAB; 64];
        reg.partial_bridge = Some(bridge);

        smt_pinned_at(&mut smt, reg.wallet_id, x);

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            5, &mut deed_collected, &signer, None, None, None, None, None, None, &[],
        );
        assert!(matches!(result, Err(NablaError::InvalidReceipt)),
            "a forged sub-quorum sig must reject");
    }

    #[test]
    fn advance_on_proof_requires_superseding_k3_heal_receipt() {
        // Check 3 / spec §5 "bare k=2 register sneaking in?". The bridge
        // is honoured ONLY because the register's own receipt is a k=3
        // heal that supersedes P. A bare sub-quorum register (the main
        // `reg.receipt` carries only 2 sigs) — even with an otherwise
        // valid bridge — must still be rejected. (`process_registration`
        // step 5 enforces the k=3 minimum; this test proves the bridge
        // path does NOT smuggle a sub-quorum register past it.)
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let signer = Ed25519Signer::from_node_index(999);

        let (x, p, h) = (st(0x01), st(0x02), st(0x03));
        let heal_vals: Vec<TestValidator> =
            (10..13).map(TestValidator::new).collect();
        let partial_vals: Vec<TestValidator> =
            (10..12).map(TestValidator::new).collect();

        let (mut reg, deed) = signed_registration(&heal_vals, 0xC5, p, h);
        // Downgrade the register's own receipt to a bare k=2 — there is
        // now NO superseding k=3 heal.
        reg.receipt.signatures.truncate(2);
        let bridge = make_bridge(
            &partial_vals, &reg.wallet_id, x, p, st(0x77),
        );
        reg.partial_bridge = Some(bridge);

        smt_pinned_at(&mut smt, reg.wallet_id, x);

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            5, &mut deed_collected, &signer, None, None, None, None, None, None, &[],
        );
        assert!(matches!(result, Err(NablaError::InvalidReceipt)),
            "a bare sub-quorum register must NOT be honoured via the \
             bridge path — a superseding k=3 heal receipt is required");
        // SMT must be untouched.
        assert_eq!(smt.get(&reg.wallet_id).unwrap().current_state, x);
    }

    #[test]
    fn advance_on_proof_rejects_rewind_bridge() {
        // Advance-only / no-rewind. A bridge whose `produced_state_id`
        // does NOT advance the SMT forward to where the heal register
        // begins is rejected. Here the bridge ends back at X (a rewind /
        // no-op) while the heal register begins at P — the flush check
        // (`produced_state_id == reg.old_state`) catches it.
        //
        // The SMT can only ever advance: it is mutated solely to
        // `produced_state_id` (and then `reg.new_state`), and a bridge is
        // applied only when `consumed_state_id == smt_state`. There is no
        // code path that writes a *prior* state back — a rewound bridge
        // never gets past the continuity checks.
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("t.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;
        let signer = Ed25519Signer::from_node_index(999);

        let (x, p, h) = (st(0x01), st(0x02), st(0x03));
        let heal_vals: Vec<TestValidator> =
            (10..13).map(TestValidator::new).collect();
        let partial_vals: Vec<TestValidator> =
            (10..12).map(TestValidator::new).collect();

        // Heal register begins at P (one step past the SMT's X).
        let (mut reg, deed) = signed_registration(&heal_vals, 0xC5, p, h);
        // Rewind bridge: anchored correctly at X, but `produced_state_id`
        // is X again — it advances nothing.
        let bridge = make_bridge(
            &partial_vals, &reg.wallet_id, x, x, st(0x77),
        );
        reg.partial_bridge = Some(bridge);

        smt_pinned_at(&mut smt, reg.wallet_id, x);

        let result = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            5, &mut deed_collected, &signer, None, None, None, None, None, None, &[],
        );
        assert!(matches!(result, Err(NablaError::StateMismatch)),
            "a rewind/no-advance bridge must reject");

        // SMT must NOT have moved — still pinned at X.
        assert_eq!(smt.get(&reg.wallet_id).unwrap().current_state, x,
            "a rejected bridge must leave the SMT untouched");
    }

    #[test]
    fn group_register_double_spend_bans() {
        let dir = tempfile::tempdir().unwrap();
        let mut smt = SparseMerkleTree::new();
        let mut wal = WriteAheadLog::open(dir.path().join("test.wal")).unwrap();
        let mut bans = BanTable::new();
        let mut deed_collected = 0u64;

        // First registration
        let (greg1, deed1) = make_group_registration(0xEE, 0x00, 0x01);
        process_group_registration(
            &mut smt, &mut wal, &mut bans, &greg1, &deed1, 1, &mut deed_collected,
            &crate::crypto::NoopSigner,
        ).unwrap();

        // Second with same old_state → conflict
        let (greg2, deed2) = make_group_registration(0xEE, 0x00, 0x02);
        let result = process_group_registration(
            &mut smt, &mut wal, &mut bans, &greg2, &deed2, 2, &mut deed_collected,
            &crate::crypto::NoopSigner,
        );

        assert!(matches!(result, Err(NablaError::DoubleSpendDetected)));
        assert!(bans.is_banned(&greg1.wallet_id));
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
        let mut pk = [0u8; 32];
        pk[0] = pk_byte0;
        let salt_hash = blake3::hash(&pk);
        let salt = &hex::encode(salt_hash.as_bytes())[..2];
        let claimant_wallet_id = generate_wallet_id(email, salt, &pk).unwrap();
        let (mut reg, deed) = make_valid_registration(pk_byte0, 0x00, new_state_byte);
        reg.wallet_id = pk;
        reg.is_genesis_claim = true;
        reg.claimant_wallet_id = claimant_wallet_id;
        reg.is_dev_claim = is_dev_claim;
        (reg, deed, pk)
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, &[],
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
        reg.wallet_id = [0xFFu8; 32];  // pk that didn't produce this wallet_id
        let err = process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, &[],
        ).expect("first dev claim must succeed");
        assert_eq!(dev_treasury.balance(), 0, "pool drained");

        let (reg2, deed2, _pk2) = make_genesis_claim_reg("dev2@axiom.internal", true, 0xD4, 0x01);
        let err = process_registration(
            &mut smt, &mut wal, &mut bans, &reg2, &deed2,
            2, &mut deed_collected, &crate::crypto::NoopSigner,
            Some(&mut airdrop), Some(&mut dev_treasury), None, None, None, None, &[],
        ).expect_err("exhausted dev pool must hard-reject");
        assert!(matches!(err, NablaError::PoolExhausted));
        assert_eq!(airdrop.local_claims, 0, "public pool untouched");
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
        let state_hash = [0x33; 32];
        let new_wallet_seq = 7;
        let commitment_hash = [0x77; 32];
        let epoch = 1_700_000_000;

        let _ = produced; // skeleton-only commitment no longer binds produced_state_id
        let commitment = axiom_core_logic::compute::compute_receipt_commitment(
            &tx_hash,
            &state_hash,
            new_wallet_seq,
            &commitment_hash,
            epoch,
            is_dev_class, None,
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
            is_recall: false,
            wallet_id,
            old_state: consumed,
            new_state: produced,
            tx_hash,
            receipt: K3Receipt {
                oods_flag: None,
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
            partial_bridge: None,
            claimant_wallet_id: String::new(),
            is_dev_claim: false,
            burn_target_tx_id: None,
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, None, None, None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, None, None, None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, None, None, None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, None, None, None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, None, None, None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, None, None, None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, None, None, None, None, &[],
        ).expect_err("missing receipt_commitment_sig must reject");
        assert!(matches!(err, NablaError::InvalidReceipt));
    }

    // ───────────────────────────────────────────────────────────────────
    // YP §20.8 / §20.11 — DEED pool credit at receiver's /register
    // ───────────────────────────────────────────────────────────────────

    use crate::node::DeedPool;

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

        process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, Some(&mut deed_pool), None, None, None, &[],
        ).expect("valid fee-carrying register must succeed");

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

        process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None,
            Some(&mut public_deed_pool),
            Some(&mut public_ledger),
            Some(&mut dev_deed_pool),
            Some(&mut dev_ledger),
            &[],
        ).expect("dev-class register must succeed (same wire path, different pool routing)");

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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None,
            Some(&mut public_deed_pool),
            Some(&mut public_ledger),
            Some(&mut dev_deed_pool),
            Some(&mut dev_ledger),
            &[],
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

        process_registration(
            &mut smt, &mut wal, &mut bans, &reg, &deed,
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, Some(&mut deed_pool), Some(&mut ledger), None, None, &[],
        ).expect("valid fee-carrying register must succeed");

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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, None, Some(&mut ledger), None, None, &[],
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
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, Some(&mut deed_pool), None, None, None, &[],
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

        process_registration(
            &mut smt, &mut wal, &mut bans, &reg1, &deed1,
            1, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, Some(&mut deed_pool), None, None, None, &[],
        ).expect("first fee register OK");
        process_registration(
            &mut smt, &mut wal, &mut bans, &reg2, &deed2,
            2, &mut deed_collected, &crate::crypto::NoopSigner,
            None, None, Some(&mut deed_pool), None, None, None, &[],
        ).expect("second fee register OK");

        // 10/10 + 20/10 = 1 + 2 = 3 atoms
        assert_eq!(deed_pool.balance(), 3,
            "DEED pool must accumulate across registers");
        assert_eq!(deed_pool.total_credited(), 3);
        assert_eq!(deed_pool.last_credit_tick, 2,
            "last_credit_tick must reflect most-recent register");
    }
}
