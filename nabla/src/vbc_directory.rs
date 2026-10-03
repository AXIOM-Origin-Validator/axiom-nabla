//! ForkSettlement wave 4a — the SELF-PROVING validator witness directory.
//!
//! The KI#170 VBC registration registry, made self-proving (design
//! `docs/AXIOM_DESIGN_ForkSettlement.md` §9c R37 as CORRECTED by §9d R42/R42a,
//! with §9e R50 for the anti-entropy exchange). Closes KI#223.
//!
//! **Which network (RULE 7 §4).** This is a VALIDATOR fact held by Nabla: the
//! entries are VBCs (three issuers, `ROOT_AUTHORITY_PKS`, stake floor). An NBC
//! (one issuer) is refused by structure — `issuer_set.len()` — before any
//! crypto. Nabla never asks a validator anything: every entry is a certificate
//! PRESENTED to Nabla (by the stake wallet at registration, or by a peer in
//! AE) and verified here from the bytes alone.
//!
//! **What an entry is.** Exactly one stamped certificate plus its supporting
//! chain (`VbcRegistrationRecord`). Nothing else rides with it: the consume-once
//! key (`vbc_hash`), the stake wallet, the stamp tick and balance, the
//! `validator_id` and `expires_at` are all READ OUT OF the verified
//! certificate and its stamp. No field is taken from a message, so there is
//! no field that can disagree with its bundle (R42 "every entry field BOUND to
//! the verified bundle"). The pre-4a record carried five free fields beside a
//! `vbc_hash` key and was set-unioned unverified — that was KI#223.
//!
//! **Admission (R42a).** `admit` runs cheap structural refusals first — the
//! `supporting_vbcs` length bound, the three-issuer (validator) shape, the
//! PROVISIONAL refusal (`vbc.rs:336` exempts provisional certs from the stamp,
//! so without this refusal a provisional cert would pass unstamped), a stamp
//! PRESENT on the target and bound to it (`vbc_hash`, `wallet_pk`) — and only
//! then the Core verifier `DIRECTORY_VERIFIER`: the target's stamp
//! (`validation::verify_vbc_stamp`: Ed25519, NBC anchor, stake ≥ floor) and the
//! whole bundle through `vbc::verify_vbc_bundle(bundle, 0)` (chain SPHINCS+ to
//! the roots, §5.3 lineage on the cert's OODS tick, reserved names, the stamp
//! on the target AND every three-issuer supporting cert). `current_time = 0`
//! skips ONLY Step 7 (expiry vs now): legs are history, so an expired witness
//! certificate must still admit an old leg (R42).
//!
//! ⚠ **NOT `verify_vbc_bundle_historical`.** That runs `require_stamp = false`
//! and CL8 signs any three-issuer certificate with no stake check
//! (`modes.rs:1788`): three free candidacy certs would become permanent
//! "priced" junk witness keys (the §9d HIGH-1 attack). The stamp is the only
//! place stake is read.
//!
//! **Caching (R42).** The directory itself is the success cache: a record
//! whose `vbc_hash` is already held is never re-verified (and never
//! overwritten — set-union). A FAILURE is never remembered, by any key: a
//! garbage copy of a genuine certificate (bad supporting chain, forged stamp)
//! must not poison that certificate's slot — the genuine copy verifies on
//! arrival. (`vbc_reference_hash` was the ruled cache key; it and `vbc_hash`
//! are both hashes of the same signed pre-image, so keying by the held
//! `vbc_hash` is the same slot. Neither covers the stamp or the supporting
//! chain, which is exactly why a success is only ever recorded AFTER the whole
//! record verified and a failure is never recorded at all.)
//!
//! **RULE 5.** This is Nabla hygiene. It keeps an honest node's directory to
//! stamped validators, so an honest node does not RECORD legs witnessed by free
//! keys (R37) and does not refuse a genuine registration on a forged peer
//! entry (KI#223). The money check stays Core's `origin_settled_*`; a hostile
//! Nabla fails open here exactly as everywhere else.
//!
//! ⚠ **SAFETY-critical under §9g R52** (the derived hold counts a producer leg
//! only if its witnesses are directory members). W7c must not go live on a
//! directory that admits anything this module refuses.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

use axiom_core_logic::errors::CoreResult;
use axiom_core_logic::types::{NablaVbcStamp, ValidationError, VBCProofBundle, VBC};
use serde::{Deserialize, Serialize};

use crate::types::NodeId;

// ── Bounds ──────────────────────────────────────────────────────────────

/// R42 — the most supporting certificates a directory bundle may carry.
/// `supporting_vbcs` has no bound in the type (`types.rs` `VBCProofBundle`)
/// and Core bounds only the recursion DEPTH (`vbc.rs` `MAX_CHAIN_DEPTH` = 10),
/// while Step 8 tries every signature against every candidate key — so a
/// padded bundle multiplies failing SPHINCS+ work. 3 issuers × depth 10: an
/// honest chain never needs more (every live joiner bundle measured
/// 2026-09-28 carries exactly 3; every genesis bundle 0). Checked BEFORE any
/// signature work.
pub const MAX_DIRECTORY_SUPPORTING_VBCS: usize = 30;

/// R45/R50 — registry AE pages by per-entry diff: at most this many records
/// per `VbcRegistrationEntries` (a depth-1 bundle is ≈100 KB, so a whole
/// registry push crossed the 20 MiB wire cap at ≈200 entries — §9d HIGH-4).
pub const MAX_DIRECTORY_ENTRIES_PER_PAGE: usize = 16;

/// R45/R50 — and at most this many serialized bytes per page (well under
/// `transport::WIRE_MAX_MSG_BYTES`); a page always carries ≥ 1 record.
pub const MAX_DIRECTORY_PAGE_BYTES: u64 = 8 * 1024 * 1024;

/// R50 — the longest `have` list a directory AE request may carry (32 B each;
/// 2 MiB). A request above it is refused before any work.
pub const MAX_DIRECTORY_HAVE_LEN: usize = 65_536;

/// R50 — directory AE requests answered per `from` per window. An honest peer
/// sends ONE per anti-entropy round (`ANTI_ENTROPY_INTERVAL` ticks); 2 leaves
/// room for two nodes scheduling each other in one round (§9d MEDIUM-2).
pub const DIRECTORY_AE_REQUESTS_PER_FROM_PER_WINDOW: u32 = 2;

/// R50 — the budget window (seconds of the node's virtual clock). One
/// anti-entropy round is `ANTI_ENTROPY_INTERVAL` (6) ticks × 5 s.
pub const DIRECTORY_AE_WINDOW_SECS: u64 = 30;

/// R50 — how long an issued request nonce stays answerable. A reply for a
/// nonce this node did not issue to that peer, or issued longer ago than this,
/// is UNSOLICITED and refused before any certificate is verified.
pub const DIRECTORY_AE_REPLY_TTL_SECS: u64 = 120;

/// R50 — recent request nonces remembered per `from` for dedupe.
const DIRECTORY_AE_SEEN_NONCES_PER_FROM: usize = 64;

// ── Counters (RULE 3 §2 — a security refusal is COUNTED, on /status) ───

static DIRECTORY_REFUSED: AtomicU64 = AtomicU64::new(0);
static REGISTRY_DECODE_REFUSED: AtomicU64 = AtomicU64::new(0);
static DIRECTORY_AE_REFUSED: AtomicU64 = AtomicU64::new(0);

/// `/status vbc_directory_refused` — certificates refused admission to the
/// witness directory (registration or AE adopt), cumulative.
pub fn directory_refused_total() -> u64 { DIRECTORY_REFUSED.load(Ordering::Relaxed) }
/// `/status vbc_registry_decode_refused` — `vbc_registrations.cbor` files that
/// did not decode under this build's record shape (refused LOUDLY at boot).
pub fn registry_decode_refused_total() -> u64 { REGISTRY_DECODE_REFUSED.load(Ordering::Relaxed) }
/// `/status vbc_directory_ae_refused` — directory AE requests / replies refused
/// (unknown sender, bad signature, replayed nonce, over budget, unsolicited,
/// oversize), cumulative.
pub fn directory_ae_refused_total() -> u64 { DIRECTORY_AE_REFUSED.load(Ordering::Relaxed) }

pub(crate) fn note_registry_decode_refused() { REGISTRY_DECODE_REFUSED.fetch_add(1, Ordering::Relaxed); }

// ── The entry ──────────────────────────────────────────────────────────

/// One directory entry as it rides the wire (`VbcRegistrationEntries`) and
/// sits on disk (`vbc_registrations.cbor`): a STAMPED certificate and its
/// supporting chain — nothing else. Unverified as a type: only
/// [`VerifiedDirectoryEntry`] enters a directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbcRegistrationRecord {
    /// The certificate, carrying the Nabla stamp (`nabla_registration`).
    pub target_vbc: VBC,
    /// Its issuers' certificates (`VBCProofBundle::supporting_vbcs`).
    pub supporting_vbcs: Vec<VBC>,
}

impl VbcRegistrationRecord {
    /// The consume-once key: the issuer-signed commitment of the target — the
    /// value a genuine stamp names (`NablaVbcStamp::vbc_hash`). Recomputed,
    /// never carried.
    pub fn vbc_hash(&self) -> [u8; 32] {
        crate::registration::vbc_registration_hash(&self.target_vbc)
    }

    /// The bundle Core verifies. `candidacy_pulse` / `renewal_work_receipt` are
    /// CL8 issuance inputs, not part of a credential, and never ride here.
    pub fn as_bundle(&self) -> VBCProofBundle {
        VBCProofBundle {
            target_vbc: self.target_vbc.clone(),
            supporting_vbcs: self.supporting_vbcs.clone(),
            candidacy_pulse: None,
            renewal_work_receipt: None,
        }
    }
}

/// Why a certificate was refused admission. Every variant is COUNTED
/// (`vbc_directory_refused`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryRefusal {
    /// More than `MAX_DIRECTORY_SUPPORTING_VBCS` supporting certificates —
    /// refused before any signature work.
    SupportingTooLong { len: usize },
    /// Not a validator certificate (`issuer_set.len() != 3`, RULE 7 §4): an NBC
    /// never enters the validator directory.
    NotAValidatorCertificate { issuers: usize },
    /// A PROVISIONAL certificate — cannot serve (§5.2.2a) and is exempt from
    /// the stamp in Core (`vbc.rs:336`), so it is refused here explicitly.
    Provisional,
    /// No Nabla stamp: a CANDIDATE (CL8-only) certificate — the §9d attack.
    Unstamped,
    /// The stamp names another document (`stamp.vbc_hash` ≠ the target's
    /// signed commitment).
    StampLifted,
    /// The stamp's wallet is not the certificate's stake wallet.
    StampWalletMismatch,
    /// `subject_pubkey_ed25519` is not a 32-byte key.
    SubjectKeyMalformed,
    /// The Core verifier refused (stamp signature / NBC anchor / floor, or the
    /// chain / lineage / a supporting stamp).
    Unverifiable(ValidationError),
}

impl DirectoryRefusal {
    pub fn reason(&self) -> String {
        match self {
            Self::SupportingTooLong { len } => format!(
                "supporting chain carries {len} certificates (max {MAX_DIRECTORY_SUPPORTING_VBCS})"),
            Self::NotAValidatorCertificate { issuers } => format!(
                "not a validator certificate ({issuers} issuers; a VBC has 3)"),
            Self::Provisional => "provisional certificate — cannot serve as a witness credential".into(),
            Self::Unstamped => "certificate carries no Nabla stamp (a candidate, not a registered validator)".into(),
            Self::StampLifted => "stamp names a different certificate".into(),
            Self::StampWalletMismatch => "stamp wallet is not the certificate's stake wallet".into(),
            Self::SubjectKeyMalformed => "certificate subject_pubkey_ed25519 is not 32 bytes".into(),
            Self::Unverifiable(e) => format!("certificate bundle does not verify: {e:?}"),
        }
    }
}

/// A directory entry whose record passed [`admit`]. The ONLY thing a
/// [`VbcDirectory`] holds; private fields, built in this module alone.
#[derive(Debug, Clone)]
pub struct VerifiedDirectoryEntry {
    vbc_hash: [u8; 32],
    wallet_pk: [u8; 32],
    record: VbcRegistrationRecord,
}

impl VerifiedDirectoryEntry {
    pub fn vbc_hash(&self) -> [u8; 32] { self.vbc_hash }
    /// The stake wallet — `stamp.wallet_pk`, bound `== subject_pubkey_ed25519`.
    /// Also the witness key (`is_witness`).
    pub fn wallet_pk(&self) -> [u8; 32] { self.wallet_pk }
    pub fn record(&self) -> &VbcRegistrationRecord { &self.record }
    fn stamp(&self) -> &NablaVbcStamp {
        // Invariant of construction: `precheck` refused every record without one.
        self.record.target_vbc.nabla_registration.as_ref().expect("admitted entry carries its stamp")
    }
    pub fn stamp_tick(&self) -> u64 { self.stamp().tick }
    pub fn stamp_balance(&self) -> u64 { self.stamp().balance }
    pub fn stamp_clone(&self) -> NablaVbcStamp { self.stamp().clone() }
    pub fn validator_id(&self) -> [u8; 32] { self.record.target_vbc.validator_id }
    pub fn expires_at(&self) -> u64 { self.record.target_vbc.expires_at }
}

// ── The verifier ───────────────────────────────────────────────────────

/// The Core verification an admission runs after the structural refusals.
/// A parameter so tests can drive the admission pipeline with fixtures no
/// unit test can root-sign (the roots are ceremony keys; `core/logic`'s test
/// roots are `cfg(test)` inside that crate). Production passes
/// [`DIRECTORY_VERIFIER`] — the ONE binding, used by every production caller.
pub type DirectoryVerifier = fn(&VBCProofBundle) -> CoreResult<()>;

/// R42 — the whole bundle, stamps included, NO time bound. `current_time = 0`
/// skips only Step 7 (`vbc.rs:758`); lineage is judged on the cert's own OODS
/// tick either way.
pub fn directory_chain_verify(bundle: &VBCProofBundle) -> CoreResult<()> {
    axiom_core_logic::vbc::verify_vbc_bundle(bundle, 0)
}

/// The production admission verifier: the target's stamp first (one Ed25519 +
/// one SPHINCS+ — a forged stamp is refused before the chain's 3+ SPHINCS+),
/// then [`directory_chain_verify`], which re-checks that stamp and checks every
/// supporting cert's.
pub fn production_directory_verify(bundle: &VBCProofBundle) -> CoreResult<()> {
    axiom_core_logic::validation::verify_vbc_stamp(&bundle.target_vbc)?;
    directory_chain_verify(bundle)
}

/// THE production verifier binding (R42).
pub const DIRECTORY_VERIFIER: DirectoryVerifier = production_directory_verify;

/// The structural refusals — no signature work. Returns the recomputed key and
/// the stamped wallet.
fn precheck(record: &VbcRegistrationRecord) -> Result<([u8; 32], [u8; 32]), DirectoryRefusal> {
    if record.supporting_vbcs.len() > MAX_DIRECTORY_SUPPORTING_VBCS {
        return Err(DirectoryRefusal::SupportingTooLong { len: record.supporting_vbcs.len() });
    }
    let t = &record.target_vbc;
    if t.issuer_set.len() != axiom_core_logic::vbc::VBC_REQUIRED_ISSUERS {
        return Err(DirectoryRefusal::NotAValidatorCertificate { issuers: t.issuer_set.len() });
    }
    if axiom_core_logic::validation::vbc_is_provisional(t.issued_at, t.expires_at) {
        return Err(DirectoryRefusal::Provisional);
    }
    let stamp = t.nabla_registration.as_ref().ok_or(DirectoryRefusal::Unstamped)?;
    let subject: [u8; 32] = t.subject_pubkey_ed25519.as_slice().try_into()
        .map_err(|_| DirectoryRefusal::SubjectKeyMalformed)?;
    let vbc_hash = record.vbc_hash();
    if stamp.vbc_hash != vbc_hash {
        return Err(DirectoryRefusal::StampLifted);
    }
    if stamp.wallet_pk != subject {
        return Err(DirectoryRefusal::StampWalletMismatch);
    }
    Ok((vbc_hash, subject))
}

/// R42/R42a — admit one record to the witness directory, or refuse it (counted).
/// Structural refusals first, then `verify`. Callers run this OFF the node lock.
pub fn admit(record: VbcRegistrationRecord, verify: DirectoryVerifier) -> Result<VerifiedDirectoryEntry, DirectoryRefusal> {
    let out = precheck(&record).and_then(|(vbc_hash, wallet_pk)| {
        verify(&record.as_bundle()).map_err(DirectoryRefusal::Unverifiable)?;
        Ok(VerifiedDirectoryEntry { vbc_hash, wallet_pk, record })
    });
    if let Err(ref r) = out {
        DIRECTORY_REFUSED.fetch_add(1, Ordering::Relaxed);
        log::warn!("[VBC-DIRECTORY] refused: {}", r.reason());
    }
    out
}

/// Reload a record THIS node wrote to its own `vbc_registrations.cbor` — every
/// one was admitted through [`admit`] before it was persisted. The structural
/// binding is re-checked (a record that no longer binds is refused and
/// counted); the SPHINCS+ chain is not re-run at boot. Own disk only — never
/// for bytes from the network.
pub(crate) fn restore_own_persisted(record: VbcRegistrationRecord) -> Result<VerifiedDirectoryEntry, DirectoryRefusal> {
    match precheck(&record) {
        Ok((vbc_hash, wallet_pk)) => Ok(VerifiedDirectoryEntry { vbc_hash, wallet_pk, record }),
        Err(r) => {
            DIRECTORY_REFUSED.fetch_add(1, Ordering::Relaxed);
            log::error!("[VBC-DIRECTORY] persisted entry refused at load: {}", r.reason());
            Err(r)
        }
    }
}

// ── The directory ──────────────────────────────────────────────────────

/// The witness directory: `vbc_hash` → verified entry, plus the derived set of
/// witness keys. Insertion takes a [`VerifiedDirectoryEntry`] only, so an
/// unverified entry cannot enter by construction (the KI#223 fix is a type).
/// Entries are never removed: membership never expires (legs are history, R37).
#[derive(Debug, Default, Clone)]
pub struct VbcDirectory {
    entries: HashMap<[u8; 32], VerifiedDirectoryEntry>,
    witnesses: HashSet<[u8; 32]>,
}

impl VbcDirectory {
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn contains(&self, vbc_hash: &[u8; 32]) -> bool { self.entries.contains_key(vbc_hash) }
    pub fn get(&self, vbc_hash: &[u8; 32]) -> Option<&VerifiedDirectoryEntry> { self.entries.get(vbc_hash) }

    /// Set-union insert: an absent key is added; a present key is NEVER
    /// overwritten (the first verified copy wins — any second copy of the same
    /// signed certificate names the same subject). Returns true if added.
    pub fn insert(&mut self, entry: VerifiedDirectoryEntry) -> bool {
        if self.entries.contains_key(&entry.vbc_hash) {
            return false;
        }
        self.witnesses.insert(entry.wallet_pk);
        self.entries.insert(entry.vbc_hash, entry);
        true
    }

    /// Is `pk` the ed25519 subject of a stamped VBC this node verified?
    pub fn is_witness(&self, pk: &[u8; 32]) -> bool { self.witnesses.contains(pk) }

    /// Test-only witness admission (no stamped VBC — see `NablaNode::
    /// admit_witness_for_test`).
    #[cfg(test)]
    pub(crate) fn insert_witness_for_test(&mut self, pk: [u8; 32]) { self.witnesses.insert(pk); }

    /// §6b.10 (KI#169) — another still-live certificate this wallet stakes.
    /// Every value compared was read out of a VERIFIED certificate/stamp, so an
    /// unverified peer entry can no longer trigger it (KI#223).
    pub fn conflict(&self, wallet_pk: &[u8; 32], validator_id: &[u8; 32], now_tick: u64) -> Option<[u8; 32]> {
        self.entries.values()
            .find(|e| &e.wallet_pk == wallet_pk && &e.validator_id() != validator_id && e.expires_at() > now_tick)
            .map(|e| e.validator_id())
    }

    /// The sorted keys — a directory AE request's `have` list.
    pub fn sorted_keys(&self) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> = self.entries.keys().copied().collect();
        v.sort();
        v
    }

    /// R45/R50 per-entry diff: the records this node holds that `have` lacks,
    /// in key order, capped at `MAX_DIRECTORY_ENTRIES_PER_PAGE` and
    /// `MAX_DIRECTORY_PAGE_BYTES` (a page always carries ≥ 1 record). The next
    /// request — whose `have` now includes this page — gets the next page.
    pub fn page_missing_from(&self, have: &[[u8; 32]]) -> Vec<VbcRegistrationRecord> {
        let have: HashSet<&[u8; 32]> = have.iter().collect();
        let mut out = Vec::new();
        let mut bytes: u64 = 0;
        for k in self.sorted_keys() {
            if have.contains(&k) {
                continue;
            }
            let rec = &self.entries[&k].record;
            let sz = bincode::serialized_size(rec).unwrap_or(u64::MAX);
            if !out.is_empty() && bytes.saturating_add(sz) > MAX_DIRECTORY_PAGE_BYTES {
                break;
            }
            bytes = bytes.saturating_add(sz);
            out.push(rec.clone());
            if out.len() >= MAX_DIRECTORY_ENTRIES_PER_PAGE {
                break;
            }
        }
        out
    }

    /// What `vbc_registrations.cbor` holds.
    pub fn persisted_list(&self) -> Vec<VbcRegistrationRecord> {
        let mut v: Vec<(&[u8; 32], &VerifiedDirectoryEntry)> = self.entries.iter().collect();
        v.sort_by(|a, b| a.0.cmp(b.0));
        v.into_iter().map(|(_, e)| e.record.clone()).collect()
    }

    /// Rebuild from this node's own persisted list (see `restore_own_persisted`).
    pub(crate) fn restore(list: Vec<VbcRegistrationRecord>) -> Self {
        let mut d = Self::default();
        for rec in list {
            if let Ok(e) = restore_own_persisted(rec) {
                d.insert(e);
            }
        }
        d
    }
}

// ── R50 — authenticated directory anti-entropy ─────────────────────────

/// Kind byte inside the signed payload: a request (the `have` list).
pub const DIRECTORY_AE_KIND_HAVE: u8 = 1;
/// Kind byte inside the signed payload: a reply page (`entries`).
pub const DIRECTORY_AE_KIND_ENTRIES: u8 = 2;

/// The body digest a request signs over (its sorted `have` list).
pub fn have_body_hash(have: &[[u8; 32]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&(have.len() as u64).to_le_bytes());
    for k in have {
        h.update(k);
    }
    *h.finalize().as_bytes()
}

/// The body digest a reply page signs over.
pub fn entries_body_hash(entries: &[VbcRegistrationRecord]) -> [u8; 32] {
    let bytes = bincode::serialize(entries).unwrap_or_default();
    *blake3::hash(&bytes).as_bytes()
}

/// Why a directory AE message was refused. Every variant is COUNTED
/// (`vbc_directory_ae_refused`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeRefusal {
    /// No verified NBC on file for `from` — no key to authenticate it with.
    UnknownSender,
    /// The signature does not verify under `from`'s NBC key.
    BadSignature,
    /// This `(from, nonce)` request was already answered.
    ReplayedNonce,
    /// `from` exceeded its per-window request budget.
    OverBudget,
    /// A reply for a nonce this node did not issue to `from` (or it expired).
    Unsolicited,
    /// The request's `have` list or the reply page is over its bound.
    Oversize,
    /// Record-AE only (Fork Settlement §9o [R59]): an ask / answer that is
    /// structurally invalid (an invalid prefix, an empty ask, a view that is
    /// not well-formed, an answer of the wrong kind). The directory AE never
    /// produces it.
    Malformed,
}

pub fn note_ae_refused(r: AeRefusal, from: &NodeId) {
    DIRECTORY_AE_REFUSED.fetch_add(1, Ordering::Relaxed);
    log::warn!("[VBC-DIRECTORY-AE] refused {:?} from {}", r, hex::encode(&from[..8]));
}

/// R50 — authenticate an AE message (the witness directory's, and since
/// Fork Settlement §9o [R59] record-AE's — `kind` separates them): the
/// signature by `from`'s NBC Ed25519 key (`sender_pk`, looked up by the caller
/// in its VERIFIED NBC set — the PoolSync pattern) over the ONE builder
/// `crypto::ae_sign_payload(kind, from, nonce, body)`. Verified with the free
/// `crypto::verify_ed25519`, never the node's `Signer` (a test `NoopSigner`
/// verifies everything).
pub fn verify_ae_signature(
    sender_pk: Option<[u8; 32]>,
    kind: u8,
    from: &NodeId,
    nonce: u64,
    body_hash: &[u8; 32],
    sig: &[u8],
) -> Result<(), AeRefusal> {
    let pk = sender_pk.ok_or(AeRefusal::UnknownSender)?;
    let payload = crate::crypto::ae_sign_payload(kind, from, nonce, body_hash);
    if crate::crypto::verify_ed25519(&pk, &payload, sig) {
        Ok(())
    } else {
        Err(AeRefusal::BadSignature)
    }
}

/// R50 — the budget of ONE AE guard instance: the directory AE
/// (`AeBudget::DIRECTORY`) and record-AE (`record_sync::RECORD_AE_BUDGET`,
/// Fork Settlement §9o [R59]) each own a guard with their own numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeBudget {
    /// Requests answered per authenticated `from` per window.
    pub requests_per_from_per_window: u32,
    /// The budget window (seconds of the node's virtual clock).
    pub window_secs: u64,
    /// How long an issued nonce stays answerable.
    pub reply_ttl_secs: u64,
    /// Recent request nonces remembered per `from` (dedupe).
    pub seen_nonces_per_from: usize,
}

impl AeBudget {
    /// The witness-directory AE budget (wave 4a, unchanged).
    pub const DIRECTORY: AeBudget = AeBudget {
        requests_per_from_per_window: DIRECTORY_AE_REQUESTS_PER_FROM_PER_WINDOW,
        window_secs: DIRECTORY_AE_WINDOW_SECS,
        reply_ttl_secs: DIRECTORY_AE_REPLY_TTL_SECS,
        seen_nonces_per_from: DIRECTORY_AE_SEEN_NONCES_PER_FROM,
    };
}

/// R50 — the per-node request/reply ledger of ONE AE protocol: nonces this
/// node issued (a reply must answer one), nonces it answered per sender
/// (dedupe), and the per-`from` budget, all under the instance's
/// [`AeBudget`]. Replies are ADDRESSED by the caller to `peer_by_id(from)` of
/// an AUTHENTICATED `from` — never `send_reply` (a node never reads its
/// outbound sockets: the KI#42 deadlock), never an unauthenticated body field.
/// ~~`DirectoryAeGuard`~~ — generalised 2026-09-30 (Fork Settlement W1) so
/// record-AE reuses the one ledger with its own budget (RULE 1).
#[derive(Debug)]
pub struct AeGuard {
    budget: AeBudget,
    outstanding: HashMap<(NodeId, u64), u64>,
    seen: HashMap<NodeId, VecDeque<u64>>,
    window: HashMap<NodeId, (u64, u32)>,
}

impl AeGuard {
    pub fn new(budget: AeBudget) -> AeGuard {
        AeGuard { budget, outstanding: HashMap::new(), seen: HashMap::new(), window: HashMap::new() }
    }

    /// The directory AE's guard.
    pub fn directory() -> AeGuard {
        AeGuard::new(AeBudget::DIRECTORY)
    }

    /// Issue a fresh request nonce to `to` at `now_secs`, pruning expired ones.
    pub fn issue(&mut self, to: NodeId, now_secs: u64) -> u64 {
        let ttl = self.budget.reply_ttl_secs;
        self.outstanding.retain(|_, sent| now_secs.saturating_sub(*sent) <= ttl);
        let nonce: u64 = rand::random();
        self.outstanding.insert((to, nonce), now_secs);
        nonce
    }

    /// Admit an AUTHENTICATED request from `from`: not a replay, within budget.
    pub fn admit_request(&mut self, from: NodeId, nonce: u64, now_secs: u64) -> Result<(), AeRefusal> {
        let seen = self.seen.entry(from).or_default();
        if seen.contains(&nonce) {
            return Err(AeRefusal::ReplayedNonce);
        }
        let (start, count) = self.window.entry(from).or_insert((now_secs, 0));
        if now_secs.saturating_sub(*start) >= self.budget.window_secs {
            *start = now_secs;
            *count = 0;
        }
        if *count >= self.budget.requests_per_from_per_window {
            return Err(AeRefusal::OverBudget);
        }
        *count += 1;
        seen.push_back(nonce);
        if seen.len() > self.budget.seen_nonces_per_from {
            seen.pop_front();
        }
        Ok(())
    }

    /// Accept an AUTHENTICATED reply: it must answer a live nonce this node
    /// issued to `from`. Consumes it (one reply per request).
    pub fn accept_reply(&mut self, from: NodeId, nonce: u64, now_secs: u64) -> Result<(), AeRefusal> {
        match self.outstanding.remove(&(from, nonce)) {
            Some(sent) if now_secs.saturating_sub(sent) <= self.budget.reply_ttl_secs => Ok(()),
            _ => Err(AeRefusal::Unsolicited),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! ForkSettlement wave 4a — witness-directory tests (R42/R42a/R50, KI#223).
    //!
    //! Real keys throughout: SPHINCS+ (SLH-DSA-128s) issuers and NBC issuer,
    //! Ed25519 subject / node keys, and the stamp built by the ONE production
    //! builder `registration::build_vbc_stamp`.
    //!
    //! ⚠ What a nabla test CANNOT do: make Core ACCEPT a bundle. The roots are
    //! ceremony keys, and `core/logic`'s test roots are `cfg(test)` inside that
    //! crate. So every REFUSAL below runs the PRODUCTION verifier (or proves no
    //! verifier ran), and only the admission-pipeline tests that need an ACCEPT
    //! stand a fixture in for Core's accept (`core_accepts`). Core pins its own
    //! half: `vbc.rs::test_unstamped_vbc_is_historical_evidence_but_not_a_live_credential`
    //! and the `validation.rs` `vbc_stamp_*` tests.
    //!
    //! Each test names the mutation that must turn it RED.

    use super::*;
    use std::sync::OnceLock;

    use axiom_core_logic::types::VBC;
    use ed25519_dalek::{Signer as _, SigningKey};

    use crate::crypto::{Ed25519Signer, Signer as NablaSigner};

    const NOW: u64 = 2_000_000_000;

    struct Fx {
        /// The node that stamps (its Ed25519 key is its NBC subject).
        node_signer: Ed25519Signer,
        nbc_bytes: Vec<u8>,
        /// A validator certificate signed by three real SPHINCS+ issuers, unstamped.
        base: VBC,
    }

    fn sphincs_keypair() -> (Vec<u8>, Vec<u8>) {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes;
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("SPHINCS+ keygen");
        (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
    }

    fn subject_key(seed: u8) -> SigningKey { SigningKey::from_bytes(&[seed; 32]) }

    fn blank_vbc(subject: &SigningKey, issuers: Vec<Vec<u8>>) -> VBC {
        let sphincs_pk = vec![subject.verifying_key().to_bytes()[0]; 32];
        VBC {
            genesis_lineage: [0u8; 32],
            network_size_baseline: 0,
            baseline_tick: 0,
            version: 0x09,
            validator_id: axiom_core_logic::compute::compute_validator_id(&sphincs_pk),
            subject_pubkey_sphincs: sphincs_pk,
            subject_pubkey_dilithium: vec![0u8; 1952],
            subject_pubkey_ed25519: subject.verifying_key().to_bytes().to_vec(),
            pgp_fingerprint: vec![],
            node_name: String::new(),
            proof_cap: String::new(),
            issued_at: 1_000,
            expires_at: 0, // the never-expires sentinel — not provisional
            chain_depth: 0,
            issuer_set: issuers,
            signatures: vec![],
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
            nabla_registration: None,
        }
    }

    fn fx() -> &'static Fx {
        static FX: OnceLock<Fx> = OnceLock::new();
        FX.get_or_init(|| {
            // Three real SPHINCS+ issuers sign the base certificate.
            let issuers: Vec<(Vec<u8>, Vec<u8>)> = (0..3).map(|_| sphincs_keypair()).collect();
            let mut base = blank_vbc(&subject_key(0x11), issuers.iter().map(|(pk, _)| pk.clone()).collect());
            let payload = axiom_core_logic::compute::compute_vbc_signing_payload(&base);
            base.signatures = issuers.iter()
                .map(|(_, sk)| axiom_core_logic::compute::sign_sphincs(sk, &payload).expect("sign"))
                .collect();
            // This node's NBC: one real SPHINCS+ issuer (NOT a Nabla root — so Core
            // refuses the stamp's anchor, which is what the stamp-first test reads).
            let node_signer = Ed25519Signer::from_seed(&[0x42; 32]);
            let (nbc_issuer_pk, nbc_issuer_sk) = sphincs_keypair();
            let mut nbc = blank_vbc(&subject_key(0x42), vec![nbc_issuer_pk]);
            nbc.subject_pubkey_ed25519 = NablaSigner::public_key(&node_signer);
            nbc.chain_depth = 1;
            let npayload = axiom_core_logic::compute::compute_vbc_signing_payload(&nbc);
            nbc.signatures = vec![axiom_core_logic::compute::sign_sphincs(&nbc_issuer_sk, &npayload).expect("sign")];
            Fx { node_signer, nbc_bytes: crate::cc::serialize_nbc(&nbc), base }
        })
    }

    /// Stamp `vbc` exactly as `register_vbc_core` does (the ONE builder).
    fn stamp(mut vbc: VBC, wallet_pk: [u8; 32], balance: u64) -> VBC {
        let f = fx();
        let h = axiom_core_logic::compute::compute_vbc_signing_payload(&vbc);
        let st = crate::registration::build_vbc_stamp(&f.nbc_bytes, h, vbc.validator_id, wallet_pk, balance, 7, &f.node_signer)
            .expect("stamp");
        vbc.nabla_registration = Some(st);
        vbc
    }

    fn subject_of(v: &VBC) -> [u8; 32] { v.subject_pubkey_ed25519.as_slice().try_into().unwrap() }

    /// The genuine registered certificate: the base, stamped for its own subject.
    fn genuine() -> VbcRegistrationRecord {
        let b = fx().base.clone();
        let pk = subject_of(&b);
        VbcRegistrationRecord { target_vbc: stamp(b, pk, 600_000_000_000), supporting_vbcs: vec![] }
    }

    /// Stands in for Core's ACCEPT only (see the module header).
    fn core_accepts(_: &VBCProofBundle) -> CoreResult<()> { Ok(()) }

    /// KI#224 K-f — a STAMPED directory entry whose subject (= witness key) is
    /// `subject`, through the real `admit` pipeline (structural prechecks +
    /// the stamp builder) with `core_accepts` standing in for Core's accept.
    /// What `NablaNode::adopt_verified_directory_entries` persists and
    /// `restore_own_persisted` reloads at open.
    pub(crate) fn admitted_entry_for_subject(subject: [u8; 32]) -> VerifiedDirectoryEntry {
        let mut b = fx().base.clone();
        b.subject_pubkey_ed25519 = subject.to_vec();
        let rec = VbcRegistrationRecord { target_vbc: stamp(b, subject, 600_000_000_000), supporting_vbcs: vec![] };
        admit(rec, core_accepts).expect("a stamped, bound bundle admits")
    }
    /// Proves a refusal came BEFORE any signature work.
    fn must_not_run(_: &VBCProofBundle) -> CoreResult<()> { panic!("Core verifier ran before a structural refusal") }
    /// Core's accept for an EMPTY supporting chain only — so a padded copy of the
    /// genuine certificate is refused and the genuine one accepted.
    fn core_accepts_unpadded(b: &VBCProofBundle) -> CoreResult<()> {
        if b.supporting_vbcs.is_empty() { Ok(()) } else { Err(ValidationError::InvalidVBC) }
    }

    // ── R42 admission ──────────────────────────────────────────────────────

    /// A stamped, bound bundle the verifier accepts enters the directory; its
    /// subject becomes a witness key. Mutation: `insert` stops recording the
    /// witness key → `is_witness` red.
    #[test]
    fn stamped_bundle_admits_and_its_subject_is_a_directory_witness() {
        let rec = genuine();
        let pk = subject_of(&rec.target_vbc);
        let e = admit(rec, core_accepts).expect("a stamped, bound bundle admits");
        assert_eq!(e.wallet_pk(), pk);
        let mut d = VbcDirectory::default();
        assert!(!d.is_witness(&pk));
        assert!(d.insert(e));
        assert!(d.is_witness(&pk), "the stamped subject is a directory witness");
        assert!(!d.is_witness(&[0x99; 32]));
    }

    /// THE §9d attack: a CL8-issued candidate (three issuers, chain-signed, NO
    /// stamp) is refused — structurally, before any SPHINCS+. Mutation: delete the
    /// `Unstamped` precheck → `must_not_run` panics (red).
    #[test]
    fn unstamped_candidacy_bundle_is_refused_before_signature_work() {
        let rec = VbcRegistrationRecord { target_vbc: fx().base.clone(), supporting_vbcs: vec![] };
        let before = directory_refused_total();
        assert_eq!(admit(rec, must_not_run).unwrap_err(), DirectoryRefusal::Unstamped);
        assert!(directory_refused_total() > before, "the refusal is COUNTED");
    }

    /// The production verifier checks the STAMP (before the chain). This fixture's
    /// stamp is genuinely signed by the node but anchored to an NBC issuer that is
    /// no Nabla root, so Core refuses it with `VbcStampInvalid`. Mutation:
    /// `DIRECTORY_VERIFIER` = chain only, or `verify_vbc_bundle_historical` (the R37
    /// bug) → the error becomes a CHAIN error (red).
    #[test]
    fn production_verifier_refuses_an_unanchored_stamp_as_a_stamp_failure() {
        let rec = genuine();
        assert_eq!(
            admit(rec, DIRECTORY_VERIFIER).unwrap_err(),
            DirectoryRefusal::Unverifiable(ValidationError::VbcStampInvalid),
        );
    }

    /// A FORGED stamp (fields bound, signature garbage) is refused by the
    /// production verifier. Mutation: drop the stamp step from
    /// `production_directory_verify` → a chain error instead (red).
    #[test]
    fn forged_stamp_signature_is_refused() {
        let mut rec = genuine();
        rec.target_vbc.nabla_registration.as_mut().unwrap().nabla_signature = vec![0u8; 64];
        assert_eq!(
            admit(rec, DIRECTORY_VERIFIER).unwrap_err(),
            DirectoryRefusal::Unverifiable(ValidationError::VbcStampInvalid),
        );
    }

    /// R42 "no time bound": an EXPIRED certificate is not refused for expiry (legs
    /// are history). The fixture reaches Step 7 — `verify_vbc_bundle(b, now)` says
    /// `VBCExpired` — while `directory_chain_verify` does not. Mutation:
    /// `verify_vbc_bundle(bundle, <now>)` in `directory_chain_verify` → red.
    #[test]
    fn directory_chain_verify_has_no_time_bound_so_an_expired_member_still_prices_old_legs() {
        let mut b = fx().base.clone();
        b.expires_at = 1_000 + 400 * 86_400; // a year+ life, long expired at NOW
        let bundle = VbcRegistrationRecord { target_vbc: b, supporting_vbcs: vec![] }.as_bundle();
        assert!(matches!(axiom_core_logic::vbc::verify_vbc_bundle(&bundle, NOW), Err(ValidationError::VBCExpired { .. })),
            "fixture must reach Step 7 for this test to mean anything");
        let e = directory_chain_verify(&bundle).unwrap_err();
        assert!(!matches!(e, ValidationError::VBCExpired { .. }), "no expiry judgement in the directory: {e:?}");
    }

    /// A PROVISIONAL certificate is refused explicitly (Core exempts it from the
    /// stamp, `vbc.rs:336`). Mutation: delete the provisional refusal → the
    /// verifier runs (`must_not_run` panics, red).
    #[test]
    fn provisional_certificate_is_refused() {
        let mut b = fx().base.clone();
        b.expires_at = b.issued_at + 3_600; // well inside PROVISIONAL_VBC_EXPIRY_SECS
        assert!(axiom_core_logic::validation::vbc_is_provisional(b.issued_at, b.expires_at));
        let pk = subject_of(&b);
        let rec = VbcRegistrationRecord { target_vbc: stamp(b, pk, 600_000_000_000), supporting_vbcs: vec![] };
        assert_eq!(admit(rec, must_not_run).unwrap_err(), DirectoryRefusal::Provisional);
    }

    /// Entry fields disagreeing with the bundle: a stamp LIFTED from another
    /// certificate, and a stamp naming another wallet. Both refused before any
    /// signature work. Mutation: delete either binding → `must_not_run` panics.
    #[test]
    fn entry_whose_stamp_disagrees_with_its_certificate_is_refused() {
        // Lifted: the genuine stamp moved onto a DIFFERENT certificate.
        let mut other = fx().base.clone();
        other.node_name = "not-the-stamped-one".into();
        other.nabla_registration = genuine().target_vbc.nabla_registration;
        let lifted = VbcRegistrationRecord { target_vbc: other, supporting_vbcs: vec![] };
        assert_eq!(admit(lifted, must_not_run).unwrap_err(), DirectoryRefusal::StampLifted);
        // Wallet: stamped for someone else's wallet.
        let b = fx().base.clone();
        let wrong = VbcRegistrationRecord { target_vbc: stamp(b, [0x77; 32], 600_000_000_000), supporting_vbcs: vec![] };
        assert_eq!(admit(wrong, must_not_run).unwrap_err(), DirectoryRefusal::StampWalletMismatch);
    }

    /// RULE 7 §4: an NBC (one issuer) never enters the VALIDATOR directory.
    /// Mutation: drop the issuer-count check → `must_not_run` panics.
    #[test]
    fn nbc_is_not_a_validator_certificate() {
        let mut b = fx().base.clone();
        b.issuer_set.truncate(1);
        let pk = subject_of(&b);
        let rec = VbcRegistrationRecord { target_vbc: stamp(b, pk, 1), supporting_vbcs: vec![] };
        assert_eq!(admit(rec, must_not_run).unwrap_err(), DirectoryRefusal::NotAValidatorCertificate { issuers: 1 });
    }

    /// R42 length bound: a padded supporting chain is refused BEFORE any SPHINCS+
    /// work. Mutation: delete the bound (or raise it past 31) → `must_not_run`.
    #[test]
    fn oversize_supporting_chain_is_refused_before_sphincs_work() {
        let mut rec = genuine();
        rec.supporting_vbcs = vec![fx().base.clone(); MAX_DIRECTORY_SUPPORTING_VBCS + 1];
        assert_eq!(admit(rec, must_not_run).unwrap_err(),
            DirectoryRefusal::SupportingTooLong { len: MAX_DIRECTORY_SUPPORTING_VBCS + 1 });
        let mut ok = genuine();
        ok.supporting_vbcs = vec![fx().base.clone(); MAX_DIRECTORY_SUPPORTING_VBCS];
        assert!(admit(ok, core_accepts).is_ok(), "the bound itself is admissible");
    }

    /// R42 "cache successes only": a garbage-padded copy of a GENUINE certificate
    /// is refused, and the genuine copy arriving later still admits (the failure
    /// poisoned nothing). Mutation: remember failures by `vbc_hash` (e.g. insert a
    /// tombstone on refusal) → the genuine copy is refused (red).
    #[test]
    fn a_failed_verify_is_not_cached_and_a_later_genuine_copy_admits() {
        let mut n = crate::node::NablaNode::new();
        let mut bad = genuine();
        bad.supporting_vbcs = vec![fx().base.clone()];
        let key = bad.vbc_hash();
        assert!(admit(bad, core_accepts_unpadded).is_err());
        assert!(!n.vbc_directory().contains(&key), "nothing recorded for the failure");
        let good = admit(genuine(), core_accepts_unpadded).expect("the genuine copy verifies on arrival");
        assert_eq!(n.adopt_verified_directory_entries(vec![good]), 1);
        assert!(n.vbc_directory().contains(&key));
    }

    /// KI#223 — THE attack: a hostile peer pushes `{wallet_pk: victim, validator_id:
    /// other}` with a forged stamp. It is refused by the production verifier, so it
    /// cannot make the victim's genuine registration a §6b.10 conflict.
    /// Mutation: make `admit` skip `verify` (the old unverified union) → the forged
    /// entry enters and `vbc_registration_conflict` returns `Some` (red).
    #[test]
    fn an_unverified_peer_entry_cannot_block_a_genuine_registration() {
        let mut n = crate::node::NablaNode::new();
        let victim_cert = genuine();
        let victim = subject_of(&victim_cert.target_vbc);
        // The forgery: the victim's wallet under ANOTHER identity, stamp forged.
        let mut forged_cert = fx().base.clone();
        forged_cert.validator_id = [0xEE; 32];
        let mut forged = VbcRegistrationRecord { target_vbc: stamp(forged_cert, victim, 600_000_000_000), supporting_vbcs: vec![] };
        forged.target_vbc.nabla_registration.as_mut().unwrap().nabla_signature = vec![1u8; 64];
        let verified: Vec<_> = vec![forged].into_iter().filter_map(|r| admit(r, DIRECTORY_VERIFIER).ok()).collect();
        assert_eq!(n.adopt_verified_directory_entries(verified), 0, "the forgery is refused");
        assert_eq!(n.vbc_registration_conflict(&victim, &victim_cert.target_vbc.validator_id, 10), None,
            "the victim's genuine registration is NOT blocked");
        let genuine_entry = admit(victim_cert, core_accepts).unwrap();
        assert!(n.record_vbc_registration(genuine_entry), "the genuine registration records");
    }

    /// KI#169 on VERIFIED entries: a second live identity on one stake wallet
    /// conflicts, a renewal (same id) does not, an expired entry stops blocking —
    /// yet stays a directory WITNESS (membership never expires).
    /// Mutation: drop `expires_at > now` → the expired case is a conflict (red).
    #[test]
    fn one_live_stamp_per_stake_wallet_on_verified_entries() {
        let mut n = crate::node::NablaNode::new();
        let mut b = fx().base.clone();
        b.expires_at = 1_000 + 400 * 86_400;
        let pk = subject_of(&b);
        let vid = b.validator_id;
        let e = admit(VbcRegistrationRecord { target_vbc: stamp(b, pk, 600_000_000_000), supporting_vbcs: vec![] }, core_accepts).unwrap();
        assert!(n.record_vbc_registration(e));
        assert_eq!(n.vbc_registration_conflict(&pk, &[0xBB; 32], 2_000), Some(vid));
        assert_eq!(n.vbc_registration_conflict(&pk, &vid, 2_000), None, "a renewal is not a conflict");
        assert_eq!(n.vbc_registration_conflict(&pk, &[0xBB; 32], NOW), None, "expired stops blocking");
        assert!(n.is_directory_witness(&pk), "an expired member still prices old legs (R37)");
    }

    // ── Persisted shape ─────────────────────────────────────────────────────

    /// A pre-4a `vbc_registrations.cbor` (the five-free-field record) is refused
    /// LOUDLY: counted, moved aside, and the node boots with an EMPTY directory
    /// (never `Err` — a retain rotation must not crash-loop). A current-shape file
    /// round-trips. Mutation: a lenient decode (e.g. skip undecodable entries
    /// silently) → the counter does not move (red); returning `Err` → `open` fails.
    #[test]
    fn persisted_shape_pre_4a_registry_is_refused_loudly() {
        #[derive(serde::Serialize)]
        struct Pre4aRecord { wallet_pk: [u8; 32], tick: u64, balance: u64, validator_id: [u8; 32], expires_at: u64 }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vbc_registrations.cbor");
        let old = vec![([1u8; 32], Pre4aRecord { wallet_pk: [7; 32], tick: 1, balance: 2, validator_id: [3; 32], expires_at: 4 })];
        let mut bytes = Vec::new();
        ciborium::into_writer(&old, &mut bytes).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let before = registry_decode_refused_total();
        let d = crate::node::load_vbc_directory_file(&path, &bytes);
        assert!(d.is_empty(), "nothing from the old shape is loaded");
        assert!(registry_decode_refused_total() > before, "COUNTED on /status");
        assert!(!path.exists() && dir.path().join("vbc_registrations.cbor.refused").exists(), "moved aside, evidence kept");

        // The current shape round-trips.
        let mut d2 = VbcDirectory::default();
        d2.insert(admit(genuine(), core_accepts).unwrap());
        let mut nb = Vec::new();
        ciborium::into_writer(&d2.persisted_list(), &mut nb).unwrap();
        let back = crate::node::load_vbc_directory_file(&path, &nb);
        assert_eq!(back.len(), 1);
        assert!(back.is_witness(&subject_of(&genuine().target_vbc)));
    }

    // ── R45/R50 — per-entry diff paging and the authenticated exchange ─────

    fn distinct_entries(n: usize) -> Vec<VerifiedDirectoryEntry> {
        (0..n).map(|i| {
            let mut b = fx().base.clone();
            b.node_name = format!("v{i}");
            let pk = subject_of(&b);
            admit(VbcRegistrationRecord { target_vbc: stamp(b, pk, 600_000_000_000), supporting_vbcs: vec![] }, core_accepts).unwrap()
        }).collect()
    }

    /// Registry AE pages by per-entry diff: only records the requester LACKS, at
    /// most one page, and the next request (its `have` grown) gets the next page.
    /// Mutation: push the whole set (ignore `have` or the cap) → red.
    #[test]
    fn directory_ae_pages_by_per_entry_diff() {
        let mut d = VbcDirectory::default();
        for e in distinct_entries(MAX_DIRECTORY_ENTRIES_PER_PAGE + 5) { d.insert(e); }
        let all = d.sorted_keys();
        let have = all[..3].to_vec();
        let page = d.page_missing_from(&have);
        assert_eq!(page.len(), MAX_DIRECTORY_ENTRIES_PER_PAGE, "capped at one page");
        assert!(page.iter().all(|r| !have.contains(&r.vbc_hash())), "only what the requester lacks");
        let mut have2 = have.clone();
        have2.extend(page.iter().map(|r| r.vbc_hash()));
        let page2 = d.page_missing_from(&have2);
        assert_eq!(page2.len(), all.len() - have2.len(), "the rest on the next round");
        assert!(d.page_missing_from(&all).is_empty(), "converged → nothing sent");
    }

    fn signed(kind: u8, key: &SigningKey, from: &NodeId, nonce: u64, body: &[u8; 32]) -> Vec<u8> {
        key.sign(&crate::crypto::ae_sign_payload(kind, from, nonce, body)).to_bytes().to_vec()
    }

    /// R50: a request is authenticated by `from`'s NBC key over (kind, from, nonce,
    /// body). A SPOOFED `from` (signed by another key), an unknown sender, a body
    /// swap and a kind swap are all refused. Mutation: verify against a key taken
    /// from the message, or drop `kind`/`body` from the payload → red.
    #[test]
    fn directory_ae_signature_binds_sender_nonce_kind_and_body() {
        let from_key = subject_key(0x21);
        let from: NodeId = [0x21; 32];
        let from_pk = from_key.verifying_key().to_bytes();
        let attacker = subject_key(0x66);
        let have = vec![[1u8; 32], [2u8; 32]];
        let body = have_body_hash(&have);
        let good = signed(DIRECTORY_AE_KIND_HAVE, &from_key, &from, 9, &body);
        assert_eq!(verify_ae_signature(Some(from_pk), DIRECTORY_AE_KIND_HAVE, &from, 9, &body, &good), Ok(()));
        let spoof = signed(DIRECTORY_AE_KIND_HAVE, &attacker, &from, 9, &body);
        assert_eq!(verify_ae_signature(Some(from_pk), DIRECTORY_AE_KIND_HAVE, &from, 9, &body, &spoof), Err(AeRefusal::BadSignature));
        assert_eq!(verify_ae_signature(None, DIRECTORY_AE_KIND_HAVE, &from, 9, &body, &good), Err(AeRefusal::UnknownSender));
        assert_eq!(verify_ae_signature(Some(from_pk), DIRECTORY_AE_KIND_HAVE, &from, 10, &body, &good), Err(AeRefusal::BadSignature), "nonce is signed");
        assert_eq!(verify_ae_signature(Some(from_pk), DIRECTORY_AE_KIND_HAVE, &from, 9, &have_body_hash(&have[..1]), &good), Err(AeRefusal::BadSignature), "body is signed");
        assert_eq!(verify_ae_signature(Some(from_pk), DIRECTORY_AE_KIND_ENTRIES, &from, 9, &body, &good), Err(AeRefusal::BadSignature), "kind is signed");
    }

    /// R50 ledger: a replayed request nonce is refused; a `from` over its window
    /// budget is refused until the window rolls; a reply must answer a nonce THIS
    /// node issued to THAT peer, once, within the TTL.
    /// Mutation: drop the dedupe / budget / outstanding check → red.
    #[test]
    fn directory_ae_guard_dedupes_budgets_and_refuses_unsolicited_replies() {
        let mut g = AeGuard::directory();
        let a: NodeId = [0xA1; 32];
        let b: NodeId = [0xB2; 32];
        assert_eq!(g.admit_request(a, 1, 100), Ok(()));
        assert_eq!(g.admit_request(a, 1, 100), Err(AeRefusal::ReplayedNonce));
        assert_eq!(g.admit_request(a, 2, 100), Ok(()));
        assert_eq!(g.admit_request(a, 3, 101), Err(AeRefusal::OverBudget), "per-from budget");
        assert_eq!(g.admit_request(b, 3, 101), Ok(()), "another sender has its own budget");
        assert_eq!(g.admit_request(a, 3, 100 + DIRECTORY_AE_WINDOW_SECS), Ok(()), "window rolls");

        let n = g.issue(b, 500);
        assert_eq!(g.accept_reply(a, n, 501), Err(AeRefusal::Unsolicited), "issued to b, not a");
        assert_eq!(g.accept_reply(b, n.wrapping_add(1), 501), Err(AeRefusal::Unsolicited), "never issued");
        assert_eq!(g.accept_reply(b, n, 501), Ok(()));
        assert_eq!(g.accept_reply(b, n, 502), Err(AeRefusal::Unsolicited), "one reply per request");
        let late = g.issue(b, 600);
        assert_eq!(g.accept_reply(b, late, 600 + DIRECTORY_AE_REPLY_TTL_SECS + 1), Err(AeRefusal::Unsolicited), "expired");
    }
}
