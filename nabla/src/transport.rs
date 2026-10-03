// AXIOM Nabla — Transport Layer
//
// Pluggable transport for nabla-node. Carries Nabla protocol messages
// over different backends without changing any protocol logic.
//
// Transports:
//   StdioTransport — stdin/stdout, line-delimited JSON (dev/testing)
//   TcpTransport   — dual-stack IPv4+IPv6, length-prefixed bincode (production)
//
// Wire format (TCP, node-to-node):
//   [4 bytes big-endian length][bincode-encoded WireMessage]
//   Max message size: WIRE_MAX_MSG_BYTES (20 MiB — see the const below;
//   an earlier 1 MB figure survived here long after the const grew)
//
// Wire format (TCP, client):
//   [4 bytes big-endian length][CBOR-encoded WireMessage]
//
// Wire format (Stdio):
//   One JSON object per line on stdin/stdout.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use log::{info, warn};

use crate::types::*;

/// Maximum wire message size (20 MiB).
///
/// KI#79: 1 MiB until 2026-08-08 — under every serialized bloom era
/// (~5.41 MiB), so era transfer could NEVER ship a frame and the KI#42
/// re-arm loop starved silently (zero `[ERA-SYNC] adopted` in any node's
/// history). Sized for the worst-case StatePull response: three sections
/// each budgeted at `STATE_PULL_MAX_BYTES` (6 MiB) + previous_states +
/// framing slack ≈ 19 MiB. Per-frame allocation from an unauthenticated
/// peer is the exposure; total buffered bytes stay governed by
/// `INBOX_MAX_BYTES`. Enforced against era sizing at boot and by
/// `ki79_era_fits_transfer_caps` — change `*_ERA_REAL_ITEMS`,
/// `STATE_PULL_MAX_BYTES` and this TOGETHER.
pub const WIRE_MAX_MSG_BYTES: usize = 20_971_520;

/// SECURITY FIX #12: Maximum inbox queue depth (secondary, count-based bound).
/// Prevents OOM under sustained load — messages beyond this limit are dropped.
/// A node that can't keep up will miss messages but won't crash.
///
/// Lowered 10_000 → 2_000 (2026-06-25). The count cap is the *secondary*
/// guard now — it bounds per-Envelope/thread overhead under a small-message
/// (gossip/query) flood. The primary governor is the BYTE bound below.
const INBOX_MAX_DEPTH: usize = 2_000;

/// Primary OOM governor: maximum total queued message bytes.
///
/// The count cap alone was unsafe: with `WIRE_MAX_MSG_BYTES = 1 MiB` and a
/// 10_000 depth, the worst-case inbox was ~10 GiB — a single writer Nabla
/// under a 50w registration flood reached ~6.5 GiB anon-rss and was
/// OOM-killed (2026-06-25 §2 endurance soak), taking txid-attestation
/// service down mesh-wide. Bounding *count* but not *bytes* was the
/// incomplete half of SECURITY FIX #12.
///
/// 256 MiB absorbs a healthy burst (~640 registration-sized messages at
/// ~400 KiB each, ~13 s of backlog at ~50 reg/s) while capping intake at a
/// small, fixed fraction of host RAM (~1.7% of a 15 GiB box, ~3-6% of a
/// 4-8 GiB production host) so intake can never OOM the node. Whichever of
/// {depth, bytes} trips first sheds load. Operationally this should scale
/// to host RAM: clamp(5% of total RAM, 64 MiB, 512 MiB).
const INBOX_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Inbox admission decision: may a message of `incoming_bytes` be enqueued
/// given the current queue depth and total queued bytes? `false` → shed it
/// (back-pressure). Bounds BOTH count (`INBOX_MAX_DEPTH`) and total bytes
/// (`INBOX_MAX_BYTES`) — the byte bound is the primary OOM governor; the
/// count cap alone (10k × ≤1 MiB) allowed a ~10 GiB inbox. Pure, so the
/// bound is unit-testable without a socket.
#[inline]
fn inbox_admits(queue_len: usize, queued_bytes: usize, incoming_bytes: usize) -> bool {
    queue_len < INBOX_MAX_DEPTH && queued_bytes.saturating_add(incoming_bytes) <= INBOX_MAX_BYTES
}

/// Read timeout for TCP connections.
/// Must be generous: SPHINCS+ verification takes 1-3s in release, ~30s in debug.
/// A connection may be idle for 60+ seconds between Hello and the next message
/// (e.g. TardisAttachRequest) while SPHINCS+ verification blocks the sender.
/// TCP keepalive probes (30s) detect truly dead connections at the OS level.
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Write timeout for TCP connections.
const TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

// ── Peer circuit-breaker (KI#96 follow-up, 2026-08-17) ──────────────
// The write timeout (above) bounds ONE stuck send to TCP_WRITE_TIMEOUT, but a
// dead / slow / wire-incompatible peer (e.g. a remote node on an older CoreID
// that can't decode our AE, or a peer on a lossy link that never drains) is
// re-attempted on EVERY gossip/AE cycle — each attempt burning up to
// TCP_WRITE_TIMEOUT while holding the node mutex, which starves client
// registration mesh-wide. The circuit-breaker makes the node ABANDON such a
// peer: after PEER_CB_FAILURE_THRESHOLD consecutive send failures the peer goes
// "cold" and outbound sends to it are skipped (return Err immediately, no
// connect/write) for an exponentially-backed-off window, until a probe after
// the window succeeds and clears it. This is the design rule "it should abandon bad
// data when it recognised it" — recognise the doomed peer, stop paying for it.
// Purely LOCAL network hygiene: the backoff is measured with a monotonic
// `Instant`, never a protocol/consensus clock, and it only decides which peer
// to attempt a TCP write to — it changes no signed value and no protocol rule.
const PEER_CB_FAILURE_THRESHOLD: u32 = 3;
const PEER_CB_BACKOFF_BASE: Duration = Duration::from_secs(30);
const PEER_CB_BACKOFF_MAX: Duration = Duration::from_secs(300);

// ── Wire Protocol ──────────────────────────────────────────────────

/// All message types that flow over the wire between Nabla nodes.
///
/// This is the transport envelope. Protocol logic (tardis.rs, mesh.rs,
/// gossip.rs) produces and consumes the inner types. The transport
/// layer only serializes/deserializes this envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    // ── TARDIS (tick authority) ──
    Tick(TickMessage),
    Approval(TickApproval),
    AuditRequest(SubtreeAuditRequest),
    AuditResponse(SubtreeAuditResponse),
    Alert(QuestionableAlert),

    // ── Gossip (flood-fill data) ──
    Gossip(GossipMessage),

    // ── Registration / Query ──
    Register(Registration, DeedTransaction),
    RegisterAck(RegistrationAck),
    /// Registration rejected — sent back to client with reason (fixes silent failure bug).
    RegisterRejected {
        wallet_id: WalletId,
        reason: String,
        #[serde(default)]
        known_peers: Vec<NablaClientPeer>,
    },
    Query { wallet_id: WalletId },
    QueryResponse(NablaResponse),
    /// YPX-021 §8.2 / Ark L Phase 2 — client asks for this node's current signed
    /// OODS reading (Nabla-signed + NBC-anchored live tick).
    OodsReadingRequest(crate::wire_client::OodsReadingRequest),
    /// Response to `OodsReadingRequest`.
    OodsReadingResponse(crate::wire_client::OodsReadingResponse),

    // ── Client TCP-CBOR migration paths (CLAUDE.md §8) ──
    // These mirror three grandfathered HTTP endpoints so the native SDK
    // can drop `http_request` and speak TCP-CBOR exclusively. HTTP
    // handlers remain for the browser SDK (WASM can't open raw TCP).
    /// `/query-txid` over TCP. SDK callsites: redeem prepass, §4.6 verify,
    /// generic txid lookup.
    QueryTxidRequest(crate::wire_client::QueryTxidRequest),
    QueryTxidResponse(crate::wire_client::QueryTxidResponse),
    /// `/register-cheque-claim` over TCP. SDK callsites: cheque claim
    /// flow in nabla.rs (×2).
    RegisterChequeClaimRequest(crate::wire_client::RegisterChequeClaimRequest),
    RegisterChequeClaimResponse(crate::wire_client::RegisterChequeClaimResponse),
    /// `/clara` over TCP. SDK callsites: heal.rs CLARA TX_HEAL
    /// participant registration.
    RegisterClaraRequest(crate::wire_client::RegisterClaraRequest),
    RegisterClaraResponse(crate::wire_client::RegisterClaraResponse),
    /// `/query?wallet_pk=...` over TCP. SDK callsites:
    /// nabla.rs::query_wallet_state — wallet registration + ban status
    /// lookup invoked from verify_cheque (§4.6 prepass + post-Timer-A
    /// re-check).  Closes the 6th of 7 grandfathered HTTP→TCP sites.
    QueryWalletStateRequest(crate::wire_client::QueryWalletStateRequest),
    QueryWalletStateResponse(crate::wire_client::QueryWalletStateResponse),
    /// `/register` over TCP (2026-05-15).  Closes the LAST
    /// grandfathered HTTP→TCP site (CLAUDE.md Upcoming Task #3).
    /// SDK callsite: nabla.rs::get_fact_confirmation — the receipt-
    /// proven state-registration path that returns `fact_confirm_signature`
    /// (the Ed25519 sig over `(old_state, new_state)` Core uses to
    /// anchor a FACT link) and the NBC trust-anchor fields.
    ///
    /// Three response variants mirror HTTP's tri-state (200 / 409 / 4xx):
    ///   - `FactConfirmResponse` — success or REDIRECT (status="REGISTERED"|"REDIRECT")
    ///   - `FactConfirmMismatch` — 409 conflict (old_state ≠ stored)
    ///   - `FactConfirmRejected` — receipt missing / insufficient k / sig verify fail
    FactConfirmRequest(crate::wire_client::RegisterRequest),
    FactConfirmResponse(crate::wire_client::RegisterResponse),
    FactConfirmMismatch(crate::wire_client::RegisterMismatchResponse),
    FactConfirmRejected(axiom_errors::ErrorResponse),

    // ── Phase 3c TCP-CBOR migration paths (CLAUDE.md §8) ──
    // The last six functional HTTP endpoints — `/pulse-proof`,
    // `/jfp-secret`, `/jfp-secrets`, `/bridge`, `/endorse-ban-challenge`,
    // `/challenge-ban` — migrated to the TCP-CBOR wire. Each request
    // variant carries the typed `wire_client` struct; each response
    // variant carries the matching typed response. Errors travel as
    // `axiom_errors::ErrorResponse` (the same shape the HTTP CBOR error
    // body used). Nabla's functional HTTP handlers were removed 2026-09-26.
    /// `/pulse-proof` over TCP — YPX-009 validator→Nabla PulseProof
    /// forward for gossip injection.
    PulseProofRequest(crate::wire_client::PulseProofRequest),
    PulseProofResponse(crate::wire_client::PulseProofResponse),
    PulseProofRejected(axiom_errors::ErrorResponse),
    /// `/jfp-secret` over TCP — JFP/DWP vote-secret registration.
    JfpSecretRequest(crate::wire_client::JfpSecretRequest),
    JfpSecretResponse(crate::wire_client::JfpSecretResponse),
    JfpSecretRejected(axiom_errors::ErrorResponse),
    /// `/jfp-secrets` over TCP — query registered vote secrets.
    JfpSecretsRequest(crate::wire_client::JfpSecretsRequest),
    JfpSecretsResponse(crate::wire_client::JfpSecretsResponse),
    /// `/bridge` over TCP — §6.6 partition-recovery peer bridge.
    BridgeRequest(crate::wire_client::BridgeRequest),
    BridgeResponse(crate::wire_client::BridgeResponse),
    BridgeRejected(axiom_errors::ErrorResponse),

    /// YP §19.6 fee ledger — validator earnings query. Hashmap nodes
    /// return signed authoritative totals from their `txid_records`
    /// store; bloom nodes return empty + non-authoritative so the SDK
    /// re-queries elsewhere. Signature verifiable via NBC chain.
    QueryValidatorEarningsRequest(crate::wire_client::QueryValidatorEarningsRequest),
    QueryValidatorEarningsResponse(crate::wire_client::QueryValidatorEarningsResponse),

    /// YP §19.6 fee ledger — validator pool linkage management.
    /// Operator-driven (per-validator dashboard at :7700-7709 / Lambda
    /// admin endpoint). Binds `validator_id` to `linked_wallet_id` for
    /// fee withdrawals; re-link via higher `linkage_epoch`. Wallet SDK
    /// is NOT a consumer.
    RegisterValidatorPoolRequest(crate::wire_client::RegisterValidatorPoolRequest),
    RegisterValidatorPoolResponse(crate::wire_client::RegisterValidatorPoolResponse),
    /// YP §19.6 — query the current pool linkage for a validator.
    QueryValidatorPoolRequest(crate::wire_client::QueryValidatorPoolRequest),
    QueryValidatorPoolResponse(crate::wire_client::QueryValidatorPoolResponse),

    // ── Mesh management ──
    IntroductionRequest { from: NodeId },
    IntroductionResponse { peers: Vec<PeerInfo> },

    // ── Identity ──
    Hello {
        node_id: NodeId,
        /// The port PEERS reach this node on — operator-declared
        /// (`node.toml::external_port`), NEVER an address.
        ///
        /// ⚠ §5.6a-bis: A NODE NEVER STATES WHERE IT IS. It states only the
        /// port it can be reached on; the receiver composes
        /// `observed source IP : this port` and stores THAT. A self-asserted
        /// address is the thing this field replaced — every peer used to relay
        /// the claim verbatim, so the observation half of §5.6a was inert while
        /// the assertion survived.
        ///
        /// The IP can be observed; the port cannot, ever — TCP carries only the
        /// ephemeral source port, which NAT rewrites again. See
        /// `ceremony::NodeToml::external_port`.
        external_port: u16,
        /// Sender's current downstream count (0, 1, or 2).
        /// Allows receivers to track which peers have open D slots.
        downstream_count: u8,
        /// Serialized NBC (bincode). Required for identity verification.
        /// Receiver verifies: well-formed, not expired, node_id matches BLAKE3(sphincs_pk).
        #[serde(default)]
        nbc_bytes: Vec<u8>,
        /// Sender's YPX-014 txid service mode — `"hashmap"` or `"bloom"`.
        /// Surfaces the operator's `--txid-mode` choice into mesh gossip so
        /// audit-grade consumers (UNCLE, regulator clients) can constrain
        /// register/query traffic to hashmap-mode nodes. Receivers populate
        /// `PeerInfo.txid_service` from this field instead of defaulting to
        /// the empty string. Default for `serde` is the empty string for
        /// cross-version compat with pre-2026-05-30 senders.
        #[serde(default)]
        txid_service: String,
        /// Serialized supporting NBC chain (`bincode` of `Vec<NBC>`), EMPTY for
        /// a genesis (chain_depth 0) node and populated only by a citizen whose
        /// own NBC is chain_depth>0 (validator-issued). The receiver needs it to
        /// walk the issuer chain to a Nabla root — without it, Core's CL7 verify
        /// fails a citizen NBC with InvalidVBC (the 2026-08-16 Pi join gap). New
        /// field goes LAST (bincode is positional); `serde(default)` keeps it
        /// empty for genesis peers and any pre-field sender.
        #[serde(default)]
        nbc_supporting_bytes: Vec<u8>,
        /// GUIDE §5.6a — the source IP we observed for the RECIPIENT of this
        /// Hello, i.e. "this is where I see you coming from". A NAT'd node
        /// cannot learn its own WAN address any other way: `getsockname()`
        /// returns the pre-NAT tuple, the rewrite happens off-host, and the
        /// return path is rewritten back before it reaches the stack. Only the
        /// far end sees it.
        ///
        /// IP ONLY, never the port — `envelope.peer`'s port is the ephemeral
        /// NAT-translated source, not the port the peer listens on. Peers must
        /// dial `WAN_IP : forwarded_port`, so the port comes from the peer's
        /// own config.
        ///
        /// Stored IPv6-mapped so v4 and v6 share one field. `None` = we have
        /// not observed an inbound connection from them yet.
        ///
        /// ⚠ This field is TRUSTED ONLY AS FAR AS THE SENDER'S NBC, which this
        /// same Hello carries. An unauthenticated peer telling a node its own
        /// address would be unauthenticated input driving a consequential
        /// decision (RULE 3 shape 5 — the KI#72 shape). Never act on it before
        /// `verify_peer_nbc_with_supporting` has passed.
        ///
        /// NEW FIELDS GO LAST — bincode is positional, so field order IS the
        /// wire format. All nodes must roll together.
        observed_peer_ip: Option<[u8; 16]>,
    },

    // ── TARDIS Join Protocol ──
    /// Request to attach as downstream child. "Do you have an open D slot?"
    TardisAttachRequest {
        /// Requesting node's ID.
        node_id: NodeId,
        /// The port PEERS reach the requester on — operator-declared
        /// (`node.toml::external_port`), NEVER an address.
        ///
        /// ⚠ §5.6a-bis: A NODE NEVER STATES WHERE IT IS. Same rule and same
        /// shape as `Hello::external_port` — the receiver composes
        /// `observed source IP : this port` and stores THAT.
        ///
        /// ⚠ WHY THIS FIELD EXISTS AT ALL (read before "simplifying" it away).
        /// `Hello` was fixed first and this message was left asserting
        /// `address: NablaAddress`, which the receiver stored VERBATIM via
        /// `upsert_peer_self_announced`. That made the Hello fix a half-measure:
        /// a node that never sent a Hello, or whose Hello claim was overwritten
        /// by a later attach, still put itself wherever it liked. Deleting
        /// `--advertise` without fixing this would have been worse still — the
        /// self-address degrades to the wildcard bind (`0.0.0.0:<port>`) and
        /// every attach target would have stored THAT, killing cross-host
        /// dial-back mesh-wide. Found 2026-08-26 while removing `--advertise`.
        external_port: u16,
        /// Whether requester has children (used for strict/relaxed placement).
        has_children: bool,
        /// If true, only accept if parent already has dc=1 (accepting creates a writer).
        /// This is the "strict pass" from orphan recovery — prefer writer-creating placements.
        prefer_writer: bool,
        /// Serialized NBC (bincode). Required for identity verification.
        #[serde(default)]
        nbc_bytes: Vec<u8>,
        /// Supporting NBC chain (bincode `Vec<NBC>`) — see Hello. Empty for
        /// genesis nodes; populated by a citizen (chain_depth>0) so a parent can
        /// verify its NBC to a Nabla root before granting a D slot.
        #[serde(default)]
        nbc_supporting_bytes: Vec<u8>,
    },
    /// Response to attach request.
    TardisAttachResponse {
        /// Responding node's ID.
        node_id: NodeId,
        /// Whether the attach was accepted (D slot available and assigned, or —
        /// with `pending: true` — the P slot granted).
        accepted: bool,
        /// YPX-003 §2.1 step 2 (KI#48, RULED 2026-09-25): `accepted: true,
        /// pending: true` = "you are my PENDING child": receive my ticks like a
        /// D child, keep seeking a D slot, I promote you when one opens. NO
        /// serde default — every node rolls together; an old node cannot decode
        /// this and must not silently read it as a D grant.
        pending: bool,
        /// Responding node's downstream count (for strict placement decisions).
        downstream_count: usize,
        /// If rejected, referrals to other nodes that may have open D slots.
        referrals: Vec<PeerInfo>,
        /// Responder's NBC for mutual identity verification (N2 tick check).
        #[serde(default)]
        nbc_bytes: Vec<u8>,
        /// Responder's supporting NBC chain (bincode `Vec<NBC>`) — see Hello.
        /// Empty for genesis responders; populated when a citizen (chain_depth>0)
        /// acts as a TARDIS parent so the attaching child can verify it to root.
        #[serde(default)]
        nbc_supporting_bytes: Vec<u8>,
    },

    /// Child notifies parent it already has an upstream — parent should free the D slot.
    /// Prevents phantom children when multiple parents accept simultaneously.
    TardisDetach {
        node_id: NodeId,
    },

    /// NBC verification failed — connection rejected.
    /// Sent back to the peer whose Hello or TardisAttachRequest had an invalid NBC.
    NbcReject {
        reason: String,
    },

    // ── Nabla Join Protocol ──

    /// First-time network join request. New node presents identity + wallet binding.
    /// The joiner is probationary while its NBC is younger than
    /// `nabla_probation_ticks` (GUIDE §5.6c) — judged from the certificate,
    /// not from this request's arrival time.
    NablaJoinRequest {
        /// Serialized NBC (bincode).
        nbc_bytes: Vec<u8>,
        /// Operator's AXIOM wallet ID.
        wallet_id: WalletId,
        /// Operator's wallet Ed25519 public key (32 bytes).
        wallet_pubkey: Vec<u8>,
        /// Operator's signature: sign_wallet_key(nabla_id || wallet_id).
        /// Proves wallet owner consents to this Nabla node binding.
        wallet_binding_sig: Vec<u8>,
    },

    /// Response to NablaJoinRequest.
    NablaJoinResponse {
        /// Whether the join was accepted (starts probation).
        accepted: bool,
        /// If rejected, reason string.
        reason: String,
        /// Assigned probation end time (unix seconds). 0 if rejected.
        probation_until: u64,
    },

    // ── NBC Peer Issuance ──
    /// Request NBC issuance from a qualified peer. New node sends its public keys.
    NbcIssuanceRequest {
        /// SPHINCS+ public key (32 bytes).
        sphincs_pk: Vec<u8>,
        /// Ed25519 public key (32 bytes).
        ed25519_pk: Vec<u8>,
        /// Dilithium public key (1952 bytes).
        dilithium_pk: Vec<u8>,
        /// Requested node name (max 64 bytes).
        node_name: String,
        /// The port the requester can be reached on — operator-declared
        /// (`node.toml::external_port`). `0` = a true external client with no
        /// listener, which reads the reply on its own connection (the issuer
        /// falls back to `send_reply`).
        ///
        /// WHY A REPLY ADDRESS IS NEEDED AT ALL: a bootstrapping node is not yet
        /// in the issuer's peer table, so the issuer cannot resolve it via
        /// `peer_by_id`; and a mesh node never reads its outbound connections
        /// (KI#42), so a `send_reply` on the inbound stream is dropped. The
        /// reply must therefore be addressed to the requester's LISTENER,
        /// exactly as `StatePullRequest.from` does.
        ///
        /// ⚠ §5.6a-bis: this was `reply_addr: Option<String>` — a full
        /// "host:port" the requester asserted. The host half was ALREADY being
        /// discarded by the issuer (which composes `envelope.peer.ip()` + the
        /// parsed port, to kill a reflection vector and to keep a blocking
        /// `getaddrinfo` off the node mutex — KI#92/#96). Keeping a String meant
        /// carrying, parsing and validating a host that could never be used:
        /// a scar, and a standing invitation to "restore" the host half. The
        /// field now carries what the issuer actually consumes, and `reply_port`
        /// (with its bracketed-IPv6 and zero-port edge cases) is deleted.
        external_port: u16,
        /// The requester's ONE operator wallet_id (`node.toml::operator_wallet`;
        /// the owner, 2026-09-20: "Nabla binds one wallet = operator wallet"). MUST be a
        /// REAL account — the issuer rejects a dev operator (`@axiom` /
        /// `@axiom.internal`) at `build_unsigned_nbc`. Empty = not declared
        /// (grandfathered). NEW FIELD LAST (bincode positional). Issuance-time
        /// check (honest issuer, k=1 Nabla trust); the tamper-proof preimage
        /// binding is the genesis-ceremony follow-up.
        operator_wallet: String,
    },
    /// Response to NBC issuance request.
    NbcIssuanceResponse {
        /// Whether the issuance was accepted.
        accepted: bool,
        /// Serialized NBC (bincode). Empty if rejected.
        nbc_bytes: Vec<u8>,
        /// Serialized supporting chain Vec<NBC> (bincode). Empty if rejected.
        supporting_chain_bytes: Vec<u8>,
        /// Rejection reason. Empty if accepted.
        rejection_reason: String,
    },

    // ── NBC Renewal ──
    /// Request NBC renewal from a qualified peer before expiry.
    NbcRenewRequest {
        /// Current NBC bytes (bincode-serialized).
        current_nbc_bytes: Vec<u8>,
        /// Ed25519 signature over BLAKE3("AXIOM_NBC_RENEW" || validator_id || current_time).
        /// Proves the requester possesses the corresponding private key.
        renewal_sig: Vec<u8>,
        /// Unix timestamp included in the renewal signature.
        current_time: u64,
    },
    /// Response to NBC renewal request.
    NbcRenewResponse {
        /// Whether renewal was accepted.
        accepted: bool,
        /// New NBC bytes (bincode-serialized). Empty if rejected.
        nbc_bytes: Vec<u8>,
        /// Supporting chain (bincode-serialized Vec<NBC>). Empty if rejected.
        supporting_chain_bytes: Vec<u8>,
        /// Rejection reason. Empty if accepted.
        rejection_reason: String,
    },

    /// DEV-MODE ONLY (KI#43b live gate): insert `state_id` into this node's
    /// consumed-state BLOOM without touching its exact record — a synthetic
    /// false positive, the one thing a real FP does that nothing else can
    /// stage on demand. Refused unless the node was started with
    /// `--dev-mode`. Test instrument for
    /// `docs/models/consumed_adjudication/` gate runs; never a protocol op.
    DevInjectConsumedBloomFp {
        state_id: Hash256,
    },
    /// Result of the above: `true` = injected (dev node), `false` = refused.
    DevInjectConsumedBloomFpAck {
        injected: bool,
    },

    // ── KI#43b heal-adjudication barrier (§12.4.4, model-checked) ──
    /// Ask a recording peer the WHOLE-HISTORY question about a consumed-bloom
    /// hit: is `state_id` anywhere in your exact record, and is your record
    /// clean since chain origin? Sent by the heal-serving node AFTER a local
    /// bloom hit (the hit triggers; the barrier decides). `born_tick` bounds
    /// the relevant history (0 = whole history; the state's receipt tick once
    /// plumbed) — peers resolve it against their own LOCAL eras; era ids
    /// never cross the wire (chains rebase, ids are node-local).
    ExactConsumedQuery {
        /// Sender's node id — replies are addressed to this peer's
        /// *listening* socket via `peer_by_id` (`None` = external tooling,
        /// which reads the reply on its own connection).
        from: Option<NodeId>,
        state_id: Hash256,
        born_tick: u64,
    },
    /// A recording peer's signed-by-transport answer. `recorded` — state_id
    /// is somewhere in the responder's exact record (⇒ REFUSE, the
    /// consumption is real). `clean` — the responder's record is
    /// continuously clean for the queried range (its half of the §12.4.4
    /// acquittal conjunction). A bloom-mode responder answers
    /// `recorded: false, clean: false` — honest: it can never vouch.
    ExactConsumedAnswer {
        /// Responder's node id — the requester counts DISTINCT recording
        /// responders toward the `RECORDING_NODES_TOTAL - 1` barrier.
        responder: NodeId,
        state_id: Hash256,
        recorded: bool,
        clean: bool,
    },

    // ── State Sync (YPX-009 §12.8) ──
    /// Request state data from a peer (bootstrap or WAL cross-verification).
    StatePullRequest {
        mode: StatePullMode,
        /// Sender's node id when the requester is a MESH NODE. Replies are
        /// addressed to this peer's *listening* socket (resolved via
        /// `peer_by_id`), same as `AeDigest::from`: a node never reads from
        /// its outbound connections, so a `send_reply` on the inbound stream
        /// is written into a socket nobody drains. `None` = external client
        /// (recovery tooling / examples) that reads the reply on its own
        /// connection — those DO get the `send_reply` path.
        from: Option<NodeId>,
        /// Our current SMT root hash (for comparison).
        our_root_hash: Hash256,
        /// Start of tick range to pull.
        from_tick: u64,
        /// End of tick range to pull.
        to_tick: u64,
        /// Section hash for WalVerify mode (None for Bootstrap).
        #[serde(default)]
        section_hash: Option<Hash256>,
        /// KI#42 step 4b — era ids we ALREADY hold in our txid bloom chain, so the
        /// peer sends only what we are missing.
        ///
        /// Era transfer must be incremental: a fully-allocated era is ~5.41 MiB
        /// at the deployed sizing (KI#79 — a pre-2026-08-08 version of this
        /// comment said ~1.7 MiB, and the caps sized to THAT number are how
        /// transfer silently starved), and `STATE_PULL_MAX_BYTES` admits one
        /// era per section per pull, so a mature chain cannot ship in one
        /// response. Advertising what we have turns this into a convergent
        /// loop — each pull closes part of the gap, and a node that is
        /// already current asks for nothing.
        #[serde(default)]
        have_era_ids: Vec<u64>,
        /// KI#42 step 4d — consumed-state era ids we already hold, same purpose.
        #[serde(default)]
        have_consumed_era_ids: Vec<u64>,
    },
    /// Response to StatePullRequest.
    StatePullResponse {
        mode: StatePullMode,
        /// State entries in the requested range.
        entries: Vec<StatePullEntry>,
        /// Highest tick served in this response.
        highest_tick_served: u64,
        /// KI#42 step 4b — serialized txid bloom ERAS the requester lacked, each
        /// CBOR-encoded `BloomEra`, bounded by `STATE_PULL_MAX_BYTES`.
        ///
        /// This is the era-chain counterpart to `consumed_bloom` below. Before it,
        /// era chains had no transfer path at all, so a fresh node could never
        /// re-arm one — which is why the plan builds this BEFORE migrating any
        /// filter onto eras (`AXIOM_DESIGN_NablaAntiEntropy.md` §12). Merged with
        /// `BloomChain::merge`: monotonic union, so a partial or empty payload can
        /// only fail to add, never disarm the receiver.
        #[serde(default)]
        bloom_eras: Vec<Vec<u8>>,
        /// WI1 (§5.2) + KI#42 step 4d: consumed-state ERAS, so a wiped/recovering
        /// node re-arms its anti-rollback view (A12) instead of coming back blind.
        /// UNION-merged on receive (monotonic), refused if implausibly dense.
        /// Bounded by `STATE_PULL_MAX_BYTES`, so a mature chain converges over
        /// several pulls — see `consumed_era_manifest` for how the receiver knows
        /// when it is done.
        consumed_eras: Vec<Vec<u8>>,
        /// KI#42 step 4d — EVERY consumed-state era id the responder holds.
        ///
        /// A fail-closed filter cannot be partially armed: a node holding 39 of 40
        /// eras is silently blind to whatever lived in the 40th and would pass a
        /// rollback. The requester arms only once it holds every id here. This is
        /// what distinguishes this chain from the txid chain, which may legitimately
        /// be tiered because a hit there is adjudicable via archive lookup.
        consumed_era_manifest: Vec<u64>,
        /// WI1 (§5.2): authoritative `previous_states` (wallet → consumed `X`).
        /// Insert-if-absent on receive; arms `is_state_consumed(X)` so a forged
        /// rollback to X is detected on the recovered node.
        previous_states: Vec<(WalletId, StateId)>,
        /// WAL verify result (only for WalVerify mode).
        #[serde(default)]
        verify_result: Option<WalVerifyResult>,
        /// Earliest tick this peer has available.
        available_from_tick: u64,
        /// Whether the peer is at serving capacity.
        overloaded: bool,
    },
    /// Request bilateral range comparison for gap fill.
    RangeSyncRequest {
        /// Start of tick range to compare.
        from_tick: u64,
        /// Number of records in our section.
        record_count: u64,
        /// BLAKE3 hash of our section's entries.
        section_hash: Hash256,
        /// Our latest tick (for the peer to gauge freshness).
        our_latest_tick: u64,
    },
    /// Response to RangeSyncRequest.
    RangeSyncResponse {
        /// Result of section comparison.
        match_result: RangeSyncMatch,
        /// Entries the peer has that we're missing (on Mismatch).
        missing_entries: Vec<StatePullEntry>,
        /// Peer's latest tick.
        peer_latest_tick: u64,
        /// Peer's section hash for the same range.
        peer_section_hash: Hash256,
    },

    /// Anti-entropy step 2 — the responder's full leaf-hash digest, sent
    /// when a `TickHash` probe shows a root mismatch. The initiator diffs
    /// it against its own `SparseMerkleTree::leaf_digest()` to localize
    /// divergent wallets without transferring entries.
    /// See `docs/AXIOM_DESIGN_NablaAntiEntropy.md` §5.3/§5.4.
    AeDigest {
        /// Sender's node id. Replies are addressed to this peer's
        /// *listening* socket (resolved via `peer_by_id`) — the inbound
        /// connection's source port is ephemeral and already closed.
        from: NodeId,
        /// `(wallet_id, leaf_hash)` for every entry in the sender's SMT.
        leaves: Vec<(WalletId, Hash256)>,
    },
    /// Anti-entropy step 3 — the initiator's reconcile message. `push`:
    /// entries the initiator holds that the responder is missing or has a
    /// different leaf for. `pull`: wallet_ids whose leaf differs (or the
    /// initiator lacks) — the responder returns those in `AeEntries`.
    AeReconcile {
        /// Sender's node id — `AeEntries` is addressed to this peer's
        /// listening socket via `peer_by_id`.
        from: NodeId,
        /// WI3 hole-1 (KI#34): each pushed entry carries its k=3 seq
        /// attestation (`None` on legacy / no-attestation paths). The
        /// receiver verifies it in `apply_remote_entry` before trusting
        /// `wallet_seq` for the merge — a bare AE seq is forgeable.
        push: Vec<(NablaEntry, Option<SeqProof>)>,
        pull: Vec<WalletId>,
        /// ForkSettlement §2.3 [R18] — the sender's fork bans WITH their
        /// self-proving evidence (`BanEvidence::Fork`'s `ForkClaim`), at most
        /// `ban::AE_FORK_BANS_MAX` per message (`NablaNode::ae_fork_bans_out`,
        /// cursor-rotated when there are more). The receiver screens them OFF
        /// the node lock (`ban::screen_ae_fork_bans`) and adopts through the
        /// ONE chokepoint (`NablaNode::adopt_ae_fork_bans` →
        /// `ban::adopt_fork_claim` → `verify_fork_claim`, [R25]); unverifiable
        /// → nothing banned, `atraxi_evidence_refused` counted. Appended LAST,
        /// no `serde(default)` (§13): a mixed fleet is not supported.
        fork_bans: Vec<ForkClaim>,
    },
    /// Anti-entropy step 4 — the responder returns the pulled entries.
    AeEntries {
        /// WI3 hole-1: pulled entries carry their k=3 seq attestation, same
        /// as `AeReconcile.push`.
        entries: Vec<(NablaEntry, Option<SeqProof>)>,
        /// ForkSettlement [R18]/[R25] — the responder's fork bans, computed
        /// AFTER it applied the reconcile's push, so a fork the push revealed
        /// travels back to the offerer in the same exchange. Same bound and
        /// same receiver path as `AeReconcile.fork_bans`. LAST, no default.
        fork_bans: Vec<ForkClaim>,
    },

    // ── Sim control (binary sim mode) ──
    /// Request node status for metrics collection.
    StatusRequest,
    /// Node status response with TARDIS metrics.
    StatusResponse {
        node_id: NodeId,
        node_name: String,
        needs_parent: bool,
        /// YPX-003 §2.1 (KI#48): parked in a host's P slot — `needs_parent`
        /// stays true while this is true. Lets the simulator SEE a P node and
        /// show its tick advancing while parked (`tardis_tick`).
        upstream_pending: bool,
        downstream_count: usize,
        is_leaf: bool,
        has_d_open: bool,
        alive: bool,
        smt_len: usize,
        peer_count: usize,
        // ── dev-status enrichment (zero/None when feature is off) ──
        tardis_tick: u64,
        root_hash: [u8; 32],
        messages_received: u64,
        upstream_id: Option<NodeId>,
        d1_id: Option<NodeId>,
        d2_id: Option<NodeId>,
        d1_approved: bool,
        d2_approved: bool,
        known_nodes: usize,
        gossip_active: bool,
        // ── Persistence metrics ──
        #[serde(default)]
        wal_file_bytes: u64,
        #[serde(default)]
        wal_ops_since_snapshot: u64,
        #[serde(default)]
        snapshot_count: usize,
        #[serde(default)]
        snapshot_total_bytes: u64,
        #[serde(default)]
        last_snapshot_tick: u64,
        #[serde(default)]
        total_disk_bytes: u64,
        #[serde(default)]
        smt_memory_bytes: u64,
        /// NBC issuer name (e.g. "alpha", "ceremony").
        #[serde(default)]
        nbc_issuer: String,
    },

    // ── §6.3.7 Latency probe (mesh-local RTT measurement) ──
    /// Liveness/latency ping. The receiver echoes a `Pong` with the same
    /// nonce to the sender's LISTENING address (`from`), so the sender can
    /// time the round-trip. Local-only signal — never bound into a fact.
    Ping { from: NodeId, nonce: u64 },
    /// Echo of a `Ping`. Lets the original sender compute RTT for `from`.
    Pong { from: NodeId, nonce: u64 },
    /// `/recall` over TCP — YPX-022 sender reclaim. SDK callsite: recall.rs (3.5).
    RecallRequest(crate::wire_client::RecallRequest),
    RecallResponse(crate::wire_client::RecallResponse),

    // ── KI#82 fee-ledger anti-entropy (§19.6 txid_records convergence) ──
    // Added LAST — bincode is positional, so new variants must not shift the
    // existing discriminants (see feedback: new wire variants go last).
    /// Step 1: `from` advertises its per-bucket fee-ledger digest vector to a
    /// rotating peer on the AE tick. Hashmap nodes only. See
    /// AXIOM_DESIGN_NablaAntiEntropy.md §13.
    TxidAeDigest {
        from: NodeId,
        /// `(bucket_id, BLAKE3 over sorted tx_hashes in that bucket)`, sorted by
        /// bucket_id. Same vector on two nodes IFF identical `txid_records` set.
        buckets: Vec<(u64, [u8; 32])>,
    },
    /// Step 2: the responder pushes its records in every bucket whose digest
    /// differs from (or is absent in) the sender's advertisement. The receiver
    /// adopts each through the cap-revalidating gossip chokepoint (dedup on
    /// tx_hash), so redundant/forged records are a no-op/reject. Union, not
    /// merge — records are immutable; the reverse direction is covered by peer
    /// rotation.
    TxidAeEntries {
        records: Vec<(crate::types::TxHash, crate::types::TxRecord)>,
    },

    // ── §10.0 FOB fee-claim attestation fetch (SDK-facing; added LAST) ──
    /// The stake wallet asks this (hashmap) Nabla for the claim attestation.
    FobClaimAttestationRequest(crate::wire_client::FobClaimAttestationRequest),
    /// Reply: status + the Ed25519-signed, NBC-anchored attestation.
    FobClaimAttestationResponse(crate::wire_client::FobClaimAttestationResponse),

    // ── KI#84 FOB ledger AE (added LAST — bincode positional) ──
    /// Step 1: `from` advertises its FOB ledger digest (over the PLUS + MINUS
    /// sets) to a rotating peer on the AE tick. If it differs from the
    /// receiver's, the receiver pushes its ledgers back. Hashmap nodes only.
    FobLedgerDigest { from: NodeId, digest: [u8; 32] },
    /// Step 2: the responder pushes BOTH full ledgers. The receiver set-unions
    /// them (idempotent per key) and rebuilds affected pools —
    /// `balance = Σplus − Σminus`. Union, not merge; the reverse direction is
    /// covered by peer rotation.
    FobLedgerEntries {
        plus: Vec<((u64, [u8; 32], bool), u64)>,
        minus: Vec<(crate::types::TxHash, ([u8; 32], bool, u64))>,
    },
    /// §6b VBC registration (client TCP-CBOR; appended LAST — bincode is
    /// positional). The operator presents a candidate certificate; reply is
    /// `RegisterVbcResponse` with the stamp or a typed refusal.
    RegisterVbcRequest(crate::wire_client::RegisterVbcRequest),
    RegisterVbcResponse(crate::wire_client::RegisterVbcResponse),
    /// Contribution emission (`AXIOM_DESIGN_ValidatorEmission.md`; appended
    /// LAST): the Operational wallet asks for this epoch's claim attestation.
    /// Reply is a `FobClaimAttestationResponse`.
    EmissionClaimAttestationRequest(crate::wire_client::EmissionClaimAttestationRequest),
    /// KI#170 VBC registry AE — the witness directory's anti-entropy
    /// (positions unchanged; FIELDS changed by ForkSettlement wave 4a, R50).
    /// ~~step 1 advertises a digest; on a mismatch the receiver pushes its full
    /// set to `peer_by_id(from)`, set-unioned~~ — an UNAUTHENTICATED `from`
    /// reflected a whole-registry push (≈100 KB per bundle-bearing entry) at
    /// any victim, and the push crossed the 20 MiB wire cap at ≈200 entries
    /// (§9d HIGH-4); the union was unverified (KI#223).
    ///
    /// Now: the REQUEST carries the sender's sorted `have` list and a fresh
    /// per-round `nonce`, SIGNED by `from`'s NBC key over
    /// `crypto::ae_sign_payload(KIND_HAVE, from, nonce,
    /// have_body_hash(have))`. The responder verifies against
    /// `verified_nbcs[from]`, dedupes the nonce, budgets per `from` per window,
    /// and replies — via `peer_by_id(from)` of the AUTHENTICATED `from`, never
    /// `send_reply` (KI#42) — with one PAGE of the records the requester lacks
    /// (per-entry diff, `vbc_directory::page_missing_from`).
    VbcRegistrationDigest { from: NodeId, nonce: u64, have: Vec<[u8; 32]>, sig: Vec<u8> },
    /// The reply page: echoes the request `nonce`, SIGNED by the responder
    /// (`KIND_ENTRIES`, `entries_body_hash`). The requester accepts it only as
    /// the answer to a nonce it issued to that `from`, then verifies EVERY
    /// record off the node lock (`vbc_directory::admit`) before adopting.
    VbcRegistrationEntries { from: NodeId, nonce: u64, entries: Vec<crate::vbc_directory::VbcRegistrationRecord>, sig: Vec<u8> },
    /// KI#59 — out-of-order scar-resolution confirm (appended LAST, bincode positional).
    /// SDK callsite: nabla.rs::resolve_own_scars_out_of_order.
    OooConfirmRequest(crate::wire_client::OooConfirmRequest),
    OooConfirmResponse(crate::wire_client::OooConfirmResponse),
    /// Fork Settlement §9o [R58/R59] — R48 RECORD-AE ASK (appended LAST —
    /// bincode is positional). The RECEIVER of records drives a descent over
    /// the responder's record trie (`record_sync`): `Ask::Nodes(prefixes)` /
    /// `Ask::Legs(keys)`, under a fresh per-ask `nonce`, SIGNED by `from`'s NBC
    /// key over `crypto::ae_sign_payload(RECORD_AE_KIND_ASK, from, nonce,
    /// record_sync::ask_body_hash(ask))`. The responder verifies against
    /// `verified_nbcs[from]`, dedupes the nonce, budgets per `from` per window
    /// and under a global answers-per-window cap, and replies ONLY via
    /// `peer_by_id(from)` of the AUTHENTICATED `from` (never `send_reply` —
    /// KI#42). ⚠ ROLLING RESTART: a node built before this variant cannot
    /// decode it — `TcpTransport::read_one` fails both decoders and
    /// `read_loop` ENDS, closing that inbound connection (every later message
    /// on it is lost until the sender re-dials). Roll every node (and the
    /// arm64 Pi binary) before any node walks record-AE.
    RecordAeAsk { from: NodeId, nonce: u64, ask: crate::record_sync::Ask, sig: Vec<u8> },
    /// The answer to one ask: echoes its `nonce`, SIGNED by the responder
    /// (`RECORD_AE_KIND_ANSWER`, `answer_body_hash`). The asker accepts it only
    /// as the answer to the in-flight ask of its descent with that `from`,
    /// refuses unrequested legs unverified, and verifies every asked leg OFF
    /// the node lock before grading it under the lock. Bounded:
    /// ≤ `RECORD_AE_MAX_PREFIXES_PER_ASK` views, ≤ `RECORD_AE_MAX_LEGS_PER_ANSWER`
    /// legs, ≤ `RECORD_AE_MAX_ANSWER_BYTES`.
    RecordAeAnswer { from: NodeId, nonce: u64, answer: crate::record_sync::Answer, sig: Vec<u8> },
}

/// An addressed wire message — what the transport sends/receives.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The peer this message is from (on receive) or to (on send).
    pub peer: SocketAddr,
    /// The message payload.
    pub message: WireMessage,
    /// Optional reply stream — when set, responses can be sent back on the
    /// same TCP connection that delivered this message. This is critical for
    /// StatusRequest queries from external tools (the caller has no listener).
    pub reply_stream: Option<Arc<std::sync::Mutex<TcpStream>>>,
    /// True if this message was decoded from CBOR (client connection).
    /// Replies must be serialized as CBOR to match the client's codec.
    pub cbor_client: bool,
    /// On-wire byte size of this message (the length-prefixed body).
    /// Used by the inbox byte-budget bound (`INBOX_MAX_BYTES`). Local /
    /// in-process transports that don't read from an untrusted socket set
    /// this to 0 (no byte accounting needed off the network path).
    pub wire_bytes: usize,
}

/// True for the bulk background-reconciliation family — gossip flood,
/// anti-entropy digest/reconcile/entries, ban alerts, and
/// state-sync/bootstrap pulls. These are high-volume and carry no client
/// blocked synchronously on a socket for the reply, so the prioritized
/// inbox drain (`pop_prioritized`) defers them behind mesh-liveness ticks
/// and client-facing requests. Deferred traffic is still drained — a
/// slower AE round only lengthens convergence (a liveness cost the mesh
/// already tolerates across peer rotations), never drops a message.
///
/// The classified set is the DEPRIORITIZED one on purpose: it is small and
/// stable (the AE family has been fixed since v2.15.0-beta3), whereas the
/// client-request surface grows with every new TCP-CBOR op. Classifying
/// "background" means a newly-added `*Request` is prioritized automatically
/// — it is simply "not background". See
/// `docs/AXIOM_DESIGN_NablaAntiEntropy.md` §8.1.
fn is_background_traffic(msg: &WireMessage) -> bool {
    matches!(
        msg,
        WireMessage::Gossip(_)
            | WireMessage::Alert(_)
            | WireMessage::AuditRequest(_)
            | WireMessage::AuditResponse(_)
            | WireMessage::AeDigest { .. }
            | WireMessage::AeReconcile { .. }
            | WireMessage::AeEntries { .. }
            | WireMessage::RangeSyncRequest { .. }
            | WireMessage::RangeSyncResponse { .. }
            | WireMessage::StatePullRequest { .. }
            | WireMessage::StatePullResponse { .. }
            | WireMessage::TxidAeDigest { .. }
            | WireMessage::TxidAeEntries { .. }
            | WireMessage::FobLedgerDigest { .. }
            | WireMessage::FobLedgerEntries { .. }
            | WireMessage::VbcRegistrationDigest { .. }
            | WireMessage::VbcRegistrationEntries { .. }
            | WireMessage::RecordAeAsk { .. }
            | WireMessage::RecordAeAnswer { .. }
    )
}

/// Prioritized pop for the mesh inbox: remove the first FOREGROUND envelope
/// (mesh liveness — `Tick`/`Approval`/`Tardis*` — plus every client-facing
/// request/response and mesh-management message) ahead of any backlog of
/// `is_background_traffic` gossip/AE. If the inbox is all background, fall
/// back to FIFO front so nothing is stranded. FIFO order is preserved
/// WITHIN each tier.
///
/// The scan is `O(n)` worst case (inbox all-background with one foreground
/// message at the back); in practice the branch-A proof-gate (§5.2.2)
/// removed the AE wedge that produced sustained floods, so the inbox is
/// normally shallow and this is `O(1)`. If profiling ever shows the scan
/// hot, the drop-in upgrade is a two-`VecDeque` split partitioned at push
/// time — same classifier, `O(1)` pop. Not built now (no evidence it is
/// needed). §14-safe: scheduling only, no verification change — every
/// message is still verified identically when drained.
/// See `docs/AXIOM_DESIGN_NablaAntiEntropy.md` §8.1.
fn pop_prioritized(inbox: &mut Vec<Envelope>) -> Option<Envelope> {
    if inbox.is_empty() {
        return None;
    }
    match inbox
        .iter()
        .position(|e| !is_background_traffic(&e.message))
    {
        Some(i) => Some(inbox.remove(i)),
        None => Some(inbox.remove(0)),
    }
}

// ── Transport Trait ────────────────────────────────────────────────

/// Transport abstraction for nabla-node.
///
/// Implementations handle the raw I/O. Protocol logic never touches
/// sockets or stdin — it only sees WireMessage values.
pub trait Transport: Send + Sync {
    /// Send a message to a specific peer address.
    fn send(&self, addr: SocketAddr, msg: &WireMessage) -> io::Result<()>;

    /// Receive the next incoming message (blocking).
    /// Returns the sender address and message.
    fn recv(&self) -> io::Result<Envelope>;

    /// Non-blocking receive. Returns `None` if no message is available.
    /// Default implementation returns None (transports that don't support
    /// non-blocking reads can use the blocking recv in a separate thread).
    fn try_recv(&self) -> Option<Envelope> { None }

    /// Our local listen address.
    fn local_addr(&self) -> SocketAddr;

    /// Remove dead connections from the connection pool.
    /// Default: no-op. TcpTransport iterates cached connections
    /// and removes ones that are no longer alive.
    fn sweep_dead_connections(&self) {}

    /// Number of cached outbound connections.
    fn connection_count(&self) -> usize { 0 }
}

/// Write a reply message on an envelope's reply_stream (same TCP connection).
/// Returns Ok(()) on success, or Err if no reply stream or write fails.
/// This is used for StatusRequest responses and Register/Query replies:
/// the caller (PMC or external tool) may not have a listener,
/// so we must reply on the same connection that delivered the request.
/// If the envelope was decoded from CBOR (cbor_client=true), the reply
/// is serialized as CBOR; otherwise bincode.
pub fn send_reply(envelope: &Envelope, msg: &WireMessage) -> io::Result<()> {
    let stream_lock = envelope.reply_stream.as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no reply stream"))?;
    let data = if envelope.cbor_client {
        let mut buf = Vec::new();
        ciborium::into_writer(msg, &mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        buf
    } else {
        bincode::serialize(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
    };
    let len_buf = (data.len() as u32).to_be_bytes();
    let mut stream = stream_lock.lock().unwrap();
    let written = stream
        .write_all(&len_buf)
        .and_then(|()| stream.write_all(&data))
        .and_then(|()| stream.flush());
    if let Err(e) = written {
        // KI#92 (2026-10-01): a failed reply write SHUTS the connection. The
        // stream may hold a partial frame (the peer can never resync), and a
        // peer that does not drain would otherwise cost EVERY later reply on
        // this connection another full TCP_WRITE_TIMEOUT stall. After the
        // shutdown the next write fails at once, and the reader thread sees EOF
        // and drops the connection. The caller must NOT re-queue the reply on
        // this same socket (the pre-KI#92 fallback did — a second stall and a
        // possible duplicate frame); `dispatch_outbound` does not.
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(e);
    }
    Ok(())
}

/// KI#92 — is this cached outbound connection alive? A per-connection mutex
/// that is HELD means a send is writing on it right now: it is in use, hence
/// alive — never block on it (a stalled send holds it up to TCP_WRITE_TIMEOUT,
/// and the callers hold the connection-map lock, `sweep_dead_connections` even
/// the node lock). Otherwise `try_clone` detects a fully-closed socket. A
/// poisoned mutex is treated as dead (evicting it is always safe).
fn cached_conn_alive(conn: &Mutex<TcpStream>) -> bool {
    match conn.try_lock() {
        Ok(stream) => stream.try_clone().is_ok(),
        Err(std::sync::TryLockError::WouldBlock) => true,
        Err(std::sync::TryLockError::Poisoned(_)) => false,
    }
}

// ── TCP Transport ──────────────────────────────────────────────────

/// Apply TCP keepalive settings to a stream.
/// 30s idle before probes, 10s between probes.
fn set_tcp_keepalive(stream: &TcpStream) {
    use socket2::SockRef;
    let sock = SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    let _ = sock.set_tcp_keepalive(&keepalive);
}

/// Production transport: TCP with length-prefixed bincode frames.
/// Binds to [::]:port by default (dual-stack IPv4+IPv6).
pub struct TcpTransport {
    listener_addr: SocketAddr,
    /// Inbox: messages received from peers, waiting to be consumed.
    inbox: Arc<Mutex<Vec<Envelope>>>,
    /// Outbound connection cache: reuse TCP streams to known peers.
    // Each cached TcpStream is wrapped in its own Mutex so concurrent
    // sends to the same peer serialize at the per-connection level
    // rather than racing at the OS socket level. Two writers that
    // share a TcpStream (or two clones of the same fd) can interleave
    // each other's `[len][body]` framing, which the reader decodes
    // as a corrupt body with an embedded length prefix at offset 0.
    // The bug surfaces as `[nabla TCP read_one] decode failed (N bytes).
    // bincode: Custom("invalid value: integer ...)` log spam — see
    // commit history for the 2026-05-30 v6 soak diagnosis.
    connections: Arc<Mutex<HashMap<SocketAddr, Arc<Mutex<TcpStream>>>>>,
    /// Signal for inbox availability.
    inbox_notify: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    /// Per-peer circuit-breaker state (KI#96 follow-up). A peer that keeps
    /// failing sends goes "cold" and is skipped until its backoff expires,
    /// so one dead/slow/incompatible peer can't starve the node by making it
    /// re-attempt a doomed 10s send every AE cycle. See PEER_CB_* consts.
    peer_health: Arc<Mutex<HashMap<SocketAddr, PeerHealth>>>,
}

/// Circuit-breaker health for a single peer (local network hygiene only).
#[derive(Default)]
struct PeerHealth {
    /// Consecutive failed `send` attempts since the last success.
    consecutive_failures: u32,
    /// If `Some`, outbound sends to this peer are skipped until this instant.
    cold_until: Option<std::time::Instant>,
}

impl TcpTransport {
    /// Create and start a TCP transport.
    /// Binds to the given address (e.g. "[::]:1211" for dual-stack).
    pub fn bind(addr: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let listener_addr = listener.local_addr()?;

        let inbox: Arc<Mutex<Vec<Envelope>>> = Arc::new(Mutex::new(Vec::new()));
        let connections: Arc<Mutex<HashMap<SocketAddr, Arc<Mutex<TcpStream>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let inbox_notify = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));

        // Accept loop in background thread
        let inbox_clone = inbox.clone();
        let notify_clone = inbox_notify.clone();
        thread::Builder::new()
            .name("tcp-accept".into())
            .spawn(move || {
                Self::accept_loop(listener, inbox_clone, notify_clone);
            })?;

        Ok(Self {
            listener_addr,
            inbox,
            connections,
            inbox_notify,
            peer_health: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Circuit-breaker: is this peer currently "cold" (in send-backoff)?
    /// Returns true only while the backoff window is unexpired; an expired
    /// window is cleared here so the next `send` is allowed one probe.
    fn peer_is_cold(&self, addr: SocketAddr) -> bool {
        let mut health = self.peer_health.lock().unwrap();
        if let Some(h) = health.get_mut(&addr) {
            if let Some(until) = h.cold_until {
                if std::time::Instant::now() < until {
                    return true;
                }
                // Backoff expired — allow a probe. Keep consecutive_failures so
                // a still-dead peer re-cools immediately (record_send_result
                // recomputes the window from the running failure count).
                h.cold_until = None;
            }
        }
        false
    }

    /// Circuit-breaker: fold one send outcome into the peer's health. On
    /// success, reset. On failure, (re)arm an exponentially-backed-off cold
    /// window — immediately if the failure was a write TIMEOUT (`timed_out`, a
    /// peer that accepted but didn't drain in TCP_WRITE_TIMEOUT), otherwise once
    /// PEER_CB_FAILURE_THRESHOLD consecutive fast failures accrue.
    fn record_send_result(&self, addr: SocketAddr, ok: bool, timed_out: bool) {
        let mut health = self.peer_health.lock().unwrap();
        let h = health.entry(addr).or_default();
        if ok {
            if h.cold_until.is_some() || h.consecutive_failures >= PEER_CB_FAILURE_THRESHOLD {
                info!("[peer-cb] {} recovered — clearing circuit-breaker", addr);
            }
            h.consecutive_failures = 0;
            h.cold_until = None;
        } else {
            h.consecutive_failures = h.consecutive_failures.saturating_add(1);
            // Trip on a timeout at once (10s wasted = definitively bad), or once
            // enough consecutive fast failures (connection refused etc.) accrue.
            if timed_out || h.consecutive_failures >= PEER_CB_FAILURE_THRESHOLD {
                let over = h.consecutive_failures.saturating_sub(PEER_CB_FAILURE_THRESHOLD);
                let mult: u32 = 1u32.checked_shl(over.min(4)).unwrap_or(16);
                let backoff = PEER_CB_BACKOFF_BASE
                    .saturating_mul(mult)
                    .min(PEER_CB_BACKOFF_MAX);
                let was_cold = h.cold_until.is_some();
                h.cold_until = Some(std::time::Instant::now() + backoff);
                if !was_cold {
                    warn!("[peer-cb] {} cold ({}) — skipping outbound AE/gossip for {:?}",
                          addr,
                          if timed_out { "write timeout" } else { "consecutive failures" },
                          backoff);
                }
            }
        }
    }

    /// One send attempt (cache hit, then zombie-recovery retry). The trait
    /// `send` wraps this with the circuit-breaker (peer_is_cold +
    /// record_send_result); this method carries the original transport logic.
    fn send_attempt(&self, addr: SocketAddr, msg: &WireMessage) -> io::Result<()> {
        // Try cached connection first. The per-connection Mutex makes
        // concurrent sends to the same peer serialize — without it,
        // two writers' `[len][body]` framing interleaves at the socket
        // level and the receiver sees a malformed body with an
        // embedded length prefix at offset 0 (decoded as the bincode
        // variant index, yielding the "invalid value: integer ..."
        // error we chased for hours during the 2026-05-30 v6 soak).
        let first = {
            let stream_arc = self.get_connection(addr)?;
            let mut stream = stream_arc.lock().unwrap();
            Self::write_one(&mut stream, msg)
        };
        if first.is_ok() {
            return Ok(());
        }

        // ── Zombie-connection recovery (2026-04-15 fix) ─────────────────
        // get_connection() caches TCP streams and uses try_clone() as its
        // "is the connection alive" probe. try_clone() only dups the file
        // descriptor — it does NOT probe the actual TCP state. A half-
        // closed connection (peer FIN'd, we have CLOSE_WAIT) passes
        // try_clone() but the next write_all/flush fails with EPIPE/ECONN.
        //
        // Without this retry, the cached zombie persists forever: every
        // subsequent send to this peer reuses the same dead fd and fails
        // the same way, silently (gossip is non-critical, so callers log
        // at debug level and move on). Result: deterministic gossip
        // partitions where node A can reach some peers and never the
        // others, with no error visible at normal log levels.
        //
        // Symptom that triggered this fix: 1h+ soak with 50 wallets,
        // wallet 022's HTTP /register at nabla-2 propagated to only
        // 4 of 10 Nabla nodes (the 4 with live TCP connections); the
        // other 6 had zombie cached streams and never received the
        // gossip message. §4.6 receiver-side checks chronically
        // deferred for redeems involving wallet 022 because Nabla
        // nodes returned different states based on whether they'd
        // received the gossip update.
        //
        // Fix: on first-send failure, evict the cached connection and
        // open a fresh TCP socket for one retry. If the retry also
        // fails, the peer is truly unreachable and the error
        // propagates as before.
        self.connections.lock().unwrap().remove(&addr);
        let stream_arc = self.get_connection(addr)?;
        let mut stream = stream_arc.lock().unwrap();
        Self::write_one(&mut stream, msg)
    }

    /// Background: accept incoming TCP connections and read messages.
    fn accept_loop(
        listener: TcpListener,
        inbox: Arc<Mutex<Vec<Envelope>>>,
        notify: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    ) {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peer_addr = match stream.peer_addr() {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    set_tcp_keepalive(&stream);
                    // ROBUSTNESS (2026-08-17): bound the INBOUND stream's write
                    // side, mirroring set_read_timeout in read_loop. Outbound
                    // streams (get_connection) already carry TCP_WRITE_TIMEOUT;
                    // the accepted stream did NOT, so `send_reply` on its cloned
                    // write half blocked FOREVER when a peer stopped draining
                    // (full recv window). That wedged a StatePull/AE responder
                    // with ~2.5MB stuck in its send-Q while holding the node
                    // mutex — a mesh-wide deadlock that starved client txid
                    // registration (os error 11). SO_SNDTIMEO is a socket-level
                    // option shared across try_clone'd fds, so setting it here —
                    // before read_loop clones the write half — covers send_reply.
                    // A stuck send now fails after TCP_WRITE_TIMEOUT; the caller
                    // drops the peer and the node stays live: it ABANDONS a peer
                    // it cannot make progress with instead of deadlocking on it.
                    let _ = stream.set_write_timeout(Some(TCP_WRITE_TIMEOUT));
                    let inbox = inbox.clone();
                    let notify = notify.clone();
                    thread::Builder::new()
                        .name(format!("tcp-read-{}", peer_addr))
                        .spawn(move || {
                            Self::read_loop(stream, peer_addr, inbox, notify);
                        })
                        .ok();
                }
                Err(e) => {
                    eprintln!("∇ TCP accept error: {}", e);
                }
            }
        }
    }

    /// Read length-prefixed bincode messages from a single TCP stream.
    fn read_loop(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        inbox: Arc<Mutex<Vec<Envelope>>>,
        notify: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    ) {
        // Clone the stream for writing replies. The read side (stream) is used
        // exclusively by this thread. The write side (write_stream) is shared
        // via reply_stream so StatusRequest responses go back on the same TCP
        // connection — no deadlock between read and write.
        let write_stream = stream.try_clone().ok().map(|s| {
            Arc::new(std::sync::Mutex::new(s)) as Arc<std::sync::Mutex<TcpStream>>
        });
        let _ = stream.set_read_timeout(Some(TCP_READ_TIMEOUT));
        while let Ok((msg, is_cbor, wire_bytes)) = Self::read_one(&mut stream) {
            let envelope = Envelope {
                peer: peer_addr,
                message: msg,
                reply_stream: write_stream.clone(),
                cbor_client: is_cbor,
                wire_bytes,
            };
            // SECURITY FIX #12: cap the inbox to prevent OOM under sustained
            // load. Bound BOTH the message COUNT (INBOX_MAX_DEPTH) and the
            // total queued BYTES (INBOX_MAX_BYTES). The byte bound is the
            // real governor — the count cap alone allowed a ~10 GiB inbox
            // (10k × ≤1 MiB) and OOM-killed a writer Nabla under a 50w
            // registration flood. Shed this message if either bound would be
            // exceeded; the dropped client retries (registration is
            // idempotent) and the closed socket is the back-pressure signal.
            // No logging here — avoids a log flood under attack/overload.
            let mut inbox_guard = inbox.lock().unwrap();
            let queued_bytes: usize = inbox_guard.iter().map(|e| e.wire_bytes).sum();
            if !inbox_admits(inbox_guard.len(), queued_bytes, wire_bytes) {
                drop(inbox_guard);
                continue;
            }
            inbox_guard.push(envelope);
            drop(inbox_guard);
            // Notify recv() that data is available
            let (lock, cvar) = &*notify;
            let mut ready = lock.lock().unwrap();
            *ready = true;
            cvar.notify_one();
            drop(ready);

            // YPX-002 §3, §4: client connections are one-shot. Wallets
            // contact Nabla in discrete bursts (register-after-TX,
            // §4 verify query, /query-txid, etc.) and must not hold
            // long-lived sockets — the mesh is sized for "dozens of
            // nodes, millions of clients", which only works if clients
            // disconnect immediately after their single exchange.
            //
            // is_cbor tells us this connection is a client (clients
            // speak CBOR; node-to-node gossip speaks bincode). Break
            // out of read_loop so we stop waiting for further messages.
            // The cloned write_stream Arc still holds the socket open
            // until the processor calls send_reply() with the response;
            // when that envelope drops, the last Arc ref dies and the
            // socket closes cleanly on both sides.
            //
            // For node-to-node connections (is_cbor == false), the loop
            // continues — gossip is persistent.
            if is_cbor {
                break;
            }
        }
    }

    /// Read one length-prefixed message from a stream.
    /// Returns (message, is_cbor, wire_bytes) where is_cbor=true if the
    /// payload was CBOR (client connection) rather than bincode
    /// (node-to-node), and wire_bytes is the body length (for the inbox
    /// byte-budget bound).
    fn read_one(stream: &mut TcpStream) -> io::Result<(WireMessage, bool, usize)> {
        // Read 4-byte big-endian length
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > WIRE_MAX_MSG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("message too large: {} bytes (max {})", len, WIRE_MAX_MSG_BYTES),
            ));
        }

        // Read message body
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;

        // Try bincode first (node-to-node), then CBOR (client)
        let bincode_err = match bincode::deserialize::<WireMessage>(&buf) {
            Ok(msg) => return Ok((msg, false, len)),
            Err(e) => e,
        };
        match ciborium::from_reader::<WireMessage, _>(&buf[..]) {
            Ok(msg) => Ok((msg, true, len)),
            Err(cbor_err) => {
                // Both decoders failed. Surface what we received so the
                // caller (TCP read loop, soak diagnostic) can pin down
                // the wire-format mismatch instead of seeing "connection
                // closed". First 64 bytes of the body in hex are usually
                // enough to identify the encoding (CBOR Map starts with
                // 0xa0..0xbf, Bincode enum starts with the variant
                // discriminant as u32 LE).
                let hex_prefix = hex::encode(&buf[..buf.len().min(64)]);
                eprintln!(
                    "[nabla TCP read_one] decode failed ({} bytes). \
                     bincode: {:?} | cbor: {:?} | first-{}-hex: {}",
                    buf.len(), bincode_err, cbor_err,
                    buf.len().min(64), hex_prefix,
                );
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("deserialize (tried bincode + CBOR): {}", cbor_err),
                ))
            }
        }
    }

    /// Write one length-prefixed message to a stream.
    fn write_one(stream: &mut TcpStream, msg: &WireMessage) -> io::Result<()> {
        let data = bincode::serialize(msg).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("serialize: {}", e))
        })?;

        if data.len() > WIRE_MAX_MSG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large to send",
            ));
        }

        let len_buf = (data.len() as u32).to_be_bytes();
        stream.write_all(&len_buf)?;
        stream.write_all(&data)?;
        stream.flush()
    }

    /// Get or create a TCP connection to a peer.
    ///
    /// Returns an `Arc<Mutex<TcpStream>>` rather than a bare
    /// `TcpStream`. Callers lock the inner mutex around their
    /// `write_one` invocation so concurrent sends to the same peer
    /// serialize. Two concurrent senders sharing the same OS socket
    /// without this lock can interleave their `[len][body]` framing,
    /// producing readers' `[nabla TCP read_one] decode failed (N bytes)`
    /// errors (with the second sender's `len_buf` appearing at offset 0
    /// of the first sender's `body`). See the 2026-05-30 v6 soak
    /// diagnosis.
    fn get_connection(&self, addr: SocketAddr) -> io::Result<Arc<Mutex<TcpStream>>> {
        // PORT 0 IS NEVER A DESTINATION. It means "let the OS pick" when BINDING,
        // so a peer entry carrying :0 is malformed — an address that was never
        // filled in. Dialing it can only fail, but the retry/circuit-breaker
        // machinery treats it like any unreachable peer: 3 attempts, backoff,
        // probe-to-recover, forever. Observed 2026-08-21: 77 dial attempts to
        // 127.0.0.1:0 across the fleet, pure noise that buries real peer failures.
        //
        // Refuse it here, at the one place every dial passes through, rather than
        // hunting every producer of a peer address.
        if addr.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("refusing to dial {addr}: port 0 is not a destination — \
                         this peer entry is malformed"),
            ));
        }

        // Check cache first
        {
            let mut conns = self.connections.lock().unwrap();
            if let Some(existing) = conns.get(&addr) {
                // Liveness probe: try_clone() on the inner stream
                // detects a fully-closed socket. Half-closed sockets
                // (peer FIN'd) pass this probe — they're caught by
                // the zombie-recovery path in `send`. KI#92: never BLOCK on
                // the per-connection mutex while holding the map lock.
                if cached_conn_alive(existing) {
                    return Ok(Arc::clone(existing));
                }
                // Dead connection — remove from cache
                conns.remove(&addr);
            }
        }

        // Open new connection
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        let _ = stream.set_write_timeout(Some(TCP_WRITE_TIMEOUT));
        let _ = stream.set_nodelay(true);
        set_tcp_keepalive(&stream);

        let wrapped = Arc::new(Mutex::new(stream));
        self.connections.lock().unwrap().insert(addr, Arc::clone(&wrapped));
        Ok(wrapped)
    }
}

impl Transport for TcpTransport {
    fn send(&self, addr: SocketAddr, msg: &WireMessage) -> io::Result<()> {
        // Circuit-breaker (KI#96 follow-up): a peer we've recognised as dead is
        // skipped for its backoff window — no connect, no write, no 10s stall
        // holding the node mutex. Callers (gossip/AE) treat send errors as
        // non-critical and move on, so a cold peer simply misses this round;
        // it is probed again once the window expires (peer_is_cold clears it).
        if self.peer_is_cold(addr) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "peer in circuit-breaker backoff (cold)",
            ));
        }
        let result = self.send_attempt(addr, msg);
        // A write TIMEOUT (peer accepted the connection but didn't drain within
        // TCP_WRITE_TIMEOUT) is definitive evidence of a dead/wedged/incompatible
        // peer — it wasted the whole 10s window holding the node mutex. Treat it
        // as an immediate trip, not "1 of 3", because a peer that alternates
        // small drained sends with large stalled ones never reaches 3
        // CONSECUTIVE failures and would stall us 10s forever.
        let timed_out = result.as_ref().err().is_some_and(|e| {
            matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
        });
        self.record_send_result(addr, result.is_ok(), timed_out);
        result
    }

    fn recv(&self) -> io::Result<Envelope> {
        loop {
            // Try to pop from inbox — client-facing requests + mesh liveness
            // jump ahead of any gossip/AE backlog (§8.1 prioritized drain).
            {
                let mut inbox = self.inbox.lock().unwrap();
                if let Some(env) = pop_prioritized(&mut inbox) {
                    return Ok(env);
                }
            }
            // Wait for notification
            let (lock, cvar) = &*self.inbox_notify;
            let mut ready = lock.lock().unwrap();
            while !*ready {
                ready = cvar.wait(ready).unwrap();
            }
            *ready = false;
        }
    }

    fn try_recv(&self) -> Option<Envelope> {
        let mut inbox = self.inbox.lock().unwrap();
        pop_prioritized(&mut inbox)
    }

    fn local_addr(&self) -> SocketAddr {
        self.listener_addr
    }

    fn sweep_dead_connections(&self) {
        let mut conns = self.connections.lock().unwrap();
        // KI#92: called UNDER the node lock (tick loop Step 8) — a blocking
        // per-connection lock here pinned the node mutex for as long as any
        // send was stalled (up to TCP_WRITE_TIMEOUT). In use = alive.
        conns.retain(|_addr, stream_arc| cached_conn_alive(stream_arc));
    }

    fn connection_count(&self) -> usize {
        self.connections.lock().unwrap().len()
    }
}

// ── Stdio Addressed Envelope ───────────────────────────────────────

/// JSON envelope used by StdioTransport. Includes destination address
/// so that an external process (e.g. binary sim) can route messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdioEnvelope {
    /// Destination address as "ip:port" string.
    pub to: String,
    /// Source address as "ip:port" string.
    pub from: String,
    /// The message payload.
    pub msg: WireMessage,
}

// ── Stdio Transport ────────────────────────────────────────────────

/// Development/testing transport: line-delimited JSON on stdin/stdout.
/// Each line is one JSON-encoded StdioEnvelope (addressed).
pub struct StdioTransport {
    /// Inbox from stdin reader thread.
    inbox: Arc<Mutex<Vec<Envelope>>>,
    /// Outbox writes to stdout.
    stdout: Arc<Mutex<io::Stdout>>,
    /// Our local address (assigned by caller or default).
    local: SocketAddr,
    /// Signal for inbox availability.
    inbox_notify: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl StdioTransport {
    /// Create a stdio transport. Spawns a background reader on stdin.
    pub fn new() -> io::Result<Self> {
        Self::with_addr("127.0.0.1:0".parse().unwrap())
    }

    /// Create a stdio transport with a specific local address.
    /// Used by binary sim mode to assign virtual addresses to nodes.
    pub fn with_addr(local: SocketAddr) -> io::Result<Self> {
        let inbox: Arc<Mutex<Vec<Envelope>>> = Arc::new(Mutex::new(Vec::new()));
        let inbox_notify = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));

        let inbox_clone = inbox.clone();
        let notify_clone = inbox_notify.clone();
        thread::Builder::new()
            .name("stdio-read".into())
            .spawn(move || {
                Self::stdin_reader(inbox_clone, notify_clone);
            })?;

        Ok(Self {
            inbox,
            stdout: Arc::new(Mutex::new(io::stdout())),
            local,
            inbox_notify,
        })
    }

    /// Read lines from stdin, parse as JSON StdioEnvelopes.
    fn stdin_reader(
        inbox: Arc<Mutex<Vec<Envelope>>>,
        notify: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    ) {
        let stdin = io::stdin();
        let reader = BufReader::new(stdin.lock());

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break, // stdin closed
            };
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }

            // Try StdioEnvelope first (addressed), fall back to bare WireMessage
            let envelope = if let Ok(env) = serde_json::from_str::<StdioEnvelope>(&line) {
                let peer: SocketAddr = env.from.parse()
                    .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap());
                Envelope { peer, message: env.msg, reply_stream: None, cbor_client: false, wire_bytes: 0 }
            } else if let Ok(msg) = serde_json::from_str::<WireMessage>(&line) {
                Envelope { peer: "127.0.0.1:0".parse().unwrap(), message: msg, reply_stream: None, cbor_client: false, wire_bytes: 0 }
            } else {
                eprintln!("∇ stdio: invalid JSON: {}", line);
                continue;
            };

            inbox.lock().unwrap().push(envelope);
            let (lock, cvar) = &*notify;
            let mut ready = lock.lock().unwrap();
            *ready = true;
            cvar.notify_one();
        }
    }
}

impl Transport for StdioTransport {
    fn send(&self, addr: SocketAddr, msg: &WireMessage) -> io::Result<()> {
        let env = StdioEnvelope {
            to: addr.to_string(),
            from: self.local.to_string(),
            msg: msg.clone(),
        };
        let json = serde_json::to_string(&env).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("serialize: {}", e))
        })?;
        let mut out = self.stdout.lock().unwrap();
        writeln!(out, "{}", json)?;
        out.flush()
    }

    fn recv(&self) -> io::Result<Envelope> {
        loop {
            {
                // §8.1 prioritized drain — foreground (liveness + client
                // requests) ahead of any gossip/AE backlog.
                let mut inbox = self.inbox.lock().unwrap();
                if let Some(env) = pop_prioritized(&mut inbox) {
                    return Ok(env);
                }
            }
            let (lock, cvar) = &*self.inbox_notify;
            let mut ready = lock.lock().unwrap();
            while !*ready {
                ready = cvar.wait(ready).unwrap();
            }
            *ready = false;
        }
    }

    fn try_recv(&self) -> Option<Envelope> {
        let mut inbox = self.inbox.lock().unwrap();
        pop_prioritized(&mut inbox)
    }

    fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// Convert a NablaAddress to a std::net::SocketAddr, resolving a `Name` HERE —
/// at dial time, locally, by whoever is dialling.
///
/// This is the ONLY place a peer's address is resolved. A `Name` hint is
/// relayed verbatim everywhere else (see `NablaAddress`), so each node resolves
/// the same name in its own context: on this box `axiom-dev.mooo.com` is the LAN
/// address, from an external node it is the public one, and both are correct
/// where they are used. Resolving anywhere else would bake one node's view of
/// the network into a hint and force it on every node downstream.
///
/// A name that does not resolve is a LOCAL, usually transient condition (DNS
/// down). It says nothing about the peer, so it must not change what we store
/// or relay — the hint stays verbatim and we simply fail to send this round,
/// exactly as an unreachable IP already does. The unresolvable case returns
/// `UNRESOLVED_ADDR`, which cannot connect, so it fails through the SAME
/// "Send failed" path as any other dead peer, and it is logged so a genuine
/// misconfiguration is visible rather than silent.
///
/// Signature stays infallible on purpose: making it `Option` forced a change at
/// 99 call sites for a condition every one of them already handles as "the send
/// failed". Keep the gears simple.
///
/// ⚠ NEVER RESOLVE A NAME ON THIS PATH. This function is called from inside
/// `handle_message`, which runs with the GLOBAL node mutex held, dozens of times
/// per message to build the gossip fan-out. A blocking `to_socket_addrs()` here
/// holds that mutex for the full resolver timeout (seconds, per peer, un-capped),
/// which starves the TARDIS tick loop, overflows the dashboard accept queue and
/// leaves handlers not reading their sockets — i.e. it wedges the whole node.
/// Observed 2026-08-18: three of ten nodes dead this way within ~90 min of soak,
/// with hundreds of KB unread on their protocol sockets, while every neighbouring
/// design comment ("Send responses (outside lock)", "capping the per-tick drain
/// bounds the lock-hold") existed precisely to keep that path short.
///
/// So resolution is a pure cache READ here and the resolver runs on
/// `spawn_resolver` background thread. A miss is the already-handled
/// "did not resolve" case: skip this send, relay the hint unchanged, and the
/// refresher fills the cache within one cycle.
pub fn to_socket_addr(addr: &NablaAddress) -> SocketAddr {
    match addr {
        NablaAddress::V4 { ip, port } => {
            SocketAddr::from((std::net::Ipv4Addr::from(*ip), *port))
        }
        NablaAddress::V6 { ip, port } => {
            SocketAddr::from((std::net::Ipv6Addr::from(*ip), *port))
        }
        NablaAddress::Name { host, port } => {
            let _ = port;
            match resolver_cache().lookup(host, *port) {
                Some(sa) => sa,
                None => UNRESOLVED_ADDR,
            }
        }
    }
}

/// The address returned for a name we cannot resolve. It must be IMPOSSIBLE to
/// connect to, so an unresolved peer fails fast down the ordinary "send failed"
/// path instead of reaching something real.
///
/// ⚠ It used to be `0.0.0.0:<peer port>`, on the stated assumption that the
/// connect "fails immediately". **On Linux it does not** — connecting to
/// 0.0.0.0 connects to LOCALHOST, so a message addressed to an unresolved peer
/// was delivered to whichever local process held that port. In this dev env the
/// ports are one-per-node on a single box, so an unresolved hint could reach
/// the WRONG NODE, or the sending node itself, and read as a legitimate peer
/// message. Verified 2026-08-18: `connect(("0.0.0.0", 7301))` returns
/// `127.0.0.1:7301`, a live node.
///
/// Port 0 is not a connectable destination, so this refuses instantly.
const UNRESOLVED_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

/// How often the background thread re-resolves every name it knows.
///
/// Also the freshness bound for KI#64: a peer whose name starts pointing
/// somewhere else is picked up within one cycle, without any caller blocking.
const RESOLVER_REFRESH: Duration = Duration::from_secs(15);

/// Non-blocking name→address cache.
///
/// `lookup` only ever touches memory. Names asked for are remembered so the
/// background thread keeps resolving them; entries are never evicted (the set of
/// peer names a node sees is small and bounded by the mesh).
pub struct ResolverCache {
    inner: Mutex<ResolverInner>,
    /// Signalled when a name is seen for the first time, so a peer we just
    /// learned about resolves within milliseconds instead of up to a full
    /// `RESOLVER_REFRESH` cycle.
    wake: std::sync::Condvar,
}

#[derive(Default)]
struct ResolverInner {
    /// Last successful resolution per (host, port).
    resolved: HashMap<(String, u16), SocketAddr>,
    /// Every name we have been asked for — the refresher's work list.
    wanted: Vec<(String, u16)>,
}

impl ResolverCache {
    /// Cache read. NEVER resolves — see the warning on `to_socket_addr`.
    ///
    /// A miss registers the name for the background thread and returns `None`.
    fn lookup(&self, host: &str, port: u16) -> Option<SocketAddr> {
        let mut inner = self.inner.lock().unwrap();
        let key = (host.to_string(), port);
        if let Some(sa) = inner.resolved.get(&key) {
            return Some(*sa);
        }
        if !inner.wanted.contains(&key) {
            inner.wanted.push(key);
            log::warn!(
                "[ADDR-UNRESOLVED] {host}:{port} not yet resolved here — skipping \
                 this send; the peer's hint is unchanged, resolving in background"
            );
            self.wake.notify_one();
        }
        None
    }

    /// Resolve every wanted name once. Runs ONLY on the background thread, so
    /// blocking here costs nothing that any lock is waiting on.
    fn refresh_once(&self) {
        use std::net::ToSocketAddrs;
        let wanted = { self.inner.lock().unwrap().wanted.clone() };
        for (host, port) in wanted {
            let got = (host.as_str(), port)
                .to_socket_addrs()
                .ok()
                .and_then(|mut i| i.next());
            if let Some(sa) = got {
                let mut inner = self.inner.lock().unwrap();
                let prev = inner.resolved.insert((host.clone(), port), sa);
                if prev.is_some() && prev != Some(sa) {
                    log::info!(
                        "[ADDR-CHANGED] {host}:{port} now resolves to {sa} (was {:?})",
                        prev.unwrap()
                    );
                }
            }
            // A failed resolution KEEPS the previous value: a transient DNS
            // outage must not tear down peers that are still reachable.
        }
    }
}

/// Process-wide resolver cache, with its refresher started on first use.
fn resolver_cache() -> &'static ResolverCache {
    static CACHE: std::sync::OnceLock<Arc<ResolverCache>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let cache = Arc::new(ResolverCache {
            inner: Mutex::new(ResolverInner::default()),
            wake: std::sync::Condvar::new(),
        });
        let bg = Arc::clone(&cache);
        thread::Builder::new()
            .name("addr-resolver".to_string())
            .spawn(move || loop {
                bg.refresh_once();
                // Wake early when a brand-new name shows up; otherwise re-resolve
                // everything once a cycle so an address change is picked up.
                let guard = bg.inner.lock().unwrap();
                let _ = bg.wake.wait_timeout(guard, RESOLVER_REFRESH);
            })
            .expect("spawn addr-resolver thread");
        cache
    })
}

/// Resolve `host:port` synchronously, for STARTUP paths only.
///
/// The node's own advertised address must be known before it can serve, and
/// nothing holds the node mutex at that point. Everything on the message path
/// must use `to_socket_addr` instead.
pub fn resolve_blocking(host: &str, port: u16) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    let got = (host, port).to_socket_addrs().ok().and_then(|mut i| i.next());
    if let Some(sa) = got {
        let cache = resolver_cache();
        let mut inner = cache.inner.lock().unwrap();
        inner.resolved.insert((host.to_string(), port), sa);
        let key = (host.to_string(), port);
        if !inner.wanted.contains(&key) {
            inner.wanted.push(key);
        }
    }
    got
}

/// Convert a std::net::SocketAddr to a NablaAddress.
pub fn from_socket_addr(addr: SocketAddr) -> NablaAddress {
    match addr {
        SocketAddr::V4(v4) => NablaAddress::V4 {
            ip: v4.ip().octets(),
            port: v4.port(),
        },
        SocketAddr::V6(v6) => NablaAddress::V6 {
            ip: v6.ip().octets(),
            port: v6.port(),
        },
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    /// Port 0 is a BIND-time wildcard, never a destination. A peer entry carrying
    /// it is malformed, and without this guard the retry + circuit-breaker
    /// machinery hammers it forever (77 attempts observed 2026-08-21), burying
    /// real peer failures in noise.
    #[test]
    fn port_zero_is_refused_before_any_dial() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        // Binding to port 0 is LEGITIMATE — the OS picks a free port. That is
        // exactly why :0 leaks into peer tables, and exactly why dialing it must
        // be refused: same literal, opposite meaning on each side.
        let t = TcpTransport::bind("127.0.0.1:0").expect("bind with OS-chosen port");
        let bad = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let err = t.get_connection(bad).expect_err("port 0 must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("port 0"), "error must name the cause: {err}");
    }

    use super::*;

    /// `to_socket_addr` must NEVER resolve a name synchronously.
    ///
    /// It runs inside `handle_message`, which holds the GLOBAL node mutex, so a
    /// blocking resolver call there freezes the whole node for the resolver
    /// timeout — the 2026-08-18 wedge that killed three of ten nodes mid-soak.
    ///
    /// This is asserted with a name that DOES resolve everywhere (`localhost`):
    /// if the first call returns a real address, resolution happened inline and
    /// the regression is back. It must report unresolved and let the background
    /// thread fill the cache.
    #[test]
    fn to_socket_addr_never_resolves_a_name_inline() {
        let addr = NablaAddress::Name { host: "localhost".to_string(), port: 7300 };
        let first = to_socket_addr(&addr);
        assert_eq!(
            first, UNRESOLVED_ADDR,
            "to_socket_addr resolved {addr:?} INLINE (got {first}) — that is a \
             blocking DNS call under the global node mutex; resolution belongs \
             on the background refresher only"
        );

        // And the background refresher must actually fill it in, or the cache
        // read above would be a permanent black hole rather than a deferral.
        let mut resolved = None;
        for _ in 0..100 {
            let sa = to_socket_addr(&addr);
            if sa != UNRESOLVED_ADDR {
                resolved = Some(sa);
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let sa = resolved.expect("background resolver never resolved `localhost`");
        assert_eq!(sa.port(), 7300);
    }

    /// A literal address must resolve with no cache involvement at all.
    #[test]
    fn to_socket_addr_literals_are_direct() {
        let v4 = to_socket_addr(&NablaAddress::V4 { ip: [10, 1, 2, 3], port: 7301 });
        assert_eq!(v4.to_string(), "10.1.2.3:7301");
    }

    // KI#96 follow-up: the peer circuit-breaker must go cold after
    // PEER_CB_FAILURE_THRESHOLD consecutive failures (so a dead peer stops
    // being re-attempted every AE cycle) and clear on the next success.
    #[test]
    fn peer_circuit_breaker_trips_and_recovers() {
        let t = TcpTransport::bind("127.0.0.1:0").expect("bind");
        let peer: SocketAddr = "127.0.0.1:59999".parse().unwrap();

        // Below threshold with fast (non-timeout) failures: not cold yet.
        for _ in 0..(PEER_CB_FAILURE_THRESHOLD - 1) {
            t.record_send_result(peer, false, false);
            assert!(!t.peer_is_cold(peer), "should not be cold below threshold");
        }
        // Crossing the threshold arms the backoff → cold.
        t.record_send_result(peer, false, false);
        assert!(t.peer_is_cold(peer), "peer must go cold at threshold");

        // A success clears it (recovered peer is attempted again immediately).
        t.record_send_result(peer, true, false);
        assert!(!t.peer_is_cold(peer), "success must clear the circuit-breaker");

        // A never-seen peer is never cold.
        let fresh: SocketAddr = "127.0.0.1:58888".parse().unwrap();
        assert!(!t.peer_is_cold(fresh));

        // A single WRITE TIMEOUT cools a peer immediately (no 3-consecutive
        // wait) — a stalling peer that wastes the whole 10s window is bad now.
        let staller: SocketAddr = "127.0.0.1:57777".parse().unwrap();
        t.record_send_result(staller, false, true);
        assert!(t.peer_is_cold(staller), "one write-timeout must cool the peer at once");
    }

    #[test]
    fn wire_message_roundtrip_bincode() {
        let msg = WireMessage::Hello {
            node_id: [0xAA; 32],
            external_port: 6225,
            downstream_count: 1,
            nbc_bytes: vec![1, 2, 3],
            observed_peer_ip: None,
            nbc_supporting_bytes: vec![],
            txid_service: "hashmap".into(),
        };

        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();

        match decoded {
            WireMessage::Hello { node_id, external_port, nbc_bytes, .. } => {
                assert_eq!(node_id, [0xAA; 32]);
                // §5.6a-bis: Hello carries a PORT, never an address.
                assert_eq!(external_port, 6225);
                assert_eq!(nbc_bytes, vec![1, 2, 3]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn wire_message_roundtrip_cbor() {
        let msg = WireMessage::Gossip(GossipMessage::StateUpdate {
                                          old_state: [0u8; 32],
                                          wallet_seq: 0,
            seq_proof: None,
            wallet_id: [0x01; 32],
            new_state: [0x02; 32],
            tx_hash: [0x03; 32],
            tick: 42,
            is_genesis_claim: false,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
            amount: 0,
            fee_breakdown: Vec::new(),
        });

        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).unwrap();
        let decoded: WireMessage = ciborium::from_reader(&buf[..]).unwrap();

        match decoded {
            WireMessage::Gossip(GossipMessage::StateUpdate { tick,
            is_genesis_claim: false, .. }) => {
                assert_eq!(tick, 42);
            }
            _ => panic!("wrong variant"),
        }
    }

    fn env(msg: WireMessage) -> Envelope {
        Envelope {
            peer: "127.0.0.1:0".parse().unwrap(),
            message: msg,
            reply_stream: None,
            cbor_client: false,
            wire_bytes: 0,
        }
    }

    fn gossip_env(tick: u64) -> Envelope {
        env(WireMessage::Gossip(GossipMessage::StateUpdate {
            old_state: [0u8; 32],
            wallet_seq: 0,
            seq_proof: None,
            wallet_id: [0x01; 32],
            new_state: [0x02; 32],
            tx_hash: [0x03; 32],
            tick,
            is_genesis_claim: false,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
            amount: 0,
            fee_breakdown: Vec::new(),
        }))
    }

    #[test]
    fn pop_prioritized_serves_client_request_ahead_of_gossip_flood() {
        // A backlog of gossip with ONE client `Query` at the very back.
        let mut inbox: Vec<Envelope> = (0..20).map(gossip_env).collect();
        inbox.push(env(WireMessage::Query { wallet_id: [0x09; 32] }));

        // First pop must be the client request, not the head-of-line gossip.
        let first = pop_prioritized(&mut inbox).expect("non-empty");
        assert!(
            matches!(first.message, WireMessage::Query { .. }),
            "client request must jump ahead of a gossip backlog"
        );
        assert_eq!(inbox.len(), 20, "only the client request was removed");

        // Remaining pops drain the gossip in FIFO order (tick 0,1,2,...).
        for expected_tick in 0..20 {
            let e = pop_prioritized(&mut inbox).expect("gossip remains");
            match e.message {
                WireMessage::Gossip(GossipMessage::StateUpdate { tick, .. }) => {
                    assert_eq!(tick, expected_tick, "gossip FIFO order preserved");
                }
                _ => panic!("expected gossip"),
            }
        }
        assert!(pop_prioritized(&mut inbox).is_none());
    }

    #[test]
    fn pop_prioritized_serves_tick_ahead_of_gossip() {
        // Mesh-liveness Tick behind a gossip backlog must not starve.
        let mut inbox: Vec<Envelope> = (0..5).map(gossip_env).collect();
        inbox.push(env(WireMessage::Tick(TickMessage {
            number: 1709000000,
            upstream_pk: [0x55; 32],
            payload: vec![],
            signature: vec![],
            timestamp_ms: 0,
            prev_sig: vec![],
            grandparent_pk: None,
            available_slots: vec![],
            downstream_approvals: 0,
            subtree_d_available: 0,
            oods_tardis: Vec::new(),
            child_pks: Vec::new(),
            gp_commitment: None,
        })));
        let first = pop_prioritized(&mut inbox).expect("non-empty");
        assert!(
            matches!(first.message, WireMessage::Tick(_)),
            "Tick liveness must jump ahead of a gossip backlog"
        );
    }

    #[test]
    fn pop_prioritized_all_background_falls_back_to_fifo() {
        // An all-gossip inbox drains front-first (FIFO); nothing stranded.
        let mut inbox: Vec<Envelope> = (0..3).map(gossip_env).collect();
        for expected_tick in 0..3 {
            let e = pop_prioritized(&mut inbox).expect("gossip remains");
            match e.message {
                WireMessage::Gossip(GossipMessage::StateUpdate { tick, .. }) => {
                    assert_eq!(tick, expected_tick);
                }
                _ => panic!("expected gossip"),
            }
        }
        assert!(pop_prioritized(&mut inbox).is_none(), "empty inbox → None");
    }

    #[test]
    fn is_background_traffic_classification() {
        // Background family is deprioritized …
        assert!(is_background_traffic(&gossip_env(0).message));
        assert!(is_background_traffic(&WireMessage::AeEntries { entries: vec![], fork_bans: vec![] }));
        // … foreground (liveness + client-facing) is not.
        assert!(!is_background_traffic(&WireMessage::Query { wallet_id: [0; 32] }));
        assert!(!is_background_traffic(&WireMessage::RegisterRejected {
            wallet_id: [0; 32],
            reason: String::new(),
            known_peers: vec![],
        }));
    }

    #[test]
    fn wire_message_tick_roundtrip() {
        let tick = TickMessage {
            number: 1709000000,
            upstream_pk: [0x55; 32],
            payload: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            timestamp_ms: 1709000000_000,
            prev_sig: vec![],
            grandparent_pk: None,
            available_slots: vec![([0xAA; 32], 5)],
            downstream_approvals: 2,
            subtree_d_available: 7,
            oods_tardis: Vec::new(),
            child_pks: Vec::new(),
            gp_commitment: None,
        };
        let msg = WireMessage::Tick(tick);

        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();

        match decoded {
            WireMessage::Tick(t) => {
                assert_eq!(t.number, 1709000000);
                assert_eq!(t.downstream_approvals, 2);
                assert_eq!(t.available_slots.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn nabla_address_socket_roundtrip_v4() {
        let addr = NablaAddress::V4 { ip: [10, 0, 0, 1], port: 1211 };
        let sock = to_socket_addr(&addr);
        assert_eq!(sock.to_string(), "10.0.0.1:1211");
        let back = from_socket_addr(sock);
        assert_eq!(back, addr);
    }

    #[test]
    fn nabla_address_socket_roundtrip_v6() {
        let mut ip = [0u8; 16];
        ip[15] = 1; // ::1
        let addr = NablaAddress::V6 { ip, port: 1211 };
        let sock = to_socket_addr(&addr);
        assert_eq!(sock.to_string(), "[::1]:1211");
        let back = from_socket_addr(sock);
        assert_eq!(back, addr);
    }

    #[test]
    fn wire_all_variants_serialize() {
        // Ensure every WireMessage variant can round-trip through bincode
        let messages: Vec<WireMessage> = vec![
            WireMessage::Tick(TickMessage {
                number: 1,
                upstream_pk: [0; 32],
                payload: vec![],
                signature: vec![],
                timestamp_ms: 0,
                prev_sig: vec![],
                grandparent_pk: None,
                available_slots: vec![],
                downstream_approvals: 0,
                subtree_d_available: 0,
                oods_tardis: Vec::new(),
                child_pks: Vec::new(),
                gp_commitment: None,
            }),
            WireMessage::Approval(TickApproval {
                tick_number: 1,
                approver_pk: [0; 32],
                signature: vec![],
                subtree_open_d: 0,
            }),
            WireMessage::AuditRequest(SubtreeAuditRequest {
                prefix: vec![],
                prefix_bits: 0,
                request_tick: 0,
                requester_pk: [0; 32],
            }),
            WireMessage::AuditResponse(SubtreeAuditResponse {
                prefix: vec![],
                prefix_bits: 0,
                subtree_hash: [0; 32],
                root_hash: [0; 32],
                response_tick: 0,
                responder_pk: [0; 32],
                siblings: vec![],
                signature: vec![],
            }),
            WireMessage::Alert(QuestionableAlert {
                suspect_pk: [0; 32],
                reporter_pk: [0; 32],
                tick: 0,
                evidence_hash: [0; 32],
                signature: vec![],
                evidence: None,
            }),
            WireMessage::Gossip(GossipMessage::TickHash {
                tick: 0,
                root_hash: [0; 32],
                node_pk: [0; 32],
                signature: vec![],
            }),
            WireMessage::Register(Registration {
                declared_balance: 0,
                declared_hibernation_until: 0,
                declared_wall_clock_lock: 0,
                declared_emission_claimed_epoch: 0,
                declared_stake_floor_until: 0,
                declared_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
                fob_claim: None,
                k_tier: 3,
                is_recall: false,
                wallet_id: [0; 32],
                old_state: [0; 32],
                new_state: [0; 32],
                tx_hash: [0; 32],
                receipt: K3Receipt {
                    sender_state: None,
                    oods_flag: None,
                    confidence_index: None,
                    consumed_state_id: [0; 32],
                    produced_state_id: [0; 32],
                    amount: 0,
                    signatures: vec![],
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
                burn_target_tx_id: None,
                // ForkSettlement wave 2a — zero-pk fixture: door 5b′ does not run (group
                // carve-out), and no WITNESS_V2 preimage reproduces this arbitrary tx_hash.
                preimage: crate::types::test_legs::opaque_redeem_leg(),
            claimant_wallet_id: String::new(),
            is_dev_claim: false,
            }, DeedTransaction {
                sender_wallet_id: [0; 32],
                receiver_wallet_id: [0xDE; 32],
                amount: 0,
                signature: vec![],
            }),
            WireMessage::RegisterAck(RegistrationAck {
                wallet_id: [0; 32],
                new_state: [0; 32],
                tick: 0,
                root_hash: [0; 32],
                signature: vec![],
                node_pk: vec![],
                node_id: vec![],
                known_peers: vec![],
                zkp_verified: false,
                cheque_status: ChequeStatus::Scarred,
                fact_confirm_signature: vec![],
                ..Default::default()
            }),
            WireMessage::RegisterRejected {
                wallet_id: [0; 32],
                reason: "test_rejection".into(),
                known_peers: vec![NablaClientPeer {
                    node_id: [0xAA; 32],
                    address: NablaAddress::V4 { ip: [10, 0, 0, 1], port: 1211 },
                    last_seen_tick: 42,
                }],
            },
            WireMessage::Query { wallet_id: [0; 32] },
            WireMessage::IntroductionRequest { from: [0; 32] },
            WireMessage::IntroductionResponse { peers: vec![] },
            WireMessage::Hello {
                node_id: [0; 32],
                external_port: 6225,
                downstream_count: 0,
                nbc_bytes: vec![],
                nbc_supporting_bytes: vec![],
                txid_service: String::new(),
                observed_peer_ip: None,
            },
            WireMessage::TardisAttachRequest {
                node_id: [0; 32],
                external_port: 0,
                has_children: false,
                prefer_writer: false,
                nbc_bytes: vec![],
                nbc_supporting_bytes: vec![],
            },
            WireMessage::TardisAttachResponse {
                node_id: [0; 32],
                accepted: true,
                pending: false,
                downstream_count: 1,
                referrals: vec![],
                nbc_bytes: vec![],
                nbc_supporting_bytes: vec![],
            },
            WireMessage::TardisDetach {
                node_id: [0; 32],
            },
            WireMessage::NbcReject {
                reason: "test".into(),
            },
            WireMessage::NablaJoinRequest {
                nbc_bytes: vec![1, 2, 3],
                wallet_id: [0; 32],
                wallet_pubkey: vec![0; 32],
                wallet_binding_sig: vec![0; 64],
            },
            WireMessage::NablaJoinResponse {
                accepted: true,
                reason: String::new(),
                probation_until: 172800,
            },
            WireMessage::NbcIssuanceRequest {
                sphincs_pk: vec![0; 32],
                ed25519_pk: vec![0; 32],
                dilithium_pk: vec![0; 1952],
                node_name: "test-node".into(),
                external_port: 0,
                operator_wallet: String::new(),
            },
            WireMessage::NbcIssuanceResponse {
                accepted: true,
                nbc_bytes: vec![1, 2, 3],
                supporting_chain_bytes: vec![4, 5, 6],
                rejection_reason: String::new(),
            },
            // ── YPX-009: StatePull + RangeSync ──
            WireMessage::StatePullRequest {
                mode: StatePullMode::Bootstrap,
                from: Some([0xEE; 32]),
                our_root_hash: [0xAA; 32],
                from_tick: 0,
                to_tick: 1000,
                section_hash: None,
                have_era_ids: Vec::new(),
                have_consumed_era_ids: Vec::new(),
            },
            WireMessage::StatePullResponse {
                bloom_eras: Vec::new(),
                previous_states: Vec::new(),
                consumed_eras: Vec::new(),
                consumed_era_manifest: Vec::new(),
                mode: StatePullMode::Bootstrap,
                entries: vec![StatePullEntry {
                                  wallet_seq: 0,
                    seq_proof: None,
                    wallet_id: [0x01; 32],
                    new_state: [0x02; 32],
                    tx_hash: [0x03; 32],
                    tick: 42,
                    client_pk: [0u8; 32],
                    client_sig: vec![0u8; 64],
                }],
                highest_tick_served: 42,
                verify_result: None,
                available_from_tick: 0,
                overloaded: false,
            },
            WireMessage::StatePullRequest {
                mode: StatePullMode::WalVerify,
                from: None,
                our_root_hash: [0xBB; 32],
                from_tick: 100,
                to_tick: 200,
                section_hash: Some([0xCC; 32]),
                have_era_ids: Vec::new(),
                have_consumed_era_ids: Vec::new(),
            },
            WireMessage::StatePullResponse {
                bloom_eras: Vec::new(),
                previous_states: Vec::new(),
                consumed_eras: Vec::new(),
                consumed_era_manifest: Vec::new(),
                mode: StatePullMode::WalVerify,
                entries: vec![],
                highest_tick_served: 200,
                verify_result: Some(WalVerifyResult::Match),
                available_from_tick: 0,
                overloaded: false,
            },
            WireMessage::RangeSyncRequest {
                from_tick: 500,
                record_count: 100,
                section_hash: [0xDD; 32],
                our_latest_tick: 1000,
            },
            WireMessage::RangeSyncResponse {
                match_result: RangeSyncMatch::Mismatch,
                missing_entries: vec![],
                peer_latest_tick: 1050,
                peer_section_hash: [0xEE; 32],
            },
            WireMessage::StatusRequest,
            WireMessage::StatusResponse {
                node_id: [0; 32],
                node_name: String::new(),
                needs_parent: false,
                upstream_pending: false,
                downstream_count: 2,
                is_leaf: false,
                has_d_open: true,
                alive: true,
                smt_len: 0,
                peer_count: 0,
                tardis_tick: 0,
                root_hash: [0; 32],
                messages_received: 0,
                upstream_id: None,
                d1_id: None,
                d2_id: None,
                d1_approved: false,
                d2_approved: false,
                known_nodes: 0,
                gossip_active: false,
                wal_file_bytes: 0,
                wal_ops_since_snapshot: 0,
                snapshot_count: 0,
                snapshot_total_bytes: 0,
                last_snapshot_tick: 0,
                total_disk_bytes: 0,
                smt_memory_bytes: 0,
                nbc_issuer: String::new(),
            },
            // YPX-022 RECALL (Phase 3.4) — optional/empty fields built empty so a
            // re-added skip_serializing_if would fail this bincode round-trip.
            WireMessage::RecallRequest(crate::wire_client::RecallRequest {
                failed_send_tx: axiom_core_logic::types::Transaction::default(),
                sender_pk: Vec::new(),
                sender_sig: Vec::new(),
            }),
            WireMessage::RecallResponse(crate::wire_client::RecallResponse {
                status: String::new(),
                attestation: None,
                error: String::new(),
            }),
            WireMessage::RegisterVbcRequest(crate::wire_client::RegisterVbcRequest {
                vbc: axiom_core_logic::types::VBC {
                    genesis_lineage: [0u8; 32],
                    network_size_baseline: 0,
                    baseline_tick: 0,
                    version: 9,
                    validator_id: [0u8; 32],
                    subject_pubkey_sphincs: Vec::new(),
                    subject_pubkey_dilithium: Vec::new(),
                    subject_pubkey_ed25519: Vec::new(),
                    pgp_fingerprint: Vec::new(),
                    node_name: String::new(),
                    proof_cap: String::new(),
                    issued_at: 0,
                    expires_at: 0,
                    chain_depth: 0,
                    issuer_set: Vec::new(),
                    signatures: Vec::new(),
                    max_tx: 0,
                    founding_vbc_hash: [0u8; 32],
                    nabla_registration: None,
                },
                wallet_id: [0; 32],
                k_tier: 3,
                declared_balance: 0,
                declared_hibernation_until: 0,
                declared_wall_clock_lock: 0,
                declared_emission_claimed_epoch: 0,
                declared_stake_floor_until: 0,
                declared_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
                client_sig: Vec::new(),
                supporting_vbcs: Vec::new(),
            }),
            WireMessage::RegisterVbcResponse(crate::wire_client::RegisterVbcResponse {
                status: String::new(),
                stamp: None,
                error: String::new(),
            }),
            // KI#59 — out-of-order scar confirm (link built minimal; FactLink has no Default).
            WireMessage::OooConfirmRequest(crate::wire_client::OooConfirmRequest {
                link: axiom_core_logic::types::FactLink {
                    tx_id: [0u8; 32],
                    previous_state_id: [0u8; 32],
                    new_state_id: [0u8; 32],
                    amount: 0,
                    tick: 0,
                    required_k: 3,
                    witnesses: Vec::new(),
                    nabla_confirmation: None,
                    burn_proof: None,
                    burn_target_tx_id: None,
                    recall_proof: None,
                    out_of_order_confirmation: None,
                    inherited_scar_txids: Vec::new(),
                    inherited_scar_resolutions: Vec::new(),
                    sender_anchor: None,
                    is_dev_class: false,
                    receiver_witness: None,
                },
            }),
            WireMessage::OooConfirmResponse(crate::wire_client::OooConfirmResponse {
                status: String::new(),
                attestation: None,
                error: String::new(),
            }),
        ];

        for msg in &messages {
            let encoded = bincode::serialize(msg).unwrap();
            let _decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        }
    }

    #[test]
    fn tcp_transport_binds_dual_stack() {
        // Bind to [::]:0 (OS-assigned port) — tests dual-stack support
        let transport = TcpTransport::bind("[::]:0");
        match transport {
            Ok(t) => {
                let addr = t.local_addr();
                assert_ne!(addr.port(), 0); // OS assigned a real port
            }
            Err(e) => {
                // Some CI environments don't support IPv6 — that's OK
                eprintln!("Note: dual-stack bind not available: {}", e);
            }
        }
    }

    #[test]
    fn tcp_transport_send_recv() {
        // Spin up a transport, connect to it, send a message, read it back
        let transport = match TcpTransport::bind("127.0.0.1:0") {
            Ok(t) => t,
            Err(_) => return, // skip in constrained environments
        };
        let listen_addr = transport.local_addr();

        // Send a Hello from a raw TCP client
        let msg = WireMessage::Hello {
            node_id: [0xBB; 32],
            external_port: 6225,
            downstream_count: 0,
            nbc_bytes: vec![],
            nbc_supporting_bytes: vec![],
            txid_service: String::new(),
            observed_peer_ip: None,
        };
        let data = bincode::serialize(&msg).unwrap();
        let len_bytes = (data.len() as u32).to_be_bytes();

        let mut client = TcpStream::connect(listen_addr).unwrap();
        client.write_all(&len_bytes).unwrap();
        client.write_all(&data).unwrap();
        client.flush().unwrap();

        // Give the accept loop time to process
        thread::sleep(Duration::from_millis(100));

        // Read from transport inbox directly
        let inbox = transport.inbox.lock().unwrap();
        assert!(!inbox.is_empty(), "should have received a message");
        match &inbox[0].message {
            WireMessage::Hello { node_id, .. } => {
                assert_eq!(*node_id, [0xBB; 32]);
            }
            other => panic!("expected Hello, got {:?}", other),
        }
    }

    /// Fork Settlement §9o [R59] (W1) — ROLLING-RESTART behaviour, measured:
    /// the record-AE variants are appended LAST (bincode tags one and two past
    /// `OooConfirmResponse`), and a node built BEFORE them sees exactly what
    /// this node sees for a tag one past its own last variant. That frame
    /// fails BOTH decoders in `read_one`, `read_loop`'s `while let Ok` ends,
    /// and the inbound connection is CLOSED — every frame queued behind it on
    /// that connection is LOST (the sender's cached outbound connection
    /// breaks; it re-dials on a later send). No crash, no mis-decode.
    /// Hence: roll every node (and the arm64 Pi binary) before any node walks
    /// record-AE. MUTATION: move `RecordAeAsk` above `OooConfirmRequest` ⇒
    /// RED (tag no longer last).
    #[test]
    fn record_ae_variant_unknown_to_an_old_node_closes_its_connection() {
        let tag = |m: &WireMessage| u32::from_le_bytes(bincode::serialize(m).unwrap()[..4].try_into().unwrap());
        let ooo = tag(&WireMessage::OooConfirmResponse(crate::wire_client::OooConfirmResponse {
            status: String::new(), attestation: None, error: String::new(),
        }));
        let ask = WireMessage::RecordAeAsk { from: [1; 32], nonce: 1, ask: crate::record_sync::Ask::Legs(vec![]), sig: vec![] };
        let answer = WireMessage::RecordAeAnswer { from: [1; 32], nonce: 1, answer: crate::record_sync::Answer::Legs(vec![]), sig: vec![] };
        assert_eq!((tag(&ask), tag(&answer)), (ooo + 1, ooo + 2), "appended LAST, in order");
        let transport = match TcpTransport::bind("127.0.0.1:0") {
            Ok(t) => t,
            Err(_) => return,
        };
        let frame = |bytes: &[u8]| {
            let mut v = (bytes.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(bytes);
            v
        };
        // What an OLD node receives: a tag one past its last variant.
        let mut unknown = bincode::serialize(&answer).unwrap();
        unknown[..4].copy_from_slice(&(ooo + 3).to_le_bytes());
        let status = bincode::serialize(&WireMessage::StatusRequest).unwrap();
        let mut client = TcpStream::connect(transport.local_addr()).unwrap();
        client.write_all(&frame(&unknown)).unwrap();
        client.write_all(&frame(&status)).unwrap();
        client.flush().unwrap();
        thread::sleep(Duration::from_millis(300));
        assert!(transport.try_recv().is_none(), "the frame queued behind the undecodable one is LOST");
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 1];
        match client.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("the receiver must CLOSE the connection, got {other:?}"),
        }
        // Control: the same valid frame on a fresh connection is delivered.
        let mut c2 = TcpStream::connect(transport.local_addr()).unwrap();
        c2.write_all(&frame(&status)).unwrap();
        c2.flush().unwrap();
        thread::sleep(Duration::from_millis(300));
        assert!(matches!(transport.try_recv().map(|e| e.message), Some(WireMessage::StatusRequest)));
    }

    #[test]
    fn tcp_keepalive_applied() {
        // Bind a transport (keepalive is applied on accept and connect).
        // This tests the code path executes without panic.
        let transport = match TcpTransport::bind("127.0.0.1:0") {
            Ok(t) => t,
            Err(_) => return,
        };
        let listen_addr = transport.local_addr();

        // Connect to trigger keepalive on the accepted stream
        let _client = TcpStream::connect(listen_addr).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Send triggers keepalive on outbound stream
        let msg = WireMessage::StatusRequest;
        let _ = transport.send(listen_addr, &msg);
        // No panic = keepalive code path is exercised
    }

    #[test]
    fn tcp_try_recv_returns_message() {
        let transport = match TcpTransport::bind("127.0.0.1:0") {
            Ok(t) => t,
            Err(_) => return,
        };
        let listen_addr = transport.local_addr();

        // Initially empty
        assert!(transport.try_recv().is_none(), "no messages yet");

        // Send a message from a raw TCP client
        let msg = WireMessage::StatusRequest;
        let data = bincode::serialize(&msg).unwrap();
        let len_bytes = (data.len() as u32).to_be_bytes();
        let mut client = TcpStream::connect(listen_addr).unwrap();
        client.write_all(&len_bytes).unwrap();
        client.write_all(&data).unwrap();
        client.flush().unwrap();

        thread::sleep(Duration::from_millis(100));

        let envelope = transport.try_recv();
        assert!(envelope.is_some(), "should have a message after send");
        assert!(matches!(envelope.unwrap().message, WireMessage::StatusRequest));
    }

    /// KI#92 — the sweep runs under the NODE lock; it must not wait for a
    /// per-connection mutex that a stalled send holds.
    ///
    /// MUTATION: make `cached_conn_alive` block (`conn.lock().unwrap()`) →
    /// the sweep waits for the holder (2 s) → RED.
    #[test]
    fn sweep_does_not_block_on_a_connection_in_use() {
        let transport = match TcpTransport::bind("127.0.0.1:0") {
            Ok(t) => t,
            Err(_) => return,
        };
        let listen_addr = transport.local_addr();
        let _ = transport.send(listen_addr, &WireMessage::StatusRequest);
        let conn = {
            let conns = transport.connections.lock().unwrap();
            Arc::clone(conns.values().next().expect("a cached connection"))
        };
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let holder = thread::spawn(move || {
            let _g = conn.lock().unwrap(); // a send "stalled" on this connection
            held_tx.send(()).unwrap();
            thread::sleep(Duration::from_secs(2));
        });
        held_rx.recv().unwrap();
        let t0 = std::time::Instant::now();
        transport.sweep_dead_connections();
        let took = t0.elapsed();
        assert!(took < Duration::from_secs(1), "sweep blocked {took:?} on a busy connection");
        assert_eq!(transport.connection_count(), 1, "a connection in use is alive");
        holder.join().unwrap();
    }

    /// KI#92 — after one reply write fails (a peer that never reads), the
    /// connection is shut, so the NEXT reply on it fails immediately instead of
    /// stalling another full write timeout.
    ///
    /// MUTATION: delete the `shutdown` in `send_reply` → the second reply waits
    /// out the write timeout again (2 s) → RED.
    #[test]
    fn failed_reply_write_shuts_the_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap(); // never reads
        let (server, peer) = listener.accept().unwrap();
        server.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        let env = Envelope {
            peer,
            message: WireMessage::StatusRequest,
            reply_stream: Some(Arc::new(Mutex::new(server))),
            cbor_client: false,
            wire_bytes: 0,
        };
        // Large enough to overrun both socket buffers of a non-reading peer.
        let big = WireMessage::NbcIssuanceResponse {
            accepted: true,
            nbc_bytes: vec![0xAB; 64 * 1024 * 1024],
            supporting_chain_bytes: vec![],
            rejection_reason: String::new(),
        };
        assert!(send_reply(&env, &big).is_err(), "the first write must time out");
        let t0 = std::time::Instant::now();
        let second = send_reply(&env, &WireMessage::StatusRequest);
        let took = t0.elapsed();
        assert!(second.is_err(), "a shut connection cannot carry another reply");
        assert!(took < Duration::from_millis(1500), "second reply stalled {took:?}");
    }

    #[test]
    fn connection_pool_sweep() {
        let transport = match TcpTransport::bind("127.0.0.1:0") {
            Ok(t) => t,
            Err(_) => return,
        };
        let listen_addr = transport.local_addr();

        // Send a message to cache a connection
        let msg = WireMessage::StatusRequest;
        let _ = transport.send(listen_addr, &msg);
        assert!(transport.connection_count() > 0, "should have cached connection");

        // Sweep — connections are still alive so should remain
        transport.sweep_dead_connections();
        // Connection may or may not survive sweep (try_clone is the test),
        // but the method must not panic.
    }

    #[test]
    fn nbc_issuance_request_roundtrip() {
        let msg = WireMessage::NbcIssuanceRequest {
            sphincs_pk: vec![0xAA; 32],
            ed25519_pk: vec![0xBB; 32],
            dilithium_pk: vec![0xCC; 1952],
            node_name: "test-node".into(),
            external_port: 0,
            operator_wallet: String::new(),
        };

        // Bincode
        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        match decoded {
            WireMessage::NbcIssuanceRequest { sphincs_pk, ed25519_pk, node_name, .. } => {
                assert_eq!(sphincs_pk, vec![0xAA; 32]);
                assert_eq!(ed25519_pk, vec![0xBB; 32]);
                assert_eq!(node_name, "test-node");
            }
            _ => panic!("wrong variant"),
        }

        // JSON
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: WireMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            WireMessage::NbcIssuanceRequest { node_name, .. } => {
                assert_eq!(node_name, "test-node");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn nbc_issuance_response_roundtrip() {
        let msg = WireMessage::NbcIssuanceResponse {
            accepted: true,
            nbc_bytes: vec![1, 2, 3, 4],
            supporting_chain_bytes: vec![5, 6, 7],
            rejection_reason: String::new(),
        };

        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        match decoded {
            WireMessage::NbcIssuanceResponse { accepted, nbc_bytes, .. } => {
                assert!(accepted);
                assert_eq!(nbc_bytes, vec![1, 2, 3, 4]);
            }
            _ => panic!("wrong variant"),
        }

        // Rejected case
        let rejected = WireMessage::NbcIssuanceResponse {
            accepted: false,
            nbc_bytes: vec![],
            supporting_chain_bytes: vec![],
            rejection_reason: "not qualified".into(),
        };
        let encoded = bincode::serialize(&rejected).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        match decoded {
            WireMessage::NbcIssuanceResponse { accepted, rejection_reason, .. } => {
                assert!(!accepted);
                assert_eq!(rejection_reason, "not qualified");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn nabla_join_request_roundtrip() {
        let msg = WireMessage::NablaJoinRequest {
            nbc_bytes: vec![1, 2, 3, 4],
            wallet_id: [0xAA; 32],
            wallet_pubkey: vec![0xBB; 32],
            wallet_binding_sig: vec![0xCC; 64],
        };
        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        match decoded {
            WireMessage::NablaJoinRequest { nbc_bytes, wallet_id, .. } => {
                assert_eq!(nbc_bytes, vec![1, 2, 3, 4]);
                assert_eq!(wallet_id, [0xAA; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn nabla_join_response_roundtrip() {
        let msg = WireMessage::NablaJoinResponse {
            accepted: true,
            reason: String::new(),
            probation_until: 172800,
        };
        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        match decoded {
            WireMessage::NablaJoinResponse { accepted, probation_until, .. } => {
                assert!(accepted);
                assert_eq!(probation_until, 172800);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── YPX-009: StatePull + RangeSync round-trip tests ──

    #[test]
    fn state_pull_bootstrap_request_roundtrip() {
        let msg = WireMessage::StatePullRequest {
            mode: StatePullMode::Bootstrap,
            from: Some([0xEE; 32]),
            our_root_hash: [0xAA; 32],
            from_tick: 0,
            to_tick: 500,
            section_hash: None,
                have_era_ids: Vec::new(),
            have_consumed_era_ids: Vec::new(),
        };
        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        match decoded {
            WireMessage::StatePullRequest { mode, from_tick, to_tick, section_hash, .. } => {
                assert!(matches!(mode, StatePullMode::Bootstrap));
                assert_eq!(from_tick, 0);
                assert_eq!(to_tick, 500);
                assert!(section_hash.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn state_pull_bootstrap_response_roundtrip() {
        let entries = vec![
            StatePullEntry {
                wallet_seq: 0,
                seq_proof: None,
                wallet_id: [0x01; 32],
                new_state: [0x02; 32],
                tx_hash: [0x03; 32],
                tick: 42,
                client_pk: [0xAA; 32],
                client_sig: vec![0xBB; 64],
            },
            StatePullEntry {
                wallet_seq: 0,
                seq_proof: None,
                wallet_id: [0x11; 32],
                new_state: [0x12; 32],
                tx_hash: [0x13; 32],
                tick: 99,
                client_pk: [0u8; 32],
                client_sig: vec![],
            },
        ];
        let msg = WireMessage::StatePullResponse {
                      bloom_eras: Vec::new(),
                      previous_states: Vec::new(),
                      consumed_eras: Vec::new(),
                consumed_era_manifest: Vec::new(),
            mode: StatePullMode::Bootstrap,
            entries,
            highest_tick_served: 99,
            verify_result: None,
            available_from_tick: 10,
            overloaded: false,
        };
        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        match decoded {
            WireMessage::StatePullResponse { mode, entries, highest_tick_served, overloaded, .. } => {
                assert!(matches!(mode, StatePullMode::Bootstrap));
                assert_eq!(entries.len(), 2);
                assert_eq!(highest_tick_served, 99);
                assert!(!overloaded);
                assert_eq!(entries[0].tick, 42);
                assert_eq!(entries[1].tick, 99);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn state_pull_wal_verify_roundtrip() {
        let msg = WireMessage::StatePullRequest {
            mode: StatePullMode::WalVerify,
            from: None,
            our_root_hash: [0xBB; 32],
            from_tick: 100,
            to_tick: 200,
            section_hash: Some([0xCC; 32]),
                have_era_ids: Vec::new(),
            have_consumed_era_ids: Vec::new(),
        };
        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        match decoded {
            WireMessage::StatePullRequest { mode, section_hash, .. } => {
                assert!(matches!(mode, StatePullMode::WalVerify));
                assert_eq!(section_hash.unwrap(), [0xCC; 32]);
            }
            _ => panic!("wrong variant"),
        }

        // Response with verify result
        let resp = WireMessage::StatePullResponse {
                       bloom_eras: Vec::new(),
                       previous_states: Vec::new(),
                       consumed_eras: Vec::new(),
                consumed_era_manifest: Vec::new(),
            mode: StatePullMode::WalVerify,
            entries: vec![],
            highest_tick_served: 0,
            verify_result: Some(WalVerifyResult::Mismatch),
            available_from_tick: 0,
            overloaded: false,
        };
        let encoded = bincode::serialize(&resp).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        match decoded {
            WireMessage::StatePullResponse { verify_result, .. } => {
                assert!(matches!(verify_result, Some(WalVerifyResult::Mismatch)));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn range_sync_request_response_roundtrip() {
        let req = WireMessage::RangeSyncRequest {
            from_tick: 500,
            record_count: 100,
            section_hash: [0xDD; 32],
            our_latest_tick: 1000,
        };
        let encoded = bincode::serialize(&req).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        match decoded {
            WireMessage::RangeSyncRequest { from_tick, record_count, .. } => {
                assert_eq!(from_tick, 500);
                assert_eq!(record_count, 100);
            }
            _ => panic!("wrong variant"),
        }

        // Response with gap-fill entries
        let resp = WireMessage::RangeSyncResponse {
            match_result: RangeSyncMatch::Mismatch,
            missing_entries: vec![StatePullEntry {
                                      wallet_seq: 0,
                seq_proof: None,
                wallet_id: [0x55; 32],
                new_state: [0x66; 32],
                tx_hash: [0x77; 32],
                tick: 550,
                client_pk: [0x88; 32],
                client_sig: vec![0x99; 64],
            }],
            peer_latest_tick: 1050,
            peer_section_hash: [0xEE; 32],
        };
        let encoded = bincode::serialize(&resp).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        match decoded {
            WireMessage::RangeSyncResponse { match_result, missing_entries, peer_latest_tick, .. } => {
                assert!(matches!(match_result, RangeSyncMatch::Mismatch));
                assert_eq!(missing_entries.len(), 1);
                assert_eq!(missing_entries[0].tick, 550);
                assert_eq!(peer_latest_tick, 1050);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn state_pull_cbor_roundtrip() {
        // Test CBOR serialization (used for client wire format)
        let msg = WireMessage::StatePullRequest {
            mode: StatePullMode::Bootstrap,
            from: Some([0xEE; 32]),
            our_root_hash: [0xAA; 32],
            from_tick: 0,
            to_tick: 100,
            section_hash: None,
                have_era_ids: Vec::new(),
            have_consumed_era_ids: Vec::new(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).unwrap();
        let decoded: WireMessage = ciborium::from_reader(&buf[..]).unwrap();
        match decoded {
            WireMessage::StatePullRequest { mode, from_tick, to_tick, .. } => {
                assert!(matches!(mode, StatePullMode::Bootstrap));
                assert_eq!(from_tick, 0);
                assert_eq!(to_tick, 100);
            }
            _ => panic!("wrong variant"),
        }

        // RangeSync via CBOR
        let msg2 = WireMessage::RangeSyncResponse {
            match_result: RangeSyncMatch::Match,
            missing_entries: vec![],
            peer_latest_tick: 999,
            peer_section_hash: [0xFF; 32],
        };
        let mut buf2 = Vec::new();
        ciborium::into_writer(&msg2, &mut buf2).unwrap();
        let decoded2: WireMessage = ciborium::from_reader(&buf2[..]).unwrap();
        match decoded2 {
            WireMessage::RangeSyncResponse { match_result, peer_latest_tick, .. } => {
                assert!(matches!(match_result, RangeSyncMatch::Match));
                assert_eq!(peer_latest_tick, 999);
            }
            _ => panic!("wrong variant"),
        }
    }

    /// The inbox byte-budget bound (2026-06-25). Fails against the old
    /// count-only cap: a queue well under the depth limit but already at the
    /// byte ceiling used to ADMIT another 1 MiB message — the ~10 GiB worst
    /// case that OOM-killed a writer Nabla. The byte bound rejects it.
    #[test]
    fn inbox_byte_budget_bounds_memory_not_just_count() {
        const MIB: usize = 1024 * 1024;

        // Under both bounds → admit.
        assert!(inbox_admits(0, 0, MIB));
        assert!(inbox_admits(100, 64 * MIB, MIB));

        // The OOM case the count-only cap missed: well under the 2 000 depth,
        // but at the byte ceiling → REJECT (old code would admit).
        assert!(
            !inbox_admits(10, INBOX_MAX_BYTES, 1),
            "byte bound must reject once INBOX_MAX_BYTES is reached, regardless of count"
        );
        assert!(
            !inbox_admits(10, INBOX_MAX_BYTES - MIB + 1, MIB),
            "a 1 MiB message must not push the queue over the byte ceiling"
        );

        // The count bound still holds for a small-message flood.
        assert!(!inbox_admits(INBOX_MAX_DEPTH, 0, 1));
        assert!(inbox_admits(INBOX_MAX_DEPTH - 1, 0, 1));

        // Worst-case memory is bounded: byte ceiling + one in-flight message
        // stays well under 512 MiB (was ~10 GiB under the count-only cap).
        assert!(INBOX_MAX_BYTES + MIB < 512 * MIB);
    }
}
