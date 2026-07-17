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
//   Max message size: 1 MB (WIRE_MAX_MSG_BYTES)
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

use crate::types::*;

/// Maximum wire message size (1 MB).
const WIRE_MAX_MSG_BYTES: usize = 1_048_576;

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
    // body used). The HTTP handlers are gated `410 Gone`.
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
    /// `/endorse-ban-challenge` over TCP — ban-challenge endorsement.
    EndorseBanChallengeRequest(crate::wire_client::EndorseBanChallengeRequest),
    EndorseBanChallengeResponse(crate::wire_client::EndorseBanChallengeResponse),
    EndorseBanChallengeRejected(axiom_errors::ErrorResponse),
    /// `/challenge-ban` over TCP — submit a full ban challenge.
    ChallengeBanRequest(crate::wire_client::ChallengeBanRequest),
    ChallengeBanResponse(crate::wire_client::ChallengeBanResponse),

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
    /// YP §19.6 Step 8.3.B — Lambda notifies Nabla after a withdrawal
    /// round finalises so future earnings queries naturally exclude
    /// the already-claimed window.
    MarkValidatorEarningsClaimedRequest(crate::wire_client::MarkValidatorEarningsClaimedRequest),
    MarkValidatorEarningsClaimedResponse(crate::wire_client::MarkValidatorEarningsClaimedResponse),

    // ── Mesh management ──
    IntroductionRequest { from: NodeId },
    IntroductionResponse { peers: Vec<PeerInfo> },

    // ── Identity ──
    Hello {
        node_id: NodeId,
        address: NablaAddress,
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
    },

    // ── TARDIS Join Protocol ──
    /// Request to attach as downstream child. "Do you have an open D slot?"
    TardisAttachRequest {
        /// Requesting node's ID.
        node_id: NodeId,
        /// Requesting node's address.
        address: NablaAddress,
        /// Whether requester has children (used for strict/relaxed placement).
        has_children: bool,
        /// If true, only accept if parent already has dc=1 (accepting creates a writer).
        /// This is the "strict pass" from orphan recovery — prefer writer-creating placements.
        prefer_writer: bool,
        /// Serialized NBC (bincode). Required for identity verification.
        #[serde(default)]
        nbc_bytes: Vec<u8>,
    },
    /// Response to attach request.
    TardisAttachResponse {
        /// Responding node's ID.
        node_id: NodeId,
        /// Whether the attach was accepted (D slot available and assigned).
        accepted: bool,
        /// Responding node's downstream count (for strict placement decisions).
        downstream_count: usize,
        /// If rejected, referrals to other nodes that may have open D slots.
        referrals: Vec<PeerInfo>,
        /// Responder's NBC for mutual identity verification (N2 tick check).
        #[serde(default)]
        nbc_bytes: Vec<u8>,
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
    /// Network places node as LEAF for NABLA_PROBATION_SECS.
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

    // ── S6: Ban Challenge Protocol ──
    /// Challenge a wallet's ban with evidence. Response: BanChallengeResult.
    BanChallenge {
        wallet_id: WalletId,
        evidence: ChallengeEvidence,
    },
    /// Result of a ban challenge request.
    BanChallengeResult {
        wallet_id: WalletId,
        accepted: bool,
        reason: String,
    },

    // ── State Sync (YPX-009 §12.8) ──
    /// Request state data from a peer (bootstrap or WAL cross-verification).
    StatePullRequest {
        mode: StatePullMode,
        /// Our current SMT root hash (for comparison).
        our_root_hash: Hash256,
        /// Start of tick range to pull.
        from_tick: u64,
        /// End of tick range to pull.
        to_tick: u64,
        /// Section hash for WalVerify mode (None for Bootstrap).
        #[serde(default)]
        section_hash: Option<Hash256>,
    },
    /// Response to StatePullRequest.
    StatePullResponse {
        mode: StatePullMode,
        /// State entries in the requested range.
        entries: Vec<StatePullEntry>,
        /// Highest tick served in this response.
        highest_tick_served: u64,
        /// WI1 (§5.2): serialized consumed-state bloom, so a wiped/recovering
        /// node re-arms its anti-rollback view (A12) instead of coming back
        /// blind. UNION-merged on receive (monotonic). Empty on non-bootstrap /
        /// pre-feature peers. No `serde(default)` (§13 clean break).
        consumed_bloom: Vec<u8>,
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
    },
    /// Anti-entropy step 4 — the responder returns the pulled entries.
    AeEntries {
        /// WI3 hole-1: pulled entries carry their k=3 seq attestation, same
        /// as `AeReconcile.push`.
        entries: Vec<(NablaEntry, Option<SeqProof>)>,
    },

    // ── Sim control (binary sim mode) ──
    /// Request node status for metrics collection.
    StatusRequest,
    /// Node status response with TARDIS metrics.
    StatusResponse {
        node_id: NodeId,
        node_name: String,
        needs_parent: bool,
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
    stream.write_all(&len_buf)?;
    stream.write_all(&data)?;
    stream.flush()?;
    Ok(())
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
        })
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
        // Check cache first
        {
            let mut conns = self.connections.lock().unwrap();
            if let Some(existing) = conns.get(&addr) {
                // Liveness probe: try_clone() on the inner stream
                // detects a fully-closed socket. Half-closed sockets
                // (peer FIN'd) pass this probe — they're caught by
                // the zombie-recovery path in `send`.
                let probe = existing.lock().unwrap().try_clone();
                if probe.is_ok() {
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

    fn recv(&self) -> io::Result<Envelope> {
        loop {
            // Try to pop from inbox
            {
                let mut inbox = self.inbox.lock().unwrap();
                if !inbox.is_empty() {
                    return Ok(inbox.remove(0));
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
        if !inbox.is_empty() {
            Some(inbox.remove(0))
        } else {
            None
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.listener_addr
    }

    fn sweep_dead_connections(&self) {
        let mut conns = self.connections.lock().unwrap();
        conns.retain(|_addr, stream_arc| {
            // Try to clone the inner stream — if that fails, the
            // connection is dead. Lock the per-connection mutex first
            // (matches the locking pattern in `send`).
            stream_arc.lock().unwrap().try_clone().is_ok()
        });
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
                let mut inbox = self.inbox.lock().unwrap();
                if !inbox.is_empty() {
                    return Ok(inbox.remove(0));
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
        if !inbox.is_empty() {
            Some(inbox.remove(0))
        } else {
            None
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// Convert a NablaAddress to a std::net::SocketAddr.
pub fn to_socket_addr(addr: &NablaAddress) -> SocketAddr {
    match addr {
        NablaAddress::V4 { ip, port } => {
            SocketAddr::from((std::net::Ipv4Addr::from(*ip), *port))
        }
        NablaAddress::V6 { ip, port } => {
            SocketAddr::from((std::net::Ipv6Addr::from(*ip), *port))
        }
    }
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
    use super::*;

    #[test]
    fn wire_message_roundtrip_bincode() {
        let msg = WireMessage::Hello {
            node_id: [0xAA; 32],
            address: NablaAddress::V6 {
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                port: 1211,
            },
            downstream_count: 1,
            nbc_bytes: vec![1, 2, 3],
            txid_service: "hashmap".into(),
        };

        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();

        match decoded {
            WireMessage::Hello { node_id, address, nbc_bytes, .. } => {
                assert_eq!(node_id, [0xAA; 32]);
                assert_eq!(address, NablaAddress::V6 {
                    ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    port: 1211,
                });
                assert_eq!(nbc_bytes, vec![1, 2, 3]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn wire_message_roundtrip_cbor() {
        let msg = WireMessage::Gossip(GossipMessage::StateUpdate {
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
                signature: vec![],
            }),
            WireMessage::Alert(QuestionableAlert {
                suspect_pk: [0; 32],
                reporter_pk: [0; 32],
                tick: 0,
                evidence_hash: [0; 32],
                signature: vec![],
            }),
            WireMessage::Gossip(GossipMessage::TickHash {
                tick: 0,
                root_hash: [0; 32],
                node_pk: [0; 32],
            }),
            WireMessage::Register(Registration {
                is_recall: false,
                wallet_id: [0; 32],
                old_state: [0; 32],
                new_state: [0; 32],
                tx_hash: [0; 32],
                receipt: K3Receipt {
                    oods_flag: None,
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
                partial_bridge: None,
                burn_target_tx_id: None,
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
                address: NablaAddress::V4 { ip: [0; 4], port: 0 },
                downstream_count: 0,
                nbc_bytes: vec![],
                txid_service: String::new(),
            },
            WireMessage::TardisAttachRequest {
                node_id: [0; 32],
                address: NablaAddress::V4 { ip: [0; 4], port: 0 },
                has_children: false,
                prefer_writer: false,
                nbc_bytes: vec![],
            },
            WireMessage::TardisAttachResponse {
                node_id: [0; 32],
                accepted: true,
                downstream_count: 1,
                referrals: vec![],
                nbc_bytes: vec![],
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
                our_root_hash: [0xAA; 32],
                from_tick: 0,
                to_tick: 1000,
                section_hash: None,
            },
            WireMessage::StatePullResponse {
                previous_states: Vec::new(),
                consumed_bloom: Vec::new(),
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
                our_root_hash: [0xBB; 32],
                from_tick: 100,
                to_tick: 200,
                section_hash: Some([0xCC; 32]),
            },
            WireMessage::StatePullResponse {
                previous_states: Vec::new(),
                consumed_bloom: Vec::new(),
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
            address: NablaAddress::V4 { ip: [127, 0, 0, 1], port: 1234 },
            downstream_count: 0,
            nbc_bytes: vec![],
            txid_service: String::new(),
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
            our_root_hash: [0xAA; 32],
            from_tick: 0,
            to_tick: 500,
            section_hash: None,
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
                      previous_states: Vec::new(),
                      consumed_bloom: Vec::new(),
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
            our_root_hash: [0xBB; 32],
            from_tick: 100,
            to_tick: 200,
            section_hash: Some([0xCC; 32]),
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
                       previous_states: Vec::new(),
                       consumed_bloom: Vec::new(),
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
            our_root_hash: [0xAA; 32],
            from_tick: 0,
            to_tick: 100,
            section_hash: None,
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
