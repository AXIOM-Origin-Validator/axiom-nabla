//! ForkSettlement §7 — the IN-PROCESS MULTI-NODE fork-detection gate.
//!
//! N REAL `NablaNode`s (each on its own data dir under ONE `tempfile::TempDir`,
//! removed on drop — the soak leaked 7.9 GB of /tmp), each with a real
//! Ed25519 node key; every leg is a GENUINE k=3-witnessed, wallet-signed send
//! leg from the ONE test builder `types::test_legs::genuine_send_leg`. Nothing
//! is mocked: messages are delivered by calling the SAME lib entry points the
//! binary's loops call —
//!
//! | binary (`bin/nabla_node.rs`)                         | router here            |
//! |------------------------------------------------------|------------------------|
//! | `handle_message` Register → `core.register(.., virtual_secs)`, on Ok flood `gossip_msg` to `forward_targets(self)` | `Mesh::register_at` |
//! | `handle_message` Gossip → `core.handle_gossip(msg, virtual_secs)`; `Forward(m)` → `forward_targets(sender)` | `Mesh::step` |
//! | `fork_ban_fanout` (after every handled message + once per tick) → `ForkBan` to `forward_targets(self)` | `Mesh::fanout` |
//! | `AeReconcile`/`AeEntries` → `core.apply_remote_entry(entry, smt.seq_proof(wid), virtual_secs)`, then the carried `fork_bans` [R18]: `prelock_ae_fork_bans` (`ae_fork_bans_known` + `ban::screen_ae_fork_bans`) → `core.adopt_ae_fork_bans` | `Mesh::ae_pull` |
//! | R48 record-AE (W1): tick walk `core.record_ae_tick` → `RecordAeAsk` arm `core.record_ae_handle_ask` → `RecordAeAnswer`: `prelock_record_ae` (`record_ae_accept_answer` + `record_sync::prepare_answer` off the lock) → `core.record_ae_apply_answer` | `Mesh::record_ae` |
//!
//! The router owns ONLY what `sim.rs` may own (its boundary rule): delivery
//! order, a full mesh (`forward_targets` = every other peer), and the
//! adversary — a per-envelope `Fate` hook that DROPS (flood shedding, the
//! `check_peer_rate` 500/60 s shed) or DELAYS a message, and CRASH/RESTART of
//! a node (drop the in-memory `NablaNode`, re-`open` it from its own WAL /
//! snapshot dir). Messages to a crashed node are lost (a closed socket), not
//! queued.
//!
//! Why a module under `nabla/src`, not `nabla/tests/`: the leg builder
//! (`types::test_legs`) and the attestation assembly
//! (`node::wave3_hook_tests::attestation`) are `#[cfg(test)] pub(crate)` — an
//! integration test links the lib WITHOUT `cfg(test)` and cannot see them, and
//! exporting a leg MINTER from the production lib is the wrong trade.
//!
//! CLOCK. One delivery round = one flood hop. The router advances the nodes'
//! wall clock (`now_secs`, the binary's `virtual_secs`, [R13]) by
//! `TICK_INTERVAL_SECS` per round — a deliberate UPPER bound: a hop in the
//! binary is a socket write handled on receipt (ms), and the slowest emitter
//! of a verdict, `fork_ban_fanout` in `tick_loop`, runs once per tick. So the
//! simulated seconds printed by S7 are "at most", never "measured latency".
//!
//! Each test names the mutation that must turn it RED (RULE 6 §3a).

use crate::crypto::Ed25519Signer;
use crate::gossip::GossipAction;
use crate::node::{wave3_hook_tests, NablaNode, OriginVouch};
use crate::types::test_legs::{self, NOW_SECS};
use crate::types::*;

use std::path::PathBuf;

/// Mesh size for every scenario unless stated.
const N: usize = 5;
/// The `from` of an envelope injected by a hostile party that is not a mesh
/// node (so no mesh node is excluded from its fan-out).
const ADVERSARY: usize = usize::MAX;
/// Upper bound of wall-clock seconds per delivery round (see CLOCK above).
const HOP_SECS: u64 = crate::constants::TICK_INTERVAL_SECS;
/// A scenario that has not quiesced by this many rounds is itself a failure.
const MAX_ROUNDS: u64 = 64;

const RECV_P: &str = "p@axiom.internal/0123456789";
const RECV_Q: &str = "q@axiom.internal/0123456789";
const RECV_R: &str = "r@axiom.internal/0123456789";

/// The dev settle twin in seconds — through `dev_or_real`, the ONE selection
/// site (`check_dev_timing.py` rule 2).
fn dev_floor_secs() -> u64 {
    axiom_core_logic::types::dev_or_real(
        true,
        axiom_core_logic::validation::SCAR_SETTLE_TICKS_DEV,
        axiom_core_logic::validation::SCAR_SETTLE_TICKS,
    )
    .to_secs()
}

fn leg(seed: u8, consumed: StateId, recv: &str, amount: u64, nonce: u64) -> ForkLeg {
    test_legs::genuine_send_leg(&test_legs::wallet(seed), consumed, 1, recv, amount, nonce, 3)
}

fn pk_of(seed: u8) -> WalletId {
    test_legs::wallet(seed).verifying_key().to_bytes()
}

// ── The router ───────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Envelope {
    from: usize,
    to: usize,
    msg: GossipMessage,
}

/// What the adversary does with one envelope at send time.
enum Fate {
    Deliver,
    Drop,
    /// Deliver this many rounds later than normal.
    Delay(u64),
}

type Filter = Box<dyn FnMut(&Envelope) -> Fate>;

struct Slot {
    dir: PathBuf,
    seed: [u8; 32],
    node: Option<NablaNode>,
    /// The binary's `origin_boot_secs` (stamped when `recv_loop` goes live):
    /// the clock at (re)open; `None` while crashed.
    boot_secs: Option<u64>,
    /// KI#224 K-e — test witnesses this node's directory has NOT learned
    /// (empty for every scenario but the directory-lag one).
    withheld: Vec<[u8; 32]>,
}

struct Mesh {
    /// Removed (recursively) on drop — every node dir lives under it.
    _root: tempfile::TempDir,
    slots: Vec<Slot>,
    /// `(deliver_at_round, envelope)`.
    queue: Vec<(u64, Envelope)>,
    round: u64,
    /// Wall-clock seconds beyond `round * HOP_SECS` (an idle wait).
    idle_secs: u64,
    filter: Filter,
    delivered: u64,
    shed: u64,
    lost_to_down: u64,
    /// Claims any node fanned out as `ForkBan` (the binary's `fork_ban_fanout`).
    claims_fanned: u64,
}

impl Mesh {
    fn new(n: usize) -> Self {
        let root = tempfile::Builder::new()
            .prefix("nabla_fork_mesh_")
            .tempdir()
            .expect("tempdir");
        let mut m = Mesh {
            slots: Vec::with_capacity(n),
            _root: root,
            queue: Vec::new(),
            round: 0,
            idle_secs: 0,
            filter: Box::new(|_| Fate::Deliver),
            delivered: 0,
            shed: 0,
            lost_to_down: 0,
            claims_fanned: 0,
        };
        for i in 0..n {
            let dir = m._root.path().join(format!("node{i}"));
            let seed = [0xD0u8.wrapping_add(i as u8); 32];
            m.slots.push(Slot { dir, seed, node: None, boot_secs: None, withheld: Vec::new() });
            m.restart(i);
        }
        m
    }

    fn n(&self) -> usize {
        self.slots.len()
    }

    fn now_secs(&self) -> u64 {
        NOW_SECS + self.round * HOP_SECS + self.idle_secs
    }

    /// The TARDIS tick VALUE stamped on messages (unix-seconds-shaped, never
    /// used as a duration here; AE refuses `tick == 0`).
    fn tick(&self) -> u64 {
        NOW_SECS / HOP_SECS + self.round
    }

    fn set_filter(&mut self, f: impl FnMut(&Envelope) -> Fate + 'static) {
        self.filter = Box::new(f);
    }

    fn node(&self, i: usize) -> &NablaNode {
        self.slots[i].node.as_ref().unwrap_or_else(|| panic!("node {i} is down"))
    }

    fn boot(&self, i: usize) -> Option<u64> {
        self.slots[i].boot_secs
    }

    fn up(&self) -> Vec<usize> {
        (0..self.n()).filter(|i| self.slots[*i].node.is_some()).collect()
    }

    /// Drop the in-memory node WITHOUT a snapshot — a crash. Whatever it did
    /// not WAL-log is gone.
    fn crash(&mut self, i: usize) {
        self.slots[i].node = None;
        self.slots[i].boot_secs = None;
    }

    /// (Re)open node `i` from ITS OWN data dir (snapshot + WAL replay + R28
    /// re-derivation, all inside `NablaNode::open`).
    fn restart(&mut self, i: usize) {
        let s = &mut self.slots[i];
        let signer = Box::new(Ed25519Signer::from_seed(&s.seed));
        let mut node = NablaNode::open(&s.dir, signer).expect("NablaNode::open");
        // W7c — the R42 directory holds the test witnesses (a real admission
        // persists; the test helper does not, so every (re)open re-admits),
        // minus any this slot withholds (KI#224 K-e).
        node.admit_test_validators_except(&s.withheld);
        node.drain_fork_side_effects();
        s.node = Some(node);
        s.boot_secs = Some(NOW_SECS + self.round * HOP_SECS + self.idle_secs);
    }

    /// A client registers `leg` at node `i`'s door (the binary's Register
    /// arm): `register`, flood the result on Ok, then the fork fan-out
    /// (Ok AND Err — a refused leg can open a claim, R30).
    fn register_at(&mut self, i: usize, leg: &ForkLeg) -> Result<(), crate::types::NablaError> {
        let (reg, deed) = test_legs::registration_of(leg);
        self.register_raw(i, &reg, &deed)
    }

    fn register_raw(
        &mut self,
        i: usize,
        reg: &Registration,
        deed: &DeedTransaction,
    ) -> Result<(), crate::types::NablaError> {
        let (now, tick) = (self.now_secs(), self.tick());
        let node = self.slots[i].node.as_mut().expect("register at a down node");
        node.set_current_tick(tick);
        let r = node.register(reg, deed, now);
        if let Ok(res) = &r {
            self.flood(i, None, res.gossip_msg.clone());
        }
        self.fanout(i);
        r.map(|_| ())
    }

    /// A hostile party (not a mesh node) sends `msg` straight to every node.
    fn inject_everywhere(&mut self, msg: GossipMessage) {
        self.flood(ADVERSARY, None, msg);
    }

    fn flood(&mut self, from: usize, except: Option<usize>, msg: GossipMessage) {
        for to in 0..self.n() {
            if to != from && Some(to) != except {
                self.send(Envelope { from, to, msg: msg.clone() });
            }
        }
    }

    fn send(&mut self, env: Envelope) {
        let at = self.round + 1;
        match (self.filter)(&env) {
            Fate::Deliver => self.queue.push((at, env)),
            Fate::Delay(d) => self.queue.push((at + d, env)),
            Fate::Drop => self.shed += 1,
        }
    }

    /// The binary's `fork_ban_fanout`: every verdict node `i` queued goes out
    /// as `GossipMessage::ForkBan` to every other peer.
    fn fanout(&mut self, i: usize) {
        let claims = match self.slots[i].node.as_mut() {
            Some(n) => n.take_pending_fork_floods(),
            None => return,
        };
        for claim in claims {
            self.claims_fanned += 1;
            self.flood(i, None, GossipMessage::ForkBan { claim });
        }
    }

    /// One delivery round: every envelope due by the new round is handed to
    /// its target's `handle_gossip` (arrival order), forwarded as the binary
    /// forwards, then that node's fork verdicts are fanned out.
    fn step(&mut self) {
        self.round += 1;
        let (now, tick, round) = (self.now_secs(), self.tick(), self.round);
        let (due, later): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.queue).into_iter().partition(|(at, _)| *at <= round);
        self.queue = later;
        for (_, env) in due {
            let Some(node) = self.slots[env.to].node.as_mut() else {
                self.lost_to_down += 1;
                continue;
            };
            self.delivered += 1;
            node.set_current_tick(tick);
            match node.handle_gossip(&env.msg, now) {
                GossipAction::Forward(m) => self.flood(env.to, Some(env.from), m),
                _ => {}
            }
            self.fanout(env.to);
        }
    }

    /// Deliver until the queue is empty. Returns the round count used.
    fn run_until_quiet(&mut self) -> u64 {
        let start = self.round;
        while !self.queue.is_empty() {
            assert!(self.round - start < MAX_ROUNDS, "mesh did not quiesce in {MAX_ROUNDS} rounds");
            self.step();
        }
        self.round - start
    }

    fn all_up_banned(&self, pk: &WalletId) -> bool {
        self.up().iter().all(|i| self.node(*i).is_banned(pk))
    }

    /// Deliver until every LIVE node has `pk` banned; returns the number of
    /// rounds that took (0 = already banned everywhere after the registers),
    /// `None` if the mesh quiesced first. Keeps delivering to quiescence.
    fn rounds_until_all_banned(&mut self, pk: &WalletId) -> Option<u64> {
        let start = self.round;
        let mut at = None;
        loop {
            if at.is_none() && self.all_up_banned(pk) {
                at = Some(self.round - start);
            }
            if self.queue.is_empty() {
                return at;
            }
            assert!(self.round - start < MAX_ROUNDS, "mesh did not quiesce in {MAX_ROUNDS} rounds");
            self.step();
        }
    }

    /// Emulate ONE anti-entropy pull of every head `peer` holds into
    /// `joiner` (the binary's `AeEntries` arm: each `(smt.get(wid),
    /// smt.seq_proof(wid))` → `apply_remote_entry`), then the message's
    /// `fork_bans` field — `peer.ae_fork_bans_out()`, what the binary's
    /// responder puts on `AeEntries` [R18/R25] — through the binary's
    /// screen (`ae_fork_bans_known` under the lock, `screen_ae_fork_bans`
    /// off it) and `adopt_ae_fork_bans`, then the fork fan-out.
    /// The digest step (which wids differ) is skipped: a joiner that lacks a
    /// wallet pulls it, and pulling an identical head is a no-op.
    fn ae_pull(&mut self, joiner: usize, peer: usize) {
        self.ae_pull_inner(joiner, peer, true);
    }

    /// As `ae_pull`, but the message carries an EMPTY `fork_bans` — what a
    /// peer that holds the heads but never learned the ban (itself cut off
    /// from every flood) sends. Drives the AE record hook on its own.
    fn ae_pull_heads_only(&mut self, joiner: usize, peer: usize) {
        self.ae_pull_inner(joiner, peer, false);
    }

    fn ae_pull_inner(&mut self, joiner: usize, peer: usize, with_bans: bool) {
        let (entries, fork_bans) = {
            let p = self.slots[peer].node.as_mut().expect("AE from a down node");
            let entries: Vec<(NablaEntry, Option<SeqProof>)> = p
                .smt()
                .entries()
                .iter()
                .map(|(wid, e)| (e.clone(), p.smt().seq_proof(wid).cloned()))
                .collect();
            (entries, if with_bans { p.ae_fork_bans_out() } else { Vec::new() })
        };
        self.ae_deliver(joiner, &entries, &fork_bans);
    }

    /// The receiving half of an `AeEntries` / `AeReconcile` exactly as the
    /// binary handles it: entries first, then the carried fork bans.
    fn ae_deliver(
        &mut self,
        to: usize,
        entries: &[(NablaEntry, Option<SeqProof>)],
        fork_bans: &[ForkClaim],
    ) {
        let now = self.now_secs();
        let node = self.slots[to].node.as_mut().expect("AE into a down node");
        for (e, proof) in entries {
            node.apply_remote_entry(e, proof.as_ref(), now);
        }
        if !fork_bans.is_empty() {
            let known = node.ae_fork_bans_known(fork_bans);
            let screen = crate::ban::screen_ae_fork_bans(fork_bans, &known);
            node.adopt_ae_fork_bans(fork_bans, &screen, now);
        }
        self.fanout(to);
    }

    /// A node's id — its Ed25519 key (the "verified NBC key" of `from`).
    fn node_id(&self, i: usize) -> NodeId {
        ed25519_dalek::SigningKey::from_bytes(&self.slots[i].seed).verifying_key().to_bytes()
    }

    /// Emulate ONE R48 record-AE descent (Fork Settlement §9o [R58/R59]) of
    /// `joiner` against `peer`, exactly as the binary runs it: the tick walk's
    /// `record_ae_start` → the responder's `RecordAeAsk` arm
    /// (`record_ae_handle_ask`, authenticated against the asker's key) → the
    /// asker's `RecordAeAnswer` arm (`record_ae_accept_answer` under the lock,
    /// `record_sync::prepare_answer` off it, `record_ae_apply_answer` under
    /// it) until the descent ends; then the fork fan-out. Real node keys; the
    /// ONE driver the node-level tests use (`node::record_ae_tests::
    /// descend_nodes`). Returns the asks sent.
    fn record_ae(&mut self, joiner: usize, peer: usize) -> u32 {
        let now = self.now_secs();
        let (jid, pid) = (self.node_id(joiner), self.node_id(peer));
        let mut a = self.slots[joiner].node.take().expect("record-AE from a down node");
        let mut b = self.slots[peer].node.take().expect("record-AE to a down node");
        let asks = crate::node::record_ae_tests::descend_nodes(&mut a, jid, &mut b, pid, now).asks;
        self.slots[joiner].node = Some(a);
        self.slots[peer].node = Some(b);
        self.fanout(joiner);
        asks
    }

    /// Let wall-clock time pass with no traffic.
    fn idle(&mut self, secs: u64) {
        self.idle_secs += secs;
    }
}

// ── Assertions shared by the fork scenarios ─────────────────────────────────

/// Core's verdict on node `i`'s signed attestation for `txid` at the node's
/// own `now` (dev twin) — the money-path view of "vouchable".
fn core_settles(m: &Mesh, i: usize, txid: &TxHash, now: u64) -> bool {
    let att = wave3_hook_tests::attestation(m.node(i), txid, now, m.boot(i));
    assert!(wave3_hook_tests::signature_verifies(&att), "node {i}'s attestation must verify");
    axiom_core_logic::fact::origin_settled_link(&att, txid, true)
}

/// Every live node: `pk` banned by a `Fork` claim that VERIFIES and names two
/// of `legs`; no leg vouchable — neither by `origin_vouch` now nor by Core
/// after the dev settle floor has fully elapsed.
fn assert_fork_banned_everywhere(m: &mut Mesh, pk: &WalletId, legs: &[&ForkLeg], label: &str) {
    let txids: Vec<TxHash> = legs.iter().map(|l| l.tx_hash).collect();
    for i in m.up() {
        let n = m.node(i);
        assert!(n.is_banned(pk), "{label}: node {i} must have A banned");
        match &n.bans().get(pk).expect("ban entry").evidence {
            BanEvidence::Fork(c) => {
                crate::ban::verify_fork_claim(c)
                    .unwrap_or_else(|e| panic!("{label}: node {i}'s ForkClaim must verify: {e:?}"));
                assert!(txids.contains(&c.a.tx_hash) && txids.contains(&c.b.tx_hash),
                    "{label}: node {i}'s claim names the fork's legs");
            }
            other => panic!("{label}: node {i} banned on non-Fork evidence {other:?}"),
        }
        for t in &txids {
            // §9p: a fork leg is signed HELD (not merely withheld) — the key
            // holds ≥ 2 legs on every node.
            assert_eq!(n.origin_vouch(t, m.boot(i)), OriginVouch::HELD,
                "{label}: node {i} must sign HELD (never vouch) for leg {}", hex::encode(&t[..4]));
        }
    }
    // Past the floor for every record and every boot: Core must still say no.
    m.idle(dev_floor_secs() + HOP_SECS * MAX_ROUNDS);
    let now = m.now_secs();
    for i in m.up() {
        for t in &txids {
            assert!(!core_settles(m, i, t, now),
                "{label}: node {i}'s attestation settles leg {} after the floor", hex::encode(&t[..4]));
        }
    }
}

// ── Scenarios ───────────────────────────────────────────────────────────────

/// The S1/S2 fork: leg a at node 0's door, leg b at node 3's door in the
/// SAME round (neither door has seen the other). Returns rounds until the
/// last node banned A.
fn simultaneous_fork(seed: u8, equal_amount: bool) -> u64 {
    let mut m = Mesh::new(N);
    let y = test_legs::opening(&test_legs::wallet(seed)); // W7c: grounded, so "not vouched" is the fork's doing
    let a = leg(seed, y, RECV_P, 100, 1);
    let b = if equal_amount { leg(seed, y, RECV_Q, 100, 1) } else { leg(seed, y, RECV_Q, 250, 2) };
    assert_ne!(a.tx_hash, b.tx_hash, "fixture: two txids");
    if equal_amount {
        assert_eq!(a.new_state, b.new_state, "fixture [R31]: ONE new_state, two txids");
    }
    m.register_at(0, &a).expect("leg a at node 0's door");
    m.register_at(3, &b).expect("leg b at node 3's door");
    let pk = pk_of(seed);
    let rounds = m.rounds_until_all_banned(&pk)
        .unwrap_or_else(|| panic!("mesh quiesced with A not banned everywhere: {:?}",
            (0..N).map(|i| m.node(i).is_banned(&pk)).collect::<Vec<_>>()));
    assert_fork_banned_everywhere(&mut m, &pk, &[&a, &b], if equal_amount { "S2" } else { "S1" });
    rounds
}

/// The S3 shed fork: as S1, but leg b's flood is SHED toward every node but
/// node 4, and delayed 2 extra rounds toward node 4. Nodes 0, 1 and 2 never
/// see leg b except inside a `ForkBan`. Returns rounds until all banned.
fn shed_fork(seed: u8) -> u64 {
    let mut m = Mesh::new(N);
    let y = test_legs::opening(&test_legs::wallet(seed));
    let a = leg(seed, y, RECV_P, 100, 1);
    let b = leg(seed, y, RECV_Q, 250, 2);
    let tx_b = b.tx_hash;
    m.set_filter(move |e| match &e.msg {
        GossipMessage::StateUpdate { tx_hash, .. } if *tx_hash == tx_b => {
            if e.to == 4 { Fate::Delay(2) } else { Fate::Drop }
        }
        _ => Fate::Deliver,
    });
    m.register_at(0, &a).expect("leg a");
    m.register_at(3, &b).expect("leg b");
    let pk = pk_of(seed);
    let rounds = m.rounds_until_all_banned(&pk)
        .unwrap_or_else(|| panic!("S3: mesh quiesced with A not banned everywhere: {:?}",
            (0..N).map(|i| m.node(i).is_banned(&pk)).collect::<Vec<_>>()));
    assert!(m.shed > 0, "fixture: the adversary shed leg b's flood");
    for i in [0usize, 1, 2] {
        let b_ = m.node(i).bans();
        assert_eq!(b_.origin_fork_claims_detected(), 0,
            "fixture: node {i} never saw leg b by flood — it cannot detect locally");
        assert!(b_.origin_fork_claims_adopted() >= 1, "node {i} banned via ForkBan ADOPTION");
    }
    assert_fork_banned_everywhere(&mut m, &pk, &[&a, &b], "S3");
    rounds
}

/// S1 — simultaneous fork, different amounts. MUTATION (measured
/// 2026-09-28): skip the FLOOD record hook in `apply_state_update` ⇒ no node
/// detects (every node holds one leg from its door or first flood) ⇒ RED.
#[test]
fn s1_simultaneous_fork_banned_everywhere() {
    let r = simultaneous_fork(0xC1, false);
    eprintln!("[S1] last node banned after {r} round(s)");
}

/// S2 — [R31] equal-amount fork: same `new_state`, different txid.
/// MUTATION (measured): re-add the `new_state` inequality to
/// `verify_fork_claim` ⇒ S2 alone goes RED.
#[test]
fn s2_equal_amount_fork_banned_everywhere() {
    let r = simultaneous_fork(0xC2, true);
    eprintln!("[S2] last node banned after {r} round(s)");
}

/// S3 — flood shed: leg b reaches ONE node (late); every other node is banned
/// through `ForkBan` adoption. MUTATION (measured): `adopt_fork_claim`
/// returns without banning ⇒ nodes 0–2 never banned ⇒ S3 RED (S7 with it; S8
/// too — its packaged claim is then never verified, so never counted).
#[test]
fn s3_shed_flood_banned_via_fork_ban_adoption() {
    let r = shed_fork(0xC3);
    eprintln!("[S3] last node banned after {r} round(s)");
}

/// S4a — restart AFTER the fork: node 2 crashes with no snapshot (WAL replay
/// only) and node 1 snapshots then restarts; both come back banned, neither
/// leg vouchable. MUTATION (measured): `drain_fork_side_effects` skips the WAL
/// `Ban` and `OriginRecord` appends ⇒ the crashed node forgets ⇒ S4a alone RED.
#[test]
fn s4a_restart_after_fork_still_banned() {
    let seed = 0xC4;
    let mut m = Mesh::new(N);
    let y = test_legs::opening(&test_legs::wallet(seed));
    let a = leg(seed, y, RECV_P, 100, 1);
    let b = leg(seed, y, RECV_Q, 250, 2);
    m.register_at(0, &a).unwrap();
    m.register_at(3, &b).unwrap();
    m.run_until_quiet();
    let pk = pk_of(seed);
    assert!(m.all_up_banned(&pk));
    m.crash(2);
    m.slots[1].node.as_mut().unwrap().take_snapshot().expect("snapshot");
    m.crash(1);
    m.idle(60);
    m.restart(2);
    m.restart(1);
    for i in [1usize, 2] {
        assert!(m.node(i).is_banned(&pk), "node {i} came back banned");
    }
    assert_fork_banned_everywhere(&mut m, &pk, &[&a, &b], "S4a");
}

/// Shared by S4b/S4c: node 4 is DOWN for the whole fork (every flood and
/// `ForkBan` toward it is lost), then restarts from its own dir. Returns the
/// mesh and the legs; node 4 has learned nothing yet.
fn late_joiner_fixture(seed: u8) -> (Mesh, ForkLeg, ForkLeg) {
    let mut m = Mesh::new(N);
    let y = test_legs::opening(&test_legs::wallet(seed));
    let a = leg(seed, y, RECV_P, 100, 1);
    let b = leg(seed, y, RECV_Q, 250, 2);
    m.crash(4);
    m.register_at(0, &a).unwrap();
    m.register_at(3, &b).unwrap();
    m.run_until_quiet();
    let pk = pk_of(seed);
    assert!(m.all_up_banned(&pk), "fixture: the four live nodes banned A");
    assert!(m.lost_to_down > 0, "fixture: traffic toward node 4 was lost");
    m.restart(4);
    assert!(!m.node(4).is_banned(&pk), "fixture: node 4 missed everything");
    (m, a, b)
}

/// S4b — the late joiner's FIRST anti-entropy exchange is with a peer whose
/// head for A is leg a (the banned-everywhere wallet's head, status Banned).
/// Heads alone would leave node 4 holding leg a as a fresh, uncontested origin
/// and — after one settle — VOUCHING for it while every other node holds the
/// verdict (MEASURED 2026-09-28 before wave 4b: RED at the vouch assertion).
/// ForkSettlement [R18] (wave 4b-minimal): the same AE message carries the
/// peer's fork bans WITH evidence, so node 4 bans A in that ONE exchange.
/// MUTATION (measured 2026-09-28): `ae_fork_bans_out` returns nothing (the
/// field dropped), or `adopt_ae_fork_bans` skips adoption ⇒ S4b RED.
#[test]
fn s4b_late_joiner_first_ae_peer_holds_one_leg() {
    let seed = 0xC5;
    let (mut m, a, b) = late_joiner_fixture(seed);
    let pk = pk_of(seed);
    let peer = (0..4)
        .find(|i| m.node(*i).smt().get(&pk).is_some_and(|e| e.tx_hash == a.tx_hash))
        .expect("fixture: some peer holds leg a as A's head");
    m.ae_pull(4, peer);
    assert!(m.node(4).is_banned(&pk), "node 4 must learn the ban within the ONE AE exchange");
    m.run_until_quiet();
    m.idle(dev_floor_secs() + HOP_SECS);
    let now = m.now_secs();
    assert!(!core_settles(&m, 4, &a.tx_hash, now),
        "node 4 vouches (Core-settled) for leg a of a wallet banned everywhere else");
    assert!(m.node(4).is_banned(&pk), "node 4 must learn the ban from its AE peer");
    assert_fork_banned_everywhere(&mut m, &pk, &[&a, &b], "S4b");
}

/// S4c — the AE RECORD HOOK on its own (wave 3): heads-only AE (empty
/// `fork_bans` — peers that hold heads but carry no ban) over EVERY live
/// peer meets both legs (node 3's head is leg b), the record hook on the AE
/// path opens the claim, and node 4 ends banned. It depends on some peer
/// still holding the other leg as its head — S4b (bans carried, R18) is the
/// case where the first peer does not. MUTATION (measured): skip the AE record hook in
/// `apply_remote_entry_inner` ⇒ node 4 never banned ⇒ S4c alone RED.
#[test]
fn s4c_late_joiner_heads_only_ae_over_all_peers_detects() {
    let seed = 0xC6;
    let (mut m, a, b) = late_joiner_fixture(seed);
    let pk = pk_of(seed);
    let heads: Vec<Option<TxHash>> =
        (0..4).map(|i| m.node(i).smt().get(&pk).map(|e| e.tx_hash)).collect();
    assert!(heads.contains(&Some(b.tx_hash)) && heads.contains(&Some(a.tx_hash)),
        "fixture: both legs survive as some peer's head: {heads:?}");
    for peer in 0..4 {
        m.ae_pull_heads_only(4, peer);
        m.run_until_quiet();
    }
    assert!(m.node(4).bans().origin_fork_claims_detected() >= 1,
        "node 4 detected the fork itself on the AE path");
    assert_fork_banned_everywhere(&mut m, &pk, &[&a, &b], "S4c");
}

/// S4d — FORGED bans on the AE field [R18/R25]: a hostile AE peer hands node 2
/// an `AeEntries` whose `fork_bans` carries (1) A's legs signed over VICTIM
/// W's bucket (framing), (2) a genuine fork of wallet C with one client sig
/// flipped, (3) two GENUINE legs of W from DIFFERENT parents (an honest chain
/// paired as a "fork"), and 30 copies of (1) so the page runs past
/// `AE_FORK_BANS_MAX`. Every one is refused and counted
/// (`atraxi_evidence_refused` += 33), nothing is banned or applied, nothing is
/// queued for the `ForkBan` fan-out, and W's honest origin stays vouchable.
/// MUTATION (measured 2026-09-28): `adopt_ae_fork_bans` skips the `Refused`
/// counter ⇒ S4d RED. NOT a mutation that turns it red, BY DESIGN: the
/// off-lock screen marking every claim `Verified` without `verify_fork_claim`
/// stays GREEN — `adopt_fork_claim` re-verifies under the lock (the ONE
/// chokepoint, [R25]) and refuses + counts the same claims. The screen is a
/// lock-time filter, never the authority; its only effect is WHERE the
/// verification cost lands, which this gate cannot observe.
#[test]
fn s4d_forged_ae_fork_bans_refused_counted_nothing_banned() {
    let (seed_a, seed_w, seed_c) = (0xD1, 0xD2, 0xD3);
    let sk_a = test_legs::wallet(seed_a);
    let w = pk_of(seed_w);
    let mut m = Mesh::new(N);
    let y_w = test_legs::opening(&test_legs::wallet(seed_w));
    let honest_w = leg(seed_w, y_w, RECV_P, 10, 1);
    m.register_at(1, &honest_w).expect("W's honest leg");
    m.run_until_quiet();

    // (1) framing: A's legs, A's client sig over W's bucket.
    let y: StateId = [0x9B; 32];
    let mut fa = leg(seed_a, y, RECV_P, 100, 1);
    let mut fb = leg(seed_a, y, RECV_Q, 250, 2);
    fa.client_sig = test_legs::client_sig_over(&sk_a, &w, &fa.new_state, &fa.tx_hash);
    fb.client_sig = test_legs::client_sig_over(&sk_a, &w, &fb.new_state, &fb.tx_hash);
    let framing = ForkClaim { a: fa, b: fb };
    // (2) a genuine fork of C, one client sig flipped.
    let y_c = test_legs::opening(&test_legs::wallet(seed_c));
    let ca = leg(seed_c, y_c, RECV_P, 100, 1);
    let mut cb = leg(seed_c, y_c, RECV_Q, 250, 2);
    cb.client_sig[0] ^= 0x01;
    let tampered = ForkClaim { a: ca, b: cb };
    // (3) two genuine legs of W from DIFFERENT parents — not siblings.
    let w_later = leg(seed_w, [0x77; 32], RECV_Q, 5, 2);
    let not_siblings = ForkClaim { a: honest_w.clone(), b: w_later };
    for c in [&framing, &tampered, &not_siblings] {
        assert!(crate::ban::verify_fork_claim(c).is_err(), "fixture: every claim is a forgery");
    }
    let mut forged = vec![framing.clone(), tampered, not_siblings];
    forged.extend(std::iter::repeat_n(framing, 30));
    assert!(forged.len() > crate::ban::AE_FORK_BANS_MAX, "fixture: the page runs past the cap");

    let before = m.node(2).bans().atraxi_evidence_refused();
    m.ae_deliver(2, &[], &forged);
    m.run_until_quiet();
    let n = m.node(2);
    assert_eq!(n.bans().atraxi_evidence_refused() - before, forged.len() as u64,
        "every AE-carried forgery (incl. past the cap) refused AND counted");
    for (who, pk) in [("W", w), ("A", pk_of(seed_a)), ("C", pk_of(seed_c))] {
        for i in m.up() {
            assert!(!m.node(i).is_banned(&pk), "node {i} banned {who} on forged AE evidence");
        }
    }
    assert_eq!(n.bans().fork_claims_applied(), 0, "no verdict applied");
    assert_eq!(m.claims_fanned, 0, "a refused claim is never fanned out");
    assert!(n.origin_vouch(&honest_w.tx_hash, m.boot(2)).origin.is_some(),
        "W's honest origin still vouchable");
}

/// S5 — a three-way fork at nodes 0, 2 and 4: A banned everywhere, NO leg
/// vouchable anywhere (the third leg is named in no ban evidence).
/// MUTATION (measured): drop `origin_vouch`'s pk-ban and key-held clauses ⇒
/// recorded legs of a banned wallet vouch ⇒ S5 RED (and every fork scenario).
/// W7c: the pk-ban clause is REMOVED (ruling 3); the key-held test now lives
/// in `provenance::Provenance::judge_send` (`legs_under(key) ≥ 2`), and the
/// legs consume A's OPENING state so an unforked leg WOULD vouch.
#[test]
fn s5_three_way_fork_banned_everywhere_no_leg_vouchable() {
    let seed = 0xC7;
    let mut m = Mesh::new(N);
    let y = test_legs::opening(&test_legs::wallet(seed));
    let legs = [
        leg(seed, y, RECV_P, 100, 1),
        leg(seed, y, RECV_Q, 200, 2),
        leg(seed, y, RECV_R, 300, 3),
    ];
    for (door, l) in [0usize, 2, 4].into_iter().zip(&legs) {
        m.register_at(door, l).expect("each leg at its own door");
    }
    let pk = pk_of(seed);
    let r = m.rounds_until_all_banned(&pk).expect("S5: all banned");
    eprintln!("[S5] last node banned after {r} round(s)");
    let refs: Vec<&ForkLeg> = legs.iter().collect();
    assert_fork_banned_everywhere(&mut m, &pk, &refs, "S5");
}

/// S6 — HONEST CONTROL (non-vacuity): ONE leg, the SAME registration retried
/// at a second door. No ban, no claim anywhere; every node holds the record
/// and vouches, and Core settles the node's attestation exactly at
/// `registered_at + dev floor`, not one second before.
/// MUTATION (measured): `record_verified_leg` without the write-once
/// short-circuit ⇒ the retry is a "second leg", its claim is refused and
/// counted ⇒ S6 alone RED. (Skipping the flood hook also turns it RED: the
/// nodes that only saw the flood hold no record — the non-vacuity half.)
#[test]
fn s6_honest_retry_same_txid_no_ban_vouchable_after_settle() {
    let seed = 0xC8;
    let mut m = Mesh::new(N);
    // W7c: consumed = A's OPENING state (a structural root) — an arbitrary
    // parent is ungrounded and never vouched (M2).
    let a = leg(seed, test_legs::opening(&test_legs::wallet(seed)), RECV_P, 100, 1);
    m.register_at(0, &a).expect("leg a at node 0");
    m.register_at(3, &a).expect("the SAME leg retried at node 3");
    m.run_until_quiet();
    let pk = pk_of(seed);
    let floor = dev_floor_secs();
    let mut latest_ready = 0u64;
    for i in m.up() {
        let n = m.node(i);
        assert!(!n.is_banned(&pk), "node {i} banned an honest retry");
        assert_eq!(n.ban_count(), 0, "node {i} holds a ban");
        assert_eq!(n.bans().origin_fork_claims_detected(), 0);
        assert_eq!(n.bans().atraxi_evidence_refused(), 0);
        let v = n.origin_vouch(&a.tx_hash, m.boot(i));
        assert!(v.origin.is_some(), "node {i} holds and vouches the honest origin");
        latest_ready = latest_ready.max(v.registered_at_secs + floor);
    }
    // One second before the latest node's floor: that node is NOT settled.
    let before = latest_ready - 1 - m.now_secs();
    m.idle(before);
    let now = m.now_secs();
    let unsettled: Vec<usize> =
        m.up().into_iter().filter(|i| !core_settles(&m, *i, &a.tx_hash, now)).collect();
    assert!(!unsettled.is_empty(), "the floor is real: someone is unsettled 1 s before");
    m.idle(1);
    let now = m.now_secs();
    for i in m.up() {
        assert!(core_settles(&m, i, &a.tx_hash, now),
            "node {i}: Core must settle the honest origin after the dev floor");
    }
}

/// S7 — TIMING: rounds until the LAST node is banned, for S1 and S3, must be
/// below the dev settle floor expressed in rounds (each round ≤
/// `TICK_INTERVAL_SECS`). Prints the numbers. Goes RED with its scenarios
/// (measured under the S1/S3 mutations); no mutation moves the round count
/// without also breaking detection outright.
#[test]
fn s7_detection_rounds_below_dev_settle_floor() {
    let floor = dev_floor_secs();
    let floor_rounds = floor / HOP_SECS;
    for (label, rounds) in [("S1", simultaneous_fork(0xC9, false)), ("S3", shed_fork(0xCA))] {
        eprintln!(
            "[S7] {label}: last node banned after {rounds} round(s) = at most {} s simulated \
             (≤ {HOP_SECS} s/round); dev settle floor = {floor} s = {floor_rounds} rounds (N={N})",
            rounds * HOP_SECS,
        );
        assert!(rounds >= 1, "{label}: detection needs at least one hop (non-vacuity)");
        assert!(rounds < floor_rounds, "{label}: {rounds} rounds is not below the floor's {floor_rounds}");
    }
}

/// S8 — FRAMING: A signs two forked legs over VICTIM W's bucket and pushes
/// them every way it can — W-keyed registers at two doors, W-keyed
/// StateUpdate floods, and a packaged `ForkBan` — after W's own honest leg is
/// held mesh-wide. Nobody bans W; W's honest origin stays vouchable; the
/// packaged claim is refused (counted) at every node and never forwarded.
/// MUTATION (measured): skip the client-sig step in `check_fork_leg` ⇒ the
/// packaged claim verifies and A is banned on legs signed over W's bucket
/// (the ban keys derive from the preimage pk, so W itself is still spared) ⇒
/// S8 alone RED.
#[test]
fn s8_framing_over_victim_bucket_bans_nobody() {
    let (seed_a, seed_w) = (0xCB, 0xCC);
    let sk_a = test_legs::wallet(seed_a);
    let w = pk_of(seed_w);
    let mut m = Mesh::new(N);
    let honest_w = leg(seed_w, test_legs::opening(&test_legs::wallet(seed_w)), RECV_P, 10, 1);
    m.register_at(1, &honest_w).expect("W's honest leg");
    m.run_until_quiet();

    let y: StateId = [0x9A; 32];
    let mut fa = leg(seed_a, y, RECV_P, 100, 1);
    let mut fb = leg(seed_a, y, RECV_Q, 250, 2);
    fa.client_sig = test_legs::client_sig_over(&sk_a, &w, &fa.new_state, &fa.tx_hash);
    fb.client_sig = test_legs::client_sig_over(&sk_a, &w, &fb.new_state, &fb.tx_hash);
    // W-keyed registers at two doors — the STRONGEST form: every witness sig
    // (step 5 and the commitment) re-made over W's id, and A's client sig over
    // W's bucket (`resign_registration`). Refused or not, nothing may ban W.
    for (door, l) in [(0usize, &fa), (3, &fb)] {
        let (mut reg, deed) = test_legs::registration_of(l);
        reg.wallet_id = w;
        test_legs::resign_registration(&mut reg, &sk_a);
        let r = m.register_raw(door, &reg, &deed);
        eprintln!("[S8] W-keyed framing register at node {door}: {:?}", r.as_ref().err());
    }
    // W-keyed floods of both legs straight from the adversary.
    for l in [&fa, &fb] {
        let mut msg = test_legs::flood_of(l, y, m.tick());
        if let GossipMessage::StateUpdate { wallet_id, .. } = &mut msg {
            *wallet_id = w;
        }
        m.inject_everywhere(msg);
    }
    // The packaged claim.
    m.inject_everywhere(GossipMessage::ForkBan { claim: ForkClaim { a: fa.clone(), b: fb.clone() } });
    m.run_until_quiet();

    for i in m.up() {
        let n = m.node(i);
        assert!(!n.is_banned(&w), "node {i} banned the framed victim W");
        assert!(!n.is_banned(&pk_of(seed_a)), "node {i} banned A on evidence that does not verify");
        assert_eq!(n.smt().get(&w).expect("W's head").status, WalletStatus::Normal,
            "node {i}: W's head flipped to a ban status");
        assert!(n.bans().atraxi_evidence_refused() >= 1, "node {i}: the packaged claim was refused + counted");
        assert!(n.origin_vouch(&honest_w.tx_hash, m.boot(i)).origin.is_some(),
            "node {i}: W's honest origin still vouchable");
        assert_eq!(n.bans().fork_claims_applied(), 0, "node {i} applied a framing verdict");
    }
}

/// S8b — the framing legs must not REPLACE the victim's head either. FOUND by
/// this gate (2026-09-28, KI#226): neither the flood (`apply_state_update`),
/// the AE path, nor the register door bound the message's `wallet_id` to its
/// `client_pk` — `verify_client_state_sig` checks A's signature over W's id,
/// and the door's 5a′ derived the bucket from `reg.wallet_id`. So A's own
/// (genuinely witnessed — and, per KI#224, even self-witnessed) leg, re-signed
/// by A over W's id, (1) replaced W's EXISTING head at every node through one
/// injected flood, and (2) was ACCEPTED at the door as a fresh W's head and
/// flooded mesh-wide. FIXED (KI#226, pending rotation): the bucket is DERIVED
/// from the signing key on all three paths (`registration::
/// bucket_derives_from_key` on flood + AE, door step 0b) and a mismatch is
/// refused + counted (`wallet_id_key_mismatch`). (3) the AE path is exercised
/// too, and W's honest head survives all three.
/// MUTATIONS (run 2026-09-28): delete the flood gate in `apply_state_update`
/// ⇒ part (1) RED; delete door step 0b ⇒ part (2) RED; delete the AE gate in
/// `apply_remote_entry_inner` ⇒ part (3) RED.
#[test]
fn s8b_framing_legs_do_not_replace_victim_head() {
    let (seed_a, seed_w) = (0xCD, 0xCE);
    let sk_a = test_legs::wallet(seed_a);
    let w = pk_of(seed_w);
    let y: StateId = [0x9B; 32];
    let mut fa = leg(seed_a, y, RECV_P, 100, 1);
    fa.client_sig = test_legs::client_sig_over(&sk_a, &w, &fa.new_state, &fa.tx_hash);
    let mismatch_before = crate::registration::wallet_id_key_mismatch_total();

    // (1) The flood path against a victim that HOLDS a head everywhere.
    let mut m = Mesh::new(N);
    let honest_w = leg(seed_w, [0x98; 32], RECV_P, 10, 1);
    m.register_at(1, &honest_w).expect("W's honest leg");
    m.run_until_quiet();
    let mut msg = test_legs::flood_of(&fa, y, m.tick() + 5);
    if let GossipMessage::StateUpdate { wallet_id, .. } = &mut msg {
        *wallet_id = w;
    }
    m.inject_everywhere(msg);
    m.run_until_quiet();
    for i in m.up() {
        let head = m.node(i).smt().get(&w).expect("W's head");
        assert_eq!((head.client_pk, head.tx_hash), (w, honest_w.tx_hash),
            "node {i}: W's head replaced by A's leg via the FLOOD");
    }

    // (3) The AE path, on the same mesh: every node is offered A's leg as W's
    // entry (A's sig over W's id, the leg's own SeqProof, a later tick).
    let mut e = test_legs::entry_of(&fa, m.tick() + 9);
    e.wallet_id = w;
    e.client_sig = fa.client_sig.clone();
    let now = m.now_secs();
    for i in m.up() {
        let node = m.slots[i].node.as_mut().expect("up");
        assert!(!node.apply_remote_entry(&e, Some(&fa.seq_proof), now), "node {i}: AE adopted A's leg as W");
        let head = node.smt().get(&w).expect("W's head");
        assert_eq!((head.client_pk, head.tx_hash), (w, honest_w.tx_hash),
            "node {i}: W's head replaced by A's leg via ANTI-ENTROPY");
    }

    // (2) The door, for a victim no node holds yet.
    let mut m = Mesh::new(N);
    let (mut reg, deed) = test_legs::registration_of(&fa);
    reg.wallet_id = w;
    test_legs::resign_registration(&mut reg, &sk_a);
    assert!(m.register_raw(0, &reg, &deed).is_err(), "the door refuses W's id under A's key");
    m.run_until_quiet();
    for i in m.up() {
        assert!(m.node(i).smt().get(&w).is_none_or(|h| h.client_pk == w),
            "node {i}: A's leg stored as W's head via the DOOR");
    }
    assert!(crate::registration::wallet_id_key_mismatch_total() >= mismatch_before + 1 + N as u64,
        "every refusal is COUNTED (flood + AE + door)");
}

/// S9 — REDEEM FORK (Fork Settlement W7b, spec R52c): receiver R redeems TWO
/// cheques from ONE state R0 — ρ1 at node 0's door, ρ2 at node 3's door in the
/// same round (two validator sets; neither door has seen the other). The
/// redeem legs ride the flood inside their `SeqProof` and are recorded in the
/// REDEEM ledger on the SHARED `(R, R0)` key, so the first node holding both
/// opens a `ForkClaim` through the Redeem arm and every node ends with R
/// banned on a VERIFIED redeem-fork claim. No origin record anywhere (R5), and
/// neither cheque's origin is vouched from R's records.
/// MUTATION (run 2026-09-28): make `SparseMerkleTree::record_verified_leg`
/// return `Duplicate` for redeem legs (the pre-W7b "redeem legs create
/// nothing") ⇒ S9 alone RED (the mesh quiesces with R unbanned).
#[test]
fn s9_redeem_fork_two_cheques_one_state_banned_everywhere() {
    let r = test_legs::wallet(0xD9);
    let r_pk = pk_of(0xD9);
    let r0: StateId = [0x99; 32];
    let rho1 = test_legs::genuine_redeem_leg(&r, r0, &crate::types::test_legs::stray_origin([0x91; 32]), 1_000, 2, 3);
    let rho2 = test_legs::genuine_redeem_leg(&r, r0, &crate::types::test_legs::stray_origin([0x92; 32]), 5_000, 2, 3);
    let mut m = Mesh::new(N);
    m.register_at(0, &rho1).expect("ρ1 at node 0's door");
    m.register_at(3, &rho2).expect("ρ2 at node 3's door");
    let rounds = m.rounds_until_all_banned(&r_pk)
        .unwrap_or_else(|| panic!("S9: mesh quiesced with R not banned everywhere: {:?}",
            (0..N).map(|i| m.node(i).is_banned(&r_pk)).collect::<Vec<_>>()));
    eprintln!("[S9] last node banned after {rounds} round(s)");
    for i in m.up() {
        let n = m.node(i);
        match &n.bans().get(&r_pk).expect("ban entry").evidence {
            BanEvidence::Fork(c) => {
                crate::ban::verify_fork_claim(c)
                    .unwrap_or_else(|e| panic!("S9: node {i}'s ForkClaim must verify: {e:?}"));
                assert_eq!((c.a.kind(), c.b.kind()),
                    (axiom_core_logic::types::LegKind::Redeem, axiom_core_logic::types::LegKind::Redeem),
                    "node {i}: banned on the REDEEM legs");
            }
            other => panic!("S9: node {i} banned on non-Fork evidence {other:?}"),
        }
        assert_eq!(n.smt().origin_len(), 0, "node {i}: a redeem is never an origin record (R5)");
        for t in [rho1.tx_hash, rho2.tx_hash] {
            assert!(!n.smt().cheque_sender_registered(&t), "node {i}: R's redeem made cheque {} look registered", hex::encode(&t[..4]));
            assert_eq!(n.origin_vouch(&t, m.boot(i)), OriginVouch::NONE);
        }
    }
}

/// S10 — Fork Settlement W7c/W7d, the COLLUDER CHAIN across the mesh (TLA+
/// c17/c17e/c19, §9k rulings 1–3). There is no byzantine node in-process, so
/// the gate is at the VOUCH level: A pays merchant M from its opening state,
/// then forks (ta at node 0, tb at node 3). Q redeems tb and pays Q2, Q2
/// redeems and pays R — each at a different door. Every honest node:
/// - vouches NOTHING descended from the fork (t_qq2, t_q2r) — Core never
///   settles them, even past the floor (NoHonestClean);
/// - still vouches M's pre-fork origin t_am, and Core settles it (ruling 3
///   negative — NoFalseHold);
/// - ACCEPTS R's redeem of t_q2r at the door and reports it `Held([t_q2r])`
///   (ruling 1: accept + mark);
/// - after R burns EXACTLY t_q2r's amount, vouches R's next payment (ruling 2).
/// MUTATIONS (run 2026-09-28): `judge_send` ignores the input roots (one
/// hop) ⇒ t_qq2 vouched ⇒ S10 RED; restore clause 4 ⇒ t_am NONE ⇒ S10 RED;
/// match any burn amount — not observable here (exact burn), covered by
/// `provenance::tests::w7c_burn_exact_amount_releases_wallet`.
#[test]
fn s10_colluder_chain_never_vouched_merchant_pre_fork_ok_burn_clears() {
    let (a, mm, q, q2, r) = (0xE1u8, 0xE2u8, 0xE3u8, 0xE4u8, 0xE5u8);
    let sk = test_legs::wallet;
    let send = |seed: u8, consumed: StateId, seq: u64, to: &str, amount: u64, nonce: u64| {
        test_legs::genuine_send_leg(&sk(seed), consumed, seq, to, amount, nonce, 3)
    };
    let redeem = |seed: u8, cheque: &ForkLeg, balance: u64| {
        test_legs::genuine_redeem_leg(&sk(seed), test_legs::opening(&sk(seed)), &test_legs::origin_of(cheque), balance, 1, 3)
    };
    let mut m = Mesh::new(N);
    // A pays M BEFORE the fork; M redeems.
    let t_am = send(a, test_legs::opening(&sk(a)), 1, "m@axiom.internal/0123456789", 100, 1);
    m.register_at(0, &t_am).expect("A pays M");
    m.run_until_quiet();
    let rho_m = redeem(mm, &t_am, 100);
    m.register_at(1, &rho_m).expect("M redeems");
    m.run_until_quiet();
    // A forks from the state after paying M.
    let ta = send(a, t_am.new_state, 2, RECV_P, 300, 2);
    let tb = send(a, t_am.new_state, 2, RECV_Q, 300, 3);
    m.register_at(0, &ta).expect("ta at node 0");
    m.register_at(3, &tb).expect("tb at node 3");
    m.rounds_until_all_banned(&pk_of(a)).expect("S10: A banned everywhere");
    // The chain downstream of tb, each hop at another door.
    let rho_q = redeem(q, &tb, 300);
    m.register_at(1, &rho_q).expect("Q redeems tb");
    m.run_until_quiet();
    let t_qq2 = send(q, rho_q.new_state, 2, "q2@axiom.internal/0123456789", 60, 1);
    m.register_at(2, &t_qq2).expect("Q pays Q2");
    m.run_until_quiet();
    let rho_q2 = redeem(q2, &t_qq2, 60);
    m.register_at(2, &rho_q2).expect("Q2 redeems");
    m.run_until_quiet();
    let t_q2r = send(q2, rho_q2.new_state, 2, RECV_R, 20, 1);
    m.register_at(4, &t_q2r).expect("Q2 pays R");
    m.run_until_quiet();
    let rho_r = redeem(r, &t_q2r, 20);
    m.register_at(0, &rho_r).expect("ruling 1: R's held redeem is ACCEPTED, never refused");
    m.run_until_quiet();
    for i in m.up() {
        let n = m.node(i);
        assert_eq!(n.origin_status(None, 0).provenance_dirty_queue, 0, "node {i}: drained");
        for t in [&ta, &tb, &t_qq2, &t_q2r] {
            // §9p: the fork legs AND their transitive descendants (the
            // laundering hops) are signed HELD on every node — the receiver
            // is told "held" at once, never "wait".
            assert_eq!(n.origin_vouch(&t.tx_hash, m.boot(i)), OriginVouch::HELD,
                "node {i} did not sign HELD for {} — downstream of the fork", hex::encode(&t.tx_hash[..4]));
        }
        assert!(n.origin_vouch(&t_am.tx_hash, m.boot(i)).origin.is_some(),
            "node {i}: M, paid BEFORE the fork, must stay vouchable (ruling 3)");
        assert_eq!(n.provenance_view(&pk_of(r), &rho_r.new_state), ProvenanceView::Held(vec![t_q2r.tx_hash]),
            "node {i}: R's redeem is MARKED held (the next-interaction discovery)");
        assert_eq!(n.provenance_view(&pk_of(mm), &rho_m.new_state), ProvenanceView::Ok, "node {i}: M is OK");
    }
    m.idle(dev_floor_secs() + HOP_SECS * MAX_ROUNDS);
    let now = m.now_secs();
    for i in m.up() {
        assert!(core_settles(&m, i, &t_am.tx_hash, now), "node {i}: Core settles M's pre-fork origin");
        for t in [&t_qq2, &t_q2r] {
            assert!(!core_settles(&m, i, &t.tx_hash, now), "node {i}: Core settles a laundered origin");
        }
    }
    // Ruling 2: R burns EXACTLY t_q2r's amount, then pays U.
    let burn = send(r, rho_r.new_state, 2, axiom_core_logic::types::BURN_ADDRESS, 20, 7);
    m.register_at(4, &burn).expect("R burns the tainted amount");
    m.run_until_quiet();
    let t_ru = send(r, burn.new_state, 3, "u@axiom.internal/0123456789", 5, 8);
    m.register_at(1, &t_ru).expect("R pays U after the burn");
    m.run_until_quiet();
    for i in m.up() {
        let n = m.node(i);
        assert_eq!(n.provenance_view(&pk_of(r), &burn.new_state), ProvenanceView::Ok, "node {i}: burn released R");
        assert!(n.origin_vouch(&t_ru.tx_hash, m.boot(i)).origin.is_some(), "node {i}: R's post-burn payment vouched");
    }
}

/// A genesis-claim-funded wallet, as the SDK builds one: the claim from the
/// OPENING state registered with `declared_balance` (0 = every claim before
/// the §9m fix), then the genesis SELF-REDEEM of that claim. Returns
/// `(claim, self_redeem)`; the wallet spends from `self_redeem.new_state`.
fn genesis_funded(m: &mut Mesh, seed: u8, door: usize, amount: u64) -> (ForkLeg, ForkLeg) {
    let sk = test_legs::wallet(seed);
    let own = format!("g{seed:02x}@axiom.internal/0123456789");
    let claim = test_legs::genesis_claim_leg(&sk, &own, amount, 1);
    m.register_at(door, &claim).expect("genesis claim");
    m.run_until_quiet();
    let self_redeem = test_legs::genuine_redeem_leg(&sk, claim.new_state, &crate::types::test_legs::origin_of(&claim), amount, 1, 3);
    m.register_at(door, &self_redeem).expect("genesis self-redeem");
    m.run_until_quiet();
    (claim, self_redeem)
}

/// S11 — Fork Settlement §9m live finding A (trustmesh 2026-09-29): two
/// wallets funded by GENESIS CLAIMS registered with the SDK's declared
/// balance 0; A pays B, B redeems, B pays C — each at another door. After the
/// dev settle floor EVERY honest node vouches A's cheque (B's inherited
/// origin) and B's onward payment, and Core settles both. Before A1 the claim
/// was never a producer (`producer_binding_refused` = the claims), every
/// state after it was ungrounded (M2) and `judge_send` answered WAIT forever:
/// the receiver of an ordinary payment met the consent gate.
/// ~~MUTATION (run 2026-09-29): drop the opening-state arm~~ — that arm is
/// DELETED (KI#251, 2026-10-02): Core's claim send binds the UNCHANGED balance,
/// so the claim leg (produced through Core's own `compute_post_tx_balance`)
/// binds on its declared 0 directly. MUTATION (KI#251): restore the send-side
/// credit in Core's genesis arm ⇒ the produced state stops matching the
/// declared 0 ⇒ S11 RED at "vouch A→B".
#[test]
fn s11_genesis_claim_funded_payment_vouched_everywhere() {
    let (a, b) = (0xF1u8, 0xF2u8);
    let g = 10_000_000_000u64;
    let mut m = Mesh::new(N);
    let (_ga, ra) = genesis_funded(&mut m, a, 0, g);
    let (_gb, rb) = genesis_funded(&mut m, b, 1, g);
    let t_ab = test_legs::genuine_send_leg(&test_legs::wallet(a), ra.new_state, 2, "gf2@axiom.internal/0123456789", 100, 2, 3);
    m.register_at(2, &t_ab).expect("A pays B");
    m.run_until_quiet();
    let rho_b = test_legs::genuine_redeem_leg(&test_legs::wallet(b), rb.new_state, &crate::types::test_legs::origin_of(&t_ab), g + 100, 1, 3);
    m.register_at(3, &rho_b).expect("B redeems A's cheque");
    m.run_until_quiet();
    let t_bc = test_legs::genuine_send_leg(&test_legs::wallet(b), rho_b.new_state, 2, "c@axiom.internal/0123456789", 50, 3, 3);
    m.register_at(4, &t_bc).expect("B pays C");
    m.run_until_quiet();
    m.idle(dev_floor_secs() + HOP_SECS * MAX_ROUNDS);
    let now = m.now_secs();
    for i in m.up() {
        let n = m.node(i);
        let st = n.origin_status(None, 0);
        assert_eq!(st.provenance_dirty_queue, 0, "node {i}: drained");
        assert!(n.origin_vouch(&t_ab.tx_hash, m.boot(i)).origin.is_some(),
            "node {i}: vouch A→B — B's inherited origin, from a genesis-funded wallet");
        assert_eq!(st.producer_binding_refused, 0, "node {i}: a genesis claim refused as a producer");
        assert!(n.origin_vouch(&t_bc.tx_hash, m.boot(i)).origin.is_some(), "node {i}: vouch B→C");
        assert_eq!(n.provenance_view(&pk_of(b), &rho_b.new_state), ProvenanceView::Ok, "node {i}: B's redeem is OK");
        for t in [&t_ab, &t_bc] {
            assert!(core_settles(&m, i, &t.tx_hash, now), "node {i}: Core settles {}", hex::encode(&t.tx_hash[..4]));
        }
    }
}

/// S12 — Fork Settlement §9m live finding B: a HAL re-anchor registered at
/// door 0 must reach every other node with its leg recorded NOT contested,
/// and every node vouches it.
/// ~~It reaches them as `GossipMessage::HalAdvance` (NO SeqProof — the head is
/// adopted, no record made); its leg arrives LATER by anti-entropy~~ — until
/// B2 (§9q, 2026-09-30). CHANGED: the HAL register now floods as a plain
/// `StateUpdate` WITH its leg, so every node records it on the flood, BEFORE
/// the put ([R24]) — asserted right after the flood (was: "HalAdvance carries
/// no leg" — `vouch_record` None until AE). The AE pulls stay (a second copy
/// is a `Duplicate`, never contested). The §9m B1 own-consumption exclusion
/// this test used to drive is now reached only by a head installed without a
/// record; it keeps its own unit test (`smt::tests::
/// origin_record_not_contested_when_head_is_this_leg`).
/// MUTATIONS: (run 2026-09-29, pre-B2) drop `&& !own_consumption` in
/// `SparseMerkleTree::record_verified_leg` ⇒ RED at "born contested" (nodes
/// 1..N). (Run 2026-09-30, B2) emit the pre-B2 `HalAdvance` at the door ⇒ RED
/// at "node 1: adopted the HAL head" (the tombstone drops it).
#[test]
fn s12_hal_advance_then_ae_leg_not_contested() {
    let h = 0xF4u8;
    let sk = test_legs::wallet(h);
    let mut m = Mesh::new(N);
    // The SDK's declaration (the unchanged balance, KI#251) — the only shape.
    let (_gh, rh) = genesis_funded(&mut m, h, 0, 10_000_000_000);
    let hal = test_legs::genuine_send_leg(&sk, rh.new_state, 2, "gf4@axiom.internal/0123456789", 500, 9, 3);
    let (mut reg, deed) = test_legs::registration_of(&hal);
    reg.is_hal_reanchor = true;
    m.register_raw(0, &reg, &deed).expect("HAL re-anchor at door 0");
    m.run_until_quiet();
    for i in 1..m.n() {
        assert_eq!(m.node(i).smt().get(&hal.bucket()).map(|e| e.current_state), Some(hal.new_state),
            "node {i}: adopted the HAL head from its StateUpdate flood");
        let rec = m.node(i).smt().vouch_record(&hal.tx_hash)
            .unwrap_or_else(|| panic!("node {i}: B2 — the HAL leg rides its flood and is recorded before the put"));
        assert!(!rec.contested, "node {i}: HAL record born contested on the flood");
    }
    for i in 1..m.n() {
        m.ae_pull(i, 0);
    }
    m.idle(dev_floor_secs() + HOP_SECS * MAX_ROUNDS);
    for i in m.up() {
        let n = m.node(i);
        let rec = n.smt().vouch_record(&hal.tx_hash)
            .unwrap_or_else(|| panic!("node {i}: the HAL leg must be recorded (door or AE)"));
        assert!(!rec.contested, "node {i}: HAL record born contested (HalAdvance-adopted head)");
        assert_eq!(n.origin_status(None, 0).origin_records_contested, 0, "node {i}");
        assert!(n.origin_vouch(&hal.tx_hash, m.boot(i)).origin.is_some(), "node {i}: vouch the HAL leg");
    }
}

/// S13 — Fork Settlement §9o [R57] (W3; KI#236): a HOSTILE STATUS PUSH blocks
/// nobody. Victim V's genuine head is held mesh-wide. A party that is not a
/// mesh node copies it (public, genuinely signed) and pushes it to ALL 5 nodes
/// over anti-entropy with `status = Banned` (the binary's `AeEntries` arm →
/// `apply_remote_entry`; `status` is outside every signature). Every node
/// discards the status (`ae_status_discarded` ≥ 1), keeps V `Normal`, and V then
/// REGISTERS at every node's door in turn (a chain of five sends, each through
/// the binary's `is_wallet_blocked` door gate) with nobody banned anywhere.
/// MUTATIONS (run 2026-09-30): delete the normalisation (and its count) in
/// `NablaNode::apply_remote_entry_inner` ⇒ S13 RED at node 0 ("the pushed
/// status was not discarded + counted"); keep the count but adopt the status
/// ⇒ S13 RED at "node 0: V's leaf status adopted".
#[test]
fn s13_hostile_status_push_blocks_nobody() {
    let seed = 0xDB;
    let sk = test_legs::wallet(seed);
    let v = pk_of(seed);
    let mut m = Mesh::new(N);
    let first = test_legs::genuine_send_leg(&sk, test_legs::opening(&sk), 1, RECV_P, 10, 1, 3);
    m.register_at(0, &first).expect("V's first leg");
    m.run_until_quiet();
    let (genuine, proof) = {
        let n0 = m.node(0);
        (n0.smt().get(&v).expect("V's head at node 0").clone(), n0.smt().seq_proof(&v).cloned())
    };
    assert_eq!(genuine.status, WalletStatus::Normal, "fixture: V is honest");
    let forged = NablaEntry { status: WalletStatus::Banned, ..genuine.clone() };
    for i in m.up() {
        m.ae_deliver(i, &[(forged.clone(), proof.clone())], &[]);
    }
    m.run_until_quiet();
    for i in m.up() {
        let n = m.node(i);
        assert!(n.ae_status_discarded() >= 1, "node {i}: the pushed status was not discarded + counted");
        assert_eq!(n.smt().get(&v).map(|e| e.status), Some(WalletStatus::Normal), "node {i}: V's leaf status adopted");
        assert!(!n.is_wallet_blocked(&v), "node {i}: V blocked by a hostile status push");
        assert!(!n.is_banned(&v), "node {i}: V banned");
    }
    // V registers at EVERY door afterwards (a chain, one leg per node).
    let mut prev = first;
    for i in 0..N {
        assert!(!m.node(i).is_wallet_blocked(&v), "node {i}: the binary's door gate would refuse V");
        let next = test_legs::genuine_send_leg(&sk, prev.new_state, i as u64 + 2, RECV_Q, 1, 10 + i as u64, 3);
        m.register_at(i, &next).unwrap_or_else(|e| panic!("node {i}: V's register refused: {e:?}"));
        m.run_until_quiet();
        prev = next;
    }
    for i in m.up() {
        let n = m.node(i);
        let head = n.smt().get(&v).expect("V's head");
        assert_eq!((head.tx_hash, head.status), (prev.tx_hash, WalletStatus::Normal), "node {i}: V's last leg is the head");
        assert!(!n.is_banned(&v), "node {i}: V banned");
        assert_eq!(n.ban_count(), 0, "node {i}: someone was banned");
    }
}

// ── Retiring check-3 (the legacy `SeqForkBan` detector) — the proof gates ──
//
// Question (2026-09-30): can the OLD same-seq/same-parent detector in
// `gossip::apply_state_update` (check-3 → `bans.ban_seq_fork` → Banned flip →
// `SeqForkBan` flood) be retired WITHOUT reducing security, and can it
// false-ban an honest wallet? Test A: the record-keyed detector alone reaches
// the verdict on the shape check-3 was built for. Test B / B2: an honest
// wallet whose node's `previous_states[W]` is NOT its head's leg parent.
// Test C: the one shape only check-3 caught, now carried by R48 record-AE.
// ANSWERED: check-3 RETIRED 2026-09-30 (Fork Settlement §9o [R56], W2) — all
// five gates green with it deleted; every filter below still counts
// `SeqForkBan` envelopes, which must stay 0 (nothing emits one).

/// Hand ONE envelope to its target exactly as `Mesh::step` does (forward,
/// then the fork fan-out) and RETURN the action, so a test can observe how
/// the node answered. (`BanDetected`, check-3's action, was deleted with it —
/// §9o [R56], W2.)
fn deliver_observed(m: &mut Mesh, env: &Envelope) -> GossipAction {
    let (now, tick) = (m.now_secs(), m.tick());
    let node = m.slots[env.to].node.as_mut().expect("deliver to a live node");
    node.set_current_tick(tick);
    let action = node.handle_gossip(&env.msg, now);
    match &action {
        GossipAction::Forward(fwd) => m.flood(env.to, Some(env.from), fwd.clone()),
        _ => {}
    }
    m.fanout(env.to);
    action
}

fn action_name(a: &GossipAction) -> &'static str {
    match a {
        GossipAction::Forward(_) => "Forward",
        GossipAction::Duplicate => "Duplicate",
        _ => "other",
    }
}

fn is_update_of(msg: &GossipMessage, txid: &TxHash) -> bool {
    matches!(msg, GossipMessage::StateUpdate { tx_hash, .. } if tx_hash == txid)
}

/// fork_retire_proof A — REDEEM + REDEEM fork, one leg HELD as a node's head,
/// the other ARRIVING BY FLOOD, with check-3's predicate TRUE at that node.
///
/// R (opening → P via ρ0, everywhere) redeems cheque c1 from P (ρ1) at door
/// 0; ρ1's flood never reaches node 3. R then redeems cheque c2 from the SAME
/// P (ρ2) at node 3's door (which never saw ρ1). Node 0 holds ρ1 as its head
/// with its SeqProof and `previous_state(R) == P`; ρ2's flood carries
/// `old_state = P` at the same seq and a different state — every clause of
/// check-3 holds (asserted BEFORE delivery, so the scenario cannot drift
/// into a shape check-3 would have fired on). The record-keyed detector
/// (`record_leg_and_detect`, flood hook) answers: `Duplicate`; R banned on a
/// VERIFIED redeem/redeem `ForkClaim`; the key `(R, P)` holds both legs; and
/// across the whole mesh ZERO `SeqForkBan` envelopes are ever sent and no node
/// holds `SeqFork` evidence. Since W2 (§9o [R56]) check-3 and its
/// `GossipAction::BanDetected` no longer exist — the record detector is the
/// ONLY detector here.
/// MUTATIONS: (run 2026-09-30, pre-W2) disable check-3's ban branch ⇒ A GREEN
/// (check-3 contributed nothing); skip the FLOOD record hook ⇒ A RED at node
/// 0's action: check-3 answered `BanDetected`. (Run 2026-09-30, W2) skip the
/// FLOOD record hook (`seq_proof.as_ref().filter(|_| false)` at the
/// `record_leg_and_detect` site in `apply_state_update`) ⇒ A RED at node 0's
/// action: `Forward` (ρ2 adopted, R not banned).
#[test]
fn fork_retire_proof_a_redeem_fork_held_head_vs_flood_leg_record_detector_alone() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    let seed = 0xA7u8;
    let sk = test_legs::wallet(seed);
    let r_pk = pk_of(seed);
    let mut m = Mesh::new(N);

    let rho0 = test_legs::genuine_redeem_leg(&sk, test_legs::opening(&sk), &crate::types::test_legs::stray_origin([0xA0; 32]), 1_000, 1, 3);
    let p = rho0.new_state;
    m.register_at(0, &rho0).expect("ρ0 at node 0");
    m.run_until_quiet();
    let rho1 = test_legs::genuine_redeem_leg(&sk, p, &crate::types::test_legs::stray_origin([0xA1; 32]), 2_000, 1, 3);
    let rho2 = test_legs::genuine_redeem_leg(&sk, p, &crate::types::test_legs::stray_origin([0xA2; 32]), 3_000, 1, 3);
    assert_ne!(rho1.new_state, rho2.new_state, "fixture: check-3 needs DIFFERENT states");
    assert_eq!(rho1.signed_seq(), rho2.signed_seq(), "fixture: a receive keeps wallet_seq");

    let seq_fork_bans = Rc::new(Cell::new(0u64));
    let held_rho2: Rc<RefCell<Vec<Envelope>>> = Rc::new(RefCell::new(Vec::new()));
    {
        let (c, h, t1, t2) = (seq_fork_bans.clone(), held_rho2.clone(), rho1.tx_hash, rho2.tx_hash);
        m.set_filter(move |env| {
            if matches!(env.msg, GossipMessage::SeqForkBan { .. }) {
                c.set(c.get() + 1);
            }
            if is_update_of(&env.msg, &t1) && env.to == 3 {
                Fate::Drop
            } else if is_update_of(&env.msg, &t2) && h.borrow().len() < N - 1 {
                // ρ2's door flood: held so node 0's delivery is observed by hand.
                h.borrow_mut().push(env.clone());
                Fate::Drop
            } else {
                Fate::Deliver
            }
        });
    }
    m.register_at(0, &rho1).expect("ρ1 at node 0");
    m.run_until_quiet();
    m.register_at(3, &rho2).expect("ρ2 at node 3's door (it never saw ρ1)");
    let held: Vec<Envelope> = held_rho2.borrow().clone();
    assert_eq!(held.len(), N - 1, "ρ2's door flood captured");

    // check-3's predicate, clause by clause, at node 0 for the incoming ρ2.
    let env0 = held.iter().find(|e| e.to == 0).expect("ρ2's flood to node 0").clone();
    let GossipMessage::StateUpdate { old_state, wallet_seq, new_state, client_pk, seq_proof, tx_hash, .. } = &env0.msg
    else { unreachable!() };
    {
        let n0 = m.node(0);
        let head = n0.smt().get(&r_pk).expect("node 0 holds R").clone();
        assert_eq!(head.current_state, rho1.new_state, "node 0 HOLDS ρ1 as its head");
        assert_eq!(head.wallet_seq, *wallet_seq, "check-3: same wallet_seq");
        assert_ne!(head.current_state, *new_state, "check-3: different current_state");
        assert!(crate::registration::verify_seq_proof(seq_proof.as_ref().unwrap(), tx_hash, *wallet_seq),
            "check-3: candidate seq_attested");
        assert!(*client_pk != [0u8; 32] && head.client_pk != [0u8; 32], "check-3: both authored");
        assert_eq!(*old_state, p, "check-3: the flood names parent P");
        assert_eq!(n0.smt().previous_state(&r_pk), Some(p), "check-3: previous_state(R) == P");
        let held_proof = n0.smt().seq_proof(&r_pk).expect("check-3: node 0 retains ρ1's proof");
        assert!(crate::registration::verify_seq_proof(held_proof, &head.tx_hash, head.wallet_seq),
            "check-3: held proof verifies");
        assert_eq!(n0.smt().legs_under(&(r_pk, p)).len(), 1, "fixture: node 0 recorded ρ1 only");
        assert!(!n0.is_banned(&r_pk), "fixture: nobody banned yet");
    }

    let action = deliver_observed(&mut m, &env0);
    assert!(matches!(action, GossipAction::Duplicate),
        "node 0: the RECORD detector must answer first (Duplicate) — got {}", action_name(&action));
    {
        let n0 = m.node(0);
        assert!(n0.is_banned(&r_pk), "node 0: R banned");
        match &n0.bans().get(&r_pk).expect("ban entry").evidence {
            BanEvidence::Fork(c) => {
                crate::ban::verify_fork_claim(c).expect("node 0: the claim verifies");
                assert_eq!((c.a.kind(), c.b.kind()),
                    (axiom_core_logic::types::LegKind::Redeem, axiom_core_logic::types::LegKind::Redeem));
                let mut t = [c.a.tx_hash, c.b.tx_hash];
                t.sort();
                let mut want = [rho1.tx_hash, rho2.tx_hash];
                want.sort();
                assert_eq!(t, want, "node 0: the claim names ρ1 and ρ2");
            }
            other => panic!("node 0: banned on non-Fork (legacy?) evidence {other:?}"),
        }
        assert_eq!(n0.smt().legs_under(&(r_pk, p)).len(), 2, "node 0: (R, P) holds both legs");
        assert_eq!(n0.smt().get(&r_pk).map(|e| e.status), Some(WalletStatus::Banned),
            "node 0: §4.6 read path reports Banned");
    }

    // The rest of ρ2's door flood, then the whole mesh to quiescence.
    for env in held.iter().filter(|e| e.to != 0) {
        m.send(env.clone());
    }
    m.rounds_until_all_banned(&r_pk).unwrap_or_else(|| panic!("A: mesh quiesced with R not banned everywhere: {:?}",
        (0..N).map(|i| m.node(i).is_banned(&r_pk)).collect::<Vec<_>>()));
    for i in m.up() {
        match &m.node(i).bans().get(&r_pk).expect("ban entry").evidence {
            BanEvidence::Fork(c) => { crate::ban::verify_fork_claim(c).expect("claim verifies"); }
            other => panic!("A: node {i} banned on non-Fork evidence {other:?}"),
        }
    }
    assert_eq!(seq_fork_bans.get(), 0, "A: check-3 emitted SeqForkBan — the record detector did not cover this shape");
}

/// Shared B fixture: honest receiver R with a SAME-SEQ redeem chain
/// opening →ρ0→ P →ρ1→ X →ρ2→ H (every redeem keeps wallet_seq; ρ1 and ρ2 are
/// two DIFFERENT cheques, sequential, NO fork). Node 4 (the victim node) has P.
fn honest_chain(seed: u8) -> (Mesh, ForkLeg, ForkLeg, ForkLeg) {
    let sk = test_legs::wallet(seed);
    let mut m = Mesh::new(N);
    let rho0 = test_legs::genuine_redeem_leg(&sk, test_legs::opening(&sk), &crate::types::test_legs::stray_origin([seed; 32]), 1_000, 1, 3);
    m.register_at(0, &rho0).expect("ρ0");
    m.run_until_quiet();
    let rho1 = test_legs::genuine_redeem_leg(&sk, rho0.new_state, &crate::types::test_legs::stray_origin([seed ^ 0x11; 32]), 2_000, 1, 3);
    let rho2 = test_legs::genuine_redeem_leg(&sk, rho1.new_state, &crate::types::test_legs::stray_origin([seed ^ 0x22; 32]), 3_000, 1, 3);
    (m, rho0, rho1, rho2)
}

/// After the victim node answered: collect every false-ban symptom across the
/// mesh (ban table, SMT status, SeqForkBan emissions, and Banned status
/// spreading by AE through `superseded_by`'s rank rule), then fail with the
/// whole list. An honest chain must produce NONE of them.
fn assert_no_false_ban(m: &mut Mesh, r_pk: &WalletId, victim: usize, seq_fork_bans: u64, label: &str) {
    let mut bad: Vec<String> = Vec::new();
    m.run_until_quiet();
    for i in m.up() {
        let n = m.node(i);
        if let Some(b) = n.bans().get(r_pk) {
            let kind = match &b.evidence {
                BanEvidence::SeqFork(_) => "SeqFork (check-3)",
                BanEvidence::Fork(_) => "Fork (record detector)",
                _ => "other",
            };
            bad.push(format!("node {i} BanTable bans honest R on {kind} evidence"));
        }
        if n.smt().get(r_pk).map(|e| e.status) == Some(WalletStatus::Banned) {
            bad.push(format!("node {i} SMT reports honest R Banned (§4.6 read path)"));
        }
    }
    if seq_fork_bans > 0 {
        bad.push(format!("{seq_fork_bans} SeqForkBan envelope(s) flooded for honest R"));
    }
    // AE from the victim: the Banned status is a rank-1 entry and wins the merge.
    for i in m.up() {
        if i != victim {
            m.ae_pull_heads_only(i, victim);
        }
    }
    for i in m.up() {
        if i != victim && m.node(i).smt().get(r_pk).map(|e| e.status) == Some(WalletStatus::Banned) {
            bad.push(format!("node {i} adopted honest R's Banned status by anti-entropy from node {victim}"));
        }
    }
    assert!(bad.is_empty(), "{label}: FALSE BAN of an honest wallet —\n  {}", bad.join("\n  "));
}

/// fork_retire_proof B — honest wallet, NO fork, anti-entropy JUMP.
///
/// Sequence: R's head is P everywhere (ρ0). ρ1 (P→X) registers at door 0 and
/// ρ2 (X→H) at door 1 — every flood of both to node 4 is shed (captured).
/// Node 4 catches up by ONE AE pull from node 0: it jumps its head P → H in a
/// single same-seq put, so `previous_state(R)` becomes P — the head the AE
/// write overwrote, NOT ρ2's leg parent X (smt.rs `previous_states` note).
/// Then the GENUINE, delayed ρ1 flood (P→X, `old_state = P`) reaches node 4:
/// same seq, different state, attested, authored, `old_state ==
/// previous_state(R)` — check-3's predicate on an honest chain. Nobody may
/// ban R, anywhere, by any path.
/// STATUS: RED until 2026-09-30 (`#[ignore]`d) — check-3 banned honest R on
/// `SeqFork` evidence, flipped its head Banned, flooded `SeqForkBan`, and the
/// Banned status spread to every peer by AE (`superseded_by` rank rule). The
/// record detector bans nobody. GREEN since W2 (check-3 deleted, §9o [R56]).
/// MUTATION (run 2026-09-30, W2): re-add the check-3 ban branch ⇒ RED.
#[test]
fn fork_retire_proof_b_honest_redeem_chain_ae_jump_then_replayed_flood_no_ban() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    let seed = 0xB7u8;
    let r_pk = pk_of(seed);
    let victim = 4usize;
    let (mut m, rho0, rho1, rho2) = honest_chain(seed);
    let (p, x) = (rho0.new_state, rho1.new_state);

    let seq_fork_bans = Rc::new(Cell::new(0u64));
    let shed: Rc<RefCell<Vec<Envelope>>> = Rc::new(RefCell::new(Vec::new()));
    {
        let (c, s, t1, t2) = (seq_fork_bans.clone(), shed.clone(), rho1.tx_hash, rho2.tx_hash);
        m.set_filter(move |env| {
            if matches!(env.msg, GossipMessage::SeqForkBan { .. }) {
                c.set(c.get() + 1);
            }
            if env.to == victim && (is_update_of(&env.msg, &t1) || is_update_of(&env.msg, &t2)) {
                s.borrow_mut().push(env.clone());
                Fate::Drop
            } else {
                Fate::Deliver
            }
        });
    }
    m.register_at(0, &rho1).expect("ρ1 at door 0");
    m.run_until_quiet();
    m.register_at(1, &rho2).expect("ρ2 at door 1");
    m.run_until_quiet();
    for i in 0..victim {
        assert_eq!(m.node(i).smt().get(&r_pk).map(|e| e.current_state), Some(rho2.new_state), "node {i} at H");
    }
    assert_eq!(m.node(victim).smt().get(&r_pk).map(|e| e.current_state), Some(p), "victim still at P");

    m.ae_pull_heads_only(victim, 0);
    {
        let v = m.node(victim);
        assert_eq!(v.smt().get(&r_pk).map(|e| e.current_state), Some(rho2.new_state), "victim jumped P → H by AE");
        assert_eq!(v.smt().previous_state(&r_pk), Some(p),
            "fixture: previous_state = the overwritten head P, not ρ2's parent X");
        assert_ne!(Some(x), v.smt().previous_state(&r_pk));
        assert!(!v.is_banned(&r_pk), "fixture: honest R not banned after the AE jump");
    }

    // The genuine ρ1 flood (from its door), delivered late.
    let replay = shed.borrow().iter().find(|e| is_update_of(&e.msg, &rho1.tx_hash)).cloned()
        .expect("a shed ρ1 flood to the victim");
    let GossipMessage::StateUpdate { old_state, .. } = &replay.msg else { unreachable!() };
    assert_eq!(*old_state, p, "fixture: ρ1's genuine flood names parent P");
    m.set_filter({
        let c = seq_fork_bans.clone();
        move |env| {
            if matches!(env.msg, GossipMessage::SeqForkBan { .. }) {
                c.set(c.get() + 1);
            }
            Fate::Deliver
        }
    });
    let action = deliver_observed(&mut m, &replay);
    eprintln!("[B] victim node {victim} answered the replayed honest ρ1 flood with {}", action_name(&action));
    m.run_until_quiet();
    let n = seq_fork_bans.get();
    assert_no_false_ban(&mut m, &r_pk, victim, n, "B (AE jump + replayed flood)");
}

/// fork_retire_proof B2 — the SAME honest chain, NO anti-entropy: plain flood
/// REORDERING. ρ1's floods to node 4 are delayed; ρ2 (X→H) reaches node 4
/// first and wins the same-seq merge by tick over P, so `previous_state(R)`
/// becomes P; ρ1 (P→X) then lands. Same predicate as B on an ordinary
/// out-of-order delivery. Nobody may ban R.
/// STATUS: RED exactly as B until 2026-09-30 (no AE needed to reach the ban);
/// GREEN since W2 (check-3 deleted, §9o [R56]).
/// MUTATION (run 2026-09-30, W2): re-add the check-3 ban branch ⇒ RED.
#[test]
fn fork_retire_proof_b2_honest_redeem_chain_flood_reorder_no_ban() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    let seed = 0xB9u8;
    let r_pk = pk_of(seed);
    let victim = 4usize;
    let (mut m, rho0, rho1, rho2) = honest_chain(seed);
    let p = rho0.new_state;

    let seq_fork_bans = Rc::new(Cell::new(0u64));
    let late: Rc<RefCell<Vec<Envelope>>> = Rc::new(RefCell::new(Vec::new()));
    {
        let (c, l, t1) = (seq_fork_bans.clone(), late.clone(), rho1.tx_hash);
        m.set_filter(move |env| {
            if matches!(env.msg, GossipMessage::SeqForkBan { .. }) {
                c.set(c.get() + 1);
            }
            if env.to == victim && is_update_of(&env.msg, &t1) {
                l.borrow_mut().push(env.clone());
                Fate::Drop // held; delivered by hand after ρ2 (a delay)
            } else {
                Fate::Deliver
            }
        });
    }
    m.register_at(0, &rho1).expect("ρ1 at door 0");
    m.run_until_quiet();
    m.register_at(1, &rho2).expect("ρ2 at door 1");
    m.run_until_quiet();
    {
        let v = m.node(victim);
        assert_eq!(v.smt().get(&r_pk).map(|e| e.current_state), Some(rho2.new_state),
            "victim adopted H from ρ2's flood while at P");
        assert_eq!(v.smt().previous_state(&r_pk), Some(p), "fixture: previous_state = P (overwritten head)");
        assert!(!v.is_banned(&r_pk));
    }
    let first = late.borrow().first().cloned().expect("a delayed ρ1 flood to the victim");
    let action = deliver_observed(&mut m, &first);
    eprintln!("[B2] victim node {victim} answered the late honest ρ1 flood with {}", action_name(&action));
    let n = seq_fork_bans.get();
    assert_no_false_ban(&mut m, &r_pk, victim, n, "B2 (flood reorder)");
}

/// fork_retire_proof C — a GENUINE redeem fork whose sibling legs meet ONLY at
/// nodes that have JUMPED their head (the one shape where check-3 can fire and
/// the record detector cannot see the pair locally).
///
/// R (at P everywhere via ρ0) forks: ρ1 = P→X (cheque c1) at door 0 and ρ2 =
/// P→Y (cheque c2) at door 1; each branch continues at its own door with a
/// same-seq redeem (ρ4 = X→Z at door 0, ρ3 = Y→H at door 1), so NEITHER fork
/// leg is a head anywhere afterwards and AE (which carries heads) can never
/// carry it. Loss model (persistent, per message): every flood of ρ2/ρ3/ρ4 is
/// shed; ρ1's flood never reaches node 1. Nodes 2–4 jump P→H by one AE pull
/// from node 1 (`previous_state(R) = P`), THEN receive ρ1's door flood —
/// check-3's predicate, a TRUE positive this time. Then convergence: 3 passes
/// of AE (heads + carried `fork_bans`) over every ordered pair, with every
/// queued flood / `ForkBan` delivered between passes.
///
/// Asserts R ends BANNED on every node — in its BanTable, on VERIFIED `Fork`
/// evidence, with both legs under (R, P) (the safety property check-3
/// retirement must not lose). The per-node table is printed.
/// ~~Record-AE (design R48) — the carrier that would bring ρ1 and ρ2 together —
/// is NOT built~~ — BUILT 2026-09-30 (W1, §9o [R58]): every convergence pass
/// now also runs `Mesh::record_ae` over every ordered pair, and the test
/// asserts BOTH legs under (R, P) and BanTable evidence (`Fork` or, while
/// check-3 lives, `SeqFork`) on EVERY node — status-only no longer counts.
///
/// Two orderings (the forker picks its timing):
/// - `_rho1_wins_merge`: all four legs in ONE round (equal ticks); at the
///   jumped nodes ρ1 (X) wins the same-seq merge tiebreak over H, becomes a
///   HEAD there, and AE carries it to node 1 (holder of ρ2).
/// - `_rho1_loses_merge`: the Y branch (ρ2, ρ3) one round LATER, so H beats X
///   by tick everywhere; ρ1 is never a head after node 0 advances to ρ4.
///
/// RESULTS (2026-09-30). Check-3 ENABLED: both GREEN — nodes 2–4 ban on
/// `SeqFork` evidence, nodes 0/1 only via the AE-merged Banned SMT status
/// (their BanTables stay empty); no node ever holds both legs. Check-3
/// DISABLED (`if false && …`): `_rho1_wins_merge` GREEN (ρ1 rides AE as a
/// head to node 1 → record-detector `Fork` verdict → converges everywhere);
/// `_rho1_loses_merge` RED — the fork is banned NOWHERE (every node Normal,
/// one leg under (R, P) each). Check-3 is the ONLY detector for that shape
/// until record-AE (R48) carries non-head legs.
/// RESULTS WITH W1 (2026-09-30, run): check-3 ENABLED — both GREEN; nodes 2–4
/// keep `SeqFork` evidence (write-once), nodes 0/1 now `Fork(record)`, both
/// legs on all 5. Check-3 DISABLED — both GREEN with `Fork(record)` on ALL 5
/// nodes and 0 `SeqForkBan` (W2's precondition). MUTATION (run): drop the
/// `m.record_ae(i, j)` pass ⇒ both RED (one leg per node).
/// W2 AS BUILT (2026-09-30): check-3 DELETED (§9o [R56]); the assertions are
/// tightened to the retired world — BanTable `Fork(record)` on ALL 5 nodes
/// (a `SeqFork` ban or a status-only "ban" is a failure) and 0 `SeqForkBan`
/// envelopes. MUTATION (run 2026-09-30, W2): drop the `m.record_ae(i, j)`
/// pass ⇒ `_rho1_loses_merge` RED ("genuine fork NOT banned on node(s)
/// [0, 1, 2, 3, 4]"); `_rho1_wins_merge` stays GREEN — ρ1 is a HEAD at the
/// jumped nodes and head-AE carries it (as it did with check-3 disabled
/// before W1). `_rho1_loses_merge` is the shape record-AE exists for.
#[test]
fn fork_retire_proof_c_genuine_fork_seen_only_after_jump_rho1_wins_merge() {
    fork_seen_only_after_jump(0xC7, false);
}

#[test]
fn fork_retire_proof_c_genuine_fork_seen_only_after_jump_rho1_loses_merge() {
    fork_seen_only_after_jump(0xC9, true);
}

fn fork_seen_only_after_jump(seed: u8, y_branch_later: bool) {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    let sk = test_legs::wallet(seed);
    let r_pk = pk_of(seed);
    let mut m = Mesh::new(N);
    let rho0 = test_legs::genuine_redeem_leg(&sk, test_legs::opening(&sk), &crate::types::test_legs::stray_origin([0xC0; 32]), 1_000, 1, 3);
    let p = rho0.new_state;
    m.register_at(0, &rho0).expect("ρ0");
    m.run_until_quiet();
    let rho1 = test_legs::genuine_redeem_leg(&sk, p, &crate::types::test_legs::stray_origin([0xC1; 32]), 2_000, 1, 3);
    let rho2 = test_legs::genuine_redeem_leg(&sk, p, &crate::types::test_legs::stray_origin([0xC2; 32]), 3_000, 1, 3);
    let rho3 = test_legs::genuine_redeem_leg(&sk, rho2.new_state, &crate::types::test_legs::stray_origin([0xC3; 32]), 4_000, 1, 3);
    let rho4 = test_legs::genuine_redeem_leg(&sk, rho1.new_state, &crate::types::test_legs::stray_origin([0xC4; 32]), 5_000, 1, 3);
    let claim = ForkClaim { a: rho1.clone(), b: rho2.clone() };
    assert_eq!(crate::ban::verify_fork_claim(&claim), Ok(()), "fixture: ρ1/ρ2 IS a genuine fork");

    let seq_fork_bans = Rc::new(Cell::new(0u64));
    let late1: Rc<RefCell<Vec<Envelope>>> = Rc::new(RefCell::new(Vec::new()));
    {
        let (c, l) = (seq_fork_bans.clone(), late1.clone());
        let (t1, t2, t3, t4) = (rho1.tx_hash, rho2.tx_hash, rho3.tx_hash, rho4.tx_hash);
        m.set_filter(move |env| {
            if matches!(env.msg, GossipMessage::SeqForkBan { .. }) {
                c.set(c.get() + 1);
            }
            let m = &env.msg;
            if is_update_of(m, &t2) || is_update_of(m, &t3) || is_update_of(m, &t4) {
                Fate::Drop
            } else if is_update_of(m, &t1) && env.to == 1 {
                Fate::Drop
            } else if is_update_of(m, &t1) && env.from == 0 {
                l.borrow_mut().push(env.clone()); // door flood: delivered after the jump
                Fate::Drop
            } else {
                Fate::Deliver
            }
        });
    }
    m.register_at(0, &rho1).expect("ρ1 at door 0");
    m.register_at(0, &rho4).expect("ρ4 continues X at door 0");
    if y_branch_later {
        m.round += 1; // one hop later: the Y branch's tick is higher
    }
    m.register_at(1, &rho2).expect("ρ2 at door 1 (never saw ρ1)");
    m.register_at(1, &rho3).expect("ρ3 continues Y at door 1");
    m.run_until_quiet();
    for i in [2usize, 3, 4] {
        m.ae_pull_heads_only(i, 1);
        let v = m.node(i);
        assert_eq!(v.smt().get(&r_pk).map(|e| e.current_state), Some(rho3.new_state), "node {i} jumped P → H");
        assert_eq!(v.smt().previous_state(&r_pk), Some(p), "node {i}: previous_state = P (jump)");
    }
    let door_floods: Vec<Envelope> = late1.borrow().clone();
    assert_eq!(door_floods.len(), 3, "ρ1's door flood to nodes 2..4 captured");
    let mut actions = Vec::new();
    for env in &door_floods {
        let a = deliver_observed(&mut m, env);
        actions.push(format!("node {} ← ρ1: {}", env.to, action_name(&a)));
    }
    m.run_until_quiet();
    for _pass in 0..3 {
        for i in 0..N {
            for j in 0..N {
                if i != j {
                    m.ae_pull(i, j);
                    // W1 (§9o [R58]) — R48 record-AE beside head AE: the carrier
                    // that brings ρ1 and ρ2 (non-heads) together.
                    m.record_ae(i, j);
                }
            }
        }
        m.run_until_quiet();
    }
    let mut table = Vec::new();
    let mut unbanned = Vec::new();
    let mut no_evidence = Vec::new();
    let mut missing_legs = Vec::new();
    for i in m.up() {
        let n = m.node(i);
        let ev = match n.bans().get(&r_pk).map(|b| &b.evidence) {
            Some(BanEvidence::Fork(c)) => {
                crate::ban::verify_fork_claim(c).expect("a Fork ban's claim verifies");
                "Fork(record)"
            }
            Some(BanEvidence::SeqFork(_)) => "SeqFork(check-3)",
            Some(_) => "other",
            None => "-",
        };
        let status = n.smt().get(&r_pk).map(|e| e.status);
        let legs = n.smt().legs_under(&(r_pk, p)).len();
        table.push(format!("node {i}: bantable={ev} smt_status={status:?} legs_under(R,P)={legs}"));
        if !n.is_banned(&r_pk) {
            unbanned.push(i);
        }
        if ev != "Fork(record)" {
            no_evidence.push(i);
        }
        if legs != 2 {
            missing_legs.push(i);
        }
    }
    eprintln!("[C y_later={y_branch_later}] {}\n[C] SeqForkBan envelopes={}\n[C] {}", actions.join("; "), seq_fork_bans.get(), table.join("\n[C] "));
    assert!(unbanned.is_empty(),
        "C (y_branch_later={y_branch_later}): genuine fork NOT banned on node(s) {unbanned:?} after convergence —\n  {}", table.join("\n  "));
    // W1 — record-AE brings BOTH legs to every node, so every BanTable holds
    // fork EVIDENCE (status-only no longer counts). W2 — check-3 is gone, so
    // every node's evidence is `Fork(record)` and nothing emits `SeqForkBan`.
    assert!(missing_legs.is_empty(),
        "C (y_branch_later={y_branch_later}): record-AE did not bring both legs to node(s) {missing_legs:?} —\n  {}", table.join("\n  "));
    assert!(no_evidence.is_empty(),
        "C (y_branch_later={y_branch_later}): node(s) {no_evidence:?} without BanTable Fork(record) evidence —\n  {}", table.join("\n  "));
    assert_eq!(seq_fork_bans.get(), 0, "C (y_branch_later={y_branch_later}): a SeqForkBan was emitted (check-3 is retired)");
}

// ── Fork Settlement §9q — design B2: the E3 HAL revival arm retired into ATRAXI ──
//
// A HAL re-anchor X→X′ is an ordinary A1 leg (a self-send `LegPreimage::Send`
// from X, k-witnessed, wallet-signed; recorded at the door's 5b‴). Since B2 it
// floods as a plain `StateUpdate` WITH that leg (`registration.rs` step 10), so
// a revival beside a recorded spend X→Y is a `ForkClaim` under (W, X) wherever
// the two legs meet — by flood (the record hook, before any put), by head-AE,
// by `ForkBan`, or by R48 record-AE when no flood ever brings them together —
// and `ban::apply_fork_verdict` bans W permanently on evidence. `HalAdvance` is
// a dropped, counted tombstone; `previous_states` judges nothing.
//
// The filters below match a wallet's flood by txid in BOTH carriers (the
// pre-B2 `HalAdvance` too) so each test runs unchanged against a pre-B2 build
// — that is how the mutations below were run.

/// The B2 fork fixture: wallet W at X on every node (its first leg, flooded
/// everywhere); the spend X→Y; the HAL re-anchor X→X′ (a SELF-send, the
/// overlap-relaxed re-activation, YPX-020); each branch's continuation — Y→Y2
/// (a send) and the HAL completion X′→Z (the self-redeem of the re-anchor's
/// own cheque, YPX-020 §2) — so, as in `fork_retire_proof_c_*`, neither fork
/// leg stays a head where it was registered.
struct HalFork {
    w: WalletId,
    x: StateId,
    spend: ForkLeg,
    hal: ForkLeg,
    y2: ForkLeg,
    done: ForkLeg,
}

fn hal_fork(m: &mut Mesh, seed: u8) -> HalFork {
    let sk = test_legs::wallet(seed);
    let first = test_legs::genuine_send_leg(&sk, test_legs::opening(&sk), 1, RECV_P, 10, 1, 3);
    m.register_at(0, &first).expect("W's first leg");
    m.run_until_quiet();
    let x = first.new_state;
    let own = format!("h{seed:02x}@axiom.internal/0123456789");
    let spend = test_legs::genuine_send_leg(&sk, x, 2, RECV_Q, 20, 2, 3);
    let hal = test_legs::genuine_send_leg(&sk, x, 2, &own, 1, 3, 3);
    let y2 = test_legs::genuine_send_leg(&sk, spend.new_state, 3, RECV_R, 5, 4, 3);
    let done = test_legs::genuine_redeem_leg(&sk, hal.new_state, &crate::types::test_legs::origin_of(&hal), 7_000, 2, 3);
    assert_eq!(crate::ban::verify_fork_claim(&ForkClaim { a: spend.clone(), b: hal.clone() }), Ok(()),
        "fixture: X→Y / X→X′ IS an A1 fork (one key, one parent, two txids)");
    for i in m.up() {
        assert_eq!(m.node(i).smt().get(&pk_of(seed)).map(|e| e.current_state), Some(x), "fixture: node {i} at X");
    }
    HalFork { w: pk_of(seed), x, spend, hal, y2, done }
}

/// A HAL re-anchor at `door` (the registration's `is_hal_reanchor` flag — the
/// door's check 1, 6c class check and hibernation stamp all run).
fn register_hal(m: &mut Mesh, door: usize, leg: &ForkLeg) -> Result<(), crate::types::NablaError> {
    let (mut reg, deed) = test_legs::registration_of(leg);
    reg.is_hal_reanchor = true;
    m.register_raw(door, &reg, &deed)
}

/// A wallet-state flood of `txid` in either carrier (B2 `StateUpdate`, or the
/// pre-B2 `HalAdvance` a mutation run emits).
fn is_flood_of(msg: &GossipMessage, txid: &TxHash) -> bool {
    match msg {
        GossipMessage::HalAdvance { tx_hash, .. } => tx_hash == txid,
        _ => is_update_of(msg, txid),
    }
}

/// Three passes of head-AE (+ its carried `fork_bans`) and, when `record_ae`,
/// R48 record-AE over every ordered pair, with every queued flood / `ForkBan`
/// delivered between passes (the `fork_retire_proof_c_*` convergence).
fn converge(m: &mut Mesh, record_ae: bool) {
    for _pass in 0..3 {
        for i in 0..m.n() {
            for j in 0..m.n() {
                if i != j {
                    m.ae_pull(i, j);
                    if record_ae {
                        m.record_ae(i, j);
                    }
                }
            }
        }
        m.run_until_quiet();
    }
}

/// Every live node: W BANNED on a verified `Fork` claim naming the spend and
/// the HAL leg, both legs under (W, X), W never `Frozen` (a local hold is not
/// a verdict), nobody else banned; then `assert_fork_banned_everywhere`'s
/// money checks (no leg vouchable, Core never settles either leg).
fn assert_hal_fork_banned_on_evidence(m: &mut Mesh, f: &HalFork, label: &str) {
    let mut table = Vec::new();
    let mut bad = Vec::new();
    for i in m.up() {
        let n = m.node(i);
        let legs = n.smt().legs_under(&(f.w, f.x)).len();
        let status = n.smt().get(&f.w).map(|e| e.status);
        let st = n.origin_status(None, 0);
        table.push(format!(
            "node {i}: banned={} legs_under(W,X)={legs} status={status:?} detected={} adopted={} record_ae_legs_recorded={}",
            n.is_banned(&f.w), st.origin_fork_claims_detected, st.origin_fork_claims_adopted, st.record_ae_legs_recorded,
        ));
        if !n.is_banned(&f.w) || legs != 2 || status == Some(WalletStatus::Frozen) || n.bans().len() != 1 {
            bad.push(i);
        }
    }
    eprintln!("[{label}]\n  {}", table.join("\n  "));
    assert!(bad.is_empty(), "{label}: node(s) {bad:?} not banned on both legs (or Frozen / another wallet banned) —\n  {}",
        table.join("\n  "));
    assert_fork_banned_everywhere(m, &f.w, &[&f.spend, &f.hal], label);
}

/// B2 (a) — a HAL revival fork whose floods are ALL LOST. X→Y (then Y→Y2) at
/// door 0, the HAL X→X′ (then its completion X′→Z) at door 1, which never saw
/// Y; every flood of all four legs is shed. No node holds both fork legs after
/// the registers and neither fork leg is a head anywhere. With the E3 arm
/// DELETED, R48 record-AE brings the door-recorded legs together and every
/// node bans W on `Fork` evidence (verified claim, both legs under (W, X)).
/// MUTATION (run 2026-09-30): drop the `m.record_ae(i, j)` pass
/// (`converge(&mut m, false)`) ⇒ RED at "not banned on both legs" — banned on
/// NO node; legs under (W, X): nodes 0/1 one each, nodes 2–4 none (head-AE
/// carries only the heads Y2 / Z). Against the
/// PRE-B2 build (E3 in place) the test is GREEN too: the floods are lost, so
/// the E3 arm never ran — record-AE (W1) is what bans, and E3 contributed
/// nothing to this shape.
#[test]
fn b2_a_hal_revival_fork_floods_lost_banned_everywhere_by_record_ae() {
    let mut m = Mesh::new(N);
    let f = hal_fork(&mut m, 0xE1);
    let lost = [f.spend.tx_hash, f.hal.tx_hash, f.y2.tx_hash, f.done.tx_hash];
    m.set_filter(move |e| if lost.iter().any(|t| is_flood_of(&e.msg, t)) { Fate::Drop } else { Fate::Deliver });
    m.register_at(0, &f.spend).expect("X→Y at door 0");
    m.register_at(0, &f.y2).expect("Y→Y2 continues the spend branch at door 0");
    register_hal(&mut m, 1, &f.hal).expect("HAL X→X′ at door 1 (it never saw Y)");
    m.register_at(1, &f.done).expect("the HAL completion X′→Z at door 1");
    m.run_until_quiet();
    for i in m.up() {
        let n = m.node(i);
        assert!(n.smt().legs_under(&(f.w, f.x)).len() <= 1, "fixture: node {i} already holds both fork legs");
        assert!(!n.is_banned(&f.w), "fixture: node {i} banned before any exchange");
    }
    converge(&mut m, true);
    assert_hal_fork_banned_on_evidence(&mut m, &f, "B2-a lost floods");
}

/// B2 (a′) — the E3 shape itself: the HAL leg's flood REACHES the nodes that
/// recorded X→Y (0, 2, 3, 4; node 1 missed Y and takes the re-anchor). Every
/// holder answers the HAL flood with its record hook BEFORE any put: it bans W
/// on the spot on `Fork` evidence and NEVER adopts X′ as its head (asserted
/// after every delivery round) — what E3 claimed to do by freezing, now on
/// evidence every node can verify; the door (node 1) is banned by the
/// holders' `ForkBan`. No AE, no record-AE.
/// The PRE-B2 E3 arm, measured with this exact shape (the §9q probe, run
/// 2026-09-30 on `82e5495c`): 0 of 4 holders froze — the door stamped
/// `HalAdvance.tick = current_tick` and E3 verified the k3 sigs over it,
/// while Lambda signs tick 0, so a genuine revival never verified (4 of 4
/// froze once the probe aligned the tick).
/// MUTATIONS (run 2026-09-30): emit the pre-B2 `HalAdvance` at the door
/// (registration step 10) ⇒ RED at "node 0: W banned on arrival" (the
/// tombstone drops it; nobody detects); skip the flood record hook in
/// `apply_state_update` ⇒ RED at "node N ADOPTED the revived head X′" (the
/// attested HAL leg wins the same-seq merge — the record hook, not the merge,
/// is what keeps X′ out). The whole PRE-B2 build, as shipped and with E3's
/// tick defect fixed ⇒ RED at "node 0: W banned on arrival" both ways.
#[test]
fn b2_a2_hal_revival_flood_meets_recorded_spend_banned_on_arrival_never_adopted() {
    let mut m = Mesh::new(N);
    let f = hal_fork(&mut m, 0xE2);
    let t_spend = f.spend.tx_hash;
    m.set_filter(move |e| if is_flood_of(&e.msg, &t_spend) && e.to == 1 { Fate::Drop } else { Fate::Deliver });
    m.register_at(0, &f.spend).expect("X→Y at door 0");
    m.run_until_quiet();
    for i in [0usize, 2, 3, 4] {
        assert_eq!(m.node(i).smt().get(&f.w).map(|e| e.current_state), Some(f.spend.new_state), "fixture: node {i} at Y");
    }
    register_hal(&mut m, 1, &f.hal).expect("HAL X→X′ at door 1 (it never saw Y)");
    let start = m.round;
    while !m.queue.is_empty() {
        assert!(m.round - start < MAX_ROUNDS, "mesh did not quiesce");
        m.step();
        for i in [0usize, 2, 3, 4] {
            assert_ne!(m.node(i).smt().get(&f.w).map(|e| e.current_state), Some(f.hal.new_state),
                "node {i} ADOPTED the revived head X′ (round {})", m.round);
        }
    }
    for i in [0usize, 2, 3, 4] {
        assert!(m.node(i).is_banned(&f.w), "node {i}: W banned on arrival of the HAL leg");
        assert!(m.node(i).bans().origin_fork_claims_detected() >= 1, "node {i}: detected LOCALLY (flood record hook)");
    }
    assert_hal_fork_banned_on_evidence(&mut m, &f, "B2-a′ flood meets the recorded spend");
}

/// B2 (b) — the HAL gossip never reaches most nodes: X→Y's flood reaches node
/// 3 only, the HAL leg's flood node 2 only, both continuations' floods are
/// lost. Node 4 never sees either fork leg by flood; nodes 0/3 and 1/2 each
/// hold one. Before B2 the E3 arm ran only where a `HalAdvance` arrived, so
/// nodes it never reached could not act. Now every node — including the ones
/// the HAL gossip never reached — ends with W banned on verified `Fork`
/// evidence (by head-AE of the X′ head, the carried `fork_bans`, `ForkBan`
/// floods and record-AE; the table prints which node detected locally and
/// which adopted a verified claim).
/// MUTATION (run 2026-09-30): make `apply_fork_verdict` refuse every claim
/// (`verify_fork_claim(claim).and(Err::<(), _>(ForkClaimRefusal::SameTxHash))`)
/// ⇒ RED at "not banned on both legs": BOTH legs reach all 5 nodes and none
/// bans — the ONE verdict path is the only way W is banned. GREEN against the
/// pre-B2 build (E3 never verified a genuine revival there; head-AE +
/// record-AE did the work).
#[test]
fn b2_b_hal_gossip_reaches_only_some_nodes_banned_everywhere() {
    let mut m = Mesh::new(N);
    let f = hal_fork(&mut m, 0xE3);
    let (t_spend, t_hal) = (f.spend.tx_hash, f.hal.tx_hash);
    let lost = [f.y2.tx_hash, f.done.tx_hash];
    m.set_filter(move |e| {
        if is_flood_of(&e.msg, &t_spend) {
            if e.to == 3 { Fate::Deliver } else { Fate::Drop }
        } else if is_flood_of(&e.msg, &t_hal) {
            if e.to == 2 { Fate::Deliver } else { Fate::Drop }
        } else if lost.iter().any(|t| is_flood_of(&e.msg, t)) {
            Fate::Drop
        } else {
            Fate::Deliver
        }
    });
    m.register_at(0, &f.spend).expect("X→Y at door 0");
    m.register_at(0, &f.y2).expect("Y→Y2 at door 0");
    register_hal(&mut m, 1, &f.hal).expect("HAL X→X′ at door 1");
    m.register_at(1, &f.done).expect("HAL completion X′→Z at door 1");
    m.run_until_quiet();
    assert_eq!(m.node(4).smt().legs_under(&(f.w, f.x)).len(), 0, "fixture: node 4 saw neither fork leg");
    for i in m.up() {
        assert!(!m.node(i).is_banned(&f.w), "fixture: node {i} banned before any exchange");
    }
    converge(&mut m, true);
    assert_hal_fork_banned_on_evidence(&mut m, &f, "B2-b partial HAL gossip");
}

/// B2 (c) — an HONEST HAL re-anchor of a dead-overlap wallet bans and freezes
/// NOBODY, including in the shape E3's predicate fires on: W at X everywhere;
/// the re-anchor X→X′ and its completion X′→Z at door 0; node 4 misses both
/// floods, JUMPS X→Z by one head-AE pull (so `previous_state(W) = X`, the head
/// the jump overwrote — KI#235's marker), THEN the genuine late HAL flood
/// (old_state X, new_state X′ ≠ its head Z) arrives: `held_current !=
/// new_state ∧ previous_state == old_state` — E3's conflict predicate, TRUE on
/// an honest chain. Then head-AE + record-AE over every pair. Nobody banned,
/// nobody frozen or blocked, no BanTable entry anywhere, every node at Z and
/// holding the HAL leg.
/// MUTATION (run 2026-09-30, against the PRE-B2 build with the E3 tick defect
/// FIXED — `HalAdvance.tick = reg.receipt.tick` at the door, so E3's k3 verify
/// passes as its authors intended): RED at "node 4: honest W status not
/// Normal" — node 4 FREEZES honest W. E3 working as designed is a KI#235-class
/// false hold; only the ghost (the tick defect) hid it (GREEN on the pre-B2
/// build as shipped).
#[test]
fn b2_c_honest_hal_reanchor_learned_by_jump_bans_and_freezes_nobody() {
    use std::cell::RefCell;
    use std::rc::Rc;
    let seed = 0xE4u8;
    let sk = test_legs::wallet(seed);
    let w = pk_of(seed);
    let victim = 4usize;
    let mut m = Mesh::new(N);
    let first = test_legs::genuine_send_leg(&sk, test_legs::opening(&sk), 1, RECV_P, 10, 1, 3);
    m.register_at(0, &first).expect("W's first leg");
    m.run_until_quiet();
    let x = first.new_state;
    let hal = test_legs::genuine_send_leg(&sk, x, 2, "h-e4@axiom.internal/0123456789", 1, 3, 3);
    let done = test_legs::genuine_redeem_leg(&sk, hal.new_state, &crate::types::test_legs::origin_of(&hal), 7_000, 2, 3);
    let held: Rc<RefCell<Vec<Envelope>>> = Rc::new(RefCell::new(Vec::new()));
    {
        let (h, t_hal, t_done) = (held.clone(), hal.tx_hash, done.tx_hash);
        m.set_filter(move |e| {
            if e.to == victim && is_flood_of(&e.msg, &t_hal) {
                h.borrow_mut().push(e.clone());
                Fate::Drop
            } else if e.to == victim && is_flood_of(&e.msg, &t_done) {
                Fate::Drop
            } else {
                Fate::Deliver
            }
        });
    }
    register_hal(&mut m, 0, &hal).expect("honest HAL re-anchor X→X′ at door 0");
    m.run_until_quiet();
    m.register_at(0, &done).expect("the HAL completion X′→Z at door 0");
    m.run_until_quiet();
    for i in 0..victim {
        assert_eq!(m.node(i).smt().get(&w).map(|e| e.current_state), Some(done.new_state), "node {i} at Z");
    }
    m.ae_pull_heads_only(victim, 0);
    {
        let v = m.node(victim);
        assert_eq!(v.smt().get(&w).map(|e| e.current_state), Some(done.new_state), "victim jumped X → Z by AE");
        assert_eq!(v.smt().previous_state(&w), Some(x), "fixture: previous_state = X (the overwritten head)");
    }
    let late = held.borrow().first().cloned().expect("the HAL flood to node 4, held");
    let action = deliver_observed(&mut m, &late);
    eprintln!("[B2-c] node {victim} answered the late honest HAL flood with {}", action_name(&action));
    m.run_until_quiet();
    converge(&mut m, true);
    for i in m.up() {
        let n = m.node(i);
        assert!(!n.is_banned(&w), "node {i}: honest W BANNED");
        assert!(n.bans().is_empty(), "node {i}: a BanTable entry for an honest HAL");
        assert_eq!(n.smt().get(&w).map(|e| e.status), Some(WalletStatus::Normal), "node {i}: honest W status not Normal");
        assert!(!n.is_wallet_blocked(&w), "node {i}: honest W blocked");
        assert_eq!(n.smt().get(&w).map(|e| e.current_state), Some(done.new_state), "node {i}: at Z");
        assert_eq!(n.smt().legs_under(&(w, x)).len(), 1, "node {i}: the HAL leg (alone) under (W, X)");
    }
}

/// B2 (d) — KI#233: a forged `HalAdvance` (three attacker-made "witness" keys,
/// the attacker's own key as the wallet half) injected at EVERY node by a
/// party outside the mesh, beside a replay of a wallet-signed one, in the
/// exact shape E3 judged (W at Y everywhere, `previous_state(W) = X`). Every
/// node drops and COUNTS both (`haladvance_dropped`), forwards nothing, and
/// W is neither frozen, banned nor blocked; W then registers a chained leg at
/// every door.
/// MUTATION (run 2026-09-30): make the tombstone arm call
/// `TardisNode::freeze_wallet(smt, wallet_id)` ⇒ RED at "node 0: W frozen".
#[test]
fn b2_d_forged_hal_advance_freezes_and_bans_nobody() {
    use ed25519_dalek::{Signer as _, SigningKey};
    let seed = 0xE5u8;
    let sk = test_legs::wallet(seed);
    let w = pk_of(seed);
    let mut m = Mesh::new(N);
    let first = test_legs::genuine_send_leg(&sk, test_legs::opening(&sk), 1, RECV_P, 10, 1, 3);
    m.register_at(0, &first).expect("W's first leg");
    m.run_until_quiet();
    let x = first.new_state;
    let spend = test_legs::genuine_send_leg(&sk, x, 2, RECV_Q, 20, 2, 3);
    m.register_at(0, &spend).expect("X→Y");
    m.run_until_quiet();
    for i in m.up() {
        assert_eq!(m.node(i).smt().previous_state(&w), Some(x), "fixture: E3's predicate substrate at node {i}");
    }
    let tick = m.tick();
    let payload = crate::crypto::receipt_sign_payload(&w, &x, tick);
    let forged_sigs: Vec<WitnessSig> = (0..3u8)
        .map(|i| {
            let k = SigningKey::from_bytes(&[0xE0 + i; 32]);
            WitnessSig {
                validator_pk: k.verifying_key().to_bytes(),
                signature: k.sign(&payload).to_bytes().to_vec(),
                execution_proof: vec![], proof_type: 0, receipt_commitment_sig: vec![],
                validator_id: [0u8; 32], slot_amount: 0,
            }
        })
        .collect();
    let attacker = SigningKey::from_bytes(&[0xEE; 32]);
    let x2 = [0x3Cu8; 32];
    let t2 = [0x3Du8; 32];
    let forged = GossipMessage::HalAdvance {
        wallet_id: w, old_state: x, new_state: x2, tx_hash: t2, tick,
        client_pk: attacker.verifying_key().to_bytes(),
        client_sig: attacker.sign(&crate::registration::client_state_sign_payload(&w, &x2, &t2)).to_bytes().to_vec(),
        k3_signatures: forged_sigs.clone(), amount: 0, fee_breakdown: Vec::new(), required_k: 3,
    };
    // A replay of a WALLET-SIGNED revival (W's genuine HAL leg, its client sig
    // copied from a flood) — the shape E3 froze when its sigs verified.
    let hal = test_legs::genuine_send_leg(&sk, x, 2, "h-e5@axiom.internal/0123456789", 1, 3, 3);
    let replayed = GossipMessage::HalAdvance {
        wallet_id: w, old_state: x, new_state: hal.new_state, tx_hash: hal.tx_hash, tick,
        client_pk: w, client_sig: hal.client_sig.clone(),
        k3_signatures: forged_sigs, amount: 0, fee_breakdown: Vec::new(), required_k: 3,
    };
    m.inject_everywhere(forged);
    m.inject_everywhere(replayed);
    m.run_until_quiet();
    for i in m.up() {
        let n = m.node(i);
        assert_eq!(n.gossip().haladvance_dropped(), 2, "node {i}: both HalAdvances dropped + COUNTED");
        assert_eq!(n.origin_status(None, 0).haladvance_dropped, 2, "node {i}: the count reaches /status");
        assert_ne!(n.smt().get(&w).map(|e| e.status), Some(WalletStatus::Frozen), "node {i}: W frozen");
        assert_eq!(n.smt().get(&w).map(|e| e.status), Some(WalletStatus::Normal), "node {i}: W not Normal");
        assert!(!n.is_banned(&w) && !n.is_wallet_blocked(&w), "node {i}: W banned / blocked");
        assert_eq!(n.smt().get(&w).map(|e| e.current_state), Some(spend.new_state), "node {i}: head moved");
    }
    let mut prev = spend.new_state;
    for (k, door) in m.up().into_iter().enumerate() {
        let next = test_legs::genuine_send_leg(&sk, prev, 3 + k as u64, RECV_P, 1, 10 + k as u64, 3);
        m.register_at(door, &next).unwrap_or_else(|e| panic!("door {door}: W's chained leg refused: {e:?}"));
        m.run_until_quiet();
        prev = next.new_state;
    }
    assert!(m.up().iter().all(|i| !m.node(*i).is_banned(&w)), "W banned after its chained legs");
}

// ── ForkSettlement §9r-E4 — the §32 SCAN retired into ATRAXI A1 + A5 ─────────
//
// Owner ruling 2026-10-01: a fork is judged only by A1 self-proving evidence; a
// downstream hold only by A5 derived from the node's own graph; a view
// disagreement does nothing. The SCAN (`detect_forked_wallets` →
// `handle_fork_evidence` → Frozen + TaintAlert), the `TaintAlert` taint arm and
// the 75 s quarantine timer are deleted / tombstoned. These four gates prove
// the ruled behaviour on the live machinery that remains.

/// Every leaf status on node `i` that is a VIEW-based hold (`Frozen` /
/// `Tainted`) — production has no writer of either since E4.
fn view_holds(n: &NablaNode) -> Vec<(WalletId, WalletStatus)> {
    n.smt().entries().values()
        .filter(|e| matches!(e.status, WalletStatus::Frozen | WalletStatus::Tainted))
        .map(|e| (e.wallet_id, e.status))
        .collect()
}

/// E4-a — HONEST view disagreements hold nobody. One mesh, two honest wallets
/// in the two shapes where a node's held head differs from what arrives:
/// R's same-seq redeem chain with ρ1's flood to node 4 REORDERED behind ρ2's
/// (the `fork_retire_proof_b2_*` shape), and W's honest HAL re-anchor that
/// node 4 learns by an AE JUMP before the late HAL flood lands (the `b2_c_*`
/// shape). Then head-AE + record-AE over every pair. On every node: no leaf
/// `Frozen` / `Tainted`, neither wallet blocked, NO ban at all, and one root.
/// MUTATION (run 2026-10-02): in `NablaNode::handle_gossip`, before
/// `process`, write `Frozen` on a `StateUpdate`'s wallet whenever the held
/// head ≠ the incoming `new_state` (the SCAN's view rule placed at a live
/// point) ⇒ RED at "node 0: a view-based hold".
#[test]
fn e4_a_honest_lag_reorder_and_hal_jump_hold_nobody() {
    use std::cell::RefCell;
    use std::rc::Rc;
    let victim = 4usize;
    // R — the B2 honest chain (opening → P → X → H, same seq).
    let r_seed = 0xA4u8;
    let r_pk = pk_of(r_seed);
    let (mut m, _rho0, rho1, rho2) = honest_chain(r_seed);
    // W — opening → X_w at every node.
    let w_seed = 0xA5u8;
    let w_sk = test_legs::wallet(w_seed);
    let w = pk_of(w_seed);
    let first = test_legs::genuine_send_leg(&w_sk, test_legs::opening(&w_sk), 1, RECV_P, 10, 1, 3);
    m.register_at(0, &first).expect("W's first leg");
    m.run_until_quiet();
    let hal = test_legs::genuine_send_leg(&w_sk, first.new_state, 2, "h-a5@axiom.internal/0123456789", 1, 3, 3);
    let done = test_legs::genuine_redeem_leg(&w_sk, hal.new_state, &crate::types::test_legs::origin_of(&hal), 7_000, 2, 3);
    let late: Rc<RefCell<Vec<Envelope>>> = Rc::new(RefCell::new(Vec::new()));
    {
        let (l, t_rho1, t_hal, t_done) = (late.clone(), rho1.tx_hash, hal.tx_hash, done.tx_hash);
        m.set_filter(move |e| {
            if e.to == victim && (is_update_of(&e.msg, &t_rho1) || is_flood_of(&e.msg, &t_hal)) {
                l.borrow_mut().push(e.clone());
                Fate::Drop // held; delivered by hand LATE
            } else if e.to == victim && is_flood_of(&e.msg, &t_done) {
                Fate::Drop // node 4 learns Z only by the AE jump
            } else {
                Fate::Deliver
            }
        });
    }
    m.register_at(0, &rho1).expect("ρ1 at door 0");
    m.run_until_quiet();
    m.register_at(1, &rho2).expect("ρ2 at door 1");
    m.run_until_quiet();
    register_hal(&mut m, 0, &hal).expect("honest HAL re-anchor at door 0");
    m.run_until_quiet();
    m.register_at(0, &done).expect("HAL completion at door 0");
    m.run_until_quiet();
    m.ae_pull_heads_only(victim, 0);
    {
        let v = m.node(victim);
        assert_eq!(v.smt().get(&r_pk).map(|e| e.current_state), Some(rho2.new_state), "fixture: node 4 at H before ρ1");
        assert_eq!(v.smt().get(&w).map(|e| e.current_state), Some(done.new_state), "fixture: node 4 jumped W to Z");
    }
    let held: Vec<Envelope> = late.borrow().iter().filter(|e| e.to == victim).cloned().collect();
    assert!(held.len() >= 2, "fixture: the late ρ1 and HAL floods to node 4 were held");
    m.set_filter(|_| Fate::Deliver);
    for env in &held {
        // Each late flood's `new_state` ≠ node 4's held head — the view
        // disagreement the SCAN keyed on.
        let action = deliver_observed(&mut m, env);
        eprintln!("[E4-a] node {victim} answered a late honest flood with {}", action_name(&action));
    }
    m.run_until_quiet();
    converge(&mut m, true);
    let roots: std::collections::BTreeSet<[u8; 32]> = m.up().iter().map(|i| m.node(*i).smt().root_hash()).collect();
    for i in m.up() {
        let n = m.node(i);
        assert!(view_holds(n).is_empty(), "node {i}: a view-based hold {:?}", view_holds(n));
        assert!(!n.is_wallet_blocked(&r_pk) && !n.is_wallet_blocked(&w), "node {i}: an honest wallet blocked");
        assert!(n.bans().is_empty(), "node {i}: somebody banned on an honest view disagreement");
    }
    assert_eq!(roots.len(), 1, "E4-a: the mesh did not converge to one root: {roots:?}");
}

/// E4-b — a REAL fork, its two legs at doors 0 and 3 with partial floods
/// (each leg's flood shed to the other half of the mesh), then head-AE +
/// record-AE: every node bans W on A1 evidence (`BanEvidence::Fork` naming
/// both legs), W's leaf is `Banned` — never `Frozen` — and W is the only ban.
/// MUTATION (run 2026-10-02): `ban::apply_fork_verdict` returns before
/// applying any claim ⇒ RED at "node 0: W not banned".
#[test]
fn e4_b_real_fork_across_merge_banned_on_a1_never_frozen() {
    let seed = 0xB4u8;
    let w = pk_of(seed);
    let sk = test_legs::wallet(seed);
    let y = test_legs::opening(&sk);
    let a = leg(seed, y, RECV_P, 100, 1);
    let b = leg(seed, y, RECV_Q, 200, 2);
    let mut m = Mesh::new(N);
    {
        let (ta, tb) = (a.tx_hash, b.tx_hash);
        m.set_filter(move |e| {
            if (is_update_of(&e.msg, &ta) && e.to >= 3) || (is_update_of(&e.msg, &tb) && e.to <= 1) {
                Fate::Drop
            } else {
                Fate::Deliver
            }
        });
    }
    m.register_at(0, &a).expect("leg a at door 0");
    m.register_at(3, &b).expect("leg b at door 3");
    m.run_until_quiet();
    m.set_filter(|_| Fate::Deliver);
    converge(&mut m, true);
    for i in m.up() {
        let n = m.node(i);
        assert!(n.is_banned(&w), "node {i}: W not banned");
        match &n.bans().get(&w).expect("ban entry").evidence {
            BanEvidence::Fork(c) => {
                crate::ban::verify_fork_claim(c).unwrap_or_else(|e| panic!("node {i}: claim must verify: {e:?}"));
                let named = [c.a.tx_hash, c.b.tx_hash];
                assert!(named.contains(&a.tx_hash) && named.contains(&b.tx_hash), "node {i}: claim names both legs");
            }
            other => panic!("node {i}: W banned on non-A1 evidence {other:?}"),
        }
        assert_eq!(n.smt().get(&w).map(|e| e.status), Some(WalletStatus::Banned), "node {i}: W's leaf not Banned");
        assert!(view_holds(n).is_empty(), "node {i}: a view-based hold {:?}", view_holds(n));
        assert_eq!(n.bans().len(), 1, "node {i}: exactly one ban (W)");
    }
}

/// E4-c — the downstream of a PROVEN forker is HELD by A5, never BLOCKED by a
/// `TaintAlert`. The S10 shape: A pays M, then forks (ta at door 0, tb at
/// door 3) and is banned everywhere; Q redeems tb. A hostile party then sends
/// `TaintAlert{wallet_id: Q, tainted_source: A}` to every node. Non-vacuity:
/// on at least one node the OLD arm's exact predicate holds (A's leaf
/// `Banned` ∧ `Q.received_from == A.current_state`), read from the SMT — so
/// under the pre-E4 arm Q would have been `Tainted` and refused at the door.
/// Now, on every node: Q is `Held([tb])` by provenance and NOT blocked; the
/// alert is dropped + counted, nothing forwarded; Q's next register is `Ok`
/// (§9k ruling 1) and that payment is signed HELD; M, paid before the fork,
/// stays vouchable (ruling 3).
/// MUTATIONS (run 2026-10-02): (i) the tombstone writes `Tainted` on
/// `wallet_id` (the old `taint_wallet`) ⇒ RED at "node 0: Q blocked";
/// (ii) `judge_send` ignores the input roots ⇒ RED at "HELD".
#[test]
fn e4_c_downstream_of_proven_forker_held_by_a5_not_blocked() {
    let (a, mm, q) = (0xC4u8, 0xC5u8, 0xC6u8);
    let sk = test_legs::wallet;
    let send = |seed: u8, consumed: StateId, seq: u64, to: &str, amount: u64, nonce: u64| {
        test_legs::genuine_send_leg(&sk(seed), consumed, seq, to, amount, nonce, 3)
    };
    let redeem = |seed: u8, cheque: &ForkLeg, balance: u64| {
        test_legs::genuine_redeem_leg(&sk(seed), test_legs::opening(&sk(seed)), &test_legs::origin_of(cheque), balance, 1, 3)
    };
    let mut m = Mesh::new(N);
    let t_am = send(a, test_legs::opening(&sk(a)), 1, "m@axiom.internal/0123456789", 100, 1);
    m.register_at(0, &t_am).expect("A pays M");
    m.run_until_quiet();
    let rho_m = redeem(mm, &t_am, 100);
    m.register_at(1, &rho_m).expect("M redeems");
    m.run_until_quiet();
    let ta = send(a, t_am.new_state, 2, RECV_P, 300, 2);
    let tb = send(a, t_am.new_state, 2, RECV_Q, 300, 3);
    m.register_at(0, &ta).expect("ta at node 0");
    m.register_at(3, &tb).expect("tb at node 3");
    m.rounds_until_all_banned(&pk_of(a)).expect("A banned everywhere");
    // Q's redeem carries the k-attested `K3Receipt.sender_state` = tb's state
    // (as a production receipt does, Core CL5) — so Q's leaf gets the §32.3
    // `received_from` edge the old taint arm walked. The witnesses re-sign the
    // commitment with it (`rewitness` recomputes it from the proof's fields).
    let rho_q = {
        let mut l = redeem(q, &tb, 300);
        l.seq_proof.sender_state = Some(tb.new_state);
        test_legs::rewitness(&l, &[test_legs::validator(0), test_legs::validator(1), test_legs::validator(2)])
    };
    let (mut reg_q, deed_q) = test_legs::registration_of(&rho_q);
    reg_q.receipt.sender_state = Some(tb.new_state);
    m.register_raw(1, &reg_q, &deed_q).expect("Q redeems tb");
    m.run_until_quiet();
    let (q_pk, a_pk) = (pk_of(q), pk_of(a));
    let old_predicate: Vec<usize> = m.up().into_iter().filter(|i| {
        let s = m.node(*i).smt();
        let (src, victim) = (s.get(&a_pk), s.get(&q_pk));
        matches!((src, victim), (Some(src), Some(v))
            if matches!(src.status, WalletStatus::Frozen | WalletStatus::Banned)
                && v.received_from == Some(src.current_state))
    }).collect();
    assert!(!old_predicate.is_empty(),
        "non-vacuity: the OLD TaintAlert arm's predicate holds on no node — the test could not fail");
    eprintln!("[E4-c] old taint predicate holds on nodes {old_predicate:?}");
    let delivered = m.delivered;
    m.inject_everywhere(GossipMessage::TaintAlert { wallet_id: q_pk, tainted_source: a_pk, detected_at_tick: m.tick() });
    m.step();
    assert_eq!(m.delivered - delivered, N as u64, "the alert reached every node");
    assert!(m.queue.is_empty(), "a node FORWARDED the TaintAlert");
    for i in m.up() {
        let n = m.node(i);
        assert_eq!(n.gossip().taintalert_dropped(), 1, "node {i}: the drop is counted");
        assert_eq!(n.origin_status(None, 0).taintalert_dropped, 1, "node {i}: the count reaches /status");
        assert!(!n.is_wallet_blocked(&q_pk), "node {i}: Q blocked");
        assert_eq!(n.smt().get(&q_pk).map(|e| e.status), Some(WalletStatus::Normal), "node {i}: Q's leaf");
        assert_eq!(n.provenance_view(&q_pk, &rho_q.new_state), ProvenanceView::Held(vec![tb.tx_hash]),
            "node {i}: Q's redeem is MARKED held by A5");
    }
    // Ruling 1: Q's next register is accepted at every door kind (here door 2).
    let t_qq2 = send(q, rho_q.new_state, 2, "q2@axiom.internal/0123456789", 60, 1);
    m.register_at(2, &t_qq2).expect("ruling 1: Q's held register is ACCEPTED");
    m.run_until_quiet();
    for i in m.up() {
        let n = m.node(i);
        assert_eq!(n.origin_vouch(&t_qq2.tx_hash, m.boot(i)), OriginVouch::HELD,
            "node {i}: Q's onward payment must be signed HELD");
        assert!(n.origin_vouch(&t_am.tx_hash, m.boot(i)).origin.is_some(),
            "node {i}: M, paid BEFORE the fork, must stay vouchable (ruling 3)");
        assert!(view_holds(n).is_empty(), "node {i}: a view-based hold {:?}", view_holds(n));
    }
}

/// E4-d — source gate: no VIEW-based status writer exists in production code.
/// Scans every `.rs` under `nabla/src` (incl. `bin/`), with `#[cfg(test)]`
/// modules and `//` comment lines removed: none of the deleted §32 SCAN /
/// taint / quarantine functions is defined or called, and nothing constructs
/// a `Frozen` / `Tainted` status (the leaf byte decoder in `crypto.rs` matches
/// on them; it does not construct). Files inspected must be > 0.
/// MUTATION (run 2026-10-02): re-add `pub fn freeze_wallet(..)` (the deleted
/// writer, body `updated.status = WalletStatus::Frozen`) to `tardis.rs` ⇒ RED.
#[test]
fn e4_d_no_view_based_status_writer() {
    fn strip_test_modules(src: &str) -> String {
        let lines: Vec<&str> = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
        let text = lines.join("\n");
        let mut out = String::new();
        let mut rest = text.as_str();
        while let Some(at) = rest.find("#[cfg(test)]") {
            out.push_str(&rest[..at]);
            let after = &rest[at + "#[cfg(test)]".len()..];
            let head = after.trim_start();
            let is_mod = head.starts_with("mod ") || head.starts_with("pub mod ") || head.starts_with("pub(crate) mod ");
            if !is_mod {
                rest = after;
                continue;
            }
            // Skip the module body by brace matching (string / char literals skipped).
            let (open, semi) = (after.find('{').unwrap_or(usize::MAX), after.find(';').unwrap_or(usize::MAX));
            if semi < open {
                rest = &after[semi + 1..]; // `#[cfg(test)] mod x;` — an out-of-line module file
                continue;
            }
            let bytes = after.as_bytes();
            let (mut depth, mut k, mut in_str) = (0i64, open, false);
            while k < bytes.len() {
                let c = bytes[k];
                if in_str {
                    if c == b'\\' { k += 1; } else if c == b'"' { in_str = false; }
                } else if c == b'"' {
                    in_str = true;
                } else if c == b'\'' && k + 2 < bytes.len() && bytes[k + 2] == b'\'' {
                    k += 2; // a char literal like '{'
                } else if c == b'{' {
                    depth += 1;
                } else if c == b'}' {
                    depth -= 1;
                    if depth == 0 { break; }
                }
                k += 1;
            }
            rest = &after[(k + 1).min(after.len())..];
        }
        out.push_str(rest);
        out
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    for dir in [root.clone(), root.join("bin")] {
        for e in std::fs::read_dir(&dir).expect("read nabla/src") {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "rs") {
                files.push(p);
            }
        }
    }
    let forbidden = [
        "fn freeze_wallet", "fn taint_wallet", "fn resolve_merge", "fn check_merge_quarantine",
        "detect_forked_wallets", "handle_fork_evidence", "propagate_taint", "enter_merge_quarantine",
        "status = WalletStatus::Frozen", "status = WalletStatus::Tainted",
        "status: WalletStatus::Frozen", "status: WalletStatus::Tainted",
        "status = crate::types::WalletStatus::Frozen", "status = crate::types::WalletStatus::Tainted",
    ];
    // Out-of-line `#[cfg(test)] mod x;` files (this one included) are test code.
    let lib = std::fs::read_to_string(root.join("lib.rs")).unwrap();
    let test_files: Vec<String> = lib.split("#[cfg(test)]").skip(1)
        .filter_map(|t| {
            let t = t.trim_start();
            let t = t.strip_prefix("pub(crate) ").or_else(|| t.strip_prefix("pub ")).unwrap_or(t);
            let name = t.strip_prefix("mod ")?.split(';').next()?;
            (!name.contains('{')).then(|| format!("{}.rs", name.trim()))
        })
        .collect();
    assert!(test_files.iter().any(|f| f == "fork_detection_mesh.rs"), "the lib.rs test-module parse found {test_files:?}");
    files.retain(|f| !test_files.iter().any(|t| f.ends_with(t)));
    let mut hits = Vec::new();
    let mut inspected = 0usize;
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap();
        let code = strip_test_modules(&src);
        if f.ends_with("bin/nabla_node.rs") {
            // Non-vacuity of the stripper: production code AFTER the binary's
            // `mod tests` must survive, and the test bodies must not.
            assert!(code.contains("fn emission_claim_identity("), "stripper ate production code after `mod tests`");
            assert!(!code.contains("fn ki55_nabla_role_both_sign_sites_match_independent_constant"), "stripper kept a test body");
        }
        inspected += 1;
        for pat in forbidden {
            if code.contains(pat) {
                hits.push(format!("{}: {pat}", f.file_name().unwrap().to_string_lossy()));
            }
        }
    }
    assert!(inspected >= 20, "E4-d inspected only {inspected} files — the gate cannot see the crate");
    assert!(files.iter().any(|f| f.ends_with("bin/nabla_node.rs")), "E4-d must inspect the binary");
    assert!(hits.is_empty(), "E4-d: a view-based status writer / §32 SCAN remnant in production code: {hits:?}");
}

// ── ForkSettlement §9r F-1(c) (KI#244) — no stamp on HELD money ─────────────
//
// `register_vbc_core` step 2c reads `NablaNode::stake_head_provenance` (the
// registered head's `provenance_view`). These two gates pin that predicate on
// the mesh shapes it must separate; the door wiring is tested in the binary
// (`register_vbc_refuses_a_stake_head_with_no_provenance_verdict` & co.).

/// F-a — a stake wallet whose balance descends from a fork: A forks (ta at
/// door 0, tb at door 3) and is banned; Q redeems tb and pays R; R redeems.
/// Every node reports R's registered head `Held([t_qr])` — so no node would
/// stamp a certificate staked on it.
/// MUTATION (run 2026-10-02): `Provenance::view` answers `Ok` for a held
/// verdict (ignores the held roots) ⇒ RED.
#[test]
fn f1c_a_stake_head_downstream_of_forker_is_held() {
    let (a, q, r) = (0xF6u8, 0xF7u8, 0xF8u8);
    let sk = test_legs::wallet;
    let mut m = Mesh::new(N);
    let y = test_legs::opening(&sk(a));
    let ta = leg(a, y, RECV_P, 300, 2);
    let tb = leg(a, y, RECV_Q, 300, 3);
    m.register_at(0, &ta).expect("ta at node 0");
    m.register_at(3, &tb).expect("tb at node 3");
    m.rounds_until_all_banned(&pk_of(a)).expect("A banned everywhere");
    let rho_q = test_legs::genuine_redeem_leg(&sk(q), test_legs::opening(&sk(q)), &test_legs::origin_of(&tb), 300, 1, 3);
    m.register_at(1, &rho_q).expect("Q redeems tb");
    m.run_until_quiet();
    let t_qr = test_legs::genuine_send_leg(&sk(q), rho_q.new_state, 2, RECV_R, 100, 1, 3);
    m.register_at(2, &t_qr).expect("Q pays R");
    m.run_until_quiet();
    let rho_r = test_legs::genuine_redeem_leg(&sk(r), test_legs::opening(&sk(r)), &test_legs::origin_of(&t_qr), 100, 1, 3);
    m.register_at(4, &rho_r).expect("ruling 1: R's held redeem is accepted");
    m.run_until_quiet();
    for i in m.up() {
        assert_eq!(m.node(i).stake_head_provenance(&pk_of(r)), Some(ProvenanceView::Held(vec![t_qr.tx_hash])),
            "node {i}: R's stake head must be HELD (no stamp)");
    }
}

/// F-b — guard against OVER-refusal: an honest stake wallet funded by a
/// genesis claim + its self-redeem (the S11 shape) is `Ok` at every node —
/// its stamp is not refused.
/// MUTATION (run 2026-10-02): `stake_head_provenance` returns
/// `Some(ProvenanceView::Wait)` unconditionally ⇒ RED.
#[test]
fn f1c_b_genesis_claim_funded_stake_head_is_ok() {
    let s = 0xF9u8;
    let mut m = Mesh::new(N);
    let (_claim, rs) = genesis_funded(&mut m, s, 0, 10_000_000_000);
    for i in m.up() {
        let n = m.node(i);
        assert_eq!(n.smt().get(&pk_of(s)).map(|e| e.current_state), Some(rs.new_state), "node {i}: fixture head");
        assert_eq!(n.stake_head_provenance(&pk_of(s)), Some(ProvenanceView::Ok), "node {i}: honest stake head not Ok");
    }
    assert_eq!(m.node(0).stake_head_provenance(&pk_of(0x01)), None, "no entry ⇒ None (the derived-head case)");
}

// ── KI#122 — the CLARA-heal `new_wallet_seq = 0` 10-vs-1 split, reproduced ──
//
// Measured 2026-08-27 (KnownIssues KI#122): a heal re-register carried the
// skeleton receipt's `new_wallet_seq = 0`; ONE node (epsilon) stored it over
// its seq-17 head (Branch A exempted the non-advance, step 8 replaced the head
// and marked 09f6 consumed), every peer AE-rejected it `not-superseding`, and
// the acceptor refused theirs `consumed-state` — a permanent 10-vs-1 fork.
// Today TWO independent door guards close it: 5b′ (`verify_registered_leg`:
// the receipt's seq must equal the k-signed leg's) refuses a skeleton, and 7a′
// refuses a seq-0 register over a held seq > 0 even when it is k-signed. Each
// test below reproduces the 10-vs-1 shape under its named mutation.

/// The KI#122 fixture: W at Y (seq 2) on every node — opening → X (seq 1) →
/// Y (seq 2) at door 0 — and the HAL heal leg Y → Y′ at seq 3 (a self-send).
fn ki122_fixture(seed: u8) -> (Mesh, WalletId, ForkLeg, ForkLeg) {
    let sk = test_legs::wallet(seed);
    let w = pk_of(seed);
    let mut m = Mesh::new(N);
    let x = test_legs::genuine_send_leg(&sk, test_legs::opening(&sk), 1, RECV_P, 10, 1, 3);
    m.register_at(0, &x).expect("opening → X");
    m.run_until_quiet();
    let y = test_legs::genuine_send_leg(&sk, x.new_state, 2, RECV_Q, 10, 2, 3);
    m.register_at(0, &y).expect("X → Y");
    m.run_until_quiet();
    for i in m.up() {
        let e = m.node(i).smt().get(&w).cloned().expect("W's head");
        assert_eq!((e.current_state, e.wallet_seq), (y.new_state, 2), "fixture: node {i} at (Y, 2)");
    }
    let own = format!("k{seed:02x}@axiom.internal/0123456789");
    let heal = test_legs::genuine_send_leg(&sk, y.new_state, 3, &own, 1, 3, 3);
    (m, w, y, heal)
}

/// Every live node holds W at `(state, seq)`, W unbanned, and ONE root.
fn assert_converged_at(m: &Mesh, w: &WalletId, state: StateId, seq: u64, label: &str) {
    let mut roots = std::collections::BTreeSet::new();
    let heads: Vec<_> = m.up().iter().map(|i| {
        let n = m.node(*i);
        roots.insert(n.smt().root_hash());
        n.smt().get(w).map(|e| (hex::encode(&e.current_state[..4]), e.wallet_seq))
    }).collect();
    for i in m.up() {
        let n = m.node(i);
        assert_eq!(n.smt().get(w).map(|e| (e.current_state, e.wallet_seq)), Some((state, seq)),
            "{label}: node {i} not at the expected head — heads per node: {heads:?} (the KI#122 split)");
        assert!(!n.is_banned(w), "{label}: node {i} banned W");
    }
    assert_eq!(roots.len(), 1, "{label}: {} distinct roots — heads per node: {heads:?}", roots.len());
}

/// KI#122 (a) — the MEASURED poison: the heal re-register carrying the
/// SKELETON seq (`new_wallet_seq = 0`) at door 1, in both carriers a CLARA heal
/// can use — a plain re-register of the stranded link, and a HAL re-anchor
/// (`is_hal_reanchor`). 5b′ refuses it exactly
/// `LegUnverifiable(WalletSeqMismatch)` — before 5b‴, so no leg is recorded
/// under (W, Y) anywhere and nothing floods; head-AE + record-AE leave every
/// node at (Y, 2) with ONE root. The CANONICAL register of the same leg then
/// succeeds at the same door and the mesh converges on (Y′, 3).
/// The convergence is asserted BEFORE the error kind, so a mutation that lets
/// the poison in fails on the split itself.
/// MUTATIONS (run 2026-10-02): skip the 5b′ call ⇒ RED at the exact error
/// (the plain carrier is then refused by 7a′ `InvalidReceipt`; the HAL carrier
/// by 6c `verify_receipt_commitment_sigs` — a THIRD guard, which recomputes the
/// commitment over the receipt's seq for recall/HAL); skip 5b′ AND 7a′ ⇒ RED
/// at "plain: node 1 not at the expected head" — node 1 holds the poison at
/// seq 0, the other four (Y, 2): the 10-vs-1 split itself (the HAL carrier
/// stays refused by 6c; skipping 6c too splits it the same way).
#[test]
fn ki122_a_skeleton_heal_register_refused_at_5b_prime_mesh_converges() {
    for (seed, hal) in [(0x7Au8, false), (0x7Cu8, true)] {
        let label = if hal { "HAL" } else { "plain" };
        let (mut m, w, y, heal) = ki122_fixture(seed);
        let (mut poison, deed) = test_legs::registration_of(&heal);
        poison.is_hal_reanchor = hal;
        poison.receipt.new_wallet_seq = 0; // the skeleton receipt's hard-coded seq
        let r = m.register_raw(1, &poison, &deed);
        let flooded = !m.queue.is_empty();
        m.run_until_quiet();
        converge(&mut m, true);
        assert_converged_at(&m, &w, y.new_state, 2, &format!("{label}: after the skeleton register"));
        assert!(matches!(r, Err(NablaError::LegUnverifiable(crate::registration::LegRefusal::WalletSeqMismatch))),
            "{label}: the skeleton heal must be refused at 5b′ (WalletSeqMismatch), got {r:?}");
        assert!(!flooded, "{label}: a refused register floods nothing");
        for i in m.up() {
            assert!(m.node(i).smt().legs_under(&(w, y.new_state)).is_empty(),
                "{label}: node {i}: a leg recorded under (W, Y) from the refused skeleton");
        }
        let (mut canon, deed) = test_legs::registration_of(&heal);
        canon.is_hal_reanchor = hal;
        m.register_raw(1, &canon, &deed).unwrap_or_else(|e| panic!("{label}: the canonical register: {e:?}"));
        m.run_until_quiet();
        converge(&mut m, true);
        assert_converged_at(&m, &w, heal.new_state, 3, &format!("{label}: after the canonical register"));
    }
}

/// KI#122 (b) — isolates 7a′: a GENUINELY k-signed leg Y → Z at seq 0 (a
/// counterfactual Core refuses — Core increments the seq on every link — so
/// it can only reach a door as a forged/buggy witness set). 5b′ passes (the
/// receipt seq IS the signed seq); 7a′ refuses `InvalidReceipt`. Every node
/// stays at (Y, 2), Y is not consumed anywhere, one root.
/// MUTATION (run 2026-10-02): delete the 7a′ block ⇒ RED at "node 1 not at
/// the expected head" — node 1 at (Z, 0) with Y consumed, the others at Y:
/// KI#122 reproduced.
#[test]
fn ki122_b_signed_seq_zero_register_refused_at_7a_prime_mesh_converges() {
    let seed = 0x7B;
    let (mut m, w, y, _heal) = ki122_fixture(seed);
    let zero = test_legs::genuine_send_leg(&test_legs::wallet(seed), y.new_state, 0, RECV_R, 1, 9, 3);
    let r = m.register_at(1, &zero);
    m.run_until_quiet();
    converge(&mut m, true);
    assert_converged_at(&m, &w, y.new_state, 2, "after the seq-0 register");
    for i in m.up() {
        assert!(!m.node(i).smt().is_state_consumed(&y.new_state), "node {i}: Y consumed by a refused register");
    }
    assert!(matches!(r, Err(NablaError::InvalidReceipt)), "7a′ must refuse seq 0 over seq 2, got {r:?}");
}

// ── KI#224 — a head's witness sigs must walk back to the root ───────────────
//
// Owner ruling 2026-10-02: a head's witness signatures count only if EVERY key
// is the subject of an R42 directory entry at the judging node
// (`ban::seq_proof_is_directory_witnessed`). Gated on ALL three head-intake
// paths — register door step 5b⁗, the StateUpdate flood, head-AE — because a
// door-only gate is bypassed by one injected StateUpdate.

/// The register carrying `leg` RE-WITNESSED by `keys`: every key genuinely
/// signs the receipt commitment (`test_legs::rewitness`) and the legacy step-5
/// payload, so the door's 5/5b′ checks pass on the bytes and ONLY the directory
/// can refuse it. (`registration_of` itself insists on `validator(i)` keys.)
fn rewitnessed_registration(leg: &ForkLeg, keys: &[ed25519_dalek::SigningKey]) -> (Registration, DeedTransaction) {
    use ed25519_dalek::Signer as _;
    let (mut reg, deed) = test_legs::registration_of(leg);
    let w = test_legs::rewitness(leg, keys);
    let step5 = crate::crypto::receipt_sign_payload(&reg.wallet_id, &reg.old_state, 0);
    reg.receipt.signatures = w
        .seq_proof
        .sigs
        .iter()
        .zip(keys)
        .map(|(s, k)| WitnessSig {
            validator_pk: s.validator_pk,
            signature: k.sign(&step5).to_bytes().to_vec(),
            execution_proof: vec![],
            proof_type: 0,
            receipt_commitment_sig: s.receipt_commitment_sig.clone(),
            validator_id: [0u8; 32],
            slot_amount: 0,
        })
        .collect();
    (reg, deed)
}

/// Three self-made keys — never in any test node's directory.
fn self_made_keys() -> Vec<ed25519_dalek::SigningKey> {
    (0..3).map(test_legs::junk_witness).collect()
}

fn vpk(i: u8) -> [u8; 32] {
    test_legs::validator(i).verifying_key().to_bytes()
}

/// W at (X, 1) on every node (an honest, directory-witnessed register at door
/// 0), plus the next honest leg X → Y at seq 2 (NOT registered).
fn ki224_fixture(seed: u8) -> (Mesh, WalletId, ForkLeg, ForkLeg) {
    let sk = test_legs::wallet(seed);
    let w = pk_of(seed);
    let mut m = Mesh::new(N);
    let x = leg(seed, test_legs::opening(&sk), RECV_P, 100, 1);
    m.register_at(0, &x).expect("fixture: opening → X");
    m.run_until_quiet();
    assert_converged_at(&m, &w, x.new_state, 1, "fixture");
    let y = test_legs::genuine_send_leg(&sk, x.new_state, 2, RECV_Q, 10, 2, 3);
    (m, w, x, y)
}

/// K-a — the DOOR refuses a head whose quorum is three self-made keys: the
/// proof is cryptographically VALID (`verify_seq_proof` passes), so before
/// KI#224 it was stored and flooded. Refused `WitnessNotInDirectory` naming
/// the first unknown key, counted, nothing stored or flooded; the leg IS still
/// recorded at 5b‴ (detect-only [R30]).
/// MUTATION (run 2026-10-02): delete the 5b⁗ block in `process_registration`
/// ⇒ RED (the register is `Ok`, the junk head stored).
#[test]
fn ki224_a_door_refuses_head_witnessed_by_self_made_keys() {
    let seed = 0x24;
    let sk = test_legs::wallet(seed);
    let w = pk_of(seed);
    let mut m = Mesh::new(N);
    let x = leg(seed, test_legs::opening(&sk), RECV_P, 100, 1);
    let (reg, deed) = rewitnessed_registration(&x, &self_made_keys());
    let p = SeqProof::from_registration(&reg).expect("fixture: a carried proof");
    assert!(crate::registration::verify_seq_proof(&p, &reg.tx_hash, 1),
        "fixture: the self-made quorum is cryptographically valid — only the directory can refuse it");
    let before = crate::registration::witness_not_in_directory_refused_total();
    let r = m.register_raw(0, &reg, &deed);
    let junk0 = test_legs::junk_witness(0).verifying_key().to_bytes();
    assert!(matches!(r, Err(NablaError::WitnessNotInDirectory(k)) if k == junk0),
        "the door must refuse a self-made quorum WitnessNotInDirectory(first junk key), got {r:?}");
    assert!(m.queue.is_empty(), "a refused register floods nothing");
    m.run_until_quiet();
    for i in m.up() {
        assert!(m.node(i).smt().get(&w).is_none(), "node {i}: a self-made-witness head was stored");
    }
    assert!(crate::registration::witness_not_in_directory_refused_total() > before, "the refusal is COUNTED");
    assert!(!m.node(0).smt().legs_under(&(w, test_legs::opening(&sk))).is_empty(),
        "the leg is still RECORDED at 5b‴ (detect-only), above the 5b⁗ refusal");
}

/// K-b — ONE self-made sig beside a full directory quorum is refused: ALL keys
/// must walk to the root (D-K224-3), never "≥ quorum of directory keys".
/// MUTATION (run 2026-10-02): `seq_proof_is_directory_witnessed` = "count of
/// directory keys ≥ `seq_proof_quorum`" ⇒ RED (the register is `Ok`).
#[test]
fn ki224_b_one_self_made_sig_beside_a_directory_quorum_is_refused() {
    let seed = 0x25;
    let sk = test_legs::wallet(seed);
    let mut m = Mesh::new(N);
    let x = leg(seed, test_legs::opening(&sk), RECV_P, 100, 1);
    let keys = vec![test_legs::validator(0), test_legs::validator(1), test_legs::validator(2), test_legs::junk_witness(0)];
    let (reg, deed) = rewitnessed_registration(&x, &keys);
    let r = m.register_raw(0, &reg, &deed);
    let junk0 = test_legs::junk_witness(0).verifying_key().to_bytes();
    assert!(matches!(r, Err(NablaError::WitnessNotInDirectory(k)) if k == junk0),
        "a junk sig beside a directory quorum must be refused, got {r:?}");
    assert!(m.node(0).smt().get(&pk_of(seed)).is_none(), "nothing stored");
}

/// K-c — the honest head (every key a directory witness) is accepted at the
/// door and converges everywhere by flood — the gate is not over-strict.
/// MUTATION (run 2026-10-02): `seq_proof_is_directory_witnessed` returns
/// `false` ⇒ RED (`WitnessNotInDirectory` at the door).
#[test]
fn ki224_c_door_accepts_directory_witnessed_head() {
    let (m, w, x, _y) = ki224_fixture(0x26);
    assert_converged_at(&m, &w, x.new_state, 1, "K-c");
}

/// K-d (flood) — a self-made-witness seq-ADVANCE injected as a StateUpdate
/// straight to every node (skipping every door) is NOT adopted anywhere; a
/// self-made-witness FIRST SIGHT above seq 0 is not stored either. The SAME
/// leg with directory witnesses, injected the same way, IS adopted (control).
/// MUTATION (run 2026-10-02): flood `seq_attested = seq_verified` (drop the
/// directory predicate in `gossip::apply_state_update`) ⇒ RED (every node
/// advances to Y).
#[test]
fn ki224_d_flood_does_not_adopt_a_self_made_witness_advance() {
    let seed = 0x27;
    let (mut m, w, x, y) = ki224_fixture(seed);
    let junk_y = test_legs::rewitness(&y, &self_made_keys());
    let tick = m.tick();
    m.inject_everywhere(test_legs::flood_of(&junk_y, x.new_state, tick));
    m.run_until_quiet();
    assert_converged_at(&m, &w, x.new_state, 1, "K-d flood: after the self-made-witness advance");
    // First sight above seq 0 for a wallet no node holds.
    let seed2 = 0x28;
    let sk2 = test_legs::wallet(seed2);
    let z = test_legs::rewitness(&leg(seed2, test_legs::opening(&sk2), RECV_P, 5, 1), &self_made_keys());
    m.inject_everywhere(test_legs::flood_of(&z, [0u8; 32], tick));
    m.run_until_quiet();
    for i in m.up() {
        assert!(m.node(i).smt().get(&pk_of(seed2)).is_none(), "node {i}: self-made-witness first sight stored");
    }
    // Control: the directory-witnessed flood of the same leg is adopted.
    m.inject_everywhere(test_legs::flood_of(&y, x.new_state, m.tick()));
    m.run_until_quiet();
    assert_converged_at(&m, &w, y.new_state, 2, "K-d flood: control");
}

/// K-d (AE) — the same self-made-witness advance offered by head-AE is NOT
/// adopted at any node; the directory-witnessed entry is (control).
/// MUTATION (run 2026-10-02): AE `seq_attested = seq_verified` (drop the
/// directory predicate in `apply_remote_entry_inner`) ⇒ RED.
#[test]
fn ki224_d_ae_does_not_adopt_a_self_made_witness_advance() {
    let seed = 0x29;
    let (mut m, w, x, y) = ki224_fixture(seed);
    let junk_y = test_legs::rewitness(&y, &self_made_keys());
    let tick = m.tick();
    for i in 0..m.n() {
        m.ae_deliver(i, &[(test_legs::entry_of(&junk_y, tick), Some(junk_y.seq_proof.clone()))], &[]);
    }
    m.run_until_quiet();
    assert_converged_at(&m, &w, x.new_state, 1, "K-d AE: after the self-made-witness advance");
    for i in 0..m.n() {
        m.ae_deliver(i, &[(test_legs::entry_of(&y, tick), Some(y.seq_proof.clone()))], &[]);
    }
    m.run_until_quiet();
    assert_converged_at(&m, &w, y.new_state, 2, "K-d AE: control");
}

/// K-e — DIRECTORY LAG heals by admission (fail closed, retryable). Node 4's
/// directory has not learned validator(2) (a fresh node before directory AE):
/// its door refuses the honest register `WitnessNotInDirectory` (the SDK walks
/// on), door 0 accepts it, node 4 does not adopt the flood nor a head-AE offer
/// — and once validator(2) is admitted at node 4 the next head-AE round
/// re-offers the head and every node converges. Nothing was remembered as
/// refused.
/// MUTATIONS (run 2026-10-02): drop the directory predicate on the AE path
/// (`apply_remote_entry_inner`) ⇒ RED at "node 4 adopted a head its directory
/// cannot walk to the root"; delete door step 5b⁗ ⇒ RED at the door assert.
/// The re-offer reads the LIVE directory (`|pk| self.vbc_registrations.
/// is_witness(pk)` per call), which "after admission" exercises.
#[test]
fn ki224_e_directory_lag_is_retryable_and_heals_by_admission() {
    let seed = 0x2A;
    let sk = test_legs::wallet(seed);
    let w = pk_of(seed);
    let mut m = Mesh::new(N);
    m.crash(4);
    m.slots[4].withheld = vec![vpk(2)];
    m.restart(4);
    let x = leg(seed, test_legs::opening(&sk), RECV_P, 100, 1);
    let r = m.register_at(4, &x);
    assert!(matches!(r, Err(NablaError::WitnessNotInDirectory(k)) if k == vpk(2)),
        "a lagging directory refuses the honest head RETRYABLY, got {r:?}");
    m.register_at(0, &x).expect("door 0 (full directory) accepts the same register");
    m.run_until_quiet();
    m.ae_pull(4, 0);
    m.run_until_quiet();
    assert!(m.node(4).smt().get(&w).is_none(), "node 4 adopted a head its directory cannot walk to the root");
    for i in 0..4 {
        assert_eq!(m.node(i).smt().get(&w).map(|e| e.current_state), Some(x.new_state), "node {i} holds X");
    }
    m.slots[4].node.as_mut().unwrap().admit_witness_for_test(vpk(2));
    m.ae_pull(4, 0);
    m.run_until_quiet();
    assert_converged_at(&m, &w, x.new_state, 1, "after admission");
}

/// K-f — a plain RESTART has no gap: the directory reloads from the node's own
/// `vbc_registrations.cbor` at open (`load_vbc_directory_file` →
/// `restore_own_persisted`), so an honest register is accepted immediately,
/// before any directory AE. Real admitted entries (the `admit` pipeline with
/// the fixture verifier), persisted by `adopt_verified_directory_entries`.
/// MUTATION (run 2026-10-02): `load_vbc_directory_file` returns
/// `Default::default()` ⇒ RED (`WitnessNotInDirectory` after the restart).
#[test]
fn ki224_f_restart_reloads_directory_no_gap() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
        let entries = (0..3u8)
            .map(|i| crate::vbc_directory::tests::admitted_entry_for_subject(vpk(i)))
            .collect();
        assert_eq!(n.adopt_verified_directory_entries(entries), 3, "fixture: three witnesses admitted");
    }
    let mut n = NablaNode::open(dir.path(), Box::new(crate::crypto::NoopSigner)).unwrap();
    let seed = 0x2B;
    let x = leg(seed, test_legs::opening(&test_legs::wallet(seed)), RECV_P, 100, 1);
    let (reg, deed) = test_legs::registration_of(&x);
    n.register(&reg, &deed, NOW_SECS).expect("the reloaded directory admits the honest head at once");
    assert_eq!(n.smt().get(&pk_of(seed)).map(|e| e.current_state), Some(x.new_state));
}
