//! Dev-only FLOOD CHAOS — the live-gate switch owed by `AXIOM_DESIGN_ForkSettlement.md` §9o
//! ("Proof obligations", KI#235/#236): a running mesh cannot otherwise LOSE or REORDER a flood
//! between two nodes, so the lost-flood redeem fork (the shape record-AE [R48/R58] exists for)
//! and the honest same-seq reorder (the shape the retired check-3 [R56] falsely banned) could
//! only be proven in-process (`fork_detection_mesh::fork_retire_proof_{b2,c}_*`).
//!
//! Compiled ONLY with the `flood-chaos` cargo feature (the dev Nabla build in
//! `scripts/axiom-env.py` passes it; no production recipe may — preflight
//! `scripts/check_flood_chaos_dev_only.sh` refuses one) and into this crate's own unit-test
//! build (`cfg(test)`, so the switch logic is exercised by the ordinary nabla suite). The
//! binary glue (`src/bin/nabla_node.rs`) is `#[cfg(feature = "flood-chaos")]` only.
//!
//! THE SWITCH is a plain file, `<data_dir>/flood-chaos`, re-read at most every
//! `RELOAD_EVERY` so a harness flips it without a restart (a restart would re-floor the vouch
//! clock and replay the WAL — the very state under test). Missing / empty file = OFF (the
//! filter is then the identity). One entry per line, `#` comments:
//!
//! ```text
//!   drop  wallet <64 hex>   suppress every outbound FLOOD of this wallet (StateUpdate — HAL
//!                           re-anchors included since §9q —, GroupUpdate) and its entries in every HEAD-AE message
//!                           this node sends (AeReconcile.push, AeEntries, StatePullResponse,
//!                           RangeSyncResponse)
//!   drop  txid   <64 hex>   the same, for the one transaction whose tx_hash this is
//!   hold  wallet|txid <hex> as drop for head-AE; each matching FLOOD is STASHED (per target)
//!                           instead of dropped, and when the line is REMOVED the stash is sent
//!                           in REVERSE arrival order — a hold exists to REORDER (the B2 shape:
//!                           the later leg reaches every neighbour before the earlier one)
//!   watch wallet <64 hex>   suppress nothing; report this node's BanTable evidence for the
//!                           wallet on /status (`flood_chaos.evidence`)
//! ```
//!
//! `wallet` keys exist because a harness cannot know a redeem's txid before the SDK registers
//! it, and the door floods AT registration — a txid-only switch could never arm in time.
//!
//! NEVER SUPPRESSED (the mechanisms under test): record-AE (`RecordAeAsk` / `RecordAeAnswer`),
//! `ForkBan` floods, the `fork_bans` riding AE, and every other message — see
//! `tests::record_ae_fork_bans_and_other_traffic_never_suppressed`.
//!
//! Counted on `/status` under `flood_chaos` (RULE 3 §2 — "0 suppressed" and "switch never
//! read" must look different): `entries`, `bad_lines` (a malformed line is NOT silently off),
//! `floods_dropped`, `floods_held`, `floods_released`, `held_now`, `hold_overflow`,
//! `ae_entries_suppressed`, `evidence`.
#![cfg(any(test, feature = "flood-chaos"))]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::transport::WireMessage;
use crate::types::{BanEvidence, GossipMessage, TxHash, WalletId};

/// The switch file's name inside the node's data dir.
pub const SWITCH_FILE: &str = "flood-chaos";
/// Re-read the switch at most this often (one `read_to_string` of a tiny file, outside the
/// node lock — `filter_outbound` / `take_released` are called from the send loops).
pub const RELOAD_EVERY: Duration = Duration::from_millis(250);
/// Held floods beyond this are DROPPED and counted `hold_overflow` (a dev bound: a forgotten
/// `hold` line must not grow memory without limit).
pub const HOLD_MAX: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Drop,
    Hold,
    Watch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Key {
    Wallet(WalletId),
    Txid(TxHash),
}

impl Key {
    fn matches(&self, wallet: &WalletId, tx: &TxHash) -> bool {
        match self {
            Key::Wallet(w) => w == wallet,
            Key::Txid(t) => t == tx,
        }
    }
}

/// A parsed switch file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Switch {
    pub entries: Vec<(Action, Key)>,
    /// Lines that were neither blank, a comment, nor a valid entry.
    pub bad_lines: u64,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let v = hex::decode(s).ok()?;
    v.try_into().ok()
}

/// Parse the switch text. Never fails: a malformed line is COUNTED (`bad_lines`, on /status),
/// so a typo reads as "1 bad line", not as a silently disarmed switch.
pub fn parse(text: &str) -> Switch {
    let mut sw = Switch::default();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let w: Vec<&str> = line.split_whitespace().collect();
        let entry = match (w.as_slice(), w.len()) {
            ([a, k, h], 3) => {
                let action = match *a {
                    "drop" => Some(Action::Drop),
                    "hold" => Some(Action::Hold),
                    "watch" => Some(Action::Watch),
                    _ => None,
                };
                let key = hex32(h).and_then(|b| match *k {
                    "wallet" => Some(Key::Wallet(b)),
                    "txid" => Some(Key::Txid(b)),
                    _ => None,
                });
                match (action, key) {
                    // `watch` reports BanTable evidence, which is per WALLET.
                    (Some(Action::Watch), Some(Key::Txid(_))) => None,
                    (Some(a), Some(k)) => Some((a, k)),
                    _ => None,
                }
            }
            _ => None,
        };
        match entry {
            Some(e) => sw.entries.push(e),
            None => sw.bad_lines += 1,
        }
    }
    sw
}

/// The (wallet, tx_hash) a FLOOD carries — `None` for everything that is not a wallet-state
/// flood (record-AE, `ForkBan`, TARDIS, pools, …: never suppressed).
fn flood_subject(msg: &WireMessage) -> Option<(WalletId, TxHash)> {
    match msg {
        // (`HalAdvance` is a tombstone since Fork Settlement §9q — never sent by
        // this build; HAL re-anchors are `StateUpdate`s and match above.)
        WireMessage::Gossip(GossipMessage::StateUpdate { wallet_id, tx_hash, .. })
        | WireMessage::Gossip(GossipMessage::GroupUpdate { wallet_id, tx_hash, .. }) => {
            Some((*wallet_id, *tx_hash))
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    pub floods_dropped: u64,
    pub floods_held: u64,
    pub floods_released: u64,
    pub hold_overflow: u64,
    pub ae_entries_suppressed: u64,
}

/// The switch applied to outbound traffic — PURE (no file, no clock): the unit tests drive
/// it directly; the binary goes through the process-global wrappers below.
#[derive(Debug, Default)]
pub struct Chaos {
    pub switch: Switch,
    /// Held floods in arrival order: (the hold key that caught it, target, message).
    held: Vec<(Key, SocketAddr, WireMessage)>,
    pub counters: Counters,
}

impl Chaos {
    /// The strongest entry matching (wallet, tx): Drop beats Hold; Watch suppresses nothing.
    fn verdict(&self, wallet: &WalletId, tx: &TxHash) -> Option<(Action, Key)> {
        let mut best: Option<(Action, Key)> = None;
        for (a, k) in &self.switch.entries {
            if *a == Action::Watch || !k.matches(wallet, tx) {
                continue;
            }
            if *a == Action::Drop {
                return Some((*a, *k));
            }
            best.get_or_insert((*a, *k));
        }
        best
    }

    fn suppress_entry(&mut self, wallet: &WalletId, tx: &TxHash) -> bool {
        let hit = self.verdict(wallet, tx).is_some();
        if hit {
            self.counters.ae_entries_suppressed += 1;
        }
        hit
    }

    /// Apply the switch to one send batch. Floods matching `drop` vanish, floods matching
    /// `hold` are stashed; head-AE messages lose the matching ENTRIES (the message itself —
    /// with its other entries and its `fork_bans` — still goes). Everything else is untouched.
    pub fn filter(&mut self, out: Vec<(SocketAddr, WireMessage)>) -> Vec<(SocketAddr, WireMessage)> {
        if self.switch.entries.iter().all(|(a, _)| *a == Action::Watch) {
            return out;
        }
        let mut kept = Vec::with_capacity(out.len());
        for (addr, mut msg) in out {
            if let Some((wallet, tx)) = flood_subject(&msg) {
                match self.verdict(&wallet, &tx) {
                    Some((Action::Drop, _)) => {
                        self.counters.floods_dropped += 1;
                        continue;
                    }
                    Some((Action::Hold, key)) => {
                        if self.held.len() >= HOLD_MAX {
                            self.counters.hold_overflow += 1;
                        } else {
                            self.counters.floods_held += 1;
                            self.held.push((key, addr, msg));
                        }
                        continue;
                    }
                    _ => {}
                }
            }
            match &mut msg {
                WireMessage::AeReconcile { push, .. } => {
                    push.retain(|(e, _)| !self.suppress_entry(&e.wallet_id, &e.tx_hash));
                }
                WireMessage::AeEntries { entries, .. } => {
                    entries.retain(|(e, _)| !self.suppress_entry(&e.wallet_id, &e.tx_hash));
                }
                WireMessage::StatePullResponse { entries, .. } => {
                    entries.retain(|e| !self.suppress_entry(&e.wallet_id, &e.tx_hash));
                }
                WireMessage::RangeSyncResponse { missing_entries, .. } => {
                    missing_entries.retain(|e| !self.suppress_entry(&e.wallet_id, &e.tx_hash));
                }
                _ => {}
            }
            kept.push((addr, msg));
        }
        kept
    }

    /// Held floods whose `hold` line is gone, in REVERSE arrival order (the reorder).
    pub fn release(&mut self) -> Vec<(SocketAddr, WireMessage)> {
        let active: Vec<Key> = self
            .switch
            .entries
            .iter()
            .filter(|(a, _)| *a == Action::Hold)
            .map(|(_, k)| *k)
            .collect();
        let (still, freed): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.held).into_iter().partition(|(k, _, _)| active.contains(k));
        self.held = still;
        let out: Vec<_> = freed.into_iter().rev().map(|(_, a, m)| (a, m)).collect();
        self.counters.floods_released += out.len() as u64;
        out
    }

    pub fn held_now(&self) -> usize {
        self.held.len()
    }

    /// Every wallet named by any entry (their BanTable evidence is reported).
    pub fn watched_wallets(&self) -> Vec<WalletId> {
        let mut v: Vec<WalletId> = self
            .switch
            .entries
            .iter()
            .filter_map(|(_, k)| match k {
                Key::Wallet(w) => Some(*w),
                Key::Txid(_) => None,
            })
            .collect();
        v.sort();
        v.dedup();
        v
    }
}

/// The name `/status` reports for a BanTable entry's evidence (None = not banned here).
pub fn evidence_kind(ev: Option<&BanEvidence>) -> &'static str {
    match ev {
        None => "none",
        Some(BanEvidence::Fork(_)) => "Fork",
        Some(BanEvidence::SeqFork(_)) => "SeqFork",
        Some(BanEvidence::LegacyConflict(..)) => "LegacyConflict",
    }
}

// ── process-global wrappers (the binary) ────────────────────────────────────

struct Global {
    path: Option<PathBuf>,
    last_read: Option<Instant>,
    chaos: Chaos,
    evidence: BTreeMap<String, &'static str>,
}

fn global() -> &'static Mutex<Global> {
    static G: OnceLock<Mutex<Global>> = OnceLock::new();
    G.get_or_init(|| {
        Mutex::new(Global { path: None, last_read: None, chaos: Chaos::default(), evidence: BTreeMap::new() })
    })
}

fn lock() -> std::sync::MutexGuard<'static, Global> {
    global().lock().unwrap_or_else(|p| p.into_inner())
}

/// Set once at startup: `<data_dir>/flood-chaos`.
pub fn set_switch_path(path: PathBuf) {
    lock().path = Some(path);
}

/// Re-read the switch if it is older than `RELOAD_EVERY`. The file read happens with NO lock
/// held — `set_evidence` is called under the NODE lock, so this mutex must never wait on I/O.
fn refresh() {
    let path = {
        let mut g = lock();
        if g.last_read.map(|t| t.elapsed() < RELOAD_EVERY).unwrap_or(false) {
            return;
        }
        g.last_read = Some(Instant::now());
        g.path.clone()
    };
    let text = path.and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
    lock().chaos.switch = parse(&text);
}

/// Called by both send loops on every outbound batch, OUTSIDE the node lock.
pub fn filter_outbound(out: Vec<(SocketAddr, WireMessage)>) -> Vec<(SocketAddr, WireMessage)> {
    refresh();
    lock().chaos.filter(out)
}

/// Called by the tick loop once per iteration, OUTSIDE the node lock: floods whose `hold`
/// line was removed, newest first.
pub fn take_released() -> Vec<(SocketAddr, WireMessage)> {
    refresh();
    lock().chaos.release()
}

/// Wallets whose evidence the status builder should report (from the cached switch; no I/O).
pub fn watched_wallets() -> Vec<WalletId> {
    lock().chaos.watched_wallets()
}

/// The status builder hands in (wallet, `evidence_kind`) for every watched wallet.
pub fn set_evidence(ev: Vec<(WalletId, &'static str)>) {
    lock().evidence = ev.into_iter().map(|(w, k)| (hex::encode(w), k)).collect();
}

/// The `/status` `flood_chaos` object.
pub fn status_json() -> serde_json::Value {
    let g = lock();
    status_value(&g.chaos, g.path.as_ref(), &g.evidence)
}

fn status_value(c: &Chaos, path: Option<&PathBuf>, evidence: &BTreeMap<String, &'static str>) -> serde_json::Value {
    serde_json::json!({
        "switch": path.map(|p| p.display().to_string()),
        "entries": c.switch.entries.len(),
        "bad_lines": c.switch.bad_lines,
        "floods_dropped": c.counters.floods_dropped,
        "floods_held": c.counters.floods_held,
        "floods_released": c.counters.floods_released,
        "held_now": c.held_now(),
        "hold_overflow": c.counters.hold_overflow,
        "ae_entries_suppressed": c.counters.ae_entries_suppressed,
        "evidence": evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{NablaEntry, StatePullEntry, WalletStatus};

    const R: WalletId = [0xAA; 32];
    const OTHER: WalletId = [0xBB; 32];

    fn addr(p: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], p))
    }

    fn flood(wallet: WalletId, tx: u8) -> WireMessage {
        WireMessage::Gossip(GossipMessage::StateUpdate {
            wallet_id: wallet,
            old_state: [1; 32],
            new_state: [2; 32],
            tx_hash: [tx; 32],
            tick: 7,
            is_genesis_claim: false,
            wallet_seq: 1,
            client_pk: [3; 32],
            client_sig: vec![],
            amount: 0,
            fee_breakdown: vec![],
            seq_proof: None,
        })
    }

    fn entry(wallet: WalletId, tx: u8) -> NablaEntry {
        NablaEntry {
            wallet_id: wallet,
            current_state: [2; 32],
            tx_hash: [tx; 32],
            tick: 7,
            wallet_seq: 1,
            group_members: None,
            status: WalletStatus::Normal,
            client_pk: [3; 32],
            client_sig: vec![],
            received_from: None,
        }
    }

    fn pull_entry(wallet: WalletId, tx: u8) -> StatePullEntry {
        StatePullEntry {
            wallet_id: wallet,
            new_state: [2; 32],
            tx_hash: [tx; 32],
            tick: 7,
            wallet_seq: 1,
            client_pk: [3; 32],
            client_sig: vec![],
            seq_proof: None,
        }
    }

    fn chaos(text: &str) -> Chaos {
        Chaos { switch: parse(text), ..Default::default() }
    }

    fn tx_of(m: &WireMessage) -> u8 {
        flood_subject(m).expect("a flood").1[0]
    }

    #[test]
    fn parses_entries_and_counts_bad_lines() {
        let r = hex::encode(R);
        let sw = parse(&format!(
            "# header\ndrop wallet {r}\n  hold txid {t}  # trailing\nwatch wallet {r}\n\n\
             watch txid {t}\ndrop wallet nothex\nexplode wallet {r}\ndrop wallet {r} extra\n",
            t = hex::encode([0x11u8; 32]),
        ));
        assert_eq!(
            sw.entries,
            vec![(Action::Drop, Key::Wallet(R)), (Action::Hold, Key::Txid([0x11; 32])), (Action::Watch, Key::Wallet(R))]
        );
        assert_eq!(sw.bad_lines, 4, "watch-txid, bad hex, bad action, extra word — each COUNTED");
        assert_eq!(parse(""), Switch::default(), "missing / empty file = off");
    }

    /// MUTATION (run 2026-09-30): make `Key::matches` ignore `Key::Wallet` ⇒ RED here (and in the
    /// hold / status / overflow tests, which key on the wallet too).
    #[test]
    fn drop_wallet_suppresses_its_floods_and_head_ae_entries_only() {
        let mut c = chaos(&format!("drop wallet {}", hex::encode(R)));
        let out = c.filter(vec![
            (addr(1), flood(R, 0x21)),
            (addr(1), flood(OTHER, 0x22)),
            (addr(2), WireMessage::AeEntries {
                entries: vec![(entry(R, 0x21), None), (entry(OTHER, 0x22), None)],
                fork_bans: vec![],
            }),
            (addr(2), WireMessage::AeReconcile { from: [9; 32], push: vec![(entry(R, 0x21), None)], pull: vec![R], fork_bans: vec![] }),
            (addr(3), WireMessage::StatePullResponse {
                mode: crate::types::StatePullMode::Bootstrap,
                entries: vec![pull_entry(R, 0x21), pull_entry(OTHER, 0x22)],
                highest_tick_served: 7,
                bloom_eras: vec![],
                consumed_eras: vec![],
                consumed_era_manifest: vec![],
                previous_states: vec![],
                verify_result: None,
                available_from_tick: 0,
                overloaded: false,
            }),
            (addr(3), WireMessage::RangeSyncResponse {
                match_result: crate::types::RangeSyncMatch::Mismatch,
                missing_entries: vec![pull_entry(R, 0x21)],
                peer_latest_tick: 7,
                peer_section_hash: [0; 32],
            }),
        ]);
        assert_eq!(out.len(), 5, "only R's flood vanishes; the AE messages still go");
        assert_eq!(tx_of(&out[0].1), 0x22, "another wallet's flood passes");
        match &out[1].1 {
            WireMessage::AeEntries { entries, .. } => {
                assert_eq!(entries.iter().map(|(e, _)| e.wallet_id).collect::<Vec<_>>(), vec![OTHER]);
            }
            m => panic!("{m:?}"),
        }
        match &out[2].1 {
            WireMessage::AeReconcile { push, pull, .. } => {
                assert!(push.is_empty(), "R's head is not SERVED");
                assert_eq!(pull, &vec![R], "asking for R is not suppressed (inbound is not filtered)");
            }
            m => panic!("{m:?}"),
        }
        match &out[3].1 {
            WireMessage::StatePullResponse { entries, .. } => assert_eq!(entries.len(), 1),
            m => panic!("{m:?}"),
        }
        match &out[4].1 {
            WireMessage::RangeSyncResponse { missing_entries, .. } => assert!(missing_entries.is_empty()),
            m => panic!("{m:?}"),
        }
        assert_eq!(c.counters.floods_dropped, 1);
        assert_eq!(c.counters.ae_entries_suppressed, 4);
        assert_eq!(c.counters.floods_held, 0);
    }

    #[test]
    fn drop_txid_suppresses_only_that_transaction() {
        let mut c = chaos(&format!("drop txid {}", hex::encode([0x21u8; 32])));
        let out = c.filter(vec![(addr(1), flood(R, 0x21)), (addr(1), flood(R, 0x23))]);
        assert_eq!(out.len(), 1);
        assert_eq!(tx_of(&out[0].1), 0x23, "the same wallet's OTHER transaction still floods");
        assert_eq!(c.counters.floods_dropped, 1);
    }

    /// The mechanisms under test must never be touched. MUTATION (run 2026-09-30): make `filter`
    /// drop `RecordAeAnswer` ⇒ RED here (and only here).
    #[test]
    fn record_ae_fork_bans_and_other_traffic_never_suppressed() {
        let sk = crate::types::test_legs::wallet(0x51);
        let pk = sk.verifying_key().to_bytes();
        let open = crate::types::test_legs::opening(&sk);
        let a = crate::types::test_legs::genuine_redeem_leg(&sk, open, &crate::types::test_legs::stray_origin([0x61; 32]), 1_000, 1, 3);
        let b = crate::types::test_legs::genuine_redeem_leg(&sk, open, &crate::types::test_legs::stray_origin([0x62; 32]), 2_000, 1, 3);
        let claim = crate::types::ForkClaim { a: a.clone(), b: b.clone() };
        // Name the wallet AND both txids — nothing below may be touched regardless.
        let mut c = chaos(&format!(
            "drop wallet {}\ndrop txid {}\nhold txid {}\ndrop wallet {}",
            hex::encode(pk), hex::encode(a.tx_hash), hex::encode(b.tx_hash), hex::encode(R)
        ));
        let msgs = vec![
            WireMessage::Gossip(GossipMessage::ForkBan { claim: claim.clone() }),
            WireMessage::RecordAeAsk { from: [1; 32], nonce: 1, ask: crate::record_sync::Ask::Legs(vec![]), sig: vec![] },
            WireMessage::RecordAeAnswer { from: [1; 32], nonce: 1, answer: crate::record_sync::Answer::Legs(vec![]), sig: vec![] },
            WireMessage::AeEntries { entries: vec![], fork_bans: vec![claim.clone()] },
            WireMessage::AeReconcile { from: [1; 32], push: vec![], pull: vec![], fork_bans: vec![claim] },
        ];
        let out = c.filter(msgs.iter().cloned().map(|m| (addr(5), m)).collect());
        assert_eq!(out.len(), msgs.len());
        for ((_, got), want) in out.iter().zip(&msgs) {
            assert_eq!(format!("{got:?}"), format!("{want:?}"), "record-AE / ForkBan / AE fork_bans untouched");
        }
        assert_eq!(c.counters, Counters::default(), "nothing counted as suppressed");
    }

    /// The B2 reorder. MUTATION (run 2026-09-30): drop the `.rev()` in `release` ⇒ RED here only.
    #[test]
    fn hold_stashes_and_releases_newest_first_when_the_line_is_removed() {
        let line = format!("hold wallet {}", hex::encode(R));
        let mut c = chaos(&line);
        let out = c.filter(vec![(addr(1), flood(R, 0x31)), (addr(2), flood(R, 0x31)), (addr(1), flood(OTHER, 0x33))]);
        assert_eq!(out.len(), 1, "only the other wallet's flood goes now");
        let out = c.filter(vec![(addr(1), flood(R, 0x32))]);
        assert!(out.is_empty());
        assert_eq!((c.counters.floods_held, c.held_now()), (3, 3));
        assert!(c.release().is_empty(), "nothing released while the hold line is present");
        c.switch = parse(&format!("watch wallet {}", hex::encode(R))); // the harness removes the hold
        let rel = c.release();
        assert_eq!(rel.iter().map(|(a, m)| (a.port(), tx_of(m))).collect::<Vec<_>>(),
                   vec![(1, 0x32), (2, 0x31), (1, 0x31)], "newest first: ρ2 reaches every target before ρ1");
        assert_eq!((c.counters.floods_released, c.held_now()), (3, 0));
        assert!(c.release().is_empty(), "released once");
    }

    #[test]
    fn drop_beats_hold_and_watch_suppresses_nothing() {
        let r = hex::encode(R);
        let mut c = chaos(&format!("hold wallet {r}\ndrop txid {}", hex::encode([0x41u8; 32])));
        assert!(c.filter(vec![(addr(1), flood(R, 0x41))]).is_empty());
        assert_eq!((c.counters.floods_dropped, c.counters.floods_held), (1, 0), "drop wins");
        let mut w = chaos(&format!("watch wallet {r}"));
        let out = w.filter(vec![(addr(1), flood(R, 0x41)), (addr(1), WireMessage::AeEntries { entries: vec![(entry(R, 0x41), None)], fork_bans: vec![] })]);
        assert_eq!(out.len(), 2);
        assert!(matches!(&out[1].1, WireMessage::AeEntries { entries, .. } if entries.len() == 1));
        assert_eq!(w.counters, Counters::default());
        assert_eq!(w.watched_wallets(), vec![R]);
    }

    #[test]
    fn hold_is_bounded_and_the_overflow_counted() {
        let mut c = chaos(&format!("hold wallet {}", hex::encode(R)));
        let batch: Vec<_> = (0..HOLD_MAX + 3).map(|_| (addr(1), flood(R, 0x51))).collect();
        assert!(c.filter(batch).is_empty());
        assert_eq!((c.held_now(), c.counters.hold_overflow), (HOLD_MAX, 3));
    }

    /// RULE 6: the instrument reports what it did, and the JSON the gate reads carries it.
    /// MUTATION (run 2026-09-30): report `floods_held` under `floods_dropped` ⇒ RED here only.
    #[test]
    fn status_reports_counters_bad_lines_and_evidence() {
        let mut c = chaos(&format!("drop wallet {}\nbogus", hex::encode(R)));
        let _ = c.filter(vec![(addr(1), flood(R, 1)), (addr(1), WireMessage::AeEntries { entries: vec![(entry(R, 1), None)], fork_bans: vec![] })]);
        let mut ev = BTreeMap::new();
        ev.insert(hex::encode(R), evidence_kind(None));
        let v = status_value(&c, Some(&PathBuf::from("/d/flood-chaos")), &ev);
        assert_eq!(v["entries"], 1);
        assert_eq!(v["bad_lines"], 1);
        assert_eq!(v["floods_dropped"], 1);
        assert_eq!(v["floods_held"], 0);
        assert_eq!(v["ae_entries_suppressed"], 1);
        assert_eq!(v["evidence"][hex::encode(R)], "none");
        assert_eq!(v["switch"], "/d/flood-chaos");
        let sk = crate::types::test_legs::wallet(0x52);
        let open = crate::types::test_legs::opening(&sk);
        let a = crate::types::test_legs::genuine_redeem_leg(&sk, open, &crate::types::test_legs::stray_origin([0x71; 32]), 1_000, 1, 3);
        let b = crate::types::test_legs::genuine_redeem_leg(&sk, open, &crate::types::test_legs::stray_origin([0x72; 32]), 2_000, 1, 3);
        assert_eq!(evidence_kind(Some(&BanEvidence::Fork(crate::types::ForkClaim { a, b }))), "Fork");
    }

    #[test]
    fn an_empty_switch_is_the_identity() {
        let mut c = Chaos::default();
        let msgs = vec![(addr(1), flood(R, 1)), (addr(1), WireMessage::AeEntries { entries: vec![(entry(R, 1), None)], fork_bans: vec![] })];
        let out = c.filter(msgs.clone());
        assert_eq!(format!("{out:?}"), format!("{msgs:?}"));
        assert_eq!(c.counters, Counters::default());
    }
}
