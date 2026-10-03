# nabla/ — AI Assistant Orientation

Nabla is AXIOM's **citizen infrastructure**: the wallet-state SMT + WAL (`src/smt.rs`, `src/wal.rs`),
the gossip mesh (`src/gossip.rs`, `src/mesh.rs`, `src/transport.rs`), the TARDIS tick tree with its
bottom-up audit (`src/tardis.rs`), NBC/VBC issuance (`src/cc.rs` — production path is
`issue_nbc_via_core()`, the bare `issue_nbc()` is dev/ceremony only), txid + garbage bloom chains
(`src/bloom_chain.rs`, `src/bloom_era.rs`), CLARA heal registration (`src/clara.rs`), FOB bounded
pools (`src/fob.rs`), and JUDOON quarantine (`src/judoon.rs`). The node binary is
`src/bin/nabla_node.rs`. Naming culture: time-travel pop culture, Doctor Who primary canon
(TARDIS, CLARA, JUDOON, FOB) — if it sounds like it belongs in a time machine, it belongs here.

## Binding trust rules (violating these is a protocol defect, not a style issue)
- **Nabla is HYGIENE, not defence. It FAILS OPEN.** An attacker runs a patched node: empty bloom,
  skipped check, withheld answer. Core is the ONLY trusted enforcement — any defence that lives
  only in Nabla is a ghost. Before shipping a "security" check here, name the Core check that
  holds when this node is hostile (CLAUDE.md RULE 5; a hostile Nabla can withhold, never lie).
- **Validators never depend on Nabla on the core service path.** The one sanctioned periodic
  dependency is VBC renewal. Nabla artifacts reach validators client-carried and are
  independently verified.
- **Demote, never disconnect.** §5.6a peer-observed demotion redirects writes via
  `writer_routing()`; a demoted node keeps gossip, AE, ticks and children. Demotion is
  **unanimity, never majority**: ONE dissenting address report demotes (`disagreed =
  distinct.len() > 1`), and a unanimous RFC1918/CGNAT address also demotes.
- **BAN is the only terminal state** and bans are PERMANENT — `BanStatus` has exactly one
  variant, `Active` (`src/types.rs`). Everything else is recoverable; no cascade.

## Concurrency — the one rule that has killed nodes
**NEVER put a blocking or unbounded call under the global node mutex.** `handle_message` runs as
`state.lock() → handle_message(&mut node, …)`; the tick loop, dashboard, and every handler share
that one `Mutex<NablaNodeState>`. A blocking DNS resolve on this path froze 3/10 nodes in ~90 min
(fixed `e475537c`: message-path resolution is a pure cache read; a background thread refreshes).
"Send responses (outside lock)" / `prelock_hal_verify` comments are load-bearing — keep the
critical section short. TCP writes carry `TCP_WRITE_TIMEOUT` (10 s) plus the KI#96 per-peer
circuit-breaker (`src/transport.rs`): a peer that times out goes cold immediately, because even a
bounded write burns its timeout under the mutex on every gossip/AE cycle.

## Storage and merge
- **Proof retention is structural.** Bare `smt.put` is `#[cfg(test)]`-only; every production head
  write declares a `PutProof` disposition via `put_with_proof` (`src/smt.rs`). Registration fails
  CLOSED on an unattestable origin head. Never reintroduce a put-then-set-proof convention.
- **A node must not store what it would reject from a peer** (AntiEntropy doc §6 owns this rule;
  cited at `src/types.rs` and `bin/nabla_node.rs`). Unauthored LOCAL writes become permanent
  divergence. When adding any acceptance gate, grep this layer's own `smt.put*`/`apply_*` sites.
- **One merge owner.** `NablaEntry::superseded_by` (`src/types.rs`) is the single merge authority;
  flood and AE both route through it, both gated on A12 `is_state_consumed` first. Never add a
  second merge rule or call-site check.

## HTTP = the local dashboard, nothing else
Nabla has no functional HTTP (YP "Transport — functional endpoints", amended 2026-09-26). The one HTTP
listener binds `127.0.0.1` only (`DASHBOARD_BIND`), serves `GET` only (`dashboard_request` → `405`
otherwise), and routes to `monitor::route_request` — a former functional path is a `404`. Every wallet,
validator and operator operation is a TCP-CBOR `WireMessage` arm; the browser reaches it through TOT.
Never add an HTTP route that changes state or serves a client, and never re-add a remote bind:
`dashboard_remote = true` in `node.toml` refuses to start.

## Configuration
- **Tuning lives in `protocol_nabla.toml`, NEVER as consts in .rs.** Edit the register, rebuild;
  `build.rs` + `src/tuning_gen.rs` regenerate `constants.rs`. Dev value is the uncommented line,
  prod value is the commented one beneath it. Nabla-only tuning has NO CoreID impact.
- **KI#47 units discipline**: a tick VALUE is a unix-second stamp; a tick COUNT is a number of
  ticks and must be projected via `ticks_to_secs` (`TickCount` typing makes raw comparison a
  compile error). The toml annotates which keys are COUNTS — read the unit note before editing.
- **`node.toml` is REQUIRED**: `external_port` has no default and 0 is rejected — an un-updated
  node REFUSES TO START. Both a MISSING `node.toml` and one that fails to load are FATAL at startup (stderr +
  exit 1, since 2026-09-26; only `--emission-bundle` runs without one). Before, a load error was
  swallowed and a missing file only panicked after the NBC fetch. `--advertise` is deleted; a node asserts no address on any channel
  (§5.6a-bis: receiver composes observed-IP : declared-port; the port stays trust-me).

## /status traps
- `is_writer` is NOT write qualification — it is `downstream_count == 2`, pure tree position.
  `is_writer: true` with `address_disputed: true` is legal. For "can this node accept writes?"
  read `address_disputed` / `reader_only`. This trap has already cost a false regression report.
- Five fields are `ALLOW_UNWIRED_FIELD` constants — `deed_collected`, `deed_split`,
  `runner_pool_balance`, `orphans_rescued`, `rotations_survived`. NEVER cite them as measurements.

## Read these first (each carries a binding AI READER PREAMBLE — the dated overlays rule)
`docs/AXIOM_GUIDE_Nabla.md` (implementation guide; §5.6a/§5.6a-bis, serve-gate, /status traps),
`docs/AXIOM_DESIGN_NablaAntiEntropy.md` (SMT convergence; merge rule, PutProof, §6 store-rule),
`docs/AXIOM_YPX-002_NABLA.md`, `docs/AXIOM_DESIGN_NablaJudoon.md`. History blocks (strikethrough,
⚠ STALE, SUPERSEDED) are deliberate retained history — never act on them, never delete them.
Attribution in docs is "AXIOM Origin Validator", never a personal name. Serve-gate: a node starts
UNARMED and refuses registrations until a completed Bootstrap StatePull (`[ARMED]`, ~2 min after
restart). TARDIS audit divergence is NEVER detach grounds — the exoneration path is normative.
