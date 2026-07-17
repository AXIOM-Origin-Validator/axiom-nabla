// AXIOM Nabla — Operator Dashboard & Health Monitoring
// Reference: AXIOM_GUIDE_Nabla.md Phase 6 Task 49
//
// Embedded HTTP server for monitoring. Serves:
//   GET /           → HTML dashboard (interactive D3 operator console)
//   GET /status     → JSON status (auto-refresh every 2s via fetch)
//   GET /health     → JSON health check (for scripts/load balancers)
//   GET /api/status → Full JSON status (for programmatic access)
//
// Architecture:
//   The monitor collects a NodeStatus snapshot from NablaNode.
//   The web server is optional — node works fine without it.
//   Default: localhost:6226 (avoids collision with P2P port 6225)
//
// Penguin Scoring System (10-year scale):
//   Contribution Score = ticks_online/1000 + writes_approved*5/1000
//                      + transactions*10/1000 + orphans_rescued*50
//                      + rotations_survived*100
//   Reliability Multiplier (30-day uptime):
//     99.9% → 3x, 99% → 2x, 95% → 1x, <90% → 0.5x
//   Combined = Contribution × Reliability
//
//   Levels:
//     0-1000      Hatchling    (~first month)
//     1000-10000  Penguin      (~6 months)
//     10000-100k  Ice Runner   (~2 years)
//     100k-500k   Emperor      (~5 years)
//     500k+       Colony Elder (~8+ years)
//
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  The monitor reads state. It never writes. No mutations.           ║
// ║  It is a read-only window into the node.                          ║
// ╚══════════════════════════════════════════════════════════════════════╝

use serde::Serialize;
use std::time::SystemTime;

/// Default monitor port (6226 to avoid collision with P2P port 6225).
pub const DEFAULT_MONITOR_PORT: u16 = 6226;

/// Complete node status snapshot — collected once and served to all endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatusSnapshot {
    // ── Identity ──
    pub version: String,
    pub node_name: String,
    pub node_id_hex: String,
    pub uptime_secs: u64,
    /// YPX-014 txid service mode this node is running — `"hashmap"`
    /// or `"bloom"`. Operator's `--txid-mode` choice. Surfaced on
    /// `/status` so the dashboard can show it per-node, and so
    /// audit-grade consumers (UNCLE, regulator clients) can verify
    /// directly from the source rather than going through a gossiped
    /// peer cache.
    #[serde(default)]
    pub txid_service: String,
    /// Number of (txid → wallet_id) entries in the exact hashmap.
    /// Always 0 in bloom mode. Operators capacity-plan against this
    /// — hashmap memory grows linearly with this count.
    #[serde(default)]
    pub txid_hashmap_len: u64,
    /// Estimated resident bytes of the exact hashmap (~96 B/entry).
    /// Always 0 in bloom mode.
    #[serde(default)]
    pub txid_hashmap_bytes: u64,
    /// Number of distinct txids inserted into the bloom filter since
    /// boot. ALWAYS populated (both modes use bloom — it's the only
    /// tier in bloom mode and the fast negative pre-check in hashmap
    /// mode).
    #[serde(default)]
    pub txid_bloom_count: u64,
    /// Physical bytes of the bloom filter. Fixed at boot.
    #[serde(default)]
    pub txid_bloom_bytes: u64,
    /// Current estimated false-positive rate of the bloom filter
    /// (0.0..=1.0). Climbs as the filter saturates; operators watch
    /// this to decide when to bump `--bloom-size`.
    #[serde(default)]
    pub txid_bloom_fpr: f64,

    // ── Network ──
    pub listen_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_addr: Option<String>,

    // ── TARDIS ──
    pub current_tick: u64,
    pub tardis_active: bool,
    pub tardis_slot: String,
    pub has_upstream: bool,
    pub downstream_count: usize,
    pub is_writer: bool,
    pub d1_approved: bool,
    pub d2_approved: bool,

    // ── Writer-rotation observability (KI#18 diagnostic, 2026-05-28) ──
    /// Ticks accumulated with the current parent since last reattach.
    /// Advances ONLY in `process_tick()` (`tardis.rs:350`) — i.e. when a
    /// child receives a TickMessage from its upstream over the wire.
    /// `wants_rotate()` fires when this exceeds `CHILD_ROTATION_INTERVAL_TICKS
    /// + jitter` (150-170 ticks ≈ 2.5-3 min). If it stays at 0 or doesn't
    /// advance, parent→child Tick delivery is broken.
    #[serde(default)]
    pub ticks_with_current_parent: u32,
    /// Decrements 1/tick. Set to `REBALANCE_COOLDOWN_TICKS + 1 = 11`
    /// after a rotation fires. If > 0 in steady state without a recent
    /// rotation, the cooldown gate is wedged.
    #[serde(default)]
    pub rebalance_cooldown: u8,

    // ── SMT / Data ──
    pub root_hash_hex: String,
    pub entry_count: usize,
    pub ban_count: usize,

    // ── Mesh ──
    pub mesh_active: bool,
    pub mesh_peer_count: usize,
    pub mesh_target_peers: usize,
    pub mesh_known_nodes: usize,
    pub estimated_network_size: usize,
    /// OODS (YPX-021) size estimate over this node's learned mesh view, via
    /// Extrema Propagation with identity-bound draws. Read-only telemetry — NOT
    /// a consensus gate. Distinct from `estimated_network_size` (the naive
    /// `unique_seen`-count heuristic, which a Sybil can inflate); OODS is the
    /// forgery-resistant readout. Watch it drop under a partition/eclipse.
    pub oods_estimate: f64,
    /// OODS-tardis (YPX-021 §6) size estimate — the SECOND, Core-produced OODS,
    /// computed by `oods_estimate` over the tick's cascaded extrema accumulator
    /// (`latest_oods_tardis`). Independent of `oods_estimate` above (gossip mesh
    /// view): this rides the TARDIS tick tree. A gap between the two flags a
    /// partition (tree view vs mesh view disagree). 0 until the first tick.
    #[serde(default)]
    pub tardis_depth: u32,
    /// E-peer (enquiry peer): reader node used for TARDIS tree exploration.
    /// Max 1 per node (E_PEER_MAX=1), TTL=12 ticks.
    pub enquiry_peer_count: usize,

    // ── CC / Runner ──
    pub cc_active: bool,
    pub cc_tick: u64,
    pub cc_ticks_helped: u64,
    pub cc_total_registrations: u64,
    pub cc_score: u64,
    pub runner_pool_balance: u64,

    // ── Airdrop Pool (§17.11) ──
    pub airdrop_pool_balance: u64,
    pub airdrop_pool_claims: u64,
    pub airdrop_local_claims: u64,

    // ── Dev Treasury Pool (FACT class isolation §6) ──
    // 1M dev-AXC, OUTSIDE the 100M public cap. Surfaced in the
    // dashboard mirror of airdrop so operators can see dev-AXC
    // consumption distinct from public-AXC airdrop consumption.
    pub dev_pool_balance: u64,
    pub dev_pool_claims: u64,
    pub dev_pool_local_claims: u64,

    // ── DEED ──
    pub deed_collected: u64,
    pub deed_split: String,
    /// PR3: DEED Pool current balance — 10% of every receiver-pays
    /// validator fee accumulated for the first 10 years
    /// (`docs/AXIOM_DESIGN_DeedDistribution.md`). Surfaced on the
    /// Protocol Pools card so operators can watch the pool grow in
    /// real time. Distinct from `deed_collected`, which counts the
    /// 1000-atom write fee on every register.
    #[serde(default)]
    pub deed_pool_balance: u64,
    #[serde(default)]
    pub deed_pool_total_credited: u64,

    /// Dev-class DEED Pool — same 10% slice mechanism, but credited
    /// from `@axiom.internal` TXs only. Observability for the dev
    /// economy; NEVER convertible to public AXC
    /// (`AXIOM_DESIGN_FactClassIsolation.md`). Surfaced on the Protocol
    /// Pools card as a small-text sub-line under the public DEED rows
    /// so operators can see what's collecting from test traffic without
    /// confusing it with the real DEED accounting.
    #[serde(default)]
    pub dev_deed_pool_balance: u64,
    #[serde(default)]
    pub dev_deed_pool_total_credited: u64,

    // ── Gossip ──
    pub gossip_seen_count: usize,
    pub last_gossip_tick: u64,

    // ── Transport observability (2026-04-15 fix `af79958` companion) ──
    /// Total TCP send failures across recv_loop + tick_loop drain paths.
    /// Counts how often the cached-connection eviction recovery in
    /// `TcpTransport::send` had to re-establish a TCP socket. Code:
    /// `E_NABLA_TRANSPORT_SEND_FAILED`. Persistent non-zero indicates
    /// network instability or peer churn — investigate per-peer breakdown.
    #[serde(default)]
    pub transport_send_failures_total: u64,
    /// Per-peer send failure breakdown. Key is "ip:port" string.
    /// Empty in steady-state; non-empty entries are recovery events.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub transport_send_failures_per_peer: std::collections::HashMap<String, u64>,

    /// KI#37 — outbound-storm circuit breaker (backstop against any
    /// re-broadcast loop/flood). `storm_shed_active` is true while the
    /// node is dropping forward/broadcast traffic because its 1s
    /// forward-send rate crossed the shed ceiling; `storm_dropped_total`
    /// and `storm_trips_total` accumulate since boot. All three are 0 /
    /// false on a healthy mesh — any non-zero value means a storm was
    /// detected and contained.
    #[serde(default)]
    pub storm_shed_active: bool,
    #[serde(default)]
    pub storm_dropped_total: u64,
    #[serde(default)]
    pub storm_trips_total: u64,

    /// Fix #1: Cumulative TARDIS tick-signature verify failures since
    /// boot. Counts how often `process_tick` saw an incoming tick
    /// whose `signature` failed Core's `signer.verify` against the
    /// claimed `upstream_pk`. Non-zero in steady state flags:
    /// transport corruption (different payload_hash from same
    /// sender), signing-key drift, or replay of stale ticks. Detail
    /// per-failure lives in `nabla.log` as `[TICK-SIG-FAIL] …`
    /// structured lines. See node.rs `TardisNode::tick_sig_failures`.
    #[serde(default)]
    pub tick_sig_failures: u64,

    /// Phase B Layer 4: number of currently-active mesh-wide
    /// quarantines this Nabla is enforcing. Non-zero means we are
    /// dropping all gossip from quarantined peers per
    /// `is_peer_quarantined`. Auto-expires after
    /// QUARANTINE_DURATION_TICKS.
    #[serde(default)]
    pub quarantine_active_count: usize,
    /// Phase B Layer 4: number of in-flight pending-alert buckets
    /// (accused-peer aggregations within the 10-tick consensus
    /// window). Increments as alerts arrive; decrements when a
    /// bucket either crosses the 3-of-N threshold (→ quarantine
    /// fires, bucket removed) or expires (sweep at window close).
    #[serde(default)]
    pub quarantine_pending_count: usize,

    // ── Scoring ──
    pub penguin_score: u64,
    pub penguin_level: String,
    pub penguin_emoji: String,
    pub uptime_streak_days: u64,
    pub writes_approved: u64,
    pub orphans_rescued: u64,
    pub rotations_survived: u64,
    pub reliability_multiplier: f64,

    // ── Persistence / Storage ──
    pub wal_file_bytes: u64,
    pub wal_ops_since_snapshot: u64,
    pub snapshot_count: usize,
    pub snapshot_total_bytes: u64,
    pub last_snapshot_tick: u64,
    pub total_disk_bytes: u64,
    pub smt_memory_bytes: u64,

    // ── Peer details (for D3 graph) ──
    pub upstream_hex: String,
    pub upstream_name: String,
    pub d1_hex: String,
    pub d1_name: String,
    pub d2_hex: String,
    pub d2_name: String,
    pub peer_list: Vec<PeerEntry>,

    // ── Bootstrap ──
    pub bootstrap_peers: Vec<BootstrapPeerEntry>,

    // ── Health ──
    pub healthy: bool,
    pub health_issues: Vec<String>,
}

/// A mesh peer for the dashboard graph.
#[derive(Debug, Clone, Serialize)]
pub struct PeerEntry {
    pub node_id_hex: String,
    pub node_name: String,
    pub is_genesis: bool,
    /// YPX-014 txid service mode, as advertised by that peer via Hello
    /// gossip (`"hashmap"` or `"bloom"`). Empty for peers running a
    /// pre-2026-05-30 binary that doesn't carry the field. Audit-grade
    /// consumers (UNCLE, regulator clients) gate register/query routing
    /// on this — empty + non-hashmap both mean "not audit-grade for k=5
    /// institutional traffic."
    #[serde(default)]
    pub txid_service: String,
}

/// A bootstrap peer with connection status.
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapPeerEntry {
    pub address: String,
    pub status: String,
    pub status_emoji: String,
    pub last_seen: String,
    pub latency_ms: Option<u64>,
}

/// Health check result (lightweight, for /health endpoint).
#[derive(Debug, Clone, Serialize)]
pub struct HealthCheck {
    pub healthy: bool,
    pub version: String,
    pub tick: u64,
    pub entry_count: usize,
    pub peer_count: usize,
    pub issues: Vec<String>,
}

impl From<&NodeStatusSnapshot> for HealthCheck {
    fn from(s: &NodeStatusSnapshot) -> Self {
        Self {
            healthy: s.healthy,
            version: s.version.clone(),
            tick: s.current_tick,
            entry_count: s.entry_count,
            peer_count: s.mesh_peer_count,
            issues: s.health_issues.clone(),
        }
    }
}

/// Determine health issues from a status snapshot.
pub fn diagnose(status: &mut NodeStatusSnapshot) {
    let mut issues = Vec::new();

    if !status.tardis_active {
        issues.push("TARDIS not initialized".into());
    }
    if !status.mesh_active {
        issues.push("Mesh not initialized".into());
    }
    if status.mesh_active && status.mesh_peer_count == 0 {
        issues.push("No mesh peers connected".into());
    }
    if status.mesh_active && status.mesh_peer_count < status.mesh_target_peers / 2 {
        issues.push(format!(
            "Low peer count: {} / {} target",
            status.mesh_peer_count, status.mesh_target_peers
        ));
    }
    if !status.cc_active {
        issues.push("CC chain not initialized".into());
    }
    if status.tardis_active && status.tardis_slot == "E" {
        issues.push("TARDIS slot: E (stateless enquiry only)".into());
    }

    status.healthy = issues.is_empty();
    status.health_issues = issues;
}

// ── Penguin Scoring ──

/// Compute the penguin contribution score.
pub fn penguin_contribution(
    ticks_online: u64,
    writes_approved: u64,
    transactions_served: u64,
    orphans_rescued: u64,
    rotations_survived: u64,
) -> u64 {
    ticks_online / 1000
        + writes_approved * 5 / 1000
        + transactions_served * 10 / 1000
        + orphans_rescued * 50
        + rotations_survived * 100
}

/// Compute the reliability multiplier from 30-day uptime percentage.
pub fn reliability_multiplier(uptime_pct: f64) -> f64 {
    if uptime_pct >= 99.9 { 3.0 }
    else if uptime_pct >= 99.0 { 2.0 }
    else if uptime_pct >= 95.0 { 1.0 }
    else if uptime_pct >= 90.0 { 0.75 }
    else { 0.5 }
}

/// Return (level_name, emoji) for a given score.
pub fn penguin_level(score: u64) -> (&'static str, &'static str) {
    if score >= 500_000      { ("Colony Elder", "\u{1F3D4}\u{FE0F}") }
    else if score >= 100_000 { ("Emperor Penguin", "\u{1F451}") }
    else if score >= 10_000  { ("Ice Runner", "\u{2744}\u{FE0F}") }
    else if score >= 1_000   { ("Penguin", "\u{1F427}") }
    else                     { ("Hatchling", "\u{1F95A}") }
}

/// Format a byte array as hex string (first 8 bytes).
pub fn hex_short(bytes: &[u8; 32]) -> String {
    bytes[..8]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Format uptime from a start timestamp.
pub fn uptime_secs(start: SystemTime) -> u64 {
    start.elapsed().map(|d| d.as_secs()).unwrap_or(0)
}

/// Format a NablaAddress as a display string.
pub fn format_address(addr: &crate::types::NablaAddress) -> String {
    match addr {
        crate::types::NablaAddress::V4 { ip, port } =>
            format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port),
        crate::types::NablaAddress::V6 { ip, port } => {
            let segs: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([ip[i*2], ip[i*2+1]])))
                .collect();
            format!("[{}]:{}", segs.join(":"), port)
        }
    }
}

// ── HTTP Response Builders ──

/// Build JSON response body for /api/status or /status.
pub fn json_status(status: &NodeStatusSnapshot) -> String {
    serde_json::to_string_pretty(status).unwrap_or_else(|_| "{}".into())
}

/// Build JSON response body for /health.
pub fn json_health(status: &NodeStatusSnapshot) -> String {
    let health: HealthCheck = status.into();
    serde_json::to_string_pretty(&health).unwrap_or_else(|_| "{}".into())
}

/// Build HTML dashboard page — single-page app with D3 network graph,
/// cockpit bar, stats cards, and auto-refresh via fetch().
pub fn html_dashboard(_status: &NodeStatusSnapshot) -> String {
    // The dashboard is fully client-side: the HTML is static, and JS
    // fetches /status every 2 seconds for live updates.
    //
    // `{{ATOMS_PER_AXC}}` is substituted from `axiom_denomination::ATOMS_PER_AXC`
    // — the workspace's single source of truth for the AXC↔atom divisor.
    // If the served HTML still shows the raw placeholder, the nabla
    // binary's dependency on the denomination crate has been severed
    // — CONSOLIDATION REGRESSION, not a UI bug.
    DASHBOARD_HTML.replace(
        "{{ATOMS_PER_AXC}}",
        &axiom_denomination::ATOMS_PER_AXC.to_string(),
    )
}

/// Format seconds into human-readable uptime.
#[cfg(test)]
fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m {}s", mins, secs % 60)
    }
}

/// Monitor configuration.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Port to listen on.
    pub port: u16,
    /// Bind address (default: 127.0.0.1).
    pub bind_addr: String,
    /// Optional auth token (if set, requires ?token=xxx on all endpoints).
    pub auth_token: Option<String>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_MONITOR_PORT,
            bind_addr: "127.0.0.1".into(),
            auth_token: None,
        }
    }
}

/// Route an HTTP request to the appropriate handler.
///
/// Returns (status_code, content_type, body).
pub fn route_request(
    path: &str,
    query: Option<&str>,
    status: &NodeStatusSnapshot,
    config: &MonitorConfig,
) -> (u16, &'static str, String) {
    // Auth check
    if let Some(ref token) = config.auth_token {
        let provided = query
            .and_then(|q| {
                q.split('&')
                    .find(|p| p.starts_with("token="))
                    .map(|p| &p[6..])
            });
        match provided {
            Some(t) if t == token => {} // OK
            _ => return (401, "text/plain", "Unauthorized".into()),
        }
    }

    match path {
        "/" => (200, "text/html; charset=utf-8", html_dashboard(status)),
        "/status" => (200, "application/json", json_status(status)),
        "/health" => {
            let code = if status.healthy { 200 } else { 503 };
            (code, "application/json", json_health(status))
        }
        "/api/status" => (200, "application/json", json_status(status)),
        "/genesis" => (200, "application/json", json_genesis()),
        _ => (404, "text/plain", "Not Found".into()),
    }
}

/// GET /genesis — public endpoint, no auth required.
/// Returns FACT #0 with headlines, sub-pools, and genesis hash.
fn json_genesis() -> String {
    use axiom_core_logic::genesis_integrity::{build_genesis_fact, compute_genesis_fact_hash, GENESIS_POOL_TOTAL};

    let fact = build_genesis_fact(1); // tick=1 for genesis
    let hash = compute_genesis_fact_hash(&fact);

    serde_json::json!({
        "fact_id": 0,
        "pool_total": GENESIS_POOL_TOTAL,
        "genesis_date": axiom_core_logic::genesis_integrity::GENESIS_DATE,
        "genesis_fact_hash": hex::encode(hash),
        "sub_pools": fact.sub_pools.iter().map(|p| {
            serde_json::json!({
                "pool_id": format!("{:?}", p.pool_id),
                "initial_balance": p.initial_balance,
            })
        }).collect::<Vec<_>>(),
        "headlines": fact.headlines.iter().map(|h| {
            serde_json::json!({
                "country": h.country,
                "organisation": h.organisation,
                "timestamp": h.timestamp,
                "headline": h.headline,
            })
        }).collect::<Vec<_>>(),
        "signed": !fact.core_signature.is_empty(),
    }).to_string()
}

// ══════════════════════════════════════════════════════════════════════
// Dashboard HTML — single-page app with embedded JS/CSS
// ══════════════════════════════════════════════════════════════════════

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AXIOM Nabla — Operator Dashboard</title>
<style>
:root {
  --bg: #0a0e17; --bg2: #111827; --bg3: #141b2d;
  --border: #1e2a3a; --text: #c8d6e5; --dim: #78909c;
  --gold: #f5a623; --green: #2ecc71; --yellow: #f39c12;
  --red: #e74c3c; --blue: #3498db; --purple: #9b59b6;
  --cyan: #00d2d3;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'SF Mono', 'Fira Code', -apple-system, BlinkMacSystemFont, 'Noto Sans CJK SC', 'Noto Sans CJK TC', 'Noto Sans CJK JP', monospace;
       background: var(--bg); color: var(--text); overflow-x: hidden; }

/* ── Cockpit Bar ── */
.cockpit { position: fixed; top: 0; left: 0; right: 0; z-index: 100;
  background: linear-gradient(180deg, #111827 0%, #0d1117 100%);
  border-bottom: 1px solid var(--border); padding: 8px 16px;
  display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
  min-height: 48px; }
.cockpit .logo { color: var(--gold); font-size: 1.1em; font-weight: 700;
  white-space: nowrap; }
.cockpit .sep { color: #333; }
.chip { display: inline-flex; align-items: center; gap: 4px;
  background: #1a1f2e; border: 1px solid var(--border); border-radius: 12px;
  padding: 2px 10px; font-size: 0.72em; white-space: nowrap; }
.chip .label { color: var(--dim); }
.chip .val { color: #e8e8e8; font-weight: 600; }
.chip .val.gold { color: var(--gold); }
.chip .val.green { color: var(--green); }
.chip .val.red { color: var(--red); }
.chip .val.cyan { color: var(--cyan); }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 2px; }
.dot.green { background: var(--green); box-shadow: 0 0 6px var(--green); }
.dot.yellow { background: var(--yellow); }
.dot.red { background: var(--red); }

/* ── Main Content ── */
.main { padding: 60px 16px 16px 16px; max-width: 1400px; margin: 0 auto; }

/* ── Network Graph ── */
.graph-container { background: var(--bg3); border: 1px solid var(--border);
  border-radius: 12px; margin-bottom: 16px; position: relative;
  overflow: hidden; }
.graph-container svg { width: 100%; display: block; }
.graph-title { position: absolute; top: 8px; left: 12px; color: var(--dim);
  font-size: 0.7em; text-transform: uppercase; letter-spacing: 2px;
  pointer-events: none; }
.graph-legend { position: absolute; bottom: 8px; right: 12px;
  font-size: 0.6em; color: var(--dim); pointer-events: none; }
.node-popup { position: absolute; background: #1a2030; border: 1px solid var(--gold);
  border-radius: 8px; padding: 10px 14px; font-size: 0.72em;
  color: var(--text); pointer-events: none; z-index: 10;
  box-shadow: 0 4px 20px rgba(0,0,0,0.5); display: none; }
.node-popup .pp-id { color: var(--gold); font-weight: 700; }
.node-popup .pp-row { margin-top: 2px; }

/* ── Stats Cards ── */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 12px; margin-bottom: 16px; }
.card { background: var(--bg3); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px; }
.card-title { color: var(--dim); font-size: 0.7em; text-transform: uppercase;
  letter-spacing: 2px; margin-bottom: 10px; display: flex;
  align-items: center; gap: 6px; }
.card-title .icon { font-size: 1.1em; }
.stat-row { display: flex; justify-content: space-between; align-items: baseline;
  padding: 3px 0; border-bottom: 1px solid #1a2030; }
.stat-row:last-child { border-bottom: none; }
.stat-label { color: var(--dim); font-size: 0.75em; }
.stat-value { color: #e8e8e8; font-weight: 600; font-size: 0.85em; }
.stat-value.gold { color: var(--gold); }
.stat-value.green { color: var(--green); }
.stat-value.cyan { color: var(--cyan); }
.stat-value.yellow { color: var(--yellow); }
.stat-value.red { color: var(--red); }
.sparkline { margin-top: 8px; height: 30px; }
.sparkline svg { width: 100%; height: 30px; }

/* ── Technical Details ── */
.details-toggle { background: none; border: 1px solid var(--border);
  color: var(--dim); padding: 6px 14px; border-radius: 6px;
  cursor: pointer; font-family: inherit; font-size: 0.72em;
  letter-spacing: 1px; text-transform: uppercase; margin-bottom: 8px; }
.details-toggle:hover { border-color: var(--gold); color: var(--gold); }
.details-panel { display: none; background: var(--bg3); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px; margin-bottom: 16px; }
.details-panel.open { display: block; }
.detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 8px; }
.detail-row { display: flex; justify-content: space-between; padding: 3px 0;
  font-size: 0.72em; }
.detail-label { color: var(--dim); }
.detail-value { color: var(--text); font-weight: 500; }

/* ── Bootstrap Peers ── */
.bp-table { width: 100%; border-collapse: collapse; font-size: 0.75em; }
.bp-table th { text-align: left; color: var(--dim); font-weight: 500;
  padding: 4px 8px; border-bottom: 1px solid var(--border);
  text-transform: uppercase; font-size: 0.85em; letter-spacing: 1px; }
.bp-table td { padding: 5px 8px; border-bottom: 1px solid #1a2030; }
.bp-table tr:last-child td { border-bottom: none; }
.bp-addr { color: var(--text); font-weight: 500; }
.bp-latency { color: var(--dim); }

/* ── Footer ── */
.footer { text-align: center; color: #333; font-size: 0.65em; padding: 16px 0; }
.footer a { color: #444; }

/* ── Mobile ── */
@media (max-width: 768px) {
  .cockpit { gap: 6px; padding: 6px 10px; }
  .chip { font-size: 0.65em; padding: 2px 6px; }
  .cards { grid-template-columns: 1fr; }
  .main { padding: 56px 8px 8px 8px; }
  .detail-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>

<!-- Cockpit Bar -->
<div class="cockpit">
  <span class="logo">&#x2207; AXIOM Nabla</span>
  <span class="sep">|</span>
  <span class="chip"><span id="ck-emoji"></span><span class="val gold" id="ck-level">--</span></span>
  <span class="chip"><span class="label">Score</span><span class="val gold" id="ck-score">0</span></span>
  <span class="chip"><span class="label">Uptime</span><span class="val green" id="ck-uptime">--</span></span>
  <span class="chip"><span class="label">AXC</span><span class="val cyan" id="ck-axc">0</span></span>
  <span class="chip"><span class="val gold" id="ck-name">--</span></span>
  <span class="chip"><span class="label">ID</span><span class="val" id="ck-id">--</span></span>
  <span class="chip"><span class="label">Addr</span><span class="val" id="ck-addr">--</span></span>
  <span class="chip"><span class="label">Settlement</span><span class="val" id="ck-txid-mode">--</span></span>
  <span class="chip"><span id="ck-role-dot" class="dot green"></span><span class="val" id="ck-role">--</span></span>
  <span class="chip"><span class="label">Tick</span><span class="val" id="ck-tick">0</span></span>
</div>

<div class="main">

<!-- Network Graph -->
<div class="graph-container">
  <div class="graph-title">Network Topology</div>
  <svg id="graph" viewBox="0 0 900 400"></svg>
  <div class="graph-legend">
    &#x25C6; genesis &nbsp; &#x25CF; peer &nbsp;
    <span style="color:var(--gold)">&#x2B24;</span> me &nbsp;
    <span style="color:var(--green)">&#x25CF;</span> healthy &nbsp;
    <span style="color:var(--yellow)">&#x25CF;</span> stale &nbsp;
    <span style="color:var(--red)">&#x25CF;</span> lost
  </div>
  <div class="node-popup" id="popup">
    <div class="pp-id" id="pp-id">--</div>
    <div class="pp-row" id="pp-role">--</div>
    <div class="pp-row" id="pp-detail">--</div>
    <div class="pp-row" id="pp-txid">--</div>
  </div>
</div>

<!-- Stats Cards -->
<div class="cards">
  <!-- Card 1: Transactions -->
  <div class="card">
    <div class="card-title"><span class="icon">&#x1F4CA;</span> Transactions</div>
    <div class="stat-row"><span class="stat-label">Total Served</span><span class="stat-value" id="s-tx-total">0</span></div>
    <div class="stat-row"><span class="stat-label">Ticks Helped</span><span class="stat-value" id="s-tx-helped">0</span></div>
    <div class="stat-row"><span class="stat-label">Entries (SMT)</span><span class="stat-value" id="s-tx-entries">0</span></div>
    <div class="stat-row"><span class="stat-label">Root Hash</span><span class="stat-value" id="s-tx-hash" style="font-size:0.65em">--</span></div>
    <div class="sparkline"><svg id="spark-tx" viewBox="0 0 280 30"></svg></div>
  </div>

  <!-- Card 2: Earnings -->
  <div class="card">
    <div class="card-title"><span class="icon">&#x1F4B0;</span> Earnings</div>
    <div class="stat-row"><span class="stat-label">AXC Accumulated</span><span class="stat-value cyan" id="s-earn-total">0</span></div>
    <div class="stat-row"><span class="stat-label">DEED Collected</span><span class="stat-value" id="s-earn-deed">0</span></div>
    <div class="stat-row"><span class="stat-label">Fee Split</span><span class="stat-value" id="s-earn-split">--</span></div>
    <div class="sparkline"><svg id="spark-earn" viewBox="0 0 280 30"></svg></div>
  </div>

  <!-- Card 2b: Protocol Pools -->
  <div class="card">
    <div class="card-title"><span class="icon">&#x1F3E6;</span> Protocol Pools</div>
    <div class="stat-row"><span class="stat-label">Runner</span><span class="stat-value" id="s-earn-pool">0</span></div>
    <div class="stat-row"><span class="stat-label">Airdrop</span><span class="stat-value cyan" id="s-airdrop-balance">--</span></div>
    <div class="stat-row"><span class="stat-label">Claims Processed</span><span class="stat-value" id="s-airdrop-claims">0</span></div>
    <div class="stat-row"><span class="stat-label">Dev Treasury</span><span class="stat-value cyan" id="s-dev-balance" title="1M dev-AXC pool — outside the 100M public cap, funds @axiom.internal genesis claims">--</span></div>
    <div class="stat-row"><span class="stat-label">Dev Claims Processed</span><span class="stat-value" id="s-dev-claims" title="local / network total">0</span></div>
    <div class="stat-row"><span class="stat-label">DEED Pool</span><span class="stat-value cyan" id="s-deed-pool-balance" title="10% of every receiver-pays validator fee, collected for the first 10 years from GENESIS_NEWS_ANCHOR. See AXIOM_DESIGN_DeedDistribution.md.">--</span></div>
    <div class="stat-row"><span class="stat-label">DEED Lifetime</span><span class="stat-value" id="s-deed-pool-total" title="Cumulative atoms ever credited to the DEED pool — informational; balance can only grow during Phase 1, never decrease.">--</span></div>
    <!-- Dev-class DEED Pool — observability for @axiom.internal traffic.
         Visually nested under the public DEED rows with dim color so
         operators see what's collecting from test wallets without
         confusing it with real DEED. NEVER convertible to public AXC
         (newtype-distinct from DeedPool — see nabla/src/node.rs LEAK
         BOUNDARY + AXIOM_DESIGN_FactClassIsolation.md). -->
    <div class="stat-row" style="border-left:2px solid var(--c-dim); padding-left:6px; opacity:0.75;"><span class="stat-label" style="font-size:11px;">Dev DEED Pool</span><span class="stat-value" id="s-dev-deed-pool-balance" style="font-size:11px;" title="10% slice from @axiom.internal TXs only. Observability only — cannot mint public AXC. See AXIOM_DESIGN_FactClassIsolation.md.">--</span></div>
    <div class="stat-row" style="border-left:2px solid var(--c-dim); padding-left:6px; opacity:0.75;"><span class="stat-label" style="font-size:11px;">Dev DEED Lifetime</span><span class="stat-value" id="s-dev-deed-pool-total" style="font-size:11px;" title="Cumulative dev-AXC ever credited to the dev DEED pool — testnet only.">--</span></div>
  </div>

  <!-- Card 3: Health -->
  <div class="card">
    <div class="card-title"><span class="icon">&#x1F3E5;</span> Health</div>
    <div class="stat-row"><span class="stat-label">Uptime</span><span class="stat-value green" id="s-hp-uptime">--</span></div>
    <div class="stat-row"><span class="stat-label">Writes Approved</span><span class="stat-value" id="s-hp-writes">0</span></div>
    <div class="stat-row"><span class="stat-label">Orphans Rescued</span><span class="stat-value" id="s-hp-orphans">0</span></div>
    <div class="stat-row"><span class="stat-label">Rotations Survived</span><span class="stat-value" id="s-hp-rotations">0</span></div>
    <div class="stat-row"><span class="stat-label">Mesh Peers</span><span class="stat-value" id="s-hp-peers">0</span></div>
    <div class="stat-row"><span class="stat-label">Known Nodes</span><span class="stat-value" id="s-hp-known">0</span></div>
    <div class="stat-row"><span class="stat-label" title="OODS-gossip (YPX-021): the size of the Nabla NETWORK — OODS Extrema-Propagation estimate over this node's verified-NBC mesh view. Forgery-resistant. Watch it drop under a partition/eclipse.">Nabla network size (OODS-gossip)</span><span class="stat-value cyan" id="s-hp-oods">0</span></div>
    <div class="stat-row"><span class="stat-label" title="TARDIS depth (YPX-021 §6): this node's DEPTH in the tick tree — OODS estimate over the tick's down-cascade accumulator = the count of verified writers in its lineage from the root. NOT a network-size count. A snapshot can be inherited by attaching under a chain; SUSTAINED depth = durable integration under a long verified writer-chain. Collapses to ~0 when the node orphans/partitions. Future use: a hard-to-forge tiebreaker for gossip conflicts.">TARDIS depth</span><span class="stat-value cyan" id="s-hp-oods-tardis">0</span></div>
  </div>

  <!-- Card 4: Storage -->
  <div class="card">
    <div class="card-title"><span class="icon">&#x1F4BE;</span> Storage</div>
    <div class="stat-row"><span class="stat-label">SMT Entries</span><span class="stat-value" id="s-st-entries">0</span></div>
    <div class="stat-row"><span class="stat-label">SMT Memory</span><span class="stat-value" id="s-st-smtmem">0</span></div>
    <div class="stat-row"><span class="stat-label">Txid Bloom</span><span class="stat-value" id="s-st-bloom">--</span></div>
    <div class="stat-row"><span class="stat-label">Txid Hashmap</span><span class="stat-value" id="s-st-hashmap">--</span></div>
    <div class="stat-row"><span class="stat-label">WAL Size</span><span class="stat-value" id="s-st-wal">0</span></div>
    <div class="stat-row"><span class="stat-label">WAL Ops</span><span class="stat-value" id="s-st-walops">0</span></div>
    <div class="stat-row"><span class="stat-label">Snapshots</span><span class="stat-value" id="s-st-snaps">0</span></div>
    <div class="stat-row"><span class="stat-label">Snapshot Size</span><span class="stat-value" id="s-st-snapsize">0</span></div>
    <div class="stat-row"><span class="stat-label">Last Snapshot</span><span class="stat-value" id="s-st-lastsnap">0</span></div>
    <div class="stat-row"><span class="stat-label">Total Disk</span><span class="stat-value cyan" id="s-st-disk">0</span></div>
  </div>
</div>

<!-- Bootstrap Peers -->
<button class="details-toggle" id="btn-bootstrap" onclick="toggleBootstrap()">&#x25B6; Bootstrap Peers <span id="bp-summary" style="font-size:0.85em;color:#78909c"></span></button>
<div class="details-panel" id="bootstrap-panel">
  <table class="bp-table">
    <thead><tr><th>Address</th><th>Status</th><th>Last Seen</th><th>Latency</th></tr></thead>
    <tbody id="bp-body"></tbody>
  </table>
</div>

<!-- Technical Details -->
<button class="details-toggle" id="btn-details" onclick="toggleDetails()">&#x25B6; Technical Details</button>
<div class="details-panel" id="details-panel">
  <div class="detail-grid">
    <div>
      <div class="detail-row"><span class="detail-label">NBC Status</span><span class="detail-value" id="d-nbc">--</span></div>
      <div class="detail-row"><span class="detail-label">CC Tick</span><span class="detail-value" id="d-cc-tick">0</span></div>
      <div class="detail-row"><span class="detail-label">CC Score</span><span class="detail-value" id="d-cc-score">0</span></div>
      <div class="detail-row"><span class="detail-label">TARDIS Slot</span><span class="detail-value" id="d-tardis-slot">--</span></div>
      <div class="detail-row"><span class="detail-label">Downstream</span><span class="detail-value" id="d-downstream">0</span></div>
    </div>
    <div>
      <div class="detail-row"><span class="detail-label">Network Size (est.)</span><span class="detail-value" id="d-net-size">0</span></div>
      <div class="detail-row"><span class="detail-label">Gossip Seen</span><span class="detail-value" id="d-gossip-seen">0</span></div>
      <div class="detail-row"><span class="detail-label">Bans Active</span><span class="detail-value" id="d-bans">0</span></div>
      <div class="detail-row"><span class="detail-label">Reliability</span><span class="detail-value" id="d-reliability">--</span></div>
      <div class="detail-row"><span class="detail-label">Version</span><span class="detail-value" id="d-version">--</span></div>
    </div>
  </div>
  <div style="margin-top:10px;font-size:0.65em;color:#555">
    <span id="d-issues"></span>
  </div>
</div>

<div class="footer">
  AXIOM Nabla Operator Dashboard &middot; Auto-refresh 2s &middot;
  <a href="/health">Health</a> &middot; <a href="/status">JSON</a>
</div>

</div><!-- /main -->

<script>
// ── State ──
let txHistory = [];
let earnHistory = [];
let prevTxTotal = null;

function formatUptime(s) {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
  if (h > 0) return h + 'h ' + m + 'm';
  return m + 'm ' + (s % 60) + 's';
}

function fmtNum(n) {
  if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
  return String(n);
}

// Substituted at serve time from `axiom_denomination::ATOMS_PER_AXC`
// (see `html_dashboard` above). Single source of truth for the
// AXC↔atom divisor — never hand-mirror this literal.
const ATOMS_PER_AXC = {{ATOMS_PER_AXC}}n;
// BigInt-based AXC formatter: keeps full precision down to the atom,
// trims trailing zeros so display stays compact. Same approach the
// per-validator dashboard (console/src/static/index.html:587) uses —
// 60,000 atoms renders as "0.000006 AXC" instead of rounding to
// "0.0000 AXC" with a lossy toFixed(4).
function fmtAxc(atoms) {
  const a = BigInt(atoms || 0);
  const whole = a / ATOMS_PER_AXC;
  const frac  = a - whole * ATOMS_PER_AXC;
  const wholeStr = whole.toLocaleString();
  if (frac === 0n) return wholeStr + ' AXC';
  const fracStr = frac.toString().padStart(10, '0').replace(/0+$/, '');
  return wholeStr + '.' + fracStr + ' AXC';
}

function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(1) + ' GB';
}

function shortId(hex) {
  if (!hex || hex.length < 8) return hex || '--';
  return hex.substring(0, 8) + '..';
}

// ── Sparkline ──
function drawSparkline(svgId, data, color) {
  const svg = document.getElementById(svgId);
  if (!svg || data.length < 2) return;
  const w = 280, h = 30;
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - (v / max) * (h - 4) - 2;
    return x + ',' + y;
  });
  svg.innerHTML =
    '<polyline points="' + pts.join(' ') + '" fill="none" stroke="' + color +
    '" stroke-width="1.5" opacity="0.8"/>' +
    '<circle cx="' + (w) + '" cy="' + (h - (data[data.length-1] / max) * (h-4) - 2) +
    '" r="2" fill="' + color + '"/>';
}

// ── Network Graph ──
function renderGraph(st) {
  const svg = document.getElementById('graph');
  const W = 900, H = 400;
  const cx = W / 2, cy = H / 2;
  let html = '';

  // Build node list: me, upstream, d1, d2, peers
  const nodes = [];
  const myId = st.node_id_hex;

  // Me (center)
  nodes.push({ id: myId, name: st.node_name, x: cx, y: cy, role: 'me', genesis: false });

  // Parent (above)
  if (st.upstream_hex && st.upstream_hex.length > 1) {
    nodes.push({ id: st.upstream_hex, name: st.upstream_name, x: cx, y: cy - 100, role: 'parent', genesis: false });
  }

  // Children (below)
  if (st.d1_hex && st.d1_hex.length > 1) {
    nodes.push({ id: st.d1_hex, name: st.d1_name, x: cx - 80, y: cy + 100, role: 'd1', genesis: false });
  }
  if (st.d2_hex && st.d2_hex.length > 1) {
    nodes.push({ id: st.d2_hex, name: st.d2_name, x: cx + 80, y: cy + 100, role: 'd2', genesis: false });
  }

  // Known peers in orbit ring
  const treeIds = new Set(nodes.map(n => n.id));
  const peers = (st.peer_list || []).filter(p => !treeIds.has(p.node_id_hex));
  const peerCount = peers.length;
  const ringR = 160;
  peers.forEach((p, i) => {
    const angle = (i / Math.max(peerCount, 1)) * Math.PI * 2 - Math.PI / 2;
    nodes.push({
      id: p.node_id_hex,
      name: p.node_name,
      x: cx + Math.cos(angle) * ringR,
      y: cy + Math.sin(angle) * ringR,
      role: 'peer',
      genesis: p.is_genesis
    });
  });

  // Draw links
  const drawLink = (ax, ay, bx, by, color, label) => {
    html += '<line x1="'+ax+'" y1="'+ay+'" x2="'+bx+'" y2="'+by+
      '" stroke="'+color+'" stroke-width="1.5" opacity="0.5"/>';
    // Animated particle (random duration + delay so dots desync)
    const mx = (ax + bx) / 2, my = (ay + by) / 2;
    const dur = (0.6 + Math.random() * 0.9).toFixed(2);
    const delay = (Math.random() * 0.1).toFixed(2);
    html += '<circle r="2" fill="'+color+'" opacity="0.8">'+
      '<animateMotion dur="'+dur+'s" begin="'+delay+'s" repeatCount="indefinite" path="M'+ax+','+ay+' L'+bx+','+by+'"/></circle>';
    if (label) {
      html += '<text x="'+mx+'" y="'+(my-5)+'" fill="'+color+
        '" font-size="8" text-anchor="middle" opacity="0.7">'+label+'</text>';
    }
  };

  // TARDIS links
  if (st.upstream_hex && st.upstream_hex.length > 1) {
    drawLink(cx, cy - 100, cx, cy, '#3498db', 'tick');
    // Red dot: ME → Parent (approval sent upstream after collecting child approvals)
    // Leaf nodes (no children) always approve; writers approve when both children approved
    const meApproved = st.downstream_count === 0
      || (st.d1_approved && st.d2_approved);
    if (meApproved) {
      drawLink(cx, cy, cx, cy - 100, '#e74c3c', 'sig');
    }
  }
  if (st.d1_hex && st.d1_hex.length > 1) {
    const approved = st.downstream_count >= 1;
    drawLink(cx, cy, cx - 80, cy + 100, approved ? '#2ecc71' : '#f39c12',
      approved ? 'approved' : 'pending');
    // Red dot: D1 → ME (child sent approval/signature back)
    if (st.d1_approved) {
      drawLink(cx - 80, cy + 100, cx, cy, '#e74c3c', 'sig');
    }
  }
  if (st.d2_hex && st.d2_hex.length > 1) {
    const approved = st.downstream_count >= 2;
    drawLink(cx, cy, cx + 80, cy + 100, approved ? '#2ecc71' : '#f39c12',
      approved ? 'approved' : 'pending');
    // Red dot: D2 → ME (child sent approval/signature back)
    if (st.d2_approved) {
      drawLink(cx + 80, cy + 100, cx, cy, '#e74c3c', 'sig');
    }
  }

  // Mesh links (faint)
  peers.forEach((p, i) => {
    const angle = (i / Math.max(peerCount, 1)) * Math.PI * 2 - Math.PI / 2;
    const px = cx + Math.cos(angle) * ringR;
    const py = cy + Math.sin(angle) * ringR;
    html += '<line x1="'+cx+'" y1="'+cy+'" x2="'+px+'" y2="'+py+
      '" stroke="#ffffff" stroke-width="0.5" opacity="0.08"/>';
  });

  // Draw nodes
  nodes.forEach(n => {
    const r = n.role === 'me' ? 14 : 8;
    const color = n.role === 'me' ? '#f5a623' :
                  n.role === 'parent' ? '#3498db' :
                  (n.role === 'd1' || n.role === 'd2') ? '#2ecc71' :
                  n.genesis ? '#9b59b6' : '#78909c';

    const dn = n.name ? ' data-name="'+n.name+'"' : '';
    if (n.genesis) {
      // Diamond shape for genesis
      const s = r;
      html += '<polygon points="'+(n.x)+','+(n.y-s)+' '+(n.x+s)+','+(n.y)+
        ' '+(n.x)+','+(n.y+s)+' '+(n.x-s)+','+(n.y)+
        '" fill="'+color+'" opacity="0.9" stroke="#fff" stroke-width="0.5"' +
        ' data-id="'+n.id+'" data-role="'+n.role+'"'+dn+' class="gnode" style="cursor:pointer"/>';
    } else if (n.role === 'me') {
      // Gold circle with glow
      html += '<circle cx="'+n.x+'" cy="'+n.y+'" r="'+(r+4)+'" fill="none" stroke="'+color+
        '" stroke-width="1" opacity="0.3"/>';
      html += '<circle cx="'+n.x+'" cy="'+n.y+'" r="'+r+'" fill="'+color+
        '" opacity="0.95" stroke="#fff" stroke-width="1"' +
        ' data-id="'+n.id+'" data-role="'+n.role+'"'+dn+' class="gnode" style="cursor:pointer"/>';
      const meLabel = st.node_name || 'ME';
      html += '<text x="'+n.x+'" y="'+(n.y+3)+'" fill="#0a0e17" font-size="10"' +
        ' text-anchor="middle" font-weight="700">'+meLabel+'</text>';
    } else {
      html += '<circle cx="'+n.x+'" cy="'+n.y+'" r="'+r+'" fill="'+color+
        '" opacity="0.85" stroke="#fff" stroke-width="0.5"' +
        ' data-id="'+n.id+'" data-role="'+n.role+'"'+dn+' class="gnode" style="cursor:pointer"/>';
    }
    // Label
    if (n.role !== 'me') {
      const lbl = n.name || shortId(n.id);
      html += '<text x="'+n.x+'" y="'+(n.y + r + 11)+'" fill="'+color+
        '" font-size="7" text-anchor="middle" opacity="0.7">'+lbl+'</text>';
    }
  });

  svg.innerHTML = html;

  // Click handler for popup
  const popup = document.getElementById('popup');
  svg.querySelectorAll('.gnode').forEach(el => {
    el.addEventListener('click', e => {
      const id = el.getAttribute('data-id');
      const role = el.getAttribute('data-role');
      const peerName = el.getAttribute('data-name');
      const shortHex = id ? (id.substring(0, 8) + '…') : '--';
      document.getElementById('pp-id').textContent = peerName ? (peerName + ' — ' + shortHex) : shortHex;
      document.getElementById('pp-role').textContent = 'Role: ' + role;
      const labels = { me: 'This node', parent: 'TARDIS parent',
        d1: 'Downstream 1', d2: 'Downstream 2', peer: 'Mesh peer' };
      document.getElementById('pp-detail').textContent = labels[role] || role;
      // YPX-014 txid service mode for the clicked node. For 'me' it's
      // on the top-level status; for everyone else look it up in
      // peer_list by node_id_hex.
      let mode = '';
      if (role === 'me') {
        mode = st.txid_service || '';
      } else {
        const row = (st.peer_list || []).find(p => p.node_id_hex === id);
        mode = row ? (row.txid_service || '') : '';
      }
      document.getElementById('pp-txid').textContent = 'Settlement: ' + (mode || '(unknown)');
      popup.style.display = 'block';
      const rect = svg.getBoundingClientRect();
      const svgW = rect.width, svgH = rect.height;
      const viewBox = svg.viewBox.baseVal;
      const scaleX = svgW / viewBox.width;
      const scaleY = svgH / viewBox.height;
      const bx = parseFloat(el.getAttribute('cx') || el.getBBox().x + el.getBBox().width/2);
      const by = parseFloat(el.getAttribute('cy') || el.getBBox().y);
      popup.style.left = (bx * scaleX + 10) + 'px';
      popup.style.top = (by * scaleY - 10) + 'px';
      setTimeout(() => { popup.style.display = 'none'; }, 3000);
    });
  });
}

// ── Toggle panels ──
function toggleBootstrap() {
  const p = document.getElementById('bootstrap-panel');
  const b = document.getElementById('btn-bootstrap');
  const open = p.classList.toggle('open');
  const summary = document.getElementById('bp-summary').outerHTML;
  b.innerHTML = (open ? '&#x25BC;' : '&#x25B6;') + ' Bootstrap Peers ' + summary;
}
function toggleDetails() {
  const p = document.getElementById('details-panel');
  const b = document.getElementById('btn-details');
  const open = p.classList.toggle('open');
  b.innerHTML = (open ? '&#x25BC;' : '&#x25B6;') + ' Technical Details';
}

// ── Update loop ──
function update() {
  fetch('/status')
    .then(r => r.json())
    .then(st => {
      // Cockpit
      document.getElementById('ck-emoji').textContent = st.penguin_emoji || '';
      document.getElementById('ck-level').textContent = st.penguin_level || '--';
      document.getElementById('ck-score').textContent = fmtNum(st.penguin_score || 0);
      const streak = st.uptime_streak_days || 0;
      document.getElementById('ck-uptime').textContent =
        formatUptime(st.uptime_secs || 0) + (streak > 0 ? ' \uD83D\uDD25' + streak + 'd' : '');
      document.getElementById('ck-axc').textContent = fmtNum(st.deed_collected || 0);
      document.getElementById('ck-name').textContent = st.node_name || shortId(st.node_id_hex);
      document.getElementById('ck-id').textContent = shortId(st.node_id_hex);
      document.getElementById('ck-addr').textContent =
        st.wan_addr ? st.listen_addr + ' / WAN ' + st.wan_addr : (st.listen_addr || '--');
      // YPX-014 settlement mode chip — hashmap (audit-grade exact lookups,
      // UNCLE §8.3) or bloom (low memory, probabilistic). Identity-only
      // here; the live entry count lives on the Storage card below.
      const txidEl = document.getElementById('ck-txid-mode');
      const txidMode = st.txid_service || '';
      txidEl.textContent = txidMode || '--';
      txidEl.className = 'val ' + (txidMode === 'hashmap' ? 'green' : txidMode === 'bloom' ? 'cyan' : '');
      const isWriter = st.is_writer;
      document.getElementById('ck-role').textContent = isWriter ? 'WRITER' : 'READER';
      const roleDot = document.getElementById('ck-role-dot');
      roleDot.className = 'dot ' + (st.healthy ? 'green' : 'red');
      document.getElementById('ck-tick').textContent = st.current_tick || 0;

      // Graph
      renderGraph(st);

      // Card 1: Transactions
      document.getElementById('s-tx-total').textContent = fmtNum(st.cc_total_registrations || 0);
      document.getElementById('s-tx-helped').textContent = fmtNum(st.cc_ticks_helped || 0);
      document.getElementById('s-tx-entries').textContent = fmtNum(st.entry_count || 0);
      document.getElementById('s-tx-hash').textContent = st.root_hash_hex || '--';

      // Track transaction sparkline
      const txNow = st.cc_total_registrations || 0;
      if (prevTxTotal !== null) {
        txHistory.push(txNow - prevTxTotal);
        if (txHistory.length > 60) txHistory.shift();
      }
      prevTxTotal = txNow;
      drawSparkline('spark-tx', txHistory.length > 1 ? txHistory : [0, 0], '#3498db');

      // Card 2: Earnings
      document.getElementById('s-earn-total').textContent = fmtNum(st.deed_collected || 0);
      document.getElementById('s-earn-deed').textContent = fmtNum(st.deed_collected || 0);
      document.getElementById('s-earn-split').textContent = st.deed_split || '--';
      document.getElementById('s-earn-pool').textContent = fmtNum(st.runner_pool_balance || 0);
      document.getElementById('s-airdrop-balance').textContent = fmtAxc(st.airdrop_pool_balance || 0);
      var localC = st.airdrop_local_claims || 0;
      var netC = st.airdrop_pool_claims || 0;
      document.getElementById('s-airdrop-claims').textContent = localC + '/' + netC;
      // Dev Treasury (FACT class isolation §6 — 1M dev-AXC, outside the
      // 100M public cap). Same shape as airdrop: balance + local/network
      // claim count.
      document.getElementById('s-dev-balance').textContent = fmtAxc(st.dev_pool_balance || 0);
      var devLocalC = st.dev_pool_local_claims || 0;
      var devNetC = st.dev_pool_claims || 0;
      document.getElementById('s-dev-claims').textContent = devLocalC + '/' + devNetC;
      // PR3 DEED Pool — 10% of every receiver-pays validator fee.
      // Current balance and lifetime cumulative ride side-by-side; in
      // Phase 1 (first 10 years from anchor) they stay equal, after the
      // cutoff balance freezes while total_credited can still grow if
      // we later wire a re-attestation path.
      document.getElementById('s-deed-pool-balance').textContent = fmtAxc(st.deed_pool_balance || 0);
      document.getElementById('s-deed-pool-total').textContent = fmtAxc(st.deed_pool_total_credited || 0);
      // Dev DEED — testnet-only observability. Shown always (even at 0)
      // so operators can confirm the line is wired.
      document.getElementById('s-dev-deed-pool-balance').textContent = fmtAxc(st.dev_deed_pool_balance || 0);
      document.getElementById('s-dev-deed-pool-total').textContent = fmtAxc(st.dev_deed_pool_total_credited || 0);
      earnHistory.push(st.deed_collected || 0);
      if (earnHistory.length > 60) earnHistory.shift();
      drawSparkline('spark-earn', earnHistory.length > 1 ? earnHistory : [0, 0], '#00d2d3');

      // Card 3: Health
      document.getElementById('s-hp-uptime').textContent = formatUptime(st.uptime_secs || 0);
      document.getElementById('s-hp-writes').textContent = fmtNum(st.writes_approved || 0);
      document.getElementById('s-hp-orphans').textContent = st.orphans_rescued || 0;
      document.getElementById('s-hp-rotations').textContent = st.rotations_survived || 0;
      document.getElementById('s-hp-peers').textContent =
        (st.mesh_peer_count || 0) + ' / ' + (st.mesh_target_peers || 0);
      document.getElementById('s-hp-known').textContent = fmtNum(st.mesh_known_nodes || 0);
      document.getElementById('s-hp-oods').textContent = Math.round(st.oods_estimate || 0);
      document.getElementById('s-hp-oods-tardis').textContent = st.tardis_depth || 0;

      // Card 4: Storage
      document.getElementById('s-st-entries').textContent = fmtNum(st.entry_count || 0);
      document.getElementById('s-st-smtmem').textContent = '~' + fmtBytes(st.smt_memory_bytes || 0);
      // YPX-014 txid tiers. Bloom is ALWAYS populated (fast negative
      // pre-check in hashmap mode, sole tier in bloom mode). Hashmap is
      // populated only in hashmap mode; bloom-mode nodes render "off".
      const bloomCount = fmtNum(st.txid_bloom_count || 0);
      const bloomSize  = fmtBytes(st.txid_bloom_bytes || 0);
      const bloomFprPct = ((st.txid_bloom_fpr || 0) * 100);
      const bloomFprTxt = bloomFprPct < 0.01
        ? bloomFprPct.toExponential(1) + '%'
        : bloomFprPct.toFixed(2) + '%';
      document.getElementById('s-st-bloom').textContent =
        bloomCount + ' / ' + bloomSize + ' (fpr ' + bloomFprTxt + ')';
      document.getElementById('s-st-hashmap').textContent =
        (st.txid_service === 'hashmap')
          ? fmtNum(st.txid_hashmap_len || 0) + ' / ~' + fmtBytes(st.txid_hashmap_bytes || 0)
          : (st.txid_service === 'bloom' ? 'off (bloom-only mode)' : '--');
      document.getElementById('s-st-wal').textContent = fmtBytes(st.wal_file_bytes || 0);
      document.getElementById('s-st-walops').textContent = fmtNum(st.wal_ops_since_snapshot || 0) + ' since snapshot';
      document.getElementById('s-st-snaps').textContent = (st.snapshot_count || 0) + ' on disk';
      document.getElementById('s-st-snapsize').textContent = fmtBytes(st.snapshot_total_bytes || 0);
      var tAgo = st.last_snapshot_tick > 0 ? ' (' + fmtNum(st.current_tick - st.last_snapshot_tick) + ' ticks ago)' : '';
      document.getElementById('s-st-lastsnap').textContent = 'tick ' + fmtNum(st.last_snapshot_tick || 0) + tAgo;
      document.getElementById('s-st-disk').textContent = fmtBytes(st.total_disk_bytes || 0);

      // Technical Details
      document.getElementById('d-nbc').textContent = st.cc_active ? 'Active' : 'Inactive';
      document.getElementById('d-cc-tick').textContent = st.cc_tick || 0;
      document.getElementById('d-cc-score').textContent = fmtNum(st.cc_score || 0);
      document.getElementById('d-tardis-slot').textContent = st.tardis_slot || '--';
      document.getElementById('d-downstream').textContent = st.downstream_count || 0;
      document.getElementById('d-net-size').textContent = st.estimated_network_size || 0;
      document.getElementById('d-gossip-seen').textContent = fmtNum(st.gossip_seen_count || 0);
      document.getElementById('d-bans').textContent = st.ban_count || 0;
      document.getElementById('d-reliability').textContent =
        (st.reliability_multiplier || 1).toFixed(1) + 'x';
      document.getElementById('d-version').textContent = st.version || '--';
      const issues = st.health_issues || [];
      document.getElementById('d-issues').textContent =
        issues.length > 0 ? 'Issues: ' + issues.join(' | ') : 'No issues';

      // Bootstrap Peers
      const bps = st.bootstrap_peers || [];
      const tbody = document.getElementById('bp-body');
      let bpHtml = '';
      let connCount = 0;
      bps.forEach(bp => {
        if (bp.status === 'connected') connCount++;
        const latStr = bp.latency_ms != null ? bp.latency_ms + 'ms' : '--';
        bpHtml += '<tr><td class="bp-addr">' + bp.address + '</td>' +
          '<td>' + bp.status_emoji + ' ' + bp.status + '</td>' +
          '<td>' + bp.last_seen + '</td>' +
          '<td class="bp-latency">' + latStr + '</td></tr>';
      });
      tbody.innerHTML = bpHtml;
      const sumEl = document.getElementById('bp-summary');
      if (bps.length > 0) {
        sumEl.textContent = '(' + connCount + '/' + bps.length + ' connected)';
      }
    })
    .catch(() => {});
}

// Start
update();
setInterval(update, 2000);
</script>
</body>
</html>"##;

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn make_status() -> NodeStatusSnapshot {
        let mut s = NodeStatusSnapshot {
            version: format!("v{}", env!("CARGO_PKG_VERSION")),
            node_name: String::new(),
            node_id_hex: "aabbccdd11223344".into(),
            uptime_secs: 3661,
            txid_service: "hashmap".into(),
            txid_hashmap_len: 123,
            txid_hashmap_bytes: 123 * 96,
            txid_bloom_count: 123,
            txid_bloom_bytes: 18_000_000,
            txid_bloom_fpr: 0.0001,
            listen_addr: "[::]:1211".into(),
            wan_addr: None,
            current_tick: 1000,
            tardis_active: true,
            tardis_slot: "D1".into(),
            has_upstream: true,
            downstream_count: 2,
            is_writer: true,
            d1_approved: true,
            d2_approved: false,
            ticks_with_current_parent: 0,
            rebalance_cooldown: 0,
            root_hash_hex: "0123456789abcdef".into(),
            entry_count: 5000,
            ban_count: 2,
            mesh_active: true,
            mesh_peer_count: 9,
            mesh_target_peers: 9,
            mesh_known_nodes: 50,
            estimated_network_size: 200,
            oods_estimate: 0.0,
            tardis_depth: 0,
            enquiry_peer_count: 0,
            cc_active: true,
            cc_tick: 999,
            cc_ticks_helped: 900,
            cc_total_registrations: 4500,
            cc_score: 45900,
            runner_pool_balance: 300,
            airdrop_pool_balance: crate::constants::AIRDROP_POOL_INITIAL_ATOMS,
            airdrop_pool_claims: 42,
            airdrop_local_claims: 12,
            dev_pool_balance: crate::constants::DEV_TREASURY_POOL_INITIAL_ATOMS,
            dev_pool_claims: 3,
            dev_pool_local_claims: 1,
            deed_collected: 50000,
            deed_split: "30/70".into(),
            deed_pool_balance: 9_000_000_000,    // 0.9 AXC — demo only
            deed_pool_total_credited: 9_000_000_000,
            dev_deed_pool_balance: 0,
            dev_deed_pool_total_credited: 0,
            gossip_seen_count: 12345,
            last_gossip_tick: 998,
            transport_send_failures_total: 0,
            transport_send_failures_per_peer: std::collections::HashMap::new(),
            storm_shed_active: false,
            storm_dropped_total: 0,
            storm_trips_total: 0,
            tick_sig_failures: 0,
            quarantine_active_count: 0,
            quarantine_pending_count: 0,
            penguin_score: 5500,
            penguin_level: "Penguin".into(),
            penguin_emoji: "\u{1F427}".into(),
            uptime_streak_days: 12,
            writes_approved: 800,
            orphans_rescued: 3,
            rotations_survived: 5,
            reliability_multiplier: 2.0,
            wal_file_bytes: 4200000,
            wal_ops_since_snapshot: 847,
            snapshot_count: 3,
            snapshot_total_bytes: 14100000,
            last_snapshot_tick: 960,
            total_disk_bytes: 18300000,
            smt_memory_bytes: 1000000,
            upstream_hex: "1122334455667788".into(),
            upstream_name: "beta".into(),
            d1_hex: "aabb000000000001".into(),
            d1_name: "Emperor".into(),
            d2_hex: "aabb000000000002".into(),
            d2_name: "皇帝企鵝".into(),
            peer_list: vec![
                PeerEntry { node_id_hex: "ddee000000000001".into(), node_name: "gamma".into(), is_genesis: true, txid_service: "hashmap".into() },
                PeerEntry { node_id_hex: "ddee000000000002".into(), node_name: String::new(), is_genesis: false, txid_service: "bloom".into() },
            ],
            bootstrap_peers: vec![
                BootstrapPeerEntry {
                    address: "10.0.0.1:6225".into(),
                    status: "connected".into(),
                    status_emoji: "\u{1F7E2}".into(),
                    last_seen: "2m ago".into(),
                    latency_ms: Some(12),
                },
                BootstrapPeerEntry {
                    address: "10.0.0.2:6225".into(),
                    status: "unreachable".into(),
                    status_emoji: "\u{1F534}".into(),
                    last_seen: "never".into(),
                    latency_ms: None,
                },
            ],
            healthy: true,
            health_issues: Vec::new(),
        };
        diagnose(&mut s);
        s
    }

    // ── Health Diagnosis ──

    #[test]
    fn healthy_node() {
        let status = make_status();
        assert!(status.healthy);
        assert!(status.health_issues.is_empty());
    }

    #[test]
    fn unhealthy_no_tardis() {
        let mut s = make_status();
        s.tardis_active = false;
        diagnose(&mut s);

        assert!(!s.healthy);
        assert!(s.health_issues.iter().any(|i| i.contains("TARDIS")));
    }

    #[test]
    fn unhealthy_no_peers() {
        let mut s = make_status();
        s.mesh_peer_count = 0;
        diagnose(&mut s);

        assert!(!s.healthy);
        assert!(s.health_issues.iter().any(|i| i.contains("peer")));
    }

    #[test]
    fn unhealthy_low_peers() {
        let mut s = make_status();
        s.mesh_peer_count = 2;
        s.mesh_target_peers = 9;
        diagnose(&mut s);

        assert!(!s.healthy);
    }

    // ── Routing ──

    #[test]
    fn route_dashboard() {
        let status = make_status();
        let config = MonitorConfig::default();

        let (code, content_type, body) = route_request("/", None, &status, &config);
        assert_eq!(code, 200);
        assert!(content_type.contains("html"));
        assert!(body.contains("AXIOM Nabla"));
    }

    #[test]
    fn route_status_json() {
        let status = make_status();
        let config = MonitorConfig::default();

        let (code, content_type, body) = route_request("/status", None, &status, &config);
        assert_eq!(code, 200);
        assert!(content_type.contains("json"));
        assert!(body.contains("\"current_tick\": 1000"));
        assert!(body.contains("\"penguin_score\": 5500"));
    }

    #[test]
    fn route_health_ok() {
        let status = make_status();
        let config = MonitorConfig::default();

        let (code, content_type, body) = route_request("/health", None, &status, &config);
        assert_eq!(code, 200);
        assert!(content_type.contains("json"));
        assert!(body.contains("\"healthy\": true"));
    }

    #[test]
    fn route_health_unhealthy() {
        let mut status = make_status();
        status.tardis_active = false;
        diagnose(&mut status);

        let config = MonitorConfig::default();
        let (code, _, body) = route_request("/health", None, &status, &config);
        assert_eq!(code, 503);
        assert!(body.contains("\"healthy\": false"));
    }

    #[test]
    fn route_api_status() {
        let status = make_status();
        let config = MonitorConfig::default();

        let (code, _, body) = route_request("/api/status", None, &status, &config);
        assert_eq!(code, 200);
        assert!(body.contains("\"current_tick\": 1000"));
        assert!(body.contains("\"entry_count\": 5000"));
    }

    #[test]
    fn route_not_found() {
        let status = make_status();
        let config = MonitorConfig::default();

        let (code, _, _) = route_request("/unknown", None, &status, &config);
        assert_eq!(code, 404);
    }

    // ── Auth ──

    #[test]
    fn auth_required() {
        let status = make_status();
        let config = MonitorConfig {
            auth_token: Some("secret123".into()),
            ..Default::default()
        };

        // No token -> 401
        let (code, _, _) = route_request("/", None, &status, &config);
        assert_eq!(code, 401);

        // Wrong token -> 401
        let (code, _, _) = route_request("/", Some("token=wrong"), &status, &config);
        assert_eq!(code, 401);

        // Correct token -> 200
        let (code, _, _) = route_request("/", Some("token=secret123"), &status, &config);
        assert_eq!(code, 200);
    }

    // ── Formatting ──

    #[test]
    fn format_uptime_minutes() {
        assert_eq!(format_uptime(90), "1m 30s");
    }

    #[test]
    fn format_uptime_hours() {
        assert_eq!(format_uptime(3661), "1h 1m");
    }

    #[test]
    fn format_uptime_days() {
        assert_eq!(format_uptime(90061), "1d 1h 1m");
    }

    // ── Dashboard Content ──

    #[test]
    fn dashboard_contains_key_elements() {
        let status = make_status();
        let html = html_dashboard(&status);

        assert!(html.contains("AXIOM Nabla"));
        assert!(html.contains("Network Topology"));
        assert!(html.contains("Transactions"));
        assert!(html.contains("Earnings"));
        assert!(html.contains("Health"));
        assert!(html.contains("Technical Details"));
        assert!(html.contains("/status"));
    }

    #[test]
    fn dashboard_shows_issues_in_json() {
        let mut status = make_status();
        status.tardis_active = false;
        diagnose(&mut status);

        let json = json_status(&status);
        assert!(json.contains("TARDIS not initialized"));
    }

    // ── Hex Formatting ──

    #[test]
    fn hex_short_format() {
        let bytes = [0xAA; 32];
        assert_eq!(hex_short(&bytes), "aaaaaaaaaaaaaaaa");
    }

    // ── Penguin Scoring ──

    #[test]
    fn penguin_score_hatchling() {
        let score = penguin_contribution(500, 0, 0, 0, 0);
        assert_eq!(score, 0); // 500/1000 = 0
        let (level, _) = penguin_level(score);
        assert_eq!(level, "Hatchling");
    }

    #[test]
    fn penguin_score_penguin_level() {
        let score = penguin_contribution(2_000_000, 200_000, 100_000, 5, 10);
        // 2000 + 1000 + 1000 + 250 + 1000 = 5250
        assert!((1_000..10_000).contains(&score));
        let (level, _) = penguin_level(score);
        assert_eq!(level, "Penguin");
    }

    #[test]
    fn penguin_score_colony_elder() {
        let score = penguin_contribution(100_000_000, 50_000_000, 50_000_000, 500, 2000);
        // 100000 + 250000 + 500000 + 25000 + 200000 = 1,075,000
        assert!(score >= 500_000);
        let (level, _) = penguin_level(score);
        assert_eq!(level, "Colony Elder");
    }

    #[test]
    fn reliability_multiplier_tiers() {
        assert_eq!(reliability_multiplier(100.0), 3.0);
        assert_eq!(reliability_multiplier(99.9), 3.0);
        assert_eq!(reliability_multiplier(99.5), 2.0);
        assert_eq!(reliability_multiplier(99.0), 2.0);
        assert_eq!(reliability_multiplier(97.0), 1.0);
        assert_eq!(reliability_multiplier(95.0), 1.0);
        assert_eq!(reliability_multiplier(92.0), 0.75);
        assert_eq!(reliability_multiplier(85.0), 0.5);
    }
}
