// AXIOM Nabla — Client wire protocol typed envelopes.
//
// MOVED 2026-05-17 (UMP Phase 1): the type definitions now live in
// `axiom_core_logic::wire_client` so the SDK — which cannot depend on the
// `axiom-nabla` server crate (its dep cone: fips204 / fips205 / tokio) —
// can construct them directly instead of hand-building
// `ciborium::Value::Map`s or layer-local mirror structs. Wire types must
// live in `axiom_core_logic` exactly once (CLAUDE.md §13 /
// feedback_no_mirror_structs).
//
// This module re-exports them unchanged so every existing
// `crate::wire_client::*` reference inside the Nabla crate keeps
// resolving. The CBOR wire is byte-identical — serde encodes by field
// name, not by type path, so relocating the definitions changes nothing
// on the wire.
pub use axiom_core_logic::wire_client::*;
