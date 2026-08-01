//! PARDA offline mesh dead-drop (Phase 4).
//!
//! No internet, no relay, no mix network — only nearby devices passing
//! encrypted bundles hand to hand. This crate implements the proximity
//! transport ([`radio`]), the DTN store-and-forward relay agent
//! ([`relay`], [`bundle`]), and the [`parda_protocol::transport::TransportLayer`]
//! implementation that wires them together ([`transport`]), alongside a
//! multi-node simulation harness ([`sim`]) used to drive every adversarial
//! test in this crate at scale.
//!
//! The anonymous dead-drop addressing scheme itself
//! (`parda_protocol::dead_drop`) lives in the `protocol` crate, not here —
//! it's a crypto primitive both a client composing a message and this
//! crate's relay agent touch, but the relay agent only ever needs to
//! treat an address as opaque bytes, never to derive one. See
//! `docs/phase4-4c-dead-drop-addressing-design.md`.
//!
//! ## The adversary this crate exists for
//!
//! Phases 1-3 defended against a network adversary and a device-seizure
//! adversary. This crate is Phase 4's answer to a third: a co-located,
//! passive/active radio observer. BLE and Wi-Fi Direct are broadcast
//! media — no key management scheme fixes that. This crate's job is to
//! minimize what such an observer learns (module-by-module: no
//! persistent advertisement identifiers in [`radio`], no recoverable
//! plaintext/metadata on an untrusted carrier in [`relay`]/[`bundle`], a
//! blinded address plus measured retrieval-pattern mitigation in
//! `parda_protocol::dead_drop`) and to be explicit, in
//! `docs/THREAT_MODEL.md` §3.7, about what remains unavoidably visible —
//! not to claim a software fix for RF physics that doesn't exist.

pub mod bundle;
pub mod error;
pub mod hybrid;
pub mod radio;
pub mod relay;
pub mod sim;
pub mod transport;

pub use error::{MeshError, Result};
