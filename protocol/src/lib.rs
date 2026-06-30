//! # PARDA Protocol Layer
//!
//! End-to-end encryption core for PARDA, built on the Signal Protocol
//! (X3DH Extended Triple Diffie-Hellman key agreement + Double Ratchet
//! Algorithm). All cryptographic operations are delegated to the
//! Signal Foundation's `libsignal-protocol` Rust crate — no custom
//! crypto primitives.
//!
//! ## Module Layout
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | [`error`] | Unified `PardaError` type |
//! | [`identity`] | Identity key generation, prekey bundles, serialisation |
//! | [`store`] | Storage trait + in-memory implementation (tests only) |
//! | [`session`] | X3DH session init + Double Ratchet encrypt / decrypt |
//! | [`envelope`] | Wire message type with Phase 2-3 extension stubs |
//! | [`transport`] | Transport abstraction (Phase 2 stub for mix-routing) |
//!
//! ## Security Properties (Phase 1)
//!
//! - **Confidentiality:** AES-256-CBC + HMAC-SHA256 (Signal Protocol default)
//! - **Authenticity:** Ed25519 signed prekeys; ratchet message authentication
//! - **Forward secrecy:** Per-message ephemeral DH keys; old keys discarded
//! - **Break-in recovery:** Double Ratchet re-establishes fresh entropy after compromise
//!
//! ## NOT provided in Phase 1 (stubbed only)
//!
//! - Metadata resistance / sender unlinkability (Phase 2)
//! - Cryptographic self-destruct (Phase 3)
//! - Post-quantum key encapsulation (Phase 5)

pub mod envelope;
pub mod error;
pub mod identity;
pub mod session;
pub mod store;
pub mod transport;

// Re-export frequently-used libsignal types so callers don't need
// to depend directly on libsignal-protocol in their own Cargo.toml.
pub use libsignal_protocol::{
    IdentityKey, IdentityKeyPair, PreKeyBundle, PreKeyId, PreKeyRecord,
    ProtocolAddress, SignedPreKeyId, SignedPreKeyRecord,
};

pub use error::PardaError;
