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
//! | [`session`] | X3DH session init + Double Ratchet encrypt / decrypt; sealed-sender encrypt / decrypt |
//! | [`sealed_sender`] | Sender-certificate authority (Sub-Phase 2A) |
//! | [`envelope`] | Wire message type, version byte, Phase 3 extension stub |
//! | [`transport`] | Transport abstraction (Sub-Phase 2B stub for mix-routing) |
//!
//! ## Security Properties
//!
//! - **Confidentiality:** AES-256-CBC + HMAC-SHA256 (Signal Protocol default)
//! - **Authenticity:** Ed25519 signed prekeys; ratchet message authentication
//! - **Forward secrecy:** Per-message ephemeral DH keys; old keys discarded
//! - **Break-in recovery:** Double Ratchet re-establishes fresh entropy after compromise
//! - **Sender-receiver unlinkability (relay-side):** sealed-sender envelopes hide
//!   `sender_id` from the relay; see [`sealed_sender`] (Sub-Phase 2A)
//!
//! ## NOT provided yet (stubbed only)
//!
//! - Mix-network routing / traffic-timing resistance (Sub-Phase 2B)
//! - Cryptographic self-destruct (Phase 3)
//! - Post-quantum key encapsulation (Phase 5)

pub mod envelope;
pub mod error;
pub mod identity;
pub mod sealed_sender;
pub mod session;
pub mod store;
pub mod transport;

// Re-export frequently-used libsignal types so callers don't need
// to depend directly on libsignal-protocol in their own Cargo.toml.
pub use libsignal_protocol::{
    DeviceId, IdentityKey, IdentityKeyPair, PreKeyBundle, PreKeyId, PreKeyRecord,
    ProtocolAddress, PublicKey, SenderCertificate, ServerCertificate, SignedPreKeyId,
    SignedPreKeyRecord,
};

pub use error::PardaError;
