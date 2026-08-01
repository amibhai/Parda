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
//! | [`envelope`] | Wire message type, version byte, self-destruct + dead-drop extension fields |
//! | [`mixnet`] | Sphinx packet construction/processing (Sub-Phase 2B) |
//! | [`transport`] | Transport abstraction — `DirectTransport`, `MixTransport` (see `parda_mesh::transport::MeshNode` in the separate `mesh` crate for the third, Sub-Phase 4C, implementation) |
//! | [`self_destruct`] | Time-bound and read-triggered self-destructing message primitive (Sub-Phases 3A/3B) |
//! | [`clock_guard`] | Clock-rollback detection for self-destruct expiry (Sub-Phase 3A) |
//! | [`secure_memory`] | Cross-platform `mlock`/`VirtualLock` to keep key material out of swap (Sub-Phase 3C) |
//! | [`dead_drop`] | Anonymous, blinded dead-drop addressing for offline mesh delivery (Sub-Phase 4C) |
//!
//! ## Security Properties
//!
//! - **Confidentiality:** AES-256-CBC + HMAC-SHA256 (Signal Protocol default)
//! - **Authenticity:** Ed25519 signed prekeys; ratchet message authentication
//! - **Forward secrecy:** Per-message ephemeral DH keys; old keys discarded
//! - **Break-in recovery:** Double Ratchet re-establishes fresh entropy after compromise
//! - **Sender-receiver unlinkability (relay-side):** sealed-sender envelopes hide
//!   `sender_id` from the relay; see [`sealed_sender`] (Sub-Phase 2A)
//! - **Sender-receiver unlinkability (send-path, network-level):** Sphinx
//!   mix routing + Loopix-style per-hop delay and drop-cover traffic; see
//!   [`mixnet`] and `mixnode::cover_traffic` (Sub-Phase 2B). Receive-path
//!   (fetching from the relay) is not yet mix-anonymized — see
//!   `transport` module docs.
//! - **Time-bound and read-triggered cryptographic self-destruct
//!   (send-path independent):** [`self_destruct::SelfDestructingMessage`]
//!   derives a fresh, local key (HKDF-SHA256), locks its memory against
//!   swap, and provably zeroizes it at expiry or first read — see
//!   [`self_destruct`] and `docs/phase3-3a-self-destruct-design.md`
//!   (Sub-Phases 3A-3C).
//! - **Anonymous dead-drop addressing (offline mesh):**
//!   [`dead_drop::TagKey`] derives blinded per-message storage addresses
//!   from a dedicated, purpose-only shared secret — opaque to a mesh
//!   carrier, unlinkable to recipient identity — see [`dead_drop`] and
//!   `docs/phase4-4c-dead-drop-addressing-design.md` (Sub-Phase 4C).
//!
//! ## NOT provided yet (stubbed only)
//!
//! - Post-quantum key encapsulation (Phase 5)

pub mod clock_guard;
pub mod dead_drop;
pub mod envelope;
pub mod error;
pub mod identity;
pub mod mixnet;
pub mod sealed_sender;
pub mod secure_memory;
pub mod self_destruct;
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
