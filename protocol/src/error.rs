//! Unified error type for the PARDA protocol layer.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PardaError {
    /// Wraps any error surfaced by libsignal-protocol.
    #[error("Signal protocol error: {0}")]
    Signal(#[from] libsignal_protocol::SignalProtocolError),

    /// Key material could not be generated or serialised.
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// No session record exists for the given remote address.
    #[error("No session found for address: {0}")]
    SessionNotFound(String),

    /// The prekey bundle from the server is malformed or missing a required field.
    #[error("Invalid prekey bundle: {0}")]
    InvalidBundle(String),

    /// Envelope serialisation / deserialisation failed.
    #[error("Envelope codec error: {0}")]
    Codec(#[from] serde_json::Error),

    /// Transport-layer failure (HTTP, socket, etc.).
    #[error("Transport error: {0}")]
    Transport(String),

    /// The backing store returned an unexpected error.
    #[error("Store error: {0}")]
    Store(String),

    /// An envelope declared a wire format version this build does not
    /// understand. Refused explicitly rather than decoded speculatively.
    #[error(
        "Unsupported envelope version {got}: this build supports up to {max_supported}"
    )]
    UnsupportedEnvelopeVersion { got: u8, max_supported: u8 },

    /// A sealed-sender envelope was structurally inconsistent (e.g.
    /// `sealed_sender = true` on a version-1 envelope, or the wrong
    /// `envelope_type` for the sealed-sender path).
    #[error("Malformed sealed-sender envelope: {0}")]
    MalformedSealedSender(String),

    /// Sender certificate failed validation (expired, wrong trust root,
    /// bad signature) during sealed-sender decryption.
    #[error("Sealed-sender authentication failed: {0}")]
    SealedSenderAuth(String),

    /// Sphinx packet construction, forwarding, or unwrap failed (Sub-Phase
    /// 2B mix routing) — malformed packet, path too long/short, wrong node
    /// key, or an address that doesn't fit the fixed-size Sphinx address
    /// encoding.
    #[error("Mix routing error: {0}")]
    MixRouting(String),

    /// A self-destructing message's key is gone — either the expiry timer
    /// already fired, `expire_now()` was called explicitly, or a read
    /// trigger already consumed it (Sub-Phase 3B). The plaintext is not
    /// recoverable; this is the intended, working state, not a bug.
    #[error("Self-destructing message has already expired — key material is gone")]
    SelfDestructExpired,

    /// The device clock was observed to have moved backward relative to
    /// the last persisted watermark — refused rather than trusted, per
    /// Phase 3's fail-closed clock-integrity requirement. See
    /// `clock_guard` module docs.
    #[error(
        "Clock rollback detected: observed {observed_ms}ms, last known-good was {watermark_ms}ms"
    )]
    ClockRollbackDetected { observed_ms: u64, watermark_ms: u64 },

    /// AEAD encryption/decryption of a self-destructing message's
    /// plaintext failed — wrong key (shouldn't happen given how the key
    /// is derived), corrupted ciphertext, or tampering.
    #[error("Self-destruct AEAD error: {0}")]
    SelfDestructCrypto(String),

    /// Catch-all for unexpected conditions.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, PardaError>;
