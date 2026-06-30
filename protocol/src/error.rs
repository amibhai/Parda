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

    /// Catch-all for unexpected conditions.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, PardaError>;
