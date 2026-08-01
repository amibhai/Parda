//! Unified error type for the `parda-mesh` crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MeshError {
    /// The requested peer is not currently reachable — out of range,
    /// partitioned, or never sighted. Distinct from a hard I/O failure:
    /// this is the expected, common case in an intermittent mesh, not an
    /// error condition callers should treat as exceptional.
    #[error("peer not reachable")]
    PeerUnreachable,

    /// The underlying radio backend is unavailable or was closed.
    #[error("radio unavailable: {0}")]
    RadioUnavailable(String),

    /// A link (BLE/Wi-Fi Direct connection) failed mid-transfer.
    #[error("link error: {0}")]
    Link(String),

    /// Bundle encode/decode failed (`bp7` CBOR framing).
    #[error("bundle codec error: {0}")]
    BundleCodec(String),

    /// A relay agent refused to accept or store a bundle — over a
    /// per-peer storage bound, a per-peer rate limit, or the bundle
    /// arrived already expired. Refusal, not a bug: see
    /// `relay` module docs.
    #[error("relay refused bundle: {0}")]
    RelayRefused(String),

    /// The dead-drop address window requested doesn't correspond to any
    /// bundle this relay currently holds — a normal "nothing new yet"
    /// outcome for `MeshTransport::receive`, not an error condition.
    #[error("no bundle for the requested address")]
    NoBundleForAddress,

    /// Wraps a `parda_protocol` error surfaced while composing or
    /// parsing an envelope.
    #[error("protocol error: {0}")]
    Protocol(#[from] parda_protocol::error::PardaError),
}

pub type Result<T> = std::result::Result<T, MeshError>;
