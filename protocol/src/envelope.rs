//! Wire message format for PARDA.
//!
//! [`MessageEnvelope`] is the unit of data posted to and fetched from the
//! relay server. The relay server is a dumb pipe — it stores and forwards
//! envelopes without being able to read `ciphertext`, and (as of Phase 2)
//! without being able to read who sent them either.
//!
//! ## Envelope versioning
//!
//! `version` is new in Phase 2. It exists so a receiver can detect a wire
//! format it doesn't understand and refuse explicitly, rather than
//! misinterpreting bytes. Phase 1 never wrote this field; JSON produced by a
//! Phase 1 client deserialises it as [`ENVELOPE_VERSION_V1`] via `#[serde(default)]`.
//! Phase 2 clients always write [`ENVELOPE_VERSION_V2`] explicitly.
//!
//! A Phase 2 client that receives a `version` it does not support (currently:
//! anything above [`ENVELOPE_VERSION_V2`]) must reject the envelope with
//! [`crate::error::PardaError::UnsupportedEnvelopeVersion`] rather than
//! attempting to decode it. See `protocol/tests/sealed_sender_tests.rs` for
//! the adversarial test covering this.
//!
//! ## Phase 2-3 extension stubs
//!
//! `self_destruct_at` remains reserved and unused (`None`) until Phase 3
//! (self-destruct). `sealed_sender` is now load-bearing: see below.
//!
//! `routing_hint` also stays unused/`None` — permanently, not just until
//! some later phase fills it in. Sub-Phase 2B's mix routing
//! (`parda_protocol::mixnet`, `protocol/src/transport.rs::MixTransport`)
//! wraps the *entire serialised envelope* as a Sphinx packet payload
//! rather than attaching a routing header to the envelope struct itself.
//! `routing_hint` predates that design settling and is not the mechanism
//! Sub-Phase 2B actually uses; it's left in place rather than removed so
//! the wire format doesn't churn, but no code path ever populates it.

use serde::{Deserialize, Serialize};

use crate::error::{PardaError, Result};

/// Wire format version written by Phase 1 clients (implicit — the field
/// did not exist yet; absent-on-the-wire is treated as this value).
pub const ENVELOPE_VERSION_V1: u8 = 1;

/// Wire format version written by Phase 2 clients: adds sealed-sender
/// (`sealed_sender` + [`EnvelopeType::SealedSender`]) and reserves
/// `routing_hint` for Sub-Phase 2B mix routing.
pub const ENVELOPE_VERSION_V2: u8 = 2;

/// Highest envelope version this build understands. Receiving anything
/// greater must fail loud via [`crate::error::PardaError::UnsupportedEnvelopeVersion`].
pub const MAX_SUPPORTED_ENVELOPE_VERSION: u8 = ENVELOPE_VERSION_V2;

fn default_envelope_version() -> u8 {
    ENVELOPE_VERSION_V1
}

/// Classifies the libsignal ciphertext variant carried in `ciphertext`.
///
/// Needed by the receiver to deserialise the correct libsignal message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeType {
    /// First message from Alice to Bob — contains the X3DH ephemeral key.
    /// Bob uses this to establish his session (PreKeySignalMessage).
    PreKey,
    /// Subsequent messages — pure Double Ratchet (SignalMessage).
    Ratchet,
    /// Sealed-sender message (Phase 2, requires `version >= ENVELOPE_VERSION_V2`).
    ///
    /// `ciphertext` holds a libsignal `UnidentifiedSenderMessage` — a
    /// self-contained blob combining the sender's certificate with the
    /// inner PreKey/Ratchet ciphertext. The inner type is recovered by
    /// `sealed_sender_decrypt` itself; the relay and this enum never need
    /// to distinguish PreKey-vs-Ratchet for sealed messages.
    SealedSender,
}

/// The wire envelope exchanged between client and relay server.
///
/// In Phase 1 (`version == 1`), all fields except `ciphertext` are plaintext
/// metadata visible to the relay. In Phase 2 (`version == 2`) with
/// `sealed_sender == true`, `sender_id` is an empty string on the wire — the
/// true sender is recoverable only by the recipient, after decryption,
/// through the certificate embedded in `ciphertext`. `recipient_id` remains
/// plaintext in both versions: the relay still needs to know where to
/// deliver the envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Sender identifier. Plaintext in Phase 1. In Phase 2 sealed-sender
    /// envelopes this is always `""` on the wire — see module docs.
    pub sender_id: String,

    /// Plaintext recipient identifier used for relay routing.
    pub recipient_id: String,

    /// Raw serialised libsignal ciphertext bytes (or, for
    /// [`EnvelopeType::SealedSender`], a serialised `UnidentifiedSenderMessage`).
    #[serde(with = "serde_bytes_base64")]
    pub ciphertext: Vec<u8>,

    /// Which libsignal message type `ciphertext` contains.
    pub envelope_type: EnvelopeType,

    /// Unix epoch timestamp in milliseconds at time of encryption.
    pub timestamp_ms: u64,

    /// Envelope wire format version. See module docs. Absent on the wire
    /// (old Phase 1 data) deserialises as [`ENVELOPE_VERSION_V1`].
    #[serde(default = "default_envelope_version")]
    pub version: u8,

    // ── Phase 2 ────────────────────────────────────────────────────────

    /// When `true`, `sender_id` is empty and the real sender is authenticated
    /// only after decryption via the embedded `SenderCertificate`. Requires
    /// `version >= ENVELOPE_VERSION_V2` and `envelope_type == SealedSender`.
    pub sealed_sender: bool,

    /// Unused — permanently `None`. Sub-Phase 2B's mix routing wraps the
    /// whole envelope as a Sphinx payload instead of using this field;
    /// see module docs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_hint: Option<Vec<u8>>,

    // ── Phase 3 (Sub-Phase 3A) ──────────────────────────────────────────

    /// Unix epoch timestamp (ms) at which the sender intends this
    /// message to become unreadable. `None` for messages that don't
    /// self-destruct.
    ///
    /// **This is advisory wire metadata, not the enforcement
    /// mechanism.** It travels in plaintext alongside the envelope (the
    /// relay and any mix node can see it, same as `timestamp_ms`), so it
    /// must never be treated as secret, and a malicious relay/mix node
    /// could in principle strip or alter it in transit. Actual
    /// enforcement happens entirely on the receiving device, locally, via
    /// `self_destruct::SelfDestructingMessage`'s monotonic-clock-anchored
    /// timer (see `docs/phase3-3a-self-destruct-design.md`) — that timer
    /// is what a receiver's own code must rely on, not trust in this
    /// field surviving the wire intact. This field exists so a receiving
    /// UI can *display* the intended expiry before it fires, and so the
    /// receiver's `SelfDestructingMessage::seal` call has a `timestamp_ms`
    /// to derive its key from — not as a security boundary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_destruct_at: Option<u64>,

    // ── Phase 3 (Sub-Phase 3B) ──────────────────────────────────────────

    /// `true` if this message should be destroyed after first read
    /// rather than (or in addition to, if `self_destruct_at` is *also*
    /// set) at a fixed deadline. `self_destruct_at` alone can't express
    /// "destroy on read" — there's no fixed timestamp for a read-triggered
    /// message — so this is a separate field, not an overload of that
    /// one. `#[serde(default)]` so envelopes from before this field
    /// existed deserialise as `false` (not self-destructing), matching
    /// how `version` already handles this project's stated
    /// wire-compatibility requirement.
    ///
    /// Same advisory-only caveat as `self_destruct_at`: this is what a
    /// receiving UI uses to decide whether to call
    /// `SelfDestructingMessage::seal` vs `seal_read_triggered`, not a
    /// security boundary a hostile relay/mix node is prevented from
    /// altering. It is, however, load-bearing for
    /// `client_store::LocalMessageStore`'s write-path enforcement (Sub-Phase
    /// 3D) — a message this device itself just decrypted and is about to
    /// persist gets checked against its *own local* copy of this flag,
    /// not one that traveled untrusted over the network, so the
    /// persistence boundary itself does not inherit the wire's
    /// advisory-only trust level. See `client_store` module docs.
    #[serde(default)]
    pub read_triggered_destruct: bool,

    // ── Phase 4 (Sub-Phase 4C) ──────────────────────────────────────────

    /// Blinded dead-drop storage address (`dead_drop::TagKey::address_for`),
    /// set when a message is composed for delivery via `parda_mesh`'s
    /// offline mesh transport. `None` for every other transport — one
    /// envelope shape, any transport, per this phase's explicit
    /// requirement; `DirectTransport`/`MixTransport` ignore this field
    /// entirely. Additive and backward-compatible (`Option` +
    /// `skip_serializing_if`), same pattern `self_destruct_at` and
    /// `read_triggered_destruct` already established.
    ///
    /// **Composing a mesh-bound envelope also requires `sealed_sender =
    /// true` with both `sender_id` and `recipient_id` empty** — unlike
    /// `DirectTransport`, mesh routing uses this address instead of
    /// `recipient_id`, so leaving either identity field populated would
    /// hand it to every untrusted carrier that stores the bundle for no
    /// routing benefit. `parda_mesh`'s `MeshTransport::send` enforces
    /// this, fail-closed. See `docs/phase4-4c-dead-drop-addressing-design.md`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dead_drop_address: Option<[u8; 32]>,
}

impl MessageEnvelope {
    /// Reject anything this build doesn't understand *before* attempting to
    /// decode `ciphertext`. Must be called first by every decrypt path —
    /// see `docs/THREAT_MODEL.md` "envelope version mismatch" handling.
    pub fn validate_version(&self) -> Result<()> {
        if self.version > MAX_SUPPORTED_ENVELOPE_VERSION {
            return Err(PardaError::UnsupportedEnvelopeVersion {
                got: self.version,
                max_supported: MAX_SUPPORTED_ENVELOPE_VERSION,
            });
        }
        if self.sealed_sender && self.version < ENVELOPE_VERSION_V2 {
            return Err(PardaError::MalformedSealedSender(
                "sealed_sender = true is not valid on a version-1 envelope".to_string(),
            ));
        }
        if self.sealed_sender && self.envelope_type != EnvelopeType::SealedSender {
            return Err(PardaError::MalformedSealedSender(format!(
                "sealed_sender = true requires envelope_type = SealedSender, got {:?}",
                self.envelope_type
            )));
        }
        if !self.sealed_sender && self.envelope_type == EnvelopeType::SealedSender {
            return Err(PardaError::MalformedSealedSender(
                "envelope_type = SealedSender requires sealed_sender = true".to_string(),
            ));
        }
        Ok(())
    }

    /// Declare this envelope as self-destructing `expiry_window` after
    /// `timestamp_ms`. Only sets the advisory wire field — see
    /// [`Self::self_destruct_at`] docs for why this alone does not
    /// enforce anything; the caller is still responsible for wrapping
    /// the plaintext in a `self_destruct::SelfDestructingMessage` on the
    /// receiving end.
    #[must_use]
    pub fn with_self_destruct(mut self, expiry_window: std::time::Duration) -> Self {
        self.self_destruct_at = Some(self.timestamp_ms + expiry_window.as_millis() as u64);
        self
    }

    /// Declare this envelope as read-triggered self-destructing — see
    /// [`Self::read_triggered_destruct`] docs for what this does and
    /// doesn't guarantee on the wire.
    #[must_use]
    pub fn with_read_triggered_destruct(mut self) -> Self {
        self.read_triggered_destruct = true;
        self
    }
}

// ─── Base64 serde helper ──────────────────────────────────────────────────────

mod serde_bytes_base64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}
