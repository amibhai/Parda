//! Wire message format for PARDA.
//!
//! [`MessageEnvelope`] is the unit of data posted to and fetched from the
//! relay server. The relay server is a dumb pipe — it stores and forwards
//! envelopes without being able to read `ciphertext`.
//!
//! ## Phase 2-3 extension stubs
//!
//! The fields `sealed_sender`, `routing_hint`, and `self_destruct_at` are
//! defined now so the wire format remains stable as later phases activate them.
//! In Phase 1 they are always `false` / `None` and are ignored by both
//! sender and receiver.

use serde::{Deserialize, Serialize};

/// Classifies the libsignal ciphertext variant.
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
}

/// The wire envelope exchanged between client and relay server.
///
/// All fields except `ciphertext` are plaintext metadata visible to the relay.
/// Phase 2 (sealed-sender) will encrypt sender metadata; Phase 3 adds
/// cryptographic self-destruct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Plaintext sender identifier (Phase 2: hidden by sealed-sender).
    pub sender_id: String,

    /// Plaintext recipient identifier used for relay routing.
    pub recipient_id: String,

    /// Raw serialised libsignal ciphertext bytes.
    #[serde(with = "serde_bytes_base64")]
    pub ciphertext: Vec<u8>,

    /// Whether this is a first-message (`PreKey`) or ratchet (`Ratchet`) envelope.
    pub envelope_type: EnvelopeType,

    /// Unix epoch timestamp in milliseconds at time of encryption.
    pub timestamp_ms: u64,

    // ── Phase 2 stubs (always false / None in Phase 1) ───────────────────

    /// When `true`, the sender identity inside `ciphertext` is hidden.
    /// Activated in Phase 2. Set to `false` in Phase 1.
    pub sealed_sender: bool,

    /// Reserved for Sphinx-packet onion routing header (Phase 2 mix-network).
    /// `None` in Phase 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_hint: Option<Vec<u8>>,

    // ── Phase 3 stub ─────────────────────────────────────────────────────

    /// Unix epoch timestamp (ms) at which the message key should be deleted
    /// on all endpoints. `None` in Phase 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_destruct_at: Option<u64>,
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
