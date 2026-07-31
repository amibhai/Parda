//! Server-side data models.
//!
//! These are the JSON shapes the relay server reads and writes.
//! The relay **never** inspects ciphertext or key material — it stores
//! blobs and forwards them on request.

use serde::{Deserialize, Serialize};

/// A serialisable prekey bundle uploaded by a registering device.
///
/// Mirrors `libsignal_protocol::PreKeyBundle` but as a plain JSON model
/// that the relay can store and serve without understanding its contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundleJson {
    /// Registering device's 32-bit registration ID.
    pub registration_id: u32,
    /// Always `1` in Phase 1 (single-device).
    pub device_id: u32,
    /// Serialised identity public key (base64-encoded).
    pub identity_key: String,
    /// ID of the signed prekey.
    pub signed_prekey_id: u32,
    /// Serialised signed prekey public key (base64-encoded).
    pub signed_prekey_public: String,
    /// Ed25519 signature over the signed prekey (base64-encoded).
    pub signed_prekey_signature: String,
    /// Optional one-time prekey ID.
    pub one_time_prekey_id: Option<u32>,
    /// Serialised one-time prekey public key (base64-encoded, optional).
    pub one_time_prekey_public: Option<String>,
}

/// Incoming encrypted envelope.
///
/// Re-exported from `parda_protocol::envelope::MessageEnvelope` — the relay
/// stores these verbatim.
pub use parda_protocol::envelope::MessageEnvelope;

/// An envelope stored in the relay queue, with an assigned message ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEnvelope {
    /// UUID assigned by the relay on receipt.
    pub id: String,
    /// The encrypted envelope payload.
    #[serde(flatten)]
    pub envelope: MessageEnvelope,
}

/// Response body for the message-fetch endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct FetchMessagesResponse {
    pub messages: Vec<StoredEnvelope>,
}

/// `POST /v1/certs/{user_id}` request body.
///
/// The relay signs whatever identity key is presented here — there is no
/// account authentication in Phase 2 (same Trust-On-First-Use posture as
/// `/v1/keys/{user_id}` prekey bundle uploads). See
/// `parda_protocol::sealed_sender` module docs and `docs/THREAT_MODEL.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueSenderCertRequest {
    /// Base64-encoded libsignal `PublicKey` bytes for the requesting
    /// identity.
    pub identity_key: String,
    /// Device ID the certificate should be bound to (`1` for single-device).
    pub device_id: u32,
    /// Requested certificate lifetime in seconds. The relay may cap this.
    pub ttl_secs: u64,
}

/// `POST /v1/certs/{user_id}` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderCertificateResponse {
    /// Base64-encoded serialised `SenderCertificate`. The requester attaches
    /// this to every sealed-sender message they send.
    pub sender_certificate: String,
}

/// `GET /v1/certs/trust-root` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRootResponse {
    /// Base64-encoded libsignal `PublicKey` bytes. Clients pin this and
    /// validate every sealed-sender message's certificate chain against it.
    pub trust_root_public_key: String,
}

/// Generic API success response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiOk {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ApiOk {
    pub fn success() -> Self {
        Self { ok: true, message: None }
    }
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self { ok: true, message: Some(msg.into()) }
    }
}
