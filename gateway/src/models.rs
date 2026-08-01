//! Typed request/response shapes for the gateway's external API.
//!
//! `MessageEnvelope` is re-exported from `parda_protocol` rather than
//! redefined here — one wire format, not a gateway-specific fork of it —
//! documenting the contract for external consumers even though the
//! message routes themselves (`routes.rs`) deliberately forward raw
//! bytes rather than decoding into this type; see that module's docs for
//! why.
//!
//! [`PreKeyBundleRequest`] is the one shape actually decoded here: the
//! relay treats prekey bundle bodies as untyped JSON, so typing them at
//! the gateway is a concrete instance of "a typed HTTP layer" adding
//! real validation the relay itself doesn't.

use serde::{Deserialize, Serialize};

#[allow(unused_imports)] // part of the documented external contract, see module docs
pub use parda_protocol::envelope::MessageEnvelope;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundleRequest {
    pub registration_id: u32,
    pub device_id: u32,
    pub identity_key: String,
    pub signed_prekey_id: u32,
    pub signed_prekey_public: String,
    pub signed_prekey_signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_time_prekey_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_time_prekey_public: Option<String>,
}
