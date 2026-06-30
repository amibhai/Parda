//! Session management: X3DH handshake and Double Ratchet encrypt / decrypt.
//!
//! # Session lifecycle
//!
//! ```text
//! Alice (sender)                              Bob (receiver)
//! ──────────────────────────────────────────────────────────
//! 1. Fetch Bob's PreKeyBundle from relay
//! 2. process_prekey_bundle() → establishes session (Alice side)
//! 3. encrypt("hello") → PreKeySignalMessage (contains ephemeral key)
//! 4. POST /v1/messages/bob
//!                                     5. GET  /v1/messages/bob
//!                                     6. decrypt(PreKeySignalMessage) →
//!                                           establishes session (Bob side)
//!                                           returns "hello"
//! ── Both ends now have a Double Ratchet session ──────────────
//! 7. encrypt("message 2") → SignalMessage
//! 8. POST /v1/messages/bob
//!                                     9. decrypt(SignalMessage) → "message 2"
//! ```
//!
//! # Forward secrecy
//!
//! After each ratchet step the previous message keys are deleted.
//! An adversary who recovers the session state at step N cannot decrypt
//! messages from steps 0 … N-1.

use std::time::SystemTime;

use libsignal_protocol::{
    message_decrypt, message_encrypt, process_prekey_bundle, CiphertextMessage,
    PreKeyBundle, ProtocolAddress,
};
use rand::rngs::OsRng;

use crate::{
    envelope::{MessageEnvelope, EnvelopeType},
    error::{PardaError, Result},
    store::InMemorySignalProtocolStore,
};

/// Wraps a single user's signal store and exposes encrypt / decrypt operations.
pub struct SessionManager {
    /// Stable identity of this device, e.g. "alice.1" (name + device_id).
    pub local_address: ProtocolAddress,
    /// Backing store (in-memory for tests; hardware-backed in production).
    pub store: InMemorySignalProtocolStore,
}

impl SessionManager {
    /// Create a new session manager for `local_address`.
    pub fn new(
        local_address: ProtocolAddress,
        store: InMemorySignalProtocolStore,
    ) -> Self {
        Self { local_address, store }
    }

    /// Initiate a session with a remote peer using their [`PreKeyBundle`].
    ///
    /// Must be called before the first `encrypt` to a new peer.
    /// Internally performs the X3DH key agreement.
    pub async fn initiate_session(
        &mut self,
        remote_address: &ProtocolAddress,
        bundle: &PreKeyBundle,
    ) -> Result<()> {
        let mut rng = OsRng;
        process_prekey_bundle(
            remote_address,
            &mut self.store, // session store
            &mut self.store, // identity key store
            bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await
        .map_err(PardaError::Signal)
    }

    /// Encrypt `plaintext` for `remote_address`.
    ///
    /// Returns a [`MessageEnvelope`] ready to POST to the relay server.
    /// If no session exists for `remote_address`, returns [`PardaError::SessionNotFound`].
    pub async fn encrypt(
        &mut self,
        remote_address: &ProtocolAddress,
        plaintext: &[u8],
    ) -> Result<MessageEnvelope> {
        let ciphertext = message_encrypt(
            plaintext,
            remote_address,
            &mut self.store, // session store
            &mut self.store, // identity key store
            SystemTime::now(),
        )
        .await
        .map_err(PardaError::Signal)?;

        let envelope_type = match ciphertext {
            CiphertextMessage::PreKeySignalMessage(_) => EnvelopeType::PreKey,
            CiphertextMessage::SignalMessage(_) => EnvelopeType::Ratchet,
            _ => EnvelopeType::Ratchet,
        };

        Ok(MessageEnvelope {
            sender_id: self.local_address.name().to_string(),
            recipient_id: remote_address.name().to_string(),
            ciphertext: ciphertext.serialize().to_vec(),
            envelope_type,
            timestamp_ms: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            // ── Phase 2 stubs ──
            sealed_sender: false,
            routing_hint: None,
            // ── Phase 3 stubs ──
            self_destruct_at: None,
        })
    }

    /// Decrypt an incoming [`MessageEnvelope`].
    ///
    /// Handles both `PreKey` envelopes (first message, establishes session
    /// on the receiver side) and `Ratchet` envelopes (subsequent messages).
    ///
    /// The Double Ratchet step is performed inside `message_decrypt`; the
    /// old ratchet key is deleted automatically.
    pub async fn decrypt(
        &mut self,
        envelope: &MessageEnvelope,
    ) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let sender_address =
            ProtocolAddress::new(envelope.sender_id.clone(), 1.into());

        let ciphertext = match envelope.envelope_type {
            EnvelopeType::PreKey => CiphertextMessage::PreKeySignalMessage(
                libsignal_protocol::PreKeySignalMessage::try_from(
                    envelope.ciphertext.as_ref(),
                )
                .map_err(PardaError::Signal)?,
            ),
            EnvelopeType::Ratchet => CiphertextMessage::SignalMessage(
                libsignal_protocol::SignalMessage::try_from(
                    envelope.ciphertext.as_ref(),
                )
                .map_err(PardaError::Signal)?,
            ),
        };

        message_decrypt(
            &ciphertext,
            &sender_address,
            &mut self.store, // session store
            &mut self.store, // identity key store
            &mut self.store, // prekey store
            &mut self.store, // signed prekey store
            &mut rng,
        )
        .await
        .map_err(PardaError::Signal)
    }
}
