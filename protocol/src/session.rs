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
    message_decrypt, message_encrypt, process_prekey_bundle, sealed_sender_decrypt,
    sealed_sender_encrypt, CiphertextMessage, DeviceId, PreKeyBundle, ProtocolAddress,
    PublicKey, SenderCertificate, Timestamp,
};
use rand::rngs::OsRng;

use crate::{
    envelope::{EnvelopeType, MessageEnvelope, ENVELOPE_VERSION_V2},
    error::{PardaError, Result},
    store::InMemorySignalProtocolStore,
};

/// Plaintext + authenticated sender identity recovered from a sealed-sender
/// envelope. The sender identity here is trustworthy — it was validated
/// against the sender certificate's signature chain during decryption, not
/// taken from an attacker-controlled plaintext field.
pub struct SealedSenderPlaintext {
    pub sender_uuid: String,
    pub device_id: DeviceId,
    pub plaintext: Vec<u8>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

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

    /// "Burn this conversation" with `remote_address` (Sub-Phase 3D).
    /// Session-level destruct, distinct from — and with a materially
    /// weaker erasure guarantee than — message-level self-destruct
    /// (`crate::self_destruct`). See
    /// `crate::store::InMemorySignalProtocolStore::burn_session`'s doc
    /// comment for exactly what is and isn't proven, and why.
    ///
    /// After this call, `encrypt`/`decrypt` against `remote_address`
    /// behave as if no session had ever been established — a fresh
    /// `initiate_session`/incoming PreKey message is required before
    /// this conversation can resume.
    pub fn burn_conversation(&self, remote_address: &ProtocolAddress) -> crate::store::SessionBurnResult {
        self.store.burn_session(remote_address)
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
        // `self.store` implements every storage trait on one handle; each
        // parameter below needs its own live `&mut` borrow, so we hand out
        // independent clones of the (Rc-backed) handle rather than the same
        // place twice — see the module docs on `InMemorySignalProtocolStore`.
        process_prekey_bundle(
            remote_address,
            &mut self.store.clone(), // session store
            &mut self.store.clone(), // identity key store
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
            &mut self.store.clone(), // session store
            &mut self.store.clone(), // identity key store
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
            timestamp_ms: now_ms(),
            version: ENVELOPE_VERSION_V2,
            // ── Phase 2 (not used on this path — see `encrypt_sealed`) ──
            sealed_sender: false,
            routing_hint: None,
            // Not self-destructing by default — callers opt in via
            // `MessageEnvelope::with_self_destruct` /
            // `::with_read_triggered_destruct` on the returned envelope.
            self_destruct_at: None,
            read_triggered_destruct: false,
        })
    }

    /// Encrypt `plaintext` for `remote_address` using sealed sender: the
    /// relay (and anyone reading its logs/store) sees only `recipient_id`.
    /// `sender_cert` must have been issued to this device's own identity key
    /// by a `CertificateAuthority` the recipient trusts — see
    /// [`crate::sealed_sender`].
    pub async fn encrypt_sealed(
        &mut self,
        remote_address: &ProtocolAddress,
        plaintext: &[u8],
        sender_cert: &SenderCertificate,
    ) -> Result<MessageEnvelope> {
        let mut rng = OsRng;
        let sealed_bytes = sealed_sender_encrypt(
            remote_address,
            sender_cert,
            plaintext,
            &mut self.store.clone(), // session store
            &mut self.store.clone(), // identity key store
            SystemTime::now(),
            &mut rng,
        )
        .await
        .map_err(PardaError::Signal)?;

        Ok(MessageEnvelope {
            // Never populated for sealed-sender envelopes: the true sender
            // is recoverable only by the recipient, after decryption, via
            // the certificate embedded in `ciphertext`.
            sender_id: String::new(),
            recipient_id: remote_address.name().to_string(),
            ciphertext: sealed_bytes,
            envelope_type: EnvelopeType::SealedSender,
            timestamp_ms: now_ms(),
            version: ENVELOPE_VERSION_V2,
            sealed_sender: true,
            routing_hint: None,
            self_destruct_at: None,
            read_triggered_destruct: false,
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
        envelope.validate_version()?;

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
            EnvelopeType::SealedSender => {
                return Err(PardaError::MalformedSealedSender(
                    "sealed-sender envelopes must be decrypted via decrypt_sealed, not decrypt"
                        .to_string(),
                ));
            }
        };

        message_decrypt(
            &ciphertext,
            &sender_address,
            &mut self.store.clone(), // session store
            &mut self.store.clone(), // identity key store
            &mut self.store.clone(), // prekey store
            &self.store.clone(),     // signed prekey store (read-only in this call)
            &mut self.store.clone(), // kyber prekey store (unused: no PQXDH until Phase 5)
            &mut rng,
        )
        .await
        .map_err(PardaError::Signal)
    }

    /// Decrypt a sealed-sender envelope produced by [`Self::encrypt_sealed`].
    ///
    /// Unlike [`Self::decrypt`], this does not trust `envelope.sender_id`
    /// (it is empty on the wire — see `envelope` module docs); the sender
    /// identity returned in [`SealedSenderPlaintext`] is instead recovered
    /// from the embedded `SenderCertificate`, which libsignal validates
    /// against `trust_root` (expiry + signature chain) *before* returning
    /// any plaintext. A forged or expired certificate yields
    /// [`PardaError::Signal`] here, never a plaintext.
    ///
    /// `local_uuid` / `local_device_id` are this device's own identity, used
    /// only for libsignal's self-send loop-detection — they are not secret.
    pub async fn decrypt_sealed(
        &mut self,
        envelope: &MessageEnvelope,
        trust_root: &PublicKey,
        local_uuid: &str,
        local_device_id: DeviceId,
    ) -> Result<SealedSenderPlaintext> {
        envelope.validate_version()?;
        if envelope.envelope_type != EnvelopeType::SealedSender {
            return Err(PardaError::MalformedSealedSender(format!(
                "decrypt_sealed requires envelope_type = SealedSender, got {:?}",
                envelope.envelope_type
            )));
        }

        let result = sealed_sender_decrypt(
            &envelope.ciphertext,
            trust_root,
            Timestamp::from_epoch_millis(now_ms()),
            None, // no e164 phone identifier in PARDA
            local_uuid.to_string(),
            local_device_id,
            &mut self.store.clone(), // identity store
            &mut self.store.clone(), // session store
            &mut self.store.clone(), // prekey store
            &self.store.clone(),     // signed prekey store (read-only in this call)
            &mut self.store.clone(), // kyber prekey store (unused: no PQXDH until Phase 5)
        )
        .await
        .map_err(PardaError::Signal)?;

        Ok(SealedSenderPlaintext {
            sender_uuid: result.sender_uuid,
            device_id: result.device_id,
            plaintext: result.message,
        })
    }
}
