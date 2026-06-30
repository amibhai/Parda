//! Identity key management and prekey bundle construction.
//!
//! A [`LocalIdentity`] holds everything the local device owns:
//! - The long-term Ed25519 identity key pair
//! - One signed prekey (rotated periodically)
//! - A batch of one-time Curve25519 prekeys
//!
//! Call [`LocalIdentity::generate`] once during first-run enrollment,
//! then persist the result via the hardware-backed key store (Android
//! Keystore / iOS Secure Enclave). **Never write private key bytes to disk.**

use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol::{
    IdentityKey, IdentityKeyPair, KeyPair, PreKeyId, PreKeyRecord,
    SignedPreKeyId, SignedPreKeyRecord, PreKeyBundle,
};
use rand::rngs::OsRng;

use crate::error::{PardaError, Result};

/// Maximum number of one-time prekeys uploaded per registration.
pub const ONE_TIME_PREKEY_BATCH: u32 = 100;

/// Holds the local device's long-term and ephemeral key material.
///
/// In production this struct is backed by the platform secure element;
/// in tests the `InMemorySignalProtocolStore` is used instead.
pub struct LocalIdentity {
    /// 32-bit opaque ID assigned by the server during registration.
    pub registration_id: u32,
    /// Long-term Ed25519 identity key pair.
    pub identity_key_pair: IdentityKeyPair,
    /// Current signed prekey (Curve25519, signed with identity private key).
    pub signed_prekey: SignedPreKeyRecord,
    /// Pool of one-time Curve25519 prekeys for X3DH.
    pub one_time_prekeys: Vec<PreKeyRecord>,
}

impl LocalIdentity {
    /// Generate a fresh identity from scratch.
    ///
    /// Should be called **once** at first-run enrollment. The returned
    /// [`LocalIdentity`] must be immediately persisted through the platform
    /// key-storage layer before the calling function returns.
    pub fn generate(registration_id: u32) -> Result<Self> {
        let mut rng = OsRng;

        // ── Long-term identity key ────────────────────────────────────────
        let identity_key_pair = IdentityKeyPair::generate(&mut rng);

        // ── Signed prekey ─────────────────────────────────────────────────
        let signed_prekey_pair = KeyPair::generate(&mut rng);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PardaError::KeyGeneration(e.to_string()))?
            .as_millis() as u64;

        let signature = identity_key_pair
            .private_key()
            .calculate_signature(&signed_prekey_pair.public_key.serialize(), &mut rng)
            .map_err(|e| PardaError::KeyGeneration(e.to_string()))?;

        let signed_prekey = SignedPreKeyRecord::new(
            SignedPreKeyId::from(1u32),
            now_ms,
            &signed_prekey_pair,
            &signature,
        );

        // ── One-time prekeys ──────────────────────────────────────────────
        let one_time_prekeys = (0..ONE_TIME_PREKEY_BATCH)
            .map(|i| {
                let kp = KeyPair::generate(&mut rng);
                PreKeyRecord::new(PreKeyId::from(i), &kp)
            })
            .collect();

        Ok(Self {
            registration_id,
            identity_key_pair,
            signed_prekey,
            one_time_prekeys,
        })
    }

    /// Build a [`PreKeyBundle`] suitable for upload to the relay server.
    ///
    /// Consumes the first one-time prekey in the pool. The server is expected
    /// to serve each one-time prekey only once; callers should replenish the
    /// pool when it runs low.
    pub fn build_prekey_bundle(&self) -> Result<PreKeyBundle> {
        let otpk = self
            .one_time_prekeys
            .first()
            .map(|pk| -> Result<(PreKeyId, libsignal_protocol::PublicKey)> {
                Ok((
                    pk.id().map_err(|e| PardaError::KeyGeneration(e.to_string()))?,
                    pk.public_key().map_err(|e| PardaError::KeyGeneration(e.to_string()))?,
                ))
            })
            .transpose()?;

        let signed_prekey_id = self
            .signed_prekey
            .id()
            .map_err(|e| PardaError::KeyGeneration(e.to_string()))?;

        let signed_prekey_pub = self
            .signed_prekey
            .public_key()
            .map_err(|e| PardaError::KeyGeneration(e.to_string()))?;

        let signature = self
            .signed_prekey
            .signature()
            .map_err(|e| PardaError::KeyGeneration(e.to_string()))?
            .to_vec();

        let bundle = PreKeyBundle::new(
            self.registration_id,
            1u32.into(), // device_id — single-device in Phase 1
            otpk,
            signed_prekey_id,
            signed_prekey_pub,
            signature,
            IdentityKey::new(*self.identity_key_pair.public_key()),
        )
        .map_err(PardaError::Signal)?;

        Ok(bundle)
    }
}
