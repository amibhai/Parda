//! Sealed-sender certificate authority.
//!
//! Wraps libsignal-protocol's own sealed-sender implementation
//! (`SenderCertificate`, `ServerCertificate`, `sealed_sender_encrypt`,
//! `sealed_sender_decrypt` — see `sealed_sender.rs` in the pinned
//! `libsignal-protocol` crate, which implements the scheme described in
//! Signal's "Sealed Sender" design: <https://signal.org/blog/sealed-sender/>).
//! No cryptographic primitives are implemented here — this module only
//! manages the certificate chain (trust root → server certificate → sender
//! certificate) that scheme requires.
//!
//! ## Certificate chain
//!
//! ```text
//! TrustRoot (long-term keypair, public half baked into every client)
//!   └─ signs ──▶ ServerCertificate (parda-relay's medium-term signing key)
//!                  └─ signs ──▶ SenderCertificate (per-user, expires)
//! ```
//!
//! In Phase 2, `parda-relay` hosts the [`CertificateAuthority`] — it issues
//! `ServerCertificate`/`SenderCertificate`s the same way it already serves
//! prekey bundles: with no account authentication behind it (none exists in
//! PARDA yet). This is the same Trust-On-First-Use posture already disclosed
//! for prekey bundles in `docs/phase1-architecture.md` §10 ("No server
//! authentication"), extended to sender certificates. It authenticates
//! *senders to recipients* (sealed-sender's actual job); it does not
//! authenticate *clients to the relay*.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libsignal_protocol::{DeviceId, KeyPair, PrivateKey, PublicKey, SenderCertificate, ServerCertificate, Timestamp};
use rand::rngs::OsRng;

use crate::error::{PardaError, Result};

/// Fixed key ID for the single server certificate this CA issues.
/// (libsignal reserves `0xDEADC357` for revocation testing — never use it.)
const SERVER_CERT_KEY_ID: u32 = 1;

/// Default sender-certificate lifetime. Kept short since Phase 2 has no
/// revocation mechanism beyond expiry.
pub const DEFAULT_SENDER_CERT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

fn now_timestamp() -> Timestamp {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64;
    Timestamp::from_epoch_millis(ms)
}

/// The long-term trust root keypair. Its public half is the one fixed value
/// every PARDA client must be configured with out-of-band (mirroring how
/// Signal's own clients embed a hardcoded trust root public key).
///
/// **Prototype limitation:** in a real deployment the trust root private key
/// would be generated once, kept offline/HSM-backed, and used only to sign
/// server certificates during key rotation — never resident in the relay
/// process. Here `CertificateAuthority` holds both halves in-process for
/// demo purposes; this is called out explicitly in `docs/THREAT_MODEL.md`
/// and must not be read as production guidance.
pub struct TrustRoot {
    key_pair: KeyPair,
}

impl TrustRoot {
    /// Generate a fresh trust root. Call once per deployment; the resulting
    /// public key must be distributed to every client that will validate
    /// sealed-sender messages against this authority.
    pub fn generate() -> Self {
        Self {
            key_pair: KeyPair::generate(&mut OsRng),
        }
    }

    /// Reconstruct a trust root from a previously generated keypair, e.g.
    /// one loaded from configuration rather than generated fresh.
    pub fn from_key_pair(key_pair: KeyPair) -> Self {
        Self { key_pair }
    }

    pub fn public_key(&self) -> PublicKey {
        self.key_pair.public_key
    }

    fn private_key(&self) -> &PrivateKey {
        &self.key_pair.private_key
    }
}

/// Issues sender certificates on behalf of a trust root.
///
/// One `CertificateAuthority` mints exactly one `ServerCertificate` at
/// construction time (signed by the trust root), then uses that server
/// certificate's key to sign as many per-user `SenderCertificate`s as are
/// requested.
pub struct CertificateAuthority {
    trust_root: TrustRoot,
    server_key_pair: KeyPair,
    server_certificate: ServerCertificate,
}

impl CertificateAuthority {
    /// Create a new CA with a freshly generated trust root and server key.
    pub fn new() -> Result<Self> {
        Self::from_trust_root(TrustRoot::generate())
    }

    /// Create a new CA rooted at an existing trust root (e.g. loaded from
    /// relay configuration so restarts don't invalidate outstanding certs
    /// held by clients).
    pub fn from_trust_root(trust_root: TrustRoot) -> Result<Self> {
        let mut rng = OsRng;
        let server_key_pair = KeyPair::generate(&mut rng);
        let server_certificate = ServerCertificate::new(
            SERVER_CERT_KEY_ID,
            server_key_pair.public_key,
            trust_root.private_key(),
            &mut rng,
        )
        .map_err(PardaError::Signal)?;

        Ok(Self {
            trust_root,
            server_key_pair,
            server_certificate,
        })
    }

    /// The trust root public key. Distribute this to clients out-of-band;
    /// they pin it to validate every sealed-sender message they decrypt.
    pub fn trust_root_public_key(&self) -> PublicKey {
        self.trust_root.public_key()
    }

    /// Issue a `SenderCertificate` binding `sender_uuid`'s identity key to
    /// their name for `ttl`. The certificate is what the sender attaches to
    /// every sealed-sender message they send; recipients validate it against
    /// [`Self::trust_root_public_key`].
    pub fn issue_sender_certificate(
        &self,
        sender_uuid: impl Into<String>,
        identity_public_key: PublicKey,
        device_id: DeviceId,
        ttl: Duration,
    ) -> Result<SenderCertificate> {
        let mut rng = OsRng;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch");
        let expiration = Timestamp::from_epoch_millis((now + ttl).as_millis() as u64);

        SenderCertificate::new(
            sender_uuid.into(),
            None, // no e164 phone identifier in PARDA
            identity_public_key,
            device_id,
            expiration,
            self.server_certificate.clone(),
            &self.server_key_pair.private_key,
            &mut rng,
        )
        .map_err(PardaError::Signal)
    }
}

/// Validate `cert` against `trust_root` at the current time. Thin wrapper
/// over `SenderCertificate::validate` that maps failure to a typed PARDA
/// error instead of a bare `false`, so callers cannot forget to check it.
pub fn validate_sender_certificate(cert: &SenderCertificate, trust_root: &PublicKey) -> Result<()> {
    let valid = cert
        .validate(trust_root, now_timestamp())
        .map_err(PardaError::Signal)?;
    if valid {
        Ok(())
    } else {
        Err(PardaError::SealedSenderAuth(
            "sender certificate failed trust-root/expiry validation".to_string(),
        ))
    }
}
