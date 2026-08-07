//! Unified trust bootstrapping — out-of-band identity-key verification
//! (Sub-Phase 4.5D). **Read `docs/phase4.5d-trust-bootstrapping-design.md`
//! first**; it records what was already there before this module (a real
//! pin-on-first-use in `store.rs`'s `IdentityKeyStore` impl, not naive
//! always-trust), and exactly which of its gaps this module closes.
//!
//! ## The construction is cited, not invented — and not bit-compatible
//!
//! The *pattern* is Signal's published "safety number" concept:
//! compare a fingerprint of both parties' long-term identity keys
//! out-of-band, then treat any later change to those keys as an attack
//! rather than a routine re-pin. The *construction* here is this
//! project's own: HKDF-SHA256 over both serialized identity keys in
//! sorted order — the same primitive already used by
//! [`crate::self_destruct`] and [`crate::dead_drop`], deliberately
//! chosen over re-deriving Signal's exact iterated-SHA-512 algorithm
//! from memory, which risks getting a security-relevant detail subtly
//! wrong while *looking* authoritative. **This is not bit-compatible
//! with Signal's safety numbers and is not intended to be** — PARDA
//! fingerprints are only ever compared against other PARDA
//! fingerprints. See the design note §2.
//!
//! ## What this proves, and what it doesn't
//!
//! **Proven, and tested** (`protocol/tests/trust_bootstrapping_tests.rs`):
//! an identity-key substitution *after* a peer has been marked
//! [`TrustLevel::Verified`] is detected and fails loud with
//! [`crate::PardaError::IdentityKeyChangedAfterVerification`].
//!
//! **Not proven, stated directly:** an active MITM present at *first*
//! contact — before any out-of-band comparison has happened — succeeds,
//! exactly as it does today and exactly as it does against any
//! trust-on-first-use scheme including Signal's. This module does not
//! change that and does not claim to. It also does not build the
//! out-of-band comparison UI; [`TrustStore::record_verified`] is the
//! seam a future UI would call, and this sub-phase's tests call it
//! directly.

use std::{collections::HashMap, sync::Mutex};

use hkdf::Hkdf;
use libsignal_protocol::IdentityKey;
use sha2::Sha256;

use crate::error::{PardaError, Result};

/// Domain-separation label. Distinct from every other HKDF use in this
/// crate (`self_destruct`'s `KDF_CONTEXT`, `dead_drop`'s tag-key
/// context) so no output of one construction can ever collide with
/// another's, even given identical input key material.
const FINGERPRINT_CONTEXT: &[u8] = b"PARDA-Fingerprint-v1";

/// HKDF output length: twelve 5-byte groups (see [`Fingerprint::digits`]).
const FINGERPRINT_LEN: usize = 60;

/// A human-comparable fingerprint over a *pair* of identity keys.
///
/// Symmetric by construction: both parties compute the identical value
/// regardless of which of them is "local" — the two serialized keys are
/// sorted before hashing, so there is no local/remote ordering to get
/// wrong (see design note §2 on why sorting is used instead of Signal's
/// interleaved-halves layout).
#[derive(Clone, PartialEq, Eq)]
pub struct Fingerprint([u8; FINGERPRINT_LEN]);

impl Fingerprint {
    /// Compute the fingerprint for the `(local, remote)` identity-key
    /// pair. Argument order does not matter — see type docs.
    pub fn compute(local: &IdentityKey, remote: &IdentityKey) -> Self {
        let a = local.serialize();
        let b = remote.serialize();
        // Lexicographic sort on the serialized encodings, so both sides
        // feed HKDF the same input regardless of perspective.
        let (first, second) = if a.as_ref() <= b.as_ref() {
            (a.as_ref(), b.as_ref())
        } else {
            (b.as_ref(), a.as_ref())
        };

        let mut ikm = Vec::with_capacity(first.len() + second.len());
        ikm.extend_from_slice(first);
        ikm.extend_from_slice(second);

        let hk = Hkdf::<Sha256>::new(Some(FINGERPRINT_CONTEXT), &ikm);
        let mut okm = [0u8; FINGERPRINT_LEN];
        // Only fails when the requested length exceeds 255 * hash_len;
        // 60 bytes is far below that for SHA-256.
        hk.expand(FINGERPRINT_CONTEXT, &mut okm)
            .expect("60-byte HKDF-Expand output is always valid for SHA-256");

        Self(okm)
    }

    /// Raw fingerprint bytes. This — not [`Self::digits`] — is what
    /// equality comparisons actually use.
    pub fn as_bytes(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.0
    }

    /// The 60-decimal-digit display form, as twelve space-separated
    /// groups of five — the shape a user reads aloud or compares against
    /// a screen. **Display formatting only**; the security property
    /// lives in [`Self::as_bytes`], and every check in this module
    /// compares those bytes, never this string.
    pub fn digits(&self) -> String {
        self.0
            .chunks_exact(5)
            .map(|chunk| {
                // Big-endian 40-bit integer, reduced to five decimal
                // digits. A `u64` holds 40 bits with room to spare.
                let value = chunk
                    .iter()
                    .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte));
                format!("{:05}", value % 100_000)
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl std::fmt::Debug for Fingerprint {
    /// Prints the display digits rather than raw bytes — a fingerprint
    /// is public, comparable information (that is its entire purpose),
    /// so there is nothing here to redact, and the digits are the form
    /// a human debugging a mismatch actually wants to see.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fingerprint({})", self.digits())
    }
}

/// How much trust has been established for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// No out-of-band verification has happened. The default, and
    /// **behaviorally identical to this project's pre-4.5D posture**:
    /// libsignal's own pin-on-first-use still applies underneath, and
    /// nothing in this module rejects anything at this level.
    Tofu,
    /// A fingerprint was compared out-of-band and confirmed. Any
    /// *different* identity key for this peer from now on is a hard
    /// failure, not a silent re-pin.
    Verified,
}

/// Persistence seam for verified fingerprints. Mirrors
/// [`crate::clock_guard::ClockWatermarkStore`]'s trait/impl split:
/// production callers back this with real durable storage,
/// [`InMemoryTrustStore`] is for tests and single-process use, where it
/// provides no protection across a restart because nothing survives
/// process exit.
///
/// Absence of an entry *is* [`TrustLevel::Tofu`] — there is deliberately
/// no separate stored flag that could drift out of sync with the
/// fingerprint itself.
pub trait TrustStore: Send + Sync {
    /// The fingerprint previously verified for `peer_id`, if any.
    fn verified_fingerprint(&self, peer_id: &str) -> Option<Fingerprint>;

    /// Record `fingerprint` as out-of-band verified for `peer_id`. The
    /// seam a verification UI would call; this sub-phase's tests call it
    /// directly (see module docs).
    fn record_verified(&self, peer_id: &str, fingerprint: Fingerprint);

    /// Forget any verification for `peer_id`, returning it to
    /// [`TrustLevel::Tofu`]. Needed for the legitimate case of a peer
    /// who really did reinstall and really does have a new identity key
    /// — the user re-verifies out-of-band and the new fingerprint is
    /// recorded. Deliberately explicit: there is no code path anywhere
    /// in this module that clears a verification on its own.
    fn forget_verification(&self, peer_id: &str);
}

/// In-memory trust store — see [`TrustStore`] docs on its limits.
#[derive(Default)]
pub struct InMemoryTrustStore(Mutex<HashMap<String, Fingerprint>>);

impl InMemoryTrustStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TrustStore for InMemoryTrustStore {
    fn verified_fingerprint(&self, peer_id: &str) -> Option<Fingerprint> {
        self.0.lock().unwrap().get(peer_id).cloned()
    }

    fn record_verified(&self, peer_id: &str, fingerprint: Fingerprint) {
        self.0.lock().unwrap().insert(peer_id.to_string(), fingerprint);
    }

    fn forget_verification(&self, peer_id: &str) {
        self.0.lock().unwrap().remove(peer_id);
    }
}

/// The trust level currently established for `peer_id`.
pub fn trust_level(store: &dyn TrustStore, peer_id: &str) -> TrustLevel {
    match store.verified_fingerprint(peer_id) {
        Some(_) => TrustLevel::Verified,
        None => TrustLevel::Tofu,
    }
}

/// Check `remote_identity_key` against whatever was verified for
/// `peer_id`.
///
/// - No verification on file ([`TrustLevel::Tofu`]) → `Ok(())`. This is
///   the unchanged, pre-4.5D behavior; see module docs on why first
///   contact is not, and cannot be, protected by a TOFU scheme.
/// - Verified fingerprint matches → `Ok(())`.
/// - Verified fingerprint does **not** match →
///   [`PardaError::IdentityKeyChangedAfterVerification`], carrying both
///   fingerprints' display digits so a caller can show the user exactly
///   what changed rather than a bare boolean failure.
pub fn check_identity(
    store: &dyn TrustStore,
    peer_id: &str,
    local_identity_key: &IdentityKey,
    remote_identity_key: &IdentityKey,
) -> Result<()> {
    let Some(verified) = store.verified_fingerprint(peer_id) else {
        return Ok(());
    };

    let observed = Fingerprint::compute(local_identity_key, remote_identity_key);
    if observed == verified {
        Ok(())
    } else {
        Err(PardaError::IdentityKeyChangedAfterVerification {
            peer_id: peer_id.to_string(),
            verified_fingerprint: verified.digits(),
            observed_fingerprint: observed.digits(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::IdentityKeyPair;
    use rand::rngs::OsRng;

    fn identity_key() -> IdentityKey {
        *IdentityKeyPair::generate(&mut OsRng).identity_key()
    }

    #[test]
    fn fingerprint_is_symmetric_in_its_arguments() {
        let alice = identity_key();
        let bob = identity_key();
        assert_eq!(
            Fingerprint::compute(&alice, &bob),
            Fingerprint::compute(&bob, &alice),
            "both parties must compute the same fingerprint regardless of perspective"
        );
    }

    #[test]
    fn fingerprint_differs_for_a_different_peer() {
        let alice = identity_key();
        let bob = identity_key();
        let mallory = identity_key();
        assert_ne!(
            Fingerprint::compute(&alice, &bob),
            Fingerprint::compute(&alice, &mallory)
        );
    }

    #[test]
    fn digits_are_twelve_groups_of_five() {
        let fp = Fingerprint::compute(&identity_key(), &identity_key());
        let digits = fp.digits();
        let groups: Vec<&str> = digits.split(' ').collect();
        assert_eq!(groups.len(), 12, "expected 12 groups, got {digits:?}");
        for group in groups {
            assert_eq!(group.len(), 5, "group {group:?} is not 5 digits");
            assert!(group.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn unverified_peer_is_tofu_and_accepts_anything() {
        let store = InMemoryTrustStore::new();
        let alice = identity_key();
        assert_eq!(trust_level(&store, "bob"), TrustLevel::Tofu);
        // Two different remote keys, both accepted — TOFU, unchanged.
        assert!(check_identity(&store, "bob", &alice, &identity_key()).is_ok());
        assert!(check_identity(&store, "bob", &alice, &identity_key()).is_ok());
    }

    #[test]
    fn verified_peer_accepts_the_verified_key_and_rejects_a_substitute() {
        let store = InMemoryTrustStore::new();
        let alice = identity_key();
        let bob = identity_key();
        let mallory = identity_key();

        store.record_verified("bob", Fingerprint::compute(&alice, &bob));
        assert_eq!(trust_level(&store, "bob"), TrustLevel::Verified);

        assert!(check_identity(&store, "bob", &alice, &bob).is_ok());

        let err = check_identity(&store, "bob", &alice, &mallory)
            .expect_err("a substituted identity key must be rejected after verification");
        assert!(matches!(
            err,
            PardaError::IdentityKeyChangedAfterVerification { .. }
        ));
    }

    /// Known-answer test pinning the exact fingerprint construction.
    ///
    /// **This is a cross-implementation contract, not just a regression
    /// guard.** `mobile/android/app/src/main/kotlin/com/parda/app/SignalPlugin.kt`
    /// reimplements this construction in Kotlin (it cannot call into
    /// this crate — the Android client uses libsignal-android, not the
    /// Rust stack), so the two must agree byte-for-byte or two honest
    /// devices would show their users different safety numbers, which is
    /// worse than showing none.
    ///
    /// The vector below was captured from a real cross-implementation
    /// run: these are the two identity keys a Pixel 8 running the
    /// Android client and a `parda-cli peer` published to a live relay,
    /// and the expected digits are what the Android UI actually
    /// displayed. Changing the construction breaks this test, which is
    /// the point — the Kotlin side would need the identical change.
    #[test]
    fn fingerprint_matches_the_android_implementation_known_answer() {
        use base64::Engine as _;
        let decode = |s: &str| {
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .expect("valid base64 test vector")
        };

        let a = IdentityKey::decode(&decode("Ba/PJNiocgVy1eIXNPIkzwFo1vz6wAEhtGrNOTNBWAoj"))
            .expect("valid identity key");
        let b = IdentityKey::decode(&decode("BcBSW4zuZfpaoAekU3rI4fuOcxvFAT+mWxI2V93zjctM"))
            .expect("valid identity key");

        const EXPECTED: &str =
            "03629 84610 48359 95354 16784 69458 58902 57435 92969 05337 94466 27238";

        assert_eq!(Fingerprint::compute(&a, &b).digits(), EXPECTED);
        // Symmetric in practice, not just in principle.
        assert_eq!(Fingerprint::compute(&b, &a).digits(), EXPECTED);
    }

    #[test]
    fn forgetting_a_verification_returns_the_peer_to_tofu() {
        let store = InMemoryTrustStore::new();
        let alice = identity_key();
        let bob = identity_key();

        store.record_verified("bob", Fingerprint::compute(&alice, &bob));
        store.forget_verification("bob");

        assert_eq!(trust_level(&store, "bob"), TrustLevel::Tofu);
        // A genuinely-new key is accepted again, which is the point of
        // the legitimate-reinstall path — see TrustStore docs.
        assert!(check_identity(&store, "bob", &alice, &identity_key()).is_ok());
    }
}
