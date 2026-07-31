//! # PARDA Protocol — Sealed Sender Tests (Sub-Phase 2A)
//!
//! Covers:
//! 1. Round trip: sealed message decrypts correctly and authenticates the
//!    real sender identity via the embedded certificate.
//! 2. The wire envelope never contains the sender's identity in plaintext.
//! 3. Adversarial: a certificate validated against the wrong trust root
//!    is rejected.
//! 4. Adversarial: an expired certificate is rejected.
//! 5. Adversarial: a certificate forged by an attacker's own (untrusted)
//!    certificate authority — claiming someone else's `sender_uuid` — is
//!    rejected when checked against the real trust root.
//! 6. `decrypt()` (the non-sealed path) refuses sealed-sender envelopes
//!    explicitly rather than mis-parsing them.
//!
//! Mirrors the adversarial-test convention established in
//! `protocol/tests/crypto_tests.rs` (e.g. `test_forward_secrecy_stale_ciphertext_rejected`).

use std::time::Duration;

use libsignal_protocol::IdentityKeyPair;
use parda_protocol::{
    envelope::EnvelopeType,
    error::PardaError,
    identity::LocalIdentity,
    sealed_sender::CertificateAuthority,
    session::SessionManager,
    store::InMemorySignalProtocolStore,
};
use rand::rngs::OsRng;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Build a fully initialised [`SessionManager`] plus its [`LocalIdentity`],
/// with prekeys seeded into its own store so it can act as the responder
/// side of an X3DH handshake.
fn make_manager_with_identity(name: &str, reg_id: u32) -> (SessionManager, LocalIdentity) {
    let identity = LocalIdentity::generate(reg_id).expect("generate identity");
    let mut store = InMemorySignalProtocolStore::new(identity.identity_key_pair, reg_id);
    store.store_prekey_batch(&identity.one_time_prekeys).unwrap();
    store.store_signed_prekey_record(&identity.signed_prekey).unwrap();
    let addr = libsignal_protocol::ProtocolAddress::new(name.to_string(), 1.into());
    (SessionManager::new(addr, store), identity)
}

fn device_id() -> libsignal_protocol::DeviceId {
    1u32.into()
}

// ─── Test 1 + 2: round trip, authentication, and wire secrecy ────────────────

#[tokio::test]
async fn test_sealed_sender_roundtrip_authenticates_real_sender() {
    let (mut alice, alice_identity) = make_manager_with_identity("alice", 1);
    let (mut bob, bob_identity) = make_manager_with_identity("bob", 2);
    let bob_addr = bob.local_address.clone();

    // Alice establishes a session with Bob via X3DH, same as Phase 1.
    let bob_bundle = bob_identity.build_prekey_bundle().unwrap();
    alice.initiate_session(&bob_addr, &bob_bundle).await.unwrap();

    // A trusted CA (in Phase 2, hosted by parda-relay) issues Alice a
    // sender certificate binding her identity key to her name.
    let ca = CertificateAuthority::new().expect("CA construction");
    let alice_cert = ca
        .issue_sender_certificate(
            "alice",
            *alice_identity.identity_key_pair.public_key(),
            device_id(),
            Duration::from_secs(3600),
        )
        .expect("issue sender cert");

    let envelope = alice
        .encrypt_sealed(&bob_addr, b"the mission is a go", &alice_cert)
        .await
        .expect("sealed encrypt");

    assert_eq!(envelope.envelope_type, EnvelopeType::SealedSender);
    assert!(envelope.sealed_sender);
    assert_eq!(
        envelope.sender_id, "",
        "sender_id must never be populated on a sealed-sender envelope"
    );

    // The wire JSON itself must not mention Alice anywhere.
    let json = serde_json::to_string(&envelope).unwrap();
    assert!(
        !json.contains("alice"),
        "sealed-sender envelope JSON leaked the sender name: {json}"
    );

    // Bob decrypts and, only now, learns who really sent it — authenticated
    // via the certificate, not taken from any plaintext field.
    let result = bob
        .decrypt_sealed(&envelope, &ca.trust_root_public_key(), "bob", device_id())
        .await
        .expect("sealed decrypt");

    assert_eq!(result.plaintext, b"the mission is a go");
    assert_eq!(result.sender_uuid, "alice");
}

// ─── Test 3: wrong trust root rejected ────────────────────────────────────────

#[tokio::test]
async fn test_sealed_sender_rejects_wrong_trust_root() {
    let (mut alice, alice_identity) = make_manager_with_identity("alice", 1);
    let (mut bob, bob_identity) = make_manager_with_identity("bob", 2);
    let bob_addr = bob.local_address.clone();

    let bob_bundle = bob_identity.build_prekey_bundle().unwrap();
    alice.initiate_session(&bob_addr, &bob_bundle).await.unwrap();

    let real_ca = CertificateAuthority::new().unwrap();
    let alice_cert = real_ca
        .issue_sender_certificate(
            "alice",
            *alice_identity.identity_key_pair.public_key(),
            device_id(),
            Duration::from_secs(3600),
        )
        .unwrap();

    let envelope = alice
        .encrypt_sealed(&bob_addr, b"secret", &alice_cert)
        .await
        .unwrap();

    // Bob is configured with a *different* CA's trust root — e.g. he's
    // talking to the wrong network, or an attacker fed him a bogus root.
    let unrelated_ca = CertificateAuthority::new().unwrap();
    let result = bob
        .decrypt_sealed(
            &envelope,
            &unrelated_ca.trust_root_public_key(),
            "bob",
            device_id(),
        )
        .await;

    assert!(
        result.is_err(),
        "decryption must fail when validated against the wrong trust root"
    );
}

// ─── Test 4: expired certificate rejected ────────────────────────────────────

#[tokio::test]
async fn test_sealed_sender_rejects_expired_certificate() {
    let (mut alice, alice_identity) = make_manager_with_identity("alice", 1);
    let (mut bob, bob_identity) = make_manager_with_identity("bob", 2);
    let bob_addr = bob.local_address.clone();

    let bob_bundle = bob_identity.build_prekey_bundle().unwrap();
    alice.initiate_session(&bob_addr, &bob_bundle).await.unwrap();

    let ca = CertificateAuthority::new().unwrap();
    // Zero-TTL certificate: expired by the time anyone checks it.
    let alice_cert = ca
        .issue_sender_certificate(
            "alice",
            *alice_identity.identity_key_pair.public_key(),
            device_id(),
            Duration::from_secs(0),
        )
        .unwrap();

    let envelope = alice
        .encrypt_sealed(&bob_addr, b"secret", &alice_cert)
        .await
        .unwrap();

    // Give the expiration timestamp a moment to be strictly in the past.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let result = bob
        .decrypt_sealed(&envelope, &ca.trust_root_public_key(), "bob", device_id())
        .await;

    assert!(result.is_err(), "an expired sender certificate must be rejected");
}

// ─── Test 5: forged certificate (untrusted CA impersonating a real user) ─────

#[tokio::test]
async fn test_sealed_sender_rejects_certificate_from_untrusted_ca_impersonating_victim() {
    let (mut attacker, _attacker_identity) = make_manager_with_identity("attacker", 1);
    let (mut bob, bob_identity) = make_manager_with_identity("bob", 2);
    let bob_addr = bob.local_address.clone();

    // The attacker establishes their own perfectly valid session with Bob —
    // sealed sender does not stop an attacker from talking to Bob under
    // their own identity. What it must stop is the attacker *claiming to be
    // someone else*.
    let bob_bundle = bob_identity.build_prekey_bundle().unwrap();
    attacker.initiate_session(&bob_addr, &bob_bundle).await.unwrap();

    // Attacker runs their own rogue CA (does not have the real network's
    // trust root private key) and mints a certificate claiming to be
    // "alice", bound to the attacker's own identity key.
    let attacker_ikp = IdentityKeyPair::generate(&mut OsRng);
    let rogue_ca = CertificateAuthority::new().unwrap();
    let forged_cert = rogue_ca
        .issue_sender_certificate(
            "alice",
            *attacker_ikp.public_key(),
            device_id(),
            Duration::from_secs(3600),
        )
        .unwrap();

    let envelope = attacker
        .encrypt_sealed(&bob_addr, b"trust me, it's alice", &forged_cert)
        .await
        .unwrap();

    // Bob only trusts the real network's CA.
    let real_ca = CertificateAuthority::new().unwrap();
    let result = bob
        .decrypt_sealed(&envelope, &real_ca.trust_root_public_key(), "bob", device_id())
        .await;

    assert!(
        result.is_err(),
        "a certificate signed by an untrusted CA must not authenticate a sender identity"
    );
}

// ─── Test 6: decrypt() refuses sealed-sender envelopes ───────────────────────

#[tokio::test]
async fn test_plain_decrypt_refuses_sealed_sender_envelope() {
    let (mut alice, alice_identity) = make_manager_with_identity("alice", 1);
    let (mut bob, bob_identity) = make_manager_with_identity("bob", 2);
    let bob_addr = bob.local_address.clone();

    let bob_bundle = bob_identity.build_prekey_bundle().unwrap();
    alice.initiate_session(&bob_addr, &bob_bundle).await.unwrap();

    let ca = CertificateAuthority::new().unwrap();
    let alice_cert = ca
        .issue_sender_certificate(
            "alice",
            *alice_identity.identity_key_pair.public_key(),
            device_id(),
            Duration::from_secs(3600),
        )
        .unwrap();

    let envelope = alice
        .encrypt_sealed(&bob_addr, b"secret", &alice_cert)
        .await
        .unwrap();

    let result = bob.decrypt(&envelope).await;
    assert!(matches!(result, Err(PardaError::MalformedSealedSender(_))));
}
