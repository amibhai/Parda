//! # PARDA Protocol — Trust Bootstrapping Adversarial Tests (Sub-Phase 4.5D)
//!
//! The named adversarial proof for `protocol/src/trust.rs`. **Read
//! `docs/phase4.5d-trust-bootstrapping-design.md` first** — it states
//! precisely what this mechanism does and does not achieve, and these
//! tests are written to demonstrate *both halves* of that claim, not
//! only the favourable one.
//!
//! The active MITM simulated here is the standard one: Mallory
//! intercepts the prekey bundle Bob published and substitutes her own
//! identity key, so Alice unknowingly establishes a session with
//! Mallory believing it is Bob.
//!
//! | Test | Scenario | Expected — and why |
//! |------|----------|--------------------|
//! | 1 | MITM at **first contact**, no verification ever performed | **Succeeds.** No regression, and no false claim of protection: this is the fundamental limit of *any* trust-on-first-use scheme, Signal's included. Asserted explicitly so a future change that silently weakened or "fixed" this would be caught, and so the documentation's honesty is itself under test. |
//! | 2 | MITM **after** out-of-band verification | **Detected**, `PardaError::IdentityKeyChangedAfterVerification`. |
//! | 3 | Verified peer, genuine key | Proceeds normally — verification must not break the honest path. |
//! | 4 | Rejected bundle leaves no session state | Fail-closed: a detected MITM must not half-establish a session. |
//! | 5 | Sealed-sender path, post-verification substitution | Detected, via `decrypt_sealed_verified`. |
//! | 6 | Legitimate reinstall after `forget_verification` | Accepted — the escape hatch works, and is explicit. |

use std::time::Duration;

use parda_protocol::{
    error::PardaError,
    identity::LocalIdentity,
    sealed_sender::CertificateAuthority,
    session::SessionManager,
    store::InMemorySignalProtocolStore,
    trust::{check_identity, Fingerprint, InMemoryTrustStore, TrustLevel, TrustStore, trust_level},
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Mirrors `sealed_sender_tests.rs`'s helper of the same shape — a fully
/// initialised manager whose store holds its own prekeys, so it can act
/// as either side of an X3DH handshake.
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

/// The fingerprint Alice and Bob would compute if they compared in
/// person — i.e. over the *genuine* identity keys, with no MITM.
fn genuine_fingerprint(alice: &LocalIdentity, bob: &LocalIdentity) -> Fingerprint {
    Fingerprint::compute(
        alice.identity_key_pair.identity_key(),
        bob.identity_key_pair.identity_key(),
    )
}

// ─── Test 1: the honest limitation — MITM at first contact succeeds ──────────

/// **This test asserts a weakness, deliberately.** A MITM present before
/// any out-of-band comparison has happened is *not* detected — TOFU
/// pins whatever arrived first, attacker's key included. The project's
/// docs say exactly this; this test holds those docs to it, so the
/// claim can't quietly drift into something stronger than what the code
/// does.
#[tokio::test]
async fn test_mitm_at_first_contact_succeeds_when_never_verified() {
    let (mut alice, _alice_identity) = make_manager_with_identity("alice", 1);
    let (_bob, _bob_identity) = make_manager_with_identity("bob", 2);
    let (_mallory, mallory_identity) = make_manager_with_identity("mallory", 3);

    let trust_store = InMemoryTrustStore::new();
    assert_eq!(
        trust_level(&trust_store, "bob"),
        TrustLevel::Tofu,
        "precondition: no verification has been performed for bob"
    );

    // Mallory substitutes her own bundle for Bob's in transit. Alice
    // believes she is talking to "bob".
    let bob_addr = libsignal_protocol::ProtocolAddress::new("bob".to_string(), 1.into());
    let mallory_bundle = mallory_identity.build_prekey_bundle().unwrap();

    let result = alice
        .initiate_session_verified(&bob_addr, &mallory_bundle, &trust_store, "bob")
        .await;

    assert!(
        result.is_ok(),
        "an unverified peer must behave exactly as pre-4.5D TOFU — first contact is \
         not protected, and this project does not claim it is (see \
         docs/phase4.5d-trust-bootstrapping-design.md §4)"
    );
}

// ─── Test 2: the actual defence — MITM after verification is detected ────────

#[tokio::test]
async fn test_mitm_after_verification_is_detected_and_fails_loud() {
    let (mut alice, alice_identity) = make_manager_with_identity("alice", 1);
    let (_bob, bob_identity) = make_manager_with_identity("bob", 2);
    let (_mallory, mallory_identity) = make_manager_with_identity("mallory", 3);

    // Alice and Bob met in person and compared fingerprints.
    let trust_store = InMemoryTrustStore::new();
    trust_store.record_verified("bob", genuine_fingerprint(&alice_identity, &bob_identity));
    assert_eq!(trust_level(&trust_store, "bob"), TrustLevel::Verified);

    // Later, Mallory substitutes her identity key into Bob's bundle.
    let bob_addr = libsignal_protocol::ProtocolAddress::new("bob".to_string(), 1.into());
    let mallory_bundle = mallory_identity.build_prekey_bundle().unwrap();

    let err = alice
        .initiate_session_verified(&bob_addr, &mallory_bundle, &trust_store, "bob")
        .await
        .expect_err("a substituted identity key must be rejected after verification");

    match err {
        PardaError::IdentityKeyChangedAfterVerification {
            peer_id,
            verified_fingerprint,
            observed_fingerprint,
        } => {
            assert_eq!(peer_id, "bob");
            assert_ne!(
                verified_fingerprint, observed_fingerprint,
                "the error must carry two genuinely different fingerprints"
            );
        }
        other => panic!(
            "expected IdentityKeyChangedAfterVerification (distinct from libsignal's \
             generic UntrustedIdentity — see error.rs), got {other:?}"
        ),
    }
}

// ─── Test 3: verification must not break the honest path ─────────────────────

#[tokio::test]
async fn test_verified_peer_with_genuine_key_proceeds_normally() {
    let (mut alice, alice_identity) = make_manager_with_identity("alice", 1);
    let (_bob, bob_identity) = make_manager_with_identity("bob", 2);

    let trust_store = InMemoryTrustStore::new();
    trust_store.record_verified("bob", genuine_fingerprint(&alice_identity, &bob_identity));

    let bob_addr = libsignal_protocol::ProtocolAddress::new("bob".to_string(), 1.into());
    let bob_bundle = bob_identity.build_prekey_bundle().unwrap();

    alice
        .initiate_session_verified(&bob_addr, &bob_bundle, &trust_store, "bob")
        .await
        .expect("the genuine peer's own key must still be accepted after verification");

    // And the session is genuinely usable, not merely "not an error".
    let envelope = alice
        .encrypt(&bob_addr, b"hello bob")
        .await
        .expect("encrypt after a verified session initiation");
    assert!(!envelope.ciphertext.is_empty());
}

// ─── Test 4: fail-closed — a rejected bundle establishes nothing ─────────────

/// A detected MITM must not leave half-built session state behind: the
/// same "never a partial write" discipline `client-store` already
/// applies on its refusal path.
#[tokio::test]
async fn test_rejected_bundle_leaves_no_session_state() {
    let (mut alice, alice_identity) = make_manager_with_identity("alice", 1);
    let (_bob, bob_identity) = make_manager_with_identity("bob", 2);
    let (_mallory, mallory_identity) = make_manager_with_identity("mallory", 3);

    let trust_store = InMemoryTrustStore::new();
    trust_store.record_verified("bob", genuine_fingerprint(&alice_identity, &bob_identity));

    let bob_addr = libsignal_protocol::ProtocolAddress::new("bob".to_string(), 1.into());
    let mallory_bundle = mallory_identity.build_prekey_bundle().unwrap();

    assert!(alice
        .initiate_session_verified(&bob_addr, &mallory_bundle, &trust_store, "bob")
        .await
        .is_err());

    assert!(
        !alice.store.has_conversation_state(&bob_addr),
        "a rejected bundle must leave no session or trusted-identity record behind"
    );

    // Encrypting to that address must therefore fail too — the
    // conversation genuinely does not exist, rather than existing in
    // some partially-initialised state.
    assert!(
        alice.encrypt(&bob_addr, b"should not send").await.is_err(),
        "no usable session may exist after a rejected bundle"
    );
}

// ─── Test 5: the sealed-sender enforcement point ─────────────────────────────

/// Sealed sender is the second of the three TOFU points §1 of the design
/// note names. The check necessarily runs *after* decryption (the sender's
/// identity is not authenticated until the certificate chain validates)
/// but *before* the plaintext is returned — see
/// `SessionManager::decrypt_sealed_verified`'s docs.
#[tokio::test]
async fn test_sealed_sender_substitution_after_verification_is_detected() {
    let (mut alice, alice_identity) = make_manager_with_identity("alice", 1);
    let (mut bob, bob_identity) = make_manager_with_identity("bob", 2);
    let (_mallory, mallory_identity) = make_manager_with_identity("mallory", 3);
    let bob_addr = bob.local_address.clone();

    // Alice → Bob session, and a CA both trust.
    let bob_bundle = bob_identity.build_prekey_bundle().unwrap();
    alice.initiate_session(&bob_addr, &bob_bundle).await.unwrap();

    let ca = CertificateAuthority::new().expect("CA construction");
    let alice_cert = ca
        .issue_sender_certificate(
            "alice",
            *alice_identity.identity_key_pair.public_key(),
            device_id(),
            Duration::from_secs(3600),
        )
        .expect("issue alice's sender certificate");

    let sealed = alice
        .encrypt_sealed(&bob_addr, b"hello from alice", &alice_cert)
        .await
        .expect("sealed-sender encrypt");

    // Bob has verified a fingerprint for "alice" — but against
    // *Mallory's* key, standing in for the case where what Bob
    // out-of-band-verified and what is now arriving disagree.
    let trust_store = InMemoryTrustStore::new();
    trust_store.record_verified(
        "alice",
        Fingerprint::compute(
            bob_identity.identity_key_pair.identity_key(),
            mallory_identity.identity_key_pair.identity_key(),
        ),
    );

    let err = bob
        .decrypt_sealed_verified(
            &sealed,
            &ca.trust_root_public_key(),
            "bob",
            device_id(),
            &trust_store,
            "alice",
        )
        .await
        .expect_err("an identity mismatch against the verified fingerprint must be rejected");

    assert!(
        matches!(err, PardaError::IdentityKeyChangedAfterVerification { .. }),
        "expected IdentityKeyChangedAfterVerification, got {err:?}"
    );
}

/// The same sealed-sender path must still return the plaintext when the
/// verified fingerprint genuinely matches — otherwise test 5 would pass
/// for the wrong reason (e.g. the wrapper failing for everyone).
#[tokio::test]
async fn test_sealed_sender_with_matching_verified_fingerprint_returns_plaintext() {
    let (mut alice, alice_identity) = make_manager_with_identity("alice", 1);
    let (mut bob, bob_identity) = make_manager_with_identity("bob", 2);
    let bob_addr = bob.local_address.clone();

    let bob_bundle = bob_identity.build_prekey_bundle().unwrap();
    alice.initiate_session(&bob_addr, &bob_bundle).await.unwrap();

    let ca = CertificateAuthority::new().expect("CA construction");
    let alice_cert = ca
        .issue_sender_certificate(
            "alice",
            *alice_identity.identity_key_pair.public_key(),
            device_id(),
            Duration::from_secs(3600),
        )
        .expect("issue alice's sender certificate");

    let sealed = alice
        .encrypt_sealed(&bob_addr, b"hello from alice", &alice_cert)
        .await
        .expect("sealed-sender encrypt");

    let trust_store = InMemoryTrustStore::new();
    trust_store.record_verified("alice", genuine_fingerprint(&bob_identity, &alice_identity));

    let result = bob
        .decrypt_sealed_verified(
            &sealed,
            &ca.trust_root_public_key(),
            "bob",
            device_id(),
            &trust_store,
            "alice",
        )
        .await
        .expect("a matching verified fingerprint must not block the honest path");

    assert_eq!(result.plaintext, b"hello from alice");
    assert_eq!(result.sender_uuid, "alice");
}

// ─── Test 6: the legitimate-reinstall escape hatch ───────────────────────────

/// A peer who genuinely reinstalled really does have a new identity key.
/// The user re-verifies out-of-band and `forget_verification` clears the
/// stale entry — this must work, and must require an explicit call, not
/// happen on its own anywhere in the module.
#[tokio::test]
async fn test_forget_verification_allows_a_genuine_key_change() {
    let (mut alice, alice_identity) = make_manager_with_identity("alice", 1);
    let (_bob_old, bob_old_identity) = make_manager_with_identity("bob", 2);
    let (_bob_new, bob_new_identity) = make_manager_with_identity("bob", 4);

    let trust_store = InMemoryTrustStore::new();
    trust_store.record_verified("bob", genuine_fingerprint(&alice_identity, &bob_old_identity));

    let bob_addr = libsignal_protocol::ProtocolAddress::new("bob".to_string(), 1.into());
    let bob_new_bundle = bob_new_identity.build_prekey_bundle().unwrap();

    // Bob's post-reinstall key is rejected while the old verification stands.
    assert!(alice
        .initiate_session_verified(&bob_addr, &bob_new_bundle, &trust_store, "bob")
        .await
        .is_err());

    // The user re-verifies in person and records the new fingerprint.
    trust_store.forget_verification("bob");
    trust_store.record_verified("bob", genuine_fingerprint(&alice_identity, &bob_new_identity));

    alice
        .initiate_session_verified(&bob_addr, &bob_new_bundle, &trust_store, "bob")
        .await
        .expect("a re-verified key must be accepted");
}

// ─── Direct check_identity coverage for the mix-topology hook ────────────────

/// The design note's §3 third point: mix-node trust is a *data-model
/// hook plus documented workflow*, not enforcement. `TrustStore` is keyed
/// by an opaque `peer_id`, so the same primitives work unchanged for
/// "verify mix node X's key" — demonstrated here directly, since no
/// mixnode call site invokes it in this sub-phase and it would otherwise
/// be an untested claim.
#[test]
fn test_check_identity_works_for_an_arbitrary_peer_id_such_as_a_mix_node() {
    let local = LocalIdentity::generate(1).unwrap();
    let node = LocalIdentity::generate(2).unwrap();
    let impostor = LocalIdentity::generate(3).unwrap();

    let store = InMemoryTrustStore::new();
    store.record_verified(
        "mixnode://alpha",
        Fingerprint::compute(
            local.identity_key_pair.identity_key(),
            node.identity_key_pair.identity_key(),
        ),
    );

    assert!(check_identity(
        &store,
        "mixnode://alpha",
        local.identity_key_pair.identity_key(),
        node.identity_key_pair.identity_key(),
    )
    .is_ok());

    assert!(matches!(
        check_identity(
            &store,
            "mixnode://alpha",
            local.identity_key_pair.identity_key(),
            impostor.identity_key_pair.identity_key(),
        ),
        Err(PardaError::IdentityKeyChangedAfterVerification { .. })
    ));
}
