//! # PARDA Protocol — Cryptographic Unit Tests
//!
//! Covers:
//! 1. Key generation produces valid key pairs
//! 2. X3DH handshake: Alice initiates a session using Bob's prekey bundle
//! 3. Double Ratchet round-trip: encrypt on Alice → decrypt on Bob
//! 4. Forward secrecy: session keys after ratchet step N cannot decrypt
//!    messages from step N-1 (old keys are deleted)
//! 5. Prekey bundle construction from LocalIdentity
//! 6. Multi-message round-trip with ratchet advancement
//!
//! All tests use the `InMemorySignalProtocolStore` — no network, no hardware.

use libsignal_protocol::{GenericSignedPreKey, IdentityKeyPair, ProtocolAddress};
use parda_protocol::{
    envelope::EnvelopeType,
    identity::LocalIdentity,
    session::SessionManager,
    store::InMemorySignalProtocolStore,
};
use rand::rngs::OsRng;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Build a fully initialised [`SessionManager`] for a named user.
fn make_manager(name: &str, reg_id: u32) -> SessionManager {
    let mut rng = OsRng;
    let ikp = IdentityKeyPair::generate(&mut rng);
    let store = InMemorySignalProtocolStore::new(ikp, reg_id);
    let addr = ProtocolAddress::new(name.to_string(), 1.into());
    SessionManager::new(addr, store)
}

/// Build a [`LocalIdentity`] + seed its keys into a fresh store.
fn make_identity_and_store(
    name: &str,
    reg_id: u32,
) -> (LocalIdentity, InMemorySignalProtocolStore, ProtocolAddress) {
    let identity = LocalIdentity::generate(reg_id).expect("LocalIdentity::generate failed");
    let mut store = InMemorySignalProtocolStore::new(
        identity.identity_key_pair,
        identity.registration_id,
    );
    store
        .store_prekey_batch(&identity.one_time_prekeys)
        .expect("store prekeys");
    store
        .store_signed_prekey_record(&identity.signed_prekey)
        .expect("store signed prekey");
    let addr = ProtocolAddress::new(name.to_string(), 1.into());
    (identity, store, addr)
}

// ─── Test 1: Key generation ──────────────────────────────────────────────────

#[test]
fn test_identity_key_generation() {
    let identity = LocalIdentity::generate(1).expect("generate identity");

    // Identity key pair must be non-zero
    assert_ne!(
        identity.identity_key_pair.public_key().serialize().to_vec(),
        vec![0u8; 33]
    );
    // Signed prekey must have correct ID
    assert_eq!(
        u32::from(identity.signed_prekey.id().unwrap()),
        1u32
    );
    // Must have produced ONE_TIME_PREKEY_BATCH prekeys
    assert_eq!(
        identity.one_time_prekeys.len(),
        parda_protocol::identity::ONE_TIME_PREKEY_BATCH as usize
    );
    // All prekey IDs should be unique
    let ids: std::collections::HashSet<u32> = identity
        .one_time_prekeys
        .iter()
        .map(|pk| u32::from(pk.id().unwrap()))
        .collect();
    assert_eq!(ids.len(), identity.one_time_prekeys.len());
}

#[test]
fn test_signed_prekey_signature_is_valid() {
    // The signed prekey signature must verify against the identity public key.
    // libsignal validates this internally during process_prekey_bundle;
    // here we confirm the LocalIdentity constructor sets it correctly.
    let identity = LocalIdentity::generate(42).unwrap();
    let sig = identity.signed_prekey.signature().unwrap();
    let pub_bytes = identity.signed_prekey.public_key().unwrap().serialize();
    let verified = identity
        .identity_key_pair
        .public_key()
        .verify_signature(&pub_bytes, &sig);
    assert!(verified, "signed prekey signature must verify");
}

// ─── Test 2: Prekey bundle construction ──────────────────────────────────────

#[test]
fn test_prekey_bundle_construction() {
    let identity = LocalIdentity::generate(7).unwrap();
    let bundle = identity.build_prekey_bundle();
    assert!(bundle.is_ok(), "build_prekey_bundle must succeed");
    let bundle = bundle.unwrap();
    // Bundle registration ID must match
    assert_eq!(bundle.registration_id().unwrap(), 7);
}

// ─── Test 3: X3DH session initiation ────────────────────────────────────────

#[tokio::test]
async fn test_x3dh_session_initiation() {
    let (bob_identity, _bob_store, bob_addr) = make_identity_and_store("bob", 2);
    let alice_ikp = IdentityKeyPair::generate(&mut OsRng);
    let alice_store = InMemorySignalProtocolStore::new(alice_ikp, 1);
    let alice_addr = ProtocolAddress::new("alice".to_string(), 1.into());
    let mut alice = SessionManager::new(alice_addr, alice_store);

    let bundle = bob_identity
        .build_prekey_bundle()
        .expect("build prekey bundle");

    // Alice initiates — this performs X3DH and stores a session record.
    let result = alice.initiate_session(&bob_addr, &bundle).await;
    assert!(
        result.is_ok(),
        "X3DH session initiation must succeed: {:?}",
        result
    );
}

// ─── Test 4: Double Ratchet round-trip ──────────────────────────────────────

#[tokio::test]
async fn test_double_ratchet_encrypt_decrypt_roundtrip() {
    let (bob_identity, bob_store, bob_addr) = make_identity_and_store("bob", 2);
    let alice_ikp = IdentityKeyPair::generate(&mut OsRng);
    let alice_store = InMemorySignalProtocolStore::new(alice_ikp, 1);
    let alice_addr = ProtocolAddress::new("alice".to_string(), 1.into());
    let mut alice = SessionManager::new(alice_addr.clone(), alice_store);
    let mut bob = SessionManager::new(bob_addr.clone(), bob_store);

    // Seed Bob's store with his own signed prekey and one-time prekeys.
    bob.store
        .store_prekey_batch(&bob_identity.one_time_prekeys)
        .unwrap();
    bob.store
        .store_signed_prekey_record(&bob_identity.signed_prekey)
        .unwrap();

    let bundle = bob_identity.build_prekey_bundle().unwrap();

    // Alice initiates session with Bob.
    alice.initiate_session(&bob_addr, &bundle).await.unwrap();

    // Alice encrypts "hello, bob".
    let plaintext = b"hello, bob";
    let envelope = alice.encrypt(&bob_addr, plaintext).await.unwrap();

    // Envelope type must be PreKey (first message).
    assert_eq!(envelope.envelope_type, EnvelopeType::PreKey);

    // Bob decrypts.
    let decrypted = bob.decrypt(&envelope).await.unwrap();
    assert_eq!(decrypted, plaintext, "decrypted plaintext must match");
}

// ─── Test 5: Multi-message ratchet advancement ───────────────────────────────

#[tokio::test]
async fn test_multi_message_ratchet_advancement() {
    let (bob_identity, bob_store, bob_addr) = make_identity_and_store("bob", 20);
    let alice_ikp = IdentityKeyPair::generate(&mut OsRng);
    let alice_store = InMemorySignalProtocolStore::new(alice_ikp, 10);
    let alice_addr = ProtocolAddress::new("alice".to_string(), 1.into());
    let mut alice = SessionManager::new(alice_addr.clone(), alice_store);
    let mut bob = SessionManager::new(bob_addr.clone(), bob_store);

    bob.store.store_prekey_batch(&bob_identity.one_time_prekeys).unwrap();
    bob.store.store_signed_prekey_record(&bob_identity.signed_prekey).unwrap();

    let bundle = bob_identity.build_prekey_bundle().unwrap();
    alice.initiate_session(&bob_addr, &bundle).await.unwrap();

    let messages = ["msg_1", "msg_2", "msg_3", "msg_4", "msg_5"];
    for (i, &msg) in messages.iter().enumerate() {
        let envelope = alice.encrypt(&bob_addr, msg.as_bytes()).await.unwrap();

        // Per the Signal Protocol spec, Alice keeps wrapping outgoing messages
        // as PreKeySignalMessage until she has processed a reply from Bob on
        // this session (libsignal clears `unacknowledged_pre_key_message`
        // only on the receiving side of a session). A one-way message stream
        // therefore stays PreKey the whole way; only after Bob acks does
        // Alice's session drop back to plain Ratchet messages.
        if i == 0 {
            assert_eq!(envelope.envelope_type, EnvelopeType::PreKey);
        } else {
            assert_eq!(envelope.envelope_type, EnvelopeType::Ratchet);
        }

        let decrypted = bob.decrypt(&envelope).await.unwrap();
        assert_eq!(decrypted, msg.as_bytes(), "message {} mismatch", i);

        if i == 0 {
            // Bob acks so Alice's session clears its unacknowledged-prekey
            // state, matching a real bidirectional conversation.
            let ack = bob.encrypt(&alice_addr, b"ack").await.unwrap();
            let ack_plain = alice.decrypt(&ack).await.unwrap();
            assert_eq!(ack_plain, b"ack");
        }
    }
}

// ─── Test 6: Forward secrecy ──────────────────────────────────────────────────
//
// Property: after the ratchet advances, old message keys no longer exist.
// We verify this by replaying a stale ciphertext after the ratchet has
// moved forward — libsignal must reject it (duplicate / old message).

#[tokio::test]
async fn test_forward_secrecy_stale_ciphertext_rejected() {
    let (bob_identity, bob_store, bob_addr) = make_identity_and_store("bob", 30);
    let alice_ikp = IdentityKeyPair::generate(&mut OsRng);
    let alice_store = InMemorySignalProtocolStore::new(alice_ikp, 31);
    let alice_addr = ProtocolAddress::new("alice".to_string(), 1.into());
    let mut alice = SessionManager::new(alice_addr.clone(), alice_store);
    let mut bob = SessionManager::new(bob_addr.clone(), bob_store);

    bob.store.store_prekey_batch(&bob_identity.one_time_prekeys).unwrap();
    bob.store.store_signed_prekey_record(&bob_identity.signed_prekey).unwrap();

    let bundle = bob_identity.build_prekey_bundle().unwrap();
    alice.initiate_session(&bob_addr, &bundle).await.unwrap();

    // Capture message 1 envelope before Bob processes it.
    let envelope_msg1 = alice.encrypt(&bob_addr, b"message one").await.unwrap();

    // Advance the ratchet: Bob decrypts message 1.
    let _ = bob.decrypt(&envelope_msg1).await.unwrap();

    // Alice sends message 2 — ratchet advances on both sides.
    let envelope_msg2 = alice.encrypt(&bob_addr, b"message two").await.unwrap();
    let _ = bob.decrypt(&envelope_msg2).await.unwrap();

    // Replay envelope_msg1 — must be rejected because the prekey has been
    // consumed and the one-time prekey no longer exists in Bob's store.
    let replay_result = bob.decrypt(&envelope_msg1).await;
    assert!(
        replay_result.is_err(),
        "replaying a stale PreKey envelope must be rejected after ratchet advancement"
    );
}

// ─── Test 7: Envelope serialisation round-trip ───────────────────────────────

#[test]
fn test_envelope_json_roundtrip() {
    use parda_protocol::envelope::{EnvelopeType, MessageEnvelope};

    let envelope = MessageEnvelope {
        sender_id: "alice".into(),
        recipient_id: "bob".into(),
        ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
        envelope_type: EnvelopeType::PreKey,
        timestamp_ms: 1_700_000_000_000,
        version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
        sealed_sender: false,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
    };

    let json = serde_json::to_string(&envelope).expect("serialise envelope");
    let decoded: MessageEnvelope =
        serde_json::from_str(&json).expect("deserialise envelope");

    assert_eq!(decoded.sender_id, envelope.sender_id);
    assert_eq!(decoded.recipient_id, envelope.recipient_id);
    assert_eq!(decoded.ciphertext, envelope.ciphertext);
    assert_eq!(decoded.envelope_type, envelope.envelope_type);
    assert_eq!(decoded.timestamp_ms, envelope.timestamp_ms);
    assert_eq!(decoded.version, envelope.version);
    assert!(!decoded.sealed_sender);
    assert!(decoded.routing_hint.is_none());
    assert!(decoded.self_destruct_at.is_none());
}

#[test]
fn test_envelope_missing_version_defaults_to_v1() {
    // Phase 1 clients never wrote a `version` field. A Phase 2 receiver must
    // still be able to parse that JSON and treat it as version 1, rather
    // than failing to deserialise legacy data.
    use parda_protocol::envelope::{EnvelopeType, MessageEnvelope, ENVELOPE_VERSION_V2, ENVELOPE_VERSION_V1};

    let modern = MessageEnvelope {
        sender_id: "alice".into(),
        recipient_id: "bob".into(),
        ciphertext: vec![0xAA],
        envelope_type: EnvelopeType::PreKey,
        timestamp_ms: 1_700_000_000_000,
        version: ENVELOPE_VERSION_V2,
        sealed_sender: false,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
    };
    let mut value = serde_json::to_value(&modern).expect("serialise envelope");
    value
        .as_object_mut()
        .expect("envelope serialises as a JSON object")
        .remove("version");

    let decoded: MessageEnvelope =
        serde_json::from_value(value).expect("legacy envelope without `version` must parse");
    assert_eq!(decoded.version, ENVELOPE_VERSION_V1);
    assert_eq!(decoded.envelope_type, EnvelopeType::PreKey);
    assert!(decoded.validate_version().is_ok());
}

#[test]
fn test_envelope_future_version_rejected_explicitly() {
    // A version this build does not understand must fail loud with a typed
    // error, never be silently misinterpreted or panic.
    use parda_protocol::envelope::{EnvelopeType, MessageEnvelope};

    let from_the_future = MessageEnvelope {
        sender_id: "alice".into(),
        recipient_id: "bob".into(),
        ciphertext: vec![0xAA],
        envelope_type: EnvelopeType::Ratchet,
        timestamp_ms: 1_700_000_000_000,
        version: 99,
        sealed_sender: false,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
    };

    let err = from_the_future
        .validate_version()
        .expect_err("version 99 must be rejected");
    assert!(matches!(
        err,
        parda_protocol::PardaError::UnsupportedEnvelopeVersion { got: 99, .. }
    ));
}
