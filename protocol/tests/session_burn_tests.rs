//! Sub-Phase 3D: "burn this conversation" (session-level destruct) tests.
//!
//! Distinct from message-level self-destruct (`self_destruct` module,
//! Sub-Phases 3A-3C) — these tests prove what `burn_session` actually
//! guarantees (the conversation becomes unusable through the normal API)
//! and deliberately do **not** claim byte-level key erasure, because
//! that claim isn't true here — see
//! `InMemorySignalProtocolStore::burn_session`'s doc comment for exactly
//! why (libsignal-protocol's own `PrivateKey` type is a non-zeroizing
//! `Copy` type outside this crate's control).

use libsignal_protocol::{IdentityKeyPair, ProtocolAddress};
use parda_protocol::{session::SessionManager, store::InMemorySignalProtocolStore};
use rand::rngs::OsRng;

fn make_identity_and_store(
    name: &str,
    reg_id: u32,
) -> (parda_protocol::identity::LocalIdentity, InMemorySignalProtocolStore, ProtocolAddress) {
    let identity = parda_protocol::identity::LocalIdentity::generate(reg_id).unwrap();
    let mut store = InMemorySignalProtocolStore::new(identity.identity_key_pair, identity.registration_id);
    store.store_prekey_batch(&identity.one_time_prekeys).unwrap();
    store.store_signed_prekey_record(&identity.signed_prekey).unwrap();
    let addr = ProtocolAddress::new(name.to_string(), 1.into());
    (identity, store, addr)
}

async fn established_pair() -> (SessionManager, SessionManager, ProtocolAddress, ProtocolAddress) {
    let (bob_identity, bob_store, bob_addr) = make_identity_and_store("bob", 2);
    let alice_ikp = IdentityKeyPair::generate(&mut OsRng);
    let alice_store = InMemorySignalProtocolStore::new(alice_ikp, 1);
    let alice_addr = ProtocolAddress::new("alice".to_string(), 1.into());

    let mut alice = SessionManager::new(alice_addr.clone(), alice_store);
    let bob = SessionManager::new(bob_addr.clone(), bob_store);

    let bundle = bob_identity.build_prekey_bundle().unwrap();
    alice.initiate_session(&bob_addr, &bundle).await.unwrap();

    (alice, bob, alice_addr, bob_addr)
}

#[tokio::test]
async fn test_burn_removes_session_and_makes_conversation_unusable() {
    let (mut alice, _bob, _alice_addr, bob_addr) = established_pair().await;

    assert!(alice.store.has_conversation_state(&bob_addr));
    // Sanity check the harness: encryption must actually work before burn.
    assert!(alice.encrypt(&bob_addr, b"hi bob").await.is_ok());

    let result = alice.burn_conversation(&bob_addr);
    assert!(result.session_removed, "burn must report it actually removed a session");

    assert!(
        !alice.store.has_conversation_state(&bob_addr),
        "no session or trust state may remain for a burned conversation"
    );
    assert!(
        alice.encrypt(&bob_addr, b"can't send this").await.is_err(),
        "encrypting to a burned conversation must fail, not silently start a new implicit session"
    );
}

#[tokio::test]
async fn test_burning_a_nonexistent_conversation_reports_nothing_removed() {
    let alice_ikp = IdentityKeyPair::generate(&mut OsRng);
    let alice_store = InMemorySignalProtocolStore::new(alice_ikp, 1);
    let alice_addr = ProtocolAddress::new("alice".to_string(), 1.into());
    let alice = SessionManager::new(alice_addr, alice_store);

    let stranger = ProtocolAddress::new("never-talked-to".to_string(), 1.into());
    let result = alice.burn_conversation(&stranger);

    assert!(!result.session_removed);
    assert!(!result.identity_trust_removed);
}

#[tokio::test]
async fn test_burning_one_conversation_does_not_affect_another() {
    let (mut alice, _bob, _alice_addr, bob_addr) = established_pair().await;

    // Alice also talks to Carol.
    let carol_identity = parda_protocol::identity::LocalIdentity::generate(3).unwrap();
    let carol_addr = ProtocolAddress::new("carol".to_string(), 1.into());
    let carol_bundle = carol_identity.build_prekey_bundle().unwrap();
    alice.initiate_session(&carol_addr, &carol_bundle).await.unwrap();

    alice.burn_conversation(&bob_addr);

    assert!(!alice.store.has_conversation_state(&bob_addr));
    assert!(
        alice.store.has_conversation_state(&carol_addr),
        "burning Bob's conversation must not touch Carol's — burn is scoped per-address"
    );
    assert!(
        alice.encrypt(&carol_addr, b"still here, carol").await.is_ok(),
        "Carol's session must still work after Bob's was burned"
    );
}

#[tokio::test]
async fn test_burn_is_idempotent() {
    let (alice, _bob, _alice_addr, bob_addr) = established_pair().await;

    let first = alice.burn_conversation(&bob_addr);
    assert!(first.session_removed);

    // Burning an already-burned conversation must not panic or error —
    // it's just "nothing left to remove," reported honestly.
    let second = alice.burn_conversation(&bob_addr);
    assert!(!second.session_removed);
    assert!(!second.identity_trust_removed);
}
