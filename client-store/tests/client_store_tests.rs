//! Sub-Phase 3D: client-side encrypted local message store tests.
//!
//! All 7 pass — see `client-store/src/lib.rs` module docs for the
//! Perl/vendored-SQLCipher build note.

use parda_protocol::envelope::{EnvelopeType, MessageEnvelope};
use parda_client_store::{LocalMessageStore, MessageDirection, StoreError};

fn plain_envelope(recipient: &str, timestamp_ms: u64) -> MessageEnvelope {
    MessageEnvelope {
        sender_id: "alice".to_string(),
        recipient_id: recipient.to_string(),
        ciphertext: b"ordinary, non-self-destructing message".to_vec(),
        envelope_type: EnvelopeType::Ratchet,
        timestamp_ms,
        version: 2,
        sealed_sender: false,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
        dead_drop_address: None,
    }
}

#[tokio::test]
async fn test_ordinary_message_round_trips() {
    let store = LocalMessageStore::open_ephemeral().unwrap();
    let envelope = plain_envelope("bob", 1000);

    store.store_message("bob", MessageDirection::Sent, &envelope).await.unwrap();

    let history = store.history_for("bob").await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].envelope.ciphertext, envelope.ciphertext);
    assert_eq!(history[0].direction, MessageDirection::Sent);
}

#[tokio::test]
async fn test_self_destructing_messages_are_refused_time_bound() {
    let store = LocalMessageStore::open_ephemeral().unwrap();
    let mut envelope = plain_envelope("bob", 1000);
    envelope.self_destruct_at = Some(1300);

    let result = store.store_message("bob", MessageDirection::Received, &envelope).await;
    assert!(matches!(result, Err(StoreError::RefusesSelfDestructingMessage)));
    assert_eq!(store.total_message_count().await.unwrap(), 0, "nothing must have been written");
}

#[tokio::test]
async fn test_self_destructing_messages_are_refused_read_triggered() {
    let store = LocalMessageStore::open_ephemeral().unwrap();
    let mut envelope = plain_envelope("bob", 1000);
    envelope.read_triggered_destruct = true;

    let result = store.store_message("bob", MessageDirection::Received, &envelope).await;
    assert!(matches!(result, Err(StoreError::RefusesSelfDestructingMessage)));
    assert_eq!(store.total_message_count().await.unwrap(), 0);
}

#[tokio::test]
async fn test_refusal_does_not_partially_write_anything() {
    // Belt-and-suspenders on the "nothing written" claim above: store one
    // legitimate message, attempt (and fail) to store a self-destructing
    // one, and confirm the count is still exactly 1 — the refusal isn't
    // silently writing a stripped-down row.
    let store = LocalMessageStore::open_ephemeral().unwrap();
    store.store_message("bob", MessageDirection::Sent, &plain_envelope("bob", 1000)).await.unwrap();

    let mut bad = plain_envelope("bob", 2000);
    bad.self_destruct_at = Some(2300);
    let _ = store.store_message("bob", MessageDirection::Sent, &bad).await;

    assert_eq!(store.total_message_count().await.unwrap(), 1);
}

#[tokio::test]
async fn test_history_scoped_per_peer() {
    let store = LocalMessageStore::open_ephemeral().unwrap();
    store.store_message("bob", MessageDirection::Sent, &plain_envelope("bob", 1000)).await.unwrap();
    store.store_message("carol", MessageDirection::Sent, &plain_envelope("carol", 1000)).await.unwrap();

    assert_eq!(store.history_for("bob").await.unwrap().len(), 1);
    assert_eq!(store.history_for("carol").await.unwrap().len(), 1);
    assert_eq!(store.history_for("nobody").await.unwrap().len(), 0);
}

#[tokio::test]
async fn test_delete_history_for_peer_scoped_correctly() {
    let store = LocalMessageStore::open_ephemeral().unwrap();
    store.store_message("bob", MessageDirection::Sent, &plain_envelope("bob", 1000)).await.unwrap();
    store.store_message("carol", MessageDirection::Sent, &plain_envelope("carol", 1000)).await.unwrap();

    let deleted = store.delete_history_for("bob").await.unwrap();
    assert_eq!(deleted, 1);
    assert_eq!(store.history_for("bob").await.unwrap().len(), 0);
    assert_eq!(
        store.history_for("carol").await.unwrap().len(),
        1,
        "deleting Bob's history must not touch Carol's"
    );
}

#[tokio::test]
async fn test_history_ordered_oldest_first() {
    let store = LocalMessageStore::open_ephemeral().unwrap();
    store.store_message("bob", MessageDirection::Sent, &plain_envelope("bob", 3000)).await.unwrap();
    store.store_message("bob", MessageDirection::Received, &plain_envelope("bob", 1000)).await.unwrap();
    store.store_message("bob", MessageDirection::Sent, &plain_envelope("bob", 2000)).await.unwrap();

    let history = store.history_for("bob").await.unwrap();
    let timestamps: Vec<u64> = history.iter().map(|m| m.envelope.timestamp_ms).collect();
    assert_eq!(timestamps, vec![1000, 2000, 3000]);
}
