//! # PARDA Relay — SQLCipher Persistence Tests
//!
//! Covers the cross-cutting Sub-Phase 2A requirement: the relay store must
//! survive a restart, and must be genuinely encrypted at rest (not just
//! "SQLite behind an unused key parameter").
//!
//! 1. Data written before a simulated restart (drop + reopen the same file)
//!    is still there afterwards.
//! 2. Reopening the same file with the wrong key fails loudly rather than
//!    silently returning garbage or plaintext.
//! 3. The raw database file on disk does not contain a known plaintext
//!    substring that was stored through the API — proving encryption is
//!    actually happening, not just assumed from the `PRAGMA key` call.
//! 4. Reopening (and thus re-running migrations against) an existing
//!    database is safe and does not lose data.

use parda_protocol::envelope::{EnvelopeType, MessageEnvelope};
use parda_relay::{
    models::{PreKeyBundleJson, StoredEnvelope},
    store::RelayStore,
};

fn temp_db_path(test_name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "parda-relay-test-{test_name}-{}.sqlite3",
        uuid::Uuid::new_v4()
    ))
}

fn make_bundle() -> PreKeyBundleJson {
    PreKeyBundleJson {
        registration_id: 42,
        device_id: 1,
        identity_key: "dGVzdC1pZGVudGl0eS1rZXk=".to_string(), // "test-identity-key"
        signed_prekey_id: 1,
        signed_prekey_public: "dGVzdC1zaWduZWQtcHJla2V5".to_string(),
        signed_prekey_signature: "dGVzdC1zaWduYXR1cmU=".to_string(),
        one_time_prekey_id: None,
        one_time_prekey_public: None,
    }
}

fn make_stored_envelope(id: &str, recipient: &str, marker: &str) -> StoredEnvelope {
    StoredEnvelope {
        id: id.to_string(),
        envelope: MessageEnvelope {
            sender_id: marker.to_string(),
            recipient_id: recipient.to_string(),
            ciphertext: marker.as_bytes().to_vec(),
            envelope_type: EnvelopeType::Ratchet,
            timestamp_ms: 1_700_000_000_000,
            version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
            sealed_sender: false,
            routing_hint: None,
            self_destruct_at: None,
        },
    }
}

#[tokio::test]
async fn test_data_survives_simulated_restart() {
    let path = temp_db_path("restart");
    let key = "correct-horse-battery-staple";

    {
        let store = RelayStore::open(&path, key);
        store.put_bundle("alice".to_string(), make_bundle()).await;
        store
            .enqueue(
                "bob".to_string(),
                make_stored_envelope("msg-1", "bob", "hello-from-before-restart"),
            )
            .await;
        // `store` (and its Connection) drops here, simulating process exit.
    }

    // Reopen the same file with the same key — a fresh RelayStore, as if
    // the relay process had just restarted.
    let store = RelayStore::open(&path, key);
    let bundle = store.get_bundle("alice").await;
    assert!(bundle.is_some(), "prekey bundle must survive a restart");
    assert_eq!(bundle.unwrap().registration_id, 42);

    let messages = store.drain("bob").await;
    assert_eq!(messages.len(), 1, "queued message must survive a restart");
    assert_eq!(messages[0].envelope.sender_id, "hello-from-before-restart");

    let _ = std::fs::remove_file(&path);
}

#[test]
#[should_panic(expected = "failed to unlock relay database")]
fn test_wrong_key_cannot_read_database() {
    let path = temp_db_path("wrong-key");

    {
        let store = RelayStore::open(&path, "the-real-key");
        // Force the runtime long enough to write something.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(store.put_bundle("alice".to_string(), make_bundle()));
    }

    // Reopening with the wrong key must fail loudly, not return an empty
    // or garbage-but-successful store.
    let _ = RelayStore::open(&path, "definitely-the-wrong-key");
}

#[test]
fn test_database_file_is_not_plaintext_on_disk() {
    let path = temp_db_path("plaintext-check");
    const MARKER: &str = "TOP-SECRET-PLAINTEXT-MARKER-0xCAFEBABE";

    {
        let store = RelayStore::open(&path, "another-strong-key");
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(store.enqueue(
            "bob".to_string(),
            make_stored_envelope("msg-marker", "bob", MARKER),
        ));
        // Force a checkpoint by dropping the store, ensuring pages are
        // actually flushed to disk before we inspect the file.
    }

    let raw_bytes = std::fs::read(&path).expect("database file must exist on disk");
    let raw_text = String::from_utf8_lossy(&raw_bytes);
    assert!(
        !raw_text.contains(MARKER),
        "database file contains the marker in plaintext — encryption at rest is not working"
    );
    assert!(
        !raw_text.contains("bob"),
        "database file contains recipient_id in plaintext outside SQLCipher's control"
    );

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn test_reopening_existing_database_is_safe_and_preserves_data() {
    let path = temp_db_path("reopen-migrations");
    let key = "yet-another-key";

    let store1 = RelayStore::open(&path, key);
    store1.put_bundle("carol".to_string(), make_bundle()).await;
    drop(store1);

    // Reopen twice in a row — migrations must be safely re-runnable
    // (`CREATE TABLE IF NOT EXISTS`) without wiping prior data.
    let store2 = RelayStore::open(&path, key);
    assert!(store2.get_bundle("carol").await.is_some());
    drop(store2);

    let store3 = RelayStore::open(&path, key);
    assert!(
        store3.get_bundle("carol").await.is_some(),
        "data must still be present after a second reopen"
    );

    let _ = std::fs::remove_file(&path);
}
