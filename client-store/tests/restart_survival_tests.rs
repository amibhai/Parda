//! Sub-Phase 4.5E: self-destruct restart-survival tests.
//!
//! A "restart" is simulated by exporting a sealed message's state,
//! staging it, dropping the in-memory [`SelfDestructingMessage`]
//! entirely, and then restoring from the store — which is exactly the
//! sequence a real restart performs, minus the process actually exiting.
//! An on-disk store is used (not `open_ephemeral`, which is in-memory
//! and would vanish with the process it is meant to outlive) wherever
//! the test's point depends on durability.
//!
//! | Test | Asserts |
//! |------|---------|
//! | 1 | A staged message round-trips through a **real reopened database file** and is readable again. |
//! | 2 | Downtime counts against the deadline — the restored timer covers the *remaining* window, not a fresh full one. |
//! | 3 | A message whose deadline passed during downtime is refused, not resurrected. |
//! | 4 | A clock rollback across the restart is refused (`clock_guard`, fail-closed). |
//! | 5 | Taking a staged message deletes its row — read-once, no lingering key on disk. |
//! | 6 | A row that cannot be restored is still deleted (no retry-under-a-better-clock). |
//! | 7 | `purge_expired_self_destructing` deletes expired rows and spares deadline-less ones. |
//! | 8 | The Sub-Phase 3D refusal boundary is intact: `store_message` still rejects self-destructing envelopes. |

use std::time::Duration;

use parda_client_store::{LocalMessageStore, MessageDirection, StoreError};
use parda_protocol::{
    clock_guard::InMemoryClockWatermarkStore,
    envelope::{EnvelopeType, MessageEnvelope},
    error::PardaError,
    self_destruct::{DestructMode, SelfDestructingMessage},
};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// ─── Test 1: real on-disk round trip across a reopen ─────────────────────────

#[tokio::test]
async fn test_staged_message_survives_a_real_database_reopen() {
    let dir = std::env::temp_dir().join(format!("parda-restart-{}", now_ms()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("client.db");
    let key = "restart-survival-test-key";

    let id = {
        let store = LocalMessageStore::open(&db, key).unwrap();
        let message =
            SelfDestructingMessage::seal(b"survives a restart", now_ms(), Duration::from_secs(3600))
                .unwrap();
        let state = message.export_for_persistence().unwrap();
        store
            .stage_self_destructing("bob", &state, now_ms())
            .await
            .unwrap()
        // `store` and `message` both drop here — this is the "process
        // exited" boundary.
    };

    // A genuinely new connection to the same file, as a restarted
    // process would open.
    let store = LocalMessageStore::open(&db, key).unwrap();
    let state = store
        .take_self_destructing(&id)
        .await
        .unwrap()
        .expect("the staged row must still be there after reopening the database");

    let clock = InMemoryClockWatermarkStore::new();
    let restored = SelfDestructingMessage::restore(&state, &clock, now_ms()).unwrap();
    let plaintext = restored.open().unwrap();
    assert_eq!(&plaintext[..], b"survives a restart");

    std::fs::remove_dir_all(&dir).ok();
}

// ─── Test 2: downtime counts against the deadline ────────────────────────────

/// The restored timer must cover only the *remaining* window. Sealed
/// with a 300 ms window, restored 250 ms later, the message must expire
/// within roughly the leftover ~50 ms — not 300 ms from restore, which
/// would let a restart loop extend a message's life indefinitely.
#[tokio::test]
async fn test_restored_timer_covers_only_the_remaining_window() {
    let store = LocalMessageStore::open_ephemeral().unwrap();
    let clock = InMemoryClockWatermarkStore::new();

    let sealed_at = now_ms();
    let message =
        SelfDestructingMessage::seal(b"downtime counts", sealed_at, Duration::from_millis(300))
            .unwrap();
    let state = message.export_for_persistence().unwrap();
    let id = store
        .stage_self_destructing("bob", &state, sealed_at)
        .await
        .unwrap();
    drop(message);

    let taken = store.take_self_destructing(&id).await.unwrap().unwrap();
    let restored =
        SelfDestructingMessage::restore(&taken, &clock, sealed_at + 250).expect("still within window");

    // ~50 ms of the original window remain. Well before a *fresh* 300 ms
    // window would have elapsed, this must already be gone.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        restored.is_expired(),
        "the restored timer re-armed a full window instead of the remaining one — a restart \
         loop could then extend a message's life indefinitely"
    );
}

// ─── Test 3: expired during downtime ─────────────────────────────────────────

#[tokio::test]
async fn test_message_that_expired_during_downtime_is_refused() {
    let store = LocalMessageStore::open_ephemeral().unwrap();
    let clock = InMemoryClockWatermarkStore::new();

    let sealed_at = now_ms();
    let message =
        SelfDestructingMessage::seal(b"expired while down", sealed_at, Duration::from_millis(100))
            .unwrap();
    let state = message.export_for_persistence().unwrap();
    let id = store
        .stage_self_destructing("bob", &state, sealed_at)
        .await
        .unwrap();
    drop(message);

    let taken = store.take_self_destructing(&id).await.unwrap().unwrap();
    // Restart happens well after the deadline.
    let err = SelfDestructingMessage::restore(&taken, &clock, sealed_at + 60_000)
        .expect_err("a message whose deadline passed during downtime must not be resurrected");
    assert!(matches!(err, PardaError::SelfDestructExpired), "got {err:?}");
}

// ─── Test 4: clock rollback across the restart ───────────────────────────────

/// A restart is exactly the window `clock_guard` exists to cover: the
/// monotonic anchor is gone, so an adversary holding the device could
/// wind the wall clock back to make an expired message look live.
#[tokio::test]
async fn test_clock_rollback_across_a_restart_is_refused() {
    let store = LocalMessageStore::open_ephemeral().unwrap();
    let clock = InMemoryClockWatermarkStore::new();

    let sealed_at = now_ms();
    let message =
        SelfDestructingMessage::seal(b"rollback target", sealed_at, Duration::from_secs(3600))
            .unwrap();
    let state = message.export_for_persistence().unwrap();
    let id = store
        .stage_self_destructing("bob", &state, sealed_at)
        .await
        .unwrap();
    drop(message);

    // The device observed this (later) time before going down.
    parda_protocol::clock_guard::check_clock_integrity(&clock, sealed_at + 100_000);

    let taken = store.take_self_destructing(&id).await.unwrap().unwrap();
    let err = SelfDestructingMessage::restore(&taken, &clock, sealed_at + 1_000)
        .expect_err("a rolled-back clock must not be trusted to restore a message");
    assert!(
        matches!(err, PardaError::ClockRollbackDetected { .. }),
        "got {err:?}"
    );
}

// ─── Test 5: fetch-and-clear ─────────────────────────────────────────────────

#[tokio::test]
async fn test_taking_a_staged_message_deletes_its_row() {
    let store = LocalMessageStore::open_ephemeral().unwrap();

    let message =
        SelfDestructingMessage::seal(b"read once", now_ms(), Duration::from_secs(3600)).unwrap();
    let state = message.export_for_persistence().unwrap();
    let id = store
        .stage_self_destructing("bob", &state, now_ms())
        .await
        .unwrap();

    assert_eq!(store.pending_self_destruct_count().await.unwrap(), 1);
    assert!(store.take_self_destructing(&id).await.unwrap().is_some());
    assert_eq!(
        store.pending_self_destruct_count().await.unwrap(),
        0,
        "the row must be deleted, not marked — the derived key must not linger on disk"
    );
    assert!(
        store.take_self_destructing(&id).await.unwrap().is_none(),
        "a second take must find nothing"
    );
}

// ─── Test 6: an unrestorable row is still deleted ────────────────────────────

/// Fail-closed direction: if a row cannot be restored (expired, or a
/// detected rollback), it must not be left on disk for a later attempt
/// under a more favourable clock.
#[tokio::test]
async fn test_row_is_deleted_even_when_it_cannot_be_restored() {
    let store = LocalMessageStore::open_ephemeral().unwrap();
    let clock = InMemoryClockWatermarkStore::new();

    let sealed_at = now_ms();
    let message =
        SelfDestructingMessage::seal(b"unrestorable", sealed_at, Duration::from_millis(50)).unwrap();
    let state = message.export_for_persistence().unwrap();
    let id = store
        .stage_self_destructing("bob", &state, sealed_at)
        .await
        .unwrap();
    drop(message);

    let taken = store.take_self_destructing(&id).await.unwrap().unwrap();
    assert!(SelfDestructingMessage::restore(&taken, &clock, sealed_at + 60_000).is_err());

    assert_eq!(
        store.pending_self_destruct_count().await.unwrap(),
        0,
        "the row must already be gone — take_self_destructing deletes unconditionally, so a \
         failed restore cannot be retried later under a rolled-back clock"
    );
}

// ─── Test 7: the expiry sweep ────────────────────────────────────────────────

#[tokio::test]
async fn test_purge_deletes_expired_rows_and_spares_deadline_less_ones() {
    let store = LocalMessageStore::open_ephemeral().unwrap();
    let base = now_ms();

    let expiring =
        SelfDestructingMessage::seal(b"will expire", base, Duration::from_millis(100)).unwrap();
    store
        .stage_self_destructing("bob", &expiring.export_for_persistence().unwrap(), base)
        .await
        .unwrap();

    // Read-triggered has no deadline by design — sweeping it on a timer
    // would silently convert it to a different mode than was chosen.
    let read_triggered = SelfDestructingMessage::seal_read_triggered(b"no deadline", base).unwrap();
    let rt_state = read_triggered.export_for_persistence().unwrap();
    assert_eq!(rt_state.mode(), DestructMode::ReadTriggered);
    assert_eq!(rt_state.expires_at_ms(), None);
    let rt_id = store
        .stage_self_destructing("bob", &rt_state, base)
        .await
        .unwrap();

    assert_eq!(store.pending_self_destruct_count().await.unwrap(), 2);

    let purged = store.purge_expired_self_destructing(base + 60_000).await.unwrap();
    assert_eq!(purged, 1, "exactly the expired row must be purged");
    assert_eq!(store.pending_self_destruct_count().await.unwrap(), 1);
    assert!(
        store.take_self_destructing(&rt_id).await.unwrap().is_some(),
        "the deadline-less read-triggered row must have survived the sweep"
    );
}

// ─── Test 8: the Sub-Phase 3D boundary is untouched ──────────────────────────

/// The holding area must not have become a back door into `messages`.
/// This re-asserts Sub-Phase 3D's refusal alongside the new feature, so
/// a future change that merged the two paths would fail here.
#[tokio::test]
async fn test_store_message_still_refuses_self_destructing_envelopes() {
    let store = LocalMessageStore::open_ephemeral().unwrap();

    let mut envelope = MessageEnvelope {
        sender_id: "alice".to_string(),
        recipient_id: "bob".to_string(),
        ciphertext: b"should never be persisted as history".to_vec(),
        envelope_type: EnvelopeType::Ratchet,
        timestamp_ms: now_ms(),
        version: 2,
        sealed_sender: false,
        routing_hint: None,
        self_destruct_at: Some(now_ms() + 60_000),
        read_triggered_destruct: false,
        dead_drop_address: None,
    };

    assert!(matches!(
        store.store_message("bob", MessageDirection::Sent, &envelope).await,
        Err(StoreError::RefusesSelfDestructingMessage)
    ));

    envelope.self_destruct_at = None;
    envelope.read_triggered_destruct = true;
    assert!(matches!(
        store.store_message("bob", MessageDirection::Sent, &envelope).await,
        Err(StoreError::RefusesSelfDestructingMessage)
    ));

    assert_eq!(store.total_message_count().await.unwrap(), 0);
}

// ─── Combined mode also survives ─────────────────────────────────────────────

/// `DestructMode::Combined` (this sub-phase's other addition) must
/// persist and restore with *both* mechanisms intact — the restored
/// message still erases on read.
#[tokio::test]
async fn test_combined_mode_survives_a_restart_with_both_mechanisms_intact() {
    let store = LocalMessageStore::open_ephemeral().unwrap();
    let clock = InMemoryClockWatermarkStore::new();
    let base = now_ms();

    let message =
        SelfDestructingMessage::seal_combined(b"combined survives", base, Duration::from_secs(3600))
            .unwrap();
    let state = message.export_for_persistence().unwrap();
    assert_eq!(state.mode(), DestructMode::Combined);
    let id = store.stage_self_destructing("bob", &state, base).await.unwrap();
    drop(message);

    let taken = store.take_self_destructing(&id).await.unwrap().unwrap();
    let restored = SelfDestructingMessage::restore(&taken, &clock, base + 1000).unwrap();

    let plaintext = restored.open().unwrap();
    assert_eq!(&plaintext[..], b"combined survives");
    assert!(
        restored.is_expired(),
        "a restored combined-mode message must still erase on read"
    );
}

// ─── Exporting an already-expired message ────────────────────────────────────

#[tokio::test]
async fn test_exporting_an_expired_message_fails_rather_than_writing_a_dead_key() {
    let message =
        SelfDestructingMessage::seal(b"already gone", now_ms(), Duration::from_secs(3600)).unwrap();
    message.expire_now();

    assert!(matches!(
        message.export_for_persistence(),
        Err(PardaError::SelfDestructExpired)
    ));
}
