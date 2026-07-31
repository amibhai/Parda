//! Sub-Phase 3A: black-box functional tests for
//! `parda_protocol::self_destruct`, exercised only through its public
//! API (the white-box memory-forensics tests live inline in
//! `protocol/src/self_destruct.rs` since they need private-field
//! access — see that module for why).

use std::time::Duration;

use parda_protocol::{
    clock_guard::InMemoryClockWatermarkStore,
    envelope::{EnvelopeType, MessageEnvelope},
    error::PardaError,
    self_destruct::SelfDestructingMessage,
};

#[test]
fn test_envelope_with_self_destruct_sets_advisory_deadline() {
    let envelope = MessageEnvelope {
        sender_id: "alice".to_string(),
        recipient_id: "bob".to_string(),
        ciphertext: vec![1, 2, 3],
        envelope_type: EnvelopeType::Ratchet,
        timestamp_ms: 1_753_900_000_000,
        version: 2,
        sealed_sender: false,
        routing_hint: None,
        self_destruct_at: None,
    }
    .with_self_destruct(Duration::from_secs(300));

    assert_eq!(envelope.self_destruct_at, Some(1_753_900_000_000 + 300_000));
}

#[tokio::test]
async fn test_real_timer_expiry_makes_open_fail_closed() {
    let message = SelfDestructingMessage::seal(
        b"this should be gone shortly",
        1_753_900_000_000,
        Duration::from_millis(50),
    )
    .unwrap();

    assert!(message.open().is_ok(), "message should still be readable immediately after seal");

    // Real wall-clock wait past the expiry window — this exercises the
    // actual background timer task (`spawn_expiry_timer`), not
    // `expire_now()`'s synchronous shortcut.
    tokio::time::sleep(Duration::from_millis(250)).await;

    assert!(message.is_expired(), "background expiry timer did not fire");
    assert!(
        matches!(message.open(), Err(PardaError::SelfDestructExpired)),
        "open() must fail closed once the real timer has fired, not return stale plaintext"
    );
}

#[tokio::test]
async fn test_message_not_yet_expired_stays_readable() {
    let message = SelfDestructingMessage::seal(
        b"still here",
        1_753_900_000_000,
        Duration::from_secs(60),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;

    assert!(!message.is_expired());
    assert_eq!(&message.open().unwrap()[..], b"still here");
}

#[tokio::test]
async fn test_clock_rollback_forces_fail_closed_and_permanently_expires_the_message() {
    let message = SelfDestructingMessage::seal(b"secret", 1_753_900_000_000, Duration::from_secs(60)).unwrap();
    let store = InMemoryClockWatermarkStore::new();

    // Establish a watermark at t=5_000_000.
    let first = message.open_with_clock_guard(&store, 5_000_000);
    assert!(first.is_ok(), "first call at an advancing clock must succeed");

    // Simulate the device clock having been rolled back to t=3_000_000 —
    // e.g. an adversary with the device changed the system date to try
    // to keep this message readable past its intended window.
    let rolled_back = message.open_with_clock_guard(&store, 3_000_000);
    assert!(
        matches!(
            rolled_back,
            Err(PardaError::ClockRollbackDetected { watermark_ms: 5_000_000, observed_ms: 3_000_000 })
        ),
        "rollback must be detected and reported, not silently trusted"
    );

    // Fail-closed: the message must now be expired for good, not just
    // for this one call — even a subsequent call with a *correct*,
    // un-rolled-back timestamp must not resurrect it.
    assert!(message.is_expired());
    assert!(matches!(message.open(), Err(PardaError::SelfDestructExpired)));
    assert!(matches!(
        message.open_with_clock_guard(&store, 5_000_001),
        Err(PardaError::SelfDestructExpired)
    ));
}

#[tokio::test]
async fn test_clock_rollback_does_not_affect_a_different_message() {
    // Fail-closed on rollback detection must be scoped to the message
    // whose `open_with_clock_guard` observed it — not a global kill
    // switch that destroys every self-destructing message on the device.
    // (A device-wide response to detected tampering is a reasonable
    // *product* decision, but it must be an explicit choice made by the
    // caller orchestrating multiple messages, not something this
    // primitive imposes unilaterally.)
    let message_a = SelfDestructingMessage::seal(b"a", 1000, Duration::from_secs(60)).unwrap();
    let message_b = SelfDestructingMessage::seal(b"b", 1000, Duration::from_secs(60)).unwrap();
    let store = InMemoryClockWatermarkStore::new();

    message_a.open_with_clock_guard(&store, 5000).unwrap();
    let _ = message_a.open_with_clock_guard(&store, 3000); // rollback, expires message_a only

    assert!(message_a.is_expired());
    assert!(!message_b.is_expired());
    assert_eq!(&message_b.open().unwrap()[..], b"b");
}
