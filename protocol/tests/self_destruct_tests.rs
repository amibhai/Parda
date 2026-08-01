//! Sub-Phases 3A + 3B: black-box functional tests for
//! `parda_protocol::self_destruct`, exercised only through its public
//! API (the white-box memory-forensics tests live inline in
//! `protocol/src/self_destruct.rs` since they need private-field
//! access — see that module for why).

use std::{sync::Arc, time::Duration};

use tokio::sync::Barrier;

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
        read_triggered_destruct: false,
        dead_drop_address: None,
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

// ─── Sub-Phase 3B: read-triggered destruction ──────────────────────────────
//
// These tests exist specifically to keep the two modes' guarantees from
// blurring together (see `self_destruct` module docs): time-bound must
// expire on schedule *even if never read*; read-triggered must survive
// indefinitely *until* read, then die atomically on that read, with no
// window in which a second reader — concurrent or sequential — can find
// the key still live.

#[tokio::test]
async fn test_time_bound_message_expires_even_if_never_read() {
    // The flip side of read-triggered's contract: time-bound destruction
    // does not depend on `open()` ever being called at all.
    let message = SelfDestructingMessage::seal(b"never opened", 1000, Duration::from_millis(50)).unwrap();

    tokio::time::sleep(Duration::from_millis(250)).await;

    assert!(message.is_expired(), "time-bound expiry must fire regardless of whether the message was ever read");
    assert!(matches!(message.open(), Err(PardaError::SelfDestructExpired)));
}

#[tokio::test]
async fn test_read_triggered_message_has_no_timer_and_survives_until_read() {
    let message = SelfDestructingMessage::seal_read_triggered(b"waiting to be read", 1000).unwrap();

    // Long enough that a mistakenly-attached timer at any of this
    // module's other tests' expiry windows would have fired.
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(!message.is_expired(), "read-triggered messages must not expire on any timer");

    let plaintext = message.open().unwrap();
    assert_eq!(&plaintext[..], b"waiting to be read");
    assert!(message.is_expired(), "the read itself must trigger destruction");
}

#[tokio::test]
async fn test_read_triggered_second_open_fails_closed_after_first_succeeds() {
    let message = SelfDestructingMessage::seal_read_triggered(b"burn after reading", 1000).unwrap();

    let first = message.open();
    assert_eq!(&first.unwrap()[..], b"burn after reading");

    // Sequential second read — the same caller, or the same UI trying to
    // re-render, asking again after the first read already happened.
    let second = message.open();
    assert!(
        matches!(second, Err(PardaError::SelfDestructExpired)),
        "a read-triggered message must not be renderable a second time after the triggering read"
    );
}

/// The core Sub-Phase 3B proof: many callers race to `open()` the same
/// read-triggered message at (as close to) the same instant as a test
/// can arrange, via a `tokio::sync::Barrier` releasing them all
/// together. Exactly one must ever see the plaintext.
///
/// This is the practical stand-in for "kill the process between decrypt
/// and display-completion" for this in-memory primitive: there is no
/// separate "finish displaying" step in this API for a kill to land
/// between — `open()` itself only ever returns *after* erasure is
/// already complete (see `self_destruct` module docs
/// "Read-triggered atomicity"). A literal OS-process-kill-and-restart
/// test doesn't apply here because nothing about this primitive persists
/// across a real process exit yet — that boundary belongs to Sub-Phase
/// 3D's SQLCipher-store work, not this in-memory-only building block.
/// What *is* provable now, and is the sharper claim underneath the
/// brief's "provably atomic with respect to display" requirement, is
/// that no two callers — however precisely they're timed — can ever
/// both observe a successful read.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_read_triggered_concurrent_opens_only_one_succeeds() {
    const RACERS: usize = 32;

    let message = SelfDestructingMessage::seal_read_triggered(b"only one winner", 1000).unwrap();
    let barrier = Arc::new(Barrier::new(RACERS));

    let mut tasks = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let message = message.clone(); // shares the same underlying Arc<Mutex<..>>
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await; // maximize contention: all racers hit open() together
            message.open()
        }));
    }

    let mut successes = 0;
    let mut failures = 0;
    for task in tasks {
        match task.await.expect("racer task panicked") {
            Ok(plaintext) => {
                assert_eq!(&plaintext[..], b"only one winner");
                successes += 1;
            }
            Err(PardaError::SelfDestructExpired) => failures += 1,
            Err(other) => panic!("unexpected error from a racing open(): {other}"),
        }
    }

    assert_eq!(successes, 1, "exactly one concurrent open() must succeed, got {successes}");
    assert_eq!(failures, RACERS - 1);
    assert!(message.is_expired());
}

// ─── Sub-Phase 4.5E: combined "by T or on read, whichever comes first" ───────

/// The read wins the race: opening well before the timer's deadline must
/// erase immediately, *without* waiting for T.
#[tokio::test]
async fn test_combined_mode_read_erases_before_the_timer_would_have() {
    let message = SelfDestructingMessage::seal_combined(
        b"combined: read first",
        1_753_900_000_000,
        Duration::from_secs(3600), // deliberately far away
    )
    .unwrap();

    let plaintext = message.open().expect("first open must succeed");
    assert_eq!(&plaintext[..], b"combined: read first");

    assert!(
        message.is_expired(),
        "a combined-mode message must be erased by its first read, not left alive until T"
    );
    assert!(
        matches!(message.open(), Err(PardaError::SelfDestructExpired)),
        "a second read must fail closed"
    );
}

/// The timer wins the race: a combined-mode message that is *never* read
/// must still be gone by T. This is the half `seal_read_triggered` alone
/// does not provide (an unread read-triggered message stays readable
/// indefinitely, by documented design) — so this test is what
/// distinguishes `Combined` from `ReadTriggered`, not a duplicate of the
/// existing timer test.
#[tokio::test]
async fn test_combined_mode_timer_erases_a_message_that_is_never_read() {
    let message = SelfDestructingMessage::seal_combined(
        b"combined: never read",
        1_753_900_000_000,
        Duration::from_millis(50),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_millis(250)).await;

    assert!(message.is_expired(), "the combined-mode timer did not fire");
    assert!(
        matches!(message.open(), Err(PardaError::SelfDestructExpired)),
        "open() must fail closed once the timer has fired"
    );
}

/// Both mechanisms firing must be harmless — the timer landing on an
/// already-read-erased message is a no-op, not a panic or a double-free.
/// This is the concrete check behind `seal_combined`'s claim that the
/// race "needs no coordination because erase is idempotent".
#[tokio::test]
async fn test_combined_mode_timer_firing_after_a_read_is_a_harmless_no_op() {
    let message = SelfDestructingMessage::seal_combined(
        b"combined: both fire",
        1_753_900_000_000,
        Duration::from_millis(50),
    )
    .unwrap();

    message.open().expect("read before the timer");
    assert!(message.is_expired());

    // Let the timer fire on the already-erased key.
    tokio::time::sleep(Duration::from_millis(250)).await;

    assert!(message.is_expired());
    assert!(matches!(message.open(), Err(PardaError::SelfDestructExpired)));
}

/// Concurrent readers of a combined-mode message must behave exactly as
/// they do for read-triggered: exactly one winner. Mirrors
/// `test_read_triggered_concurrent_opens_only_one_succeeds`, since
/// `Combined` takes the same erase-inside-the-decrypt-lock path and that
/// atomicity claim now covers a second mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_combined_mode_concurrent_opens_only_one_succeeds() {
    const RACERS: usize = 32;

    let message = SelfDestructingMessage::seal_combined(
        b"combined: one winner",
        1000,
        Duration::from_secs(3600),
    )
    .unwrap();
    let barrier = Arc::new(Barrier::new(RACERS));

    let mut tasks = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let message = message.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            message.open()
        }));
    }

    let mut successes = 0;
    for task in tasks {
        match task.await.expect("racer task panicked") {
            Ok(plaintext) => {
                assert_eq!(&plaintext[..], b"combined: one winner");
                successes += 1;
            }
            Err(PardaError::SelfDestructExpired) => {}
            Err(other) => panic!("unexpected error from a racing open(): {other}"),
        }
    }

    assert_eq!(successes, 1, "exactly one concurrent open() must succeed, got {successes}");
}
