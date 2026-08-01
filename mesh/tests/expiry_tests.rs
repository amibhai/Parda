//! Sub-Phase 4C adversarial gate: self-destruct interaction under mesh
//! latency — see `docs/phase4-4c-dead-drop-addressing-design.md` §5. A
//! dead-dropped bundle sitting on an untrusted carrier is exactly Phase
//! 3's scenario; this proves the mesh layer's own TTL enforcement
//! (`mesh/src/relay.rs::sweep_expired`, driven from
//! `mesh/src/bundle.rs::wrap`'s lifetime derivation) closes it correctly
//! under realistic mesh conditions (multi-hop propagation, partition),
//! not just a single always-connected pair.
//!
//! What this file does NOT re-test: `protocol/tests/self_destruct_tests.rs`
//! already proves `SelfDestructingMessage` itself refuses an expired
//! message at the application layer, independent of transport. This
//! file's job is the layer below that — does an expired bundle even
//! survive to be handed to that code at all.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parda_mesh::{bundle, radio::simulated::SimProfile, relay::RelayConfig, sim::SimHarness};
use parda_protocol::envelope::{EnvelopeType, MessageEnvelope};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn envelope_with_lifetime(lifetime_ms: u64) -> MessageEnvelope {
    let ts = now_ms();
    MessageEnvelope {
        sender_id: String::new(),
        recipient_id: String::new(),
        ciphertext: b"expiry-test-payload".to_vec(),
        envelope_type: EnvelopeType::SealedSender,
        timestamp_ms: ts,
        version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
        sealed_sender: true,
        routing_hint: None,
        self_destruct_at: Some(ts + lifetime_ms),
        read_triggered_destruct: false,
        dead_drop_address: None,
    }
}

const RELAY_CONFIG: RelayConfig = RelayConfig {
    max_total_bundles: 50,
    max_total_bytes: 4 * 1024 * 1024,
    max_bundles_per_session: 50,
};

/// A bundle that expires before any carrier ever delivers it is purged
/// by every carrier holding it, and stays gone — not retried, not
/// resurrected by a later sync round.
#[tokio::test]
async fn bundle_expiring_before_pickup_is_purged_and_permanently_undeliverable() {
    let harness = SimHarness::new(3, SimProfile::Ble, RELAY_CONFIG);
    const ORIGIN: usize = 0;
    const CARRIER: usize = 1;
    const DEST: usize = 2;

    let address = [55u8; 32];
    let bytes = bundle::wrap(&envelope_with_lifetime(150), address).unwrap();
    harness.node(ORIGIN).relay.admit(bytes).unwrap();

    // Propagate to the carrier before it expires.
    harness.run_sync_rounds(2).await;
    assert_eq!(harness.node(CARRIER).relay.stored_count(), 1, "carrier should have picked it up while still valid");

    // Let it expire everywhere it's held.
    tokio::time::sleep(Duration::from_millis(250)).await;
    harness.node(ORIGIN).relay.sweep_expired();
    harness.node(CARRIER).relay.sweep_expired();
    assert_eq!(harness.node(ORIGIN).relay.stored_count(), 0, "origin's own copy must also expire");
    assert_eq!(harness.node(CARRIER).relay.stored_count(), 0, "carrier's copy must be purged once expired");

    // Even with the destination now fully reachable, further sync
    // rounds must not resurrect or deliver it — it's gone, not queued.
    harness.run_sync_rounds(5).await;
    assert_eq!(harness.node(DEST).relay.stored_count(), 0, "an expired bundle must never be delivered");
    let leftover = harness.node(DEST).relay.bundles_for_addresses(&[address]);
    assert!(leftover.is_empty());
}

/// Mesh latency (a slow/partitioned path) delaying delivery past the
/// deadline produces the *same* outcome as never-picked-up — not a race
/// that sometimes succeeds depending on exactly when the partition
/// heals relative to the deadline.
#[tokio::test]
async fn mesh_latency_delaying_delivery_past_deadline_never_delivers() {
    let harness = SimHarness::new(2, SimProfile::Ble, RELAY_CONFIG);
    const ORIGIN: usize = 0;
    const DEST: usize = 1;

    harness.sever(ORIGIN, DEST); // destination unreachable — simulates mesh latency/partition

    let address = [66u8; 32];
    let bytes = bundle::wrap(&envelope_with_lifetime(150), address).unwrap();
    harness.node(ORIGIN).relay.admit(bytes).unwrap();

    // The deadline passes while still partitioned.
    tokio::time::sleep(Duration::from_millis(250)).await;
    harness.node(ORIGIN).relay.sweep_expired();
    assert_eq!(harness.node(ORIGIN).relay.stored_count(), 0);

    // The path reopens *after* expiry — mesh latency is exactly this:
    // connectivity returning too late.
    harness.heal(ORIGIN, DEST);
    harness.run_sync_rounds(5).await;

    assert_eq!(
        harness.node(DEST).relay.stored_count(),
        0,
        "a message delayed past its own deadline must never arrive, regardless of when the \
         partition happens to heal relative to the deadline"
    );
}

/// Contrast/sanity check: mesh-derived TTL enforcement must not
/// interfere with ordinary in-time delivery — a generous deadline that
/// hasn't elapsed must not be treated as expired.
#[tokio::test]
async fn a_bundle_well_within_its_lifetime_is_delivered_normally() {
    let harness = SimHarness::new(2, SimProfile::Ble, RELAY_CONFIG);
    let address = [77u8; 32];
    let bytes = bundle::wrap(&envelope_with_lifetime(60_000), address).unwrap();
    harness.node(0).relay.admit(bytes).unwrap();

    harness.run_sync_rounds(3).await;
    harness.node(1).relay.sweep_expired(); // must be a no-op this soon

    assert_eq!(harness.node(1).relay.stored_count(), 1);
    let matches = harness.node(1).relay.bundles_for_addresses(&[address]);
    assert_eq!(matches.len(), 1);
}

/// A bundle with no `self_destruct_at` at all still gets
/// `bundle::DEFAULT_MAX_LIFETIME_MS` — an untrusted carrier is never
/// asked to hold something with an unbounded lifetime just because the
/// sender didn't opt into self-destruct.
#[test]
fn a_bundle_without_self_destruct_still_gets_a_bounded_default_lifetime() {
    let ts = now_ms();
    let envelope = MessageEnvelope {
        sender_id: String::new(),
        recipient_id: String::new(),
        ciphertext: b"no explicit expiry".to_vec(),
        envelope_type: EnvelopeType::SealedSender,
        timestamp_ms: ts,
        version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
        sealed_sender: true,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
        dead_drop_address: None,
    };
    let bytes = bundle::wrap(&envelope, [1u8; 32]).unwrap();
    let expiry = bundle::expiry_ms(&bytes).unwrap();
    // `wrap()` samples its own creation timestamp independently of
    // `envelope.timestamp_ms` (see its doc comment — the bundle's
    // creation time, not the envelope's), so this allows a small
    // real-clock drift between the two `SystemTime::now()` calls rather
    // than asserting bit-exact equality against a timestamp sampled
    // slightly earlier in this test.
    let expected = ts + bundle::DEFAULT_MAX_LIFETIME_MS;
    let drift = expiry.abs_diff(expected);
    assert!(drift < 1000, "expiry {expiry} too far from expected {expected} (drift {drift}ms)");
}
