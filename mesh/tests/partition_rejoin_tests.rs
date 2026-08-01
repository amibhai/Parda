//! Sub-Phase 4B adversarial gate: mesh partition and reconnection. A
//! node that's been offline and rejoins must reconcile without
//! duplicating delivered bundles or dropping ones still in flight —
//! tested against a real partition/churn schedule on
//! [`parda_mesh::sim::SimHarness`], not a single always-connected pair.

use parda_mesh::{
    bundle,
    radio::simulated::SimProfile,
    relay::RelayConfig,
    sim::SimHarness,
};
use parda_protocol::envelope::{EnvelopeType, MessageEnvelope};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn envelope() -> MessageEnvelope {
    MessageEnvelope {
        sender_id: String::new(),
        recipient_id: String::new(),
        ciphertext: b"partition-rejoin-test-payload".to_vec(),
        envelope_type: EnvelopeType::SealedSender,
        timestamp_ms: now_ms(),
        version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
        sealed_sender: true,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
        dead_drop_address: None,
    }
}

const RELAY_CONFIG: RelayConfig = RelayConfig {
    max_total_bundles: 50,
    max_total_bytes: 4 * 1024 * 1024,
    max_bundles_per_session: 50,
};

/// origin(0) -- relayA(1) -- destination(3)
///         \-- relayB(2) --/
/// destination starts partitioned from both relays; the bundle
/// propagates to both relays first, then destination rejoins and is
/// reachable via *two* paths simultaneously — dedup must still land it
/// exactly once.
#[tokio::test]
async fn rejoining_via_two_paths_delivers_exactly_once_not_duplicated() {
    let harness = SimHarness::new(4, SimProfile::Ble, RELAY_CONFIG);
    const ORIGIN: usize = 0;
    const RELAY_A: usize = 1;
    const RELAY_B: usize = 2;
    const DEST: usize = 3;

    // Destination starts unreachable from either relay — and, since
    // `SimHarness` defaults to full connectivity, from origin directly
    // too (otherwise this test wouldn't actually exercise the two-relay
    // topology the name promises; found by the direct origin-destination
    // link leaking the bundle straight through on the first run).
    harness.sever(RELAY_A, DEST);
    harness.sever(RELAY_B, DEST);
    harness.sever(ORIGIN, DEST);

    let address = [42u8; 32];
    let bytes = bundle::wrap(&envelope(), address).unwrap();
    harness.node(ORIGIN).relay.admit(bytes).unwrap();

    // Propagate origin -> both relays.
    harness.run_sync_rounds(3).await;
    assert_eq!(harness.node(RELAY_A).relay.stored_count(), 1);
    assert_eq!(harness.node(RELAY_B).relay.stored_count(), 1);
    assert_eq!(harness.node(DEST).relay.stored_count(), 0, "must not have leaked across a severed link");

    // Destination rejoins via both paths at once.
    harness.heal(RELAY_A, DEST);
    harness.heal(RELAY_B, DEST);
    harness.run_sync_rounds(4).await;

    assert_eq!(
        harness.node(DEST).relay.stored_count(),
        1,
        "destination reachable via two paths must still store the bundle exactly once, not twice"
    );
    let matches = harness.node(DEST).relay.bundles_for_addresses(&[address]);
    assert_eq!(matches.len(), 1);

    // Further rounds (more re-propagation opportunities) must not
    // duplicate it either.
    harness.run_sync_rounds(5).await;
    assert_eq!(harness.node(DEST).relay.stored_count(), 1);
}

/// A carrier holding an in-flight bundle that goes offline (churn) must
/// not lose it — its own storage is independent of whether its radio is
/// currently reachable — and must still deliver it once it rejoins.
#[tokio::test]
async fn a_carrier_going_offline_mid_mesh_does_not_drop_its_in_flight_bundle() {
    let harness = SimHarness::new(3, SimProfile::Ble, RELAY_CONFIG);
    const ORIGIN: usize = 0;
    const CARRIER: usize = 1;
    const DEST: usize = 2;

    harness.sever(CARRIER, DEST); // destination not reachable yet
    harness.sever(ORIGIN, DEST); // nor directly from origin — see the
                                  // two-path test's identical fix above

    let address = [7u8; 32];
    let bytes = bundle::wrap(&envelope(), address).unwrap();
    harness.node(ORIGIN).relay.admit(bytes).unwrap();

    harness.run_sync_rounds(2).await;
    assert_eq!(harness.node(CARRIER).relay.stored_count(), 1, "carrier should have picked it up from origin");

    // Carrier drops off the mesh entirely.
    harness.set_online(CARRIER, false);
    assert_eq!(
        harness.node(CARRIER).relay.stored_count(),
        1,
        "a relay agent's own storage must not depend on its radio's online/offline state"
    );

    // Time passes with the carrier offline; nothing else can reach
    // destination either.
    harness.run_sync_rounds(3).await;
    assert_eq!(harness.node(DEST).relay.stored_count(), 0);

    // Carrier rejoins and destination becomes reachable through it.
    harness.set_online(CARRIER, true);
    harness.heal(CARRIER, DEST);
    harness.run_sync_rounds(3).await;

    assert_eq!(
        harness.node(DEST).relay.stored_count(),
        1,
        "the bundle carried through the offline period must still be delivered after rejoin"
    );
}

/// A full partition (origin cannot reach anyone) followed by healing
/// must eventually deliver, and running many more rounds afterward must
/// not duplicate — the general "no silent duplication under repeated
/// re-sync" property epidemic routing needs to hold structurally, not
/// just in the minimal two-path case above.
#[tokio::test]
async fn full_partition_then_heal_delivers_once_and_stays_at_once_under_repeated_resync() {
    let harness = SimHarness::new(5, SimProfile::Ble, RELAY_CONFIG);
    const ORIGIN: usize = 0;
    const DEST: usize = 4;

    for other in 1..5 {
        if other != ORIGIN {
            harness.sever(ORIGIN, other);
        }
    }
    // Also isolate DEST from the middle relays so nothing leaks through
    // during the partition.
    harness.sever(1, DEST);
    harness.sever(2, DEST);
    harness.sever(3, DEST);

    let address = [17u8; 32];
    let bytes = bundle::wrap(&envelope(), address).unwrap();
    harness.node(ORIGIN).relay.admit(bytes).unwrap();

    harness.run_sync_rounds(5).await;
    assert_eq!(harness.node(DEST).relay.stored_count(), 0, "fully partitioned — nothing should move");

    // Heal everything at once.
    for other in 1..5 {
        if other != ORIGIN {
            harness.heal(ORIGIN, other);
        }
    }
    harness.heal(1, DEST);
    harness.heal(2, DEST);
    harness.heal(3, DEST);

    harness.run_sync_rounds(10).await;
    assert_eq!(harness.node(DEST).relay.stored_count(), 1);

    // Many more rounds after full mesh connectivity — must stay at 1.
    harness.run_sync_rounds(20).await;
    assert_eq!(
        harness.node(DEST).relay.stored_count(),
        1,
        "repeated re-sync across a fully healed mesh must not duplicate an already-delivered bundle"
    );
}
