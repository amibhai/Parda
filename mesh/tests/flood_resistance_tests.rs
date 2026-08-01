//! Sub-Phase 4B adversarial gate: flood/Sybil resistance. An offline
//! mesh has no central admission control — this proves a single
//! malicious peer (whether one device or many rotating "identities"
//! behind one physical radio, which look identical to this project's
//! deliberately-unlinkable peer model — see `mesh/src/relay.rs` module
//! docs on why per-peer-identity rate limiting doesn't fit here) cannot
//! turn an honest carrier into an unbounded or evictable-on-demand
//! garbage store.

use parda_mesh::{
    bundle,
    radio::{simulated::SimNetwork, simulated::SimProfile, MeshRadio},
    relay::{MeshRelayAgent, RelayConfig},
};
use parda_protocol::envelope::{EnvelopeType, MessageEnvelope};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn envelope_with(marker: u8) -> MessageEnvelope {
    MessageEnvelope {
        sender_id: String::new(),
        recipient_id: String::new(),
        ciphertext: vec![marker; 16],
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

fn bundle_with(marker: u8, address_byte: u8) -> Vec<u8> {
    bundle::wrap(&envelope_with(marker), [address_byte; 32]).unwrap()
}

#[test]
fn direct_flood_is_bounded_by_the_global_storage_cap() {
    let config = RelayConfig {
        max_total_bundles: 25,
        max_total_bytes: 1024 * 1024,
        max_bundles_per_session: 25,
    };
    let relay = MeshRelayAgent::new(config);

    let mut accepted = 0;
    let mut refused = 0;
    for i in 0..200u16 {
        // Distinct content + distinct address per bundle so dedup never
        // kicks in — this is testing the cap, not dedup.
        let bytes = bundle_with((i % 256) as u8, (i % 256) as u8);
        match relay.admit(bytes) {
            Ok(()) => accepted += 1,
            Err(_) => refused += 1,
        }
    }

    assert_eq!(relay.stored_count(), 25, "storage must saturate exactly at the configured cap");
    assert_eq!(accepted, 25);
    assert_eq!(refused, 175);
}

#[test]
fn already_expired_bundles_are_refused_before_ever_being_stored() {
    let relay = MeshRelayAgent::new(RelayConfig::default());
    let mut envelope = envelope_with(1);
    // self_destruct_at in the past relative to timestamp_ms — bundle.rs
    // derives lifetime as timestamp_ms..self_destruct_at, so this
    // produces a bundle whose declared expiry has already elapsed.
    envelope.self_destruct_at = Some(envelope.timestamp_ms); // zero lifetime
    std::thread::sleep(std::time::Duration::from_millis(5));
    let bytes = bundle::wrap(&envelope, [1u8; 32]).unwrap();

    let result = relay.admit(bytes);
    assert!(result.is_err(), "an already-expired bundle must be refused, not stored then swept later");
    assert_eq!(relay.stored_count(), 0);
}

/// A single sync session pushing far more bundles than
/// `max_bundles_per_session` must not be able to consume more than that
/// session's own budget — see `relay.rs` module docs §2 for why this,
/// not per-identity rate limiting, is this project's actual flood
/// defense given peers have no stable identity by design.
#[tokio::test]
async fn a_single_sync_session_cannot_exceed_its_own_admission_cap() {
    let net = SimNetwork::new();
    let attacker_radio = net.register(SimProfile::Ble);
    let victim_radio = net.register(SimProfile::Ble);

    let attacker_relay = MeshRelayAgent::new(RelayConfig {
        max_total_bundles: 500,
        max_total_bytes: 8 * 1024 * 1024,
        max_bundles_per_session: 500,
    });
    // The attacker holds far more than the victim will ever accept from
    // one session.
    for i in 0..100u16 {
        let bytes = bundle_with((i % 256) as u8, (i % 256) as u8);
        attacker_relay.admit(bytes).unwrap();
    }

    let victim_relay = MeshRelayAgent::new(RelayConfig {
        max_total_bundles: 500,
        max_total_bytes: 8 * 1024 * 1024,
        max_bundles_per_session: 5, // the cap under test
    });

    parda_mesh::radio::MeshRadio::advertise(
        &attacker_radio,
        parda_mesh::radio::AdvertToken::fresh(),
    )
    .await
    .unwrap();
    let mut sightings = victim_radio.scan().await.unwrap();
    let sighting = sightings.recv().await.expect("victim should see attacker's advertisement");

    let mut victim_link = victim_radio.connect(&sighting.handle).await.unwrap();
    let mut attacker_link = attacker_radio.accept().await.unwrap();

    let (attacker_result, victim_result) = tokio::join!(
        attacker_relay.sync_with_peer(attacker_link.as_mut()),
        victim_relay.sync_with_peer(victim_link.as_mut()),
    );
    attacker_result.unwrap();
    victim_result.unwrap();

    assert!(
        victim_relay.stored_count() <= 5,
        "victim accepted {} bundles from a single session against a cap of 5",
        victim_relay.stored_count()
    );
}

/// Honest bundles admitted before a flood must survive it — a flood
/// that fills the remaining global capacity must be refused, not make
/// room by evicting what's already there.
#[test]
fn flood_does_not_evict_already_stored_honest_bundles() {
    let config = RelayConfig {
        max_total_bundles: 10,
        max_total_bytes: 1024 * 1024,
        max_bundles_per_session: 10,
    };
    let relay = MeshRelayAgent::new(config);

    let honest_bytes: Vec<Vec<u8>> = (0..10u8)
        .map(|i| {
            let bytes = bundle_with(i, i);
            relay.admit(bytes.clone()).unwrap();
            bytes
        })
        .collect();

    // Flood: storage is already full, every one of these must be
    // refused rather than evicting an honest bundle to make room.
    for i in 100..150u16 {
        let bytes = bundle_with((i % 256) as u8, (i % 256) as u8);
        let _ = relay.admit(bytes); // expected to Err; ignored deliberately
    }

    assert_eq!(relay.stored_count(), 10, "flood must not change the stored count");
    let still_present = relay.debug_all_stored_bytes();
    for honest in &honest_bytes {
        assert!(
            still_present.iter().any(|b| b == honest),
            "an honest bundle admitted before the flood is missing after it"
        );
    }
}
