//! Functional (non-adversarial) test that the whole Sub-Phase 4C stack
//! actually works end-to-end: `MeshTransport` is the third
//! `TransportLayer` implementation alongside `DirectTransport`/
//! `MixTransport`, and a message composed with a dead-drop address must
//! actually travel sender -> mesh propagation -> recipient. The
//! adversarial claims (retrieval-pattern mitigation, expiry interaction)
//! get their own dedicated test files; this one just proves the pipeline
//! isn't broken before those build on top of it.

use parda_mesh::{radio::simulated::SimProfile, relay::RelayConfig, sim::SimHarness, transport::MeshTransport};
use parda_protocol::{
    dead_drop::DeadDropKeyPair,
    envelope::{EnvelopeType, MessageEnvelope},
    transport::TransportLayer,
};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[tokio::test]
async fn send_and_receive_round_trips_through_the_full_mesh_stack() {
    let harness = SimHarness::new(2, SimProfile::Ble, RelayConfig::default());

    let alice_keys = DeadDropKeyPair::generate();
    let bob_keys = DeadDropKeyPair::generate();
    let alice_tag = alice_keys.derive_tag_key(&bob_keys.public_key());
    let bob_tag = bob_keys.derive_tag_key(&alice_keys.public_key());

    let alice_transport = MeshTransport::new(harness.node(0), alice_tag);
    let bob_transport = MeshTransport::new(harness.node(1), bob_tag);

    let address = alice_transport.next_send_address();
    let envelope = MessageEnvelope {
        sender_id: String::new(),
        recipient_id: String::new(),
        ciphertext: b"hello mesh".to_vec(),
        envelope_type: EnvelopeType::SealedSender,
        timestamp_ms: now_ms(),
        version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
        sealed_sender: true,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
        dead_drop_address: Some(address),
    };

    alice_transport.send(&envelope).await.unwrap();

    // Propagate node 0 -> node 1 (fully connected default topology).
    harness.run_sync_rounds(3).await;

    let received = bob_transport.receive("unused-mesh-ignores-this").await.unwrap();
    assert_eq!(received.len(), 1, "bob should have received exactly one envelope");
    assert_eq!(received[0].ciphertext, b"hello mesh");

    // A second receive() call must not re-deliver the same message —
    // it was claimed (removed from local storage) on first pickup.
    let second_poll = bob_transport.receive("unused-mesh-ignores-this").await.unwrap();
    assert!(second_poll.is_empty(), "the same message must not be delivered twice");
}

#[tokio::test]
async fn send_refuses_an_envelope_that_is_not_properly_sealed() {
    let harness = SimHarness::new(1, SimProfile::Ble, RelayConfig::default());
    let alice_keys = DeadDropKeyPair::generate();
    let bob_keys = DeadDropKeyPair::generate();
    let alice_tag = alice_keys.derive_tag_key(&bob_keys.public_key());
    let alice_transport = MeshTransport::new(harness.node(0), alice_tag);

    let mut envelope = MessageEnvelope {
        sender_id: "alice".to_string(), // populated — must be refused
        recipient_id: String::new(),
        ciphertext: b"oops".to_vec(),
        envelope_type: EnvelopeType::SealedSender,
        timestamp_ms: now_ms(),
        version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
        sealed_sender: true,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
        dead_drop_address: Some(alice_transport.next_send_address()),
    };
    assert!(alice_transport.send(&envelope).await.is_err());

    envelope.sender_id = String::new();
    envelope.recipient_id = "bob".to_string(); // populated — must also be refused
    assert!(alice_transport.send(&envelope).await.is_err());

    envelope.recipient_id = String::new();
    envelope.sealed_sender = false; // not sealed — must also be refused
    assert!(alice_transport.send(&envelope).await.is_err());
}

#[tokio::test]
async fn send_requires_a_dead_drop_address_to_already_be_set() {
    let harness = SimHarness::new(1, SimProfile::Ble, RelayConfig::default());
    let alice_keys = DeadDropKeyPair::generate();
    let bob_keys = DeadDropKeyPair::generate();
    let alice_tag = alice_keys.derive_tag_key(&bob_keys.public_key());
    let alice_transport = MeshTransport::new(harness.node(0), alice_tag);

    let envelope = MessageEnvelope {
        sender_id: String::new(),
        recipient_id: String::new(),
        ciphertext: b"no address set".to_vec(),
        envelope_type: EnvelopeType::SealedSender,
        timestamp_ms: now_ms(),
        version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
        sealed_sender: true,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
        dead_drop_address: None, // never set via next_send_address()
    };
    assert!(alice_transport.send(&envelope).await.is_err());
}

/// Reordering tolerance, tested directly against the receiver's own
/// local relay storage (bypassing radio propagation, which doesn't let
/// a test control arrival order precisely): message index 1 (`n=1`)
/// arrives before message index 0 (`n=0`) does. The receiver must still
/// end up with both, and must not have permanently skipped past the
/// still-missing `n=0` just because a later index showed up first — see
/// `docs/phase4-4c-dead-drop-addressing-design.md` §2 and
/// `MeshTransport`'s `ReceiveState` doc comment.
#[tokio::test]
async fn out_of_order_arrival_within_the_window_is_still_delivered() {
    let harness = SimHarness::new(1, SimProfile::Ble, RelayConfig::default());
    let alice_keys = DeadDropKeyPair::generate();
    let bob_keys = DeadDropKeyPair::generate();
    let tag_for_deriving = alice_keys.derive_tag_key(&bob_keys.public_key());
    let bob_tag = bob_keys.derive_tag_key(&alice_keys.public_key());
    let bob_transport = MeshTransport::new(harness.node(0), bob_tag);

    let make = |address: [u8; 32], tag: &[u8]| MessageEnvelope {
        sender_id: String::new(),
        recipient_id: String::new(),
        ciphertext: tag.to_vec(),
        envelope_type: EnvelopeType::SealedSender,
        timestamp_ms: now_ms(),
        version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
        sealed_sender: true,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
        dead_drop_address: Some(address),
    };

    let addr0 = tag_for_deriving.address_for(0);
    let addr1 = tag_for_deriving.address_for(1);
    let bytes1 = parda_mesh::bundle::wrap(&make(addr1, b"second"), addr1).unwrap();
    let bytes0 = parda_mesh::bundle::wrap(&make(addr0, b"first"), addr0).unwrap();

    // n=1 "arrives" first — admitted directly to bob's own local relay,
    // simulating a bundle that reached him via a faster path than n=0's.
    harness.node(0).relay.admit(bytes1).unwrap();
    let first_poll = bob_transport.receive("ignored").await.unwrap();
    assert_eq!(first_poll.len(), 1);
    assert_eq!(first_poll[0].ciphertext, b"second");

    // n=0 hasn't arrived yet — polling again must find nothing new, not
    // error, and must not have given up on ever finding it.
    let empty_poll = bob_transport.receive("ignored").await.unwrap();
    assert!(empty_poll.is_empty());

    // n=0 now arrives.
    harness.node(0).relay.admit(bytes0).unwrap();
    let second_poll = bob_transport.receive("ignored").await.unwrap();
    assert_eq!(second_poll.len(), 1);
    assert_eq!(second_poll[0].ciphertext, b"first");
}
