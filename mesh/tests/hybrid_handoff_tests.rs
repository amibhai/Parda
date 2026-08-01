//! Sub-Phase 4D: hybrid online/mesh handoff. A client with both
//! transports available uses the network when reachable and falls back
//! to mesh when it drops, without manual mode switching or losing
//! in-flight state across the transition — see
//! `mesh/src/hybrid.rs` module docs for the design (in particular why
//! `send` redacts `recipient_id` before handing an envelope to the mesh
//! fallback).

mod common;

use common::MockOnlineTransport;
use parda_mesh::{hybrid::HybridTransport, radio::simulated::SimProfile, relay::RelayConfig, sim::SimHarness, transport::MeshTransport};
use parda_protocol::{
    dead_drop::DeadDropKeyPair,
    envelope::{EnvelopeType, MessageEnvelope},
    transport::TransportLayer,
};

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

fn make_envelope(recipient_id: &str, dead_drop_address: [u8; 32], payload: &[u8]) -> MessageEnvelope {
    MessageEnvelope {
        sender_id: String::new(),
        recipient_id: recipient_id.to_string(),
        ciphertext: payload.to_vec(),
        envelope_type: EnvelopeType::SealedSender,
        timestamp_ms: now_ms(),
        version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
        sealed_sender: true,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
        dead_drop_address: Some(dead_drop_address),
    }
}

#[tokio::test]
async fn falls_back_to_mesh_when_network_drops_and_resumes_online_after() {
    let harness = SimHarness::new(2, SimProfile::Ble, RelayConfig::default());
    let alice_keys = DeadDropKeyPair::generate();
    let bob_keys = DeadDropKeyPair::generate();
    let alice_tag = alice_keys.derive_tag_key(&bob_keys.public_key());
    let bob_tag = bob_keys.derive_tag_key(&alice_keys.public_key());

    // A shared mock "relay" — both Alice's and Bob's hybrid transports
    // talk to it, the same way both real clients talk to the same real
    // relay.
    let network = MockOnlineTransport::new();

    let alice = HybridTransport::new(network.clone(), MeshTransport::new(harness.node(0), alice_tag));
    let bob = HybridTransport::new(network.clone(), MeshTransport::new(harness.node(1), bob_tag));

    // 1. Network up: message 1 goes via the online path.
    let addr0 = alice_keys.derive_tag_key(&bob_keys.public_key()).address_for(0);
    alice.send(&make_envelope("bob", addr0, b"message one (online)")).await.unwrap();

    let bob_inbox = bob.receive("bob").await.unwrap();
    assert_eq!(bob_inbox.len(), 1);
    assert_eq!(bob_inbox[0].ciphertext, b"message one (online)");

    // Nothing should have touched the mesh for message 1 — confirm no
    // bundle exists on bob's mesh node.
    assert_eq!(harness.node(1).relay.stored_count(), 0);

    // 2. Network drops.
    network.set_up(false);

    // 3. Alice sends message 2 while offline — falls back to mesh
    // automatically, no manual mode switch.
    let addr1 = alice_keys.derive_tag_key(&bob_keys.public_key()).address_for(1);
    alice.send(&make_envelope("bob", addr1, b"message two (mesh fallback)")).await.unwrap();

    // Propagate through the (still fully connected) simulated mesh.
    harness.run_sync_rounds(3).await;

    // 4. Bob polls while still offline — primary fails silently, mesh
    // half of the union still delivers message 2.
    let bob_inbox_2 = bob.receive("bob").await.unwrap();
    assert_eq!(bob_inbox_2.len(), 1);
    assert_eq!(bob_inbox_2[0].ciphertext, b"message two (mesh fallback)");

    // 5. Network returns; a third message goes via the online path
    // again automatically.
    network.set_up(true);
    let addr2 = alice_keys.derive_tag_key(&bob_keys.public_key()).address_for(2);
    alice.send(&make_envelope("bob", addr2, b"message three (online again)")).await.unwrap();
    let bob_inbox_3 = bob.receive("bob").await.unwrap();
    assert_eq!(bob_inbox_3.len(), 1);
    assert_eq!(bob_inbox_3[0].ciphertext, b"message three (online again)");

    // 6. No duplication: polling again finds nothing left over from any
    // of the three messages.
    let bob_inbox_4 = bob.receive("bob").await.unwrap();
    assert!(bob_inbox_4.is_empty());
}

/// The mesh-fallback envelope must never carry the plaintext
/// `recipient_id` into an untrusted carrier's storage — confirms
/// `HybridTransport::send`'s redaction actually happens, not just that
/// delivery works.
#[tokio::test]
async fn recipient_id_is_redacted_before_falling_back_to_mesh() {
    let harness = SimHarness::new(2, SimProfile::Ble, RelayConfig::default());
    let alice_keys = DeadDropKeyPair::generate();
    let bob_keys = DeadDropKeyPair::generate();
    let alice_tag = alice_keys.derive_tag_key(&bob_keys.public_key());

    let network = MockOnlineTransport::new();
    network.set_up(false); // offline from the start — every send falls back

    let alice = HybridTransport::new(network, MeshTransport::new(harness.node(0), alice_tag));
    let address = alice_keys.derive_tag_key(&bob_keys.public_key()).address_for(0);
    alice
        .send(&make_envelope("bob-distinctive-recipient-id", address, b"payload"))
        .await
        .unwrap();

    let stored = harness.node(0).relay.debug_all_stored_bytes();
    assert_eq!(stored.len(), 1);
    assert!(
        !contains_subslice(&stored[0], b"bob-distinctive-recipient-id"),
        "recipient_id leaked into the mesh bundle despite falling back through HybridTransport"
    );
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
