//! Sub-Phase 2B: Sphinx packet construction/processing and `MixTransport`
//! adversarial + correctness tests.
//!
//! These exercise `parda_protocol::mixnet` directly (no HTTP, no running
//! mix node processes) by walking a packet through `process_packet` hop
//! by hop in-process — the same unwrap function a real `parda-mixnode`
//! daemon calls from its `/mix/packet` handler. Network-level behavior
//! (actual forwarding over HTTP, timing correlation across real daemons)
//! is covered by `mixnode/tests/`.

use std::time::Duration;

use parda_protocol::{
    envelope::{EnvelopeType, MessageEnvelope},
    error::PardaError,
    mixnet::{self, MixNodeDescriptor, MixTopology, UnwrapOutcome},
    transport::{MixTransport, TransportLayer},
};

fn make_node(address: &str) -> (x25519_dalek::StaticSecret, MixNodeDescriptor) {
    let (secret, public) = mixnet::generate_node_keypair();
    (
        secret,
        MixNodeDescriptor {
            address: address.to_string(),
            public_key: public,
        },
    )
}

fn sample_envelope() -> MessageEnvelope {
    MessageEnvelope {
        sender_id: "alice".to_string(),
        recipient_id: "bob".to_string(),
        ciphertext: b"totally opaque ciphertext".to_vec(),
        envelope_type: EnvelopeType::Ratchet,
        timestamp_ms: 1_753_900_000_000,
        version: 2,
        sealed_sender: false,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
        dead_drop_address: None,
    }
}

/// Drive a built packet through however many hops it takes, using each
/// hop's real secret key, and return the terminal outcome. Panics if a
/// `Forward` outcome names a node not present in `secrets_by_address`
/// (the test wired the wrong path).
fn drive_to_completion(
    mut packet_bytes: Vec<u8>,
    secrets_by_address: &[(String, x25519_dalek::StaticSecret)],
) -> UnwrapOutcome {
    loop {
        // Route by whichever secret currently unwraps the header
        // successfully — mirrors how a real daemon only has its own key
        // and doesn't know in advance whether it's hop 1, 2, or 3.
        let mut last_err = None;
        let mut matched = None;
        for (_, secret) in secrets_by_address {
            match mixnet::process_packet(&packet_bytes, secret) {
                Ok(outcome) => {
                    matched = Some(outcome);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        match matched {
            Some(UnwrapOutcome::Forward { packet_bytes: next, .. }) => {
                packet_bytes = next;
            }
            Some(terminal) => return terminal,
            None => panic!(
                "no configured node key could unwrap this packet: {:?}",
                last_err
            ),
        }
    }
}

#[test]
fn test_three_hop_packet_round_trips_envelope_bit_identical() {
    let (s1, n1) = make_node("10.0.0.1:9001");
    let (s2, n2) = make_node("10.0.0.2:9001");
    let (s3, n3) = make_node("10.0.0.3:9001");
    let path = vec![n1, n2, n3];
    let secrets = vec![
        ("n1".to_string(), s1),
        ("n2".to_string(), s2),
        ("n3".to_string(), s3),
    ];

    let envelope = sample_envelope();
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();

    let packet_bytes = mixnet::build_packet(
        &envelope_bytes,
        &path,
        Duration::from_millis(1),
        mixnet::DEFAULT_MIX_PAYLOAD_SIZE,
    )
    .expect("packet should build over a valid 3-node path");

    match drive_to_completion(packet_bytes, &secrets) {
        UnwrapOutcome::Deliver { envelope_bytes: recovered } => {
            assert_eq!(
                recovered, envelope_bytes,
                "envelope recovered at the final hop must be bit-identical to what the sender built"
            );
            let recovered_envelope: MessageEnvelope = serde_json::from_slice(&recovered).unwrap();
            assert_eq!(recovered_envelope.recipient_id, "bob");
            assert_eq!(recovered_envelope.ciphertext, b"totally opaque ciphertext");
        }
        _ => panic!("expected Deliver, got a different outcome"),
    }
}

#[test]
fn test_wrong_key_cannot_unwrap_a_hop_it_is_not_addressed_to() {
    let (_s1, n1) = make_node("10.0.0.1:9001");
    let (_s2, n2) = make_node("10.0.0.2:9001");
    let (_s3, n3) = make_node("10.0.0.3:9001");
    let path = vec![n1, n2, n3];

    let packet_bytes = mixnet::build_packet(
        b"secret payload",
        &path,
        Duration::from_millis(1),
        mixnet::DEFAULT_MIX_PAYLOAD_SIZE,
    )
    .unwrap();

    // An adversary's own freshly-generated key must fail closed, not
    // produce a plausible-looking (wrong) forward/deliver decision.
    let (attacker_secret, _) = mixnet::generate_node_keypair();
    let result = mixnet::process_packet(&packet_bytes, &attacker_secret);
    assert!(
        matches!(result, Err(PardaError::MixRouting(_))),
        "unwrapping with an unaddressed key must return Err(MixRouting), not succeed"
    );
}

#[test]
fn test_drop_cover_packet_terminates_in_drop_cover_not_deliver() {
    let (s1, n1) = make_node("10.0.0.1:9001");
    let (s2, n2) = make_node("10.0.0.2:9001");
    let (s3, n3) = make_node("10.0.0.3:9001");
    let path = vec![n1, n2, n3];
    let secrets = vec![
        ("n1".to_string(), s1),
        ("n2".to_string(), s2),
        ("n3".to_string(), s3),
    ];

    let packet_bytes = mixnet::build_packet_to(
        b"parda-drop-cover",
        &path,
        Duration::from_millis(1),
        mixnet::DEFAULT_MIX_PAYLOAD_SIZE,
        mixnet::COVER_DESTINATION_TAG,
    )
    .unwrap();

    match drive_to_completion(packet_bytes, &secrets) {
        UnwrapOutcome::DropCover => {}
        _ => panic!("a packet tagged COVER_DESTINATION_TAG must terminate as DropCover, never Deliver"),
    }
}

#[test]
fn test_final_hop_with_unrecognised_destination_tag_is_refused_not_guessed() {
    let (s1, n1) = make_node("10.0.0.1:9001");
    let (s2, n2) = make_node("10.0.0.2:9001");
    let (s3, n3) = make_node("10.0.0.3:9001");
    let path = vec![n1, n2, n3];

    let packet_bytes = mixnet::build_packet_to(
        b"payload",
        &path,
        Duration::from_millis(1),
        mixnet::DEFAULT_MIX_PAYLOAD_SIZE,
        b"SOME-OTHER-TAG",
    )
    .unwrap();

    // Walk the first two hops in known path order (only the final hop
    // inspects the destination tag), then assert the final hop errors.
    let after_hop1 = match mixnet::process_packet(&packet_bytes, &s1).unwrap() {
        UnwrapOutcome::Forward { packet_bytes, .. } => packet_bytes,
        _ => panic!("expected first hop to forward"),
    };
    let after_hop2 = match mixnet::process_packet(&after_hop1, &s2).unwrap() {
        UnwrapOutcome::Forward { packet_bytes, .. } => packet_bytes,
        _ => panic!("expected second hop to forward"),
    };
    let final_result = mixnet::process_packet(&after_hop2, &s3);
    assert!(
        matches!(final_result, Err(PardaError::MixRouting(_))),
        "a final hop with an unrecognised destination tag must be refused, not delivered or guessed at"
    );
}

#[test]
fn test_build_packet_rejects_path_shorter_than_minimum() {
    let (_s1, n1) = make_node("10.0.0.1:9001");
    let (_s2, n2) = make_node("10.0.0.2:9001");
    let path = vec![n1, n2]; // below MIN_PATH_LENGTH (3)

    let result = mixnet::build_packet(
        b"payload",
        &path,
        Duration::from_millis(1),
        mixnet::DEFAULT_MIX_PAYLOAD_SIZE,
    );
    assert!(matches!(result, Err(PardaError::MixRouting(_))));
}

#[test]
fn test_topology_choose_path_rejects_when_too_few_nodes() {
    let (_s1, n1) = make_node("10.0.0.1:9001");
    let (_s2, n2) = make_node("10.0.0.2:9001");
    let topology = MixTopology::new(vec![n1, n2]);

    let result = topology.choose_path(3);
    assert!(matches!(result, Err(PardaError::MixRouting(_))));
}

#[test]
fn test_topology_choose_path_returns_distinct_nodes() {
    let nodes: Vec<MixNodeDescriptor> = (0..5)
        .map(|i| make_node(&format!("10.0.0.{i}:9001")).1)
        .collect();
    let topology = MixTopology::new(nodes);

    let path = topology.choose_path(3).unwrap();
    assert_eq!(path.len(), 3);
    let mut addresses: Vec<&str> = path.iter().map(|n| n.address.as_str()).collect();
    addresses.sort();
    addresses.dedup();
    assert_eq!(addresses.len(), 3, "chosen path must not repeat a node");
}

// ─── MixTransport fail-closed behaviour ─────────────────────────────────────

#[tokio::test]
async fn test_mix_transport_send_fails_closed_when_first_hop_unreachable() {
    // A syntactically valid topology whose address nothing listens on.
    // `MixTransport::send`'s implementation contains no code path to the
    // relay other than through the mix network's first hop — see
    // `protocol/src/transport.rs::MixTransport::send`. If the first hop
    // is unreachable, `send` returning `Err` is therefore sufficient to
    // establish "no envelope reached the relay": there is no fallback
    // branch to reach it through.
    let nodes: Vec<MixNodeDescriptor> = (0..3)
        .map(|i| make_node(&format!("127.0.0.1:{}", 1 + i)).1) // port 1-3: nothing binds there
        .collect();
    let topology = MixTopology::new(nodes);
    let transport = MixTransport::new(topology, "http://127.0.0.1:9998");

    let envelope = sample_envelope();
    let result = transport.send(&envelope).await;
    assert!(
        matches!(result, Err(PardaError::Transport(_))),
        "send() over an unreachable mix network must return Err, not silently succeed"
    );
}

#[tokio::test]
async fn test_mix_transport_send_rejects_path_length_below_minimum() {
    let nodes: Vec<MixNodeDescriptor> = (0..3)
        .map(|i| make_node(&format!("127.0.0.1:{}", 10 + i)).1)
        .collect();
    let topology = MixTopology::new(nodes);
    let transport = MixTransport::new(topology, "http://127.0.0.1:9998").with_path_length(2);

    let envelope = sample_envelope();
    let result = transport.send(&envelope).await;
    assert!(
        matches!(result, Err(PardaError::MixRouting(_))),
        "a path length below MIN_PATH_LENGTH must be refused before any network call, not silently accepted"
    );
}
