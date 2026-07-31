//! Sub-Phase 2B degradation tests: a misbehaving mix node must degrade
//! the system to "message delayed" or "message lost", never to
//! "message deanonymized" or a silent wrong delivery.
//!
//! The malicious/broken node in each test is a small standalone Axum
//! handler defined right here in the test — not a flag bolted onto
//! `parda_mixnode`'s production router. It still participates honestly
//! at the *cryptographic* layer (it holds a real keypair and calls the
//! same `parda_protocol::mixnet::process_packet` production code calls)
//! so these tests exercise real Sphinx unwrap/forward against a
//! deliberately faulty *operational* decision, which is the actual
//! threat this sub-phase's Definition of Done item is about.

mod common;

use std::{
    sync::Arc,
    time::Duration,
};

use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse, routing::post, Router};
use parda_protocol::{
    envelope::{EnvelopeType, MessageEnvelope},
    mixnet::{self, MixNodeDescriptor, UnwrapOutcome},
};

struct FaultyNodeState {
    secret_key: mixnet::StaticSecret,
    http: reqwest::Client,
    /// If `Some`, forwarding sleeps this long *in addition to* the
    /// packet's own instructed delay before honoring it. If `None`, the
    /// node silently drops anything it would otherwise forward.
    extra_delay: Option<Duration>,
}

async fn faulty_handler(
    State(state): State<Arc<FaultyNodeState>>,
    body: Bytes,
) -> impl IntoResponse {
    match mixnet::process_packet(&body, &state.secret_key) {
        Ok(UnwrapOutcome::Forward {
            next_hop_address,
            delay,
            packet_bytes,
        }) => match state.extra_delay {
            None => {
                // Drop: unwrap correctly, then simply never forward.
            }
            Some(extra) => {
                let http = state.http.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay + extra).await;
                    let url = format!("http://{next_hop_address}/mix/packet");
                    let _ = http.post(&url).body(packet_bytes).send().await;
                });
            }
        },
        Ok(_) | Err(_) => {
            // Not exercised by these tests (faulty node is always an
            // interior hop), but fail closed rather than panic either way.
        }
    }
    StatusCode::ACCEPTED
}

async fn spawn_faulty_node(extra_delay: Option<Duration>) -> MixNodeDescriptor {
    let (secret, public) = mixnet::generate_node_keypair();
    let state = Arc::new(FaultyNodeState {
        secret_key: secret,
        http: reqwest::Client::new(),
        extra_delay,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let router = Router::new()
        .route("/mix/packet", post(faulty_handler))
        .with_state(state);
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("faulty node server error");
    });
    MixNodeDescriptor {
        address,
        public_key: public,
    }
}

fn test_envelope(recipient_id: &str) -> MessageEnvelope {
    MessageEnvelope {
        sender_id: "degradation-test-sender".to_string(),
        recipient_id: recipient_id.to_string(),
        ciphertext: b"correct plaintext must survive or the message must not arrive at all".to_vec(),
        envelope_type: EnvelopeType::Ratchet,
        timestamp_ms: 1_753_900_000_000,
        version: 2,
        sealed_sender: false,
        routing_hint: None,
        self_destruct_at: None,
    }
}

#[tokio::test]
async fn test_dropped_packet_degrades_to_never_arrives_not_misdelivery() {
    let relay = common::spawn_relay().await;
    let honest_entry = common::spawn_mixnode(&relay.base_url).await;
    let dropper = spawn_faulty_node(None).await; // hop 2: silently drops
    let honest_exit = common::spawn_mixnode(&relay.base_url).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let path = vec![honest_entry, dropper, honest_exit];
    let recipient_id = "degradation-drop-recipient";
    let envelope = test_envelope(recipient_id);
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
    let packet_bytes = mixnet::build_packet(
        &envelope_bytes,
        &path,
        Duration::from_millis(20),
        mixnet::DEFAULT_MIX_PAYLOAD_SIZE,
    )
    .unwrap();

    let http = reqwest::Client::new();
    let url = format!("http://{}/mix/packet", path[0].address);
    let response = http
        .post(&url)
        .body(packet_bytes)
        .send()
        .await
        .expect("first (honest) hop must accept the packet");
    // The sender only ever learns "the first hop accepted delivery" —
    // never "which downstream hop dropped it". That the response here is
    // a plain 202 regardless of the eventual drop *is* the property
    // under test: no leak of where/whether a later hop misbehaves.
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let never_arrived = tokio::time::timeout(
        Duration::from_millis(600),
        common::wait_for_delivery(&relay.store, recipient_id, Duration::from_secs(600)),
    )
    .await;
    assert!(
        never_arrived.is_err(),
        "a message routed through a dropping hop must never arrive at the relay — \
         it must not be silently rerouted or misdelivered elsewhere"
    );
}

#[tokio::test]
async fn test_delayed_hop_still_delivers_correct_plaintext_eventually() {
    let relay = common::spawn_relay().await;
    let honest_entry = common::spawn_mixnode(&relay.base_url).await;
    let slow = spawn_faulty_node(Some(Duration::from_millis(800))).await; // hop 2: +800ms
    let honest_exit = common::spawn_mixnode(&relay.base_url).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let path = vec![honest_entry, slow, honest_exit];
    let recipient_id = "degradation-delay-recipient";
    let envelope = test_envelope(recipient_id);
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
    let packet_bytes = mixnet::build_packet(
        &envelope_bytes,
        &path,
        Duration::from_millis(20),
        mixnet::DEFAULT_MIX_PAYLOAD_SIZE,
    )
    .unwrap();

    let http = reqwest::Client::new();
    let url = format!("http://{}/mix/packet", path[0].address);
    let send_time = tokio::time::Instant::now();
    http.post(&url)
        .body(packet_bytes)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Baseline (no injected fault) total latency is on the order of
    // 3 * 20ms average delay — generously bounded, this asserts the
    // message still gets there, and gets there *later* than that
    // baseline would predict, not that it silently vanished or arrived
    // suspiciously fast via some fallback path.
    let delivered = common::wait_for_delivery(&relay.store, recipient_id, Duration::from_secs(5)).await;
    let elapsed = send_time.elapsed();

    assert_eq!(delivered.len(), 1);
    let recovered: MessageEnvelope =
        serde_json::from_str(&serde_json::to_string(&delivered[0].envelope).unwrap()).unwrap();
    assert_eq!(recovered.ciphertext, envelope.ciphertext, "plaintext must survive intact");
    assert_eq!(recovered.recipient_id, recipient_id);
    assert!(
        elapsed >= Duration::from_millis(800),
        "delivery ({elapsed:?}) should reflect the injected extra delay, not bypass it"
    );
}
