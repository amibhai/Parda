//! # PARDA Relay — Malicious Relay Adversarial Test (Sub-Phase 2A)
//!
//! Simulates an adversary who has **full access to the real relay
//! process**: every log line it emits and every byte it holds in its
//! in-memory store. Sends a corpus of N sealed-sender messages from
//! distinct identities through the real `parda_relay::app()` router (the
//! same one `main.rs` serves), then inspects both surfaces and asserts
//! neither contains anything that identifies a sender.
//!
//! This does not test cryptography (`protocol/tests/sealed_sender_tests.rs`
//! covers that) — it tests that *this server's code path* upholds the
//! "relay never touches sender identity" requirement in practice, the same
//! way `test_forward_secrecy_stale_ciphertext_rejected` in
//! `protocol/tests/crypto_tests.rs` tests a property adversarially rather
//! than just confirming the happy path.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum_test::TestServer;
use parda_protocol::{
    envelope::EnvelopeType, identity::LocalIdentity, sealed_sender::CertificateAuthority,
    session::SessionManager, store::InMemorySignalProtocolStore, ProtocolAddress,
};
use parda_relay::{app, store::RelayStore};
use serde_json::json;
use tracing_subscriber::fmt::MakeWriter;

/// Writes every log line into a shared buffer instead of stdout, so the
/// test can inspect exactly what the relay process would have logged.
#[derive(Clone, Default)]
struct CapturingWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturingWriter {
    type Writer = CapturingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn make_manager(name: &str, reg_id: u32) -> (SessionManager, LocalIdentity) {
    let identity = LocalIdentity::generate(reg_id).expect("generate identity");
    let mut store = InMemorySignalProtocolStore::new(identity.identity_key_pair, reg_id);
    store.store_prekey_batch(&identity.one_time_prekeys).unwrap();
    store.store_signed_prekey_record(&identity.signed_prekey).unwrap();
    let addr = ProtocolAddress::new(name.to_string(), 1.into());
    (SessionManager::new(addr, store), identity)
}

/// Sends `count` sealed-sender messages from distinct senders to `bob`,
/// each carrying its sender's real name in the plaintext (to prove the
/// *ciphertext* isn't what's protecting them — only sealed sender is), and
/// returns (sender names used, everything the relay logged, everything the
/// relay's own store held for `bob` afterwards).
fn run_malicious_relay_scenario(count: usize) -> (Vec<String>, String, Vec<serde_json::Value>) {
    let log_buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = CapturingWriter(log_buffer.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .finish();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let (sender_names, stored) = tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async move {
            let store = RelayStore::open_ephemeral();
            let server = TestServer::new(app(store.clone())).unwrap();

            let (bob, bob_identity) = make_manager("bob", 999);
            let bob_addr = bob.local_address.clone();
            // Bob's prekey bundle isn't uploaded through the relay API for
            // this test — senders build sessions with him directly, exactly
            // like protocol/tests/sealed_sender_tests.rs. That's enough to
            // produce real Sphinx-free sealed envelopes to submit.
            let bob_bundle = bob_identity.build_prekey_bundle().unwrap();

            let ca = CertificateAuthority::new().unwrap();

            let mut sender_names = Vec::new();
            for i in 0..count {
                let name = format!("agent-{i:03}-classified-codename");
                sender_names.push(name.clone());

                let (mut sender, sender_identity) = make_manager(&name, 100 + i as u32);
                sender.initiate_session(&bob_addr, &bob_bundle).await.unwrap();

                let cert = ca
                    .issue_sender_certificate(
                        name.clone(),
                        *sender_identity.identity_key_pair.public_key(),
                        1u32.into(),
                        Duration::from_secs(3600),
                    )
                    .unwrap();

                let envelope = sender
                    .encrypt_sealed(&bob_addr, format!("message from {name}").as_bytes(), &cert)
                    .await
                    .unwrap();
                assert_eq!(envelope.envelope_type, EnvelopeType::SealedSender);

                let resp = server
                    .post(&format!("/v1/messages/{}", bob_addr.name()))
                    .json(&envelope)
                    .await;
                resp.assert_status(axum::http::StatusCode::CREATED);

                // The relay's own HTTP response is adversary-visible too.
                let resp_text = resp.text();
                assert!(
                    !resp_text.contains(&name),
                    "relay's submit-message response leaked sender name: {resp_text}"
                );
            }

            // Pull exactly what the relay's in-memory store holds for Bob —
            // the same data structure `fetch_messages` serves over HTTP.
            let stored = store.drain(bob_addr.name()).await;
            let stored_json: Vec<serde_json::Value> = stored
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .collect();

            (sender_names, stored_json)
        })
    });

    let log_text = String::from_utf8(log_buffer.lock().unwrap().clone()).unwrap();
    (sender_names, log_text, stored)
}

#[test]
fn test_malicious_relay_cannot_recover_sender_identity() {
    const N: usize = 12;
    let (sender_names, logs, stored) = run_malicious_relay_scenario(N);

    assert_eq!(stored.len(), N, "all N messages must have reached the relay's store");

    // Sanity check the harness itself: recipient routing metadata (which
    // sealed sender does *not* hide) must actually be present, proving this
    // test exercises the real store rather than trivially passing on empty
    // data.
    for entry in &stored {
        assert_eq!(entry["recipient_id"], json!("bob"));
        assert_eq!(entry["sealed_sender"], json!(true));
        assert_eq!(entry["envelope_type"], json!("sealed_sender"));
    }

    for name in &sender_names {
        for entry in &stored {
            let entry_str = entry.to_string();
            assert!(
                !entry_str.contains(name),
                "relay store entry contained sender-identifying string {name:?}: {entry_str}"
            );
        }
        assert!(
            !logs.contains(name),
            "relay log output contained sender-identifying string {name:?}"
        );

        // The stored `sender_id` field specifically must be empty, not just
        // "doesn't happen to contain the name" (belt and suspenders).
        for entry in &stored {
            assert_eq!(
                entry["sender_id"],
                json!(""),
                "stored envelope must not carry a populated sender_id"
            );
        }
    }
}
