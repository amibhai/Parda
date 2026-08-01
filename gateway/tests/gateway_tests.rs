//! Gateway integration tests, against a minimal stand-in relay (not the
//! real `parda-relay` crate — see below for why) run on a real loopback
//! TCP port.
//!
//! ## Why a stand-in relay, not `parda-relay` itself
//!
//! `parda-relay` requires `rusqlite`'s vendored-SQLCipher build, which
//! needs a complete Perl (`server/src/store.rs` module docs;
//! `docs/phase1-architecture.md` §11). `parda-gateway`'s own production
//! code has no such dependency — deliberately, per `lib.rs` module docs,
//! so it stays buildable without that toolchain requirement. Pulling in
//! `parda-relay` as a *test*-only dependency would reintroduce that
//! requirement for this crate's tests even though nothing about what's
//! under test here needs SQLCipher specifically — these tests are about
//! the gateway's forwarding/passthrough behavior, not the relay's
//! storage layer (which `server/tests/` already covers). The stand-in
//! implements just enough of the relay's `/v1/keys` and `/v1/messages`
//! surface, in-memory, to exercise that behavior.

use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use parda_gateway::{app, GatewayState};

#[derive(Default)]
struct StubRelayState {
    bundles: Mutex<std::collections::HashMap<String, serde_json::Value>>,
    messages: Mutex<std::collections::HashMap<String, Vec<serde_json::Value>>>,
}

type SharedStub = Arc<StubRelayState>;

async fn stub_upload_bundle(
    State(state): State<SharedStub>,
    Path(user_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    state.bundles.lock().unwrap().insert(user_id, body);
    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

async fn stub_get_bundle(State(state): State<SharedStub>, Path(user_id): Path<String>) -> impl IntoResponse {
    match state.bundles.lock().unwrap().get(&user_id).cloned() {
        Some(b) => (StatusCode::OK, Json(b)).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response(),
    }
}

async fn stub_submit_message(
    State(state): State<SharedStub>,
    Path(recipient_id): Path<String>,
    Json(envelope): Json<serde_json::Value>,
) -> impl IntoResponse {
    state.messages.lock().unwrap().entry(recipient_id).or_default().push(envelope);
    (StatusCode::CREATED, Json(serde_json::json!({ "ok": true, "message_id": "stub-1" })))
}

async fn stub_fetch_messages(State(state): State<SharedStub>, Path(user_id): Path<String>) -> impl IntoResponse {
    let drained = state.messages.lock().unwrap().remove(&user_id).unwrap_or_default();
    Json(serde_json::json!({ "messages": drained }))
}

async fn stub_delete_message(
    State(_state): State<SharedStub>,
    Path((_user_id, _msg_id)): Path<(String, String)>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

fn stub_relay_router() -> Router {
    let state: SharedStub = Arc::new(StubRelayState::default());
    Router::new()
        .route("/v1/keys/:user_id", post(stub_upload_bundle))
        .route("/v1/keys/:user_id", get(stub_get_bundle))
        .route("/v1/messages/:user_id", post(stub_submit_message))
        .route("/v1/messages/:user_id", get(stub_fetch_messages))
        .route("/v1/messages/:user_id/:msg_id", axum::routing::delete(stub_delete_message))
        .with_state(state)
}

async fn spawn_stub_relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, stub_relay_router()).await.unwrap();
    });
    base_url
}

async fn spawn_gateway(relay_base_url: &str) -> (reqwest::Client, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();
    let state = GatewayState::new(relay_base_url.to_string());
    tokio::spawn(async move {
        axum::serve(listener, app(state)).await.unwrap();
    });
    // give the listener a moment to actually accept
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    (reqwest::Client::new(), format!("http://{gateway_addr}"))
}

#[tokio::test]
async fn test_ciphertext_passes_through_bit_identical() {
    let relay_base = spawn_stub_relay().await;
    let (http, gateway_url) = spawn_gateway(&relay_base).await;

    // A ciphertext value distinctive enough that any transformation
    // (re-encoding, truncation, mutation) would be obvious.
    let envelope = serde_json::json!({
        "sender_id": "alice",
        "recipient_id": "bob",
        "ciphertext": "cGFyZGEtZ2F0ZXdheS1wYXNzdGhyb3VnaC1jYW5hcnk=",
        "envelope_type": "ratchet",
        "timestamp_ms": 1_753_900_000_000u64,
        "version": 2,
        "sealed_sender": false
    });

    let submit_resp = http
        .post(format!("{gateway_url}/api/v1/messages/bob"))
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert_eq!(submit_resp.status(), 201);

    let fetch_resp = http
        .get(format!("{gateway_url}/api/v1/messages/bob"))
        .send()
        .await
        .unwrap();
    assert_eq!(fetch_resp.status(), 200);
    let body: serde_json::Value = fetch_resp.json().await.unwrap();
    let fetched_ciphertext = body["messages"][0]["ciphertext"].as_str().unwrap();

    assert_eq!(
        fetched_ciphertext, "cGFyZGEtZ2F0ZXdheS1wYXNzdGhyb3VnaC1jYW5hcnk=",
        "ciphertext must pass through the gateway bit-identical, never re-encoded or inspected"
    );
}

#[tokio::test]
async fn test_prekey_bundle_round_trips_through_gateway() {
    let relay_base = spawn_stub_relay().await;
    let (http, gateway_url) = spawn_gateway(&relay_base).await;

    let bundle = serde_json::json!({
        "registration_id": 42,
        "device_id": 1,
        "identity_key": "aWRlbnRpdHkta2V5",
        "signed_prekey_id": 1,
        "signed_prekey_public": "c2lnbmVkLXByZWtleQ==",
        "signed_prekey_signature": "c2ln",
        "one_time_prekey_id": 5,
        "one_time_prekey_public": "b3Rwaw=="
    });

    let upload = http
        .post(format!("{gateway_url}/api/v1/keys/carol"))
        .json(&bundle)
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), 200);

    let fetched = http
        .get(format!("{gateway_url}/api/v1/keys/carol"))
        .send()
        .await
        .unwrap();
    assert_eq!(fetched.status(), 200);
    let fetched_body: serde_json::Value = fetched.json().await.unwrap();
    assert_eq!(fetched_body["registration_id"], 42);
    assert_eq!(fetched_body["identity_key"], "aWRlbnRpdHkta2V5");
}

#[tokio::test]
async fn test_gateway_returns_bad_gateway_when_relay_unreachable() {
    // Port 1 on loopback: nothing listens there.
    let (http, gateway_url) = spawn_gateway("http://127.0.0.1:1").await;

    let resp = http
        .get(format!("{gateway_url}/api/v1/messages/nobody"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        502,
        "an unreachable relay must surface as a clear gateway error, not a silent empty success"
    );
}
