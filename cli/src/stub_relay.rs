//! An in-process, in-memory stand-in for `parda-relay`, used only so
//! `parda-cli demo` runs end-to-end with zero setup.
//!
//! **This is not `parda-relay`.** The real relay (`server/` — SQLCipher
//! persistence, sealed-sender certificate authority) needs a vendored
//! SQLCipher/OpenSSL build (Perl toolchain requirement — see
//! `client-store/src/lib.rs` module docs for the same gap affecting this
//! workspace). This stub implements just enough of the relay's
//! `/v1/keys` and `/v1/messages` HTTP surface, in memory, for the demo
//! to exercise `parda_protocol::transport::DirectTransport` against a
//! real HTTP server — the transport code path is real; this HTTP
//! endpoint behind it is a convenience stand-in, not a production
//! component. Point `--relay-url` at a real running `parda-relay`
//! instead for a genuine end-to-end run once that's built.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

#[derive(Default)]
struct StubState {
    bundles: Mutex<HashMap<String, serde_json::Value>>,
    messages: Mutex<HashMap<String, Vec<serde_json::Value>>>,
}

type Shared = Arc<StubState>;

async fn upload_bundle(
    State(state): State<Shared>,
    Path(user_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    state.bundles.lock().unwrap().insert(user_id, body);
    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

async fn get_bundle(State(state): State<Shared>, Path(user_id): Path<String>) -> impl IntoResponse {
    match state.bundles.lock().unwrap().get(&user_id).cloned() {
        Some(b) => (StatusCode::OK, Json(b)).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "no bundle"}))).into_response(),
    }
}

async fn submit_message(
    State(state): State<Shared>,
    Path(recipient_id): Path<String>,
    Json(envelope): Json<serde_json::Value>,
) -> impl IntoResponse {
    state.messages.lock().unwrap().entry(recipient_id).or_default().push(envelope);
    (StatusCode::CREATED, Json(serde_json::json!({ "ok": true, "message_id": "demo" })))
}

async fn fetch_messages(State(state): State<Shared>, Path(user_id): Path<String>) -> impl IntoResponse {
    let drained = state.messages.lock().unwrap().remove(&user_id).unwrap_or_default();
    Json(serde_json::json!({ "messages": drained }))
}

fn router() -> Router {
    let state: Shared = Arc::new(StubState::default());
    Router::new()
        .route("/v1/keys/:user_id", post(upload_bundle))
        .route("/v1/keys/:user_id", get(get_bundle))
        .route("/v1/messages/:user_id", post(submit_message))
        .route("/v1/messages/:user_id", get(fetch_messages))
        .with_state(state)
}

/// Bind a stub relay on an ephemeral loopback port and return its base
/// URL (`http://127.0.0.1:PORT`).
pub async fn spawn() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind stub relay port");
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, router()).await.expect("stub relay server error");
    });
    base_url
}
