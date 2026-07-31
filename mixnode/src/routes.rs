//! Axum route handlers for a mix node.

use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use parda_protocol::mixnet;

use crate::{mixing, SharedMixNodeState};

pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

/// `GET /mix/pubkey` — this node's X25519 public key, base64-encoded.
/// Used by operators/tests bootstrapping a `MixTopology`.
pub async fn pubkey(State(state): State<SharedMixNodeState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "public_key": STANDARD.encode(state.public_key.as_bytes())
    }))
}

/// `POST /mix/packet` — receive a raw Sphinx packet as the request body,
/// unwrap one onion layer, and schedule the resulting forward/deliver/
/// drop action.
///
/// Responds as soon as the packet is validly unwrapped — actual
/// forwarding or delivery happens asynchronously after the mixing delay
/// (see `mixing::schedule`), so HTTP response latency never reveals the
/// sampled delay to whoever sent this node the packet.
pub async fn receive_packet(
    State(state): State<SharedMixNodeState>,
    body: Bytes,
) -> impl IntoResponse {
    match mixnet::process_packet(&body, &state.secret_key) {
        Ok(outcome) => {
            mixing::schedule(state, outcome);
            (StatusCode::ACCEPTED, Json(serde_json::json!({ "ok": true })))
        }
        Err(e) => {
            tracing::warn!(error = %e, "rejected malformed/undecryptable mix packet");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        }
    }
}
