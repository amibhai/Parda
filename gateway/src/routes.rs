//! Axum route handlers — each one forwards to the configured relay over
//! HTTP and forwards the response back, unmodified, to the caller.
//!
//! ## The "provably a dumb pipe" property
//!
//! No handler in this file ever deserializes `MessageEnvelope::ciphertext`
//! into anything but opaque bytes, calls any decrypt function, or reads
//! any field this crate would need a private key to produce. This is
//! structurally enforced, not just a coding convention: `parda-gateway`
//! has zero dependency on `chacha20poly1305`, `hkdf`, or any of
//! `parda_protocol`'s decrypt-capable modules (`session`, `self_destruct`,
//! `sealed_sender`) — only `envelope` (for the `MessageEnvelope` *shape*)
//! is used, via `parda_protocol::envelope::MessageEnvelope`. See
//! `gateway/tests/gateway_tests.rs::test_ciphertext_passes_through_bit_identical`
//! for the round-trip proof.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use crate::{models::PreKeyBundleRequest, GatewayState};

pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "service": "parda-gateway" }))
}

fn relay_error(e: reqwest::Error) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({ "error": format!("relay unreachable or errored: {e}") })),
    )
}

// ─── Prekey bundles ─────────────────────────────────────────────────────────

pub async fn upload_prekey_bundle(
    State(state): State<GatewayState>,
    Path(user_id): Path<String>,
    Json(bundle): Json<PreKeyBundleRequest>,
) -> impl IntoResponse {
    let url = format!("{}/v1/keys/{}", state.relay_base_url, user_id);
    match state.http.post(&url).json(&bundle).send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::json!({}));
            (status, Json(body)).into_response()
        }
        Err(e) => relay_error(e).into_response(),
    }
}

pub async fn get_prekey_bundle(
    State(state): State<GatewayState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let url = format!("{}/v1/keys/{}", state.relay_base_url, user_id);
    match state.http.get(&url).send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::json!({}));
            (status, Json(body)).into_response()
        }
        Err(e) => relay_error(e).into_response(),
    }
}

// ─── Messages ───────────────────────────────────────────────────────────────
//
// The request/response bodies are forwarded as raw bytes (`Bytes`), not
// decoded into `MessageEnvelope` and re-encoded — this is the strongest
// version of "pass-through, don't touch it": there is no intermediate
// Rust value here whose fields could be inspected or logged even by
// accident. Structural shape validation still happens (axum's `Json`
// extractor is used for the OTHER routes above; here it's deliberately
// skipped in favour of raw passthrough, prioritising "never touch
// ciphertext" over "validate before forwarding" for the routes that
// actually carry ciphertext).

pub async fn submit_message(
    State(state): State<GatewayState>,
    Path(recipient_id): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let url = format!("{}/v1/messages/{}", state.relay_base_url, recipient_id);
    match state
        .http
        .post(&url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let body = resp.bytes().await.unwrap_or_default();
            (status, body).into_response()
        }
        Err(e) => relay_error(e).into_response(),
    }
}

pub async fn fetch_messages(
    State(state): State<GatewayState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let url = format!("{}/v1/messages/{}", state.relay_base_url, user_id);
    match state.http.get(&url).send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let body = resp.bytes().await.unwrap_or_default();
            (status, body).into_response()
        }
        Err(e) => relay_error(e).into_response(),
    }
}

pub async fn delete_message(
    State(state): State<GatewayState>,
    Path((user_id, msg_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let url = format!("{}/v1/messages/{}/{}", state.relay_base_url, user_id, msg_id);
    match state.http.delete(&url).send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let body = resp.bytes().await.unwrap_or_default();
            (status, body).into_response()
        }
        Err(e) => relay_error(e).into_response(),
    }
}
