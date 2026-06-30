//! Axum route handlers for the PARDA relay server.
//!
//! ## API v1 surface
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | POST | `/v1/keys/{user_id}` | Upload / replace prekey bundle |
//! | GET  | `/v1/keys/{user_id}` | Fetch prekey bundle for a user |
//! | POST | `/v1/messages/{recipient_id}` | Submit encrypted envelope |
//! | GET  | `/v1/messages/{user_id}` | Fetch and drain pending messages |
//! | DELETE | `/v1/messages/{user_id}/{msg_id}` | Ack and delete a single message |
//! | GET  | `/health` | Health check (no auth, no state) |
//!
//! The relay inspects **only** routing metadata (`recipient_id`).
//! It stores the `ciphertext` blob verbatim and cannot decrypt it.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use uuid::Uuid;

use crate::{
    models::{ApiOk, FetchMessagesResponse, MessageEnvelope, PreKeyBundleJson, StoredEnvelope},
    store::SharedRelayStore,
};

// ─── Health ───────────────────────────────────────────────────────────────────

pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

// ─── Prekey bundle endpoints ──────────────────────────────────────────────────

/// `POST /v1/keys/{user_id}` — upload or refresh a prekey bundle.
pub async fn upload_prekey_bundle(
    State(store): State<SharedRelayStore>,
    Path(user_id): Path<String>,
    Json(bundle): Json<PreKeyBundleJson>,
) -> impl IntoResponse {
    tracing::info!(user_id = %user_id, "prekey bundle uploaded");
    store.put_bundle(user_id, bundle).await;
    (StatusCode::OK, Json(ApiOk::with_message("bundle stored")))
}

/// `GET /v1/keys/{user_id}` — fetch another user's prekey bundle.
pub async fn get_prekey_bundle(
    State(store): State<SharedRelayStore>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    match store.get_bundle(&user_id).await {
        Some(bundle) => (StatusCode::OK, Json(bundle)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no prekey bundle found for user" })),
        )
            .into_response(),
    }
}

// ─── Message endpoints ────────────────────────────────────────────────────────

/// `POST /v1/messages/{recipient_id}` — submit an encrypted envelope.
///
/// The relay does NOT read `ciphertext`. It assigns a UUID message ID and
/// queues the envelope for the recipient.
pub async fn submit_message(
    State(store): State<SharedRelayStore>,
    Path(recipient_id): Path<String>,
    Json(envelope): Json<MessageEnvelope>,
) -> impl IntoResponse {
    // Sanity check: recipient in path must match envelope field.
    if envelope.recipient_id != recipient_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "recipient_id path param does not match envelope.recipient_id"
            })),
        )
            .into_response();
    }

    let msg_id = Uuid::new_v4().to_string();
    tracing::debug!(
        msg_id = %msg_id,
        sender = %envelope.sender_id,
        recipient = %recipient_id,
        envelope_type = ?envelope.envelope_type,
        "envelope queued"
    );

    let stored = StoredEnvelope {
        id: msg_id.clone(),
        envelope,
    };
    store.enqueue(recipient_id, stored).await;

    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "ok": true, "message_id": msg_id })),
    )
        .into_response()
}

/// `GET /v1/messages/{user_id}` — drain and return all pending messages.
///
/// Messages are removed from the queue on retrieval. The client is
/// responsible for persisting them locally before acknowledging.
pub async fn fetch_messages(
    State(store): State<SharedRelayStore>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let messages = store.drain(&user_id).await;
    tracing::debug!(user_id = %user_id, count = messages.len(), "messages fetched");
    Json(FetchMessagesResponse { messages })
}

/// `DELETE /v1/messages/{user_id}/{msg_id}` — delete a specific message.
///
/// Used when the client wants to acknowledge individual messages rather than
/// draining the whole queue (e.g., after guaranteed local persistence).
pub async fn delete_message(
    State(store): State<SharedRelayStore>,
    Path((user_id, msg_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let deleted = store.delete_message(&user_id, &msg_id).await;
    if deleted {
        (StatusCode::OK, Json(ApiOk::success()))
    } else {
        (StatusCode::NOT_FOUND, Json(ApiOk::with_message("message not found")))
    }
}
