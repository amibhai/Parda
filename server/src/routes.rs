//! Axum route handlers for the PARDA relay server.
//!
//! ## API v1 surface
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | POST | `/v1/keys/{user_id}` | Upload / replace prekey bundle |
//! | GET  | `/v1/keys/{user_id}` | Fetch prekey bundle for a user |
//! | POST | `/v1/certs/{user_id}` | Issue a sealed-sender certificate (Phase 2) |
//! | GET  | `/v1/certs/trust-root` | Fetch the sealed-sender trust root public key (Phase 2) |
//! | POST | `/v1/messages/{recipient_id}` | Submit encrypted envelope |
//! | GET  | `/v1/messages/{user_id}` | Fetch and drain pending messages |
//! | DELETE | `/v1/messages/{user_id}/{msg_id}` | Ack and delete a single message |
//! | GET  | `/health` | Health check (no auth, no state) |
//!
//! ## Sender-identity discipline (Phase 2)
//!
//! Every handler in this file, and everything it logs, is written to never
//! read or print `envelope.sender_id`. The relay routes on `recipient_id`
//! only. This is enforced structurally (the field is simply never accessed
//! below) and checked by `server/tests/sealed_sender_relay_tests.rs`, which
//! captures the relay's own trace output and store contents and asserts no
//! sender-linkable material appears in either.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use uuid::Uuid;

use crate::{
    models::{
        ApiOk, FetchMessagesResponse, IssueSenderCertRequest, MessageEnvelope, PreKeyBundleJson,
        SenderCertificateResponse, StoredEnvelope, TrustRootResponse,
    },
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

// ─── Sealed-sender certificate endpoints (Phase 2) ────────────────────────────

/// `POST /v1/certs/{user_id}` — issue a sealed-sender `SenderCertificate`
/// binding `user_id` to the identity key presented in the request body.
///
/// Same trust posture as `/v1/keys/{user_id}`: no account authentication
/// gates this (none exists yet). What this certificate authenticates is
/// *senders to recipients* once embedded in a sealed-sender message — it
/// does not authenticate the caller to the relay. See
/// `parda_protocol::sealed_sender` module docs and `docs/THREAT_MODEL.md`.
pub async fn issue_sender_certificate(
    State(store): State<SharedRelayStore>,
    Path(user_id): Path<String>,
    Json(req): Json<IssueSenderCertRequest>,
) -> impl IntoResponse {
    let identity_key_bytes = match STANDARD.decode(&req.identity_key) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "identity_key is not valid base64" })),
            )
                .into_response();
        }
    };
    let identity_key = match parda_protocol::PublicKey::try_from(identity_key_bytes.as_slice()) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "identity_key is not a valid public key" })),
            )
                .into_response();
        }
    };

    match store.issue_sender_certificate(
        user_id,
        identity_key,
        req.device_id.into(),
        req.ttl_secs,
    ) {
        Ok(cert) => {
            let Ok(serialized) = cert.serialized() else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "failed to serialise certificate" })),
                )
                    .into_response();
            };
            (
                StatusCode::OK,
                Json(SenderCertificateResponse {
                    sender_certificate: STANDARD.encode(serialized),
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("failed to issue certificate: {e}") })),
        )
            .into_response(),
    }
}

/// `GET /v1/certs/trust-root` — fetch the trust root public key clients
/// pin to validate sealed-sender certificate chains.
pub async fn get_trust_root(State(store): State<SharedRelayStore>) -> impl IntoResponse {
    let key_bytes = store.trust_root_public_key().serialize();
    Json(TrustRootResponse {
        trust_root_public_key: STANDARD.encode(key_bytes),
    })
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
    // Deliberately does not log `envelope.sender_id` — see module docs.
    tracing::debug!(
        msg_id = %msg_id,
        recipient = %recipient_id,
        envelope_type = ?envelope.envelope_type,
        sealed_sender = envelope.sealed_sender,
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
