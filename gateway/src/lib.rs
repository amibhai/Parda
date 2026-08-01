//! `parda-gateway` — typed, versioned external REST API in front of
//! `parda-relay` (Sub-Phase 3D).
//!
//! ## What this is, honestly
//!
//! `parda-relay` is already a dumb pipe — it stores and forwards opaque
//! `MessageEnvelope`s without ever reading `ciphertext`. This gateway
//! does not add a new security property the relay lacks; it adds an
//! external-facing API surface (`/api/v1/...`, versioned independently
//! of the relay's own route names) that could grow authentication, rate
//! limiting, or request-shape validation over time **without any of
//! that touching the relay's own trusted core**. That's the actual
//! value: a separable place to put external-integration concerns, not a
//! new cryptographic boundary.
//!
//! ## "Provably a dumb pipe"
//!
//! Same standard the relay holds itself to. Structurally, not just by
//! convention: `parda-gateway` depends on `parda_protocol` for exactly
//! one thing (the `MessageEnvelope` *type*, for external API
//! documentation — see `models.rs`) and has **zero** dependency on any
//! decrypt-capable code (`chacha20poly1305`, `hkdf`,
//! `parda_protocol::session`, `::self_destruct`, `::sealed_sender`).
//! Every message-carrying route forwards the request body as raw bytes,
//! never deserializing into a typed value that could be logged or
//! inspected — see `routes.rs` module docs and
//! `tests/gateway_tests.rs::test_ciphertext_passes_through_bit_identical`.

pub mod models;
pub mod routes;

use axum::{
    routing::{delete, get, post},
    Router,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

#[derive(Clone)]
pub struct GatewayState {
    pub relay_base_url: String,
    pub http: reqwest::Client,
}

impl GatewayState {
    pub fn new(relay_base_url: impl Into<String>) -> Self {
        Self {
            relay_base_url: relay_base_url.into(),
            http: reqwest::Client::new(),
        }
    }
}

/// Build the gateway's Axum router. Mirrors `parda_relay::app(store)` /
/// `parda_mixnode::app(state)`'s pattern so tests can construct it
/// without a real TCP bind.
pub fn app(state: GatewayState) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route("/api/v1/keys/:user_id", post(routes::upload_prekey_bundle))
        .route("/api/v1/keys/:user_id", get(routes::get_prekey_bundle))
        .route("/api/v1/messages/:user_id", get(routes::fetch_messages))
        .route("/api/v1/messages/:user_id", post(routes::submit_message))
        .route("/api/v1/messages/:user_id/:msg_id", delete(routes::delete_message))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(state)
}
