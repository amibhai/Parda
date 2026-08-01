//! PARDA Relay Server — library surface.
//!
//! Exists mainly so integration tests (`server/tests/`) can construct the
//! same [`axum::Router`] `main.rs` serves, without going through a real
//! TCP bind, and can hold a direct handle to the [`store::SharedRelayStore`]
//! to inspect exactly what the relay persisted. See
//! `server/tests/sealed_sender_relay_tests.rs` for the sealed-sender
//! adversarial "malicious relay" test this enables.

pub mod models;
pub mod routes;
pub mod store;

use axum::{
    routing::{delete, get, post},
    Router,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use store::SharedRelayStore;

/// Build the relay's Axum router over `store`. Identical to what `main.rs`
/// serves over HTTP — the only thing tests skip is the TCP bind.
pub fn app(store: SharedRelayStore) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route("/v1/keys/:user_id", post(routes::upload_prekey_bundle))
        .route("/v1/keys/:user_id", get(routes::get_prekey_bundle))
        .route("/v1/certs/:user_id", post(routes::issue_sender_certificate))
        .route("/v1/certs/trust-root", get(routes::get_trust_root))
        // Same path template on both methods — axum's router requires
        // identical parameter names across method registrations that share
        // a path; `submit_message` just treats the captured value as a
        // recipient rather than a user_id.
        .route("/v1/messages/:user_id", get(routes::fetch_messages))
        .route("/v1/messages/:user_id", post(routes::submit_message))
        .route("/v1/messages/:user_id/:msg_id", delete(routes::delete_message))
        // Sub-Phase 4.5A — see docs/phase4.5a-receive-path-design.md.
        .route("/v1/pulls", post(routes::stage_pull))
        .route("/v1/pulls/:rendezvous_token", get(routes::fetch_pull))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(store)
}
