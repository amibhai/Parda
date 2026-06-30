//! PARDA Relay Server
//!
//! A minimal store-and-forward relay for end-to-end encrypted messages.
//!
//! ## Security contract
//!
//! - This server stores and delivers opaque ciphertext blobs only.
//! - It **cannot** decrypt any message — all key material lives on client devices.
//! - It **can** see sender → recipient metadata in Phase 1. Phase 2 (sealed-sender)
//!   will remove this visibility.
//!
//! ## Running
//!
//! ```bash
//! PARDA_BIND=0.0.0.0:8080 cargo run -p parda-relay
//! ```
//!
//! Default bind address: `127.0.0.1:8080`

mod models;
mod routes;
mod store;

use axum::{
    routing::{delete, get, post},
    Router,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use store::RelayStore;

#[tokio::main]
async fn main() {
    // ── Logging ────────────────────────────────────────────────────────────
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("parda_relay=debug".parse().unwrap()))
        .init();

    // ── Shared state ───────────────────────────────────────────────────────
    let store = RelayStore::new();

    // ── Router ─────────────────────────────────────────────────────────────
    let app = Router::new()
        // Health
        .route("/health", get(routes::health))
        // Prekey bundle management
        .route("/v1/keys/:user_id",   post(routes::upload_prekey_bundle))
        .route("/v1/keys/:user_id",   get(routes::get_prekey_bundle))
        // Message store-and-forward
        .route("/v1/messages/:user_id",           get(routes::fetch_messages))
        .route("/v1/messages/:recipient_id",      post(routes::submit_message))
        .route("/v1/messages/:user_id/:msg_id",   delete(routes::delete_message))
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(store);

    // ── Bind & serve ───────────────────────────────────────────────────────
    let bind_addr = std::env::var("PARDA_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind to {bind_addr}: {e}"));

    tracing::info!(
        addr = %listener.local_addr().unwrap(),
        "PARDA relay server listening"
    );
    tracing::warn!(
        "Phase 1 relay: sender/recipient metadata is NOT hidden. \
         Phase 2 will add sealed-sender envelopes."
    );

    axum::serve(listener, app)
        .await
        .expect("server error");
}
