//! PARDA mix node — Sphinx packet forwarding daemon (Sub-Phase 2B).
//!
//! Each node holds an X25519 identity keypair and, for every packet it
//! receives, unwraps exactly one Sphinx onion layer
//! (`parda_protocol::mixnet::process_packet`) and either forwards the
//! result to the next hop or delivers it to the relay — honoring the
//! sender-chosen per-hop delay in both directions of that decision. See
//! `parda_protocol::mixnet` module docs for why the *node* never samples
//! its own delay.
//!
//! ## Deliberately no topology
//!
//! A mix node holds only its own keypair, plus — optionally — a short
//! list of peers used solely to emit its own cover traffic
//! ([`cover_traffic`]). It never needs the full network topology client
//! path-selection does, because the next hop's address is recovered
//! directly from what it decrypts out of the packet header (see
//! `parda_protocol::mixnet` module docs, "Address encoding").

pub mod cover_traffic;
pub mod identity;
pub mod mixing;
pub mod routes;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use parda_protocol::mixnet::{PublicKey, StaticSecret};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

/// Shared state for a running mix node.
pub struct MixNodeState {
    pub secret_key: StaticSecret,
    pub public_key: PublicKey,
    /// Base URL of the relay this node delivers final-hop envelopes to.
    pub relay_base_url: String,
    pub http: reqwest::Client,
}

pub type SharedMixNodeState = Arc<MixNodeState>;

impl MixNodeState {
    pub fn new(secret_key: StaticSecret, relay_base_url: impl Into<String>) -> SharedMixNodeState {
        let public_key = PublicKey::from(&secret_key);
        Arc::new(Self {
            secret_key,
            public_key,
            relay_base_url: relay_base_url.into(),
            http: reqwest::Client::new(),
        })
    }
}

/// Build this node's Axum router. Mirrors `parda_relay`'s `app(store)`
/// pattern (`server/src/lib.rs`) so tests can construct the same router
/// without a real TCP bind.
pub fn app(state: SharedMixNodeState) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route("/mix/pubkey", get(routes::pubkey))
        .route("/mix/packet", post(routes::receive_packet))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(state)
}
