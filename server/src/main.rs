//! PARDA Relay Server
//!
//! A minimal store-and-forward relay for end-to-end encrypted messages.
//!
//! ## Security contract
//!
//! - This server stores and delivers opaque ciphertext blobs only.
//! - It **cannot** decrypt any message — all key material lives on client devices.
//! - It **can** see sender → recipient metadata for envelopes that don't opt
//!   into sealed sender (`sealed_sender = false`; still true for any Phase 1
//!   peer, and any Phase 2 peer that chooses not to seal a given message).
//!   For `sealed_sender = true` envelopes, this server's code path never
//!   reads or logs a sender identity — see `routes.rs` module docs and
//!   `server/tests/sealed_sender_relay_tests.rs`.
//! - This server also hosts the sealed-sender certificate authority
//!   (`/v1/certs/*`) — see `parda_protocol::sealed_sender` module docs for
//!   what that does and does not authenticate.
//! - The store is a SQLCipher database, encrypted at rest — see `store.rs`
//!   module docs. Messages now survive a relay restart (Phase 1 Known Risk
//!   #2 in `docs/phase1-architecture.md` §10 is resolved as of Phase 2).
//!
//! ## Running
//!
//! ```bash
//! PARDA_DB_KEY=$(openssl rand -hex 32) \
//! PARDA_DB_PATH=./data/parda-relay.sqlite3 \
//! PARDA_BIND=0.0.0.0:8080 \
//! cargo run -p parda-relay
//! ```
//!
//! `PARDA_DB_KEY` is required — the store is a SQLCipher database encrypted
//! at rest (see `store.rs` module docs) and refuses to start with a default
//! or missing key. `PARDA_DB_PATH` defaults to `parda-relay.sqlite3` in the
//! working directory. Default bind address: `127.0.0.1:8080`.

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use parda_relay::{app, store::RelayStore};

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
    let app = app(store);

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
        "Sender metadata is hidden only for envelopes sent with sealed_sender = true. \
         Phase 1 peers, and any Phase 2 peer not opting in, remain visible to this relay."
    );

    axum::serve(listener, app)
        .await
        .expect("server error");
}
