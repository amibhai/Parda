//! `parda-mixnode` daemon binary.
//!
//! ## Environment configuration
//!
//! | Variable | Required | Default | Meaning |
//! |----------|----------|---------|---------|
//! | `MIXNODE_BIND` | no | `127.0.0.1:9001` | HTTP listen address |
//! | `MIXNODE_RELAY_URL` | **yes** | — | Base URL of the `parda-relay` this node delivers final-hop envelopes to |
//! | `MIXNODE_SECRET_KEY_HEX` | no | ephemeral | 64 hex chars (32 bytes) — see `identity` module docs |
//! | `MIXNODE_COVER_AVG_INTERVAL_MS` | no | `500` | Average interval between this node's own cover-traffic emissions |
//! | `MIXNODE_PEERS` | no | none | Comma-separated `host:port\|base64pubkey` entries used only for cover traffic — see `cover_traffic` module docs |
//!
//! ```bash
//! MIXNODE_RELAY_URL=http://127.0.0.1:8080 \
//! MIXNODE_BIND=127.0.0.1:9001 \
//! cargo run -p parda-mixnode
//! ```

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use parda_mixnode::{app, cover_traffic, identity, MixNodeState};
use parda_protocol::mixnet::{MixNodeDescriptor, PublicKey};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("parda_mixnode=debug".parse().unwrap()))
        .init();

    let relay_url = std::env::var("MIXNODE_RELAY_URL").unwrap_or_else(|_| {
        panic!(
            "MIXNODE_RELAY_URL is not set — this node needs the base URL of the parda-relay \
             it delivers final-hop envelopes to."
        )
    });
    let secret_key = identity::load_or_generate();
    let state = MixNodeState::new(secret_key, relay_url);

    tracing::info!(
        public_key = %STANDARD.encode(state.public_key.as_bytes()),
        "mix node identity"
    );

    let cover_interval_ms: u64 = std::env::var("MIXNODE_COVER_AVG_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let peers = parse_peers(&std::env::var("MIXNODE_PEERS").unwrap_or_default());
    cover_traffic::spawn(state.clone(), peers, Duration::from_millis(cover_interval_ms));

    let bind_addr = std::env::var("MIXNODE_BIND").unwrap_or_else(|_| "127.0.0.1:9001".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind to {bind_addr}: {e}"));

    tracing::info!(
        addr = %listener.local_addr().unwrap(),
        "parda-mixnode listening"
    );

    axum::serve(listener, app(state)).await.expect("mix node server error");
}

fn parse_peers(raw: &str) -> Vec<MixNodeDescriptor> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|entry| {
            let (address, key_b64) = entry.split_once('|')?;
            let key_bytes = STANDARD.decode(key_b64).ok()?;
            let arr: [u8; 32] = key_bytes.try_into().ok()?;
            Some(MixNodeDescriptor {
                address: address.to_string(),
                public_key: PublicKey::from(arr),
            })
        })
        .collect()
}
