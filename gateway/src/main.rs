//! `parda-gateway` daemon binary.
//!
//! ```bash
//! PARDA_RELAY_URL=http://127.0.0.1:8080 \
//! PARDA_GATEWAY_BIND=127.0.0.1:8090 \
//! cargo run -p parda-gateway
//! ```

use parda_gateway::{app, GatewayState};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("parda_gateway=debug".parse().unwrap()))
        .init();

    let relay_url = std::env::var("PARDA_RELAY_URL")
        .unwrap_or_else(|_| panic!("PARDA_RELAY_URL is not set — the base URL of the parda-relay this gateway fronts"));
    let state = GatewayState::new(relay_url.clone());

    let bind_addr = std::env::var("PARDA_GATEWAY_BIND").unwrap_or_else(|_| "127.0.0.1:8090".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind to {bind_addr}: {e}"));

    tracing::info!(addr = %listener.local_addr().unwrap(), relay = %relay_url, "parda-gateway listening");

    axum::serve(listener, app(state)).await.expect("gateway server error");
}
