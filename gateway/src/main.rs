//! `parda-gateway` daemon binary.
//!
//! ```bash
//! PARDA_RELAY_URL=http://127.0.0.1:8080 \
//! PARDA_GATEWAY_BIND=127.0.0.1:8090 \
//! cargo run -p parda-gateway
//! ```

use parda_gateway::{app_with_security, ApiSecurity, GatewayState};
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

    // Sub-Phase 4.5E: API-key auth + rate limiting. Both log their
    // posture at startup — an open gateway is never silent about being
    // open. See gateway/src/auth.rs module docs.
    let security = ApiSecurity::from_env();
    security.log_posture();

    let tls = parda_tls::TlsSettings::from_env()
        .unwrap_or_else(|e| panic!("TLS configuration error: {e}"));

    let bind_addr = std::env::var("PARDA_GATEWAY_BIND").unwrap_or_else(|_| "127.0.0.1:8090".to_string());
    let addr: std::net::SocketAddr = bind_addr.parse().unwrap_or_else(|e| {
        panic!("PARDA_GATEWAY_BIND is not a valid socket address ({bind_addr}): {e}")
    });

    tracing::info!(%addr, relay = %relay_url, "parda-gateway listening");

    parda_tls::serve(addr, app_with_security(state, security), &tls)
        .await
        .expect("gateway server error");
}
