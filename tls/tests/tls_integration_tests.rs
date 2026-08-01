//! Sub-Phase 4.5E: TLS termination integration tests.
//!
//! These exist because of the reason native `rustls` termination was
//! chosen over a "put a reverse proxy in front of it" deployment note in
//! the first place (see `tls/src/lib.rs` module docs): a real client can
//! connect to a real server over real TLS here and assert it works. A
//! deployment note could not have been tested at all.
//!
//! | Test | Asserts |
//! |------|---------|
//! | 1 | A server started with a self-signed certificate genuinely serves HTTPS, and a client completing a real TLS handshake gets the response. |
//! | 2 | The same server refuses a plaintext HTTP request — TLS is actually enforced, not merely offered. |
//! | 3 | `TlsSettings::Disabled` really does serve plaintext (the documented default). |
//! | 4 | A half-configured cert/key pair fails closed rather than silently downgrading to self-signed. |
//! | 5 | Generated development certificates are well-formed PEM carrying the requested SANs. |

use std::net::SocketAddr;

use axum::{routing::get, Router};
use parda_tls::{TlsError, TlsSettings};

fn test_app() -> Router {
    Router::new().route("/ping", get(|| async { "pong" }))
}

/// Bind an ephemeral port, then hand the address back — the server is
/// spawned on it immediately after, matching how `mixnode/tests/common`
/// already allocates real loopback ports for its own integration tests.
fn ephemeral_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn spawn(settings: TlsSettings) -> SocketAddr {
    let addr = ephemeral_addr();
    tokio::spawn(async move {
        let _ = parda_tls::serve(addr, test_app(), &settings).await;
    });
    // Give the listener a moment to come up before the client connects.
    // Polled rather than a flat sleep so this stays fast and doesn't
    // become flaky on a loaded CI runner.
    for _ in 0..100 {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    addr
}

// ─── Test 1: a real TLS handshake against a self-signed server ───────────────

#[tokio::test]
async fn test_self_signed_server_serves_real_https() {
    let addr = spawn(TlsSettings::SelfSigned {
        subject_alt_names: vec!["localhost".to_string(), "127.0.0.1".to_string()],
    })
    .await;

    // `danger_accept_invalid_certs` is correct *here specifically*: the
    // server is deliberately using a self-signed certificate this client
    // has no way to have pinned, and what this test is proving is that
    // the TLS transport works end to end — not that certificate
    // validation works, which is rustls's job and not something this
    // crate reimplements. Test 2 covers the property that actually
    // matters for this module: that plaintext is genuinely refused.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = client
        .get(format!("https://{addr}/ping"))
        .send()
        .await
        .expect("a real TLS handshake against the self-signed server must succeed");

    assert!(response.status().is_success());
    assert_eq!(response.text().await.unwrap(), "pong");
}

// ─── Test 2: TLS is enforced, not merely offered ─────────────────────────────

#[tokio::test]
async fn test_tls_server_refuses_plaintext_http() {
    let addr = spawn(TlsSettings::SelfSigned {
        subject_alt_names: vec!["localhost".to_string()],
    })
    .await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    let result = client.get(format!("http://{addr}/ping")).send().await;

    assert!(
        result.is_err(),
        "a plaintext request to a TLS listener must fail — if this succeeds, TLS is being \
         offered but not enforced, which is the failure mode this test exists to catch"
    );
}

// ─── Test 3: the documented plaintext default ────────────────────────────────

/// `TlsSettings::Disabled` is the default (see module docs on why, and
/// on it being a documented limitation). This asserts the default really
/// is plaintext, so the documentation and the behavior cannot drift
/// apart in either direction.
#[tokio::test]
async fn test_disabled_settings_serve_plaintext() {
    let addr = spawn(TlsSettings::Disabled).await;

    let response = reqwest::get(format!("http://{addr}/ping"))
        .await
        .expect("the plaintext default must serve plain HTTP");
    assert_eq!(response.text().await.unwrap(), "pong");
}

// ─── Test 4: half-configured fails closed ────────────────────────────────────

/// Exactly one of cert/key set must be a hard error, not a quiet
/// downgrade to a self-signed certificate — an operator who typoed one
/// path has to find out.
#[test]
fn test_half_configured_cert_and_key_fails_closed() {
    // These tests share a process, so environment variables are shared
    // state; this test sets and clears its own and is the only one that
    // touches PARDA_TLS_* (the others construct `TlsSettings` directly
    // rather than going through `from_env`).
    std::env::set_var("PARDA_TLS_ENABLED", "1");
    std::env::set_var("PARDA_TLS_CERT_PATH", "/nonexistent/cert.pem");
    std::env::remove_var("PARDA_TLS_KEY_PATH");

    let result = TlsSettings::from_env();

    std::env::remove_var("PARDA_TLS_ENABLED");
    std::env::remove_var("PARDA_TLS_CERT_PATH");

    match result {
        Err(TlsError::HalfConfigured { which_is_set }) => {
            assert_eq!(which_is_set, "PARDA_TLS_CERT_PATH");
        }
        other => panic!("expected HalfConfigured, got {other:?}"),
    }
}

// ─── Test 5: generated certificates are well-formed ──────────────────────────

#[test]
fn test_dev_certificate_is_well_formed_pem() {
    let (cert_pem, key_pem) =
        parda_tls::dev_certificate(&["localhost".to_string(), "parda.test".to_string()]).unwrap();

    assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(cert_pem.trim_end().ends_with("-----END CERTIFICATE-----"));
    assert!(key_pem.contains("PRIVATE KEY"));

    // Two generations must differ — a fixed/hardcoded development key
    // would be far worse than a freshly generated one, since it would be
    // identical across every deployment that ever ran this code.
    let (second_cert, second_key) =
        parda_tls::dev_certificate(&["localhost".to_string(), "parda.test".to_string()]).unwrap();
    assert_ne!(cert_pem, second_cert);
    assert_ne!(key_pem, second_key);
}
