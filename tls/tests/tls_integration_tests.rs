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
//! | 6 | A client trusting **only** the pinned authority completes a real handshake against a relay certificate issued by it. |
//! | 7 | **The adversarial case.** An active man-in-the-middle holding its own authority — a certificate that is valid, self-consistent, and issued for the very hostname the client asked for — is rejected. This is the property `pinned_authority` claims and the reason the whole construction exists. |
//! | 8 | A leaf reissued from the same authority is accepted by an already-pinned client, so rotating the relay's certificate does not require shipping a new app. |
//! | 9 | Issuing a certificate with no subject alternative names fails closed. |
//! | 9b | A self-signed leaf *is* usable as a trust anchor — recording a measured fact that contradicts an earlier assumption in `pinned_authority`'s design note, so the reason for the CA stays the honest one (rotation) rather than the one first guessed. |

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

// ─── Certificate pinning (tests 6-9) ─────────────────────────────────────────

/// Write a PEM chain and key to unique temp files and hand back their
/// paths, so the server exercises the same `RustlsConfig::from_pem_file`
/// path a real deployment uses rather than a test-only shortcut.
fn write_pem_pair(chain: &str, key: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("parda-tls-test-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let cert_path = dir.join("chain.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, chain).unwrap();
    std::fs::write(&key_path, key).unwrap();
    (cert_path, key_path)
}

/// A client whose *only* trust anchor is `authority_pem` — built-in root
/// CAs explicitly off, which is what makes this a pin rather than an
/// addition to the usual ~150 roots.
fn client_pinned_to(authority_pem: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(authority_pem.as_bytes()).unwrap())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap()
}

async fn spawn_with_chain(chain: &str, key: &str) -> SocketAddr {
    let (cert_path, key_path) = write_pem_pair(chain, key);
    spawn(TlsSettings::FromFiles { cert_path, key_path }).await
}

// ─── Test 6: the pinned client accepts its own authority's leaf ──────────────

#[tokio::test]
async fn test_pinned_client_accepts_leaf_from_its_authority() {
    let authority = parda_tls::pinned_authority().unwrap();
    let (chain, key) =
        parda_tls::relay_certificate(&authority, &["127.0.0.1".to_string()]).unwrap();
    let addr = spawn_with_chain(&chain, &key).await;

    let response = client_pinned_to(&authority.certificate_pem)
        .get(format!("https://{addr}/ping"))
        .send()
        .await
        .expect("a client pinning this authority must accept a leaf the authority issued");

    assert_eq!(response.text().await.unwrap(), "pong");
}

// ─── Test 7: the adversarial case — an active MITM is rejected ───────────────

/// The property the entire pinning construction exists to provide.
///
/// The attacker here is not weak. They hold a complete, self-consistent
/// certificate authority of their own; the leaf they serve is validly
/// signed, correctly formed, unexpired, and issued for exactly the
/// hostname the client is asking for. Against a client using the normal
/// public-CA trust store this is precisely the certificate a compromised
/// or coerced CA would issue, and it would be accepted.
///
/// It must fail here, because the client trusts one key and the attacker
/// does not have it.
#[tokio::test]
async fn test_pinned_client_rejects_a_man_in_the_middle_authority() {
    let real = parda_tls::pinned_authority().unwrap();
    let attacker = parda_tls::pinned_authority().unwrap();

    // The attacker issues for the same host the client will request.
    let (mitm_chain, mitm_key) =
        parda_tls::relay_certificate(&attacker, &["127.0.0.1".to_string()]).unwrap();
    let addr = spawn_with_chain(&mitm_chain, &mitm_key).await;

    // Sanity: the attacker's certificate is not malformed — a client that
    // pins *the attacker's* authority accepts it happily. Without this,
    // the rejection below could be caused by a broken certificate rather
    // than by pinning doing its job.
    let accepted_by_its_own_pin = client_pinned_to(&attacker.certificate_pem)
        .get(format!("https://{addr}/ping"))
        .send()
        .await;
    assert!(
        accepted_by_its_own_pin.is_ok(),
        "the attacker's certificate must itself be valid, or this test proves nothing"
    );

    // The real client pins the real authority, and must refuse.
    let result = client_pinned_to(&real.certificate_pem)
        .get(format!("https://{addr}/ping"))
        .send()
        .await;

    assert!(
        result.is_err(),
        "a client pinned to the real authority accepted a certificate issued by a different \
         authority — pinning is not in effect, and every deployment relying on it is open to an \
         active man-in-the-middle"
    );
}

// ─── Test 8: leaves rotate without touching the pin ──────────────────────────

/// `pinned_authority`'s documented operational claim: the relay's
/// certificate can be reissued — new key, new hostname — without shipping
/// a new client build, because clients pin the authority rather than the
/// leaf. If this failed, the design would collapse back into the
/// pinned-leaf approach it was chosen over.
#[tokio::test]
async fn test_reissued_leaf_is_accepted_without_changing_the_pin() {
    let authority = parda_tls::pinned_authority().unwrap();

    let (first_chain, _) =
        parda_tls::relay_certificate(&authority, &["127.0.0.1".to_string()]).unwrap();

    // A completely separate issuance: different key, and an extra name,
    // as if the relay had moved host.
    let (second_chain, second_key) = parda_tls::relay_certificate(
        &authority,
        &["127.0.0.1".to_string(), "relay.parda.test".to_string()],
    )
    .unwrap();
    assert_ne!(first_chain, second_chain, "reissue must produce a genuinely new certificate");

    let addr = spawn_with_chain(&second_chain, &second_key).await;

    let response = client_pinned_to(&authority.certificate_pem)
        .get(format!("https://{addr}/ping"))
        .send()
        .await
        .expect("a reissued leaf from the same authority must be accepted by an unchanged pin");

    assert_eq!(response.text().await.unwrap(), "pong");
}

// ─── Test 9b: pinning a bare leaf works, and is still the wrong design ───────

/// Records a fact that was assumed wrongly and then measured.
///
/// `pinned_authority`'s design note originally claimed a self-signed leaf
/// could not serve as a trust anchor, because path building wants
/// `basicConstraints: CA:TRUE` on the anchor. This test was written to
/// back that claim and instead disproved it — rustls accepts the leaf.
/// The documentation was corrected to match; the reason this project
/// still issues from an authority is purely operational (a pinned leaf
/// cannot be rotated without shipping a new client), which test 8 covers.
///
/// Kept as a regression test in both directions: it is the only place
/// stating that the simpler design is technically viable, so if this ever
/// starts failing, the design note's history is wrong again and the next
/// reader deserves to know which way.
#[tokio::test]
async fn test_a_self_signed_leaf_is_accepted_as_a_trust_anchor() {
    let (leaf_pem, leaf_key) = parda_tls::dev_certificate(&["127.0.0.1".to_string()]).unwrap();
    let addr = spawn_with_chain(&leaf_pem, &leaf_key).await;

    let result = client_pinned_to(&leaf_pem).get(format!("https://{addr}/ping")).send().await;

    assert!(
        result.is_ok(),
        "a self-signed leaf was refused as a trust anchor: {result:?} — pinned_authority's design \
         note says the opposite and must be corrected"
    );
}

// ─── Test 9: no SANs fails closed ────────────────────────────────────────────

/// A certificate naming nothing matches nothing. Rejecting at issuance
/// turns a confusing handshake failure at deployment time into a clear
/// error at the moment the operator made the mistake.
#[test]
fn test_relay_certificate_without_sans_fails_closed() {
    let authority = parda_tls::pinned_authority().unwrap();
    match parda_tls::relay_certificate(&authority, &[]) {
        Err(TlsError::NoSubjectAltNames) => {}
        other => panic!("expected NoSubjectAltNames, got {other:?}"),
    }
}
