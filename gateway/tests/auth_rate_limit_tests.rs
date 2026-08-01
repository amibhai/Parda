//! Sub-Phase 4.5E: gateway API-key auth and rate-limiting tests.
//!
//! Uses the same real-loopback-server harness `gateway_tests.rs`
//! established (a stand-in relay rather than `parda-relay` itself — see
//! that file's header for why), so these exercise the actual middleware
//! stack over real HTTP, not a mocked transport.
//!
//! | Test | Asserts |
//! |------|---------|
//! | 1 | With keys configured, a request carrying a valid bearer key is accepted. |
//! | 2 | A missing `Authorization` header is rejected `401`. |
//! | 3 | A wrong key is rejected `401`. |
//! | 4 | A *prefix* of a valid key is rejected — the constant-time comparison is not a prefix match. |
//! | 5 | `/health` stays reachable without a credential (liveness probes must not depend on auth config). |
//! | 6 | With no keys configured, requests are accepted — the documented, non-regressing default. |
//! | 7 | Exceeding the burst returns `429`, and the response is a typed JSON error rather than a bare status. |
//! | 8 | Rate-limit buckets are per API key: one client exhausting its allowance does not affect another. |

use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use parda_gateway::{app_with_security, ApiSecurity, GatewayState};

// ─── Minimal stand-in relay (same rationale as gateway_tests.rs) ─────────────

#[derive(Default)]
struct StubRelayState {
    messages: Mutex<std::collections::HashMap<String, Vec<serde_json::Value>>>,
}

type SharedStub = Arc<StubRelayState>;

async fn stub_submit_message(
    State(state): State<SharedStub>,
    Path(user_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    state
        .messages
        .lock()
        .unwrap()
        .entry(user_id)
        .or_default()
        .push(body);
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "status": "accepted" })))
}

async fn stub_fetch_messages(
    State(state): State<SharedStub>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let messages = state
        .messages
        .lock()
        .unwrap()
        .get(&user_id)
        .cloned()
        .unwrap_or_default();
    (StatusCode::OK, Json(serde_json::json!({ "messages": messages })))
}

async fn spawn_stub_relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/v1/messages/:user_id", post(stub_submit_message))
        .route("/v1/messages/:user_id", get(stub_fetch_messages))
        .with_state(SharedStub::default());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    base_url
}

/// Spawn a gateway with the given security policy. Uses
/// `into_make_service_with_connect_info` to match how `parda_tls::serve`
/// (the real binary's path) serves — so the per-client rate-limit
/// bucketing under test here behaves the same way it will in production.
async fn spawn_gateway(relay_base_url: &str, security: ApiSecurity) -> (reqwest::Client, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = GatewayState::new(relay_base_url.to_string());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app_with_security(state, security)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    (reqwest::Client::new(), format!("http://{addr}"))
}

fn envelope() -> serde_json::Value {
    serde_json::json!({
        "sender_id": "alice",
        "recipient_id": "bob",
        "ciphertext": "cGFyZGEtYXV0aC10ZXN0LWNhbmFyeQ==",
        "envelope_type": "ratchet",
        "timestamp_ms": 1_753_900_000_000u64,
        "version": 2,
        "sealed_sender": false
    })
}

/// A generous burst so auth tests are never accidentally rate limited —
/// the rate-limit tests below configure their own tight limits.
fn keys(keys: &[&str]) -> ApiSecurity {
    ApiSecurity::new(keys.iter().map(|s| s.to_string()).collect(), 10_000, 10_000.0)
}

// ─── Tests 1-4: authentication ───────────────────────────────────────────────

#[tokio::test]
async fn test_valid_bearer_key_is_accepted() {
    let relay = spawn_stub_relay().await;
    let (http, url) = spawn_gateway(&relay, keys(&["correct-horse-battery-staple"])).await;

    let resp = http
        .post(format!("{url}/api/v1/messages/bob"))
        .bearer_auth("correct-horse-battery-staple")
        .json(&envelope())
        .send()
        .await
        .unwrap();

    assert!(
        resp.status().is_success(),
        "a valid key must be accepted, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_missing_authorization_header_is_rejected() {
    let relay = spawn_stub_relay().await;
    let (http, url) = spawn_gateway(&relay, keys(&["secret"])).await;

    let resp = http
        .post(format!("{url}/api/v1/messages/bob"))
        .json(&envelope())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "unauthorized");
}

#[tokio::test]
async fn test_wrong_key_is_rejected() {
    let relay = spawn_stub_relay().await;
    let (http, url) = spawn_gateway(&relay, keys(&["secret"])).await;

    let resp = http
        .get(format!("{url}/api/v1/messages/bob"))
        .bearer_auth("not-the-secret")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A prefix of a valid key must not authenticate. This is the property a
/// naive `starts_with`/short-circuiting comparison would break, and the
/// reason `auth.rs` uses `subtle::ConstantTimeEq`.
#[tokio::test]
async fn test_prefix_of_a_valid_key_is_rejected() {
    let relay = spawn_stub_relay().await;
    let (http, url) = spawn_gateway(&relay, keys(&["supersecretkey"])).await;

    for candidate in ["s", "super", "supersecretke", "supersecretkeyy"] {
        let resp = http
            .get(format!("{url}/api/v1/messages/bob"))
            .bearer_auth(candidate)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "candidate {candidate:?} must not authenticate"
        );
    }
}

// ─── Test 5: /health is deliberately outside the security layer ──────────────

#[tokio::test]
async fn test_health_is_reachable_without_a_credential() {
    let relay = spawn_stub_relay().await;
    let (http, url) = spawn_gateway(&relay, keys(&["secret"])).await;

    let resp = http.get(format!("{url}/health")).send().await.unwrap();
    assert!(
        resp.status().is_success(),
        "a liveness probe must not require a credential — otherwise a misconfigured key makes \
         a healthy gateway report as down"
    );
}

// ─── Test 6: the documented open default ─────────────────────────────────────

/// With no keys configured, the gateway behaves exactly as it did before
/// Sub-Phase 4.5E. This asserts the documented default really is open,
/// so the docs and the behavior cannot drift apart in either direction.
#[tokio::test]
async fn test_no_configured_keys_means_requests_are_accepted() {
    let relay = spawn_stub_relay().await;
    let security = ApiSecurity::new(Vec::new(), 10_000, 10_000.0);
    assert!(!security.auth_enabled());
    let (http, url) = spawn_gateway(&relay, security).await;

    let resp = http
        .post(format!("{url}/api/v1/messages/bob"))
        .json(&envelope())
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_success());
}

// ─── Tests 7-8: rate limiting ────────────────────────────────────────────────

#[tokio::test]
async fn test_exceeding_the_burst_returns_429_with_a_typed_error() {
    let relay = spawn_stub_relay().await;
    // 3-token burst, negligible refill, so the 4th request within the
    // test window is guaranteed to be over the limit.
    let security = ApiSecurity::new(vec!["k".to_string()], 3, 0.0001);
    let (http, url) = spawn_gateway(&relay, security).await;

    for i in 0..3 {
        let resp = http
            .get(format!("{url}/api/v1/messages/bob"))
            .bearer_auth("k")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success(), "request {i} should be within the burst");
    }

    let resp = http
        .get(format!("{url}/api/v1/messages/bob"))
        .bearer_auth("k")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "rate_limited");
}

/// Buckets are per API key: one client exhausting its allowance must not
/// consume another's. Without this, a single noisy integration would
/// deny service to every other client — which would make the rate
/// limiter itself the outage.
#[tokio::test]
async fn test_rate_limit_buckets_are_per_api_key() {
    let relay = spawn_stub_relay().await;
    let security = ApiSecurity::new(vec!["alpha".to_string(), "beta".to_string()], 2, 0.0001);
    let (http, url) = spawn_gateway(&relay, security).await;

    // Exhaust alpha's bucket.
    for _ in 0..2 {
        assert!(http
            .get(format!("{url}/api/v1/messages/bob"))
            .bearer_auth("alpha")
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
    }
    assert_eq!(
        http.get(format!("{url}/api/v1/messages/bob"))
            .bearer_auth("alpha")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    // beta must be unaffected.
    assert!(
        http.get(format!("{url}/api/v1/messages/bob"))
            .bearer_auth("beta")
            .send()
            .await
            .unwrap()
            .status()
            .is_success(),
        "a second key's bucket must be independent of the first's"
    );
}
