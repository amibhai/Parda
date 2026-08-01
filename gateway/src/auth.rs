//! Bearer API-key authentication and token-bucket rate limiting for the
//! external gateway surface (Sub-Phase 4.5E).
//!
//! ## Why this lives here and not in `parda-relay`
//!
//! This is exactly the thing `lib.rs`'s module docs said this crate
//! existed to make possible: "a separable place to put
//! external-integration concerns" that grows authentication and rate
//! limiting "**without any of that touching the relay's own trusted
//! core**." That claim is now cashed in — the relay is unchanged by this
//! sub-phase.
//!
//! ## Scope, stated plainly
//!
//! This is a shared-secret API key checked against a configured set. It
//! is **not** user authentication, and it deliberately does not become
//! one: PARDA has no accounts, and adding a real identity system at the
//! gateway would create exactly the metadata concentration point the
//! rest of this project works to avoid. What it does is let an operator
//! stop the gateway being an open relay for anyone who finds the URL.
//! `docs/THREAT_MODEL.md` states this in the same terms.
//!
//! **An API key says nothing about who sent a message.** Envelopes stay
//! end-to-end encrypted and (when sealed) sender-anonymous; the key
//! authenticates the *API client*, not the human, and the gateway never
//! records a mapping between the two.
//!
//! ## Disabled by default, and never silently
//!
//! With no `PARDA_GATEWAY_API_KEYS` configured, requests are allowed —
//! which is exactly today's behavior, so nothing regresses — and every
//! startup logs a warning saying so. That matches `parda-relay`'s
//! already-documented "no account authentication" posture
//! (`docs/phase1-architecture.md` §10) rather than quietly diverging
//! from it. Configuring keys turns enforcement on.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, State},
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use subtle::ConstantTimeEq;

/// Default token-bucket capacity (burst) and refill rate.
const DEFAULT_BURST: u32 = 60;
const DEFAULT_PER_SECOND: f64 = 10.0;

#[derive(Clone)]
pub struct ApiSecurity {
    inner: Arc<ApiSecurityInner>,
}

struct ApiSecurityInner {
    /// Empty means authentication is disabled — see module docs.
    api_keys: Vec<String>,
    limiter: RateLimiter,
}

impl ApiSecurity {
    /// Build from the environment: `PARDA_GATEWAY_API_KEYS`
    /// (comma-separated), `PARDA_GATEWAY_RATE_LIMIT_BURST`,
    /// `PARDA_GATEWAY_RATE_LIMIT_PER_SEC`.
    pub fn from_env() -> Self {
        let api_keys: Vec<String> = std::env::var("PARDA_GATEWAY_API_KEYS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let burst = std::env::var("PARDA_GATEWAY_RATE_LIMIT_BURST")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_BURST);
        let per_second = std::env::var("PARDA_GATEWAY_RATE_LIMIT_PER_SEC")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_PER_SECOND);

        Self::new(api_keys, burst, per_second)
    }

    pub fn new(api_keys: Vec<String>, burst: u32, per_second: f64) -> Self {
        Self {
            inner: Arc::new(ApiSecurityInner {
                api_keys,
                limiter: RateLimiter::new(burst, per_second),
            }),
        }
    }

    pub fn auth_enabled(&self) -> bool {
        !self.inner.api_keys.is_empty()
    }

    /// Log the security posture at startup — never silent about being
    /// open, same discipline as `parda_tls::TlsSettings::log_posture`.
    pub fn log_posture(&self) {
        if self.auth_enabled() {
            tracing::info!(
                key_count = self.inner.api_keys.len(),
                "gateway API-key authentication enabled"
            );
        } else {
            tracing::warn!(
                "gateway API-key authentication is DISABLED — every request is accepted without \
                 a credential. Set PARDA_GATEWAY_API_KEYS (comma-separated) to enable it. Rate \
                 limiting still applies, keyed by client address."
            );
        }
    }

    /// Constant-time check of `candidate` against every configured key.
    ///
    /// Constant-time (via `subtle::ConstantTimeEq`) rather than `==`
    /// specifically because a byte-by-byte early-exit comparison against
    /// a secret leaks its prefix through timing — the standard, and
    /// entirely practical, attack against naive API-key checks. Every
    /// configured key is compared even after a match is found, so the
    /// work done does not reveal *which* key matched or how many were
    /// checked.
    fn key_is_valid(&self, candidate: &str) -> bool {
        let mut matched = false;
        for key in &self.inner.api_keys {
            // `ConstantTimeEq` on unequal-length inputs returns false
            // without a length-dependent branch on content; length
            // itself is not treated as secret here (an API key's length
            // is not the part worth protecting).
            matched |= bool::from(key.as_bytes().ct_eq(candidate.as_bytes()));
        }
        matched
    }
}

/// Axum middleware: authenticate (if enabled), then rate limit.
///
/// Order matters and is deliberate — authentication runs first so that
/// rate limiting can be keyed by API key for authenticated callers,
/// giving each client its own bucket rather than letting one noisy
/// client exhaust a shared one.
pub async fn api_security_middleware(
    State(security): State<ApiSecurity>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let bucket_key = if security.auth_enabled() {
        let presented = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim);

        match presented {
            Some(key) if security.key_is_valid(key) => format!("key:{key}"),
            Some(_) => return unauthorized("invalid API key"),
            None => return unauthorized("missing Authorization: Bearer <key> header"),
        }
    } else {
        // Unauthenticated: bucket by peer address so one client cannot
        // exhaust everyone else's allowance. `ConnectInfo` is only
        // present when the server was started with
        // `into_make_service_with_connect_info` (the real binary does;
        // `axum-test`'s mocked transport does not) — falling back to a
        // single shared bucket there is acceptable because that path is
        // tests only, and is called out rather than left implicit.
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| format!("addr:{}", addr.ip()))
            .unwrap_or_else(|| "anonymous".to_string())
    };

    if !security.inner.limiter.try_acquire(&bucket_key) {
        return rate_limited();
    }

    next.run(request).await
}

fn unauthorized(detail: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "unauthorized", "detail": detail })),
    )
        .into_response()
}

fn rate_limited() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({ "error": "rate_limited", "detail": "request rate exceeded" })),
    )
        .into_response()
}

// ─── Token bucket ────────────────────────────────────────────────────────────

/// Classic token bucket: `capacity` tokens, refilled at `per_second`,
/// one consumed per request.
///
/// Hand-written rather than pulled from a crate (`tower-governor` and
/// similar exist) for the same reason `parda-mesh` wrote its own
/// admission control instead of adopting a rate-limiting dependency: the
/// whole mechanism is ~40 reviewable lines, and a token bucket is a
/// textbook algorithm, not a cryptographic primitive where "don't roll
/// your own" applies.
///
/// **Per-process, in-memory.** Restarting the gateway resets every
/// bucket, and two gateway instances behind a load balancer do not share
/// state. Stated rather than implied: this bounds accidental and casual
/// abuse, not a distributed attacker who can reconnect across instances.
struct RateLimiter {
    capacity: f64,
    per_second: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(capacity: u32, per_second: f64) -> Self {
        Self {
            capacity: f64::from(capacity),
            per_second,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn try_acquire(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();

        // Opportunistic eviction: drop buckets that have been idle long
        // enough to have fully refilled anyway, so a long-running
        // gateway facing many distinct clients doesn't grow this map
        // without bound. Removing a full bucket is behaviourally
        // identical to keeping it — a fresh bucket starts full.
        if buckets.len() > 10_000 {
            let idle_to_full = Duration::from_secs_f64(self.capacity / self.per_second.max(0.001));
            buckets.retain(|_, b| now.duration_since(b.last_refill) < idle_to_full);
        }

        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: self.capacity,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.per_second).min(self.capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_refuses() {
        let limiter = RateLimiter::new(3, 0.0001); // effectively no refill during the test
        assert!(limiter.try_acquire("k"));
        assert!(limiter.try_acquire("k"));
        assert!(limiter.try_acquire("k"));
        assert!(!limiter.try_acquire("k"), "the 4th request must exceed a 3-token burst");
    }

    #[test]
    fn buckets_are_independent_per_key() {
        let limiter = RateLimiter::new(1, 0.0001);
        assert!(limiter.try_acquire("a"));
        assert!(!limiter.try_acquire("a"));
        assert!(
            limiter.try_acquire("b"),
            "one client exhausting its bucket must not affect another's"
        );
    }

    #[test]
    fn bucket_refills_over_time() {
        let limiter = RateLimiter::new(1, 1000.0); // 1000 tokens/sec — refills fast
        assert!(limiter.try_acquire("k"));
        assert!(!limiter.try_acquire("k"));
        std::thread::sleep(Duration::from_millis(20));
        assert!(limiter.try_acquire("k"), "the bucket must refill over time");
    }

    #[test]
    fn key_validation_accepts_configured_keys_and_rejects_others() {
        let security = ApiSecurity::new(vec!["alpha".into(), "beta".into()], 10, 10.0);
        assert!(security.key_is_valid("alpha"));
        assert!(security.key_is_valid("beta"));
        assert!(!security.key_is_valid("gamma"));
        assert!(!security.key_is_valid(""));
        assert!(!security.key_is_valid("alph"), "a prefix must not be accepted");
        assert!(!security.key_is_valid("alphaa"), "a superstring must not be accepted");
    }

    #[test]
    fn auth_is_disabled_when_no_keys_are_configured() {
        assert!(!ApiSecurity::new(vec![], 10, 10.0).auth_enabled());
        assert!(ApiSecurity::new(vec!["k".into()], 10, 10.0).auth_enabled());
    }
}
