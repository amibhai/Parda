//! Shared TLS termination for `parda-relay` and `parda-mixnode`
//! (Sub-Phase 4.5E).
//!
//! Native `rustls` termination via `axum-server`, rather than a
//! documented "put nginx in front of it" recommendation. The reason is
//! testability, and it is the same reason this project prefers a named
//! adversarial test to a stated intention everywhere else: a real
//! integration test can connect to this over TLS and assert it works
//! (`tls/tests/tls_integration_tests.rs`), whereas a reverse-proxy
//! deployment note is a claim nothing in CI can check.
//!
//! ## TLS is opt-in, and that is a documented limitation, not an oversight
//!
//! [`TlsSettings::from_env`] enables TLS only when `PARDA_TLS_ENABLED=1`.
//! Plaintext HTTP remains the default. Stated plainly: **that means a
//! default-configured relay or mix node still speaks plaintext HTTP, and
//! a network adversary on the path sees every request.** It is the
//! default for one concrete reason — every existing integration test in
//! this workspace (`server/tests/*`, `mixnode/tests/*`, and the CLI)
//! connects to a real loopback socket over `http://`, and silently
//! flipping the default would have made a large, untested change to all
//! of them while claiming to be a hardening step. What this module
//! provides is a *tested, working* TLS path a deployment can turn on;
//! what it does not do is make that path the default. Both halves are in
//! `docs/THREAT_MODEL.md` and the README.
//!
//! Whichever way it is configured, startup says so out loud — see
//! [`TlsSettings::log_posture`]. A plaintext deployment is never silent
//! about being plaintext.
//!
//! ## Self-signed certificates
//!
//! With TLS enabled but no `PARDA_TLS_CERT_PATH`/`PARDA_TLS_KEY_PATH`
//! configured, a self-signed certificate is generated at startup, with a
//! loud warning. See [`dev_certificate`] for exactly what that is and is
//! not good for.

use std::{net::SocketAddr, path::PathBuf};

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;

/// Install `ring` as the process-wide rustls crypto provider.
///
/// Idempotent and non-fatal: `install_default` fails if a provider is
/// already installed, which is a perfectly fine state to be in (another
/// component in the same process got there first) and not a reason to
/// refuse to start. See this crate's `Cargo.toml` for why the provider
/// is pinned explicitly at all.
pub fn install_ring_provider() {
    // Returns Err(current_provider) when one is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// How a server should listen, resolved from the environment.
#[derive(Debug, Clone)]
pub enum TlsSettings {
    /// Plaintext HTTP. The default — see module docs.
    Disabled,
    /// TLS with a certificate and key read from disk.
    FromFiles { cert_path: PathBuf, key_path: PathBuf },
    /// TLS with a self-signed certificate generated at startup.
    SelfSigned { subject_alt_names: Vec<String> },
}

impl TlsSettings {
    /// Resolve from `PARDA_TLS_ENABLED`, `PARDA_TLS_CERT_PATH`,
    /// `PARDA_TLS_KEY_PATH`, and `PARDA_TLS_SAN` (comma-separated,
    /// defaults to `localhost,127.0.0.1`).
    ///
    /// **Fails closed on a half-configured pair:** exactly one of
    /// cert/key path set is a configuration error, not a silent fallback
    /// to a self-signed certificate — an operator who set one and typoed
    /// the other must find out, not quietly get a weaker certificate than
    /// they asked for.
    pub fn from_env() -> Result<Self, TlsError> {
        if std::env::var("PARDA_TLS_ENABLED").unwrap_or_default() != "1" {
            return Ok(Self::Disabled);
        }

        let cert = std::env::var("PARDA_TLS_CERT_PATH").ok();
        let key = std::env::var("PARDA_TLS_KEY_PATH").ok();

        match (cert, key) {
            (Some(cert_path), Some(key_path)) => Ok(Self::FromFiles {
                cert_path: PathBuf::from(cert_path),
                key_path: PathBuf::from(key_path),
            }),
            (None, None) => {
                let sans = std::env::var("PARDA_TLS_SAN")
                    .unwrap_or_else(|_| "localhost,127.0.0.1".to_string())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                Ok(Self::SelfSigned { subject_alt_names: sans })
            }
            (cert, _) => Err(TlsError::HalfConfigured {
                which_is_set: if cert.is_some() {
                    "PARDA_TLS_CERT_PATH"
                } else {
                    "PARDA_TLS_KEY_PATH"
                },
            }),
        }
    }

    /// Log the transport posture at startup. Called unconditionally by
    /// every server that uses this module — a plaintext deployment is
    /// never silent about being plaintext.
    pub fn log_posture(&self) {
        match self {
            Self::Disabled => tracing::warn!(
                "TLS is DISABLED — this server is speaking plaintext HTTP and every request is \
                 readable by anyone on the network path. Set PARDA_TLS_ENABLED=1 (with \
                 PARDA_TLS_CERT_PATH/PARDA_TLS_KEY_PATH for a real certificate) to enable it."
            ),
            Self::FromFiles { cert_path, .. } => {
                tracing::info!(cert = %cert_path.display(), "TLS enabled with a configured certificate")
            }
            Self::SelfSigned { subject_alt_names } => tracing::warn!(
                sans = ?subject_alt_names,
                "TLS enabled with a SELF-SIGNED certificate generated at startup. No client can \
                 meaningfully authenticate this server: a self-signed certificate stops passive \
                 eavesdropping but not an active man-in-the-middle, who can simply present their \
                 own. Development and testing only — set PARDA_TLS_CERT_PATH/PARDA_TLS_KEY_PATH \
                 for any real deployment."
            ),
        }
    }

    /// Build the `axum-server` rustls config, generating a self-signed
    /// certificate if that is what was configured. `Ok(None)` means
    /// plaintext.
    pub async fn build_config(&self) -> Result<Option<RustlsConfig>, TlsError> {
        match self {
            Self::Disabled => Ok(None),
            Self::FromFiles { cert_path, key_path } => {
                let config = RustlsConfig::from_pem_file(cert_path, key_path)
                    .await
                    .map_err(|e| TlsError::CertificateLoad(e.to_string()))?;
                Ok(Some(config))
            }
            Self::SelfSigned { subject_alt_names } => {
                let (cert_pem, key_pem) = dev_certificate(subject_alt_names)?;
                let config = RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes())
                    .await
                    .map_err(|e| TlsError::CertificateLoad(e.to_string()))?;
                Ok(Some(config))
            }
        }
    }
}

/// Generate a self-signed certificate + private key, both PEM-encoded.
///
/// **Development and testing only.** A self-signed certificate provides
/// confidentiality against a *passive* eavesdropper and nothing more: a
/// client has no way to distinguish this server's certificate from one
/// an active man-in-the-middle generated for itself, so it defends
/// against exactly the weaker of the two adversaries. This is the same
/// honesty boundary `sealed_sender`'s in-process trust root already
/// draws for itself — a working demo path, explicitly not production
/// guidance.
pub fn dev_certificate(subject_alt_names: &[String]) -> Result<(String, String), TlsError> {
    let cert = rcgen::generate_simple_self_signed(subject_alt_names.to_vec())
        .map_err(|e| TlsError::CertificateGeneration(e.to_string()))?;
    Ok((cert.cert.pem(), cert.key_pair.serialize_pem()))
}

/// Serve `app` on `addr`, over TLS if `settings` says so, plaintext
/// otherwise. Installs the rustls provider first — callers do not have
/// to remember to.
///
/// Both paths use a **connect-info** make service, so handlers and
/// middleware can extract `ConnectInfo<SocketAddr>` for the peer
/// address. `parda-gateway`'s rate limiter depends on this to give each
/// unauthenticated client its own token bucket rather than sharing one
/// (see `gateway/src/auth.rs`); serving without connect info would
/// silently degrade that to a single global bucket, so it is set here
/// once for every PARDA server rather than left to each binary to
/// remember.
pub async fn serve(addr: SocketAddr, app: Router, settings: &TlsSettings) -> Result<(), TlsError> {
    install_ring_provider();
    settings.log_posture();

    match settings.build_config().await? {
        Some(config) => {
            // `axum_server::bind_rustls` defers the actual bind until the
            // returned server is awaited, so there is no earlier point at
            // which a successful bind can be confirmed here.
            tracing::info!(%addr, "listening (TLS)");
            axum_server::bind_rustls(addr, config)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .map_err(|e| TlsError::Serve(e.to_string()))
        }
        None => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| TlsError::Serve(format!("failed to bind {addr}: {e}")))?;
            // Logged only once the bind has actually succeeded — a server
            // that announces it is listening and then dies on a port
            // conflict sends whoever is reading the logs after the wrong
            // problem.
            tracing::info!(addr = %listener.local_addr().unwrap_or(addr), "listening");
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(|e| TlsError::Serve(e.to_string()))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error(
        "TLS is half-configured: {which_is_set} is set but its counterpart is not. Set both \
         PARDA_TLS_CERT_PATH and PARDA_TLS_KEY_PATH, or neither (for a self-signed development \
         certificate)."
    )]
    HalfConfigured { which_is_set: &'static str },

    #[error("failed to load TLS certificate/key: {0}")]
    CertificateLoad(String),

    #[error("failed to generate a self-signed development certificate: {0}")]
    CertificateGeneration(String),

    #[error("server error: {0}")]
    Serve(String),
}
