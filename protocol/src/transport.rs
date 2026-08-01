//! Transport layer abstraction.
//!
//! The `TransportLayer` trait decouples the crypto/session layer from
//! the underlying message delivery mechanism. `DirectTransport` POSTs
//! envelopes directly to the relay server via HTTP. `MixTransport`
//! (Sub-Phase 2B) routes the *send* path through a Sphinx mix network
//! first. `SessionManager` does not need to change between the two —
//! only the `TransportLayer` implementation is swapped.
//!
//! ```text
//! DirectTransport:  SessionManager → DirectTransport → Relay Server
//! MixTransport:      SessionManager → MixTransport → Mix Network → Relay Server
//! ```
//!
//! ## `MixTransport` receive-path scope
//!
//! `MixTransport::receive` fetches from the relay exactly the way
//! `DirectTransport` does — mix routing in this sub-phase anonymizes only
//! the *send* path (which entry connection correlates with which envelope
//! the relay ultimately receives). `recipient_id` is necessarily plaintext
//! to the relay regardless (routing requires it — see
//! `docs/THREAT_MODEL.md` §3.1/§3.5), so pulling messages by
//! `recipient_id` doesn't leak anything beyond what's already documented
//! as visible to the relay. Anonymizing the pull side too would need a
//! Loopix-style provider/pull protocol — a materially separate feature,
//! not attempted here. This boundary is deliberate, not an oversight; see
//! `docs/THREAT_MODEL.md` §3.6.
//!
//! ## Fail-closed
//!
//! `MixTransport::send` never falls back to a direct relay POST if the
//! mix network is unreachable. A network-level adversary who can block
//! the first hop must not be able to force a metadata-leaking fallback —
//! see `mixnode_tests` / `protocol/tests/mixnet_tests.rs`.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::{
    envelope::MessageEnvelope,
    error::{PardaError, Result},
    mixnet::{self, MixTopology},
};

/// Matches `parda-relay`'s actual `GET /v1/messages/{user_id}` response
/// shape (`server/src/models.rs::FetchMessagesResponse` — `{"messages":
/// [...]}`, not a bare array). Not re-exported: this is purely a
/// deserialization target for `receive()`, kept in sync with the relay's
/// wire shape by hand since `protocol` doesn't depend on `server`
/// (that dependency would run the wrong direction — the relay depends on
/// the protocol crate, not vice versa).
///
/// This mismatch was live in both `DirectTransport::receive` and
/// `MixTransport::receive` — deserializing straight into `Vec<MessageEnvelope>`
/// — from Phase 1 until Sub-Phase 3D's CLI prototype exercised `receive()`
/// against a real relay for the first time and hit it immediately. No
/// existing test called `receive()` against a live relay before that;
/// `grep -r DirectTransport` across the whole repo, pre-fix, turned up
/// zero test files. Recorded here, not just fixed silently, because it's
/// exactly the kind of gap a real end-to-end harness catches and a
/// mocked/unit-only one doesn't — the brief's stated reason for building
/// the CLI early.
#[derive(Deserialize)]
struct FetchMessagesResponse {
    messages: Vec<MessageEnvelope>,
}

// ─── Transport trait ──────────────────────────────────────────────────────────

/// Abstract transport: send an envelope and fetch pending envelopes.
///
/// Implementors MUST NOT inspect or modify `MessageEnvelope::ciphertext`.
#[async_trait]
pub trait TransportLayer: Send + Sync {
    /// Transmit `envelope` to the relay (or mix network in Phase 2).
    async fn send(&self, envelope: &MessageEnvelope) -> Result<()>;

    /// Fetch and remove all pending envelopes for `recipient_id`.
    async fn receive(&self, recipient_id: &str) -> Result<Vec<MessageEnvelope>>;
}

// ─── Phase 1: Direct HTTP transport ──────────────────────────────────────────

/// Phase 1 transport: sends envelopes directly to the relay server via HTTP.
///
/// No metadata obfuscation. Replace with `MixTransport` in Phase 2.
pub struct DirectTransport {
    /// Base URL of the relay server, e.g. `http://127.0.0.1:8080`.
    relay_base_url: String,
    /// HTTP client.
    http: reqwest::Client,
}

impl DirectTransport {
    pub fn new(relay_base_url: impl Into<String>) -> Self {
        Self {
            relay_base_url: relay_base_url.into(),
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl TransportLayer for DirectTransport {
    async fn send(&self, envelope: &MessageEnvelope) -> Result<()> {
        let url = format!(
            "{}/v1/messages/{}",
            self.relay_base_url, envelope.recipient_id
        );
        self.http
            .post(&url)
            .json(envelope)
            .send()
            .await
            .map_err(|e| PardaError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| PardaError::Transport(e.to_string()))?;
        Ok(())
    }

    async fn receive(&self, recipient_id: &str) -> Result<Vec<MessageEnvelope>> {
        let url = format!("{}/v1/messages/{}", self.relay_base_url, recipient_id);
        let response: FetchMessagesResponse = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| PardaError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| PardaError::Transport(e.to_string()))?
            .json()
            .await
            .map_err(|e| PardaError::Transport(e.to_string()))?;
        Ok(response.messages)
    }
}

// ─── Sub-Phase 2B: Sphinx mix-network transport ────────────────────────────────

/// Default average per-hop mixing delay. Configurable via
/// [`MixTransport::with_avg_delay`] — this is a threat-model parameter
/// (higher delay → stronger timing-correlation resistance, at the cost of
/// latency), not a value to hardcode past a sensible default.
pub const DEFAULT_AVG_DELAY: Duration = Duration::from_millis(200);

/// Sends over a Sphinx mix network ([`crate::mixnet`]); receives directly
/// from the relay. See module docs for the receive-path scope boundary
/// and the fail-closed requirement on `send`.
pub struct MixTransport {
    topology: MixTopology,
    path_length: usize,
    avg_delay: Duration,
    payload_size: usize,
    relay_base_url: String,
    http: reqwest::Client,
}

impl MixTransport {
    /// `topology` is the static, TOFU-configured list of known mix nodes
    /// (see [`MixTopology`] docs for the trust posture this carries).
    /// `relay_base_url` is used only for `receive()` and for the
    /// destination the mix network's final hop delivers to.
    pub fn new(topology: MixTopology, relay_base_url: impl Into<String>) -> Self {
        Self {
            topology,
            path_length: mixnet::MIN_PATH_LENGTH,
            avg_delay: DEFAULT_AVG_DELAY,
            payload_size: mixnet::DEFAULT_MIX_PAYLOAD_SIZE,
            relay_base_url: relay_base_url.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Override the path length. Refuses anything below
    /// [`mixnet::MIN_PATH_LENGTH`] at build-packet time, not silently
    /// clamped here.
    #[must_use]
    pub fn with_path_length(mut self, path_length: usize) -> Self {
        self.path_length = path_length;
        self
    }

    #[must_use]
    pub fn with_avg_delay(mut self, avg_delay: Duration) -> Self {
        self.avg_delay = avg_delay;
        self
    }

    #[must_use]
    pub fn with_payload_size(mut self, payload_size: usize) -> Self {
        self.payload_size = payload_size;
        self
    }
}

#[async_trait]
impl TransportLayer for MixTransport {
    async fn send(&self, envelope: &MessageEnvelope) -> Result<()> {
        let path = self.topology.choose_path(self.path_length)?;
        let envelope_bytes = serde_json::to_vec(envelope)?;
        let packet_bytes = mixnet::build_packet(
            &envelope_bytes,
            &path,
            self.avg_delay,
            self.payload_size,
        )?;

        // Deliberately no fallback to a direct relay POST on failure here
        // — see module docs "Fail-closed".
        let first_hop = &path[0];
        let url = format!("http://{}/mix/packet", first_hop.address);
        self.http
            .post(&url)
            .body(packet_bytes)
            .send()
            .await
            .map_err(|e| PardaError::Transport(format!("mix network first hop unreachable: {e}")))?
            .error_for_status()
            .map_err(|e| PardaError::Transport(format!("mix network first hop rejected packet: {e}")))?;
        Ok(())
    }

    async fn receive(&self, recipient_id: &str) -> Result<Vec<MessageEnvelope>> {
        // See module docs "MixTransport receive-path scope" — intentionally
        // identical to DirectTransport's fetch.
        let url = format!("{}/v1/messages/{}", self.relay_base_url, recipient_id);
        let response: FetchMessagesResponse = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| PardaError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| PardaError::Transport(e.to_string()))?
            .json()
            .await
            .map_err(|e| PardaError::Transport(e.to_string()))?;
        Ok(response.messages)
    }
}
