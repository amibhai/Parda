//! Transport layer abstraction — Phase 2 extension point.
//!
//! The `TransportLayer` trait decouples the crypto/session layer from
//! the underlying message delivery mechanism. In Phase 1 the only
//! implementation is `DirectTransport`, which POSTs envelopes directly
//! to the relay server via HTTPS.
//!
//! In Phase 2 a `MixTransport` will implement the same trait, routing
//! envelopes through a Sphinx-packet mix network before delivery. The
//! `SessionManager` will not need to change — only the `TransportLayer`
//! implementation is swapped.
//!
//! ```text
//! Phase 1:  SessionManager → DirectTransport → Relay Server
//! Phase 2:  SessionManager → MixTransport → Mix Network → Relay Server
//! ```

use async_trait::async_trait;

use crate::{
    envelope::MessageEnvelope,
    error::{PardaError, Result},
};

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
        let envelopes: Vec<MessageEnvelope> = self
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
        Ok(envelopes)
    }
}

// ─── Phase 2 stub ─────────────────────────────────────────────────────────────

/// Placeholder for the Phase 2 Sphinx-packet mix-network transport.
///
/// This type exists to show where Phase 2 will plug in.
/// It panics if constructed — it is not yet implemented.
///
/// TODO(phase2): Implement Sphinx packet construction, onion encryption,
/// cover traffic scheduler, and Loopix-inspired batching delay here.
pub struct MixTransport;

#[async_trait]
impl TransportLayer for MixTransport {
    async fn send(&self, _envelope: &MessageEnvelope) -> Result<()> {
        unimplemented!("MixTransport is a Phase 2 deliverable")
    }

    async fn receive(&self, _recipient_id: &str) -> Result<Vec<MessageEnvelope>> {
        unimplemented!("MixTransport is a Phase 2 deliverable")
    }
}
