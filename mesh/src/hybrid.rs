//! Hybrid online/mesh handoff (Sub-Phase 4D).
//!
//! Composes any two [`TransportLayer`] implementations — in practice a
//! networked one (`DirectTransport`/`MixTransport`) as `primary` and
//! [`crate::transport::MeshTransport`] as `fallback` — so a client
//! automatically uses the network when it's reachable and falls back to
//! mesh when it isn't, without the caller manually switching transports
//! or losing state across the transition. No new per-message state is
//! introduced here: the state that matters (the dead-drop send/receive
//! counters — `docs/phase4-4c-dead-drop-addressing-design.md` §2) already
//! lives inside the `fallback` transport itself, which `HybridTransport`
//! merely holds a reference to rather than reconstructing per call, so
//! it survives across however many `send`/`receive` calls straddle a
//! connectivity transition.
//!
//! ## Why `send` redacts `recipient_id` before falling back, not before
//!
//! A single envelope composed once needs `recipient_id` populated for
//! the *networked* path (the relay routes on it — see
//! `protocol/src/transport.rs`) and empty for the *mesh* path
//! (`MeshTransport::send` refuses a populated one, fail-closed, to keep
//! it from leaking to an untrusted carrier — see
//! `mesh/src/bundle.rs::wrap`'s doc comment). These requirements are
//! genuinely incompatible on one wire value, not a small omission to
//! paper over: the honest fix is for `HybridTransport` to hand the
//! networked transport the caller's envelope exactly as composed, and
//! hand the mesh transport a redacted **clone** with `recipient_id`
//! cleared — an internal transport-layer decision, not something that
//! forces the caller to compose two different envelope shapes up front.
//! `sender_id` needs no equivalent redaction: a properly sealed-sender
//! envelope already carries `sender_id = ""` for *every* transport, not
//! just mesh.

use async_trait::async_trait;
use parda_protocol::{envelope::MessageEnvelope, error::Result as ProtoResult, transport::TransportLayer};

/// Prefers `primary`; falls back to `fallback` on failure. See module
/// docs for the `recipient_id` redaction `send` performs specifically
/// for the fallback path.
pub struct HybridTransport<P: TransportLayer, F: TransportLayer> {
    primary: P,
    fallback: F,
}

impl<P: TransportLayer, F: TransportLayer> HybridTransport<P, F> {
    pub fn new(primary: P, fallback: F) -> Self {
        Self { primary, fallback }
    }
}

#[async_trait]
impl<P: TransportLayer, F: TransportLayer> TransportLayer for HybridTransport<P, F> {
    async fn send(&self, envelope: &MessageEnvelope) -> ProtoResult<()> {
        match self.primary.send(envelope).await {
            Ok(()) => Ok(()),
            Err(primary_err) => {
                tracing::debug!(
                    error = %primary_err,
                    "primary transport unavailable, falling back to mesh"
                );
                let mut mesh_envelope = envelope.clone();
                mesh_envelope.recipient_id = String::new();
                self.fallback.send(&mesh_envelope).await
            }
        }
    }

    /// Merges whatever's available from both paths — a message
    /// delivered while online and a message picked up from the mesh are
    /// structurally disjoint (each only ever exists wherever it was
    /// actually sent), so concatenating rather than choosing one is
    /// correct, not merely convenient. The primary path failing (e.g.
    /// still offline) degrades to "mesh only, this call," not an error —
    /// a caller polling periodically shouldn't have to treat "network's
    /// still down" as exceptional.
    async fn receive(&self, recipient_id: &str) -> ProtoResult<Vec<MessageEnvelope>> {
        let mut combined = match self.primary.receive(recipient_id).await {
            Ok(envelopes) => envelopes,
            Err(e) => {
                tracing::debug!(error = %e, "primary transport unavailable for receive, checking mesh only");
                Vec::new()
            }
        };
        match self.fallback.receive(recipient_id).await {
            Ok(mut from_mesh) => combined.append(&mut from_mesh),
            Err(e) => tracing::debug!(error = %e, "mesh transport unavailable for receive, checking primary only"),
        }
        Ok(combined)
    }
}
