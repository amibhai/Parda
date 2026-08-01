//! Per-hop Loopix-style mixing delay.
//!
//! Deliberately **not** a batching queue with flush semantics. The
//! sender already sampled this packet's delay when it built the Sphinx
//! packet (see `parda_protocol::mixnet` module docs) — a node's only job
//! is to hold the packet for that long, then act. Modelling this as a
//! synchronised batch-and-flush would add nothing and would reintroduce
//! a "which packets shared a batch" correlation signal that Loopix's
//! continuous-time, per-packet delay design specifically avoids.

use parda_protocol::{
    envelope::MessageEnvelope,
    mixnet::{PullRequest, UnwrapOutcome},
};

use crate::SharedMixNodeState;

/// Spawn a detached task that waits the packet's instructed delay, then
/// forwards or delivers according to `outcome`. Returns immediately —
/// the HTTP handler that received the packet must not block its response
/// on another node's or the relay's latency, the same way a real mix
/// node's ingress can't stall on egress.
pub fn schedule(state: SharedMixNodeState, outcome: UnwrapOutcome) {
    tokio::spawn(async move {
        match outcome {
            UnwrapOutcome::Forward {
                next_hop_address,
                delay,
                packet_bytes,
            } => {
                tokio::time::sleep(delay).await;
                if let Err(e) = forward(&state, &next_hop_address, packet_bytes).await {
                    tracing::warn!(
                        next_hop = %next_hop_address,
                        error = %e,
                        "failed to forward mix packet"
                    );
                }
            }
            UnwrapOutcome::Deliver { envelope_bytes } => {
                deliver(&state, envelope_bytes).await;
            }
            UnwrapOutcome::PullRequest { request_bytes } => {
                stage_pull(&state, request_bytes).await;
            }
            UnwrapOutcome::DropCover => {
                tracing::debug!("discarded drop-cover packet at its final hop");
            }
        }
    });
}

async fn forward(
    state: &SharedMixNodeState,
    next_hop_address: &str,
    packet_bytes: Vec<u8>,
) -> Result<(), reqwest::Error> {
    let url = format!("http://{next_hop_address}/mix/packet");
    state
        .http
        .post(&url)
        .body(packet_bytes)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// Sub-Phase 4.5A: final-hop handling for a `PULL_DESTINATION_TAG`
/// packet — POST the decoded [`PullRequest`] to the relay's `/v1/pulls`
/// staging endpoint instead of delivering an envelope. See
/// `docs/phase4.5a-receive-path-design.md`. Same fire-and-forget shape
/// as [`deliver`] — this node never learns or needs to know whether the
/// client ever actually retrieves what gets staged.
async fn stage_pull(state: &SharedMixNodeState, request_bytes: Vec<u8>) {
    let request: PullRequest = match serde_json::from_slice(&request_bytes) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "final-hop payload did not deserialise as a PullRequest — dropping"
            );
            return;
        }
    };
    let url = format!("{}/v1/pulls", state.relay_base_url);
    match state.http.post(&url).json(&request).send().await {
        Ok(resp) => {
            if let Err(e) = resp.error_for_status() {
                tracing::warn!(error = %e, "relay rejected mix-routed pull request");
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to reach relay for mix-routed pull request"),
    }
}

async fn deliver(state: &SharedMixNodeState, envelope_bytes: Vec<u8>) {
    let envelope: MessageEnvelope = match serde_json::from_slice(&envelope_bytes) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "final-hop payload did not deserialise as a MessageEnvelope — dropping"
            );
            return;
        }
    };
    let url = format!("{}/v1/messages/{}", state.relay_base_url, envelope.recipient_id);
    match state.http.post(&url).json(&envelope).send().await {
        Ok(resp) => {
            if let Err(e) = resp.error_for_status() {
                tracing::warn!(error = %e, "relay rejected mix-routed envelope");
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to reach relay for mix-routed delivery"),
    }
}
