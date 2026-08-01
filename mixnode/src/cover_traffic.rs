//! Loopix-style "drop cover" traffic scheduler.
//!
//! Each node independently emits dummy Sphinx packets at
//! exponentially-distributed intervals (`sample_exponential_delay`,
//! Piotrowska et al., "The Loopix Anonymity System", USENIX Security
//! 2017), routed through a real path of its configured peers and tagged
//! [`parda_protocol::mixnet::COVER_DESTINATION_TAG`] so whichever node
//! processes the final hop discards it instead of delivering to the
//! relay. Real and cover packets are fixed-size Sphinx packets carried
//! through the identical per-hop mixing path (`mixing::schedule`), so a
//! GPA observing ingress/egress at any single node cannot distinguish
//! them by size or by timing behavior.
//!
//! Cover traffic must be validly Sphinx-encrypted to be indistinguishable
//! from real traffic — it can't be conjured without knowing who it's
//! nominally routed through. This is why a node needs `MIXNODE_PEERS`
//! (address + public key for at least [`mixnet::MIN_PATH_LENGTH`] peers).
//! This is a smaller trust requirement than the client-side
//! `MixTopology` (a node only needs its immediate peers, not the whole
//! network), but it is a config a node operator must still provide. If
//! too few peers are configured, cover traffic is simply not emitted —
//! logged clearly as a limitation, not silently degraded to "less cover
//! traffic than intended."
//!
//! ## Sub-Phase 4.5A: pull-request cover traffic
//!
//! [`spawn_pull_cover`] emits dummy packets tagged
//! [`parda_protocol::mixnet::PULL_DESTINATION_TAG`] — unlike the
//! `COVER_DESTINATION_TAG` traffic above, these are **not** discarded at
//! the final hop. They carry a real (if fabricated, never-to-be-claimed)
//! [`parda_protocol::mixnet::PullRequest`] and genuinely reach the
//! relay's `POST /v1/pulls`, exactly like a real pull would — that's the
//! point: the signal this masks is "did a pull arrive at the relay right
//! now," which only exists at `/v1/pulls` itself, not earlier in the mix
//! path, so discarding before reaching the relay (like ordinary drop
//! cover) wouldn't mask it. The fabricated recipient/token are never
//! shared with anyone, so the resulting staged entry is simply never
//! claimed and expires off `RelayStore::stage_pull`'s own TTL sweep —
//! the same harmless-unclaimed-entry shape a real pull that's abandoned
//! mid-flight would also produce, not a special case the relay needs to
//! distinguish.

use std::time::Duration;

use parda_protocol::mixnet::{self, MixNodeDescriptor, PullRequest};
use rand::{seq::SliceRandom, Rng};

use crate::SharedMixNodeState;

const COVER_PAYLOAD_MARKER: &[u8] = b"parda-drop-cover";

/// Spawn the cover-traffic loop. No-op (with a warning) if fewer than
/// [`mixnet::MIN_PATH_LENGTH`] peers are configured — see module docs.
pub fn spawn(state: SharedMixNodeState, peers: Vec<MixNodeDescriptor>, avg_interval: Duration) {
    if peers.len() < mixnet::MIN_PATH_LENGTH {
        tracing::warn!(
            configured_peers = peers.len(),
            required = mixnet::MIN_PATH_LENGTH,
            "MIXNODE_PEERS has too few entries — this node will not emit cover traffic. \
             Real traffic routed through it is still correctly mixed, but its own \
             egress volume will vary with real load, which a GPA can observe."
        );
        return;
    }

    tokio::spawn(async move {
        loop {
            let wait = mixnet::sample_exponential_delay(avg_interval);
            tokio::time::sleep(wait).await;

            let path: Vec<MixNodeDescriptor> = {
                let mut rng = rand::thread_rng();
                peers
                    .choose_multiple(&mut rng, mixnet::MIN_PATH_LENGTH)
                    .cloned()
                    .collect()
            };

            match mixnet::build_packet_to(
                COVER_PAYLOAD_MARKER,
                &path,
                avg_interval,
                mixnet::DEFAULT_MIX_PAYLOAD_SIZE,
                mixnet::COVER_DESTINATION_TAG,
            ) {
                Ok(packet_bytes) => {
                    let url = format!("http://{}/mix/packet", path[0].address);
                    if let Err(e) = state.http.post(&url).body(packet_bytes).send().await {
                        tracing::debug!(error = %e, "cover packet emission failed (non-fatal)");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "failed to build cover packet"),
            }
        }
    });
}

/// Spawn the pull-cover-traffic loop — see module docs. Same
/// too-few-peers no-op/warning posture as [`spawn`], same exponential
/// scheduling, same peer set; a genuinely separate loop (not merged into
/// `spawn`) because it builds a different, real `PullRequest` payload
/// rather than an opaque marker.
pub fn spawn_pull_cover(state: SharedMixNodeState, peers: Vec<MixNodeDescriptor>, avg_interval: Duration) {
    if peers.len() < mixnet::MIN_PATH_LENGTH {
        tracing::warn!(
            configured_peers = peers.len(),
            required = mixnet::MIN_PATH_LENGTH,
            "MIXNODE_PEERS has too few entries — this node will not emit pull-cover traffic \
             either, for the same reason drop-cover traffic is skipped."
        );
        return;
    }

    tokio::spawn(async move {
        loop {
            let wait = mixnet::sample_exponential_delay(avg_interval);
            tokio::time::sleep(wait).await;

            let path: Vec<MixNodeDescriptor> = {
                let mut rng = rand::thread_rng();
                peers
                    .choose_multiple(&mut rng, mixnet::MIN_PATH_LENGTH)
                    .cloned()
                    .collect()
            };

            // Fabricated, never-shared recipient — nobody will ever poll
            // for this token, so the resulting relay-side stage simply
            // expires unclaimed. Random length so the fabricated ID
            // doesn't have an obviously-synthetic fixed shape.
            let fake_recipient: String = {
                let mut rng = rand::thread_rng();
                let len = rng.gen_range(8..24);
                (0..len).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect()
            };
            let request = PullRequest::new(fake_recipient);
            let payload = match serde_json::to_vec(&request) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to serialise pull-cover payload");
                    continue;
                }
            };

            match mixnet::build_packet_to(
                &payload,
                &path,
                avg_interval,
                mixnet::DEFAULT_MIX_PAYLOAD_SIZE,
                mixnet::PULL_DESTINATION_TAG,
            ) {
                Ok(packet_bytes) => {
                    let url = format!("http://{}/mix/packet", path[0].address);
                    if let Err(e) = state.http.post(&url).body(packet_bytes).send().await {
                        tracing::debug!(error = %e, "pull-cover packet emission failed (non-fatal)");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "failed to build pull-cover packet"),
            }
        }
    });
}
