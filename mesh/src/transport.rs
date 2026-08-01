//! Mesh node propagation driver (Sub-Phase 4B) and
//! [`parda_protocol::transport::TransportLayer`] implementation
//! (Sub-Phase 4C — see that sub-phase's design note; the `TransportLayer`
//! impl itself lands once the dead-drop addressing scheme it depends on
//! is designed and reviewed, per this phase's explicit build order).
//!
//! [`MeshNode`] is the 4B-scoped piece: it owns a [`MeshRadio`] and a
//! [`MeshRelayAgent`] and drives opportunistic epidemic propagation —
//! scanning for peers, connecting out to ones it sees, accepting
//! connections from ones that see it, and running
//! [`MeshRelayAgent::sync_with_peer`] on every resulting link. This is
//! genuinely all the store-and-forward relay agent needs to do; there is
//! no separate "routing" decision beyond "sync with whoever's in range,"
//! which is the flooding/epidemic strategy — the simplest of the routing
//! families `dtn7-rs` itself names (see `bundle.rs` module docs).

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use parda_protocol::{
    dead_drop::{Address, TagKey},
    envelope::MessageEnvelope,
    error::{PardaError, Result as ProtoResult},
    transport::TransportLayer,
};

use crate::{
    bundle,
    error::Result,
    radio::MeshRadio,
    relay::MeshRelayAgent,
};

/// A running mesh device: its radio and its relay agent, wired together.
pub struct MeshNode {
    pub radio: Arc<dyn MeshRadio>,
    pub relay: Arc<MeshRelayAgent>,
}

impl MeshNode {
    pub fn new(radio: Arc<dyn MeshRadio>, relay: Arc<MeshRelayAgent>) -> Arc<Self> {
        Arc::new(Self { radio, relay })
    }

    /// One outbound propagation pass: scan for currently-visible peers,
    /// connect to each, and sync. Returns the total number of bundles
    /// admitted across all peers synced with in this pass. Used directly
    /// by tests that want deterministic, single-shot propagation instead
    /// of the background loop.
    pub async fn sync_once(&self) -> Result<usize> {
        let mut stream = self.radio.scan().await?;
        let mut total_admitted = 0usize;
        while let Some(sighting) = stream.recv().await {
            match self.radio.connect(&sighting.handle).await {
                Ok(mut link) => match self.relay.sync_with_peer(link.as_mut()).await {
                    Ok(admitted) => total_admitted += admitted,
                    Err(e) => tracing::debug!(error = %e, "sync with peer failed (non-fatal)"),
                },
                Err(e) => tracing::debug!(error = %e, "connect to sighted peer failed (non-fatal)"),
            }
        }
        Ok(total_admitted)
    }

    /// Background loop: repeatedly [`Self::sync_once`] on `interval`.
    pub fn spawn_sync_loop(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = self.sync_once().await {
                    tracing::debug!(error = %e, "sync_once failed (non-fatal)");
                }
            }
        })
    }

    /// Background loop: repeatedly accept inbound connections and sync
    /// with each. Symmetric to [`Self::spawn_sync_loop`] — a device
    /// propagates bundles both by connecting out to peers it sees and by
    /// accepting connections from peers that see it.
    pub fn spawn_accept_loop(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                match self.radio.accept().await {
                    Ok(mut link) => {
                        let relay = Arc::clone(&self.relay);
                        tokio::spawn(async move {
                            if let Err(e) = relay.sync_with_peer(link.as_mut()).await {
                                tracing::debug!(error = %e, "inbound sync failed (non-fatal)");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "accept failed — stopping accept loop");
                        break;
                    }
                }
            }
        })
    }
}

// ─── Sub-Phase 4C: TransportLayer implementation ───────────────────────────

/// Default forward-polling window: how many upcoming counter values a
/// receiver polls for per call, tolerating that many messages'
/// worth of reordering/loss — see
/// `docs/phase4-4c-dead-drop-addressing-design.md` §2.
pub const DEFAULT_ADDRESS_WINDOW: usize = 8;

/// Default decoys per real address polled — see design note §3.
/// Matches the scale `mesh/tests/retrieval_pattern_tests.rs` measures
/// against.
pub const DEFAULT_DECOYS_PER_REAL: usize = 7;

struct ReceiveState {
    /// Lowest counter value not yet confirmed delivered. Only advances
    /// past a *contiguous* run of claimed indices — an out-of-order
    /// early arrival is remembered in `claimed_ahead` without moving
    /// this forward, so a still-missing lower index keeps being polled
    /// for rather than silently skipped. See design note §2.
    low_watermark: u64,
    claimed_ahead: HashSet<u64>,
}

/// The third [`TransportLayer`] implementation, alongside
/// `DirectTransport`/`MixTransport` (`parda_protocol::transport`) —
/// Sub-Phase 4C. One `MeshTransport` instance serves one conversation's
/// dead-drop channel (it owns that conversation's [`TagKey`] and
/// counter state); a client talking to multiple peers over mesh holds
/// one instance per peer, the same way a real deployment would hold
/// distinct session state per peer for `SessionManager` itself.
pub struct MeshTransport {
    node: Arc<MeshNode>,
    tag_key: TagKey,
    send_counter: AtomicU64,
    receive_state: Mutex<ReceiveState>,
    window: usize,
    decoys_per_real: usize,
}

impl MeshTransport {
    pub fn new(node: Arc<MeshNode>, tag_key: TagKey) -> Self {
        Self {
            node,
            tag_key,
            send_counter: AtomicU64::new(0),
            receive_state: Mutex::new(ReceiveState {
                low_watermark: 0,
                claimed_ahead: HashSet::new(),
            }),
            window: DEFAULT_ADDRESS_WINDOW,
            decoys_per_real: DEFAULT_DECOYS_PER_REAL,
        }
    }

    #[must_use]
    pub fn with_window(mut self, window: usize) -> Self {
        self.window = window;
        self
    }

    #[must_use]
    pub fn with_decoys_per_real(mut self, decoys: usize) -> Self {
        self.decoys_per_real = decoys;
        self
    }

    /// The address the *next* [`Self::send`] on this instance will use —
    /// exposed so a caller composing a `MessageEnvelope` can set
    /// `dead_drop_address` before calling `send` (this transport reads
    /// that field; it does not derive it lazily inside `send`, since the
    /// envelope is meant to be composable once and handed to whichever
    /// transport ends up carrying it — see design note §4).
    pub fn next_send_address(&self) -> Address {
        let n = self.send_counter.load(Ordering::SeqCst);
        self.tag_key.address_for(n)
    }

    /// Advance the send counter after composing an envelope with
    /// [`Self::next_send_address`]. Separate from `send` itself so a
    /// caller can compose (and retry sending) the same envelope without
    /// silently burning counter values on a failed attempt — only a
    /// successful hand-off to local storage advances it.
    fn advance_send_counter(&self) {
        self.send_counter.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl TransportLayer for MeshTransport {
    /// Requires `envelope.dead_drop_address` to already be set (via
    /// [`MeshTransport::next_send_address`] at composition time) and
    /// `envelope.sealed_sender == true` with both `sender_id` and
    /// `recipient_id` empty — fail-closed, the same posture
    /// `MixTransport::send` already takes toward an unreachable first
    /// hop (`protocol/src/transport.rs` module docs "Fail-closed"). See
    /// `mesh/src/bundle.rs::wrap`'s doc comment for why this is this
    /// layer's responsibility rather than the bundle-framing layer's.
    async fn send(&self, envelope: &MessageEnvelope) -> ProtoResult<()> {
        if !envelope.sealed_sender || !envelope.sender_id.is_empty() || !envelope.recipient_id.is_empty()
        {
            return Err(PardaError::Transport(
                "MeshTransport::send refuses an envelope that isn't sealed_sender=true with \
                 empty sender_id/recipient_id — a mesh carrier would otherwise learn identity \
                 metadata the blinded address exists specifically to avoid leaking; see \
                 docs/phase4-4c-dead-drop-addressing-design.md"
                    .to_string(),
            ));
        }
        let address = envelope.dead_drop_address.ok_or_else(|| {
            PardaError::Transport(
                "MeshTransport::send requires envelope.dead_drop_address to be set \
                 (see MeshTransport::next_send_address)"
                    .to_string(),
            )
        })?;

        let bytes = bundle::wrap(envelope, address)
            .map_err(|e| PardaError::Transport(format!("mesh bundle framing failed: {e}")))?;
        self.node
            .relay
            .admit(bytes)
            .map_err(|e| PardaError::Transport(format!("local relay refused own outgoing bundle: {e}")))?;
        self.advance_send_counter();
        Ok(())
    }

    /// Ignores `recipient_id` (mesh routing uses the address window
    /// derived from [`TagKey`], not a plaintext recipient identifier —
    /// see module docs on `parda_protocol::transport`'s receive-path
    /// scope for why `DirectTransport`/`MixTransport` still need it and
    /// this transport doesn't). Polls a forward window of addresses,
    /// each accompanied by decoys (design note §3), and claims
    /// (removes from local storage) any bundles matching a *real*
    /// address — see [`MeshRelayAgent::take_for_addresses`] for why
    /// claiming is correct here specifically.
    async fn receive(&self, _recipient_id: &str) -> ProtoResult<Vec<MessageEnvelope>> {
        let (poll_set, window_start) = {
            let state = self.receive_state.lock().unwrap();
            (
                parda_protocol::dead_drop::build_poll_set(
                    &self.tag_key,
                    state.low_watermark,
                    self.window,
                    self.decoys_per_real,
                ),
                state.low_watermark,
            )
        };
        let window_addresses = self.tag_key.address_window(window_start, self.window);

        let taken = self.node.relay.take_for_addresses(&poll_set);

        let mut envelopes = Vec::with_capacity(taken.len());
        let mut newly_claimed: Vec<u64> = Vec::with_capacity(taken.len());
        for bytes in taken {
            let Ok((address, envelope)) = bundle::unwrap(&bytes) else {
                continue; // malformed bundle at a real address — drop, don't fail the whole poll
            };
            if let Some(offset) = window_addresses.iter().position(|a| *a == address) {
                newly_claimed.push(window_start + offset as u64);
                envelopes.push(envelope);
            }
            // else: a decoy happened to match something in storage —
            // astronomically unlikely at 32 bytes of address space (same
            // reasoning as radio::AdvertToken's collision analysis) and
            // not this transport's to explain away further; the bundle
            // is simply not decodable as belonging to this window and is
            // dropped rather than guessed at.
        }

        let mut state = self.receive_state.lock().unwrap();
        for n in newly_claimed {
            state.claimed_ahead.insert(n);
        }
        loop {
            let watermark = state.low_watermark;
            if !state.claimed_ahead.remove(&watermark) {
                break;
            }
            state.low_watermark += 1;
        }

        Ok(envelopes)
    }
}
