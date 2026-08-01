//! DTN store-and-forward relay agent (Sub-Phase 4B).
//!
//! Runs on every mesh-mode device — in an offline mesh with no
//! infrastructure, "the carrier" is just whichever nearby phone happened
//! to be in range, so every node is both a client and a relay for other
//! people's bundles. `MeshRelayAgent` is, from a security standpoint,
//! exactly as untrusted as the Phase 1 relay server was before sealed
//! sender — except now it's a random nearby device, not infrastructure
//! anyone operates: see `docs/THREAT_MODEL.md` §3.7.
//!
//! ## Opacity
//!
//! A relay agent stores and indexes bundles by their (opaque, blinded)
//! destination address only — [`bundle::destination_address`] — and
//! never decodes the payload block into a `MessageEnvelope`. It
//! structurally cannot recover sender, recipient, or plaintext from
//! anything it holds. `mesh/tests/malicious_carrier_tests.rs` gives a
//! simulated adversary direct access to a relay's raw backing store
//! (not going through this module's own API — a real attacker with the
//! device wouldn't be limited to it either) and proves nothing
//! recoverable is there.
//!
//! ## Flood/Sybil resistance, and why "per-peer" needed rethinking
//!
//! The brief's literal ask — "bound per-peer storage contribution,
//! rate-limit bundle acceptance from a single observed peer identity" —
//! runs into a real tension with Sub-Phase 4A's own design: this
//! project deliberately gives peers no stable identity across sessions
//! (`radio` module docs). A classic per-identity rate limiter has
//! nothing durable to key on, and building one anyway (e.g. by pinning a
//! peer to its momentary [`crate::radio::AdvertToken`]) would just
//! incentivize an attacker to rotate faster than the limiter, achieving
//! nothing but adding an identity-linkage temptation this project
//! otherwise avoids. This module's actual defenses, chosen for that
//! reason:
//!
//! 1. **A hard global storage cap** ([`RelayConfig::max_total_bundles`]) —
//!    bounded no matter how many distinct (real or Sybil) peers
//!    contributed, so total flood impact on this device is capped
//!    regardless of attacker identity count.
//! 2. **A per-connection-session admission cap**
//!    ([`RelayConfig::max_bundles_per_session`]), well below the global
//!    cap — a single sync session (one physical connection, however
//!    long it's held open) can only push a bounded slice of the total
//!    capacity. A Sybil attacker must open many separate sessions to
//!    fill storage, which costs real time/energy on a real radio even
//!    though it costs nothing to fake an *identity* — a real, if
//!    imperfect, cost this project can actually impose. **Stated
//!    honestly: this raises the cost of flooding, it does not make
//!    flooding by an attacker willing to reconnect repeatedly
//!    impossible** — no purely local defense can, without the
//!    reputation/identity infrastructure this project has already
//!    declined to build for privacy reasons.
//! 3. **Immediate rejection of anything already expired or malformed** —
//!    never even enters storage, so a flood of garbage-but-expired
//!    bundles costs the attacker bandwidth but never occupies space.
//! 4. **Content-hash dedup** — the same bundle arriving via multiple
//!    epidemic-routing paths counts once against the global cap, not
//!    once per path, so honest multi-hop propagation doesn't
//!    self-inflict the same pressure a flood would.
//! 5. **TTL sweep** ([`MeshRelayAgent::sweep_expired`]) — an unclaimed
//!    bundle is purged once its own declared lifetime elapses, so a
//!    malicious sender can't turn an honest carrier into an indefinite
//!    garbage store just by never letting a bundle expire on its own
//!    device (the carrier enforces the deadline unilaterally,
//!    independent of what the origin does with its own copy).
//!
//! ## Sync protocol
//!
//! [`MeshRelayAgent::sync_with_peer`] runs a minimal epidemic/flooding
//! exchange (the simplest of the routing families `dtn7-rs` itself
//! names — see `bundle.rs` module docs on why this project builds its
//! own minimal logic rather than embedding that daemon): both sides
//! exchange content-hash summaries of what they hold, then push whatever
//! the other side is missing, each subject to the caps above. See the
//! function's own doc comment for why this specific message ordering is
//! deadlock-free without needing an initiator/responder role split.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    bundle,
    error::{MeshError, Result},
    radio::MeshLink,
};

pub type BundleHash = [u8; 32];

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis() as u64
}

fn hash_bundle(bytes: &[u8]) -> BundleHash {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[derive(Debug, Clone, Copy)]
pub struct RelayConfig {
    /// Hard cap on total bundle *count* held at once, across every
    /// address. See module docs §1.
    pub max_total_bundles: usize,
    /// Hard cap on total bundle *bytes* held at once.
    pub max_total_bytes: usize,
    /// Cap on bundles accepted from a single sync session. See module
    /// docs §2.
    pub max_bundles_per_session: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_total_bundles: 500,
            max_total_bytes: 8 * 1024 * 1024, // 8 MiB
            max_bundles_per_session: 20,
        }
    }
}

struct StoredBundle {
    bytes: Vec<u8>,
    address: [u8; 32],
    expiry_ms: u64,
}

#[derive(Default)]
struct RelayStore {
    by_hash: HashMap<BundleHash, StoredBundle>,
    total_bytes: usize,
}

/// DTN store-and-forward relay agent. See module docs for the threat
/// model and the flood/Sybil defenses this implements.
pub struct MeshRelayAgent {
    config: RelayConfig,
    store: Mutex<RelayStore>,
}

impl MeshRelayAgent {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            store: Mutex::new(RelayStore::default()),
        }
    }

    /// Number of bundles currently held. Exposed for tests proving
    /// storage stays bounded under flooding.
    pub fn stored_count(&self) -> usize {
        self.store.lock().unwrap().by_hash.len()
    }

    pub fn stored_bytes(&self) -> usize {
        self.store.lock().unwrap().total_bytes
    }

    /// Raw access to every stored bundle's bytes, address, and expiry —
    /// deliberately the same visibility a real adversary who has seized
    /// this device would have. Used only by
    /// `mesh/tests/malicious_carrier_tests.rs`; production code never
    /// needs this (it only ever asks for bundles matching specific
    /// addresses via [`Self::bundles_for_addresses`]).
    #[doc(hidden)]
    pub fn debug_all_stored_bytes(&self) -> Vec<Vec<u8>> {
        self.store
            .lock()
            .unwrap()
            .by_hash
            .values()
            .map(|b| b.bytes.clone())
            .collect()
    }

    /// Admit one bundle directly (not via a peer sync session) — used by
    /// `MeshTransport::send` for the local device's own outgoing
    /// bundles, and directly by tests. No session cap applies here (a
    /// device's own composition isn't "a peer flooding it"), but every
    /// other check (expiry, malformed, global caps, dedup) still does.
    pub fn admit(&self, bytes: Vec<u8>) -> Result<()> {
        self.admit_checked(bytes, None)
    }

    fn admit_checked(&self, bytes: Vec<u8>, session_budget: Option<&mut usize>) -> Result<()> {
        let expiry_ms = bundle::expiry_ms(&bytes)?;
        if expiry_ms <= now_ms() {
            return Err(MeshError::RelayRefused(
                "bundle already expired on arrival".to_string(),
            ));
        }
        let address = bundle::destination_address(&bytes_as_bundle(&bytes)?)?;
        let hash = hash_bundle(&bytes);

        let mut store = self.store.lock().unwrap();
        if store.by_hash.contains_key(&hash) {
            return Ok(()); // dedup — already held, not an error
        }
        if let Some(budget) = session_budget {
            if *budget == 0 {
                return Err(MeshError::RelayRefused(
                    "per-session admission cap reached".to_string(),
                ));
            }
        }
        if store.by_hash.len() >= self.config.max_total_bundles
            || store.total_bytes + bytes.len() > self.config.max_total_bytes
        {
            return Err(MeshError::RelayRefused(
                "global storage cap reached".to_string(),
            ));
        }

        store.total_bytes += bytes.len();
        store.by_hash.insert(
            hash,
            StoredBundle {
                bytes,
                address,
                expiry_ms,
            },
        );
        Ok(())
    }

    /// Every bundle currently held whose address is in `addresses` — the
    /// caller's real derived address plus, when used by
    /// `MeshTransport::receive`, its decoy addresses (see
    /// `docs/phase4-4c-dead-drop-addressing-design.md`). The relay
    /// cannot and does not distinguish real from decoy — that is the
    /// entire point.
    pub fn bundles_for_addresses(&self, addresses: &[[u8; 32]]) -> Vec<Vec<u8>> {
        let wanted: HashSet<[u8; 32]> = addresses.iter().copied().collect();
        self.store
            .lock()
            .unwrap()
            .by_hash
            .values()
            .filter(|b| wanted.contains(&b.address))
            .map(|b| b.bytes.clone())
            .collect()
    }

    /// Every bundle currently held whose address is in `addresses`,
    /// **removed from storage as they're returned**. This is the "pick
    /// up the dead drop" primitive `MeshTransport::receive` (Sub-Phase
    /// 4C) uses — unlike [`Self::bundles_for_addresses`] (a
    /// non-destructive read, used by tests/introspection and internally
    /// by [`Self::sync_with_peer`]'s epidemic exchange, which must not
    /// remove bundles other peers still need), consuming on receive is
    /// correct here specifically because only the device holding the
    /// matching `tag_key` can ever produce a real (non-decoy) match in
    /// the first place — i.e. only the true recipient's own device ever
    /// calls this with a poll set that actually resolves to something,
    /// so "claimed by the caller" and "delivered to the intended
    /// recipient" are the same event. Intermediate carriers never call
    /// this; they only ever run [`Self::sync_with_peer`].
    pub fn take_for_addresses(&self, addresses: &[[u8; 32]]) -> Vec<Vec<u8>> {
        let wanted: HashSet<[u8; 32]> = addresses.iter().copied().collect();
        let mut store = self.store.lock().unwrap();
        let matching_hashes: Vec<BundleHash> = store
            .by_hash
            .iter()
            .filter(|(_, b)| wanted.contains(&b.address))
            .map(|(h, _)| *h)
            .collect();

        let mut taken = Vec::with_capacity(matching_hashes.len());
        for hash in matching_hashes {
            if let Some(b) = store.by_hash.remove(&hash) {
                store.total_bytes -= b.bytes.len();
                taken.push(b.bytes);
            }
        }
        taken
    }

    /// Purge every bundle whose declared lifetime has elapsed. Call
    /// periodically (a background task in a real deployment); tests call
    /// it directly against a controlled clock scenario. A message that
    /// expires before ever being picked up is, after this call, gone —
    /// permanently and structurally, not retried, per the brief's
    /// explicit requirement.
    pub fn sweep_expired(&self) {
        let now = now_ms();
        let mut store = self.store.lock().unwrap();
        let expired: Vec<BundleHash> = store
            .by_hash
            .iter()
            .filter(|(_, b)| b.expiry_ms <= now)
            .map(|(h, _)| *h)
            .collect();
        for hash in expired {
            if let Some(b) = store.by_hash.remove(&hash) {
                store.total_bytes -= b.bytes.len();
            }
        }
    }

    /// Run one epidemic-routing sync session over an already-established
    /// [`MeshLink`]. Both sides of a connection run this exact same
    /// function — there is no initiator/responder role distinction, by
    /// design: every `send` here is fire-and-forget into a buffered
    /// channel/stream (never blocks on the peer having read anything
    /// yet) and every `recv` only waits on a message the peer sends
    /// unconditionally, at a point in *its own* identical sequence that
    /// never depends on first hearing back from us. That symmetry is
    /// what makes this deadlock-free without a role split — see the
    /// adjacent step-by-step reasoning in this phase's plan/design notes
    /// for why each step's ordering was chosen deliberately, not
    /// arbitrarily.
    pub async fn sync_with_peer(&self, link: &mut dyn MeshLink) -> Result<usize> {
        self.sweep_expired();

        let my_hashes: Vec<BundleHash> = {
            let store = self.store.lock().unwrap();
            store.by_hash.keys().copied().collect()
        };
        send_msg(link, &SyncMessage::Have(my_hashes.clone())).await?;

        let their_hashes = match recv_msg(link).await? {
            SyncMessage::Have(h) => h,
            other => return Err(unexpected(other)),
        };

        let my_set: HashSet<BundleHash> = my_hashes.into_iter().collect();
        let mut want: Vec<BundleHash> = their_hashes
            .into_iter()
            .filter(|h| !my_set.contains(h))
            .collect();
        want.truncate(self.config.max_bundles_per_session);
        send_msg(link, &SyncMessage::Want(want)).await?;

        let their_want = match recv_msg(link).await? {
            SyncMessage::Want(w) => w,
            other => return Err(unexpected(other)),
        };

        // Collect bytes to send *before* awaiting anything — holding a
        // std Mutex guard across an `.await` point is a footgun (blocks
        // any other task needing the lock for the whole await), so the
        // lock is taken once here and dropped before the send loop.
        let to_send: Vec<Vec<u8>> = {
            let store = self.store.lock().unwrap();
            their_want
                .iter()
                .take(self.config.max_bundles_per_session)
                .filter_map(|h| store.by_hash.get(h).map(|b| b.bytes.clone()))
                .collect()
        };
        for bytes in to_send {
            send_msg(link, &SyncMessage::Bundle(bytes)).await?;
        }
        send_msg(link, &SyncMessage::Done).await?;

        let mut admitted = 0usize;
        let mut session_budget = self.config.max_bundles_per_session;
        loop {
            match recv_msg(link).await? {
                SyncMessage::Bundle(bytes) => {
                    if self.admit_checked(bytes, Some(&mut session_budget)).is_ok() {
                        admitted += 1;
                        session_budget = session_budget.saturating_sub(1);
                    }
                }
                SyncMessage::Done => break,
                other => return Err(unexpected(other)),
            }
        }
        Ok(admitted)
    }
}

fn unexpected(_msg: SyncMessage) -> MeshError {
    MeshError::Link("sync protocol violation: message out of order".to_string())
}

fn bytes_as_bundle(bytes: &[u8]) -> Result<bp7::Bundle> {
    bp7::Bundle::try_from(bytes).map_err(|e| MeshError::BundleCodec(format!("{e:?}")))
}

#[derive(Debug, Serialize, Deserialize)]
enum SyncMessage {
    Have(Vec<BundleHash>),
    Want(Vec<BundleHash>),
    Bundle(Vec<u8>),
    Done,
}

async fn send_msg(link: &mut dyn MeshLink, msg: &SyncMessage) -> Result<()> {
    let bytes = serde_json::to_vec(msg)
        .map_err(|e| MeshError::Link(format!("sync message encode failed: {e}")))?;
    link.send(&bytes).await
}

async fn recv_msg(link: &mut dyn MeshLink) -> Result<SyncMessage> {
    let bytes = link.recv().await?;
    serde_json::from_slice(&bytes)
        .map_err(|e| MeshError::Link(format!("sync message decode failed: {e}")))
}
