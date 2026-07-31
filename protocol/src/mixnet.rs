//! Sphinx mix-network packet construction and processing (Sub-Phase 2B).
//!
//! Wraps [`sphinx-packet`](https://github.com/nymtech/sphinx) (Nym
//! Technologies, Apache-2.0, crates.io `sphinx-packet` v0.7.0) — an
//! existing, production-used implementation of the Sphinx packet format
//! from Danezis & Goldberg, "Sphinx: A Compact and Provably Secure Mix
//! Format" (IEEE S&P 2009, cited in `docs/THREAT_MODEL.md` §6) — rather
//! than assembling onion encryption from primitives. This keeps the
//! project's no-custom-crypto constraint (`docs/phase1-architecture.md`
//! §2) intact for mix routing the same way it already holds for the
//! Signal Protocol layer.
//!
//! This module owns everything both sides of the mix network need:
//! [`crate::transport::MixTransport`] (client, builds packets) calls
//! [`build_packet`]; `parda-mixnode` daemons (node, unwrap packets) call
//! [`process_packet`]. Neither side hand-rolls Sphinx framing.
//!
//! ## Address encoding
//!
//! Sphinx node/destination addresses are fixed-size byte arrays
//! (`sphinx_packet::constants::NODE_ADDRESS_LENGTH` /
//! `DESTINATION_ADDRESS_LENGTH`, both 32 bytes). PARDA encodes a
//! `"host:port"` string directly into a node's address token (1-byte
//! length prefix + UTF-8 bytes, zero-padded) so a mix node can resolve the
//! next hop purely from what it decrypts out of the packet header — it
//! never needs a separate directory lookup of its own. Only the sender
//! (which picks the *initial* path) needs a full [`MixTopology`].
//!
//! ## Destination addressing
//!
//! There is exactly one delivery target in this prototype: `parda-relay`.
//! The `Destination` address carries a fixed marker
//! ([`RELAY_DESTINATION_TAG`]) rather than an actual network address —
//! the final-hop mix node is separately configured with the relay's real
//! base URL (`MIXNODE_RELAY_URL`). This is checked, not assumed:
//! [`process_packet`] rejects a `FinalHop` whose destination tag doesn't
//! match, rather than silently delivering to whatever the packet claims.
//! Loopix "drop cover" traffic ([`COVER_DESTINATION_TAG`]) uses the same
//! mechanism to mark itself for silent discard instead of delivery — see
//! `mixnode::cover_traffic` module docs.
//!
//! ## Mixing delay
//!
//! Per-hop delays are sampled by the **sender** and embedded in the
//! packet; each node honors the delay it's handed after unwrap rather
//! than sampling its own. This is the actual Sphinx/Loopix design (a node
//! cannot distinguish an adversarially-influenced delay from a naturally
//! sampled one if it never does the sampling itself). PARDA calls
//! `sphinx_packet::header::delays::generate_from_average_duration`
//! directly — the crate's own Poisson/exponential delay sampler
//! (Piotrowska et al., "The Loopix Anonymity System", USENIX Security
//! 2017, cited in `docs/THREAT_MODEL.md` §6) — rather than reimplementing
//! sampling.
//!
//! ## What this does NOT cover (see `docs/THREAT_MODEL.md` §3.6 for the
//! full, precise statement)
//!
//! - No decentralized directory authority: [`MixTopology`] is a static,
//!   trust-on-first-use configured list, same posture already accepted
//!   elsewhere in the project (prekey bundle upload, sealed-sender
//!   certificate issuance).
//! - Only the send path is mix-anonymized. Fetching messages
//!   (`MixTransport::receive`) still talks to the relay directly — see
//!   `transport` module docs.

use std::time::Duration;

use rand::seq::SliceRandom;
use sphinx_packet::{
    constants::{DESTINATION_ADDRESS_LENGTH, NODE_ADDRESS_LENGTH},
    header::delays::{self, Delay},
    route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes},
    ProcessedPacketData, SphinxPacket, SphinxPacketBuilder,
};
pub use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{PardaError, Result};

/// Marks a Sphinx `Destination` as "deliver the recovered payload to
/// `parda-relay`". Any other tag is refused, not guessed at — see module
/// docs.
pub const RELAY_DESTINATION_TAG: &[u8] = b"PARDA-RELAY-V1";

/// Marks a Sphinx `Destination` as Loopix-style "drop cover" traffic — a
/// packet that traversed a real path but must never reach the relay.
pub const COVER_DESTINATION_TAG: &[u8] = b"PARDA-COVER-V1";

/// Lower bound on mix-network path length. Below this, a single
/// compromised or observant node could trivially correlate sender and
/// recipient — see `docs/THREAT_MODEL.md` §3.6.
pub const MIN_PATH_LENGTH: usize = 3;

/// Default Sphinx payload capacity in bytes. Sealed-sender ciphertext
/// envelopes are larger than the crate's own 1024-byte default; this is
/// generous enough for realistic `MessageEnvelope` JSON without needing
/// per-call tuning. Configurable via [`MixTopology`]/`MixTransport`
/// builder methods, not hardcoded past this default.
pub const DEFAULT_MIX_PAYLOAD_SIZE: usize = 8192;

// ─── Address encoding ─────────────────────────────────────────────────────────

fn encode_fixed(bytes: &[u8], capacity: usize) -> Result<Vec<u8>> {
    if bytes.len() > capacity - 1 {
        return Err(PardaError::MixRouting(format!(
            "{} bytes do not fit in a {}-byte Sphinx address token",
            bytes.len(),
            capacity
        )));
    }
    let mut buf = vec![0u8; capacity];
    buf[0] = bytes.len() as u8;
    buf[1..1 + bytes.len()].copy_from_slice(bytes);
    Ok(buf)
}

fn decode_fixed(buf: &[u8]) -> Result<Vec<u8>> {
    let len = buf[0] as usize;
    if 1 + len > buf.len() {
        return Err(PardaError::MixRouting(
            "corrupt Sphinx address token: declared length exceeds buffer".to_string(),
        ));
    }
    Ok(buf[1..1 + len].to_vec())
}

fn encode_node_address(host_port: &str) -> Result<NodeAddressBytes> {
    let encoded = encode_fixed(host_port.as_bytes(), NODE_ADDRESS_LENGTH)?;
    let mut arr = [0u8; NODE_ADDRESS_LENGTH];
    arr.copy_from_slice(&encoded);
    Ok(NodeAddressBytes::from_bytes(arr))
}

fn decode_node_address(addr: &NodeAddressBytes) -> Result<String> {
    let bytes = decode_fixed(addr.as_bytes())?;
    String::from_utf8(bytes)
        .map_err(|e| PardaError::MixRouting(format!("next-hop address is not valid UTF-8: {e}")))
}

fn tagged_destination(tag: &[u8]) -> Result<Destination> {
    let encoded = encode_fixed(tag, DESTINATION_ADDRESS_LENGTH)?;
    let mut arr = [0u8; DESTINATION_ADDRESS_LENGTH];
    arr.copy_from_slice(&encoded);
    Ok(Destination::new(
        DestinationAddressBytes::from_bytes(arr),
        [0u8; sphinx_packet::constants::IDENTIFIER_LENGTH],
    ))
}

fn destination_tag(dest: &DestinationAddressBytes) -> Result<Vec<u8>> {
    decode_fixed(&dest.as_bytes())
}

// ─── Topology ───────────────────────────────────────────────────────────────

/// One mix node as known to a client picking a path. Not needed by mix
/// nodes themselves for forwarding — see module docs.
#[derive(Clone, Debug)]
pub struct MixNodeDescriptor {
    /// `host:port` the node's HTTP `/mix/packet` endpoint listens on.
    pub address: String,
    pub public_key: PublicKey,
}

/// A static, trust-on-first-use list of known mix nodes a client can
/// route through. No directory authority, no freshness/revocation
/// mechanism — see `docs/THREAT_MODEL.md` §3.6 and §4 for this documented
/// limitation.
#[derive(Clone, Debug, Default)]
pub struct MixTopology {
    pub nodes: Vec<MixNodeDescriptor>,
}

impl MixTopology {
    pub fn new(nodes: Vec<MixNodeDescriptor>) -> Self {
        Self { nodes }
    }

    /// Choose `len` distinct nodes at random to form a path. Fails rather
    /// than silently routing through fewer/duplicate nodes if the
    /// topology is too small.
    pub fn choose_path(&self, len: usize) -> Result<Vec<MixNodeDescriptor>> {
        if len < MIN_PATH_LENGTH {
            return Err(PardaError::MixRouting(format!(
                "path length {len} is below the minimum of {MIN_PATH_LENGTH}"
            )));
        }
        if self.nodes.len() < len {
            return Err(PardaError::MixRouting(format!(
                "topology has {} nodes, need at least {len} for a path",
                self.nodes.len()
            )));
        }
        let mut rng = rand::thread_rng();
        Ok(self
            .nodes
            .choose_multiple(&mut rng, len)
            .cloned()
            .collect())
    }
}

// ─── Packet construction (client / sender side) ────────────────────────────

/// Build a Sphinx packet carrying `payload` (typically a serialised
/// `MessageEnvelope`) through `path`, addressed for delivery to the relay.
/// `avg_delay` parameterises the per-hop exponential mixing delay
/// (sampled here, by the sender — see module docs).
pub fn build_packet(
    payload: &[u8],
    path: &[MixNodeDescriptor],
    avg_delay: Duration,
    payload_size: usize,
) -> Result<Vec<u8>> {
    build_packet_to(
        payload,
        path,
        avg_delay,
        payload_size,
        RELAY_DESTINATION_TAG,
    )
}

/// Like [`build_packet`] but with an explicit destination tag — used by
/// `parda-mixnode`'s cover-traffic scheduler to build "drop cover"
/// packets tagged [`COVER_DESTINATION_TAG`] instead of real ones.
pub fn build_packet_to(
    payload: &[u8],
    path: &[MixNodeDescriptor],
    avg_delay: Duration,
    payload_size: usize,
    destination_tag_bytes: &[u8],
) -> Result<Vec<u8>> {
    if path.len() < MIN_PATH_LENGTH {
        return Err(PardaError::MixRouting(format!(
            "path length {} is below the minimum of {MIN_PATH_LENGTH}",
            path.len()
        )));
    }
    let nodes = path
        .iter()
        .map(|d| Ok(Node::new(encode_node_address(&d.address)?, d.public_key)))
        .collect::<Result<Vec<Node>>>()?;
    let destination = tagged_destination(destination_tag_bytes)?;
    let delays: Vec<Delay> = delays::generate_from_average_duration(path.len(), avg_delay);

    let packet = SphinxPacketBuilder::new()
        .with_payload_size(payload_size)
        .build_packet(payload, &nodes, &destination, &delays)
        .map_err(|e| PardaError::MixRouting(format!("failed to build Sphinx packet: {e}")))?;

    Ok(packet.to_bytes())
}

// ─── Packet processing (mix node side) ─────────────────────────────────────

/// What a mix node should do after unwrapping one onion layer.
pub enum UnwrapOutcome {
    /// Hold `packet_bytes` for `delay`, then forward to `next_hop_address`.
    Forward {
        next_hop_address: String,
        delay: Duration,
        packet_bytes: Vec<u8>,
    },
    /// This node is the final hop and the destination tag matched the
    /// relay marker. `envelope_bytes` is the recovered plaintext.
    Deliver { envelope_bytes: Vec<u8> },
    /// This node is the final hop of a drop-cover packet. Nothing should
    /// be delivered anywhere — discard.
    DropCover,
}

/// Unwrap one Sphinx onion layer using this node's secret key. Fails
/// closed: a malformed packet, a wrong-destination final hop, or a
/// decode error all return `Err` rather than a best-effort guess.
pub fn process_packet(packet_bytes: &[u8], node_secret: &StaticSecret) -> Result<UnwrapOutcome> {
    let packet = SphinxPacket::from_bytes(packet_bytes)
        .map_err(|e| PardaError::MixRouting(format!("malformed Sphinx packet: {e}")))?;
    let processed = packet
        .process(node_secret)
        .map_err(|e| PardaError::MixRouting(format!("failed to unwrap Sphinx packet: {e}")))?;

    match processed.data {
        ProcessedPacketData::ForwardHop {
            next_hop_packet,
            next_hop_address,
            delay,
        } => {
            let next_hop_address = decode_node_address(&next_hop_address)?;
            Ok(UnwrapOutcome::Forward {
                next_hop_address,
                delay: delay.to_duration(),
                packet_bytes: next_hop_packet.to_bytes(),
            })
        }
        ProcessedPacketData::FinalHop {
            destination,
            payload,
            ..
        } => {
            let tag = destination_tag(&destination)?;
            if tag == RELAY_DESTINATION_TAG {
                let envelope_bytes = payload.recover_plaintext().map_err(|e| {
                    PardaError::MixRouting(format!("failed to recover Sphinx payload: {e}"))
                })?;
                Ok(UnwrapOutcome::Deliver { envelope_bytes })
            } else if tag == COVER_DESTINATION_TAG {
                Ok(UnwrapOutcome::DropCover)
            } else {
                Err(PardaError::MixRouting(format!(
                    "final hop with unrecognised destination tag {tag:?} — refusing to guess where to deliver it"
                )))
            }
        }
    }
}

/// Sample a single delay from the same Poisson/exponential distribution
/// used for per-hop mixing delay ([`build_packet`]). General-purpose —
/// used by `parda-mixnode`'s cover-traffic scheduler to pick emission
/// intervals, not just per-hop packet delay.
pub fn sample_exponential_delay(avg: Duration) -> Duration {
    delays::generate_from_average_duration(1, avg)
        .into_iter()
        .next()
        .map(|d| d.to_duration())
        .unwrap_or(avg)
}

/// Generate a fresh X25519 keypair for a mix node identity.
///
/// **Prototype-only posture:** ephemeral, in-memory generation — no
/// persistent/hardware-backed node identity yet, matching the
/// trust-on-first-use posture Phase 1 already accepts for prekey bundle
/// uploads (`docs/THREAT_MODEL.md` §3.5). A production deployment needs a
/// long-lived, published node identity; out of scope here.
pub fn generate_node_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
    (secret, public)
}
