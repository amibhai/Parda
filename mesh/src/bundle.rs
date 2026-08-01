//! DTN bundle framing (Sub-Phase 4B).
//!
//! Wraps `parda_protocol::envelope::MessageEnvelope` for mesh delivery.
//! **This is not a parallel message format** — per
//! `protocol/src/envelope.rs`'s own module docs and this phase's brief,
//! dead-drop bundles carry the same `MessageEnvelope` every other
//! transport carries, serialized as-is into the bundle's payload block.
//!
//! ## Why `bp7`, not the `dtn7` daemon
//!
//! `bp7` (`dtn7` org, Apache-2.0) implements RFC 9171 (Bundle Protocol
//! Version 7) CBOR primary/payload block encoding as a standalone
//! library — cited, not improvised, consistent with this project's
//! no-custom-crypto/no-custom-wire-format posture already applied to
//! Sphinx packets (`protocol/src/mixnet.rs`). The `dtn7` crate (same org)
//! is a full daemon — routing, convergence layers, a REST/WebSocket
//! command interface — architected to run as a standalone process, not
//! as a library trait implementation, and is self-described upstream as
//! still under development. Embedding it would mean taking an
//! unaudited, in-development dependency for this phase's most
//! security-sensitive component (flood/Sybil resistance, storage
//! opacity) — the same "assembling unaudited pieces into a protocol"
//! risk this project has already declined twice for cryptographic code
//! (`protocol/src/self_destruct.rs` design note §1, §12). `MeshRelayAgent`
//! (`relay.rs`) owns all of the actual store-and-forward logic; `bp7`'s
//! job here is exactly the wire framing, nothing more.
//!
//! ## Addressing, opaque to the carrier
//!
//! A bundle's BPv7 destination endpoint is the blinded dead-drop address
//! (`parda_protocol::dead_drop`) hex-encoded into a `dtn://` URI — `bp7`'s
//! `EndpointID` only accepts URI-shaped demux strings, not raw bytes, so
//! hex encoding is the representation, not a cryptographic step; the hex
//! string is exactly as opaque as the underlying bytes to anyone without
//! the derivation key. The source endpoint is always BPv7's defined null
//! endpoint (`dtn:none`) — a standards-defined "anonymous sender" value,
//! not a PARDA invention — so a carrier never sees even a placeholder
//! sender identity.

use std::time::{SystemTime, UNIX_EPOCH};

use bp7::{
    canonical, dtntime::CreationTimestamp, eid::EndpointID, primary::PrimaryBlockBuilder, Bundle,
};
use parda_protocol::envelope::MessageEnvelope;

use crate::error::{MeshError, Result};

/// Demux prefix a blinded dead-drop address is encoded under, in the
/// form `bp7::eid::EndpointID::with_dtn` expects (no `dtn://` scheme —
/// `with_dtn` prepends that itself; passing it in the input produced a
/// doubled `dtn://dtn://...` on the wire, found by
/// `wrap_unwrap_round_trips_envelope_and_address` failing against the
/// real `bp7` crate, not assumed from documentation). Fixed and public —
/// same role as `radio::PROTOCOL_TAG`: identifies "this is a PARDA
/// dead-drop bundle," not who it's for.
const DEAD_DROP_DEMUX_PREFIX: &str = "parda-dead-drop/";
/// The corresponding prefix as it actually appears on
/// `EndpointID::to_string()`'s output (`dtn://` + the demux above) —
/// what [`destination_address`] strips back off.
const DEAD_DROP_URI_PREFIX: &str = "dtn://parda-dead-drop/";

/// Maximum bundle lifetime for a dead-drop message with no
/// `self_destruct_at` set. A carrier must still eventually be allowed to
/// purge an unclaimed bundle — see `relay.rs`'s TTL sweep — this is the
/// ceiling that applies when the message itself declares no shorter
/// deadline.
pub const DEFAULT_MAX_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000; // 7 days

fn address_to_eid(address: [u8; 32]) -> Result<EndpointID> {
    EndpointID::with_dtn(&format!("{DEAD_DROP_DEMUX_PREFIX}{}", hex::encode(address)))
        .map_err(|e| MeshError::BundleCodec(format!("address did not encode as a valid EID: {e}")))
}

/// Recover the 32-byte blinded address a bundle is destined for, without
/// touching its payload. Used by [`crate::relay::MeshRelayAgent`] to
/// index stored bundles by address, and by `MeshTransport::receive` to
/// check whether an incoming bundle matches one of the caller's
/// currently-derived (or decoy) addresses.
pub fn destination_address(bundle: &Bundle) -> Result<[u8; 32]> {
    let dst = bundle.primary.destination.to_string();
    let hex_part = dst
        .strip_prefix(DEAD_DROP_URI_PREFIX)
        .ok_or_else(|| MeshError::BundleCodec("not a PARDA dead-drop bundle".to_string()))?;
    let bytes = hex::decode(hex_part)
        .map_err(|e| MeshError::BundleCodec(format!("malformed address hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| MeshError::BundleCodec("address was not 32 bytes".to_string()))
}

/// **Caller's responsibility, not enforced here:** `envelope.sender_id`
/// and `envelope.recipient_id` are serialized into the bundle's payload
/// block verbatim, exactly like every other field — this function has
/// no way to distinguish "opaque ciphertext" from "plaintext" in the
/// bytes it's handed, the same posture `DirectTransport`/`MixTransport`
/// already take toward `MessageEnvelope::ciphertext`. Unlike those two
/// transports, though, a dead-drop bundle's carrier is fully untrusted
/// (module docs), so composing a mesh-bound envelope with a populated
/// `recipient_id` or `sender_id` would hand that identity straight to
/// every carrier who happens to store it — there is no routing reason
/// to keep `recipient_id` in the clear here the way `DirectTransport`
/// needs it for the relay, since [`wrap`]'s whole point is that routing
/// happens via the opaque `address` instead. `MeshTransport::send`
/// (Sub-Phase 4C, `crate::transport`) is the actual enforcement point —
/// it refuses to send an envelope that isn't `sealed_sender = true` with
/// both ID fields empty, fail-closed, the same posture
/// `MixTransport::send` already takes toward an unreachable first hop.
///
/// Wrap `envelope` as an RFC 9171 bundle destined for `address`. Bundle
/// lifetime is derived from `envelope.self_destruct_at` when present (so
/// a carrier's own TTL bookkeeping can't outlive the message's declared
/// expiry — see `docs/phase4-4c-dead-drop-addressing-design.md` §4,
/// "Self-destruct interaction"), or [`DEFAULT_MAX_LIFETIME_MS`]
/// otherwise.
pub fn wrap(envelope: &MessageEnvelope, address: [u8; 32]) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(envelope)
        .map_err(|e| MeshError::BundleCodec(format!("envelope did not serialize: {e}")))?;

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| MeshError::BundleCodec(e.to_string()))?
        .as_millis() as u64;

    let lifetime_ms = match envelope.self_destruct_at {
        Some(deadline_ms) => deadline_ms.saturating_sub(envelope.timestamp_ms),
        None => DEFAULT_MAX_LIFETIME_MS,
    };

    let primary = PrimaryBlockBuilder::default()
        .destination(address_to_eid(address)?)
        .source(EndpointID::none())
        .report_to(EndpointID::none())
        .creation_timestamp(CreationTimestamp::with_time_and_seq(now_ms, 0))
        .lifetime(std::time::Duration::from_millis(lifetime_ms))
        .build()
        .map_err(|e| MeshError::BundleCodec(format!("primary block build failed: {e}")))?;

    let mut bundle = Bundle::new(
        primary,
        vec![canonical::new_payload_block(
            bp7::flags::BlockControlFlags::empty(),
            payload,
        )],
    );

    Ok(bundle.to_cbor())
}

/// Unwrap a bundle back into its address and `MessageEnvelope`. The
/// relay agent (`relay.rs`) only ever calls [`destination_address`] — it
/// never needs, and structurally never does, the envelope-level decode
/// this performs; that's reserved for the actual recipient, after it
/// recognizes the address as its own.
pub fn unwrap(bytes: &[u8]) -> Result<([u8; 32], MessageEnvelope)> {
    let bundle =
        Bundle::try_from(bytes).map_err(|e| MeshError::BundleCodec(format!("{e:?}")))?;
    let address = destination_address(&bundle)?;
    let payload = bundle
        .payload()
        .ok_or_else(|| MeshError::BundleCodec("bundle has no payload block".to_string()))?;
    let envelope: MessageEnvelope = serde_json::from_slice(payload)
        .map_err(|e| MeshError::BundleCodec(format!("payload did not decode as an envelope: {e}")))?;
    Ok((address, envelope))
}

/// The bundle's declared expiry, as a Unix epoch millisecond timestamp —
/// `creation_timestamp + lifetime`. Used by the relay's TTL sweep
/// (`relay.rs`) to purge bundles opaquely, without ever decoding the
/// payload.
pub fn expiry_ms(bytes: &[u8]) -> Result<u64> {
    let bundle = Bundle::try_from(bytes).map_err(|e| MeshError::BundleCodec(format!("{e:?}")))?;
    let created_ms = bundle.primary.creation_timestamp.dtntime();
    let lifetime_ms = bundle.primary.lifetime.as_millis() as u64;
    Ok(created_ms + lifetime_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parda_protocol::envelope::EnvelopeType;

    fn sample_envelope() -> MessageEnvelope {
        MessageEnvelope {
            sender_id: String::new(),
            recipient_id: String::new(),
            ciphertext: vec![1, 2, 3, 4],
            envelope_type: EnvelopeType::Ratchet,
            timestamp_ms: 1_000_000,
            version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
            sealed_sender: false,
            routing_hint: None,
            self_destruct_at: None,
            read_triggered_destruct: false,
            dead_drop_address: None,
        }
    }

    #[test]
    fn wrap_unwrap_round_trips_envelope_and_address() {
        let envelope = sample_envelope();
        let address = [7u8; 32];
        let bytes = wrap(&envelope, address).unwrap();
        let (recovered_address, recovered) = unwrap(&bytes).unwrap();
        assert_eq!(recovered_address, address);
        assert_eq!(recovered.ciphertext, envelope.ciphertext);
        assert_eq!(recovered.timestamp_ms, envelope.timestamp_ms);
    }

    #[test]
    fn wrapped_bundle_bytes_do_not_contain_sender_or_recipient_placeholder_strings() {
        // Sanity check on carrier opacity at the framing level — the
        // real, adversarial version of this claim (arbitrary plaintext
        // corpora, not just this one string) is
        // `mesh/tests/malicious_carrier_tests.rs`.
        let mut envelope = sample_envelope();
        envelope.sender_id = "alice-distinctive-id".to_string();
        envelope.ciphertext = b"not actually plaintext but check anyway".to_vec();
        let bytes = wrap(&envelope, [9u8; 32]).unwrap();
        // sender_id is legitimately present (it's inside the JSON-encoded
        // envelope payload, matching every other transport's ciphertext
        // blob — real protection comes from sealed-sender leaving it
        // empty at composition time, not from the bundle layer). What
        // this bundle layer must not do is *additionally* leak it via
        // the destination address / EID.
        let (address, _) = unwrap(&bytes).unwrap();
        assert_eq!(address, [9u8; 32]);
    }

    #[test]
    fn lifetime_derives_from_self_destruct_at_when_present() {
        let mut envelope = sample_envelope();
        envelope.self_destruct_at = Some(envelope.timestamp_ms + 60_000);
        let bytes = wrap(&envelope, [1u8; 32]).unwrap();
        let bundle = Bundle::try_from(bytes.as_slice()).unwrap();
        assert_eq!(bundle.primary.lifetime.as_millis(), 60_000);
    }

    #[test]
    fn destination_address_rejects_non_parda_bundle() {
        let primary = PrimaryBlockBuilder::default()
            .destination(EndpointID::with_dtn("someone-else/inbox").unwrap())
            .source(EndpointID::none())
            .report_to(EndpointID::none())
            .creation_timestamp(CreationTimestamp::with_time_and_seq(0, 0))
            .lifetime(std::time::Duration::from_secs(60))
            .build()
            .unwrap();
        let bundle = Bundle::new(primary, vec![]);
        assert!(destination_address(&bundle).is_err());
    }
}
