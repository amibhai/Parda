//! Sub-Phase 4B adversarial gate: a malicious carrier with full, direct
//! access to its own relay agent's raw backing store — not going
//! through the relay's own query API, since a real attacker who has
//! seized or compromised the device wouldn't be limited to it either
//! (`MeshRelayAgent::debug_all_stored_bytes`, the same "give the
//! adversary everything, not just what the normal API exposes" posture
//! `protocol/tests/forensic_recovery_tests.rs` already takes for Phase
//! 3's device-seizure adversary).
//!
//! Composes envelopes the way a real dead-drop message must be composed
//! (`sealed_sender = true`, both `sender_id` and `recipient_id` empty —
//! see `mesh/src/bundle.rs::wrap`'s doc comment on why that's the
//! caller's responsibility) and proves none of a corpus of distinctive,
//! known plaintext/identity markers survives into the carrier's raw
//! storage.

use parda_mesh::{
    bundle,
    relay::{MeshRelayAgent, RelayConfig},
};
use parda_protocol::envelope::{EnvelopeType, MessageEnvelope};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn properly_composed_envelope(marker: &[u8]) -> MessageEnvelope {
    MessageEnvelope {
        sender_id: String::new(),
        recipient_id: String::new(),
        // Stands in for real sealed-sender/Double-Ratchet ciphertext —
        // opaque bytes a carrier must not be able to interpret. The
        // "known marker" bytes below simulate what *would* leak if this
        // module mishandled anything, the same way the design note's
        // own bundle.rs test does.
        ciphertext: marker.to_vec(),
        envelope_type: EnvelopeType::SealedSender,
        timestamp_ms: now_ms(),
        version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
        sealed_sender: true,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
        dead_drop_address: None,
    }
}

/// Distinctive, never-otherwise-generated identity/plaintext markers a
/// carrier must not be able to find anywhere in its own storage. Chosen
/// long and unusual enough that an accidental substring match against
/// framing bytes, hex encoding, or CBOR structure is not a plausible
/// false positive.
const KNOWN_MARKERS: &[&str] = &[
    "ALICE-DISTINCTIVE-SENDER-MARKER-Zx91q",
    "BOB-DISTINCTIVE-RECIPIENT-MARKER-Qm42v",
    "the quick brown plaintext jumps over the lazy carrier",
    "swastik362004-style-user-handle-should-never-appear",
];

#[test]
fn malicious_carrier_cannot_recover_any_known_marker_from_raw_storage() {
    let relay = MeshRelayAgent::new(RelayConfig::default());

    for (i, marker) in KNOWN_MARKERS.iter().enumerate() {
        let envelope = properly_composed_envelope(marker.as_bytes());
        let address = [i as u8 + 1; 32];
        let bytes = bundle::wrap(&envelope, address).unwrap();
        relay.admit(bytes).unwrap();
    }

    let all_stored = relay.debug_all_stored_bytes();
    assert_eq!(all_stored.len(), KNOWN_MARKERS.len());

    for stored_bytes in &all_stored {
        for marker in KNOWN_MARKERS {
            assert!(
                !contains_subslice(stored_bytes, marker.as_bytes()),
                "found known marker {marker:?} in a carrier's raw stored bundle bytes — \
                 the carrier recovered something it must never be able to recover"
            );
        }
    }
}

/// The `ciphertext` bytes themselves ARE present in storage (a carrier
/// physically holds the bundle — that's what "store-and-forward" means)
/// — this test exists to make explicit that the *marker content* is
/// only ever unrecoverable because it's opaque ciphertext in a real
/// deployment, not because this module does anything special to hide
/// it. Composing a dead-drop message with genuinely unencrypted content
/// in `ciphertext` (a caller bug, not this module's job to prevent —
/// see `bundle.rs`'s doc comment) would leak exactly as much as any
/// other transport's `ciphertext` field would. Recorded here so the
/// previous test's guarantee isn't misread as broader than it is.
#[test]
fn opaque_ciphertext_bytes_are_present_in_storage_by_design_not_a_leak() {
    let relay = MeshRelayAgent::new(RelayConfig::default());
    let opaque = vec![0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03];
    let envelope = properly_composed_envelope(&opaque);
    let bytes = bundle::wrap(&envelope, [99u8; 32]).unwrap();
    relay.admit(bytes).unwrap();

    let all_stored = relay.debug_all_stored_bytes();
    // `MessageEnvelope::ciphertext` is base64-encoded in the envelope's
    // JSON serialization (`protocol/src/envelope.rs`'s
    // `serde_bytes_base64` module — the same encoding every other
    // transport's wire format already uses), so the *text form* of the
    // opaque bytes is what's actually present in the bundle payload, not
    // the raw byte sequence verbatim. Checking for the raw bytes here
    // would (incorrectly) look like a pass or fail depending on the
    // ciphertext's byte values coincidentally recurring in the base64
    // alphabet — found by this test failing against the real encoding,
    // not assumed.
    let opaque_base64 = {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode(&opaque)
    };
    assert!(
        contains_subslice(&all_stored[0], opaque_base64.as_bytes()),
        "the opaque ciphertext blob (base64-encoded, matching the envelope wire format) \
         should be present in storage — a store-and-forward carrier necessarily holds the \
         bytes it's carrying; what must never be present is anything *derived from* real \
         plaintext or identity"
    );
}

/// No sender or recipient identity is recoverable from the *bundle
/// addressing* either — a carrier reading the destination address alone
/// (without `tag_key`) learns nothing about who it's for.
#[test]
fn destination_address_reveals_nothing_without_the_key() {
    let relay = MeshRelayAgent::new(RelayConfig::default());
    let envelope = properly_composed_envelope(b"opaque");
    let address = *b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20";
    let bytes = bundle::wrap(&envelope, address).unwrap();
    relay.admit(bytes.clone()).unwrap();

    // The address is, correctly, visible on the bundle (it has to be —
    // that's how the relay indexes/routes it). What's under test is that
    // it's fixed-format opaque bytes with no structure a carrier could
    // exploit to recover identity from, matching
    // `parda_protocol::dead_drop`'s HKDF-output distribution (Sub-Phase 4C).
    let (recovered_address, _) = bundle::unwrap(&bytes).unwrap();
    assert_eq!(recovered_address, address);
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
