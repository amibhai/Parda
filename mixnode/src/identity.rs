//! Mix node keypair loading.
//!
//! **Prototype-only posture:** no persistent or hardware-backed node
//! identity mechanism exists yet. If `MIXNODE_SECRET_KEY_HEX` isn't set,
//! a fresh ephemeral identity is generated on every start — fine for
//! dev/test, but such a node changes its public key on every restart,
//! which breaks any peer's cached `MixTopology`/peer list pointing at it.
//! A production deployment needs a persisted, ideally hardware-backed,
//! node identity — same category of gap already flagged for other
//! trust-on-first-use trust anchors in this project (see
//! `docs/THREAT_MODEL.md` §3.5, §4).

use parda_protocol::mixnet::{self, StaticSecret};

/// Load a 32-byte hex-encoded secret key from `MIXNODE_SECRET_KEY_HEX`,
/// or generate a fresh ephemeral one if unset.
pub fn load_or_generate() -> StaticSecret {
    match std::env::var("MIXNODE_SECRET_KEY_HEX") {
        Ok(hex_str) => {
            let bytes = hex_decode(&hex_str)
                .expect("MIXNODE_SECRET_KEY_HEX must be 64 hex characters (32 bytes)");
            let arr: [u8; 32] = bytes
                .try_into()
                .expect("MIXNODE_SECRET_KEY_HEX must decode to exactly 32 bytes");
            StaticSecret::from(arr)
        }
        Err(_) => {
            tracing::warn!(
                "MIXNODE_SECRET_KEY_HEX not set — generating an ephemeral node identity \
                 (dev/test only; this node's public key will change on every restart)"
            );
            mixnet::generate_node_keypair().0
        }
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_round_trips() {
        let bytes = vec![0u8, 1, 254, 255, 16, 32];
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex_decode(&hex), Some(bytes));
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert_eq!(hex_decode("abc"), None);
    }
}
