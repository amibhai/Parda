//! Mix node keypair loading and persistence.
//!
//! ## Resolution order
//!
//! 1. `MIXNODE_SECRET_KEY_HEX` — an explicitly supplied key always wins.
//!    Nothing is read from or written to disk in this case.
//! 2. `MIXNODE_KEY_PATH` — load the key from that file if it exists,
//!    otherwise generate one and write it there (Sub-Phase 4.5E). The
//!    node then keeps the same public key across restarts.
//! 3. Neither set — generate a fresh ephemeral key, with a loud warning.
//!    Unchanged pre-4.5E behavior: fine for dev/test, but such a node
//!    changes its public key on every restart, breaking any peer's
//!    cached `MixTopology`/peer list pointing at it.
//!
//! ## What persistence here does and does not solve
//!
//! It solves exactly one operational problem: a restarted node keeps its
//! identity, so peers' configured topologies stay valid. **It is not the
//! directory-authority design**, which stays out of scope — there is
//! still no mechanism by which a client *discovers* mix nodes or learns
//! that a node's key legitimately changed; peer lists remain manually
//! configured (`MIXNODE_PEERS`), and the trust posture for a mix node's
//! key is still the one `docs/THREAT_MODEL.md` §3.6 describes.
//! `parda_protocol::trust` (Sub-Phase 4.5D) provides the fingerprint
//! primitive an operator could use to verify one of these keys
//! out-of-band; wiring that into a workflow is documented there as a
//! deliberate gap, not something this module closes.
//!
//! ## Key file handling
//!
//! The key is written as 64 hex characters — the same encoding
//! `MIXNODE_SECRET_KEY_HEX` accepts, so an operator can move a key
//! between the two mechanisms without re-encoding it. On Unix the file
//! is created with mode `0600`; **on Windows it is not**, because there
//! is no equivalent one-call permission bit and doing this properly
//! needs an ACL API this crate does not otherwise touch. That gap is
//! stated here rather than left for a reader to assume the file is
//! protected on every platform.

use parda_protocol::mixnet::{self, StaticSecret};

/// Resolve this node's secret key — see module docs for the order.
pub fn load_or_generate() -> StaticSecret {
    if let Ok(hex_str) = std::env::var("MIXNODE_SECRET_KEY_HEX") {
        let bytes =
            hex_decode(&hex_str).expect("MIXNODE_SECRET_KEY_HEX must be 64 hex characters (32 bytes)");
        let arr: [u8; 32] = bytes
            .try_into()
            .expect("MIXNODE_SECRET_KEY_HEX must decode to exactly 32 bytes");
        return StaticSecret::from(arr);
    }

    if let Ok(path) = std::env::var("MIXNODE_KEY_PATH") {
        return load_or_create_key_file(std::path::Path::new(&path));
    }

    tracing::warn!(
        "Neither MIXNODE_SECRET_KEY_HEX nor MIXNODE_KEY_PATH is set — generating an ephemeral \
         node identity (dev/test only; this node's public key will change on every restart, \
         invalidating any peer's configured topology entry for it)"
    );
    mixnet::generate_node_keypair().0
}

/// Load the key at `path`, or generate and persist one if it is absent.
///
/// Panics on a *malformed* existing file rather than overwriting it.
/// That is deliberate and is the fail-closed direction: silently
/// replacing a key file that failed to parse would destroy a node's
/// identity — possibly a recoverable one, e.g. a partially-written file
/// an operator could repair — in response to a read error.
pub fn load_or_create_key_file(path: &std::path::Path) -> StaticSecret {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let bytes = hex_decode(&contents).unwrap_or_else(|| {
                panic!(
                    "mix node key file {} is not 64 hex characters — refusing to overwrite it; \
                     repair or remove it explicitly",
                    path.display()
                )
            });
            let arr: [u8; 32] = bytes.try_into().unwrap_or_else(|_| {
                panic!(
                    "mix node key file {} must decode to exactly 32 bytes — refusing to \
                     overwrite it; repair or remove it explicitly",
                    path.display()
                )
            });
            tracing::info!(path = %path.display(), "loaded persisted mix node identity");
            StaticSecret::from(arr)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let (secret, _public) = mixnet::generate_node_keypair();
            write_key_file(path, &secret);
            tracing::info!(
                path = %path.display(),
                "generated and persisted a new mix node identity"
            );
            secret
        }
        Err(e) => panic!("failed to read mix node key file {}: {e}", path.display()),
    }
}

fn write_key_file(path: &std::path::Path, secret: &StaticSecret) {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("failed to create {}: {e}", parent.display()));
        }
    }

    let hex: String = secret.to_bytes().iter().map(|b| format!("{b:02x}")).collect();

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // Create with 0600 from the outset rather than writing first and
        // chmod-ing after — the latter leaves a window in which the key
        // exists on disk world-readable.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap_or_else(|e| panic!("failed to create mix node key file {}: {e}", path.display()));
        file.write_all(hex.as_bytes())
            .unwrap_or_else(|e| panic!("failed to write mix node key file {}: {e}", path.display()));
    }

    #[cfg(not(unix))]
    {
        // See module docs: no equivalent one-call permission bit here.
        std::fs::write(path, hex.as_bytes())
            .unwrap_or_else(|e| panic!("failed to write mix node key file {}: {e}", path.display()));
        tracing::warn!(
            path = %path.display(),
            "mix node key file written without restrictive permissions — this platform has no \
             equivalent of Unix mode 0600 in this code path; protect the file at the filesystem \
             or volume level"
        );
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

    /// The actual point of Sub-Phase 4.5E's persistence: the same public
    /// key must come back after a "restart" (a second call against the
    /// same path, with no in-memory state carried over).
    #[test]
    fn key_file_yields_a_stable_identity_across_reloads() {
        let dir = std::env::temp_dir().join(format!(
            "parda-mixnode-identity-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.key");

        let first = load_or_create_key_file(&path);
        assert!(path.exists(), "the key file must have been created");

        let second = load_or_create_key_file(&path);
        assert_eq!(
            first.to_bytes(),
            second.to_bytes(),
            "a restarted node must keep its identity, or every peer's configured topology \
             entry for it silently breaks"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A fresh path must produce a *different* key — persistence must
    /// not have been accidentally implemented as a fixed key.
    #[test]
    fn distinct_paths_yield_distinct_identities() {
        let base = std::env::temp_dir().join(format!(
            "parda-mixnode-identity-distinct-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();

        let a = load_or_create_key_file(&base.join("a.key"));
        let b = load_or_create_key_file(&base.join("b.key"));
        assert_ne!(a.to_bytes(), b.to_bytes());

        std::fs::remove_dir_all(&base).ok();
    }

    /// A malformed key file must not be silently overwritten — see
    /// [`load_or_create_key_file`]'s docs on why that direction is the
    /// fail-closed one.
    #[test]
    #[should_panic(expected = "refusing to overwrite")]
    fn malformed_key_file_panics_rather_than_being_replaced() {
        let dir = std::env::temp_dir().join(format!(
            "parda-mixnode-identity-malformed-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.key");
        std::fs::write(&path, "not hex at all").unwrap();

        let _ = load_or_create_key_file(&path);
    }
}
