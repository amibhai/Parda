//! Anonymous dead-drop addressing (Sub-Phase 4C).
//!
//! See `docs/phase4-4c-dead-drop-addressing-design.md` for the full,
//! reviewed design note this module implements — the summary here is
//! just enough to orient a reader of the code; the note is the actual
//! design record.
//!
//! A bundle's mesh storage address must be derivable by sender and
//! recipient (via a dedicated, purpose-only shared secret — never the
//! Signal identity key, never reachable from inside the Double-Ratchet
//! session, same reasoning as [`crate::self_destruct`]'s design note
//! §1) but must reveal nothing about recipient identity to a
//! [`crate::transport`] carrier or any other observer of the address.
//! `parda_mesh::relay::MeshRelayAgent` never calls anything in this
//! module — it only ever treats an [`Address`] as opaque bytes.

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// A blinded dead-drop storage address — an HKDF output, uniformly
/// distributed, indistinguishable from a random decoy
/// ([`random_decoy_address`]) to anyone without [`TagKey`].
pub const ADDRESS_LEN: usize = 32;
pub type Address = [u8; ADDRESS_LEN];

const ADDRESS_KDF_CONTEXT: &[u8] = b"PARDA-Phase4-DeadDropAddress-V1";

/// A dedicated, purpose-only X25519 keypair for dead-drop address
/// derivation — generated once per conversation, exchanged alongside
/// prekey-bundle enrollment (design note §1). Never reused for message
/// content or any other purpose.
pub struct DeadDropKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl DeadDropKeyPair {
    /// Generate a fresh keypair. Same RNG posture as
    /// `mixnet::generate_node_keypair` — `StaticSecret::random()`, backed
    /// by the `getrandom` feature already enabled on this crate's
    /// `x25519-dalek` dependency, no separately-specified RNG needed.
    pub fn generate() -> Self {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// The public half to send the peer during enrollment.
    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Derive this conversation's [`TagKey`] from the peer's dead-drop
    /// public key. Both sides call this with the other's public key and
    /// arrive at the identical `TagKey` — standard ECDH symmetry, the
    /// same property X3DH itself relies on.
    pub fn derive_tag_key(&self, remote_public: &PublicKey) -> TagKey {
        let shared = self.secret.diffie_hellman(remote_public);
        // HKDF-Extract with an all-zero salt (RFC 5869 §2.2) — same
        // pattern `self_destruct::derive_key` already uses via
        // `Hkdf::new(None, ikm)`.
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(&[], okm.as_mut())
            .expect("32-byte HKDF-Expand output is always valid for SHA-256");
        TagKey(okm)
    }
}

/// Per-conversation address-derivation key. Never transmitted; used for
/// nothing except deriving [`Address`]es via [`TagKey::address_for`].
/// Zeroized on drop.
pub struct TagKey(Zeroizing<[u8; 32]>);

impl TagKey {
    /// Derive the address for message index `n` in this conversation.
    /// Deterministic and identical on both sides given the same `n` —
    /// see design note §2 for why `n` is a monotonic per-peer counter,
    /// not wall-clock time.
    pub fn address_for(&self, n: u64) -> Address {
        let mut info = Vec::with_capacity(ADDRESS_KDF_CONTEXT.len() + 8);
        info.extend_from_slice(ADDRESS_KDF_CONTEXT);
        info.extend_from_slice(&n.to_be_bytes());

        let hk = Hkdf::<Sha256>::new(None, self.0.as_ref());
        let mut address = [0u8; ADDRESS_LEN];
        hk.expand(&info, &mut address)
            .expect("32-byte HKDF-Expand output is always valid for SHA-256");
        address
    }

    /// A forward window of addresses starting at `start`, inclusive —
    /// what a recipient polls to tolerate reordering/loss of the
    /// sender's counter, the same way Double Ratchet tolerates skipped
    /// message keys via a bounded lookahead. See design note §2.
    pub fn address_window(&self, start: u64, window: usize) -> Vec<Address> {
        (start..start.saturating_add(window as u64))
            .map(|n| self.address_for(n))
            .collect()
    }
}

/// A freshly-random address, computationally indistinguishable from a
/// real [`TagKey::address_for`] output to anyone without the key — both
/// are uniformly-distributed 32-byte values. Used by
/// [`build_poll_set`] to construct decoy queries (design note §3).
pub fn random_decoy_address() -> Address {
    let mut bytes = [0u8; ADDRESS_LEN];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Build the set of addresses to poll a mesh carrier for: the real
/// forward-window addresses plus `decoys_per_real` freshly-random decoys
/// per real address, all shuffled together so position in the returned
/// list carries no signal about which entries are real. This is what
/// `parda_mesh`'s `MeshTransport::receive` (Sub-Phase 4C wiring) hands to
/// `MeshRelayAgent::bundles_for_addresses` — the relay cannot and does
/// not distinguish real from decoy, which is the entire point (design
/// note §3, measured in `mesh/tests/retrieval_pattern_tests.rs`).
pub fn build_poll_set(tag_key: &TagKey, start: u64, window: usize, decoys_per_real: usize) -> Vec<Address> {
    use rand::seq::SliceRandom;

    let mut addresses = tag_key.address_window(start, window);
    for _ in 0..(window * decoys_per_real) {
        addresses.push(random_decoy_address());
    }
    addresses.shuffle(&mut rand::thread_rng());
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_tag_key() {
        let alice = DeadDropKeyPair::generate();
        let bob = DeadDropKeyPair::generate();

        let alice_tag = alice.derive_tag_key(&bob.public_key());
        let bob_tag = bob.derive_tag_key(&alice.public_key());

        // Same address for the same n on both sides — the property the
        // whole scheme depends on.
        assert_eq!(alice_tag.address_for(0), bob_tag.address_for(0));
        assert_eq!(alice_tag.address_for(41), bob_tag.address_for(41));
    }

    #[test]
    fn different_conversations_derive_unrelated_tag_keys() {
        let alice = DeadDropKeyPair::generate();
        let bob = DeadDropKeyPair::generate();
        let carol = DeadDropKeyPair::generate();

        let alice_bob = alice.derive_tag_key(&bob.public_key());
        let alice_carol = alice.derive_tag_key(&carol.public_key());

        assert_ne!(alice_bob.address_for(0), alice_carol.address_for(0));
    }

    #[test]
    fn successive_addresses_in_one_conversation_are_unrelated() {
        let alice = DeadDropKeyPair::generate();
        let bob = DeadDropKeyPair::generate();
        let tag = alice.derive_tag_key(&bob.public_key());

        let addresses: Vec<Address> = (0..50).map(|n| tag.address_for(n)).collect();
        for i in 0..addresses.len() {
            for j in (i + 1)..addresses.len() {
                assert_ne!(addresses[i], addresses[j], "addresses {i} and {j} collided");
            }
        }
    }

    #[test]
    fn address_window_matches_individual_derivation() {
        let alice = DeadDropKeyPair::generate();
        let bob = DeadDropKeyPair::generate();
        let tag = alice.derive_tag_key(&bob.public_key());

        let window = tag.address_window(10, 5);
        let individual: Vec<Address> = (10..15).map(|n| tag.address_for(n)).collect();
        assert_eq!(window, individual);
    }

    #[test]
    fn build_poll_set_always_contains_every_real_address_in_the_window() {
        let alice = DeadDropKeyPair::generate();
        let bob = DeadDropKeyPair::generate();
        let tag = alice.derive_tag_key(&bob.public_key());

        let real: Vec<Address> = tag.address_window(0, 3);
        let poll_set = build_poll_set(&tag, 0, 3, 5);

        for addr in &real {
            assert!(poll_set.contains(addr));
        }
        assert_eq!(poll_set.len(), 3 + 3 * 5);
    }
}
