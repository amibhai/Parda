//! In-memory implementation of the libsignal-protocol storage traits.
//!
//! ## ⚠️ TEST / DEVELOPMENT ONLY
//!
//! `InMemorySignalProtocolStore` is gated behind `#[cfg(test)]` or an explicit
//! `dev` feature flag. **It must never be used in production.** Production code
//! must bridge to the platform secure element:
//! - Android: Android Keystore (StrongBox if available)
//! - iOS: iOS Secure Enclave
//!
//! The `PardaKeyStore` trait defined below is the interface production
//! implementations must satisfy.
//!
//! ## Why `Rc<RefCell<..>>`
//!
//! `message_encrypt` / `message_decrypt` / `process_prekey_bundle` each take
//! several storage traits as *separate* `&mut dyn Trait` parameters (session
//! store, identity store, prekey store, ...). When one struct backs all of
//! them, Rust cannot hand out two simultaneous `&mut` borrows of the same
//! field for a single call. `InMemorySignalProtocolStore` is therefore a
//! cheap `Clone`-able handle around shared interior-mutable state: callers
//! pass `&mut store.clone()` per parameter, each clone aliasing the same
//! underlying `RefCell`. This mirrors the role-separated test stores used in
//! libsignal-protocol's own test suite, without changing any public method
//! signature this crate's tests already depend on.

use std::{cell::RefCell, collections::HashMap, rc::Rc};

use async_trait::async_trait;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
    ProtocolAddress, SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore,
};

// ─── Production storage trait ────────────────────────────────────────────────

/// Marker trait that production key stores must implement.
///
/// Blanket: any type that satisfies all five libsignal storage traits
/// automatically satisfies `PardaKeyStore`.
///
/// `KyberPreKeyStore` is required by libsignal-protocol v0.66.0's
/// `message_decrypt` signature even though PARDA does not yet use PQXDH
/// (post-quantum key encapsulation is deferred to Phase 5 per
/// `docs/phase1-architecture.md` §9). Implementations may store zero
/// Kyber prekeys.
pub trait PardaKeyStore:
    SessionStore + PreKeyStore + SignedPreKeyStore + KyberPreKeyStore + IdentityKeyStore + Send + Sync
{
}

impl<T> PardaKeyStore for T where
    T: SessionStore + PreKeyStore + SignedPreKeyStore + KyberPreKeyStore + IdentityKeyStore + Send + Sync
{
}

// ─── In-memory store (tests / development) ───────────────────────────────────

/// Shared state behind an [`InMemorySignalProtocolStore`] handle.
#[derive(Default)]
struct StoreState {
    /// Local identity key pair.
    identity_key_pair: Option<IdentityKeyPair>,
    /// Local registration ID.
    registration_id: u32,
    /// Trusted remote identity keys, keyed by address string.
    trusted_identities: HashMap<String, IdentityKey>,
    /// Session records, keyed by address string.
    sessions: HashMap<String, SessionRecord>,
    /// One-time prekey records, keyed by prekey ID.
    prekeys: HashMap<u32, PreKeyRecord>,
    /// Signed prekey records, keyed by signed prekey ID.
    signed_prekeys: HashMap<u32, SignedPreKeyRecord>,
    /// Signed Kyber prekey records, keyed by Kyber prekey ID.
    /// Unused in Phase 1/2 (no PQXDH); present only to satisfy
    /// `KyberPreKeyStore`, which `message_decrypt` now requires.
    kyber_prekeys: HashMap<u32, KyberPreKeyRecord>,
}

/// An entirely in-memory implementation of all five libsignal storage traits.
///
/// Suitable for unit tests and local integration tests.
/// **Not suitable for production use** — all key material is plaintext in RAM
/// and is lost when the process exits.
///
/// Cloning an `InMemorySignalProtocolStore` clones the handle, not the data —
/// all clones observe the same underlying session/key state. This is what
/// lets a single store satisfy several simultaneous trait-object parameters
/// in one `message_encrypt` / `message_decrypt` call (see module docs).
///
/// For production, replace this with a store that:
/// - Persists session records to SQLCipher (encrypted SQLite)
/// - Wraps identity key operations through the platform keystore
/// - Implements the same five traits so `SessionManager` needs no changes
#[derive(Clone, Default)]
pub struct InMemorySignalProtocolStore {
    state: Rc<RefCell<StoreState>>,
}

impl InMemorySignalProtocolStore {
    /// Initialise the store with a local identity.
    pub fn new(identity_key_pair: IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            state: Rc::new(RefCell::new(StoreState {
                identity_key_pair: Some(identity_key_pair),
                registration_id,
                ..Default::default()
            })),
        }
    }

    /// Seed a batch of one-time prekeys (called after key generation).
    pub fn store_prekey_batch(&mut self, prekeys: &[PreKeyRecord]) -> Result<(), SignalProtocolError> {
        let mut state = self.state.borrow_mut();
        for pk in prekeys {
            let id: u32 = pk.id()?.into();
            state.prekeys.insert(id, pk.clone());
        }
        Ok(())
    }

    /// Seed a signed prekey.
    pub fn store_signed_prekey_record(&mut self, record: &SignedPreKeyRecord) -> Result<(), SignalProtocolError> {
        let id: u32 = record.id()?.into();
        self.state.borrow_mut().signed_prekeys.insert(id, record.clone());
        Ok(())
    }

    /// "Burn this conversation" (Sub-Phase 3D): deliberately remove every
    /// piece of session and trust state this store holds for `address`.
    ///
    /// **Read this before treating `burn_session` as equivalent to
    /// [`crate::self_destruct`]'s guarantees — it is not, and the brief
    /// this project follows is explicit that the two must not be
    /// conflated.** `self_destruct::SelfDestructingMessage` provably
    /// zeroizes its key material (`protocol/src/self_destruct.rs`'s
    /// memory-forensics tests). `burn_session` cannot make that claim,
    /// for a reason outside this crate's control: `libsignal-protocol`
    /// v0.66.0's `SessionRecord` and the `PrivateKey` type underneath
    /// `IdentityKeyPair` are ordinary, non-zeroizing Rust values — in
    /// fact `PrivateKey` is `#[derive(Clone, Copy, ...)]` wrapping a
    /// plain `[u8; 32]` (confirmed by reading
    /// `rust/core/src/curve.rs` in the pinned `v0.66.0` tag), which
    /// means libsignal's own internals may hold an unknown number of
    /// implicit stack/register copies that no amount of care on PARDA's
    /// side can enumerate or overwrite. Reaching into libsignal to force
    /// zeroization there would mean forking or patching it — reopening
    /// the same no-custom-crypto risk `docs/phase1-architecture.md` §2
    /// already rejected once, for the same reason it was rejected for
    /// Sub-Phase 3A's KDF (see `docs/phase3-3a-self-destruct-design.md`
    /// §1).
    ///
    /// **What `burn_session` actually, provably does** (see
    /// `protocol/tests/session_burn_tests.rs`): removes the session
    /// record and trusted-identity entry for `address` from this store's
    /// own `HashMap`s, so every subsequent operation through the normal
    /// API — `SessionManager::encrypt`/`decrypt`, `load_session` — behaves
    /// exactly as if no conversation with `address` had ever existed.
    /// This is a real, tested, load-bearing guarantee (the conversation
    /// is unusable, not just "marked burned") — it is just a *narrower*
    /// one than byte-level erasure, and the narrowing is documented here
    /// rather than left for a reader to assume away.
    pub fn burn_session(&self, address: &ProtocolAddress) -> SessionBurnResult {
        let mut state = self.state.borrow_mut();
        let addr_str = address.to_string();
        SessionBurnResult {
            session_removed: state.sessions.remove(&addr_str).is_some(),
            identity_trust_removed: state.trusted_identities.remove(&addr_str).is_some(),
        }
    }

    /// `true` if this store still holds a session record or trusted
    /// identity for `address` — i.e. `burn_session` has not (yet) been
    /// called for it, or it was never established.
    pub fn has_conversation_state(&self, address: &ProtocolAddress) -> bool {
        let state = self.state.borrow();
        let addr_str = address.to_string();
        state.sessions.contains_key(&addr_str) || state.trusted_identities.contains_key(&addr_str)
    }
}

/// What [`InMemorySignalProtocolStore::burn_session`] actually removed.
/// Both `false` means there was nothing to burn — not necessarily an
/// error, but worth a caller being able to distinguish from "burned
/// something real."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBurnResult {
    pub session_removed: bool,
    pub identity_trust_removed: bool,
}

// ─── SessionStore ─────────────────────────────────────────────────────────────

#[async_trait(?Send)]
impl SessionStore for InMemorySignalProtocolStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        Ok(self.state.borrow().sessions.get(&address.to_string()).cloned())
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        self.state
            .borrow_mut()
            .sessions
            .insert(address.to_string(), record.clone());
        Ok(())
    }
}

// ─── PreKeyStore ──────────────────────────────────────────────────────────────

#[async_trait(?Send)]
impl PreKeyStore for InMemorySignalProtocolStore {
    async fn get_pre_key(
        &self,
        prekey_id: PreKeyId,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        let id: u32 = prekey_id.into();
        self.state
            .borrow()
            .prekeys
            .get(&id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        self.state.borrow_mut().prekeys.insert(id, record.clone());
        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: PreKeyId,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        self.state.borrow_mut().prekeys.remove(&id);
        Ok(())
    }
}

// ─── SignedPreKeyStore ────────────────────────────────────────────────────────

#[async_trait(?Send)]
impl SignedPreKeyStore for InMemorySignalProtocolStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let id: u32 = signed_prekey_id.into();
        self.state
            .borrow()
            .signed_prekeys
            .get(&id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = signed_prekey_id.into();
        self.state.borrow_mut().signed_prekeys.insert(id, record.clone());
        Ok(())
    }
}

// ─── KyberPreKeyStore ─────────────────────────────────────────────────────────
//
// Not exercised by Phase 1/2 sessions (no PQXDH); required only to satisfy
// `message_decrypt`'s trait bounds. Behaves like `PreKeyStore` above.

#[async_trait(?Send)]
impl KyberPreKeyStore for InMemorySignalProtocolStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        self.state
            .borrow()
            .kyber_prekeys
            .get(&id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        self.state.borrow_mut().kyber_prekeys.insert(id, record.clone());
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        self.state.borrow_mut().kyber_prekeys.remove(&id);
        Ok(())
    }
}

// ─── IdentityKeyStore ────────────────────────────────────────────────────────

#[async_trait(?Send)]
impl IdentityKeyStore for InMemorySignalProtocolStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        self.state
            .borrow()
            .identity_key_pair
            .ok_or_else(|| SignalProtocolError::InvalidState("identity", "not initialized".into()))
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.state.borrow().registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalProtocolError> {
        let addr_str = address.to_string();
        let mut state = self.state.borrow_mut();
        let changed = state
            .trusted_identities
            .get(&addr_str)
            .map(|existing| existing != identity)
            .unwrap_or(true);
        state.trusted_identities.insert(addr_str, *identity);
        Ok(changed)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        // Trust-On-First-Use (TOFU) — Phase 1 default.
        // Phase 2 upgrades this to explicit safety-number verification:
        // the user compares a fingerprint of identity keys out-of-band
        // (similar to Signal's "safety number" screen) before marking
        // a remote identity as permanently trusted.
        Ok(self
            .state
            .borrow()
            .trusted_identities
            .get(&address.to_string())
            .map(|stored| stored == identity)
            .unwrap_or(true)) // trust if unseen
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        Ok(self.state.borrow().trusted_identities.get(&address.to_string()).copied())
    }
}
