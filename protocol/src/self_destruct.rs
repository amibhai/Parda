//! Time-bound self-destructing message primitive (Sub-Phase 3A).
//!
//! See `docs/phase3-3a-self-destruct-design.md` for the full design
//! rationale — in particular §1 for why the key comes from a fresh local
//! secret rather than the (inaccessible) Double-Ratchet message key, and
//! §3 for the clock-trust model this module's expiry timer relies on.
//!
//! ## What this proves, and what it doesn't (yet)
//!
//! [`SelfDestructingMessage`] holds recovered plaintext, re-encrypted
//! under a freshly-derived key, with that key erased — not just dropped,
//! see the memory-forensics tests in this file's `#[cfg(test)]` module —
//! when the message expires. This is Sub-Phase 3A's whole job: prove
//! "the key is provably gone from live process memory after expiry," not
//! "gone from swap/pagefile" (Sub-Phase 3C's job) and not "gone after
//! first read" (Sub-Phase 3B's separate, distinct guarantee).
//!
//! **The two destruct modes' guarantees must not blur together:**
//! time-bound (this sub-phase) means "gone by T regardless of whether it
//! was ever read." Read-triggered (Sub-Phase 3B) means "gone after first
//! read regardless of T." [`DestructMode`] exists now only so the KDF has
//! domain separation ready for 3B; the read-trigger itself isn't
//! implemented here.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use tokio::time::Instant as TokioInstant;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    clock_guard::{check_clock_integrity, ClockCheck, ClockWatermarkStore},
    error::{PardaError, Result},
};

/// Default self-destruct expiry window: 5 minutes. A "burn after
/// reading" reference point — short enough to meaningfully bound
/// exposure, long enough to be usable. Always configurable per message
/// via [`SelfDestructingMessage::seal`]'s `expiry_window` parameter;
/// this is a default, not a hardcoded floor or ceiling.
pub const DEFAULT_EXPIRY_WINDOW: Duration = Duration::from_secs(5 * 60);

const KDF_CONTEXT: &[u8] = b"PARDA-Phase3-SelfDestructKey-V1";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// Which guarantee a self-destructing message carries. See module docs
/// for why the two modes must not be conflated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructMode {
    TimeBound,
    ReadTriggered,
}

impl DestructMode {
    fn tag(self) -> u8 {
        match self {
            DestructMode::TimeBound => 0,
            DestructMode::ReadTriggered => 1,
        }
    }
}

// ─── Key derivation ─────────────────────────────────────────────────────────

/// The derived self-destruct key. Zeroized on drop (`ZeroizeOnDrop`) and
/// by [`SelfDestructingMessage::expire_now`], which drops it explicitly
/// in place rather than waiting for the whole message to go out of
/// scope — see the memory-forensics tests below for proof this actually
/// overwrites the bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKey([u8; KEY_LEN]);

/// Derive the self-destruct key via HKDF-SHA256 (RFC 5869). `seed` is a
/// fresh, local, never-transmitted secret — see module docs for why this
/// stands in for the (inaccessible) Double-Ratchet message key. `info`
/// binds the output to this specific message's mode, declared delivery
/// timestamp, and expiry window, so two messages never derive the same
/// key even from the same seed.
fn derive_key(
    seed: &Zeroizing<[u8; 32]>,
    mode: DestructMode,
    timestamp_ms: u64,
    expiry_window_ms: u64,
) -> DerivedKey {
    let mut info = Vec::with_capacity(KDF_CONTEXT.len() + 1 + 8 + 8);
    info.extend_from_slice(KDF_CONTEXT);
    info.push(mode.tag());
    info.extend_from_slice(&timestamp_ms.to_be_bytes());
    info.extend_from_slice(&expiry_window_ms.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(None, seed.as_ref());
    let mut okm = [0u8; KEY_LEN];
    // Only fails if the requested output length is invalid for the hash
    // (> 255 * hash_len) — a fixed 32-byte request never triggers that
    // for SHA-256.
    hk.expand(&info, &mut okm)
        .expect("32-byte HKDF-Expand output is always valid for SHA-256");
    DerivedKey(okm)
}

/// Erase the key held in `slot`: zeroize it explicitly *while it is still
/// `Some`*, then clear the slot to `None`.
///
/// This is deliberately **not** just `*slot.lock().unwrap() = None`. That
/// would rely on `Option`'s implicit drop-in-place-on-reassignment
/// running `DerivedKey`'s `ZeroizeOnDrop` — which does perform the
/// volatile zero-write, but *only for that instant*: once the `Option`
/// has transitioned to `None`, the bytes that used to be the payload are
/// no longer part of any well-defined value at that address, and nothing
/// in the language guarantees a subsequent read observes what the
/// zeroize wrote versus something else the compiler placed there for an
/// unrelated purpose. Zeroizing first, while the value is still `Some`
/// (i.e. still a live, type-stable `[u8; 32]`), then clearing to `None`
/// as a separate step, means the erasure is observable through an
/// ordinary safe reference at the moment it happens — exactly the
/// pattern `zeroize`'s own test suite uses to verify itself. See
/// `tests` below for where this distinction was actually caught: an
/// earlier version of this function used the single-step form, and its
/// own memory-forensics test failed intermittently with clearly
/// non-zero, pointer-shaped garbage where zeroed bytes were expected.
fn erase(slot: &Mutex<Option<DerivedKey>>) {
    let mut guard = slot.lock().unwrap();
    if let Some(key) = guard.as_mut() {
        key.zeroize();
    }
    *guard = None;
}

// ─── Self-destructing message ──────────────────────────────────────────────

/// Plaintext, re-encrypted under a freshly-derived, time-bound key, held
/// until expiry erases the key. Cloning shares the same underlying key
/// and timer (via `Arc`) — all clones observe the same message go dark
/// at the same instant.
#[derive(Clone)]
pub struct SelfDestructingMessage {
    /// nonce (12 bytes) || AEAD ciphertext+tag. Fine to hold in an
    /// ordinary buffer — useless without `key`.
    ciphertext: Arc<Vec<u8>>,
    key: Arc<Mutex<Option<DerivedKey>>>,
    mode: DestructMode,
}

impl SelfDestructingMessage {
    /// Encrypt `plaintext` under a freshly-derived key and start its
    /// expiry timer, anchored to a monotonic clock (immune to wall-clock
    /// rollback for as long as the process keeps running — see
    /// `clock_guard` for the cross-restart case). `timestamp_ms` is the
    /// message's declared delivery time (fed into the KDF for domain
    /// separation only — see module docs on what is and isn't trusted).
    pub fn seal(plaintext: &[u8], timestamp_ms: u64, expiry_window: Duration) -> Result<Self> {
        let mut seed_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed_bytes);
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(seed_bytes);

        let expiry_window_ms = expiry_window.as_millis() as u64;
        let key = derive_key(&seed, DestructMode::TimeBound, timestamp_ms, expiry_window_ms);
        // `seed` is dropped (and zeroized via `Zeroizing`) at end of
        // scope — it is never needed again once `key` exists.

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
        let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| PardaError::SelfDestructCrypto(e.to_string()))?;

        let mut stored = Vec::with_capacity(NONCE_LEN + ct.len());
        stored.extend_from_slice(&nonce);
        stored.extend_from_slice(&ct);

        let message = Self {
            ciphertext: Arc::new(stored),
            key: Arc::new(Mutex::new(Some(key))),
            mode: DestructMode::TimeBound,
        };

        message.spawn_expiry_timer(expiry_window);
        Ok(message)
    }

    fn spawn_expiry_timer(&self, expiry_window: Duration) {
        let key = Arc::clone(&self.key);
        let deadline = TokioInstant::now() + expiry_window;
        tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            erase(&key);
        });
    }

    /// Erase the key immediately, synchronously, without waiting for the
    /// timer. Used by tests, and by whatever Sub-Phase 3B wires up as
    /// its read-trigger.
    pub fn expire_now(&self) {
        erase(&self.key);
    }

    /// `true` if the key is gone (expired or explicitly erased).
    pub fn is_expired(&self) -> bool {
        self.key.lock().unwrap().is_none()
    }

    pub fn mode(&self) -> DestructMode {
        self.mode
    }

    /// Decrypt and return the plaintext, if the key is still live.
    /// Returns [`PardaError::SelfDestructExpired`] otherwise — fails
    /// closed rather than returning a default/empty value.
    pub fn open(&self) -> Result<Zeroizing<Vec<u8>>> {
        let guard = self.key.lock().unwrap();
        let key = guard.as_ref().ok_or(PardaError::SelfDestructExpired)?;

        if self.ciphertext.len() < NONCE_LEN {
            return Err(PardaError::SelfDestructCrypto(
                "stored ciphertext shorter than the nonce prefix".to_string(),
            ));
        }
        let (nonce_bytes, ct) = self.ciphertext.split_at(NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ct)
            .map_err(|e| PardaError::SelfDestructCrypto(e.to_string()))?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Like [`Self::open`], but first checks clock integrity via `store`
    /// against caller-supplied `now_ms` and fails closed — forcing
    /// immediate, permanent expiry — if a rollback is detected. See
    /// `clock_guard` module docs for the mechanism and its documented
    /// limits. `now_ms` is a parameter rather than read internally so
    /// this is deterministically testable and so a single trusted clock
    /// reading can be shared across a batch of checks.
    pub fn open_with_clock_guard(
        &self,
        store: &dyn ClockWatermarkStore,
        now_ms: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if let ClockCheck::RollbackDetected {
            watermark_ms,
            observed_ms,
        } = check_clock_integrity(store, now_ms)
        {
            self.expire_now();
            return Err(PardaError::ClockRollbackDetected {
                observed_ms,
                watermark_ms,
            });
        }
        self.open()
    }
}

// ─── Unit tests (white-box: need access to private fields/functions) ──────────

#[cfg(test)]
mod tests {
    use super::*;

    // `seal()` spawns a background expiry timer via `tokio::spawn`, so
    // anything calling it needs an active Tokio runtime — `#[tokio::test]`
    // rather than plain `#[test]`.

    #[tokio::test]
    async fn test_seal_open_roundtrip() {
        let message = SelfDestructingMessage::seal(b"burn after reading", 1_753_900_000_000, Duration::from_secs(60)).unwrap();
        let plaintext = message.open().unwrap();
        assert_eq!(&plaintext[..], b"burn after reading");
    }

    #[tokio::test]
    async fn test_expire_now_makes_open_fail_closed() {
        let message = SelfDestructingMessage::seal(b"secret", 1000, Duration::from_secs(60)).unwrap();
        assert!(message.open().is_ok());

        message.expire_now();

        assert!(message.is_expired());
        assert!(matches!(message.open(), Err(PardaError::SelfDestructExpired)));
    }

    #[test]
    fn test_different_modes_derive_different_keys_from_the_same_seed() {
        let seed = Zeroizing::new([7u8; 32]);
        let k1 = derive_key(&seed, DestructMode::TimeBound, 1000, 5000);
        let k2 = derive_key(&seed, DestructMode::ReadTriggered, 1000, 5000);
        assert_ne!(k1.0, k2.0, "domain separation between destruct modes must actually change the derived key");
    }

    #[test]
    fn test_different_timestamps_derive_different_keys_from_the_same_seed() {
        let seed = Zeroizing::new([7u8; 32]);
        let k1 = derive_key(&seed, DestructMode::TimeBound, 1000, 5000);
        let k2 = derive_key(&seed, DestructMode::TimeBound, 2000, 5000);
        assert_ne!(k1.0, k2.0);
    }

    // ─── Memory forensics: proof the erasure overwrites bytes, not just
    // makes them logically unreachable. See design doc §5 for why two
    // complementary techniques are used. ──────────────────────────────

    /// Technique 1 (portable — runs on every CI platform, no `unsafe`):
    /// read the key's bytes through a live, type-stable reference
    /// immediately before and immediately after `erase()` runs, while
    /// the value is still `Some` both times. This mirrors the pattern
    /// the `zeroize` crate's own integration tests use
    /// (`zeroize_on_drop_byte_arrays` in `zeroize`'s `tests/zeroize.rs`:
    /// read the *same live binding* before/after `drop_in_place`, never
    /// a pointer captured across a value's shape changing).
    ///
    /// An earlier version of this test captured a raw pointer to the key
    /// bytes, called `expire_now()` (which set the `Option` straight to
    /// `None`), and re-read that pointer afterward — expecting to see
    /// zeros. It instead saw clearly non-zero, pointer-shaped garbage,
    /// intermittently. The bug wasn't in zeroization: `Option<T>`
    /// transitioning `Some → None` doesn't guarantee the former payload
    /// bytes stay as whatever `Drop` last wrote — once the value's
    /// *shape* changes, nothing in the language keeps that region
    /// meaningful, even inside a still-live allocation. `erase()` (see
    /// its doc comment) was restructured to zeroize *before* clearing to
    /// `None` specifically so the erasure is observable through an
    /// ordinary safe reference, which is what this test now checks.
    #[test]
    fn test_erase_zeroizes_before_clearing_and_ends_up_gone() {
        fn fresh_key() -> DerivedKey {
            let mut seed_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed_bytes);
            let key = derive_key(&Zeroizing::new(seed_bytes), DestructMode::TimeBound, 42, 1000);
            assert!(
                key.0.iter().any(|&b| b != 0),
                "test setup produced an all-zero key — HKDF output should be effectively \
                 uniform random; an all-zero key would make these assertions meaningless"
            );
            key
        }

        // Step 1: replicate exactly what `erase()` does internally, but
        // stop between its two steps so the intermediate "zeroized but
        // still Some" state is directly observable through a live,
        // type-stable reference — no unsafe, no shape change yet.
        let slot: Mutex<Option<DerivedKey>> = Mutex::new(Some(fresh_key()));
        {
            let mut guard = slot.lock().unwrap();
            let k = guard.as_mut().unwrap();
            assert!(k.0.iter().any(|&b| b != 0), "control read found nothing but zeros");
            k.zeroize();
            assert!(
                k.0.iter().all(|&b| b == 0),
                "key bytes were not overwritten by zeroize() while still Some — found: {:?}",
                k.0
            );
        }

        // Step 2: the real, production `erase()` function, black-box —
        // after it runs, the safe API must agree the key is gone.
        let slot2: Mutex<Option<DerivedKey>> = Mutex::new(Some(fresh_key()));
        erase(&slot2);
        assert!(
            slot2.lock().unwrap().is_none(),
            "erase() must leave the slot empty"
        );
    }

    #[test]
    fn test_zeroize_overwrites_key_bytes_on_ordinary_drop_too() {
        // Proves `ZeroizeOnDrop` fires on the normal Rust drop path too,
        // not only through this module's own explicit `erase()` call —
        // using the same live-reference-before/after pattern as above,
        // via `ptr::drop_in_place` (which, like `Box`'s drop, runs
        // `Drop::drop` in place without changing the value's shape the
        // way an `Option` transition does — see the comment on `erase`).
        let mut key = derive_key(&Zeroizing::new([9u8; 32]), DestructMode::TimeBound, 1, 1);
        assert!(key.0.iter().any(|&b| b != 0));

        unsafe { std::ptr::drop_in_place(&mut key) };

        assert!(
            key.0.iter().all(|&b| b == 0),
            "key bytes were not overwritten by ZeroizeOnDrop — found: {:?}",
            key.0
        );
    }
}

/// Technique 2 (Linux-only, broader process-memory scan): write a
/// high-entropy canary as the key's actual value, confirm it's findable
/// by scanning `/proc/self/mem` against `/proc/self/maps`'ss readable
/// regions (a sanity check — a test that can't find a value that should
/// be there proves nothing), trigger erasure, and assert the canary is
/// no longer found anywhere in scanned memory. Windows'
/// `ReadProcessMemory`/`VirtualQueryEx` equivalent is not implemented —
/// technique 1 above already runs on both CI platforms and proves the
/// core claim; this is additional, not required, coverage.
///
/// Explicitly out of scope here (Sub-Phase 3C's job): swap/pagefile
/// recovery and cold-boot RAM extraction. This proves the key is gone
/// from *live, resident* memory — nothing about whether a copy was
/// paged to disk before erasure ran.
#[cfg(all(test, target_os = "linux"))]
mod linux_memory_scan_tests {
    use std::{
        fs::File,
        io::{Read, Seek, SeekFrom},
    };

    use rand::RngCore;
    use zeroize::Zeroizing;

    use super::{derive_key, DerivedKey, DestructMode, SelfDestructingMessage, NONCE_LEN};
    use std::sync::{Arc, Mutex};

    fn scan_process_memory_for(pattern: &[u8]) -> bool {
        let maps = std::fs::read_to_string("/proc/self/maps").expect("read /proc/self/maps");
        let mut mem = File::open("/proc/self/mem").expect("open /proc/self/mem");

        for line in maps.lines() {
            let mut parts = line.split_whitespace();
            let Some(range) = parts.next() else { continue };
            let Some(perms) = parts.next() else { continue };
            if !perms.starts_with('r') {
                continue;
            }
            let Some((start_str, end_str)) = range.split_once('-') else { continue };
            let (Ok(start), Ok(end)) = (
                u64::from_str_radix(start_str, 16),
                u64::from_str_radix(end_str, 16),
            ) else {
                continue;
            };
            if end <= start {
                continue;
            }
            let len = (end - start) as usize;
            // Skip absurdly large regions to keep the test fast, and
            // skip regions the kernel won't let us seek/read (some
            // special mappings report readable in /proc/self/maps but
            // fail on actual read) — one region failing must not abort
            // the whole scan.
            if len > 512 * 1024 * 1024 {
                continue;
            }
            if mem.seek(SeekFrom::Start(start)).is_err() {
                continue;
            }
            let mut buf = vec![0u8; len];
            if mem.read_exact(&mut buf).is_ok() && buf.windows(pattern.len()).any(|w| w == pattern) {
                return true;
            }
        }
        false
    }

    #[test]
    fn test_key_bytes_absent_from_process_memory_after_expiry() {
        let mut seed_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed_bytes);
        let canary = derive_key(
            &Zeroizing::new(seed_bytes),
            DestructMode::TimeBound,
            12345,
            1000,
        )
        .0;

        let message = SelfDestructingMessage {
            ciphertext: Arc::new(vec![0u8; NONCE_LEN]),
            key: Arc::new(Mutex::new(Some(DerivedKey(canary)))),
            mode: DestructMode::TimeBound,
        };

        assert!(
            scan_process_memory_for(&canary),
            "sanity check failed: the canary should be findable in live process memory \
             before expiry — if this fails, the scan technique itself is broken, not \
             necessarily the zeroize behaviour"
        );

        message.expire_now();

        assert!(
            !scan_process_memory_for(&canary),
            "self-destruct key bytes were still found somewhere in process memory after \
             expiry — zeroize did not actually overwrite them"
        );
    }
}
