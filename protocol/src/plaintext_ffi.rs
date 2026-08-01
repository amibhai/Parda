//! Native-owned plaintext buffer + C-ABI FFI surface (Sub-Phase 4.5C) —
//! the fix for the Dart plaintext problem documented in
//! `docs/phase4.5c-dart-plaintext-design.md` (design note, read first).
//!
//! Reuses exactly the zeroize/lock discipline `self_destruct::DerivedKey`
//! already established (`Box<[u8]>`, its own dedicated allocation,
//! `secure_memory::lock`/`unlock`, explicit zeroize-while-still-`Some`
//! before drop) — applied here to a decrypted plaintext buffer instead
//! of a derived key. No new primitive, no new pattern.
//!
//! ## What this proves, and what it doesn't
//!
//! A [`PlaintextHandle`] is zeroized and its memory unlocked on
//! [`PlaintextHandle::release`] (or `Drop`, as a safety net — but
//! callers should call `release` explicitly; see module docs on why
//! relying on Dart's GC to trigger a Rust `Drop` at a predictable time
//! is not something this design leans on). **What this module cannot
//! prove, stated directly (see the design note §4):** the Dart-side
//! `Uint8List`/`String` a caller creates from [`PlaintextHandle::copy_into`]'s
//! output is a *separate* copy this module has no control over past the
//! moment it's written — Dart's own zeroize discipline for that copy is
//! the Dart-side half of this fix, not something Rust can enforce from
//! here.

use std::sync::Mutex;

use zeroize::Zeroize;

use crate::secure_memory;

/// A decrypted plaintext buffer, native-owned, zeroized and unlocked on
/// release. `Box<[u8]>` — its own dedicated heap allocation, same
/// reasoning as `self_destruct::DerivedKey`: locking must not also lock
/// unrelated bookkeeping sharing a page with it.
pub struct PlaintextHandle {
    bytes: Mutex<Option<Box<[u8]>>>,
}

impl PlaintextHandle {
    /// Take ownership of `bytes` (the caller's copy is *not* cleared by
    /// this call — clearing the caller's own buffer, if it has one
    /// separate from what's moved in here, is the caller's job, matching
    /// `SignalPlugin.kt`/`SignalPlugin.swift`'s existing `finally`/`defer`
    /// discipline for their own JVM/ObjC-side copies).
    pub fn new(bytes: Vec<u8>) -> Self {
        let boxed: Box<[u8]> = bytes.into_boxed_slice();
        secure_memory::lock(boxed.as_ptr(), boxed.len());
        Self {
            bytes: Mutex::new(Some(boxed)),
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.lock().unwrap().as_ref().map_or(0, |b| b.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copy into `out`. Returns `false` (copying nothing) if `out` is too
    /// small or the handle was already released — fail closed, never a
    /// partial/truncated copy a caller might mistake for the whole thing.
    pub fn copy_into(&self, out: &mut [u8]) -> bool {
        let guard = self.bytes.lock().unwrap();
        match guard.as_ref() {
            Some(bytes) if bytes.len() <= out.len() => {
                out[..bytes.len()].copy_from_slice(bytes);
                true
            }
            _ => false,
        }
    }

    /// Explicit release: zeroize while still `Some` (see
    /// `self_destruct::erase`'s doc comment for exactly why this two-step
    /// shape matters and a bare `*guard = None` would not prove the same
    /// thing), unlock, then clear the slot. Idempotent — releasing an
    /// already-released handle is a no-op, not an error.
    pub fn release(&self) {
        let mut guard = self.bytes.lock().unwrap();
        if let Some(bytes) = guard.as_mut() {
            let ptr = bytes.as_ptr();
            let len = bytes.len();
            bytes.zeroize();
            secure_memory::unlock(ptr, len);
        }
        *guard = None;
    }
}

impl Drop for PlaintextHandle {
    fn drop(&mut self) {
        // Safety net, not the primary path — see module docs.
        self.release();
    }
}

// ─── C ABI (called from Kotlin/Swift via JNI / a C-ABI bridge) ────────────

/// # Safety
/// `bytes` must point to `len` valid, readable bytes for the duration of
/// this call (the standard JNI byte-array-argument contract). Returns an
/// owning pointer the caller must eventually pass to
/// [`parda_plaintext_release`] exactly once.
#[no_mangle]
pub unsafe extern "C" fn parda_plaintext_new(bytes: *const u8, len: usize) -> *mut PlaintextHandle {
    let slice = std::slice::from_raw_parts(bytes, len);
    let handle = PlaintextHandle::new(slice.to_vec());
    Box::into_raw(Box::new(handle))
}

/// # Safety
/// `handle` must be a live pointer previously returned by
/// [`parda_plaintext_new`], not yet released.
#[no_mangle]
pub unsafe extern "C" fn parda_plaintext_len(handle: *const PlaintextHandle) -> usize {
    if handle.is_null() {
        return 0;
    }
    (*handle).len()
}

/// # Safety
/// `handle` as above; `out` must point to `out_len` valid, writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn parda_plaintext_copy_into(
    handle: *const PlaintextHandle,
    out: *mut u8,
    out_len: usize,
) -> bool {
    if handle.is_null() {
        return false;
    }
    let out_slice = std::slice::from_raw_parts_mut(out, out_len);
    (*handle).copy_into(out_slice)
}

/// # Safety
/// `handle` must be a live pointer previously returned by
/// [`parda_plaintext_new`], not already released. After this call the
/// pointer is invalid and must not be used again.
#[no_mangle]
pub unsafe extern "C" fn parda_plaintext_release(handle: *mut PlaintextHandle) {
    if handle.is_null() {
        return;
    }
    let boxed = Box::from_raw(handle);
    boxed.release();
    // `boxed` drops here — release() already zeroized/unlocked, so this
    // is just freeing the now-empty `Mutex<Option<..>>` wrapper.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_into_round_trips_and_release_zeroizes() {
        let handle = PlaintextHandle::new(b"distinctive-canary-plaintext".to_vec());
        let mut out = [0u8; 28];
        assert!(handle.copy_into(&mut out));
        assert_eq!(&out, b"distinctive-canary-plaintext");

        handle.release();
        assert_eq!(handle.len(), 0);
        let mut out2 = [0u8; 28];
        assert!(!handle.copy_into(&mut out2), "a released handle must refuse to copy, not return stale bytes");
    }

    #[test]
    fn release_is_idempotent() {
        let handle = PlaintextHandle::new(b"x".to_vec());
        handle.release();
        handle.release(); // must not panic
        assert_eq!(handle.len(), 0);
    }

    #[test]
    fn copy_into_refuses_a_too_small_destination() {
        let handle = PlaintextHandle::new(b"twelve-bytes".to_vec());
        let mut out = [0u8; 4];
        assert!(!handle.copy_into(&mut out));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canary_bytes_absent_from_process_memory_after_release() {
        // Same technique `self_destruct.rs`'s Linux-only tests already
        // use — see that file for the full method. Applied here to a
        // plaintext buffer instead of a derived key.
        use std::io::Read;

        fn scan_for(needle: &[u8]) -> bool {
            let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
            let mut mem = std::fs::File::open("/proc/self/mem").unwrap();
            for line in maps.lines() {
                let Some((range, perms_rest)) = line.split_once(' ') else { continue };
                if !perms_rest.starts_with('r') {
                    continue;
                }
                let Some((start_hex, end_hex)) = range.split_once('-') else { continue };
                let (Ok(start), Ok(end)) = (
                    u64::from_str_radix(start_hex, 16),
                    u64::from_str_radix(end_hex, 16),
                ) else {
                    continue;
                };
                use std::io::Seek;
                if mem.seek(std::io::SeekFrom::Start(start)).is_err() {
                    continue;
                }
                let mut buf = vec![0u8; (end - start) as usize];
                if mem.read_exact(&mut buf).is_err() {
                    continue;
                }
                if buf.windows(needle.len()).any(|w| w == needle) {
                    return true;
                }
            }
            false
        }

        let canary = b"PARDA-4-5-C-PLAINTEXT-FFI-CANARY-7f3a9c";
        let handle = PlaintextHandle::new(canary.to_vec());
        assert!(scan_for(canary), "sanity check: canary must be findable before release");
        handle.release();
        assert!(!scan_for(canary), "canary must be absent from process memory after release");
    }
}
