//! Cross-platform memory locking — `mlock`/`VirtualLock` — to keep key
//! material out of swap/pagefile (Sub-Phase 3C).
//!
//! `zeroize` (used throughout [`crate::self_destruct`]) guarantees a key's
//! bytes are overwritten when erased. It says nothing about whether the
//! OS paged a *copy* of those bytes to disk while the key was live — a
//! cold-boot or forensic-imaging adversary who can read swap/pagefile
//! could recover a paged-out copy even after the in-memory original has
//! been correctly zeroized. Locking the pages a key lives on prevents
//! the OS from ever writing them to backing storage in the first place.
//!
//! ## What this proves, and what it doesn't
//!
//! [`lock`] and [`unlock`] wrap the platform syscall and — this is the
//! point, not an afterthought — [`locked_byte_count`] reads back the
//! OS's *own accounting* of how much memory this process currently has
//! locked, so callers (and tests) can verify the lock actually took
//! effect rather than trusting a return code alone. See
//! `tests::test_lock_increases_os_reported_locked_byte_count` and, more
//! deeply on Linux, `protocol/tests/forensic_recovery_tests.rs`.
//!
//! **What this does NOT prove:** that the specific bytes were never
//! swapped *before* `lock()` was called (there's an unavoidable window
//! between allocation and the lock call — kept as small as possible by
//! calling `lock()` immediately after allocating, before writing key
//! material into the buffer where practical), or that hibernation
//! (which can write locked pages to disk as part of a full memory
//! snapshot, by design — `mlock` does not defend against hibernation)
//! is defended against. Both are documented limitations, not silent
//! gaps — see `docs/phase3-3a-self-destruct-design.md` §8.
//!
//! ## Failure is not fatal, but is never silent
//!
//! `mlock`/`VirtualLock` can fail — most commonly `RLIMIT_MEMLOCK` on
//! Linux being lower than what's requested (common in constrained
//! containers) or the Windows process's minimum working set quota being
//! exhausted. A failure here must not stop the key from being generated,
//! used, or zeroized correctly — the swap-avoidance property degrades,
//! it doesn't cascade into breaking correctness. Every failure is logged
//! at `warn` level so the degradation is observable, not swallowed.

/// Lock the `len` bytes at `ptr` into physical memory. Returns `true` if
/// the OS confirms the lock (see module docs on why a plain "no error"
/// return isn't treated as sufficient on its own by callers that care —
/// use [`locked_byte_count`] to verify). Logs and returns `false` on
/// failure rather than panicking — see module docs "Failure is not
/// fatal."
pub fn lock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    imp::lock(ptr, len)
}

/// Unlock previously-locked memory. Safe to call even if [`lock`]
/// failed or was never called (best-effort).
pub fn unlock(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    imp::unlock(ptr, len);
}

/// Bytes this process currently has locked into physical memory, per the
/// OS's own accounting — not PARDA's internal bookkeeping. `None` if
/// this platform doesn't expose a way to ask. Used to verify `lock()`
/// actually took effect, not just that the syscall didn't return an
/// error code.
pub fn locked_byte_count() -> Option<u64> {
    imp::locked_byte_count()
}

#[cfg(unix)]
mod imp {
    pub fn lock(ptr: *const u8, len: usize) -> bool {
        let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
        if ret != 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                len,
                "mlock failed — key material may be swappable on this system \
                 (commonly RLIMIT_MEMLOCK too low; see module docs)"
            );
            false
        } else {
            true
        }
    }

    pub fn unlock(ptr: *const u8, len: usize) {
        unsafe {
            let _ = libc::munlock(ptr as *const libc::c_void, len);
        }
    }

    #[cfg(target_os = "linux")]
    pub fn locked_byte_count() -> Option<u64> {
        // /proc/self/status's VmLck line, e.g. "VmLck:      64 kB".
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmLck:") {
                let kb: u64 = rest.trim().split_whitespace().next()?.parse().ok()?;
                return Some(kb * 1024);
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    pub fn locked_byte_count() -> Option<u64> {
        // No portable, permission-free equivalent of /proc/self/status on
        // other Unixes wired up here — mlock() itself still runs and
        // still defends against swap; only the "verify via OS accounting"
        // layer is Linux-specific. See module docs.
        None
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

    pub fn lock(ptr: *const u8, len: usize) -> bool {
        let ret = unsafe { VirtualLock(ptr as *mut core::ffi::c_void, len) };
        if ret == 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                len,
                "VirtualLock failed — key material may be swappable on this system \
                 (commonly the process's minimum working set quota; see module docs)"
            );
            false
        } else {
            true
        }
    }

    pub fn unlock(ptr: *const u8, len: usize) {
        unsafe {
            let _ = VirtualUnlock(ptr as *mut core::ffi::c_void, len);
        }
    }

    pub fn locked_byte_count() -> Option<u64> {
        // Windows has no simple, permission-free per-process "bytes
        // currently VirtualLock'd" counter analogous to Linux's VmLck —
        // VirtualLock's own return code plus the working-set-quota
        // failure mode it documents is the verification surface
        // available here. See module docs.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_unlock_round_trip_on_a_real_buffer() {
        let buf = vec![0xABu8; 4096]; // page-sized, so the lock covers exactly this allocation's page(s)
        let locked = lock(buf.as_ptr(), buf.len());
        // Not asserting `locked` is unconditionally `true`: a sandboxed
        // CI environment may have RLIMIT_MEMLOCK set to 0, in which case
        // failure is expected and already logged — see module docs. What
        // must hold regardless is that the call doesn't panic or corrupt
        // the buffer.
        assert_eq!(buf[0], 0xAB, "lock() must not disturb the buffer's contents");
        unlock(buf.as_ptr(), buf.len());
        assert_eq!(buf[0], 0xAB, "unlock() must not disturb the buffer's contents either");
        let _ = locked;
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_lock_increases_os_reported_locked_byte_count() {
        let before = locked_byte_count().expect("Linux must expose /proc/self/status");

        let buf = vec![0u8; 64 * 1024]; // 64 KiB, comfortably within typical default RLIMIT_MEMLOCK
        let ok = lock(buf.as_ptr(), buf.len());
        if !ok {
            eprintln!(
                "mlock failed in this environment (likely RLIMIT_MEMLOCK) — skipping the \
                 OS-accounting assertion; failure itself was already logged at warn level"
            );
            return;
        }

        let after_lock = locked_byte_count().unwrap();
        assert!(
            after_lock >= before + buf.len() as u64,
            "VmLck did not increase by at least the locked region's size: before={before}, \
             after={after_lock}, requested={}",
            buf.len()
        );

        unlock(buf.as_ptr(), buf.len());
        let after_unlock = locked_byte_count().unwrap();
        assert!(
            after_unlock <= after_lock,
            "VmLck did not decrease after unlock(): after_lock={after_lock}, after_unlock={after_unlock}"
        );
    }

    /// Fulfils the brief's explicit requirement to "test that
    /// swap-resident memory doesn't contain the key under memory
    /// pressure" — as far as that's honestly testable in a portable,
    /// non-destructive CI job (see the narrower claim below).
    ///
    /// **What this proves:** the OS's own locked-byte accounting for an
    /// already-locked region is unaffected by a large volume of
    /// unrelated allocation/write activity happening around it — i.e.
    /// the lock isn't silently dropped or "spent" under pressure.
    ///
    /// **What this does NOT prove:** that any of the 256 MiB of pressure
    /// allocated below actually got swapped out. Whether that happens
    /// depends on the runner's total RAM, other concurrent load, and
    /// swap configuration — none of which this test controls or can
    /// assert about portably. Directly inspecting swap contents for the
    /// literal absence of the key bytes would need root and a
    /// specifically swap-starved environment; that's a deliberately
    /// narrower, achievable stand-in, not the full claim.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_locked_region_accounting_survives_memory_pressure() {
        let buf = vec![0xEFu8; 64 * 1024];
        let ok = lock(buf.as_ptr(), buf.len());
        if !ok {
            eprintln!("mlock failed in this environment — skipping the memory-pressure check");
            return;
        }
        let locked_before = locked_byte_count().unwrap();

        // Real, substantial allocation-and-touch pressure — `vec![v; n]`
        // both allocates and initialises every byte, so every page is
        // genuinely touched, not just reserved.
        let pressure: Vec<u8> = vec![0xCDu8; 256 * 1024 * 1024];
        std::hint::black_box(&pressure);

        let locked_after = locked_byte_count().unwrap();
        assert_eq!(
            locked_after, locked_before,
            "locked byte count changed after unrelated memory pressure — the lock may have \
             been silently dropped"
        );
        assert!(
            buf.iter().all(|&b| b == 0xEF),
            "locked buffer's content changed under memory pressure — it should have been \
             immune to being paged out and back in with different content"
        );

        unlock(buf.as_ptr(), buf.len());
        drop(pressure);
    }
}
