//! Sub-Phase 3C's actual deliverable: the forensic-recovery adversarial
//! test. Per the brief, this is "more important than the feature code
//! itself" — it simulates a device seizure immediately after a
//! self-destructing message's expiry/read-trigger fires and asserts zero
//! recoverable plaintext.
//!
//! ## Scope, stated precisely
//!
//! This exercises `parda_protocol::self_destruct` only through its
//! public API — it cannot reach the module-private `DerivedKey` type at
//! all, so it proves plaintext (not raw key bytes) is unrecoverable from
//! scanned process memory. The key-bytes-specifically claim is proven
//! separately by the white-box tests inside
//! `protocol/src/self_destruct.rs` (which do have private-field access).
//! Together: the key is provably zeroized (inline tests) *and* the
//! plaintext it protected is provably gone from live process memory
//! after destruction fires (this file).
//!
//! **"Dump all accessible storage"**, the brief's other half of this
//! test: `SelfDestructingMessage` has no serialization implementation
//! and no code path that writes to disk at all (see
//! `protocol/src/self_destruct.rs` — there is no `Serialize` impl, no
//! file I/O). There is therefore nothing on storage to recover, by the
//! absence of any persistence capability rather than by a runtime check
//! — recorded here so that absence reads as a verified property of this
//! sub-phase's scope, not an oversight. A real persistent holding area
//! (Sub-Phase 3D) will need this same "never written" property enforced
//! at its write path, not assumed to carry over automatically.
//!
//! **What this does NOT prove** (same boundary as `secure_memory`'s own
//! tests): swap/pagefile contents specifically, or anything about a
//! memory dump taken *before* destruction fires — that always yields
//! the plaintext, for any self-destruct scheme, and isn't a PARDA-specific
//! gap. See `docs/phase3-3a-self-destruct-design.md` §8.

use std::time::Duration;

use parda_protocol::self_destruct::SelfDestructingMessage;

/// A canary distinctive enough that a false-positive match (finding
/// these exact bytes somewhere else in this process's memory by chance)
/// is not a realistic concern.
const SEIZED_DEVICE_PLAINTEXT: &[u8] =
    b"PARDA-FORENSIC-CANARY-9f3b2c7e-classified-field-report-follows";

#[tokio::test]
async fn test_time_bound_message_unrecoverable_via_public_api_after_seizure() {
    let message = SelfDestructingMessage::seal(
        SEIZED_DEVICE_PLAINTEXT,
        1_753_900_000_000,
        Duration::from_millis(50),
    )
    .unwrap();

    // Simulated seizure: wait past expiry (the timer fires with no
    // further action from this test), then behave exactly as a seizing
    // adversary's forensic tooling would — try every public entry point
    // that could conceivably yield the plaintext.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(message.is_expired());
    assert!(
        message.open().is_err(),
        "the only public API that could yield plaintext must refuse, post-seizure"
    );
}

#[tokio::test]
async fn test_read_triggered_message_unrecoverable_via_public_api_after_seizure() {
    let message = SelfDestructingMessage::seal_read_triggered(SEIZED_DEVICE_PLAINTEXT, 1_753_900_000_000).unwrap();

    // The read that triggers destruction — e.g. the last thing the user
    // did before the device was seized.
    let _ = message.open().unwrap();

    // Seizure happens immediately after.
    assert!(message.is_expired());
    assert!(message.open().is_err());
}

/// The literal "dump all accessible memory" version of this test —
/// Linux only, for the same reason `self_destruct.rs`'s own
/// `linux_memory_scan_tests` are Linux only: `/proc/self/mem` has no
/// portable equivalent used here. Runs in the `ubuntu-latest` CI leg.
#[cfg(target_os = "linux")]
mod linux_full_memory_dump {
    use super::*;
    use std::{
        fs::File,
        io::{Read, Seek, SeekFrom},
    };

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

    /// The capstone: seal a message, confirm the plaintext IS findable
    /// in this process's own memory (sanity check — a scan that can't
    /// find data known to be present proves nothing), trigger
    /// destruction via whichever mode, dump memory again, and assert
    /// the plaintext is gone.
    #[tokio::test]
    async fn test_seized_device_memory_dump_contains_no_recoverable_plaintext_time_bound() {
        let message = SelfDestructingMessage::seal(
            SEIZED_DEVICE_PLAINTEXT,
            1_753_900_000_000,
            Duration::from_millis(50),
        )
        .unwrap();

        // The plaintext only exists AEAD-encrypted at rest inside
        // `message` at this point (self_destruct re-encrypts immediately
        // on seal) — so before destruction, it should NOT be findable in
        // plaintext form either, which is itself worth confirming: the
        // "encrypted under a derived key" design isn't just decorative.
        assert!(
            !scan_process_memory_for(SEIZED_DEVICE_PLAINTEXT),
            "plaintext was found in process memory even before any read — sealing should have \
             left only AEAD ciphertext resident, not the plaintext itself"
        );

        // Confirm it becomes findable exactly when we deliberately read
        // it — this is the sanity check that the scan technique works
        // at all, timed to also prove the read genuinely materializes
        // plaintext in memory.
        let opened = message.open().unwrap();
        assert!(
            scan_process_memory_for(SEIZED_DEVICE_PLAINTEXT),
            "sanity check failed: plaintext should be findable in memory right after a \
             successful open() — if this fails, the scan technique itself is broken"
        );
        drop(opened); // the caller's own copy — self_destruct's internal
                      // Zeroizing<Vec<u8>> already covers this; dropping
                      // it here just stops it pinning a live reference
                      // for the rest of this test.

        // Simulated seizure, after expiry.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(message.is_expired());

        assert!(
            !scan_process_memory_for(SEIZED_DEVICE_PLAINTEXT),
            "plaintext was still recoverable from process memory after a simulated device \
             seizure post-expiry — this is the failure the entire sub-phase exists to catch"
        );
    }

    #[tokio::test]
    async fn test_seized_device_memory_dump_contains_no_recoverable_plaintext_read_triggered() {
        let message = SelfDestructingMessage::seal_read_triggered(SEIZED_DEVICE_PLAINTEXT, 1_753_900_000_000).unwrap();

        assert!(!scan_process_memory_for(SEIZED_DEVICE_PLAINTEXT));

        let opened = message.open().unwrap();
        assert!(
            scan_process_memory_for(SEIZED_DEVICE_PLAINTEXT),
            "sanity check failed: plaintext should be findable right after the triggering read"
        );
        drop(opened);

        // Seizure immediately after the triggering read — the scenario
        // the brief names explicitly.
        assert!(message.is_expired());
        assert!(
            !scan_process_memory_for(SEIZED_DEVICE_PLAINTEXT),
            "plaintext was still recoverable immediately after the triggering read — a device \
             seized the instant after the user read this message must not yield it"
        );
    }
}
