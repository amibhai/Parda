//! Clock-rollback detection for time-bound self-destruct (Sub-Phase 3A).
//!
//! Phase 3's threat model assumes the adversary has the device — which
//! includes the ability to change its wall clock. A time-bound expiry
//! check based solely on `SystemTime::now() >= expiry_at` is trivially
//! defeated by setting the clock backward before that comparison runs.
//!
//! [`crate::self_destruct`] enforces expiry primarily via a monotonic
//! `Instant`-anchored timer, which is immune to wall-clock changes for
//! as long as the process keeps running. This module covers the gap
//! `Instant` can't: recovering elapsed time correctly across a process
//! restart, without blindly trusting whatever wall clock the restarted
//! process observes.
//!
//! ## Mechanism
//!
//! A watermark — the last wall-clock time this device was known to have
//! observed — is persisted (via [`ClockWatermarkStore`]) and checked on
//! every [`check_clock_integrity`] call. If the current wall clock is
//! *earlier* than the persisted watermark, that's direct evidence the
//! clock moved backward: [`ClockCheck::RollbackDetected`] is returned and
//! callers must fail closed (treat pending self-destructing messages as
//! already expired) rather than trust the rolled-back clock. If the
//! current wall clock is at or after the watermark, it's accepted and the
//! watermark is advanced.
//!
//! ## What this does NOT defend against (documented, not solved)
//!
//! - **A rooted/jailbroken device can rewrite the persisted watermark
//!   itself, not just the OS clock.** This mechanism defeats an adversary
//!   who changes the system date through ordinary means but cannot also
//!   modify arbitrary app storage. A fully-privileged local attacker can
//!   advance the watermark to match a rolled-back clock, defeating
//!   detection entirely. This is the specific, known, documented
//!   limitation the README's Status & Limitations table names explicitly
//!   — not a solved problem.
//! - **A device that never runs the app again after seizure** is
//!   unaffected by any user-space mechanism, this one included — nothing
//!   here executes if the process doesn't run.
//! - No network time cross-check is performed. See
//!   `docs/phase3-3a-self-destruct-design.md` §3 for why this is
//!   deliberately deferred rather than made a load-bearing online
//!   dependency for an offline-capable project.

use std::sync::Mutex;

/// Where the clock-integrity watermark is persisted. Production callers
/// (CLI, mobile bridge) implement this against real durable storage;
/// [`InMemoryClockWatermarkStore`] is for tests and short-lived
/// in-process use only — it provides no rollback protection across a
/// real process restart, since nothing persists past process exit.
pub trait ClockWatermarkStore: Send + Sync {
    /// Last known-good wall-clock time in milliseconds since the Unix
    /// epoch, if one has ever been recorded.
    fn load_watermark_ms(&self) -> Option<u64>;

    /// Record `wall_clock_ms` as the new watermark.
    fn store_watermark_ms(&self, wall_clock_ms: u64);
}

/// In-memory watermark store. Only useful within a single process
/// lifetime — see trait docs.
#[derive(Default)]
pub struct InMemoryClockWatermarkStore(Mutex<Option<u64>>);

impl InMemoryClockWatermarkStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ClockWatermarkStore for InMemoryClockWatermarkStore {
    fn load_watermark_ms(&self) -> Option<u64> {
        *self.0.lock().unwrap()
    }

    fn store_watermark_ms(&self, wall_clock_ms: u64) {
        *self.0.lock().unwrap() = Some(wall_clock_ms);
    }
}

/// Result of a clock-integrity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockCheck {
    /// Wall clock is at or after the last watermark — accepted, and the
    /// watermark has been advanced to `now_ms`.
    Ok,
    /// Wall clock moved backward relative to the last watermark. The
    /// watermark is deliberately **not** advanced in this case — a
    /// rolled-back clock must not become the new trusted baseline.
    RollbackDetected { watermark_ms: u64, observed_ms: u64 },
}

/// Check `now_ms` against the persisted watermark in `store`, updating it
/// if the check passes. Callers that get [`ClockCheck::RollbackDetected`]
/// back must fail closed — see module docs and
/// `crate::self_destruct::SelfDestructingMessage::open_with_clock_guard`.
pub fn check_clock_integrity(store: &dyn ClockWatermarkStore, now_ms: u64) -> ClockCheck {
    match store.load_watermark_ms() {
        Some(watermark_ms) if now_ms < watermark_ms => ClockCheck::RollbackDetected {
            watermark_ms,
            observed_ms: now_ms,
        },
        _ => {
            store.store_watermark_ms(now_ms);
            ClockCheck::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_check_always_succeeds_and_sets_watermark() {
        let store = InMemoryClockWatermarkStore::new();
        assert_eq!(check_clock_integrity(&store, 1000), ClockCheck::Ok);
        assert_eq!(store.load_watermark_ms(), Some(1000));
    }

    #[test]
    fn test_advancing_clock_is_always_accepted() {
        let store = InMemoryClockWatermarkStore::new();
        assert_eq!(check_clock_integrity(&store, 1000), ClockCheck::Ok);
        assert_eq!(check_clock_integrity(&store, 2000), ClockCheck::Ok);
        assert_eq!(check_clock_integrity(&store, 2000), ClockCheck::Ok); // equal is fine
        assert_eq!(store.load_watermark_ms(), Some(2000));
    }

    #[test]
    fn test_rollback_is_detected_and_watermark_not_advanced() {
        let store = InMemoryClockWatermarkStore::new();
        assert_eq!(check_clock_integrity(&store, 5000), ClockCheck::Ok);

        let result = check_clock_integrity(&store, 3000);
        assert_eq!(
            result,
            ClockCheck::RollbackDetected {
                watermark_ms: 5000,
                observed_ms: 3000
            }
        );
        // The rolled-back time must NOT become the new trusted baseline.
        assert_eq!(store.load_watermark_ms(), Some(5000));
    }

    #[test]
    fn test_recovery_after_rollback_requires_reaching_the_old_watermark() {
        let store = InMemoryClockWatermarkStore::new();
        check_clock_integrity(&store, 5000);
        check_clock_integrity(&store, 3000); // rollback, ignored

        // A slightly-later-than-rollback time is STILL behind the real
        // watermark and must still be rejected — the attacker doesn't
        // get partial credit for rolling back "less far".
        assert_eq!(
            check_clock_integrity(&store, 4999),
            ClockCheck::RollbackDetected {
                watermark_ms: 5000,
                observed_ms: 4999
            }
        );
        // Only reaching or passing the original watermark is accepted again.
        assert_eq!(check_clock_integrity(&store, 5000), ClockCheck::Ok);
    }
}
