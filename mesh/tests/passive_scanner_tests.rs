//! Sub-Phase 4A adversarial gate: a passive-scanner harness with full
//! visibility into every advertisement token emitted across many
//! devices and many rotation windows, checking that no cross-window
//! linkage signal survives — not just asserting "looks random," but
//! measuring a couple of concrete linkage adversaries against a random-
//! guess baseline, per the brief's explicit "measured, not just claimed"
//! standard (mirroring `mixnode/tests/timing_correlation_tests.rs`'s own
//! permutation-test rigor for the analogous mix-network claim).
//!
//! What this test does **not** claim: nothing here says anything about
//! RF-layer presence detection, signal strength profiling, or timing
//! side channels a real radio might expose — see
//! `docs/THREAT_MODEL.md` §3.7. It claims exactly one thing, precisely:
//! the *advertised payload* this crate controls carries no linkage
//! signal across rotation windows, at the tested scale.

use std::collections::HashMap;

use parda_mesh::radio::{AdvertToken, RotatingIdentity, ADVERT_TOKEN_LEN};

const DEVICES: usize = 30;
const WINDOWS_PER_DEVICE: usize = 40;

#[derive(Clone, Copy)]
struct Sighting {
    device: usize,
    #[allow(dead_code)] // kept for readability of what a sighting represents
    window: usize,
    token: AdvertToken,
}

fn build_corpus() -> Vec<Sighting> {
    let mut corpus = Vec::with_capacity(DEVICES * WINDOWS_PER_DEVICE);
    for device in 0..DEVICES {
        let identity = RotatingIdentity::with_default_interval();
        for window in 0..WINDOWS_PER_DEVICE {
            // Drive rotation directly (deterministic, no wall-clock
            // sleeps) — see `RotatingIdentity::rotate` docs.
            let token = identity.rotate();
            corpus.push(Sighting {
                device,
                window,
                token,
            });
        }
    }
    corpus
}

#[test]
fn same_device_never_repeats_a_token_across_windows() {
    let corpus = build_corpus();
    let mut seen_per_device: HashMap<usize, Vec<AdvertToken>> = HashMap::new();
    for s in &corpus {
        let tokens = seen_per_device.entry(s.device).or_default();
        assert!(
            !tokens.contains(&s.token),
            "device {} emitted the same token twice across rotation windows",
            s.device
        );
        tokens.push(s.token);
    }
}

/// The most naive possible linkage adversary: "if I see the exact same
/// token twice, it's the same device." At [`ADVERT_TOKEN_LEN`] = 16
/// bytes (128 bits) of fresh randomness per rotation, this adversary
/// should never fire at all in a corpus this size — its expected false
/// (or true) link count is astronomically below one, so this test
/// asserts the observed count is exactly zero, not merely "low."
#[test]
fn full_token_adversary_finds_zero_cross_window_links_at_128_bits() {
    let corpus = build_corpus();
    let mut by_token: HashMap<AdvertToken, Vec<usize>> = HashMap::new();
    for s in &corpus {
        by_token.entry(s.token).or_default().push(s.device);
    }

    let total_pairs = corpus.len() * (corpus.len() - 1) / 2;
    let colliding_groups: usize = by_token.values().filter(|v| v.len() > 1).count();

    assert_eq!(
        colliding_groups, 0,
        "found a full-token collision across {} devices x {} windows ({} total pairwise comparisons) — \
         at {}-byte tokens this should never happen and would indicate a broken RNG, not bad luck",
        DEVICES, WINDOWS_PER_DEVICE, total_pairs, ADVERT_TOKEN_LEN
    );
}

/// A meaningfully weaker adversary than the previous test — one that
/// only gets to see the token's first byte (as if 15 of the 16 bytes
/// were somehow unusable to it) and clusters sightings that share that
/// one byte. This is deliberately a much easier task for an adversary
/// than anything this design actually exposes; the point is to show
/// that *even* a drastically weakened linkage signal does not beat the
/// random-guess baseline of correctly pairing two sightings from the
/// same device (1 / DEVICES) by more than a small, explicitly-bounded
/// margin — a stronger and more informative claim than "16 bytes never
/// collides," which is close to tautological on its own.
#[test]
fn one_byte_prefix_adversary_does_not_beat_random_guess_baseline_by_more_than_margin() {
    let corpus = build_corpus();
    let mut by_prefix: HashMap<u8, Vec<usize>> = HashMap::new(); // prefix -> device ids
    for s in &corpus {
        by_prefix.entry(s.token.0[0]).or_default().push(s.device);
    }

    // Pairwise precision: among all pairs of sightings sharing a
    // 1-byte prefix, what fraction are actually the same device?
    let mut same_device_pairs = 0u64;
    let mut total_pairs = 0u64;
    for devices_in_bucket in by_prefix.values() {
        let n = devices_in_bucket.len();
        if n < 2 {
            continue;
        }
        for i in 0..n {
            for j in (i + 1)..n {
                total_pairs += 1;
                if devices_in_bucket[i] == devices_in_bucket[j] {
                    same_device_pairs += 1;
                }
            }
        }
    }

    assert!(
        total_pairs > 200,
        "test parameters too small to draw a stable conclusion ({total_pairs} pairs observed)"
    );

    let observed_precision = same_device_pairs as f64 / total_pairs as f64;
    let baseline = 1.0 / DEVICES as f64;
    // Generous margin (2x baseline, plus a small absolute slack) to
    // keep this non-flaky while still catching a real leak, which would
    // show up as precision far above baseline, not a marginal wobble.
    let margin = baseline * 2.0 + 0.02;

    assert!(
        observed_precision <= baseline + margin,
        "one-byte-prefix adversary's pairwise same-device precision was {observed_precision:.4}, \
         random-guess baseline is {baseline:.4} (margin {margin:.4}) — a weakened signal is \
         correlating with device identity above chance, which would indicate a real leak"
    );
}
