//! Sub-Phase 4D: battery/resource cost, measured and documented rather
//! than left as an unquantified caveat. Mesh mode requires active
//! scanning/advertising — a mode that silently drains a field device's
//! battery is an operational failure this project should not hide, per
//! the brief's explicit instruction.
//!
//! **What this file measures:** operation counts and wire-byte sizes at
//! this crate's actual default parameters — concrete numbers a reviewer
//! can recompute. **What this file cannot measure, stated plainly, same
//! as the Windows `VirtualLock`-verification asymmetry precedent
//! (`docs/phase3-3a-self-destruct-design.md` §8):** actual on-device
//! power draw in milliwatts, radio-chipset-specific advertise/scan
//! energy cost, or anything requiring real BLE hardware — none of which
//! exists in this execution environment (see the plan/limitations doc).
//! Operation-count characterization is a legitimate, if partial, stand-in
//! — it's the input every real power model multiplies by a
//! hardware-specific constant this project has no way to measure here.

use parda_mesh::radio::{AdvertToken, DEFAULT_ROTATION_INTERVAL, PROTOCOL_TAG};

/// Advertising duty cycle: one rotation (and, on a real backend, one
/// re-advertisement call) per [`DEFAULT_ROTATION_INTERVAL`].
#[test]
fn advertisement_operation_rate_at_default_rotation_interval() {
    let rotations_per_hour = 3600.0 / DEFAULT_ROTATION_INTERVAL.as_secs_f64();
    let bytes_per_advertisement = PROTOCOL_TAG.len() + std::mem::size_of::<AdvertToken>();
    let bytes_per_hour = rotations_per_hour * bytes_per_advertisement as f64;

    let interval_secs = DEFAULT_ROTATION_INTERVAL.as_secs();
    println!(
        "[battery-cost] rotation interval = {interval_secs}s -> {rotations_per_hour:.1} advertise \
         operations/hour, {bytes_per_advertisement} bytes/advertisement -> {bytes_per_hour:.0} \
         advertisement bytes/hour (payload size only — does not include real BLE link-layer/PHY \
         overhead, which is chipset- and PHY-mode-dependent and not modeled here)"
    );

    // Sanity bounds, not brittle exact-value pins: catches a gross
    // accidental change to the default (e.g. rotating every second)
    // without pinning the specific chosen interval as immutable.
    assert!(
        (1.0..=120.0).contains(&rotations_per_hour),
        "default rotation rate moved outside a sane range for a battery-conscious default: {rotations_per_hour}/hour"
    );
}

/// Sync-session wire cost: the `Have`/`Want`/`Done` epidemic-routing
/// handshake overhead (`relay.rs::sync_with_peer`), measured at a few
/// representative storage sizes — this is the cost paid *per
/// connection*, independent of how many bundles actually change hands
/// (see `relay.rs` module docs on the sync protocol).
#[test]
fn sync_handshake_overhead_bytes_at_representative_storage_sizes() {
    // Mirrors the private `SyncMessage` wire shape
    // (`relay.rs::SyncMessage`) closely enough for a size estimate
    // without needing that type to be `pub` just for this benchmark —
    // a 32-byte hash per held bundle, JSON-encoded (matching what
    // `sync_with_peer` actually serializes via `serde_json`).
    #[derive(serde::Serialize)]
    enum SyncMessageShape {
        Have(Vec<[u8; 32]>),
    }

    for held_bundles in [0usize, 10, 100, 500] {
        let hashes: Vec<[u8; 32]> = (0..held_bundles).map(|i| [i as u8; 32]).collect();
        let msg = SyncMessageShape::Have(hashes);
        let bytes = serde_json::to_vec(&msg).unwrap();
        println!(
            "[battery-cost] Have-message size with {held_bundles} bundles held: {} bytes \
             (one such message sent per sync session, one received back from the peer)",
            bytes.len()
        );
    }
}

/// Radio-on time proxy: at a chosen sync duty cycle (how often
/// `MeshNode::spawn_sync_loop` is configured to fire — caller-supplied,
/// not hardcoded by this crate; 30s is used here as a representative
/// "check for peers roughly every half minute" choice), how many
/// scan+connect attempts happen per hour. This is the number a real
/// power model would multiply by a chipset's per-scan energy cost — a
/// number this environment cannot supply (no real radio here; see
/// module docs).
#[test]
fn sync_attempt_rate_at_a_representative_duty_cycle() {
    let duty_cycle = std::time::Duration::from_secs(30);
    let attempts_per_hour = 3600.0 / duty_cycle.as_secs_f64();
    println!(
        "[battery-cost] at a {}s sync duty cycle: {attempts_per_hour:.0} scan+connect attempts/hour \
         (each attempt is one MeshRadio::scan call plus zero or more MeshRadio::connect calls, \
         one per currently-visible peer)",
        duty_cycle.as_secs()
    );
    assert!(attempts_per_hour > 0.0);
}
