//! Sub-Phase 4D: multi-node simulation harness, driven at real scale —
//! every adversarial claim in Sub-Phases 4A-4C was already proven
//! against `parda_mesh::sim::SimHarness` at small (2-5 node) scale; this
//! file's job is running the *same* harness at N~30 with a genuine
//! multi-hop topology and a churn schedule, per the brief's explicit
//! "drive every adversarial test above at scale rather than as isolated
//! two-node tests."
//!
//! Deliberately deterministic, not randomized: a **ring** topology
//! (node `i` reachable only via `i-1` and `i+1`, wrapping around) forces
//! genuine multi-hop epidemic propagation across the whole network for
//! a message to cross it, and a **fixed** (not RNG-seeded) churn
//! schedule takes specific nodes briefly offline on a repeatable
//! pattern. This keeps the test's pass/fail non-flaky while still
//! genuinely exercising multi-hop routing and node churn together, which
//! the small-scale tests in `partition_rejoin_tests.rs` don't — those
//! prove correctness of the *mechanism*; this proves it still holds
//! when the mechanism has to do real work across a real topology.

use parda_mesh::{bundle, radio::simulated::SimProfile, relay::RelayConfig, sim::SimHarness};
use parda_protocol::envelope::{EnvelopeType, MessageEnvelope};

const N: usize = 30;
const RELAY_CONFIG: RelayConfig = RelayConfig {
    max_total_bundles: 200,
    max_total_bytes: 8 * 1024 * 1024,
    max_bundles_per_session: 200,
};

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

fn envelope(payload: &[u8]) -> MessageEnvelope {
    MessageEnvelope {
        sender_id: String::new(),
        recipient_id: String::new(),
        ciphertext: payload.to_vec(),
        envelope_type: EnvelopeType::SealedSender,
        timestamp_ms: now_ms(),
        version: parda_protocol::envelope::ENVELOPE_VERSION_V2,
        sealed_sender: true,
        routing_hint: None,
        self_destruct_at: None,
        read_triggered_destruct: false,
        dead_drop_address: None,
    }
}

fn ring_sever_all_but_neighbors(harness: &SimHarness) {
    for i in 0..N {
        for j in (i + 1)..N {
            let is_ring_edge = j == i + 1 || (i == 0 && j == N - 1);
            if !is_ring_edge {
                harness.sever(i, j);
            }
        }
    }
}

/// A fixed, repeatable churn pattern: at round `r`, node
/// `(r * 7) % N` goes offline for exactly that round, then returns.
/// Deterministic — no RNG, so no seed to record and no flakiness.
fn apply_churn_for_round(harness: &SimHarness, round: usize, previously_offline: &mut Option<usize>) {
    if let Some(node) = previously_offline.take() {
        harness.set_online(node, true);
    }
    let node = (round * 7) % N;
    harness.set_online(node, false);
    *previously_offline = Some(node);
}

#[tokio::test]
async fn messages_cross_a_30_node_ring_under_churn_without_loss_or_duplication() {
    let harness = SimHarness::new(N, SimProfile::Ble, RELAY_CONFIG);
    ring_sever_all_but_neighbors(&harness);

    // Several conversations spanning very different ring distances,
    // including the farthest-apart pair (half the ring away).
    let scenarios: [(usize, usize, [u8; 32], &[u8]); 4] = [
        (0, 15, [1u8; 32], b"opposite side of the ring"),
        (3, 8, [2u8; 32], b"medium distance"),
        (20, 22, [3u8; 32], b"adjacent-ish"),
        (5, 29, [4u8; 32], b"wraps around the seam"),
    ];

    for (origin, _, address, payload) in &scenarios {
        let bytes = bundle::wrap(&envelope(payload), *address).unwrap();
        harness.node(*origin).relay.admit(bytes).unwrap();
    }

    let mut offline_node: Option<usize> = None;
    // Enough rounds for a signal to cross ~half the ring (15 hops) even
    // with one node intermittently down per round; generous margin.
    for round in 0..60 {
        apply_churn_for_round(&harness, round, &mut offline_node);
        harness.run_sync_round().await;
    }
    if let Some(node) = offline_node {
        harness.set_online(node, true);
    }
    // A few clean rounds with everyone online to mop up anything still
    // in flight right at the churn schedule's tail end.
    harness.run_sync_rounds(5).await;

    for (_, dest, address, payload) in &scenarios {
        let matches = harness.node(*dest).relay.bundles_for_addresses(&[*address]);
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one copy of {payload:?} at node {dest}, found {}",
            matches.len()
        );
        let (_, decoded) = bundle::unwrap(&matches[0]).unwrap();
        assert_eq!(&decoded.ciphertext, payload);
    }

    // No-duplication check: every node in the whole ring holds at most
    // one copy of each address, not just the destinations — epidemic
    // flooding legitimately leaves copies at intermediate hops (that's
    // how store-and-forward works), but dedup must still hold at each
    // individual node.
    for i in 0..N {
        for (_, _, address, _) in &scenarios {
            let matches = harness.node(i).relay.bundles_for_addresses(&[*address]);
            assert!(matches.len() <= 1, "node {i} holds {} copies of one address", matches.len());
        }
    }
}
