//! Multi-node offline simulation harness (Sub-Phase 4D, built here so
//! Sub-Phases 4A-4C's own adversarial tests — which already need
//! multi-device scenarios with partition and rejoin — exercise the real
//! thing at small scale rather than a throwaway duplicate. Sub-Phase 4D
//! is what runs it at real N with full churn/partition schedules; the
//! harness itself is not something to build twice.
//!
//! Wraps N [`crate::transport::MeshNode`]s over one shared
//! [`crate::radio::simulated::SimNetwork`], with helpers for
//! deterministic, round-based propagation (no background tasks/timing
//! races — a test calls [`SimHarness::run_sync_round`] explicitly and
//! knows exactly what happened) plus the same partition
//! (`sever`/`heal`) and churn (`set_online`) controls the underlying
//! network already provides.

use std::sync::Arc;

use crate::{
    radio::{
        simulated::{SimNetwork, SimProfile},
        MeshRadio,
    },
    relay::{MeshRelayAgent, RelayConfig},
    transport::MeshNode,
};

pub struct SimHarness {
    pub network: Arc<SimNetwork>,
    pub nodes: Vec<Arc<MeshNode>>,
    device_indices: Vec<u64>,
    accept_loops: Vec<tokio::task::JoinHandle<()>>,
}

impl SimHarness {
    /// Every node gets a running accept loop from construction on — a
    /// `sync_once`/`run_sync_round` caller only drives the *outbound*
    /// (scan + connect) side explicitly; the *inbound* side
    /// (`MeshRadio::accept` + `sync_with_peer`) has to be running
    /// concurrently on whichever node gets connected to, or that node
    /// never replies and the connecting side's `sync_with_peer` blocks
    /// forever waiting for a peer that's never going to answer. Found by
    /// `mesh/tests/partition_rejoin_tests.rs` completing in ~0ms with
    /// zero propagation instead of exercising anything — not something
    /// to route around with a manual accept step at each call site.
    pub fn new(n: usize, profile: SimProfile, relay_config: RelayConfig) -> Self {
        let network = SimNetwork::new();
        let mut nodes = Vec::with_capacity(n);
        let mut device_indices = Vec::with_capacity(n);
        let mut accept_loops = Vec::with_capacity(n);
        for _ in 0..n {
            let sim_radio = network.register(profile);
            device_indices.push(sim_radio.device_index());
            let radio: Arc<dyn MeshRadio> = Arc::new(sim_radio);
            let node = MeshNode::new(radio, Arc::new(MeshRelayAgent::new(relay_config)));
            accept_loops.push(Arc::clone(&node).spawn_accept_loop());
            nodes.push(node);
        }
        Self {
            network,
            nodes,
            device_indices,
            accept_loops,
        }
    }

    pub fn node(&self, i: usize) -> Arc<MeshNode> {
        Arc::clone(&self.nodes[i])
    }

    /// Deterministic device index for `nodes[i]`'s radio — only valid
    /// for the simulated backend, which is all this harness ever drives.
    pub fn device_index(&self, i: usize) -> u64 {
        self.device_indices[i]
    }

    pub fn sever(&self, i: usize, j: usize) {
        self.network.sever(self.device_index(i), self.device_index(j));
    }

    pub fn heal(&self, i: usize, j: usize) {
        self.network.heal(self.device_index(i), self.device_index(j));
    }

    pub fn set_online(&self, i: usize, online: bool) {
        self.network.set_online(self.device_index(i), online);
    }

    /// One full round: every node scans and syncs with whoever it can
    /// currently see, in index order (deterministic). Returns the total
    /// number of (peer, admitted-count) pairs across the round, for
    /// tests that want a coarse "did anything move" signal.
    pub async fn run_sync_round(&self) -> usize {
        let mut total = 0usize;
        for node in &self.nodes {
            if let Ok(admitted) = node.sync_once().await {
                total += admitted;
            }
        }
        total
    }

    pub async fn run_sync_rounds(&self, rounds: usize) {
        for _ in 0..rounds {
            self.run_sync_round().await;
        }
    }
}

impl Drop for SimHarness {
    /// Dropping a `JoinHandle` does not cancel the task it refers to —
    /// tokio tasks are detached by default — so without this, every
    /// harness's accept loops would keep running (and holding their
    /// `Arc<MeshNode>` alive) for the rest of the process, not just the
    /// test that created them. Each `#[tokio::test]` gets its own
    /// runtime torn down at test end regardless, so this isn't a
    /// correctness bug in practice today, but it's a real leak this
    /// harness shouldn't rely on test-runner behavior to paper over.
    fn drop(&mut self) {
        for handle in &self.accept_loops {
            handle.abort();
        }
    }
}
