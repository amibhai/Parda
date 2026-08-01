//! In-process, deterministic simulated radio (Sub-Phase 4A, reused at
//! scale by Sub-Phase 4D's multi-node harness).
//!
//! This is the backend every adversarial test in this crate runs
//! against: `passive_scanner_tests.rs`, `malicious_carrier_tests.rs`,
//! `flood_resistance_tests.rs`, `partition_rejoin_tests.rs`,
//! `retrieval_pattern_tests.rs`, and the 4D multi-node/hybrid-handoff
//! tests. That is a deliberate choice, not a shortcut: every claim those
//! tests make is about *protocol-level* behavior (does an advertisement
//! payload repeat, can a carrier recover plaintext from its own storage,
//! does a partition-and-rejoin duplicate or drop a bundle, does a
//! decoy-query scheme degrade a logging adversary's linkage accuracy) —
//! none of it is a claim about RF physics, which no software backend,
//! real or simulated, could prove anyway (see `docs/THREAT_MODEL.md`
//! §3.7). This mirrors `mixnode`'s own adversarial tests, which run real
//! mix-node daemons over real loopback HTTP rather than a physical
//! multi-host network — the thing under test is the protocol, not the
//! wire.
//!
//! ## Simplification, stated precisely
//!
//! Real BLE/Wi-Fi Direct scanning is continuous — advertisements arrive
//! over time as a stream. [`SimulatedMeshRadio::scan`] instead returns an
//! immediate snapshot of whoever is currently reachable and advertising,
//! as a pre-filled, already-closed channel. This is simpler to reason
//! about deterministically (no timing races in tests) and is equivalent
//! in what it proves for this crate's purposes: callers that want
//! continuous discovery call `scan()` repeatedly (which is exactly what
//! [`crate::relay::MeshRelayAgent`]'s sync loop does).

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use async_trait::async_trait;
use tokio::sync::mpsc;

use super::{AdvertToken, MeshLink, MeshRadio, PeerHandle, PeerHandleInner, PeerSighting, PeerSightingStream};
use crate::error::{MeshError, Result};

pub type DeviceIndex = u64;

/// Bundle-size/throughput profile a simulated device advertises itself
/// as. Lets 4C/4D tests prove the relay/addressing/handoff logic is
/// transport-agnostic without real Wi-Fi Direct platform code existing —
/// see the crate root docs and the limitations doc for why no real
/// Wi-Fi Direct backend was written this phase (no viable Rust crate
/// exists for it on any target platform, a searched-and-confirmed gap,
/// not an assumed one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimProfile {
    /// Small-MTU profile matching BLE's realistic per-packet ceiling.
    Ble,
    /// Large-MTU profile matching Wi-Fi Direct's realistic throughput.
    WifiDirect,
}

impl SimProfile {
    /// Rough max bytes deliverable in one `send()` call before a
    /// realistic radio would need to fragment. Not enforced as a hard
    /// limit by [`SimulatedMeshRadio`] itself (fragmentation is a
    /// transport-layer concern `mesh::relay`/`mesh::bundle` would need to
    /// handle for a real backend) — exposed so tests can size bundles
    /// meaningfully per profile.
    pub fn approx_mtu(self) -> usize {
        match self {
            SimProfile::Ble => 512,
            SimProfile::WifiDirect => 65536,
        }
    }
}

struct DeviceState {
    token: Option<AdvertToken>,
    online: bool,
    accept_tx: mpsc::UnboundedSender<SimLink>,
}

/// The shared simulated "air" — every [`SimulatedMeshRadio`] registered
/// against the same `SimNetwork` can potentially reach every other,
/// subject to the connectivity graph ([`SimNetwork::sever`]/`heal`) and
/// churn ([`SimNetwork::set_online`]) controls below.
pub struct SimNetwork {
    devices: Mutex<HashMap<DeviceIndex, DeviceState>>,
    severed: Mutex<HashSet<(DeviceIndex, DeviceIndex)>>,
    next_index: AtomicU64,
}

impl SimNetwork {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            devices: Mutex::new(HashMap::new()),
            severed: Mutex::new(HashSet::new()),
            next_index: AtomicU64::new(0),
        })
    }

    /// Register a new simulated device and return a radio handle for it.
    ///
    /// Seeds an initial advertisement token immediately, rather than
    /// leaving it unset until an explicit [`MeshRadio::advertise`] call —
    /// a registered-but-silent device would never be discoverable via
    /// `scan()` (found by `mesh/tests/partition_rejoin_tests.rs`'s
    /// scenarios completing instantly with zero propagation instead of
    /// exercising anything, because nothing was ever visible to scan for
    /// in the first place). [`MeshRadio::advertise`] still works
    /// normally afterward — this is a starting default, not a
    /// restriction on later rotation.
    pub fn register(self: &Arc<Self>, profile: SimProfile) -> SimulatedMeshRadio {
        let index = self.next_index.fetch_add(1, Ordering::SeqCst);
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        self.devices.lock().unwrap().insert(
            index,
            DeviceState {
                token: Some(AdvertToken::fresh()),
                online: true,
                accept_tx,
            },
        );
        SimulatedMeshRadio {
            network: Arc::clone(self),
            device: index,
            profile,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
        }
    }

    fn pair(a: DeviceIndex, b: DeviceIndex) -> (DeviceIndex, DeviceIndex) {
        if a <= b {
            (a, b)
        } else {
            (b, a)
        }
    }

    /// Cut connectivity between two devices (partition). Idempotent.
    pub fn sever(&self, a: DeviceIndex, b: DeviceIndex) {
        self.severed.lock().unwrap().insert(Self::pair(a, b));
    }

    /// Restore connectivity between two devices. Idempotent.
    pub fn heal(&self, a: DeviceIndex, b: DeviceIndex) {
        self.severed.lock().unwrap().remove(&Self::pair(a, b));
    }

    /// Take a device fully offline (churn: it stops being visible to, or
    /// able to reach, anyone — including bundles already in its own
    /// relay's local queue, which simply wait until it's back online).
    pub fn set_online(&self, device: DeviceIndex, online: bool) {
        if let Some(state) = self.devices.lock().unwrap().get_mut(&device) {
            state.online = online;
        }
    }

    fn reachable(&self, a: DeviceIndex, b: DeviceIndex) -> bool {
        if a == b {
            return false;
        }
        let devices = self.devices.lock().unwrap();
        let a_online = devices.get(&a).map(|d| d.online).unwrap_or(false);
        let b_online = devices.get(&b).map(|d| d.online).unwrap_or(false);
        if !a_online || !b_online {
            return false;
        }
        drop(devices);
        !self.severed.lock().unwrap().contains(&Self::pair(a, b))
    }
}

/// A live in-process link: an mpsc channel pair. `send`/`recv` are
/// whole-message (each `send` call is exactly one `recv` on the other
/// end) — real backends fragment/reassemble; the simulated backend
/// doesn't need to, since it never actually serializes onto a wire.
struct SimLink {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

#[async_trait]
impl MeshLink for SimLink {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.tx
            .send(bytes.to_vec())
            .map_err(|_| MeshError::Link("peer link closed".to_string()))
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| MeshError::Link("peer link closed".to_string()))
    }
}

pub struct SimulatedMeshRadio {
    network: Arc<SimNetwork>,
    device: DeviceIndex,
    profile: SimProfile,
    accept_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<SimLink>>,
}

impl SimulatedMeshRadio {
    pub fn device_index(&self) -> DeviceIndex {
        self.device
    }

    pub fn profile(&self) -> SimProfile {
        self.profile
    }
}

#[async_trait]
impl MeshRadio for SimulatedMeshRadio {
    async fn advertise(&self, token: AdvertToken) -> Result<()> {
        let mut devices = self.network.devices.lock().unwrap();
        let state = devices
            .get_mut(&self.device)
            .ok_or_else(|| MeshError::RadioUnavailable("device not registered".to_string()))?;
        state.token = Some(token);
        Ok(())
    }

    async fn scan(&self) -> Result<PeerSightingStream> {
        // Snapshot — see module docs "Simplification, stated precisely".
        //
        // Deliberately does NOT call `SimNetwork::reachable` from inside
        // this block: `reachable` takes its own lock on `self.network.devices`,
        // and `std::sync::Mutex` is not reentrant — doing so while the
        // `devices` guard below is still held self-deadlocks (found by
        // `radio::simulated::tests::connected_devices_see_each_others_advertisements`
        // hanging, not a false-positive-shaped failure). `severed` is a
        // *separate* mutex, so locking it here alongside `devices` is
        // fine.
        let severed = self.network.severed.lock().unwrap().clone();
        let sightings: Vec<PeerSighting> = {
            let devices = self.network.devices.lock().unwrap();
            let self_online = devices.get(&self.device).map(|d| d.online).unwrap_or(false);
            devices
                .iter()
                .filter(|(&idx, state)| {
                    idx != self.device
                        && self_online
                        && state.online
                        && !severed.contains(&SimNetwork::pair(self.device, idx))
                })
                .filter_map(|(&idx, state)| {
                    state.token.map(|token| PeerSighting {
                        handle: PeerHandle(PeerHandleInner::Simulated(idx)),
                        token,
                        seen_at: Instant::now(),
                    })
                })
                .collect()
        };

        let (tx, rx) = mpsc::channel(sightings.len().max(1));
        for sighting in sightings {
            // Bounded to exactly the snapshot size, so this never blocks.
            let _ = tx.send(sighting).await;
        }
        Ok(rx)
    }

    async fn connect(&self, peer: &PeerHandle) -> Result<Box<dyn MeshLink>> {
        // Irrefutable on this platform (the `Bluez` variant only exists
        // under `cfg(target_os = "linux", feature = "bluez")`), but
        // genuinely refutable once that cfg is active — a peer handle
        // from the wrong backend must be rejected, not panic.
        #[allow(irrefutable_let_patterns)]
        let PeerHandleInner::Simulated(target) = peer.0
        else {
            return Err(MeshError::PeerUnreachable);
        };
        if !self.network.reachable(self.device, target) {
            return Err(MeshError::PeerUnreachable);
        }
        let (my_tx, their_rx) = mpsc::unbounded_channel();
        let (their_tx, my_rx) = mpsc::unbounded_channel();

        let accept_tx = {
            let devices = self.network.devices.lock().unwrap();
            devices
                .get(&target)
                .ok_or(MeshError::PeerUnreachable)?
                .accept_tx
                .clone()
        };
        accept_tx
            .send(SimLink {
                tx: their_tx,
                rx: their_rx,
            })
            .map_err(|_| MeshError::PeerUnreachable)?;

        Ok(Box::new(SimLink {
            tx: my_tx,
            rx: my_rx,
        }))
    }

    async fn accept(&self) -> Result<Box<dyn MeshLink>> {
        let mut rx = self.accept_rx.lock().await;
        let link = rx
            .recv()
            .await
            .ok_or_else(|| MeshError::RadioUnavailable("radio closed".to_string()))?;
        Ok(Box::new(link))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connected_devices_see_each_others_advertisements() {
        let net = SimNetwork::new();
        let a = net.register(SimProfile::Ble);
        let b = net.register(SimProfile::Ble);

        let token_b = AdvertToken::fresh();
        b.advertise(token_b).await.unwrap();

        let mut stream = a.scan().await.unwrap();
        let sighting = stream.recv().await.expect("a should see b");
        assert_eq!(sighting.token, token_b);
    }

    #[tokio::test]
    async fn severed_devices_do_not_see_each_other() {
        let net = SimNetwork::new();
        let a = net.register(SimProfile::Ble);
        let b = net.register(SimProfile::Ble);
        b.advertise(AdvertToken::fresh()).await.unwrap();

        net.sever(a.device_index(), b.device_index());
        let mut stream = a.scan().await.unwrap();
        assert!(stream.recv().await.is_none(), "severed peer must not be visible");

        net.heal(a.device_index(), b.device_index());
        let mut stream = a.scan().await.unwrap();
        assert!(stream.recv().await.is_some(), "healed peer must become visible again");
    }

    #[tokio::test]
    async fn offline_device_is_unreachable_for_connect() {
        let net = SimNetwork::new();
        let a = net.register(SimProfile::Ble);
        let b = net.register(SimProfile::Ble);
        b.advertise(AdvertToken::fresh()).await.unwrap();
        net.set_online(b.device_index(), false);

        let peer = PeerHandle(PeerHandleInner::Simulated(b.device_index()));
        let result = a.connect(&peer).await;
        assert!(matches!(result, Err(MeshError::PeerUnreachable)));
    }

    #[tokio::test]
    async fn connect_and_accept_exchange_bytes_both_directions() {
        let net = SimNetwork::new();
        let a = net.register(SimProfile::Ble);
        let b = net.register(SimProfile::Ble);
        let b_handle = PeerHandle(PeerHandleInner::Simulated(b.device_index()));

        let b_task = tokio::spawn(async move {
            let mut link = b.accept().await.unwrap();
            let got = link.recv().await.unwrap();
            link.send(&[got[0] + 1]).await.unwrap();
        });

        let mut link = a.connect(&b_handle).await.unwrap();
        link.send(&[41]).await.unwrap();
        let reply = link.recv().await.unwrap();
        assert_eq!(reply, vec![42]);

        b_task.await.unwrap();
    }
}
