//! Proximity radio abstraction (Sub-Phase 4A).
//!
//! [`MeshRadio`] decouples the relay agent and [`crate::transport::MeshTransport`]
//! from the underlying BLE or Wi-Fi Direct hardware, the same way
//! `parda_protocol::transport::TransportLayer` decouples the session
//! layer from HTTP/mix-network delivery (see that module's docs — this
//! is the same design move, one layer down).
//!
//! ## No persistent radio-layer identifiers
//!
//! An [`AdvertToken`] is the *entire* advertisement payload this crate
//! ever emits: fixed-size random bytes plus a 2-byte protocol tag. No
//! device name, no service UUID, no anything that survives past its
//! rotation window (see [`RotatingIdentity`]). This is deliberately the
//! smallest thing that lets a legitimate peer recognize "a PARDA node is
//! here" without it being stable across sessions or linkable to a
//! specific identity — the brief's literal requirement for Sub-Phase 4A.
//!
//! ## What this crate controls, and what it doesn't
//!
//! App code controls the *advertised payload* — that's [`AdvertToken`]
//! and its rotation. App code does **not** control the underlying
//! link-layer MAC/random address on any platform this project has a real
//! backend for or has researched: iOS hides the address from apps
//! entirely (assigns a random per-app `CBPeripheral` UUID instead of a
//! MAC) and rotates the real address at the OS level on its own schedule
//! (~15 minutes), with zero app-level control; Android's address
//! randomization is OS/manufacturer policy, also not exposed for
//! fine-grained app control. Linux/BlueZ's resolvable-private-address
//! rotation is likewise a kernel/`bluetoothd` privacy-subsystem concern,
//! not something [`radio::bluez`] drives directly. This module's job —
//! and the only thing it can actually guarantee — is that the *payload*
//! never repeats or carries anything stable; see
//! `docs/THREAT_MODEL.md` §3.7 for the full, precise statement of what
//! is and isn't defended, and the README limitations list for the
//! platform-by-platform citation.
//!
//! ## Backends
//!
//! - [`simulated`] — in-process, deterministic. What every adversarial
//!   and multi-node simulation test in this crate runs against. See its
//!   module docs for why this is the right tool for the claims Phase 4
//!   actually needs to prove.
//! - [`bluez`] (`target_os = "linux"`, feature `bluez`) — real backend on
//!   `bluer` (BlueZ). The one real, compiling platform backend this phase
//!   ships — see its module docs and the plan/limitations doc for why
//!   CoreBluetooth/Android/Windows are documented gaps, not stub code.

pub mod simulated;

#[cfg(all(target_os = "linux", feature = "bluez"))]
pub mod bluez;

use std::time::{Duration, Instant};

use async_trait::async_trait;
use rand::RngCore;
use tokio::sync::mpsc;

use crate::error::Result;

/// Length of the opaque advertisement token, in bytes. Deliberately
/// small — BLE advertisement payloads are tightly size-constrained, and
/// this needs to fit alongside the 2-byte protocol tag with room to
/// spare in a legacy (31-byte) advertisement PDU.
pub const ADVERT_TOKEN_LEN: usize = 16;

/// Marks an advertisement as "a PARDA Phase 4 node" without identifying
/// *which* one. Fixed, public, and the same for every node and every
/// rotation window — recognizability is the point; only the random bytes
/// alongside it are meant to be unlinkable.
pub const PROTOCOL_TAG: [u8; 2] = *b"P4";

/// Default rotation interval for [`RotatingIdentity`]. A threat-model
/// parameter, not a hardcoded floor — same treatment
/// `mixnet::DEFAULT_AVG_DELAY` already gets in Sub-Phase 2B: shorter
/// means less time for a co-located observer to build a session-long
/// presence profile against a single token, at the cost of more
/// frequent re-advertisement (and, on a real radio, more radio-on time —
/// see the Sub-Phase 4D battery-cost note).
pub const DEFAULT_ROTATION_INTERVAL: Duration = Duration::from_secs(120);

/// The opaque bytes a PARDA node advertises. Carries no information
/// beyond "a PARDA node, of this protocol version, is here right now" —
/// see module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdvertToken(pub [u8; ADVERT_TOKEN_LEN]);

impl AdvertToken {
    /// Draw a fresh, uniformly random token. Never derived from any
    /// stable per-device secret — a fresh CSPRNG draw every time, same
    /// posture as `self_destruct`'s IKM and `mixnode::identity`'s
    /// ephemeral fallback keys.
    pub fn fresh() -> Self {
        let mut bytes = [0u8; ADVERT_TOKEN_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// The bytes actually placed on the wire: protocol tag first (fixed,
    /// public), then the random token.
    pub fn to_wire(self) -> [u8; 2 + ADVERT_TOKEN_LEN] {
        let mut out = [0u8; 2 + ADVERT_TOKEN_LEN];
        out[..2].copy_from_slice(&PROTOCOL_TAG);
        out[2..].copy_from_slice(&self.0);
        out
    }
}

/// Rotates an [`AdvertToken`] on a fixed interval. Holds no state that
/// survives a rotation beyond the current token's random bytes — the
/// previous token is simply dropped, not derivable from the new one (no
/// hash chain, no counter relationship between successive tokens; a
/// linkage adversary who recovers one token learns nothing about the
/// next). See `mesh/tests/passive_scanner_tests.rs` for the adversarial
/// test this property is checked against.
pub struct RotatingIdentity {
    interval: Duration,
    current: std::sync::Mutex<(AdvertToken, Instant)>,
}

impl RotatingIdentity {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            current: std::sync::Mutex::new((AdvertToken::fresh(), Instant::now())),
        }
    }

    pub fn with_default_interval() -> Self {
        Self::new(DEFAULT_ROTATION_INTERVAL)
    }

    /// The currently-advertised token, rotating first if the interval
    /// has elapsed since the last rotation. Time-driven, for real
    /// backends that just want "give me whatever's current right now."
    pub fn current_token(&self) -> AdvertToken {
        let mut guard = self.current.lock().unwrap();
        if guard.1.elapsed() >= self.interval {
            *guard = (AdvertToken::fresh(), Instant::now());
        }
        guard.0
    }

    /// Force a rotation regardless of elapsed time and return the new
    /// token. Used directly by tests that need to drive many rotation
    /// windows deterministically without depending on wall-clock sleeps
    /// (see the passive-scanner test) and by [`spawn_rotation_loop`].
    pub fn rotate(&self) -> AdvertToken {
        let mut guard = self.current.lock().unwrap();
        *guard = (AdvertToken::fresh(), Instant::now());
        guard.0
    }
}

/// Spawn a background task that calls [`RotatingIdentity::rotate`] and
/// re-advertises on `radio` every `interval`. This is what a real,
/// continuously-running node uses; tests drive rotation directly via
/// `RotatingIdentity::rotate()` instead, to stay deterministic.
pub fn spawn_rotation_loop(
    identity: std::sync::Arc<RotatingIdentity>,
    radio: std::sync::Arc<dyn MeshRadio>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let token = identity.rotate();
            if let Err(e) = radio.advertise(token).await {
                tracing::debug!(error = %e, "re-advertisement after rotation failed (non-fatal)");
            }
        }
    })
}

/// An opaque handle to a peer sighted via [`MeshRadio::scan`]. Valid only
/// within the scanning session that produced it — never persisted, never
/// meaningfully comparable across two separate `scan()` calls beyond
/// "same call." Backends are free to give this whatever internal shape
/// they need (a `bluer` device path, a simulated device index); nothing
/// outside this crate ever inspects it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHandle(pub(crate) PeerHandleInner);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerHandleInner {
    Simulated(u64),
    #[cfg(all(target_os = "linux", feature = "bluez"))]
    Bluez(bluer::Address),
}

/// A single observed advertisement: which opaque token, and a handle
/// usable to attempt a connection right now. No RSSI/stable-ID
/// bookkeeping beyond this — anything richer risks becoming a linkage
/// signal in its own right.
#[derive(Debug, Clone)]
pub struct PeerSighting {
    pub handle: PeerHandle,
    pub token: AdvertToken,
    pub seen_at: Instant,
}

pub type PeerSightingStream = mpsc::Receiver<PeerSighting>;

/// A live, bidirectional byte-stream connection to a peer, established
/// via [`MeshRadio::connect`] or received via [`MeshRadio::accept`].
#[async_trait]
pub trait MeshLink: Send + Sync {
    async fn send(&mut self, bytes: &[u8]) -> Result<()>;
    async fn recv(&mut self) -> Result<Vec<u8>>;
}

/// Abstract proximity radio: advertise an opaque presence token, scan
/// for others, and exchange bytes with a sighted peer. Implementors MUST
/// NOT advertise anything beyond an [`AdvertToken`] (see module docs) and
/// MUST NOT persist a peer's identity beyond a single [`PeerHandle`]'s
/// validity window.
#[async_trait]
pub trait MeshRadio: Send + Sync {
    /// Begin advertising `token`, replacing whatever was previously
    /// advertised.
    async fn advertise(&self, token: AdvertToken) -> Result<()>;

    /// Snapshot currently-visible PARDA advertisements. Real backends may
    /// implement this as a short active/passive scan window; the
    /// simulated backend returns an immediate snapshot (see its module
    /// docs for why that simplification is acceptable for what this
    /// crate's tests need to prove).
    async fn scan(&self) -> Result<PeerSightingStream>;

    /// Open a connection to a previously-sighted peer.
    async fn connect(&self, peer: &PeerHandle) -> Result<Box<dyn MeshLink>>;

    /// Block until a peer connects to this device's advertised token.
    async fn accept(&self) -> Result<Box<dyn MeshLink>>;
}
