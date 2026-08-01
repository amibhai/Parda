//! Real BLE backend on `bluer` (official BlueZ bindings), Linux only.
//!
//! **Not compiled or run in this session.** This module is gated
//! `#[cfg(target_os = "linux")]` behind the `bluez` feature; the machine
//! this was written on is Windows, so `cargo check`/`cargo test` here
//! never touches this file at all — there is no local toolchain
//! (`bluetoothd`, D-Bus dev headers) to build or run it against either.
//! It will get its first real compile in CI's `ubuntu-latest` leg (see
//! `.github/workflows/ci.yml`'s `mesh-adversarial` job, which adds the
//! `libdbus-1-dev` package this needs). This is a materially weaker
//! evidentiary claim than the rest of this crate — "reasoned against
//! `bluer`'s published API, not yet verified to compile" — stated here
//! explicitly rather than left for a reader to assume otherwise, same
//! standard the Sub-Phase 3C Kotlin fix held itself to. Even once it
//! compiles in CI, no GitHub-hosted runner has a Bluetooth radio, so
//! `advertise`/`scan`/`connect`/`accept` cannot be exercised against real
//! RF there either — see the crate root docs and `docs/THREAT_MODEL.md`
//! §3.7.
//!
//! ## Design: GATT for presence, L2CAP for data
//!
//! The advertised [`super::AdvertToken`] rides as BLE service data under
//! [`PARDA_SERVICE_UUID`] (a fixed, public "this is a PARDA node" marker
//! — the same role [`super::PROTOCOL_TAG`] plays for the simulated
//! backend; it identifies the *protocol*, not the device, and is
//! identical across every node and every rotation window). Bulk bundle
//! transfer after connection uses an L2CAP connection-oriented channel
//! (`bluer::l2cap`) rather than a custom GATT characteristic protocol —
//! L2CAP CoC behaves like a plain stream socket, which is a closer match
//! to [`super::MeshLink`]'s `send`/`recv` than modeling bundle framing as
//! a sequence of small GATT attribute writes would be.
//!
//! ## What this does NOT control (see `super` module docs)
//!
//! BlueZ's resolvable-private-address rotation is a kernel/`bluetoothd`
//! privacy-subsystem setting, not something this module drives per
//! advertisement — the same restriction researched and cited for
//! iOS/Android. What this module does control, and does rotate every
//! call, is the service-data token payload.

use std::collections::BTreeMap;

use async_trait::async_trait;
use bluer::{adv::Advertisement, l2cap, Uuid};
use tokio::sync::mpsc;

use super::{AdvertToken, MeshLink, MeshRadio, PeerHandle, PeerHandleInner, PeerSighting, PeerSightingStream, ADVERT_TOKEN_LEN};
use crate::error::{MeshError, Result};

/// Fixed, public service UUID marking "a PARDA Phase 4 node." Carries no
/// per-device information — see module docs.
pub const PARDA_SERVICE_UUID: Uuid = Uuid::from_u128(0x50415244_41340000_0000_000000000001);

/// PSM (Protocol/Service Multiplexer) this backend listens on for L2CAP
/// CoC bundle-transfer connections. Chosen from the dynamically-assignable
/// range per the Bluetooth Core Spec (0x1001-0xFFFF, odd values).
const PARDA_L2CAP_PSM: u16 = 0x1001;

pub struct BluezMeshRadio {
    adapter: bluer::Adapter,
    _advertisement: tokio::sync::Mutex<Option<bluer::adv::AdvertisementHandle>>,
    listener: l2cap::stream::StreamListener,
}

impl BluezMeshRadio {
    /// Bind to the first powered local adapter and start listening for
    /// L2CAP CoC connections. Does not advertise until [`MeshRadio::advertise`]
    /// is called.
    pub async fn new() -> Result<Self> {
        let session = bluer::Session::new()
            .await
            .map_err(|e| MeshError::RadioUnavailable(e.to_string()))?;
        let adapter = session
            .default_adapter()
            .await
            .map_err(|e| MeshError::RadioUnavailable(e.to_string()))?;
        adapter
            .set_powered(true)
            .await
            .map_err(|e| MeshError::RadioUnavailable(e.to_string()))?;

        let local_addr = l2cap::SocketAddr::new(adapter.address().await.map_err(|e| {
            MeshError::RadioUnavailable(e.to_string())
        })?, bluer::AddressType::LePublic, PARDA_L2CAP_PSM);
        let listener = l2cap::stream::StreamListener::bind(local_addr)
            .await
            .map_err(|e| MeshError::RadioUnavailable(e.to_string()))?;

        Ok(Self {
            adapter,
            _advertisement: tokio::sync::Mutex::new(None),
            listener,
        })
    }
}

#[async_trait]
impl MeshRadio for BluezMeshRadio {
    async fn advertise(&self, token: AdvertToken) -> Result<()> {
        let mut service_data = BTreeMap::new();
        service_data.insert(PARDA_SERVICE_UUID, token.0.to_vec());

        let adv = Advertisement {
            advertisement_type: bluer::adv::Type::Peripheral,
            service_uuids: [PARDA_SERVICE_UUID].into_iter().collect(),
            service_data,
            discoverable: Some(true),
            local_name: None, // never advertise a device name — see crate root docs
            ..Default::default()
        };

        let handle = self
            .adapter
            .advertise(adv)
            .await
            .map_err(|e| MeshError::RadioUnavailable(e.to_string()))?;

        // Dropping the previous handle (replaced here) stops that
        // advertisement — this *is* the rotation mechanism at the BlueZ
        // layer: a fresh `advertise()` call with a new token payload.
        *self._advertisement.lock().await = Some(handle);
        Ok(())
    }

    async fn scan(&self) -> Result<PeerSightingStream> {
        use futures::StreamExt;

        let mut discover = self
            .adapter
            .discover_devices()
            .await
            .map_err(|e| MeshError::RadioUnavailable(e.to_string()))?;

        let (tx, rx) = mpsc::channel(32);
        let adapter = self.adapter.clone();
        tokio::spawn(async move {
            // Short discovery window per call — see module docs on why
            // this backend doesn't hold a scan open indefinitely inside
            // one `scan()` call; `MeshRelayAgent`'s sync loop calls
            // `scan()` repeatedly instead (mirrors the simulated
            // backend's snapshot behavior at the trait level).
            let deadline = tokio::time::sleep(std::time::Duration::from_secs(5));
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    _ = &mut deadline => break,
                    event = discover.next() => {
                        let Some(bluer::AdapterEvent::DeviceAdded(addr)) = event else { continue };
                        let Ok(device) = adapter.device(addr) else { continue };
                        let Ok(Some(service_data)) = device.service_data().await else { continue };
                        let Some(bytes) = service_data.get(&PARDA_SERVICE_UUID) else { continue };
                        if bytes.len() != ADVERT_TOKEN_LEN {
                            continue;
                        }
                        let mut token_bytes = [0u8; ADVERT_TOKEN_LEN];
                        token_bytes.copy_from_slice(bytes);
                        let sighting = PeerSighting {
                            handle: PeerHandle(PeerHandleInner::Bluez(addr)),
                            token: AdvertToken(token_bytes),
                            seen_at: std::time::Instant::now(),
                        };
                        if tx.send(sighting).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(rx)
    }

    async fn connect(&self, peer: &PeerHandle) -> Result<Box<dyn MeshLink>> {
        let PeerHandleInner::Bluez(addr) = peer.0 else {
            return Err(MeshError::PeerUnreachable);
        };
        let target = l2cap::SocketAddr::new(addr, bluer::AddressType::LePublic, PARDA_L2CAP_PSM);
        let stream = l2cap::stream::Stream::connect(target)
            .await
            .map_err(|e| MeshError::Link(e.to_string()))?;
        Ok(Box::new(BluezLink { stream }))
    }

    async fn accept(&self) -> Result<Box<dyn MeshLink>> {
        let (stream, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| MeshError::Link(e.to_string()))?;
        Ok(Box::new(BluezLink { stream }))
    }
}

struct BluezLink {
    stream: l2cap::stream::Stream,
}

#[async_trait]
impl MeshLink for BluezLink {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        // Length-prefixed framing: L2CAP CoC is a byte stream, not a
        // message boundary-preserving transport, so `send`/`recv` need
        // an explicit frame length the way the simulated backend's
        // whole-message mpsc channel gets for free.
        let len = (bytes.len() as u32).to_be_bytes();
        self.stream
            .write_all(&len)
            .await
            .map_err(|e| MeshError::Link(e.to_string()))?;
        self.stream
            .write_all(bytes)
            .await
            .map_err(|e| MeshError::Link(e.to_string()))
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| MeshError::Link(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| MeshError::Link(e.to_string()))?;
        Ok(buf)
    }
}
