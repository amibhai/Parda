//! `AndroidMeshRadio` — a real `parda_mesh::radio::MeshRadio`
//! implementation backed by Android's `BluetoothLeAdvertiser`/
//! `BluetoothLeScanner`/GATT-server APIs, reached via the JNI bridge in
//! [`crate::ffi`]/[`crate::jni_exports`]. See crate root docs for the
//! overall design and its honesty caveats.

use async_trait::async_trait;
use parda_mesh::{
    error::{MeshError, Result},
    radio::{AdvertToken, MeshLink, MeshRadio, PeerHandle, PeerSighting, PeerSightingStream},
};
use tokio::sync::mpsc;

use crate::{
    ffi,
    pending::{self, OneshotResult},
};

pub struct AndroidMeshRadio;

impl AndroidMeshRadio {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AndroidMeshRadio {
    fn default() -> Self {
        Self::new()
    }
}

fn oneshot_to_mesh_result(result: OneshotResult) -> Result<Vec<u8>> {
    match result {
        OneshotResult::Bytes(b) => Ok(b),
        OneshotResult::Empty => Ok(Vec::new()),
        OneshotResult::Error(e) => Err(MeshError::RadioUnavailable(e)),
    }
}

#[async_trait]
impl MeshRadio for AndroidMeshRadio {
    async fn advertise(&self, token: AdvertToken) -> Result<()> {
        let id = pending::next_id();
        let rx = pending::register_oneshot(id);
        ffi::start_advertise(id, &token.to_wire())
            .map_err(|e| MeshError::RadioUnavailable(format!("JNI startAdvertise failed: {e}")))?;
        let result = rx
            .await
            .map_err(|_| MeshError::RadioUnavailable("advertise callback channel closed".to_string()))?;
        oneshot_to_mesh_result(result).map(|_| ())
    }

    async fn scan(&self) -> Result<PeerSightingStream> {
        let stream_id = pending::next_id();
        let mut raw_rx = pending::register_stream(stream_id);
        ffi::start_scan(stream_id)
            .map_err(|e| MeshError::RadioUnavailable(format!("JNI startScan failed: {e}")))?;

        // `MeshRadio::scan` returns a snapshot-shaped stream on the
        // simulated backend (see mesh/src/radio/simulated.rs module
        // docs); a real BLE scan is genuinely open-ended. This adapter
        // collects a short window of results (matching how
        // `MeshRelayAgent`'s sync loop already treats `scan()` as "poll,
        // then act on whatever's visible right now" — see
        // mesh/src/transport.rs) rather than leaving the underlying
        // Android scan running forever attached to a stream nobody is
        // still draining.
        let (tx, out_rx) = mpsc::channel(64);
        tokio::spawn(async move {
            let deadline = tokio::time::sleep(std::time::Duration::from_secs(4));
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    _ = &mut deadline => break,
                    sighting = raw_rx.recv() => {
                        let Some(sighting) = sighting else { break };
                        if sighting.token.len() != parda_mesh::radio::ADVERT_TOKEN_LEN {
                            continue; // malformed/foreign advertisement — skip, don't guess
                        }
                        let mut token_bytes = [0u8; parda_mesh::radio::ADVERT_TOKEN_LEN];
                        token_bytes.copy_from_slice(&sighting.token);
                        let peer_sighting = PeerSighting {
                            handle: PeerHandle::from_opaque_bytes(sighting.peer_handle),
                            token: AdvertToken(token_bytes),
                            seen_at: std::time::Instant::now(),
                        };
                        if tx.send(peer_sighting).await.is_err() {
                            break;
                        }
                    }
                }
            }
            pending::unregister_stream(stream_id);
            let _ = ffi::stop_scan(stream_id);
        });
        Ok(out_rx)
    }

    async fn connect(&self, peer: &PeerHandle) -> Result<Box<dyn MeshLink>> {
        let peer_handle_bytes = peer
            .opaque_bytes()
            .ok_or(MeshError::PeerUnreachable)?
            .to_vec();
        let id = pending::next_id();
        let rx = pending::register_oneshot(id);
        ffi::connect(id, &peer_handle_bytes)
            .map_err(|e| MeshError::Link(format!("JNI connect failed: {e}")))?;
        let result = rx
            .await
            .map_err(|_| MeshError::Link("connect callback channel closed".to_string()))?;
        let handle_bytes = oneshot_to_mesh_result(result)?;
        let link_handle = i64::from_be_bytes(
            handle_bytes
                .try_into()
                .map_err(|_| MeshError::Link("malformed link handle from connect callback".to_string()))?,
        );
        Ok(Box::new(AndroidMeshLink { link_handle }))
    }

    async fn accept(&self) -> Result<Box<dyn MeshLink>> {
        let id = pending::next_id();
        let rx = pending::register_oneshot(id);
        ffi::accept(id).map_err(|e| MeshError::RadioUnavailable(format!("JNI accept failed: {e}")))?;
        let result = rx
            .await
            .map_err(|_| MeshError::RadioUnavailable("accept callback channel closed".to_string()))?;
        let handle_bytes = oneshot_to_mesh_result(result)?;
        let link_handle = i64::from_be_bytes(
            handle_bytes
                .try_into()
                .map_err(|_| MeshError::RadioUnavailable("malformed link handle from accept callback".to_string()))?,
        );
        Ok(Box::new(AndroidMeshLink { link_handle }))
    }
}

/// A live link to a connected/accepted peer, identified by an opaque
/// `i64` handle Kotlin assigns (indexing whatever it uses internally —
/// a `BluetoothGatt`/`BluetoothGattServer` client reference).
struct AndroidMeshLink {
    link_handle: i64,
}

#[async_trait]
impl MeshLink for AndroidMeshLink {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        let id = pending::next_id();
        let rx = pending::register_oneshot(id);
        ffi::link_send(id, self.link_handle, bytes)
            .map_err(|e| MeshError::Link(format!("JNI send failed: {e}")))?;
        let result = rx
            .await
            .map_err(|_| MeshError::Link("send callback channel closed".to_string()))?;
        oneshot_to_mesh_result(result).map(|_| ())
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        let id = pending::next_id();
        let rx = pending::register_oneshot(id);
        ffi::link_recv(id, self.link_handle)
            .map_err(|e| MeshError::Link(format!("JNI recv failed: {e}")))?;
        let result = rx
            .await
            .map_err(|_| MeshError::Link("recv callback channel closed".to_string()))?;
        oneshot_to_mesh_result(result)
    }
}
