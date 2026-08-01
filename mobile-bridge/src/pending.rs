//! Pending-request registries bridging Kotlin's callback-based BLE APIs
//! into Rust's `async`/`await` — see crate root docs for the overall
//! design. Two registries, because Android's BLE callbacks have two
//! different shapes:
//!
//! - **One-shot** (`register_oneshot`/`resolve_oneshot`): an operation
//!   that completes exactly once — `advertise` starting successfully or
//!   failing, a GATT `connect` succeeding, one `send`/`recv` on an
//!   established link.
//! - **Streaming** (`register_stream`/`push_stream`): `scan` produces an
//!   open-ended sequence of sightings until the caller stops scanning,
//!   which is what `MeshRadio::scan`'s `mpsc::Receiver` already expects.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicI64, Ordering},
        Mutex, OnceLock,
    },
};

use tokio::sync::{mpsc, oneshot};

static NEXT_ID: AtomicI64 = AtomicI64::new(1);

/// Fresh, process-unique request ID — passed to Kotlin so its callback
/// knows which pending Rust future (or stream) to resolve/push to.
pub fn next_id() -> i64 {
    NEXT_ID.fetch_add(1, Ordering::SeqCst)
}

#[derive(Debug)]
pub enum OneshotResult {
    Bytes(Vec<u8>),
    Empty,
    Error(String),
}

fn oneshot_registry() -> &'static Mutex<HashMap<i64, oneshot::Sender<OneshotResult>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<i64, oneshot::Sender<OneshotResult>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register_oneshot(id: i64) -> oneshot::Receiver<OneshotResult> {
    let (tx, rx) = oneshot::channel();
    oneshot_registry().lock().unwrap().insert(id, tx);
    rx
}

/// Called from the JNI-exported native callback entry points. Silently
/// drops the result if nothing is waiting (already resolved, timed out
/// and given up, or a spurious/duplicate callback) — a defensive no-op,
/// not an error condition worth propagating back into the JVM.
pub fn resolve_oneshot(id: i64, result: OneshotResult) {
    if let Some(tx) = oneshot_registry().lock().unwrap().remove(&id) {
        let _ = tx.send(result);
    }
}

#[derive(Debug, Clone)]
pub struct ScanResultBytes {
    /// Opaque per-sighting handle bytes (Kotlin's own device reference,
    /// e.g. a MAC string or GATT server client handle) — round-tripped
    /// back to Kotlin unchanged when Rust later calls `connect`.
    pub peer_handle: Vec<u8>,
    pub token: Vec<u8>,
}

fn stream_registry() -> &'static Mutex<HashMap<i64, mpsc::Sender<ScanResultBytes>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<i64, mpsc::Sender<ScanResultBytes>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register_stream(id: i64) -> mpsc::Receiver<ScanResultBytes> {
    let (tx, rx) = mpsc::channel(64);
    stream_registry().lock().unwrap().insert(id, tx);
    rx
}

pub fn push_stream(id: i64, sighting: ScanResultBytes) {
    if let Some(tx) = stream_registry().lock().unwrap().get(&id) {
        // A full channel or a closed receiver both just drop this
        // sighting — scan results are inherently best-effort/lossy
        // (a real scanner can't guarantee every advertisement is
        // captured either), not a condition to propagate as an error.
        let _ = tx.try_send(sighting);
    }
}

pub fn unregister_stream(id: i64) {
    stream_registry().lock().unwrap().remove(&id);
}
